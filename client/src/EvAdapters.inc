// EvAdapters.inc —— 动态 API 薄封装的实现主体（由 Compat.cpp 包含）
//
// 每个封装的形状都一样：
//   using Fn = <原始签名>;
//   static Fn fn = ::r6m::ev::Api::F<Fn>(模块哈希, 过程哈希);   // 首次调用惰性解析并缓存
//   if (!fn) return <失败默认值>;
//   return fn(参数...);
//
// 为什么单独成 .inc：这段是纯机械代码（30+ 个），单独放便于审阅"是否每个都
// 真的走了哈希解析"，也便于用脚本核对与工具生成的哈希常量是否一一对应。

// 这些封装位于**文件作用域**（声明与实现在同一作用域），
// 因为参数类型是 Windows SDK 的全局类型名，放进 r6m::ev 会解析失败。

// 注意：函数指针类型必须与**封装自身的调用约定**一致（都是 __cdecl）。
// 若写成 WINAPI(__stdcall) 会在链接期出现"无法解析的外部符号"——
// x64 上两种约定行为相同，但名字修饰不同，声明与实现会配不上对（踩过）。
#define EV_ADAPT(name, modhash, procHash, ret, dflt, sig, args)   \
    using name##_Fn = ret(__cdecl*) sig;                           \
    name##_Fn fn = ::r6m::ev::Api::F<name##_Fn>(modhash, procHash);\
    if (!fn) return dflt;                                          \
    return fn args;

//   CryptoAPI 里只有 CryptProtectData / CryptUnprotectData / CertFreeCertificateChain
//   位于 crypt32.dll；而 CryptAcquireContextW / CryptCreateHash / CryptHashData /
//   CryptGetHashParam / CryptDestroyHash / CryptReleaseContext / CryptGenRandom
//   **都在 advapi32.dll**（转发到 cryptsp.dll）。
//   GetComputerNameW 在 kernel32.dll，不在 advapi32。
//   写错模块的症状很隐蔽：Api::M 能按哈希找到那个 DLL（因为它确实被加载了），
//   且**不设置 LastError**，日志表现为 "xxx 失败 err=0"（err=0 = 调用压根没发生）。
//   核对方法（PowerShell）：
//     LoadLibraryA("advapi32.dll") + GetProcAddress(h,"CryptAcquireContextW")

// ── WinINet ──
HINTERNET EvInternetOpenA(LPCSTR a, DWORD t, LPCSTR p, LPCSTR b, DWORD f) {
    EV_ADAPT(InternetOpenA, R6M_M_WININET, R6M_H_InternetOpenA, HINTERNET, nullptr,
             (LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD), (a, t, p, b, f))
}
HINTERNET EvInternetConnectA(HINTERNET h, LPCSTR host, INTERNET_PORT port, LPCSTR u,
                             LPCSTR pw, DWORD svc, DWORD fl, DWORD_PTR cx) {
    EV_ADAPT(InternetConnectA, R6M_M_WININET, R6M_H_InternetConnectA, HINTERNET, nullptr,
             (HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR),
             (h, host, port, u, pw, svc, fl, cx))
}
HINTERNET EvHttpOpenRequestA(HINTERNET h, LPCSTR verb, LPCSTR path, LPCSTR ver,
                             LPCSTR ref, LPCSTR* types, DWORD fl, DWORD_PTR cx) {
    EV_ADAPT(HttpOpenRequestA, R6M_M_WININET, R6M_H_HttpOpenRequestA, HINTERNET, nullptr,
             (HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR),
             (h, verb, path, ver, ref, types, fl, cx))
}
BOOL EvHttpSendRequestA(HINTERNET h, LPCSTR hd, DWORD hl, LPVOID opt, DWORD ol) {
    EV_ADAPT(HttpSendRequestA, R6M_M_WININET, R6M_H_HttpSendRequestA, BOOL, FALSE,
             (HINTERNET, LPCSTR, DWORD, LPVOID, DWORD), (h, hd, hl, opt, ol))
}
BOOL EvHttpQueryInfoA(HINTERNET h, DWORD lv, LPVOID buf, LPDWORD len, LPDWORD idx) {
    EV_ADAPT(HttpQueryInfoA, R6M_M_WININET, R6M_H_HttpQueryInfoA, BOOL, FALSE,
             (HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD), (h, lv, buf, len, idx))
}
BOOL EvInternetReadFile(HINTERNET h, LPVOID buf, DWORD n, LPDWORD rd) {
    EV_ADAPT(InternetReadFile, R6M_M_WININET, R6M_H_InternetReadFile, BOOL, FALSE,
             (HINTERNET, LPVOID, DWORD, LPDWORD), (h, buf, n, rd))
}
BOOL EvInternetCloseHandle(HINTERNET h) {
    EV_ADAPT(InternetCloseHandle, R6M_M_WININET, R6M_H_InternetCloseHandle, BOOL, FALSE,
             (HINTERNET), (h))
}
BOOL EvInternetSetOptionA(HINTERNET h, DWORD o, LPVOID buf, DWORD l) {
    EV_ADAPT(InternetSetOptionA, R6M_M_WININET, R6M_H_InternetSetOptionA, BOOL, FALSE,
             (HINTERNET, DWORD, LPVOID, DWORD), (h, o, buf, l))
}
BOOL EvInternetQueryOptionA(HINTERNET h, DWORD o, LPVOID buf, LPDWORD l) {
    EV_ADAPT(InternetQueryOptionA, R6M_M_WININET, R6M_H_InternetQueryOptionA, BOOL, FALSE,
             (HINTERNET, DWORD, LPVOID, LPDWORD), (h, o, buf, l))
}
BOOL EvInternetCrackUrlA(LPCSTR url, DWORD len, DWORD fl, LPURL_COMPONENTSA c) {
    EV_ADAPT(InternetCrackUrlA, R6M_M_WININET, R6M_H_InternetCrackUrlA, BOOL, FALSE,
             (LPCSTR, DWORD, DWORD, LPURL_COMPONENTSA), (url, len, fl, c))
}

// ── Crypt32 ──
BOOL EvCryptProtectData(DATA_BLOB* in, LPCWSTR d, DATA_BLOB* e, PVOID r, PVOID p, DWORD f, DATA_BLOB* o) {
    EV_ADAPT(CryptProtectData, R6M_M_CRYPT32, R6M_H_CryptProtectData, BOOL, FALSE,
             (DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, PVOID, DWORD, DATA_BLOB*), (in, d, e, r, p, f, o))
}
BOOL EvCryptUnprotectData(DATA_BLOB* in, LPWSTR* d, DATA_BLOB* e, PVOID r, PVOID p, DWORD f, DATA_BLOB* o) {
    EV_ADAPT(CryptUnprotectData, R6M_M_CRYPT32, R6M_H_CryptUnprotectData, BOOL, FALSE,
             (DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, PVOID, DWORD, DATA_BLOB*), (in, d, e, r, p, f, o))
}
BOOL EvCryptAcquireContextW(HCRYPTPROV* pv, LPCWSTR c, LPCWSTR pr, DWORD t, DWORD f) {
    EV_ADAPT(CryptAcquireContextW, R6M_M_ADVAPI32, R6M_H_CryptAcquireContextW, BOOL, FALSE,
             (HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD), (pv, c, pr, t, f))
}
BOOL EvCryptCreateHash(HCRYPTPROV pv, ALG_ID a, HCRYPTKEY k, DWORD f, HCRYPTHASH* h) {
    EV_ADAPT(CryptCreateHash, R6M_M_ADVAPI32, R6M_H_CryptCreateHash, BOOL, FALSE,
             (HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*), (pv, a, k, f, h))
}
BOOL EvCryptHashData(HCRYPTHASH h, const BYTE* d, DWORD l, DWORD f) {
    EV_ADAPT(CryptHashData, R6M_M_ADVAPI32, R6M_H_CryptHashData, BOOL, FALSE,
             (HCRYPTHASH, const BYTE*, DWORD, DWORD), (h, d, l, f))
}
BOOL EvCryptGetHashParam(HCRYPTHASH h, DWORD p, BYTE* d, DWORD* l, DWORD f) {
    EV_ADAPT(CryptGetHashParam, R6M_M_ADVAPI32, R6M_H_CryptGetHashParam, BOOL, FALSE,
             (HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD), (h, p, d, l, f))
}
BOOL EvCryptDestroyHash(HCRYPTHASH h) {
    EV_ADAPT(CryptDestroyHash, R6M_M_ADVAPI32, R6M_H_CryptDestroyHash, BOOL, FALSE,
             (HCRYPTHASH), (h))
}
BOOL EvCryptReleaseContext(HCRYPTPROV p, DWORD f) {
    EV_ADAPT(CryptReleaseContext, R6M_M_ADVAPI32, R6M_H_CryptReleaseContext, BOOL, FALSE,
             (HCRYPTPROV, DWORD), (p, f))
}
BOOL EvCryptGenRandom(HCRYPTPROV p, DWORD l, BYTE* b) {
    EV_ADAPT(CryptGenRandom, R6M_M_ADVAPI32, R6M_H_CryptGenRandom, BOOL, FALSE,
             (HCRYPTPROV, DWORD, BYTE*), (p, l, b))
}
BOOL EvCertFreeCertificateChain(PCCERT_CHAIN_CONTEXT c) {
    EV_ADAPT(CertFreeCertificateChain, R6M_M_CRYPT32, R6M_H_CertFreeCertificateChain, BOOL, FALSE,
             (PCCERT_CHAIN_CONTEXT), (c))
}

// ── Shell32 ──
// 注意：这两个封装在 EvAdaptersShell.inc 里，本文件**不能**定义它们。
// 原因：Compat.cpp 为了让自身调用走动态解析，用 #define 把这两个名字
// 重定向到了 Ev*；宏在预处理期对整个翻译单元生效，实现体写在同文件里
// 会被替换成自己，编译报 RMM084（函数已有主体）。

// ── Shell32 ──
// 这两个封装**不能**被别名宏指到自身（见 Compat.cpp 顶部说明），
// 因此实现体直接写原始 API 名，靠 IAT 解析。
BOOL EvShellExecuteExW(LPSHELLEXECUTEINFOW sei) {
    EV_ADAPT(ShellExecuteExW, R6M_M_SHELL32, R6M_H_ShellExecuteExW, BOOL, FALSE,
             (LPSHELLEXECUTEINFOW), (sei))
}
HRESULT EvSHGetFolderPathW(HWND o, int csidl, HANDLE t, DWORD f, LPWSTR p) {
    using Fn = HRESULT(__cdecl*)(HWND, int, HANDLE, DWORD, LPWSTR);
    static Fn fn = ::r6m::ev::Api::F<Fn>(R6M_M_SHELL32, R6M_H_SHGetFolderPathW);
    if (!fn) return E_FAIL;
    return fn(o, csidl, t, f, p);
}

// ── Advapi32 ──
LONG EvRegOpenKeyExW(HKEY r, LPCWSTR s, DWORD o, REGSAM m, PHKEY k) {
    EV_ADAPT(RegOpenKeyExW, R6M_M_ADVAPI32, R6M_H_RegOpenKeyExW, LONG, ERROR_CALL_NOT_IMPLEMENTED,
             (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY), (r, s, o, m, k))
}
LONG EvRegQueryValueExW(HKEY k, LPCWSTR n, LPDWORD r, LPDWORD t, LPBYTE d, LPDWORD c) {
    EV_ADAPT(RegQueryValueExW, R6M_M_ADVAPI32, R6M_H_RegQueryValueExW, LONG, ERROR_CALL_NOT_IMPLEMENTED,
             (HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD), (k, n, r, t, d, c))
}
LONG EvRegCloseKey(HKEY k) {
    EV_ADAPT(RegCloseKey, R6M_M_ADVAPI32, R6M_H_RegCloseKey, LONG, ERROR_CALL_NOT_IMPLEMENTED, (HKEY), (k))
}
LONG EvRegCreateKeyExW(HKEY r, LPCWSTR s, DWORD rv, LPWSTR c, DWORD o, REGSAM m,
                       LPSECURITY_ATTRIBUTES sa, PHKEY k, LPDWORD dp) {
    EV_ADAPT(RegCreateKeyExW, R6M_M_ADVAPI32, R6M_H_RegCreateKeyExW, LONG, ERROR_CALL_NOT_IMPLEMENTED,
             (HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD),
             (r, s, rv, c, o, m, sa, k, dp))
}
LONG EvRegSetValueExW(HKEY k, LPCWSTR n, DWORD r, DWORD t, const BYTE* d, DWORD c) {
    EV_ADAPT(RegSetValueExW, R6M_M_ADVAPI32, R6M_H_RegSetValueExW, LONG, ERROR_CALL_NOT_IMPLEMENTED,
             (HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD), (k, n, r, t, d, c))
}
LONG EvRegDeleteValueW(HKEY k, LPCWSTR n) {
    EV_ADAPT(RegDeleteValueW, R6M_M_ADVAPI32, R6M_H_RegDeleteValueW, LONG, ERROR_CALL_NOT_IMPLEMENTED,
             (HKEY, LPCWSTR), (k, n))
}
LONG EvRegDeleteKeyW(HKEY r, LPCWSTR s) {
    EV_ADAPT(RegDeleteKeyW, R6M_M_ADVAPI32, R6M_H_RegDeleteKeyW, LONG, ERROR_CALL_NOT_IMPLEMENTED,
             (HKEY, LPCWSTR), (r, s))
}
BOOL EvGetUserNameW(LPWSTR b, LPDWORD l) {
    EV_ADAPT(GetUserNameW, R6M_M_ADVAPI32, R6M_H_GetUserNameW, BOOL, FALSE, (LPWSTR, LPDWORD), (b, l))
}
BOOL EvGetComputerNameW(LPWSTR b, LPDWORD l) {
    EV_ADAPT(GetComputerNameW, R6M_M_KERNEL32, R6M_H_GetComputerNameW, BOOL, FALSE, (LPWSTR, LPDWORD), (b, l))
}

// ── IpHlpApi ──
DWORD EvGetAdaptersInfo(PIP_ADAPTER_INFO i, PULONG l) {
    EV_ADAPT(GetAdaptersInfo, R6M_M_IPHLPAPI, R6M_H_GetAdaptersInfo, DWORD, ERROR_CALL_NOT_IMPLEMENTED,
             (PIP_ADAPTER_INFO, PULONG), (i, l))
}

#undef EV_ADAPT


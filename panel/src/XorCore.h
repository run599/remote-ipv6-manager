#pragma once
// ═══════════════════════════════════════════════════════════════════════════
// XorCore.h —— 字符串混淆的密码学内核（唯一真源）
//
// 这里只有两个纯常量表达式函数：
//
// 为什么单独成文件：Compat.h 与 generated_strings.h 都要用它们，
// 而 generated_strings.h 可能先于 Compat.h 的函数定义被解析
// （实测：把 include 提到文件作用域后，Decode() 里 keybyte 找不到标识符）。
//
// Python 实现。任一侧改动都必须同步另一侧，否则出现"解密出乱码"这类静默故障。
// 自证：python tools/obfuscate_strings.py --selftest 会验证往返一致性。
// ═══════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <cstddef>
#include <string>
#include <windows.h>

namespace r6m {
namespace ev {

// FNV-1a 64 位（也是 API 名哈希用的同一算法，见 generated_hashes.h）
constexpr uint64_t fnv1a64(const char* s, size_t n, uint64_t h = 0xcbf29ce484222325ULL) {
    return n == 0 ? h : fnv1a64(s + 1, n - 1, (h ^ (uint64_t)(unsigned char)*s) * 0x100000001b3ULL);
}
inline constexpr uint64_t fnv1a64(const char* s) {
    size_t n = 0;
    while (s[n]) ++n;
    return fnv1a64(s, n);
}

// 由 (seed, index) 派生密钥字节（SplitMix64 的轻量变体，纯常量表达式）
constexpr uint8_t keybyte(uint64_t seed, size_t i) {
    uint64_t z = seed + 0x9e3779b97f4a7c15ULL * (uint64_t)(i + 1);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return (uint8_t)(z ^ (z >> 31));
}

// ── UTF-8 ↔ UTF-16 转换 ─────────────────────────────────────────────────
// 放在这里（而不是各 .cpp 自己写一份）的原因：混淆后的字面量取出的是
// UTF-8 窄串，而大量调用点需要宽串（注册表路径/驱动文件名/比较关键字）。
// 注意：返回的是**临时对象**，只可在完整表达式内使用；需要长期保存时必须
// 落到具名变量或 static 缓存（Compat.cpp 的取用层就是这么做的）。
inline std::wstring Widen(const char* utf8) {
    if (!utf8 || !*utf8) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 1) return std::wstring();
    std::wstring w((size_t)(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &w[0], n);
    return w;
}
inline std::string Narrow(const wchar_t* w) {
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s((size_t)(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

} // namespace ev
} // namespace r6m

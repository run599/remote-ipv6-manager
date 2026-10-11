#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
obfuscate_strings.py —— 兼容层源码字面量混淆器（构建前置步骤）

做什么：
  扫描 client/src 下的 .cpp/.h，找出所有 XS("...") / XSC(<seed>,"...") 标记，
  把它们**原地展开**成 XSD(0x<seed>ULL, "<xor 密文>")，并生成
  generated_strings.h（供 include 后按 R6M_STR_<seed> 取用）。

为什么必须跑：
  XS()/XSC() 是"占位标记"，不是能编译的构造。不跑本工具就编译 = 编译期报错。
  这是有意的：宁可构建失败，也不要"忘了跑工具"导致明文进二进制。

扫描器关键设计（前一版用正则踩过的坑，勿回退）：
  ① 必须跳过注释、普通字符串字面量、字符字面量 —— 否则 "XSD(0x..." 这种
     说明文字、以及宏定义体里的 XS(literal)（参数名而非字面量）都会被误改。
  ② **必须跳过 XSD(...) 内部的递归扫描** —— 展开后的结果本身就是以
     "XSD(" 开头，若在其中继续扫 XS，会把 XSD 的 X 和 S 拆开匹配。
  ③ 必须识别 XSC(seed, "lit") 在 XS 之前 —— 切片优先匹配更长的模式。

用法：
    python obfuscate_strings.py --scan     # 只统计（列出会进二进制的串）
    python obfuscate_strings.py --gen      # 只生成 generated_strings.h
    python obfuscate_strings.py --expand   # 只展开（先写 .xsbak 备份）
    python obfuscate_strings.py --run      # = --gen + --expand（推荐）
"""

import argparse
import glob
import os
import sys

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF


def fnv1a64(data: bytes, h: int = FNV_OFFSET) -> int:
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


def keybyte(seed: int, i: int) -> int:
    z = (seed + 0x9E3779B97F4A7C15 * (i + 1)) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return (z ^ (z >> 31)) & 0xFF


_ESC = {"n": 0x0A, "r": 0x0D, "t": 0x09, "0": 0x00, "\\": 0x5C, "'": 0x27,
        '"': 0x22, "a": 0x07, "b": 0x08, "f": 0x0C, "v": 0x0B, "?": 0x3F}


def c_unescape(s: str) -> bytes:
    """把 C 字面量正文（不含两端引号）解成真实字节。"""
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out += c.encode("utf-8")
            i += 1
            continue
        i += 1
        if i >= n:
            out.append(0x5C)
            break
        e = s[i]
        if e in _ESC:
            out.append(_ESC[e]); i += 1
        elif e == "x":
            j, h = i + 1, ""
            while j < n and len(h) < 2 and s[j] in "0123456789abcdefABCDEF":
                h += s[j]; j += 1
            if not h:
                raise ValueError("空的 \\x 转义")
            out.append(int(h, 16) & 0xFF); i = j
        elif e in "01234567":
            j, o = i, ""
            while j < n and len(o) < 3 and s[j] in "01234567":
                o += s[j]; j += 1
            out.append(int(o, 8) & 0xFF); i = j
        elif e in ("u", "U"):
            ln = 4 if e == "u" else 8
            h = s[i + 1:i + 1 + ln]
            if len(h) != ln:
                raise ValueError(f"非法的 \\{e} 转义")
            out += chr(int(h, 16)).encode("utf-8"); i += 1 + ln
        else:
            out.append(0x5C); out += e.encode("utf-8"); i += 1
    return bytes(out)


def c_escape_bytes(b: bytes) -> str:
    """字节  C 字符串正文。\\xNN 后紧跟十六进制字符时插入断链，避免吞并。"""
    hexd = "0123456789abcdefABCDEF"
    parts = []
    for idx, ch in enumerate(b):
        if ch == 0x5C:
            parts.append("\\\\")
        elif ch == 0x22:
            parts.append('\\"')
        elif 0x20 <= ch < 0x7F:
            parts.append(chr(ch))
        else:
            parts.append(f"\\x{ch:02x}")
            if idx + 1 < len(b) and chr(b[idx + 1]) in hexd:
                parts.append('" "')
    return "".join(parts)


# ── 扫描器 ──────────────────────────────────────────────────────────────────
def _ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _skip_quoted(t: str, i: int) -> int:
    """t[i] == '"'；返回闭合引号之后的位置。"""
    i += 1
    while i < len(t):
        if t[i] == "\\":
            i += 2
            continue
        if t[i] == '"':
            return i + 1
        i += 1
    raise ValueError("字符串字面量未闭合")


def scan_text(t: str):
    """返回 [(kind, seed_or_None, plain_bytes, start, end)]，start/end 覆盖整个调用。"""
    hits = []
    i, n = 0, len(t)
    while i < n:
        c = t[i]

        if c == "/" and i + 1 < n and t[i + 1] == "/":
            j = t.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "/" and i + 1 < n and t[i + 1] == "*":
            j = t.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '"':
            i = _skip_quoted(t, i)
            continue
        if c == "'":
            i += 1
            while i < n and t[i] != "'":
                i += 2 if t[i] == "\\" else 1
            i += 1
            continue

        # XSD(...) 整体跳过（展开产物的递归保护）
        if t.startswith("XSD", i) and i + 3 < n and t[i + 3] == "(":
            depth = 0
            j = i + 3
            while j < n:
                if t[j] == "(":
                    depth += 1
                elif t[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            i = j + 1
            continue

        # XSC(<seed>, "...")
        if t.startswith("XSC", i) and i + 3 < n and t[i + 3] == "(":
            j = t.find(",", i + 4)
            if j < 0:
                i += 3
                continue
            seed_txt = t[i + 4:j].strip()
            k = j + 1
            while k < n and t[k] in " \t\r\n":
                k += 1
            if k < n and t[k] == '"':
                try:
                    e = _skip_quoted(t, k)
                    lit = t[k + 1:e - 1]
                    plain = c_unescape(lit)
                    try:
                        seed = int(seed_txt, 0)
                    except ValueError:
                        seed = fnv1a64(plain)
                    hits.append(("XSC", seed, plain, i, e))
                    i = e
                    continue
                except ValueError:
                    pass
            i += 3
            continue

        # XS("...")：标识符边界必须是"非标识符字符"（避免命中 XSC 与宏名）
        if t.startswith("XS", i) and i + 2 < n and t[i + 2] == "(" \
                and (i == 0 or not _ident_char(t[i - 1])):
            k = i + 3
            while k < n and t[k] in " \t\r\n":
                k += 1
            if k < n and t[k] == '"':
                try:
                    e = _skip_quoted(t, k)
                    lit = t[k + 1:e - 1]
                    plain = c_unescape(lit)
                    hits.append(("XS", fnv1a64(plain), plain, i, e))
                    i = e
                    continue
                except ValueError:
                    pass
            i += 2
            continue

        i += 1
    return hits


def find_sources(src_dir: str):
    out = []
    for pat in ("*.cpp", "*.h", "*.hpp", "*.cc"):
        out += glob.glob(os.path.join(src_dir, pat))
    return sorted(out)


def scan(src_dir: str):
    result = {}
    for f in find_sources(src_dir):
        # newline="" 是必须的：默认的通用换行会把 \r\n 折成 \n，
        # 使字符索引与磁盘文件不一致，展开时切错位置（踩过）。
        with open(f, "r", encoding="utf-8", newline="") as fh:
            text = fh.read()
        hits = scan_text(text)
        if hits:
            result[f] = hits
    return result


def collect_literals(res):
    seen = {}
    for _f, hits in res.items():
        for _kind, seed, plain, _s, _e in hits:
            seen.setdefault(plain, seed)
    return seen


def gen_header(literals, path: str):
    """生成常表头：所有密文放进专用只读节 .r6ms，并给出查表函数。

    为什么必须单独成节（实测踩过）：
      最初把整个 .rdata 加密，PE 加载器会在加载期读其中的导入描述符/加载配置，
      直接拒绝映像 —— CreateProcess 报 Win32 error 998（ERROR_NOACCESS）。
      所以加密范围只能限定在"加载器不解析的数据"，即本文件生成的这张表。
    """
    entries = sorted(literals.items(), key=lambda kv: kv[1])
    lines = [
        "#pragma once",
        "// ═══════════════════════════════════════════════════════════════════",
        "// generated_strings.h —— 由 tools/obfuscate_strings.py 自动生成，请勿手改",
        "// 内容：受保护字面量的 XOR 密文表（放在专用只读节 .r6ms）+ 查表函数",
        "//",
        "// 密文规则：enc[i] = plain[i] ^ keybyte(seed, i)，seed = fnv1a64(明文)",
        "// keybyte 是 SplitMix64 变体，与 Compat.h / pack_sections.py 逐位一致。",
        "// 声明 keybyte 由 Compat.h 提供（本文件必须在 Compat.h 之后包含）。",
        "// ═══════════════════════════════════════════════════════════════════",
        "#include <cstdint>",
        "#include <cstddef>",
        "",
        "// 数据放进 .r6ms：加载器不解析这一节，因此可以整节加密（见 pack_sections.py）",
        "#pragma section(\".r6ms\", read)",
        "#pragma comment(linker, \"/SECTION:.r6ms,R\")",
        "",
        "namespace r6m { namespace ev { namespace strtab {",
        "",
        "struct StrEnt { uint64_t seed; uint32_t len; uint32_t off; };",
        "",
    ]
    # 字面量池（密文，含结尾 \0）
    pool = bytearray()
    offs = []
    for plain, seed in entries:
        offs.append(len(pool))
        enc = bytes(b ^ keybyte(seed, i) for i, b in enumerate(plain)) + b"\x00"
        pool += enc
    lines.append("__declspec(allocate(\".r6ms\")) const unsigned char g_pool[%d] = {" % len(pool))
    for i in range(0, len(pool), 24):
        lines.append("    " + ",".join(f"0x{b:02x}" for b in pool[i:i + 24]) + ",")
    lines.append("};")
    lines.append("")
    lines.append("__declspec(allocate(\".r6ms\")) const StrEnt g_ents[%d] = {" % len(entries))
    for (plain, seed), off in zip(entries, offs):
        lines.append(f"    {{ 0x{seed:016X}ULL, {len(plain)}u, {off}u }},")
    lines.append("};")
    lines.append("")
    lines.append(f"constexpr unsigned g_count = {len(entries)}u;")
    lines.append("""
// 查表并解出明文（线程局部缓冲，指针在程序期内有效）
inline const char* Decode(uint64_t seed) {
    // 环形缓冲（4 格），不是单个 static 缓冲。
    //
    // 一旦同一表达式里调用两次 —— 例如 LOG_I(R6M_STR_tag, R6M_STR_msg)
    // 或 std::string u = PREFIX + id + SUFFIX（两端都是 R6M_STR_ 宏）——
    // 两个操作数会指向**同一块内存**，后执行的那次覆盖内容，
    // 于是两边读到同一个字符串。实测踩到的两个后果：
    //   · 日志里 tag 与正文变成同一个值（"kernel32.dll@kernel32.dll"）。
    // 4 格依据实测：全树 33 处两连调用，无三连以上。
    static thread_local char bufs[4][512];
    static thread_local unsigned turn = 0;
    for (unsigned i = 0; i < g_count; ++i) {
        if (g_ents[i].seed != seed) continue;
        const unsigned char* src = g_pool + g_ents[i].off;
        const uint32_t n = g_ents[i].len;
        char* buf = bufs[turn];
        turn = (turn + 1) & 3u;
        if (n + 1 > 512u) return "";
        for (uint32_t k = 0; k < n; ++k) buf[k] = (char)(src[k] ^ keybyte(seed, k));
        buf[n] = 0;
        return buf;
    }
    return "";
}

}}} // namespace r6m::ev::strtab

// 取用宏：#define R6M_STR_<SEED> r6m::ev::strtab::Decode(0x<SEED>ULL)
""")
    lines.append("// 共 %d 条去重字面量（密文总量 %d 字节）" % (len(entries), len(pool)))
    for plain, seed in entries:
        try:
            disp = plain.decode("utf-8")
        except UnicodeDecodeError:
            disp = plain.hex()
        lines.append(f"// {disp!r}  (len={len(plain)})")
        lines.append(f"#define R6M_STR_{seed:016X} ::r6m::ev::strtab::Decode(0x{seed:016X}ULL)")
    lines.append("")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print(f"[xref] 生成 {os.path.basename(path)}（{len(entries)} 条字面量，"
          f"密文 {len(pool)} 字节，节 .r6ms）")


def expand(src_dir: str, res, backup: bool = True) -> int:
    total = 0
    for f, hits in res.items():
        with open(f, "r", encoding="utf-8", newline="") as fh:
            text = fh.read()
        if backup:
            b = f + ".xsbak"
            if not os.path.exists(b):
                with open(b, "w", encoding="utf-8", newline="") as bf:
                    bf.write(text)
        # 从后往前替换，保证前面的位置索引仍然有效
        for kind, seed, plain, s, e in sorted(hits, key=lambda h: -h[3]):
            enc = bytes(b ^ keybyte(seed, i) for i, b in enumerate(plain)) + b"\x00"
            text = text[:s] + f'XSD(0x{seed:016X}ULL, "{c_escape_bytes(enc)}")' + text[e:]
            total += 1
        with open(f, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        if hits:
            print(f"[xref] 展开 {os.path.basename(f)}：{len(hits)} 处")
    print(f"[xref] 共展开 {total} 处")
    return total


def selftest() -> int:
    ok = True
    samples = ["r6m.ini", "X-Agent-Key", "https://", "MachineGuid", "", "中文测试"]
    for s in samples:
        raw = s.encode("utf-8")
        seed = fnv1a64(raw)
        enc = bytes(b ^ keybyte(seed, i) for i, b in enumerate(raw))
        dec = bytes(b ^ keybyte(seed, i) for i, b in enumerate(enc))
        if dec != raw:
            print(f"[FAIL] 往返失败: {s!r}"); ok = False
    # 扫描器自证：确认不会误伤宏定义体里的 XS(literal)
    probe = ('#define XW(n,l) const wchar_t* n(){static const std::wstring s=Widen(XS(l));return s.c_str();}\n'
             'void f(){ auto a = XS("real"); auto b = XSC(1, "seeded"); }\n'
             '// XS("commented-out") 不应被展开\n')
    got = [p for _k, _s, p, _a, _b in scan_text(probe)]
    print(f"[selftest] 扫描器识别到 {len(got)} 处：{got}")
    if got != [b"real", b"seeded"]:
        print("[FAIL] 扫描器误判（应为 ['real','seeded']）"); ok = False
    print("[selftest] " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.normpath(os.path.join(here, "..", "src"))
    ap = argparse.ArgumentParser(description="XS(...) 字面量混淆器")
    ap.add_argument("--src", default=src)
    ap.add_argument("--out", default=None)
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--gen", action="store_true")
    ap.add_argument("--expand", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--no-backup", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()

    out = a.out or os.path.join(a.src, "generated_strings.h")
    res = scan(a.src)
    lits = collect_literals(res)
    n_hits = sum(len(v) for v in res.values())
    print(f"[xref] 扫描 {len(res)} 个文件，命中 {n_hits} 处，去重后 {len(lits)} 条")

    if a.scan:
        for plain, seed in sorted(lits.items(), key=lambda kv: kv[1]):
            try:
                disp = plain.decode("utf-8")
            except UnicodeDecodeError:
                disp = plain.hex()
            print(f"  0x{seed:016X}  {disp!r}")
        return 0
    if a.gen or a.run:
        gen_header(lits, out)
    if a.expand or a.run:
        expand(a.src, res, backup=not a.no_backup)
    if not (a.gen or a.expand or a.run):
        print("[xref] 未指定动作（--scan/--gen/--expand/--run/--selftest）")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

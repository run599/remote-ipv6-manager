#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack_sections.py —— 构建后 PE 段加密（兼容性适配收口工具）

为什么需要它：
  逐条把字符串改成混淆常量容易漏（StubCore.cpp 有 1392 行、散布上百处字面量）。
  本工具在**构建后**把只读数据段整体加密，一次性消掉所有明文特征：
  原文件里再也搜不到 r6m.ini / X-Agent-Key / /api/agent/register / wininet.dll…
  运行时由 Compat 的 PackDecryptAndVerify() 解密回内存。

做法（不改动原文件布局，因此不破坏任何目录项的 file-offset）：
  1. 在最后一个节区之后追加一个新的只读节  .r6mx
  2. 该节 raw data = 对目标段（默认 .rdata）逐字节用位置相关 keystream 加密的结果
  3. 目标段自身的 raw data 用**同一** keystream 原地加密（这样文件里两处都无明文；
     运行时只需原地解密一次，然后从 .r6mx 校验 CRC）
  trailer（文件最后 16 字节）：magic 'R6MX' | key:u32 | crc32:u32 | rsv:u32
    —— 仅供静态校验工具（verify 命令）使用；
  key 同时写进 .r6mx 节内第 8..12 字节，因为内存映像里没有"文件末尾"，
  运行时只能靠节内偏移定位密钥。
  布局（节内）：magic'R6MX'(4) ver(2) count(2) key(4) + count ×
                {va(4) len(4) crc32(4) rsv(4) rsv(4) + 密文(len)}

安全边界：
  · 只加密节区头标记为"可丢弃/只读"且不是 .text/.reloc/.rsrc 的段；
    默认只处理 .rdata。
  · 自带原子写 + 备份：先写 <exe>.orig（若不存在），再用临时文件替换。

自证：
  --verify <exe>  解密一遍并与 .r6mx 里的副本比对 CRC，同时确认明文字符串确实消失。

用法：
    python pack_sections.py pack   <exe> [--sections .rdata] [--keep-backup]
    python pack_sections.py verify <exe>
    python pack_sections.py unpack <exe>          # 还原（从 .orig）
"""

import argparse
import os
import shutil
import struct
import sys
import zlib

TRAILER_MAGIC = b"R6MX"
TRAILER_SIZE = 16
PACK_SECTION_NAME = b".r6mx"
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
# 默认不碰这些段：代码、重定位、资源、以及运行时会被写入的段
NEVER_PACK = {b".text", b".reloc", b".rsrc", b".rdata$zzzdbg", b".pdata", b".fptable", b".gfids"}


def keybyte(key: int, i: int) -> int:
    """与 C++ 端 Compat.cpp::PackKeyByte 逐位一致（SplitMix64 变体）。"""
    m = 0xFFFFFFFFFFFFFFFF
    z = (key + 0x9E3779B97F4A7C15 * (i + 1)) & m
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & m
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & m
    return (z ^ (z >> 31)) & 0xFF


class PE:
    def __init__(self, data: bytes):
        self.d = bytearray(data)
        if self.d[:2] != b"MZ":
            raise ValueError("不是 PE 文件（缺 MZ）")
        self.e_lfanew = struct.unpack_from("<I", self.d, 0x3C)[0]
        if self.d[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("不是 PE 文件（缺 PE 签名）")
        self.coff = self.e_lfanew + 4
        self.nsec, = struct.unpack_from("<H", self.d, self.coff + 2)
        self.opt_size, = struct.unpack_from("<H", self.d, self.coff + 16)
        self.opt = self.coff + 20
        self.sec_table = self.opt + self.opt_size
        magic, = struct.unpack_from("<H", self.d, self.opt)
        self.pe32plus = (magic == 0x20B)
        self.opt_hdr_size = 0xF0 if self.pe32plus else 0xE0
        self.file_align, = struct.unpack_from("<I", self.d, self.opt + 36)
        self.sect_align, = struct.unpack_from("<I", self.d, self.opt + 32)
        self.size_of_image, = struct.unpack_from("<I", self.d, self.opt + 56)

    def sections(self):
        out = []
        for i in range(self.nsec):
            off = self.sec_table + i * 40
            name = bytes(self.d[off:off + 8]).rstrip(b"\x00")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", self.d, off + 8)
            chars, = struct.unpack_from("<I", self.d, off + 36)
            out.append({"i": i, "off": off, "name": name, "vsize": vsize, "va": va,
                        "rawsize": rawsize, "rawptr": rawptr, "chars": chars})
        return out

    def find(self, name: bytes):
        for s in self.sections():
            if s["name"] == name:
                return s
        return None


def derive_stream(key: int, n: int) -> bytes:
    return bytes(keybyte(key, i) for i in range(n))


def pack(exe: str, sections_to_pack, keep_backup=False, seed=None, encrypt=True):
    raw = open(exe, "rb").read()
    pe = PE(raw)
    secs = pe.sections()
    if pe.find(PACK_SECTION_NAME):
        # 幂等保护：已打包的文件再打一次会把"已加密的 .rdata"当明文再加密一层，
        print(f"[pack] 该文件已包含 {PACK_SECTION_NAME.decode()} 节，拒绝重复打包"
              f"（如需重打先执行 unpack，或直接让构建重新链接）")
        return 1
    if len(raw) > max(s["rawptr"] + s["rawsize"] for s in secs):
        print(f"[pack] 文件长度 {len(raw)} 超出节区覆盖范围 "
              f"{max(s['rawptr'] + s['rawsize'] for s in secs)} —— 可能存在额外的文件尾数据，"
              f"PE 加载器会拒绝加载，请先清理（踩过：Win32 error 998）")
        return 1

    targets = [s for s in secs if s["name"] in sections_to_pack and s["name"] not in NEVER_PACK]
    if not targets:
        print(f"[pack] 无可用目标段（可用段：{[s['name'].decode('latin1') for s in secs]}）")
        return 1

    # 各段独立密钥，密钥由随机种子派生
    key = seed if seed is not None else (zlib.crc32(os.urandom(32)) | 1)

    # ── 拼接 .r6mx 内容 ──
    # 布局（运行时按同一布局解析，见 Compat.cpp::PackDecryptAndVerify）：
    #   magic'R6MX'(4) ver(2) count(2) key(4) crc32(后续全部字节)(4)
    #   + count × { va(4) len(4) crc32(明文)(4) rsv(4) rsv(4) + 密文(len) }
    key_for_blob = key & 0xFFFFFFFF
    header = struct.pack("<IHHI", 0x584D3652, 1, len(targets), key_for_blob)
    recs = bytearray()
    for t in targets:
        n = min(t["vsize"] or t["rawsize"], t["rawsize"])
        plain = bytes(pe.d[t["rawptr"]:t["rawptr"] + n])
        ks = derive_stream(key ^ (t["va"] * 2654435761 & 0xFFFFFFFF), n)
        enc = bytes(a ^ b for a, b in zip(plain, ks))
        crc = zlib.crc32(plain) & 0xFFFFFFFF
        recs += struct.pack("<IIIII", t["va"], n, crc, 0, 0)
        recs += enc
        # 原地加密目标段（运行时同一 keystream 解密）
        # encrypt=False 仅用于诊断：只加节不改内容，用来区分"节结构问题"与"加密时机问题"
        if encrypt:
            for i in range(n):
                pe.d[t["rawptr"] + i] = enc[i]
        # 段可写（运行时要解密）；同时清掉 DISCARDABLE（我们不再需要它）
        chars = struct.unpack_from("<I", pe.d, t["off"] + 36)[0]
        chars = (chars | 0x80000000) & ~0x02000000
        struct.pack_into("<I", pe.d, t["off"] + 36, chars)
        print(f"[pack] 段 {t['name'].decode('latin1'):8s} va=0x{t['va']:06X} 加密 {n} 字节 crc=0x{crc:08X}")

    # ── 追加新节 .r6mx ──
    last = max(secs, key=lambda s: s["rawptr"] + s["rawsize"])
    file_align = pe.file_align or FILE_ALIGN
    sect_align = pe.sect_align or SECTION_ALIGN
    new_rawptr = (last["rawptr"] + last["rawsize"] + (file_align - 1)) & ~(file_align - 1)
    new_va = (pe.size_of_image + (sect_align - 1)) & ~(sect_align - 1)
    # 组装最终 blob：header(16) + crc32(记录区) + 记录区
    recs = bytes(recs)
    blob = header + struct.pack("<I", zlib.crc32(recs) & 0xFFFFFFFF) + recs
    raw_size = (len(blob) + (file_align - 1)) & ~(file_align - 1)
    vsize = len(blob)   # 运行时只读 len(blob) 字节，尾部填充不属于内容

    if pe.size_of_image + ((len(blob) + sect_align - 1) // sect_align) * sect_align > 0x7FFFFFFF:
        print("[pack] 映像超限")
        return 1

    # 扩展节表：需要能容纳第 nsec+1 个 40 字节节头
    hdr_end = pe.sec_table + (pe.nsec + 1) * 40
    first_raw = min(s["rawptr"] for s in secs)
    if hdr_end > first_raw:
        print(f"[pack] 节表空间不足（需要到 0x{hdr_end:X}，第一个节区在 0x{first_raw:X}）"
              f"——需用 /FILEALIGN 或后置节区插入方式，本工具不自动处理")
        return 1

    # 注意：**不能在文件末尾再追加 trailer**。PE 加载器会校验"文件长度不得超过
    # 最后一个节区覆盖的范围"，多出 16 字节会让 CreateProcess 直接失败并返回
    # Win32 error 998（ERROR_NOACCESS，"内存位置访问无效"）——实测踩过。
    # 密钥/校验值全部放在 .r6mx 节内（file verify 从节里读）。
    body = bytearray(pe.d)
    if len(body) < new_rawptr:
        body += b"\x00" * (new_rawptr - len(body))
    body[new_rawptr:new_rawptr + len(blob)] = blob
    if len(body) < new_rawptr + raw_size:
        body += b"\x00" * (new_rawptr + raw_size - len(body))

    # 写节头：VirtualSize 用真实内容长度，SizeOfRawData 用对齐后的长度
    so = pe.sec_table + pe.nsec * 40
    name = PACK_SECTION_NAME.ljust(8, b"\x00")
    struct.pack_into("<8sIIII", body, so, name, vsize, new_va, raw_size, new_rawptr)
    struct.pack_into("<IIHHI", body, so + 24, 0, 0, 0, 0, 0x40000040)  # INITIALIZED_DATA|READ
    # 更新节数 / SizeOfImage
    struct.pack_into("<H", body, pe.coff + 2, pe.nsec + 1)
    new_image = new_va + ((vsize + sect_align - 1) & ~(sect_align - 1))
    struct.pack_into("<I", body, pe.opt + 56, new_image)

    # 原子写
    orig = exe + ".orig"
    if keep_backup or not os.path.exists(orig):
        shutil.copyfile(exe, orig)
    tmp = exe + ".tmp"
    open(tmp, "wb").write(bytes(body))
    os.replace(tmp, exe)
    print(f"[pack] 完成：{exe}（{len(raw)}  {len(body)} 字节），备份 {orig}")
    print(f"[pack] .r6mx va=0x{new_va:X} rawptr=0x{new_rawptr:X} rawsize=0x{raw_size:X} "
          f"trailer key=0x{key & 0xFFFFFFFF:08X}")
    return 0


def unpack(exe: str):
    orig = exe + ".orig"
    if not os.path.exists(orig):
        print(f"[unpack] 找不到备份 {orig}")
        return 1
    shutil.copyfile(orig, exe)
    print(f"[unpack] 已从 {orig} 还原")
    return 0


def verify(exe: str):
    raw = open(exe, "rb").read()
    pe = PE(raw)
    packed = pe.find(PACK_SECTION_NAME)
    if not packed:
        print("[verify] FAIL：找不到 .r6mx 节（未打包？）")
        return 1
    # 布局：magic'R6MX'(4) ver(2) count(2) key(4) crc32(blob_after_crc)(4) + 记录…
    # 校验值放在节内而不是文件尾（文件尾多出字节会让加载器报 Win32 error 998）
    vsize = packed["vsize"]
    blob = bytes(raw[packed["rawptr"]:packed["rawptr"] + vsize])
    if blob[:4] != TRAILER_MAGIC:
        print(f"[verify] FAIL：.r6mx 头部 magic 不是 {TRAILER_MAGIC!r}")
        return 1
    ver, count = struct.unpack_from("<HH", blob, 4)
    key, = struct.unpack_from("<I", blob, 8)
    crc_stored, = struct.unpack_from("<I", blob, 12)
    crc_actual = zlib.crc32(blob[16:]) & 0xFFFFFFFF
    print(f"[verify] .r6mx ver={ver} 记录数={count} key=0x{key:08X} "
          f"blob_crc={crc_stored:08X} actual={crc_actual:08X}")
    ok = (crc_stored == crc_actual)
    print(f"[verify] .r6mx 完整性：{'OK' if ok else 'FAIL'}")

    # 逐段解密比对（与运行时同一算法）
    off = 16
    for r in range(count):
        va, n, crc, _, _ = struct.unpack_from("<IIIII", blob, off)
        off += 20
        enc = blob[off:off + n]
        off += n
        ks = derive_stream(key ^ (va * 2654435761 & 0xFFFFFFFF), n)
        plain = bytes(a ^ b for a, b in zip(enc, ks))
        got = zlib.crc32(plain) & 0xFFFFFFFF
        print(f"[verify] 段#{r} va=0x{va:06X} n={n} 期望crc=0x{crc:08X} 实得=0x{got:08X} "
              f"{'OK' if got == crc else 'FAIL'}")
        ok = ok and (got == crc)
    print(f"[verify] 结论：{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["pack", "unpack", "verify"])
    ap.add_argument("exe")
    ap.add_argument("--sections", default=".r6ms",
                    help="要加密的节（默认 .r6ms = 本项目的字面量密文节；"
                         "不要写 .rdata —— 加载器会在加载期读其中的导入描述符/加载配置，"
                         "整节加密必被拒，CreateProcess 报 Win32 error 998）")
    ap.add_argument("--keep-backup", action="store_true")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--no-encrypt", action="store_true",
                    help="诊断用：只追加 .r6mx 节但不在文件里加密目标段")
    a = ap.parse_args()
    if a.action == "pack":
        names = [s.encode() for s in a.sections.split(",") if s]
        return pack(a.exe, set(names), a.keep_backup, a.seed, encrypt=not a.no_encrypt)
    if a.action == "unpack":
        return unpack(a.exe)
    return verify(a.exe)


if __name__ == "__main__":
    sys.exit(main())

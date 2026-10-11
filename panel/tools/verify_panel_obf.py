#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_panel_obf.py —— 面板（Qt GUI）兼容性适配判据实测

面板的威胁模型与客户端/服务端都不同，判据也不同：
  · 它是 GUI 程序，运行在操作者自己的机器上  不做与自身场景无关的兼容性处理
  · 会被本机 EDR 扫、被取证者 strings  需要"标识串不进二进制 + 有正常元数据"
所以这里查三类：
  A. 标识串：产品名、控制台字样、自定义协议头/cookie 名不得以明文出现
  B. 元数据：必须带版本信息（三无 exe 是加分项可疑特征）
  C. 调试痕迹：不得残留源码路径与调试符号段

用法：
    python verify_panel_obf.py <panel.exe>
退出码：0 全部通过；1 有未通过项
"""
import argparse
import os
import re
import struct
import subprocess
import sys

# A. 不应以明文出现的标识串（UTF-8 与 UTF-16LE 两种编码都要查：
#    Qt 内部大量使用 QString/UTF-16，只查 UTF-8 会漏）
BANNED = [
    "RMM Panel",
    "远程管理控制台",
    "X-Agent-Key",
    "X-Agent-HWID",
    "c2session",
    "r6m-server",
    "RemoteIPv6Manager",
    "RMMPanel",          # 资源路径 qrc:/RMMPanel/... 与 QML 模块名
]
# C. 调试痕迹：源码路径前缀（构建机用户名会随之泄漏）
PATH_HINTS = [b"panel\\src\\", b"panel/src/", b"E:\\", b"C:\\Users\\"]


def scan(exe):
    d = open(exe, "rb").read()
    print(f"══ 面板兼容性适配判据：{exe}（{len(d)} 字节）══")
    fails = []

    print("── A. 标识串（UTF-8 / UTF-16LE 双编码）──")
    for s in BANNED:
        n8 = d.count(s.encode("utf-8"))
        n16 = d.count(s.encode("utf-16-le"))
        ok = (n8 == 0 and n16 == 0)
        if not ok:
            fails.append(s)
        print(f"  [{'PASS' if ok else 'FAIL'}] {s:22s} UTF-8 {n8}  UTF-16 {n16}")

    print("── B. 版本信息（三无 exe 是加分项可疑特征）──")
    ver = {}
    try:
        ps = ("$v=(Get-Item '" + exe + "').VersionInfo; "
              "Write-Output ($v.CompanyName + '|' + $v.FileDescription + '|' + "
              "$v.FileVersion + '|' + $v.ProductName)")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        line = (r.stdout or "").strip()
        keys = ["CompanyName", "FileDescription", "FileVersion", "ProductName"]
        if line:
            ver = dict(zip(keys, line.split("|")))
    except FileNotFoundError:
        print("  [SKIP] 无 powershell")
    missing = [k for k in ("CompanyName", "FileDescription", "FileVersion", "ProductName")
               if not ver.get(k)]
    if missing:
        fails.append("version-info")
    print(f"  [{'PASS' if not missing else 'FAIL'}] 版本信息"
          + (f"  缺 {missing}" if missing else "  " + "; ".join(f"{k}={v}" for k, v in ver.items())))

    print("── C. 调试痕迹 ──")
    leak = []
    for h in PATH_HINTS:
        n = d.count(h)
        if n:
            leak.append((h.decode("latin1"), n))
    if leak:
        fails.append("path-leak")
    print(f"  [{'PASS' if not leak else 'FAIL'}] 源码/构建路径残留"
          + (f"  {leak}" if leak else "  0 命中"))
    # 调试符号节（MinGW 常见 .debug_*；-s 剥掉后应消失）
    dbg = re.findall(rb"\.debug_(?:info|line|abbrev|str)", d)
    if dbg:
        fails.append("debug-sections")
    print(f"  [{'PASS' if not dbg else 'FAIL'}] 调试符号节名 {len(dbg)} 处")

    print(f"══ 结论：{'全部判据通过' if not fails else '存在未通过判据 ' + str(fails)} ══")
    return 0 if not fails else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    a = ap.parse_args()
    if not os.path.isfile(a.exe):
        print("文件不存在:", a.exe)
        return 1
    return scan(a.exe)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_version.py —— 构建后回读版本信息（防静默失效）

为什么需要它：
  版本资源这类"构建期写入"的东西极容易**静默失效** —— 实测踩到三层：
    ① rc.exe 缺 /I 报 RC1015，但 CMake 的 POST_BUILD 不失败  产出空 .res
    ② .res 没启用 RC 语言  只当 order-only 依赖，不进链接命令行
    ③ CMake 的 LANGUAGES RC 若不显式处理，可能与自定义 .res 路径不一致
  这三层都不会让构建报错，只是 exe 里没有版本信息。所以链接后必须**回读**。

判据：CompanyName / FileDescription / FileVersion / ProductName 四项都要非空。
失败时退出码 1（会让构建失败 —— 这是有意的：这件事必须可见）。

用法：python check_version.py <exe>
"""
import subprocess
import sys

REQUIRED = ["CompanyName", "FileDescription", "FileVersion", "ProductName"]


def main():
    if len(sys.argv) < 2:
        print("[check_version] 用法: check_version.py <exe>")
        return 1
    exe = sys.argv[1]
    ps = ("$v=(Get-Item '" + exe + "').VersionInfo; "
          "Write-Output ($v.CompanyName + '|' + $v.FileDescription + '|' + "
          "$v.FileVersion + '|' + $v.ProductName + '|' + $v.OriginalFilename)")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        print("[check_version] 找不到 powershell，跳过检查")
        return 0
    line = (r.stdout or "").strip()
    parts = line.split("|")
    vals = dict(zip(REQUIRED + ["OriginalFilename"], parts)) if line else {}
    missing = [k for k in REQUIRED if not vals.get(k)]
    if missing:
        print(f"[check_version] FAIL：版本信息缺失 {missing}（原始输出 {line!r}）")
        print("   排查顺序：rc.exe 是否带 /I；project() 是否 LANGUAGES CXX RC；"
              ".res 是否进了链接命令行（看 build.ninja 的 LINK 行）")
        return 1
    print("[check_version] OK：" + " / ".join(f"{k}={vals[k]}" for k in REQUIRED))
    return 0


if __name__ == "__main__":
    sys.exit(main())

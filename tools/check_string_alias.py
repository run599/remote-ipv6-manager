# -*- coding: utf-8 -*-
"""
守卫：检查是否有语句超出 Decode 环形缓冲的容量。

背景（2026-10-07 实测）：
  generated_strings.h 的 Decode() 返回内部缓冲的地址。原实现只有**一格**
  static thread_local char buf[512]，于是同一表达式里调用两次就互相覆盖 ——
  两个操作数指向同一块内存，后执行的那次说了算。这不是求值顺序问题，是纯别名。
  实测踩到两个后果：
    · std::string u = PREFIX + id + SUFFIX（两端都是 R6M_STR_ 宏）
       拼出 "/api/plugins/get?name=x/api/plugins/get?name="  服务端 404
       404 响应体被当 plugin.json 写盘  插件缺 command  不下 .py
       工具映射 0 条（表现为"同步成功但一个工具都没有"）
    · IntegrityCheck 的 CriticalApi 表用花括号初始化，name/module 两个指针同址
       日志打出 "kernel32.dll@kernel32.dll"（应为 "CreateProcessW@KERNEL32.DLL"）

现状：Decode 已改为 4 格环形缓冲，2~3 连调用安全。本脚本守的是**容量边界**：
  同一语句里出现 >= RING 次调用时，环会被绕回、重新别名，必须拆语句或加大环。
  这类错误没有编译告警、没有运行时报错，只有机械检查才抓得住。

用法: python tools/check_string_alias.py [--ring 4]
退出码: 0 = 无超限；1 = 发现超限
"""
import argparse
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

MACRO = re.compile(r"\bR6M_STR_[0-9A-F]{16}\b")


def main() -> int:
    ap = argparse.ArgumentParser(description="Decode 环形缓冲容量守卫")
    ap.add_argument("--ring", type=int, default=4, help="Decode 的环形缓冲格数（默认 4）")
    ap.add_argument("--src", default=None, help="源码目录（默认 client/src）")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    src = a.src or os.path.join(os.path.dirname(here), "client", "src")
    if not os.path.isdir(src):
        print("[alias] 找不到源码目录: %s" % src)
        return 1

    # 环的实际格数以后端头文件为准，避免脚本与实现漂移
    hdr = os.path.join(src, "generated_strings.h")
    ring = a.ring
    if os.path.isfile(hdr):
        t = open(hdr, encoding="utf-8", errors="replace").read()
        m = re.search(r"bufs\[(\d+)\]\[", t)
        if m:
            ring = int(m.group(1))
            print("[alias] 从头文件读到环形缓冲格数 = %d" % ring)

    # 第二类隐患：把 Decode() 的返回值**长期持有**（存进指针变量 / 结构体指针成员 /
    # static 变量）。环形缓冲只保证"连续 N 次调用互不干扰"，不保证跨语句有效 ——
    # 任何后续 Decode() 都会复用环里的格子，被持有的指针就指向了别人的字符串。
    # 实测事故（2026-10-07）：IntegrityCheck 的关键 API 表存 const char*，
    # 表建好后被 HTTP 的字段名字符串覆盖，完整性报告里冒出
    # HTTP@clear_integrity、request_id@X-Agent-HWID 这类"API 名"。
    # 判据：持有方必须是 std::string（赋值即拷贝）或显式 strdup/自己拷进缓冲区。
    HOLD = re.compile(r"\b(?:const\s+)?char\s*\*\s*\w+\s*=\s*R6M_STR_|"
                      r"\bstatic\s+(?:const\s+)?char\s*\*\s*\w+\s*=\s*R6M_STR_")
    held = []

    over, two = [], []
    for root, _d, fs in os.walk(src):
        for f in fs:
            if not f.endswith((".cpp", ".h", ".inc")) or f == "generated_strings.h":
                continue
            path = os.path.join(root, f)
            raw = open(path, encoding="utf-8", errors="replace").read()
            # 以 ; { } 为界切语句：够用，覆盖宏调用所在表达式
            for m in re.finditer(r"[^;{}]*", raw):
                n = len(MACRO.findall(m.group(0)))
                if n >= 2:
                    line = raw[:m.start()].count("\n") + 1
                    rel = os.path.relpath(path, src)
                    rec = (rel, line, n, " ".join(m.group(0).split())[:120])
                    (over if n >= ring else two).append(rec)

    # 扫长期持有
    for root, _d, fs in os.walk(src):
        for f in fs:
            if not f.endswith((".cpp", ".h", ".inc")) or f == "generated_strings.h":
                continue
            path = os.path.join(root, f)
            for i, l in enumerate(open(path, encoding="utf-8", errors="replace").read().split("\n"), 1):
                if HOLD.search(l):
                    held.append((os.path.relpath(path, src), i, l.strip()[:110]))

    print("[alias] 同语句 2~%d 连调用（环内安全）: %d 处" % (ring - 1, len(two)))
    print("[alias] 把 Decode 结果长期存进指针变量（必须改 std::string）: %d 处" % len(held))
    for rel, line, s in held:
        print("   %s:%d  %s" % (rel, line, s))
    print("[alias] 同语句 >= %d 连调用（会绕回别名，必须修）: %d 处" % (ring, len(over)))
    for rel, line, n, s in over:
        print("   %s:%d  (%d 次)  %s" % (rel, line, n, s))
    if over or held:
        if over:
            print("\n[alias] FAIL：这些语句里的 Decode 调用超过了环形缓冲格数，"
                  "拆开语句或加大格数。")
        if held:
            print("\n[alias] FAIL：这些地方长期持有 Decode 返回的指针，"
                  "必须改成 std::string（赋值即拷贝）或自己拷进缓冲区。")
        return 1
    print("[alias] PASS：无语句超出环形缓冲容量")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Process List MCP Server — 进程管理
通过 stdio JSON-RPC 2.0 与 Stub 通信
改进：健壮解析、搜索过滤、排序、内存显示
"""
import sys, json, subprocess, os, ctypes, ctypes.wintypes, re as _re

def log(msg):
    print(f"[process_list] {msg}", file=sys.stderr, flush=True)

def decode_output(data):
    try:
        return data.decode("utf-8")
    except:
        try:
            return data.decode("cp936")
        except:
            return data.decode("latin1")

def parse_tasklist():
    """解析 tasklist CSV 输出，返回进程列表"""
    result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, timeout=10)
    stdout = decode_output(result.stdout)
    lines = stdout.strip().split("\n")
    procs = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split('","')
        if len(parts) >= 5:
            name = parts[0].strip('"')
            pid = parts[1].strip('"')
            session = parts[2].strip('"')
            session_num = parts[3].strip('"')
            mem_str = parts[4].strip('"')
            # 解析内存字符串 "12,345 K" → 12345
            mem_kb = 0
            try:
                mem_clean = mem_str.replace(",", "").replace(" K", "").replace(" M", "").replace(" G", "")
                mem_kb = int(mem_clean)
                if " M" in mem_str:
                    mem_kb *= 1024
                elif " G" in mem_str:
                    mem_kb *= 1024 * 1024
            except:
                pass
            procs.append({
                "name": name,
                "pid": int(pid) if pid.isdigit() else pid,
                "session": session,
                "mem_kb": mem_kb,
                "mem_display": mem_str
            })
    return procs

# ── 参数校验：pid 必须是整数，name 必须是裸进程名 ──────────────
def as_pid(v):
    """PID 必须是整数。原实现把 pid 原样拼进 shell 命令，构成命令注入。"""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if n <= 0 or n > 0xFFFFFFFF:
        return None
    return n


_IMAGE_RE = _re.compile(r'^[A-Za-z0-9._\- ]{1,260}$')

def as_image_name(v):
    """进程名白名单：只允许裸文件名，禁止引号/路径分隔符/通配符/命令元字符。"""
    if not isinstance(v, str) or not v.strip():
        return None
    name = v.strip()
    if not _IMAGE_RE.match(name):
        return None
    if name.upper() in {"CON", "PRN", "AUX", "NUL"}:
        return None
    return name


# ── 进程详情：纯 ctypes 快照（不再依赖已弃用的 wmic）──────────
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.wintypes.WCHAR * 260),
    ]

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("PageFaultCount", ctypes.wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
_k32.CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
_k32.Process32FirstW.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_k32.Process32NextW.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_k32.OpenProcess.restype = ctypes.wintypes.HANDLE
_k32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
_k32.QueryFullProcessImageNameW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                            ctypes.wintypes.LPWSTR, ctypes.POINTER(ctypes.wintypes.DWORD)]
_k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
_k32.K32GetProcessMemoryInfo.argtypes = [ctypes.wintypes.HANDLE,
                                        ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                                        ctypes.wintypes.DWORD]
INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value


def snapshot_info(pid):
    """父进程/线程数/名称来自工具帮助快照，镜像路径来自 OpenProcess+QueryFullProcessImageNameW。"""
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise OSError("CreateToolhelp32Snapshot 失败: %d" % ctypes.get_last_error())
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        found = None
        ok = _k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.th32ProcessID == pid:
                found = (entry.szExeFile, entry.th32ParentProcessID, entry.cntThreads)
                break
            ok = _k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _k32.CloseHandle(snap)

    if not found:
        return None

    name, ppid, threads = found
    info = {"Name": name, "ProcessId": pid, "ParentProcessId": ppid, "ThreadCount": threads}

    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if h:
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = ctypes.wintypes.DWORD(len(buf))
            if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                info["ExecutablePath"] = buf.value
            mem = PROCESS_MEMORY_COUNTERS()
            mem.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if _k32.K32GetProcessMemoryInfo(h, ctypes.byref(mem), mem.cb):
                info["WorkingSetSize"] = int(mem.WorkingSetSize)
                info["mem_kb"] = int(mem.WorkingSetSize) // 1024
        finally:
            _k32.CloseHandle(h)
    else:
        # 受保护进程（系统/杀软）拿不到句柄：明确标注而不是静默给空值
        info["note"] = "无法打开进程（权限不足或受保护进程），仅返回快照字段"
    return info


def handle_request(req):
    method = req.get("method", "")
    params = req.get("params", {})

    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "list_processes",
                    "description": "列出所有进程（可搜索、排序）",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "search": {
                                "type": "string",
                                "description": "按名称搜索（模糊匹配）"
                            },
                            "sort_by": {
                                "type": "string",
                                "description": "排序字段：name/pid/mem",
                                "default": "mem"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "最多返回条数（默认100）",
                                "default": 100
                            }
                        }
                    }
                },
                {
                    "name": "kill_process",
                    "description": "结束指定进程（按 PID 或名称）",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pid": {
                                "type": "integer",
                                "description": "进程ID"
                            },
                            "name": {
                                "type": "string",
                                "description": "进程名称（如 notepad.exe）"
                            }
                        }
                    }
                },
                {
                    "name": "process_info",
                    "description": "获取单个进程详细信息",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pid": {"type": "integer", "description": "进程ID"}
                        },
                        "required": ["pid"]
                    }
                }
            ]
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name == "list_processes":
            try:
                procs = parse_tasklist()
                # 搜索过滤
                search = arguments.get("search", "")
                if search:
                    search_lower = search.lower()
                    procs = [p for p in procs if search_lower in p["name"].lower()]
                # 排序
                sort_by = arguments.get("sort_by", "mem")
                if sort_by == "mem":
                    procs.sort(key=lambda x: x["mem_kb"], reverse=True)
                elif sort_by == "pid":
                    procs.sort(key=lambda x: x["pid"])
                elif sort_by == "name":
                    procs.sort(key=lambda x: x["name"].lower())
                # 限制
                try:
                    limit = int(arguments.get("limit", 100))
                except (TypeError, ValueError):
                    limit = 100
                limit = max(1, min(5000, limit))
                procs = procs[:limit]
                return {"content": [{"type": "text", "text": json.dumps(procs, ensure_ascii=False, indent=2)}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"获取进程列表失败: {e}"}]}

        elif tool_name == "kill_process":
            pid_raw = arguments.get("pid")
            name_raw = arguments.get("name")
            argv = None
            if pid_raw is not None and str(pid_raw) != "":
                pid = as_pid(pid_raw)
                if pid is None:
                    return {"content": [{"type": "text", "text": "pid 必须是正整数"}]}
                log(f"结束进程 PID={pid}")
                # 参数数组 + shell=False：pid 已强制为整数，不存在拼接注入
                argv = ["taskkill", "/PID", str(pid), "/F"]
            elif name_raw:
                name = as_image_name(name_raw)
                if name is None:
                    return {"content": [{"type": "text", "text": "进程名非法（只允许裸文件名，如 notepad.exe）"}]}
                log(f"结束进程 NAME={name}")
                argv = ["taskkill", "/IM", name, "/F"]
            else:
                return {"content": [{"type": "text", "text": "需要提供 pid 或 name 参数"}]}
            try:
                result = subprocess.run(argv, capture_output=True, timeout=10)
                stdout = decode_output(result.stdout)
                stderr = decode_output(result.stderr)
                output = stdout or stderr or "操作完成"
                return {"content": [{"type": "text", "text": output.strip()}]}
            except subprocess.TimeoutExpired:
                return {"content": [{"type": "text", "text": "taskkill 超时"}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"结束进程失败: {e}"}]}

        elif tool_name == "process_info":
            pid = as_pid(arguments.get("pid"))
            if pid is None:
                return {"content": [{"type": "text", "text": "pid 必须是正整数"}]}
            try:
                info = snapshot_info(pid)
                if info is None:
                    return {"content": [{"type": "text", "text": f"未找到 PID={pid} 的进程"}]}
                # 说明：CommandLine 需要读目标进程 PEB，属越权读取，本插件不提供。
                return {"content": [{"type": "text", "text": json.dumps(info, ensure_ascii=False, indent=2)}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"获取进程信息失败: {e}"}]}

        return {"content": [{"type": "text", "text": f"未知工具: {tool_name}"}]}

    return {"error": f"unknown method: {method}"}


def _send(obj):
    # stdout 是 JSON-RPC 通道：这里只允许出现单个 JSON（每行一个消息）
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def main():
    log("process_list MCP server 启动")
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            _send({"jsonrpc": "2.0", "id": None,
                   "error": {"code": -32700, "message": "parse error: %s" % e}})
            continue

        rid = req.get("id")

        # 优雅退出：先回执再退出，客户端不需要再 TerminateProcess
        if req.get("method") == "shutdown":
            if rid is not None:
                _send({"jsonrpc": "2.0", "id": rid, "result": {"ok": True, "bye": True}})
            log("收到 shutdown，正常退出")
            return

        err_obj = None
        try:
            payload = handle_request(req)
        except Exception as e:
            payload = None
            err_obj = {"code": -32603, "message": "%s: %s" % (type(e).__name__, e)}

        if rid is None:
            # JSON-RPC 通知：执行但不回应（原实现会回一条无 id 的消息，污染通道）
            continue

        if payload is None:
            _send({"jsonrpc": "2.0", "id": rid, "error": err_obj})
        elif isinstance(payload, dict) and set(payload.keys()) == {"error"}:
            _send({"jsonrpc": "2.0", "id": rid,
                   "error": {"code": -32601, "message": str(payload["error"])}})
        else:
            # 关键词：工具结果必须包在 result 里，否则标准 MCP 客户端会解析失败
            _send({"jsonrpc": "2.0", "id": rid, "result": payload})


if __name__ == "__main__":
    main()

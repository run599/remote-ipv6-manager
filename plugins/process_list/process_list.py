#!/usr/bin/env python3
"""
Process List MCP Server — 进程管理
通过 stdio JSON-RPC 2.0 与 Stub 通信
改进：健壮解析、搜索过滤、排序、内存显示
"""
import sys, json, subprocess, os

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
    result = subprocess.run(
        "tasklist /FO CSV /NH",
        shell=True, capture_output=True, timeout=10
    )
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
                limit = arguments.get("limit", 100)
                procs = procs[:limit]
                return {"content": [{"type": "text", "text": json.dumps(procs, ensure_ascii=False, indent=2)}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"获取进程列表失败: {e}"}]}

        elif tool_name == "kill_process":
            pid = arguments.get("pid")
            name = arguments.get("name")
            if pid:
                log(f"结束进程 PID={pid}")
                cmd = f"taskkill /PID {pid} /F"
            elif name:
                log(f"结束进程 NAME={name}")
                cmd = f'taskkill /IM "{name}" /F'
            else:
                return {"content": [{"type": "text", "text": "需要提供 pid 或 name 参数"}]}
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                stdout = decode_output(result.stdout)
                stderr = decode_output(result.stderr)
                output = stdout or stderr or "操作完成"
                return {"content": [{"type": "text", "text": output.strip()}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"结束进程失败: {e}"}]}

        elif tool_name == "process_info":
            pid = arguments.get("pid", 0)
            try:
                # 用 wmic 获取详细信息
                result = subprocess.run(
                    f'wmic process where ProcessId={pid} get Name,ProcessId,CommandLine,ExecutablePath,ParentProcessId,WorkingSetSize /FORMAT:LIST',
                    shell=True, capture_output=True, timeout=10
                )
                stdout = decode_output(result.stdout)
                if not stdout.strip():
                    return {"content": [{"type": "text", "text": f"未找到 PID={pid} 的进程"}]}
                # 解析 LIST 格式
                info = {}
                for line in stdout.split("\n"):
                    line = line.strip()
                    if "=" in line:
                        key, _, val = line.partition("=")
                        info[key.strip()] = val.strip()
                return {"content": [{"type": "text", "text": json.dumps(info, ensure_ascii=False, indent=2)}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"获取进程信息失败: {e}"}]}

        return {"content": [{"type": "text", "text": f"未知工具: {tool_name}"}]}

    return {"error": f"unknown method: {method}"}


def main():
    log("process_list MCP server 启动")
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            resp["jsonrpc"] = "2.0"
            resp["id"] = req.get("id")
            print(json.dumps(resp, ensure_ascii=False), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"jsonrpc": "2.0", "error": "invalid json"}), flush=True)
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "error": str(e)}), flush=True)


if __name__ == "__main__":
    main()

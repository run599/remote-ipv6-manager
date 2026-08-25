#!/usr/bin/env python3
"""
Shell Exec MCP Server — 执行系统命令
通过 stdio JSON-RPC 2.0 与 Stub 通信
改进：编码处理、输出截断、错误处理
"""
import sys, json, subprocess, os, locale

def log(msg):
    print(f"[shell_exec] {msg}", file=sys.stderr, flush=True)

MAX_OUTPUT = 50000  # 最大输出字符数

def decode_output(data):
    """尝试多种编码解码，处理中文乱码"""
    if not data:
        return ""
    # 先试 utf-8
    try:
        return data.decode("utf-8")
    except:
        pass
    # 试系统默认编码（中文 Windows 通常是 gbk/cp936）
    try:
        return data.decode(locale.getpreferredencoding(False))
    except:
        pass
    # 试 cp936
    try:
        return data.decode("cp936")
    except:
        pass
    # 最后 latin1（不会失败）
    return data.decode("latin1")

def truncate(text, max_len=MAX_OUTPUT):
    """截断过长输出"""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return text[:half] + f"\n\n... [截断 {len(text) - max_len} 字符] ...\n\n" + text[-half:]

def handle_request(req):
    method = req.get("method", "")
    params = req.get("params", {})
    req_id = req.get("id")

    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "execute",
                    "description": "执行系统命令并返回输出",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "要执行的命令"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "超时秒数（默认30）",
                                "default": 30
                            },
                            "cwd": {
                                "type": "string",
                                "description": "工作目录（默认用户主目录）"
                            }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "powershell",
                    "description": "执行 PowerShell 命令（支持复杂脚本）",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "PowerShell 命令或脚本"
                            }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "cmd",
                    "description": "执行 CMD 命令（通过 cmd.exe /c）",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "CMD 命令"
                            }
                        },
                        "required": ["command"]
                    }
                }
            ]
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        cwd = arguments.get("cwd") or os.environ.get("USERPROFILE", "C:\\")

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            timeout = arguments.get("timeout", 30)
            log(f"执行: {cmd}")
            try:
                # 用 cmd.exe /c 执行，支持管道、重定向等
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, timeout=timeout, cwd=cwd
                )
                stdout = decode_output(result.stdout)
                stderr = decode_output(result.stderr)
                output = stdout
                if stderr:
                    output += "\n[stderr] " + stderr
                if not output.strip():
                    output = "(命令执行完成，无输出)"
                return {"content": [{"type": "text", "text": truncate(output)}]}
            except subprocess.TimeoutExpired:
                return {"content": [{"type": "text", "text": f"命令超时（{timeout}秒）"}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"执行失败: {e}"}]}

        elif tool_name == "powershell":
            cmd = arguments.get("command", "")
            log(f"PowerShell: {cmd}")
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                     "-Command", cmd],
                    capture_output=True, timeout=60, cwd=cwd
                )
                stdout = decode_output(result.stdout)
                stderr = decode_output(result.stderr)
                output = stdout
                if stderr:
                    output += "\n[stderr] " + stderr
                if not output.strip():
                    output = "(PowerShell 执行完成，无输出)"
                return {"content": [{"type": "text", "text": truncate(output)}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"PowerShell 执行失败: {e}"}]}

        elif tool_name == "cmd":
            cmd = arguments.get("command", "")
            log(f"CMD: {cmd}")
            try:
                result = subprocess.run(
                    ["cmd.exe", "/c", cmd],
                    capture_output=True, timeout=60, cwd=cwd
                )
                stdout = decode_output(result.stdout)
                stderr = decode_output(result.stderr)
                output = stdout
                if stderr:
                    output += "\n[stderr] " + stderr
                if not output.strip():
                    output = "(CMD 执行完成，无输出)"
                return {"content": [{"type": "text", "text": truncate(output)}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"CMD 执行失败: {e}"}]}

        return {"content": [{"type": "text", "text": f"未知工具: {tool_name}"}]}

    return {"error": f"unknown method: {method}"}


def main():
    log("shell_exec MCP server 启动")
    # 嵌入式 Python 默认 GBK，强制 stdout 用 UTF-8（MCP JSON-RPC 必须 UTF-8）
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

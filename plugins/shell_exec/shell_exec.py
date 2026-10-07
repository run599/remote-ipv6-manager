#!/usr/bin/env python3
"""
Shell Exec MCP Server — 执行系统命令
通过 stdio JSON-RPC 2.0 与 Stub 通信
改进：编码处理、输出截断、错误处理
"""
import sys, json, subprocess, os, locale, threading

def log(msg):
    print(f"[shell_exec] {msg}", file=sys.stderr, flush=True)

MAX_OUTPUT = 50000          # 返回给调用方的最大字符数
MAX_OUTPUT_BYTES = 1 << 20  # 单次命令抓取的最大字节数（防止 GB 级输出把 agent 内存打爆）
MAX_TIMEOUT = 600           # timeout 上限（秒）


def as_int(v, default, lo, hi):
    """把外部传入的参数安全转成 int 并夹在 [lo, hi]；非法值回落到 default。"""
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


def run_capped(argv, timeout, cwd=None, max_bytes=MAX_OUTPUT_BYTES, use_shell=False):
    """执行命令并限制抓取字节数。

    关键点：超限后仍在读但不累积（否则子进程会因管道写满而永久阻塞），
    只保留前 max_bytes 字节并标记 truncated。
    """
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=cwd, shell=use_shell)
    out, err = bytearray(), bytearray()
    truncated = [False, False]

    def drain(pipe, buf, idx):
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    break
                room = max_bytes - len(buf)
                if room > 0:
                    buf.extend(chunk[:room])
                if len(chunk) > room:
                    truncated[idx] = True
        except Exception:
            pass

    t1 = threading.Thread(target=drain, args=(proc.stdout, out, 0), daemon=True)
    t2 = threading.Thread(target=drain, args=(proc.stderr, err, 1), daemon=True)
    t1.start(); t2.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        t1.join(2); t2.join(2)
        raise
    t1.join(5); t2.join(5)
    return bytes(out), bytes(err), (truncated[0] or truncated[1])


def resolve_cwd(arguments):
    """校验工作目录：不存在/不是目录时明确报错，而不是让 subprocess 抛一个含糊异常。"""
    cwd = arguments.get("cwd")
    if not cwd:
        return os.environ.get("USERPROFILE", "C:\\"), None
    if not os.path.isdir(cwd):
        return None, f"工作目录不存在或不是目录: {cwd}"
    return cwd, None

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
            if not isinstance(cmd, str) or not cmd.strip():
                return {"content": [{"type": "text", "text": "缺少 command 参数"}]}
            timeout = as_int(arguments.get("timeout", 30), 30, 1, MAX_TIMEOUT)
            cwd, cwd_err = resolve_cwd(arguments)
            if cwd_err:
                return {"content": [{"type": "text", "text": cwd_err}]}
            log(f"执行: {cmd}")
            try:
                # execute 的语义就是 shell 命令（管道/重定向），因此这里保留 shell=True；
                # 注入面由"谁能下发命令"控制，不由参数拼接控制。
                raw_out, raw_err, clipped = run_capped(cmd, timeout, cwd=cwd, use_shell=True)
                output = decode_output(raw_out)
                stderr = decode_output(raw_err)
                if stderr:
                    output += "\n[stderr] " + stderr
                if clipped:
                    output += f"\n[输出超过 {MAX_OUTPUT_BYTES // 1024}KB，已在采集侧截断]"
                if not output.strip():
                    output = "(命令执行完成，无输出)"
                return {"content": [{"type": "text", "text": truncate(output)}]}
            except subprocess.TimeoutExpired:
                return {"content": [{"type": "text", "text": f"命令超时（{timeout}秒）"}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"执行失败: {e}"}]}

        elif tool_name == "powershell":
            cmd = arguments.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return {"content": [{"type": "text", "text": "缺少 command 参数"}]}
            cwd, cwd_err = resolve_cwd(arguments)
            if cwd_err:
                return {"content": [{"type": "text", "text": cwd_err}]}
            log(f"PowerShell: {cmd}")
            try:
                raw_out, raw_err, clipped = run_capped(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                    60, cwd=cwd)
                output = decode_output(raw_out)
                stderr = decode_output(raw_err)
                if stderr:
                    output += "\n[stderr] " + stderr
                if clipped:
                    output += f"\n[输出超过 {MAX_OUTPUT_BYTES // 1024}KB，已在采集侧截断]"
                if not output.strip():
                    output = "(PowerShell 执行完成，无输出)"
                return {"content": [{"type": "text", "text": truncate(output)}]}
            except subprocess.TimeoutExpired:
                return {"content": [{"type": "text", "text": "PowerShell 超时（60秒）"}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"PowerShell 执行失败: {e}"}]}

        elif tool_name == "cmd":
            cmd = arguments.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return {"content": [{"type": "text", "text": "缺少 command 参数"}]}
            cwd, cwd_err = resolve_cwd(arguments)
            if cwd_err:
                return {"content": [{"type": "text", "text": cwd_err}]}
            log(f"CMD: {cmd}")
            try:
                raw_out, raw_err, clipped = run_capped(["cmd.exe", "/c", cmd], 60, cwd=cwd)
                output = decode_output(raw_out)
                stderr = decode_output(raw_err)
                if stderr:
                    output += "\n[stderr] " + stderr
                if clipped:
                    output += f"\n[输出超过 {MAX_OUTPUT_BYTES // 1024}KB，已在采集侧截断]"
                if not output.strip():
                    output = "(CMD 执行完成，无输出)"
                return {"content": [{"type": "text", "text": truncate(output)}]}
            except subprocess.TimeoutExpired:
                return {"content": [{"type": "text", "text": "CMD 超时（60秒）"}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"CMD 执行失败: {e}"}]}

        return {"content": [{"type": "text", "text": f"未知工具: {tool_name}"}]}

    return {"error": f"unknown method: {method}"}


def _send(obj):
    # stdout 是 JSON-RPC 通道：这里只允许出现单个 JSON（每行一个消息）
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def main():
    log("shell_exec MCP server 启动")
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

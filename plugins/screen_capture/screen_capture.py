#!/usr/bin/env python3
"""
Screen Capture MCP Server — 截屏
通过 stdio JSON-RPC 2.0 与 Stub 通信
纯 Windows API (ctypes)，BMP 输出 + 降分辨率
"""
import sys, json, ctypes, ctypes.wintypes, base64, struct, os

# ═══════════════════════════════════════════════
# Windows API
# ═══════════════════════════════════════════════
user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

MAX_B64_CHARS = 32 * 1024 * 1024  # base64 上限（约 24MB 原始 BMP），防止单次响应撑爆管道

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
BI_RGB = 0


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", ctypes.wintypes.DWORD),
        ("biWidth", ctypes.wintypes.LONG),
        ("biHeight", ctypes.wintypes.LONG),
        ("biPlanes", ctypes.wintypes.WORD),
        ("biBitCount", ctypes.wintypes.WORD),
        ("biCompression", ctypes.wintypes.DWORD),
        ("biSizeImage", ctypes.wintypes.DWORD),
        ("biXPelsPerMeter", ctypes.wintypes.LONG),
        ("biYPelsPerMeter", ctypes.wintypes.LONG),
        ("biClrUsed", ctypes.wintypes.DWORD),
        ("biClrImportant", ctypes.wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", ctypes.wintypes.DWORD * 3),
    ]


def log(msg):
    print(f"[screen_capture] {msg}", file=sys.stderr, flush=True)


def capture_screen(scale=1):
    """
    截取主屏幕
    scale: 1=原始, 2=半屏, 4=四分之一
    返回 (bytes, format_name)
    """
    screen_w = user32.GetSystemMetrics(0)
    screen_h = user32.GetSystemMetrics(1)
    dst_w = max(1, screen_w // scale)
    dst_h = max(1, screen_h // scale)

    hdc_screen = user32.GetDC(0)
    hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)

    if scale > 1:
        # 先截全屏
        hbitmap_full = gdi32.CreateCompatibleBitmap(hdc_screen, screen_w, screen_h)
        gdi32.SelectObject(hdc_mem, hbitmap_full)
        gdi32.BitBlt(hdc_mem, 0, 0, screen_w, screen_h, hdc_screen, 0, 0, SRCCOPY)
        # 缩放到目标
        hdc_mem2 = gdi32.CreateCompatibleDC(hdc_screen)
        hbitmap = gdi32.CreateCompatibleBitmap(hdc_screen, dst_w, dst_h)
        gdi32.SelectObject(hdc_mem2, hbitmap)
        gdi32.SetStretchBltMode(hdc_mem2, 4)  # HALFTONE
        gdi32.StretchBlt(hdc_mem2, 0, 0, dst_w, dst_h, hdc_mem, 0, 0, screen_w, screen_h, SRCCOPY)
        gdi32.DeleteObject(hbitmap_full)
        gdi32.DeleteDC(hdc_mem)
        hdc_mem = hdc_mem2
    else:
        hbitmap = gdi32.CreateCompatibleBitmap(hdc_screen, screen_w, screen_h)
        gdi32.SelectObject(hdc_mem, hbitmap)
        gdi32.BitBlt(hdc_mem, 0, 0, screen_w, screen_h, hdc_screen, 0, 0, SRCCOPY)

    # 提取像素
    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = dst_w
    bmi.bmiHeader.biHeight = -dst_h  # top-down
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = BI_RGB

    buf_size = dst_w * dst_h * 4
    buf = ctypes.create_string_buffer(buf_size)
    gdi32.GetDIBits(hdc_mem, hbitmap, 0, dst_h, buf, ctypes.byref(bmi), DIB_RGB_COLORS)

    gdi32.DeleteObject(hbitmap)
    gdi32.DeleteDC(hdc_mem)
    user32.ReleaseDC(0, hdc_screen)

    pixel_data = buf.raw[:dst_w * dst_h * 4]

    # 构造 BMP 文件
    row_size = dst_w * 4
    bmp_file_size = 54 + row_size * dst_h
    bmp = bytearray(bmp_file_size)
    # 文件头
    bmp[0:2] = b'BM'
    struct.pack_into('<I', bmp, 2, bmp_file_size)
    struct.pack_into('<I', bmp, 10, 54)
    # DIB 头
    struct.pack_into('<I', bmp, 14, 40)
    struct.pack_into('<i', bmp, 18, dst_w)
    struct.pack_into('<i', bmp, 22, dst_h)
    struct.pack_into('<H', bmp, 26, 1)
    struct.pack_into('<H', bmp, 28, 32)
    struct.pack_into('<I', bmp, 30, 0)
    struct.pack_into('<I', bmp, 34, row_size * dst_h)
    # 像素
    bmp[54:54 + row_size * dst_h] = pixel_data

    return bytes(bmp), "bmp"


def handle_request(req):
    method = req.get("method", "")
    params = req.get("params", {})

    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "screenshot",
                    "description": "截取主屏幕，返回 base64 编码 BMP 图片",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scale": {
                                "type": "integer",
                                "description": "缩放：1=原始(8MB), 2=半屏(2MB), 4=四分之一(500KB)",
                                "default": 2
                            }
                        }
                    }
                },
                {
                    "name": "screen_info",
                    "description": "获取屏幕分辨率",
                    "inputSchema": {"type": "object", "properties": {}}
                }
            ]
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name == "screenshot":
            try:
                scale = int(arguments.get("scale", 2))
            except (TypeError, ValueError):
                scale = 2
            if scale not in (1, 2, 4):
                return {"content": [{"type": "text", "text": "scale 只支持 1/2/4"}]}
            try:
                img_data, fmt = capture_screen(scale=scale)
                b64 = base64.b64encode(img_data).decode("ascii")
                if len(b64) > MAX_B64_CHARS:
                    return {"content": [{"type": "text", "text": (
                        f"截屏过大（{len(b64) // 1024}KB base64，上限 {MAX_B64_CHARS // 1024}KB）："
                        f"请改用 scale=4 重试")}]}
                log(f"截屏: {len(img_data)//1024}KB {fmt} → {len(b64)//1024}KB b64 (scale={scale})")
                # 同时给出结构化字段（字段优先，避免调用方对文本做子串搜索）与兼容标记
                return {
                    "content": [{"type": "text", "text": f"[BMP base64]{b64}"}],
                    "image_base64": b64,
                    "image_format": fmt,
                    "bytes": len(img_data),
                }
            except Exception as e:
                return {"content": [{"type": "text", "text": f"截屏失败: {e}"}]}

        elif tool_name == "screen_info":
            try:
                w = user32.GetSystemMetrics(0)
                h = user32.GetSystemMetrics(1)
                return {"content": [{"type": "text", "text": json.dumps({
                    "width": w, "height": h,
                    "scale_2": f"{w//2}x{h//2}",
                    "scale_4": f"{w//4}x{h//4}"
                })}]}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"失败: {e}"}]}

        return {"content": [{"type": "text", "text": f"未知工具: {tool_name}"}]}

    return {"error": f"unknown method: {method}"}


def _send(obj):
    # stdout 是 JSON-RPC 通道：这里只允许出现单个 JSON（每行一个消息）
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def main():
    log("screen_capture MCP server 启动")
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

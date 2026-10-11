#!/usr/bin/env python3
"""
Screen Capture MCP Server — 截屏
通过 stdio JSON-RPC 2.0 与 Stub 通信
纯 Windows API (ctypes)，BMP 输出 + 降分辨率
"""
import sys, json, ctypes, ctypes.wintypes, base64, struct, os, zlib
import tempfile

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


# ═══════════════════════════════════════════════
# PNG 编码（纯 Python + zlib，不依赖 PIL）
#
# 内嵌 Python 是官方的 embed 包，没有 PIL；但 zlib 是标准库自带的（实测 1.3.1），
# 足够手写 PNG：PNG = 签名 + IHDR + IDAT(zlib) + IEND，每块带 CRC32。
# ═══════════════════════════════════════════════

def _png_chunk(tag, data):
    return (struct.pack('>I', len(data)) + tag + data
            + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF))


def encode_png(pixel_bgra, w, h, level=6):
    """32bpp BGRA 像素 -> PNG（RGB, 8bit, filter=0）。

    通道分离用步长切片而不是逐像素循环：
      pixel_bgra[2::4] 一次拿到整张图的 R 通道（C 层做），
      再按 0::3 / 1::3 / 2::3 填回交错缓冲。
    逐像素写法在 960x540 下要 51.8 万次迭代，实测会把帧率吃光。
    """
    n = w * h
    r = pixel_bgra[2::4]
    g = pixel_bgra[1::4]
    b = pixel_bgra[0::4]
    if len(r) != n or len(g) != n or len(b) != n:
        raise ValueError("像素数据长度与 %dx%d 不匹配" % (w, h))

    inter = bytearray(n * 3)
    inter[0::3] = r
    inter[1::3] = g
    inter[2::3] = b

    # 每行前置一个 filter 字节 0（None 过滤）。
    # filter=0 时行数据就是原始字节，所以除了每行头部的 0 之外没有任何变换。
    stride = w * 3
    raw = b''.join(b'\x00' + bytes(inter[y * stride:(y + 1) * stride]) for y in range(h))

    ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)  # color_type=2 (truecolor RGB)
    return (b'\x89PNG\r\n\x1a\n'
            + _png_chunk(b'IHDR', ihdr)
            + _png_chunk(b'IDAT', zlib.compress(raw, level))
            + _png_chunk(b'IEND', b''))




# ══════════════════════════════════════════════════════════════════════════════
# JPEG 编码（2026-10-10 新增）—— 治帧率的关键
# ══════════════════════════════════════════════════════════════════════════════
_gdiplus_ready = None
_jpeg_clsid = None


def _init_gdiplus():
    """惰性初始化 GDI+ 并找到 JPEG 编码器 CLSID。返回 (gdiplus, clsid) 或 None。"""
    global _gdiplus_ready, _jpeg_clsid
    if _gdiplus_ready is not None:
        return _gdiplus_ready
    try:
        gdip = ctypes.WinDLL("gdiplus.dll")

        class GdiplusStartupInput(ctypes.Structure):
            _fields_ = [("GdiplusVersion", ctypes.c_uint32),
                        ("DebugEventCallback", ctypes.c_void_p),
                        ("SuppressBackgroundThread", ctypes.c_int),
                        ("SuppressExternalCodecs", ctypes.c_int)]

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                        ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

        class ImageCodecInfo(ctypes.Structure):
            _fields_ = [("Clsid", GUID), ("FormatID", GUID), ("CodecName", ctypes.c_wchar_p),
                        ("DllName", ctypes.c_wchar_p), ("FormatDescription", ctypes.c_wchar_p),
                        ("FilenameExtension", ctypes.c_wchar_p), ("MimeType", ctypes.c_wchar_p),
                        ("Flags", ctypes.c_uint32), ("Version", ctypes.c_uint32),
                        ("SigCount", ctypes.c_uint32), ("SigSize", ctypes.c_uint32),
                        ("SigPattern", ctypes.c_void_p), ("SigMask", ctypes.c_void_p)]

        token = ctypes.c_void_p()
        si = GdiplusStartupInput(1, None, 0, 0)
        if gdip.GdiplusStartup(ctypes.byref(token), ctypes.byref(si), None) != 0:
            raise RuntimeError("GdiplusStartup 失败")

        num = ctypes.c_uint32(0)
        size = ctypes.c_uint32(0)
        gdip.GdipGetImageEncodersSize(ctypes.byref(num), ctypes.byref(size))
        if size.value == 0:
            raise RuntimeError("枚举编码器得到 0 字节")
        buf = ctypes.create_string_buffer(size.value)
        gdip.GdipGetImageEncoders(num, size, buf)
        arr = ctypes.cast(buf, ctypes.POINTER(ImageCodecInfo))
        clsid = None
        for i in range(num.value):
            if arr[i].MimeType and arr[i].MimeType.lower() == "image/jpeg":
                clsid = arr[i].Clsid
                break
        if clsid is None:
            raise RuntimeError("系统没有 image/jpeg 编码器")
        _gdiplus_ready = (gdip, clsid)
        log("GDI+ 就绪，JPEG 编码器已找到 ")
        return _gdiplus_ready
    except Exception as e:
        log("GDI+ 初始化失败，JPEG 不可用（将回退 PNG）: %r" % (e,))
        _gdiplus_ready = False
        return False


def encode_jpeg(pixel_bgra, w, h, quality=60):
    """用 GDI+ 把 BGRA 像素编成 JPEG。失败返回 None（调用方回退 PNG ）。"""
    st = _init_gdiplus()
    if not st:
        return None
    gdip, clsid = st
    try:
        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32),
                        ("biHeight", ctypes.c_int32), ("biPlanes", ctypes.c_uint16),
                        ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                        ("biSizeImage", ctypes.c_uint32), ("biXPelsPerMeter", ctypes.c_int32),
                        ("biYPelsPerMeter", ctypes.c_int32), ("biClrUsed", ctypes.c_uint32),
                        ("biClrImportant", ctypes.c_uint32)]

        class BITMAPINFO(ctypes.Structure):
            _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", ctypes.c_uint32 * 3)]

        bi = BITMAPINFO()
        bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bi.bmiHeader.biWidth = w
        bi.bmiHeader.biHeight = -h          # 顶向下 （与我们的像素顺序一致）
        bi.bmiHeader.biPlanes = 1
        bi.bmiHeader.biBitCount = 32
        bi.bmiHeader.biCompression = 0      # BI_RGB

        gdi32 = ctypes.WinDLL("gdi32.dll")
        user32 = ctypes.WinDLL("user32.dll")
        bits = ctypes.c_void_p()
        hdc = user32.GetDC(0)
        hbmp = gdi32.CreateDIBSection(hdc, ctypes.byref(bi), 0, ctypes.byref(bits), None, 0)
        user32.ReleaseDC(0, hdc)
        if not hbmp:
            return None
        ctypes.memmove(bits, pixel_bgra, len(pixel_bgra))

        bmp = ctypes.c_void_p()
        if gdip.GdipCreateBitmapFromHBITMAP(hbmp, None, ctypes.byref(bmp)) != 0 or not bmp:
            gdi32.DeleteObject(hbmp)
            return None

        class EncoderParameter(ctypes.Structure):
            _fields_ = [("Guid", ctypes.c_ubyte * 16), ("NumberOfValues", ctypes.c_uint32),
                        ("Type", ctypes.c_uint32), ("Value", ctypes.c_void_p)]

        class EncoderParameters(ctypes.Structure):
            _fields_ = [("Count", ctypes.c_uint32), ("Parameter", EncoderParameter * 1)]

        q = ctypes.c_uint32(quality)
        params = EncoderParameters()
        params.Count = 1
        qguid = bytes([0xB5, 0xE4, 0x5B, 0x1D, 0x4A, 0xFA, 0x2D, 0x45,
                       0x9C, 0xDD, 0x5D, 0xB3, 0x51, 0x05, 0xE7, 0xEB])
        ctypes.memmove(ctypes.byref(params.Parameter[0].Guid), qguid, 16)
        params.Parameter[0].NumberOfValues = 1
        params.Parameter[0].Type = 4          # EncoderParameterValueTypeLong
        params.Parameter[0].Value = ctypes.cast(ctypes.byref(q), ctypes.c_void_p)

        tmp = os.path.join(tempfile.gettempdir(), "r6m_frame.jpg")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        rc = gdip.GdipSaveImageToFile(bmp, tmp, ctypes.byref(clsid), ctypes.byref(params))
        gdip.GdipDisposeImage(bmp)
        gdi32.DeleteObject(hbmp)
        if rc != 0:
            log("GdipSaveImageToFile rc=%d（回退 PNG）" % rc)
            return None
        with open(tmp, "rb") as f:
            data = f.read()
        try:
            os.remove(tmp)
        except Exception:
            pass
        return data if len(data) > 0 else None
    except Exception as e:
        log("encode_jpeg 异常（回退 PNG）: %r" % (e,))
        return None

def capture_screen(scale=1, fmt="bmp"):
    """
    截取主屏幕
    scale: 1=原始, 2=半屏, 4=四分之一, 8=八分之一
    fmt:   "bmp"（无损、体积大，适合单张取图）
           "png"（压缩，约 1/11 体积，适合连续监控）
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

    if fmt == "jpeg":
        jd = encode_jpeg(pixel_data, dst_w, dst_h, quality=60)
        if jd:
            return jd, "jpeg"
    if fmt == "png":
        return encode_png(pixel_data, dst_w, dst_h), "png"

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
                    "description": "截取主屏幕，返回 base64 编码图片（BMP 或 PNG）",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scale": {
                                "type": "integer",
                                "description": "缩放：1=原始, 2=半屏, 4=四分之一, 8=八分之一（配合 png 可做到几十 KB 一帧）",
                                "default": 2
                            },
                            "format": {
                                "type": "string",
                                "enum": ["bmp", "png"],
                                "description": "bmp=无损但大（单张取图）；png=压缩约 1/11（连续监控用）",
                                "default": "bmp"
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
            if scale not in (1, 2, 4, 8):
                return {"content": [{"type": "text", "text": "scale 只支持 1/2/4/8"}]}
            # 默认仍是 bmp：保持既有调用方（面板单张取图）行为不变，
            # 只有显式要 png 的（实时监控）才走压缩路径。
            fmt_req = str(arguments.get("format", "jpeg")).lower()
            if fmt_req not in ("bmp", "png", "jpeg"):
                fmt_req = "jpeg"     # 默认改 jpeg （单张截图也享受小体积 ）
            try:
                img_data, fmt = capture_screen(scale=scale, fmt=fmt_req)
                b64 = base64.b64encode(img_data).decode("ascii")
                if len(b64) > MAX_B64_CHARS:
                    return {"content": [{"type": "text", "text": (
                        f"截屏过大（{len(b64) // 1024}KB base64，上限 {MAX_B64_CHARS // 1024}KB）："
                        f"请改用 scale=4 重试")}]}
                log(f"截屏: {len(img_data)//1024}KB {fmt}  {len(b64)//1024}KB b64 (scale={scale})")
                # 同时给出结构化字段（字段优先，避免调用方对文本做子串搜索）与兼容标记
                marker = ("[JPEG base64]" if fmt == "jpeg" else
                          ("[PNG base64]" if fmt == "png" else "[BMP base64]"))
                return {
                    "content": [{"type": "text", "text": f"{marker}{b64}"}],
                    "image_base64": b64,
                    "image_format": fmt,
                    "bytes": len(img_data),
                    # 分辨率一并回传：面板显示"480x270"不必先解码整张图
                    "width": user32.GetSystemMetrics(0) // scale,
                    "height": user32.GetSystemMetrics(1) // scale,
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
                    "scale_4": f"{w//4}x{h//4}",
                    "scale_8": f"{w//8}x{h//8}"
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
            module = handle_request(req)
        except Exception as e:
            module = None
            err_obj = {"code": -32603, "message": "%s: %s" % (type(e).__name__, e)}

        if rid is None:
            # JSON-RPC 通知：执行但不回应（原实现会回一条无 id 的消息，污染通道）
            continue

        if module is None:
            _send({"jsonrpc": "2.0", "id": rid, "error": err_obj})
        elif isinstance(module, dict) and set(module.keys()) == {"error"}:
            _send({"jsonrpc": "2.0", "id": rid,
                   "error": {"code": -32601, "message": str(module["error"])}})
        else:
            # 关键词：工具结果必须包在 result 里，否则标准 MCP 客户端会解析失败
            _send({"jsonrpc": "2.0", "id": rid, "result": module})


if __name__ == "__main__":
    main()

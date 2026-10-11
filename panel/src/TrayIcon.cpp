#include "TrayIcon.h"

#include <QSettings>
#include <QCoreApplication>
#include <QDir>
#include <windows.h>
#include <shellapi.h>

// 托盘回调用的自定义消息。WM_APP 之后的区间是留给应用的，不会和系统消息冲突。
static const UINT kTrayMsg = WM_APP + 1;
static const wchar_t* kTrayClass = L"R6MTrayWnd";
static const wchar_t* kRunKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const wchar_t* kRunValue = L"R6M RMMPanel";

// WndProc 是静态的，用文件内单例把回调转回对象上。
static TrayIcon* g_self = nullptr;
static HWND g_wnd = nullptr;
static NOTIFYICONDATAW g_nid = {};

// 菜单项 id
enum { IDM_SHOW = 1001, IDM_AUTOSTART = 1002, IDM_QUIT = 1003 };

static void showMenu(HWND h) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, IDM_SHOW, L"显示主界面");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (g_self && g_self->autoStartEnabled() ? MF_CHECKED : 0),
                IDM_AUTOSTART, L"开机自动启动");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_QUIT, L"退出管理端");
    // TPM_RETURNCMD：直接拿回用户点的 id，省掉 WM_COMMAND 路由
    // （托盘菜单挂在隐藏消息窗口上，走 WM_COMMAND 还得额外记状态）
    const int cmd = (int)TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                        pt.x, pt.y, 0, h, nullptr);
    DestroyMenu(m);
    if (!g_self) return;
    switch (cmd) {
    case IDM_SHOW:
        emit g_self->showRequested();
        break;
    case IDM_AUTOSTART:
        g_self->setAutoStart(!g_self->autoStartEnabled());
        break;
    case IDM_QUIT:
        emit g_self->quitRequested();
        break;
    default:
        break;
    }
}

static LRESULT CALLBACK TrayWndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == kTrayMsg) {
        switch (LOWORD(lp)) {
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
            if (g_self) emit g_self->showRequested();
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            showMenu(h);
            return 0;
        default:
            return 0;
        }
    }
    return DefWindowProcW(h, m, wp, lp);
}

TrayIcon::TrayIcon(QObject* parent) : QObject(parent) { g_self = this; }

TrayIcon::~TrayIcon() { uninstall(); if (g_self == this) g_self = nullptr; }

bool TrayIcon::install(const QString& tooltip) {
    if (_installed) return true;
    // 隐藏的消息窗口：只用来收托盘回调，不显示
    if (!g_wnd) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = TrayWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = kTrayClass;
        RegisterClassExW(&wc);
        g_wnd = CreateWindowExW(0, kTrayClass, L"", 0, 0, 0, 0, 0,
                                HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
        if (!g_wnd) return false;
    }
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_wnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = kTrayMsg;
    // 优先用 exe 自带的图标（版本资源里那个）；没有就退回系统默认图标 ——
    // 退回而不是失败：托盘没图标会让"关窗后程序还在不在"变得完全不可见。
    g_nid.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    if (!g_nid.hIcon) g_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    const QString tip = tooltip.isEmpty() ? QStringLiteral("管理端") : tooltip;
    lstrcpynW(g_nid.szTip, (const wchar_t*)tip.utf16(), 128);
    if (!Shell_NotifyIconW(NIM_ADD, &g_nid)) return false;
    _installed = true;
    return true;
}

void TrayIcon::uninstall() {
    if (_installed) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        _installed = false;
    }
}

void TrayIcon::balloon(const QString& title, const QString& body) {
    if (!_installed) return;
    g_nid.uFlags = NIF_INFO;
    lstrcpynW(g_nid.szInfoTitle, (const wchar_t*)title.utf16(), 64);
    lstrcpynW(g_nid.szInfo, (const wchar_t*)body.utf16(), 256);
    g_nid.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    // 复位 uFlags，否则后续 NIM_MODIFY 会一直带气泡
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
}

QString TrayIcon::exePath() const {
    wchar_t buf[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    return QString::fromWCharArray(buf);
}

bool TrayIcon::autoStartEnabled() const {
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_READ, &k) != ERROR_SUCCESS) return false;
    wchar_t val[MAX_PATH * 2] = {};
    DWORD sz = sizeof(val), type = 0;
    const LONG r = RegQueryValueExW(k, kRunValue, nullptr, &type, (LPBYTE)val, &sz);
    RegCloseKey(k);
    return r == ERROR_SUCCESS && val[0] != 0;
}

bool TrayIcon::setAutoStart(bool on) {
    HKEY k = nullptr;
    // KEY_WRITE 而不是只 KEY_SET_VALUE：RegCreateKeyEx 在"键不存在需要创建"时
    // 需要创建权限；只给 KEY_SET_VALUE 会在那种情况下直接失败，
    // 表现为"自启动静默没配上"（本机就踩到了这个：函数返回 false 但没人看返回值）。
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &k, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    LONG r;
    if (on) {
        // 路径一定要带引号：装在含空格的目录时，不带引号的 Run 值会被系统
        // 按空格切成"程序 + 参数"，表现为"开机自启失败但不报错"。
        const QString quoted = QLatin1Char('"') + exePath() + QLatin1Char('"');
        const std::wstring w = quoted.toStdWString();
        r = RegSetValueExW(k, kRunValue, 0, REG_SZ, (const BYTE*)w.c_str(),
                           (DWORD)((w.size() + 1) * sizeof(wchar_t)));
    } else {
        r = RegDeleteValueW(k, kRunValue);
        if (r == ERROR_FILE_NOT_FOUND) r = ERROR_SUCCESS;
    }
    RegCloseKey(k);
    // 记住用户的选择：关过就别再自动加回来（见 ensureAutoStart）
    QSettings s(QStringLiteral("r6m"), QStringLiteral("RMMPanel"));
    s.setValue(QStringLiteral("autostart_off"), on ? 0 : 1);
    s.sync();
    return r == ERROR_SUCCESS;
}

void TrayIcon::ensureAutoStart() {
    QSettings s(QStringLiteral("r6m"), QStringLiteral("RMMPanel"));
    // 这个"记住"很关键：否则"关掉自启动"会在下次启动时被无声恢复，
    // 变成一个用户无法摆脱的行为。
    if (s.value(QStringLiteral("autostart_off"), 0).toInt() == 1) return;
    // 默认开启。每次启动都写一遍是幂等的，顺带修正"exe 被挪了位置"的陈旧路径。
    // 把结果写进 settings：静默失败过一次（注册表权限不足时返回 false 没人看），
    // 下次可以直接查 autostart_ok 定位，不用再来回猜。
    const bool ok = setAutoStart(true);
    s.setValue(QStringLiteral("autostart_ok"), ok ? 1 : 0);
    s.sync();
}

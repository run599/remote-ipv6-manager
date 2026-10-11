import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ui

// ═══════════════════════════════════════════════════════════════════════════
// main.qml —— 窗口根
//
// 导入路径注意：qml.qrc 的 prefix 是 /ui，qmldir 里 `module ui`，所以这里
// `import ui` —— 四个页签也都靠它拿到 LoginPage / MainPage / Theme 等类型。
// （历史上这个文件名与模块名对不上过一次，导致 "module RMMPanel is not installed"
//   面板启动即 return -1、双击没窗口。改前缀时务必两处一起改。）
// ═══════════════════════════════════════════════════════════════════════════

Window {
    id: root
    visible: true
    width: 1440; height: 920
    // 最小尺寸按"侧栏 268 + 工作区最小 720 + 边距"估出来，避免用户把窗口拖到
    // 把内容挤变形（分段控件在过窄时会重叠）
    minimumWidth: 1080
    minimumHeight: 680
    title: panelTitle   // 运行期由 C++ 集成（见 qml_main.cpp）
    color: Theme.bgPrimary

    property bool loggedIn: false
    property string serverUrl: ""
    property string cookie: ""

    // ── 托盘与自启动 ──
    // 关窗口 ≠ 退出：默认收进右下角继续后台跑（管理端要长期挂着看在线状态），
    // 真正退出只能从托盘菜单走。真正退出时把 reallyQuit 置真，临时授权这次关闭。
    property bool reallyQuit: false

    onClosing: function(close) {
        if (root.reallyQuit) return
        close.accepted = false
        root.hide()
        tray.balloon("仍在后台运行",
                     "管理端已收进右下角托盘，仍在监控。要完全退出请右键托盘图标选「退出管理端」。")
    }

    Connections {
        target: tray
        function onShowRequested() {
            root.show()
            root.raise()
            root.requestActivate()
        }
        function onQuitRequested() {
            root.reallyQuit = true
            Qt.quit()
        }
    }

    Component.onCompleted: {
        tray.install(panelTitle)
        // 默认开启开机自启动；用户主动关过则尊重其选择（C++ 侧记着）
        tray.ensureAutoStart()
    }

    LoginPage {
        id: loginPage
        anchors.fill: parent
        visible: !root.loggedIn
        onLoginSuccess: function(url, ck) {
            root.serverUrl = url
            root.cookie = ck
            root.loggedIn = true
            agentModel.refresh()
        }
    }

    MainPage {
        anchors.fill: parent
        visible: root.loggedIn
        serverUrl: root.serverUrl
        cookie: root.cookie
    }

    // 原来什么都不做，界面停在主界面空转：列表显示缓存的旧数据、命令全部失败，
    // 用户完全不知道是"会话过期"还是"受管端挂了"。实测症状见 ApiClient.h 的说明。
    Connections {
        target: api
    function onSessionExpired() {
        // 先**自动重登**：面板本来就用 DPAPI 存着账号口令（"记住密码"）。
        // 人看到的只是满屏 401，完全不知道该做什么（实测就是这样）。
        // 重登成功就静默恢复；失败（比如真改了密码）才回登录页并说明原因。
        if (api.savedUser().length > 0 && api.savedPass().length > 0) {
            const r = api.login(api.savedUser(), api.savedPass())
            if (r === "") {          // 空串 = 成功（ApiClient::login 的约定）
                console.log("[会话] 已用保存的凭据自动重登成功")
                return
            }
            console.log("[会话] 自动重登失败: " + r)
        }
        loginPage.statusText = " 会话已过期，且自动重登失败（请检查口令是否改过），请重新登录"
        stack.currentIndex = 0
    }
    }
}

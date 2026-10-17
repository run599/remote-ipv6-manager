import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

// ═══════════════════════════════════════════════════════════════════════════
// QueueTab —— 指令队列（2026-10-11 新增）
//
// 为什么要有这一页：以前指令发出去只有两种结局 —— 要么拿到结果，要么
// 调用方干等（面板还会因此"点什么都没反应"）。**排队中/执行中/失败**三态
//
// 数据源：GET /api/queue?hwid=<hwid>
//   counts: pending/inflight/failed   stats: sent/retry/fail
//   policy: ack_timeout / max_attempts / command_ttl / deadline
// 语义（与服务端一致）：
// ═══════════════════════════════════════════════════════════════════════════
Rectangle {
    id: queueTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    property var counts: ({ pending: 0, inflight: 0, failed: 0 })
    property var stats: ({ sent: 0, retry: 0, fail: 0 })
    property var policy: ({})
    property var desired: []
    property string dropMsg: ""
    property bool runAfterDeploy: true
    property bool runAsAdmin: false
    property bool dragHover: false
    property var pending: []
    property var inflight: []
    property var failed: []
    property string status: ""

    function refresh() {
        if (hwid === "" || serverUrl === "") { return }
        var raw = api.get("/api/queue?hwid=" + hwid)
        var o = null
        try { o = JSON.parse(raw) } catch (e) { o = null }
        if (!o || o.ok === false) { status = "读取失败：" + (raw || "").substring(0, 120); return }
        counts = o.counts || counts
        desired = o.desired || []
        stats = o.stats || stats
        policy = o.policy || {}
        pending = o.pending || []
        inflight = o.inflight || []
        failed = o.failed || []
        status = "已刷新 " + new Date().toLocaleTimeString()
    }


    function deployPaths(paths) {
        if (!queueTab.hwid || queueTab.hwid.length === 0) {
            dropMsg = " 请先在左侧「受管端」列表里点选一台机器，再投放（当前 hwid 为空）"
            return
        }
        var lines = []
        for (var i = 0; i < paths.length; i++) {
            var p = paths[i]
            var name = p.replace(/\\/g, "/").split("/").pop()
            var up = api.uploadFile(p)
            var uo = null
            try { uo = JSON.parse(up) } catch (e) { uo = null }
            if (!uo || uo.ok === false) {
                lines.push(" " + name + " 上传失败：" + (up || "").substring(0, 90))
                continue
            }
            var srvName = uo.name || uo.file || uo.saved || name
            var dep = api.post("/api/files/deploy", JSON.stringify({
                agent_hwid: queueTab.hwid,
                file_name: srvName,
                target_dir: "C:\\r6mstage\\drop",
                run: queueTab.runAfterDeploy || queueTab.runAsAdmin,
                run_mode: queueTab.runAsAdmin ? "admin" : "user",
                apply: "none"
            }))
            var do_ = null
            try { do_ = JSON.parse(dep) } catch (e) { do_ = null }
            if (do_ && do_.request_id) {
                lines.push(" " + srvName + " 已入队 " + do_.request_id.substring(0, 14)
                           + (queueTab.runAfterDeploy ? "（投放后运行）" : "（仅落盘）"))
            } else {
                lines.push(" " + srvName + " 入队失败(" + queueTab.hwid.substring(0,8) + "…)：" + (dep || "").substring(0, 90))
            }
        }
        dropMsg = lines.join("   |   ")
        refresh()
    }

    Timer {
        interval: 2000
        running: queueTab.hwid !== ""
        repeat: true
        onTriggered: queueTab.refresh()
    }
    onHwidChanged: refresh()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacingM
        spacing: Theme.spacingM

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacingS
            Text {
                text: "指令队列"
                font.pixelSize: 16; font.bold: true
                color: Theme.textPrimary; font.family: Theme.fontUI
            }
            Rectangle {
                radius: 8; color: Theme.bgSecondary; border.color: Theme.cardBorder; border.width: 1
                implicitWidth: cTxt.implicitWidth + 16; implicitHeight: 24
                Text { id: cTxt; anchors.centerIn: parent
                    text: "待执行 " + counts.pending + " · 执行中 " + counts.inflight + " · 失败 " + counts.failed
                    color: counts.failed > 0 ? Theme.red : Theme.textSecondary
                    font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI
                }
            }
            Item { Layout.fillWidth: true }
            Text {
                text: "累计投递 " + stats.sent + " · 重投 " + stats.retry + " · 失败 " + stats.fail
                color: Theme.textTertiary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI
            }
            Button {
                text: "刷新"
                implicitHeight: Theme.controlHeight
                Accessible.name: "刷新指令队列"
                onClicked: queueTab.refresh()
            }
        }

        Text {
            Layout.fillWidth: true
            text: "策略：投出后 " + (policy.ack_timeout || "-") + " 未回报即重投，最多 "
                  + (policy.max_attempts || "-") + " 次；单条截止 " + (policy.deadline || "-")
                  + "；排队上限 " + (policy.command_ttl || "-") + "（超时判失败并写出原因）"
            color: Theme.textTertiary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI
            wrapMode: Text.WordWrap
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 138
            radius: Theme.radiusL
            color: queueTab.dragHover ? Theme.bgSecondary : "transparent"
            border.color: queueTab.dragHover ? Theme.accent : Theme.cardBorder
            border.width: queueTab.dragHover ? 2 : 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.spacingS
                spacing: 4
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        text: "📥 拖文件到这里 / 选择文件 / 粘贴路径  进入投放队列（ 需先在左侧选中受管端）"
                        color: Theme.textPrimary; font.bold: true
                        font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI
                    }
                    Item { Layout.fillWidth: true }
                    Button {
                        text: "📄 选择文件…"
                        implicitHeight: Theme.controlHeight
                        Accessible.name: "选择要投放的文件"
                        onClicked: {
                            var p = api.pickOpenFile("选择要投放的文件", "所有文件 (*.*)")
                            if (p && p.length > 0) queueTab.deployPaths([p])
                        }
                    }
                    ComboBox {
                        id: runCombo
                        implicitWidth: 190; implicitHeight: Theme.controlHeight
                        model: ["投放后不运行", "投放后以当前用户运行", "投放后以管理员运行"]
                        currentIndex: queueTab.runAfterDeploy ? 1 : 0
                        Accessible.name: "投放后的执行权限"
                        onActivated: {
                            queueTab.runAfterDeploy = (currentIndex >= 1)
                            queueTab.runAsAdmin = (currentIndex === 2)
                            if (currentIndex === 2)
                                queueTab.dropMsg = "将以管理员拉起（未提升权限时弹 UAC；兼容模式下只需点同意）"
                        }
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacingS
                    TextField {
                        id: pathInput
                        Layout.fillWidth: true
                        implicitHeight: Theme.controlHeight
                        placeholderText: "或直接粘贴文件完整路径（如 C:\\\\Users\\user\\\\Desktop\\\\a.exe），回车即投放"
                        Accessible.name: "要投放的文件路径"
                        onAccepted: if (text.length > 0) queueTab.deployPaths([text])
                    }
                    Button {
                        text: "投放"
                        implicitHeight: Theme.controlHeight
                        enabled: pathInput.text.length > 0
                        Accessible.name: "按路径投放"
                        onClicked: queueTab.deployPaths([pathInput.text])
                    }
                }
                Text {
                    Layout.fillWidth: true
                    text: queueTab.dropMsg === "" ? "落到受管端 C:\\r6mstage\\drop；拖入时**边框应变蓝加粗**（若不变  是 Qt 没接住拖拽，用上面输入框即可）"
                                                  : queueTab.dropMsg
                    color: queueTab.dropMsg.indexOf("") >= 0 ? Theme.red : Theme.textTertiary
                    font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI
                    elide: Text.ElideRight
                }
            }
        }

        Text {
            Layout.fillWidth: true
            visible: queueTab.desired.length > 0
            text: {
                var s = "期望态（声明式收敛）："
                for (var i = 0; i < queueTab.desired.length; i++) {
                    var d = queueTab.desired[i]
                    s += "rev " + d.desired_rev + (d.converged ? "  已收敛" : "  待收敛(drift)")
                    if (d.pending_revert_at_ms) s += " · 有到点恢复预约"
                }
                return s
            }
            color: Theme.textSecondary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI
            wrapMode: Text.WordWrap
        }

        // ── 执行中 ──
        Text { text: "执行中（已投出，等回报）"; color: Theme.textSecondary; font.bold: true
               font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI }
        ListView {
            Layout.fillWidth: true; Layout.preferredHeight: 120
            clip: true; model: queueTab.inflight
            delegate: Rectangle {
                width: ListView.view.width; height: 26; color: "transparent"
                RowLayout { anchors.fill: parent; spacing: 8
                    Text { text: (modelData.method || "?") + "  " + (modelData.request_id || "").substring(0, 14)
                           color: Theme.textPrimary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI }
                    Item { Layout.fillWidth: true }
                    Text { text: "已投 " + Math.round((modelData.sent_ms_ago || 0) / 1000) + "s · 第 "
                                 + (modelData.attempts || 0) + " 次"
                           color: (modelData.sent_ms_ago > 60000) ? Theme.orange : Theme.textTertiary
                           font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI }
                }
            }
            Text { anchors.centerIn: parent; visible: queueTab.inflight.length === 0
                   text: "（无）"; color: Theme.textTertiary; font.pixelSize: Theme.fsTiny }
        }

        // ── 待执行 ──
        Text { text: "待执行（排队中）"; color: Theme.textSecondary; font.bold: true
               font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI }
        ListView {
            Layout.fillWidth: true; Layout.preferredHeight: 140
            clip: true; model: queueTab.pending
            delegate: Rectangle {
                width: ListView.view.width; height: 26; color: "transparent"
                RowLayout { anchors.fill: parent; spacing: 8
                    Text { text: (modelData.method || "?") + "  " + (modelData.request_id || "").substring(0, 14)
                           color: Theme.textPrimary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI }
                    Item { Layout.fillWidth: true }
                    Text { text: "排队 " + Math.round((modelData.age_ms || 0) / 1000) + "s"
                           color: Theme.textTertiary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI }
                }
            }
            Text { anchors.centerIn: parent; visible: queueTab.pending.length === 0
                   text: "（无）"; color: Theme.textTertiary; font.pixelSize: Theme.fsTiny }
        }

        // ── 失败 ──
        Text { text: "失败（含原因）"; color: Theme.red; font.bold: true
               font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI }
        ListView {
            Layout.fillWidth: true; Layout.fillHeight: true
            clip: true; model: queueTab.failed
            delegate: Rectangle {
                width: ListView.view.width; height: 44; color: "transparent"
                ColumnLayout { anchors.fill: parent; spacing: 2
                    Text { text: (modelData.request_id || "").substring(0, 22)
                           color: Theme.textPrimary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI }
                    Text { text: (modelData.result || "").replace(/\s+/g, " ").substring(0, 150)
                           color: Theme.orange; font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI
                           elide: Text.ElideRight; Layout.fillWidth: true }
                }
            }
            Text { anchors.centerIn: parent; visible: queueTab.failed.length === 0
                   text: "（无失败 ）"; color: Theme.textTertiary; font.pixelSize: Theme.fsTiny }
        }

        Text { text: queueTab.status; color: Theme.textTertiary
               font.pixelSize: Theme.fsTiny; font.family: Theme.fontUI }
    }
    DropArea {
        id: pageDrop
        anchors.fill: parent
        onEntered: function(drag) { queueTab.dragHover = true }
        onExited: function() { queueTab.dragHover = false }
        onDropped: function(drop) {
            queueTab.dragHover = false
            drop.accept()
            var paths = []
            for (var i = 0; i < drop.urls.length; i++) {
                var u = drop.urls[i].toString()
                if (u.indexOf("file:///") === 0) {
                    var p = decodeURIComponent(u.substring(8))
                    paths.push(p.split("/").join(String.fromCharCode(92)))   // 92 = 反斜杠（不用转义 ）
                }
            }
            if (paths.length === 0) { queueTab.dropMsg = " 没解析出文件路径（拖入的可能是文本/链接）"; return }
            queueTab.deployPaths(paths)
        }
    }
}

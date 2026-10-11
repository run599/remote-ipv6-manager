import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

// ═══════════════════════════════════════════════════════════════════════════
// ShellTab —— 远程终端
//
// 视觉改动：
//   · 输出区做成真正的"终端窗口"：顶部三个圆点 + 等宽字体 + 凹陷底色
//   · 输入行加 ❯ 提示符前缀，和输出里的 $ 行形成呼应
//   · 快捷命令从普通 Button 改成圆角胶囊，不再和"执行"按钮抢注意力
//
//   1) outputMirror + 那个 1x1 的 Accessible 节点 —— 命令结果靠它被外部读取
//   2) 快捷按钮的文案（Whoami / 进程 / 截屏 / IPConfig）—— 外部脚本按名字点击
//   3) execCmd / appendOutput / history 的签名与行为
// ═══════════════════════════════════════════════════════════════════════════

Rectangle {
    id: shellTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    // 命令历史
    property var history: []
    property int historyIdx: -1

    // 无障碍用：最近若干行输出（读屏与自动化据此读取命令结果）。
    // 逐行 Text 不参与无障碍树，所以在这里维护一份文本镜像。
    property string outputMirror: ""

    // 无障碍镜像节点：1x1 透明（visible:false 会被排除出无障碍树）
    Rectangle {
        width: 1; height: 1; color: "transparent"
        Accessible.role: Accessible.StaticText
        Accessible.name: shellTab.outputMirror === "" ? "(无输出)" : shellTab.outputMirror
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.spacingS

        // ── 状态行 ──
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacingS
            Rectangle {
                width: 7; height: 7; radius: 3.5
                color: hwid ? Theme.green : Theme.textTertiary
            }
            Text {
                text: hwid ? ("已连接 · " + hwid.substring(0, 12)) : "请先在左侧选择一个客户端"
                color: hwid ? Theme.textSecondary : Theme.orange
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
            }
        }

        // ── 终端窗口 ──
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.bgSunken
            radius: Theme.radiusM
            border.color: Theme.cardBorder
            border.width: 1
            clip: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                // 窗口标题栏
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 30
                    color: Theme.bgTertiary
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.spacingM
                        anchors.rightMargin: Theme.spacingM
                        spacing: 6
                        Repeater {
                            model: ["#FF5F57", "#FEBRMME", "#28C840"]
                            delegate: Rectangle {
                                width: 10; height: 10; radius: 5
                                color: modelData
                                opacity: 0.85
                            }
                        }
                        Item { Layout.fillWidth: true }
                        Text {
                            text: "远程 Shell"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                        }
                        Item { Layout.fillWidth: true }
                        Item { Layout.preferredWidth: 42; Layout.preferredHeight: 1 }
                    }
                    Rectangle {
                        anchors.bottom: parent.bottom
                        width: parent.width; height: 1
                        color: Theme.divider
                    }
                }

                ListView {
                    id: outputView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.margins: Theme.spacingM
                    clip: true
                    spacing: 3
                    model: ListModel { id: outputModel }
                    delegate: Text {
                        width: outputView.width
                        wrapMode: Text.Wrap
                        text: model.text
                        color: model.color || "#CDD6F4"
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.fsMono
                        lineHeight: 1.25
                    }
                    // currentIndex 只影响高亮/键盘导航，不会滚动视图；
                    // 正确做法是显式滚到底部（否则用户以为"命令没反应"）
                    onCountChanged: Qt.callLater(outputView.positionViewAtEnd)
                }
            }

            // 空态提示
            Text {
                anchors.centerIn: parent
                visible: outputModel.count === 0
                text: "选择客户端后，点下面的快捷命令或直接输入"
                color: Theme.textTertiary
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
            }
        }

        // ── 快捷命令胶囊 ──
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacingXS + 2

            Repeater {
                model: [
                    {label: "👤 Whoami", cmd: "whoami"},
                    {label: "📊 进程", cmd: ""},
                    {label: "📸 截屏", cmd: ""},
                    {label: "🔧 IPConfig", cmd: "ipconfig /all"}
                ]
                delegate: Rectangle {
                    Layout.preferredHeight: 28
                    Layout.preferredWidth: chipText.implicitWidth + 22
                    radius: 14
                    color: chipMouse.containsMouse ? Theme.accentSoft : Theme.bgTertiary
                    border.color: chipMouse.containsMouse ? Theme.accentLine : Theme.cardBorder
                    border.width: 1
                    Behavior on color { ColorAnimation { duration: Theme.durFast } }

                    // 无障碍：胶囊是纯 Rectangle + MouseArea，Qt 不会给它建 UIA 节点，
                    // 于是"读屏点不到"、自动化也点不到。视觉改为自绘后必须补这三个属性
                    // （实测漏掉后 UI Automation 的 InvokePattern 直接拿不到，
                    //   点 Whoami 静默失败 —— 这是改版时我自己引入的回归）。
                    Accessible.role: Accessible.Button
                    Accessible.name: modelData.label
                    Accessible.onPressAction: shellTab.triggerQuick(index)

                    Text {
                        id: chipText
                        anchors.centerIn: parent
                        text: modelData.label
                        color: chipMouse.containsMouse ? Theme.accent : Theme.textSecondary
                        font.pixelSize: Theme.fsSmall
                        font.family: Theme.fontUI
                    }
                    MouseArea {
                        id: chipMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: shellTab.triggerQuick(index)
                    }
                }
            }

            Item { Layout.fillWidth: true }
        }

        // ── 输入行 ──
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 40
            radius: Theme.radiusM
            color: Theme.bgElevated
            border.width: cmdInput.activeFocus ? 2 : 1
            border.color: cmdInput.activeFocus ? Theme.accent : Theme.cardBorder
            Behavior on border.color { ColorAnimation { duration: Theme.durFast } }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.spacingM
                anchors.rightMargin: Theme.spacingS
                spacing: Theme.spacingS

                Text {
                    text: "❯"
                    color: Theme.accent
                    font.pixelSize: Theme.fsMono + 2
                    font.bold: true
                    font.family: Theme.fontMono
                }

                TextField {
                    id: cmdInput
                    Layout.fillWidth: true
                    placeholderText: "输入命令，回车执行…"
                    placeholderTextColor: Theme.textTertiary
                    color: Theme.textPrimary
                    font.family: Theme.fontMono
                    font.pixelSize: Theme.fsMono + 1
                    background: null
                    onAccepted: shellTab.execCmd(text)
                    Keys.onUpPressed: {
                        if (history.length === 0) return
                        historyIdx = Math.min(historyIdx + 1, history.length - 1)
                        text = history[history.length - 1 - historyIdx]
                    }
                    Keys.onDownPressed: {
                        historyIdx = Math.max(historyIdx - 1, -1)
                        text = historyIdx >= 0 ? history[history.length - 1 - historyIdx] : ""
                    }
                }

                Button {
                    id: runBtn
                    text: "执行"
                    enabled: cmdInput.text.length > 0
                    Layout.preferredHeight: 28
                    Layout.preferredWidth: 64
                    background: Rectangle {
                        radius: Theme.radiusS
                        color: !runBtn.enabled ? Theme.bgTertiary
                                               : (runBtn.down ? Theme.accentPress
                                                              : (runBtn.hovered ? Theme.accentHover : Theme.accent))
                        Behavior on color { ColorAnimation { duration: Theme.durFast } }
                    }
                    contentItem: Text {
                        text: runBtn.text
                        color: runBtn.enabled ? Theme.textOnAccent : Theme.textTertiary
                        font.pixelSize: Theme.fsSmall
                        font.bold: true
                        font.family: Theme.fontUI
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    onClicked: shellTab.execCmd(cmdInput.text)
                }
            }
        }
    }

    function execCmd(cmd) {
        if (!hwid) return
        history.push(cmd)
        historyIdx = -1
        appendOutput("$ " + cmd, "#CDD6F4")
        cmdInput.text = ""
        mcp.callTool(hwid, serverUrl, cookie, "execute",
            JSON.stringify({"command": cmd, "timeout": 30}), "shell")
    }

    // 快捷命令的统一入口：鼠标点击与无障碍 onPressAction 共用一份逻辑
    // （原来动作写死在 MouseArea.onClicked 里，补无障碍时会复制成两份实现）
    function triggerQuick(index) {
        var map = [
            {cmd: "whoami"},
            {cmd: ""},
            {cmd: ""},
            {cmd: "ipconfig /all"}
        ]
        if (index < 0 || index >= map.length) return
        if (map[index].cmd) {
            execCmd(map[index].cmd)
        } else if (index === 1) {
            mcp.callTool(hwid, serverUrl, cookie, "list_processes",
                         '{"sort_by":"mem","limit":20}', "shell")
        } else if (index === 2) {
            mcp.callTool(hwid, serverUrl, cookie, "screenshot", '{"scale":4}', "shell")
        }
    }

    Connections {
        target: mcp
        function onToolResult(tool, result, source) {
            if (source !== "shell") return
            var obj = null
            try { obj = JSON.parse(result) } catch (e) { obj = null }
            if (obj === null) { appendOutput(result, "#A6E3A1"); return }
            // 按字段判错：原来只要输出里含 "error" 子串就整段标红
            // （findstr error、日志内容、字段名 error_count 都会被误判）
            if (obj.error !== undefined) {
                appendOutput("[error] " + obj.error, "#F38BA8")
                return
            }
            if (obj.content && obj.content[0] && obj.content[0].text !== undefined) {
                appendOutput(obj.content[0].text, "#A6E3A1")
            } else {
                appendOutput(JSON.stringify(obj, null, 2), "#CDD6F4")
            }
        }
    }

    function appendOutput(text, color) {
        outputModel.append({"text": text, "color": color || "#CDD6F4"})
        // 同步到无障碍镜像（保留尾部 800 字符，够验证命令结果）
        var joined = outputMirror === "" ? text : (outputMirror + "\n" + text)
        outputMirror = joined.length > 800 ? joined.slice(joined.length - 800) : joined
    }
}

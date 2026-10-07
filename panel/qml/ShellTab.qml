import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import C2Panel

Rectangle {
    id: shellTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    // 命令历史
    property var history: []
    property int historyIdx: -1

    ColumnLayout {
        anchors.fill: parent; spacing: Theme.spacingS

        // 状态栏
        RowLayout {
            Layout.fillWidth: true
            Rectangle { width: 8; height: 8; radius: 4; color: hwid ? Theme.green : Theme.textTertiary }
            Text { text: hwid ? "已连接: " + hwid.substring(0,12) : "请先选择客户端"; font.pixelSize: 12; color: Theme.textSecondary }
        }

        // 输出区（深色终端风格）
        Rectangle {
            Layout.fillWidth: true; Layout.fillHeight: true
            color: "#1E1E2E"; radius: Theme.radiusS
            ListView {
                id: outputView
                anchors.fill: parent; anchors.margins: 12
                clip: true; spacing: 2
                model: ListModel { id: outputModel }
                delegate: Text {
                    width: outputView.width; wrapMode: Text.Wrap
                    text: model.text; color: model.color || "#CDD6F4"
                    font.family: "SF Mono, Cascadia Code, Consolas, monospace"
                    font.pixelSize: 13
                }
                // currentIndex 只影响高亮/键盘导航，不会滚动视图；
                // 正确做法是显式滚到底部（否则用户以为"命令没反应"）
                onCountChanged: Qt.callLater(outputView.positionViewAtEnd)
            }
        }

        // 快捷按钮
        RowLayout {
            Layout.fillWidth: true; spacing: 4
            Repeater {
                model: [
                    {label: "👤 Whoami", cmd: "whoami"},
                    {label: "📊 进程", cmd: ""},
                    {label: "📸 截屏", cmd: ""},
                    {label: "🔧 IPConfig", cmd: "ipconfig /all"}
                ]
                delegate: Button {
                    text: modelData.label
                    font.pixelSize: 11
                    onClicked: {
                        if (modelData.cmd) shellTab.execCmd(modelData.cmd)
                        else if (index === 1) mcp.callTool(hwid, serverUrl, cookie, "list_processes", '{"sort_by":"mem","limit":20}', "shell")
                        else if (index === 2) mcp.callTool(hwid, serverUrl, cookie, "screenshot", '{"scale":2}', "shell")
                    }
                }
            }
        }

        // 输入行
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            TextField {
                id: cmdInput; Layout.fillWidth: true; placeholderText: "输入命令..."
                font.family: "SF Mono, Cascadia Code, Consolas, monospace"
                font.pixelSize: 13
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
                text: "执行"; enabled: cmdInput.text.length > 0
                onClicked: shellTab.execCmd(cmdInput.text)
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
    }
}

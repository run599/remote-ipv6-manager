import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: mcpTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    property var toolNames: ["execute", "powershell", "list_processes", "screenshot", "screen_info",
                             "list_directory", "read_file", "kill_process"]

    ColumnLayout {
        anchors.fill: parent; anchors.margins: Theme.spacingM; spacing: Theme.spacingM

        Text { text: "MCP 工具调用"; font.pixelSize: 16; font.bold: true; color: Theme.textPrimary }

        // 工具选择
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            ComboBox {
                id: toolCombo; Layout.preferredWidth: 250
                model: mcpTab.toolNames
                font.pixelSize: 13
            }
            Button { text: "刷新工具列表"; onClicked: mcp.getToolList(hwid, serverUrl, cookie) }
        }

        // 参数输入
        ColumnLayout {
            Layout.fillWidth: true; spacing: 4
            Text { text: "参数 (JSON)"; font.pixelSize: 12; font.bold: true; color: Theme.textSecondary }
            TextField {
                id: paramInput
                Layout.fillWidth: true; Layout.preferredHeight: 80
                placeholderText: '{"command":"whoami"}'
                font.family: "Consolas, monospace"; font.pixelSize: 13
                wrapMode: TextEdit.Wrap
            }
        }

        // 执行按钮
        Button {
            text: mcp.busy ? "执行中..." : "▶ 执行"
            enabled: !mcp.busy && hwid
            Layout.preferredWidth: 160; Layout.preferredHeight: 36
            onClicked: {
                mcp.callTool(hwid, serverUrl, cookie,
                    toolCombo.currentText, paramInput.text)
            }
        }

        // 结果区
        ColumnLayout {
            Layout.fillWidth: true; Layout.fillHeight: true; spacing: 4
            Text { text: "结果"; font.pixelSize: 12; font.bold: true; color: Theme.textSecondary }
            Rectangle {
                Layout.fillWidth: true; Layout.fillHeight: true
                color: "#1E1E2E"; radius: Theme.radiusS
                ScrollView {
                    anchors.fill: parent; anchors.margins: 8
                    TextArea {
                        id: resultArea; readOnly: true; wrapMode: TextEdit.Wrap
                        color: "#CDD6F4"; font.family: "Consolas, monospace"; font.pixelSize: 13
                        background: null
                    }
                }
            }
        }
    }

    Connections {
        target: mcp
        function onToolResult(result) {
            resultArea.text = result
        }
    }
}

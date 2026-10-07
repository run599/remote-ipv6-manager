import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import C2Panel

Rectangle {
    id: mcpTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    ColumnLayout {
        anchors.fill: parent; anchors.margins: Theme.spacingM; spacing: Theme.spacingM

        Text { text: "MCP 工具调用"; font.pixelSize: 16; font.bold: true; color: Theme.textPrimary }

        // 工具选择
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            ComboBox {
                id: toolCombo; Layout.preferredWidth: 250
                model: mcp.toolList
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
                    toolCombo.currentText, paramInput.text, "mcp")
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
        function onToolResult(tool, result, source) {
            if (source !== "mcp") return      // 其它页签的调用不再串到这里
            if (tool === "tools/list") {
                resultArea.text = "已刷新工具列表（共 " + mcp.toolList.length + " 个）"
                return
            }
            // 解析后再展示：不要直接显示原始 JSON 文本，也不要靠子串判错
            try {
                var obj = JSON.parse(result)
                if (obj.error !== undefined) {
                    resultArea.text = "[error] " + obj.error
                } else if (obj.content && obj.content[0] && obj.content[0].text !== undefined) {
                    resultArea.text = obj.content[0].text
                } else {
                    resultArea.text = JSON.stringify(obj, null, 2)
                }
            } catch (e) {
                resultArea.text = result
            }
        }
    }
}

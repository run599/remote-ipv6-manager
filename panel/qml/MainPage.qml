import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import C2Panel

Item {
    id: mainPage
    property string serverUrl: ""
    property string cookie: ""
    property string selectedHwid: ""

    // 自动刷新
    Timer {
        // 未登录时 serverUrl 为空，每 5 秒发一次必然失败的请求并清空列表
        interval: 5000; running: mainPage.serverUrl !== ""; repeat: true
        onTriggered: agentModel.refresh()
    }

    // ═══ 顶栏 ═══
    Rectangle {
        id: topBar
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: 52
        color: Qt.rgba(1, 1, 1, 0.85)
        Rectangle { width: parent.width; height: 1; anchors.bottom: parent.bottom; color: Qt.rgba(0,0,0,0.08) }

        RowLayout {
            anchors.fill: parent; anchors.leftMargin: 24; anchors.rightMargin: 24
            spacing: Theme.spacingM

            // Logo
            Rectangle { width: 32; height: 32; radius: 16
                gradient: Gradient { GradientStop { position: 0.0; color: Theme.accent }
                                     GradientStop { position: 1.0; color: "#5856D6" } }
                Text { anchors.centerIn: parent; text: "⌘"; color: "white"; font.pixelSize: 16; font.bold: true }
            }

            Text { text: "C2 Panel"; font.pixelSize: 15; font.bold: true; color: Theme.textPrimary }

            // 在线数
            Rectangle { radius: 10; width: onlineLabel.width + 16; height: 22
                color: Qt.rgba(52/255, 199/255, 89/255, 0.12)
                Text { id: onlineLabel; anchors.centerIn: parent; text: "● " + agentModel.onlineCount + " Online"; color: Theme.green; font.pixelSize: 11; font.bold: true }
            }

            Item { Layout.fillWidth: true }

            // 服务器地址
            Rectangle { radius: 10; width: urlLabel.width + 16; height: 22
                color: Qt.rgba(0,0,0,0.04)
                Text { id: urlLabel; anchors.centerIn: parent; text: mainPage.serverUrl; color: Theme.textTertiary; font.pixelSize: 11 }
            }
        }
    }

    // ═══ 内容区 ═══
    RowLayout {
        anchors.top: topBar.bottom; anchors.bottom: footer.top
        anchors.left: parent.left; anchors.right: parent.right
        anchors.margins: Theme.spacingL
        spacing: Theme.spacingM

        // 左侧 Agent 列表
        AgentList {
            Layout.preferredWidth: 260; Layout.fillHeight: true
            onAgentSelected: function(hwid) { mainPage.selectedHwid = hwid }
        }

        // 右侧面板
        Rectangle {
            Layout.fillWidth: true; Layout.fillHeight: true
            color: Theme.bgSecondary; radius: Theme.radiusM

            ColumnLayout {
                anchors.fill: parent; anchors.margins: Theme.spacingM; spacing: 0

                // 分段控制
                Rectangle {
                    Layout.fillWidth: true; height: 36
                    color: Qt.rgba(0,0,0,0.04); radius: Theme.radiusS
                    RowLayout {
                        anchors.fill: parent; anchors.margins: 3; spacing: 2

                        Repeater {
                            model: ["🖥 终端", "🔧 工具", "📁 文件", "⚡ 截屏"]
                            delegate: Rectangle {
                                Layout.fillWidth: true; Layout.fillHeight: true
                                radius: Theme.radiusS
                                property bool isActive: tabBar.currentIndex === index
                                color: isActive ? Theme.bgSecondary : "transparent"
                                border.color: isActive ? Qt.rgba(0,0,0,0.08) : "transparent"

                                Text {
                                    anchors.centerIn: parent
                                    text: modelData; font.pixelSize: 13; font.bold: isActive
                                    color: isActive ? Theme.textPrimary : Theme.textSecondary
                                }
                                MouseArea { onClicked: tabBar.currentIndex = index }
                            }
                        }
                    }
                }

                Item { Layout.preferredHeight: Theme.spacingS }

                // 标签页内容
                StackLayout {
                    id: tabBar
                    Layout.fillWidth: true; Layout.fillHeight: true
                    currentIndex: 0

                    ShellTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    McpTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    FileTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    ScreenTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                }
            }
        }
    }

    // ═══ 底栏 ═══
    Rectangle {
        id: footer
        anchors.bottom: parent.bottom; anchors.left: parent.left; anchors.right: parent.right
        height: 32
        color: Qt.rgba(1, 1, 1, 0.8)
        Rectangle { width: parent.width; height: 1; anchors.top: parent.top; color: Qt.rgba(0,0,0,0.06) }
        RowLayout {
            anchors.fill: parent; anchors.leftMargin: 24; anchors.rightMargin: 24
            Text { text: "C2 Panel v2.0"; font.pixelSize: 11; color: Theme.textTertiary }
            Item { Layout.fillWidth: true }
            Text { text: "C++ Qt6 · IPv6 · MCP"; font.pixelSize: 11; color: Theme.textTertiary }
        }
    }
}

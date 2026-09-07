import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: agentList
    color: Qt.rgba(245/255, 245/255, 247/255, 0.92)
    radius: Theme.radiusM
    border.color: Qt.rgba(0,0,0,0.06)

    signal agentSelected(string hwid)

    ColumnLayout {
        anchors.fill: parent; anchors.margins: Theme.spacingM; spacing: Theme.spacingS

        // 搜索框
        Rectangle { Layout.fillWidth: true; height: 32; radius: Theme.radiusS; color: "white"
            border.color: searchInput.activeFocus ? Theme.accent : Qt.rgba(0,0,0,0.1)
            TextField {
                id: searchInput; anchors.fill: parent; anchors.margins: 1
                placeholderText: "🔍 搜索..."; font.pixelSize: 12; background: null
            }
        }

        // Agent 列表
        ListView {
            id: listView
            Layout.fillWidth: true; Layout.fillHeight: true
            clip: true; spacing: 2
            model: agentModel

            delegate: Rectangle {
                width: listView.width; height: 52; radius: 8
                property bool isSelected: agentModel.selectedHwid() === model.hwid
                property bool isHovered: agentMouse.containsMouse
                color: isSelected ? Qt.rgba(10/255, 132/255, 255/255, 0.12) :
                       isHovered ? Qt.rgba(0,0,0,0.04) : "transparent"

                RowLayout {
                    anchors.fill: parent; anchors.margins: 8; spacing: 10

                    // 状态圆点
                    Rectangle {
                        width: 8; height: 8; radius: 4
                        color: model.online ? Theme.green : Theme.textTertiary
                    }

                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 2
                        Text { text: model.user || model.hwid.substring(0,8); font.pixelSize: 13; font.bold: true; color: Theme.textPrimary }
                        Text { text: model.os; font.pixelSize: 11; color: Theme.textSecondary; elide: Text.ElideRight; Layout.fillWidth: true }
                    }
                }

                MouseArea {
                    id: agentMouse; anchors.fill: parent; hoverEnabled: true
                    onClicked: {
                        agentModel.setProperty(model.index, "selected", true)
                        agentList.agentSelected(model.hwid)
                    }
                }
            }
        }

        // 底部统计
        Rectangle { Layout.fillWidth: true; height: 1; color: Qt.rgba(0,0,0,0.06) }
        Text {
            Layout.fillWidth: true
            text: agentModel.onlineCount + "/" + agentModel.totalCount + " 台在线"
            font.pixelSize: 11; color: Theme.textSecondary; horizontalAlignment: Text.AlignHCenter
        }
    }
}

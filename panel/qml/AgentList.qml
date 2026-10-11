import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

// ═══════════════════════════════════════════════════════════════════════════
// AgentList —— 受管端列表
//
// 视觉改动：
//   · 每行加"首字母头像圆牌"，让一行有视觉锚点（原来只有左侧 8px 小圆点，
//     整列看起来是一条没有节奏的横线）
//   · 在线状态从"一个小圆点"升级为圆点 + 语义色淡底胶囊，远处也能一眼扫到
//   · 悬停/选中改成有过渡的背景色，而不是瞬间跳色
//   · 加空列表提示（原来列表为空时整块是灰的，分不清"没数据"和"没加载"）
//
//    之前正是靠这些 Accessible.* 才能用 UI Automation 读到列表并按名字选中
//    Accessible.name 的字段顺序也别改：外部脚本按 "| online" 匹配。
// ═══════════════════════════════════════════════════════════════════════════

Rectangle {
    id: agentList
    color: Theme.bgSecondary
    radius: Theme.radiusL
    border.color: Theme.cardBorder
    border.width: 1

    signal agentSelected(string hwid)

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacingM
        spacing: Theme.spacingS

        // ── 搜索框 ──
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: Theme.controlHeight
            radius: Theme.radiusM
            color: Theme.bgSunken
            border.width: 1
            border.color: searchInput.activeFocus ? Theme.accent : Theme.cardBorder
            Behavior on border.color { ColorAnimation { duration: Theme.durFast } }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.spacingS + 2
                anchors.rightMargin: Theme.spacingS
                spacing: Theme.spacingXS

                Text {
                    text: "🔍"
                    font.pixelSize: Theme.fsSmall
                    opacity: 0.7
                }
                TextField {
                    id: searchInput
                    Layout.fillWidth: true
                    placeholderText: "搜索主机 / 用户…"
                    placeholderTextColor: Theme.textTertiary
                    color: Theme.textPrimary
                    font.pixelSize: Theme.fsSmall
                    font.family: Theme.fontUI
                    background: null
                }
            }
        }

        // ── 列表 ──
        ListView {
            id: listView
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: Theme.spacingXS
            model: agentModel
            boundsBehavior: Flickable.StopAtBounds

            delegate: Rectangle {
                id: row
                width: listView.width
                height: Theme.rowHeight
                radius: Theme.radiusM
                property bool isSelected: model.selected === true
                property bool isHovered: agentMouse.containsMouse
                color: isSelected ? Theme.selectedBg : (isHovered ? Theme.hoverBg : "transparent")
                border.width: isSelected ? 1 : 0
                border.color: Theme.accentLine
                Behavior on color { ColorAnimation { duration: Theme.durFast } }

                activeFocusOnTab: true
                Accessible.role: Accessible.ListItem
                Accessible.name: (model.user || model.hwid.substring(0, 8))
                                 + " | " + model.hwid
                                 + " | " + (model.online ? "online" : "offline")
                                 + " | " + model.os
                                 // 把"已提交核验"也放进无障碍名：读屏管理员能听到，
                                 // 自动化也能据此判断反向通道到底通没通
                                 + (model.taskClaim > 0 ? " | 待检查" : "")
                Accessible.description: "选中该客户端"
                Accessible.focusable: true
                Accessible.selected: isSelected
                Accessible.onPressAction: {
                    agentModel.selectAgent(model.hwid)
                    agentList.agentSelected(model.hwid)
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.spacingS + 2
                    anchors.rightMargin: Theme.spacingS
                    spacing: Theme.spacingS

                    // 首字母头像
                    Rectangle {
                        Layout.preferredWidth: 34
                        Layout.preferredHeight: 34
                        radius: 17
                        gradient: Gradient {
                            GradientStop {
                                position: 0.0
                                color: model.online ? Theme.accent : Theme.textTertiary
                            }
                            GradientStop {
                                position: 1.0
                                color: model.online ? Theme.brand2 : Qt.darker(Theme.textTertiary, 1.2)
                            }
                        }
                        opacity: model.online ? 1.0 : 0.65
                        Text {
                            anchors.centerIn: parent
                            text: (model.user || model.hwid || "?").substring(0, 1).toUpperCase()
                            color: "white"
                            font.pixelSize: 15
                            font.bold: true
                            font.family: Theme.fontUI
                        }
                    }

                    // 名称 + 标识 / 系统
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 1
                        Text {
                            Layout.fillWidth: true
                            text: model.user || model.hwid.substring(0, 8)
                            color: Theme.textPrimary
                            font.pixelSize: Theme.fsBody
                            font.bold: true
                            font.family: Theme.fontUI
                            elide: Text.ElideRight
                        }
                        Text {
                            Layout.fillWidth: true
                            text: model.hwid.substring(0, 12) + " · " + model.os
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontMono
                            elide: Text.ElideRight
                        }
                    }

                    // 反向通道标记：使用人在屏幕锁定上按了"我已完成"。
                    // 管理员侧不用主动去点什么 —— 列表每 5 秒刷一次，按下就会亮。
                    Rectangle {
                        visible: model.taskClaim > 0
                        Layout.preferredWidth: claimRow.width + 14
                        Layout.preferredHeight: 20
                        radius: 10
                        color: Theme.orangeSoft
                        RowLayout {
                            id: claimRow
                            anchors.centerIn: parent
                            spacing: 4
                            Text { text: "🙋"; font.pixelSize: Theme.fsTiny }
                            Text {
                                text: "待检查"
                                color: Theme.orange
                                font.pixelSize: Theme.fsTiny
                                font.bold: true
                                font.family: Theme.fontUI
                            }
                        }
                    }

                    // 状态胶囊
                    Rectangle {
                        Layout.preferredWidth: statusRow.width + 14
                        Layout.preferredHeight: 20
                        radius: 10
                        color: model.online ? Theme.greenSoft : Theme.hoverBg
                        RowLayout {
                            id: statusRow
                            anchors.centerIn: parent
                            spacing: 4
                            Rectangle {
                                width: 6; height: 6; radius: 3
                                color: model.online ? Theme.green : Theme.textTertiary
                            }
                            Text {
                                text: model.online ? "在线" : "离线"
                                color: model.online ? Theme.green : Theme.textTertiary
                                font.pixelSize: Theme.fsTiny
                                font.bold: true
                                font.family: Theme.fontUI
                            }
                        }
                    }
                }

                MouseArea {
                    id: agentMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        agentModel.selectAgent(model.hwid)
                        agentList.agentSelected(model.hwid)
                    }
                }
            }

            // 空列表提示：区分"没有客户端"与"还没加载完"
            Text {
                anchors.centerIn: parent
                visible: listView.count === 0
                text: "暂无在线客户端\n请确认受管端已启动并连上服务端"
                color: Theme.textTertiary
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
                horizontalAlignment: Text.AlignHCenter
                lineHeight: 1.5
            }
        }

        // ── 底部统计 ──
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: Theme.divider
        }
        Text {
            id: statsText
            Layout.fillWidth: true
            text: agentModel.onlineCount + "/" + agentModel.totalCount + " 台在线"
            color: Theme.textTertiary
            font.pixelSize: Theme.fsTiny
            font.family: Theme.fontUI
            horizontalAlignment: Text.AlignHCenter
            Accessible.role: Accessible.StaticText
            Accessible.name: "统计 " + agentModel.onlineCount + "/" + agentModel.totalCount
        }
    }
}

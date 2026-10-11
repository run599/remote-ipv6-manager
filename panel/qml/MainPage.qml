import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

// ═══════════════════════════════════════════════════════════════════════════
// MainPage —— 主界面
//
// 视觉改动：
//   · 顶栏做成"工具栏"：Logo 方块 + 标题 + 在线胶囊 + 服务器 chip + 主题开关
//     （原来是一条白带里散着几个标签，既没有分组也没有层级）
//   · 页签从"文字拼在一个灰条里"改成**带滑动指示块的分段控件**，
//     切换时有位移动画 —— 这是最容易看出"做没做过设计"的一处
//   · 内容区与侧栏都变成带描边的卡片，层级靠底色 + 描边区分，不再靠灰度差
//
//     · tabBar.currentIndex 驱动四个页签切换
//     · 页签节点 Accessible.role=Button + onPressAction（否则自动化点不动）
//     · 顶栏忙碌指示 Accessible.name 含"忙碌中"（自动化脚本按此匹配）
//     · selectedHwid= 镜像节点（自动化读当前选中的客户端）
// ═══════════════════════════════════════════════════════════════════════════

Item {
    id: mainPage
    property string serverUrl: ""
    property string cookie: ""
    property string selectedHwid: ""

    // 移除受管端的操作反馈（不让它静默：成功/失败都在列表下方写一行）
    property string removeStatus: ""

    property string gateCode: ""
    property int    gateRemain: 0
    property string gateErr: ""

    function refreshGateCode() {
        try {
            const o = JSON.parse(api.get("/api/gate/code"))
            if (o && o.ok) {
                //   30 秒那个 code 是校验投递码，不用它显示（曾混淆过，见 2026-10-09 的修正）
                mainPage.gateCode = o.pwd ? o.pwd : o.code
                mainPage.gateRemain = (o.pwd_remaining !== undefined) ? o.pwd_remaining : o.remaining
                mainPage.gateErr = ""
            } else {
                mainPage.gateCode = ""
                mainPage.gateErr = (o && o.error) ? o.error : "取码失败"
            }
        } catch (e) {
            mainPage.gateCode = ""
            mainPage.gateErr = "取码异常"
        }
    }

    // 自动刷新
    Timer {
        // 未登录时 serverUrl 为空，每 5 秒发一次必然失败的请求并清空列表
        interval: 5000; running: mainPage.serverUrl !== ""; repeat: true
        onTriggered: agentModel.refresh()
    }

    Timer {
        interval: 1000
        running: mainPage.serverUrl !== ""
        repeat: true
        onTriggered: {
            if (mainPage.gateRemain > 0) mainPage.gateRemain = mainPage.gateRemain - 1
            if (mainPage.gateRemain <= 0) mainPage.refreshGateCode()
        }
    }

    // ═══ 背景 ═══
    Rectangle { anchors.fill: parent; color: Theme.bgPrimary }

    // 无障碍镜像：当前选中的客户端 hwid（自动化读它判断列表行是否真的被选中）
    Rectangle {
        width: 1; height: 1; color: "transparent"
        Accessible.role: Accessible.StaticText
        Accessible.name: "selectedHwid=" + (mainPage.selectedHwid || "(none)")
    }

    // ═══ 顶栏 ═══
    Rectangle {
        id: topBar
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: Theme.topBarHeight
        color: Theme.bgSecondary

        Rectangle {
            anchors.bottom: parent.bottom
            width: parent.width; height: 1
            color: Theme.divider
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.spacingXL
            anchors.rightMargin: Theme.spacingXL
            spacing: Theme.spacingM

            Rectangle {
                Layout.preferredWidth: 30
                Layout.preferredHeight: 30
                radius: Theme.radiusS + 2
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Theme.accent }
                    GradientStop { position: 1.0; color: Theme.brand2 }
                }
                Text {
                    anchors.centerIn: parent
                    text: "⌘"; color: "white"
                    font.pixelSize: 15; font.bold: true
                }
            }

            Text {
                text: panelTitle
                color: Theme.textPrimary
                font.pixelSize: Theme.fsTitle
                font.bold: true
                font.family: Theme.fontUI
            }

            Rectangle {
                Layout.preferredHeight: 24
                Layout.preferredWidth: onlineRow.width + 20
                radius: 12
                color: Theme.greenSoft
                RowLayout {
                    id: onlineRow
                    anchors.centerIn: parent
                    spacing: 6
                    Rectangle { width: 7; height: 7; radius: 3.5; color: Theme.green }
                    Text {
                        text: agentModel.onlineCount + " 在线 / " + agentModel.totalCount
                        color: Theme.green
                        font.pixelSize: Theme.fsTiny
                        font.bold: true
                        font.family: Theme.fontUI
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "在线数 " + agentModel.onlineCount + "/" + agentModel.totalCount
                    }
                }
            // ── 提升权限码胶囊（校验用；服务端 /api/gate/code 提供）──────────────
            Rectangle {
                Layout.preferredHeight: 24
                Layout.preferredWidth: gateRow.width + 20
                radius: 12
                color: mainPage.gateErr !== "" ? Theme.orangeSoft : Theme.accentSoft
                RowLayout {
                    id: gateRow
                    anchors.centerIn: parent
                    spacing: 6
                    Rectangle {
                        width: 7; height: 7; radius: 3.5
                        color: mainPage.gateErr !== "" ? Theme.orange : Theme.accent
                    }
                    Text {
                        text: mainPage.gateErr !== ""
                              ? "提升权限密码 不可用"
                              : ("r6mop " + (mainPage.gateCode || "----") + "  " + mainPage.gateRemain + "s")
                        color: mainPage.gateErr !== "" ? Theme.orange : Theme.accent
                        font.pixelSize: Theme.fsTiny
                        font.bold: true
                        font.family: Theme.fontUI
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "提升权限密码 " + (mainPage.gateCode || "(none)") +
                                         " 剩余 " + mainPage.gateRemain + "秒"
                    }
                }
            }

            }

            Item { Layout.fillWidth: true }

            // 忙碌指示 + 全局取消。放在顶栏而不是某个页签里：四个页签的动作按钮
            // 都绑定 enabled: !mcp.busy，一旦有调用卡住，用户在任何一个页签里都
            // 手足无措，需要一个随时可用的出口。
            Rectangle {
                visible: mcp.busy
                Layout.preferredHeight: 24
                Layout.preferredWidth: busyRow.width + 20
                radius: 12
                color: Theme.orangeSoft
                RowLayout {
                    id: busyRow
                    anchors.centerIn: parent
                    spacing: Theme.spacingS
                    Text {
                        text: "⏳ 执行中 " + mcp.busySeconds + "s"
                        color: Theme.orange
                        font.pixelSize: Theme.fsTiny
                        font.bold: true
                        font.family: Theme.fontUI
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "忙碌中 " + mcp.busySeconds + " 秒"
                    }
                    Text {
                        text: "取消"
                        color: Theme.orange
                        font.pixelSize: Theme.fsTiny
                        font.underline: true
                        font.family: Theme.fontUI
                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: mcp.cancel()
                        }
                    }
                }
            }

            Rectangle {
                Layout.preferredHeight: 24
                Layout.preferredWidth: Math.min(340, urlText.implicitWidth + 20)
                radius: 12
                color: Theme.bgSunken
                border.color: Theme.cardBorder
                border.width: 1
                Text {
                    id: urlText
                    anchors.centerIn: parent
                    text: mainPage.serverUrl
                    color: Theme.textSecondary
                    font.pixelSize: Theme.fsTiny
                    font.family: Theme.fontMono
                    elide: Text.ElideMiddle
                }
            }

            // 主题开关
            Rectangle {
                Layout.preferredWidth: 30
                Layout.preferredHeight: 30
                radius: Theme.radiusS + 2
                color: themeMouse.containsMouse ? Theme.hoverBg : "transparent"
                Behavior on color { ColorAnimation { duration: Theme.durFast } }
                Text {
                    anchors.centerIn: parent
                    text: Theme.dark ? "☀" : "🌙"
                    font.pixelSize: 14
                }
                MouseArea {
                    id: themeMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: Theme.dark = !Theme.dark
                }
                Accessible.role: Accessible.Button
                Accessible.name: "切换主题"
                Accessible.onPressAction: Theme.dark = !Theme.dark
            }
        }
    }

    // ═══ 内容区 ═══
    RowLayout {
        anchors.top: topBar.bottom
        anchors.bottom: footer.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: Theme.spacingL
        spacing: Theme.spacingL

        // 左侧栏：工具条 + 受管端列表 + 操作反馈。
        // 为什么要包一层 ColumnLayout：原来 AgentList 直接是 RowLayout 的子项
        //（靠 Layout.preferredWidth 定宽），要在它上方插按钮就得给它一个父布局，
        // 否则按钮会变成 RowLayout 的兄弟、把侧栏挤成两列。
        ColumnLayout {
            //    工具条/状态行的固有宽度参与了最小宽度计算，左栏就被撑宽、
            Layout.preferredWidth: Theme.sidebarWidth
            Layout.minimumWidth: Theme.sidebarWidth
            Layout.maximumWidth: Theme.sidebarWidth
            Layout.fillHeight: true
            spacing: Theme.spacingS

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.spacingS
                Layout.maximumWidth: Theme.sidebarWidth

                Button {
                    // 移除 = 从管理端列表清掉这台（服务端删登记记录 + per-agent 密钥 + 它的期望态）
                    // 语义边界：**不是拉黑** —— 该机若再次运行会回退用引导密钥重新登记，于是又会出现在列表里。
                    text: "✖ 移除受管端"
                    implicitHeight: Theme.controlHeight
                    enabled: mainPage.selectedHwid !== ""
                    Accessible.role: Accessible.Button
                    Accessible.name: "移除受管端"
                    onClicked: { removeDlg.targetHwid = mainPage.selectedHwid; removeDlg.open() }
                }
                Item { Layout.fillWidth: true }
                Text {
                    text: mainPage.selectedHwid === "" ? "未选中"
                                                 : mainPage.selectedHwid.substring(0, 8) + "…"
                    elide: Text.ElideRight
                    Layout.maximumWidth: 96
                    color: Theme.textTertiary
                    font.pixelSize: Theme.fsSmall
                    font.family: Theme.fontMono
                    Accessible.role: Accessible.StaticText
                    Accessible.name: "当前选中 " + (mainPage.selectedHwid || "(none)")
                }
            }

            AgentList {
                id: agentListPanel
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                Layout.fillHeight: true
                onAgentSelected: function(hwid) { mainPage.selectedHwid = hwid }
            }

            Text {
                Layout.fillWidth: true
                visible: mainPage.removeStatus !== ""
                Layout.maximumWidth: Theme.sidebarWidth
                Layout.minimumWidth: 0
                text: mainPage.removeStatus
                color: Theme.orange
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: "移除结果 " + mainPage.removeStatus
            }
        }

        // 确认弹窗：移除是"看着无害但会让那台机器从列表消失"的操作，
        // 所以不裸点即执行 —— 要说清后果（它还会自己回来）再让人确认。
        Dialog {
            id: removeDlg
            property string targetHwid: ""
            modal: true
            anchors.centerIn: parent
            width: Math.min(460, mainPage.width - 80)
            //    显式赋值即替换掉那条内部绑定，环就断了。
            implicitHeight: 250
            title: "移除受管端？"
            closePolicy: Popup.CloseOnEscape

            Text {
                //    availableWidth 是控件按自身宽度算好的可用宽，用它打断环。
                width: removeDlg.availableWidth
                wrapMode: Text.WordWrap
                color: Theme.textPrimary
                font.family: Theme.fontUI
                text: "将从管理端列表里移除：\n\n    " + (removeDlg.targetHwid || "(未选中)") +
                      "\n\n会同时清掉它的 per-agent 密钥与期望态（服务端不再记着这台机）。\n" +
                      "受管端程序本身不会被卸载，本机设置也不会被改回。\n\n" +
                      "注意：这不是拉黑 —— 那台机若再次运行受管端，会回退用引导密钥重新登记，于是又会出现。"
            }

            footer: RowLayout {
                spacing: Theme.spacingS
                Item { Layout.fillWidth: true }
                Button {
                    text: "取消"
                    implicitHeight: Theme.controlHeight
                    Accessible.role: Accessible.Button
                    Accessible.name: "取消移除"
                    onClicked: removeDlg.close()
                }
                Button {
                    text: "确认移除"
                    implicitHeight: Theme.controlHeight
                    Accessible.role: Accessible.Button
                    Accessible.name: "确认移除受管端"
                    onClicked: { removeDlg.close(); mainPage.doRemoveAgent(removeDlg.targetHwid) }
                }
            }
        }

        function doRemoveAgent(hwid) {
            if (!hwid) { mainPage.removeStatus = "没选中受管端"; return }
            var r = null
            try {
                r = JSON.parse(api.post("/api/agents/remove?hwid=" + encodeURIComponent(hwid), "{}"))
            } catch (e) {
                mainPage.removeStatus = "移除失败：返回不是合法 JSON"
                return
            }
            if (r === null || r.error !== undefined) {
                mainPage.removeStatus = "移除失败：" + ((r && r.error) ? r.error : "服务端无响应")
                return
            }
            mainPage.removeStatus = "已移除 " + hwid.substring(0, 12) + "…（它若再次运行会重新登记）"
            if (mainPage.selectedHwid === hwid) mainPage.selectedHwid = ""
            agentModel.refresh()
        }

        // 右侧工作区
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.bgSecondary
            radius: Theme.radiusL
            border.color: Theme.cardBorder
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.spacingM
                spacing: Theme.spacingM

                // ── 分段控件（带滑动指示块）──
                Rectangle {
                    id: segment
                    Layout.fillWidth: true
                    Layout.preferredHeight: 38
                    radius: Theme.radiusM
                    color: Theme.bgSunken
                    border.color: Theme.cardBorder
                    border.width: 1

                    readonly property int segCount: 6

                    // 指示块必须先声明：QML 按声明顺序绘制，放后面会盖住文字
                    Rectangle {
                        id: segIndicator
                        readonly property real cellW: (segment.width - 6) / segment.segCount
                        x: 3 + tabBar.currentIndex * cellW
                        y: 3
                        width: cellW
                        height: segment.height - 6
                        radius: Theme.radiusS
                        color: Theme.bgSecondary
                        border.color: Theme.cardBorder
                        border.width: 1
                        Behavior on x {
                            NumberAnimation { duration: Theme.durMed; easing.type: Theme.easeOut }
                        }
                    }

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 3
                        spacing: 0

                        Repeater {
                            model: ["🖥 终端", "📁 文件", "⚡ 截屏", "🧩 插件", "⚙ 设置", "📦 投放", "📋 队列"]
                            delegate: Item {
                                Layout.fillWidth: true
                                Layout.fillHeight: true

                                Text {
                                    anchors.centerIn: parent
                                    text: modelData
                                    color: tabBar.currentIndex === index ? Theme.textPrimary : Theme.textSecondary
                                    font.pixelSize: Theme.fsBody
                                    font.bold: tabBar.currentIndex === index
                                    font.family: Theme.fontUI
                                    Behavior on color { ColorAnimation { duration: Theme.durFast } }
                                }
                                MouseArea {
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: tabBar.currentIndex = index
                                }

                                // 无障碍：页签可按名字点击（自动化与读屏都靠它）
                                Accessible.role: Accessible.Button
                                Accessible.name: "页签 " + modelData
                                Accessible.onPressAction: tabBar.currentIndex = index
                            }
                        }
                    }
                }

                // ── 页签内容 ──
                StackLayout {
                    id: tabBar
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: 0

                    ShellTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    FileTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    ScreenTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    PluginsTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    PoliciesTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    DeployTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                    QueueTab { serverUrl: mainPage.serverUrl; cookie: mainPage.cookie; hwid: mainPage.selectedHwid }
                }
            }
        }
    }

    // ═══ 底栏 ═══
    Rectangle {
        id: footer
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: Theme.footerHeight
        color: Theme.bgSecondary

        Rectangle {
            anchors.top: parent.top
            width: parent.width; height: 1
            color: Theme.divider
        }
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.spacingXL
            anchors.rightMargin: Theme.spacingXL
            Text {
                text: panelTitle + " v2.0"
                color: Theme.textTertiary
                font.pixelSize: Theme.fsTiny
                font.family: Theme.fontUI
            }
            Item { Layout.fillWidth: true }
            Text {
                text: "C++ Qt6 · IPv6 · MCP"
                color: Theme.textTertiary
                font.pixelSize: Theme.fsTiny
                font.family: Theme.fontUI
            }
        }
    }
}

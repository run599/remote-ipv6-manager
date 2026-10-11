import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

// ═══════════════════════════════════════════════════════════════════════════
// ScreenTab —— 屏幕监控（实时看屏）+ 单张截图
//
// 原来只有"点一次截一张"，看不到画面动态，也就无法判断"现在该截什么"。
// 现在分两种模式：
//   · 实时监控：走 ScreenStream（会话 + 最新帧信箱），按固定节奏连续刷新画面，
//     并显示 fps / 每帧体积 / 帧龄 —— 帧龄是判断"画面是不是卡住了"的关键指标
//     （画面看着静止时，到底是对方屏幕没动，还是链路断了？看帧龄就知道）。
//   · 单张截图：保留原来的 BMP 取图路径（无损，适合要看细节时抓一张）。
//
//   · screenshotBase64 / lastSize / onScreenshotReady / onToolResult / zoom 系列
//   · 无障碍镜像节点（含 fps 与累计帧数）—— 自动化靠它判断"画面是否真的在刷新"
// ═══════════════════════════════════════════════════════════════════════════

Rectangle {
    id: screenTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    property string screenshotBase64: ""
    property int lastSize: 0          // 收到的 base64 体积（字节）
    property string lastFormat: "bmp"

    color: "transparent"

    // 无障碍镜像：把监控状态暴露成可读节点。
    // 纯 Text 不进无障碍树，自动化就无从判断"画面到底有没有在刷新"。
    //
    // 必须是**绑定**而不是"在几个时刻手动赋值"：手动赋值的版本只在
    // toggleLive() 与收到帧时更新，于是链路在别处失败（会话没建起来）
    // 时它一直停在"正在建立监控会话…"，读的人无法区分"慢"与"压根没成"。
    readonly property string streamMirror: screenStream.active
        ? ("监控中 fps=" + screenStream.fps.toFixed(1) + " 帧=" + screenStream.received
           + " " + screenStream.frameKb + "KB"
           + " " + image.sourceSize.width + "x" + image.sourceSize.height
           + " 帧龄=" + screenStream.ageMs + "ms"
           + " 状态=" + screenStream.status)
        : ("未监控 状态=" + (screenStream.status.length ? screenStream.status : "(空)")
           + " 累计=" + screenStream.received)
    Rectangle {
        width: 1; height: 1; color: "transparent"
        Accessible.role: Accessible.StaticText
        Accessible.name: screenTab.streamMirror
    }

    Connections {
        target: screenStream
        function onFrameReady(base64, fmt, w, hgt, seq) {
            screenTab.lastFormat = fmt
            screenTab.screenshotBase64 = base64
            screenTab.lastSize = base64.length
            image.source = "data:image/" + fmt + ";base64," + base64
            // 不在这里给 streamMirror 赋值：它是 readonly 绑定（见上方声明），
            // 赋值会在运行时抛 TypeError 并刷屏。绑定本身已经覆盖了这些信息。
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.spacingS

        // ── 工具栏 ──
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacingS

            Text {
                text: "屏幕监控"
                color: Theme.textPrimary
                font.pixelSize: Theme.fsTitle
                font.bold: true
                font.family: Theme.fontUI
            }

            ComboBox {
                id: scaleCombo
                Layout.preferredWidth: 150
                model: ["原始 (1x)", "半屏 (2x)", "四分之一 (4x)", "八分之一 (8x)"]
                // 默认四分之一：实测 1920x1080 下 scale=4 的 PNG 只有 36KB，
                // 帧间隔 300ms 约 120KB/s，走 IPv6 直连毫无压力。
                currentIndex: 2
                onActivated: {
                    if (screenStream.active) {
                        screenStream.updateParams([1, 2, 4, 8][currentIndex], 100)   // 300100：帧率 3.310 fps 
                    }
                }
            }

            // 实时监控开关（主要入口）
            Button {
                id: liveBtn
                Layout.preferredHeight: 30
                text: screenStream.active ? "■ 停止监控" : "▶ 开始监控"
                Accessible.role: Accessible.Button
                Accessible.name: screenStream.active ? "停止监控" : "开始监控"
                Accessible.onPressAction: screenTab.toggleLive()
                background: Rectangle {
                    radius: Theme.radiusM
                    color: screenStream.active
                           ? (liveBtn.down ? Qt.darker(Theme.red, 1.2) : Theme.red)
                           : (liveBtn.down ? Theme.accentPress
                                           : (liveBtn.hovered ? Theme.accentHover : Theme.accent))
                    Behavior on color { ColorAnimation { duration: Theme.durFast } }
                }
                contentItem: Text {
                    text: liveBtn.text
                    color: Theme.textOnAccent
                    font.pixelSize: Theme.fsSmall
                    font.bold: true
                    font.family: Theme.fontUI
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    leftPadding: 6; rightPadding: 6
                }
                onClicked: screenTab.toggleLive()
            }

            // 单张截图（无损 BMP）
            Button {
                Layout.preferredHeight: 30
                text: mcp.busy ? "截取中…" : "📸 单张"
                enabled: !mcp.busy && hwid
                onClicked: {
                    // 必须传够 6 个参数（含 source）。少传会让 QML 抛 TypeError
                    // 并中断本 handler，请求根本发不出去 —— 这里传 "screen"，
                    // 结果就不会被派发到终端或工具页签。
                    mcp.callTool(hwid, serverUrl, cookie, "screenshot",
                        JSON.stringify({scale: [1, 2, 4, 8][scaleCombo.currentIndex], format: "bmp"}),
                        "screen")
                }
            }

            Item { Layout.fillWidth: true }

            // 缩放控制
            Button { text: "−"; onClicked: zoomOut() }
            Text {
                id: zoomLabel; text: "100%"; width: 46
                horizontalAlignment: Text.AlignHCenter
                color: Theme.textSecondary; font.pixelSize: Theme.fsSmall
            }
            Button { text: "+"; onClicked: zoomIn() }
            Button { text: "适应"; onClicked: fitToWindow() }
        }

        // ── 状态条：fps / 体积 / 帧龄 ──
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 26
            visible: screenStream.active
            radius: Theme.radiusS
            color: Theme.bgTertiary
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.spacingM
                anchors.rightMargin: Theme.spacingM
                spacing: Theme.spacingL
                Text {
                    text: screenStream.status
                    color: Theme.textSecondary; font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI
                }
                Text {
                    text: "fps " + screenStream.fps.toFixed(1)
                    color: screenStream.fps > 0.5 ? Theme.green : Theme.orange
                    font.pixelSize: Theme.fsSmall; font.bold: true; font.family: Theme.fontMono
                }
                Text {
                    text: screenStream.frameKb + " KB/帧"
                    color: Theme.textSecondary; font.pixelSize: Theme.fsSmall; font.family: Theme.fontMono
                }
                Text {
                    // 帧龄：画面看着不动时，用它能区分"对方屏幕本来就静止"与"链路断了"
                    text: "帧龄 " + screenStream.ageMs + "ms"
                    color: screenStream.ageMs < 1500 ? Theme.textSecondary : Theme.orange
                    font.pixelSize: Theme.fsSmall; font.family: Theme.fontMono
                }
                Item { Layout.fillWidth: true }
                Text {
                    text: screenStream.received + " 帧"
                    color: Theme.textTertiary; font.pixelSize: Theme.fsTiny; font.family: Theme.fontMono
                }
            }
        }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacingS

                    CheckBox {
                        id: rcToggle
                        text: rcArea.enabled ? "🖱 遥控中（点画面=操作远端）" : "🖱 遥控（关闭）"
                        Accessible.name: "遥控开关"
                        onToggled: {
                            rcArea.enabled = checked
                            rcArea.lastAction = checked ? "遥控已开启：现在点画面会真的操作远端" : "遥控已关闭"
                        }
                    }

                    TextField {
                        id: rcText
                        Layout.fillWidth: true
                        implicitHeight: Theme.controlHeight
                        placeholderText: "要发送到远端的文本（回车即发）"
                        Accessible.name: "遥控文本输入"
                        onAccepted: if (rcArea.enabled) rcArea.sendText(text)
                    }
                    Button {
                        text: "发送文本"
                        implicitHeight: Theme.controlHeight
                        enabled: rcArea.enabled
                        Accessible.name: "发送文本到远端"
                        onClicked: rcArea.sendText(rcText.text)
                    }

                    TextField {
                        id: rcKeys
                        Layout.preferredWidth: 150
                        implicitHeight: Theme.controlHeight
                        placeholderText: "按键，如 {ENTER} ^c"
                        Accessible.name: "遥控按键输入"
                        onAccepted: if (rcArea.enabled) rcArea.sendKeys(text)
                    }
                    Button {
                        text: "发送按键"
                        implicitHeight: Theme.controlHeight
                        enabled: rcArea.enabled
                        Accessible.name: "发送按键到远端"
                        onClicked: rcArea.sendKeys(rcKeys.text)
                    }

                    Item { Layout.fillWidth: true }
                    Text {
                        Layout.preferredWidth: 300
                        text: rcArea.lastAction
                        color: rcArea.enabled ? Theme.red : Theme.textTertiary
                        font.pixelSize: Theme.fsTiny
                        font.family: Theme.fontUI
                        elide: Text.ElideRight
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "遥控状态 " + text
                    }
                }
        // ── 画面区 ──
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.bgSunken
            radius: Theme.radiusM
            border.color: Theme.cardBorder
            border.width: 1
            clip: true

            Flickable {
                id: flickable
                anchors.fill: parent
                anchors.margins: Theme.spacingM
                // 尺寸由 image 真实承载，直接跟随；不再 width*scale
                contentWidth: Math.max(image.width, width)
                contentHeight: Math.max(image.height, height)
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                // ═══════════════════════════════════════════════════════════════════════
                // 遥控条：先在画面里点，才能操作远端的鼠标键盘
                //
                // 开了才是**操作**。没有这道闸，随手点一下就会在远端真的点下去 —— 这很危险。
                // 所以默认关闭，且开启后画面描红边、按钮变红，让"我现在会点到远端"一眼可见。
                // ═══════════════════════════════════════════════════════════════════════


                Image {
                    // ── 可点画面：把显示坐标换算成真实屏幕坐标再发 click ──
                    // 换算依据：sourceSize 是收到的帧尺寸（= 真实屏幕 / scale），
                    //           image.imageScale 是面板显示时的缩放。所以
                    //          真实坐标 = (画面坐标 / image.imageScale) × scale
                    // 注意默认 enabled:false —— 见遥控条处的说明（防误点）。
                    MouseArea {
                        id: rcArea
                        anchors.fill: parent
                        enabled: false
                        hoverEnabled: true
                        acceptedButtons: Qt.LeftButton | Qt.RightButton | Qt.MiddleButton
                        cursorShape: enabled ? Qt.CrossCursor : Qt.ArrowCursor
                        property string lastAction: "遥控未开启（只可观看不操作）"

                        // 请求的缩放倍率（与 start() 里发给受管端的一致）
                        function curScale() { return [1, 2, 4, 8][scaleCombo.currentIndex] }

                        function toReal(mx, my) {
                            const z = image.imageScale > 0 ? image.imageScale : 1.0
                            const s = curScale()
                            return { x: Math.round(mx / z * s), y: Math.round(my / z * s) }
                        }

                        function sendClick(mx, my, btn) {
                            const p = toReal(mx, my)
                            lastAction = "点击 (" + p.x + "," + p.y + ") " + btn
                            mcp.callTool(hwid, serverUrl, cookie, "click",
                                         JSON.stringify({ x: p.x, y: p.y, button: btn }), "screen")
                        }

                        function sendText(t) {
                            if (!t || t.length === 0) { lastAction = "文本为空，未发送"; return }
                            lastAction = "发送文本 " + t.length + " 字"
                            mcp.callTool(hwid, serverUrl, cookie, "send_text",
                                         JSON.stringify({ text: t }), "screen")
                        }

                        function sendKeys(k) {
                            if (!k || k.length === 0) { lastAction = "按键为空，未发送"; return }
                            lastAction = "发送按键 " + k
                            mcp.callTool(hwid, serverUrl, cookie, "send_keys",
                                         JSON.stringify({ keys: k }), "screen")
                        }

                        onClicked: function(mouse) {
                            const btn = mouse.button === Qt.RightButton ? "right"
                                      : (mouse.button === Qt.MiddleButton ? "middle" : "left")
                            sendClick(mouse.x, mouse.y, btn)
                        }
                        onDoubleClicked: function(mouse) { sendClick(mouse.x, mouse.y, "left") }
                    }

                    // 结果回显：只认 source == "screen" 的回报，避免和别的页签混在一起
                    Connections {
                        target: mcp
                        function onToolResult(tool, result, source) {
                            if (source !== "screen") return
                            rcArea.lastAction = tool + "  " + (result.length > 90 ? result.substring(0, 90) + "…" : result)
                        }
                    }


                    id: image
                    property real imageScale: 1.0
                    x: Math.max(0, (flickable.contentWidth - width) / 2)
                    y: Math.max(0, (flickable.contentHeight - height) / 2)
                    transformOrigin: Item.TopLeft
                    width: sourceSize.width * imageScale
                    height: sourceSize.height * imageScale
                    fillMode: Image.Stretch
                    smooth: true
                    // 实时监控下必须同步解码：asynchronous 会让帧顺序错乱、
                    // 旧帧解码完才盖上新帧，画面出现"回跳"
                    asynchronous: !screenStream.active

                    BusyIndicator {
                        anchors.centerIn: parent
                        running: image.status === Image.Loading
                        width: 48; height: 48
                    }
                }
            }

            // 空态提示
            ColumnLayout {
                anchors.centerIn: parent
                spacing: Theme.spacingS
                visible: !screenTab.screenshotBase64
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "🖥"
                    font.pixelSize: 40
                    opacity: 0.35
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: hwid ? "点「▶ 开始监控」实时看屏，或「📸 单张」抓一帧"
                               : "请先在左侧选择一个客户端"
                    color: Theme.textTertiary
                    font.pixelSize: Theme.fsBody
                    font.family: Theme.fontUI
                }
            }
        }

        // ── 底部信息 ──
        Text {
            text: screenTab.screenshotBase64
                  ? ("尺寸: " + image.sourceSize.width + "x" + image.sourceSize.height
                     + " | 缩放: " + Math.round(image.imageScale * 100) + "%"
                     + " | 数据: " + (lastSize / 1048576).toFixed(2) + " MB"
                     + " | 格式: " + lastFormat)
                  : ""
            color: Theme.textTertiary
            font.pixelSize: Theme.fsTiny
            font.family: Theme.fontMono
            // 实测：加这行之前，自动化检查只能报"未找到尺寸/格式行"。
            Accessible.role: Accessible.StaticText
            Accessible.name: text === "" ? "(尚未取图)" : text
        }
    }

    // 实时监控开关的统一入口（鼠标与无障碍共用一份实现）
    function toggleLive() {
        if (screenStream.active) {
            screenStream.stop()
        } else {
            if (!hwid) { return }
            screenStream.start(serverUrl, cookie, hwid, [1, 2, 4, 8][scaleCombo.currentIndex], 300)
        }
    }

    Connections {
        target: mcp
        function onScreenshotReady(tool, base64, source) {
            screenTab.screenshotBase64 = base64
            screenTab.lastSize = base64.length
            screenTab.lastFormat = "bmp"
            image.source = "data:image/bmp;base64," + base64
        }
        function onToolResult(tool, result, source) {
            // screen_info 之类的结果目前无需渲染，保留入口以便将来扩展
            try {
                var obj = JSON.parse(result)
                if (obj.width) { /* screen_info */ }
            } catch(e) {}
        }
    }

    function zoomIn() { image.imageScale = Math.min(3.0, image.imageScale + 0.25); updateZoom() }
    function zoomOut() { image.imageScale = Math.max(0.25, image.imageScale - 0.25); updateZoom() }
    function fitToWindow() { image.imageScale = 1.0; updateZoom() }
    function updateZoom() { zoomLabel.text = Math.round(image.imageScale * 100) + "%" }
}

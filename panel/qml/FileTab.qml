import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: fileTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    property string currentPath: "/"
    color: "transparent"

    ColumnLayout {
        anchors.fill: parent; anchors.margins: Theme.spacingM; spacing: Theme.spacingS

        // 导航栏
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            Button { text: "⬆"; onClicked: navigateUp(); enabled: fileTab.currentPath !== "/" }
            TextField { id: pathInput; Layout.fillWidth: true; text: fileTab.currentPath; font.pixelSize: 13
                onAccepted: navigateTo(text) }
            Button { text: "🔄"; onClicked: navigateTo(pathInput.text) }
            Item { Layout.fillWidth: true }
            Button { text: "📤 上传"; onClicked: uploadFile() }
            Button { text: "📥 下载"; onClicked: downloadFile(); enabled: selectedRow >= 0 }
            Button { text: "🗑 删除"; onClicked: deleteFile(); enabled: selectedRow >= 0 }
        }

        // 文件列表
        Rectangle {
            Layout.fillWidth: true; Layout.fillHeight: true
            color: Theme.bgSecondary; radius: Theme.radiusS; border.color: Qt.rgba(0,0,0,0.06)

            ListView {
                id: fileListView
                anchors.fill: parent; clip: true; spacing: 1
                model: ListModel { id: fileModel }

                header: RowLayout {
                    width: fileListView.width; height: 32
                    Rectangle { width: parent.width; height: 1; anchors.bottom: parent.bottom; color: Qt.rgba(0,0,0,0.06) }
                    Text { text: "名称"; width: parent.width * 0.5; font.pixelSize: 11; font.bold: true; color: Theme.textSecondary; leftPadding: 8 }
                    Text { text: "大小"; width: parent.width * 0.2; font.pixelSize: 11; font.bold: true; color: Theme.textSecondary }
                    Text { text: "类型"; width: parent.width * 0.3; font.pixelSize: 11; font.bold: true; color: Theme.textSecondary }
                }

                delegate: Rectangle {
                    width: fileListView.width; height: 36
                    property bool isHovered: delegateMouse.containsMouse
                    property bool isSelected: fileTab.selectedRow === index
                    color: isSelected ? Qt.rgba(10/255,132/255,255/255,0.12) : isHovered ? Qt.rgba(0,0,0,0.03) : "transparent"

                    RowLayout {
                        anchors.fill: parent; anchors.leftMargin: 8; spacing: 0
                        Text { text: model.isDir ? "📁 " + model.name : "📄 " + model.name; width: parent.width * 0.5; font.pixelSize: 13; color: Theme.textPrimary; elide: Text.ElideRight }
                        Text { text: model.isDir ? "-" : formatSize(model.size); width: parent.width * 0.2; font.pixelSize: 12; color: Theme.textSecondary }
                        Text { text: model.isDir ? "文件夹" : "文件"; width: parent.width * 0.3; font.pixelSize: 12; color: Theme.textTertiary }
                    }
                    MouseArea {
                        id: delegateMouse; anchors.fill: parent; hoverEnabled: true
                        onClicked: fileTab.selectedRow = index
                        onDoubleClicked: {
                            if (model.isDir) navigateTo(fileTab.currentPath === "/" ? "/" + model.name : fileTab.currentPath + "/" + model.name)
                        }
                    }
                }
            }
        }
    }

    property int selectedRow: -1

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + " B"
        if (bytes < 1048576) return (bytes/1024).toFixed(1) + " KB"
        return (bytes/1048576).toFixed(1) + " MB"
    }

    function navigateTo(path) {
        if (!hwid) return
        currentPath = path
        pathInput.text = path
        fileModel.clear()
        selectedRow = -1
        mcp.callTool(hwid, serverUrl, cookie, "list_directory", JSON.stringify({path: path}))
    }

    function navigateUp() {
        var parts = currentPath.split("/")
        parts.pop()
        navigateTo(parts.join("/") || "/")
    }

    function uploadFile() { /* TODO: 文件选择对话框 */ }
    function downloadFile() { /* TODO: 下载选中文件 */ }
    function deleteFile() { /* TODO: 确认删除 */ }
}

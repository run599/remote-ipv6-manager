import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import C2Panel

Rectangle {
    id: fileTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    property string currentPath: "/"
    property string notice: ""
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

        // 操作反馈：让"未实现/失败"变成可见信息
        Text {
            Layout.fillWidth: true
            visible: fileTab.notice.length > 0
            text: fileTab.notice
            color: Theme.orange
            font.pixelSize: 12
            wrapMode: Text.WordWrap
        }

        // 文件列表
        Rectangle {
            Layout.fillWidth: true; Layout.fillHeight: true
            color: Theme.bgSecondary; radius: Theme.radiusS; border.color: Qt.rgba(0,0,0,0.06)

            ListView {
                id: fileListView
                anchors.fill: parent; clip: true; spacing: 1
                model: ListModel { id: fileModel }

                // 表头：外层的 1px 分隔线不能放在 RowLayout 里面
                // （RowLayout 的子项由布局管理，再写 anchors 是未定义行为，
                //   Qt 会刷 "Detected anchors on an item that is managed by a layout"）
                header: Rectangle {
                    width: fileListView.width; height: 32
                    color: "transparent"
                    Rectangle {
                        width: parent.width; height: 1
                        anchors.bottom: parent.bottom
                        color: Qt.rgba(0,0,0,0.06)
                    }
                    RowLayout {
                        anchors.fill: parent
                        Text { text: "名称"; Layout.preferredWidth: parent.width * 0.5; font.pixelSize: 11; font.bold: true; color: Theme.textSecondary; leftPadding: 8 }
                        Text { text: "大小"; Layout.preferredWidth: parent.width * 0.2; font.pixelSize: 11; font.bold: true; color: Theme.textSecondary }
                        Text { text: "类型"; Layout.preferredWidth: parent.width * 0.3; font.pixelSize: 11; font.bold: true; color: Theme.textSecondary }
                    }
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
        mcp.callTool(hwid, serverUrl, cookie, "list_directory", JSON.stringify({path: path}), "file")
    }

    function navigateUp() {
        var parts = currentPath.split("/")
        parts.pop()
        navigateTo(parts.join("/") || "/")
    }

    // 这三个操作需要被控端的 file_manager 插件（读/写/删远端文件），
    // 当前仓库只附带 shell_exec / process_list / screen_capture 三个插件，
    // 因此这里明确告知"缺什么"，而不是留一个点了没反应的按钮。
    function uploadFile() {
        notice = "上传未实现：需要被控端的 file_manager 插件（本项目未附带）"
        console.log(notice)
    }
    function downloadFile() {
        notice = "下载未实现：需要被控端的 file_manager 插件（本项目未附带）"
        console.log(notice)
    }
    function deleteFile() {
        notice = "删除未实现：需要被控端的 file_manager 插件（本项目未附带）"
        console.log(notice)
    }

    // 消费 list_directory 的结果：原来整个文件没有任何 Connections，
    // fileModel 只 clear 不 append，文件页永远是空的
    Connections {
        target: mcp
        function onToolResult(tool, result, source) {
            if (source !== "file" && tool !== "list_directory") return
            var obj = null
            try { obj = JSON.parse(result) } catch (e) { notice = "结果解析失败: " + result; return }
            if (obj.error !== undefined) { notice = "[error] " + obj.error; return }
            var list = obj.files
            if (!list && obj.content && obj.content[0] && obj.content[0].text) {
                try { var inner = JSON.parse(obj.content[0].text); list = inner.files } catch (e) { list = null }
            }
            if (!list) { notice = "该工具未返回文件列表（需要 file_manager 插件）"; return }
            notice = ""
            fileModel.clear()
            for (var i = 0; i < list.length; ++i) {
                var f = list[i]
                fileModel.append({ name: f.name, size: f.size || 0,
                                   isDir: f.is_dir === true, modTime: f.mod_time || "" })
            }
            selectedRow = -1
        }
    }
}

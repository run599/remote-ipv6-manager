// ═══════════════════════════════════════════════════════════════════════════
// DeployTab —— 投放页签（工件 / 按类型应用 / 事务化 / 回滚）
//
// 为什么补这个页签：这一轮加的能力（15 种 apply 类型、事务化批量、按事务回滚、
// 工件密钥台账）全在服务端与客户端里，界面上一个入口都没有。
//
// 布局：左侧 filestore 清单（点一下填进"文件名"），右侧投放表单 + 结果台。
// 全部走 api.get / api.post（同步、自带会话），不改 C++。
// ═══════════════════════════════════════════════════════════════════════════

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

Rectangle {
    id: deployTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    // ── 「直接写文件到受管端」的状态（走 file_browser 的 write_file，免走 filestore）──
    property string wfLocal: ""
    property string wfRemote: ""
    property int    wfOffset: 0
    property int    wfBytes: 0
    property bool   wfBusy: false
    readonly property int wfChunk: 1048576   // 刚刚从本机选中的文件（绝对路径）

    property var files: []        // filestore
    property var artifacts: []    // 工件台账
    property string log: ""
    property string status: ""

    // ── 声明期望态 ──
    // desiredRev  = 服务端当前的"目标"版本（改一次就 +1）
    // appliedRev  = 受管端上报的"已达成"版本（来自 /api/agents 的运行事实）
    // 两者相等才算收敛。这样"我改了什么"和"它到底做到没有"在同一个界面里对上。
    property int  desiredRev: 0
    property string appliedRev: ""
    property var  desiredItems: []
    property var  desiredHistory: []   // 收敛历史（新的在前）
    // 待生效清单：可视化编辑的期望态（不用写 JSON）。
    // 注意 QML 里数组必须**换新引用**（pendingDesired = a.slice()）才触发界面刷新。
    property var  pendingDesired: []

    readonly property var applyKinds: [
        "none（仅落地）", "exe（可执行）", "zip（解压）",
        "reg（注册表）", "policy（策略，同 reg）", "ps1（PowerShell）",
        "bat（批处理）", "msi（安装包）", "cert（证书）",
        "task（计划任务）", "service（服务）", "hosts", "firewall", "secedit（本地安全策略）"
    ]

    function kindOf(text) {
        const i = text.indexOf("（")
        return i > 0 ? text.substring(0, i) : text
    }

    function refreshFiles() {
        try {
            const o = JSON.parse(api.get("/api/files/list"))
            if (o.error !== undefined) { status = "列文件失败：" + o.error; return }
            files = o
        } catch (e) { status = "文件列表返回不是合法 JSON" }
    }

    function refreshArtifacts() {
        if (!hwid) { artifacts = []; return }
        try {
            const o = JSON.parse(api.get("/api/artifact/list?hwid=" + hwid))
            artifacts = o.artifacts || []
        } catch (e) { artifacts = [] }
    }

    function say(s) { log = s + "\n" + log }

    // ── 直接写文件到受管端（免走服务端 filestore 中转）──
    // 为什么单独做一条：filestore 投放要先上传到服务端再下发，适合"要留档/要 sha 校验"的工件；
    // 但临时塞个小文件（配置、脚本、样本）时那两步纯属绕路。这条直接经 write_file 落盘。
    // 上限：一次 1MB、按 append 分片（write_file 无 offset，所以只能按顺序追加）。
    function writeLocalFile() {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        if (wfBusy) { status = "正在写，先等它结束"; return }
        var path = api.pickOpenFile("选一个要直接写到受管端的文件（上限约 1MB/片，自动分片）",
                                    "所有文件 (*.*)|*.*")
        if (!path || path === "") { status = "已取消"; return }
        var info = JSON.parse(api.localFileInfo(path))
        if (info.exists !== true) { status = "本机文件不存在"; return }
        var dir = targetInput.text.trim()
        if (dir === "") dir = "C:\\ProgramData\\r6m-policies"
        wfLocal = path
        wfRemote = dir.replace(/[\\/]+$/, "") + "\\" + info.name
        wfOffset = 0
        wfBytes = 0
        wfBusy = true
        status = "写入中…（" + info.name + "，" + info.size + " 字节  " + wfRemote + "）"
        requestWrite()
    }

    function requestWrite() {
        var err = ""
        var b64 = api.readLocalFileBase64(wfLocal, wfOffset, wfChunk)
        if (!b64 || b64 === "") { wfBusy = false; status = "读本机文件失败（偏移 " + wfOffset + "）"; return }
        mcp.callTool(hwid, serverUrl, cookie, "write_file",
            JSON.stringify({ path: wfRemote, content: b64, encoding: "base64", append: wfOffset > 0 }), "write")
    }

    // ── 从本机选文件并投放（把这套流程做成一次点击）──
    // 前一版连"选本机文件"都没有，只能对着 filestore 清单点。
    function pickLocalFile(andDeploy) {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        // 走 Win32 通用对话框（ApiClient::pickOpenFile 里有理由：
        // QtQuick.Dialogs 是插件模块，部署缺一个 DLL 就报 not installed，整片 QML 直接挂）
        var path = api.pickOpenFile(
            "选一个要投放到受管端的文件（投放后默认以管理员权限启动）",
            "可执行文件 (*.exe)|*.exe|脚本 (*.ps1;*.bat)|*.ps1;*.bat|压缩包 (*.zip)|*.zip|注册表文件 (*.reg)|*.reg|所有文件 (*.*)|*.*")
        if (!path || path === "") { status = "已取消选文件"; return }
        pickedLocalPath = path
        afterPick(path, andDeploy === true)
    }


    function afterPick(path, andDeploy) {
        const info = JSON.parse(api.localFileInfo(path))
        if (info.exists !== true) { status = "选中的文件不存在："; say(" " + path); return }
        status = "上传中…（" + info.name + "，" + info.size + " 字节）"
        say("⬆ 上传中 " + info.name)
        const r = JSON.parse(api.uploadFile(path))
        if (r.error !== undefined) {
            status = "上传失败：" + r.error
            say(" 上传失败：" + r.error)
            return
        }
        // 服务端返回的是 basename（它会做 basename + 路径校验）
        fileNameInput.text = r.name
        // 默认按"管理员程序运行"：应用类型=exe + 投放后启动=开。
        for (var i = 0; i < applyKinds.length; ++i) {
            if (applyKinds[i].indexOf("exe") === 0) { kindCombo.currentIndex = i; break }
        }
        swRun.checked = true
        swDry.checked = false
        refreshFiles()
        say(" 已上传 " + r.name + "（" + r.size + " 字节） 服务端 filestore")
        status = "已上传并填好表单（应用类型=exe，投放后启动=开）"
        if (andDeploy === true) deploy()
    }


    // ── 期望态：读取目标 + 读取受管端是否已达成 ──
    function refreshDesired() {
        if (!hwid) { desiredRev = 0; desiredItems = []; appliedRev = ""; return }
        try {
            const o = JSON.parse(api.get("/api/desired?hwid=" + hwid))
            if (o.error !== undefined) { status = "读期望态失败：" + o.error; return }
            desiredRev = o.rev || 0
            desiredItems = o.items || []
        } catch (e) { status = "期望态返回不是合法 JSON"; return }
        // 收敛历史：每次 rev 的设定/达成时间与耗时
        try {
            const h = JSON.parse(api.get("/api/desired/history?hwid=" + hwid))
            desiredHistory = h.history || []
        } catch (e) { desiredHistory = [] }
        // 达成情况在 /api/agents 的运行事实里（status 字段也带，但列表更稳）
        appliedRev = ""
        try {
            const arr = JSON.parse(api.get("/api/agents"))
            const list = Array.isArray(arr) ? arr : (arr.agents || [])
            for (let i = 0; i < list.length; i++) {
                if (list[i].hwid === hwid) { appliedRev = list[i].applied_rev || ""; break }
            }
        } catch (e) { appliedRev = "" }
    }

    // 期望态与批量投放同构，所以直接复用上面那个 items 框，少一个要填的地方
    function parseBatchItems() {
        const txt = batchInput.text.trim()
        if (txt === "") return null
        try {
            const p = JSON.parse(txt)
            return Array.isArray(p) ? p : (p.items || null)
        } catch (e) { return null }
    }

    function setDesiredFromBatch() {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        const items = parseBatchItems()
        if (!items) { status = "先把 items JSON 填进上面的批量框（期望态与它同构）"; return }
        try {
            const r = JSON.parse(api.post("/api/desired",
                JSON.stringify({ hwid: hwid, items: items })))
            if (r.error !== undefined) { status = "设置期望态失败：" + r.error; say(" " + r.error); return }
            status = "已设为目标 rev=" + r.rev + " —— 受管端下一轮 poll 会自己收敛"
            say(" desired set rev=" + r.rev + "，共 " + items.length + " 项")
            refreshDesired()
        } catch (e) { status = "返回不是合法 JSON" }
    }

    function clearDesired() {
        if (!hwid) { return }
        try {
            const r = JSON.parse(api.post("/api/desired",
                JSON.stringify({ hwid: hwid, items: [] })))
            if (r.error !== undefined) { status = "清空失败：" + r.error; return }
            // 这点必须写清楚：清空期望态**不会卸载**已经应用的工件。
            // 收敛只负责"让该有的出现"，不负责"把不该有的删掉"——自动卸载太危险。
            status = "期望态已清空（rev=" + r.rev + "）；已应用的工件不会被卸载"
            say(" desired clear rev=" + r.rev + "（不卸载已应用项）")
            refreshDesired()
        } catch (e) { status = "返回不是合法 JSON" }
    }

    // ── 表单式编辑期望态（降低门槛的核心）──
    function fileKnown(name) {
        for (let i = 0; i < files.length; i++) {
            if (files[i].name === name) return true
        }
        return false
    }

    function pendingWarnings() {
        const w = []
        const hard = ["ps1", "bat", "cmd", "msi"]   // 服务端也会拒，这里提前说
        for (let i = 0; i < pendingDesired.length; i++) {
            const it = pendingDesired[i]
            if (!fileKnown(it.file_name)) w.push(" 文件不在库里：" + it.file_name)
            if (hard.indexOf(it.apply) >= 0)
                w.push(" " + it.file_name + "（" + it.apply + "）无法自动回滚")
        }
        return w
    }

    function addItemFromForm() {
        if (!hwid || fileNameInput.text === "") { status = "先在上面选一个文件"; return }
        const it = { file_name: fileNameInput.text, apply: kindOf(kindCombo.currentText) }
        if (targetInput.text !== "") it.target_dir = targetInput.text
        if (argsInput.text !== "")   it.apply_args = argsInput.text
        if (swArtifact.checked)      it.artifact = true
        if (swRun.checked)           it.run = true
        let a = pendingDesired.slice()
        a.push(it)
        pendingDesired = a
        const w = pendingWarnings()
        status = "已加入清单（共 " + a.length + " 项）" +
                 (w.length > 0 ? "；有 " + w.length + " 处要注意" : "")
        say("＋ " + it.file_name + " [" + it.apply + "]")
    }

    function removePending(i) {
        let a = pendingDesired.slice()
        a.splice(i, 1)
        pendingDesired = a
        status = "清单剩 " + a.length + " 项"
    }

    // 把服务端当前的期望态搬进清单 —— 于是"改一点"不必重打全部
    function loadCurrentDesired() {
        let a = []
        for (let i = 0; i < desiredItems.length; i++) a.push(desiredItems[i])
        pendingDesired = a
        if (a.length === 0) {
            status = "当前期望态是空的：用上面的表单加入几项，再点「生效」"
        } else {
            status = "已读入当前期望态（" + a.length + " 项）—— 改完点「生效」"
            say("📥 读入 " + a.length + " 项")
        }
    }

    function applyPending() {
        if (!hwid || pendingDesired.length === 0) { status = "清单是空的"; return }
        const w = pendingWarnings()
        if (w.length > 0) say(" 清单有 " + w.length + " 处要注意：" + w.join("；"))
        try {
            const r = JSON.parse(api.post("/api/desired",
                JSON.stringify({ hwid: hwid, items: pendingDesired })))
            if (r.error !== undefined) { status = "生效失败：" + r.error; say(" " + r.error); return }
            status = "已生效为目标 rev=" + r.rev + " —— 受管端下一轮会自动收敛"
            say(" 生效 rev=" + r.rev + "，共 " + pendingDesired.length + " 项")
            refreshDesired()
        } catch (e) { status = "返回不是合法 JSON" }
    }

    function isConverged() {
        return desiredRev > 0 && appliedRev !== "" && appliedRev === String(desiredRev)
    }

    function deploy() {
        if (!hwid || fileNameInput.text === "") { status = "先选受管端与文件名"; return }
        const body = {
            agent_hwid: hwid,
            file_name: fileNameInput.text,
            target_dir: targetInput.text,
            apply: kindOf(kindCombo.currentText),
            apply_args: argsInput.text,
            artifact: swArtifact.checked,
            run: swRun.checked,
            dry_run: swDry.checked
        }
        status = swDry.checked ? "dry-run 中…" : "投放中…"
        say(" deploy " + body.file_name + " apply=" + body.apply +
            (swDry.checked ? "（dry-run）" : ""))
        try {
            const r = JSON.parse(api.post("/api/files/deploy", JSON.stringify(body)))
            if (r.error !== undefined) { status = "受理失败：" + r.error; say(" " + r.error); return }
            status = "已下发（异步执行），稍后刷新台账"
            say("  已下发 request_id=" + (r.request_id || "?"))
            refreshArtifacts()
        } catch (e) { status = "返回不是合法 JSON" }
    }

    function rollbackRecent() {
        if (!hwid || fileNameInput.text === "") { status = "先选要回滚的工件"; return }
        try {
            const r = JSON.parse(api.post("/api/files/rollback",
                JSON.stringify({ agent_hwid: hwid, file_name: fileNameInput.text })))
            if (r.error !== undefined) { status = "回滚受理失败：" + r.error; return }
            status = "已下发回滚（异步）"
            say(" rollback " + fileNameInput.text)
        } catch (e) { status = "返回不是合法 JSON" }
    }

    function rollbackTx() {
        if (!hwid || txInput.text === "") { status = "先填事务 id"; return }
        try {
            const r = JSON.parse(api.post("/api/files/rollback_tx",
                JSON.stringify({ agent_hwid: hwid, tx: txInput.text })))
            if (r.error !== undefined) { status = "回滚受理失败：" + r.error; return }
            status = "已下发按事务回滚（异步）"
            say(" rollback_tx " + txInput.text)
        } catch (e) { status = "返回不是合法 JSON" }
    }

    function batchDeploy() {
        if (!hwid) { status = "先选受管端"; return }
        const txt = batchInput.text.trim()
        if (txt === "") { status = "把 items JSON 贴进下面的框"; return }
        let items = null
        try {
            const p = JSON.parse(txt)
            items = Array.isArray(p) ? p : (p.items || null)
        } catch (e) { status = "JSON 解析失败：不是合法 JSON"; return }
        if (!items) { status = "JSON 里没有 items 数组"; return }
        status = "事务投放在执行…"
        say(" batch " + items.length + " 项（全成或全回滚）")
        try {
            const r = JSON.parse(api.post("/api/files/deploy_batch",
                JSON.stringify({ agent_hwid: hwid, items: items })))
            if (r.error !== undefined) { status = "受理失败：" + r.error; return }
            status = "已下发事务 tx=" + (r.tx || "?") + "；用该 id 可整批回滚"
            say("  事务 id=" + (r.tx || "?"))
            txInput.text = r.tx || ""
        } catch (e) { status = "返回不是合法 JSON" }
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacingM
        spacing: Theme.spacingM

        // ── 左：filestore + 工件台账 ──
        ColumnLayout {
            // 必须是**硬上界**：只写 preferredWidth 管不住下限 ——
            // QML 布局里 minimumWidth 默认取内容隐式宽度，而列表委托的
            // contentWidth 又会反过来影响隐式宽度，于是左列被撑到 1038px、
            // 把右列整个挤出窗口（实测右列控件右边界到 2440，窗口只有 1680）。
            Layout.preferredWidth: 320
            Layout.minimumWidth: 260
            Layout.maximumWidth: 360
            Layout.fillHeight: true
            spacing: Theme.spacingM

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: Theme.radiusL
                color: Theme.bgSecondary
                border.color: Theme.cardBorder
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: Theme.spacingM
                    spacing: Theme.spacingS

                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                        text: "filestore"
                        color: Theme.textPrimary
                        font.pixelSize: Theme.fsTitle
                        font.bold: true
                        font.family: Theme.fontUI
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "filestore面板"
                    }
                        Item { Layout.fillWidth: true }
                        Button { text: "刷新"; implicitHeight: 26
                                 Accessible.name: "刷新文件列表"
                                 onClicked: { deployTab.refreshFiles(); deployTab.refreshArtifacts() } }
                    }
                    ListView {
                        id: fileList
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        model: deployTab.files
                        spacing: 2
                        delegate: Rectangle {
                            // 用 ListView.view.width，不要读 parent、也不要经 id 读自身：
                            // 经 id 会让 contentWidth == 自身宽度，形成反馈环把外层布局撑开。
                            width: ListView.view ? ListView.view.width : 0
                            height: 30
                            radius: Theme.radiusS
                            color: fh.hovered ? Theme.hoverBg : "transparent"
                            HoverHandler { id: fh }
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.spacingS
                                anchors.rightMargin: Theme.spacingS
                                Text {
                                    text: (modelData.is_dir ? "📁 " : "📄 ") + modelData.name
                                    color: Theme.textPrimary
                                    font.pixelSize: Theme.fsBody
                                    font.family: Theme.fontUI
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                Text {
                                    text: modelData.is_dir ? "" : (Math.round(modelData.size / 1024) + " KB")
                                    color: Theme.textTertiary
                                    font.pixelSize: Theme.fsSmall
                                    font.family: Theme.fontMono
                                }
                            }
                            MouseArea {
                                anchors.fill: parent
                                enabled: !modelData.is_dir
                                cursorShape: Qt.PointingHandCursor
                                onClicked: fileNameInput.text = modelData.name
                            }
                            Accessible.role: Accessible.Button
                            Accessible.name: "文件 " + modelData.name
                            // 只是声明 role 而没给 onPressAction，等于对外说"我是按钮"
                            // 却按不动：键盘/读屏/自动化都点不了这些行（实测就是这个缺口）。
                            Accessible.onPressAction: {
                                if (!modelData.is_dir) fileNameInput.text = modelData.name
                            }
                        }
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 170
                radius: Theme.radiusL
                color: Theme.bgSecondary
                border.color: Theme.cardBorder
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: Theme.spacingM
                    spacing: Theme.spacingS
                    Text { text: "工件台账（密钥 ↔ 文件）"; color: Theme.textPrimary
                           font.pixelSize: Theme.fsBody; font.bold: true; font.family: Theme.fontUI }
                    ListView {
                        id: artifactList
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        model: deployTab.artifacts
                        spacing: 2
                        delegate: Column {
                            // 同理：ListView.view.width 既避开"创建瞬间 parent 为 null"，
                            // 又避开了经 id 读自身造成的宽度反馈环。
                            width: ListView.view ? ListView.view.width : 0
                            spacing: 1
                            Text { text: modelData.name || "?"; color: Theme.textPrimary
                                   font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI }
                            Text {
                                text: "🔑 " + (modelData.key || "-") + "   " +
                                      (modelData.sha256 ? modelData.sha256.substring(0, 12) + "…" : "")
                                color: Theme.textTertiary
                                font.pixelSize: Theme.fsTiny
                                font.family: Theme.fontMono
                            }
                        }
                        Text {
                            anchors.centerIn: parent
                            visible: parent.count === 0
                            text: "暂无登记（投放时勾选「登记工件」）"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsSmall
                            font.family: Theme.fontUI
                        }
                    }
                }
            }
        }

        // ── 右：投放表单 + 结果台 ──
        ColumnLayout {
            Layout.fillWidth: true
            Layout.minimumWidth: 0      // 允许收缩，否则内容会顶宽整行
            Layout.fillHeight: true
            spacing: Theme.spacingM

            Rectangle {
                Layout.fillWidth: true
                implicitHeight: formCol.implicitHeight + Theme.spacingM * 2
                radius: Theme.radiusL
                color: Theme.bgSecondary
                border.color: Theme.cardBorder
                border.width: 1

                ColumnLayout {
                    id: formCol
                    anchors.fill: parent
                    anchors.margins: Theme.spacingM
                    spacing: Theme.spacingS

                    Text {
                        text: "投放 / 应用"
                        color: Theme.textPrimary
                        font.pixelSize: Theme.fsTitle
                        font.bold: true
                        font.family: Theme.fontUI
                        // UIA 不会把裸 Text 放进树里 —— 不标就没有可验证的抓手
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "投放页"
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacingS
                        TextField {
                            id: fileNameInput
                            Layout.fillWidth: true
                            implicitHeight: Theme.controlHeight
                            placeholderText: "文件名（点左侧文件自动填入）"
                            font.family: Theme.fontMono
                            Accessible.name: "投放文件名"
                        }
                        TextField {
                            id: targetInput
                            Layout.fillWidth: true
                            implicitHeight: Theme.controlHeight
                            placeholderText: "目标目录，留空=受管端同目录"
                            font.family: Theme.fontMono
                            Accessible.name: "目标目录"
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacingS
                        ComboBox {
                            id: kindCombo
                            Layout.preferredWidth: 240
                            implicitHeight: Theme.controlHeight
                            model: deployTab.applyKinds
                            Accessible.name: "应用类型"
                        }
                        TextField {
                            id: argsInput
                            Layout.fillWidth: true
                            implicitHeight: Theme.controlHeight
                            placeholderText: "类型参数，如 name=MyTask 或 store=Root"
                            font.family: Theme.fontMono
                            Accessible.name: "应用参数"
                        }
                    }

                    // 开关单独一行；按钮另起一行。
                    // 原来 3 个开关 + 2 个按钮挤一行，总隐式宽度约 700px，
                    // 窗口一窄就整行溢出到卡片外（QML 布局不会自动换行）。
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacingM
                        Switch { id: swArtifact; text: "登记工件"
                                 Accessible.name: "登记工件" }
                        Switch { id: swRun; text: "投放后启动"
                                 Accessible.name: "投放后启动" }
                        Switch { id: swDry; text: "dry-run"
                                 Accessible.name: "dry-run" }
                        Text {
                            text: "（登记工件=签发密钥并登记到台账；dry-run=只报影响面不动系统）"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacingS
                        Button {
                            text: "🚀 投放"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid && fileNameInput.text !== ""
                            Accessible.name: "投放"
                            onClicked: deployTab.deploy()
                        }
                        Button {
                            text: "↩ 回滚最近一次"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid && fileNameInput.text !== ""
                            Accessible.name: "回滚最近一次"
                            onClicked: deployTab.rollbackRecent()
                        }
                        Item { Layout.fillWidth: true }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacingS
                        Button {
                            text: "📂 选本机文件…"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid
                            Accessible.name: "选本机文件"
                            onClicked: deployTab.pickLocalFile(false)
                        }
                        Button {
                            text: "✍ 直接写文件到受管端…"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid && !deployTab.wfBusy
                            Accessible.name: "直接写文件到受管端"
                            onClicked: deployTab.writeLocalFile()
                        }
                        Button {
                            text: "⚡ 选文件并立即投放"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid
                            Accessible.name: "选文件并立即投放"
                            onClicked: deployTab.pickLocalFile(true)
                        }
                        Text {
                            text: "选完自动上传到服务端并填好表单（默认 exe + 投放后启动）"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }

                    Text { text: deployTab.status; visible: text !== ""
                           color: Theme.orange; font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI }
                }
            }

            // 事务化批量
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: batchCol.implicitHeight + Theme.spacingM * 2
                radius: Theme.radiusL
                color: Theme.bgSecondary
                border.color: Theme.cardBorder
                border.width: 1

                ColumnLayout {
                    id: batchCol
                    anchors.fill: parent
                    anchors.margins: Theme.spacingM
                    spacing: Theme.spacingS
                    Text { text: "事务化批量投放（全成或全回滚）"; color: Theme.textPrimary
                           font.pixelSize: Theme.fsBody; font.bold: true; font.family: Theme.fontUI }
                    TextArea {
                        id: batchInput
                        Layout.fillWidth: true
                        Layout.preferredHeight: 84
                        placeholderText: '[{"file_name":"policy.reg","target_dir":"C:\\\\x","apply":"reg"},\n ' +
                                         '{"file_name":"rule.wfw","target_dir":"C:\\\\x","apply":"firewall"}]'
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.fsMono
                        wrapMode: TextEdit.Wrap
                        background: Rectangle { color: Theme.bgSunken
                                                radius: Theme.radiusS
                                                border.color: Theme.cardBorder }
                        Accessible.name: "批量 items JSON"
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacingS
                        Button {
                            text: "📌 作为期望态"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid
                            Accessible.name: "用 JSON 设为期望态"
                            onClicked: deployTab.setDesiredFromBatch()
                        }
                        Button {
                            text: "📦 事务投放"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid
                            Accessible.name: "事务投放"
                            onClicked: deployTab.batchDeploy()
                        }
                        TextField {
                            id: txInput
                            Layout.preferredWidth: 300
                            implicitHeight: Theme.controlHeight
                            placeholderText: "事务 id（事务投放后自动填入）"
                            font.family: Theme.fontMono
                            Accessible.name: "事务 id"
                        }
                        Button {
                            text: "↩ 按事务回滚"
                            implicitHeight: Theme.controlHeight
                            enabled: deployTab.hwid && txInput.text !== ""
                            Accessible.name: "按事务回滚"
                            onClicked: deployTab.rollbackTx()
                        }
                        Item { Layout.fillWidth: true }
                    }
                }
            }

            // ── 期望态（声明式收敛）──
            //
            // 与"发指令"的区别值得写在界面上：这里的 items 是**持久目标**，
            // 缺什么补什么。于是离线机器回来自动补齐、服务端重启也不丢。
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: desiredCol.implicitHeight + Theme.spacingM * 2
                radius: Theme.radiusL
                color: Theme.bgSecondary
                border.color: isConverged() ? Theme.green : Theme.cardBorder
                border.width: 1

                ColumnLayout {
                    id: desiredCol
                    anchors.fill: parent
                    anchors.margins: Theme.spacingM
                    spacing: Theme.spacingS

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: Theme.spacingS
                        Text {
                            text: "期望态（声明式收敛）"
                            color: Theme.textPrimary
                            font.pixelSize: Theme.fsBody
                            font.bold: true
                            font.family: Theme.fontUI
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "期望态面板"
                        }
                        // 目标 rev
                        Rectangle {
                            implicitWidth: revText.implicitWidth + 16; implicitHeight: 22
                            radius: Theme.radiusPill; color: Theme.accentSoft
                            border.color: Theme.accentLine; border.width: 1
                            Text {
                                id: revText; anchors.centerIn: parent
                                text: "目标 rev " + deployTab.desiredRev
                                color: Theme.accent; font.pixelSize: Theme.fsSmall
                                font.family: Theme.fontUI
                                Accessible.role: Accessible.StaticText
                                Accessible.name: "目标 rev " + deployTab.desiredRev
                            }
                        }
                        // 已达成 rev
                        Rectangle {
                            implicitWidth: appText.implicitWidth + 16; implicitHeight: 22
                            radius: Theme.radiusPill
                            color: deployTab.isConverged() ? Theme.greenSoft : Theme.orangeSoft
                            border.color: deployTab.isConverged() ? Theme.green : Theme.orange
                            border.width: 1
                            Text {
                                id: appText; anchors.centerIn: parent
                                text: "已达成 " + (deployTab.appliedRev === "" ? "未知" : deployTab.appliedRev)
                                color: deployTab.isConverged() ? Theme.green : Theme.orange
                                font.pixelSize: Theme.fsSmall; font.family: Theme.fontUI
                                Accessible.role: Accessible.StaticText
                                Accessible.name: "已达成 rev " +
                                    (deployTab.appliedRev === "" ? "未知" : deployTab.appliedRev)
                            }
                        }
                        Text {
                            text: deployTab.desiredRev === 0
                                  ? "未配置期望态"
                                  : (deployTab.isConverged() ? " 已收敛"
                                     : "⏳ 收敛中（受管端下一轮 poll 会取全量）")
                            color: deployTab.isConverged() ? Theme.green : Theme.textSecondary
                            font.pixelSize: Theme.fsSmall
                            font.family: Theme.fontUI
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "收敛状态 " + (deployTab.isConverged() ? "已收敛" :
                                    (deployTab.desiredRev === 0 ? "未配置" : "收敛中"))
                        }
                        Item { Layout.fillWidth: true }
                        Button {
                            text: "🔄 刷新"
                            implicitHeight: 26
                            Accessible.name: "刷新期望态"
                            onClicked: deployTab.refreshDesired()
                        }
                        Button {
                            text: "📥 读入编辑"
                            implicitHeight: 26
                            enabled: deployTab.hwid
                            Accessible.name: "读入编辑"
                            onClicked: deployTab.loadCurrentDesired()
                        }
                        Button {
                            text: "🗑 清空"
                            implicitHeight: 26
                            enabled: deployTab.hwid && deployTab.desiredRev > 0
                            Accessible.name: "清空期望态"
                            onClicked: deployTab.clearDesired()
                        }
                    }

                    // ── 待生效清单：可视化编辑 ──
                    // 门槛就在这里降下来的：不用写 JSON、不用记类型英文名，
                    // 用上面的投放表单选好点「＋」即可；每项可单独删；
                    // 文件名不在库里 / 属于不可自动回滚的类型，会当场标出来。
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: Theme.spacingXS

                        Text {
                            text: "待生效清单（" + deployTab.pendingDesired.length + " 项）"
                            color: Theme.textSecondary
                            font.pixelSize: Theme.fsSmall
                            font.bold: true
                            font.family: Theme.fontUI
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "待生效清单 " + deployTab.pendingDesired.length + " 项"
                        }

                        Repeater {
                            model: deployTab.pendingDesired
                            delegate: RowLayout {
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                spacing: Theme.spacingS
                                Text {
                                    text: deployTab.fileKnown(modelData.file_name) ? "•" : ""
                                    color: deployTab.fileKnown(modelData.file_name) ? Theme.green : Theme.orange
                                    font.pixelSize: Theme.fsSmall
                                    font.family: Theme.fontUI
                                }
                                Text {
                                    text: (modelData.file_name || "?")
                                    color: Theme.textPrimary
                                    font.pixelSize: Theme.fsSmall
                                    font.family: Theme.fontMono
                                    elide: Text.ElideRight
                                    Layout.preferredWidth: 190
                                }
                                Text {
                                    text: (modelData.apply || "none")
                                    color: Theme.accent
                                    font.pixelSize: Theme.fsSmall
                                    font.family: Theme.fontMono
                                    Layout.preferredWidth: 72
                                }
                                Text {
                                    text: (modelData.target_dir || "（同目录）")
                                    color: Theme.textTertiary
                                    font.pixelSize: Theme.fsSmall
                                    font.family: Theme.fontMono
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                Button {
                                    text: "✕"
                                    implicitWidth: 28
                                    implicitHeight: 24
                                    Accessible.name: "移除 " + (modelData.file_name || "")
                                    onClicked: deployTab.removePending(index)
                                }
                            }
                        }

                        Text {
                            Layout.fillWidth: true
                            visible: text !== ""
                            text: deployTab.pendingWarnings().join("    ")
                            color: Theme.orange
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                            wrapMode: Text.WordWrap
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "清单问题 " + deployTab.pendingWarnings().length + " 条"
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            spacing: Theme.spacingS
                            Button {
                                text: "＋ 把上面的表单加入清单"
                                implicitHeight: 28
                                enabled: deployTab.hwid && fileNameInput.text !== ""
                                Accessible.name: "加入清单"
                                onClicked: deployTab.addItemFromForm()
                            }
                            Button {
                                text: " 生效（" + deployTab.pendingDesired.length + " 项）"
                                implicitHeight: 28
                                enabled: deployTab.hwid && deployTab.pendingDesired.length > 0
                                Accessible.name: "期望态生效"
                                onClicked: deployTab.applyPending()
                            }
                            Item { Layout.fillWidth: true }
                        }
                    }

                    // ── 收敛历史（最近 5 次）──
                    // 只有当前 rev 的即时状态回答不了"上次那批多久铺完、有没有一直没达成的"。
                    Column {
                        Layout.fillWidth: true
                        spacing: 1
                        visible: deployTab.desiredHistory.length > 0

                        Text {
                            text: "收敛历史（最近 5 次）"
                            color: Theme.textSecondary
                            font.pixelSize: Theme.fsSmall
                            font.bold: true
                            font.family: Theme.fontUI
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "收敛历史"
                        }
                        Repeater {
                            model: deployTab.desiredHistory.slice(0, 5)
                            delegate: Text {
                                readonly property bool done: (modelData.achieved_ms || 0) > 0
                                readonly property real secs: (modelData.duration_ms || 0) / 1000.0
                                text: (done ? " " : "⏳ ") +
                                      "rev " + modelData.rev +
                                      "　" + (modelData.items || 0) + " 项" +
                                      (done ? ("　达成耗时 " + secs.toFixed(1) + "s")
                                            : "　尚未达成") +
                                      ((modelData.failed && modelData.failed.length > 0)
                                        ? ("　失败: " + modelData.failed.join("; "))
                                        : "")
                                color: done ? Theme.green : Theme.orange
                                font.pixelSize: Theme.fsTiny
                                font.family: Theme.fontMono
                                elide: Text.ElideRight
                                width: parent.width
                                Accessible.role: Accessible.StaticText
                                Accessible.name: "历史 rev " + modelData.rev +
                                    (done ? " 已达成" : " 未达成")
                            }
                        }
                    }

                    Text {
                        Layout.fillWidth: true
                        text: "用法：在上面把文件/类型/目录选好 「＋ 把上面的表单加入清单」 重复几次 「 生效」。" +
                              "生效后受管端自己取全量并对账：缺什么补什么、版本不对就换；离线机器回来也会自动补齐。" +
                              " 清空期望态不会卸载已应用项（收敛只负责「让该有的出现」，不负责删东西）。"
                        color: Theme.textTertiary
                        font.pixelSize: Theme.fsTiny
                        font.family: Theme.fontUI
                        wrapMode: Text.WordWrap
                    }
                }
            }

            // 结果台
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: Theme.radiusL
                color: Theme.bgSunken
                border.color: Theme.cardBorder
                border.width: 1

                ScrollView {
                    anchors.fill: parent
                    anchors.margins: Theme.spacingS
                    TextArea {
                        id: logArea
                        readOnly: true
                        wrapMode: TextEdit.Wrap
                        text: deployTab.log === "" ? "（操作记录会显示在这里）" : deployTab.log
                        color: Theme.textPrimary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.fsMono
                        background: null
                        Accessible.name: "投放操作记录"
                    }
                }
            }
        }
    }

    // 关键时机：filestore 清单必须在**登录并选中受管端之后**再拉。
    // 原来只在 Component.onCompleted 拉一次 —— 那发生在登录之前，
    // 请求是未认证的（401），于是清单永久空着，看起来像"文件列表坏了"。
    // 实测：点一下「刷新文件列表」就出来了。
    onHwidChanged: { refreshFiles(); refreshArtifacts(); refreshDesired() }
    Component.onCompleted: { /* 登录前不拉：那时没有会话，只会白得一个 401 */ }

    // 「直接写文件」的结果处理（file_browser.write_file 经 JSON-RPC 信封回来）
    Connections {
        target: mcp
        function onToolResult(tool, result, source) {
            if (source !== "write") return
            if (!deployTab.wfBusy) return
            var o = null
            try { o = JSON.parse(result) } catch (e) { o = null }
            if (o && o.content && o.content.length > 0 && o.content[0] && o.content[0].text !== undefined) {
                try { o = JSON.parse(o.content[0].text) } catch (e) { }
            }
            if (!o) { deployTab.wfBusy = false; deployTab.status = "写文件返回无法解析"; return }
            if (o.error !== undefined) { deployTab.wfBusy = false; deployTab.status = "写文件失败：" + o.error; return }
            var info = JSON.parse(api.localFileInfo(deployTab.wfLocal))
            var total = info.size || 0
            deployTab.wfBytes = Math.min(deployTab.wfOffset + deployTab.wfChunk, total)
            deployTab.wfOffset += deployTab.wfChunk
            if (deployTab.wfOffset >= total) {
                deployTab.wfBusy = false
                deployTab.status = "已直接写入受管端：" + deployTab.wfRemote + "（" + total + " 字节，"
                                 + Math.ceil(total / deployTab.wfChunk) + " 片）"
                deployTab.say("✍ 直接写入完成 " + deployTab.wfRemote + "（" + total + " 字节）")
                deployTab.refreshFiles()
            } else {
                deployTab.status = "写入中… " + deployTab.wfBytes + " / " + total + " 字节"
                deployTab.requestWrite()
            }
        }
    }
}

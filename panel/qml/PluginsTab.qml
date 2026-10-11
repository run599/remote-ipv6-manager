// ═══════════════════════════════════════════════════════════════════════════
// PluginsTab —— 插件页
//
// 这一页回答三个问题（对应插件标准 v3 的三大声明）：
//   ① 这台系统里有哪些插件、跑在哪一侧（side）
//   ② 每个插件**声明**了要调宿主哪些能力（host_caps）—— 能力可见，才谈得上可审计
//   ③ 每个插件**声明**了需要哪些文件（requires）—— 并提供「一键装」把依赖
//      并进期望态（P1）。装 = 期望态 +N 项，剩下的收敛/重试/回滚/历史全是现成的。
//
// 数据源：GET /api/plugins/meta（会话鉴权）。服务端用通用 map 透传 plugin.json，
// 所以插件以后加字段不必改服务端 —— 这里也就跟着自动多出来。
// ═══════════════════════════════════════════════════════════════════════════

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

Rectangle {
    id: pluginsTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    property var plugins: []        // /api/plugins/meta 的 plugins[]
    property var desiredItems: []   // 当前期望态条目（用来判断"装了没"）
    property string status: ""
    property bool loading: false

    function capLabel(c) {
        const m = {
            "report": "回报结果", "state_read": "读状态", "state_write": "写状态",
            "deploy_file": "投放文件", "upload_file": "上传文件", "rollback": "回收文件",
            "invoke_tool": "调机器工具", "routes": "接外部请求",
            "agents": "读机器清单", "exec": "执行命令"
        }
        return m[c] || c
    }
    function capTone(c) {
        if (c === "exec") return Theme.red                    // 很高危
        if (c === "deploy_file" || c === "state_write") return Theme.orange
        if (c === "rollback" || c === "upload_file") return Theme.blue
        if (c === "routes" || c === "invoke_tool") return Theme.accent
        return Theme.textTertiary                             // 只读类
    }
    function sideLabel(s) { return (s === "server") ? "服务端侧" : "受管端侧" }
    function sideTone(s) { return (s === "server") ? Theme.orange : Theme.accent }

    function refresh() {
        loading = true
        try {
            const o = JSON.parse(api.get("/api/plugins/meta"))
            const arr = o.plugins || []
            // 把**有声明**的插件排前面（有依赖 requires / 有能力 host_caps / 是 server 侧）。
            // 理由：这一页真正要看的就是"它声明了什么"；11 个工具型插件既无依赖也无能力声明，
            // 把它们堆在前面，会把唯一需要看的那个挤到滚动区外（实测就是这样）。
            const rich = [], plain = []
            for (let i = 0; i < arr.length; i++) {
                const p = arr[i]
                const hasDecl = (p.requires && p.requires.length > 0) ||
                                (p.host_caps && p.host_caps.length > 0) ||
                                p.side === "server"
                ;(hasDecl ? rich : plain).push(p)
            }
            plugins = rich.concat(plain)
        } catch (e) { plugins = []; status = "读插件清单失败（返回不是合法 JSON）" }
        refreshDesired()
        loading = false
    }

    function refreshDesired() {
        if (!hwid) { desiredItems = []; return }
        try {
            const d = JSON.parse(api.get("/api/desired?hwid=" + hwid))
            desiredItems = d.items || []
        } catch (e) { desiredItems = [] }
    }

    // 某个依赖文件是否已在期望态里
    function inDesired(name) {
        for (let i = 0; i < desiredItems.length; i++) {
            if (desiredItems[i].file_name === name) return true
        }
        return false
    }
    function reqCount(p) { return (p.requires || []).length }
    function installedCount(p) {
        const r = p.requires || []
        let n = 0
        for (let i = 0; i < r.length; i++) if (inDesired(r[i].artifact)) n++
        return n
    }

    // ── 一键装：把 requires 并进期望态（P1 的核心动作）──
    // 要点：不是"发一次投放"，而是**写进期望态** —— 于是离线机器回来会自动补齐，
    //      失败会自动重试，装了哪一版会被 sha256 比对，历史可查，坏了能回滚。
    function installPlugin(p) {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        const req = p.requires || []
        if (req.length === 0) { status = p.name + "：没有声明需要投放的文件"; return }

        // 必须是"读-改-写"：直接覆盖会把别的插件/手工加的条目冲掉。
        let items = []
        try {
            const cur = JSON.parse(api.get("/api/desired?hwid=" + hwid))
            items = (cur.items || []).slice()
        } catch (e) { items = [] }

        let added = 0, updated = 0
        for (let i = 0; i < req.length; i++) {
            const r = req[i]
            const it = {
                file_name: r.artifact,
                target_dir: r.target_dir || "",
                apply: r.apply || "none",
                artifact: (r.artifact_key === true || r.artifact === true),
                run: r.run === true,
                from: "plugin:" + (p.id || "unknown")
            }
            if (r.apply_args) it.apply_args = r.apply_args
            let replaced = false
            for (let k = 0; k < items.length; k++) {
                if (items[k].file_name === it.file_name &&
                    (items[k].target_dir || "") === it.target_dir) {
                    items[k] = it; replaced = true; break
                }
            }
            if (replaced) updated++
            else { items.push(it); added++ }
        }

        try {
            const r = JSON.parse(api.post("/api/desired",
                JSON.stringify({ hwid: hwid, items: items })))
            if (r.error !== undefined) { status = "装失败：" + r.error; return }
            status = "已把「" + p.name + "」的依赖并入期望态（新增 " + added +
                     " 项，更新 " + updated + " 项） 目标 rev=" + r.rev +
                     "；受管端下一轮会自动收敛"
            refreshDesired()
        } catch (e) { status = "返回不是合法 JSON" }
    }

    // 小徽标
    component Pill: Rectangle {
        property string text: ""
        property color tone: Theme.textSecondary
        implicitWidth: pillText.implicitWidth + 14
        implicitHeight: 20
        radius: Theme.radiusPill
        color: Qt.rgba(tone.r, tone.g, tone.b, 0.14)
        border.color: Qt.rgba(tone.r, tone.g, tone.b, 0.34)
        border.width: 1
        Text {
            id: pillText
            anchors.centerIn: parent
            text: parent.text
            color: parent.tone
            font.pixelSize: Theme.fsTiny
            font.family: Theme.fontUI
            // 裸 Text 不进 UIA 树（本项目反复踩到的坑：图标/徽标看着在，
            // 读屏和自动化却完全读不到）。标注出来，读屏才念得到"投放文件""服务端侧"。
            Accessible.role: Accessible.StaticText
            Accessible.name: parent.text
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacingM
        spacing: Theme.spacingM

        // ── 顶栏 ──
        RowLayout {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            spacing: Theme.spacingS
            Text {
                text: "插件"
                color: Theme.textPrimary
                font.pixelSize: Theme.fsTitle
                font.bold: true
                font.family: Theme.fontUI
                Accessible.role: Accessible.StaticText
                Accessible.name: "插件面板"
            }
            Pill { text: plugins.length + " 个"; tone: Theme.accent }
            Text {
                Layout.fillWidth: true
                text: loading ? "读取中…" : (status !== "" ? status : "")
                color: Theme.orange
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
                elide: Text.ElideRight
                Accessible.role: Accessible.StaticText
                Accessible.name: "插件页状态"
            }
            Button {
                text: "🔄 刷新"
                implicitHeight: 28
                Accessible.name: "刷新插件清单"
                onClicked: pluginsTab.refresh()
            }
        }

        // ── 插件列表 ──
        ListView {
            id: pluginList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: Theme.spacingS
            model: pluginsTab.plugins

            Text {
                anchors.centerIn: parent
                visible: pluginList.count === 0
                text: pluginsTab.loading ? "读取中…" : "没有读到插件（检查服务端 filestore/plugins/）"
                color: Theme.textTertiary
                font.pixelSize: Theme.fsBody
                font.family: Theme.fontUI
            }

            delegate: Rectangle {
                width: pluginList.width
                implicitHeight: cardCol.implicitHeight + Theme.spacingM * 2
                radius: Theme.radiusL
                color: Theme.bgSecondary
                border.color: Theme.cardBorder
                border.width: 1

                ColumnLayout {
                    id: cardCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: Theme.spacingM
                    spacing: Theme.spacingXS

                    // 第一行：名字 + 形态 + 来源 + 装的状态
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: Theme.spacingS
                        Text {
                            text: (modelData.name || modelData.id || "?")
                            color: Theme.textPrimary
                            font.pixelSize: Theme.fsBody
                            font.bold: true
                            font.family: Theme.fontUI
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "插件 " + (modelData.name || modelData.id)
                        }
                        Text {
                            text: (modelData.id || "") + "  v" + (modelData.version || "?")
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontMono
                        }
                        // side 是这套标准里最要紧的一个字段：决定它跑在哪一侧
                        Pill {
                            text: pluginsTab.sideLabel(modelData.side)
                            tone: pluginsTab.sideTone(modelData.side)
                        }
                        Pill {
                            visible: (modelData.kind || "tool") !== "tool"
                            text: modelData.kind || ""
                            tone: Theme.orange
                        }
                        Item { Layout.fillWidth: true }
                        // 服务端侧插件的**运行状态** —— 这是 P3 第一步的落点。
                        // 为什么要显眼地摆在卡片上：本项目反复吃过"静默失败"的亏
                        // （插件扫到 0 就把映射清空、校验因编码恒判一致…），
                        // 所以"这个插件到底跑没跑起来"必须一眼可见，而不是靠猜。
                        // agent 侧插件没有 run 字段（它们跑在受管端，服务端不管它们）。
                        Pill {
                            readonly property var r: modelData.run || null
                            visible: r !== null
                            text: r === null ? "" :
                                  (r.state === "loaded"
                                     ? (" 运行中 · " + r.tool_count + " 工具" +
                                        (r.pid ? (" · pid " + r.pid) : ""))
                                     : (r.state === "failed" ? " 加载失败" : ("· " + r.state)))
                            tone: r === null ? Theme.textTertiary
                                  : (r.state === "loaded" ? Theme.green
                                     : (r.state === "failed" ? Theme.red : Theme.orange))
                            Accessible.role: Accessible.StaticText
                            Accessible.name: r === null ? "" :
                                ("运行状态 " + text + (r.err ? ("：" + r.err) : ""))
                        }
                        // 依赖文件的安装进度
                        Pill {
                            visible: pluginsTab.reqCount(modelData) > 0
                            readonly property int done: pluginsTab.installedCount(modelData)
                            readonly property int all: pluginsTab.reqCount(modelData)
                            text: (done >= all) ? (" 依赖已就绪 " + all + "/" + all)
                                                : ("依赖 " + done + "/" + all)
                            tone: (done >= all) ? Theme.green : Theme.orange
                        }
                        Button {
                            text: "📦 一键装到这台机器"
                            implicitHeight: 28
                            enabled: pluginsTab.hwid && pluginsTab.reqCount(modelData) > 0
                            Accessible.name: "一键装 " + (modelData.name || modelData.id)
                            onClicked: pluginsTab.installPlugin(modelData)
                        }
                    }

                    // 加载失败的原因：**单独一行、完整显示**。
                    // 塞进徽标会被省略号截断，而"为什么失败"恰恰是唯一有用的信息。
                    Text {
                        Layout.fillWidth: true
                        readonly property var r: modelData.run || null
                        visible: r !== null && r.state === "failed"
                        text: " " + ((r && r.err) ? r.err : "（宿主没给出错误信息）")
                        color: Theme.red
                        font.pixelSize: Theme.fsTiny
                        font.family: Theme.fontUI
                        wrapMode: Text.WordWrap
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "加载失败原因 " + text
                    }

                    // 已加载时把它暴露的工具名列出来 —— 这是"它到底能做什么"的直接证据
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: Theme.spacingXS
                        readonly property var r: modelData.run || null
                        visible: r !== null && r.state === "loaded" && (r.tools || []).length > 0
                        Text {
                            text: "工具："
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                        }
                        Repeater {
                            model: ((modelData.run || {}).tools) || []
                            delegate: Pill { text: modelData; tone: Theme.accent }
                        }
                        Item { Layout.fillWidth: true }
                    }

                    // 描述
                    Text {
                        Layout.fillWidth: true
                        visible: (modelData.description || "") !== ""
                        text: modelData.description || ""
                        color: Theme.textSecondary
                        font.pixelSize: Theme.fsSmall
                        font.family: Theme.fontUI
                        wrapMode: Text.WordWrap
                    }

                    // 声明的能力（host_caps）
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: Theme.spacingXS
                        Text {
                            text: "可调能力："
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "可调能力"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                        }
                        Repeater {
                            model: modelData.host_caps || []
                            delegate: Pill {
                                text: pluginsTab.capLabel(modelData)
                                tone: pluginsTab.capTone(modelData)
                            }
                        }
                        Text {
                            visible: !(modelData.host_caps && modelData.host_caps.length > 0)
                            text: "（未声明：只能回报结果）"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                        }
                        Item { Layout.fillWidth: true }
                    }

                    // 声明的依赖（requires）
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 1
                        visible: pluginsTab.reqCount(modelData) > 0
                        Text {
                            text: "需要的文件："
                            Accessible.role: Accessible.StaticText
                            Accessible.name: "需要的文件"
                            color: Theme.textTertiary
                            font.pixelSize: Theme.fsTiny
                            font.family: Theme.fontUI
                        }
                        Repeater {
                            model: modelData.requires || []
                            delegate: RowLayout {
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                spacing: Theme.spacingXS
                                Text {
                                    text: pluginsTab.inDesired(modelData.artifact) ? "" : ""
                                    Accessible.role: Accessible.StaticText
                                    Accessible.name: (pluginsTab.inDesired(modelData.artifact)
                                                      ? "已在期望态 " : "未加入 ") + (modelData.artifact || "")
                                    color: pluginsTab.inDesired(modelData.artifact)
                                           ? Theme.green : Theme.textTertiary
                                    font.pixelSize: Theme.fsTiny
                                    font.family: Theme.fontUI
                                }
                                Text {
                                    text: modelData.artifact || "?"
                                    Accessible.role: Accessible.StaticText
                                    Accessible.name: "依赖文件 " + (modelData.artifact || "")
                                    color: Theme.textPrimary
                                    font.pixelSize: Theme.fsTiny
                                    font.family: Theme.fontMono
                                    Layout.preferredWidth: 170
                                    elide: Text.ElideRight
                                }
                                Text {
                                    Accessible.role: Accessible.StaticText
                                    Accessible.name: "依赖参数 " + text
                                    text: " " + (modelData.target_dir || "（同目录）") +
                                          "   [" + (modelData.apply || "none") + "]" +
                                          (modelData.run ? "  投放后启动" : "") +
                                          (modelData.artifact_key ? "  签发工件密钥" : "")
                                    color: Theme.textTertiary
                                    font.pixelSize: Theme.fsTiny
                                    font.family: Theme.fontMono
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
                                }
                            }
                        }
                    }
                }
            }
        }

        Text {
            Layout.fillWidth: true
            text: "「一键装」不是发一次投放，而是把插件声明的依赖**并入期望态**：" +
                  "受管端离线也没关系（回来自动补齐）、失败会自动重试、版本按 sha256 比对、" +
                  "过程记入收敛历史、装错了能按事务回滚。"
            color: Theme.textTertiary
            font.pixelSize: Theme.fsTiny
            font.family: Theme.fontUI
            wrapMode: Text.WordWrap
        }
    }

    // 只挂 Component.onCompleted 的话，它发生在**登录之前** —— 请求未认证（401），
    // 列表就永久空着。这个坑我在投放页签已经踩过一次（filestore 清单），这是复发。
    onHwidChanged: { refresh(); refreshDesired() }
    // 登录前不拉：那时没有会话，只会白得一个 401
    Component.onCompleted: { /* 等 hwid 变化再拉 */ }
}

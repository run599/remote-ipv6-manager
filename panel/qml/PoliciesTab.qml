// ═══════════════════════════════════════════════════════════════════════════
// PoliciesTab —— 策略/设置页（路径 A）
//
// 三种控件，对应三类设置项（都由清单声明，界面不猜）：
//                            所以 on/off 两个值一律由清单给出）
//
//   面板不自己拼 .reg、不碰上传接口：那些是服务端擅长的事，塞进 QML 只会把协议细节漏进来。
//
//   读回远端真值必须经受管端（服务端看不到远端注册表），属于下一版，本版不假装能做。
// ═══════════════════════════════════════════════════════════════════════════

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

Rectangle {
    id: polTab
    property string serverUrl: ""
    property string cookie: ""
    property string hwid: ""
    color: "transparent"

    property var settings: []
    property var grouped: []       // [{group, items:[...]}]
    property var values: ({})      // 设置项 id  将要下发的值（字符串）
    property string status: ""
    property bool loading: false
    property bool showNotes: true

    function refresh() {
        if (!hwid) { status = "先在左侧选一个受管端"; settings = []; grouped = []; return }
        loading = true
        let list = []
        let packList = []   // packs 要在 try 外可用（o 是 try 内的局部变量）
        let assetList = []
        let curVals = {}   // 服务端反解出的"当前已下发值"
        try {
            const o = JSON.parse(api.get("/api/policies"))
            list = o.settings || []
            packList = o.packs || []
            assetList = o.assets || []
            try {
                const cur = JSON.parse(api.get("/api/policies/current?hwid=" + hwid))
                curVals = cur.values || {}
                dispatchedCount = (cur.dispatched || []).length
            } catch (e2) { curVals = {} }
            status = o.error ? o.error : ("清单 " + list.length + " 项，改动后点「保存并下发」")
        } catch (e) {
            status = "读清单失败：返回不是合法 JSON（服务端 /api/policies）"
        }
        settings = list
        packs = packList
        assets = assetList
        // 分组（保持清单顺序）
        const order = [], byG = {}
        for (let i = 0; i < list.length; i++) {
            const g = list[i].group || "其它"
            if (!byG[g]) { byG[g] = []; order.push(g) }
            byG[g].push(list[i])
        }
        const gs = []
        for (let i = 0; i < order.length; i++) gs.push({ group: order[i], items: byG[order[i]] })
        grouped = gs
        // 初值：**以服务端反解出的"当前已下发值"为准**，没下发过的才用保守默认。
        const v = {}
        for (let i = 0; i < list.length; i++) {
            const s = list[i]
            const cur = curVals[s.id]
            if (cur !== undefined && cur !== "") {
                v[s.id] = cur                      // 服务端说它现在是这个值
            } else if (s.type === "bool") {
                v[s.id] = (s.off || "0")           // 从未下发过：显示为"关"（最保守）
            } else {
                v[s.id] = ""                       // 从未下发过：留空 = 不下发
            }
        }
        values = v
        loading = false
        refreshDrift()
        convLive = true   // 手动刷新 = 人已进场，恢复轮询
        refreshConv()
    }

    // 偏离详情：受管端检查发现的"哪一项/哪个值不符"。
    // 数据来自 /api/agents 的 desired_drift —— 服务端这次才刚接上这个字段
    // （客户端其实一直在发，被服务端静默丢弃了）。
    property var drift: []
    function refreshDrift() {
        if (!hwid) { drift = []; return }
        try {
            const o = JSON.parse(api.get("/api/agents"))
            const list = Array.isArray(o) ? o : (o.agents || [])
            for (let k = 0; k < list.length; k++) {
                if (list[k].hwid === hwid) { drift = list[k].desired_drift || []; return }
            }
            drift = []
        } catch (e) { drift = [] }
    }

    function setValue(id, val) {
        // 那会让"绑定在 values 上的控件"重算，而控件又把值推回来，形成**绑定环**
        // （实测刷屏 "QML TextField: Binding loop detected for property text"）。
        if (values[id] === val) return
        const v = {}
        for (const k in values) v[k] = values[k]
        v[id] = val
        values = v
    }

    function touchRow(id) { /* 触发重绘用；QML 的 var 属性赋新对象即刷新 */ }

    // ── 期望态收敛的实时显示 ──
    // 轮询开关：**会话失效时必须停下**。
    // 实测（2026-10-09）：服务端一重启，面板 cookie 就失效，而这个 3 秒 Timer
    // 而登录页同时弹出来了 —— 人只看到洪水，看不出"其实只要重新登录"。
    // 现在：读到 401 就自己停；手动刷新或重新登录成功后再自动恢复。
    // 策略包（服务端下发：一个包 = 一组预置值，展开成同一份 .reg）
    property var packs: []
    property var assets: []   // 策略资产（ps1/hosts/secedit —— reg 表达不了的那些）
    // 已下发的项数（服务端反解出来的真实状态，不是界面上的猜测）
    property int dispatchedCount: 0
    property bool convLive: true

    property string wantRev: "—"
    property string haveRev: "—"
    property string convText: "未知"
    property color convTone: Theme.textTertiary

    function refreshConv() {
        if (!hwid) { wantRev = "—"; haveRev = "—"; convText = "未选机器"; convTone = Theme.textTertiary; return }
        let want = "", have = ""
        try {
            const d = JSON.parse(api.get("/api/desired?hwid=" + hwid))
            if (d.rev !== undefined) want = String(d.rev)
        } catch (e) { }
        try {
            const a = JSON.parse(api.get("/api/agents"))
            const list = Array.isArray(a) ? a : (a.agents || [])
            for (let k = 0; k < list.length; k++) {
                if (list[k].hwid === hwid) { have = String(list[k].applied_rev || ""); break }
        if (want === "" && have === "" && convLive) {
            convLive = false
            convText = " 会话已失效（轮询已暂停，请重新登录）"
            convTone = Theme.red
        }
            }
        } catch (e) { }
        wantRev = want === "" ? "—" : want
        haveRev = have === "" ? "—" : have
        if (want === "") { convText = "读不到期望态"; convTone = Theme.orange; return }
        if (have === want) { convText = "已达成 "; convTone = Theme.green; return }
        // 差几个 rev：给出人话，而不是只显示两个数字让人自己比
        const dw = parseInt(want, 10), dh = parseInt(have, 10)
        if (!isNaN(dw) && !isNaN(dh) && dw > dh) {
            convText = "收敛中…（还差 " + (dw - dh) + " 个版本）"
        } else {
            convText = "收敛中…"
        }
        convTone = Theme.orange
    }

    // 只产生一个 rev、一次收敛，并且白拿按值校验 + 漂移自愈 + 备份回滚。
    function applyPack(id, vals) {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        try {
            const r = JSON.parse(api.post("/api/policies/apply",
                JSON.stringify({ hwid: hwid, pack: id })))
            if (r.error !== undefined) { status = "策略包下发失败：" + r.error; return }
            status = "策略包「" + r.pack_name + "」已下发：rev=" + r.rev +
                     "，共 " + ((r.applied || []).length) + " 个值；受管端下一轮收敛"
            // 让界面上的开关跟着这个包走 —— 否则"界面显示的"和"实际下发的"会不一致，
            // 那种不一致比"没反应"更坏（人会以为已经改回去了）。
            const v = {}
            for (const k in values) v[k] = values[k]
            for (const k in (vals || {})) v[k] = vals[k]
            values = v
            refreshConv()
        } catch (e) { status = "策略包下发失败：返回不是合法 JSON" }
    }

    // 一键下发一个策略资产。载荷由服务端写成文件，再以对应的 apply 类型进期望态
    // —— 所以它走的是**同一套**收敛 / 按值校验 / 漂移自愈 / 备份回滚。
    function applyAsset(id) {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        try {
            const r = JSON.parse(api.post("/api/policies/apply",
                JSON.stringify({ hwid: hwid, asset: id })))
            if (r.error !== undefined) { status = "资产下发失败：" + r.error; return }
            status = "资产「" + r.asset_name + "」已下发（apply=" + r.kind + "，file=" + r.file +
                     "，rev=" + r.rev + "）；受管端下一轮收敛"
            refreshConv()
        } catch (e) { status = "资产下发失败：返回不是合法 JSON" }
        syncValues()   //  资产会改机器状态  必须把开关同步过来 
    }

    function save() {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        // 只发改过的项：bool 一定发（它的初值可能就是 off）；enum/int 为空则不发
        const send = {}
        let n = 0
        for (let i = 0; i < settings.length; i++) {
            const s = settings[i]
            const v = values[s.id]
            if (s.type === "bool" && v !== "-") { send[s.id] = v; n++ }
            else if (v !== undefined && v !== "") { send[s.id] = v; n++ }
        }
        if (n === 0) { status = "没有要下发的项"; return }
        try {
            const r = JSON.parse(api.post("/api/policies/apply",
                JSON.stringify({ hwid: hwid, values: send })))
            if (r.error !== undefined) { status = "下发失败：" + r.error; return }
            status = "已生成 " + r.file + "（" + r.bytes + " 字节）并写进期望态，rev=" + r.rev +
                     "；受管端下一轮会收敛（含按值校验与漂移自愈）"
        } catch (e) { status = "下发失败：返回不是合法 JSON" }
            refreshConv()   // 保存后立刻刷新，别让用户盯着不动的界面等
    }

    // 修复两个旧 bug（2026-10-10）：
    // 规则：default===true 取该项的 on（enum 取 options[0]）；default===false 取 off；
    function buildDefaults() {
        const v = {}
        let nOn = 0, nOff = 0
        for (let i = 0; i < settings.length; i++) {
            const s = settings[i]
            if (s.default === true) {
                v[s.id] = (s.on !== undefined && s.on !== null) ? String(s.on)
                        : ((s.options && s.options.length) ? String(s.options[0]) : "")
                if (v[s.id] !== "") nOn++
            } else if (s.default === false) {
                v[s.id] = (s.off !== undefined && s.off !== null) ? String(s.off) : "0"
                nOff++
            }
        }
        return { values: v, on: nOn, off: nOff }
    }

    // ═══ 三种形态 ═══════════════════════════════════════════════════════════
    readonly property var formRelease: [          // ③ 解锁使用：解除"挡人操作"的禁用
        "taskmgr_off", "regedit_off", "controlpanel_off", "cmd_off", "run_dialog_off",
        "rdp_off", "remote_registry_off", "usbstor_off", "spooler_off", "bluetooth_off"
    ]
    //   llmnr_off / smb1_off / wpad_off / wdigest_off / lsa_ppl_on / lm_compat_level /
    //   restrict_anonymous / everyone_anon_off / wsh_off / 隐私 9 项

    readonly property var formAssets: ({          // 形态携带的资产（按需 ）
        locked:    ["admin_mode_off", "daily_demote", "gate_rotate_arm", "desk_pw_off", "autorun_harden", "ps_v2_disable", "ensure_dirs"],
        tempadmin: ["daily_promote", "gate_rotate_arm", "autorun_harden", "ensure_dirs"],   // 去掉 admin_mode_off：提升权限与权限回收不能同框 
        open:      ["admin_mode_off", "gate_rotate_arm", "autorun_harden", "ensure_dirs"],
        openadmin: ["daily_promote", "gate_rotate_arm", "autorun_harden", "ensure_dirs"]
    })

    function buildForm(kind) {
        const v = {}
        for (let i = 0; i < settings.length; i++) {
            const s = settings[i]
            if (s.default === true) {
                v[s.id] = (s.on !== undefined && s.on !== null) ? String(s.on)
                        : ((s.options && s.options.length) ? String(s.options[0]) : "")
            }
        }
        const uiOn = (kind !== "open")
        for (let i = 0; i < settings.length; i++) {
            const s = settings[i]
            if (s.default === false) {
                v[s.id] = uiOn ? ((s.on !== undefined && s.on !== null) ? String(s.on) : "1")
                               : ((s.off !== undefined && s.off !== null) ? String(s.off) : "0")
            }
        }
        for (let k = 0; k < formRelease.length; k++) {
            const id = formRelease[k]
            if (id === "taskmgr_off" || id === "regedit_off" || id === "controlpanel_off" ||
                id === "cmd_off" || id === "run_dialog_off") continue      // 已在 ② 处理 
            let s = null
            for (let i = 0; i < settings.length; i++) if (settings[i].id === id) { s = settings[i]; break }
            if (!s) continue
            if (kind === "open") {
                v[id] = (s.off !== undefined && s.off !== null) ? String(s.off) : "2"
            } else {
                v[id] = (s.on !== undefined && s.on !== null) ? String(s.on) : "4"
            }
        }
        return v
    }

    function applyForm(kind) {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        const v = buildForm(kind)
        const send = {}
        let n = 0
        for (const k in v) if (v[k] !== "") { send[k] = v[k]; n++ }
        if (n === 0) { status = "形态为空，先点「刷新」拉清单"; return }
        let rev = "?"
        try {
            const r = JSON.parse(api.post("/api/policies/apply",
                JSON.stringify({ hwid: hwid, values: send })))
            if (r.error !== undefined) { status = "下发失败：" + r.error; return }
            rev = r.rev
        } catch (e) { status = "下发失败：返回不是合法 JSON"; return }
        values = v
        const gs = []
        for (let i = 0; i < grouped.length; i++) gs.push({ group: grouped[i].group, items: grouped[i].items })
        grouped = gs
        const list = formAssets[kind] || []
        let nA = 0
        for (let i = 0; i < list.length; i++) {
            try {
                api.post("/api/policies/apply", JSON.stringify({ hwid: hwid, asset: list[i] }))
                nA++
            } catch (e) { }
        }
        const nm = (kind === "locked") ? "一键锁死" : (kind === "tempadmin" ? "临时开放管理员" : (kind === "openadmin" ? "兼容模式" : "解锁使用"))
        const acc = (kind === "locked") ? "；日常账号恢复为标准用户" :
                    (kind === "tempadmin" ? "；日常账号已临时授予管理员（动态密码仍生效 ）" : "")
        syncValues()   //  形态下发后同步开关（含资产造成的变更 ）
        status = "「" + nm + "」已下发 " + n + " 个值 + " + nA + " 个资产" + acc +
                 "，rev=" + rev + "；受管端下一轮收敛，之后仍按值校验、乱改会被自动改回 "
    }

    // ═══ 与服务端"当前已下发值"同步 ═══════════════════════════════════════
    function syncValues() {
        if (!hwid) return
        let cur = {}
        try {
            const c = JSON.parse(api.get("/api/policies/current?hwid=" + hwid))
            cur = c.values || {}
        } catch (e) { return }
        const v = {}
        for (let i = 0; i < settings.length; i++) {
            const s = settings[i]
            if (cur[s.id] !== undefined && cur[s.id] !== "") {
                v[s.id] = String(cur[s.id])          // 服务端说了算 
            } else if (values[s.id] !== undefined) {
                v[s.id] = values[s.id]               // 没下发过的，保留界面现状 
            }
        }
        values = v
        const gs = []
        for (let i = 0; i < grouped.length; i++) gs.push({ group: grouped[i].group, items: grouped[i].items })
        grouped = gs
        refreshConv()
    }

    property bool showAdvanced: false

    // 为什么（2026-10-10 用户反馈）：像 autorun_harden / daily_demote 这些「一键锁死」本来就会下发，
    readonly property var standaloneAssets: {
        const out = []
        for (let i = 0; i < assets.length; i++) {
            if (!assets[i].form_only) out.push(assets[i])
        }
        return out
    }

    function applyFormPack(kind, packId) {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        let rev = "?"
        try {
            const r = JSON.parse(api.post("/api/policies/apply",
                JSON.stringify({ hwid: hwid, pack: packId })))
            if (r.error !== undefined) { status = "下发失败：" + r.error; return }
            rev = r.rev
        } catch (e) { status = "下发失败：返回不是合法 JSON"; return }
        const list = formAssets[kind] || []
        let nA = 0
        for (let i = 0; i < list.length; i++) {
            try {
                api.post("/api/policies/apply", JSON.stringify({ hwid: hwid, asset: list[i] }))
                nA++
            } catch (e) { }
        }
        syncValues()   //  同步开关（否则保存会把效果推回去 ）
        const nm = (kind === "locked") ? "一键锁死" : (kind === "tempadmin" ? "临时开放管理员" : "解锁使用")
        const acc = (kind === "locked") ? "；日常账号已收回管理员" :
                    (kind === "tempadmin" ? "；日常账号已临时授予管理员（动态密码仍生效 ）" :
                    (kind === "openadmin" ? "；已进入兼容模式：常驻管理员 + 提升权限只需点同意 " : ""))
        status = "「" + nm + "」已下发（服务端 pack ）+ " + nA + " 个资产" + acc +
                 "，rev=" + rev + "；受管端下一轮收敛，之后仍按值校验、乱改会被自动改回 "
    }

    function resetAll() {
        if (!hwid) { status = "先在左侧选一个受管端"; return }
        const d = buildDefaults()
        const v = d.values
        values = v
        const gs = []
        for (let i = 0; i < grouped.length; i++) gs.push({ group: grouped[i].group, items: grouped[i].items })
        grouped = gs
        const send = {}
        for (const k in v) if (v[k] !== "") send[k] = v[k]
        let rev = "?"
        try {
            const r = JSON.parse(api.post("/api/policies/apply",
                JSON.stringify({ hwid: hwid, values: send })))
            if (r.error !== undefined) { status = "恢复默认下发失败：" + r.error; return }
            rev = r.rev
        } catch (e) { status = "恢复默认下发失败：返回不是合法 JSON"; return }
        let nA = 0
        try {
            for (let i = 0; i < assets.length; i++) {
                if (assets[i].default === true) {
                    api.post("/api/policies/apply", JSON.stringify({ hwid: hwid, asset: assets[i].id }))
                    nA++
                }
            }
        } catch (e) { /* 单个资产失败不影响值已下发  */ }
        status = "已下发标准期望态：开 " + d.on + " 项 / 关 " + d.off + " 项，资产 " + nA +
                 " 个（含日常账号恢复为标准用户），rev=" + rev + "；受管端下一轮收敛"
    }

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
            Accessible.role: Accessible.StaticText
            Accessible.name: parent.text
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacingM
        spacing: Theme.spacingS

        // ── 顶栏 ──
        RowLayout {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            spacing: Theme.spacingS
            Text {
                text: "策略 / 设置"
                color: Theme.textPrimary
                font.pixelSize: Theme.fsTitle
                font.bold: true
                font.family: Theme.fontUI
                Accessible.role: Accessible.StaticText
                Accessible.name: "策略设置页"
            }
            Pill { text: settings.length + " 项"; tone: Theme.accent }
            Text {
                Layout.fillWidth: true
                text: polTab.status
                color: Theme.orange
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
                elide: Text.ElideRight
                Accessible.role: Accessible.StaticText
                Accessible.name: "策略页状态"
            }
            Pill {
            Pill {
                text: "已下发 " + polTab.dispatchedCount + " 项"
                tone: polTab.dispatchedCount > 0 ? Theme.green : Theme.textTertiary
            }
                text: "期望态 rev " + polTab.wantRev + "  已达成 " + polTab.haveRev
                tone: Theme.accent
            }
            Pill {
                text: polTab.convText
                tone: polTab.convTone
            }
            Button { text: "🔄 刷新"; implicitHeight: 28; Accessible.name: "刷新策略清单"
                     onClicked: polTab.refresh() }
            Button {
                text: "🔒 一键锁死"
                implicitHeight: 28
                Accessible.name: "一键锁死（整合包）"
                enabled: polTab.hwid !== ""
                onClicked: polTab.applyFormPack("locked", "form_locked")
            }
            Button {
                text: "🔓 临时开放管理员"
                implicitHeight: 28
                Accessible.name: "在锁死基础上临时开放管理员权限"
                enabled: polTab.hwid !== ""
                onClicked: polTab.applyFormPack("tempadmin", "form_tempadmin")
            }
            Button {
                text: "🧹 解锁使用"
                implicitHeight: 28
                Accessible.name: "解除界面与服务类禁用，保留隐私与期望态"
                enabled: polTab.hwid !== ""
                onClicked: polTab.applyFormPack("open", "form_open")
            }
            Button {
                text: "🔧 兼容模式"
                implicitHeight: 28
                Accessible.name: "兼容模式：解锁使用、常驻管理员、提升权限只需点同意"
                enabled: polTab.hwid !== ""
                onClicked: polTab.applyFormPack("openadmin", "form_open_admin")
            }
            Button {
                text: "💾 保存并下发"
                implicitHeight: 28
                enabled: polTab.hwid !== "" && polTab.settings.length > 0
                Accessible.name: "保存并下发策略"
                onClicked: polTab.save()
            }
        }

        Text {
            Layout.fillWidth: true
            text: " 这里显示的是【将要下发】的值，不是远端真实值 —— 读回远端真值要经受管端（下一版）。" +
                  " 下发走的是 reg 链：能被按值校验，有人改了会被自动改回。"
            color: Theme.textTertiary
            font.pixelSize: Theme.fsTiny
            font.family: Theme.fontUI
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: "策略页说明"
        }

        // ── 策略包：一键套用一组相关设置（服务端展开成同一份 .reg）──
        Flow {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            visible: polTab.packs.length > 0
            spacing: Theme.spacingXS
            Text {
                text: "策略包："
                color: Theme.textTertiary
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
                Accessible.role: Accessible.StaticText
                Accessible.name: "策略包"
            }
            Repeater {
                model: polTab.packs
                delegate: Button {
                    text: modelData.name
                    implicitHeight: 26
                    Accessible.name: "策略包 " + modelData.name
                    onClicked: polTab.applyPack(modelData.id, modelData.values)
                }
            }
        }

        // ── 策略资产：reg 表达不了的那些（服务当场停/禁用、口令策略、hosts 屏蔽）──
        // 这段是照抄上面策略包那段的写法：Flow 的子项**绝不能写 anchors**
        Flow {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            visible: polTab.standaloneAssets.length > 0
            spacing: Theme.spacingXS
            Button {
                text: (polTab.showAdvanced ? "▾ 高级资产（" : "▸ 高级资产（") + polTab.standaloneAssets.length + "）"
                visible: polTab.standaloneAssets.length > 0
                implicitHeight: 26
                Accessible.name: "展开或收起高级策略资产列表"
                onClicked: polTab.showAdvanced = !polTab.showAdvanced
            }
            Text {
                text: "策略资产："
                visible: polTab.showAdvanced
                color: Theme.textTertiary
                font.pixelSize: Theme.fsSmall
                font.family: Theme.fontUI
                Accessible.role: Accessible.StaticText
                Accessible.name: "策略资产"
            }
            Repeater {
                model: polTab.showAdvanced ? polTab.standaloneAssets : []
                delegate: Button {
                    text: modelData.name
                    implicitHeight: 26
                    Accessible.name: "策略资产 " + modelData.name
                    onClicked: polTab.applyAsset(modelData.id)
                }
            }
        }

        // ── 偏离告警条：只有真的被改过才出现 ──
        Rectangle {
            Layout.fillWidth: true
            visible: polTab.drift.length > 0
            implicitHeight: driftCol.implicitHeight + Theme.spacingS * 2
            radius: Theme.radiusM
            color: Qt.rgba(Theme.red.r, Theme.red.g, Theme.red.b, 0.10)
            border.color: Qt.rgba(Theme.red.r, Theme.red.g, Theme.red.b, 0.35)
            border.width: 1

            ColumnLayout {
                id: driftCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: Theme.spacingS
                spacing: 2
                Text {
                    text: " 受管端报告 " + polTab.drift.length + " 项配置偏离（有人改过；自愈会按值重做）"
                    color: Theme.red
                    font.pixelSize: Theme.fsSmall
                    font.bold: true
                    font.family: Theme.fontUI
                    Accessible.role: Accessible.StaticText
                    Accessible.name: "偏离告警 " + text
                }
                Repeater {
                    model: polTab.drift
                    delegate: Text {
                        Layout.fillWidth: true
                        text: "· " + modelData
                        color: Theme.textSecondary
                        font.pixelSize: Theme.fsTiny
                        font.family: Theme.fontUI
                        wrapMode: Text.WordWrap
                        Accessible.role: Accessible.StaticText
                        Accessible.name: "偏离项 " + modelData
                    }
                }
            }
        }

        // ── 分组 + 设置项 ──
        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentHeight: bodyCol.implicitHeight + 8
            clip: true

            ColumnLayout {
                id: bodyCol
                width: parent.width
                spacing: Theme.spacingS

                Repeater {
                    model: polTab.grouped
                    delegate: Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: gCol.implicitHeight + Theme.spacingM * 2
                        radius: Theme.radiusL
                        color: Theme.bgSecondary
                        border.color: Theme.cardBorder
                        border.width: 1

                        ColumnLayout {
                            id: gCol
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: Theme.spacingM
                            spacing: Theme.spacingXS

                            Text {
                                text: modelData.group
                                color: Theme.textPrimary
                                font.pixelSize: Theme.fsBody
                                font.bold: true
                                font.family: Theme.fontUI
                                Accessible.role: Accessible.StaticText
                                Accessible.name: "分组 " + modelData.group
                            }

                            Repeater {
                                model: modelData.items
                                delegate: ColumnLayout {
                                    Layout.fillWidth: true
                                    Layout.minimumWidth: 0
                                    spacing: 2

                                    RowLayout {
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        spacing: Theme.spacingS

                                        Text {
                                            Layout.preferredWidth: 190
                                            text: modelData.name
                                            color: Theme.textPrimary
                                            font.pixelSize: Theme.fsSmall
                                            font.family: Theme.fontUI
                                            elide: Text.ElideRight
                                            Accessible.role: Accessible.StaticText
                                            Accessible.name: "设置项 " + modelData.name
                                        }

                                        // ① 开关
                                        CheckBox {
                                            visible: modelData.type === "bool"
                                            text: (polTab.values[modelData.id] === modelData.on) ? "开" : "关"
                                            checked: polTab.values[modelData.id] === modelData.on
                                            Accessible.name: modelData.name + " 开关 " + text
                                            onToggled: polTab.setValue(modelData.id, checked ? modelData.on : modelData.off)
                                        }

                                        // ② 下拉（固定几项）
                                        ComboBox {
                                            visible: modelData.type === "enum"
                                            Layout.preferredWidth: 170
                                            implicitHeight: Theme.controlHeight
                                            model: modelData.options || []
                                            Accessible.name: modelData.name + " 下拉"
                                            onActivated: polTab.setValue(modelData.id, modelData.options[currentIndex])
                                        }

                                        // ③ 填数字
                                        TextField {
                                            visible: modelData.type === "int" || modelData.type === "string"
                                            Layout.preferredWidth: 140
                                            implicitHeight: Theme.controlHeight
                                            placeholderText: modelData.type === "string" ? "填文本（留空=不改）" : "留空=不改"
                                            text: polTab.values[modelData.id] || ""
                                            Accessible.name: modelData.name + " 数值"
                                            // 只在"真的不一样"时才回推 —— 无条件下推就是绑定环的成因
                                            onTextChanged: {
                                                if ((polTab.values[modelData.id] || "") !== text)
                                                    polTab.setValue(modelData.id, text)
                                            }
                                        }

                                        Pill {
                                            text: modelData.hive + "\\" + String(modelData.value)
                                            tone: Theme.textTertiary
                                        }
                                        // 删键：值置为 "-"，服务端生成 `"Name"=-`（.reg 的删除语义）。
                                        // 受管端侧的校验已经支持它（期望"这个值不存在"），所以删除也会被自愈照看。
                                        Button {
                                            text: polTab.values[modelData.id] === "-" ? "将删除" : "删除此键"
                                            implicitHeight: 24
                                            Accessible.name: "删除 " + modelData.name + " 注册表值"
                                            onClicked: polTab.setValue(modelData.id, polTab.values[modelData.id] === "-" ? "" : "-")
                                        }
                                        Item { Layout.fillWidth: true }
                                    }

                                    Text {
                                        Layout.fillWidth: true
                                        visible: polTab.showNotes && (modelData.note || "") !== ""
                                        text: modelData.note || ""
                                        color: Theme.textTertiary
                                        font.pixelSize: Theme.fsTiny
                                        font.family: Theme.fontUI
                                        wrapMode: Text.WordWrap
                                        Accessible.role: Accessible.StaticText
                                        Accessible.name: "说明 " + (modelData.note || "")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3 秒自动刷新收敛状态：这是"看得见它在同步"的关键。
    // 只读两个轻量接口（/api/desired、/api/agents），不触发任何下发动作。
    Timer {
        interval: 3000
        running: polTab.hwid !== "" && polTab.convLive
        repeat: true
        onTriggered: polTab.refreshConv()
    }


    onHwidChanged: refresh()
}

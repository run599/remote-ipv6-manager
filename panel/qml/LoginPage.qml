import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ui

// ═══════════════════════════════════════════════════════════════════════════
// LoginPage —— 左品牌栏 + 右表单的浮层卡片
//
// 布局改为左右分栏的原因：原来是一个 420x520 的单列居中小卡片，标题、Logo、
// 三个输入框、按钮全挤在一列里，垂直方向留白和层级都做不出来 —— 这是"看着一般"
// 的主要来源。分栏后形成"品牌区 / 表单区"两块，视觉重量有了对比。
//
// 阴影不用 MultiEffect（会引入未部署的 QML 模块，加载失败就是整页空白），
// 改成卡背面叠几层递减透明度的圆角描边，效果够用且零依赖。
// ═══════════════════════════════════════════════════════════════════════════

Item {
    id: loginPage
    signal loginSuccess(string url, string cookie)

    property string statusText: ""
    property bool loading: false

    // ═══ 内联组件：统一样式的"标签 + 输入框" ═══
    // 必须声明在**文档顶层**：放进布局里会被 QML 当成普通子项，直接语法报错
    component Field: ColumnLayout {
        property alias label: lbl.text
        property alias input: field
        Layout.fillWidth: true
        spacing: Theme.spacingXS
        Text {
            id: lbl
            color: Theme.textSecondary
            font.pixelSize: Theme.fsSmall
            font.bold: true
            font.family: Theme.fontUI
        }
        TextField {
            id: field
            Layout.fillWidth: true
            Layout.preferredHeight: 40
            color: Theme.textPrimary
            placeholderTextColor: Theme.textTertiary
            font.pixelSize: Theme.fsBody
            font.family: Theme.fontUI
            leftPadding: Theme.spacingM
            rightPadding: Theme.spacingM
            background: Rectangle {
                radius: Theme.radiusM
                color: Theme.bgElevated
                border.width: field.activeFocus ? 2 : 1
                border.color: field.activeFocus ? Theme.accent : Theme.cardBorder
                Behavior on border.color {
                    ColorAnimation { duration: Theme.durFast }
                }
            }
        }
    }

    // ── 背景：底色 + 两团弥散光斑，给暗色底一点"空间感" ──
    Rectangle { anchors.fill: parent; color: Theme.bgPrimary }

    Rectangle {
        width: 620; height: 620; radius: 310
        x: parent.width * 0.12 - width * 0.5
        y: parent.height * 0.30 - height * 0.5
        color: Theme.accent
        opacity: Theme.dark ? 0.10 : 0.07
    }
    Rectangle {
        width: 520; height: 520; radius: 260
        x: parent.width * 0.92 - width * 0.5
        y: parent.height * 0.78 - height * 0.5
        color: Theme.brand2
        opacity: Theme.dark ? 0.10 : 0.06
    }

    // ── 卡片 ──
    Rectangle {
        id: card
        anchors.centerIn: parent
        width: 860; height: 520
        radius: Theme.radiusXL
        color: Theme.bgSecondary
        border.color: Theme.cardBorder
        border.width: 1

        // 叠层阴影
        Repeater {
            model: Theme.shadowLayers
            Rectangle {
                anchors.fill: card
                anchors.margins: -(index + 1) * 3
                radius: card.radius + (index + 1) * 3
                color: "transparent"
                border.width: 3
                border.color: Qt.rgba(0, 0, 0, Theme.shadowOpacity * 0.22 / (index + 1))
                z: -1
            }
        }

        RowLayout {
            anchors.fill: parent
            spacing: 0

            // ═══ 左：品牌区 ═══
            Rectangle {
                Layout.preferredWidth: 340
                Layout.fillHeight: true
                radius: card.radius
                gradient: Gradient {
                    orientation: Gradient.Vertical
                    GradientStop { position: 0.0; color: Theme.accent }
                    GradientStop { position: 1.0; color: Theme.brand2 }
                }

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: Theme.spacingXXL
                    spacing: Theme.spacingL

                    Item { Layout.preferredHeight: Theme.spacingS }

                    // Logo 方块
                    Rectangle {
                        Layout.preferredWidth: 56; Layout.preferredHeight: 56
                        radius: Theme.radiusL
                        color: Qt.rgba(1, 1, 1, 0.20)
                        border.color: Qt.rgba(1, 1, 1, 0.35)
                        Text {
                            anchors.centerIn: parent
                            text: "⌘"; color: "white"
                            font.pixelSize: 28; font.bold: true
                        }
                    }

                    Text {
                        text: panelTitle
                        color: "white"
                        font.pixelSize: Theme.fsDisplay
                        font.bold: true
                        font.family: Theme.fontUI
                    }
                    Text {
                        text: panelConsoleLabel
                        color: Qt.rgba(1, 1, 1, 0.82)
                        font.pixelSize: Theme.fsBody
                        font.family: Theme.fontUI
                    }

                    Item { Layout.preferredHeight: Theme.spacingS }

                    // 特性列表（替代原来挤在底部的技术标签）
                    Repeater {
                        model: [
                            { t: "IPv6 直连", d: "无需端口映射" },
                            { t: "端到端加密", d: "证书标识固定" },
                            { t: "插件化工具", d: "MCP 协议中继" }
                        ]
                        delegate: RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.spacingS
                            Rectangle {
                                Layout.preferredWidth: 18; Layout.preferredHeight: 18
                                radius: 9
                                color: Qt.rgba(1, 1, 1, 0.22)
                                Text {
                                    anchors.centerIn: parent
                                    text: ""; color: "white"; font.pixelSize: 11; font.bold: true
                                }
                            }
                            ColumnLayout {
                                spacing: 0
                                Text {
                                    text: modelData.t; color: "white"
                                    font.pixelSize: Theme.fsBody; font.bold: true
                                    font.family: Theme.fontUI
                                }
                                Text {
                                    text: modelData.d; color: Qt.rgba(1, 1, 1, 0.72)
                                    font.pixelSize: Theme.fsTiny
                                    font.family: Theme.fontUI
                                }
                            }
                        }
                    }

                    Item { Layout.fillHeight: true }
                }
            }

            // ═══ 右：表单区 ═══
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.margins: Theme.spacingXXL
                spacing: Theme.spacingM

                Text {
                    text: "登录"
                    color: Theme.textPrimary
                    font.pixelSize: Theme.fsTitle + 3
                    font.bold: true
                    font.family: Theme.fontUI
                }
                Text {
                    text: "连接到远程管理服务端"
                    color: Theme.textSecondary
                    font.pixelSize: Theme.fsBody
                    font.family: Theme.fontUI
                }

                Item { Layout.preferredHeight: Theme.spacingS }

                Field {
                    id: urlField
                    label: "服务器地址"
                    input.placeholderText: "https://[::1]:8443"
                    // 优先用上次登录成功保存的地址；没有才用这个内置默认值。
                    // （原来这里的注释写着"登录成功后会记住本次输入"，但代码里
                    //   根本没有自启动配置 —— 注释承诺了没做的事，这次真做了。）
                    input.text: api.savedServer().length > 0
                                ? api.savedServer() : "https://192.168.1.10:8443"
                }
                Field {
                    id: userField
                    label: "用户名"
                    input.placeholderText: "admin"
                    input.text: api.savedUser().length > 0 ? api.savedUser() : "admin"
                }
                Field {
                    id: passField
                    label: "密码"
                    input.placeholderText: "••••••••"
                    input.echoMode: TextInput.Password
                    // 记住过就直接填好 —— 这串口令是 24 位随机串，每次手输必然出错
                    input.text: api.savedPass()
                }

                // 记住密码 + 显示密码。
                // "显示"不是花哨功能：口令大小写混合且长，打错了却看不出来，
                // 只会得到一句"密码不正确"。
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacingS
                    CheckBox {
                        id: rememberBox
                        text: "记住密码（本机加密保存）"
                        checked: api.savedPass().length > 0
                        font.pixelSize: Theme.fsSmall
                        Accessible.name: "记住密码"
                    }
                    Item { Layout.fillWidth: true }
                    Button {
                        implicitHeight: 28
                        text: passField.input.echoMode === TextInput.Password ? "👁 显示" : "🙈 隐藏"
                        Accessible.name: "切换密码可见"
                        onClicked: passField.input.echoMode =
                            (passField.input.echoMode === TextInput.Password)
                                ? TextInput.Normal : TextInput.Password
                    }
                }

                Item { Layout.preferredHeight: Theme.spacingXS }

                // 登录按钮
                Button {
                    id: loginBtn
                    Layout.fillWidth: true
                    Layout.preferredHeight: 44
                    enabled: !loginPage.loading
                    text: loginPage.loading ? "连接中..." : "登  录"

                    background: Rectangle {
                        radius: Theme.radiusM
                        gradient: Gradient {
                            GradientStop {
                                position: 0.0
                                color: loginBtn.down ? Theme.accentPress
                                                     : (loginBtn.hovered ? Theme.accentHover : Theme.accent)
                            }
                            GradientStop {
                                position: 1.0
                                color: loginBtn.down ? Qt.darker(Theme.accentPress, 1.1)
                                                     : Qt.darker(Theme.accent, 1.12)
                            }
                        }
                        opacity: loginBtn.enabled ? 1.0 : 0.55
                        Behavior on opacity { NumberAnimation { duration: Theme.durFast } }
                    }
                    contentItem: Text {
                        text: loginBtn.text
                        color: Theme.textOnAccent
                        font.pixelSize: Theme.fsBody + 1
                        font.bold: true
                        font.family: Theme.fontUI
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    onClicked: loginPage.doLogin()
                }

                // 状态行：成功/失败用语义色，带一点淡底更醒目
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 34
                    visible: loginPage.statusText.length > 0
                    radius: Theme.radiusS
                    color: loginPage.statusText.indexOf("") === 0 ? Theme.greenSoft : Theme.orangeSoft
                    Text {
                        anchors.centerIn: parent
                        text: loginPage.statusText
                        color: loginPage.statusText.indexOf("") === 0 ? Theme.green : Theme.red
                        font.pixelSize: Theme.fsSmall
                        font.family: Theme.fontUI
                    }
                    // 错误提示必须能被无障碍读到：纯 Text 不进 UIA 树，
                    // 读屏用户与自动化都拿不到"到底为什么失败"。
                    Accessible.role: Accessible.StaticText
                    Accessible.name: loginPage.statusText
                }

                Item { Layout.fillHeight: true }

                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "C++ Qt6 · IPv6 Direct · MCP Plugin"
                    color: Theme.textTertiary
                    font.pixelSize: Theme.fsTiny
                    font.family: Theme.fontUI
                }
            }
        }
    }

    function doLogin() {
        loginPage.loading = true
        loginPage.statusText = ""
        api.serverUrl = urlField.input.text
        api.login(userField.input.text, passField.input.text)
        loginPage.loading = false
        // 判据用 ApiClient 维护的权威状态，不再靠匹配服务端 JSON 的字节形态
        // （字段顺序/空格一变就会把成功判成失败）
        if (api.connected) {
            loginPage.statusText = " 连接成功"
            // 登录成功才保存（失败时不落盘，避免把错口令记住）
            api.saveCreds(urlField.input.text, userField.input.text,
                          passField.input.text, rememberBox.checked)
            // 注意：ApiClient 现在真的暴露了 cookie 属性；
            // 导致登录后四个页签全部在无凭据请求、界面永远为空。
            loginPage.loginSuccess(urlField.input.text, api.cookie)
        } else if (api.lastError.length > 0) {
            // 把服务端原话带出来，并给"口令打错"这个最常见原因一个可操作提示 ——
            // 原来只有一句笼统的失败文案，用户无从判断是打错了还是地址错了。
            var hint = ""
            var low = api.lastError.toLowerCase()
            if (low.indexOf("credential") >= 0 || low.indexOf("unauthorized") >= 0 ||
                api.lastError.indexOf("密码") >= 0 || api.lastError.indexOf("口令") >= 0) {
                hint = "（口令区分大小写；点右边「👁 显示」核对一下，或勾选「记住密码」下次自动填好）"
            }
            loginPage.statusText = " " + api.lastError + hint
        } else {
            loginPage.statusText = " 登录失败：连不上服务端，请检查地址与端口"
        }
    }
}

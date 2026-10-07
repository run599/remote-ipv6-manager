import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import C2Panel

Item {
    id: loginPage
    signal loginSuccess(string url, string cookie)

    property string statusText: ""
    property bool loading: false

    // 居中卡片
    Rectangle {
        anchors.centerIn: parent
        width: 420; height: 520
        color: Theme.bgSecondary
        radius: Theme.radiusL

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 40
            spacing: Theme.spacingL

            Item { Layout.preferredHeight: 20 }

            // Logo
            Rectangle {
                Layout.alignment: Qt.AlignHCenter
                width: 64; height: 64; radius: 32
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Theme.accent }
                    GradientStop { position: 1.0; color: "#5856D6" }
                }
                Text {
                    anchors.centerIn: parent
                    text: "⌘"; font.pixelSize: 32; font.bold: true; color: "white"
                }
            }

            // 标题
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "C2 Panel"; font.pixelSize: 24; font.bold: true
                color: Theme.textPrimary
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "远程管理控制台"; font.pixelSize: 14
                color: Theme.textSecondary
            }

            Item { Layout.preferredHeight: 10 }

            // 服务器地址
            ColumnLayout {
                Layout.fillWidth: true; spacing: 4
                Text { text: "服务器地址"; font.pixelSize: 12; font.bold: true; color: Theme.textSecondary }
                TextField {
                    id: urlInput
                    Layout.fillWidth: true; placeholderText: "https://[::1]:8443"
                    text: "https://[2001:db8:YOUR-SERVER-IPv6-HERE]:8443"
                    font.pixelSize: 14
                }
            }

            // 用户名
            ColumnLayout {
                Layout.fillWidth: true; spacing: 4
                Text { text: "用户名"; font.pixelSize: 12; font.bold: true; color: Theme.textSecondary }
                TextField {
                    id: userInput
                    Layout.fillWidth: true; placeholderText: "admin"
                    text: "admin"; font.pixelSize: 14
                }
            }

            // 密码
            ColumnLayout {
                Layout.fillWidth: true; spacing: 4
                Text { text: "密码"; font.pixelSize: 12; font.bold: true; color: Theme.textSecondary }
                TextField {
                    id: passInput
                    Layout.fillWidth: true; placeholderText: "••••••••"
                    echoMode: TextInput.Password; font.pixelSize: 14
                }
            }

            Item { Layout.preferredHeight: 8 }

            // 登录按钮
            Button {
                id: loginBtn
                Layout.fillWidth: true; Layout.preferredHeight: 44
                text: loginPage.loading ? "连接中..." : "登  录"
                enabled: !loginPage.loading
                background: Rectangle {
                    radius: Theme.radiusS
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: loginBtn.down ? "#4890CC" : "#6CB4EE" }
                        GradientStop { position: 1.0; color: loginBtn.down ? "#0060C0" : "#0A84FF" }
                    }
                }
                contentItem: Text {
                    text: parent.text; color: "white"; font.pixelSize: 15
                    font.bold: true; horizontalAlignment: Text.AlignHCenter
                }
                onClicked: loginPage.doLogin()
            }

            // 状态
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: loginPage.statusText
                color: loginPage.statusText.includes("✓") ? Theme.green : Theme.red
                font.pixelSize: 12
                opacity: text.length > 0 ? 1 : 0
            }

            Item { Layout.fillHeight: true }

            // 底部技术标签
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "C++ Qt6 · IPv6 Direct · MCP Plugin"
                font.pixelSize: 11; color: Theme.textTertiary
            }
        }
    }

    function doLogin() {
        loginPage.loading = true
        loginPage.statusText = ""
        api.serverUrl = urlInput.text
        api.login(userInput.text, passInput.text)
        loginPage.loading = false
        // 判据用 ApiClient 维护的权威状态，不再靠匹配服务端 JSON 的字节形态
        // （字段顺序/空格一变就会把成功判成失败）
        if (api.connected) {
            loginPage.statusText = "✓ 连接成功"
            // 注意：ApiClient 现在真的暴露了 cookie 属性；
            // 原实现读的是不存在的属性（undefined → 空串），
            // 导致登录后四个页签全部在无凭据请求、界面永远为空。
            loginPage.loginSuccess(urlInput.text, api.cookie)
        } else if (api.lastError.length > 0) {
            loginPage.statusText = "✗ " + api.lastError
        } else {
            loginPage.statusText = "✗ 登录失败，请检查地址和密码"
        }
    }
}

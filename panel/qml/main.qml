import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

Window {
    id: root
    visible: true
    width: 1400; height: 900
    title: "C2 Panel"
    color: "#F5F5F7"

    property bool loggedIn: false
    property string serverUrl: ""
    property string cookie: ""

    LoginPage {
        anchors.fill: parent
        visible: !root.loggedIn
        onLoginSuccess: function(url, ck) {
            root.serverUrl = url
            root.cookie = ck
            root.loggedIn = true
            agentModel.refresh()
        }
    }

    MainPage {
        anchors.fill: parent
        visible: root.loggedIn
        serverUrl: root.serverUrl
        cookie: root.cookie
    }
}

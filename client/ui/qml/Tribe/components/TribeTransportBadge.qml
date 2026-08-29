import QtQuick

import ".." // Theme

// Displays runtime fact, never the preferred mode. Green is reserved for a
// cryptographically verified DNS+traffic receipt.
Rectangle {
    id: root

    property string transport: "none" // none | awg | xray
    property string verification: "idle" // idle | starting | dns | traffic | verified | unknown | failed
    property bool compact: false
    property string awgLabel: qsTr("AWG")
    property string xrayLabel: qsTr("Xray")

    readonly property bool verified: verification === "verified"
    readonly property bool warning: verification === "starting"
                                    || verification === "dns"
                                    || verification === "traffic"
                                    || verification === "unknown"
    readonly property bool failed: verification === "failed"
    readonly property string transportLabel: transport === "awg" ? awgLabel
                                                   : (transport === "xray" ? xrayLabel
                                                                           : qsTr("Нет соединения"))
    readonly property string stateLabel: verified ? qsTr("проверено")
                                       : (verification === "unknown" ? qsTr("проверка недоступна")
                                       : (verification === "dns" || verification === "traffic"
                                              ? qsTr("проверяем")
                                       : (verification === "starting" ? qsTr("запускаем")
                                       : (failed ? qsTr("ошибка") : ""))))

    implicitHeight: compact ? 25 : 30
    implicitWidth: content.implicitWidth + 2 * (compact ? Theme.space.sm : Theme.space.md)
    radius: Theme.radius.pill
    color: verified ? Theme.color.badgeOn
                    : (warning ? Theme.color.badgeWarn
                               : (failed ? Theme.color.badgeOff : Theme.color.glass))
    border.width: 1
    border.color: verified ? Theme.color.connected
                           : (warning ? Theme.color.warning
                                      : (failed ? Theme.color.danger : Theme.color.border2))
    Accessible.role: Accessible.StaticText
    Accessible.name: contentLabel.text

    Row {
        id: content
        anchors.centerIn: parent
        spacing: Theme.space.sm

        Rectangle {
            anchors.verticalCenter: parent.verticalCenter
            width: root.compact ? 6 : 7
            height: width
            radius: width / 2
            color: root.verified ? Theme.color.connected
                                 : (root.warning ? Theme.color.warning
                                                 : (root.failed ? Theme.color.danger
                                                                : Theme.color.text3))
        }

        Text {
            id: contentLabel
            anchors.verticalCenter: parent.verticalCenter
            text: root.stateLabel.length > 0
                    ? qsTr("%1 · %2").arg(root.transportLabel).arg(root.stateLabel)
                    : root.transportLabel
            textFormat: Text.PlainText
            color: root.verified ? Theme.color.connected
                                 : (root.warning ? Theme.color.warning
                                                 : (root.failed ? Theme.color.danger
                                                                : Theme.color.text2))
            font.family: Theme.font.body
            font.pixelSize: root.compact ? Theme.font.caption - 1 : Theme.font.caption
            font.weight: Theme.font.wBold
        }
    }
}

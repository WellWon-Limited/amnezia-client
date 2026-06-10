import QtQuick

import ".."   // Theme

// AVPN: status badge with dot. variant: "on" | "warn" | "off" | "neutral".
Rectangle {
    id: badge
    property string variant: "on"
    property string text: ""

    readonly property color _fg: variant === "on" ? Theme.color.connected
        : variant === "warn" ? Theme.color.warning
        : variant === "off" ? Theme.color.danger
        : Theme.color.text2
    readonly property color _bg: variant === "on" ? Theme.color.badgeOn
        : variant === "warn" ? Theme.color.badgeWarn
        : variant === "off" ? Theme.color.badgeOff
        : Theme.color.glass

    implicitHeight: 24
    implicitWidth: row.implicitWidth + 2 * Theme.space.md
    radius: Theme.radius.pill
    color: _bg

    Row {
        id: row
        anchors.centerIn: parent
        spacing: Theme.space.sm
        Rectangle {
            width: 7; height: 7; radius: 3.5
            anchors.verticalCenter: parent.verticalCenter
            color: badge._fg
        }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: badge.text
            color: badge._fg
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
        }
    }
}

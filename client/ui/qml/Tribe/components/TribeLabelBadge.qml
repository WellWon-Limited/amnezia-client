import QtQuick

import ".."   // Theme

// Outlined label badge whose colour carries the meaning (owner, test of 5.1.102, 2026-11-05):
// ONLINE (Theme.color.connected — the data check through the exit passed) and the active protocol
// on the Connect card (Amnezia — accent, Xray Reality — Theme.color.xray). The caller passes the
// token pair (fg + its alpha fill); `small` is the dense variant for the server-list rows.
Rectangle {
    id: badge

    property string label: ""
    property color fg: Theme.color.accent
    property color fill: Theme.color.badgeAccent
    property bool small: false

    implicitHeight: small ? 15 : 17
    implicitWidth: badgeText.implicitWidth + 2 * (small ? Theme.space.xs + 2 : Theme.space.sm)
    radius: Theme.radius.pill
    color: badge.fill
    border.width: 1
    border.color: badge.fg

    Accessible.role: Accessible.StaticText
    Accessible.name: badge.label

    Text {
        id: badgeText
        anchors.centerIn: parent
        text: badge.label
        textFormat: Text.PlainText
        color: badge.fg
        font.family: Theme.font.body
        font.pixelSize: badge.small ? Theme.font.caption - 2 : Theme.font.caption - 1
        font.weight: Theme.font.wBold
    }
}

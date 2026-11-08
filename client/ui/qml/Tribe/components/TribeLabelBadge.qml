import QtQuick

import ".."   // Theme

// Outlined label badge whose colour carries the meaning (owner, test of 5.1.102, 2026-11-05):
// ONLINE (Theme.color.connected — data flows through the tunnel, AvpnEngineQml::dataFlowing) and the
// protocol under the node name on the Connect card (Amnezia — accent, Xray Reality — Theme.color.xray). The caller passes the
// token pair (fg + its alpha fill); `small` is the dense variant for the server-list rows.
Rectangle {
    id: badge

    property string label: ""
    property color fg: Theme.color.accent
    property color fill: Theme.color.badgeAccent
    property bool small: false

    implicitHeight: small ? Theme.badge.heightSmall : Theme.badge.height
    implicitWidth: badgeText.implicitWidth + 2 * (small ? Theme.badge.padXSmall : Theme.badge.padX)
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
        font.pixelSize: badge.small ? Theme.badge.textSmall : Theme.badge.text
        font.weight: Theme.font.wBold
    }
}

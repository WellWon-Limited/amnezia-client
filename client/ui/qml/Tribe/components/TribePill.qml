import QtQuick

import ".."   // Theme

// AVPN: info pill (glass + border, optional accent dot). UI-DESIGN.md §3.
// `icon` (a TribeStrokeIcon key) replaces the dot with a 14 px stroke icon in text2 - the Scanner's status chips
// in the corners of the radar block (owner 18.11): last check «только что» (clock) and the network (wifi / cellular).
Rectangle {
    id: pill
    property string text: ""
    property bool showDot: true
    property string icon: ""

    implicitHeight: 30
    implicitWidth: row.implicitWidth + 2 * Theme.space.md
    radius: Theme.radius.pill
    color: Theme.color.glass
    border.width: 1
    border.color: Theme.color.border

    Accessible.role: Accessible.StaticText
    Accessible.name: pill.text

    Row {
        id: row
        anchors.centerIn: parent
        spacing: pill.icon !== "" ? 6 : Theme.space.sm
        Rectangle {
            visible: pill.showDot && pill.icon === ""
            width: 7; height: 7; radius: 3.5
            anchors.verticalCenter: parent.verticalCenter
            color: Theme.color.accent
        }
        TribeStrokeIcon {
            visible: pill.icon !== ""
            width: 14; height: 14
            anchors.verticalCenter: parent.verticalCenter
            icon: pill.icon
            tint: Theme.color.text2
            weight: 2
        }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: pill.text
            textFormat: Text.PlainText
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: pill.icon !== "" ? Theme.font.caption : Theme.font.monoData
            font.weight: pill.icon !== "" ? Theme.font.wSemibold : Theme.font.wRegular
        }
    }
}

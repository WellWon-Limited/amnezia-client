import QtQuick

import ".."   // Theme

// AVPN: info pill (glass + border, optional accent dot). UI-DESIGN.md §3.
Rectangle {
    id: pill
    property string text: ""
    property bool showDot: true

    implicitHeight: 30
    implicitWidth: row.implicitWidth + 2 * Theme.space.md
    radius: Theme.radius.pill
    color: Theme.color.glass
    border.width: 1
    border.color: Theme.color.border

    Row {
        id: row
        anchors.centerIn: parent
        spacing: Theme.space.sm
        Rectangle {
            visible: pill.showDot
            width: 7; height: 7; radius: 3.5
            anchors.verticalCenter: parent.verticalCenter
            color: Theme.color.accent
        }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: pill.text
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.monoData
        }
    }
}

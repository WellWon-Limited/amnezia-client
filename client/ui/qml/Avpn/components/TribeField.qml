import QtQuick
import QtQuick.Controls

import ".."   // Theme

// AVPN: text field. surface1 + border, r-sm; focus → accent + ring. UI-DESIGN.md §3.
TextField {
    id: control
    implicitHeight: 46
    leftPadding: Theme.space.lg
    rightPadding: Theme.space.lg
    color: Theme.color.text1
    placeholderTextColor: Theme.color.text3
    font.family: Theme.font.body
    font.pixelSize: Theme.font.bodyS
    selectByMouse: true
    selectionColor: Theme.color.accentDeep

    property bool error: false

    background: Rectangle {
        radius: Theme.radius.sm
        color: Theme.color.surface1
        border.width: control.activeFocus ? 2 : 1
        border.color: control.error ? Theme.color.danger
                    : control.activeFocus ? Theme.color.accent
                    : Theme.color.border
        Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

        // focus ring
        Rectangle {
            anchors.fill: parent
            anchors.margins: -3
            radius: parent.radius + 3
            color: "transparent"
            border.width: 3
            border.color: Theme.color.focusRing
            visible: control.activeFocus && !control.error
        }
    }
}

import QtQuick
import QtQuick.Controls

import ".."   // Theme

// AVPN: switch. 46×26, off surface3 → on accent, knob 20.
Switch {
    id: control
    implicitWidth: 46
    implicitHeight: 26

    indicator: Rectangle {
        width: control.width; height: control.height
        radius: height / 2
        color: control.checked ? Theme.color.accent : Theme.color.surface3
        Behavior on color { ColorAnimation { duration: 180 } }

        Rectangle {
            width: 20; height: 20; radius: 10
            color: "white"
            y: 3
            x: control.checked ? control.width - width - 3 : 3
            Behavior on x { NumberAnimation { duration: 180; easing.type: Easing.OutCubic } }
        }
    }
    contentItem: Item {}   // label handled externally (in list rows)
}

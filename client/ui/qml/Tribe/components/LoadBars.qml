import QtQuick

import ".."   // Theme

// AVPN: node load/quality indicator — 4 bars. level 0..4 active. UI-DESIGN.md §3.
Row {
    id: bars
    property int level: 3        // 0..4 active bars
    property color barColor: Theme.color.accent
    spacing: 3

    Repeater {
        model: 4
        delegate: Rectangle {
            width: 4
            height: 6 + index * 3.3      // 6,9,12,16 (rising)
            radius: 1
            anchors.bottom: parent ? undefined : undefined
            y: bars.height - height       // align bottoms
            color: bars.barColor
            opacity: index < bars.level ? 1.0 : 0.35
            Behavior on opacity { NumberAnimation { duration: Theme.motion.fast } }
        }
    }
    height: 16
}

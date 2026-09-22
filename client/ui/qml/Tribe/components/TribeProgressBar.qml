import QtQuick

import ".."   // Theme

// AVPN (self-update v2): тонкая полоса прогресса. percent 0..100 — определённый прогресс;
// percent < 0 — процент неизвестен, бежит короткий сегмент (indeterminate). Единственная
// анимация — движение заливки; цвета/радиусы/длительности только из Theme.
Item {
    id: bar
    property int percent: -1
    readonly property bool indeterminate: percent < 0
    implicitHeight: 3
    height: implicitHeight

    Rectangle {
        anchors.fill: parent
        radius: Theme.radius.pill
        color: Theme.color.surface2
        clip: true

        Rectangle {
            id: fill
            height: parent.height
            radius: Theme.radius.pill
            color: Theme.color.accent
            width: bar.indeterminate ? parent.width * 0.3 : parent.width * Math.max(0, Math.min(100, bar.percent)) / 100
            x: 0
            Behavior on width { enabled: !bar.indeterminate; NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic } }

            SequentialAnimation on x {
                running: bar.indeterminate && bar.visible
                loops: Animation.Infinite
                NumberAnimation { from: -fill.width; to: bar.width; duration: Theme.motion.slow * 3; easing.type: Easing.InOutQuad }
            }
        }
    }
}

import QtQuick

import ".."   // Theme

// AVPN (self-update v2): тонкая полоса прогресса. percent 0..100 — определённый прогресс;
// percent < 0 — процент неизвестен, бежит короткий сегмент (indeterminate). Единственная
// анимация — движение заливки; цвета/радиусы/длительности только из Theme.
Item {
    id: bar
    property int percent: -1
    property int thickness: 3
    property color fillColor: Theme.color.accent
    readonly property bool indeterminate: percent < 0
    implicitHeight: thickness
    height: implicitHeight
    // Бегунок останавливается там, где застал его первый процент: без сброса определённая
    // заливка росла из середины полосы (баг 5.1.85, скриншот владельца 2026-09-23).
    onIndeterminateChanged: if (!indeterminate) fill.x = 0

    Rectangle {
        anchors.fill: parent
        radius: Theme.radius.pill
        color: Theme.color.surface2
        clip: true

        Rectangle {
            id: fill
            height: parent.height
            radius: Theme.radius.pill
            color: bar.fillColor
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

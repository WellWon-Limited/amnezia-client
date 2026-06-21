pragma ComponentBehavior: Bound

import QtQuick

import ".."   // Theme

// AVPN: индикатор качества сигнала — 5 баров. level 0..count активны (зелёные), остальные — серый трек.
// Число активных баров — ОСНОВНОЙ носитель уровня (WCAG 1.4.1: не только цветом; рядом обычно стоит
// числовой RTT). Зелёный = это статус соединения (Theme.color.connected). UI-DESIGN.md §3.
// Источник уровня — реальный app-layer RTT через туннель (TribeEngine.liveBars), см. SignalQuality.h.
Row {
    id: bars
    property int count: 5                              // всего баров
    property int level: 0                              // 0..count активных
    property bool failed: false                        // связь мертва → ВСЕ бары красные, level игнорируется
    property color barColor: Theme.color.connected     // заполненные (зелёный #41C28C)
    property color trackColor: Theme.color.text3       // пустые «серые» (#64748B)
    property color dangerColor: Theme.color.danger     // мёртвая связь (красный #E2625C)
    spacing: 3

    Repeater {
        model: bars.count
        delegate: Rectangle {
            required property int index
            readonly property bool active: index < bars.level
            width: 4
            height: 6 + index * ((16 - 6) / Math.max(1, bars.count - 1)) // 6..16; guard от count==1
            radius: 1
            y: bars.height - height                              // выравнивание по нижнему краю
            color: bars.failed ? bars.dangerColor : (active ? bars.barColor : bars.trackColor)
            opacity: bars.failed ? 1.0 : (active ? 1.0 : 0.4)
            Behavior on color   { ColorAnimation  { duration: Theme.motion.fast } }
            Behavior on opacity { NumberAnimation  { duration: Theme.motion.fast } }
        }
    }
    height: 16
}

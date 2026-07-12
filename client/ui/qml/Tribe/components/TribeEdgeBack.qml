import QtQuick

import ".."   // Haptic

// AVPN: краевой свайп слева-направо = «назад». Узкая полоса вдоль левого края поверх контента.
// РЕАЛИЗАЦИЯ ЧЕРЕЗ MouseArea + preventStealing (2026-07-11): DragHandler НЕ работал — ListView/
// Flickable отбирал жест эксклюзивным грабом при малейшей вертикальной составляющей пальца.
// preventStealing запрещает Flickable красть нажатие, начатое в краевой зоне.
Item {
    id: root

    signal triggered()

    anchors.left: parent.left
    anchors.top: parent.top
    anchors.bottom: parent.bottom
    width: 28
    z: 90

    MouseArea {
        anchors.fill: parent
        preventStealing: true
        property real startX: 0
        onPressed: function(mouse) { startX = mouse.x }
        onReleased: function(mouse) {
            if (mouse.x - startX > 60) {
                Haptic.play("selection") // AVPN (haptics): тик «назад» = тик смены вкладки
                root.triggered()
            }
        }
    }
}

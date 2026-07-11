import QtQuick

// AVPN: краевой свайп слева-направо = «назад» (жалоба 2026-07-11: жест не работал нигде,
// кроме QR-шита). Узкая полоса вдоль левого края поверх контента; жест не мешает тапам
// (target: null, порог 60px). Родитель обязан заполнять страницу.
Item {
    id: root

    signal triggered()

    anchors.left: parent.left
    anchors.top: parent.top
    anchors.bottom: parent.bottom
    width: 28
    z: 90

    DragHandler {
        target: null
        xAxis.enabled: true
        yAxis.enabled: false
        onActiveChanged: {
            if (!active && activeTranslation.x > 60)
                root.triggered()
        }
    }
}

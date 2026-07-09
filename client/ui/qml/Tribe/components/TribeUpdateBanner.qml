import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (Task 7): ненавязчивый баннер «доступно обновление» (TribeEngine.updateState === 1 —
// remote-config §Task 6, мягкая рекомендация обновиться, НЕ блокер). Дисмисс держится в памяти
// сессии (property, не Settings) — баннер вернётся при следующем запуске, если версия всё ещё
// устарела. Токены — только Theme; закрывающая иконка — inline-вектор (Lucide "x"), без эмодзи.
Item {
    id: root

    property bool dismissed: false
    readonly property bool shouldShow: (typeof TribeEngine !== "undefined")
                                        && TribeEngine.updateState === 1 && !dismissed

    visible: shouldShow
    // Item, не Layout-делегат: ширину задаёт место монтирования (anchors.left/right, как у
    // autoVpnCard на PageConnectTribe) — без предположений о родителе (Layout/Column/anchors).
    implicitHeight: shouldShow ? card.implicitHeight : 0
    height: implicitHeight
    clip: true
    Behavior on implicitHeight { NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic } }

    Rectangle {
        id: card
        width: parent.width
        implicitHeight: row.implicitHeight + 2 * Theme.space.md
        radius: Theme.radius.lg
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.border

        RowLayout {
            id: row
            anchors.left: parent.left; anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.md
            spacing: Theme.space.md

            Text {
                Layout.fillWidth: true
                text: qsTr("Доступна новая версия Tribe VPN")
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wMedium
                wrapMode: Text.WordWrap
            }

            Text {
                text: qsTr("Обновить")
                color: Theme.color.accent
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wSemibold
                MouseArea {
                    anchors.fill: parent
                    anchors.margins: -Theme.space.sm   // увеличенная зона тапа для мелкого текста
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        var url = (typeof TribeEngine !== "undefined") ? TribeEngine.storeUrl : ""
                        if (url) Qt.openUrlExternally(url)
                    }
                }
            }

            // закрыть — inline-вектор Lucide "x" (24-grid → 16px), НЕ эмодзи (правило проекта)
            Item {
                Layout.preferredWidth: 28; Layout.preferredHeight: 28
                Shape {
                    anchors.centerIn: parent
                    width: 16; height: 16
                    transform: Scale { xScale: 16 / 24; yScale: 16 / 24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M18 6 L6 18 M6 6 L18 18" }
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.dismissed = true
                }
            }
        }
    }
}

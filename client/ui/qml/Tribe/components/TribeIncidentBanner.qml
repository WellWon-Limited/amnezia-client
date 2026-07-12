import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN backend-first-3 (Task 7): incident-баннер из подписанного /v1/config — единственный
// анонимно-достижимый канал оповещения (пуш/чат требуют enrollment, конфиг доезжает всем).
// Показ: TribeEngine.incidentText непуст (strings.incident_text_<lang>, localizedOr в движке);
// тап при непустом incidentUrl открывает браузер. Дисмисса НЕТ намеренно: инцидент гасится
// сервером (PATCH client_urls incident_text=""), а не юзером. Warning-семантика — токены Theme
// (badgeWarn/warning), иконка — inline-вектор Lucide "triangle-alert" (правило: без эмодзи).
// Скрытый = implicitHeight 0 (как TribeUpdateBanner) — не двигает якорную цепочку ни на пиксель.
Item {
    id: root

    readonly property string incidentText: (typeof TribeEngine !== "undefined")
                                            ? TribeEngine.incidentText : ""
    readonly property string incidentUrl: (typeof TribeEngine !== "undefined")
                                           ? TribeEngine.incidentUrl : ""
    readonly property bool shouldShow: incidentText !== ""

    visible: shouldShow
    // Item, не Layout-делегат: ширину задаёт место монтирования (anchors.left/right, как у
    // TribeUpdateBanner на PageConnectTribe) — без предположений о родителе.
    implicitHeight: shouldShow ? card.implicitHeight : 0
    height: implicitHeight
    clip: true
    Behavior on implicitHeight { NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic } }

    Rectangle {
        id: card
        width: parent.width
        implicitHeight: row.implicitHeight + 2 * Theme.space.md
        radius: Theme.radius.lg
        color: Theme.color.badgeWarn
        border.width: 1
        border.color: Qt.alpha(Theme.color.warning, 0.35)

        RowLayout {
            id: row
            anchors.left: parent.left; anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
            spacing: Theme.space.md

            // иконка предупреждения — inline-вектор Lucide "triangle-alert" (24-grid → 18px)
            Item {
                Layout.preferredWidth: 18; Layout.preferredHeight: 18
                Layout.alignment: Qt.AlignVCenter
                Shape {
                    anchors.fill: parent
                    transform: Scale { xScale: 18 / 24; yScale: 18 / 24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.warning; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 20h16a2 2 0 0 0 1.73-2Z M12 9v4 M12 17h.01" }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                text: root.incidentText
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wMedium
                wrapMode: Text.WordWrap
            }

            // шеврон-подсказка «тапабельно» — только при непустом url (Lucide "chevron-right")
            Item {
                visible: root.incidentUrl !== ""
                Layout.preferredWidth: 16; Layout.preferredHeight: 16
                Layout.alignment: Qt.AlignVCenter
                Shape {
                    anchors.fill: parent
                    transform: Scale { xScale: 16 / 24; yScale: 16 / 24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "m9 18 6-6-6-6" }
                    }
                }
            }
        }

        MouseArea {
            anchors.fill: parent
            enabled: root.incidentUrl !== ""
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: Qt.openUrlExternally(root.incidentUrl)
        }
    }
}

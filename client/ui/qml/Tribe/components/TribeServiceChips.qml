pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: чипы «работает ли сервис через эту ноду» — узнаваемый лого + цветной статус-дот.
// Модель — TribeEngine.serviceStatus: [{key,label,state,rttMs}], state: -1 неизв / 0 заблок / 1 медленно / 2 работает.
// Замер идёт С УСТРОЙСТВА через туннель (ServiceProbe.cpp). Тап по чипу → повторная проба.
// Статус-цвета — ТОКЕНЫ Theme (connected/warning/danger/text3). Цвета ЛОГО — фирменные (бренд-исключение
// из правила «только токены», как сценические детали Connect: иначе лого нераспознаваемо). UI-DESIGN.md §3.
Row {
    id: chips
    property var model: []           // TribeEngine.serviceStatus
    signal recheck()                 // тап по чипу → перепроверить
    spacing: Theme.space.sm
    // AVPN: ВСЕ чипы в ОДНУ строку — делим ширину поровну (не Flow с переносом), чтобы три сервиса
    // всегда влезали в один ряд на любом экране; лейбл с эллипсисом, если узко.
    readonly property real chipW: (model && model.length > 0)
                                  ? (width - (model.length - 1) * spacing) / model.length : 0

    function stateColor(s) {
        if (s === 2) return Theme.color.connected   // работает — зелёный
        if (s === 1) return Theme.color.warning      // медленно (троттлинг) — янтарь
        if (s === 0) return Theme.color.danger       // заблокировано — красный
        return Theme.color.text3                      // неизвестно — серый
    }
    function stateLabel(s) {
        if (s === 2) return qsTr("работает")
        if (s === 1) return qsTr("медленно")
        if (s === 0) return qsTr("заблок.")
        return qsTr("…")
    }

    Repeater {
        model: chips.model
        delegate: Rectangle {
            id: chip
            required property var modelData
            readonly property string key: modelData ? (modelData.key || "") : ""
            readonly property int st: modelData && modelData.state !== undefined ? modelData.state : -1
            height: 32
            width: chips.chipW           // равная доля ширины — гарантирует одну строку // AVPN
            radius: Theme.radius.pill
            color: Theme.color.surface1
            border.width: 1
            border.color: Qt.rgba(chips.stateColor(st).r, chips.stateColor(st).g, chips.stateColor(st).b, 0.45)

            Row {
                id: row
                anchors.centerIn: parent
                spacing: Theme.space.sm

                // лого сервиса (фирменный цвет — бренд-исключение)
                Loader {
                    anchors.verticalCenter: parent.verticalCenter
                    sourceComponent: chip.key === "telegram" ? logoTelegram
                                   : chip.key === "youtube"  ? logoYoutube
                                   : chip.key === "instagram" ? logoInstagram
                                   : logoGeneric
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: modelData ? (modelData.label || chip.key) : ""
                    color: Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                    font.weight: Theme.font.wMedium
                    // эллипсис, если лейбл не влезает в равную долю чипа // AVPN
                    elide: Text.ElideRight
                    width: Math.min(implicitWidth, chip.width - 18 - 8 - 3 * Theme.space.sm)
                }
                // статус-дот (цвет = статус)
                Rectangle {
                    anchors.verticalCenter: parent.verticalCenter
                    width: 8; height: 8; radius: 4
                    color: chips.stateColor(chip.st)
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: chips.recheck()
            }
        }
    }

    // --- логотипы (18×18, viewBox 24) ---
    Component {
        id: logoTelegram
        Shape {
            width: 18; height: 18; preferredRendererType: Shape.CurveRenderer
            transform: Scale { xScale: 18/24; yScale: 18/24 }   // 24-grid path → 18px (transform на Shape, не ShapePath)
            ShapePath {
                fillColor: "#29A9EB"   // бренд Telegram
                strokeColor: "transparent"
                PathSvg { path: "M2.3 8.6 L20 1.8 c0.8-0.3 1.5 0.2 1.3 1.4 L19.3 18.5 c-0.2 1-0.8 1.2-1.6 0.7 l-4.4-3.2 -2.1 2 c-0.2 0.2-0.4 0.4-0.9 0.4 l0.3-4.6 8.4-7.6 c0.4-0.3-0.1-0.5-0.6-0.2 L7.9 11.7 3.6 10.3 c-0.9-0.3-0.9-0.9 0.2-1.3 z" }
            }
        }
    }
    Component {
        id: logoYoutube
        Item {
            width: 18; height: 18
            Rectangle {   // скруглённый прямоугольник — бренд YouTube
                anchors.centerIn: parent
                width: 18; height: 13; radius: 4
                color: "#FF0000"
                Shape {   // белый «play»-треугольник (оптический сдвиг вправо для центровки)
                    anchors.centerIn: parent
                    anchors.horizontalCenterOffset: 1
                    width: 7; height: 8
                    ShapePath {
                        fillColor: "white"; strokeColor: "transparent"
                        PathSvg { path: "M0 0 L7 4 L0 8 Z" }
                    }
                }
            }
        }
    }
    Component {
        id: logoInstagram
        Shape {
            width: 18; height: 18
            preferredRendererType: Shape.CurveRenderer
            // скруглённый квадрат + объектив (контур) + видоискатель (залитый кружок) — бренд-розовый
            transform: Scale { xScale: 18/24; yScale: 18/24 }
            ShapePath {
                strokeColor: "#E1306C"; fillColor: "transparent"; strokeWidth: 2
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M6 2 h12 a4 4 0 0 1 4 4 v12 a4 4 0 0 1 -4 4 h-12 a4 4 0 0 1 -4 -4 v-12 a4 4 0 0 1 4 -4 z M12 8 a4 4 0 1 0 0.01 0 z" }
            }
            ShapePath {   // точка-видоискатель залитым кружком (надёжнее вырожденной микро-дуги)
                strokeColor: "transparent"; fillColor: "#E1306C"
                PathSvg { path: "M16.6 6.5 a0.9 0.9 0 1 0 1.8 0 a0.9 0.9 0 1 0 -1.8 0 z" }
            }
        }
    }
    Component {
        id: logoGeneric
        Rectangle { width: 14; height: 14; radius: 4; color: Theme.color.surface2 }
    }
}

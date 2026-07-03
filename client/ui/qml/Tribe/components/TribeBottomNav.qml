import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: bottom navigation (replaces Amnezia TabBar). 4 tabs. UI-DESIGN.md §4.
// Tabler-style stroke icons drawn inline (no PNG). Emits activated(index).
Item {
    id: nav
    property int currentIndex: 0
    signal activated(int index)

    // tab spec: { label, icon path (24-grid) } — Tabler Home/Globe/Shield/User
    readonly property var tabs: [
        { label: qsTr("Главная"), icon: "M5 12 L3 12 L12 3 L21 12 L19 12 M5 12 L5 20 L9 20 L9 14 L15 14 L15 20 L19 20 L19 12" },
        { label: qsTr("Поддержка"), icon: "M4 13 v-2 a8 8 0 0 1 16 0 v2 M7 13 h-2 a1 1 0 0 0 -1 1 v3 a1 1 0 0 0 1 1 h1 a1 1 0 0 0 1 -1 v-4z M17 13 h2 a1 1 0 0 1 1 1 v3 a1 1 0 0 1 -1 1 h-1 a1 1 0 0 1 -1 -1 v-4z M19 18 v1 a3 3 0 0 1 -3 3 h-2" },
        { label: qsTr("Рефералка"), icon: "M4 8 h16 a1 1 0 0 1 1 1 v2 a1 1 0 0 1 -1 1 h-16 a1 1 0 0 1 -1 -1 v-2 a1 1 0 0 1 1 -1z M12 8 v13 M5 12 v7 a2 2 0 0 0 2 2 h10 a2 2 0 0 0 2 -2 v-7 M7.5 8 a2.5 2.5 0 0 1 0 -5 a4.8 8 0 0 1 4.5 5 a4.8 8 0 0 1 4.5 -5 a2.5 2.5 0 0 1 0 5" },
        { label: qsTr("Настройки"), icon: "M10.3 3.2 a1 1 0 0 1 3.4 0 l.2 1.2 a7 7 0 0 1 2 .8 l1 -.7 a1 1 0 0 1 2.4 2.4 l-.7 1 a7 7 0 0 1 .8 2 l1.2 .2 a1 1 0 0 1 0 3.4 l-1.2 .2 a7 7 0 0 1 -.8 2 l.7 1 a1 1 0 0 1 -2.4 2.4 l-1 -.7 a7 7 0 0 1 -2 .8 l-.2 1.2 a1 1 0 0 1 -3.4 0 l-.2 -1.2 a7 7 0 0 1 -2 -.8 l-1 .7 a1 1 0 0 1 -2.4 -2.4 l.7 -1 a7 7 0 0 1 -.8 -2 l-1.2 -.2 a1 1 0 0 1 0 -3.4 l1.2 -.2 a7 7 0 0 1 .8 -2 l-.7 -1 a1 1 0 0 1 2.4 -2.4 l1 .7 a7 7 0 0 1 2 -.8z M12 15 a3 3 0 1 0 0 -6 3 3 0 0 0 0 6z" }
    ]

    implicitHeight: 72 + bottomInset
    property real bottomInset: 0   // wired to safe-area by host
    // фон: без скруглений (плоская панель во всю ширину, реш. 2026-06-11).
    // macOS: НЕПРОЗРАЧНЫЙ bg800 — окно frameless/transparent, и через альфу токена nav (0.95)
    // просвечивал рабочий стол ЗА окном (реш. 2026-07-02)
    Rectangle {
        anchors.fill: parent
        color: Qt.platform.os === "osx" ? Theme.color.bg800 : Theme.color.nav
    }
    // top hairline
    Rectangle { anchors.top: parent.top; width: parent.width; height: 1; color: Theme.color.border }

    // активный цвет = единый акцент (Theme.color.accent), idle — приглушён (textDisabled)
    // для контраста с активным табом
    readonly property color navActive: Theme.color.accent
    readonly property color navIdle: Theme.color.textDisabled

    Row {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: 72
        Repeater {
            model: nav.tabs
            delegate: Item {
                width: nav.width / nav.tabs.length
                height: parent.height
                readonly property bool active: index === nav.currentIndex
                readonly property color tint: active ? nav.navActive : nav.navIdle

                Column {
                    anchors.centerIn: parent
                    spacing: 6
                    Shape {
                        id: navIcon
                        anchors.horizontalCenter: parent.horizontalCenter
                        width: 22; height: 22
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: tint; fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: modelData.icon }
                        }
                    }
                    Text {
                        anchors.horizontalCenter: parent.horizontalCenter
                        text: modelData.label
                        color: tint
                        font.family: Theme.font.body
                        font.pixelSize: 10
                        font.weight: active ? Theme.font.wMedium : Theme.font.wRegular
                        font.letterSpacing: 0.3
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: { nav.currentIndex = index; nav.activated(index) }
                }
            }
        }
    }
}

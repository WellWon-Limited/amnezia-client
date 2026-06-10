import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: bottom navigation (replaces Amnezia TabBar). 4 tabs. UI-DESIGN.md §4.
// Tabler-style stroke icons drawn inline (no PNG). Emits activated(index).
Rectangle {
    id: nav
    property int currentIndex: 0
    signal activated(int index)

    // tab spec: { label, icon path (24-grid) } — Tabler Home/Globe/Shield/User
    readonly property var tabs: [
        { label: qsTr("Главная"), icon: "M5 12 L3 12 L12 3 L21 12 L19 12 M5 12 L5 20 L9 20 L9 14 L15 14 L15 20 L19 20 L19 12" },
        { label: qsTr("Серверы"), icon: "M12 3 a9 9 0 1 0 0.01 0 M3 12 L21 12 M12 3 c-3 3 -3 15 0 18 M12 3 c3 3 3 15 0 18" },
        { label: qsTr("Защита"),  icon: "M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" },
        { label: qsTr("Профиль"), icon: "M12 12 a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M6 20 v-1 a6 6 0 0 1 12 0 v1" }
    ]

    implicitHeight: 72 + bottomInset
    property real bottomInset: 0   // wired to safe-area by host
    radius: 24
    color: Theme.color.nav
    // top hairline
    Rectangle { anchors.top: parent.top; width: parent.width; height: 1; color: Theme.color.border }
    // скруглить только верхние углы (нижние перекрыты краем экрана)
    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: parent.radius; color: Theme.color.nav }

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

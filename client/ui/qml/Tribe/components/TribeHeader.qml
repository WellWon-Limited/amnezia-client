import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: screen header — title + optional back + right action. NO logo/app name (per design).
// titleAlignment: Qt.AlignHCenter (default) or Qt.AlignRight - the title at the page's right content edge
// (Theme.space.xl), elided before the back button (the Scanner, owner 24.11).
Item {
    id: header
    property string title: ""
    property bool showBack: false
    property int titleAlignment: Qt.AlignHCenter
    property alias rightItem: rightSlot.data
    signal backClicked()

    implicitHeight: 52

    // back chevron
    Item {
        id: back
        visible: header.showBack
        width: 40; height: 40
        anchors.left: parent.left
        anchors.leftMargin: Theme.space.sm
        anchors.verticalCenter: parent.verticalCenter
        objectName: "headerBack"
        Accessible.role: Accessible.Button
        Accessible.name: qsTr("Назад")
        Accessible.onPressAction: header.backClicked()
        Shape {
            anchors.centerIn: parent
            width: 22; height: 22
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 2
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M15 5 8 12 15 19" }
            }
        }
        MouseArea {
            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
            // AVPN (haptics, 2026-07-12): «назад» тикает как смена вкладки навбара
            onClicked: { Haptic.play("selection"); header.backClicked() }
        }
    }

    Text {
        readonly property bool atRight: header.titleAlignment === Qt.AlignRight
        anchors.verticalCenter: parent.verticalCenter
        x: atRight ? parent.width - Theme.space.xl - width : (parent.width - width) / 2
        width: atRight ? Math.min(implicitWidth, parent.width - Theme.space.xl
                                  - (back.visible ? back.x + back.width + Theme.space.sm : Theme.space.xl))
                       : implicitWidth
        horizontalAlignment: atRight ? Text.AlignRight : Text.AlignHCenter
        elide: Text.ElideRight
        textFormat: Text.PlainText
        text: header.title
        color: Theme.color.text1
        font.family: Theme.font.display
        font.pixelSize: Theme.font.h3
        font.weight: Theme.font.wBold
    }

    Item {
        id: rightSlot
        anchors.right: parent.right
        anchors.rightMargin: Theme.space.md
        anchors.verticalCenter: parent.verticalCenter
        width: childrenRect.width; height: parent.height
    }
}

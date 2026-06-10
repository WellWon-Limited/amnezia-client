import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: screen header — title + optional back + right action. NO logo/app name (per design).
Item {
    id: header
    property string title: ""
    property bool showBack: false
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
        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: header.backClicked() }
    }

    Text {
        anchors.centerIn: parent
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

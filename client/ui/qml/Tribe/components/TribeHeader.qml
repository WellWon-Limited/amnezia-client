import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: screen header — title + optional back + right action. NO logo/app name (per design).
// titleAlignment: Qt.AlignHCenter (default) or Qt.AlignLeft - the title right after the back arrow (the Support
// chat header's place: back 4 + 44, then 4). With the left title, `caption` is a secondary caption at the page's
// right content edge (Theme.space.xl) on the title's baseline, in the header caption style of «Локаций: N»
// (PageServersTribe) - the Scanner, owner 25.11: «Сканер» left, «Подбор серверов» right.
// A long title elides before the caption. The caption is the lesser of the two: it steps aside only when the title
// would neither fit whole nor keep at least the caption's own width - then the title takes the row (elided at the
// right content edge).
Item {
    id: header
    property string title: ""
    property bool showBack: false
    property int titleAlignment: Qt.AlignHCenter
    property string caption: ""
    property alias rightItem: rightSlot.data
    signal backClicked()

    readonly property bool titleAtLeft: titleAlignment === Qt.AlignLeft
    readonly property real titleLeft: back.visible ? back.x + back.width + Theme.space.xs : Theme.space.xl

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
        id: titleText
        objectName: "headerTitle"
        // the left title's room: up to the caption (Theme.space.md before it) or to the right content edge
        readonly property real room: (captionText.visible ? captionText.x - Theme.space.md
                                                          : parent.width - Theme.space.xl) - header.titleLeft
        anchors.verticalCenter: parent.verticalCenter
        x: header.titleAtLeft ? header.titleLeft : (parent.width - width) / 2
        width: header.titleAtLeft ? Math.max(0, Math.min(implicitWidth, room)) : implicitWidth
        horizontalAlignment: header.titleAtLeft ? Text.AlignLeft : Text.AlignHCenter
        elide: Text.ElideRight
        textFormat: Text.PlainText
        text: header.title
        color: Theme.color.text1
        font.family: Theme.font.display
        font.pixelSize: Theme.font.h3
        font.weight: Theme.font.wBold
    }

    Text {
        id: captionText
        objectName: "headerCaption"
        // the long-title rule: shown while the title fits whole beside it or keeps at least the caption's own width
        visible: header.titleAtLeft && header.caption !== ""
                 && parent.width - Theme.space.xl - implicitWidth - Theme.space.md - header.titleLeft
                    >= Math.min(titleText.implicitWidth, implicitWidth)
        anchors.baseline: titleText.baseline
        x: parent.width - Theme.space.xl - width
        textFormat: Text.PlainText
        text: header.caption
        color: Theme.color.text3
        font.family: Theme.font.body
        font.pixelSize: Theme.font.caption
        font.weight: Theme.font.wSemibold
    }

    Item {
        id: rightSlot
        anchors.right: parent.right
        anchors.rightMargin: Theme.space.md
        anchors.verticalCenter: parent.verticalCenter
        width: childrenRect.width; height: parent.height
    }
}

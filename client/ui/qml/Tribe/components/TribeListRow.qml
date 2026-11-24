import QtQuick

import ".."   // Theme

// AVPN: list row — [icon] title / sub(mono) [right slot]. Used for locations & settings.
Rectangle {
    id: rowRoot
    property string title: ""
    property string subtitle: ""
    property string iconSource: ""
    property alias rightItem: rightSlot.data
    property alias leftItem: leftSlot.data
    property bool interactive: true
    property bool monoSubtitle: true    // false: the subtitle in the body font (words, not an endpoint - the Scanner's choice)
    // the chosen row of a choice list: the kit's selection look (the server list's chosen row, the «Авто» card,
    // the transport segment): chipSelected fill + accent border
    property bool selected: false
    signal clicked()

    implicitHeight: 60
    radius: Theme.radius.md
    color: selected ? Theme.color.chipSelected
                    : (hover.hovered && interactive ? Theme.color.surface2 : Theme.color.surface1)
    border.width: 1
    border.color: selected ? Theme.color.accent : Theme.color.border
    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

    Row {
        anchors.fill: parent
        anchors.leftMargin: Theme.space.lg
        anchors.rightMargin: Theme.space.lg
        spacing: Theme.space.md

        // left slot (icon / flag), falls back to iconSource image
        Item {
            id: leftSlot
            width: childrenRect.width > 0 ? childrenRect.width : (rowRoot.iconSource !== "" ? 34 : 0)
            height: parent.height
            Image {
                visible: rowRoot.iconSource !== "" && leftSlot.children.length <= 1
                source: rowRoot.iconSource
                anchors.verticalCenter: parent.verticalCenter
                sourceSize.width: 22; sourceSize.height: 22
            }
        }

        Column {
            anchors.verticalCenter: parent.verticalCenter
            spacing: 2
            width: rowRoot.width - leftSlot.width - rightSlot.width - 3 * Theme.space.md - 2 * Theme.space.lg
            Text {
                text: rowRoot.title
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wMedium
                elide: Text.ElideRight
                width: parent.width
            }
            Text {
                visible: rowRoot.subtitle !== ""
                text: rowRoot.subtitle
                color: Theme.color.text3
                font.family: rowRoot.monoSubtitle ? Theme.font.mono : Theme.font.body
                font.pixelSize: Theme.font.caption
                elide: Text.ElideRight
                width: parent.width
            }
        }
    }

    Item {
        id: rightSlot
        anchors.right: parent.right
        anchors.rightMargin: Theme.space.lg
        anchors.verticalCenter: parent.verticalCenter
        width: childrenRect.width
        height: parent.height
    }

    // The hover look only for a pointer that hovers (mouse, trackpad - TribeButton's pattern): a touch that scrolled the
    // list and lifted on a row left MouseArea.containsMouse true, and the row kept a «pressed» background (device round
    // air-C, D7, English list, the Poland row).
    HoverHandler {
        id: hover
        enabled: rowRoot.interactive
        acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
        cursorShape: Qt.PointingHandCursor
    }
    MouseArea {
        id: ma
        anchors.fill: parent
        enabled: rowRoot.interactive
        onClicked: rowRoot.clicked()
    }
}

import QtQuick

import ".."   // Theme

// AVPN: пузырь сообщения чата поддержки. mine=true → справа (accent), иначе слева (surface1).
// Ширина пузыря = по контенту, но не шире 78% доступной ширины (перенос внутри).
Item {
    id: bubble
    property string text: ""
    property bool mine: false
    property string time: ""
    readonly property real pad: Theme.space.md
    implicitHeight: col.implicitHeight

    Column {
        id: col
        spacing: 3
        anchors.left: bubble.mine ? undefined : parent.left
        anchors.right: bubble.mine ? parent.right : undefined

        Rectangle {
            id: box
            anchors.left: bubble.mine ? undefined : parent.left
            anchors.right: bubble.mine ? parent.right : undefined
            // implicitWidth текста — натуральная (без переноса) ширина → нет binding-loop с msg.width
            width: Math.min(msg.implicitWidth + 2 * bubble.pad, bubble.width * 0.78)
            implicitHeight: msg.implicitHeight + 2 * Theme.space.sm
            radius: Theme.radius.lg
            color: bubble.mine ? Theme.color.accent : Theme.color.surface1
            border.width: bubble.mine ? 0 : 1
            border.color: Theme.color.border

            Text {
                id: msg
                x: bubble.pad
                y: Theme.space.sm
                width: box.width - 2 * bubble.pad
                text: bubble.text
                wrapMode: Text.Wrap
                color: bubble.mine ? Theme.color.bg900 : Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
            }
        }

        Text {
            anchors.left: bubble.mine ? undefined : parent.left
            anchors.right: bubble.mine ? parent.right : undefined
            text: bubble.time
            visible: bubble.time !== ""
            color: Theme.color.text3
            font.family: Theme.font.mono
            font.pixelSize: 10
        }
    }
}

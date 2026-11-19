import QtQuick
import QtQuick.Layouts

import ".."   // Theme

// AVPN: «шторка-уведомление» (artboard vpn-scanner-kit.js shade; construction from the owner's Poker Club toast,
// src/components/ui/sonner.tsx): full width from the top edge over the status bar, bottom corners radius.xl, a SOLID
// fill per tone (Theme.color.shade*, darker than the tone: no gradient, no shadow, owner 2026-11-19), a 20 px icon
// directly left of a 15 px semibold white line, the pair centred horizontally (a wrapped line is centred too).
// Height = safe top + max(Theme.shade.body, text block + 2 * Theme.shade.padY); the text block sits centred in the
// part below the safe top, so it never reaches under the notch / Dynamic Island and has equal room above and below.
// Slides down / up in motion.slow (360 ms). Purely visual: TribeShadeHost decides what is shown and for how long.
Item {
    id: root

    property string tone: "info"          // info | success | warning | error
    property string text: ""
    property real safeTop: 0
    property bool shown: false
    signal tapped()

    readonly property color fillColor: tone === "success" ? Theme.color.shadeSuccess
                                       : tone === "warning" ? Theme.color.shadeWarning
                                       : tone === "error" ? Theme.color.shadeError : Theme.color.shadeInfo
    readonly property string iconKey: tone === "success" ? "check-circle"
                                      : (tone === "warning" || tone === "error") ? "alert-triangle" : "info-circle"

    width: parent ? parent.width : 0
    height: safeTop + Math.max(Theme.shade.body, content.height + 2 * Theme.shade.padY)
    y: shown ? 0 : -height
    visible: shown || slide.running
    Behavior on y {
        NumberAnimation {
            id: slide
            duration: Theme.motion.reduceMotion ? 0 : Theme.motion.slow
            easing.type: root.shown ? Easing.OutCubic : Easing.InCubic
        }
    }

    Accessible.role: Accessible.AlertMessage
    Accessible.name: root.text

    // Rounded bottom corners only: a uniform-radius rectangle reaches radius.xl above the top edge and is clipped there.
    Item {
        anchors.fill: parent
        clip: true
        Rectangle {
            y: -Theme.radius.xl
            width: parent.width
            height: parent.height + Theme.radius.xl
            radius: Theme.radius.xl
            color: root.fillColor
        }
    }

    RowLayout {
        id: content
        width: Math.min(implicitWidth, root.width - 2 * Theme.shade.padX)
        x: (root.width - width) / 2
        y: root.safeTop + (root.height - root.safeTop - height) / 2
        spacing: Theme.space.md
        TribeStrokeIcon {
            Layout.preferredWidth: Theme.shade.icon
            Layout.preferredHeight: Theme.shade.icon
            Layout.alignment: Qt.AlignVCenter
            icon: root.iconKey
            tint: Theme.color.shadeText
        }
        Text {
            id: line
            Layout.fillWidth: true
            Layout.maximumWidth: Math.ceil(implicitWidth)   // layouts snap to whole pixels
            text: root.text
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.color.shadeText
            font.family: Theme.font.body
            font.pixelSize: Theme.shade.text
            font.weight: Theme.font.wSemibold
            lineHeight: Theme.shade.textLine
            lineHeightMode: Text.FixedHeight
        }
    }

    MouseArea {
        anchors.fill: parent
        onClicked: root.tapped()
    }
}

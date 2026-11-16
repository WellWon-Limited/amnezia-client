import QtQuick
import QtQuick.Layouts

import ".."   // Theme

// AVPN: «шторка-уведомление» (artboard vpn-scanner-kit.js shade, kit spec «Шторка-уведомление»; construction from
// the owner's Poker Club shade): full width from the top edge over the status bar, bottom corners radius.xl 20,
// height = safe top + 69, a 20 px icon left of a 15 px semibold line. Fill top-down: the tone's dark band up to
// safeTop - 18 (the white iOS status bar stays readable), the tone from safeTop + 6, the sheen (white 11 % -> 0
// at 55 % -> black 10 %) over it, a bottom edge in the tone at 40 %. Slides down / up in motion.slow (360 ms).
// Purely visual: TribeShadeHost decides what is shown and for how long.
Item {
    id: root

    property string tone: "info"          // info | success | warning
    property string text: ""
    property real safeTop: 0
    property bool shown: false
    signal tapped()

    readonly property color toneColor: tone === "success" ? Theme.color.connected
                                       : tone === "warning" ? Theme.color.warning : Theme.color.accent
    readonly property color deepColor: tone === "success" ? Theme.color.shadeSuccessDeep
                                       : tone === "warning" ? Theme.color.shadeWarningDeep : Theme.color.shadeInfoDeep
    readonly property string iconKey: tone === "success" ? "check-circle"
                                      : tone === "warning" ? "alert-triangle" : "info-circle"

    width: parent ? parent.width : 0
    height: Math.max(safeTop + Theme.shade.body, safeTop + Theme.space.md + line.implicitHeight + Theme.space.md)
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

    // Rounded bottom corners only: uniform-radius rectangles reach radius.xl above the top edge and are clipped
    // there (a per-corner-radius Rectangle with a gradient renders its stops skewed on the RHI backends).
    Item {
        id: body
        anchors.fill: parent
        clip: true
        readonly property real lift: Theme.radius.xl
        readonly property real fullH: height + lift
        // bottom edge: the tone at 40 %, 1 px under the fill
        Rectangle {
            y: -body.lift
            width: parent.width
            height: body.fullH
            radius: Theme.radius.xl
            color: Qt.alpha(root.toneColor, Theme.shade.borderAlpha)
        }
        Rectangle {
            id: fill
            y: -body.lift
            width: parent.width
            height: body.fullH - 1
            radius: Theme.radius.xl
            readonly property real bandEnd: (body.lift + Math.max(0, root.safeTop - Theme.shade.bandLead)) / Math.max(1, height)
            readonly property real toneAt: Math.min(1, (body.lift + root.safeTop + Theme.shade.toneLag) / Math.max(1, height))
            gradient: Gradient {
                GradientStop { position: 0.0; color: root.deepColor }
                GradientStop { position: Math.min(0.998, fill.bandEnd); color: root.deepColor }
                GradientStop { position: Math.max(Math.min(0.999, fill.bandEnd + 0.001), fill.toneAt); color: root.toneColor }
                GradientStop { position: 1.0; color: root.toneColor }
            }
        }
        // sheen over the visible part: white 11 % at the top edge -> 0 at 55 % -> black 10 % at the bottom
        Rectangle {
            id: sheen
            y: -body.lift
            width: parent.width
            height: body.fullH - 1
            radius: Theme.radius.xl
            readonly property real lead: body.lift / Math.max(1, height)
            gradient: Gradient {
                GradientStop { position: 0.0; color: Theme.color.shadeSheenTop }
                GradientStop { position: sheen.lead; color: Theme.color.shadeSheenTop }
                GradientStop { position: sheen.lead + 0.55 * (1 - sheen.lead); color: "transparent" }
                GradientStop { position: 1.0; color: Theme.color.shadeSheenBottom }
            }
        }
    }

    RowLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.shade.padX
        anchors.rightMargin: Theme.shade.padX
        y: root.safeTop + Theme.space.md + (root.height - root.safeTop - 2 * Theme.space.md - height) / 2
        spacing: Theme.space.md
        TribeStrokeIcon {
            Layout.preferredWidth: Theme.shade.icon
            Layout.preferredHeight: Theme.shade.icon
            Layout.alignment: Qt.AlignVCenter
            icon: root.iconKey
            tint: Theme.color.bg900
        }
        Text {
            id: line
            Layout.fillWidth: true
            text: root.text
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            color: Theme.color.bg900
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

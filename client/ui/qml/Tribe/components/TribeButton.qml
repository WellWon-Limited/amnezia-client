import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Qt5Compat.GraphicalEffects

import ".."   // Tribe/qmldir → Theme singleton

// AVPN: Tribe VPN button. Variants: "primary" (gradient + glow), "glass", "ghost", "icon".
// Tokens only (Theme). UI-DESIGN.md §3.
AbstractButton {
    id: control

    property string variant: "primary"          // primary | glass | ghost | icon
    property string iconSource: ""
    property bool loading: false
    readonly property bool isIcon: variant === "icon"

    implicitHeight: isIcon ? 44 : 46
    implicitWidth: isIcon ? 44 : Math.max(120, contentRow.implicitWidth + 2 * Theme.space.xl)
    padding: isIcon ? 0 : Theme.space.md
    opacity: enabled ? 1.0 : 0.45
    hoverEnabled: true

    contentItem: RowLayout {
        id: contentRow
        spacing: Theme.space.sm
        layoutDirection: Qt.LeftToRight

        BusyIndicator {
            visible: control.loading
            running: control.loading
            Layout.alignment: Qt.AlignVCenter
            implicitWidth: 18; implicitHeight: 18
        }
        Image {
            visible: control.iconSource !== "" && !control.loading
            source: control.iconSource
            sourceSize.width: 20; sourceSize.height: 20
            Layout.alignment: Qt.AlignVCenter
        }
        Text {
            visible: control.text !== "" && !control.isIcon && !control.loading
            text: control.text
            Layout.alignment: Qt.AlignVCenter
            font.family: Theme.font.body
            font.pixelSize: 15
            font.weight: Theme.font.wSemibold
            color: control.variant === "primary" ? "white"
                 : control.variant === "ghost" ? Theme.color.text2
                 : Theme.color.text1
        }
    }
    // center content
    Component.onCompleted: contentRow.anchors.centerIn = control

    background: Rectangle {
        id: bg
        radius: control.isIcon ? Theme.radius.md : Theme.radius.md
        // primary uses gradient; others flat/glass
        gradient: control.variant === "primary" ? primaryGrad : null
        color: {
            if (control.variant === "primary") return "transparent"
            if (control.variant === "ghost") return control.hovered ? Theme.color.glass : "transparent"
            // glass + icon
            return control.hovered ? Theme.color.surface2 : Theme.color.glassStrong
        }
        border.width: control.variant === "primary" ? 0 : 1
        border.color: control.hovered ? Theme.color.border2 : Theme.color.border
        layer.enabled: control.variant === "primary"
        layer.effect: Glow {
            color: Theme.color.accentGlow
            radius: 18; samples: 25; spread: 0.2
            transparentBorder: true
        }
        Behavior on color { ColorAnimation { duration: Theme.motion.fast } }

        Gradient {
            id: primaryGrad
            orientation: Gradient.Vertical
            GradientStop { position: 0.0; color: control.pressed ? Theme.color.accentDeep : Theme.color.gradTop }
            GradientStop { position: 1.0; color: Theme.color.gradBottom }
        }
    }
}

import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects

import ".."   // Theme

// AVPN: signature element — concentric "signal waves" + central core button.
// state: "off" | "connecting" | "connected" | "switching". UI-DESIGN.md §2/§6.1.
Item {
    id: root
    implicitWidth: 250
    implicitHeight: 250

    property string ringState: "off"
    signal coreClicked()

    readonly property bool isOff: ringState === "off"
    readonly property bool busy: ringState === "connecting" || ringState === "switching"
    readonly property bool animated: (ringState === "connected") && !Theme.motion.reduceMotion

    // accent колец/свечения = состояние; в OFF — приглушённый серо-синий, чтобы было ясно «выключено»
    readonly property color stateColor: ringState === "connected" ? Theme.color.connected
        : busy ? Theme.color.warning
        : Theme.color.text3
    // ядро-кнопка: серое в OFF, янтарь в connecting, зелёное в connected
    readonly property color coreTop: ringState === "connected" ? "#52CFA0"
        : busy ? "#E8B45A"
        : "#26314A"
    readonly property color coreBottom: ringState === "connected" ? "#33A37D"
        : busy ? "#D2952F"
        : "#172033"
    readonly property color glyphColor: isOff ? Theme.color.text2 : "white"

    // ── concentric rings (80 / 140 / 200 / 250) ──────────────────────────────
    Repeater {
        model: [
            { d: 80,  o: 0.90 },
            { d: 140, o: 0.45 },
            { d: 200, o: 0.22 },
            { d: 250, o: 0.10 }
        ]
        delegate: Rectangle {
            anchors.centerIn: parent
            width: modelData.d
            height: modelData.d
            radius: width / 2
            color: "transparent"
            border.width: 1
            border.color: root.stateColor
            opacity: modelData.o
            // "breathing" when connected
            SequentialAnimation on scale {
                running: root.animated
                loops: Animation.Infinite
                NumberAnimation { from: 1.0; to: 1.06; duration: 1800 + index * 120; easing.type: Easing.InOutSine }
                NumberAnimation { from: 1.06; to: 1.0; duration: 1800 + index * 120; easing.type: Easing.InOutSine }
            }
            Behavior on border.color { ColorAnimation { duration: Theme.motion.normal } }
        }
    }

    // ── core button (88) ─────────────────────────────────────────────────────
    Rectangle {
        id: core
        anchors.centerIn: parent
        width: 96; height: 96; radius: 48
        gradient: Gradient {
            orientation: Gradient.Vertical
            GradientStop { position: 0.0; color: coreMa.pressed ? Qt.darker(root.coreTop, 1.15) : root.coreTop }
            GradientStop { position: 1.0; color: root.coreBottom }
        }
        // в OFF — тонкая обводка, чтобы читалось как кнопка
        border.width: root.isOff ? 1 : 0
        border.color: Theme.color.border2
        scale: coreMa.pressed ? 0.96 : 1.0
        Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

        layer.enabled: !root.isOff
        layer.effect: Glow {
            color: root.stateColor
            radius: 30; samples: 41; spread: 0.35
            transparentBorder: true
        }

        // shield icon (centered, 24-grid path uniformly scaled)
        Shape {
            anchors.centerIn: parent
            width: 24; height: 24
            scale: 1.45
            preferredRendererType: Shape.CurveRenderer
            visible: !root.busy
            ShapePath {
                strokeColor: root.glyphColor; fillColor: "transparent"; strokeWidth: 1.7
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" }
            }
            ShapePath {
                strokeColor: root.glyphColor; fillColor: "transparent"; strokeWidth: 1.7
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M9 12 11 14 15 10" }
            }
        }

        // busy spinner
        BusyIndicator {
            anchors.centerIn: parent
            running: root.busy
            visible: root.busy
            implicitWidth: 38; implicitHeight: 38
        }

        MouseArea {
            id: coreMa
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.coreClicked()
        }
    }
}

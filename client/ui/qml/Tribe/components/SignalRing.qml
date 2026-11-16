import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects

import ".."   // Theme

// AVPN: signature element — concentric "signal waves" + central core button.
// state: "off" | "connecting" | "connected" | "switching" | "scanning". UI-DESIGN.md §2/§6.1.
// "scanning" (the Scanner, plan scanner-client-plan.md §4, artboard vpn-scanner-kit.js scanRings): rings in
// the accent, breathing, two outward waves 80 -> 250, the Connect orb's 28-segment tapered arc on the 200
// ring and a radar glyph in the core. `compact` = the 18 px header mark after the scan (rings .22/.45/.90).
// Reduce Motion: static rings, no waves, no arc.
Item {
    id: root
    implicitWidth: compact ? Theme.scan.mark : 250
    implicitHeight: compact ? Theme.scan.mark : 250

    property string ringState: "off"
    property bool compact: false
    signal coreClicked()

    readonly property bool isOff: ringState === "off"
    readonly property bool scanning: ringState === "scanning"
    readonly property bool busy: ringState === "connecting" || ringState === "switching"
    readonly property bool motion: !Theme.motion.reduceMotion && root.visible
    readonly property bool animated: (ringState === "connected" || scanning) && motion

    // accent колец/свечения = состояние; в OFF — приглушённый серо-синий, чтобы было ясно «выключено»
    readonly property color stateColor: ringState === "connected" ? Theme.color.connected
        : busy ? Theme.color.warning
        : scanning ? Theme.color.accent
        : Theme.color.text3
    // ядро-кнопка: серое в OFF и при скане, янтарь в connecting, зелёное в connected
    readonly property bool plainCore: isOff || scanning
    readonly property color coreTop: ringState === "connected" ? "#52CFA0"
        : busy ? "#E8B45A"
        : Theme.color.ringCoreTop
    readonly property color coreBottom: ringState === "connected" ? "#33A37D"
        : busy ? "#D2952F"
        : Theme.color.ringCoreBottom
    readonly property color glyphColor: scanning ? Theme.color.accent : (isOff ? Theme.color.text2 : "white")

    // ── compact header mark (18): three rings, outer .22 / middle .45 / inner .90 ──
    Repeater {
        model: root.compact ? [ { d: 18, o: 0.22 }, { d: 12, o: 0.45 }, { d: 6, o: 0.90 } ] : []
        delegate: Rectangle {
            required property var modelData
            anchors.centerIn: parent
            width: modelData.d
            height: modelData.d
            radius: width / 2
            color: "transparent"
            border.width: 1
            border.color: Qt.alpha(Theme.color.accent, modelData.o)
        }
    }

    // ── concentric rings (80 / 140 / 200 / 250) ──────────────────────────────
    Repeater {
        model: root.compact ? [] : [
            { d: 80,  o: 0.90 },
            { d: 140, o: 0.45 },
            { d: 200, o: 0.22 },
            { d: 250, o: 0.10 }
        ]
        delegate: Rectangle {
            required property var modelData
            required property int index
            anchors.centerIn: parent
            width: modelData.d
            height: modelData.d
            radius: width / 2
            color: "transparent"
            border.width: 1
            border.color: root.stateColor
            opacity: modelData.o
            // "breathing" when connected / scanning
            SequentialAnimation on scale {
                running: root.animated
                loops: Animation.Infinite
                NumberAnimation { from: 1.0; to: 1.06; duration: 1800 + index * 120; easing.type: Easing.InOutSine }
                NumberAnimation { from: 1.06; to: 1.0; duration: 1800 + index * 120; easing.type: Easing.InOutSine }
            }
            Behavior on border.color { ColorAnimation { duration: Theme.motion.normal } }
        }
    }

    // ── scanning: two outward waves 80 -> 250 (scale 3.125), .45 -> 0, 1800 ms, the second +900 ms ──
    Repeater {
        model: (root.scanning && !root.compact) ? 2 : 0
        delegate: Rectangle {
            id: wave
            required property int index
            anchors.centerIn: parent
            width: 80; height: 80
            radius: width / 2
            color: "transparent"
            border.width: 1
            border.color: Theme.color.accent
            opacity: 0
            visible: root.motion
            SequentialAnimation {
                running: root.scanning && root.motion
                loops: 1
                PauseAnimation { duration: wave.index * 900 }
                ScriptAction { script: waveLoop.start() }
            }
            ParallelAnimation {
                id: waveLoop
                loops: Animation.Infinite
                ScaleAnimator { target: wave; from: 1.0; to: 3.125; duration: 1800; easing.type: Easing.InOutSine }
                OpacityAnimator { target: wave; from: 0.45; to: 0; duration: 1800; easing.type: Easing.InOutSine }
            }
            Connections {
                target: root
                function onMotionChanged() { if (!root.motion) waveLoop.stop() }
            }
        }
    }

    // ── scanning: the Connect orb's tapered arc (28 segments over 180°, width 1 -> 6.5) on the 200 ring ──
    Item {
        id: sweep
        anchors.centerIn: parent
        width: 250; height: 250
        visible: root.scanning && !root.compact && root.motion
        opacity: 0.7
        // the arc is one stroke at 70 %: composite the overlapping segments first (CSS opacity on the svg group)
        layer.enabled: visible
        readonly property int segs: 28
        readonly property real step: 180 / segs
        Repeater {
            model: sweep.visible ? sweep.segs : 0
            Shape {
                required property int index
                anchors.fill: parent
                preferredRendererType: Shape.CurveRenderer
                antialiasing: true
                ShapePath {
                    fillColor: "transparent"
                    strokeColor: Theme.color.accent
                    capStyle: ShapePath.RoundCap
                    strokeWidth: 1.0 + 5.5 * (index / (sweep.segs - 1))
                    PathAngleArc {
                        centerX: 125; centerY: 125; radiusX: 100; radiusY: 100
                        startAngle: -90 + index * sweep.step
                        sweepAngle: sweep.step + 0.8
                    }
                }
            }
        }
        RotationAnimator on rotation {
            running: sweep.visible
            from: 0; to: 360; duration: 1050; loops: Animation.Infinite
        }
    }

    // ── core button (96) ─────────────────────────────────────────────────────
    Rectangle {
        id: core
        visible: !root.compact
        anchors.centerIn: parent
        width: 96; height: 96; radius: 48
        gradient: Gradient {
            orientation: Gradient.Vertical
            GradientStop { position: 0.0; color: coreMa.pressed ? Qt.darker(root.coreTop, 1.15) : root.coreTop }
            GradientStop { position: 1.0; color: root.coreBottom }
        }
        // в OFF и при скане — тонкая обводка, чтобы читалось как кнопка
        border.width: root.plainCore ? 1 : 0
        border.color: Theme.color.border2
        scale: coreMa.pressed ? 0.96 : 1.0
        Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

        layer.enabled: !root.plainCore
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
            visible: !root.busy && !root.scanning
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

        // radar glyph while scanning (Lucide radar, the kit's "radar" key)
        TribeStrokeIcon {
            anchors.centerIn: parent
            width: 24; height: 24
            scale: 1.45
            visible: root.scanning
            icon: "radar"
            tint: root.glyphColor
            weight: 1.7
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
            enabled: !root.scanning
            cursorShape: Qt.PointingHandCursor
            onClicked: root.coreClicked()
        }
    }
}

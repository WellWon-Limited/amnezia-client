import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Connect-экран (звёздное небо + горы во всю ширину + орб-сфера). Горы full-bleed и
// заходят на нижнюю часть круга. Синий = Theme.accent (#7ca2d0, финал). UI: переписан 2026-06.
PageType {
    id: root

    readonly property color blueAccent: Theme.color.accent
    readonly property color blue300: "#93C5FD"
    readonly property color blue400: "#60A5FA"
    readonly property color blue600: "#2563EB"
    readonly property color slate400: Theme.color.text2
    readonly property color slate500: Theme.color.text3
    readonly property color slate900: "#0F172A"

    // previewSim: визуальная симуляция (off→Поиск…→Connected) ТОЛЬКО для превью-демо.
    // false = орб ходит в реальный ConnectionController (прод-поведение). // AVPN
    property bool previewSim: false
    property bool simConnected: false
    property bool simConnecting: false
    readonly property bool isOn:  previewSim ? simConnected  : ConnectionController.isConnected
    readonly property bool isBusy: previewSim ? simConnecting : ConnectionController.isConnectionInProgress

    signal requestTab(int index)
    signal requestSettings()

    function onOrbClicked() {
        if (previewSim) {
            if (simConnected) { simConnected = false; return }
            simConnecting = true; simTimer.restart()
        } else {
            ConnectionController.connectButtonClicked()
        }
    }
    Timer { id: simTimer; interval: 1500; onTriggered: { root.simConnecting = false; root.simConnected = true } }

    // ── фон ─────────────────────────────────────────────────────────────
    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // ── звёздное небо (full-bleed, верхняя зона) ────────────────────────
    Item {
        id: starField
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: 340; clip: true; z: 0
        property var starsData: []
        Component.onCompleted: {
            var arr = []
            for (var i = 0; i < 32; i++)
                arr.push({ tx: Math.random(), ty: Math.random() * 0.6,
                           s: Math.random() * 1.8 + 1, o: Math.random() * 0.6 + 0.15,
                           d: Math.random() * 2600 })
            starsData = arr
        }
        Repeater {
            model: starField.starsData
            delegate: Rectangle {
                width: modelData.s; height: modelData.s; radius: width / 2; color: "white"
                x: modelData.tx * starField.width; y: modelData.ty * starField.height
                opacity: modelData.o
                SequentialAnimation on opacity {
                    running: !Theme.motion.reduceMotion; loops: Animation.Infinite
                    NumberAnimation { from: modelData.o; to: modelData.o * 0.25; duration: 1400; easing.type: Easing.InOutSine }
                    NumberAnimation { from: modelData.o * 0.25; to: modelData.o; duration: 1400; easing.type: Easing.InOutSine }
                    PauseAnimation { duration: modelData.d }
                }
            }
        }
        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(0x1E/255, 0x3A/255, 0x8A/255, 0.10) }
                GradientStop { position: 0.55; color: "transparent" }
                GradientStop { position: 1.0; color: Theme.color.bg800 }
            }
        }
    }

    // ── header: бренд-марк + Tribe VPN + шестерёнка ─────────────────────
    Item {
        id: header
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        anchors.topMargin: 16 + PageController.safeAreaTopMargin
        anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.lg
        height: 40; z: 10

        Item {
            id: brand
            anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter
            width: brandMark.width + 10 + brandText.width
            height: brandText.height

            Row {  // brand-mark: 5 баров сигнала (пропорции лого-SVG 16/28/36/26/18), высота = капсам,
                   // низ баров — на базовой линии wordmark (одна линия с текстом)
                id: brandMark
                anchors.left: parent.left
                anchors.bottom: brandText.baseline
                spacing: 2
                Rectangle { width: 3; height: 7;  radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 12; radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 16; radius: 1.5; color: root.blueAccent;  anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 12; radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 8;  radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
            }
            Text {
                id: brandText
                anchors.left: brandMark.right; anchors.leftMargin: 10
                text: "Tribe VPN"; color: "#EEF3F9"
                font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * Theme.font.h2
            }
        }
        // gear (lucide settings)
        Item {
            anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter
            width: 40; height: 40
            Shape {
                anchors.centerIn: parent
                width: 24; height: 24
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: gearMa.containsMouse ? "white" : root.slate400
                    fillColor: "transparent"; strokeWidth: 1.7
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" }
                }
                ShapePath {
                    strokeColor: gearMa.containsMouse ? "white" : root.slate400
                    fillColor: "transparent"; strokeWidth: 1.7
                    PathSvg { path: "M12 12 m-3 0 a3 3 0 1 0 6 0 a3 3 0 1 0 -6 0" }
                }
            }
            MouseArea { id: gearMa; anchors.fill: parent; hoverEnabled: true
                cursorShape: Qt.PointingHandCursor; onClicked: root.requestSettings() }
        }
    }

    // ── ОРБ (центрирован, z10) ──────────────────────────────────────────
    Item {
        id: orb
        width: 256; height: 256
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: header.bottom; anchors.topMargin: 76   // сцена опущена к подписи «Подключиться…», шапка на месте
        z: 10

        // внешнее свечение (КРУГЛОЕ — задаём радиусы = половине ширины, иначе квадрат)
        Fx.RadialGradient {
            anchors.centerIn: parent
            width: 360; height: 360
            horizontalRadius: width / 2
            verticalRadius: height / 2
            scale: root.isOn ? 1.2 : (root.isBusy ? 1.1 : 1.0)
            Behavior on scale { NumberAnimation { duration: 700; easing.type: Easing.InOutSine } }
            SequentialAnimation on opacity {
                running: root.isBusy && !Theme.motion.reduceMotion; loops: Animation.Infinite
                NumberAnimation { from: 0.6; to: 0.3; duration: 700 }
                NumberAnimation { from: 0.3; to: 0.6; duration: 700 }
            }
            opacity: root.isOn ? 0.5 : (root.isBusy ? 0.6 : 0.22)
            gradient: Gradient {
                GradientStop { position: 0.0;  color: root.isOn ? root.blueAccent : (root.isBusy ? root.blue400 : Qt.rgba(1,1,1,1)) }
                GradientStop { position: 0.42; color: root.isOn ? Qt.rgba(0x3E/255,0x80/255,0xED/255,0.45) : Qt.rgba(1,1,1,0.22) }
                GradientStop { position: 0.72; color: "transparent" }
                GradientStop { position: 1.0;  color: "transparent" }
            }
        }

        // 2 внешних кольца (эталон: -inset-18 → 292, -inset-36 → 328)
        Rectangle { anchors.centerIn: parent; width: 292; height: 292; radius: 146
            color: "transparent"; border.width: 1.5; border.color: Qt.rgba(1,1,1,0.15) }
        Rectangle { anchors.centerIn: parent; width: 328; height: 328; radius: 164
            color: "transparent"; border.width: 1; border.color: Qt.rgba(1,1,1,0.10) }

        // основная сфера (эталон: inset-2 от 256 → 240)
        Rectangle {
            id: sphere
            anchors.centerIn: parent
            width: 240; height: 240; radius: 120
            gradient: Gradient {
                GradientStop { position: 0.0; color: root.isOn ? root.blue300 : "white" }
                GradientStop { position: 1.0; color: root.isOn ? root.blue600 : "#F1F5F9" }
            }
            scale: orbMa.pressed ? 0.97 : 1.0
            Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
            Rectangle { anchors.fill: parent; anchors.margins: 3;  radius: width/2; color: "transparent"; border.width: 1.5; border.color: Qt.rgba(1,1,1,0.40) }
            Rectangle { anchors.fill: parent; anchors.margins: 13; radius: width/2; color: "transparent"; border.width: 1;   border.color: Qt.rgba(1,1,1,0.20) }
            Rectangle { anchors.fill: parent; anchors.margins: 26; radius: width/2; color: "transparent"; border.width: 1;   border.color: Qt.rgba(1,1,1,0.10) }
        }

        Text {
            anchors.centerIn: parent; z: 40
            text: root.isBusy ? "Connecting…" : (root.isOn ? "Connected" : "Connect")
            color: root.isOn ? "white" : root.slate900
            font.family: Theme.font.display; font.pixelSize: 26; font.weight: Theme.font.wBold
        }

        MouseArea { id: orbMa; anchors.fill: sphere; cursorShape: Qt.PointingHandCursor; onClicked: root.onOrbClicked() }
    }

    // ── ГОРЫ (FULL-BLEED, 1:1 с эталонным React-макетом: 3 слоя, каждый —
    //    градиент, растворяющийся в фон #0A111D к нижней кромке) ───────────
    Item {
        id: mtn
        anchors.left: parent.left; anchors.right: parent.right
        anchors.top: orb.top; anchors.topMargin: 88   // top-[120px] макета при орбе на +32
        height: 250; z: 20
        Shape {
            width: 1000; height: 320
            transform: Scale { xScale: mtn.width / 1000; yScale: 250 / 320 }
            preferredRendererType: Shape.CurveRenderer
            // дальний misty-план (farMountainGrad). SVG-градиенты в эталоне привязаны к bbox
            // КАЖДОГО слоя (objectBoundingBox), поэтому y1 = вершина слоя, не 0.
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 130; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x1E/255,0x29/255,0x3B/255,0.35) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,200 L 100,160 L 200,190 L 320,140 L 410,180 L 500,130 L 590,180 L 680,140 L 820,180 L 920,150 L 1000,180 L 1000,320 L 0,320 Z" }
            }
            // средний план (midMountainGrad)
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 150; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x1E/255,0x24/255,0x30/255,0.75) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,240 L 120,190 L 240,230 L 350,165 L 430,200 L 500,150 L 570,200 L 660,160 L 780,210 L 900,170 L 1000,200 L 1000,320 L 0,320 Z" }
            }
            // передний план (frontMountainGrad) — тоже градиент, НЕ сплошной.
            // Левый склон (550,220→640,180) ПАРАЛЛЕЛЕН подъёму среднего (570,200→660,160),
            // отступ 20 — скала «вписана в силуэт тени», грани не пересекаются (эталон 2026-06-10).
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 170; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x15/255,0x1B/255,0x28/255,0.90) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,280 L 150,230 L 280,260 L 380,190 L 450,220 L 500,170 L 550,220 L 640,180 L 750,240 L 880,200 L 1000,240 L 1000,320 L 0,320 Z" }
            }
        }
    }

    // подпись под орбом (поверх гор)
    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: orb.bottom; anchors.topMargin: 20
        z: 30; horizontalAlignment: Text.AlignHCenter
        text: root.isOn ? qsTr("Защита активна — ваше соединение безопасно")
                        : qsTr("Подключиться — нажмите кнопку выше")
        color: root.slate400
        font.family: Theme.font.body; font.pixelSize: Theme.font.monoData; font.weight: Theme.font.wMedium
    }

    // ── низ: карточка сервера + кнопка обновить (z30 — выше основания гор) ──
    Column {
        anchors.bottom: parent.bottom; anchors.left: parent.left; anchors.right: parent.right
        anchors.bottomMargin: Theme.space.lg
        anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.lg
        z: 30

        // карточка сервера
        Rectangle {
            width: parent.width; implicitHeight: 84; height: 84
            radius: 24
            color: Qt.rgba(0x1E/255, 0x29/255, 0x3B/255, 0.40)
            border.width: 1; border.color: Qt.rgba(0x33/255, 0x41/255, 0x55/255, 0.5)
            Row {
                anchors.fill: parent; anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.lg
                // флаг Латвии
                Rectangle {
                    width: 52; height: 52; radius: 26; anchors.verticalCenter: parent.verticalCenter
                    color: Qt.rgba(0x0F/255,0x17/255,0x2A/255,0.8)
                    border.width: 1; border.color: Qt.rgba(0x33/255,0x41/255,0x55/255,0.5)
                    Item {
                        anchors.centerIn: parent; width: 32; height: 32
                        layer.enabled: true
                        layer.effect: Fx.OpacityMask { maskSource: Rectangle { width: 32; height: 32; radius: 16 } }
                        Column {
                            anchors.fill: parent
                            Rectangle { width: parent.width; height: parent.height * 0.4; color: "#9E3039" }
                            Rectangle { width: parent.width; height: parent.height * 0.2; color: "white" }
                            Rectangle { width: parent.width; height: parent.height * 0.4; color: "#9E3039" }
                        }
                    }
                }
                Column {
                    anchors.verticalCenter: parent.verticalCenter; spacing: 2
                    width: parent.width - 52 - 30 - 18 - 3 * Theme.space.lg
                    Text { text: qsTr("Латвия"); color: "white"
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold }
                    Text { text: "IP: 213.155.12.184"; color: root.slate500
                        font.family: Theme.font.mono; font.pixelSize: 10 }
                }
                Row {  // сигнал-бары
                    spacing: 2; height: 16; anchors.verticalCenter: parent.verticalCenter
                    Rectangle { width: 4; height: 8;  radius: 2; color: root.blueAccent; anchors.bottom: parent.bottom }
                    Rectangle { width: 4; height: 12; radius: 2; color: root.blueAccent; anchors.bottom: parent.bottom }
                    Rectangle { width: 4; height: 16; radius: 2; color: root.blueAccent; anchors.bottom: parent.bottom }
                }
                Shape {
                    width: 18; height: 18; anchors.verticalCenter: parent.verticalCenter
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath { strokeColor: root.slate500; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M7 4 L13 9 L7 14" } }
                }
            }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.requestTab(1) }
        }

        // кнопка «Обновить коннект»
        Rectangle {
            width: parent.width; height: 52; radius: 16
            color: refreshMa.containsMouse ? Qt.rgba(0x1E/255,0x29/255,0x3B/255,0.5) : "transparent"
            border.width: 1
            border.color: refreshMa.containsMouse ? Qt.rgba(0x3E/255,0x80/255,0xED/255,0.5) : Qt.rgba(0x33/255,0x41/255,0x55/255,0.8)
            Behavior on color { ColorAnimation { duration: 160 } }
            Row {
                anchors.centerIn: parent; spacing: 10
                // иконка обновления (Tabler refresh, 24-grid → ровно в 20px, по центру)
                Shape {
                    width: 20; height: 20; anchors.verticalCenter: parent.verticalCenter
                    transform: Scale { xScale: 20/24; yScale: 20/24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath { strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M20 11 a8.1 8.1 0 0 0 -15.5 -2 M4 5 v4 h4" } }
                    ShapePath { strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M4 13 a8.1 8.1 0 0 0 15.5 2 M20 19 v-4 h-4" } }
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter; text: qsTr("Обновить подключение")
                    color: "#DBEAFE"; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium
                }
            }
            MouseArea { id: refreshMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor }
        }
    }
}

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"

// Наш Connect-экран (поверх движка Amnezia). PageHome.qml (полный интерфейс Amnezia)
// остаётся нетронутым и доступен по временной кнопке «А» — потом скроем.
// Состояние/подключение берём из синглтона ConnectionController.
PageType {
    id: root

    readonly property bool isOn:   ConnectionController.isConnected
    readonly property bool isBusy: ConnectionController.isConnectionInProgress

    readonly property color accent:  "#34D399"
    readonly property color idleRing: "#2A2F3A"
    readonly property color iconColor: isOn ? accent : (isBusy ? "#9A9DA6" : "#C9CDD6")

    Rectangle {
        anchors.fill: parent
        color: "#0B0C10"
    }

    // ----------------------------------------------------------------- верхняя панель
    Item {
        id: topBar
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 18 + PageController.safeAreaTopMargin
        anchors.leftMargin: 20
        anchors.rightMargin: 16
        height: 38

        Row {
            id: logoRow
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            spacing: 8

            // мини-щит
            Item {
                width: 22; height: 22
                anchors.verticalCenter: parent.verticalCenter
                Shape {
                    anchors.fill: parent
                    preferredRendererType: Shape.CurveRenderer
                    transform: Scale { xScale: 22/24; yScale: 22/24 }
                    ShapePath {
                        strokeColor: root.accent; fillColor: "transparent"; strokeWidth: 1.8
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }
                    }
                }
            }

            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Tribe VPN"
                color: "#F2F2F5"
                font.pixelSize: 17
                font.weight: Font.Bold
                font.letterSpacing: -0.2
            }
        }

        // Скрытый вход в диагностику: 5 тапов по логотипу за 3 секунды (CLIENT/§7).
        property int logoTaps: 0
        Timer { id: tapReset; interval: 3000; onTriggered: topBar.logoTaps = 0 }
        MouseArea {
            anchors.left: logoRow.left
            anchors.top: logoRow.top
            width: logoRow.width
            height: logoRow.height
            onClicked: {
                tapReset.restart()
                if (++topBar.logoTaps >= 5) {
                    topBar.logoTaps = 0
                    tapReset.stop()
                    // push нашего экрана по относительному URL (резолвится в qrc и с диска), без C++/enum.
                    if (root.StackView.view)
                        root.StackView.view.push(Qt.resolvedUrl("PageDiagnostics.qml"))
                }
            }
        }

        // временная «А» → полный интерфейс Amnezia (со всеми функциями). TODO: скрыть позже.
        Rectangle {
            id: amneziaBridge
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: 38; height: 38; radius: 19
            color: bridgeMouse.pressed ? "#1C1F26" : "#13151B"
            border.color: "#262A33"
            border.width: 1

            Text {
                anchors.centerIn: parent
                text: "A"
                color: "#9A9DA6"
                font.pixelSize: 18
                font.weight: Font.Bold
            }

            MouseArea {
                id: bridgeMouse
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: PageController.goToPage(PageEnum.PageHome)
            }
        }
    }

    // ----------------------------------------------------------------- центральный «диск»
    Item {
        id: dial
        width: 244; height: 244
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        anchors.verticalCenterOffset: -28

        // лицо диска
        Rectangle {
            anchors.centerIn: parent
            width: 196; height: 196; radius: 98
            color: "#0E1118"
            border.color: "#181B22"
            border.width: 1
        }

        // серое кольцо (когда выключено)
        Shape {
            anchors.fill: parent
            visible: !root.isOn && !root.isBusy
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                fillColor: "transparent"; strokeColor: root.idleRing; strokeWidth: 4
                capStyle: ShapePath.RoundCap
                PathAngleArc { centerX: 122; centerY: 122; radiusX: 100; radiusY: 100; startAngle: 0; sweepAngle: 360 }
            }
        }

        // зелёное кольцо + свечение (когда подключено)
        Shape {
            id: glowRing
            anchors.fill: parent
            opacity: root.isOn ? 1 : 0
            visible: opacity > 0
            Behavior on opacity { NumberAnimation { duration: 450; easing.type: Easing.OutCubic } }

            preferredRendererType: Shape.CurveRenderer
            layer.enabled: true
            layer.samples: 4
            layer.smooth: true
            layer.effect: DropShadow {
                horizontalOffset: 0; verticalOffset: 0
                radius: 26; samples: 40
                color: root.accent
            }
            ShapePath {
                fillColor: "transparent"; strokeColor: root.accent; strokeWidth: 4
                capStyle: ShapePath.RoundCap
                PathAngleArc { centerX: 122; centerY: 122; radiusX: 100; radiusY: 100; startAngle: 0; sweepAngle: 360 }
            }

            // «дыхание» при активном подключении
            SequentialAnimation on opacity {
                running: root.isOn
                loops: Animation.Infinite
                NumberAnimation { to: 0.62; duration: 1400; easing.type: Easing.InOutSine }
                NumberAnimation { to: 1.0;  duration: 1400; easing.type: Easing.InOutSine }
            }
        }

        // спиннер (когда подключаемся)
        Shape {
            id: spinner
            anchors.fill: parent
            visible: root.isBusy
            preferredRendererType: Shape.CurveRenderer
            layer.enabled: true
            layer.samples: 4
            ShapePath {
                fillColor: "transparent"; strokeColor: root.accent; strokeWidth: 4
                capStyle: ShapePath.RoundCap
                PathAngleArc { centerX: 122; centerY: 122; radiusX: 100; radiusY: 100; startAngle: -90; sweepAngle: 110 }
            }
            RotationAnimator on rotation {
                running: root.isBusy
                from: 0; to: 360
                loops: Animation.Infinite
                duration: 1100
            }
        }

        // иконка по центру: щит (+ галочка, когда подключено)
        Item {
            id: centerIcon
            anchors.centerIn: parent
            width: 78; height: 78

            Shape {
                anchors.fill: parent
                preferredRendererType: Shape.CurveRenderer
                transform: Scale { xScale: centerIcon.width/24; yScale: centerIcon.height/24 }
                ShapePath {
                    strokeColor: root.iconColor; fillColor: "transparent"; strokeWidth: 1.5
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }
                }
                ShapePath {
                    strokeColor: root.isOn ? root.accent : "transparent"; fillColor: "transparent"; strokeWidth: 1.5
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M8.5 12l2.5 2.5 4.5-4.5" }
                }
            }
        }

        // вся область диска — кнопка-тоггл
        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: ConnectionController.connectButtonClicked()
        }
    }

    // ----------------------------------------------------------------- статус под диском
    ColumnLayout {
        anchors.top: dial.bottom
        anchors.topMargin: 28
        anchors.horizontalCenter: parent.horizontalCenter
        width: Math.min(parent.width - 56, 360)
        spacing: 6

        Text {
            Layout.fillWidth: true
            text: root.isOn ? qsTr("Защита включена")
                  : (root.isBusy ? qsTr("Подключаемся…") : qsTr("Готов к подключению"))
            color: "#F2F2F5"
            font.pixelSize: 24
            font.weight: Font.Bold
            font.letterSpacing: -0.3
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            text: root.isOn ? ServersUiController.defaultServerName
                  : (root.isBusy ? qsTr("Устанавливаем защищённое соединение")
                                 : qsTr("Нажмите на кнопку, чтобы подключиться"))
            color: "#9A9DA6"
            font.pixelSize: 14
            lineHeight: 1.4
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            visible: text.length > 0
        }
    }

    // ----------------------------------------------------------------- продающее пояснение снизу
    Text {
        anchors.bottom: parent.bottom
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottomMargin: 28 + PageController.safeAreaBottomMargin
        width: Math.min(parent.width - 56, 360)
        text: qsTr("Рунет — напрямую · зарубежные сайты — через VPN")
        color: "#6B7078"
        font.pixelSize: 13
        lineHeight: 1.4
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
    }
}

import QtQuick
import QtQuick.Layouts

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: онбординг первого запуска (вместо ванильного PageSetupWizardStart).
// Большой бренд-марк + Tribe VPN, тексты ценности, CTA «Приступим».
// PageStart по requestStart() помечает онбординг пройденным и уводит на Connect.
PageType {
    id: root

    signal requestStart()

    // iOS: PageController.safeArea* реализован только для Android → берём максимум
    // с SafeArea (Qt 6.9+); окно edge-to-edge (Qt.ExpandedClientAreaHint в main2.qml)
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property real safeBottom: Math.max(PageController.safeAreaBottomMargin, SafeArea.margins.bottom)

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // звёздное небо (как на Connect, облегчённое)
    Item {
        id: starField
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: parent.height * 0.5; clip: true
        property var starsData: []
        Component.onCompleted: {
            var arr = []
            for (var i = 0; i < 24; i++)
                arr.push({ tx: Math.random(), ty: Math.random() * 0.7,
                           s: Math.random() * 1.8 + 1, o: Math.random() * 0.5 + 0.12 })
            starsData = arr
        }
        Repeater {
            model: starField.starsData
            delegate: Rectangle {
                width: modelData.s; height: modelData.s; radius: width / 2; color: "white"
                x: modelData.tx * starField.width; y: modelData.ty * starField.height
                opacity: modelData.o
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

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: 0

        Item { Layout.fillHeight: true }

        // большой бренд по центру: марка из 5 баров (пропорции лого 16/28/36/26/18),
        // под ней wordmark «Tribe VPN» ровно на ширину марки (HorizontalFit)
        Column {
            Layout.alignment: Qt.AlignHCenter
            spacing: Theme.space.lg

            Row {
                id: bigMark
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: 11
                // низ баров на одной линии; масштаб ×2.3 от пропорций лого
                Rectangle { width: 18; height: 37; radius: 9; color: "#EEF3F9";           anchors.bottom: parent.bottom }
                Rectangle { width: 18; height: 64; radius: 9; color: "#EEF3F9";           anchors.bottom: parent.bottom }
                Rectangle { width: 18; height: 83; radius: 9; color: Theme.color.accent;  anchors.bottom: parent.bottom }
                Rectangle { width: 18; height: 60; radius: 9; color: "#EEF3F9";           anchors.bottom: parent.bottom }
                Rectangle { width: 18; height: 41; radius: 9; color: "#EEF3F9";           anchors.bottom: parent.bottom }
            }
            Text {
                id: bigText
                anchors.horizontalCenter: parent.horizontalCenter
                width: bigMark.width
                text: "Tribe VPN"; color: "#EEF3F9"
                fontSizeMode: Text.HorizontalFit
                font.family: Theme.font.display; font.pixelSize: 64; minimumPixelSize: 12
                font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * 32
                horizontalAlignment: Text.AlignHCenter
            }
        }

        // слоган + описание — посередине между лого и кнопкой
        Item { Layout.fillHeight: true }

        Text {
            Layout.fillWidth: true
            text: qsTr("Умный VPN\nс искусственным\nинтеллектом")
            color: Theme.color.text1
            font.family: Theme.font.display; font.pixelSize: Theme.font.h2
            font.weight: Theme.font.wBold
            lineHeight: 1.2
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.lg
            text: qsTr("Зарубежные сайты открываются через VPN, а российские — банки, Госуслуги, маркетплейсы — напрямую. Без блокировок и переключений: всё работает сразу.")
            color: Theme.color.text2
            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
            lineHeight: 1.5
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }

        Item { Layout.fillHeight: true }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 52
            Layout.bottomMargin: Theme.space.xl + root.safeBottom
            radius: Theme.radius.lg
            color: ctaMa.pressed ? Theme.color.accentDeep
                                 : (ctaMa.containsMouse ? Theme.color.accentBright : Theme.color.accent)
            Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
            Text {
                anchors.centerIn: parent
                text: qsTr("Приступим")
                color: "white"
                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                font.weight: Theme.font.wSemibold
            }
            MouseArea { id: ctaMa; anchors.fill: parent; hoverEnabled: true
                cursorShape: Qt.PointingHandCursor; onClicked: root.requestStart() }
        }
    }
}

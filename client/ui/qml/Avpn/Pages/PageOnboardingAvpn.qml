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
        anchors.topMargin: PageController.safeAreaTopMargin
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: 0

        Item { Layout.fillHeight: true }

        // большой бренд: 5 баров (пропорции лого 16/28/36/26/18) + wordmark, низ баров на базовой линии
        Item {
            Layout.alignment: Qt.AlignHCenter
            implicitWidth: bigMark.width + 16 + bigText.width
            implicitHeight: bigText.height
            Row {
                id: bigMark
                anchors.left: parent.left
                anchors.bottom: bigText.baseline
                spacing: 5
                Rectangle { width: 8; height: 18; radius: 4; color: "#EEF3F9";           anchors.bottom: parent.bottom }
                Rectangle { width: 8; height: 31; radius: 4; color: "#EEF3F9";           anchors.bottom: parent.bottom }
                Rectangle { width: 8; height: 40; radius: 4; color: Theme.color.accent;  anchors.bottom: parent.bottom }
                Rectangle { width: 8; height: 29; radius: 4; color: "#EEF3F9";           anchors.bottom: parent.bottom }
                Rectangle { width: 8; height: 20; radius: 4; color: "#EEF3F9";           anchors.bottom: parent.bottom }
            }
            Text {
                id: bigText
                anchors.left: bigMark.right; anchors.leftMargin: 16
                text: "Tribe VPN"; color: "#EEF3F9"
                font.family: Theme.font.display; font.pixelSize: 36; font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * 36
            }
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.xxl
            text: qsTr("Работает всё — и Рунет,\nи весь интернет")
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
            Layout.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
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

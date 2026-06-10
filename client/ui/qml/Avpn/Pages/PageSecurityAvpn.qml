import QtQuick
import QtQuick.Layouts

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: «Защита» (вкладка nav) — P-U1 стаб. Реальные тогглы (Kill Switch/DNS/авто-выкл) — P-U5.
PageType {
    id: root

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 8 + PageController.safeAreaTopMargin
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        TribeHeader { Layout.fillWidth: true; title: qsTr("Защита") }

        TribeListRow {
            Layout.fillWidth: true
            title: qsTr("Kill Switch")
            subtitle: qsTr("блокировать трафик без VPN")
            interactive: false
            rightItem: TribeToggle { anchors.verticalCenter: parent.verticalCenter }
        }
        TribeListRow {
            Layout.fillWidth: true
            title: qsTr("Авто-выкл для РФ-приложений")
            subtitle: qsTr("WB, Озон, банки")
            rightItem: Text { text: "›"; color: Theme.color.text3; font.pixelSize: Theme.font.h3; anchors.verticalCenter: parent.verticalCenter }
        }
        TribeListRow {
            Layout.fillWidth: true
            title: qsTr("DNS")
            subtitle: qsTr("1.1.1.1")
            rightItem: Text { text: "›"; color: Theme.color.text3; font.pixelSize: Theme.font.h3; anchors.verticalCenter: parent.verticalCenter }
        }

        Item { Layout.fillHeight: true }
    }
}

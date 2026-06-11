import QtQuick
import QtQuick.Layouts

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Locations (regions + Auto). P-U1 stub with static data — real pool wired in P-U4.
PageType {
    id: root

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // static demo regions (P-U4: from GET /v1/subscription pool)
    readonly property var regions: [
        { name: qsTr("Авто (быстрейший)"), sub: "8 ms · выбрано движком", load: 4, auto: true },
        { name: qsTr("Нидерланды"),        sub: "node-ams · 12 ms",       load: 4, auto: false },
        { name: qsTr("Германия"),          sub: "node-fra · 18 ms",       load: 3, auto: false },
        { name: qsTr("Финляндия"),         sub: "node-hel · 22 ms",       load: 2, auto: false }
    ]
    property int selected: 0

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 8 + Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top) // iOS: PageController даёт 0
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        Text {
            text: qsTr("РЕКОМЕНДУЕМЫЕ")
            color: Theme.color.accent
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        Repeater {
            model: root.regions
            delegate: TribeListRow {
                Layout.fillWidth: true
                title: modelData.name
                subtitle: modelData.sub
                onClicked: root.selected = index
                rightItem: RowLayout {
                    spacing: Theme.space.md
                    anchors.verticalCenter: parent.verticalCenter
                    LoadBars { level: modelData.load }
                    Text {
                        text: index === root.selected ? "✓" : ""
                        color: Theme.color.accent
                        font.pixelSize: Theme.font.h3
                    }
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}

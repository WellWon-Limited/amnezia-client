import QtQuick
import QtQuick.Layouts

import ".."   // Theme, ScanTexts, Haptic

// AVPN: «Все страны» and its menu (artboard vpn-scanner-kit.js scanFoot, kit spec «Все страны» и меню):
// the button = TribeTransportSelector's surface (surface1, border, radius md) at TribeButton height 46, up to 150
// wide, flag 18 + name when a country is chosen, chevron 16; the menu = TribeCard elevated (surface2, border2,
// radius lg) 244 wide, rows 44 like TribeListRow (flag 22 + name + count), the chosen row = the segment fill
// (chipSelected + accent border) with the «Авто» card's check circle 20. It opens upwards, `menuLift` above the
// button top (the bar sets it so the menu bottom sits 4 px under the bar's top edge). The menu is an overlay:
// the UI-DESIGN §8a.1 drawerDepth contract (Back / Escape closes it, not the page).
Item {
    id: root

    property var countries: []          // ScanView bar.countries: [{cc, count, name?}]
    property int total: 0
    property string selected: ""        // "" = «Все страны»
    property real menuLift: 4
    property real maxButtonWidth: Theme.scan.menuButtonMax   // the bar narrows it on small screens
    readonly property bool opened: panel.opened
    signal chosen(string cc)

    implicitWidth: btn.width
    implicitHeight: Theme.scan.barHeight

    function nameOf(cc) {
        for (let i = 0; i < countries.length; ++i)
            if (countries[i].cc === cc)
                return countries[i].name || cc
        return cc
    }
    function open() { panel.open() }
    function close() { panel.close(false) }
    function toggle() { if (panel.opened) panel.close(false); else panel.open() }

    onEnabledChanged: if (!enabled) panel.close(false)

    Rectangle {
        id: btn
        height: Theme.scan.barHeight
        width: Math.min(root.maxButtonWidth, Math.ceil(btnRow.implicitWidth) + Theme.space.md + 10)
        radius: Theme.radius.md
        color: panel.opened ? Theme.color.chipSelected : Theme.color.surface1
        border.width: 1
        border.color: panel.opened ? Theme.color.accent : Theme.color.border
        opacity: root.enabled ? 1.0 : 0.45

        Accessible.role: Accessible.ComboBox
        Accessible.name: root.selected === "" ? ScanTexts.allCountries : root.nameOf(root.selected)

        RowLayout {
            id: btnRow
            anchors.left: parent.left
            anchors.leftMargin: Theme.space.md
            anchors.right: parent.right
            anchors.rightMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.space.sm
            TribeFlag {
                visible: root.selected !== ""
                Layout.preferredWidth: 18; Layout.preferredHeight: 18
                code: root.selected
            }
            Text {
                id: btnLabel
                Layout.fillWidth: true
                Layout.maximumWidth: Theme.scan.menuButtonMax
                text: root.selected === "" ? ScanTexts.allCountries : root.nameOf(root.selected)
                textFormat: Text.PlainText
                elide: Text.ElideRight
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wSemibold
            }
            TribeStrokeIcon {
                Layout.preferredWidth: 16; Layout.preferredHeight: 16
                icon: panel.opened ? "chevron-up" : "chevron-down"
                tint: Theme.color.text3
            }
        }
        MouseArea {
            anchors.fill: parent
            enabled: root.enabled
            cursorShape: Qt.PointingHandCursor
            onClicked: { Haptic.play("selection"); root.toggle() }
        }
    }

    Rectangle {
        id: panel
        property bool opened: false
        property int depthIndex: 0
        function open() {
            if (opened) return
            opened = true
            depthIndex = PageController.incrementDrawerDepth()
        }
        function close(viaController) {
            if (!opened) return
            opened = false
            depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }
        Connections {
            target: PageController
            enabled: panel.opened
            function onCloseTopDrawer() {
                if (panel.depthIndex === PageController.getDrawerDepth())
                    panel.close(true)
            }
        }
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        visible: opened
        x: 0
        y: -(height + root.menuLift)
        z: 30
        width: Theme.scan.menuWidth
        height: Math.min(Theme.scan.menuMaxHeight, menuCol.implicitHeight + 2 * 6)
        radius: Theme.radius.lg
        color: Theme.color.surface2
        border.width: 1
        border.color: Theme.color.border2

        Flickable {
            anchors.fill: parent
            anchors.margins: 6
            contentHeight: menuCol.implicitHeight
            clip: contentHeight > height
            interactive: contentHeight > height
            boundsBehavior: Flickable.StopAtBounds

            Column {
                id: menuCol
                width: parent.width
                spacing: 2
                Repeater {
                    model: [{ cc: "", count: root.total }].concat(root.countries)
                    delegate: Rectangle {
                        id: mrow
                        required property var modelData
                        readonly property bool on: root.selected === (modelData.cc || "")
                        width: menuCol.width
                        height: Theme.scan.menuRow
                        radius: Theme.radius.sm
                        color: on ? Theme.color.chipSelected : (mma.containsMouse ? Theme.color.glassStrong : "transparent")
                        border.width: 1
                        border.color: on ? Theme.color.accent : "transparent"
                        Accessible.role: Accessible.RadioButton
                        Accessible.name: mrowName.text
                        Accessible.checked: on
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 10
                            anchors.rightMargin: 10
                            spacing: 10
                            TribeFlag {
                                visible: (mrow.modelData.cc || "") !== ""
                                Layout.preferredWidth: 22; Layout.preferredHeight: 22
                                code: mrow.modelData.cc || ""
                            }
                            Text {
                                id: mrowName
                                Layout.fillWidth: true
                                text: (mrow.modelData.cc || "") === "" ? ScanTexts.allCountries
                                                                       : (mrow.modelData.name || mrow.modelData.cc)
                                textFormat: Text.PlainText
                                elide: Text.ElideRight
                                color: Theme.color.text1
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.bodyS
                                font.weight: Theme.font.wMedium
                            }
                            Text {
                                text: String(mrow.modelData.count || 0)
                                textFormat: Text.PlainText
                                color: Theme.color.text3
                                font.family: Theme.font.mono
                                font.pixelSize: Theme.font.caption
                            }
                            Rectangle {
                                Layout.preferredWidth: 20; Layout.preferredHeight: 20
                                radius: Theme.radius.pill
                                color: mrow.on ? Theme.color.accent : "transparent"
                                TribeStrokeIcon {
                                    anchors.centerIn: parent
                                    width: 12; height: 12
                                    visible: mrow.on
                                    icon: "check-mark"
                                    tint: Theme.color.bg800
                                    weight: 2.6
                                }
                            }
                        }
                        MouseArea {
                            id: mma
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                Haptic.play("selection")
                                panel.close(false)
                                root.chosen(mrow.modelData.cc || "")
                            }
                        }
                    }
                }
            }
        }
    }
}

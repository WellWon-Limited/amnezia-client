import QtQuick
import QtQuick.Layouts

import ".."   // Theme, ScanTexts

// AVPN: what is connected now, at the top of the Scanner's list - ONE line (owner 18.11, variant B; artboard
// «Правки 18.11», kit «Подключение одной строкой»): the live state badge (filled green «Подключено», amber
// «Подключение…»), the flag, the server and the protocol; with the VPN off a dash and «VPN не подключён».
// The former card «Ваше подключение» (services, «Сайты РФ», speed and «Проверить и отправить отчёт») left the
// Scanner: the check with the report runs from Support (TribeSupportCheckBar, TribeScanner.checkFromSupport()),
// the service dots stay on the home screen. The state comes from the engine in every Scanner phase.
Rectangle {
    id: root

    property string serverLabel: ""        // the live node: the view's current row, else the engine's node
    property string serverCc: ""
    property string liveState: "off"       // "off" | "connecting" | "connected" (PageScannerTribe.liveVpn)
    property string liveProto: ""          // "awg" | "xray" - the transport the tunnel runs on
    property string liveProtoVersion: ""

    readonly property bool liveOn: liveState === "connected"
    readonly property bool named: liveState !== "off" && serverLabel !== ""

    implicitHeight: Math.max(Theme.scan.cardRow, row.implicitHeight) + 2 * 12
    radius: Theme.radius.lg
    color: Theme.color.surface1
    border.width: 1
    border.color: Theme.color.border

    Accessible.role: Accessible.StaticText
    Accessible.name: root.liveState === "off" ? ScanTexts.cardOff
        : (root.liveOn ? ScanTexts.rowConnected : ScanTexts.rowConnecting) + (root.named ? ", " + root.serverLabel : "")

    RowLayout {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: Theme.space.lg
        anchors.rightMargin: Theme.space.lg
        spacing: Theme.space.sm

        // off: the Doctor sheet's «skip» dash and the sentence, not a grey badge alone
        Rectangle {
            visible: root.liveState === "off"
            Layout.preferredWidth: 20; Layout.preferredHeight: 20
            color: "transparent"
            Rectangle {
                anchors.centerIn: parent
                width: 8; height: 2; radius: 1
                color: Theme.color.text3
            }
        }
        Text {
            visible: root.liveState === "off"
            Layout.fillWidth: true
            text: ScanTexts.cardOff
            textFormat: Text.PlainText
            elide: Text.ElideRight
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyS
        }
        TribeLabelBadge {
            visible: root.liveState !== "off"
            small: true
            label: root.liveOn ? ScanTexts.rowConnected : ScanTexts.rowConnecting
            fg: root.liveOn ? Theme.color.bg800 : Theme.color.warning
            fill: root.liveOn ? Theme.color.connected : Theme.color.badgeWarn
            filled: root.liveOn
        }
        TribeFlag {
            visible: root.named && root.serverCc !== ""
            Layout.preferredWidth: 18; Layout.preferredHeight: 18
            code: root.serverCc
        }
        Text {
            visible: root.named
            Layout.fillWidth: true
            Layout.maximumWidth: Math.ceil(implicitWidth)
            text: root.serverLabel
            textFormat: Text.PlainText
            elide: Text.ElideRight
            color: Theme.color.text1
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyS
            font.weight: Theme.font.wMedium
        }
        TribeTransportBadge {
            visible: root.liveOn && root.liveProto !== ""
            transport: root.liveProto
            version: root.liveProtoVersion
            active: true
        }
        Item { Layout.fillWidth: true }
    }
}

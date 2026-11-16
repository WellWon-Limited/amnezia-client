import QtQuick
import QtQuick.Layouts

import ".."   // Theme, ScanTexts, Haptic

// AVPN: one row of the Scanner (artboard vpn-scanner-kit.js scanRow, kit spec «Строка Сканера»): the server-list
// row of PageServersTribe (66, radius 16, flag 38, name Manrope 15/700) with the small state badge
// (TribeLabelBadge) next to the name, the transport badge + speed word / reason + the crowd mark under it, and the
// speed class as LoadBars (5 / 3 / 2 / 0) over the ms. Values come from the ScanView row JSON (ScanMachine.h
// scanRowViewToJson): state, speed, bars, ms, flags cache / dimmed / verifying / current / unverified /
// live_unverified / crowd / not_tappable. The row never reorders itself: the list owns the order.
Rectangle {
    id: row

    property string label: ""
    property string countryCode: ""
    property string transport: "xray"     // "awg" | "xray"
    property string version: ""           // AWG major ("3.1"); empty -> «Amnezia»
    property string rowState: "works"     // works | slow | not_verified | connecting | connected | failed
    property string speed: "none"         // fast | medium | slow | none
    property int bars: 0
    property int ms: -1
    property bool cached: false           // the last result shown while no scan can run (drawn at 55 %)
    property bool dimmed: false           // «Не удалось» (50 %)
    property bool tappable: true
    property bool verifying: false
    property bool liveUnverified: false   // «Подключено» before its own tunnel probe: «проверяем загрузку…»
    property bool unverified: false       // «Не проверено»
    property bool crowd: false            // «работает у других в вашей сети»
    property Component fallbackFlag: null // provider row without a country: the servers page's globe tile
    signal tapped()

    readonly property bool live: rowState === "connecting" || rowState === "connected"
    readonly property bool failed: rowState === "failed"
    readonly property bool notVerified: unverified && rowState !== "connected"
    readonly property bool hideFigures: notVerified || liveUnverified

    readonly property string badgeText: rowState === "works" ? ScanTexts.rowWorks
        : rowState === "slow" ? ScanTexts.rowSlow
        : rowState === "not_verified" ? ScanTexts.rowNotVerified
        : rowState === "connecting" ? ScanTexts.rowConnecting
        : rowState === "connected" ? ScanTexts.rowConnected
        : ScanTexts.rowFailed
    readonly property color badgeFg: (rowState === "works" || rowState === "connected") ? Theme.color.connected
        : (rowState === "slow" || rowState === "connecting") ? Theme.color.warning
        : rowState === "failed" ? Theme.color.danger
        : Theme.color.text3
    readonly property color badgeFill: (rowState === "works" || rowState === "connected") ? Theme.color.badgeOn
        : (rowState === "slow" || rowState === "connecting") ? Theme.color.badgeWarn
        : rowState === "failed" ? Theme.color.badgeOff
        : Theme.color.glass
    readonly property string subText: notVerified ? ScanTexts.rowCheckOnConnect
        : (liveUnverified && rowState === "connected") ? ScanTexts.liveChecking
        : speed === "fast" ? ScanTexts.speedFast
        : speed === "medium" ? ScanTexts.speedMedium
        : ""
    readonly property bool subIsReason: notVerified || (liveUnverified && rowState === "connected")

    implicitHeight: Theme.scan.rowHeight
    radius: Theme.radius.lg
    color: live ? Theme.color.chipSelected : Theme.color.surface1
    border.width: 1
    border.color: live ? Theme.color.accent : Theme.color.border
    opacity: (failed || dimmed) ? 0.5 : (cached ? 0.55 : 1.0)
    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }
    Behavior on opacity { NumberAnimation { duration: Theme.motion.fast } }

    Accessible.role: Accessible.Button
    Accessible.name: label + ", " + badgeText

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.space.md
        anchors.rightMargin: Theme.space.lg
        spacing: Theme.space.md

        TribeFlag {
            Layout.preferredWidth: Theme.scan.flag
            Layout.preferredHeight: Theme.scan.flag
            code: row.countryCode
            fallback: row.fallbackFlag
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: Theme.badge.stackGap

            RowLayout {
                id: nameLine
                Layout.fillWidth: true
                spacing: 6
                Text {
                    // shrink-to-fit next to the badge: fills up to its own width, elides below it
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    Layout.maximumWidth: Math.ceil(implicitWidth)   // layouts snap to whole pixels
                    text: row.label
                    textFormat: Text.PlainText
                    elide: Text.ElideRight
                    color: Theme.color.text1
                    font.family: Theme.font.display
                    font.pixelSize: Theme.font.bodyS + 1
                    font.weight: Theme.font.wBold
                }
                TribeLabelBadge {
                    id: stateBadge
                    small: true
                    label: row.badgeText
                    fg: row.badgeFg
                    fill: row.badgeFill
                }
                Item { Layout.fillWidth: true }
            }

            RowLayout {
                id: subLine
                Layout.fillWidth: true
                spacing: Theme.space.xs
                TribeTransportBadge {
                    id: transportBadge
                    transport: row.transport
                    version: row.version
                    active: row.live
                    verifying: row.rowState === "connecting" || (row.live && row.verifying)
                }
                Text {
                    visible: row.subText !== ""
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    Layout.maximumWidth: Math.ceil(implicitWidth)   // layouts snap to whole pixels
                    text: row.subText
                    textFormat: Text.PlainText
                    elide: Text.ElideRight
                    color: Theme.color.text3
                    font.family: row.subIsReason ? Theme.font.body : Theme.font.mono
                    font.pixelSize: row.subIsReason ? Theme.badge.text : Theme.font.micro
                }
                TribeStrokeIcon {
                    id: crowdIcon
                    visible: row.crowd
                    Layout.preferredWidth: 12
                    Layout.preferredHeight: 12
                    icon: "users"
                    tint: Theme.color.accent
                    Accessible.role: Accessible.Graphic
                    Accessible.name: ScanTexts.crowdName
                }
                Item { Layout.fillWidth: true }
            }
        }

        ColumnLayout {
            Layout.alignment: Qt.AlignVCenter
            spacing: Theme.badge.stackGap
            LoadBars {
                Layout.alignment: Qt.AlignHCenter
                scale: 0.9
                transformOrigin: Item.Bottom
                level: row.hideFigures ? 0 : row.bars
                failed: row.failed
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: (row.liveUnverified || row.ms < 0) ? "—"
                      : (row.notVerified ? ScanTexts.msApprox.arg(row.ms) : ScanTexts.ms.arg(row.ms))
                textFormat: Text.PlainText
                color: Theme.color.text3
                font.family: Theme.font.mono
                font.pixelSize: Theme.font.caption
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        enabled: row.tappable
        cursorShape: row.tappable ? Qt.PointingHandCursor : Qt.ArrowCursor
        onClicked: { Haptic.play("selection"); Haptic.arm(); row.tapped() }
    }
}

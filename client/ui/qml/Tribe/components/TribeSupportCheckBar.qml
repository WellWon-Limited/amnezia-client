import QtQuick
import QtQuick.Layouts

import ".."   // Theme, ScanTexts, Haptic

// AVPN: «Проверить подключение и отправить отчёт» - the Support tab's own action (owner decision 18.11, variant B;
// artboard «Правки 18.11», frames «Поддержка»). Pinned under the chat header, so it never scrolls away with a long
// thread. A tap runs the full check of the connection (server, services, «Сайты РФ», speed) and sends the report to
// THIS chat: TribeScanner.checkFromSupport() - no Scanner screen, no scan. While it runs the bar says so and fills
// a thin progress bar (view.support_check {running, progress}; progress -1 = the report alone, no stages); the end
// is the report message in the thread plus the shade «Отчёт отправлен в поддержку» / «Отчёт уйдёт, когда появится
// связь» the machine raises on any page. A second tap while it runs answers «Проверка уже идёт» (the machine).
Rectangle {
    id: root

    property var check: ({})               // TribeScanner.view.support_check
    signal tapped()

    readonly property bool running: check.running === true
    readonly property real progress: check.progress === undefined ? -1 : Number(check.progress)

    implicitHeight: 60
    color: Theme.color.bg700
    // the chat header's hairline continues under the bar: one block over the thread
    Rectangle { width: parent.width; height: 1; color: Theme.color.border; anchors.bottom: parent.bottom }

    Accessible.role: Accessible.Button
    Accessible.name: running ? (progress < 0 ? ScanTexts.supportSending : ScanTexts.supportChecking) : ScanTexts.supportCheck

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.space.lg
        anchors.rightMargin: Theme.space.lg
        spacing: Theme.space.md

        // the icon tile of the old «Доктор» (activity glyph), accent on a glass tile
        Rectangle {
            Layout.preferredWidth: 34; Layout.preferredHeight: 34
            radius: Theme.radius.md
            color: Theme.color.badgeAccent
            border.width: 1
            border.color: Theme.color.border
            TribeStrokeIcon {
                anchors.centerIn: parent
                width: 20; height: 20
                icon: "activity"
                tint: Theme.color.accent
                weight: 2
                // breathes while the check runs (the Doctor sheet's current-stage pulse), steady otherwise
                property real pulse: 1
                opacity: root.running ? pulse : 1
                SequentialAnimation on pulse {
                    running: root.running && !Theme.motion.reduceMotion
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 0.4; duration: 600; easing.type: Easing.InOutSine }
                    NumberAnimation { from: 0.4; to: 1.0; duration: 600; easing.type: Easing.InOutSine }
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text {
                Layout.fillWidth: true
                text: root.running ? (root.progress < 0 ? ScanTexts.supportSending : ScanTexts.supportChecking)
                                   : ScanTexts.supportCheck
                textFormat: Text.PlainText
                elide: Text.ElideRight
                // the whole action fits on a 360 px phone: shrink a little before eliding
                fontSizeMode: Text.HorizontalFit
                minimumPixelSize: Theme.font.caption
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wSemibold
            }
            Text {
                Layout.fillWidth: true
                text: root.running ? ScanTexts.supportCheckingSub : ScanTexts.supportCheckSub
                textFormat: Text.PlainText
                elide: Text.ElideRight
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: Theme.font.caption
            }
        }

    }

    // the check's progress along the bottom edge (indeterminate for the report alone)
    TribeProgressBar {
        visible: root.running
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        percent: root.progress < 0 ? -1 : Math.round(100 * root.progress)
    }

    MouseArea {
        anchors.fill: parent
        enabled: !root.running
        cursorShape: Qt.PointingHandCursor
        onClicked: { Haptic.play("light"); root.tapped() }
    }
}

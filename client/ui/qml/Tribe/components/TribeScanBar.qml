import QtQuick
import QtQuick.Layouts

import ".."   // Theme, ScanTexts, Haptic

// AVPN: the Scanner's pinned bottom bar (artboard vpn-scanner-kit.js scanFoot, plan §1.2/§1.3): the hint line, then
// ONE full-width action button. `bar` is the ScanView bar JSON (ScanMachine.h): button stop | retry | retry_in_s |
// retry_in_min | connect_and_scan, button_enabled, button_value, hint none | cellular_budget_hour, scope_countries.
// Owner 24.11: the country menu left of the button is gone - the Scanner opens on its country choice (the page's
// «Выбор»), so the bar serves both views of the page:
//  - choosing (one screen, owner 24.11 evening: a row tap only selects): the page says what a press does with the
//    selected scope (`chooseAction`): scan - «Сканировать» (primary; during the 30 s pause or the cellular hour its
//    countdown, disabled, the hour's hint over it); show - «Показать результат» (no scan can run now and the scope
//    has a fresh result; the hint says why it does not scan); connect - «Подключиться и проверить»;
//  - the result: «Остановить» while scanning, then «Сканировать снова» / its countdown, «Подключиться и проверить».
// The countdown lives INSIDE the bar: a 1 s Timer rewrites only the texts from the end time (the view's
// cooldown_ends_at_ms against its now_ms; minutes and a view without them: now + button_value at arrival), so the
// screen is not rebuilt every second; at zero the button is enabled again (the machine re-checks the cooldown).
Item {
    id: root

    property var bar: ({})
    property bool choosing: false        // the page's country choice: the button acts on the selected scope
    property string chooseAction: "scan" // the choice's press: scan | show | connect (the page decides)
    property bool again: false           // a result is on the screen: «Сканировать снова» instead of «Сканировать»
    signal stopTapped()
    signal retryTapped()
    signal connectAndScanTapped()
    signal scanTapped()                  // the choice: scan the selected scope
    signal showTapped()                  // the choice: show the selected scope's fresh result (no scan)

    readonly property string kind: bar.button || "retry"
    readonly property bool countdown: kind === "retry_in_s" || kind === "retry_in_min"
    readonly property bool fallback: kind === "connect_and_scan" && !choosing
    function countryName(cc) {
        if (cc === "")
            return ScanTexts.allCountries
        if (cc === "whitelist")
            return ScanTexts.whitelists
        const lists = [bar.scope_countries || [], bar.countries || []]
        for (let k = 0; k < lists.length; ++k)
            for (let i = 0; i < lists[k].length; ++i)
                if (lists[k][i].cc === cc) return lists[k][i].name || cc
        return cc
    }

    // countdown end (wall clock); re-anchored only when the view's figure disagrees by more than 1.5 s
    property double endsAtMs: 0
    property double nowMs: Date.now()
    // the view's own clock: TribeScanner.view.cooldown_ends_at_ms / now_ms (scanner-api-note.md (b)); the end is
    // taken relative to now_ms, so a skew between the coordinator's clock and Date.now() does not matter
    property double cooldownEndsAtMs: 0
    property double viewNowMs: 0
    function anchorCountdown() {
        if (!countdown) { endsAtMs = 0; return }
        const unit = kind === "retry_in_min" ? 60000 : 1000
        const target = (kind === "retry_in_s" && cooldownEndsAtMs > 0 && viewNowMs > 0)
                       ? Date.now() + Math.max(0, cooldownEndsAtMs - viewNowMs)
                       : Date.now() + Number(bar.button_value || 0) * unit
        nowMs = Date.now()
        if (Math.abs(target - endsAtMs) > 1500 || endsAtMs === 0)
            endsAtMs = target
    }
    onBarChanged: anchorCountdown()
    onCooldownEndsAtMsChanged: anchorCountdown()
    Component.onCompleted: anchorCountdown()
    Timer {
        interval: 1000
        repeat: true
        running: root.countdown && root.remaining > 0   // also drives the page's choice rows and empty / blocked buttons
        onTriggered: root.nowMs = Date.now()
    }
    readonly property int remaining: !countdown ? 0
        : Math.max(0, Math.ceil((endsAtMs - nowMs) / (kind === "retry_in_min" ? 60000 : 1000)))
    readonly property bool counting: countdown && remaining > 0
    // a tap that would start a scan now is refused by the machine (retryTapped ignores it silently): the page never
    // offers it - the choice's Scan and the empty state's buttons
    readonly property bool gated: counting
    // the gate said in words, the hint style of the bar (the choice view and the empty state of a country)
    readonly property string gateText: !counting ? ""
        : kind === "retry_in_min" ? ScanTexts.hourLimit
        : ScanTexts.rescanInS.arg(remaining)
    // the choice: the hour's limit always (the countdown alone does not say why); the pause only under «Показать
    // результат» (the button does not say it); the result: the view's hint
    readonly property string hintText: choosing ? (chooseAction === "connect" ? ScanTexts.fallbackHint
                                                   : (kind === "retry_in_min" || chooseAction === "show") ? gateText
                                                   : "")
        : fallback ? ScanTexts.fallbackHint
        : bar.hint === "cellular_budget_hour" ? ScanTexts.hourLimit
        : ""
    // The result's Scan button (owner 19.11: one button, one meaning - it scans the chosen scope); its countdown says
    // the same («Сканировать через N с|мин»). The page's empty and blocked states reuse it.
    readonly property string retryText: counting ? (kind === "retry_in_min" ? ScanTexts.scanInMin.arg(remaining)
                                                                            : ScanTexts.scanInS.arg(remaining))
                                                 : (again ? ScanTexts.scanAgain : ScanTexts.scanScope)
    readonly property bool retryEnabled: countdown ? !counting : bar.button_enabled !== false

    // what a tap of the button does now (F1: the press keeps its own)
    function action() {
        if (choosing)
            return chooseAction === "show" ? "show" : chooseAction === "connect" ? "connect" : "scan"
        return kind === "stop" ? "stop" : fallback ? "connect" : "retry"
    }
    property string pressAction: ""
    function fire(a) {
        Haptic.play("light")
        if (a === "scan") root.scanTapped()
        else if (a === "show") root.showTapped()
        else if (a === "stop") root.stopTapped()
        else if (a === "connect") root.connectAndScanTapped()
        else root.retryTapped()
    }

    implicitHeight: col.implicitHeight + Theme.space.sm + Theme.space.lg

    ColumnLayout {
        id: col
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        anchors.topMargin: Theme.space.sm
        spacing: Theme.space.sm

        Text {
            visible: root.hintText !== ""
            Layout.fillWidth: true
            text: root.hintText
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            lineHeight: 15
            lineHeightMode: Text.FixedHeight
        }

        TribeButton {
            id: actionButton
            objectName: "scannerActionButton"
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            Layout.preferredHeight: Theme.scan.barHeight
            padding: 0
            leftPadding: Theme.space.lg
            rightPadding: Theme.space.lg
            variant: root.choosing ? "primary"
                     : root.kind === "stop" ? "ghost" : (root.fallback ? "primary" : "glass")
            text: root.choosing ? (root.chooseAction === "show" ? ScanTexts.showResult
                                   : root.chooseAction === "connect" ? ScanTexts.connectAndScan
                                   : root.retryText)
                  : root.kind === "stop" ? ScanTexts.stop
                  : root.fallback ? ScanTexts.connectAndScan
                  : root.retryText
            enabled: root.choosing ? (root.kind !== "stop" && (root.chooseAction === "show"
                                       || (root.chooseAction === "connect" ? root.bar.button_enabled !== false : !root.gated)))
                     : (root.kind === "stop" || root.fallback) ? root.bar.button_enabled !== false : root.retryEnabled
            // Review round 36, F1 + round 37, F5: this one button changes its action when it is tapped («Остановить» ->
            // «Сканировать снова» / the choice's «Сканировать», «Сканировать» -> «Остановить»). The rule is asymmetric:
            //  - a tap never STARTS anything it did not mean when the finger went down: a press fires only the action it
            //    began with (none if the button changed its meaning while pressed), and the second tap of a double tap
            //    (Qt's own double-tap recognition of this button, doubleClicked) starts nothing - a double tap on
            //    «Остановить» only stops, it never starts a scan;
            //  - a STOP is always delivered: a press that began as «Остановить» on a button that still means it stops,
            //    also as the second tap of a double tap («Сканировать», then «Остановить» at once).
            onPressed: root.pressAction = root.action()
            onCanceled: root.pressAction = ""
            onDoubleClicked: {
                const a = root.pressAction
                root.pressAction = ""
                if (a === "stop" && root.action() === "stop") root.fire("stop")
            }
            onClicked: {
                const a = root.pressAction !== "" ? root.pressAction : root.action()
                root.pressAction = ""
                if (a === root.action()) root.fire(a)    // the button changed its meaning while pressed: nothing
            }
        }
    }
}

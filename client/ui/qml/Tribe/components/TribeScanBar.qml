import QtQuick
import QtQuick.Layouts

import ".."   // Theme, ScanTexts, Haptic

// AVPN: the Scanner's pinned bottom bar (artboard vpn-scanner-kit.js scanFoot, plan §1.2/§1.3): the hint line,
// then the country menu LEFT of the action button. `bar` is the ScanView bar JSON (ScanMachine.h): menu_visible,
// menu_enabled, selected, countries, total, button stop | retry | retry_in_s | retry_in_min | connect_and_scan,
// button_enabled, button_value, hint none | cellular_budget_hour.
// Owner 18.11: no «Скан потратит до N МБ» line (the machine no longer computes it); only the hourly limit
// (cellular_budget_hour) and the VPN-off hint keep a line. The budget rule is unchanged.
// The countdown lives INSIDE the button: a 1 s Timer rewrites only the button text from the end time
// (the view's cooldown_ends_at_ms against its now_ms; minutes and a view without them: now + button_value at
// arrival), so the screen is not rebuilt every second; at zero the button turns into «Повторить» (the machine
// re-checks the cooldown).
Item {
    id: root

    property var bar: ({})
    readonly property bool menuOpen: menu.opened
    signal stopTapped()
    signal retryTapped()
    signal connectAndScanTapped()
    signal countryChosen(string cc)

    readonly property string kind: bar.button || "retry"
    readonly property bool countdown: kind === "retry_in_s" || kind === "retry_in_min"
    readonly property bool fallback: kind === "connect_and_scan"
    readonly property string hintText: fallback ? ScanTexts.fallbackHint
        : bar.hint === "cellular_budget_hour" ? ScanTexts.hourLimit
        : ""
    // Country = the scan's SCOPE over the whole pool (owner 18.11). WAITS FOR THE ENGINE: bar.scope_countries
    // [{cc, count, name}] = every country of the pool (own nodes + provider profiles, count = its paths) and
    // bar.scanned_scope = the country the shown result covers ("" = all). Without them the menu stays what it is
    // today: a filter over the countries the scan found (bar.countries).
    readonly property bool scopeMode: Array.isArray(bar.scope_countries) && bar.scope_countries.length > 0
    readonly property var menuCountries: scopeMode ? bar.scope_countries : (bar.countries || [])
    readonly property int menuTotal: {
        if (!scopeMode) return Number(bar.total || 0)
        let n = 0
        for (let i = 0; i < bar.scope_countries.length; ++i) n += Number(bar.scope_countries[i].count || 0)
        return n
    }
    // a country chosen that the shown result does not cover: the button scans it («Сканировать»)
    readonly property bool scopeChanged: scopeMode && kind !== "stop" && !fallback
                                         && String(bar.selected || "") !== String(bar.scanned_scope || "")
    readonly property bool showMenu: !fallback && bar.menu_visible === true
                                     && (!scopeMode || bar.scope_countries.length >= 2)
    function countryName(cc) {
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
        running: root.countdown && root.remaining > 0   // also drives the empty / blocked buttons of the page
        onTriggered: root.nowMs = Date.now()
    }
    readonly property int remaining: !countdown ? 0
        : Math.max(0, Math.ceil((endsAtMs - nowMs) / (kind === "retry_in_min" ? 60000 : 1000)))
    readonly property bool counting: countdown && remaining > 0
    // «Повторить» / «Повторить через N с|мин» - the page's empty and blocked states reuse the same countdown
    readonly property string retryText: counting ? (kind === "retry_in_min" ? ScanTexts.retryInMin.arg(remaining)
                                                                            : ScanTexts.retryInS.arg(remaining))
                                                 : ScanTexts.retry
    readonly property bool retryEnabled: countdown ? !counting : bar.button_enabled !== false

    function closeMenu() { menu.close() }

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

        RowLayout {
            id: barRow
            Layout.fillWidth: true
            spacing: Theme.space.md

            TribeCountryMenu {
                id: menu
                visible: root.showMenu
                enabled: root.bar.menu_enabled === true
                Layout.preferredWidth: implicitWidth
                Layout.preferredHeight: Theme.scan.barHeight
                countries: root.menuCountries
                total: root.menuTotal
                selected: root.bar.selected || ""
                // menu bottom = 4 px under the bar's top edge (artboard .mn bottom: calc(100% - 4px))
                menuLift: barRow.y + Theme.space.sm - 4
                // up to 150, but never squeezing the action button below its own text (360 px phones)
                maxButtonWidth: Math.max(Theme.scan.barHeight * 2,
                                         Math.min(Theme.scan.menuButtonMax,
                                                  root.width - 2 * Theme.space.xl - barRow.spacing - actionButton.textNeed))
                onChosen: (cc) => root.countryChosen(cc)
            }

            TribeButton {
                id: actionButton
                // the label plus 12 px a side (implicitWidth carries TribeButton's own 24 a side)
                readonly property real textNeed: Math.ceil(implicitWidth - 2 * Theme.space.xl + 2 * Theme.space.md)
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                Layout.preferredHeight: Theme.scan.barHeight
                padding: 0
                leftPadding: Theme.space.lg
                rightPadding: Theme.space.lg
                variant: root.kind === "stop" ? "ghost" : (root.fallback ? "primary" : "glass")
                text: root.kind === "stop" ? ScanTexts.stop
                      : root.fallback ? ScanTexts.connectAndScan
                      : (root.scopeChanged && !root.counting) ? ScanTexts.scanScope
                      : root.retryText
                enabled: (root.kind === "stop" || root.fallback) ? root.bar.button_enabled !== false : root.retryEnabled
                onClicked: {
                    Haptic.play("light")
                    if (root.kind === "stop") root.stopTapped()
                    else if (root.fallback) root.connectAndScanTapped()
                    else root.retryTapped()
                }
            }
        }
    }
}

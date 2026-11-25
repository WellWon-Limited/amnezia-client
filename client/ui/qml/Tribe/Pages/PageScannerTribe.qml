pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts

import ".."              // Theme, ScanTexts, ScanSwitches, Haptic
import "../components"
import "../../Controls2" // PageType

// AVPN: the Scanner («Сканер») - ONE screen (owner 24.11, the same on every platform):
//  - header (owner 25.11): back arrow, the title right after it («Сканер» on the choice, the scope's name on its
//    result), the caption «Подбор серверов» at the right edge; under it two badges of one kind (TribePill): the servers
//    of the selected scope left (the server icon and «69»; the screen reader says «69 серверов»), the network right
//    («Wi‑Fi» / «LTE»);
//  - the rings: the scrolling list's FIRST item in every state, never removed (a long list scrolls them away, no
//    band stays), ONE size in one place in every state (owner 25.11: Theme.scan.hero, no animation between the choice
//    and a result; the status line under them only with a scan or its result). The choice: still, with the radar
//    glyph; a scan: they move; a result: still, with the number of available servers in the core (0 too) and the
//    check's age under them; «Остановить» keeps what was found (the same count, «Скан остановлен»); a refused scan
//    («Скан сейчас невозможен») greys them with the reason's icon in the core;
//  - under the rings EITHER the choice: the live connection's row first (when there is one), then «ВЫБЕРИТЕ СТРАНУ»:
//    «Все страны» (selected when the page opens), «Белые списки» when the pool has them, every country of the pool;
//    a tap only SELECTS (the kit's selection: chipSelected + accent border + the «Авто» card's check circle), a scope
//    with a fresh result of this network says « · M доступно · K мин назад» - OR the result of the scope that was
//    scanned / shown: the machine's rows in its order (the live connection first), «Найти ещё», the crowd legend, the
//    empty result's advice, the refused scan's reason;
//  - ONE pinned button that says what a press does now: the choice - «Сканировать» the selected scope (its countdown
//    during the 30 s pause / the cellular hour), «Показать результат» when no scan can run and the scope has a fresh
//    result, «Подключиться и проверить»; the result - «Остановить», «Сканировать снова» / its countdown.
// The back arrow (and the edge swipe, Android Back, Escape) goes from a result back to the choice, from the choice
// out of the Scanner. Opening the page never scans.
// The screen only DRAWS the view: TribeScanner.view = ScanView JSON (ScanMachine.h scanViewToJson); every decision
// (order, row lifetime, scope, stop, cooldown, budget, shades) is the pure machine's. The selection is the page's own
// until the button: then chooseCountry(scope) + retry() / showSlot(scope) / connectAndScan().
// Non-tab page (goToTabBarPageUrl); back from the choice returns to where it was opened from. After a row tap the
// user STAYS here.
PageType {
    id: root

    signal back()                 // -> home (PageStart.goAvpnTab(0))
    signal requestServerPicker()  // -> the servers page it was opened from
    signal requestTab(int index)  // -> the chat (tab 1) it was opened from

    property string origin: "home"        // "home" | "servers" | "chat"

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property bool hasScanner: typeof TribeScanner !== "undefined"
    readonly property var view: (hasScanner && TribeScanner.view) ? TribeScanner.view : ({ phase: "idle" })
    readonly property string phase: view.phase || "idle"
    readonly property bool scanning: phase === "preparing" || phase === "connecting" || phase === "reach"
                                     || phase === "data"
    readonly property var barView: view.bar || ({})
    readonly property var emptyView: view.empty || ({})
    readonly property string reason: emptyView.reason || ""
    readonly property bool noScan: phase === "no_scan"
    // NoScan: every reason of the coordinator's vocabulary is mapped in ScanTexts.noScan() (one table): "list" = the
    // last result + the bar with the view's buttons; "blocked" = «Скан сейчас невозможен» (figures 21-26): the reason's
    // icon in the rings, title, text, one action, the last result below, no bar
    readonly property var block: noScan ? ScanTexts.noScan(reason) : ({ layout: "list" })
    readonly property bool blocked: block.layout === "blocked"
    // desktop service states (24, 25): the engine's existing service step (TribeEngine.scannerEnsureService(), the end
    // scannerEnsureServiceFinished(ok, detail)); the button says what the tap really does - TribeEngine.
    // scannerServiceAction() (install | start | update | none | unsupported), read when the state is shown (it reads
    // files and processes: never in a binding). Without the API: «Повторить» as the view says.
    readonly property bool isServiceReason: reason === "service_off" || reason === "service_old" || reason === "service_mismatch"
    readonly property bool hasEnsure: typeof TribeEngine !== "undefined" && typeof TribeEngine.scannerEnsureService === "function"
    property string serviceAction: ""
    function refreshServiceAction() {
        if (!noScan || !isServiceReason) return
        serviceAction = (typeof TribeEngine !== "undefined" && typeof TribeEngine.scannerServiceAction === "function")
                        ? String(TribeEngine.scannerServiceAction()) : ""
    }
    property bool completed: false              // one read on show (onCompleted), then only on a real change
    // Deferred: reason and noScan change in one view update, and a handler of one can still read the other (and
    // isServiceReason) before its binding is re-evaluated - then neither handler read the action.
    onReasonChanged: if (completed) Qt.callLater(refreshServiceAction)
    onNoScanChanged: if (completed) Qt.callLater(refreshServiceAction)
    readonly property var svc: (blocked && block.action === "ensureService") ? ScanTexts.serviceState(reason, serviceAction) : ({})
    property bool ensureRunning: false
    readonly property bool serviceBusy: ensureRunning
        || (typeof TribeEngine !== "undefined" && (TribeEngine.scannerEnsureServiceRunning === true || TribeEngine.svcInstalling === true))
    function ensureService() {
        if (!hasEnsure || serviceBusy) return
        ensureRunning = true
        TribeEngine.scannerEnsureService()
    }
    Connections {
        target: typeof TribeEngine !== "undefined" ? TribeEngine : null
        ignoreUnknownSignals: true
        function onScannerEnsureServiceFinished(ok, detail) {
            root.ensureRunning = false
            const d = String(detail || "")
            if (ok) {                                   // the service runs: the scan starts by itself
                if (root.hasScanner) TribeScanner.retry()
                return
            }
            if (d.indexOf("unsupported") === 0) {        // Windows: the installer owns the service
                root.serviceAction = "unsupported"
                return
            }
            root.refreshServiceAction()
            if (d.indexOf("declined") === 0 || d.indexOf("busy") === 0)   // cancelled by the person / already running
                return
            if (root.hasScanner)
                TribeScanner.showShade("warning", d.indexOf("vpn_on") === 0 ? "service_vpn_on" : "service_failed", [])
        }
    }
    readonly property bool emptyResult: phase === "empty"
    // the bar is up on the choice, and on the result in every state but blocked / empty (they carry their own action)
    readonly property bool showBar: choosing || (!blocked && !emptyResult)

    // ── the choice and the result: one screen, one list under the rings ──
    property string pane: "choose"       // "choose" = the country choice, "result" = the scanned / shown scope
    readonly property bool choosing: pane === "choose"
    // the choice's selected scope: "" = «Все страны» (every page open starts here), "whitelist", a country code. Only
    // the button hands it to the machine (chooseCountry / showSlot): a row tap never scans nor navigates.
    property string selected: ""
    // view.slots: [{scope, works, ago_min, partial}] - this network's fresh results, one per scope (ScanMachine.h scopeSlots)
    readonly property var slotList: Array.isArray(view.slots) ? view.slots : []
    function slotOf(sc) {
        for (let i = 0; i < slotList.length; ++i)
            if (String(slotList[i].scope || "") === sc) return slotList[i]
        return null
    }
    readonly property var poolCountries: Array.isArray(barView.scope_countries) ? barView.scope_countries : []
    readonly property int poolWhitelist: Number(barView.scope_whitelist || 0)
    // a scope with its row on the choice: «Все страны» always, «Белые списки» while the pool has them, a pool country
    function listed(sc) {
        if (sc === "") return true
        if (sc === "whitelist") return poolWhitelist > 0
        for (let i = 0; i < poolCountries.length; ++i)
            if (String(poolCountries[i].cc || "") === sc) return true
        return false
    }
    // review F2 (24.11): the button acts only on the scope shown as selected - a selection whose row left the list (a
    // pool answer without it, another network's pool) falls back to «Все страны», visibly
    readonly property bool selectedListed: listed(selected)
    // deferred: the selection is not written from inside its own binding's change
    onSelectedListedChanged: if (!selectedListed) Qt.callLater(dropUnlistedSelection)
    function dropUnlistedSelection() { if (!listed(selected)) selected = "" }
    // the machine refuses a scan now (the 30 s pause, the cellular hour): nothing that would scan is offered
    readonly property bool scanGated: bar.gated
    // what the choice's button does with the selected scope: connect (VPN off and the switch scanner_connect_on_open
    // off: the view's own button), show (no scan can run now and the scope has a fresh result), else scan (disabled
    // with its countdown while gated)
    readonly property string chooseAction: bar.kind === "connect_and_scan" ? "connect"
                                           : (scanGated && slotOf(selected) !== null) ? "show" : "scan"
    function slotAgo(slot) {
        return slot ? ScanTexts.ago(Number(slot.ago_min || 0), Number(view.now_ms || Date.now())) : ""
    }
    // a fresh result's second line on its row: its age, marked when it is a stopped scan's
    function slotLine(slot) {
        if (!slot) return ""
        return slot.partial === true ? ScanTexts.slotStopped.arg(slotAgo(slot)) : slotAgo(slot)
    }
    // a row tap: the selection only
    function select(sc) {
        if (selected === sc) return
        Haptic.play("selection")
        selected = sc
    }
    // the choice's button: scan the selected scope (a new list of that scope), show its fresh result, or connect and scan.
    // Only a scope shown as selected, and only once the machine took it as its scope (it refuses one it cannot scan:
    // then nothing scans - never the scope it had before).
    function takeSelected() {
        if (!listed(selected)) {
            selected = ""
            return false
        }
        TribeScanner.chooseCountry(selected)
        return String(barView.scope || "") === selected
    }
    function scanSelected() {
        if (!hasScanner || scanGated || !takeSelected()) return
        showResult()
        TribeScanner.retry()
    }
    function showSelected() {
        if (!hasScanner || !listed(selected)) return
        showResult()
        TribeScanner.showSlot(selected)
    }
    function connectSelected() {
        if (!hasScanner || !takeSelected()) return
        showResult()
        TribeScanner.connectAndScan()
    }
    // the empty country result's «Сканировать все страны»: the whole pool, always a scan
    function scanAll() {
        if (!hasScanner || scanGated) return
        selected = ""
        TribeScanner.chooseCountry("")
        showResult()
        TribeScanner.retry()
    }
    function retryScan() {
        if (hasScanner) TribeScanner.retry()
    }
    function showResult() {
        list.contentY = 0
        pane = "result"
    }
    // back to the choice; a running scan is stopped (it keeps what it found: that scope's fresh result); the selected
    // row is brought into view (device round air-C, D7)
    function showChoice() {
        stopPending = false
        if (scanning && hasScanner) TribeScanner.stop()
        list.contentY = 0
        pane = "choose"
        revealSelected()
    }
    // «Остановить»: the machine keeps what the scan found (Done, its count in the rings, view.partial); stopped before
    // anything was found it is idle again - nothing to show, the page goes back to the choice
    property bool stopPending: false
    function stopScan() {
        if (!hasScanner) return
        stopPending = true
        TribeScanner.stop()
    }
    onScanningChanged: {
        if (scanning) {
            stopPending = false
            return
        }
        if (!stopPending) return
        stopPending = false
        if (phase !== "done" && phase !== "empty" && !choosing) showChoice()
    }
    // Owner 19.11 (device test, iPhone Air): the country is the SCOPE of the next scan over the whole pool, never a
    // filter of rows found before. The result shows the machine's scope.
    readonly property string scope: String(barView.scope || "")
    // the result shows nothing of its scope (a scan the machine refused at once, a network change): its summary
    // (the live connection's row, when there is one, is always above it and does not count)
    readonly property bool scopeStart: !choosing && !scanning && !blocked && !emptyResult && otherCount === 0
    // the pool's answer is known (fetched now or kept from an earlier launch): scope_whitelist stays -1 until then; the
    // countries before it are the manifest's first screen, never the pool's size (device round air-D, E1: «8 серверов»
    // instead of 228 when the fetch failed through the tunnel) - no total is shown then
    readonly property bool poolKnown: Number(barView.scope_whitelist ?? -1) >= 0
    // the servers of a scope: «Все страны» scans every row of the pool - the countries AND the white lists (review F3)
    function scopeCount(cc) {
        if (!poolKnown)
            return 0
        if (cc === "whitelist")
            return Math.max(0, poolWhitelist)
        let n = cc === "" ? Math.max(0, poolWhitelist) : 0
        for (let i = 0; i < poolCountries.length; ++i)
            if (cc === "" || poolCountries[i].cc === cc) n += Number(poolCountries[i].count || 0)
        return n
    }
    property bool allCache: false         // every shown row is a cached one (set by syncRows)
    readonly property bool lastResult: !scanning && otherCount > 0 && (blocked || allCache)
    // the live connection's row is view.rows[0] (the «current» flag) when the machine built the list with it; otherCount =
    // the rows besides it - the result's own rows (set by syncRows)
    property bool liveFirst: false
    // the live connection's row wherever the result has it (review round 36, F4: a row connected from the list keeps
    // its place - rows never jump - and the choice still shows it under «ВАШЕ ПОДКЛЮЧЕНИЕ»); -1 = none (set by syncRows)
    property int liveIndex: -1
    readonly property int otherCount: rowsModel.count - (liveFirst ? 1 : 0)
    property bool anyCrowd: false
    property bool leaving: false

    // ── the rings: what they show ──
    // idle: the choice, or a result pane with nothing yet (radar, still); scan: a scan runs (radar, moving); count: a
    // result (the found number, still); alert: a refused scan (grey rings, the reason's icon)
    readonly property string ringMode: choosing ? "idle"
                                       : scanning ? "scan"
                                       : blocked ? "alert"
                                       : (phase === "done" || emptyResult || otherCount > 0) ? "count"
                                       : "idle"
    // the number in the rings: the rows the list shows as available in the shown scope - the machine's one count
    // (view.available: fresh and cached rows, the proven live connection of the scope, never «Не удалось»)
    readonly property int foundCount: Number(view.available || 0)
    // the shown result was cut short by «Остановить» (view.partial: right after the stop, and the stored result later)
    readonly property bool partialResult: view.partial === true
    readonly property string agoText: ScanTexts.ago(Number(view.checked_ago_min ?? -1), Number(view.now_ms || Date.now()))
    readonly property string stageText: {
        switch (view.stage) {
        case "connecting": return ScanTexts.stageConnecting
        case "reach": return ScanTexts.stageReach.arg(view.stage_count || 0).arg(view.stage_total || 0)
        case "data": return ScanTexts.stageData.arg(view.stage_count || 0).arg(view.stage_total || 0)
        }
        return ScanTexts.stageReachShort
    }
    // the line under the rings: the stage while scanning; a result - its check's age, «Скан остановлен» for a stopped one
    readonly property string ringLine: ringMode === "scan" ? stageText
                                       : ringMode !== "count" ? ""
                                       : partialResult ? (agoText !== "" ? ScanTexts.stoppedAgo.arg(agoText) : ScanTexts.stoppedLine)
                                       : agoText !== "" ? ScanTexts.agoName.arg(agoText) : ""

    // ── navigation ──
    function goBack() {
        if (leaving) return
        leaving = true
        if (origin === "servers") root.requestServerPicker()
        else if (origin === "chat") root.requestTab(1)
        else root.back()
    }
    // header back, the edge swipe, Android Back / Escape (PageStart.onEscapePressed): the result goes back to the
    // choice, the choice leaves the Scanner
    function navBack() {
        if (choosing) goBack()
        else showChoice()
    }
    function systemBack() { navBack() }

    Component.onCompleted: {
        syncRows()
        completed = true
        refreshServiceAction()
        // the check with the report runs from Support now (variant B, 18.11): the Scanner never opens with it
        // owner 19.11: opening the Scanner never starts a scan - the Scan button does (show(); open() scans)
        if (hasScanner) {
            if (typeof TribeScanner.show === "function") TribeScanner.show()
            else TribeScanner.open(false)
        }
        // owner 24.11: the page opens on the choice with «Все страны» selected; only a scan that already runs (Support's
        // check started it with the page closed) is shown as it goes
        pane = scanning ? "result" : "choose"
    }
    // leaving the screen = closed(): a running scan stops, a pending connect the scan started is cancelled (S19)
    Component.onDestruction: if (hasScanner) TribeScanner.close()

    Connections {
        target: root.hasScanner ? TribeScanner : null
        ignoreUnknownSignals: true
        function onCloseScreenRequested() { root.goBack() }
        function onViewChanged() { root.syncRows() }
    }

    // scanner_return_home (server switch, default off): the engine decides WHEN (scannerReturnHomeRequested: the
    // tapped row reached «Подключено» with the switch on); the page only waits 1 s so the row's change is seen
    Timer {
        id: returnHomeTimer
        interval: 1000
        onTriggered: root.goBack()
    }
    Connections {
        target: typeof TribeEngine !== "undefined" ? TribeEngine : null
        ignoreUnknownSignals: true
        function onScannerReturnHomeRequested() { if (!returnHomeTimer.running) returnHomeTimer.start() }
    }
    // the server switched the Scanner off while the page is open (scanner_off, then scannerEnabled false): leave
    readonly property bool scannerOn: ScanSwitches.scanner
    onScannerOnChanged: if (!scannerOn) goBack()

    // ── rows: diff the view into a ListModel so delegates, scroll and arrive animations survive updates ──
    ListModel { id: rowsModel }
    function flagSet(r) {
        const f = {}
        const list = r.flags || []
        for (let i = 0; i < list.length; ++i) f[list[i]] = true
        return f
    }
    function versionMap() {
        const m = {}
        const pool = (typeof TribeEngine !== "undefined" && TribeEngine.nodePool) ? TribeEngine.nodePool : []
        for (let i = 0; i < pool.length; ++i)
            if (pool[i] && pool[i].nodeId !== undefined) m[String(pool[i].nodeId)] = String(pool[i].protoVersion || "")
        return m
    }
    function toItem(r, vmap) {
        const f = flagSet(r)
        return {
            rid: String(r.id || ""), label: String(r.label || ""), cc: String(r.cc || ""),
            transport: String(r.transport || "xray"),
            version: r.version !== undefined ? String(r.version) : (r.transport === "awg" ? (vmap[String(r.id)] || "") : ""),
            rstate: String(r.state || "works"), speed: String(r.speed || "none"),
            bars: Number(r.bars || 0), ms: r.ms === undefined ? -1 : Number(r.ms),
            fromCache: f.cache === true, dimmed: f.dimmed === true, tappable: f.not_tappable !== true,
            verifying: f.verifying === true, current: f.current === true,
            unverified: f.unverified === true, liveUnverified: f.live_unverified === true, crowd: f.crowd === true
        }
    }
    // The list is the machine's (ScanMachine.h syncList, owner 19.11): between two builds of it (view.list_build) its
    // rows only join its END - a row keeps its index until the list is built again (page open, a scope change, a new
    // network, or a scan the person starts: «Сканировать» clears the old rows and builds from empty) and never leaves
    // while a scan runs; «Не проверено» rows join only once final. So the model follows the view index by index: a
    // row changes in place, a new one is appended; a new build replaces the model.
    property real listBuild: -1
    function sameItem(a, b) {
        for (const k in a)
            if (a[k] !== b[k]) return false
        return true
    }
    function syncRows() {
        const src = view.rows || []
        const vmap = src.some(r => r.transport === "awg" && r.version === undefined) ? versionMap() : {}
        const build = Number(view.list_build || 0)
        if (build !== listBuild || src.length < rowsModel.count) {
            rowsModel.clear()
            listBuild = build
        }
        let cacheAll = true, crowd = false
        for (let i = 0; i < src.length; ++i) {
            const it = toItem(src[i], vmap)
            cacheAll = cacheAll && it.fromCache
            crowd = crowd || it.crowd
            if (i >= rowsModel.count) rowsModel.append(it)
            else if (rowsModel.get(i).rid !== it.rid) { rowsModel.remove(i, rowsModel.count - i); rowsModel.append(it) }
            else if (!sameItem(it, rowsModel.get(i))) rowsModel.set(i, it)
        }
        liveFirst = rowsModel.count > 0 && rowsModel.get(0).current === true
        let live = -1
        for (let k = 0; k < rowsModel.count && live < 0; ++k)
            if (rowsModel.get(k).current === true) live = k
        liveIndex = live
        allCache = src.length > 0 && cacheAll
        anyCrowd = crowd
    }

    // the choice's selected row brought into the list's view (Back from a result of a country far down the list left it
    // off screen); nothing moves when it is already in view. The choice was hidden until now: its rows are placed first.
    function revealSelected() {
        chooseCol.forceLayout()
        content.forceLayout()
        let row = null
        for (let i = 0; i < chooseCol.children.length && !row; ++i)
            if (chooseCol.children[i].objectName === "scannerScope_" + (selected === "" ? "all" : selected))
                row = chooseCol.children[i]
        if (!row || !row.visible) return
        const top = row.mapToItem(list.contentItem, 0, 0).y
        const bottom = top + row.height
        if (top < list.contentY)
            list.contentY = Math.max(0, top - list.padTop)
        else if (bottom > list.contentY + list.height)
            list.contentY = Math.max(0, Math.min(list.contentHeight - list.height, bottom - list.height + list.padBottom))
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    TribeEdgeBack { onTriggered: root.navBack() }

    // ── header (owner 25.11): back, the title right after it, «Подбор серверов» at the right edge ──
    TribeHeader {
        id: header
        anchors.top: parent.top
        anchors.topMargin: root.safeTop
        anchors.left: parent.left
        anchors.right: parent.right
        title: root.choosing ? ScanTexts.title : bar.countryName(root.scope)
        titleAlignment: Qt.AlignLeft
        caption: ScanTexts.titleCaption
        showBack: true
        onBackClicked: root.navBack()
    }

    // ── the two badges under the header, one component (TribePill): the servers of the selected scope left (owner
    // 24.11: «как бейдж Wi‑Fi»; 25.11: the server icon and the number only), the network right. The row is fixed under
    // the header in every state.
    Item {
        id: badgesRow
        anchors.top: header.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        height: Theme.scan.chip
        z: 2
        // the choice: the selected scope; the result: the scope it shows (0 = the pool's counts are not here yet)
        readonly property int count: root.scopeCount(root.choosing ? root.selected : root.scope)
        readonly property string netText: ScanTexts.netCaption(root.view.net || "", root.view.net_radio || "")
        TribePill {
            objectName: "scannerCountBadge"
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            visible: badgesRow.count > 0
            icon: "server"
            text: String(badgesRow.count)
            // the whole phrase for the screen reader and the UI driver: «228 серверов»
            Accessible.name: ScanTexts.servers(badgesRow.count)
        }
        TribePill {
            objectName: "scannerNetBadge"
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            visible: badgesRow.netText !== ""
            icon: ScanTexts.netIcon(root.view.net || "")
            text: badgesRow.netText
            Accessible.name: ScanTexts.netName.arg(badgesRow.netText)
        }
    }

    // ── the scrolling list: the rings first, then the choice or the result ──
    Item {
        id: listArea
        y: badgesRow.y + badgesRow.height
        height: (root.showBar ? bar.y : root.height) - y
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl

        Flickable {
            id: list
            objectName: "scannerList"
            anchors.fill: parent
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            readonly property real padTop: Theme.space.md
            readonly property real padBottom: Theme.space.lg
            contentWidth: width
            contentHeight: content.y + content.height + padBottom

            // ── the rings + one status line + a thin bar: ONE block, the list's first item. The rings are one size in one
            // place in every state (owner 25.11, no animation); the status line is there while a scan or its result is
            // shown - the choice has nothing to say under the rings, so no blank line ──
            Item {
                id: ringsBox
                objectName: "scannerRings"
                y: list.padTop
                width: list.width
                // + the gap to the first item under it
                height: Theme.scan.hero + (status.visible ? status.implicitHeight : 0) + Theme.space.md
                Accessible.role: Accessible.Graphic
                Accessible.name: root.ringMode === "scan" ? root.stageText
                                 : root.ringMode === "count" ? ScanTexts.ringName.arg(root.foundCount)
                                 : root.ringMode === "alert" ? (root.block.title || "")
                                 : ScanTexts.title
                // the rings at their own 250, centred on the band
                Item {
                    width: 250
                    height: 250
                    x: (parent.width - width) / 2
                    y: (Theme.scan.hero - height) / 2
                    SignalRing {
                        anchors.centerIn: parent
                        ringState: root.ringMode === "alert" ? "off" : "scanning"
                        still: root.ringMode !== "scan"
                        showGlyph: root.ringMode === "scan" || root.ringMode === "idle"
                        tappable: false
                    }
                    Column {
                        anchors.centerIn: parent
                        visible: root.ringMode === "count"
                        Text {
                            anchors.horizontalCenter: parent.horizontalCenter
                            text: String(root.foundCount)
                            textFormat: Text.PlainText
                            color: Theme.color.text1
                            font.family: Theme.font.display
                            font.pixelSize: Theme.font.displayL
                            font.weight: Theme.font.wBold
                        }
                        Text {
                            anchors.horizontalCenter: parent.horizontalCenter
                            text: ScanTexts.available(root.foundCount)
                            textFormat: Text.PlainText
                            color: Theme.color.text2
                            font.family: Theme.font.body
                            font.pixelSize: Theme.badge.text
                            font.weight: Theme.font.wSemibold
                        }
                    }
                    TribeStrokeIcon {
                        anchors.centerIn: parent
                        width: 24; height: 24
                        scale: 1.45
                        visible: root.ringMode === "alert"
                        icon: root.block.icon || "alert-circle"
                        tint: Theme.color.warning
                        weight: 1.7
                    }
                }
                ColumnLayout {
                    id: status
                    y: Theme.scan.hero
                    width: parent.width
                    visible: !root.choosing
                    spacing: Theme.space.sm
                    Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        elide: Text.ElideRight
                        text: root.ringLine
                        textFormat: Text.PlainText
                        color: Theme.color.text2
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.monoData
                        font.weight: Theme.font.wMedium
                        lineHeight: 17
                        lineHeightMode: Text.FixedHeight
                    }
                    // kept in every state of the full block (transparent when no scan runs): the list never steps
                    TribeProgressBar {
                        Layout.fillWidth: true
                        opacity: root.ringMode === "scan" ? 1 : 0
                        percent: (root.view.stage === "connecting" || root.view.stage === "preparing" || Number(root.view.progress) < 0)
                                 ? -1 : Math.round(100 * Number(root.view.progress || 0))
                    }
                }
            }

            Column {
                id: content
                y: ringsBox.y + ringsBox.height
                width: list.width

                // ── the choice: the live connection, then every scope of the pool (owner 24.11) ──
                Column {
                    id: chooseCol
                    visible: root.choosing
                    width: parent.width
                    spacing: Theme.space.sm
                    ChoiceCaption {
                        visible: root.liveIndex >= 0
                        text: ScanTexts.liveCaption
                    }
                    // the live connection's row, drawn as on the result - found by its «current» flag, at any place of
                    // the result (F4)
                    Item {
                        id: chooseLive
                        visible: root.liveIndex >= 0
                        width: parent.width
                        height: root.liveIndex >= 0 ? Theme.scan.rowHeight : 0
                        Repeater {
                            model: rowsModel
                            delegate: ScanRowSlot {
                                liveSlot: true
                                liveAt: root.liveIndex
                                liveFirst: root.liveFirst
                                scanning: root.scanning
                                rowWidth: chooseLive.width
                                pitch: Theme.scan.rowHeight + chooseCol.spacing
                                gap: chooseCol.spacing
                                onRowTapped: (rid) => { if (root.hasScanner) TribeScanner.tapRow(rid) }
                            }
                        }
                    }
                    ChoiceCaption {
                        // under the live row: the result's section label spacing (.sec-label.in-list margin-top 4)
                        topPadding: root.liveIndex >= 0 ? Theme.space.xs : 0
                        text: ScanTexts.chooseCaption
                    }
                    // «Все страны»: always the first scope, selected when the page opens
                    ScopeRow {
                        scope: ""
                        name: ScanTexts.allCountries
                        count: root.scopeCount("")
                    }
                    ScopeRow {
                        visible: root.poolWhitelist > 0
                        scope: "whitelist"
                        name: ScanTexts.whitelists
                        count: root.poolWhitelist
                        whitelist: true
                    }
                    Repeater {
                        model: root.poolCountries
                        delegate: ScopeRow {
                            required property var modelData
                            scope: String(modelData.cc || "")
                            cc: String(modelData.cc || "")
                            name: String(modelData.name || modelData.cc || "")
                            count: Number(modelData.count || 0)
                        }
                    }
                    // before the pool answers (or when it cannot): «Все страны» still checks everything
                    Text {
                        visible: root.poolCountries.length === 0 && root.poolWhitelist <= 0
                        width: parent.width
                        topPadding: Theme.space.sm
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                        text: ScanTexts.poolWait
                        textFormat: Text.PlainText
                        color: Theme.color.text3
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyS
                        lineHeight: 20
                        lineHeightMode: Text.FixedHeight
                    }
                }

                // ── the result ──
                Column {
                    id: resultCol
                    visible: !root.choosing
                    width: parent.width
                    spacing: Theme.space.sm

                    // «Скан сейчас невозможен»: the reason's icon is in the rings; title, text, one action
                    Column {
                        visible: root.blocked
                        width: parent.width
                        bottomPadding: Theme.space.sm + Theme.space.xs   // + the button's 4 px shift below
                        spacing: Theme.space.md
                        // service states: the per-action act (ensure / retry / none); others: the table's action
                        readonly property string act: root.block.action !== "ensureService" ? (root.block.action || "")
                            : (root.svc.act === "ensure" && !root.hasEnsure ? "retry" : (root.svc.act || ""))
                        readonly property bool ensure: act === "ensure"
                        Heading {
                            maxWidth: parent.width - 2 * Theme.space.lg
                            x: (parent.width - width) / 2
                            text: root.block.title || ""
                            textFormat: Text.PlainText
                            color: Theme.color.text1
                            font.family: Theme.font.display
                            font.pixelSize: Theme.font.h3
                            font.weight: Theme.font.wBold
                            lineHeight: 24
                            lineHeightMode: Text.FixedHeight
                        }
                        Text {
                            visible: text !== ""
                            x: Theme.space.lg
                            width: parent.width - 2 * Theme.space.lg
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            text: root.block.action === "ensureService" ? (root.svc.text || "") : (root.block.text || "")
                            textFormat: Text.PlainText
                            color: Theme.color.text2
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            lineHeight: 20
                            lineHeightMode: Text.FixedHeight
                        }
                        TribeButton {
                            visible: parent.act !== "none"
                            x: Theme.space.lg
                            width: parent.width - 2 * Theme.space.lg
                            // .blocked .t-btn margin-top 4 over the column gap 12
                            transform: Translate { y: Theme.space.xs }
                            variant: root.block.primary === false ? "glass" : "primary"
                            // gotIt / ensureService: the state's own button; retry: the view's button (no countdown of its own)
                            // the service flow running: the button says so and waits (the artboard's busy pattern, «Проверяем…»)
                            text: root.block.action === "gotIt" ? (root.block.actionText || "")
                                  : parent.ensure ? (root.serviceBusy ? (root.svc.busy || "") : (root.svc.button || ""))
                                  : parent.act === "retryNow" ? ScanTexts.scanScope
                                  : bar.retryText
                            enabled: (root.block.action === "gotIt" || parent.act === "retryNow") ? true
                                     : (parent.ensure ? !root.serviceBusy : bar.retryEnabled)
                            onClicked: {
                                Haptic.play("light")
                                if (root.block.action === "gotIt") {
                                    if (root.hasScanner) TribeScanner.gotIt()
                                    root.goBack()
                                } else if (parent.ensure) {
                                    root.ensureService()
                                } else {
                                    root.retryScan()
                                }
                            }
                        }
                    }

                    Text {
                        id: sectionLabel
                        visible: root.otherCount > 0
                        text: root.lastResult ? ScanTexts.sectionLast : ScanTexts.sectionNow
                        textFormat: Text.PlainText
                        color: Theme.color.text3
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.caption
                        font.weight: Theme.font.wSemibold
                        font.letterSpacing: Theme.font.trackCaption * Theme.font.caption
                        lineHeight: 15
                        lineHeightMode: Text.FixedHeight
                    }
                    // The rows place THEMSELVES: y = index x pitch. Rows only join the end (the machine's list), so an index
                    // never changes while the list lives. A new row fades in at its own place, rising from one gap below
                    // (never over a row).
                    // The live connection (device round air-C, D4) is one of these rows, drawn the one way every list draws
                    // it (TribeScanRow «Подключено», highlighted) - never a separate card above the caption. Where it stands
                    // is the machine's list rule: first in a list that is built (page open, a scan, a scope, a network), and
                    // in its own place when it was connected from the list the person is looking at - it never jumps under
                    // the finger; it moves to the top when the result is next built.
                    Item {
                        id: rowsBox
                        readonly property real pitch: Theme.scan.rowHeight + resultCol.spacing
                        visible: rowsModel.count > 0
                        width: parent.width
                        height: Math.max(0, rowsModel.count * pitch - resultCol.spacing)
                        // the lines under the rows (wait line, legend, «Найти ещё») slide with the list's growth
                        Behavior on height {
                            enabled: !Theme.motion.reduceMotion
                            NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                        }
                        Repeater {
                            model: rowsModel
                            delegate: ScanRowSlot {
                                liveSlot: false
                                liveFirst: false
                                scanning: root.scanning
                                rowWidth: rowsBox.width
                                pitch: rowsBox.pitch
                                gap: resultCol.spacing
                                onRowTapped: (rid) => { if (root.hasScanner) TribeScanner.tapRow(rid) }
                            }
                        }
                    }

                    // «Все страны · 46 серверов» / «Германия · 12 серверов» + what the Scan button does, under the live
                    // connection's row when there is one: the result shows nothing of its scope (the kit's empty-state pattern: title, text; the action is the bar's Scan
                    // button - one button, one meaning; the radar is the rings')
                    Column {
                        visible: root.scopeStart
                        width: parent.width
                        bottomPadding: Theme.space.lg
                        spacing: Theme.space.md
                        readonly property int count: root.scopeCount(root.scope)
                        Heading {
                            maxWidth: parent.width - 2 * Theme.space.lg
                            x: (parent.width - width) / 2
                            text: parent.count > 0
                                  ? ScanTexts.scopeTitle.arg(bar.countryName(root.scope)).arg(ScanTexts.servers(parent.count))
                                  : ScanTexts.startTitle
                            textFormat: Text.PlainText
                            color: Theme.color.text1
                            font.family: Theme.font.display
                            font.pixelSize: Theme.font.h3
                            font.weight: Theme.font.wBold
                            lineHeight: 24
                            lineHeightMode: Text.FixedHeight
                        }
                        Text {
                            x: Theme.space.lg
                            width: parent.width - 2 * Theme.space.lg
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            text: parent.count > 0 ? ScanTexts.scopeText : ScanTexts.startText
                            textFormat: Text.PlainText
                            color: Theme.color.text2
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            lineHeight: 20
                            lineHeightMode: Text.FixedHeight
                        }
                    }

                    // «Доступные серверы появятся здесь» / «Ищем ещё… до N с»
                    Text {
                        readonly property string w: root.view.wait || "none"
                        visible: w !== "none" && !root.blocked && !root.emptyResult
                        width: parent.width
                        topPadding: rowsModel.count === 0 ? Theme.space.lg : Theme.space.xxl - resultCol.spacing
                        horizontalAlignment: Text.AlignHCenter
                        text: w === "rows_appear_here" ? ScanTexts.waitRows : ScanTexts.waitMore.arg(root.view.wait_s || 0)
                        textFormat: Text.PlainText
                        color: Theme.color.text3
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyS
                        lineHeight: 20
                        lineHeightMode: Text.FixedHeight
                    }
                    // «Найти ещё» (owner 18.11): a finished scan continues with the next batch of paths and ADDS its rows
                    // to this list - no second mode, no other screen. view.more = {state: available | running |
                    // exhausted} and TribeScanner.findMore(); without them nothing is drawn.
                    Item {
                        id: moreBox
                        readonly property string st: (root.view.more && root.view.more.state) ? String(root.view.more.state) : ""
                        readonly property int unshown: (root.view.more && root.view.more.unshown) ? Number(root.view.more.unshown) : 0
                        readonly property bool canAsk: root.hasScanner && typeof TribeScanner.findMore === "function"
                        // the engine's one gate (view.more.blocked): a limit is said on the button, never a dead tap
                        readonly property string limit: (root.view.more && root.view.more.blocked) ? String(root.view.more.blocked) : ""
                        visible: !root.blocked && !root.emptyResult && rowsModel.count > 0
                                 && (st === "available" || st === "running" || st === "exhausted")
                        width: parent.width
                        height: st === "exhausted" ? moreDone.implicitHeight + Theme.space.sm : moreBtn.implicitHeight + Theme.space.sm
                        TribeButton {
                            id: moreBtn
                            objectName: "scannerMoreButton"
                            visible: moreBox.st !== "exhausted"
                            y: Theme.space.sm
                            width: parent.width
                            variant: "glass"
                            strokeIcon: moreBox.st === "running" ? "" : "radar"
                            text: moreBox.st === "running" ? ScanTexts.moreRunning
                                  : moreBox.limit === "budget" ? ScanTexts.moreInMin.arg(root.view.more.retry_min || 1)
                                  : ScanTexts.more
                            enabled: moreBox.st === "available" && moreBox.limit === "" && moreBox.canAsk
                            onClicked: { Haptic.play("light"); TribeScanner.findMore() }
                        }
                        Text {
                            id: moreDone
                            visible: moreBox.st === "exhausted"
                            y: Theme.space.sm
                            width: parent.width
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            // a country scope: every server of that country was checked («Найти ещё» has nothing left)
                            // (the menu counted more servers than the list shows: it says how many did not answer here)
                            text: root.scope !== "" && root.scope === String(root.barView.scanned_scope || "")
                                  ? (Number(moreBox.unshown) > 0
                                     ? ScanTexts.moreExhaustedUnshown.arg(bar.countryName(root.scope)).arg(moreBox.unshown)
                                     : ScanTexts.moreExhaustedScope.arg(bar.countryName(root.scope)))
                                  : ScanTexts.moreExhausted
                            textFormat: Text.PlainText
                            color: Theme.color.text3
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            lineHeight: 20
                            lineHeightMode: Text.FixedHeight
                        }
                    }
                    // the people mark's one-line legend, only while a visible row carries it
                    Row {
                        visible: root.anyCrowd && !root.blocked && !root.emptyResult
                        topPadding: 2   // .legend padding 2 4 0, after the 8 gap
                        leftPadding: Theme.space.xs
                        rightPadding: Theme.space.xs
                        spacing: 6
                        width: parent.width
                        TribeStrokeIcon {
                            anchors.verticalCenter: parent.verticalCenter
                            width: 12; height: 12
                            icon: "users"
                            tint: Theme.color.accent
                        }
                        Text {
                            width: parent.width - 12 - 6 - 2 * Theme.space.xs
                            text: ScanTexts.legend
                            textFormat: Text.PlainText
                            wrapMode: Text.WordWrap
                            color: Theme.color.text3
                            font.family: Theme.font.body
                            font.pixelSize: Theme.badge.text
                            lineHeight: 13
                            lineHeightMode: Text.FixedHeight
                        }
                    }
                    // a finished scan WITH rows and no live connection (desktop with the VPN off) still sends its results
                    // to support - the empty state's link, the view's empty.report_link (ScanMachine reportLinkOffered;
                    // lab seam S7, no artboard frame)
                    ReportLink {
                        visible: root.phase === "done" && root.emptyView.report_link === true
                        x: (parent.width - width) / 2
                        topPadding: Theme.space.md   // 12 + the column's 8 = the empty state's 16 + 4
                        sending: root.emptyView.report_sending === true
                        onTapped: if (root.hasScanner) TribeScanner.tapReportLink()
                    }

                    // ── empty result: the advice under the rings' «0», «Понял…» / «Сканировать все страны», the second
                    // button, the report link (the kit's empty-state pattern; the rings are its picture) ──
                    ColumnLayout {
                        id: emptyBlock
                        visible: root.emptyResult
                        x: Theme.space.sm
                        width: parent.width - 2 * Theme.space.sm
                        spacing: Theme.space.lg
                        readonly property bool cell: (root.view.net || "") === "cellular"
                        // a country scan found nothing (owner 18.11, the country as the scan's scope): view.empty.scope_cc;
                        // the country's name comes from bar.scope_countries (else the result's countries)
                        readonly property string scopeCc: String(root.emptyView.scope_cc || "")
                        readonly property bool scoped: scopeCc !== ""
                        Heading {
                            maxWidth: emptyBlock.width
                            Layout.preferredWidth: width
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: root.liveFirst ? Theme.space.sm : 0
                            text: emptyBlock.scoped ? ScanTexts.emptyScopeTitle.arg(bar.countryName(emptyBlock.scopeCc))
                                  : emptyBlock.cell ? ScanTexts.emptyCellTitle : ScanTexts.emptyWifiTitle
                            textFormat: Text.PlainText
                            color: Theme.color.text1
                            font.family: Theme.font.display
                            font.pixelSize: Theme.font.h3
                            font.weight: Theme.font.wBold
                            lineHeight: 24
                            lineHeightMode: Text.FixedHeight
                        }
                        Text {
                            Layout.fillWidth: true
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            text: emptyBlock.scoped ? ScanTexts.emptyScopeText
                                  : emptyBlock.cell ? ScanTexts.emptyCellText : ScanTexts.emptyWifiText
                            textFormat: Text.PlainText
                            color: Theme.color.text2
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            lineHeight: 20
                            lineHeightMode: Text.FixedHeight
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.topMargin: Theme.space.sm
                            spacing: Theme.space.md
                            // a country found nothing: the pause after its scan says why «Сканировать все страны» waits (the bar's hint style)
                            Text {
                                visible: emptyBlock.scoped && bar.gateText !== ""
                                Layout.fillWidth: true
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.WordWrap
                                text: bar.gateText
                                textFormat: Text.PlainText
                                color: Theme.color.text3
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.caption
                                lineHeight: 15
                                lineHeightMode: Text.FixedHeight
                            }
                            TribeButton {
                                objectName: "scannerEmptyPrimary"
                                Layout.fillWidth: true
                                variant: "primary"
                                text: emptyBlock.scoped ? ScanTexts.scanAll
                                      : emptyBlock.cell ? ScanTexts.emptyCellOk : ScanTexts.emptyWifiOk
                                enabled: !emptyBlock.scoped || !root.scanGated
                                onClicked: {
                                    Haptic.play("light")
                                    if (emptyBlock.scoped) {            // the whole pool: the scope «Все страны», then a scan
                                        root.scanAll()
                                        return
                                    }
                                    if (root.hasScanner) TribeScanner.gotIt()
                                    root.goBack()
                                }
                            }
                            TribeButton {
                                objectName: "scannerEmptySecondary"
                                Layout.fillWidth: true
                                variant: "glass"
                                // a country: back to the choice; the whole pool: the same scan again
                                text: emptyBlock.scoped ? ScanTexts.chooseOther : bar.retryText
                                enabled: emptyBlock.scoped || bar.retryEnabled
                                onClicked: {
                                    Haptic.play("light")
                                    if (emptyBlock.scoped) root.showChoice()
                                    else root.retryScan()
                                }
                            }
                        }
                        ReportLink {
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: Theme.space.xs
                            sending: root.emptyView.report_sending === true
                            onTapped: if (root.hasScanner) TribeScanner.tapReportLink()
                        }
                    }
                }
            }
        }
        // The list's top edge (device round air-C, D3): content scrolled under the badges fades out over Theme.space.xl -
        // a line cut at the edge (the half «ДОСТУПНЫ СЕЙЧАС» under the count badge) never shows as a fragment. Only while
        // the list is scrolled; the badges row above keeps its own background.
        Rectangle {
            objectName: "scannerListEdge"
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: Theme.space.xl
            visible: list.contentY > 0
            // solid over the first third (a cut line is never taller), then the fade
            gradient: Gradient {
                GradientStop { position: 0.0; color: Theme.color.bg800 }
                GradientStop { position: 0.35; color: Theme.color.bg800 }
                GradientStop { position: 1.0; color: Qt.alpha(Theme.color.bg800, 0) }
            }
        }
    }

    // ── the one pinned button ──
    TribeScanBar {
        id: bar
        objectName: "scannerBar"   // found by name: the desktop test rig presses this button (scan.start / scan.stop)
        z: 10
        visible: root.showBar
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        bar: root.barView
        choosing: root.choosing
        chooseAction: root.chooseAction
        again: !root.choosing && root.otherCount > 0
        cooldownEndsAtMs: Number(root.view.cooldown_ends_at_ms || 0)
        viewNowMs: Number(root.view.now_ms || 0)
        onStopTapped: root.stopScan()
        onRetryTapped: root.retryScan()
        onConnectAndScanTapped: {
            if (root.choosing) root.connectSelected()
            else if (root.hasScanner) TribeScanner.connectAndScan()
        }
        onScanTapped: root.scanSelected()
        onShowTapped: root.showSelected()
    }

    // One list row (flag, name, badges, bars, ms) with its arrive animation, for the model's row at `index`. liveSlot:
    // the slot of the live connection's row (index 0 while liveFirst) above the list; else every other row. A slot that
    // is not its row's (the other repeater's) loads nothing; one that becomes its row's plays the arrive animation.
    component ScanRowSlot: Item {
        id: slot
        required property var model
        required property int index
        property bool liveSlot: false
        property bool liveFirst: false
        property int liveAt: 0          // the live slot shows the model's row at this index (the result: 0 while liveFirst)
        property bool scanning: false
        property real rowWidth: 0
        property real pitch: 0
        property real gap: 0
        signal rowTapped(string rid)
        readonly property bool mine: liveSlot ? (liveAt === 0 ? (liveFirst && index === 0) : (liveAt > 0 && index === liveAt))
                                              : !(liveFirst && index === 0)
        width: rowWidth
        height: Theme.scan.rowHeight
        y: liveSlot ? 0 : (index - (liveFirst ? 1 : 0)) * pitch
        visible: mine
        Loader {
            anchors.fill: parent
            active: slot.mine
            // the wrapper takes the arrive animation, so the row keeps its own opacity (cached 55 %, failed 50 %)
            sourceComponent: Item {
                id: rowWrap
                opacity: Theme.motion.reduceMotion ? 1 : 0
                Component.onCompleted: if (!Theme.motion.reduceMotion) arrive.start()
                ParallelAnimation {
                    id: arrive
                    NumberAnimation { target: rowWrap; property: "opacity"; from: 0; to: 1; duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                    NumberAnimation { target: lift; property: "y"; from: slot.gap; to: 0; duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                }
                // Every role read with its default (device round air-C, D8): a new list build clears the model, and
                // a row being removed reads its roles as undefined once more before it goes ("Unable to assign
                // [undefined] to bool" at the start of a scope's scan).
                TribeScanRow {
                    anchors.fill: parent
                    transform: Translate { id: lift }
                    label: slot.model.label ?? ""
                    countryCode: slot.model.cc ?? ""
                    transport: slot.model.transport ?? "xray"
                    version: slot.model.version ?? ""
                    rowState: slot.model.rstate ?? "works"
                    speed: slot.model.speed ?? "none"
                    bars: slot.model.bars ?? 0
                    ms: slot.model.ms ?? -1
                    // a cached row is drawn as cache whenever no scan runs: the whole last result, or a row of it the
                    // finished scan did not judge again (it stays in its place)
                    cached: (slot.model.fromCache ?? false) && !slot.scanning
                    dimmed: slot.model.dimmed ?? false
                    tappable: slot.model.tappable ?? false
                    verifying: slot.model.verifying ?? false
                    liveUnverified: slot.model.liveUnverified ?? false
                    unverified: slot.model.unverified ?? false
                    crowd: slot.model.crowd ?? false
                    whitelist: slot.model.cc === ""
                    onTapped: slot.rowTapped(slot.model.rid ?? "")
                }
            }
        }
    }

    // the choice's section caption: the result's «ДОСТУПНЫ СЕЙЧАС» style
    component ChoiceCaption: Text {
        textFormat: Text.PlainText
        color: Theme.color.text3
        font.family: Theme.font.body
        font.pixelSize: Theme.font.caption
        font.weight: Theme.font.wSemibold
        font.letterSpacing: Theme.font.trackCaption * Theme.font.caption
        lineHeight: 15
        lineHeightMode: Text.FixedHeight
    }

    // One scope of the choice (the kit's list row, 66 like the server list): flag, name, «N серверов» (+ the fresh
    // result's «M доступно» over «K мин назад»), the «Авто» card's check circle. A tap SELECTS it (owner 24.11: no
    // navigation, no scan); the chosen row wears the kit's selection (chipSelected + accent border, filled circle).
    component ScopeRow: TribeListRow {
        id: scopeRow
        property string scope: ""
        property string cc: ""
        property string name: ""
        property int count: 0
        property bool whitelist: false
        readonly property var slot: root.slotOf(scope)
        readonly property bool chosen: root.selected === scope
        objectName: "scannerScope_" + (scope === "" ? "all" : scope)
        width: parent ? parent.width : 0
        height: Theme.scan.rowHeight
        selected: chosen
        title: name
        subtitle: count > 0 && root.poolKnown ? ScanTexts.servers(count) : ""
        monoSubtitle: false
        leftItem: Item {
            width: Theme.scan.flag
            height: Theme.scan.rowHeight
            TribeFlag {
                anchors.centerIn: parent
                width: Theme.scan.flag
                height: Theme.scan.flag
                code: scopeRow.cc
                whitelist: scopeRow.whitelist
                // «Все страны»: the white-list flag's shape (disc, hairline ring, globe 62 %) in the glass tone
                fallback: Component {
                    Rectangle {
                        radius: width / 2
                        color: Theme.color.glass
                        border.width: 1
                        border.color: Theme.color.border2
                        TribeStrokeIcon {
                            anchors.centerIn: parent
                            width: parent.width * 0.62
                            height: parent.height * 0.62
                            icon: "globe"
                            tint: Theme.color.accent
                        }
                    }
                }
            }
        }
        // a fresh result: «M доступно» over its age, as the server row's bars over its ms; then the choice mark
        rightItem: Row {
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.space.md
            Column {
                visible: scopeRow.slot !== null
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2
                Text {
                    anchors.right: parent.right
                    text: scopeRow.slot ? ScanTexts.slotAvailable(Number(scopeRow.slot.works || 0)) : ""
                    textFormat: Text.PlainText
                    color: Theme.color.accent
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    font.weight: Theme.font.wSemibold
                }
                // a stopped scan's result says so (review F5): «остановлен · 3 мин назад»
                Text {
                    anchors.right: parent.right
                    text: root.slotLine(scopeRow.slot)
                    textFormat: Text.PlainText
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                }
            }
            // the «Авто» card's choice mark (PageServersTribe): accent with the check when chosen, surface3 when not
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 22; height: 22
                radius: Theme.radius.pill
                color: scopeRow.chosen ? Theme.color.accent : Theme.color.surface3
                Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                TribeStrokeIcon {
                    anchors.centerIn: parent
                    width: 12; height: 12
                    visible: scopeRow.chosen
                    icon: "check-mark"
                    tint: Theme.color.bg800
                    weight: 2.6
                }
            }
        }
        Accessible.role: Accessible.RadioButton
        Accessible.checked: chosen
        Accessible.name: title + (subtitle !== "" ? ", " + subtitle : "")
                         + (slot ? ", " + ScanTexts.slotAvailable(Number(slot.works || 0)) + ", " + root.slotLine(slot) : "")
        Accessible.onPressAction: root.select(scope)
        onClicked: root.select(scope)
    }

    // titles wrap balanced (artboard text-wrap: balance): the narrowest width that keeps the greedy line count,
    // so the last line is not an orphan word
    component Heading: Text {
        id: heading
        property real maxWidth: 0
        FontMetrics { id: metrics; font: heading.font }
        function linesAt(words, w) {
            const space = metrics.advanceWidth(" ")
            let n = 1, cur = 0
            for (let i = 0; i < words.length; ++i) {
                const ww = metrics.advanceWidth(words[i])
                if (cur > 0 && cur + space + ww > w) { n += 1; cur = ww } else cur += (cur > 0 ? space : 0) + ww
            }
            return n
        }
        function balanced(t, maxW) {
            const words = String(t).split(" ").filter(x => x.length > 0)
            if (maxW <= 0 || words.length < 2) return maxW
            const target = linesAt(words, maxW)
            if (target < 2) return maxW
            let lo = 0, hi = maxW
            for (let k = 0; k < 12; ++k) {
                const mid = (lo + hi) / 2
                if (linesAt(words, mid) <= target) hi = mid; else lo = mid
            }
            return Math.min(maxW, Math.ceil(hi) + 2)
        }
        width: balanced(text, maxWidth)
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
    }

    // «Отправить отчёт в поддержку» → «Отправляем отчёт…» (artboard figs 14-15): the empty result's link, also under
    // the list of a finished scan without a live connection. One definition for both places.
    component ReportLink: Text {
        id: link
        property bool sending: false
        signal tapped()
        text: sending ? ScanTexts.reportSending : ScanTexts.report
        textFormat: Text.PlainText
        color: Theme.color.text2
        font.family: Theme.font.body
        font.pixelSize: Theme.font.monoData
        font.weight: Theme.font.wMedium
        font.underline: true
        Accessible.role: Accessible.Link
        Accessible.name: text
        MouseArea {
            anchors.fill: parent
            anchors.margins: -Theme.space.sm
            enabled: !link.sending
            cursorShape: Qt.PointingHandCursor
            onClicked: { Haptic.play("light"); link.tapped() }
        }
    }
}

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts

import ".."              // Theme, ScanTexts, ScanSwitches, Haptic
import "../components"
import "../../Controls2" // PageType

// AVPN: the Scanner («Сканер») — ONE page with two views (owner 24.11, the same on every platform):
//  - «Выбор» (choosing): the page always opens here and never scans by itself. The live connection's row first under
//    «ВАШЕ ПОДКЛЮЧЕНИЕ» (when there is one), then «ВЫБЕРИТЕ СТРАНУ»: «Белые списки» when the pool has them and every
//    country of the pool with its servers (bar.scope_countries / scope_whitelist); a scope with a fresh result of this
//    network (view.slots) says « · M доступно · K мин назад». Pinned: «Сканировать все страны». A tap shows the fresh
//    result of that scope without a scan, or scans it at once; during the 30 s pause / the cellular hour the rows that
//    would scan and the button are disabled and the hint line says why.
//  - «Результат»: header = the scope's name with the back arrow to «Выбор»; the two status chips (last check,
//    network); the rings with one status line and a thin bar while scanning - the first item of the scrolling list,
//    collapsing in 360 ms once the scan ends; the machine's rows in its order (the live connection first, drawn like
//    the others); «Найти ещё», the crowd legend; the pinned bar («Остановить» = stop and back to «Выбор»,
//    «Сканировать снова» / its countdown). The empty result and the «Скан сейчас невозможен» reasons are drawn from
//    the same kit parts.
// The screen only DRAWS the view: TribeScanner.view = ScanView JSON (ScanMachine.h scanViewToJson); every decision
// (order, row lifetime, scope, stop, cooldown, budget, shades) is the pure machine's.
// Non-tab page (goToTabBarPageUrl); back from «Выбор» returns to where it was opened from. After a row tap the user
// STAYS here.
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
    readonly property bool hero: view.hero === true
    readonly property var barView: view.bar || ({})
    readonly property var emptyView: view.empty || ({})
    readonly property string reason: emptyView.reason || ""
    readonly property bool noScan: phase === "no_scan"
    // NoScan: every reason of the coordinator's vocabulary is mapped in ScanTexts.noScan() (one table): "list" = the
    // last result + the bar with the view's buttons; "blocked" = «Скан сейчас невозможен» (figures 21-26): icon,
    // title, text, one action, the last result below, no bar
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
    // the bar is up on the choice, and on the result in every state but blocked / empty
    readonly property bool showBar: choosing || (!blocked && !emptyResult)

    // ── the two views (owner 24.11) ──
    property string pane: "choose"       // "choose" = «Выбор», "result" = «Результат»
    readonly property bool choosing: pane === "choose"
    // view.slots: [{scope, works, ago_min}] - this network's fresh results, one per scope (ScanMachine.h scopeSlots):
    // a choice row with one shows it without a scan
    readonly property var slotList: Array.isArray(view.slots) ? view.slots : []
    function slotOf(sc) {
        for (let i = 0; i < slotList.length; ++i)
            if (String(slotList[i].scope || "") === sc) return slotList[i]
        return null
    }
    readonly property var poolCountries: Array.isArray(barView.scope_countries) ? barView.scope_countries : []
    readonly property int poolWhitelist: Number(barView.scope_whitelist || 0)
    // the machine refuses a scan now (the 30 s pause, the cellular hour): nothing that would scan is offered
    readonly property bool scanGated: bar.gated
    function slotAgo(slot) {
        return slot ? ScanTexts.ago(Number(slot.ago_min || 0), Number(view.now_ms || Date.now())) : ""
    }
    // a scope tapped on the choice: its fresh result is shown as it is (showSlot: also out of a failed re-scan of the
    // same scope - review round 36, F3), else that scope is scanned at once
    function pick(sc) {
        if (!hasScanner) return
        const fresh = slotOf(sc) !== null
        if (!fresh && scanGated) return
        showResult()
        if (fresh && typeof TribeScanner.showSlot === "function") {
            TribeScanner.showSlot(sc)
            return
        }
        TribeScanner.chooseCountry(sc)
        if (!fresh) TribeScanner.retry()
    }
    // «Сканировать все страны»: the whole pool, always a scan
    function scanAll() {
        if (!hasScanner || scanGated) return
        showResult()
        TribeScanner.chooseCountry("")
        TribeScanner.retry()
    }
    function showResult() {
        list.contentY = 0
        pane = "result"
    }
    // back to the choice; a running scan is stopped (the machine keeps the screen open: ScanMachine::stopTapped)
    function showChoice() {
        if (scanning && hasScanner) TribeScanner.stop()
        pane = "choose"
    }
    // Owner 19.11 (device test, iPhone Air): the country is the SCOPE of the next scan over the whole pool, never a
    // filter of rows found before. A scope the shown result does not cover = the machine's list is empty: only the
    // scope's summary («Германия · 12 серверов») and the Scan button; its own result appears after its scan.
    readonly property string scope: String(barView.scope || "")
    // nothing of this scope on the screen yet (page open without results, or a scope not scanned): its summary
    // (the live connection's row, when there is one, is always above it and does not count)
    readonly property bool scopeStart: !scanning && !blocked && !emptyResult && otherCount === 0
    function scopeCount(cc) {
        if (cc === "whitelist")
            return Number(barView.scope_whitelist || 0)
        const list = Array.isArray(barView.scope_countries) ? barView.scope_countries : []
        let n = 0
        for (let i = 0; i < list.length; ++i)
            if (cc === "" || list[i].cc === cc) n += Number(list[i].count || 0)
        return n
    }
    readonly property bool showMark: phase === "done" || phase === "empty"
    property bool allCache: false         // every shown row is a cached one (set by syncRows)
    readonly property bool lastResult: !scanning && otherCount > 0 && (blocked || allCache)
    // the live connection's row (view.rows[0] with the «current» flag) is drawn first, above everything else of the list;
    // otherCount = the rows besides it (set by syncRows)
    property bool liveFirst: false
    // the live connection's row wherever the result has it (review round 36, F4: a row connected from the list keeps
    // its place - rows never jump - and the choice still shows it under «ВАШЕ ПОДКЛЮЧЕНИЕ»); -1 = none (set by syncRows)
    property int liveIndex: -1
    readonly property int otherCount: rowsModel.count - (liveFirst ? 1 : 0)
    property bool anyCrowd: false
    property bool leaving: false

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
        heroFrac = hero ? 1 : 0
        syncRows()
        completed = true
        refreshServiceAction()
        // the check with the report runs from Support now (variant B, 18.11): the Scanner never opens with it
        // owner 19.11: opening the Scanner never starts a scan - the Scan button does (show(); open() scans)
        if (hasScanner) {
            if (typeof TribeScanner.show === "function") TribeScanner.show()
            else TribeScanner.open(false)
        }
        // owner 24.11: the page opens on the choice; only a scan that already runs (Support's check started it with
        // the page closed) is shown as it goes
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
    // network, or a scan the person starts: «Сканировать» clears the old rows and builds from empty) and never leaves while a scan runs; «Не проверено» rows join only once final. So the model follows the
    // view index by index: a row changes in place, a new one is appended; a new build replaces the model.
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

    // ── rings collapse (360 ms) into the header mark, and grow back the same way on «Сканировать снова» ──
    // heroFrac 1 = rings + status line shown, 0 = gone. The block is the FIRST item of the scrolling list (owner 24.11:
    // after a scan the rows move up into the place the rings held - no empty band stays at the top).
    // Device round 13, A5 (rows jumped up under the finger) is kept as a rule, not as a held band:
    //  - the block collapses only while the list is at rest: a finger on it, a drag or a flick defers the collapse until
    //    it settles;
    //  - a scrolled list keeps the rows on the screen still: the block's change of height is taken out of contentY
    //    (heroBox.onHeightChanged), so only a list at its top moves up.
    property real heroFrac: 0
    property bool heroPending: false            // the scan ended under a finger / a moving list: collapse once it rests
    readonly property bool listHeld: list.moving || listFinger.active
    function applyHero() {
        const want = hero ? 1 : 0
        if (!hero && listHeld && heroFrac > 0) {
            heroPending = true
            return
        }
        heroPending = false
        if (heroAnim.running && heroAnim.to === want) return
        if (!heroAnim.running && heroFrac === want) return
        heroAnim.to = want
        heroAnim.restart()
    }
    onHeroChanged: applyHero()
    onListHeldChanged: if (!listHeld && heroPending) applyHero()
    // a deferred collapse: the rings and the status line fade out at once (the scan has ended), the block keeps its
    // height until the list rests
    property real heroFade: heroPending ? 0 : 1
    Behavior on heroFade { NumberAnimation { duration: Theme.motion.reduceMotion ? 0 : Theme.motion.fast } }
    NumberAnimation {
        id: heroAnim
        target: root; property: "heroFrac"
        duration: Theme.motion.reduceMotion ? 0 : Theme.motion.slow
        // in-out: the list under the block starts moving gently (OutCubic moved it 35 px in the first frame)
        easing.type: Easing.InOutCubic
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    TribeEdgeBack { onTriggered: root.navBack() }

    // ── header: «Сканер» on the choice, the scope's name on the result ──
    TribeHeader {
        id: header
        anchors.top: parent.top
        anchors.topMargin: root.safeTop
        anchors.left: parent.left
        anchors.right: parent.right
        title: root.choosing ? ScanTexts.title : bar.countryName(root.scope)
        showBack: true
        onBackClicked: root.navBack()
        rightItem: SignalRing {
            anchors.verticalCenter: parent.verticalCenter
            compact: true
            visible: opacity > 0
            opacity: (root.showMark && !root.choosing) ? 1 : 0
            Behavior on opacity { NumberAnimation { duration: Theme.motion.reduceMotion ? 0 : Theme.motion.slow } }
            Accessible.role: Accessible.Graphic
            Accessible.name: ScanTexts.markName
        }
    }

    // ── the two status chips (owner 18.11, his sketch): the last check top-left and the network top-right, in the
    // corners of the radar block. The row is fixed under the header: the rings sit under it while scanning and
    // collapse away, the chips never move (scan running, finished, blocked, empty - the same place).
    Item {
        id: chipsRow
        anchors.top: header.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        height: Theme.scan.chip
        z: 2
        // checked_ago_min: the finished scan, or the cached rows shown while a new scan runs / no scan can run
        readonly property string agoText: ScanTexts.ago(Number(root.view.checked_ago_min ?? -1),
                                                        Number(root.view.now_ms || Date.now()))
        readonly property string netText: ScanTexts.netCaption(root.view.net || "", root.view.net_radio || "")
        TribePill {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            visible: opacity > 0
            // the choice says each scope's age on its own row: the chip belongs to the result
            opacity: (chipsRow.agoText !== "" && !root.choosing) ? 1 : 0
            Behavior on opacity { NumberAnimation { duration: Theme.motion.reduceMotion ? 0 : Theme.motion.fast } }
            icon: "clock"
            text: chipsRow.agoText
            Accessible.name: ScanTexts.agoName.arg(chipsRow.agoText)
        }
        TribePill {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            visible: chipsRow.netText !== ""
            icon: ScanTexts.netIcon(root.view.net || "")
            text: chipsRow.netText
            Accessible.name: ScanTexts.netName.arg(chipsRow.netText)
        }
    }

    // ── the list: caption, rows, wait line, legend (all inside the scroll) ──
    Item {
        id: listArea
        // the empty result draws its own block below; the rings still collapse here when a scan ends empty
        visible: !root.choosing && (!root.emptyResult || root.heroFrac > 0)
        // under the chips row, in every phase: the rings scroll with the list (their block is its first item)
        y: chipsRow.y + chipsRow.height
        height: (root.showBar ? bar.y : root.height) - y
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl

        // a Flickable + Column (the list holds <= 12 rows + 2 «Не проверено»): the caption and the rows
        // scroll together; rows keep their delegates across view updates (ListModel diff) and animate in once
        Flickable {
            id: list
            anchors.fill: parent
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            readonly property real padTop: Theme.space.md   // one value in every phase: no step when the rings go
            readonly property real padBottom: Theme.space.lg
            contentWidth: width
            contentHeight: heroBox.height + content.height + padTop + padBottom

            // ── rings + one status line + a thin bar: ONE block, the list's first item, that grows and collapses as a
            // whole, so the rows under it move once, smoothly (owner 18.11 «передёргивание»: the status line used to vanish
            // at once and the list jumped by its height before the rings collapsed)
            Item {
                id: heroBox
                y: list.padTop
                width: list.width
                // + the gap to the first row (the list's top padding), so it goes with the block
                readonly property real full: Theme.scan.hero + status.implicitHeight + list.padTop
                height: full * root.heroFrac
                clip: true
                visible: height > 0
                // A5: a scrolled list keeps its visible rows still while the block changes height
                property real lastHeight: 0
                onHeightChanged: {
                    const d = height - lastHeight
                    lastHeight = height
                    if (d !== 0 && list.contentY > 0)
                        list.contentY = Math.max(0, list.contentY + d)
                }
                SignalRing {
                    x: (parent.width - width) / 2
                    y: (Theme.scan.hero - height) / 2
                    ringState: "scanning"
                    visible: root.heroFrac > 0
                    opacity: root.heroFrac * root.heroFade
                    scale: 0.07 + 0.93 * root.heroFrac
                    transform: Translate { x: (1 - root.heroFrac) * 150; y: -(1 - root.heroFrac) * 150 }
                }
                ColumnLayout {
                    id: status
                    y: Theme.scan.hero
                    width: parent.width
                    opacity: root.heroFrac * root.heroFade
                    spacing: Theme.space.sm
                    Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        elide: Text.ElideRight
                        text: {
                            const v = root.view
                            switch (v.stage) {
                            case "connecting": return ScanTexts.stageConnecting
                            case "reach": return ScanTexts.stageReach.arg(v.stage_count || 0).arg(v.stage_total || 0)
                            case "data": return ScanTexts.stageData.arg(v.stage_count || 0).arg(v.stage_total || 0)
                            }
                            return ScanTexts.stageReachShort
                        }
                        textFormat: Text.PlainText
                        color: Theme.color.text2
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.monoData
                        font.weight: Theme.font.wMedium
                        lineHeight: 17
                        lineHeightMode: Text.FixedHeight
                    }
                    TribeProgressBar {
                        Layout.fillWidth: true
                        percent: (root.view.stage === "connecting" || root.view.stage === "preparing" || Number(root.view.progress) < 0)
                                 ? -1 : Math.round(100 * Number(root.view.progress || 0))
                    }
                }
            }

            Column {
                id: content
                y: list.padTop + heroBox.height
                width: list.width
                spacing: Theme.space.sm
                visible: !root.emptyResult

                // «Скан сейчас невозможен»: the empty-state pattern (amber icon, title, text, one action)
                Column {
                    visible: root.blocked
                    width: parent.width
                    topPadding: Theme.space.lg
                    bottomPadding: Theme.space.sm + Theme.space.xs   // + the button's 4 px shift below
                    spacing: Theme.space.md
                    // service states: the per-action act (ensure / retry / none); others: the table's action
                    readonly property string act: root.block.action !== "ensureService" ? (root.block.action || "")
                        : (root.svc.act === "ensure" && !root.hasEnsure ? "retry" : (root.svc.act || ""))
                    readonly property bool ensure: act === "ensure"
                    TribeStrokeIcon {
                        anchors.horizontalCenter: parent.horizontalCenter
                        width: 40; height: 40
                        icon: root.block.icon || "alert-circle"
                        tint: Theme.color.warning
                        weight: 1.8
                    }
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
                            } else if (root.hasScanner) {
                                TribeScanner.retry()
                            }
                        }
                    }
                }

                // the live connection's row: always the first thing of the list, drawn like every other row
                Item {
                    id: liveBox
                    visible: root.liveFirst
                    width: parent.width
                    height: root.liveFirst ? Theme.scan.rowHeight : 0
                    Repeater {
                        model: rowsModel
                        delegate: ScanRowSlot {
                            liveSlot: true
                            liveFirst: root.liveFirst
                            scanning: root.scanning
                            rowWidth: liveBox.width
                            pitch: Theme.scan.rowHeight + content.spacing
                            gap: content.spacing
                            onRowTapped: (rid) => { if (root.hasScanner) TribeScanner.tapRow(rid) }
                        }
                    }
                }

                // «Все страны · 46 серверов» / «Германия · 12 серверов» + what the Scan button does: page open
                // without results, or a scope the shown result does not cover (the kit's empty-state pattern: icon,
                // title, text; the action is the bar's Scan button - one button, one meaning)
                Column {
                    visible: root.scopeStart
                    width: parent.width
                    topPadding: Theme.space.xxl
                    bottomPadding: Theme.space.lg
                    spacing: Theme.space.md
                    readonly property int count: root.scopeCount(root.scope)
                    TribeStrokeIcon {
                        anchors.horizontalCenter: parent.horizontalCenter
                        width: 40; height: 40
                        icon: "radar"
                        tint: Theme.color.accent
                        weight: 1.8
                    }
                    Heading {
                        maxWidth: parent.width - 2 * Theme.space.lg
                        x: (parent.width - width) / 2
                        text: parent.count > 0
                              ? ScanTexts.scopeTitle.arg(root.scope === "" ? ScanTexts.allCountries : bar.countryName(root.scope))
                                                    .arg(ScanTexts.servers(parent.count))
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

                Text {
                    id: sectionLabel
                    visible: root.otherCount > 0
                    // under the connected row (when there is one) .sec-label.in-list margin-top 4; else the list's first child
                    topPadding: root.liveFirst ? Theme.space.xs : 0
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
                // The other rows place THEMSELVES: y = place x pitch (place = index, less the live row above). Rows only
                // join the end (the machine's list), so an index never changes while the list lives. A new row fades in
                // at its own place, rising from one gap below (never over a row). One delegate (ScanRowSlot) serves the
                // live row's repeater above and this one: a slot shows itself or hides by index 0 + liveFirst.
                Item {
                    id: rowsBox
                    readonly property real pitch: Theme.scan.rowHeight + content.spacing
                    visible: root.otherCount > 0
                    width: parent.width
                    height: Math.max(0, root.otherCount * pitch - content.spacing)
                    // the lines under the rows (wait line, legend, «Найти ещё») slide with the list's growth
                    Behavior on height {
                        enabled: !Theme.motion.reduceMotion
                        NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                    }
                    Repeater {
                        model: rowsModel
                        delegate: ScanRowSlot {
                            liveSlot: false
                            liveFirst: root.liveFirst
                            scanning: root.scanning
                            rowWidth: rowsBox.width
                            pitch: rowsBox.pitch
                            gap: content.spacing
                            onRowTapped: (rid) => { if (root.hasScanner) TribeScanner.tapRow(rid) }
                        }
                    }
                }

                // «Рабочие ноды появятся здесь» / «Ищем ещё… до N с»; alone in the list it sits in the middle
                Text {
                    readonly property string w: root.view.wait || "none"
                    visible: w !== "none" && !root.blocked
                    width: parent.width
                    // alone in the list it sits in the middle (artboard .list.empty: centred with its 32 margin)
                    topPadding: rowsModel.count === 0
                                ? Math.max(Theme.space.xxl, (list.height - list.padTop - list.padBottom - 20 + Theme.space.xxl) / 2)
                                : Theme.space.xxl - content.spacing
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
                // to this list - no second mode, no other screen. WAITS FOR THE ENGINE: view.more = {state:
                // available | running | exhausted} and TribeScanner.findMore(); without them nothing is drawn.
                Item {
                    id: moreBox
                    readonly property string st: (root.view.more && root.view.more.state) ? String(root.view.more.state) : ""
                    readonly property int unshown: (root.view.more && root.view.more.unshown) ? Number(root.view.more.unshown) : 0
                    readonly property bool canAsk: root.hasScanner && typeof TribeScanner.findMore === "function"
                    // the engine's one gate (view.more.blocked): a limit is said on the button, never a dead tap
                    readonly property string limit: (root.view.more && root.view.more.blocked) ? String(root.view.more.blocked) : ""
                    visible: !root.blocked && rowsModel.count > 0 && (st === "available" || st === "running" || st === "exhausted")
                    width: parent.width
                    height: st === "exhausted" ? moreDone.implicitHeight + Theme.space.sm : moreBtn.implicitHeight + Theme.space.sm
                    TribeButton {
                        id: moreBtn
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
                    visible: root.anyCrowd && !root.blocked
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
                // a finished scan WITH rows and no live connection (desktop with the VPN off) still sends its results to support - the empty state's link, the view's
                // empty.report_link (ScanMachine reportLinkOffered; lab seam S7, no artboard frame)
                ReportLink {
                    visible: root.phase === "done" && root.emptyView.report_link === true
                    x: (parent.width - width) / 2
                    topPadding: Theme.space.md   // 12 + the column's 8 = the empty state's 16 + 4
                    sending: root.emptyView.report_sending === true
                    onTapped: if (root.hasScanner) TribeScanner.tapReportLink()
                }
            }
        }
        // a finger on the list (a row press included - a MouseArea takes it before the Flickable would): the rings wait
        // with their collapse until it lifts (A5). A passive grab: rows, «Найти ещё» and the scroll get the touch as before.
        Item {
            anchors.fill: parent
            PointHandler { id: listFinger; target: null }
        }
    }

    // ── empty result: the live connection's row first, then the advice ──
    Item {
        id: emptyLive
        visible: !root.choosing && root.emptyResult && root.liveFirst
        y: chipsRow.y + chipsRow.height + list.padTop
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        height: Theme.scan.rowHeight
        Repeater {
            model: rowsModel
            delegate: ScanRowSlot {
                liveSlot: true
                liveFirst: root.liveFirst
                scanning: root.scanning
                rowWidth: emptyLive.width
                pitch: Theme.scan.rowHeight + Theme.space.sm
                gap: Theme.space.sm
                onRowTapped: (rid) => { if (root.hasScanner) TribeScanner.tapRow(rid) }
            }
        }
    }

    // ── empty result: advice, «Понял…», «Повторить», the report link ──
    ColumnLayout {
        id: emptyBlock
        visible: !root.choosing && root.emptyResult
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xxl
        anchors.rightMargin: Theme.space.xxl
        readonly property real topEdge: emptyLive.visible ? emptyLive.y + emptyLive.height + Theme.space.md : chipsRow.y + chipsRow.height
        y: topEdge + (root.height - topEdge - implicitHeight) / 2
        spacing: Theme.space.lg
        readonly property bool cell: (root.view.net || "") === "cellular"
        // a country scan found nothing (owner 18.11, the menu as the scan's scope). WAITS FOR THE ENGINE:
        // view.empty.scope_cc; the country's name comes from bar.scope_countries (else the result's countries)
        readonly property string scopeCc: String(root.emptyView.scope_cc || "")
        readonly property bool scoped: scopeCc !== ""
        TribeStrokeIcon {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 48; Layout.preferredHeight: 48
            icon: "wifi-off"
            tint: Theme.color.warning
            weight: 1.8
        }
        Heading {
            maxWidth: emptyBlock.width
            Layout.preferredWidth: width
            Layout.alignment: Qt.AlignHCenter
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
                Layout.fillWidth: true
                variant: "glass"
                // a country: back to the choice; the whole pool: the same scan again
                text: emptyBlock.scoped ? ScanTexts.chooseOther : bar.retryText
                enabled: emptyBlock.scoped || bar.retryEnabled
                onClicked: {
                    Haptic.play("light")
                    if (emptyBlock.scoped) root.showChoice()
                    else if (root.hasScanner) TribeScanner.retry()
                }
            }
        }
        ReportLink {
            id: reportLink
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Theme.space.xs
            sending: root.emptyView.report_sending === true
            onTapped: if (root.hasScanner) TribeScanner.tapReportLink()
        }
    }

    // ── «Выбор»: the live connection, then every scope of the pool (owner 24.11) ──
    Item {
        id: chooseArea
        visible: root.choosing
        y: chipsRow.y + chipsRow.height
        height: bar.y - y
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        Flickable {
            id: chooseList
            anchors.fill: parent
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            contentWidth: width
            contentHeight: chooseCol.height + list.padTop + list.padBottom
            Column {
                id: chooseCol
                y: list.padTop
                width: chooseList.width
                spacing: Theme.space.sm
                ChoiceCaption {
                    visible: root.liveIndex >= 0
                    text: ScanTexts.liveCaption
                }
                // the live connection's row, drawn as on the result - found by its «current» flag, at any place of the
                // result (F4)
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
                // a fresh result of the whole pool («Сканировать все страны» before): it stays one tap away
                ScopeRow {
                    visible: root.slotOf("") !== null
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
                // before the pool answers (or when it cannot): the pinned button still checks everything
                Text {
                    visible: root.poolCountries.length === 0 && root.poolWhitelist <= 0
                    width: parent.width
                    topPadding: Theme.space.lg
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
        }
    }

    // ── pinned bar ──
    TribeScanBar {
        id: bar
        z: 10
        visible: root.showBar
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        bar: root.barView
        choosing: root.choosing
        again: root.otherCount > 0
        cooldownEndsAtMs: Number(root.view.cooldown_ends_at_ms || 0)
        viewNowMs: Number(root.view.now_ms || 0)
        // owner 24.11: «Остановить» cancels the scan and goes back to the choice (the Scanner stays open)
        onStopTapped: root.showChoice()
        onRetryTapped: if (root.hasScanner) TribeScanner.retry()
        onConnectAndScanTapped: if (root.hasScanner) TribeScanner.connectAndScan()
        onScanAllTapped: root.scanAll()
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
                TribeScanRow {
                    anchors.fill: parent
                    transform: Translate { id: lift }
                    label: slot.model.label
                    countryCode: slot.model.cc
                    transport: slot.model.transport
                    version: slot.model.version
                    rowState: slot.model.rstate
                    speed: slot.model.speed
                    bars: slot.model.bars
                    ms: slot.model.ms
                    // a cached row is drawn as cache whenever no scan runs: the whole last result, or a row of it the
                    // finished scan did not judge again (it stays in its place)
                    cached: slot.model.fromCache && !slot.scanning
                    dimmed: slot.model.dimmed
                    tappable: slot.model.tappable
                    verifying: slot.model.verifying
                    liveUnverified: slot.model.liveUnverified
                    unverified: slot.model.unverified
                    crowd: slot.model.crowd
                    whitelist: slot.model.cc === ""
                    onTapped: slot.rowTapped(slot.model.rid)
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
    // result's « · M доступно · K мин назад»), chevron. A scope without a fresh result is disabled while the machine
    // refuses a scan (the 30 s pause, the cellular hour); one with a result stays tappable - it only shows it.
    component ScopeRow: TribeListRow {
        id: scopeRow
        property string scope: ""
        property string cc: ""
        property string name: ""
        property int count: 0
        property bool whitelist: false
        readonly property var slot: root.slotOf(scope)
        readonly property bool canTap: slot !== null || !root.scanGated
        width: parent ? parent.width : 0
        height: Theme.scan.rowHeight
        interactive: canTap
        opacity: canTap ? 1 : 0.45   // TribeButton's disabled look
        Behavior on opacity { NumberAnimation { duration: Theme.motion.fast } }
        title: name
        subtitle: ScanTexts.servers(count)
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
        // a fresh result: «M доступно» over its age, as the server row's bars over its ms; then the chevron
        rightItem: Row {
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.space.sm
            Column {
                visible: scopeRow.slot !== null
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2
                Text {
                    anchors.right: parent.right
                    text: scopeRow.slot ? ScanTexts.slotWorks.arg(Number(scopeRow.slot.works || 0)) : ""
                    textFormat: Text.PlainText
                    color: Theme.color.accent
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    font.weight: Theme.font.wSemibold
                }
                Text {
                    anchors.right: parent.right
                    text: root.slotAgo(scopeRow.slot)
                    textFormat: Text.PlainText
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                }
            }
            TribeStrokeIcon {
                anchors.verticalCenter: parent.verticalCenter
                width: Theme.space.lg
                height: Theme.space.lg
                icon: "chevron-right"
                tint: Theme.color.text3
            }
        }
        Accessible.role: Accessible.Button
        Accessible.name: title + ", " + subtitle
                         + (slot ? ", " + ScanTexts.slotWorks.arg(Number(slot.works || 0)) + ", " + root.slotAgo(slot) : "")
        onClicked: { Haptic.play("light"); root.pick(scope) }
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

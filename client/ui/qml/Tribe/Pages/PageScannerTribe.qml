pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts

import ".."              // Theme, ScanTexts, ScanSwitches, Haptic
import "../components"
import "../../Controls2" // PageType

// AVPN: the Scanner («Сканер») — ONE screen (owner, artboard design/systems/tribe-backend/lab/vpn-scanner @ 9ac7ccff,
// plan scanner-client-plan.md §1, §4; owner review 18.11): header «Сканер» (+ the 18 px mark after the scan), the
// two status chips (last check, network), the rings with one status line and a thin bar while scanning (they
// collapse in 360 ms), then the list - one line of what is connected now (variant B: the card «Ваше подключение»
// and its check left for Support), rows by speed, the crowd legend - and the pinned bar (country
// menu left of «Повторить» / «Остановить»). The empty result and the «Скан сейчас невозможен» reasons are drawn from
// the same kit parts. The screen only DRAWS the view: TribeScanner.view = ScanView JSON (ScanMachine.h
// scanViewToJson); every decision (order, filter, stop, cooldown, budget, card, shades) is the pure machine's.
// Non-tab page (goToTabBarPageUrl); back returns to where it was opened from. After a row tap the user STAYS here.
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
    // The live VPN state from the engine (the card's badge): connected = data path up, connecting = an attempt runs
    readonly property string liveVpn: typeof TribeEngine === "undefined" ? "off"
        : TribeEngine.state === "connected" ? "connected"
        : (TribeEngine.busy === true && TribeEngine.stopping !== true) || TribeEngine.state === "verifying" ? "connecting"
        : "off"
    readonly property bool emptyResult: phase === "empty"
    // the bar is up in every state but blocked / empty: on page open too (idle) - it holds the one Scan button
    readonly property bool showBar: !blocked && !emptyResult
    // Owner 19.11 (device test, iPhone Air): the country is the SCOPE of the next scan over the whole pool, never a
    // filter of rows found before. A scope the shown result does not cover = nothing of that result is shown, only
    // the scope's summary («Германия · 12 серверов») and the Scan button; its own result appears after its scan.
    readonly property string scope: String(barView.scope || "")
    readonly property bool scopeKnown: barView.scope !== undefined && Array.isArray(barView.scope_countries)
    readonly property bool scopePending: scopeKnown && !scanning && scope !== String(barView.scanned_scope || "")
    onScopePendingChanged: syncRows()
    // nothing of this scope on the screen yet (page open without results, or a scope not scanned): its summary
    readonly property bool scopeStart: !scanning && !blocked && !emptyResult && (scopePending || rowsModel.count === 0)
    function scopeCount(cc) {
        const list = Array.isArray(barView.scope_countries) ? barView.scope_countries : []
        let n = 0
        for (let i = 0; i < list.length; ++i)
            if (cc === "" || list[i].cc === cc) n += Number(list[i].count || 0)
        return n
    }
    readonly property bool showMark: phase === "done" || phase === "empty"
    property bool allCache: false         // every shown row is a cached one (set by syncRows)
    readonly property bool lastResult: !scanning && rowsModel.count > 0 && (blocked || allCache)
    property bool anyCrowd: false
    property string liveLabel: ""
    property string liveCc: ""
    property bool leaving: false

    // ── navigation ──
    function goBack() {
        if (leaving) return
        leaving = true
        if (origin === "servers") root.requestServerPicker()
        else if (origin === "chat") root.requestTab(1)
        else root.back()
    }
    function systemBack() { goBack() }     // PageStart.onEscapePressed (Android Back / Escape)

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
    // Calm arrival (owner 18.11 «передёргивание при появлении вкладок нод»): while a scan runs, a row already on
    // the screen keeps its place - a new row joins the end of its group (proven rows, then «Не проверено»), so
    // nothing visible jumps when a faster row arrives or a figure changes. Results arrive roughly fastest-first, so
    // the held order is already close to the speed order. The view's speed order (ScanMachine displayRows) is
    // applied once, after the rings have collapsed, as one short move animation. false = the previous behaviour
    // (every update re-sorted in place), kept for the side-by-side shots of the harness only.
    readonly property bool holdOrderWhileScanning: true
    // «Найти ещё» adds a batch the same way: its rows join the end while it runs (view.more.state "running")
    readonly property bool moreRunning: !!view.more && view.more.state === "running"
    readonly property bool arriving: scanning || moreRunning
    readonly property bool orderHeld: holdOrderWhileScanning && (arriving || settleOrder.running)
    onArrivingChanged: if (!arriving && holdOrderWhileScanning) settleOrder.restart()
    Timer {
        id: settleOrder
        interval: Theme.motion.reduceMotion ? 0 : Theme.motion.slow
        onTriggered: root.syncRows()
    }
    function syncRows() {
        const src = root.scopePending ? [] : (view.rows || [])
        const vmap = src.some(r => r.transport === "awg" && r.version === undefined) ? versionMap() : {}
        let cacheAll = src.length > 0, crowd = false, liveL = "", liveC = ""
        const byId = {}
        const items = []
        for (let i = 0; i < src.length; ++i) {
            const it = toItem(src[i], vmap)
            cacheAll = cacheAll && it.fromCache
            crowd = crowd || it.crowd
            if (it.current && liveL === "") { liveL = it.label; liveC = it.cc }
            byId[it.rid] = it
            items.push(it)
        }
        // rows that left the view go first, so the rest only moves where it has to
        for (let j = rowsModel.count - 1; j >= 0; --j)
            if (byId[rowsModel.get(j).rid] === undefined) rowsModel.remove(j, 1)
        let order = items
        if (orderHeld && rowsModel.count > 0) {
            const shown = {}
            const held = []
            for (let j = 0; j < rowsModel.count; ++j) {
                const rid = rowsModel.get(j).rid
                shown[rid] = true
                held.push(byId[rid])
            }
            for (let i = 0; i < items.length; ++i)
                if (shown[items[i].rid] !== true) held.push(items[i])
            const group = it => (it.unverified && !it.current) ? 1 : 0
            order = held.filter(it => group(it) === 0).concat(held.filter(it => group(it) === 1))
        }
        for (let i = 0; i < order.length; ++i) {
            const it = order[i]
            let at = -1
            for (let j = i; j < rowsModel.count; ++j)
                if (rowsModel.get(j).rid === it.rid) { at = j; break }
            if (at < 0) rowsModel.insert(i, it)
            else {
                if (at !== i) rowsModel.move(at, i, 1)
                rowsModel.set(i, it)
            }
        }
        allCache = cacheAll
        anyCrowd = crowd
        liveLabel = liveL
        liveCc = liveC
    }

    // ── rings collapse (360 ms) into the header mark, and grow back the same way on «Повторить» ──
    // heroFrac 1 = rings + status line shown, 0 = gone; the block and the list under it follow it every frame
    property real heroFrac: 0
    onHeroChanged: {
        heroAnim.to = hero ? 1 : 0
        heroAnim.restart()
    }
    NumberAnimation {
        id: heroAnim
        target: root; property: "heroFrac"
        duration: Theme.motion.reduceMotion ? 0 : Theme.motion.slow
        // in-out: the list under the block starts moving gently (OutCubic moved it 35 px in the first frame)
        easing.type: Easing.InOutCubic
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    TribeEdgeBack { onTriggered: root.goBack() }

    // a TAP outside the open country menu closes it; a swipe outside does nothing (the catcher holds the touch so
    // the list under the menu does not scroll, and only a tap - not a drag - closes the menu)
    MouseArea {
        anchors.fill: parent
        z: 5
        visible: bar.menuOpen
        TapHandler {
            gesturePolicy: TapHandler.DragThreshold
            onTapped: bar.closeMenu()
        }
    }

    // ── header ──
    TribeHeader {
        id: header
        anchors.top: parent.top
        anchors.topMargin: root.safeTop
        anchors.left: parent.left
        anchors.right: parent.right
        title: ScanTexts.title
        showBack: true
        onBackClicked: root.goBack()
        rightItem: SignalRing {
            anchors.verticalCenter: parent.verticalCenter
            compact: true
            visible: opacity > 0
            opacity: root.showMark ? 1 : 0
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
            opacity: chipsRow.agoText !== "" ? 1 : 0
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

    // ── rings + one status line + a thin bar: ONE block under the chips that grows and collapses as a whole, so the
    // list under it moves once, smoothly (owner 18.11 «передёргивание»: the status line used to vanish at once and
    // the list jumped by its height before the rings collapsed)
    Item {
        id: heroBox
        anchors.top: chipsRow.top
        anchors.left: parent.left
        anchors.right: parent.right
        readonly property real full: Theme.scan.hero + status.implicitHeight
        height: full * root.heroFrac
        clip: true
        visible: height > 0
        SignalRing {
            x: (parent.width - width) / 2
            y: (Theme.scan.hero - height) / 2
            ringState: "scanning"
            visible: root.heroFrac > 0
            opacity: root.heroFrac
            scale: 0.07 + 0.93 * root.heroFrac
            transform: Translate { x: (1 - root.heroFrac) * 150; y: -(1 - root.heroFrac) * 150 }
        }
    }

    ColumnLayout {
        id: status
        parent: heroBox
        y: Theme.scan.hero
        x: Theme.space.xl
        width: heroBox.width - 2 * Theme.space.xl
        opacity: root.heroFrac
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

    // ── the list: card, rows, wait line, legend (all inside the scroll) ──
    Item {
        id: listArea
        visible: !root.emptyResult
        // under the chips, or under the rings block while it is taller: one continuous edge, no switch of anchors
        y: chipsRow.y + Math.max(chipsRow.height, heroBox.height)
        height: (root.showBar ? bar.y : root.height) - y
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl

        // a Flickable + Column (the list holds <= 12 rows + 2 «Не проверено»): the card, the caption and the rows
        // scroll together; rows keep their delegates across view updates (ListModel diff) and animate in once
        Flickable {
            id: list
            anchors.fill: parent
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            readonly property real padTop: Theme.space.md   // one value in every phase: no step when the rings go
            readonly property real padBottom: Theme.space.lg
            contentWidth: width
            contentHeight: content.height + padTop + padBottom

            Column {
                id: content
                y: list.padTop
                width: list.width
                spacing: Theme.space.sm

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

                TribeConnectionCard {
                    // what is connected now, one line (owner 18.11, variant B): always on the list, in every phase
                    width: parent.width
                    liveState: root.liveVpn
                    liveProto: (typeof TribeEngine !== "undefined") ? String(TribeEngine.activeProto || "") : ""
                    liveProtoVersion: (typeof TribeEngine !== "undefined" && TribeEngine.currentNode)
                                      ? String(TribeEngine.currentNode.protoVersion || "") : ""
                    serverLabel: root.liveLabel
                                 || ((typeof TribeEngine !== "undefined" && TribeEngine.currentNode) ? (TribeEngine.currentNode.name || "") : "")
                    serverCc: root.liveCc
                              || ((typeof TribeEngine !== "undefined" && TribeEngine.currentNode) ? (TribeEngine.currentNode.countryCode || "") : "")
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
                    visible: rowsModel.count > 0
                    // .sec-label.in-list margin-top 4, none as the list's first child
                    topPadding: Theme.space.xs   // the card is always above it now
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
                // The rows place THEMSELVES (owner 18.11 «передёргивание», harness traces): y = index x pitch, a
                // change of place glides 220 ms, a new row fades in at its own place. Before, the Column positioned
                // them: a new delegate was born at the top of the list and its move transition flew it down over
                // the other rows, and every height change of the card above restarted the move animation of every
                // row, so the rows lagged behind the card and slid over its lines.
                Item {
                    id: rowsBox
                    readonly property real pitch: Theme.scan.rowHeight + content.spacing
                    visible: rowsModel.count > 0
                    width: parent.width
                    height: Math.max(0, rowsModel.count * pitch - content.spacing)
                    // the lines under the rows (wait line, legend, «Найти ещё») slide with the list's growth
                    Behavior on height {
                        enabled: !Theme.motion.reduceMotion
                        NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                    }
                    Repeater {
                        model: rowsModel
                        // the wrapper takes the arrive / move animations, so the row keeps its own opacity (cached 55 %,
                        // failed 50 %)
                        delegate: Item {
                            id: rowWrap
                            required property var model
                            required property int index
                            width: rowsBox.width
                            height: Theme.scan.rowHeight
                            y: index * rowsBox.pitch
                            Behavior on y {
                                enabled: !Theme.motion.reduceMotion
                                NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                            }
                            opacity: Theme.motion.reduceMotion ? 1 : 0
                            Component.onCompleted: if (!Theme.motion.reduceMotion) arrive.start()
                            ParallelAnimation {
                                id: arrive
                                NumberAnimation { target: rowWrap; property: "opacity"; from: 0; to: 1; duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                                NumberAnimation { target: lift; property: "y"; from: 8; to: 0; duration: Theme.motion.normal; easing.type: Easing.OutCubic }
                            }
                            TribeScanRow {
                                id: rowItem
                                anchors.fill: parent
                                transform: Translate { id: lift }
                                label: rowWrap.model.label
                                countryCode: rowWrap.model.cc
                                transport: rowWrap.model.transport
                                version: rowWrap.model.version
                                rowState: rowWrap.model.rstate
                                speed: rowWrap.model.speed
                                bars: rowWrap.model.bars
                                ms: rowWrap.model.ms
                                cached: rowWrap.model.fromCache && root.lastResult
                                dimmed: rowWrap.model.dimmed
                                tappable: rowWrap.model.tappable
                                verifying: rowWrap.model.verifying
                                liveUnverified: rowWrap.model.liveUnverified
                                unverified: rowWrap.model.unverified
                                crowd: rowWrap.model.crowd
                                fallbackFlag: globeTile
                                onTapped: {
                                    if (root.hasScanner) TribeScanner.tapRow(rowWrap.model.rid)
                                }
                            }
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
                        text: root.scope !== "" && root.scope === String(root.barView.scanned_scope || "")
                              ? ScanTexts.moreExhaustedScope.arg(bar.countryName(root.scope)) : ScanTexts.moreExhausted
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
                // a finished scan WITH rows and no live connection (desktop with the VPN off: the line says «VPN не
                // подключён») still sends its results to support - the empty state's link, the view's
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
    }

    // ── empty result: advice, «Понял…», «Повторить», the report link ──
    ColumnLayout {
        id: emptyBlock
        visible: root.emptyResult
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.space.xxl
        anchors.rightMargin: Theme.space.xxl
        y: chipsRow.y + chipsRow.height + (root.height - chipsRow.y - chipsRow.height - implicitHeight) / 2
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
            TribeButton {
                Layout.fillWidth: true
                variant: "primary"
                text: emptyBlock.scoped ? ScanTexts.allCountries
                      : emptyBlock.cell ? ScanTexts.emptyCellOk : ScanTexts.emptyWifiOk
                onClicked: {
                    Haptic.play("light")
                    if (emptyBlock.scoped) {            // back to the whole pool: the scope «Все страны», then a scan
                        if (root.hasScanner) { TribeScanner.chooseCountry(""); TribeScanner.retry() }
                        return
                    }
                    if (root.hasScanner) TribeScanner.gotIt()
                    root.goBack()
                }
            }
            TribeButton {
                Layout.fillWidth: true
                variant: "glass"
                text: bar.retryText
                enabled: bar.retryEnabled
                onClicked: { Haptic.play("light"); if (root.hasScanner) TribeScanner.retry() }
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

    // ── pinned bar ──
    TribeScanBar {
        id: bar
        z: 10
        visible: root.showBar
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        bar: root.barView
        cooldownEndsAtMs: Number(root.view.cooldown_ends_at_ms || 0)
        viewNowMs: Number(root.view.now_ms || 0)
        onStopTapped: {
            if (root.hasScanner) TribeScanner.stop()
            root.goBack()
        }
        onRetryTapped: if (root.hasScanner) TribeScanner.retry()
        onConnectAndScanTapped: if (root.hasScanner) TribeScanner.connectAndScan()
        onCountryChosen: (cc) => { if (root.hasScanner) TribeScanner.chooseCountry(cc) }
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

    // a provider row without a country: the servers page's globe tile
    Component {
        id: globeTile
        Rectangle {
            radius: width / 2
            color: Theme.color.surface3
            border.width: 1
            border.color: Theme.color.border
            TribeStrokeIcon {
                anchors.centerIn: parent
                width: parent.width * 0.5
                height: parent.height * 0.5
                icon: "globe"
                tint: Theme.color.text3
            }
        }
    }
}

import QtQuick

import ".."   // Theme, ScanTexts, ScanSwitches

// AVPN: the one host of the top shade over every Tribe page (PageStart, z 210; plan scanner-client-plan.md §4).
// The queue is the coordinator's (TribeScanner.shade = ShadeQueue.h state {visible, leaving, id, tone, text_key,
// args}, NOTIFY shadeChanged; one queue for the app, hold scan_shade_ms, coalescing, warnings first; a tap goes
// back as TribeScanner.tapShade(); scanner-api-note.md (b)). The host only draws it: text keys map to strings in
// ScanTexts; the key "notice" carries a ready text in args[0] (the engine's notices, PageStart.onNotice).
// A binary without TribeScanner.shade (dev preview, mock scenes) uses a local fallback with the same rules in
// short: one visible, FIFO with warnings first, identical requests coalesced, info / success older than 3 s
// dropped, at most 3 waiting, hold Theme.shade.holdMs (2.5 s), a tap hides at once.
// Only while the `scanner` switch is on: with it off nothing here ever shows (today's toasts stay).
Item {
    id: host

    property real safeTop: 0
    readonly property bool active: ScanSwitches.scanner
    readonly property bool queueDriven: typeof TribeScanner !== "undefined" && TribeScanner.shade !== undefined
    readonly property var q: queueDriven ? (TribeScanner.shade || ({})) : ({})
    readonly property int holdMs: Theme.shade.holdMs
    readonly property int staleMs: 3000
    readonly property int maxPending: 3

    anchors.left: parent ? parent.left : undefined
    anchors.right: parent ? parent.right : undefined
    anchors.top: parent ? parent.top : undefined
    height: shade.height

    function reportsPending() {
        return (typeof TribeSupport !== "undefined" && TribeSupport.reportsPending !== undefined)
               ? TribeSupport.reportsPending : 0
    }
    function textOf(key, args) {
        if (key === "notice")
            return (args && args.length > 0) ? String(args[0]) : ""
        return ScanTexts.shadeText(key, args, host.reportsPending())
    }

    // ── queue mode: draw the coordinator's visible shade ──
    readonly property string qText: queueDriven ? textOf(q.text_key || "", q.args || []) : ""
    readonly property bool qShown: queueDriven && active && q.visible === true && q.leaving !== true && qText !== ""
    onQShownChanged: if (queueDriven) sync()
    onQTextChanged: if (queueDriven) sync()
    function sync() {
        if (qShown) {
            shade.tone = q.tone || "info"
            shade.text = qText
        }
        shade.shown = qShown
    }
    // a key without a text must not hold the queue: let it go (after this change settles)
    onQChanged: {
        if (queueDriven && active && q.visible === true && q.leaving !== true
                && textOf(q.text_key || "", q.args || []) === "") {
            const id = q.id
            Qt.callLater(function () {
                if (TribeScanner.shade && TribeScanner.shade.id === id && TribeScanner.shade.leaving !== true)
                    TribeScanner.tapShade()
            })
        }
    }

    // enqueue from QML (PageStart's engine notices)
    function enqueue(tone, text) {
        if (!active || !text) return
        if (queueDriven) { TribeScanner.showShade(tone, "notice", [text]); return }
        localEnqueue(tone, text)
    }
    function enqueueKey(tone, key, args) {
        if (!active) return
        if (queueDriven) { TribeScanner.showShade(tone, key, args || []); return }
        localEnqueue(tone, textOf(key, args))
    }

    // ── local fallback ──
    property var pending: []          // [{tone, text, at}]
    property bool leaving: false
    function localEnqueue(tone, text) {
        if (!text) return
        const key = tone + "|" + text
        if (shade.shown && !leaving && (shade.tone + "|" + shade.text) === key) return
        for (let i = 0; i < pending.length; ++i)
            if (pending[i].tone + "|" + pending[i].text === key) return
        const next = pending.slice()
        next.push({ tone: tone, text: text, at: Date.now() })
        while (next.length > maxPending) {
            let drop = -1
            for (let j = 0; j < next.length && drop < 0; ++j)
                if (next[j].tone !== "warning") drop = j
            next.splice(drop < 0 ? 0 : drop, 1)
        }
        pending = next
        showNext()
    }
    function showNext() {
        if (shade.shown || leaving) return
        const now = Date.now()
        const list = pending.filter(p => p.tone === "warning" || now - p.at <= staleMs)
        if (list.length === 0) { pending = []; return }
        let pick = list.findIndex(p => p.tone === "warning")
        if (pick < 0) pick = 0
        const p = list[pick]
        list.splice(pick, 1)
        pending = list
        shade.tone = p.tone
        shade.text = p.text
        shade.shown = true
        holdTimer.restart()
    }
    function hideLocal() {
        if (!shade.shown) return
        holdTimer.stop()
        shade.shown = false
        leaving = true
        freeTimer.restart()
    }
    Timer { id: holdTimer; interval: host.holdMs; onTriggered: host.hideLocal() }
    Timer { id: freeTimer; interval: Theme.motion.slow; onTriggered: { host.leaving = false; host.showNext() } }

    TribeShade {
        id: shade
        safeTop: host.safeTop
        onTapped: {
            if (host.queueDriven) TribeScanner.tapShade()
            else host.hideLocal()
        }
    }
}

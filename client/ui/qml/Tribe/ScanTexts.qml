pragma Singleton

import QtQuick

// AVPN: every user-facing string of the Scanner («Сканер») in ONE place (artboard
// design/systems/tribe-backend/lab/vpn-scanner @ 9ac7ccff: vpn-scanner.js + vpn-scanner-kit.js texts).
// Strings are readonly qsTr properties (retranslated by the engine); callers fill numbers with .arg().
// Text keys of ShadeQueue.h / ScanMachine.h map to strings here (shadeText). Numbers keep their units with a
// no-break space, as on the artboard. Plan scanner-client-plan.md §4 «Strings».
QtObject {
    id: t

    // ── screen ──
    readonly property string title: qsTr("Сканер")
    readonly property string netWifi: qsTr("Wi‑Fi")
    readonly property string netCellular: qsTr("Сотовая")
    // the last-check chip in the radar block's top-left corner (owner 18.11, replaces «Проверено …» under the title)
    readonly property string agoNow: qsTr("только что")
    readonly property string agoMin: qsTr("%1 мин назад")
    readonly property string agoHours: qsTr("%1 ч назад")
    readonly property string agoYesterday: qsTr("вчера")
    readonly property string agoDays: qsTr("%1 дн. назад")
    readonly property string agoName: qsTr("Проверено: %1")      // screen reader name of the chip
    // the network chip in the top-right corner: the radio of a mobile network when the engine reports it
    readonly property string netLte: qsTr("LTE")
    readonly property string net5g: qsTr("5G")
    readonly property string net3g: qsTr("3G")
    readonly property string netName: qsTr("Сеть: %1")           // screen reader name of the chip
    readonly property string sectionNow: qsTr("ДОСТУПНЫ СЕЙЧАС")
    readonly property string stageConnecting: qsTr("Подбираем сервер…")
    readonly property string stageReach: qsTr("Проверяем доступность · %1 из %2")
    readonly property string stageReachShort: qsTr("Проверяем доступность")
    readonly property string stageData: qsTr("Проверяем передачу данных · доступно %1 из %2")
    readonly property string waitRows: qsTr("Рабочие ноды появятся здесь")
    readonly property string waitMore: qsTr("Ищем ещё… до %1 с")
    readonly property string legend: qsTr("работает у других в вашей сети — по обезличенным отчётам устройств того же оператора")
    readonly property string crowdName: qsTr("Работает у других в вашей сети")
    readonly property string markName: qsTr("Скан завершён")

    // ── rows ──
    readonly property string rowWorks: qsTr("Доступно")   // owner, device test of 142 (was «Работает»)
    readonly property string rowSlow: qsTr("Медленно")
    readonly property string rowNotVerified: qsTr("Не проверено")
    readonly property string rowConnecting: qsTr("Подключение…")
    readonly property string rowConnected: qsTr("Подключено")
    readonly property string rowFailed: qsTr("Не удалось")
    readonly property string ms: qsTr("%1 мс")
    readonly property string msApprox: qsTr("~%1 мс")

    // ── what is connected now: the one line at the top of the list (variant B, 18.11) ──
    readonly property string cardOff: qsTr("VPN не подключён")

    // ── bottom bar ──
    readonly property string allCountries: qsTr("Все страны")
    readonly property string stop: qsTr("Остановить")
    readonly property string hourLimit: qsTr("Лимит сканов в мобильной сети на этот час")

    // ── empty result ──
    readonly property string emptyCellTitle: qsTr("В мобильной сети сейчас ничего не работает")
    readonly property string emptyCellText: qsTr("Подключитесь к Wi‑Fi — через него VPN обычно работает. Потом откройте Сканер и нажмите «Сканировать».")
    readonly property string emptyCellOk: qsTr("Понял, подключусь к Wi‑Fi")
    readonly property string emptyWifiTitle: qsTr("В этой сети Wi‑Fi сейчас ничего не работает")
    readonly property string emptyWifiText: qsTr("Попробуйте мобильный интернет или другую сеть Wi‑Fi.")
    readonly property string emptyWifiOk: qsTr("Понял")
    readonly property string report: qsTr("Отправить отчёт в поддержку")
    readonly property string reportSending: qsTr("Отправляем отчёт…")

    // ── shades (ShadeQueue text keys) ──
    readonly property string foundOne: qsTr("Найдена 1 доступная нода")
    readonly property string foundFormOne: qsTr("Найдена %1 доступная нода")
    readonly property string foundFormFew: qsTr("Найдено %1 доступные ноды")
    readonly property string foundFormMany: qsTr("Найдено %1 доступных нод")
    readonly property string seatsBusy: qsTr("Сейчас все места заняты — подключаем следующую")
    readonly property string connectFailedNext: qsTr("Не удалось подключиться — подключаем следующую")
    readonly property string connectFailedLater: qsTr("Не удалось подключиться — проверьте снова через минуту")
    readonly property string reportSent: qsTr("Отчёт отправлен в поддержку")
    readonly property string reportQueued: qsTr("Отчёт уйдёт, когда появится связь")

    // ── entry points ──
    readonly property string homeButton: qsTr("Сканер")
    readonly property string serversButton: qsTr("Запустить сканер")

    // ── NEW TEXTS: the artboard's «Новые тексты» (16.11) + every later string - the ONE list the owner reviews.
    // Change wording here only. "NO FRAME" = the state has no artboard frame: the text / layout is the lane's
    // fallback until a design card exists. (index.html of the shots renders this block for the owner.)
    // NEWTEXTS-BEGIN
    readonly property string pauseTitle: qsTr("Пауза между сканами")                     // title, state 21
    readonly property string pauseText: qsTr("Повторный скан — через полминуты после прошлого.") // text, state 21
    readonly property string limitTitle: hourLimit                                      // was a caption, now the title, state 22
    readonly property string engineTitle: qsTr("Не удалось запустить проверку")            // title, state 23
    readonly property string engineText: qsTr("Попробуйте ещё раз через минуту.")          // text, state 23
    readonly property string serviceTitle: qsTr("Служба Tribe VPN не запущена")            // title, state 24 (Mac, Windows)
    readonly property string sectionLast: qsTr("ПРОШЛЫЙ РЕЗУЛЬТАТ")                         // caption over the last result, 20-28
    readonly property string fallbackHint: qsTr("VPN выключен — чтобы проверить ноды, нужно подключиться") // hint over the button, state 20
    readonly property string connectAndScan: qsTr("Подключиться и проверить")              // button, state 20
    readonly property string networkChanged: qsTr("Сеть сменилась — проверяем заново")      // shade, info
    readonly property string queueFull: qsTr("Отчёты ждут связи: %1. Новая проверка — после отправки") // shade, warning
    readonly property string liveChecking: qsTr("проверяем загрузку…")                     // the «Подключено» row before its own check
    readonly property string serviceUpdateTitle: qsTr("Службу Tribe VPN нужно обновить")    // title, state 25 service_old / service_mismatch (16.11)
    // states 24 / 25: the body = the reason's lead + the action's sentence; the button = what the tap really does
    // (TribeEngine.scannerServiceAction(): install | start | update | none | unsupported), 16.11
    readonly property string serviceLeadOff: qsTr("Сканер проверяет ноды через службу приложения, а она сейчас не запущена.") // text, state 24: action none / unsupported / unknown
    readonly property string serviceLeadMissing: qsTr("Сканер проверяет ноды через службу приложения, а она не установлена.") // text, state 24: action install
    readonly property string serviceLeadStopped: qsTr("Сканер проверяет ноды через службу приложения, а она остановлена.") // text, state 24: action start
    readonly property string serviceLeadOutdated: qsTr("Сканер проверяет ноды через службу приложения, а она устарела.") // text, state 24: action update
    readonly property string serviceLeadOld: qsTr("Подключаться к VPN можно как обычно, а Сканеру нужна обновлённая служба.") // text, state 25 (every action)
    readonly property string servicePassword: qsTr("Система спросит пароль администратора.")  // added after the lead: actions install / update only
    readonly property string serviceReinstall: qsTr("Переустановите приложение его установщиком — служба установится вместе с ним.") // added after the lead: state 24, action unsupported (Windows), no button
    readonly property string serviceReinstallUpdate: qsTr("Обновите приложение его установщиком — служба обновится вместе с ним.") // added after the lead: state 25, action unsupported (Windows), no button
    readonly property string serviceInstall: qsTr("Установить службу")                       // button, action install
    readonly property string serviceStart: qsTr("Запустить службу")                         // button, action start
    readonly property string serviceUpdate: qsTr("Обновить службу")                         // button, action update (state 24 or 25)
    readonly property string serviceInstalling: qsTr("Устанавливаем службу…")               // the same button while it runs (disabled, like «Проверяем…» of the card)
    readonly property string serviceStarting: qsTr("Запускаем службу…")                    // the same, action start
    readonly property string serviceUpdating: qsTr("Обновляем службу…")                    // the same, action update
    readonly property string serviceVpnOn: qsTr("Отключите VPN, чтобы обновить службу: при обновлении соединение прервётся") // shade, warning: install / update refused while the VPN is on (16.11)
    readonly property string killSwitchTitle: qsTr("Защита от утечек не дала запустить проверку") // title, state 26 host_kill_switch (16.11), button «Повторить»
    readonly property string serviceFailed: qsTr("Не удалось запустить службу")              // shade, warning: the installer / start failed (detail failed:*); a refused password shows nothing (NO FRAME)
    readonly property string checkBusy: qsTr("Проверка уже идёт")                           // shade, info: report_check_busy (NO FRAME)
    readonly property string checkUnavailable: qsTr("Отчёт сейчас отправить нельзя")       // shade: report_check_unavailable - reports off on the server, or rejected as too large twice (NO FRAME)
    readonly property string checkNotSaved: qsTr("Не удалось сохранить отчёт — освободите место на устройстве") // shade, warning: report_check_not_saved - not written to the device, not confirmed as delivered (NO FRAME)
    readonly property string checkRejected: qsTr("Сервер не принял отчёт. Он сохранён и уйдёт после обновления приложения") // shade, warning: report_check_rejected - refused by the server, kept on the device (NO FRAME)
    readonly property string vpnSwitching: qsTr("VPN сейчас переключается — проверим через несколько секунд") // title, NoScan host_busy / host_tunnel_changed / host_stop_pending / host_teardown_pending, button «Повторить» (NO FRAME)
    readonly property string scannerOffTitle: qsTr("Сканер временно недоступен")               // title, NoScan scanner_off (the server's switch, 404), no button (NO FRAME)
    readonly property string scannerOffText: qsTr("Мы выключили его на время работ. Подключение к VPN работает как обычно.") // text, the same state (NO FRAME)
    readonly property string rejectedWaiting: qsTr("Есть неотправленные отчёты: %1 — отправятся вместе с логами") // chat, the logs confirm sheet: a quiet line while the server-refused reports wait (NO FRAME)
    // owner 18.11 (artboard «Правки 18.11»): «Найти ещё» continues the scan with the next batch (waits for the
    // engine's view.more + TribeScanner.findMore()); the country menu as the scan's scope over the whole pool
    // (waits for bar.scope_countries + empty.scope_cc)
    readonly property string more: qsTr("Найти ещё")                                       // button under the list, a finished scan
    readonly property string moreRunning: qsTr("Ищем ещё…")                                // the same button while the next batch runs
    readonly property string moreInMin: qsTr("Найти ещё через %1 мин")                     // the same button, disabled: the cellular hour's limit (view.more.blocked "budget"; the bar says hourLimit)
    readonly property string moreExhausted: qsTr("Больше доступных нод в этой сети нет")   // replaces the button: nothing left to check
    readonly property string scanScope: qsTr("Сканировать")                               // THE Scan button (owner 19.11: one button, one meaning - scan the chosen scope)
    readonly property string scanInS: qsTr("Сканировать через %1 с")                      // the same button during the 30 s pause between scans
    readonly property string scanInMin: qsTr("Сканировать через %1 мин")                  // the same button while the cellular hour's budget is spent
    // owner 19.11: page open without results / a scope the shown result does not cover - its summary
    readonly property string scopeTitle: qsTr("%1 · %2")                                 // «Германия · 12 серверов» (%1 = country or «Все страны», %2 = servers())
    readonly property string serverOne: qsTr("%1 сервер")
    readonly property string serverFew: qsTr("%1 сервера")
    readonly property string serverMany: qsTr("%1 серверов")
    readonly property string scopeText: qsTr("Нажмите «Сканировать» — проверим, какие из них работают в этой сети.")
    readonly property string startTitle: qsTr("Найдём, через что подключиться")          // no pool counts yet
    readonly property string startText: qsTr("Нажмите «Сканировать» — проверим серверы в этой сети.")
    readonly property string moreExhaustedScope: qsTr("%1: проверены все серверы")        // «Найти ещё» has nothing left in a country scope
    readonly property string emptyScopeTitle: qsTr("%1: доступных нод сейчас нет")         // empty result of a country scan (%1 = the country)
    readonly property string emptyScopeText: qsTr("Попробуйте другую страну или проверьте все страны.") // text, the same state
    // variant B (owner decision 18.11): the check with the report lives in Support - the bar under the chat header
    readonly property string supportCheck: qsTr("Проверить подключение и отправить отчёт") // Support bar, idle
    readonly property string supportCheckSub: qsTr("Отчёт придёт сюда, в чат") // its second line
    readonly property string supportChecking: qsTr("Проверяем подключение…")             // the bar while the stages run
    readonly property string supportSending: qsTr("Отправляем отчёт…")                    // the bar: no connection, the report alone / the last stage
    readonly property string supportCheckingSub: qsTr("До 20 секунд — отчёт сам придёт в чат") // its second line while running
    readonly property string whitelists: qsTr("Белые списки")  // the country menu's white-list scope (rows without a country), «Белые списки · N»
    // ELSEWHERE: «Не удалось сохранить отчёт на устройстве — он не отправлен» - chat toast, TribeSupportChat.cpp (queue lane)
    // NO FRAME, existing texts reused (no new wording; listed so the owner sees every fallback):
    //  - stage «preparing» (manifest requested): stageReachShort without the counts + an indeterminate bar
    //  - NoScan not_entitled / over_quota / manifest_invalid / manifest_unavailable / host_* (generic): state 23
    //    texts (engineTitle + engineText + «Повторить»)
    //  - shade scan_budget: hourLimit
    //  - network chip for ethernet / unknown: no chip
    // NEWTEXTS-END

    // States 24 / 25 by what the button really does (TribeEngine.scannerServiceAction(), read when the state is
    // shown): text, button text, its busy text, and act = ensure (TribeEngine.scannerEnsureService()) | retry
    // (the view's «Повторить») | none (no button). The password sentence only where the system will ask for it.
    // action "" = an engine without scannerServiceAction(): start for service_off, update for service_old.
    function serviceState(reason, action) {
        const old = reason === "service_old" || reason === "service_mismatch"
        const a = action !== "" ? action : (old ? "update" : "start")
        const lead = old ? t.serviceLeadOld
                   : a === "install" ? t.serviceLeadMissing
                   : a === "start" ? t.serviceLeadStopped
                   : a === "update" ? t.serviceLeadOutdated
                   : t.serviceLeadOff
        switch (a) {
        case "install": return { text: lead + " " + t.servicePassword, button: t.serviceInstall, busy: t.serviceInstalling, act: "ensure" }
        case "start": return { text: lead, button: t.serviceStart, busy: t.serviceStarting, act: "ensure" }
        case "update": return { text: lead + " " + t.servicePassword, button: t.serviceUpdate, busy: t.serviceUpdating, act: "ensure" }
        case "unsupported": return { text: lead + " " + (old ? t.serviceReinstallUpdate : t.serviceReinstall), button: "", busy: "", act: "none" }
        }
        return { text: lead, button: "", busy: "", act: "retry" }   // none: installed and running per its files
    }

    // NoScan reasons (ScanView empty.reason, scanner-api-note.md (b) «ONE vocabulary» + TribeScanner.h scanner_off):
    // every reason the coordinator and the machine emit has its own case below; only a string newer than this
    // build reaches the generic fallback at the end.
    // layout "list" = the result list + the bar with the view's own buttons; "blocked" = «Скан сейчас невозможен»:
    // icon, title, text, ONE action, the last result below, no bar. action: retry (the bar's button: «Повторить» /
    // its countdown exactly as the view says) | retryNow («Повторить», always enabled) | gotIt | ensureService
    // (TribeEngine.scannerEnsureService(), see serviceState()).
    function noScan(reason) {
        const engine = { layout: "blocked", icon: "alert-circle", title: t.engineTitle, text: t.engineText,
                         action: "retry", primary: true }
        switch (reason) {
        case "scanner_off":             // NO FRAME: the server switched the Scanner off (404); no button - the page
                                        // closes itself when the engine's scannerEnabled turns false
            return { layout: "blocked", icon: "alert-circle", title: t.scannerOffTitle, text: t.scannerOffText, action: "none", primary: true }
        case "vpn_off":                 // state 20: last result + «Подключиться и проверить» (the bar)
            return { layout: "list" }
        case "cooldown":                // state 21
            return { layout: "blocked", icon: "clock", title: t.pauseTitle, text: t.pauseText, action: "retry", primary: false }
        case "budget":                  // state 22
            return { layout: "blocked", icon: "wifi", title: t.limitTitle, text: t.emptyCellText, action: "gotIt", actionText: t.emptyCellOk, primary: true }
        case "service_off":             // state 24 (desktop)
            return { layout: "blocked", icon: "shield-x", title: t.serviceTitle, action: "ensureService", primary: true }
        case "service_old":             // state 25 (desktop): the installed service is of another version
        case "service_mismatch":
            return { layout: "blocked", icon: "refresh", title: t.serviceUpdateTitle, action: "ensureService", primary: true }
        case "host_kill_switch":        // state 26 (desktop): the kill switch could not be opened for the probes
            return { layout: "blocked", icon: "lock", title: t.killSwitchTitle, text: "", action: "retry", primary: true }
        case "host_busy":               // NO FRAME: the host's "not now" - the tunnel is switching; «Повторить» at once
        case "host_tunnel_changed":
        case "host_stop_pending":
        case "host_teardown_pending":
            return { layout: "blocked", icon: "alert-circle", title: t.vpnSwitching, text: "", action: "retryNow", primary: true }
        case "host_no_vpn":             // the tunnel process does not answer (iOS / Android)
        case "host_rate_limited":       // the service's start rate
        case "host_queue_full":
        case "host_too_large":
        case "host_shutting_down":
        case "host_internal":
        case "host_memory":
        case "host_version":
        case "host_unknown_action":
        case "host_malformed":
        case "host_other":
        case "host_awg_live_peer_unknown":
            return engine               // state 23
        case "not_entitled":            // NO FRAME (server side): state 23 texts
        case "over_quota":
        case "manifest_invalid":
        case "manifest_unavailable":
            return engine
        }
        // a host_<detail> or a reason newer than this build: the generic host failure (state 23)
        return engine
    }

    // ── helpers (read the properties above, so bindings follow a retranslation) ──
    function plural(n, one, few, many) {
        const a = n % 10, b = n % 100
        return a === 1 && b !== 11 ? one : ((a >= 2 && a <= 4 && (b < 12 || b > 14)) ? few : many)
    }
    function servers(n) { return t.plural(n, t.serverOne, t.serverFew, t.serverMany).arg(n) }
    function found(n) {
        return n === 1 ? t.foundOne : t.plural(n, t.foundFormOne, t.foundFormFew, t.foundFormMany).arg(n)
    }
    // radio: the engine's view.net_radio ("5g" | "lte" | "3g" | "2g"; not sent yet) - without it «Сотовая»
    function netCaption(net, radio) {
        if (net === "wifi") return t.netWifi
        if (net !== "cellular") return ""
        return radio === "5g" ? t.net5g : radio === "lte" ? t.netLte : (radio === "3g" || radio === "2g") ? t.net3g
             : t.netCellular
    }
    function netIcon(net) { return net === "wifi" ? "wifi" : (net === "cellular" ? "cellular" : "") }
    // view.checked_ago_min -> «только что» / «5 мин назад» / «3 ч назад» / «вчера» / «4 дн. назад»; "" = unknown.
    // «вчера» is the calendar day before today (nowMs = the caller's clock), not "24-48 h ago".
    function ago(min, nowMs) {
        if (min < 0) return ""
        if (min === 0) return t.agoNow
        if (min < 60) return t.agoMin.arg(min)
        const now = new Date(nowMs)
        const then = new Date(nowMs - min * 60000)
        const day = 86400000
        const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()
        if (then.getTime() >= startToday) return t.agoHours.arg(Math.floor(min / 60))
        if (then.getTime() >= startToday - day) return t.agoYesterday
        return t.agoDays.arg(Math.max(2, Math.round((startToday - then.getTime()) / day) + 1))
    }
    // ScanMachine shade keys + the app's own; "" = no text (the host shows nothing)
    function shadeText(key, args, reportsPending) {
        const a = args || []
        switch (key) {
        case "scan_found": return t.found(Number(a[0] || 0))
        case "connect_failed_next": return t.connectFailedNext
        case "connect_failed_later": return t.connectFailedLater
        case "report_sent": return t.reportSent
        case "report_queued": return t.reportQueued
        case "report_queue_full": return t.queueFull.arg(a.length > 0 ? a[0] : reportsPending)
        case "network_changed": return t.networkChanged
        case "seats_busy_next": return t.seatsBusy
        case "scan_budget": return t.hourLimit
        case "report_check_busy": return t.checkBusy
        case "service_failed": return t.serviceFailed
        case "service_vpn_on": return t.serviceVpnOn
        case "report_check_unavailable": return t.checkUnavailable
        case "report_check_not_saved": return t.checkNotSaved
        case "report_check_rejected": return t.checkRejected
        }
        return ""
    }
}

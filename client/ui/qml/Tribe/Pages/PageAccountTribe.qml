import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import QRCodeReader 1.0  // AVPN: in-app сканер QR переноса (iOS натив; на desktop — no-op заглушка)

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Настройки (таб 3). Профиль (триал/плашка) + подписка + тумблеры подключения.
// Поддержка вынесена в отдельный таб — кнопки поддержки здесь больше нет.
// NO price / payment UI in-app (Apple compliance, UI-DESIGN.md §10); «Управлять подпиской» лишь
// открывает web-кабинет во ВНЕШНЕМ браузере (web-link, одноразовый авто-логин) — цен в апке нет.
PageType {
    id: root

    // мост в полный интерфейс Amnezia (PageStart включает Dev.amneziaMode)
    signal requestAmnezia()
    // AVPN: «Панель администратора» (низ настроек) → PageAdminTribe (бенч соединения, тесты)
    signal requestAdminPanel()
    // AVPN in-app Legal: Privacy/Terms открываются внутри приложения (PageLegalTribe), не в браузере
    signal requestLegalDoc(string doc)
    // AVPN (перенос): после «подписка перенесена» уводим на главную (роутер goAvpnTab в PageStart)
    signal requestTab(int index)
    // AVPN (store-flow): открыть вкладку «Поддержка» с черновиком в composer (кнопка «Написать
    // в поддержку» у карточки активации). Отправляет пользователь сам — только подстановка.
    signal requestSupportChat(string draft)

    // AVPN: модель — анонимный триал-по-device (кодов на бэке пока нет). Реальные данные из движка.
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property real trafficUsedB:  hasEngine ? Number(TribeEngine.trafficUsed)  : 0
    readonly property real trafficLimitB: hasEngine ? Number(TribeEngine.trafficLimit) : 0
    readonly property int  daysLeftN:     hasEngine ? TribeEngine.daysLeft : -1
    readonly property real usedFrac: trafficLimitB > 0 ? Math.min(1, trafficUsedB / trafficLimitB) : 0
    // AVPN (group-aware, 2026-07-21): «истекла» решают device-часы /v1/subscription (бэк учитывает
    // группы: unlimited/bonus_days/bonus_traffic), КАК на Connect (subExpired). account.status —
    // аккаунт-часы, групп не знает → членам групп показывал «Истекла» при живом доступе; за ним
    // остаётся только оттенок Премиум/Пробный. Композит зеркалит PageConnectTribe.subExpired
    // (без transferredAway/whitelist — у них тут свои экраны/состояния).
    readonly property bool subDeadNow: hasEngine
        && ((TribeEngine.subMissing === true)
            || (daysLeftN >= 0 && (!(TribeEngine.subActive === true)
                                   || daysLeftN === 0
                                   || (trafficLimitB > 0 && trafficUsedB >= trafficLimitB))))
    // AVPN: traffic_limit/used = СЫРЫЕ БАЙТЫ, двоичная база (бэк подтвердил по openapi/schemas/models/
    // collector + живым значениям: триал=10·1024³, кап=100·1024³). ГиБ = ÷1024³ → ровно. НЕ ×1e9 и НЕ
    // ×1024⁴. (Откат ошибочного ÷1024⁴ из build 38; 2026-06-23.)
    function fmtGb(b) { return (b / 1073741824).toFixed(1) }
    // AVPN (#37): реферальный баннер перенесён на вкладку «Рефералка» (PageReferralTribe).

    // AVPN (Task 14): активация ключа (redeem) через движок — POST /v1/code/redeem.
    // TribeEngine.redeemCode(code[, evictDeviceId]) синхронный (QEventLoop):
    //   200 → ротация токена + re-fetch подписки → changed(); 401 → error(); 409 → seatLimitReached(devices[]).
    // Успех определяем по флагу: failure-сигналы (error/seatLimitReached) прилетают ВО ВРЕМЯ вызова —
    // если после возврата redeemCode флаг не взведён, значит успех.
    property bool   redeeming: false
    property string redeemHint: ""     // локальный пояснительный текст (text3) под полем
    property bool   redeemError: false
    property bool   redeemFailed: false  // взводится onError/onSeatLimitReached в рамках синхронного вызова
    // AVPN (device_fingerprint): 403 rehome-гейта — показываем кнопку «Написать в поддержку»
    property bool   fingerprintBlocked: false
    property string redeemLastCode: ""   // для повторного redeem с evict_device_id после кика

    // AVPN (store-flow, 2026-07-09): store-сборка (-DTRIBE_STORE_BUILD=ON) — в UI нет прямых
    // платёжных переходов (Google Play Payments / Apple §3.1.1). dev-превью без движка → false.
    readonly property bool storeBuild: root.hasEngine && TribeEngine.storeBuild === true

    // AVPN (оплата): «Управлять подпиской» — минт одноразовой ссылки (TribeEngine.requestCabinetLink,
    // POST /v1/cabinet/web-link) и открытие web-кабинета во ВНЕШНЕМ браузере (НЕ webview — §3.1.1).
    // В store-сборке кнопки НЕТ (compile-time, см. storeBuild) — бейдж-инфо подписки остаётся,
    // путь продления = карточка «Активировать ключ» + чат поддержки (store-flow).
    // Решение владельца 2026-07-11: на iOS/Android кнопки веб-кабинета НЕТ ни в какой сборке
    // (оплата на мобилках — только через чат поддержки, store-flow); десктоп — как раньше.
    readonly property bool mobilePlatform: Qt.platform.os === "ios" || Qt.platform.os === "android"
    readonly property bool manageSubEnabled: !root.storeBuild && !root.mobilePlatform
    property bool cabinetLinking: false   // loading кнопки; сбрасывается в onCabinetLinkReady (приходит всегда)

    // Язык приложения → веб-страницы (ЛК/legal) открываются на нём же (i18n сайта, 2026-07-07).
    // Биндинг живой: смена языка в настройках перечитывает ссылки (NOTIFY appLangChanged). // AVPN
    readonly property string webLang: (root.hasEngine && TribeEngine.appLang)
                                      ? TribeEngine.appLang
                                      : Qt.locale().name.split("_")[0]

    function manageSubscription() {
        if (root.cabinetLinking) return
        if (!(root.hasEngine && typeof TribeEngine.requestCabinetLink === "function")) {
            // dev-превью / стейл-бинарник без движка: кабинет без авто-логина (юзер войдёт сам);
            // домен — TribeEngine.cabinetUrl (server-driven urls.cabinet), литерал ТОЛЬКО
            // в dev-превью без движка. // AVPN backend-first (Task 9)
            Qt.openUrlExternally((root.hasEngine ? TribeEngine.cabinetUrl : "https://tribevpn.com/account")
                                 + "?lang=" + root.webLang)
            return
        }
        root.cabinetLinking = true
        TribeEngine.requestCabinetLink()  // async; ссылка одноразовая (TTL ~90с) — минт строго по тапу
    }

    // ── УНИВЕРСАЛЬНОЕ ПОЛЕ «Активировать ключ» — диспатч по формату ввода (2026-07-03): ────
    //   • ссылка переноса (tribe://transfer?t=… / https://tribevpn.com/transfer?t=…) → мост диплинка
    //     (тот же путь, что скан QR/переход по ссылке) → POST /v1/transfer/redeem;
    //   • grant-ключ TRIBE-XXXX-XXXX-XXXX (3 группы) → POST /v1/key/redeem (промо/подарок/компенсация);
    //   • иначе (access-code, 4+ группы) → POST /v1/code/redeem как раньше.
    function isTransferInput(c) {
        return c.indexOf("tribe://transfer") === 0
               || c.indexOf("tribevpn.com/transfer") >= 0
               || c.indexOf("transfer?t=") >= 0
    }
    function isGrantKey(c) {
        return /^TRIBE-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(c.toUpperCase().replace(/\s+/g, ""))
    }

    function redeemKey(code) {
        var c = (code || "").trim()
        if (c.length === 0) {
            root.redeemError = true
            root.redeemHint = qsTr("Введите код активации")
            return
        }
        if (isTransferInput(c)) {
            // AVPN backend-first-3 (Task 6): kill-switch features.transfer — гасим ДО диплинка
            // (redeemTransfer тоже гейтит, но так не гоняем поле/хинт впустую).
            if (root.hasEngine && TribeEngine.transferEnabled === false) {
                PageController.showErrorMessage(qsTr("Перенос временно недоступен"))
                return
            }
            if (typeof AvpnDeepLink !== "undefined") {
                root.redeemError = false
                redeemField.clear()
                root.redeemHint = qsTr("Переносим доступ на это устройство…")
                AvpnDeepLink.handleUrl(c)   // → transferRequested → TribeEngine.redeemTransfer
            } else {
                root.redeemError = true
                root.redeemHint = qsTr("Движок недоступен — обновите приложение")
            }
            return
        }
        if (!(root.hasEngine && typeof TribeEngine.redeemCode === "function")) {
            // dev-превью / стейл-бинарник без движка — не падаем
            root.redeemError = true
            root.redeemHint = qsTr("Движок недоступен — обновите приложение")
            return
        }
        root.redeemError = false
        root.redeemFailed = false
        root.fingerprintBlocked = false
        root.redeeming = true
        root.redeemHint = qsTr("Проверяем…")
        root.redeemLastCode = c
        if (isGrantKey(c) && typeof TribeEngine.redeemGrantKey === "function")
            doRedeemGrant(c)
        else
            doRedeem(c, "")
    }

    // grant-ключ (промо/подарок/компенсация): токен НЕ ротируется, показываем что начислено.
    function doRedeemGrant(key) {
        root.redeemFailed = false
        root.redeeming = true
        root.redeemHint = qsTr("Проверяем…")
        var res = TribeEngine.redeemGrantKey(key)  // синхронно; провал = emit error → redeemFailed
        root.redeeming = false
        root.redeemHint = ""
        if (root.redeemFailed)
            return
        root.redeemError = false
        redeemField.clear()
        var parts = []
        if (res && Number(res.granted_days) > 0) parts.push(qsTr("+%1 дней").arg(Number(res.granted_days)))
        if (res && Number(res.granted_gib) > 0)  parts.push(qsTr("+%1 ГБ").arg(Number(res.granted_gib)))
        PageController.showNotificationMessage(parts.length > 0
            ? qsTr("Код активирован: %1").arg(parts.join(" · "))
            : qsTr("Код активирован — доступ обновлён"))
    }

    // общий вызов движка (обычный redeem и повтор с evict_device_id после кика устройства).
    function doRedeem(code, evictDeviceId) {
        root.redeemFailed = false
        root.redeeming = true
        root.redeemHint = qsTr("Проверяем…")
        TribeEngine.redeemCode(code, evictDeviceId || "")  // синхронно: failure-сигналы взведут redeemFailed
        root.redeeming = false
        root.redeemHint = ""
        if (!root.redeemFailed) {
            // успех (200): токен ротирован, подписка перечитана движком
            seatSheet.close()
            root.redeemError = false
            redeemField.clear()
            PageController.showNotificationMessage(qsTr("Код активирован — доступ обновлён"))
        }
    }

    // сигналы движка redeem: error (401/прочее) и seatLimitReached (409, мест нет → выбор кого отключить).
    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onError(message) {
            // тост показывает host-обработчик в PageStart — здесь только redeem-флаги
            root.redeemFailed = true
            root.redeeming = false
            root.redeemError = true
            root.redeemHint = ""
        }
        function onSeatLimitReached(devices) {
            root.redeemFailed = true
            root.redeeming = false
            root.redeemHint = ""
            seatSheet.devices = devices
            seatSheet.open()
        }
        // AVPN (device_fingerprint): rehome-гейт 403 — устройство заштамповано другим якорем
        // железа (защита от угона по утёкшему device_id). Терминально: без ретраев, локальный
        // стейт не трогаем (текущая подписка устройства цела); даём мостик в чат поддержки.
        function onFingerprintMismatch() {
            root.redeemFailed = true
            root.redeeming = false
            root.redeemError = true
            root.fingerprintBlocked = true
            root.redeemHint = qsTr("Это устройство привязано к другому аккаунту. Обратитесь в поддержку — мы поможем.")
        }
        // перенос принят НА ЭТО устройство (скан QR / ссылка / ввод в поле): токен ротирован,
        // подписка перечитана движком. Полноэкранный успех показывает PageStart (хост всегда жив,
        // диплинк может прилететь на любой вкладке) — здесь только прибираем локальный UI.
        function onTransferRedeemed() {
            root.redeemHint = ""
            root.redeemError = false
            scanSheet.close()
            settingsLoadTimer.restart()
        }
        // движок перечитал данные (kick / redeem / transfer) → освежаем устройства и аккаунт.
        // НЕ синхронно в обработчике: changed() может прилетать пачкой (connect/state) — дебаунсим
        // через таймер, иначе каждый сигнал = 2 сетевых вызова прямо в слоте (джанк/фриз).
        function onChanged() { settingsLoadTimer.restart() }
        // ссылка web-кабинета готова (успех или fallback — эмитится всегда). Гард по cabinetLinking:
        // сигнал общий на движок — не реагируем на запросы, инициированные другими страницами.
        function onCabinetLinkReady(url) {
            if (!root.cabinetLinking) return
            root.cabinetLinking = false
            Qt.openUrlExternally(url)
        }
    }

    // ── УСТРОЙСТВА + АККАУНТ (TribeEngine.listDevices/kickDevice/accountInfo) ──────────────
    // Ключи из движка — snake_case (GET /v1/devices → device_id/platform/label/last_seen/is_current;
    // GET /v1/account → account_id/status/expires_at/...). Все вызовы под гардом typeof (в превью без
    // движка секции просто пустые). Перечитываем при загрузке страницы и по TribeEngine.changed().
    // Биндинг на async-property движка: refreshDevices()/refreshAccount() запускают фоновый GET,
    // результат прилетает в TribeEngine.devices/account (NOTIFY) → эти биндинги пересчитываются.
    property var    devicesList: root.hasEngine ? TribeEngine.devices : []
    property var    accountData: root.hasEngine ? TribeEngine.account : ({})
    property bool   kicking: false

    // Только ТРИГГЕРЫ — без синхронного ожидания (движок грузит async, без nested loop на GUI).
    function refreshDevices() {
        if (root.hasEngine && typeof TribeEngine.refreshDevices === "function")
            TribeEngine.refreshDevices()
    }
    function refreshAccount() {
        if (root.hasEngine && typeof TribeEngine.refreshAccount === "function")
            TribeEngine.refreshAccount()
    }

    // человекочитаемый статус аккаунта для строки ПРОФИЛЬ. «Истекла» — только по device-часам
    // (subDeadNow); account.status=expired при живой подписке = отставшие аккаунт-часы (группы).
    function accountStatusLabel() {
        if (root.subDeadNow) return qsTr("Истекла")
        var s = root.accountData ? (root.accountData.status || "") : ""
        if (s === "active")  return qsTr("Активна")
        if (s === "trial")   return qsTr("Пробный доступ")
        if (s === "expired") return qsTr("Активна")
        return ""
    }
    // дата истечения (expires_at, ISO) → локальная короткая дата; пусто = бессрочно/неизвестно.
    function fmtDate(iso) {
        if (!iso || iso === "") return ""
        var d = new Date(iso)
        if (isNaN(d.getTime())) return ""
        return d.toLocaleDateString(Qt.locale(), Locale.ShortFormat)
    }
    // человекочитаемое имя платформы (движок шлёт raw «macos/ios/...»). Для строки устройства.
    function prettyPlatform(p) {
        switch (("" + (p || "")).toLowerCase()) {
        case "macos": case "osx": return "macOS"
        case "ios":     return "iOS"
        case "android": return "Android"
        case "windows": return "Windows"
        case "linux":   return "Linux"
        default:        return p ? p : qsTr("Устройство")
        }
    }
    // нативные имя/ОС ТЕКУЩЕГО устройства из движка (маркетинговая модель «MacBook Pro» и т.п.).
    function thisDeviceName() { return (root.hasEngine && TribeEngine.thisDeviceName) ? TribeEngine.thisDeviceName : "" }
    // ОС без версии в скобках: «macOS Tahoe (26.5.1)» → «macOS Tahoe» (короче, влезает в подзаголовок)
    function thisDeviceOs() {
        var s = (root.hasEngine && TribeEngine.thisDeviceOs) ? ("" + TribeEngine.thisDeviceOs) : ""
        return s.replace(/\s*\(.*\)\s*$/, "")
    }
    // отображаемое имя устройства из backend-данных: label, если осмысленный (не пуст и не равен
    // платформе, как часто бывает «macos»), иначе — человекочитаемая платформа.
    function deviceDisplayName(d) {
        var lbl = ("" + (d.label || "")).trim()
        var plat = "" + (d.platform || "")
        var meaningful = lbl !== "" && lbl.toLowerCase() !== plat.toLowerCase()
        return meaningful ? lbl : root.prettyPlatform(plat)
    }
    // AVPN: идентификаторы для поддержки. account_id (номер аккаунта, /v1/account) и device_id
    // ТЕКУЩЕГО устройства (/v1/devices, где is_current). Оба уже у клиента — копируем и шлём в саппорт.
    function accountNumber() { return root.accountData ? ("" + (root.accountData.account_id || "")) : "" }
    // КОРОТКИЙ отображаемый ID (канон 2026-07-21): порядковый числовой account_number с бэка
    // («ID: 83»); старый бэк без поля → фолбэк первые 8 hex. Полный hex — только копия в саппорт.
    function shortAccountId() {
        var n = root.accountData ? Number(root.accountData.account_number || 0) : 0
        if (n > 0) return "" + n
        return root.accountNumber().substring(0, 8)
    }
    // Плашка операторской группы (group-aware волна): есть group.name → бейдж показывает её.
    readonly property var accountGroup: (root.accountData && root.accountData.group
                                         && ("" + (root.accountData.group.name || "")) !== "")
                                        ? root.accountData.group : null
    function currentDeviceId() {
        var l = root.devicesList || []
        for (var i = 0; i < l.length; i++)
            // device_uuid (install-UUID) — публичный ID устройства; device_id (PK) deprecated.
            if (l[i].is_current === true) return "" + (l[i].device_uuid || l[i].device_id || "")
        // Фолбэк: локальный installation-UUID из движка (тот же, что ушёл на backend) — доступен
        // ВСЕГДА, без сети/подписки. Так раздел «Устройства» показывает ID этого устройства всегда.
        if (root.hasEngine && typeof TribeEngine.localDeviceId === "function")
            return "" + TribeEngine.localDeviceId()
        return ""
    }

    // AVPN (краш/freeze-фикс): refreshDevices/refreshAccount делают СИНХРОННЫЙ сетевой вызов.
    // Из Component.onCompleted это блокирует главный поток во время построения страницы
    // (re-entrancy/зависание граба). Деферим через Timer — после показа экрана. Этот же таймер
    // служит дебаунсером для TribeEngine.changed() (restart() коллапсит пачку сигналов в один рефреш).
    // Сами вызовы теперь с таймаутом (NetAwait.h на стороне движка) — UI не зависнет навсегда.
    Component.onCompleted: settingsLoadTimer.start()
    Timer {
        id: settingsLoadTimer; interval: 400; repeat: false
        onTriggered: { root.refreshDevices(); root.refreshAccount() }
    }

    // ── СКАНЕР QR (приём переноса / ключа камерой) ──────────────────────────────────────
    // iOS: in-app оверлей с апстрим-QRCodeReader (нативное превью камеры). Android: нативная
    // CameraActivity апстрима (ImportController.startDecodingQr) — результат вернётся через
    // AVPN-хук в ImportUiController::decodeQrCode → мост диплинка. Desktop: кнопка скрыта.
    readonly property bool scanAvailable: Qt.platform.os === "ios" || Qt.platform.os === "android"

    function openScanner() {
        if (Qt.platform.os === "android") {
            if (typeof ImportController !== "undefined" && typeof ImportController.startDecodingQr === "function")
                ImportController.startDecodingQr()
            return
        }
        scanSheet.open()
    }

    function handleScannedCode(code) {
        var c = ("" + code).trim()
        if (c.length === 0)
            return
        scanSheet.close()
        if (isTransferInput(c)) {
            // AVPN backend-first-3 (Task 6): kill-switch features.transfer — тост вместо действия
            // (симметрично redeemKey; redeemTransfer тоже гейтит как страховка).
            if (root.hasEngine && TribeEngine.transferEnabled === false) {
                PageController.showErrorMessage(qsTr("Перенос временно недоступен"))
                return
            }
            root.redeemHint = qsTr("Переносим доступ на это устройство…")
            if (typeof AvpnDeepLink !== "undefined")
                AvpnDeepLink.handleUrl(c)
        } else {
            redeemField.text = c   // ключ в QR — прогоняем через тот же диспатчер поля
            root.redeemKey(c)
        }
    }

    // ── ПЕРЕНОС НА НОВОЕ УСТРОЙСТВО (createTransfer) ─────────────────────────────────────
    // Выпуск одноразового токена «как SIM» (POST /v1/transfer). Возвращает {transfer_token, deep_link,
    // web_link?, expires_in_s?} (опциональные — бэк по TRANSFER-KEYS-BACKEND-HANDOFF). QR кодирует
    // web_link (откроется и системной камерой), пока бэк не отдаёт — deep_link (in-app сканер понимает).

    // Отправитель: пока QR-модалка открыта, движок поллит /v1/subscription (таймер в transferSheet);
    // бэк ответил 410 → transferredAway взводится → закрываем модалку и показываем полноэкранный
    // результат (не оставляем юзера на «мёртвом» QR). «Понятно» → на главную (там golden CTA).
    readonly property bool transferredAwayNow: root.hasEngine && TribeEngine.transferredAway === true
    onTransferredAwayNowChanged: {
        if (transferredAwayNow && transferSheet.opened) {
            transferSheet.close()
            transferOutResult.show(qsTr("Доступ перенесён"),
                                   qsTr("Новое устройство активировано. Это устройство отключено — чтобы вернуть доступ, активируйте новый код или перенесите доступ обратно."))
        }
    }

    function createTransfer() {
        if (!(root.hasEngine && typeof TribeEngine.createTransfer === "function")) {
            PageController.showErrorMessage(qsTr("Движок недоступен — обновите приложение"))
            return
        }
        var res = TribeEngine.createTransfer()  // синхронно; пустая мапа + emit error при сбое
        if (!res || !res.deep_link || res.deep_link === "") return // onError уже показал тост
        transferSheet.deepLink = res.deep_link
        transferSheet.webLink = res.web_link || ""
        transferSheet.token = res.transfer_token || ""
        transferSheet.secsLeft = Number(res.expires_in_s) > 0 ? Number(res.expires_in_s) : 0
        transferSheet.qrSource = (typeof TribeEngine.makeQrCode === "function")
                                 ? TribeEngine.makeQrCode(transferSheet.shareUrl) : ""
        transferSheet.open()
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // AVPN (#17): весь контент — в прокрутке. Хост страниц (tabBarStackView в PageStart) уже
    // заканчивается на avpnBottomNav.top — высоту навбара отдельно вычитать НЕ нужно. Иначе
    // двойной отступ давал тёмно-синюю полосу снизу (контент не доходил до меню). Теперь контент
    // идёт до низа области, как на остальных вкладках; нижний воздух — через contentHeight (+lg).
    Flickable {
        id: settingsFlick
        anchors.fill: parent
        // Верхний воздух (16) — ВНУТРИ скролла (settingsCol.y), НЕ в рамке: рамочный topMargin
        // при прокрутке обрезал контент на 16px НИЖЕ плашки — «мёртвая» полоса читалась как
        // утолщение плашки против главной (жалоба 2026-07-10). В рамке остаётся только
        // iOS-инсет чёлки. // AVPN
        anchors.topMargin: PageController.safeAreaTopMargin // iOS: натив-инсет
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        contentWidth: width
        contentHeight: settingsCol.y + settingsCol.implicitHeight + Theme.space.lg

        ColumnLayout {
            id: settingsCol
            y: Theme.space.lg   // тот самый верхний воздух — скроллится вместе с контентом
            width: settingsFlick.width
            // AVPN: ColumnLayout как прямой content-item Flickable не подгоняет height под implicitHeight
            // сам (в отличие от позиционера Column). Без этого height=0 → нижние секции схлопываются и
            // под карточкой подписки остаётся большая пустая тёмная полоса. Биндим к implicitHeight.
            height: implicitHeight
            spacing: Theme.space.md

        // AVPN: заголовок «Настройки» убран (нижняя навигация уже подписана). Admin-кнопки
        // (мост в Amnezia + тумблер Dev.adminMode) скрыты — контент начинается сразу с баннера.


        // ── ПОДПИСКА ─────────────────────────────────────────────────────────
        // Единый блок: статус/срок/трафик/устройства. Отдельного «Профиля» нет — устройство
        // и так видно в списке УСТРОЙСТВА ниже; всё остальное сведено сюда (без дублирования).
        // Справа в строке заголовка — переключатель языка (сегмент-пилюля RU/EN/ES): ручной
        // выбор поверх авто-детекта по языку системы (дефолт SecureAppSettingsRepository =
        // QLocale::system()). Коды-эндонимы, НЕ переводятся (без qsTr). Заменил список «ЯЗЫК» внизу.
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.sm
            spacing: Theme.space.md

            Text {
                text: qsTr("СТАТУС ДОСТУПА")
                color: Theme.color.text3
                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            }
            Item { Layout.fillWidth: true }

            Rectangle {
                Layout.preferredWidth: langRow.implicitWidth + 2 * Theme.space.xs
                Layout.preferredHeight: 32
                radius: Theme.radius.pill
                color: Theme.color.glass
                border.width: 1
                border.color: Theme.color.border

                Row {
                    id: langRow
                    anchors.centerIn: parent
                    spacing: 2
                    Repeater {
                        model: ["ru", "en", "es"]
                        delegate: Rectangle {
                            id: langSeg
                            required property var modelData
                            readonly property bool active: root.hasEngine && TribeEngine.appLang === modelData
                            width: 34; height: 24
                            radius: Theme.radius.pill
                            color: active ? Theme.color.surface2 : "transparent"
                            Behavior on color { ColorAnimation { duration: Theme.motion.fast } }

                            Text {
                                anchors.centerIn: parent
                                text: langSeg.modelData.toUpperCase()
                                color: langSeg.active ? Theme.color.accent : Theme.color.text3
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.caption
                                font.weight: Theme.font.wSemibold
                                Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                            }
                            MouseArea {
                                anchors.fill: parent
                                onClicked: if (root.hasEngine) TribeEngine.setAppLang(langSeg.modelData)
                            }
                        }
                    }
                }
            }
        }

        // перенос «как SIM» завершён С ЭТОГО устройства (бэк ответил 410 transferred):
        // подписка уехала целиком — объясняем и показываем путь назад (новый ключ/перенос обратно).
        TribeCard {
            visible: root.hasEngine && TribeEngine.transferredAway === true
            Layout.fillWidth: true
            implicitHeight: transferredCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: transferredCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.xs
                Text {
                    text: qsTr("Доступ перенесён на другое устройство")
                    color: Theme.color.warning
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                Text {
                    text: qsTr("Это устройство отключено. Чтобы вернуть доступ — активируйте код или перенесите доступ обратно.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
            }
        }

        TribeCard {
            Layout.fillWidth: true
            implicitHeight: planCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: planCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                // заголовок = КОРОТКИЙ ID аккаунта (порядковый account_number с бэка, «ID: 83»;
                // фолбэк для старого бэка — первые 8 hex; полный hex копируется в саппорт-блоке
                // ниже); название подписки живёт в бейдже: группа / Премиум / Пробный / Истекла
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: root.shortAccountId() !== "" ? qsTr("ID: %1").arg(root.shortAccountId()) : "Tribe VPN"
                        color: Theme.color.text1
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                        elide: Text.ElideMiddle
                    }
                    // Приоритет бейджа: живая операторская группа (плашка с её именем) →
                    // «Истекла» по device-часам (subDeadNow, group-aware) → оттенок из
                    // account.status (active=Премиум, иначе Пробный).
                    TribeBadge {
                        variant: (root.accountGroup && !root.subDeadNow) ? "on"
                               : root.subDeadNow ? "off"
                               : (root.accountData && root.accountData.status === "active") ? "on" : "warn"
                        text: (root.accountGroup && !root.subDeadNow) ? ("" + root.accountGroup.name)
                            : root.subDeadNow ? qsTr("Истекла")
                            : (root.accountData && root.accountData.status === "active") ? qsTr("Премиум")
                            : qsTr("Пробный")
                    }
                }

                // срок действия: остаток дней + дата окончания (бывшая отдельная строка статуса).
                // Дни И дата — из ОДНОГО источника (device-часы /v1/subscription, group-aware);
                // раньше дата бралась из account.expires_at → оксюморон «361 дн. · до <прошлое>».
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Действует"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text {
                        text: {
                            var parts = []
                            if (root.daysLeftN >= 0) parts.push(qsTr("%1 дн.").arg(root.daysLeftN))
                            var d = root.fmtDate(root.hasEngine ? TribeEngine.subExpiresAt : "")
                            if (d !== "") parts.push(qsTr("до ") + d)
                            return parts.length ? parts.join(" · ") : qsTr("Активен")
                        }
                        color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                    }
                }

                // трафик: ОСТАТОК (не «израсходовано/лимит») — юзеру важно «сколько ещё можно»;
                // единицы адаптивные как в пилюле Главной (≥1024 ГиБ → ТБ), двоичная база
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Осталось трафика"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text {
                        text: {
                            if (!(root.trafficLimitB > 0)) return qsTr("Безлимит")
                            var gib = Math.max(0, root.trafficLimitB - root.trafficUsedB) / 1073741824
                            if (isNaN(gib)) return qsTr("Безлимит")
                            if (gib >= 1024) return (gib / 1024).toFixed(1).replace(/\.0$/, "") + qsTr(" ТБ")
                            return gib.toFixed(1).replace(/\.0$/, "") + qsTr(" ГБ")
                        }
                        color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                    }
                }
                // полоса — тоже остаток (полная = весь трафик на месте), в тон тексту выше
                Rectangle {
                    Layout.fillWidth: true; height: 6; radius: 3; color: Theme.color.surface3
                    visible: root.trafficLimitB > 0
                    Rectangle { width: parent.width * (1 - root.usedFrac); height: parent.height; radius: 3; color: Theme.color.accent }
                }

                // AVPN (оплата): открыть web-кабинет (продление/тарифы — ТОЛЬКО на сайте). Без цен
                // и слов про оплату в UI. loading до cabinetLinkReady — сигнал приходит всегда.
                TribeButton {
                    visible: root.manageSubEnabled
                    variant: "glass"
                    text: qsTr("Управлять подпиской")
                    loading: root.cabinetLinking
                    enabled: !root.cabinetLinking
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xs
                    onClicked: root.manageSubscription()
                }
            }
        }

        // активировать ключ (redeem) — часть раздела ПОДПИСКА. Поле сверху, accent-кнопка во всю
        // ширину снизу; кнопка активна только когда введён ключ. Движок: TribeEngine.redeemCode (POST /v1/code/redeem).
        TribeCard {
            Layout.fillWidth: true
            implicitHeight: redeemCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: redeemCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Активировать код")
                    color: Theme.color.text1
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                    Layout.fillWidth: true
                }
                Text {
                    text: qsTr("Если у вас есть код активации — введите его ниже, доступ продлится сразу.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }

                TribeField {
                    id: redeemField
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xs
                    enabled: !root.redeeming
                    horizontalAlignment: TextInput.AlignHCenter // код по центру, как OTP-поле (и подсказка тоже)
                    placeholderText: qsTr("Введите код активации")
                    error: root.redeemError
                    onTextChanged: { root.redeemError = false; root.redeemHint = ""; root.fingerprintBlocked = false }
                    onAccepted: root.redeemKey(text)
                }

                // одна строка: слева квадратная иконка-кнопка скана QR (только моб. платформы —
                // root.scanAvailable, на desktop камеры-бэкенда нет), справа accent-кнопка
                // «Активировать» на всю оставшуюся ширину (активна только при непустом поле).
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.sm

                    TribeButton {
                        visible: root.scanAvailable
                        variant: "icon"
                        Layout.preferredWidth: 46
                        Layout.preferredHeight: 46
                        onClicked: root.openScanner()

                        // иконка «скан QR» (lucide scan-line, 24-грид), вектор через Shape
                        Shape {
                            anchors.centerIn: parent
                            width: 24; height: 24
                            scale: 20 / 24
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 1.8
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                PathSvg { path: "M3 7 V5 A2 2 0 0 1 5 3 H7 M17 3 H19 A2 2 0 0 1 21 5 V7 M21 17 V19 A2 2 0 0 1 19 21 H17 M7 21 H5 A2 2 0 0 1 3 19 V17 M7 12 H17" }
                            }
                        }
                    }

                    TribeButton {
                        variant: "primary"
                        text: qsTr("Активировать")
                        loading: root.redeeming
                        enabled: !root.redeeming && redeemField.text.trim().length > 0
                        Layout.fillWidth: true
                        onClicked: root.redeemKey(redeemField.text)
                    }
                }

                // нет кода → чат поддержки с заготовленным вопросом в composer (отправляет
                // пользователь САМ — приложение диалог не инициирует). Во ВСЕХ сборках
                // (2026-07-09; раньше только store — это просто мостик в чат, платёжных ссылок нет).
                Text {
                    text: qsTr("Нет кода? Напишите нам — поможем.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                    Layout.topMargin: Theme.space.xs
                }
                TribeButton {
                    variant: "glass"
                    text: qsTr("Написать в поддержку")
                    Layout.fillWidth: true
                    onClicked: root.requestSupportChat(qsTr("Здравствуйте! Как мне активировать код?"))
                }

                // пояснительный текст (text3): «Проверяем…» / ошибка валидации непустоты
                Text {
                    visible: root.redeemHint !== ""
                    text: root.redeemHint
                    color: root.redeemError ? Theme.color.danger : Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }

                // AVPN (device_fingerprint): rehome-гейт 403 — прямой мостик в чат поддержки
                // (черновик подставляем, отправляет пользователь САМ). Не гейтим storeBuild:
                // мисматч — ситуация «сам не решишь», поддержка нужна в любой сборке.
                TribeButton {
                    visible: root.fingerprintBlocked
                    variant: "glass"
                    text: qsTr("Написать в поддержку")
                    Layout.fillWidth: true
                    onClicked: root.requestSupportChat(qsTr("Здравствуйте! При активации пишет «устройство привязано к другому аккаунту». Помогите, пожалуйста, разобраться."))
                }
            }
        }

        // перенос подписки «как SIM» — тоже часть ПОДПИСКИ. Вторичная (glass) кнопка во всю ширину.
        // AVPN backend-first-3 (Task 6): kill-switch features.transfer (default TRUE — без сервера/
        // на старом конфиге карточка видима, как раньше). Dev-превью без движка (!hasEngine) — видима.
        TribeCard {
            visible: !(root.hasEngine && TribeEngine.transferEnabled === false)
            Layout.fillWidth: true
            implicitHeight: transferCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: transferCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Перенос на новое устройство")
                    color: Theme.color.text1
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                Text {
                    text: qsTr("Создайте одноразовую ссылку и откройте её на другом устройстве. Текущее устройство отключится автоматически.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                // Единственный способ самостоятельной миграции: аккаунты анонимны (без email/Telegram),
                // без переноса восстановление доступа — только вручную через поддержку. // AVPN
                Text {
                    text: qsTr("Перенос — единственный способ забрать доступ с собой. Потеряете устройство без переноса — восстановление только через поддержку.")
                    color: Theme.color.text2
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                TribeButton {
                    variant: "glass"
                    text: qsTr("Перенести на новое устройство")
                    Layout.fillWidth: true
                    onClicked: root.createTransfer()
                }
            }
        }

        // ── УСТРОЙСТВА ───────────────────────────────────────────────────────
        Text {
            text: qsTr("УСТРОЙСТВА")
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        // пусто (нет движка / нет токена / нет устройств) — мягкая подсказка вместо пустоты
        TribeCard {
            Layout.fillWidth: true
            visible: !root.devicesList || root.devicesList.length === 0
            implicitHeight: 56
            Text {
                anchors.fill: parent
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                verticalAlignment: Text.AlignVCenter
                text: qsTr("Список устройств появится после активации кода")
                color: Theme.color.text3
                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                wrapMode: Text.WordWrap
            }
        }

        // строка на каждое устройство аккаунта. Текущее помечено, кнопка кика справа.
        Repeater {
            model: root.devicesList
            delegate: TribeListRow {
                required property var modelData
                Layout.fillWidth: true
                interactive: false
                // заголовок: текущее устройство — нативная маркетинговая модель из движка
                // («MacBook Pro», «iPhone 15 Pro»); остальные — осмысленный backend-label или
                // человекочитаемая платформа. Метку «это устройство» в заголовок НЕ клеим (обрезается).
                title: (modelData.is_current && root.thisDeviceName() !== "")
                       ? root.thisDeviceName()
                       : root.deviceDisplayName(modelData)
                subtitle: {
                    var parts = []
                    if (modelData.is_current) {
                        var os = root.thisDeviceOs()
                        if (os !== "") parts.push(os)               // «macOS Sequoia (15.5)»
                        parts.push(qsTr("это устройство"))
                    } else {
                        var lbl = ("" + (modelData.label || "")).trim()
                        var plat = "" + (modelData.platform || "")
                        if (lbl !== "" && lbl.toLowerCase() !== plat.toLowerCase())
                            parts.push(root.prettyPlatform(plat))
                        var seen = root.fmtDate(modelData.last_seen)
                        if (seen !== "") parts.push(qsTr("активность ") + seen)
                    }
                    return parts.join(" · ")
                }
                // левая иконка device (Tabler, inline-вектор)
                leftItem: Shape {
                    width: 22; height: 22
                    anchors.verticalCenter: parent.verticalCenter
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: modelData.is_current ? Theme.color.accent : Theme.color.text2
                        fillColor: "transparent"; strokeWidth: 1.8
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M7 4 h10 a1 1 0 0 1 1 1 v14 a1 1 0 0 1-1 1 h-10 a1 1 0 0 1-1-1 v-14 a1 1 0 0 1 1-1z" }
                        PathSvg { path: "M11 18 h2" }
                    }
                }
                // кнопка кика только для ЧУЖИХ устройств. Своё не выкидываем кнопкой — перенос
                // подписки сам отключит это устройство (см. карточку «Перенести подписку»).
                rightItem: TribeButton {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: modelData.is_current !== true
                    // скрытая кнопка НЕ должна резервировать ширину (TribeListRow считает правый слот
                    // по childrenRect — invisible иначе крадёт ~120px и обрезает имя устройства).
                    width: visible ? implicitWidth : 0
                    variant: "ghost"
                    text: qsTr("Отключить")
                    enabled: !root.kicking
                    onClicked: {
                        kickConfirm.deviceId = modelData.device_uuid || modelData.device_id || ""
                        kickConfirm.deviceLabel = modelData.label || modelData.platform || qsTr("устройство")
                        kickConfirm.isSelf = modelData.is_current === true
                        kickConfirm.open()
                    }
                }
            }
        }

        // ── ДЛЯ ПОДДЕРЖКИ: копируемые идентификаторы ────────────────────────
        // Номер аккаунта (account_id) + ID этого устройства (device_id текущего) — чтобы скопировать
        // и отправить в поддержку. Копирование — паттерн форка: read-only TextEdit + selectAll()/copy()
        // (без зависимостей, как в блоке переноса подписки). // AVPN
        TribeCard {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.sm
            visible: root.accountNumber() !== "" || root.currentDeviceId() !== ""
            implicitHeight: supportIdsCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: supportIdsCol
                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                anchors.topMargin: Theme.space.lg
                spacing: Theme.space.md

                // Номер аккаунта
                RowLayout {
                    Layout.fillWidth: true
                    visible: root.accountNumber() !== ""
                    spacing: Theme.space.sm
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 1
                        Text {
                            text: qsTr("ID вашего аккаунта")
                            color: Theme.color.text3
                            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                        }
                        TextEdit {
                            id: acctIdEdit
                            Layout.fillWidth: true
                            text: root.accountNumber()
                            readOnly: true; selectByMouse: true
                            color: Theme.color.text1; selectionColor: Theme.color.accent
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS
                            wrapMode: TextEdit.WrapAnywhere
                        }
                    }
                    Rectangle {
                        Layout.alignment: Qt.AlignVCenter
                        width: 36; height: 36; radius: Theme.radius.md
                        color: acctCopyMa.pressed ? Theme.color.surface3 : Theme.color.surface2
                        border.width: 1; border.color: Theme.color.border
                        // Tabler copy в сетке 24 (bbox 4..20, центр 12) → шейп 24×24 + масштаб
                        // вокруг центра: прежний 18-бокс с 24-путём смещал иконку вправо-вниз. // AVPN
                        Shape {
                            anchors.centerIn: parent; width: 24; height: 24
                            scale: 18 / 24; transformOrigin: Item.Center
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 2
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                PathSvg { path: "M8 8 m2 0 h8 a2 2 0 0 1 2 2 v8 a2 2 0 0 1 -2 2 h-8 a2 2 0 0 1 -2 -2 v-8 a2 2 0 0 1 2 -2 M16 8 V6 a2 2 0 0 0 -2 -2 H6 a2 2 0 0 0 -2 2 v8 a2 2 0 0 0 2 2 h2" }
                            }
                        }
                        MouseArea {
                            id: acctCopyMa
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                acctIdEdit.selectAll(); acctIdEdit.copy(); acctIdEdit.deselect()
                                PageController.showNotificationMessage(qsTr("ID аккаунта скопирован"))
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true; height: 1; color: Theme.color.border
                    visible: root.accountNumber() !== "" && root.currentDeviceId() !== ""
                }

                // ID этого устройства
                RowLayout {
                    Layout.fillWidth: true
                    visible: root.currentDeviceId() !== ""
                    spacing: Theme.space.sm
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 1
                        Text {
                            text: qsTr("ID этого устройства")
                            color: Theme.color.text3
                            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                        }
                        TextEdit {
                            id: devIdEdit
                            Layout.fillWidth: true
                            text: root.currentDeviceId()
                            readOnly: true; selectByMouse: true
                            color: Theme.color.text1; selectionColor: Theme.color.accent
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS
                            wrapMode: TextEdit.WrapAnywhere
                        }
                    }
                    Rectangle {
                        Layout.alignment: Qt.AlignVCenter
                        width: 36; height: 36; radius: Theme.radius.md
                        color: devCopyMa.pressed ? Theme.color.surface3 : Theme.color.surface2
                        border.width: 1; border.color: Theme.color.border
                        // Tabler copy в сетке 24 (bbox 4..20, центр 12) → шейп 24×24 + масштаб
                        // вокруг центра: прежний 18-бокс с 24-путём смещал иконку вправо-вниз. // AVPN
                        Shape {
                            anchors.centerIn: parent; width: 24; height: 24
                            scale: 18 / 24; transformOrigin: Item.Center
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 2
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                PathSvg { path: "M8 8 m2 0 h8 a2 2 0 0 1 2 2 v8 a2 2 0 0 1 -2 2 h-8 a2 2 0 0 1 -2 -2 v-8 a2 2 0 0 1 2 -2 M16 8 V6 a2 2 0 0 0 -2 -2 H6 a2 2 0 0 0 -2 2 v8 a2 2 0 0 0 2 2 h2" }
                            }
                        }
                        MouseArea {
                            id: devCopyMa
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                devIdEdit.selectAll(); devIdEdit.copy(); devIdEdit.deselect()
                                PageController.showNotificationMessage(qsTr("ID устройства скопирован"))
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true; height: 1; color: Theme.color.border
                }

                // Восстановление при потере устройства: identity-каналов нет (аноним),
                // единственный путь — ручной перенос оператором по данным платежа. // AVPN
                Text {
                    text: qsTr("Потеряли устройство? Напишите в поддержку с нового устройства и укажите платёж — сумму, дату и способ оплаты. Мы вручную перенесём доступ.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
            }
        }

        // ── ПРАВОВАЯ ИНФОРМАЦИЯ ─────────────────────────────────────────────
        // Видимые ссылки на политику/условия обязательны для VPN (App Review 5.4).
        Text {
            text: qsTr("ПРАВОВАЯ ИНФОРМАЦИЯ")
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }
        Repeater {
            // AVPN in-app Legal: внутренняя страница (кэш+fallback, не зависит от доступности сайта)
            model: [
                { label: qsTr("Политика конфиденциальности"), doc: "privacy" },
                { label: qsTr("Условия использования"),       doc: "terms" }
            ]
            delegate: TribeListRow {
                required property var modelData
                Layout.fillWidth: true
                title: modelData.label
                rightItem: Shape { // шеврон ›
                    width: 16; height: 16
                    anchors.verticalCenter: parent.verticalCenter
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.8
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M6 3 l6 5 -6 5" }
                    }
                }
                onClicked: root.requestLegalDoc(modelData.doc)
            }
        }

        // ── ПАНЕЛЬ АДМИНИСТРАТОРА (низ настроек) ────────────────────────────
        // Бенч соединения и тест-инструменты (PageAdminTribe). Видна только устройствам
        // с серверным is_admin (devices.is_admin → GET /v1/account → TribeEngine.isAdminDevice);
        // Dev.adminPanelVisible — локальный override для превью с диска без движка. // AVPN
        TribeCard {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.sm
            visible: (root.hasEngine && TribeEngine.isAdminDevice === true) || Dev.adminPanelVisible
            implicitHeight: adminRow.implicitHeight + 2 * Theme.space.lg
            RowLayout {
                id: adminRow
                anchors.left: parent.left; anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.md
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 1
                    Text {
                        text: qsTr("Панель администратора")
                        color: Theme.color.text1
                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    }
                    Text {
                        text: qsTr("Бенчмарк соединения и тесты")
                        color: Theme.color.text3
                        font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    }
                }
                Shape { // шеврон ›
                    width: 16; height: 16
                    Layout.alignment: Qt.AlignVCenter
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.8
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M6 3 l6 5 -6 5" }
                    }
                }
            }
            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: root.requestAdminPanel()
            }
        }

        }   // ColumnLayout settingsCol
    }       // Flickable settingsFlick

    // ── ВЫБОР УСТРОЙСТВА (409 seat-limit) ────────────────────────────────
    // Модалка: список устройств аккаунта. На каждом — «Отключить и активировать»:
    //   kickDevice(id) → повторный redeem с evict_device_id (doRedeem(lastCode, id)).
    Item {
        id: seatSheet
        anchors.fill: parent
        visible: opened
        z: 100
        property bool opened: false
        property var devices: []
        property bool busy: false
        // участие в back-логике (паттерн DrawerType2): Back/Escape закрывает модалку, не страницу
        property int depthIndex: 0
        function open()  { opened = true; depthIndex = PageController.incrementDrawerDepth() }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            opened = false; busy = false; depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }

        // свайп слева направо = закрыть (единый жест «назад», 2026-07-11)
        TribeEdgeBack { onTriggered: seatSheet.close() }

        Connections {
            target: PageController
            enabled: seatSheet.opened
            function onCloseTopDrawer() {
                if (seatSheet.depthIndex === PageController.getDrawerDepth() && !seatSheet.busy)
                    seatSheet.close(true)
            }
        }
        // смена вкладки (replace) с открытой модалкой → деструкция без close(): компенсируем depth
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        // затемнение фона + перехват кликов
        Rectangle {
            anchors.fill: parent
            color: "#CC000000"
            MouseArea { anchors.fill: parent; onClicked: { if (!seatSheet.busy) seatSheet.close() } }
        }

        // карточка снизу
        TribeCard {
            id: seatPanel
            elevated: true
            width: parent.width - 2 * Theme.space.xl
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
            implicitHeight: seatCol.implicitHeight + 2 * Theme.space.lg
            MouseArea { anchors.fill: parent } // не закрывать при клике по карточке

            ColumnLayout {
                id: seatCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Достигнут лимит устройств")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                Text {
                    text: qsTr("Выберите устройство, которое нужно отключить, чтобы активировать код здесь.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }

                Repeater {
                    model: seatSheet.devices
                    delegate: RowLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: Theme.space.md

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2
                            Text {
                                text: {
                                    var lbl = modelData.label || modelData.platform || qsTr("Устройство")
                                    return modelData.isCurrent ? (lbl + qsTr(" (это устройство)")) : lbl
                                }
                                color: Theme.color.text1
                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                                font.weight: Theme.font.wMedium
                                Layout.fillWidth: true; elide: Text.ElideRight
                            }
                            Text {
                                visible: text !== ""
                                text: modelData.platform || ""
                                color: Theme.color.text3
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                Layout.fillWidth: true; elide: Text.ElideRight
                            }
                        }
                        TribeButton {
                            variant: "primary"
                            text: qsTr("Отключить и активировать")
                            loading: seatSheet.busy
                            enabled: !seatSheet.busy
                            onClicked: {
                                var id = modelData.deviceId
                                if (!id) return
                                seatSheet.busy = true
                                var killed = TribeEngine.kickDevice(id)  // синхронно (DELETE /v1/devices/{id})
                                if (!killed) { seatSheet.busy = false; return } // onError уже показал тост
                                root.doRedeem(root.redeemLastCode, id)  // повтор redeem c evict_device_id
                                seatSheet.busy = false
                            }
                        }
                    }
                }

                TribeButton {
                    variant: "ghost"
                    text: qsTr("Отмена")
                    enabled: !seatSheet.busy
                    Layout.alignment: Qt.AlignRight
                    onClicked: seatSheet.close()
                }
            }
        }
    }

    // ── ПОДТВЕРЖДЕНИЕ КИКА УСТРОЙСТВА ────────────────────────────────────
    // Свое устройство = выход (предупреждаем), чужое = отключение. TribeEngine.kickDevice(id) синхронно.
    Item {
        id: kickConfirm
        anchors.fill: parent
        visible: opened
        z: 100
        property bool   opened: false
        property string deviceId: ""
        property string deviceLabel: ""
        property bool   isSelf: false
        // участие в back-логике (паттерн DrawerType2, фикс ревью 2026-07-07): раньше Back при
        // открытом диалоге уходил в escapePressed → closePage → hideWindow (сворачивал приложение)
        property int depthIndex: 0
        function open()  { opened = true; depthIndex = PageController.incrementDrawerDepth() }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            opened = false; depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }

        // свайп слева направо = закрыть (единый жест «назад», 2026-07-11)
        TribeEdgeBack { onTriggered: kickConfirm.close() }

        Connections {
            target: PageController
            enabled: kickConfirm.opened
            function onCloseTopDrawer() {
                if (kickConfirm.depthIndex === PageController.getDrawerDepth() && !root.kicking)
                    kickConfirm.close(true)
            }
        }
        // смена вкладки (replace) с открытым диалогом → деструкция без close(): компенсируем depth
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        Rectangle {
            anchors.fill: parent
            color: "#CC000000"
            MouseArea { anchors.fill: parent; onClicked: { if (!root.kicking) kickConfirm.close() } }
        }

        TribeCard {
            elevated: true
            width: parent.width - 2 * Theme.space.xl
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
            implicitHeight: kickCol.implicitHeight + 2 * Theme.space.lg
            MouseArea { anchors.fill: parent }

            ColumnLayout {
                id: kickCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: kickConfirm.isSelf ? qsTr("Выйти на этом устройстве?")
                                             : qsTr("Отключить устройство?")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                Text {
                    text: kickConfirm.isSelf
                          ? qsTr("Доступ на этом устройстве будет отозван. Чтобы вернуться, активируйте код заново.")
                          : qsTr("«%1» потеряет доступ к VPN. Это действие нельзя отменить.").arg(kickConfirm.deviceLabel)
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.md
                    Item { Layout.fillWidth: true }
                    TribeButton {
                        variant: "ghost"
                        text: qsTr("Отмена")
                        enabled: !root.kicking
                        onClicked: kickConfirm.close()
                    }
                    TribeButton {
                        variant: "primary"
                        text: kickConfirm.isSelf ? qsTr("Выйти") : qsTr("Отключить")
                        loading: root.kicking
                        enabled: !root.kicking
                        onClicked: {
                            var id = kickConfirm.deviceId
                            if (!id) { kickConfirm.close(); return }
                            if (!(root.hasEngine && typeof TribeEngine.kickDevice === "function")) {
                                PageController.showErrorMessage(qsTr("Движок недоступен — обновите приложение"))
                                kickConfirm.close(); return
                            }
                            root.kicking = true
                            var ok = TribeEngine.kickDevice(id)  // синхронно (DELETE /v1/devices/{id})
                            root.kicking = false
                            kickConfirm.close()
                            if (ok) {
                                root.refreshDevices()  // changed() тоже перечитает, но обновим сразу
                                PageController.showNotificationMessage(qsTr("Устройство отключено"))
                            } // иначе onError уже показал тост
                        }
                    }
                }
            }
        }
    }

    // ── ПЕРЕНОС: QR + ССЫЛКА ─────────────────────────────────────────────
    // Показ реального QR (TribeEngine.makeQrCode — сырая ссылка, читается системной камерой и нашим
    // in-app сканером) + инструкция + копирование/share + таймер TTL (когда бэк отдаёт expires_in_s).
    Item {
        id: transferSheet
        anchors.fill: parent
        visible: opened
        z: 100
        property bool   opened: false
        property string deepLink: ""
        property string webLink: ""    // https-вариант (опционально, бэк по handoff)
        property string token: ""
        property string qrSource: ""   // data:image/svg;base64,… или "" (плейсхолдер)
        property int    secsLeft: 0    // TTL-обратный отсчёт (0 = бэк не отдал expires_in_s)
        // что копируем/шарим/кодируем в QR: web_link предпочтительнее (откроется без приложения)
        readonly property string shareUrl: webLink !== "" ? webLink : deepLink
        // участие в back-логике (паттерн DrawerType2): Back/Escape закрывает ЭТОТ оверлей, не страницу
        property int depthIndex: 0
        function open()  { opened = true; depthIndex = PageController.incrementDrawerDepth() }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            opened = false; depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }

        Connections {
            target: PageController
            enabled: transferSheet.opened
            function onCloseTopDrawer() {
                if (transferSheet.depthIndex === PageController.getDrawerDepth())
                    transferSheet.close(true)
            }
        }
        // смена вкладки (replace) с открытым шитом → деструкция без close(): компенсируем depth,
        // иначе Back/Escape ломаются во всём приложении
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        function copyShareUrl() {
            linkText.selectAll(); linkText.copy(); linkText.deselect()
            PageController.showNotificationMessage(qsTr("Ссылка скопирована"))
        }
        // «Поделиться» = ссылка + QR-картинка (получатель может тапнуть или отсканировать).
        // Каскад фолбэков: shareTextWithQr → shareText (стейл-бинарник) → копирование (desktop).
        function shareUrlNative() {
            var shared = false
            if (root.hasEngine && typeof TribeEngine.shareTextWithQr === "function")
                shared = TribeEngine.shareTextWithQr(transferSheet.shareUrl, transferSheet.shareUrl)
            else if (root.hasEngine && typeof TribeEngine.shareText === "function")
                shared = TribeEngine.shareText(transferSheet.shareUrl)
            if (!shared)
                copyShareUrl() // desktop/стейл-бинарник: fallback = копирование + тост
        }

        // тик TTL; на нуле ссылку считаем истёкшей — закрываем с тостом
        Timer {
            interval: 1000; repeat: true
            running: transferSheet.opened && transferSheet.secsLeft > 0
            onTriggered: {
                transferSheet.secsLeft--
                if (transferSheet.secsLeft <= 0) {
                    transferSheet.close()
                    PageController.showNotificationMessage(qsTr("Ссылка переноса истекла — создайте новую"))
                }
            }
        }

        // поллинг «перенос принят?»: лёгкий async GET /v1/subscription (движок сам взводит
        // transferredAway на 410 → onTransferredAwayNowChanged закроет модалку и покажет результат).
        // Только пока модалка открыта — вне её хватает foreground-рефреша.
        Timer {
            // AVPN backend-first (Task 9): server-tunable numbers.transfer_poll_ms, фолбэк 4000мс.
            interval: root.hasEngine ? TribeEngine.transferPollMs : 4000
            repeat: true
            running: transferSheet.opened && root.hasEngine
            onTriggered: {
                if (typeof TribeEngine.refreshSubscription === "function")
                    TribeEngine.refreshSubscription()
            }
        }

        Rectangle {
            anchors.fill: parent
            color: "#CC000000"
            MouseArea { anchors.fill: parent; onClicked: transferSheet.close() }
        }

        // свайп слева направо = закрыть (TribeEdgeBack: DragHandler жест не держал — Flickable крал)
        TribeEdgeBack { onTriggered: transferSheet.close() }

        TribeCard {
            elevated: true
            width: parent.width - 2 * Theme.space.xl
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
            implicitHeight: transferSheetCol.implicitHeight + 2 * Theme.space.lg
            MouseArea { anchors.fill: parent }

            ColumnLayout {
                id: transferSheetCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Откройте на новом устройстве")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                Text {
                    text: qsTr("На новом устройстве: установите Tribe VPN → Настройки → «Сканировать QR» и наведите камеру. Или откройте эту ссылку там. Доступ переедет целиком, это устройство отключится сразу.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }

                // настоящий QR (сырая ссылка; белая подложка + quiet zone — читается камерой).
                // Пустой qrSource (стейл-бинарник без makeQrCode) → контур-плейсхолдер как раньше.
                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Theme.space.sm
                    width: 180; height: 180
                    radius: Theme.radius.md
                    color: transferSheet.qrSource !== "" ? "#FFFFFF" : Theme.color.surface2 // белое поле QR — намеренно вне токенов
                    border.width: 1; border.color: Theme.color.border

                    Image {
                        visible: transferSheet.qrSource !== ""
                        anchors.fill: parent
                        anchors.margins: Theme.space.sm
                        source: transferSheet.qrSource
                        sourceSize.width: width; sourceSize.height: height
                        fillMode: Image.PreserveAspectFit
                        smooth: false   // резкие модули QR, без мыла на ресайзе
                    }
                    Shape {
                        visible: transferSheet.qrSource === ""
                        anchors.centerIn: parent
                        width: 48; height: 48
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M4 4 h7 v7 h-7z M4 13 h7 v7 h-7z M13 4 h7 v7 h-7z" }
                            PathSvg { path: "M13 13 h3 v3 h-3z M19 13 v3 M13 19 h3 v1 M19 19 h1" }
                        }
                    }
                }

                // TTL-отсчёт (виден только когда бэк отдаёт expires_in_s)
                Text {
                    visible: transferSheet.secsLeft > 0
                    Layout.alignment: Qt.AlignHCenter
                    text: qsTr("Ссылка истечёт через %1:%2")
                          .arg(Math.floor(transferSheet.secsLeft / 60))
                          .arg(("0" + (transferSheet.secsLeft % 60)).slice(-2))
                    color: Theme.color.text3
                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                }

                // ссылка (mono, переносится) — read-only TextEdit: даёт нативное выделение и copy().
                Rectangle {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    implicitHeight: linkText.implicitHeight + 2 * Theme.space.md
                    radius: Theme.radius.md
                    color: Theme.color.surface2
                    border.width: 1; border.color: Theme.color.border
                    TextEdit {
                        id: linkText
                        anchors.fill: parent
                        anchors.margins: Theme.space.md
                        verticalAlignment: Text.AlignVCenter
                        text: transferSheet.shareUrl
                        readOnly: true
                        selectByMouse: true
                        color: Theme.color.text2
                        selectionColor: Theme.color.accent
                        font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                        wrapMode: TextEdit.WrapAnywhere
                    }
                }

                TribeButton {
                    variant: "primary"
                    text: qsTr("Поделиться")
                    Layout.fillWidth: true
                    onClicked: transferSheet.shareUrlNative()
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.md
                    TribeButton {
                        variant: "glass"
                        text: qsTr("Скопировать ссылку")
                        Layout.fillWidth: true
                        onClicked: transferSheet.copyShareUrl()
                    }
                    TribeButton {
                        variant: "ghost"
                        text: qsTr("Готово")
                        onClicked: transferSheet.close()
                    }
                }
            }
        }
    }

    // ── СКАНЕР QR (iOS in-app; см. openScanner) ──────────────────────────
    // Камера живёт только пока открыт оверлей: Loader active → startReading, unload → stopReading.
    Item {
        id: scanSheet
        anchors.fill: parent
        visible: opened
        z: 110
        property bool opened: false
        // участие в back-логике (паттерн DrawerType2): Back/Escape закрывает сканер, не страницу
        property int depthIndex: 0
        function open()  { opened = true; depthIndex = PageController.incrementDrawerDepth() }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            opened = false; depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }

        Connections {
            target: PageController
            enabled: scanSheet.opened
            function onCloseTopDrawer() {
                if (scanSheet.depthIndex === PageController.getDrawerDepth())
                    scanSheet.close(true)
            }
        }
        // смена вкладки (replace) с открытым сканером → деструкция без close(): компенсируем depth
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

        // свайп слева направо = закрыть (iOS-жест «назад»). Кромка в QML-слое: превью камеры —
        // нативное вью строго над scanArea (x ≥ отступа xl), левая полоса остаётся кликабельной.
        TribeEdgeBack { onTriggered: scanSheet.close() }

        Loader {
            anchors.fill: parent
            active: scanSheet.opened
            sourceComponent: Item {
                id: scanRoot

                ColumnLayout {
                    anchors.fill: parent
                    anchors.topMargin: Theme.space.xl + PageController.safeAreaTopMargin
                    anchors.leftMargin: Theme.space.xl
                    anchors.rightMargin: Theme.space.xl
                    anchors.bottomMargin: Theme.space.lg
                    spacing: Theme.space.lg

                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Сканирование QR")
                        color: Theme.color.text1
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    }
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Наведите камеру на QR-код переноса или кода активации и удержите пару секунд.")
                        color: Theme.color.text3; wrapMode: Text.WordWrap
                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                    }

                    // область нативного превью камеры (координаты уходят в setCameraSize)
                    Item {
                        id: scanArea
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                    }

                    TribeButton {
                        variant: "glass"
                        text: qsTr("Отмена")
                        Layout.fillWidth: true
                        onClicked: scanSheet.close()
                    }
                }

                QRCodeReader {
                    id: qrReader
                    onCodeReaded: function(code) { root.handleScannedCode(code) }
                }

                // setCameraSize нужен ПОСЛЕ раскладки (в onCompleted у scanArea ещё нулевая ширина) —
                // добиваем коротким ретраем, координаты в системе окна (mapToItem(null)).
                function armCamera() {
                    if (scanArea.width < 10) { armTimer.restart(); return }
                    var p = scanArea.mapToItem(null, 0, 0)
                    qrReader.setCameraSize(Qt.rect(p.x, p.y, scanArea.width, scanArea.height))
                    qrReader.startReading()
                }
                Timer { id: armTimer; interval: 60; onTriggered: scanRoot.armCamera() }
                Component.onCompleted: armCamera()
                Component.onDestruction: qrReader.stopReading()
            }
        }
    }

    // ── РЕЗУЛЬТАТ ПЕРЕНОСА (отправитель) ─────────────────────────────────
    // Полноэкранный «Подписка перенесена» после подтверждённого 410 (см. onTransferredAwayNowChanged).
    // «Понятно»/Back → на главную: там состояние «подписка закончилась» + золотая CTA.
    TribeResultSheet {
        id: transferOutResult
        anchors.fill: parent
        z: 200
        onDone: root.requestTab(0)
    }
}

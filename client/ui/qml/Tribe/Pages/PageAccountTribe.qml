import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Настройки (таб 3). Профиль (триал/плашка) + подписка + тумблеры подключения.
// Поддержка вынесена в отдельный таб — кнопки поддержки здесь больше нет.
// NO purchase button / price / payment link (Apple compliance, UI-DESIGN.md §10).
PageType {
    id: root

    // мост в полный интерфейс Amnezia (PageStart включает Dev.amneziaMode)
    signal requestAmnezia()

    // AVPN: модель — анонимный триал-по-device (кодов на бэке пока нет). Реальные данные из движка.
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property real trafficUsedB:  hasEngine ? Number(TribeEngine.trafficUsed)  : 0
    readonly property real trafficLimitB: hasEngine ? Number(TribeEngine.trafficLimit) : 0
    readonly property int  daysLeftN:     hasEngine ? TribeEngine.daysLeft : -1
    readonly property real usedFrac: trafficLimitB > 0 ? Math.min(1, trafficUsedB / trafficLimitB) : 0
    function fmtGb(b) { return (b / 1e9).toFixed(1) }
    // AVPN: shareUrl ДОЛЖЕН быть на root (раньше был на ColumnLayout → root.shareUrl=undefined →
    // «Поделиться» молча не работала). Сайт деплоит веб-команда.
    readonly property string shareUrl: "https://tribevpn.com"

    // AVPN (Task 14): активация ключа (redeem) через движок — POST /v1/code/redeem.
    // TribeEngine.redeemCode(code[, evictDeviceId]) синхронный (QEventLoop):
    //   200 → ротация токена + re-fetch подписки → changed(); 401 → error(); 409 → seatLimitReached(devices[]).
    // Успех определяем по флагу: failure-сигналы (error/seatLimitReached) прилетают ВО ВРЕМЯ вызова —
    // если после возврата redeemCode флаг не взведён, значит успех.
    property bool   redeeming: false
    property string redeemHint: ""     // локальный пояснительный текст (text3) под полем
    property bool   redeemError: false
    property bool   redeemFailed: false  // взводится onError/onSeatLimitReached в рамках синхронного вызова
    property string redeemLastCode: ""   // для повторного redeem с evict_device_id после кика

    function redeemKey(code) {
        var c = (code || "").trim()
        if (c.length === 0) {
            root.redeemError = true
            root.redeemHint = qsTr("Введите ключ активации")
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
        root.redeeming = true
        root.redeemHint = qsTr("Проверяем…")
        root.redeemLastCode = c
        doRedeem(c, "")
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
            PageController.showNotificationMessage(qsTr("Ключ активирован — доступ обновлён"))
        }
    }

    // сигналы движка redeem: error (401/прочее) и seatLimitReached (409, мест нет → выбор кого отключить).
    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onError(message) {
            root.redeemFailed = true
            root.redeeming = false
            root.redeemError = true
            root.redeemHint = ""
            PageController.showErrorMessage(message)
        }
        function onSeatLimitReached(devices) {
            root.redeemFailed = true
            root.redeeming = false
            root.redeemHint = ""
            seatSheet.devices = devices
            seatSheet.open()
        }
        // движок перечитал данные (kick / redeem / transfer) → освежаем устройства и аккаунт.
        // НЕ синхронно в обработчике: changed() может прилетать пачкой (connect/state) — дебаунсим
        // через таймер, иначе каждый сигнал = 2 сетевых вызова прямо в слоте (джанк/фриз).
        function onChanged() { settingsLoadTimer.restart() }
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

    // человекочитаемый статус аккаунта для строки ПРОФИЛЬ.
    function accountStatusLabel() {
        var s = root.accountData ? (root.accountData.status || "") : ""
        if (s === "active")  return qsTr("Активна")
        if (s === "trial")   return qsTr("Пробный доступ")
        if (s === "expired") return qsTr("Истекла")
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

    // ── ПЕРЕНОС НА НОВОЕ УСТРОЙСТВО (createTransfer) ─────────────────────────────────────
    // Выпуск одноразового токена «как SIM» (POST /v1/transfer). Возвращает {transfer_token, deep_link}.
    function createTransfer() {
        if (!(root.hasEngine && typeof TribeEngine.createTransfer === "function")) {
            PageController.showErrorMessage(qsTr("Движок недоступен — обновите приложение"))
            return
        }
        var res = TribeEngine.createTransfer()  // синхронно; пустая мапа + emit error при сбое
        if (!res || !res.deep_link || res.deep_link === "") return // onError уже показал тост
        transferSheet.deepLink = res.deep_link
        transferSheet.token = res.transfer_token || ""
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
        anchors.topMargin: Theme.space.xl + PageController.safeAreaTopMargin // iOS: натив-инсет
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        contentWidth: width
        contentHeight: settingsCol.implicitHeight + Theme.space.lg

        ColumnLayout {
            id: settingsCol
            width: settingsFlick.width
            // AVPN: ColumnLayout как прямой content-item Flickable не подгоняет height под implicitHeight
            // сам (в отличие от позиционера Column). Без этого height=0 → нижние секции схлопываются и
            // под карточкой подписки остаётся большая пустая тёмная полоса. Биндим к implicitHeight.
            height: implicitHeight
            spacing: Theme.space.md

        // AVPN: заголовок «Настройки» убран (нижняя навигация уже подписана). Admin-кнопки
        // (мост в Amnezia + тумблер Dev.adminMode) скрыты — контент начинается сразу с баннера.

        // ── БАННЕР «ПОДЕЛИТЬСЯ» ──────────────────────────────────────────────
        // Самый верх, без заголовка раздела. Accent-градиент + soft-визуал, ровно 2 строки текста.
        // Тап → открыть сайт (root.shareUrl, Apple-safe: только URL, без цен/рефералов §10).
        Rectangle {
            id: shareBanner
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.xs
            implicitHeight: shareRow.implicitHeight + 2 * Theme.space.lg
            radius: Theme.radius.lg
            gradient: Gradient {
                orientation: Gradient.Horizontal
                GradientStop { position: 0.0; color: Theme.color.gradTop }
                GradientStop { position: 1.0; color: Theme.color.gradBottom }
            }
            // мягкий внутренний хайлайт — даёт «стеклянный» объём без тяжёлого Glow
            border.width: 1
            border.color: Theme.color.border2
            scale: shareMa.pressed ? 0.99 : 1.0
            Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

            RowLayout {
                id: shareRow
                anchors.fill: parent
                anchors.leftMargin: Theme.space.lg
                anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.md

                // ── бейдж «подарок»: светящийся круг + объёмный подарок + золотой «+» + блёстки ──
                // подарок периодически «вздрагивает» (наклон у основания), привлекая внимание. // AVPN
                Item {
                    id: giftBadge
                    Layout.alignment: Qt.AlignVCenter
                    Layout.preferredWidth: 56; Layout.preferredHeight: 56

                    // светящийся круг-подложка
                    Rectangle {
                        anchors.centerIn: parent
                        width: 52; height: 52; radius: 26
                        color: Qt.rgba(1, 1, 1, 0.20)
                        border.width: 1; border.color: Qt.rgba(1, 1, 1, 0.28)
                    }

                    // блёстки (4-конечные звёзды) — статичный декор
                    Shape {
                        anchors.right: parent.right; anchors.top: parent.top
                        anchors.rightMargin: 2; anchors.topMargin: 4
                        width: 9; height: 9
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            fillColor: Qt.rgba(1, 1, 1, 0.85); strokeColor: "transparent"
                            PathSvg { path: "M4.5 0 L5.6 3.4 L9 4.5 L5.6 5.6 L4.5 9 L3.4 5.6 L0 4.5 L3.4 3.4 Z" }
                        }
                    }
                    Shape {
                        anchors.left: parent.left; anchors.bottom: parent.bottom
                        anchors.leftMargin: 1; anchors.bottomMargin: 8
                        width: 6; height: 6
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            fillColor: Qt.rgba(1, 1, 1, 0.6); strokeColor: "transparent"
                            PathSvg { path: "M3 0 L3.7 2.3 L6 3 L3.7 3.7 L3 6 L2.3 3.7 L0 3 L2.3 2.3 Z" }
                        }
                    }

                    // объёмный подарок (заполненный) — вздрагивает вокруг основания
                    Shape {
                        id: giftShape
                        anchors.centerIn: parent
                        width: 30; height: 30
                        transformOrigin: Item.Bottom
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {   // коробка (светлая)
                            fillColor: "#DCE8F7"; strokeColor: "transparent"
                            PathSvg { path: "M6 14 H24 V25 a2 2 0 0 1 -2 2 H8 a2 2 0 0 1 -2 -2 Z" }
                        }
                        ShapePath {   // крышка (белая)
                            fillColor: "#FFFFFF"; strokeColor: "transparent"
                            PathSvg { path: "M4 10 H26 V14 H4 Z" }
                        }
                        ShapePath {   // вертикальная лента (золото)
                            fillColor: Theme.color.cta; strokeColor: "transparent"
                            PathSvg { path: "M13.4 10 H16.6 V27 H13.4 Z" }
                        }
                        ShapePath {   // левый бант
                            fillColor: Theme.color.cta; strokeColor: "transparent"
                            PathSvg { path: "M15 10 C12 5 8 5.5 9 8.6 C9.7 10.4 13 10.8 15 10 Z" }
                        }
                        ShapePath {   // правый бант
                            fillColor: Theme.color.cta; strokeColor: "transparent"
                            PathSvg { path: "M15 10 C18 5 22 5.5 21 8.6 C20.3 10.4 17 10.8 15 10 Z" }
                        }
                    }

                    // золотой бейдж «+» (бонус) в правом-нижнем углу круга
                    Rectangle {
                        anchors.right: parent.right; anchors.bottom: parent.bottom
                        anchors.rightMargin: 1; anchors.bottomMargin: 1
                        width: 19; height: 19; radius: width / 2
                        color: Theme.color.cta
                        border.width: 2; border.color: Theme.color.gradBottom
                        Shape {
                            anchors.centerIn: parent; width: 11; height: 11
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2
                                capStyle: ShapePath.RoundCap
                                PathSvg { path: "M5.5 1.6 V9.4 M1.6 5.5 H9.4" }
                            }
                        }
                    }

                    // петля вздрагивания: длинная пауза → быстрый «качок». Глушится reduceMotion.
                    SequentialAnimation {
                        running: !Theme.motion.reduceMotion
                        loops: Animation.Infinite
                        PauseAnimation { duration: 2600 }
                        NumberAnimation { target: giftShape; property: "rotation"; to: -9; duration: 90 }
                        NumberAnimation { target: giftShape; property: "rotation"; to: 9;  duration: 150; easing.type: Easing.InOutSine }
                        NumberAnimation { target: giftShape; property: "rotation"; to: -6; duration: 120; easing.type: Easing.InOutSine }
                        NumberAnimation { target: giftShape; property: "rotation"; to: 0;  duration: 130; easing.type: Easing.OutBack }
                    }
                }

                // ── текст: заголовок (2 строки) + пилюля-оффер + подпись ──
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    spacing: Theme.space.xs

                    Text {
                        text: qsTr("Пригласи друзей —\nполучай подарки")
                        color: "white"
                        font.family: Theme.font.display
                        font.pixelSize: Theme.font.bodyM
                        font.weight: Theme.font.wExtra
                        lineHeight: 1.05
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                    // пилюля: числа золотом (CTA), остальное белым; короткая — влезает на узких экранах
                    Rectangle {
                        Layout.alignment: Qt.AlignLeft
                        implicitWidth: pillText.implicitWidth + 2 * Theme.space.sm
                        implicitHeight: pillText.implicitHeight + 2 * Theme.space.xs
                        radius: Theme.radius.pill
                        color: Qt.rgba(0, 0, 0, 0.20)
                        Text {
                            id: pillText
                            anchors.centerIn: parent
                            textFormat: Text.StyledText
                            text: "<b><font color='" + Theme.color.cta + "'>+7 дней</font></b> и <b><font color='"
                                  + Theme.color.cta + "'>+3 ГБ</font></b>"
                            color: "white"
                            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                            font.weight: Theme.font.wSemibold
                        }
                    }
                    Text {
                        text: qsTr("за каждого друга по твоей ссылке")
                        color: Qt.rgba(1, 1, 1, 0.78)
                        font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                        Layout.fillWidth: true; wrapMode: Text.WordWrap
                    }
                }

                // ── шеврон в полупрозрачном круге ──
                Rectangle {
                    Layout.alignment: Qt.AlignVCenter
                    Layout.preferredWidth: 30; Layout.preferredHeight: 30
                    radius: width / 2
                    color: Qt.rgba(1, 1, 1, 0.18)
                    Shape {
                        anchors.centerIn: parent; width: 24; height: 24; scale: 16 / 24
                        transformOrigin: Item.Center
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2.4
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M9 6 L15 12 L9 18" }
                        }
                    }
                }
            }
            MouseArea {
                id: shareMa
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: Qt.openUrlExternally(root.shareUrl)
            }
        }

        // ── ПОДПИСКА ─────────────────────────────────────────────────────────
        // Единый блок: статус/срок/трафик/устройства. Отдельного «Профиля» нет — устройство
        // и так видно в списке УСТРОЙСТВА ниже; всё остальное сведено сюда (без дублирования).
        Text {
            text: qsTr("ПОДПИСКА")
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        TribeCard {
            Layout.fillWidth: true
            implicitHeight: planCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: planCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                // название плана + статус (active/trial/expired из движка, fallback — пробный)
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Tribe Trial"); color: Theme.color.text1
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    }
                    TribeBadge {
                        variant: (root.accountData && root.accountData.status === "active") ? "on"
                               : (root.accountData && root.accountData.status === "expired") ? "off" : "warn"
                        text: (root.accountData && root.accountData.status === "active") ? qsTr("Активна")
                            : (root.accountData && root.accountData.status === "expired") ? qsTr("Истекла")
                            : qsTr("Пробный")
                    }
                }

                // срок действия: остаток дней + дата окончания (бывшая отдельная строка статуса)
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Действует"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text {
                        text: {
                            var parts = []
                            if (root.daysLeftN >= 0) parts.push(qsTr("%1 дн.").arg(root.daysLeftN))
                            var d = root.fmtDate(root.accountData ? root.accountData.expires_at : "")
                            if (d !== "") parts.push(qsTr("до ") + d)
                            return parts.length ? parts.join(" · ") : qsTr("Активен")
                        }
                        color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                    }
                }

                // трафик
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Трафик"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text {
                        text: root.trafficLimitB > 0
                              ? (root.fmtGb(root.trafficUsedB) + " / " + root.fmtGb(root.trafficLimitB) + qsTr(" ГБ"))
                              : qsTr("Безлимит")
                        color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                    }
                }
                Rectangle {
                    Layout.fillWidth: true; height: 6; radius: 3; color: Theme.color.surface3
                    visible: root.trafficLimitB > 0
                    Rectangle { width: parent.width * root.usedFrac; height: parent.height; radius: 3; color: Theme.color.accent }
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
                    text: qsTr("Активировать ключ")
                    color: Theme.color.text1
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                    Layout.fillWidth: true
                }
                Text {
                    text: qsTr("Введите ключ активации, чтобы продлить доступ.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }

                TribeField {
                    id: redeemField
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xs
                    enabled: !root.redeeming
                    placeholderText: qsTr("Введите ключ активации")
                    error: root.redeemError
                    onTextChanged: { root.redeemError = false; root.redeemHint = "" }
                    onAccepted: root.redeemKey(text)
                }

                // accent-кнопка во всю ширину; активна только при непустом поле
                TribeButton {
                    variant: "primary"
                    text: qsTr("Активировать")
                    loading: root.redeeming
                    enabled: !root.redeeming && redeemField.text.trim().length > 0
                    Layout.fillWidth: true
                    onClicked: root.redeemKey(redeemField.text)
                }

                // пояснительный текст (text3): «Проверяем…» / ошибка валидации непустоты
                Text {
                    visible: root.redeemHint !== ""
                    text: root.redeemHint
                    color: root.redeemError ? Theme.color.danger : Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
            }
        }

        // перенос подписки «как SIM» — тоже часть ПОДПИСКИ. Вторичная (glass) кнопка во всю ширину.
        TribeCard {
            Layout.fillWidth: true
            implicitHeight: transferCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: transferCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Перенести подписку на другое устройство")
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
                TribeButton {
                    variant: "glass"
                    text: qsTr("Перенести подписку")
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
                text: qsTr("Список устройств появится после активации ключа")
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
                        kickConfirm.deviceId = modelData.device_id || ""
                        kickConfirm.deviceLabel = modelData.label || modelData.platform || qsTr("устройство")
                        kickConfirm.isSelf = modelData.is_current === true
                        kickConfirm.open()
                    }
                }
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
        function open()  { opened = true }
        function close() { opened = false; busy = false }

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
                    text: qsTr("Выберите устройство, которое нужно отключить, чтобы активировать ключ здесь.")
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
        function open()  { opened = true }
        function close() { opened = false }

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
                          ? qsTr("Доступ на этом устройстве будет отозван. Чтобы вернуться, активируйте ключ заново.")
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

    // ── ПЕРЕНОС: ССЫЛКА / КОД ────────────────────────────────────────────
    // Показ deep_link/transfer_token из createTransfer(). QR — TODO; для MVP ссылка + копирование.
    Item {
        id: transferSheet
        anchors.fill: parent
        visible: opened
        z: 100
        property bool   opened: false
        property string deepLink: ""
        property string token: ""
        function open()  { opened = true }
        function close() { opened = false }

        Rectangle {
            anchors.fill: parent
            color: "#CC000000"
            MouseArea { anchors.fill: parent; onClicked: transferSheet.close() }
        }

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
                    text: qsTr("Перейдите по этой ссылке на новом устройстве, чтобы перенести подписку. Ссылка одноразовая и скоро истечёт.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }

                // QR-плейсхолдер (полноценный QR — TODO). Контур + подпись.
                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Theme.space.sm
                    width: 160; height: 160
                    radius: Theme.radius.md
                    color: Theme.color.surface2
                    border.width: 1; border.color: Theme.color.border
                    Shape {
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
                        text: transferSheet.deepLink
                        readOnly: true
                        selectByMouse: true
                        color: Theme.color.text2
                        selectionColor: Theme.color.accent
                        font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                        wrapMode: TextEdit.WrapAnywhere
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.md
                    TribeButton {
                        variant: "glass"
                        text: qsTr("Скопировать ссылку")
                        Layout.fillWidth: true
                        onClicked: {
                            // dependency-free copy: выделить весь read-only TextEdit и copy() в системный буфер
                            linkText.selectAll()
                            linkText.copy()
                            linkText.deselect()
                            PageController.showNotificationMessage(qsTr("Ссылка скопирована"))
                        }
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
}

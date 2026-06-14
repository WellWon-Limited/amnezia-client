import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import QtCore                 // AVPN: Settings (персист тумблеров)

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

    // AVPN: персист настроек подключения (QtCore.Settings). Авто-пауза для РФ-приложений — ВКЛ по умолчанию.
    Settings {
        id: avpnSettings
        category: "AvpnSettings"
        property bool autoPauseRu: true
        property bool autoConnect: false
    }

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
            root.redeemHint = qsTr("Введите ключ или код активации")
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

    // AVPN (#17): весь контент — в прокрутке; Flickable заканчивается НАД нижней навигацией
    // (bottomMargin = высота TribeBottomNav 72 + safe-area), чтобы доскроллить и не лезть под меню.
    Flickable {
        id: settingsFlick
        anchors.fill: parent
        anchors.topMargin: Theme.space.xl + PageController.safeAreaTopMargin // iOS: натив-инсет
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        anchors.bottomMargin: 72 + PageController.safeAreaBottomMargin       // выше нижнего меню
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

        // AVPN (#16): заголовок «Настройки» убран (нижняя навигация уже подписана). Оставляем только
        // admin-кнопки справа: мост в Amnezia (виден в adminMode) + тумблер Dev.adminMode (shield).
        RowLayout {
            Layout.fillWidth: true
            spacing: 2
            Item { Layout.fillWidth: true }
            Item {
                Layout.preferredWidth: 36; Layout.preferredHeight: 36
                visible: Dev.adminMode
                Image {
                    anchors.centerIn: parent
                    source: "qrc:/images/controls/amnezia.svg"
                    sourceSize: Qt.size(22, 22)
                    opacity: amneziaMa.containsMouse ? 1.0 : 0.65
                }
                MouseArea { id: amneziaMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: root.requestAmnezia() }
            }
            Item {
                Layout.preferredWidth: 36; Layout.preferredHeight: 36
                opacity: Dev.adminMode ? 1.0 : 0.55
                Shape {
                    anchors.centerIn: parent
                    width: 22; height: 22
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Dev.adminMode ? Theme.color.accent
                                                   : (adminMa.containsMouse ? Theme.color.text1 : Theme.color.text3)
                        fillColor: Dev.adminMode ? Theme.color.chipSelected : "transparent"
                        strokeWidth: 1.7
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }
                    }
                }
                MouseArea { id: adminMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: Dev.adminMode = !Dev.adminMode }
            }
        }

        // ── ПРОФИЛЬ ──────────────────────────────────────────────────────────
        Text {
            text: qsTr("ПРОФИЛЬ")
            color: Theme.color.accent
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        // плашка пользователя / триала
        TribeCard {
            Layout.fillWidth: true
            implicitHeight: 64
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space.lg
                anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.md
                Rectangle {
                    width: 40; height: 40; radius: 20
                    color: Theme.color.surface2
                    // Tabler "user" (inline vector, без emoji)
                    Shape {
                        anchors.centerIn: parent
                        width: 24; height: 24
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.text2; fillColor: "transparent"; strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M12 12 a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" }
                            PathSvg { path: "M6 20 v-1 a6 6 0 0 1 12 0 v1" }
                        }
                    }
                }
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Пробный доступ")
                    color: Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                }
                // остаток триала — реальные данные (не кнопка; вход по кодам появится с бэкендом P-B12)
                TribeBadge {
                    variant: "warn"
                    text: root.daysLeftN >= 0 ? qsTr("%1 дн.").arg(root.daysLeftN) : qsTr("Активен")
                }
            }
        }

        // строка статуса аккаунта (GET /v1/account). Видна только когда движок вернул данные.
        TribeListRow {
            Layout.fillWidth: true
            visible: root.accountStatusLabel() !== ""
            interactive: false
            title: qsTr("Статус аккаунта")
            // левая иконка badge (Tabler, inline-вектор)
            leftItem: Shape {
                width: 22; height: 22
                anchors.verticalCenter: parent.verticalCenter
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 1.8
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M9 12 l2 2 l4-4" }
                    PathSvg { path: "M12 3 a9 9 0 1 0 0 18 a9 9 0 0 0 0-18z" }
                }
            }
            rightItem: RowLayout {
                anchors.verticalCenter: parent.verticalCenter
                spacing: Theme.space.sm
                Text {
                    text: {
                        var d = root.fmtDate(root.accountData ? root.accountData.expires_at : "")
                        return d !== "" ? qsTr("до ") + d : ""
                    }
                    visible: text !== ""
                    color: Theme.color.text3
                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                    Layout.alignment: Qt.AlignVCenter
                }
                TribeBadge {
                    variant: (root.accountData && root.accountData.status === "active") ? "on"
                           : (root.accountData && root.accountData.status === "expired") ? "off" : "warn"
                    text: root.accountStatusLabel()
                }
            }
        }

        // активировать ключ (redeem) — поле + accent-кнопка. Движок: TribeEngine.redeemCode (POST /v1/code/redeem).
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

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.md
                    TribeField {
                        id: redeemField
                        Layout.fillWidth: true
                        enabled: !root.redeeming
                        placeholderText: qsTr("Ключ или код")
                        error: root.redeemError
                        onTextChanged: { root.redeemError = false; root.redeemHint = "" }
                        onAccepted: root.redeemKey(text)
                    }
                    TribeButton {
                        variant: "primary"
                        text: qsTr("Активировать")
                        loading: root.redeeming
                        enabled: !root.redeeming
                        onClicked: root.redeemKey(redeemField.text)
                    }
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

        // ── ПОДПИСКА ─────────────────────────────────────────────────────────
        Text {
            text: qsTr("ПОДПИСКА")
            color: Theme.color.accent
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
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Tribe Trial"); color: Theme.color.text1
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    }
                    TribeBadge { variant: "warn"; text: qsTr("Пробный") }
                }
                // traffic
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
                // devices
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Устройства"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text { text: "1 / 1"; color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData }
                }
            }
        }

        // ── УСТРОЙСТВА ───────────────────────────────────────────────────────
        Text {
            text: qsTr("УСТРОЙСТВА")
            color: Theme.color.accent
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
                title: {
                    var lbl = modelData.label || modelData.platform || qsTr("Устройство")
                    return modelData.is_current ? (lbl + qsTr(" (это устройство)")) : lbl
                }
                subtitle: {
                    var parts = []
                    if (modelData.platform && modelData.platform !== "") parts.push(modelData.platform)
                    var seen = root.fmtDate(modelData.last_seen)
                    if (seen !== "") parts.push(qsTr("активность ") + seen)
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
                // кнопка кика (своё устройство = «Выйти», иначе «Отключить»)
                rightItem: TribeButton {
                    anchors.verticalCenter: parent.verticalCenter
                    variant: "ghost"
                    text: modelData.is_current ? qsTr("Выйти") : qsTr("Отключить")
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

        // ── ПЕРЕНОС НА НОВОЕ УСТРОЙСТВО ──────────────────────────────────────
        Text {
            text: qsTr("ПЕРЕНОС НА НОВОЕ УСТРОЙСТВО")
            color: Theme.color.accent
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        TribeCard {
            Layout.fillWidth: true
            implicitHeight: transferCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: transferCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Перенести подписку как SIM-карту")
                    color: Theme.color.text1
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                Text {
                    text: qsTr("Создайте одноразовую ссылку и откройте её на новом устройстве. Текущее устройство будет отключено.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    Layout.fillWidth: true; wrapMode: Text.WordWrap
                }
                TribeButton {
                    variant: "primary"
                    text: qsTr("Перенести подписку")
                    Layout.alignment: Qt.AlignRight
                    onClicked: root.createTransfer()
                }
            }
        }

        // ── ПОДКЛЮЧЕНИЕ ──────────────────────────────────────────────────────
        Text {
            text: qsTr("ПОДКЛЮЧЕНИЕ")
            color: Theme.color.accent
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        TribeCard {
            Layout.fillWidth: true
            implicitHeight: togglesCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: togglesCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.lg

                // Авто-пауза для РФ-приложений
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.md
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            text: qsTr("Авто-пауза для РФ-приложений")
                            color: Theme.color.text1
                            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                            font.weight: Theme.font.wMedium
                            Layout.fillWidth: true; wrapMode: Text.WordWrap
                        }
                        Text {
                            text: qsTr("VPN автоматически выключается для российских сервисов")
                            color: Theme.color.text3
                            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            Layout.fillWidth: true; wrapMode: Text.WordWrap
                        }
                    }
                    TribeToggle {
                        Layout.alignment: Qt.AlignVCenter
                        checked: avpnSettings.autoPauseRu
                        onToggled: avpnSettings.autoPauseRu = checked
                    }
                }

                Rectangle { Layout.fillWidth: true; height: 1; color: Theme.color.border }

                // Автоподключение при запуске
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space.md
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            text: qsTr("Автоподключение при запуске")
                            color: Theme.color.text1
                            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                            font.weight: Theme.font.wMedium
                            Layout.fillWidth: true; wrapMode: Text.WordWrap
                        }
                        Text {
                            text: qsTr("Включать VPN сразу при открытии приложения")
                            color: Theme.color.text3
                            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            Layout.fillWidth: true; wrapMode: Text.WordWrap
                        }
                    }
                    TribeToggle {
                        Layout.alignment: Qt.AlignVCenter
                        checked: avpnSettings.autoConnect
                        onToggled: avpnSettings.autoConnect = checked
                    }
                }
            }
        }

        // AVPN: Apple-safe share. URL-only (никаких цен/промо/рефералов — §10). root.shareUrl.
        TribeListRow {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.sm
            title: qsTr("Поделиться приложением")
            iconSource: ""
            // левая иконка share (Tabler, inline-вектор)
            leftItem: Shape {
                width: 22; height: 22
                anchors.verticalCenter: parent.verticalCenter
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 1.8
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M6 12 a3 3 0 1 0 0-0.01 M18 6 a3 3 0 1 0 0-0.01 M18 18 a3 3 0 1 0 0-0.01" }
                    PathSvg { path: "M8.5 10.5 L15.5 7 M8.5 13.5 L15.5 17" }
                }
            }
            rightItem: Text { text: "›"; color: Theme.color.text3; font.pixelSize: Theme.font.h3; anchors.verticalCenter: parent.verticalCenter }
            onClicked: Qt.openUrlExternally(root.shareUrl)
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

import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import QtCore                        // AVPN: Settings (флаг «АвтоVPN» AvpnBypass/masterOn)
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components" // TribeFlag (круглый флаг по country_code) и др.
import "../../Controls2" // PageType

// AVPN: Connect-экран (звёздное небо + горы во всю ширину + орб-сфера). Горы full-bleed и
// заходят на нижнюю часть круга. Синий = Theme.accent (#7ca2d0, финал). UI: переписан 2026-06.
PageType {
    id: root

    readonly property color blueAccent: Theme.color.accent
    readonly property color blue300: "#93C5FD"
    readonly property color blue400: "#60A5FA"
    readonly property color blue600: "#2563EB"
    readonly property color slate400: Theme.color.text2
    readonly property color slate500: Theme.color.text3
    readonly property color slate900: "#0F172A"

    // previewSim: визуальная симуляция (off→Поиск…→Connected) ТОЛЬКО для превью-демо.
    // false = орб ходит в РЕАЛЬНЫЙ движок (TribeEngine), а не в ванильный ConnectionController. // AVPN
    property bool previewSim: false
    property bool simConnected: false
    property bool simConnecting: false

    // AVPN (фикс рассинхрона орба): состояние орба берём из TribeEngine (наша стейт-машина), а НЕ из
    // ванильного ConnectionController — иначе орб решал stop/start по чужому состоянию и расходился с
    // движком (повторный Connect делал stop, смена ноды «не коннектила»). Фолбэк на ConnectionController
    // только если движка нет (не наш кейс на проде).
    readonly property bool isOn:  previewSim ? simConnected
                                  : (hasEngine ? (TribeEngine.state === "connected") : ConnectionController.isConnected)
    readonly property bool isBusy: previewSim ? simConnecting
                                  : (hasEngine ? TribeEngine.busy : ConnectionController.isConnectionInProgress)

    signal requestTab(int index)
    signal requestSettings()
    signal requestNotifications()
    signal requestAdminServers()  // AVPN: админ-просмотр пула нод (только Dev.adminMode)

    // AVPN: центр уведомлений — счётчик непрочитанных. Реальные пуши (#9) идут через мост
    // AvpnPush (APNs/FCM → C++ → QML). В dev-превью моста нет → фолбэк 2 (mock-бейдж).
    readonly property bool hasPush: (typeof AvpnPush !== "undefined")
    readonly property int unreadCount: hasPush ? Number(AvpnPush.unreadCount) : 2

    // AVPN: бейдж подписки. Реактивные Q_PROPERTY на TribeEngine (NOTIFY changed): trafficUsed/
    // trafficLimit/daysLeft/subActive — читают загруженную Subscription через движок. Гард на
    // undefined-движок (dev-превью) с литеральными фолбэками.
    readonly property bool hasEngine:     (typeof TribeEngine !== "undefined")
    // AVPN (оплата): гард двойного тапа по золотой CTA — ждём cabinetLinkReady (приходит всегда).
    property bool ctaLinking: false
    // AVPN (оплата): троттл foreground-рефреша статуса подписки (мс, Date.now()).
    property double lastFgRefreshMs: 0
    readonly property real trafficUsedB:  hasEngine ? Number(TribeEngine.trafficUsed)  : 0
    readonly property real trafficLimitB: hasEngine ? Number(TribeEngine.trafficLimit) : 0
    readonly property bool subActive:     (hasEngine && TribeEngine.subActive !== undefined) ? TribeEngine.subActive : true
    // AVPN: триал/подписка исчерпаны → монетизационный CTA «Получить ключ» вместо ротации.
    // Исчерпан, если: подписка неактивна, ИЛИ дней не осталось (0), ИЛИ лимит трафика выбран.
    // Гейт daysLeft >= 0: ПОКА данные не загружены (пустой снапшот, daysLeft = -1) CTA не показываем —
    // «не знаем» ≠ «истёк»; после foreground-рефетча /v1/subscription состояние догонит правду.
    readonly property bool subExpired: root.hasEngine && TribeEngine.daysLeft >= 0 && (!root.subActive
                              || (TribeEngine.daysLeft === 0)
                              || (root.trafficLimitB > 0 && root.trafficUsedB >= root.trafficLimitB))
    // Причина CTA для текста кнопки: подписка/срок живы, кончился ТОЛЬКО трафик → «Продлить трафик»
    // (иначе юзер видит «Обновить ключ» при непросроченном сроке и не понимает, что случилось —
    // реальный кейс did=40: expires_at в будущем, а 4 GiB триала выбраны). Гард как у subExpired:
    // при !hasEngine subExpired=false → до TribeEngine не дойдёт (короткое замыкание). // AVPN
    readonly property bool ctaTrafficOnly: root.subExpired && root.subActive
                              && (TribeEngine.daysLeft !== 0)
                              && (root.trafficLimitB > 0 && root.trafficUsedB >= root.trafficLimitB)
    // остаток трафика: «∞» при безлимите/неизвестно (limit 0 или NaN). Компактно: ≥1024 ГиБ → «N TB»,
    // иначе «N GB»; хвост «.0» убираем (чтобы влезало в узкое macOS-окно). Двоичная база (ГиБ, бэк подтвердил).
    function fmtTrafficLeft() {
        if (!hasEngine) return "3.2 GB"                // dev-превью: литеральный фолбэк
        if (!(trafficLimitB > 0)) return "∞"           // безлимит / ещё не загружено (0 или NaN)
        var leftB = Math.max(0, trafficLimitB - trafficUsedB)
        if (isNaN(leftB)) return "∞"
        var gib = leftB / 1073741824                   // 1024³
        if (gib >= 1024)
            return (gib / 1024).toFixed(1).replace(/\.0$/, "") + " TB"
        return gib.toFixed(1).replace(/\.0$/, "") + " GB"
    }
    // daysLeft<0 = бессрочно/неизвестно → «∞»; иначе «N дн.»
    readonly property string daysLeftText: !hasEngine ? qsTr("12 дн.")
                              : (TribeEngine.daysLeft >= 0 ? qsTr("%1 дн.").arg(TribeEngine.daysLeft)
                                                          : qsTr("∞"))

    // AVPN: реальный сервер из подписки (карточка внизу). Гард на undefined currentNode (иначе краш).
    readonly property var curNode: (hasEngine && TribeEngine.currentNode) ? TribeEngine.currentNode
                                             : ({ region: "", ip: "", hasNode: false })

    // iOS: PageController.safeArea* реализован только для Android → берём максимум с SafeArea
    // (Qt 6.9+, реактивный UIKit-инсет). БЕЗ этого на холодном старте iOS PageController=0 →
    // верх съезжает под чёлку, и «чинится» только после пересоздания страницы (смена вкладки).
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    // Мобайл: сцена (орб + горы + подпись) опущена на ~20% высоты экрана, но так, чтобы
    // подпись не наезжала на карточку сервера (низ сцены ≥ 24px над bottomBlock).
    // Шапку, бейдж, карточку и кнопку не трогаем (реш. 2026-06-11).
    readonly property bool isMobile: Qt.platform.os === "ios" || Qt.platform.os === "android"
    readonly property real sceneShift: {
        if (!isMobile) return 0
        // орб теперь под баннером АнтиВПН: header (safeTop+16+40) + отступ lg (24) + баннер (68)
        // + 56 (кольцо 32 + зазор lg) — база на 72 ниже старой (76)
        var orbBase = safeTop + 16 + 40 + 24 + 68 + 56
        var captionBottom = orbBase + 256 + 30 + 18   // орб + отступ подписи + высота подписи
        var maxShift = bottomBlock.y - captionBottom - 24
        // прежний целевой сдвиг (~20% высоты − 44) уменьшен ещё на 72 — ровно настолько сцену
        // уже опустил баннер сверху (итого −116)
        return Math.max(0, Math.min(Math.round(root.height * 0.20) - 116, maxShift))
    }

    function onOrbClicked() {
        if (previewSim) {
            if (simConnected) { simConnected = false; return }
            simConnecting = true; simTimer.restart()
        } else if (typeof TribeEngine !== "undefined") {
            // сервисная модель: enroll → /v1/subscription → выбор ноды → туннель (E2E №1)
            if (isOn || isBusy) TribeEngine.stop()
            else TribeEngine.start()
        } else if (ServersUiController.getServersCount() === 0) {
            // нет ни движка, ни конфигурации — не уводим в ванильный wizard.
            // Гостевой trial (без аккаунта) подключится вместе с control plane (POST /v1/trial).
            PageController.showNotificationMessage(qsTr("Серверы сервиса запускаются — пробный доступ появится в ближайшем обновлении, аккаунт не нужен"))
        } else {
            ConnectionController.connectButtonClicked()
        }
    }

    // ошибки движка — в стандартный тост
    Connections {
        target: typeof TribeEngine !== "undefined" ? TribeEngine : null
        ignoreUnknownSignals: true
        function onError(message) { PageController.showErrorMessage(message) }
        // AVPN (оплата): ссылка web-кабинета готова (успех или fallback). Гард по ctaLinking —
        // сигнал общий на движок, не реагируем на запросы других страниц (кнопка в Настройках).
        function onCabinetLinkReady(url) {
            if (!root.ctaLinking) return
            root.ctaLinking = false
            Qt.openUrlExternally(url)
        }
        // AVPN (macOS): обнаружен другой активный VPN → конфликт маршрутов/демонов. Предупреждаем.
        function onVpnConflict(name) {
            PageController.showNotificationMessage(
                qsTr("Обнаружен другой активный VPN (%1). Отключите его — Tribe VPN может не подключиться из-за конфликта.").arg(name))
        }
    }

    // AVPN (Task 13): активация после покупки по диплинку → re-fetch подписки (бейдж оживёт).
    Connections {
        target: (typeof AvpnDeepLink !== "undefined") ? AvpnDeepLink : null
        ignoreUnknownSignals: true
        function onActivated(token, accountId) {
            if (typeof TribeEngine !== "undefined" && typeof TribeEngine.bootstrap === "function")
                TribeEngine.bootstrap()
            PageController.showNotificationMessage(qsTr("Доступ активирован на этом устройстве"))
        }
    }

    // AVPN (оплата): возврат приложения в foreground (например, из Safari после оплаты в кабинете) —
    // освежить ЧАСЫ УСТРОЙСТВА (GET /v1/subscription, их продлевает платёж): новый expires_at/трафик
    // приедет в бейдж, CTA «Обновить ключ» погаснет сам. refreshAccount — справочно (account_id,
    // списки в Настройках), в бейдж НЕ пишет. Троттл 30с, чтобы не дёргать бэк на каждый свап
    // приложений. bootstrap() тут НЕ зовём — он трогает подписку/туннель-флоу (CONNECT-INVARIANTS).
    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.application.state !== Qt.ApplicationActive) return
            if (!root.hasEngine) return
            var now = Date.now()
            if (now - root.lastFgRefreshMs < 30000) return
            root.lastFgRefreshMs = now
            if (typeof TribeEngine.refreshSubscription === "function")
                TribeEngine.refreshSubscription()   // device-часы: бейдж/CTA
            if (typeof TribeEngine.refreshAccount === "function")
                TribeEngine.refreshAccount()        // account-справка: Настройки
        }
    }

    // AVPN (Task 11): bootstrap НЕ зовём из Component.onCompleted — он делает блокирующий сетевой
    // вызов (вложенный QEventLoop), а во время построения QML это вызывает re-entrancy и краш
    // (QQuickItem::setFocus на недостроенном элементе). Движок сам дефер-вызывает bootstrap из
    // конструктора уже ПОСЛЕ показа окна (QTimer::singleShot) — безопасно, как обычный start().
    Timer { id: simTimer; interval: 1500; onTriggered: { root.simConnecting = false; root.simConnected = true } }

    // AVPN RU-direct: флаг «АвтоVPN» (единый РФ-доступ). Тот же стор/ключ, что читает движок
    // (AvpnEngineQml::applyRuBypassSplit → QSettings AvpnBypass/masterOn). defaultOnMigrated — одноразовый
    // force-on для старых юзеров (перенесён из удалённого PageSecurityTribe), чтобы РФ-доступ работал у всех.
    Settings {
        id: bypassStore
        category: "AvpnBypass"
        property bool masterOn: true
        property bool defaultOnMigrated: false
    }
    Component.onCompleted: {
        if (!bypassStore.defaultOnMigrated) {
            bypassStore.masterOn = true
            bypassStore.defaultOnMigrated = true
        }
    }

    // AVPN: иконка «RU-шар» (редизайн 2026-07-02, по эталон-скрину): тёмная скруглённая плитка,
    // внутри круг с мягким диагональным сине-красным градиентом (RU-мотив, НЕ триколор-полосы)
    // и белым «RU». Хардкод-цвета шара — сценические (бренд-мотив, вне палитры токенов).
    component AutoVpnIcon: Item {
        id: avIcon
        property bool active: true
        // круглая подложка — РОВНО по контуру шара (совпадающие круги); видна когда шар притушен.
        // Сам Item остаётся 52×52 для выравнивания 1:1 с иконкой карточки сервера
        Rectangle {
            width: ruBall.width; height: ruBall.height
            anchors.centerIn: parent
            radius: width / 2
            color: Qt.rgba(0x0F/255, 0x17/255, 0x2A/255, 0.8)
        }
        // круг-шар с градиентом (~87% подложки — тонкий тёмный кант; синий верх-право → красный низ-лево).
        // Ширина ЧЁТНАЯ: нечётная в чётном родителе даёт полупиксельный офсет, и слой-маска
        // снапится к пикселю не так, как кольцо → шар «уезжает» влево-вверх от контура.
        Item {
            id: ruBall
            width: 2 * Math.round(avIcon.width * 0.87 / 2); height: width
            anchors.centerIn: parent
            opacity: avIcon.active ? 1.0 : 0.4
            Behavior on opacity { NumberAnimation { duration: Theme.motion.normal } }
            layer.enabled: true
            layer.effect: Fx.OpacityMask {
                maskSource: Rectangle { width: ruBall.width; height: ruBall.height; radius: width / 2 }
            }
            Fx.LinearGradient {
                anchors.fill: parent
                start: Qt.point(width * 0.85, 0); end: Qt.point(width * 0.15, height)
                gradient: Gradient {
                    GradientStop { position: 0.0;  color: "#4E7FCB" }   // scenic: RU-шар синий
                    GradientStop { position: 0.45; color: "#4E7FCB" }
                    GradientStop { position: 1.0;  color: "#C1524E" }   // scenic: RU-шар красный
                }
            }
            Text {
                anchors.centerIn: parent
                text: "RU"; color: "white"
                font.family: Theme.font.display
                font.pixelSize: Math.round(parent.height * 0.42)
                font.weight: Theme.font.wBold
            }
        }
        // контурное кольцо вокруг шара: НЕ по самому краю (там его съедает антиалиасинг маски),
        // а с зазором 2px — тонкий читаемый контур, концентричный шару
        Rectangle {
            width: ruBall.width + 6; height: width   // чётная ширина — интовый офсет центрирования
            anchors.centerIn: parent
            radius: width / 2
            color: "transparent"
            border.width: 1; border.color: Qt.rgba(0x64/255, 0x74/255, 0x8B/255, 0.55)
        }
    }

    // ── фон ─────────────────────────────────────────────────────────────
    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // ── звёздное небо (full-bleed, верхняя зона) ────────────────────────
    Item {
        id: starField
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: 400; clip: true; z: 0   // выше = звёзды тянутся ниже, ближе к орбу
        property var starsData: []
        Component.onCompleted: {
            var arr = []
            for (var i = 0; i < 32; i++)
                arr.push({ tx: Math.random(), ty: Math.random() * 0.6,
                           s: Math.random() * 1.8 + 1, o: Math.random() * 0.6 + 0.15,
                           d: Math.random() * 2600 })
            starsData = arr
        }
        Repeater {
            model: starField.starsData
            delegate: Rectangle {
                width: modelData.s; height: modelData.s; radius: width / 2; color: "white"
                x: modelData.tx * starField.width; y: modelData.ty * starField.height
                opacity: modelData.o
                SequentialAnimation on opacity {
                    running: !Theme.motion.reduceMotion; loops: Animation.Infinite
                    NumberAnimation { from: modelData.o; to: modelData.o * 0.25; duration: 1400; easing.type: Easing.InOutSine }
                    NumberAnimation { from: modelData.o * 0.25; to: modelData.o; duration: 1400; easing.type: Easing.InOutSine }
                    PauseAnimation { duration: modelData.d }
                }
            }
        }
        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(0x1E/255, 0x3A/255, 0x8A/255, 0.10) }
                GradientStop { position: 0.55; color: "transparent" }
                GradientStop { position: 1.0; color: Theme.color.bg800 }
            }
        }
    }

    // ── header: бренд-марк + Tribe VPN + бейдж подписки ─────────────────
    Item {
        id: header
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        anchors.topMargin: 16 + root.safeTop
        anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.lg
        height: 40; z: 10

        Item {
            id: brand
            anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter
            width: brandMark.width + 10 + brandText.width
            height: brandText.height

            Row {  // brand-mark: 5 баров сигнала (пропорции лого-SVG 16/28/36/26/18), высота = капсам,
                   // низ баров — на базовой линии wordmark (одна линия с текстом)
                id: brandMark
                anchors.left: parent.left
                anchors.bottom: brandText.baseline
                spacing: 2
                Rectangle { width: 3; height: 7;  radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 12; radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 16; radius: 1.5; color: root.blueAccent;  anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 12; radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 8;  radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
            }
            Text {
                id: brandText
                anchors.left: brandMark.right; anchors.leftMargin: 10
                text: "Tribe VPN"; color: "#EEF3F9"
                font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * Theme.font.h2
            }
        }
        // AVPN: админ-вход в просмотр пула нод (server/stack, vector). Только Dev.adminMode.
        // Маленькая иконка справа от бренда; тап → requestAdminServers() → PageLocationsTribe (админ).
        Rectangle {
            id: adminServersBtn
            visible: Dev.adminMode
            anchors.left: brand.right; anchors.leftMargin: Theme.space.md
            anchors.verticalCenter: parent.verticalCenter
            width: 36; height: 36
            radius: Theme.radius.pill
            color: adminMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
            border.width: 1; border.color: Theme.color.border
            Behavior on color { ColorAnimation { duration: 160 } }
            // иконка «server/stack» (Tabler "stack", 24-grid → 22px)
            Shape {
                anchors.centerIn: parent
                width: 22; height: 22
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 1.7
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M12 3 L21 8 L12 13 L3 8 Z M3 12 L12 17 L21 12 M3 16 L12 21 L21 16" }
                }
            }
            MouseArea { id: adminMa; anchors.fill: parent; hoverEnabled: true
                cursorShape: Qt.PointingHandCursor; onClicked: root.requestAdminServers() }
        }

        // бейдж подписки + колокол уведомлений (прижаты вправо одной Row); // AVPN
        Row {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.space.md

            // бейдж подписки (одна строка): остаток трафика (real) + дни (real daysLeft).
            // тап → Профиль (заменяет шестерёнку). subActive гейтит цвет рамки.
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: statRow.width + 2 * Theme.space.lg
                height: 36
                radius: Theme.radius.pill
                color: statMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
                border.width: 1
                border.color: root.subActive ? Theme.color.border : Theme.color.warning
                Behavior on color { ColorAnimation { duration: 160 } }
                Row {
                    id: statRow
                    anchors.centerIn: parent
                    spacing: Theme.space.sm
                    Text { text: root.fmtTrafficLeft(); color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: 13; anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: 3; height: 3; radius: 1.5; color: root.slate500; anchors.verticalCenter: parent.verticalCenter }
                    Text { text: root.daysLeftText; color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: 13; anchors.verticalCenter: parent.verticalCenter }
                }
                MouseArea { id: statMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: root.requestSettings() }
            }

            // колокол уведомлений (vector Tabler "bell") + бейдж непрочитанных
            Rectangle {
                id: bellBtn
                anchors.verticalCenter: parent.verticalCenter
                width: 36; height: 36
                radius: Theme.radius.pill
                color: bellMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
                border.width: 1; border.color: Theme.color.border
                Behavior on color { ColorAnimation { duration: 160 } }
                Shape {
                    anchors.centerIn: parent
                    width: 22; height: 22
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 1.7
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M6 8 a6 6 0 0 1 12 0 c0 7 3 9 3 9 H3 s3 -2 3 -9z M10.5 21 a2 2 0 0 0 3 0" }
                    }
                }
                // бейдж непрочитанных (красный кружок с числом)
                Rectangle {
                    visible: root.unreadCount > 0
                    width: 16; height: 16; radius: 8
                    color: Theme.color.danger
                    anchors.right: parent.right; anchors.top: parent.top
                    anchors.rightMargin: -2; anchors.topMargin: -2
                    Text {
                        anchors.centerIn: parent
                        text: root.unreadCount > 9 ? "9+" : String(root.unreadCount)
                        color: "#FFFFFF"
                        font.family: Theme.font.body; font.pixelSize: 10; font.weight: Theme.font.wBold
                    }
                }
                MouseArea { id: bellMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: root.requestNotifications() }
            }
        }
    }

    // ── карточка «АвтоVPN» — НАД кнопкой Connect (перенос из bottomBlock, реш. 2026-07-02):
    //    РФ-сайты всегда работают (единый тумблер РФ-доступа AvpnBypass/masterOn) ──
    Rectangle {
        id: autoVpnCard
        anchors.top: header.bottom; anchors.topMargin: Theme.space.lg
        anchors.left: parent.left; anchors.right: parent.right
        anchors.leftMargin: root.isMobile ? Theme.space.xl : Theme.space.lg
        anchors.rightMargin: root.isMobile ? Theme.space.xl : Theme.space.lg
        implicitHeight: 68; height: 68   // ниже серверной карточки (84) — компактный баннер
        radius: Theme.radius.xl
        color: Qt.rgba(0x1E/255, 0x29/255, 0x3B/255, 0.40)
        border.width: 1; border.color: Qt.rgba(0x33/255, 0x41/255, 0x55/255, 0.5)
        z: 10
        Item {
            anchors.fill: parent; anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
            AutoVpnIcon {
                id: avCardIcon
                width: 52; height: 52
                anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter
                active: bypassStore.masterOn
            }
            TribeToggle {
                id: avCardToggle
                anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter
                checked: bypassStore.masterOn
                // тост при переключении убран (реш. 2026-07-02) — состояние видно по текстовке баннера
                onToggled: {
                    // bypassStore (QML Settings) флашится с задержкой ~500 мс — для UI-биндингов этого
                    // достаточно, но движок читает QSettings РАНЬШЕ (teardown быстрее записи). Поэтому
                    // значение передаём явно: setBypassMasterOn пишет синхронно и передёргивает туннель.
                    bypassStore.masterOn = checked
                    if (root.hasEngine) TribeEngine.setBypassMasterOn(checked)
                }
            }
            Column {
                // отступы уже (md/sm, не lg/md) — обе текстовки влезают без обрезки // AVPN
                anchors.left: avCardIcon.right; anchors.leftMargin: Theme.space.md
                anchors.right: avCardToggle.left; anchors.rightMargin: Theme.space.sm
                anchors.verticalCenter: parent.verticalCenter
                spacing: 0   // подзаголовок вплотную к заголовку (реш. 2026-07-02)
                // текстовки зависят от тумблера (реш. 2026-07-02): off = оффер, on = подтверждение
                Text {
                    width: parent.width
                    text: bypassStore.masterOn ? qsTr("AntiVPN активирован!")
                                               : qsTr("Надоело выключать VPN?")
                    color: "white"; elide: Text.ElideRight
                    fontSizeMode: Text.HorizontalFit; minimumPixelSize: 10
                    font.family: Theme.font.display; font.pixelSize: 16; font.weight: Theme.font.wBold
                }
                Text {
                    width: parent.width
                    text: bypassStore.masterOn ? qsTr("Теперь VPN выключать не нужно.")
                                               : qsTr("Ozon, WB, Госуслуги, Банки, Kinopoisk")
                    color: root.slate500; elide: Text.ElideRight
                    fontSizeMode: Text.HorizontalFit; minimumPixelSize: 9
                    font.family: Theme.font.body; font.pixelSize: 11
                }
            }
        }
    }

    // ── ОРБ (центрирован, z10) ──────────────────────────────────────────
    Item {
        id: orb
        width: 256; height: 256
        anchors.horizontalCenter: parent.horizontalCenter
        // якорь ПОД карточкой «АвтоVPN»: внешнее кольцо (r=160) выступает на 32px за Item орба
        // (256×256), поэтому марджин = 32 + видимый зазор lg от кольца до карточки.
        // Десктоп: добавочный сдвиг 16 (итерации 2026-07-02: 36 → 0 после тайтлбара → 16 финал) —
        // сцена чуть ниже, но подпись НЕ заходит на круг. // AVPN
        anchors.top: autoVpnCard.bottom
        anchors.topMargin: 32 + Theme.space.lg + (root.isMobile ? root.sceneShift : 16)
        z: 10

        // внешнее свечение (КРУГЛОЕ — задаём радиусы = половине ширины, иначе квадрат)
        Fx.RadialGradient {
            anchors.centerIn: parent
            width: 360; height: 360
            horizontalRadius: width / 2
            verticalRadius: height / 2
            scale: root.isOn ? 1.2 : (root.isBusy ? 1.1 : 1.0)
            Behavior on scale { NumberAnimation { duration: 700; easing.type: Easing.InOutSine } }
            SequentialAnimation on opacity {
                running: root.isBusy && !Theme.motion.reduceMotion; loops: Animation.Infinite
                NumberAnimation { from: 0.6; to: 0.3; duration: 700 }
                NumberAnimation { from: 0.3; to: 0.6; duration: 700 }
            }
            opacity: root.isOn ? 0.5 : (root.isBusy ? 0.6 : 0.22)
            gradient: Gradient {
                GradientStop { position: 0.0;  color: root.isOn ? root.blueAccent : (root.isBusy ? root.blue400 : Qt.rgba(1,1,1,1)) }
                GradientStop { position: 0.42; color: root.isOn ? Qt.rgba(0x3E/255,0x80/255,0xED/255,0.45) : Qt.rgba(1,1,1,0.22) }
                GradientStop { position: 0.72; color: "transparent" }
                GradientStop { position: 1.0;  color: "transparent" }
            }
        }

        // ── КОНЦЕНТРИЧЕСКИЕ КОНТУРЫ (5 шт; шаг и толщина ПЛАВНО УБЫВАЮТ к центру) ──
        // Радиусы 160 / 138 / 119 / 102 / 87 → gap 22/19/17/15 (к центру меньше).
        // r=119 ≈ периметр кнопки (240) — самый заметный, ЧУТЬ толще; по нему идёт дуга-спиннер.
        // Рендер через Shape (CurveRenderer) — гарантированно гладкие круги (не ломаные линии).
        // Белые контуры, все тонкие/неброские, ярче на синей кнопке. Хардкоды — сценические. // AVPN (scenic)
        property bool ringActive: root.isBusy

        // 2 ВНЕШНИХ контура (вне кнопки) — под сферой.
        Shape {
            anchors.centerIn: parent; width: 340; height: 340
            preferredRendererType: Shape.CurveRenderer; antialiasing: true
            ShapePath { fillColor: "transparent"; strokeWidth: 0.75            // r1 внешний (самый бледный)
                strokeColor: Qt.rgba(1,1,1, root.isOn ? 0.14 : 0.10)
                PathAngleArc { centerX: 170; centerY: 170; radiusX: 160; radiusY: 160; startAngle: 0; sweepAngle: 360 } }
            ShapePath { fillColor: "transparent"; strokeWidth: 0.9             // r2
                strokeColor: Qt.rgba(1,1,1, root.isOn ? 0.18 : 0.12)
                PathAngleArc { centerX: 170; centerY: 170; radiusX: 138; radiusY: 138; startAngle: 0; sweepAngle: 360 } }
        }

        // основная сфера (кнопка) — белая (idle/connecting) / синяя (connected)
        Rectangle {
            id: sphere
            anchors.centerIn: parent
            width: 240; height: 240; radius: 120
            gradient: Gradient {
                GradientStop { position: 0.0; color: root.isOn ? root.blue300 : "white" }
                GradientStop { position: 1.0; color: root.isOn ? root.blue600 : "#F1F5F9" }
            }
            scale: orbMa.pressed ? 0.97 : 1.0
            Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
        }

        // 3-й (ПЕРИМЕТР кнопки, r=119) + 2 ВНУТРЕННИХ контура — ПОВЕРХ кнопки (видны на синей).
        Shape {
            anchors.centerIn: parent; width: 256; height: 256
            preferredRendererType: Shape.CurveRenderer; antialiasing: true
            ShapePath { fillColor: "transparent"; strokeWidth: 1.25           // r3 периметр — чуть толще, самый заметный
                strokeColor: Qt.rgba(1,1,1, root.isOn ? 0.34 : 0.16)
                PathAngleArc { centerX: 128; centerY: 128; radiusX: 119; radiusY: 119; startAngle: 0; sweepAngle: 360 } }
            ShapePath { fillColor: "transparent"; strokeWidth: 0.9            // r4 внутр.
                strokeColor: Qt.rgba(1,1,1, root.isOn ? 0.20 : 0.08)
                PathAngleArc { centerX: 128; centerY: 128; radiusX: 102; radiusY: 102; startAngle: 0; sweepAngle: 360 } }
            ShapePath { fillColor: "transparent"; strokeWidth: 0.75           // r5 внутр. — гаснет к центру
                strokeColor: Qt.rgba(1,1,1, root.isOn ? 0.12 : 0.05)
                PathAngleArc { centerX: 128; centerY: 128; radiusX: 87; radiusY: 87; startAngle: 0; sweepAngle: 360 } }
        }

        // Вращающаяся дуга-спиннер ИДЁТ ПО 3-му контуру (периметр кнопки, r=119) — только connecting.
        // КОНУСОМ: голова толстая (5px) → к хвосту всё тоньше (0.5px). Цвет сплошной blue300 (без прозрачности).
        // Толщину вдоль штриха QML не сужает → набираем дугу из сегментов с убывающей strokeWidth.
        Item {
            id: spinnerArc
            anchors.centerIn: parent; width: 256; height: 256
            visible: orb.ringActive
            readonly property int  segs: 28
            readonly property real span: 180          // суммарный угол дуги, ° (50% круга)
            readonly property real step: span / segs
            readonly property real headW: 6.5   // голова чуть толще (было 5.0)
            readonly property real tailW: 1.0   // хвост тоже чуть плотнее (было 0.5)
            Repeater {
                model: spinnerArc.segs
                Shape {
                    anchors.fill: parent
                    preferredRendererType: Shape.CurveRenderer; antialiasing: true
                    ShapePath {
                        fillColor: "transparent"; strokeColor: root.blue300; capStyle: ShapePath.RoundCap
                        // index 0 = ХВОСТ (тонкий, сзади) → последний = ГОЛОВА (толстая, по ходу движения CW)
                        strokeWidth: spinnerArc.tailW + (spinnerArc.headW - spinnerArc.tailW) * (index / (spinnerArc.segs - 1))
                        PathAngleArc {
                            centerX: 128; centerY: 128; radiusX: 119; radiusY: 119
                            startAngle: -90 + index * spinnerArc.step
                            sweepAngle: spinnerArc.step + 0.8     // лёгкое перекрытие — без швов (штрих непрозрачный)
                        }
                    }
                }
            }
            RotationAnimation on rotation {
                running: orb.ringActive && !Theme.motion.reduceMotion
                from: 0; to: 360; duration: 1050; loops: Animation.Infinite
            }
        }

        Text {
            anchors.centerIn: parent; z: 40
            text: root.isBusy ? "Connecting…" : (root.isOn ? "Connected" : "Connect")
            color: root.isOn ? "white" : root.slate900
            font.family: Theme.font.display; font.pixelSize: 26; font.weight: Theme.font.wBold
        }

        MouseArea { id: orbMa; anchors.fill: sphere; cursorShape: Qt.PointingHandCursor; onClicked: root.onOrbClicked() }
    }

    // ── ГОРЫ (FULL-BLEED, 1:1 с эталонным React-макетом: 3 слоя, каждый —
    //    градиент, растворяющийся в фон #0A111D к нижней кромке) ───────────
    Item {
        id: mtn
        anchors.left: parent.left; anchors.right: parent.right
        anchors.top: orb.top; anchors.topMargin: 88   // top-[120px] макета при орбе на +32
        height: 250; z: 20
        Shape {
            width: 1000; height: 320
            transform: Scale { xScale: mtn.width / 1000; yScale: 250 / 320 }
            preferredRendererType: Shape.CurveRenderer
            // дальний misty-план (farMountainGrad). SVG-градиенты в эталоне привязаны к bbox
            // КАЖДОГО слоя (objectBoundingBox), поэтому y1 = вершина слоя, не 0.
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 130; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x1E/255,0x29/255,0x3B/255,0.35) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,200 L 100,160 L 200,190 L 320,140 L 410,180 L 500,130 L 590,180 L 680,140 L 820,180 L 920,150 L 1000,180 L 1000,320 L 0,320 Z" }
            }
            // средний план (midMountainGrad)
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 150; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x1E/255,0x24/255,0x30/255,0.75) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,240 L 120,190 L 240,230 L 350,165 L 430,200 L 500,150 L 570,200 L 660,160 L 780,210 L 900,170 L 1000,200 L 1000,320 L 0,320 Z" }
            }
            // передний план (frontMountainGrad) — тоже градиент, НЕ сплошной.
            // Левый склон (550,220→640,180) ПАРАЛЛЕЛЕН подъёму среднего (570,200→660,160),
            // отступ 20 — скала «вписана в силуэт тени», грани не пересекаются (эталон 2026-06-10).
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 170; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x15/255,0x1B/255,0x28/255,0.90) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,280 L 150,230 L 280,260 L 380,190 L 450,220 L 500,170 L 550,220 L 640,180 L 750,240 L 880,200 L 1000,240 L 1000,320 L 0,320 Z" }
            }
        }
    }

    // подпись под орбом (поверх гор)
    Text {
        id: connectCaption
        anchors.horizontalCenter: parent.horizontalCenter
        // мобайл: чуть ниже орба; десктоп: ровно на lg ВЫШЕ карточки — тот же зазор, что чипы↔карточка // AVPN
        anchors.top: root.isMobile ? orb.bottom : undefined
        anchors.topMargin: 30
        anchors.bottom: root.isMobile ? undefined : bottomBlock.top
        anchors.bottomMargin: Theme.space.lg
        z: 30; horizontalAlignment: Text.AlignHCenter
        text: root.isOn ? qsTr("Защита активна — ваше соединение безопасно")
                        : qsTr("Подключиться — нажмите кнопку выше")
        color: root.slate400
        font.family: Theme.font.body; font.pixelSize: Theme.font.monoData; font.weight: Theme.font.wMedium
    }

    // ── низ: карточка сервера + кнопка обновить (z30 — выше основания гор) ──
    Column {
        id: bottomBlock
        anchors.bottom: parent.bottom; anchors.left: parent.left; anchors.right: parent.right
        anchors.bottomMargin: Theme.space.lg
        // десктоп: боковые отступы чуть меньше (lg вместо xl) — чипам/карточке больше ширины // AVPN
        anchors.leftMargin: root.isMobile ? Theme.space.xl : Theme.space.lg
        anchors.rightMargin: root.isMobile ? Theme.space.xl : Theme.space.lg
        spacing: Theme.space.lg
        z: 30

        // карточка сервера — тап открывает шторку выбора сервера (TribeNodeSheet). // AVPN
        // (карточка «АвтоVPN» перенесена НАД орб — см. autoVpnCard выше, реш. 2026-07-02)
        Rectangle {
            id: serverCard
            width: parent.width; implicitHeight: 84; height: 84
            radius: 24
            color: Qt.rgba(0x1E/255, 0x29/255, 0x3B/255, 0.40)
            border.width: 1; border.color: Qt.rgba(0x33/255, 0x41/255, 0x55/255, 0.5)
            // press-scale (как у кнопок) — тактильный отклик при тапе по карточке
            scale: serverCardMa.pressed ? 0.985 : 1.0
            Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }
            Item {
                anchors.fill: parent; anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                // якорная раскладка (не Row-позиционер): флаг слева, сигнал-блок справа с симметричным
                // отступом lg, имя/IP — между ними. // AVPN
                // иконка региона: КРУГЛЫЙ флаг по country_code «во всю плашку» (SVG из flagKit,
                // не эмодзи), иначе тёмная плашка с Tabler "world".
                TribeFlag {
                    id: regionFlag
                    width: 52; height: 52
                    anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter
                    code: root.curNode.hasNode ? (root.curNode.countryCode || "") : ""
                    fallback: Component {
                        Rectangle {
                            radius: width / 2
                            color: Qt.rgba(0x0F/255,0x17/255,0x2A/255,0.8)
                            border.width: 1; border.color: Qt.rgba(0x33/255,0x41/255,0x55/255,0.5)
                            Shape {
                                anchors.centerIn: parent; width: 26; height: 26
                                preferredRendererType: Shape.CurveRenderer
                                ShapePath {
                                    strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 1.8
                                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                    PathSvg { path: "M13 2 a11 11 0 1 0 0.01 0z M2 13 h22 M13 2 a16 16 0 0 1 0 22 a16 16 0 0 1 0 -22z" }
                                }
                            }
                        }
                    }
                }
                // имя+бары (верхняя строка) и IP+мс (нижняя строка) — ДВЕ выровненные строки:
                // бары РОВНО над именем, мс РОВНО на линии IP и ТОГО ЖЕ размера (mono 10). // AVPN
                Column {
                    id: infoCol
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.left: regionFlag.right; anchors.leftMargin: Theme.space.lg
                    anchors.right: parent.right
                    spacing: 3

                    // палочки/мс показываем ТОЛЬКО когда подключены к живому узлу. // AVPN
                    readonly property bool sig: root.isOn && root.curNode.hasNode
                    readonly property bool reachable: root.hasEngine && TribeEngine.liveReachable === true
                    // мёртвая связь = движок подтвердил неудачу пробы (kLiveDeadStreak подряд). // AVPN
                    readonly property bool dead: root.hasEngine && TribeEngine.liveDead === true

                    // ── верхняя строка: имя сервера (+бейдж auto) слева, палочки справа ──
                    Item {
                        width: parent.width
                        height: nameRow.implicitHeight
                        Row {
                            id: nameRow
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.right: infoCol.sig ? topBars.left : parent.right
                            anchors.rightMargin: infoCol.sig ? Theme.space.md : 0
                            spacing: Theme.space.sm
                            Text {
                                id: nodeName
                                text: root.curNode.hasNode ? (root.curNode.name || root.curNode.region) : qsTr("Умный выбор сервера")
                                color: "white"; elide: Text.ElideRight
                                // оставляем место под бейдж, чтобы имя не наезжало на него
                                width: Math.min(implicitWidth, parent.width - (autoBadge.visible ? autoBadge.width + Theme.space.sm : 0))
                                font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                            }
                            // нежный blue-accent бейдж «auto» (виден ТОЛЬКО при auto-подключении). // AVPN
                            Rectangle {
                                id: autoBadge
                                visible: root.curNode.auto === true
                                anchors.verticalCenter: nodeName.verticalCenter
                                height: 20; width: autoLabel.implicitWidth + 2 * Theme.space.sm
                                radius: Theme.radius.pill
                                color: Qt.rgba(0x7C/255, 0xA2/255, 0xD0/255, 0.16)
                                border.width: 1; border.color: Qt.rgba(0x7C/255, 0xA2/255, 0xD0/255, 0.45)
                                Text {
                                    id: autoLabel
                                    anchors.centerIn: parent
                                    text: qsTr("auto")
                                    color: Theme.color.accent
                                    font.family: Theme.font.body; font.pixelSize: 11; font.weight: Theme.font.wBold
                                }
                            }
                        }
                        LoadBars {
                            id: topBars
                            visible: infoCol.sig
                            anchors.right: parent.right
                            anchors.verticalCenter: nameRow.verticalCenter
                            // мёртвая связь → 0 зелёных + красные; иначе мин. 1 зелёная, reachable уточняет 1..5. // AVPN
                            failed: infoCol.dead
                            level: infoCol.dead ? 0 : (infoCol.reachable ? Math.max(1, Number(TribeEngine.liveBars)) : 1)
                        }
                    }

                    // ── нижняя строка: IP слева, мс справа (тот же размер/линия) ──
                    Item {
                        width: parent.width
                        height: ipText.implicitHeight
                        Text {
                            id: ipText
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.right: msText.visible ? msText.left : parent.right
                            anchors.rightMargin: msText.visible ? Theme.space.md : 0
                            elide: Text.ElideRight
                            text: root.curNode.hasNode ? ("IP: " + root.curNode.ip) : qsTr("Сервис запускает узел")
                            color: root.slate500
                            font.family: Theme.font.mono; font.pixelSize: 10
                        }
                        // число мс — на линии IP, того же размера; виден, когда проба дошла. // AVPN
                        Text {
                            id: msText
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            visible: infoCol.sig && infoCol.reachable && Number(TribeEngine.liveRttMs) >= 0
                            text: (root.hasEngine ? Number(TribeEngine.liveRttMs) : 0) + qsTr(" мс")
                            color: root.slate500
                            font.family: Theme.font.mono; font.pixelSize: 10
                        }
                    }
                }
            }
            // тап по всей карточке → шторка выбора сервера (живые узлы пула). Шеврон убран. // AVPN
            MouseArea {
                id: serverCardMa
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: nodeSheet.open()
            }
        }

        // ── чипы доступности сервисов ЧЕРЕЗ текущую ноду (Telegram/YouTube/Instagram) ──
        // Замер с устройства через туннель (ServiceProbe): 🟢 работает / 🟡 медленно(троттл) / 🔴 заблок.
        // Тап по чипу → перепроверить. Видны ВСЕГДА (и ДО подключения / в авто-режиме) — чтобы раскладка
        // не «прыгала»: до коннекта статусы -1 (серый дот «…») + приглушённая прозрачность = неактивны;
        // тап перепроверяет только когда подключены. // AVPN
        TribeServiceChips {
            width: parent.width
            visible: root.hasEngine
                     && TribeEngine.serviceStatus !== undefined && TribeEngine.serviceStatus.length > 0
            opacity: root.isOn ? 1.0 : 0.4   // не подключены → серые/неактивные
            model: root.hasEngine ? TribeEngine.serviceStatus : []
            onRecheck: if (root.hasEngine && root.isOn) TribeEngine.probeServices()
        }
        // AVPN: редкий авто-self-heal чипов, пока подключены. Чипы youtube/instagram теперь GOODPUT
        // (качают ~128 КБ каждый), а статус цензуры/троттлинга меняется медленно (не раз в секунды) —
        // поэтому 3 мин, а не 12с (иначе лишний фоновый трафик). Мгновенно — тап по чипу (onRecheck).
        // Движок делает первую пробу при коннекте (~1.5с, DNS-warm). При обрыве таймер стоит (running←isOn).
        Timer {
            interval: 180000
            repeat: true
            running: root.isOn && root.hasEngine
            onTriggered: TribeEngine.probeServices()
        }

        // ── нижний слот: два состояния одной геометрии (52/lg) ──────────────
        // subExpired → ЗОЛОТАЯ кнопка «Получить ключ» (CTA, монетизация).
        // иначе      → кнопка «Обновить подключение» (ротация ноды).
        // ────────────────────────────────────────────────────────────────────

        // ЗОЛОТАЯ CTA «Обновить ключ» — в личный кабинет с JWT-авторизацией (триал исчерпан). // AVPN
        Rectangle {
            id: ctaBtn
            visible: root.subExpired
            width: parent.width; height: 52; radius: Theme.radius.lg
            gradient: Gradient {
                GradientStop { position: 0.0; color: ctaMa.pressed ? Theme.color.ctaDeep : Theme.color.cta }
                GradientStop { position: 1.0; color: Theme.color.ctaDeep }
            }
            scale: ctaMa.pressed ? 0.985 : 1.0
            Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
            Row {
                anchors.centerIn: parent; spacing: 10
                // иконка ключа (lucide "key-round", 24-grid → 20px)
                Shape {
                    width: 20; height: 20; anchors.verticalCenter: parent.verticalCenter
                    transform: Scale { xScale: 20/24; yScale: 20/24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath { strokeColor: Theme.color.bg900; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M2.586 17.414 A2 2 0 0 0 2 18.828 V21 a1 1 0 0 0 1 1 h3 a1 1 0 0 0 1 -1 v-1 a1 1 0 0 1 1 -1 h1 a1 1 0 0 0 1 -1 v-1 a1 1 0 0 1 1 -1 h.172 a2 2 0 0 0 1.414 -.586 l.814 -.814 a6.5 6.5 0 1 0 -4 -4z M15.5 7.5 a.5 .5 0 1 0 .01 0z" } }
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.ctaTrafficOnly ? qsTr("Продлить трафик") : qsTr("Обновить ключ")
                    color: Theme.color.bg900
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM; font.weight: Theme.font.wBold
                }
            }
            MouseArea {
                id: ctaMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onClicked: {
                    // Оплата — ВНЕШНИЙ сайт (Apple §10: в апке нет цен/IAP). Одноразовый web-link
                    // (POST /v1/cabinet/web-link, авто-логин, TTL ~90с) вместо JWT в query —
                    // долгоживущий токен не светится в истории браузера/логах. device_uuid дописывает
                    // движок (дни зачислятся на ЭТО устройство). Ошибка/нет движка → голый кабинет. // AVPN
                    if (root.hasEngine && typeof TribeEngine.requestCabinetLink === "function") {
                        if (root.ctaLinking) return
                        root.ctaLinking = true
                        TribeEngine.requestCabinetLink()  // ответ всегда придёт в onCabinetLinkReady
                    } else {
                        Qt.openUrlExternally("https://tribevpn.com/account")
                    }
                }
            }
        }

        // кнопка «Обновить коннект» → round-robin на следующую живую ноду (TribeEngine.rotateNext,
        // круговой обход от текущей с заворотом). Активна только при подключении; на время свитча — busy. // AVPN
        Rectangle {
            id: refreshBtn
            visible: !root.subExpired
            width: parent.width; height: 52; radius: 16
            // ротация осмысленна только когда туннель поднят; иначе приглушаем
            opacity: (root.hasEngine && !root.isOn) ? 0.45 : 1.0
            color: refreshMa.containsMouse ? Qt.rgba(0x1E/255,0x29/255,0x3B/255,0.5) : "transparent"
            border.width: 1
            border.color: refreshMa.containsMouse ? Qt.rgba(0x3E/255,0x80/255,0xED/255,0.5) : Qt.rgba(0x33/255,0x41/255,0x55/255,0.8)
            Behavior on color { ColorAnimation { duration: 160 } }
            Row {
                anchors.centerIn: parent; spacing: 10
                // иконка обновления (Tabler refresh, 24-grid → ровно в 20px, по центру).
                // На время свитча — бесконечное вращение. // AVPN
                Shape {
                    id: refreshIcon
                    // 24×24 = система координат путей (24-сетка) → Item.Center=(12,12)=центр иконки.
                    // scale-конвенс (а НЕ transform:Scale{origin 0,0}) → и масштаб, и вращение вокруг
                    // центра → крутится ровно вокруг своей оси, без биения. // AVPN
                    width: 24; height: 24; anchors.verticalCenter: parent.verticalCenter
                    scale: 20/24; transformOrigin: Item.Center
                    preferredRendererType: Shape.CurveRenderer
                    RotationAnimation on rotation {
                        running: root.hasEngine && TribeEngine.busy && !Theme.motion.reduceMotion
                        from: 0; to: 360; duration: 900; loops: Animation.Infinite
                    }
                    ShapePath { strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M20 11 a8.1 8.1 0 0 0 -15.5 -2 M4 5 v4 h4" } }
                    ShapePath { strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M4 13 a8.1 8.1 0 0 0 15.5 2 M20 19 v-4 h-4" } }
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    // AVPN: «Подбираем сервер…» ТОЛЬКО в авто-режиме (узел выбирает движок). При РУЧНОМ
                    // выборе (curNode.pinned) сервер уже задан — показываем «Подключаемся…», не «подбираем».
                    text: !(root.hasEngine && TribeEngine.busy) ? qsTr("Сменить сервер")
                          : (root.curNode.pinned === true ? qsTr("Подключаемся…") : qsTr("Подбираем сервер…"))
                    color: "#DBEAFE"; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium
                }
            }
            MouseArea {
                id: refreshMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onClicked: {
                    if (!root.hasEngine) return
                    if (TribeEngine.busy) return
                    if (!root.isOn) {     // не подключены — обычный старт вместо ротации
                        TribeEngine.start()
                        return
                    }
                    TribeEngine.rotateNext()   // round-robin на следующую живую ноду (заворот) // AVPN
                }
            }
        }
    }

    // AVPN (live-node picker): шторка выбора сервера. z выше bottomBlock (z:30) → перекрывает сцену.
    TribeNodeSheet {
        id: nodeSheet
        z: 200
    }

}

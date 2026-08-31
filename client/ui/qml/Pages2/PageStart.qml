import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Shapes
import QtCore                 // AVPN: Settings (флаг пройденного онбординга)

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"
import "../Tribe"              // AVPN: singletons Theme + Dev (admin/amnezia-режимы)
import "../Tribe/components"   // AVPN: TribeBottomNav (наша навигация)

PageType {
    id: root

    property bool isControlsDisabled: false
    property bool isTabBarDisabled: false

    // AVPN: наша нижняя навигация вместо Amnezia TabBar; Dev.amneziaMode переключает
    // на ПОЛНЫЙ ванильный интерфейс (их TabBar + страницы), возврат — кнопка «‹ Tribe».
    readonly property bool avpnNav: !Dev.amneziaMode

    // AVPN: первый запуск (нет серверов + онбординг не пройден) → наш PageOnboardingTribe,
    // а не ванильный wizard. После «Приступим» (requestStart) попадаем на наш Connect.
    // onboardingActive ставится императивно в точках роутинга (isStartPageVisible — не реактивный).
    Settings { id: avpnOnboard; category: "AvpnOnboarding"; property bool done: false }
    property bool onboardingActive: false

    // AVPN: страница ОДНОЙ из наших вкладок (или онбординг) — в отличие от overlay-страниц
    // (Legal/Admin/Notifications/Locations), системный «назад» на них ведёт себя по-старому.
    function isAvpnTabPage(pageName) {
        var s = pageName.toString()
        return s.indexOf("PageConnectTribe.qml") !== -1 || s.indexOf("PageSupportTribe.qml") !== -1
            || s.indexOf("PageReferralTribe.qml") !== -1 || s.indexOf("PageAccountTribe.qml") !== -1
            || s.indexOf("PageOnboardingTribe.qml") !== -1
    }

    // AVPN (клавиатура): imeHeight = цель, приходит с willShow (старт анимации клавиатуры);
    // margin анимирует Behavior ниже. Фокус-срез (inputFocused страницы) прячет навбар
    // СРАЗУ по тапу в поле. Qt.inputMethod.visible — страховка от «застрявшего» imeHeight
    // (меню пропадало). Вся схема — ТОЛЬКО сенсорные платформы (PLATFORM-SCOPING).
    readonly property bool kbPlatform: Qt.platform.os === "ios" || Qt.platform.os === "android"
    readonly property bool kbActive: kbPlatform &&
        ((PageController.imeHeight > 0 && Qt.inputMethod.visible)
         || (tabBarStackView.currentItem && tabBarStackView.currentItem.inputFocused === true))

    // Смена вкладки с открытой клавиатурой: margin схлопывается МГНОВЕННО (без Behavior) —
    // иначе 500мс-анимация доигрывалась уже на новой странице и её контент «съезжал
    // сверху вниз» (жалоба 2026-07-13: свайп-назад из чата → блок кнопок Главной едет).
    property bool kbInstant: false
    Timer { id: kbInstantReset; interval: 600; onTriggered: root.kbInstant = false }

    // AVPN: единый роутер наших вкладок (0 Главная / 1 Поддержка / 2 Рефералка / 3 Настройки=Профиль).
    function goAvpnTab(index) {
        if (PageController.imeHeight > 0 || Qt.inputMethod.visible) {
            root.kbInstant = true
            kbInstantReset.restart()
        }
        Qt.inputMethod.hide()   // смена вкладки с открытой клавиатурой: спрятать ЯВНО,
                                // иначе imeHeight мог застрять и навбар не возвращался
        avpnBottomNav.currentIndex = index
        if (index === 1)
            tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageSupportTribe.qml")
        else if (index === 2)
            tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageReferralTribe.qml")
        else if (index === 3)
            tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageAccountTribe.qml")
        else
            tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageConnectTribe.qml")
    }

    // AVPN (Support): тап по APNs-пушу «ответ поддержки» → сразу в чат (вкладка 1).
    Connections {
        target: (typeof AvpnPush !== "undefined") ? AvpnPush : null
        ignoreUnknownSignals: true
        function onPushTapped(type) {
            AvpnPush.takePendingPushTap()   // сигнал обработан — pending-копию гасим
            if (type === "support" && root.avpnNav && !root.onboardingActive)
                root.goAvpnTab(1)
        }
    }

    // AVPN: Connect-экран просит переключить вкладку / открыть настройки.
    Connections {
        target: tabBarStackView ? tabBarStackView.currentItem : null
        ignoreUnknownSignals: true
        function onRequestTab(index) { root.goAvpnTab(index) }
        function onRequestSettings() { root.goAvpnTab(3) }
        // AVPN (store-flow): чат поддержки с черновиком в composer (кнопка «Написать в поддержку»
        // у карточки активации). Черновик передаём свойством страницы — отправляет юзер сам.
        function onRequestSupportChat(draft) {
            avpnBottomNav.currentIndex = 1
            tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageSupportTribe.qml", { prefillDraft: draft })
        }
        // AVPN: колокол → центр уведомлений (#3). Тот же сигнал шлёт деталь уведомления
        // («назад» с неё — в центр, не на Connect).
        function onRequestNotifications() { tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageNotificationsTribe.qml") }
        // AVPN (read per-элемент): тап по карточке в центре → полноэкранная деталь уведомления
        // (снапшот данных передаём свойством страницы, как docKey у PageLegalTribe).
        function onRequestNotificationDetail(notif) {
            tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageNotificationDetailTribe.qml", { notif: notif })
        }
        // AVPN: «назад» с уведомлений/админ-пула. Эти страницы открыты через replace (depth=1), поэтому
        // PageController.closePage() уходил в ветку depth<=1 → hideWindow() (прятал окно). Возвращаем на Connect.
        function onBack() { root.goAvpnTab(0) }
        // AVPN: админ-вход (Dev.adminMode) → просмотр пула нод (#5)
        function onRequestAdminServers() { tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageLocationsTribe.qml") }
        // AVPN (server picker): страница выбора сервера (замена шторки TribeNodeSheet)
        function onRequestServerPicker() { tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageServersTribe.qml") }
        // Тап по стране: СНАЧАЛА уход на Connect, ПОТОМ движок (CONNECT-INVARIANTS §5).
        // pinAndReconnect сам решает: онлайн → stop→start (путь rotateNext); офлайн → только пин;
        // kill-switch picker_instant_reconnect=false → старая семантика switchToNode.
        function onPickNode(nodeId) {
            root.goAvpnTab(0)
            if (typeof TribeEngine !== "undefined") TribeEngine.pinAndReconnect(nodeId)
        }
        // «Авто» со страницы выбора: онлайн + флаг → reprobe (перевыбор + реконнект);
        // иначе selectAuto (пин снят, намерение OFF — §4)
        function onPickAuto() {
            root.goAvpnTab(0)
            if (typeof TribeEngine === "undefined") return
            const st = TribeEngine.state
            const online = (st === "connected" || st === "connecting"
                            || st === "switching" || st === "selecting")
            if (online && TribeEngine.featureEnabled("picker_instant_reconnect", true))
                TribeEngine.reprobe()
            else
                TribeEngine.selectAuto()
        }
        // AVPN: «Панель администратора» (низ настроек, Dev.adminPanelVisible) → бенч соединения
        function onRequestAdminPanel() { tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageAdminTribe.qml") }
        // AVPN (Доктор v1): любая страница просит попап диагностики (главная/чат)
        function onRequestDoctor() { doctorSheet.show() }
        // AVPN in-app Legal: Privacy/Terms внутри приложения (кэш+fallback, без выброса в браузер)
        function onRequestLegalDoc(doc) { tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageLegalTribe.qml", { docKey: doc }) }
        // AVPN: онбординг пройден («Приступим») → запоминаем и уводим на Connect
        function onRequestStart() {
            avpnOnboard.done = true
            root.onboardingActive = false
            // AVPN (announce-quiet): отметка времени для тихого окна попапов — синхронно в
            // движке (НЕ QML Settings: его 500мс-флаш опоздал бы к announceShowTimer 900мс)
            if (typeof TribeEngine !== "undefined" && typeof TribeEngine.markOnboardingDone === "function")
                TribeEngine.markOnboardingDone()
            root.goAvpnTab(0)
            announceShowTimer.restart()   // AVPN (P-ANN): рассылка, ждавшая онбординг
        }
        // AVPN: мост в ПОЛНЫЙ интерфейс Amnezia — ванильный TabBar + их главная;
        // возврат — плавающая кнопка «‹ Tribe» (низ экрана).
        function onRequestAmnezia() {
            Dev.amneziaMode = true
            tabBar.visible = true
            ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
            tabBarStackView.goToTabBarPage(PageEnum.PageHome)
            tabBar.currentIndex = 0
        }
    }

    Connections {
        objectName: "pageControllerConnection"

        target: PageController

        function onGoToPageHome() {
            // AVPN: наш флоу — онбординг только на первом запуске, дальше всегда наш Connect
            if (root.avpnNav) {
                if (PageController.isStartPageVisible() && !avpnOnboard.done) {
                    root.onboardingActive = true
                    tabBar.visible = false
                    tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageOnboardingTribe.qml")
                } else {
                    root.onboardingActive = false
                    tabBar.visible = true
                    tabBar.setCurrentIndex(0)
                    if (!PageController.isStartPageVisible())
                        ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
                    root.goAvpnTab(0)
                    // AVPN (Support): cold start ТАПОМ по пушу — сигнал pushTapped ушёл до
                    // создания QML, тип ждёт в мосте. Забираем после штатного роутинга.
                    if (typeof AvpnPush !== "undefined"
                            && AvpnPush.takePendingPushTap() === "support")
                        root.goAvpnTab(1)
                }
                return
            }
            // AVPN: amneziaMode → ванильный флоу
            if (PageController.isStartPageVisible()) {
                tabBar.visible = false
                tabBarStackView.goToTabBarPage(PageEnum.PageSetupWizardStart)
            } else {
                tabBar.visible = true
                tabBar.setCurrentIndex(0)
                ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
                tabBarStackView.goToTabBarPage(PageEnum.PageHome)
            }
        }

        function onGoToPageSettings() {
            tabBar.setCurrentIndex(2)
            tabBarStackView.goToTabBarPage(PageEnum.PageSettings)
        }

        function onGoToPageViewConfig() {
            var pagePath = PageController.getPagePath(PageEnum.PageSetupWizardViewConfig)
            tabBarStackView.push(pagePath, { "objectName" : pagePath }, StackView.PushTransition)
        }

        function onGoToShareConnectionPage(headerText, configContentHeaderText, configCaption, configExtension, configFileName) {
            var pagePath = PageController.getPagePath(PageEnum.PageShareConnection)
            tabBarStackView.push(pagePath,
                                 { "objectName" : pagePath,
                                     "headerText" : headerText,
                                     "configContentHeaderText" : configContentHeaderText,
                                     "configCaption" : configCaption,
                                     "configExtension" : configExtension,
                                     "configFileName" : configFileName
                                 },
                                 StackView.PushTransition)
        }

        function onDisableControls(disabled) {
            isControlsDisabled = disabled
        }

        function onDisableTabBar(disabled) {
            isTabBarDisabled = disabled
        }

        function onClosePage() {
            if (tabBarStackView.depth <= 1) {
                PageController.hideWindow()
                return
            }
            tabBarStackView.pop()
        }

        function onGoToPage(page, slide) {
            var pagePath = PageController.getPagePath(page)

            if (slide) {
                tabBarStackView.push(pagePath, { "objectName" : pagePath }, StackView.PushTransition)
            } else {
                tabBarStackView.push(pagePath, { "objectName" : pagePath }, StackView.Immediate)
            }
        }

        function onGoToStartPage() {
            while (tabBarStackView.depth > 1) {
                tabBarStackView.pop()
            }
        }

        function onEscapePressed() {
            if (root.isControlsDisabled || root.isTabBarDisabled) {
                return
            }

            var pageName = tabBarStackView.currentItem.objectName
            // AVPN: системный «назад» (Android Back / Escape) на наших OVERLAY-страницах
            // (Legal/Admin/Notifications/Locations — открыты через replace, depth=1) раньше
            // проваливался в closePage() → hideWindow(): Android сворачивал ВСЁ приложение.
            // Возвращаем страницу текущей вкладки (индекс bottom-nav при открытии overlay
            // не меняется): Legal/Admin → Настройки, Уведомления → Connect. Вкладочные
            // страницы и онбординг — прежнее поведение (свернуть приложение — норма Android).
            if (root.avpnNav && !root.onboardingActive
                    && pageName.toString().indexOf("/Tribe/Pages/") !== -1
                    && !root.isAvpnTabPage(pageName)) {
                root.goAvpnTab(avpnBottomNav.currentIndex)
                return
            }
            if ((pageName === PageController.getPagePath(PageEnum.PageShare)) ||
                    (pageName === PageController.getPagePath(PageEnum.PageSettings)) ||
                    (pageName === PageController.getPagePath(PageEnum.PageSetupWizardConfigSource))) {
                PageController.goToPageHome()
            } else {
                PageController.closePage()
            }
        }
    }

    Connections {
        objectName: "connectionControllerConnections"

        target: ConnectionController

        function onNoInstalledContainers() {
            PageController.setTriggeredByConnectButton(true)

            ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
            PageController.goToPage(PageEnum.PageSetupWizardEasy)
        }
    }

    Connections {
        objectName: "installControllerConnections"

        target: InstallController

        function onInstallationErrorOccurred(error) {
            PageController.showBusyIndicator(false)

            PageController.showErrorMessage(error)

            var needCloseCurrentPage = false
            var currentPageName = tabBarStackView.currentItem.objectName

            if (currentPageName === PageController.getPagePath(PageEnum.PageSetupWizardInstalling)) {
                needCloseCurrentPage = true
            } else if (currentPageName === PageController.getPagePath(PageEnum.PageDeinstalling)) {
                needCloseCurrentPage = true
            }
            if (needCloseCurrentPage) {
                PageController.closePage()
            }
        }

        function onWrongInstallationUser(message) {
            onInstallationErrorOccurred(message)
        }

        function onUpdateContainerFinished(message, closePage) {
            PageController.showNotificationMessage(message)
            if (closePage) {
                PageController.closePage()
            }
        }

        function onCachedProfileCleared(message) {
            PageController.showNotificationMessage(message)
        }

        function onRemoveServerFinished(finishedMessage) {
            if (!ServersUiController.getServersCount()) {
                PageController.goToPageHome()
            } else {
                PageController.goToStartPage()
                PageController.goToPage(PageEnum.PageSettingsServersList)
            }
            PageController.showNotificationMessage(finishedMessage)
        }

        function onRemoveAllContainersFinished(finishedMessage) {
            if (tabBarStackView.currentItem.objectName === PageController.getPagePath(PageEnum.PageDeinstalling)) {
                PageController.closePage()
            }
            PageController.showNotificationMessage(finishedMessage)
        }

        function onRemoveContainerFinished(finishedMessage) {
            if (tabBarStackView.currentItem.objectName === PageController.getPagePath(PageEnum.PageDeinstalling)) {
                PageController.closePage()
            }
            PageController.closePage()
            PageController.showNotificationMessage(finishedMessage)
        }
    }

    Connections {
        objectName: "importControllerConnections"

        target: ImportController

        function onImportErrorOccurred(error, goToPageHome) {
            PageController.showErrorMessage(error)
        }

        function onRestoreAppConfig(data) {
            PageController.showBusyIndicator(true)
            SettingsController.restoreAppConfigFromData(data)
            PageController.showBusyIndicator(false)
        }
    }

    Connections {
        objectName: "settingsControllerConnections"

        target: SettingsController

        function onLoggingDisableByWatcher() {
            PageController.showNotificationMessage(qsTr("Logging was disabled after 14 days, log files were deleted"))
        }

        function onRestoreBackupFinished() {
            PageController.showNotificationMessage(qsTr("Settings restored from backup file"))
            PageController.goToPageHome()
        }

        function onLoggingStateChanged() {
            if (SettingsController.isLoggingEnabled) {
                var message = qsTr("Logging is enabled. Note that logs will be automatically" +
                                   "disabled after 14 days, and all log files will be deleted.")
                PageController.showNotificationMessage(message)
            }
        }
    }

    Connections {
        target: SubscriptionUiController

        function onErrorOccurred(error) {
            PageController.showErrorMessage(error)
        }
    }

    Connections {
        target: SubscriptionUiController

        function onApiConfigRemoved(message) {
            PageController.showNotificationMessage(message)
        }

        function onApiServerRemoved(message) {
            if (!ServersUiController.getServersCount()) {
                PageController.goToPageHome()
            } else {
                PageController.goToStartPage()
                PageController.goToPage(PageEnum.PageSettingsServersList)
            }
            PageController.showNotificationMessage(message)
        }

        function onInstallServerFromApiFinished(message, preferredDefaultIndex) {
            PageController.goToPageHome()
            PageController.showNotificationMessage(message)
        }

        function onBackgroundPurchaseCompleted(message) {
            PageController.showNotificationMessage(message)
        }

        function onChangeApiCountryFinished(message) {
            PageController.goToPageHome()
            PageController.showNotificationMessage(message)
        }

        function onReloadServerFromApiFinished(message) {
            PageController.goToPageHome()
            PageController.showNotificationMessage(message)
        }
    }

    StackViewType {
        id: tabBarStackView
        objectName: "tabBarStackView"

        anchors.top: parent.top
        anchors.right: parent.right
        anchors.left: parent.left
        // AVPN: над нашей навигацией; на онбординге навигации нет — страница до низа окна.
        // Клавиатура (телеграм-схема, единая для iOS/Android): навбар СКРЫТ (kbActive),
        // контент СЖАТ margin'ом = высоте клавиатуры, шапка страницы на месте. Авто-сдвиг
        // окна iOS (QIOSInputContext, «чёрная дыра» в билдах 75–77) гасится нативным
        // observer'ом AvpnKeyboardFix.mm (ставится в pageController).
        // Якорь у наших вкладок ВСЕГДА parent.bottom; «над навбаром» выражено margin'ом =
        // avpnBottomNav.height. Прошлая схема (переключение якоря navbar.top ↔ parent.bottom
        // по kbActive) в момент фокуса давала margin 0 при ещё нулевом imeHeight — композер
        // нырял вниз на кадр и телепортом прыгал над клавиатуру («мерцает, появляется дважды»,
        // жалоба 2026-07-12). Теперь в момент фокуса геометрия НЕ меняется
        // (max(imeHeight=0, navH) = navH), а приход imeHeight анимируется Behavior'ом —
        // композер плавно съезжает вверх в темпе клавиатуры, как в телеграме.
        anchors.bottom: (root.onboardingActive || root.avpnNav) ? parent.bottom : tabBar.top
        anchors.bottomMargin: (root.avpnNav && !root.onboardingActive)
                              ? (root.kbActive ? Math.max(PageController.imeHeight, avpnBottomNav.height)
                                               : avpnBottomNav.height)
                              : 0
        Behavior on anchors.bottomMargin {
            // Кривая ≈ клавиатура iOS (bezier .38,.7,.125,1 / 500мс). На 120 Гц
            // (CADisableMinimumFrameDurationOnPhone в Info.plist) анимация лайаута идёт
            // вдвое чаще прежнего — плавно; кадр рендерится за 2-3мс (QSG_RENDER_TIMING).
            // Экспериментальные покадровые фиды/GPU-сдвиги откачены (артефакты хуже
            // микро-рассинхрона кривой — история в памяти tribe-support-chat-native).
            // kbInstant: уход со страницы с клавиатурой — схлопнуться мгновенно.
            enabled: !root.kbInstant
            NumberAnimation {
                duration: 500
                easing.type: Easing.BezierSpline
                easing.bezierCurve: [0.38, 0.7, 0.125, 1.0, 1, 1]
            }
        }

        enabled: !root.isControlsDisabled

        function goToTabBarPage(page) {
            var pagePath = PageController.getPagePath(page)
            tabBarStackView.clear(StackView.Immediate)
            tabBarStackView.replace(pagePath, { "objectName" : pagePath }, StackView.Immediate)
        }

        // AVPN: загрузка нашей страницы по относительному URL (резолвится и в qrc, и с диска).
        // extraProps (опционально) — начальные свойства страницы (напр. docKey у PageLegalTribe).
        function goToTabBarPageUrl(relUrl, extraProps) {
            var pagePath = Qt.resolvedUrl(relUrl)
            var props = { "objectName": pagePath }
            for (var k in (extraProps || {}))
                props[k] = extraProps[k]
            tabBarStackView.clear(StackView.Immediate)
            tabBarStackView.replace(pagePath, props, StackView.Immediate)
        }

        Component.onCompleted: {
            var pagePath
            if (root.avpnNav && PageController.isStartPageVisible() && !avpnOnboard.done) {
                // AVPN: первый запуск → наш онбординг
                root.onboardingActive = true
                tabBar.visible = false
                pagePath = Qt.resolvedUrl("../Tribe/Pages/PageOnboardingTribe.qml")
            } else if (!root.avpnNav && PageController.isStartPageVisible()) {
                tabBar.visible = false
                pagePath = PageController.getPagePath(PageEnum.PageSetupWizardStart)
            } else {
                tabBar.visible = true
                pagePath = Qt.resolvedUrl(root.avpnNav ? "../Tribe/Pages/PageConnectTribe.qml"
                                                       : "PageHomeTribe.qml") // AVPN: наш Connect-экран
                if (!PageController.isStartPageVisible())
                    ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
            }

            tabBarStackView.push(pagePath, { "objectName" : pagePath })
        }

        Keys.onPressed: function(event) {
            switch (event.key) {
            case Qt.Key_Tab:
            case Qt.Key_Down:
            case Qt.Key_Right:
                FocusController.nextKeyTabItem()
                break
            case Qt.Key_Backtab:
            case Qt.Key_Up:
            case Qt.Key_Left:
                FocusController.previousKeyTabItem()
                break
            default:
                PageController.keyPressEvent(event.key)
                event.accepted = true
            }
        }
    }

    TabBar {
        id: tabBar
        objectName: "tabBar"

        anchors.right: parent.right
        anchors.left: parent.left
        anchors.bottom: parent.bottom

        // Also adjust TabBar position when keyboard appears (Android 14+ workaround)
        anchors.bottomMargin: PageController.imeHeight

        topPadding: 8
        bottomPadding: 8 + Math.max(PageController.safeAreaBottomMargin, SafeArea.margins.bottom) // AVPN: iOS — PageController даёт 0
        leftPadding: 96
        rightPadding: 96

        // AVPN: при нашей навигации Amnezia TabBar схлопнут и неактивен (обработчики его ещё трогают).
        opacity: root.avpnNav ? 0 : 1
        height: root.avpnNav ? 0 : (visible ? homeTabButton.implicitHeight + tabBar.topPadding + tabBar.bottomPadding : 0)

        enabled: !root.avpnNav && !root.isControlsDisabled && !root.isTabBarDisabled

        background: Shape {
            objectName: "backgroundShape"

            width: parent.width
            height: parent.height

            ShapePath {
                startX: 0
                startY: 0

                PathLine { x: width; y: 0 }
                PathLine { x: width; y: tabBar.height - 1 }
                PathLine { x: 0; y: tabBar.height - 1 }
                PathLine { x: 0; y: 0 }

                strokeWidth: 1
                strokeColor: AmneziaStyle.color.slateGray
                fillColor: AmneziaStyle.color.onyxBlack
            }
        }

        TabImageButtonType {
            id: homeTabButton
            objectName: "homeTabButton"

            isSelected: tabBar.currentIndex === 0
            image: "qrc:/images/controls/home.svg"
            clickedFunc: function () {
                ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
                tabBarStackView.goToTabBarPage(PageEnum.PageHome) // AVPN: таб-бар виден только в amneziaMode → ванильная главная
                tabBar.currentIndex = 0
            }
        }

        TabImageButtonType {
            id: shareTabButton
            objectName: "shareTabButton"

            Connections {
                target: ServersModel

                function onModelReset() {
                    if (!SettingsController.isOnTv()) {
                        var hasServerWithWriteAccess = ServersUiController.hasServerWithWriteAccess()
                        shareTabButton.visible = hasServerWithWriteAccess
                        shareTabButton.width = hasServerWithWriteAccess ? undefined : 0
                    }
                }
            }

            visible: !SettingsController.isOnTv() && ServersUiController.hasServerWithWriteAccess()
            width: !SettingsController.isOnTv() && ServersUiController.hasServerWithWriteAccess() ? undefined : 0

            isSelected: tabBar.currentIndex === 1
            image: "qrc:/images/controls/share-2.svg"
            clickedFunc: function () {
                tabBarStackView.goToTabBarPage(PageEnum.PageShare)
                tabBar.currentIndex = 1
            }
        }

        TabImageButtonType {
            id: settingsTabButton
            objectName: "settingsTabButton"

            isSelected: tabBar.currentIndex === 2
            image: (ServersUiController.hasServersFromGatewayApi && NewsModel.hasUnread && SettingsController.isNewsNotificationsEnabled()) ? "qrc:/images/controls/settings-news.svg" : "qrc:/images/controls/settings.svg"
            Binding {
                target: settingsTabButton
                property: "defaultColor"
                value: "transparent"
                when: (ServersUiController.hasServersFromGatewayApi && NewsModel.hasUnread)
            }
            clickedFunc: function () {
                tabBarStackView.goToTabBarPage(PageEnum.PageSettings)
                tabBar.currentIndex = 2
            }
        }

        TabImageButtonType {
            id: plusTabButton
            objectName: "plusTabButton"

            isSelected: tabBar.currentIndex === 3
            image: "qrc:/images/controls/plus.svg"
            clickedFunc: function () {
                tabBarStackView.goToTabBarPage(PageEnum.PageSetupWizardConfigSource)
                tabBar.currentIndex = 3
            }
        }
    }

    // AVPN: возврат из полного Amnezia-UI в Tribe (виден только в Dev.amneziaMode)
    Rectangle {
        visible: Dev.amneziaMode && !PageController.isStartPageVisible()
        anchors.right: parent.right
        anchors.rightMargin: Theme.space.lg
        anchors.bottom: tabBar.top
        anchors.bottomMargin: Theme.space.md
        width: backRow.width + 2 * Theme.space.lg
        height: 36
        radius: Theme.radius.pill
        color: Theme.color.surface1
        border.color: Theme.color.border2
        border.width: 1
        z: 50
        Row {
            id: backRow
            anchors.centerIn: parent
            spacing: Theme.space.xs
            Text {
                text: "‹"
                color: Theme.color.accent
                font.family: Theme.font.display
                font.pixelSize: Theme.font.h3
                anchors.verticalCenter: parent.verticalCenter
            }
            Text {
                text: "Tribe"
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wSemibold
                anchors.verticalCenter: parent.verticalCenter
            }
        }
        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: { Dev.amneziaMode = false; root.goAvpnTab(0) }
        }
    }

    // AVPN: наша нижняя навигация (3 вкладки) — замена Amnezia TabBar.
    TribeBottomNav {
        id: avpnBottomNav
        objectName: "avpnBottomNav"

        anchors.right: parent.right
        anchors.left: parent.left
        anchors.bottom: parent.bottom

        // AVPN (Support, handoff Занавеса): при клавиатуре навбар ПРЯЧЕТСЯ, а не поднимается
        // (PWA-паттерн kb-open .tabbar{display:none}) — над клавиатурой живёт только композер.
        // kbActive включает фокус-срез (скрытие ДО анимации клавиатуры) и страховку от
        // застрявшего imeHeight (меню «пропадало навсегда» после «назад» — 2026-07-11).
        visible: root.avpnNav && !root.onboardingActive && !root.kbActive
        // iOS: PageController.safeArea* только для Android → SafeArea (Qt 6.9+); фон нава
        // уходит под home-индикатор до самого низа (implicitHeight = 72 + inset)
        bottomInset: Math.max(PageController.safeAreaBottomMargin, SafeArea.margins.bottom)
        enabled: !root.isControlsDisabled && !root.isTabBarDisabled
        // AVPN (Support): бейдж непрочитанных ответов оператора на вкладке «Поддержка».
        supportBadge: (typeof TribeSupport !== "undefined") ? TribeSupport.unread : 0

        onActivated: function(index) { root.goAvpnTab(index) }
    }

    // AVPN (перенос «как SIM», приёмник): полноэкранный успех «Подписка перенесена на это
    // устройство». Живёт ЗДЕСЬ (хост всегда жив), а не в PageAccountTribe: диплинк с системной
    // камеры может прилететь на ЛЮБОЙ вкладке — тост легко пропустить, полноэкранный экран нет.
    TribeResultSheet {
        id: transferInResult
        anchors.fill: parent
        z: 200
    }
    Connections {
        target: (typeof TribeEngine !== "undefined") ? TribeEngine : null
        ignoreUnknownSignals: true
        function onTransferRedeemed() {
            transferInResult.show(qsTr("Подписка перенесена на это устройство"),
                                  qsTr("Дни и трафик уже здесь. Прежнее устройство отключено — можно подключаться."))
        }
        // AVPN: ЕДИНСТВЕННАЯ точка тоста TribeEngine.error — хост жив на любой вкладке,
        // ошибка deep-link/kill-switch не теряется вне Connect/Настроек. Страницы в своих
        // onError держат ТОЛЬКО побочные эффекты (хаптика, redeem-флаги) и тост НЕ зовут —
        // добавишь showErrorMessage в странице → будет дубль.
        function onError(message) {
            PageController.showErrorMessage(message)
        }
    }

    // AVPN (рассылки P-ANN v2): попап важной рассылки — ГЛОБАЛЬНЫЙ слой поверх любого
    // экрана и нижней навигации (реш. 2026-07-10; хост всегда жив — вкладки/оверлеи его
    // не прячут). Закрыть можно ТОЛЬКО кнопками уведомления: системный «назад»
    // проглатывается внутри TribeAnnouncementSheet. Показ — самое новое непрочитанное
    // kind=popup (сервер отдаёт новые первыми), по одному; на онбординге не показываем.
    property bool announceLinkWait: false   // гард cabinetLinkReady (сигнал общий на движок)
    TribeAnnouncementSheet {
        id: announceSheet
        z: 190   // под transferInResult (полноэкранный успех переноса важнее)
        onWeblinkRequested: {
            if (typeof TribeEngine === "undefined") return
            root.announceLinkWait = true
            TribeEngine.requestCabinetLink("")
        }
        onScreenRequested: function(name) {
            if (name === "support") root.goAvpnTab(1)
            // AVPN backend-first (Task 9): kill-switch features.referral гейтит и CTA объявлений
            else if (name === "referral" && (typeof TribeEngine === "undefined" || TribeEngine.referralEnabled !== false)) root.goAvpnTab(2)
            else if (name === "settings" || name === "account") root.goAvpnTab(3)
            else if (name === "notifications") tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageNotificationsTribe.qml")
            // неизвестный экран (рассылка новее клиента) — молча игнорируем
        }
    }

    // AVPN (Доктор v1): попап полной диагностики — глобальный хост (тест переживает смену
    // вкладок; входы: кнопка «Доктор» на главной, чат — карточка run_diag / send_diag при
    // включённом diag_v2 / пункт меню «+»). Спека: 2026-07-17-doctor-v1-design.md.
    TribeDoctorSheet {
        id: doctorSheet
        z: 185   // под объявлениями/transferInResult; поверх вкладок и навигации
    }

    function maybeShowAnnouncement() {
        if (typeof TribeEngine === "undefined" || announceSheet.opened) return
        if (!root.avpnNav || root.onboardingActive) return
        // AVPN (announce-quiet, инцидент «два онбординга» 2026-07-12): N минут после
        // онбординга автопоказ попапа молчит (rich-попап визуально дублирует онбординг).
        // Server-tunable: numbers.announce_onboarding_quiet_min + kill-switch
        // features.announce_onboarding_quiet. Бейдж колокольчика и лента НЕ глушатся.
        if (typeof TribeEngine.announcementsQuietNow === "function" && TribeEngine.announcementsQuietNow()) return
        var list = TribeEngine.announcements
        for (var i = 0; i < list.length; ++i) {
            if (list[i].kind === "popup") { announceSheet.show(list[i]); return }
        }
    }
    Connections {
        target: (typeof TribeEngine !== "undefined") ? TribeEngine : null
        ignoreUnknownSignals: true
        function onAnnouncementsChanged() { announceShowTimer.restart() }
        function onCabinetLinkReady(url) {
            if (!root.announceLinkWait) return
            root.announceLinkWait = false
            Qt.openUrlExternally(url)
        }
    }
    Timer {
        id: announceShowTimer
        interval: 900; repeat: false                 // первый показ после LKG-загрузки движка
        running: typeof TribeEngine !== "undefined"  // не из кадра создания страницы
        onTriggered: root.maybeShowAnnouncement()
    }
    // Возврат в foreground → свежие рассылки (дёшево; свой троттл не нужен — движок
    // ходит асинхронно, а показ и так дедуплицируется по прочитанности).
    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.application.state !== Qt.ApplicationActive) return
            if (typeof TribeEngine !== "undefined"
                    && typeof TribeEngine.refreshAnnouncements === "function")
                TribeEngine.refreshAnnouncements()
        }
    }




}

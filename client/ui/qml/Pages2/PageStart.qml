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
import "../Avpn"              // AVPN: singletons Theme + Dev (admin/amnezia-режимы)
import "../Avpn/components"   // AVPN: TribeBottomNav (наша навигация)

PageType {
    id: root

    property bool isControlsDisabled: false
    property bool isTabBarDisabled: false

    // AVPN: наша нижняя навигация вместо Amnezia TabBar; Dev.amneziaMode переключает
    // на ПОЛНЫЙ ванильный интерфейс (их TabBar + страницы), возврат — кнопка «‹ Tribe».
    readonly property bool avpnNav: !Dev.amneziaMode

    // AVPN: первый запуск (нет серверов + онбординг не пройден) → наш PageOnboardingAvpn,
    // а не ванильный wizard. После «Приступим» (requestStart) попадаем на наш Connect.
    // onboardingActive ставится императивно в точках роутинга (isStartPageVisible — не реактивный).
    Settings { id: avpnOnboard; category: "AvpnOnboarding"; property bool done: false }
    property bool onboardingActive: false

    // AVPN: единый роутер наших вкладок (0 Главная / 1 Серверы / 2 Анти-VPN / 3 Профиль).
    function goAvpnTab(index) {
        avpnBottomNav.currentIndex = index
        if (index === 1)
            tabBarStackView.goToTabBarPageUrl("../Avpn/Pages/PageLocationsAvpn.qml")
        else if (index === 2)
            tabBarStackView.goToTabBarPageUrl("../Avpn/Pages/PageSecurityAvpn.qml")
        else if (index === 3)
            tabBarStackView.goToTabBarPageUrl("../Avpn/Pages/PageAccountAvpn.qml")
        else
            tabBarStackView.goToTabBarPageUrl("../Avpn/Pages/PageConnectAvpn.qml")
    }

    // AVPN: Connect-экран просит переключить вкладку / открыть настройки.
    Connections {
        target: tabBarStackView ? tabBarStackView.currentItem : null
        ignoreUnknownSignals: true
        function onRequestTab(index) { root.goAvpnTab(index) }
        function onRequestSettings() { root.goAvpnTab(3) }
        // AVPN: онбординг пройден («Приступим») → запоминаем и уводим на Connect
        function onRequestStart() {
            avpnOnboard.done = true
            root.onboardingActive = false
            root.goAvpnTab(0)
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
                    tabBarStackView.goToTabBarPageUrl("../Avpn/Pages/PageOnboardingAvpn.qml")
                } else {
                    root.onboardingActive = false
                    tabBar.visible = true
                    tabBar.setCurrentIndex(0)
                    if (!PageController.isStartPageVisible())
                        ServersUiController.setProcessedServerId(ServersUiController.defaultServerId)
                    root.goAvpnTab(0)
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
        // AVPN: над нашей навигацией; на онбординге навигации нет — страница до низа окна
        anchors.bottom: root.onboardingActive ? parent.bottom
                                              : (root.avpnNav ? avpnBottomNav.top : tabBar.top)

        enabled: !root.isControlsDisabled

        function goToTabBarPage(page) {
            var pagePath = PageController.getPagePath(page)
            tabBarStackView.clear(StackView.Immediate)
            tabBarStackView.replace(pagePath, { "objectName" : pagePath }, StackView.Immediate)
        }

        // AVPN: загрузка нашей страницы по относительному URL (резолвится и в qrc, и с диска).
        function goToTabBarPageUrl(relUrl) {
            var pagePath = Qt.resolvedUrl(relUrl)
            tabBarStackView.clear(StackView.Immediate)
            tabBarStackView.replace(pagePath, { "objectName" : pagePath }, StackView.Immediate)
        }

        Component.onCompleted: {
            var pagePath
            if (root.avpnNav && PageController.isStartPageVisible() && !avpnOnboard.done) {
                // AVPN: первый запуск → наш онбординг
                root.onboardingActive = true
                tabBar.visible = false
                pagePath = Qt.resolvedUrl("../Avpn/Pages/PageOnboardingAvpn.qml")
            } else if (!root.avpnNav && PageController.isStartPageVisible()) {
                tabBar.visible = false
                pagePath = PageController.getPagePath(PageEnum.PageSetupWizardStart)
            } else {
                tabBar.visible = true
                pagePath = Qt.resolvedUrl(root.avpnNav ? "../Avpn/Pages/PageConnectAvpn.qml"
                                                       : "PageHomeAvpn.qml") // AVPN: наш Connect-экран
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
        anchors.bottomMargin: PageController.imeHeight

        visible: root.avpnNav && !root.onboardingActive   // AVPN: на онбординге навигации нет
        // iOS: PageController.safeArea* только для Android → SafeArea (Qt 6.9+); фон нава
        // уходит под home-индикатор до самого низа (implicitHeight = 72 + inset)
        bottomInset: Math.max(PageController.safeAreaBottomMargin, SafeArea.margins.bottom)
        enabled: !root.isControlsDisabled && !root.isTabBarDisabled

        onActivated: function(index) { root.goAvpnTab(index) }
    }
}

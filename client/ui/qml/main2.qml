import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import Qt5Compat.GraphicalEffects as Fx // AVPN (macOS): OpacityMask для скругления окна
import QtQuick.Shapes                   // AVPN (macOS): глифы светофоров тайтлбара

import PageEnum 1.0
import Style 1.0

import "Config"
import "Controls2"
import "Components"
import "Pages2"
import "Tribe"   // AVPN (macOS): Theme-токены для кастомного тайтлбара

Window  {
    id: root
    objectName: "mainWindow"

    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.platform.os === "android") {
                if (Qt.application.state === Qt.ApplicationActive) {
                    root.visible = true
                    refreshTimer.restart()
                }
            }
        }
    }

    // Hide the window immediately when Android Activity.onPause() fires so that
    // Qt's render loop stops before the EGL surface is disconnected.  This
    // prevents "QRhiGles2: Failed to make context current" and the resulting
    // black screen that appears after swiping home and returning.
    Connections {
        target: SettingsController
        function onActivityPaused() {
            if (Qt.platform.os === "android") root.visible = false
        }
        function onActivityResumed() {
            if (Qt.platform.os === "android") root.visible = true
        }
    }

    Timer {
        id: refreshTimer
        interval: 150
        repeat: false
        onTriggered: {
            if (Qt.platform.os === "android" && PageController.isEdgeToEdgeEnabled()) {
                console.log("QML: Application resumed with edge-to-edge")
            }
        }
    }

    visible: true
    width: GC.screenWidth
    height: GC.screenHeight
    minimumWidth: GC.isDesktop() ? 380 : 0
    // AVPN: подняли высоту окна на десктопе — на главном экране появилась карточка «АвтоVPN» над
    // «Умный выбор сервера»; при 640 контент (орб+кольца+2 карточки+кнопки) наезжал (экран без скролла).
    minimumHeight: GC.isDesktop() ? 760 : 0
    // AVPN: клампить окно только на десктопе — на iPhone (высота > 800pt) кламп даёт letterbox
    maximumWidth: GC.isDesktop() ? 600 : 16777215
    maximumHeight: GC.isDesktop() ? 1000 : 16777215
    // AVPN (macOS): окно со скруглением 24 — frameless + прозрачный фон, углы режет OpacityMask
    // на appContent. Перемещение окна — DragHandler (startSystemMove) за любую пустую область.
    readonly property bool roundedMac: Qt.platform.os === "osx" && GC.isDesktop()
    // AVPN: верхняя полоса с версией — ТОЛЬКО десктоп (macOS + Windows); на мобилках её нет.
    // На Windows окно остаётся с системной рамкой/кнопками — показываем только версию.
    readonly property bool desktopBar: roundedMac || (Qt.platform.os === "windows" && GC.isDesktop())
    // AVPN: с Qt 6.9 окно на iOS НЕ заходит под статус-бар/home-индикатор без этого флага —
    // без него фон обрезан сверху и снизу. Отступы контента — SafeArea.margins в страницах.
    flags: Qt.platform.os === "ios" ? (Qt.Window | Qt.ExpandedClientAreaHint)
         : (roundedMac ? (Qt.Window | Qt.FramelessWindowHint) : Qt.Window)

    color: roundedMac ? "transparent" : AmneziaStyle.color.midnightBlack

    onClosing: function(close) {
        close.accepted = false
        PageController.closeWindow()
    }

    onSceneGraphError: function(error, message) {
        // Prevent qFatal crash on Android when EGL context is lost
        console.warn("Scene graph error:", error, message)
    }

    title: "Tribe VPN"

    Item { // This item is needed for focus handling
        id: defaultFocusItem
        objectName: "defaultFocusItem"

        focus: true

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

    // AVPN (macOS rounded): ВЕСЬ визуальный контент — внутри appContent, чтобы маска резала углы
    // у всего сразу (страницы, шторки, тосты). Функции/FileDialog остаются на root (scope-вызовы).
    Item {
        id: appContent
        anchors.fill: parent
        layer.enabled: root.roundedMac
        layer.effect: Fx.OpacityMask {
            maskSource: Rectangle { width: appContent.width; height: appContent.height; radius: 24 }
        }

        // frameless-окно двигаем за любую «пустую» область (клики по контролам не задевает)
        DragHandler {
            enabled: root.roundedMac
            target: null
            onActiveChanged: if (active) root.startSystemMove()
        }

    Loader {
        active: Qt.platform.os === "android"
        source: Qt.platform.os === "android" ? "Components/GamepadLoader.qml" : ""
    }

    Connections {
        objectName: "pageControllerConnections"

        target: PageController

        function onRaiseMainWindow() {
            root.show()
            root.raise()
            root.requestActivate()
        }

        function onHideMainWindow() {
            root.hide()
        }

        function onShowErrorMessage(errorMessage) {
            popupErrorMessage.text = errorMessage
            popupErrorMessage.open()
        }

        function onShowNotificationMessage(message) {
            popupNotificationMessage.text = message
            popupNotificationMessage.closeButtonVisible = false
            popupNotificationMessage.open()
            popupNotificationTimer.start()
        }

        function onShowPassphraseRequestDrawer() {
            privateKeyPassphraseDrawer.openTriggered()
        }

        function onGoToPageSettingsBackup() {
            PageController.goToPage(PageEnum.PageSettingsBackup)
        }

        function onShowBusyIndicator(visible) {
            busyIndicator.visible = visible
            PageController.disableControls(visible)
        }

        function onShowChangelogDrawer() {
            changelogDrawer.openTriggered()
        }
    }

    Connections {
        objectName: "settingsControllerConnections"

        target: SettingsController

        function onChangeSettingsFinished(finishedMessage) {
            PageController.showNotificationMessage(finishedMessage)
        }
    }

    PageStart {
        objectName: "pageStart"
        width: root.width
        // AVPN (desktop bar): контент — ПОД верхней полосой (macOS: кастомный тайтлбар; Win: версия)
        y: root.desktopBar ? macTitleBar.height : 0
        height: root.height - (root.desktopBar ? macTitleBar.height : 0)
    }

    // AVPN (macOS rounded): кастомный тайтлбар — светофоры (закрыть/свернуть/развернуть) в капсуле
    // + серый слоган по центру. Окно frameless, системных кнопок нет — это их замена.
    Rectangle {
        id: macTitleBar
        visible: root.desktopBar
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: root.desktopBar ? 40 : 0
        color: Theme.color.bg800

        // капсула со светофорами (референс-дизайн 2026-07-02). Как в macOS: глифы (×/−/зум)
        // проявляются во ВСЕХ трёх кружках при наведении на любую часть капсулы.
        Rectangle {
            id: lightsPill
            visible: root.roundedMac   // светофоры — только macOS (Win: системные кнопки рамки)
            anchors.left: parent.left; anchors.leftMargin: Theme.space.md
            anchors.verticalCenter: parent.verticalCenter
            width: lightsRow.width + 2 * Theme.space.md; height: 26
            radius: Theme.radius.pill
            color: Theme.color.surface1
            border.width: 1; border.color: Theme.color.border

            HoverHandler { id: pillHover }
            readonly property bool showGlyphs: pillHover.hovered
            readonly property color glyphColor: Qt.rgba(0, 0, 0, 0.55)

            Row {
                id: lightsRow
                anchors.centerIn: parent
                spacing: Theme.space.sm

                // закрыть (в трей — как системный крестик через onClosing)
                Rectangle {
                    width: 12; height: 12; radius: 6
                    color: Theme.color.danger
                    opacity: lightsPill.showGlyphs ? 1.0 : 0.85
                    Shape {
                        anchors.centerIn: parent; width: 8; height: 8
                        visible: lightsPill.showGlyphs
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: lightsPill.glyphColor; fillColor: "transparent"
                            strokeWidth: 1.4; capStyle: ShapePath.RoundCap
                            PathSvg { path: "M2 2 L6 6 M6 2 L2 6" }
                        }
                    }
                    MouseArea { anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor; onClicked: PageController.closeWindow() }
                }
                // свернуть
                Rectangle {
                    width: 12; height: 12; radius: 6
                    color: Theme.color.warning
                    opacity: lightsPill.showGlyphs ? 1.0 : 0.85
                    Shape {
                        anchors.centerIn: parent; width: 8; height: 8
                        visible: lightsPill.showGlyphs
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: lightsPill.glyphColor; fillColor: "transparent"
                            strokeWidth: 1.6; capStyle: ShapePath.RoundCap
                            PathSvg { path: "M1.6 4 L6.4 4" }
                        }
                    }
                    MouseArea { anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor; onClicked: root.showMinimized() }
                }
                // развернуть/вернуть (глиф — два треугольника, как системный зум)
                Rectangle {
                    width: 12; height: 12; radius: 6
                    color: Theme.color.connected
                    opacity: lightsPill.showGlyphs ? 1.0 : 0.85
                    Shape {
                        anchors.centerIn: parent; width: 8; height: 8
                        visible: lightsPill.showGlyphs
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: "transparent"; fillColor: lightsPill.glyphColor
                            PathSvg { path: "M1.6 5.8 L1.6 1.6 L5.8 1.6 Z" }
                        }
                        ShapePath {
                            strokeColor: "transparent"; fillColor: lightsPill.glyphColor
                            PathSvg { path: "M6.4 2.2 L6.4 6.4 L2.2 6.4 Z" }
                        }
                    }
                    MouseArea { anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.visibility === Window.Maximized ? root.showNormal() : root.showMaximized() }
                }
            }
        }

        // версия приложения по правому краю (слоган убран, реш. 2026-07-03); mono — версия это данные.
        // Qt.application.version отдаёт голый билд-номер («52») → берём TRIBE_VERSION из
        // SettingsController.getAppVersion() («5.1.25.50 (дата, хеш)» — первый токен).
        Text {
            anchors.right: parent.right; anchors.rightMargin: Theme.space.lg
            anchors.verticalCenter: parent.verticalCenter
            text: "v" + SettingsController.getAppVersion().split(" ")[0]
            color: Theme.color.text3
            font.family: Theme.font.mono; font.pixelSize: 11
        }
    }

    Item {
        objectName: "popupNotificationItem"

        anchors.right: parent.right
        anchors.left: parent.left
        // AVPN: уведомления — в ВЕРХ под логотип/плашку Tribe (бренд-решение 2026-06-11), не в низ
        anchors.top: parent.top
        anchors.topMargin: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top) + 64

        implicitHeight: popupNotificationMessage.height

        PopupType {
            id: popupNotificationMessage
        }

        Timer {
            id: popupNotificationTimer

            interval: 3000
            repeat: false
            running: false
            onTriggered: {
                popupNotificationMessage.close()
            }
        }
    }

    Item {
        objectName: "popupErrorMessageItem"

        anchors.right: parent.right
        anchors.left: parent.left
        // AVPN: ошибки — тоже в ВЕРХ под логотип/плашку Tribe (бренд-решение 2026-06-11)
        anchors.top: parent.top
        anchors.topMargin: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top) + 64

        implicitHeight: popupErrorMessage.height

        PopupType {
            id: popupErrorMessage
        }
    }

    Item {
        objectName: "captchaDialogItem"

        anchors.fill: parent

        CaptchaDialogType {
            id: captchaDialog

            onCaptchaSolved: function(captchaId, solution) {
                PageController.showBusyIndicator(true)
                Qt.callLater(function() {
                    SubscriptionUiController.onCaptchaSolved(captchaId, solution)
                })
            }

            onRefreshCaptchaRequested: function() {
                SubscriptionUiController.onRefreshCaptchaRequested()
            }
        }
    }

    Item {
        objectName: "privateKeyPassphraseDrawerItem"

        anchors.fill: parent

        DrawerType2 {
            id: privateKeyPassphraseDrawer

            property bool isCloseByUser: false

            anchors.fill: parent
            expandedHeight: root.height * 0.35 + PageController.safeAreaBottomMargin + PageController.imeHeight

            expandedStateContent: ColumnLayout {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.topMargin: 16
                anchors.leftMargin: 16
                anchors.rightMargin: 16

                Connections {
                    target: privateKeyPassphraseDrawer
                    function onOpened() {
                        passphrase.textField.text = ""
                        passphrase.textField.forceActiveFocus()
                    }

                    function onAboutToHide() {
                        if (privateKeyPassphraseDrawer.isCloseByUser === false) {
                            privateKeyPassphraseDrawer.isCloseByUser = true
                            PageController.passphraseRequestDrawerClosed("")
                        }

                        if (passphrase.textField.text !== "") {
                            PageController.showBusyIndicator(true)
                        }
                    }

                    function onAboutToShow() {
                        PageController.showBusyIndicator(false)
                    }
                }

                TextFieldWithHeaderType {
                    id: passphrase

                    property bool hidePassword: true

                    Layout.fillWidth: true
                    headerText: qsTr("Private key passphrase")
                    textField.echoMode: hidePassword ? TextInput.Password : TextInput.Normal
                    buttonImageSource: hidePassword ? "qrc:/images/controls/eye.svg" : "qrc:/images/controls/eye-off.svg"

                    clickedFunc: function() {
                        hidePassword = !hidePassword
                    }
                }

                BasicButtonType {
                    id: saveButton

                    Layout.fillWidth: true

                    defaultColor: AmneziaStyle.color.transparent
                    hoveredColor: AmneziaStyle.color.translucentWhite
                    pressedColor: AmneziaStyle.color.sheerWhite
                    disabledColor: AmneziaStyle.color.mutedGray
                    textColor: AmneziaStyle.color.paleGray
                    borderWidth: 1

                    text: qsTr("Save")

                    clickedFunc: function() {
                        privateKeyPassphraseDrawer.isCloseByUser = true
                        privateKeyPassphraseDrawer.closeTriggered()
                        PageController.passphraseRequestDrawerClosed(passphrase.textField.text)
                    }
                }
            }
        }
    }

    Item {
        objectName: "questionDrawerItem"

        anchors.fill: parent

        QuestionDrawer {
            id: questionDrawer

            anchors.fill: parent
        }
    }

    Item {
        objectName: "subscriptionExpiredDrawerItem"

        anchors.fill: parent

        SubscriptionExpiredDrawer {
            id: subscriptionExpiredDrawer

            anchors.fill: parent
        }
    }

    Connections {
        target: PageController

        function onUnsupportedConnectDrawerRequested() {
            root.showUnsupportedConnectDrawer()
        }
    }

    Connections {
        target: SubscriptionUiController

        function onSubscriptionExpiredOnServer() {
            subscriptionExpiredDrawer.openTriggered()
        }

        function onCaptchaRequired(captchaId, captchaImageBase64, hint) {
            if (captchaDialog.opened) {
                PageController.showBusyIndicator(false)
            }
            captchaDialog.captchaId = captchaId
            captchaDialog.captchaImageBase64 = captchaImageBase64
            captchaDialog.hint = hint
            captchaDialog.open()
        }

        function onCaptchaFlowDismissRequested() {
            PageController.showBusyIndicator(false)
            captchaDialog.close()
        }

        function onErrorOccurred(error) {
            if (captchaDialog.opened) {
                PageController.showBusyIndicator(false)
            }
        }
    }

    Connections {
        target: SubscriptionUiController

        function onRenewalLinkReceived(url) {
            Qt.openUrlExternally(url)
        }
    }

    Item {
        objectName: "busyIndicatorItem"

        anchors.fill: parent

        BusyIndicatorType {
            id: busyIndicator
            anchors.centerIn: parent
            z: 1
        }
    }

    Item {
        anchors.fill: parent

        ChangelogDrawer {
            id: changelogDrawer

            anchors.fill: parent
        }
    }
    } // конец appContent // AVPN (macOS rounded)

    function showUnsupportedConnectDrawer() {
        let headerText = qsTr("This subscription format is no longer supported")
        let descriptionText = qsTr("This legacy Amnezia subscription type can no longer be used to connect in this application version.\nRemove the server from the app to continue.")
        let yesButtonText = qsTr("Continue")
        let noButtonText = qsTr("Cancel")

        let yesButtonFunction = function() {
            if (ConnectionController.isConnected) {
                PageController.showNotificationMessage(qsTr("Cannot remove server during active connection"))
                return
            }

            PageController.showBusyIndicator(true)
            InstallController.removeServer(ServersUiController.defaultServerId)
            PageController.showBusyIndicator(false)
        }
        let noButtonFunction = function() {
        }

        showQuestionDrawer(headerText, descriptionText, yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
    }

    function showQuestionDrawer(headerText, descriptionText, yesButtonText, noButtonText, yesButtonFunction, noButtonFunction) {
        questionDrawer.headerText = headerText
        questionDrawer.descriptionText = descriptionText
        questionDrawer.yesButtonText = yesButtonText
        questionDrawer.noButtonText = noButtonText

        questionDrawer.yesButtonFunction = function() {
            questionDrawer.closeTriggered()
            if (yesButtonFunction && typeof yesButtonFunction === "function") {
                yesButtonFunction()
            }
        }
        questionDrawer.noButtonFunction = function() {
            questionDrawer.closeTriggered()
            if (noButtonFunction && typeof noButtonFunction === "function") {
                noButtonFunction()
            }
        }
        questionDrawer.openTriggered()
    }

    FileDialog {
        id: mainFileDialog
        objectName: "mainFileDialog"

        property bool isSaveMode: false

        fileMode: isSaveMode ? FileDialog.SaveFile : FileDialog.OpenFile

        onAccepted: SystemController.fileDialogClosed(true)
        onRejected: SystemController.fileDialogClosed(false)
    }

}

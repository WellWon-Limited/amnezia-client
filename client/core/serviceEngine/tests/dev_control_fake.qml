// AVPN (desktop test rig): the app's QML shape for tests/dev_control_check.cpp - the main window (objectName
// mainWindow), PageStart (pageStart: goAvpnTab, openScanner, the handlers of the current page's signals), its stack
// (tabBarStackView.currentItem) and bottom bar (avpnBottomNav.activated), and the pages' functions and signals the
// channel calls (PageConnectTribe.onOrbClicked, PageServersTribe.tapRow / tapAuto / tapMode, the Scanner's
// systemBack). The page bodies are stand-ins; check_dev_control_wiring.sh pins the real ones.
import QtQuick
import QtQuick.Window

Window {
    id: win
    objectName: "mainWindow"
    width: 360
    height: 640
    visible: true
    color: "#0A111D"

    Item {
        id: pageStart
        objectName: "pageStart"
        anchors.fill: parent
        property bool avpnNav: true
        property bool onboardingActive: false

        function goAvpnTab(index) {
            bottomNav.currentIndex = index
            stack.goToTabBarPageUrl(["PageConnectTribe", "PageSupportTribe", "PageReferralTribe", "PageAccountTribe"][index])
        }
        function openScanner(origin) {
            if (TribeEngine.scannerEnabled !== true) return   // PageStart: if (!ScanSwitches.scanner) return
            stack.goToTabBarPageUrl("PageScannerTribe", { origin: origin })
        }

        Item {
            id: stack
            objectName: "tabBarStackView"
            anchors.fill: parent
            property Item currentItem: null
            function goToTabBarPageUrl(name, extra) {
                const c = ({ PageConnectTribe: connectPage, PageSupportTribe: plainPage, PageReferralTribe: plainPage,
                             PageAccountTribe: plainPage, PageServersTribe: serversPage,
                             PageScannerTribe: scannerPage })[name]
                const props = { objectName: "qrc:/ui/qml/Tribe/Pages/" + name + ".qml" }
                for (const k in (extra || {})) props[k] = extra[k]
                const old = currentItem
                currentItem = c.createObject(stack, props)
                if (old) old.destroy()
            }
        }

        Connections {
            target: stack.currentItem
            ignoreUnknownSignals: true
            function onRequestServerPicker() { stack.goToTabBarPageUrl("PageServersTribe") }
            function onRequestScanner() {
                pageStart.openScanner(stack.currentItem.objectName.indexOf("PageServersTribe") !== -1 ? "servers" : "home")
            }
            function onPickNode(nodeId) { pageStart.goAvpnTab(0); TribeEngine.pinAndReconnect(nodeId) }
            function onPickAuto() { pageStart.goAvpnTab(0); TribeEngine.selectAuto() }
            function onPickTransport(mode) { TribeEngine.setTransportMode(mode) }
            function onBack() { pageStart.goAvpnTab(0) }
        }
        Connections {
            target: PageController
            function onEscapePressed() {
                if (stack.currentItem && typeof stack.currentItem.systemBack === "function")
                    stack.currentItem.systemBack()
            }
            function onRaiseMainWindow() { win.show(); win.raise() }
        }

        Item {
            id: bottomNav
            objectName: "avpnBottomNav"
            property int currentIndex: 0
            property bool referralVisible: true
            signal activated(int index)
            visible: pageStart.avpnNav && !pageStart.onboardingActive
            onActivated: function(index) { pageStart.goAvpnTab(index) }
        }

        Component.onCompleted: goAvpnTab(0)
    }

    Component {
        id: plainPage
        Rectangle { anchors.fill: parent; color: "#16233A" }
    }

    Component {
        id: connectPage
        Rectangle {
            anchors.fill: parent
            color: "#7ca2d0"
            signal requestServerPicker()
            signal requestScanner()
            function onOrbClicked() {
                if (TribeEngine.whitelistMode === true)
                    TribeEngine.setWhitelistAcked(false)
                TribeEngine.orbTap()
            }
        }
    }

    Component {
        id: serversPage
        Rectangle {
            id: sp
            anchors.fill: parent
            color: "#0A111D"
            signal back()
            signal pickNode(string nodeId)
            signal pickAuto()
            signal pickTransport(string mode)
            signal requestScanner()
            readonly property string transportMode: TribeEngine.transportMode
            readonly property bool autoMode: TribeEngine.currentNode.pinned !== true
            property bool showTransportSelector: true
            property bool awgInPool: true
            property bool xrayInPool: true
            property var countries: [
                { key: "ee", cc: "EE", name: "Эстония", nodeId: "15", rtt: 42, bars: 4, upstream: false,
                  badges: [{ proto: "awg", version: "2", supported: true, active: true },
                           { proto: "xray", version: "", supported: true, active: false }],
                  disabled: false, modeOnly: false, reason: "", attemptFailed: false, isCurrent: true, isChosen: false },
                { key: "up:3f9c2a7b1d4e8f60", cc: "NL", name: "Нидерланды 1", nodeId: "up:3f9c2a7b1d4e8f60", rtt: -1,
                  bars: -1, upstream: true, badges: [{ proto: "xray", version: "", supported: true, active: false }],
                  disabled: false, modeOnly: false, reason: "", attemptFailed: true, isCurrent: false, isChosen: false },
                { key: "us", cc: "US", name: "США", nodeId: "20", rtt: -1, bars: -1, upstream: false,
                  badges: [{ proto: "wireguard", version: "", supported: false, active: false }],
                  disabled: true, modeOnly: false, reason: "недоступно в этой версии", attemptFailed: false,
                  isCurrent: false, isChosen: false },
                { key: "fi", cc: "FI", name: "Финляндия", nodeId: "11:xray", rtt: 61, bars: 3, upstream: false,
                  badges: [{ proto: "xray", version: "", supported: true, active: false }],
                  disabled: true, modeOnly: true, reason: "недоступно для этого режима", attemptFailed: false,
                  isCurrent: false, isChosen: false }
            ]
            function tapRow(entry) {
                if (entry.modeOnly) { sp.pickTransport("auto"); sp.pickNode(entry.nodeId); return "mode_auto_then_pick" }
                if (entry.disabled) { PageController.showNotificationMessage(entry.reason); return "disabled" }
                if (entry.isChosen && !sp.autoMode) { sp.back(); return "already_chosen" }
                sp.pickNode(entry.nodeId)
                return "picked"
            }
            function tapAuto() {
                if (sp.autoMode) return "already_auto"
                sp.pickAuto()
                return "picked"
            }
            function tapMode(key) {
                if (!sp.showTransportSelector) return "hidden"
                if (sp.transportMode === key) return "selected"
                sp.pickTransport(key)
                return "requested"
            }
        }
    }

    Component {
        id: scannerPage
        Rectangle {
            id: scp
            anchors.fill: parent
            color: "#111827"
            property string origin: "home"
            signal back()
            signal requestServerPicker()
            function systemBack() {
                if (scp.origin === "servers") scp.requestServerPicker()
                else scp.back()
            }
            Component.onCompleted: TribeScanner.show()
            Component.onDestruction: TribeScanner.close()
        }
    }
}

// AVPN (desktop test rig): the app's QML shape for tests/dev_control_check.cpp - the main window (objectName
// mainWindow), PageStart (pageStart: goAvpnTab, openScanner, the handlers of the current page's signals), its stack
// (tabBarStackView.currentItem) and bottom bar (avpnBottomNav.activated), and the pages' functions and signals the
// channel calls (PageConnectTribe.onOrbClicked, PageServersTribe.tapRow / tapAuto / tapMode and its shownKeys /
// rowsByKey, the Scanner page's select / pane and its bar's action / fire, systemBack). The page bodies are stand-ins; check_dev_control_wiring.sh pins the real ones.
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
            // the real page's model: the location keys in the order on screen + each key's values (ServerListOrder.js)
            property var shownKeys: ["ee", "up:3f9c2a7b1d4e8f60", "us", "fi"]
            property var rowsByKey: ({
                "ee": { key: "ee", cc: "EE", name: "Эстония", nodeId: "15", rtt: 42, bars: 4, upstream: false,
                        badges: [{ proto: "awg", version: "2", supported: true, active: true },
                                 { proto: "xray", version: "", supported: true, active: false }],
                        disabled: false, modeOnly: false, reason: "", attemptFailed: false, isCurrent: true, isChosen: false },
                "up:3f9c2a7b1d4e8f60": { key: "up:3f9c2a7b1d4e8f60", cc: "NL", name: "Нидерланды 1",
                        nodeId: "up:3f9c2a7b1d4e8f60", rtt: -1, bars: -1, upstream: true,
                        badges: [{ proto: "xray", version: "", supported: true, active: false }],
                        disabled: false, modeOnly: false, reason: "", attemptFailed: true, isCurrent: false, isChosen: false },
                "us": { key: "us", cc: "US", name: "США", nodeId: "20", rtt: -1, bars: -1, upstream: false,
                        badges: [{ proto: "wireguard", version: "", supported: false, active: false }],
                        disabled: true, modeOnly: false, reason: "недоступно в этой версии", attemptFailed: false,
                        isCurrent: false, isChosen: false },
                "fi": { key: "fi", cc: "FI", name: "Финляндия", nodeId: "11:xray", rtt: 61, bars: 3, upstream: false,
                        badges: [{ proto: "xray", version: "", supported: true, active: false }],
                        disabled: true, modeOnly: true, reason: "недоступно для этого режима", attemptFailed: false,
                        isCurrent: false, isChosen: false },
                "gone": { key: "gone", cc: "LV", name: "Латвия", nodeId: "6", rtt: -1, bars: -1, upstream: false,
                        badges: [], disabled: false, modeOnly: false, reason: "", attemptFailed: false,
                        isCurrent: false, isChosen: false }
            })
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
            // the real page's state the channel reads and the functions its bar and rows call (PageScannerTribe.qml)
            readonly property var view: TribeScanner.view
            readonly property var barView: view.bar || ({})
            property string pane: "choose"
            readonly property bool choosing: pane === "choose"
            property string selected: ""
            function slotOf(sc) {
                const l = view.slots || []
                for (let i = 0; i < l.length; ++i)
                    if (String(l[i].scope || "") === sc) return l[i]
                return null
            }
            readonly property string chooseAction: bar.kind === "connect_and_scan" ? "connect"
                                                   : (bar.gated && slotOf(selected) !== null) ? "show" : "scan"
            function select(sc) { if (selected !== sc) selected = sc }
            function takeSelected() {
                TribeScanner.chooseCountry(selected)
                return String(TribeScanner.view.bar.scope || "") === selected
            }
            function scanSelected() { if (bar.gated || !takeSelected()) return; pane = "result"; TribeScanner.retry() }
            function showSelected() { pane = "result"; TribeScanner.showSlot(selected) }
            function connectSelected() { if (!takeSelected()) return; pane = "result"; TribeScanner.connectAndScan() }
            function retryScan() { TribeScanner.retry() }
            function stopScan() { TribeScanner.stop() }
            function navBack() {
                if (!choosing) { pane = "choose"; return }
                if (scp.origin === "servers") scp.requestServerPicker()
                else scp.back()
            }
            function systemBack() { navBack() }
            Component.onCompleted: TribeScanner.show()
            Component.onDestruction: TribeScanner.close()

            // TribeScanBar's shape: what a press does now (action), the press (fire), the button
            Item {
                id: bar
                objectName: "scannerBar"
                visible: true
                readonly property string kind: scp.barView.button || "retry"
                readonly property bool countdown: kind === "retry_in_s" || kind === "retry_in_min"
                readonly property bool fallback: kind === "connect_and_scan" && !scp.choosing
                readonly property int remaining: countdown ? 7 : 0
                readonly property bool gated: countdown
                function action() {
                    if (scp.choosing)
                        return scp.chooseAction === "show" ? "show" : scp.chooseAction === "connect" ? "connect" : "scan"
                    return kind === "stop" ? "stop" : fallback ? "connect" : "retry"
                }
                function fire(a) {
                    if (a === "scan") scp.scanSelected()
                    else if (a === "show") scp.showSelected()
                    else if (a === "stop") scp.stopScan()
                    else if (a === "connect") { if (scp.choosing) scp.connectSelected(); else TribeScanner.connectAndScan() }
                    else scp.retryScan()
                }
                Item {
                    objectName: "scannerActionButton"
                    enabled: scp.choosing ? (bar.kind !== "stop" && (scp.chooseAction === "show"
                                             || (scp.chooseAction === "connect" ? scp.barView.button_enabled !== false : !bar.gated)))
                             : (bar.kind === "stop" || bar.fallback) ? scp.barView.button_enabled !== false
                             : (bar.countdown ? false : scp.barView.button_enabled !== false)
                }
            }
        }
    }
}

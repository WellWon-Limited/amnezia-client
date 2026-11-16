import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme, ScanTexts, Haptic
import "../Pages" as TribePages   // PageConnectTribe.AutoVpnIcon (the home card's RU ball)

// AVPN: «Ваше подключение» — the Doctor's checks of the current connection inside the Scanner (artboard
// vpn-scanner-kit.js connCard, kit spec: radius 16, padding 14/16, rows 26 at step 10, caption 66, chips 26,
// glass button 46). Built from the kit: TribeCard surface, the Doctor sheet's stage icons, TribeFlag,
// TribeServiceChips (dense / askMarks), LoadBars, TribeProgressBar, TribeButton glass. `card` is the ScanView card
// JSON (ScanMachine.h scanViewToJson "card"): mode hidden | off | filling | filled | checking | checked, button
// hidden | ready | disabled | busy, facts server / services / sites / speed {state pending | running | done |
// unknown | off, chips, ok, bars, word, needs_button}, server_ms, progress 0..1.
Rectangle {
    id: root

    property var card: ({})
    property string serverLabel: ""      // the live node: card.server_label, else the view's current row
    property string serverCc: ""
    signal checkTapped()

    readonly property string mode: card.mode || "hidden"
    readonly property bool off: mode === "off"
    readonly property var server: card.server || ({})
    readonly property var services: card.services || ({})
    readonly property var sites: card.sites || ({})
    readonly property var speedFact: card.speed || null
    readonly property string button: card.button || "hidden"
    readonly property bool checking: mode === "checking"

    readonly property var serviceKeys: ["telegram", "youtube", "instagram", "whatsapp"]
    function chipsModel(states) {
        const out = []
        for (let i = 0; i < serviceKeys.length; ++i)
            out.push({ key: serviceKeys[i], state: (states && states.length > i) ? Number(states[i]) : -1 })
        return out
    }
    function waiting(f) { return !f || f.state === "pending" || f.state === "running" }
    // stage icon of a fact (TribeDoctorSheet stage rows): future / current pulse / ok check / warn dot / skip dash
    function iconOf(f, kind) {
        if (!f || f.state === "pending") return "future"
        if (f.state === "running") return "current"
        if (f.state === "off" || f.state === "unknown") return "skip"
        if (kind === "services") {
            if (f.needs_button) return "skip"
            const c = f.chips || []
            for (let i = 0; i < c.length; ++i)
                if (Number(c[i]) < 2) return "warn"
            return "ok"
        }
        if (kind === "sites") return f.ok ? "ok" : "warn"
        if (kind === "speed") return Number(f.bars || 0) >= 3 ? "ok" : "warn"
        return "ok"
    }

    visible: mode !== "hidden"
    implicitHeight: col.implicitHeight + 2 * 14
    radius: Theme.radius.lg
    color: Theme.color.surface1
    border.width: 1
    border.color: Theme.color.border

    // the Doctor sheet's stage glyphs, 20 x 20 (TribeDoctorSheet.qml stage row)
    component StageIcon: Item {
        id: si
        property string kind: "future"
        implicitWidth: 20; implicitHeight: 20
        Rectangle {
            anchors.centerIn: parent
            width: 8; height: 8; radius: 4
            visible: si.kind === "future"
            color: Theme.color.text3
            opacity: 0.4
        }
        Rectangle {
            anchors.centerIn: parent
            width: 10; height: 10; radius: 5
            visible: si.kind === "current"
            color: Theme.color.accent
            SequentialAnimation on opacity {
                running: si.kind === "current" && si.visible && !Theme.motion.reduceMotion
                loops: Animation.Infinite
                NumberAnimation { from: 1.0; to: 0.35; duration: 600; easing.type: Easing.InOutSine }
                NumberAnimation { from: 0.35; to: 1.0; duration: 600; easing.type: Easing.InOutSine }
            }
        }
        Shape {       // ok: the Doctor sheet's check (14 grid)
            anchors.centerIn: parent
            width: 14; height: 14
            visible: si.kind === "ok"
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: Theme.color.connected; fillColor: "transparent"; strokeWidth: 2
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M2 8 L6 12 L13 3" }
            }
        }
        Rectangle {
            anchors.centerIn: parent
            width: 10; height: 10; radius: 5
            visible: si.kind === "warn" || si.kind === "bad"
            color: si.kind === "bad" ? Theme.color.danger : Theme.color.warning
        }
        Rectangle {
            anchors.centerIn: parent
            width: 8; height: 2; radius: 1
            visible: si.kind === "skip"
            color: Theme.color.text3
        }
    }

    component Caption: Text {
        Layout.preferredWidth: Theme.scan.cardLabel
        textFormat: Text.PlainText
        elide: Text.ElideRight
        color: Theme.color.text2
        font.family: Theme.font.body
        font.pixelSize: Theme.font.monoData
    }

    component Word: Text {
        textFormat: Text.PlainText
        elide: Text.ElideRight
        font.family: Theme.font.body
        font.pixelSize: Theme.font.monoData
        font.weight: Theme.font.wMedium
    }

    component Dots: Text {
        text: "…"
        color: Theme.color.text3
        font.family: Theme.font.body
        font.pixelSize: Theme.font.bodyS
        font.weight: Theme.font.wMedium
    }

    // the RU ball = the home card's own component (PageConnectTribe.AutoVpnIcon: ball, ring, «RU»; `active` false
    // = its dimmed state) at the card's 18 px slot: an item of 21 gives the 18 px ball and its 24 px ring, which
    // overhang the slot like the artboard's box-shadow ring
    component RuMini: Item {
        id: ru
        property bool on: true
        implicitWidth: 18; implicitHeight: 18
        TribePages.PageConnectTribe.AutoVpnIcon {
            anchors.centerIn: parent
            width: 21; height: 21
            active: ru.on
        }
    }

    ColumnLayout {
        id: col
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.leftMargin: Theme.space.lg
        anchors.rightMargin: Theme.space.lg
        anchors.topMargin: 14
        spacing: 10

        Text {
            text: ScanTexts.cardTitle
            textFormat: Text.PlainText
            color: Theme.color.text1
            font.family: Theme.font.display
            font.pixelSize: Theme.font.bodyS + 1
            font.weight: Theme.font.wBold
        }

        TribeProgressBar {
            visible: root.checking
            Layout.fillWidth: true
            Layout.topMargin: -2
            Layout.bottomMargin: 2
            percent: Math.round(100 * Number(root.card.progress || 0))
        }

        // ── off: one row «VPN не подключён» ──
        RowLayout {
            visible: root.off
            Layout.fillWidth: true
            Layout.minimumHeight: Theme.scan.cardRow
            spacing: Theme.space.sm
            StageIcon { kind: "skip" }
            Text {
                Layout.fillWidth: true
                text: ScanTexts.cardOff
                textFormat: Text.PlainText
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
            }
        }

        // ── Сервер: flag + name + ms ──
        RowLayout {
            visible: !root.off
            Layout.fillWidth: true
            Layout.minimumHeight: Theme.scan.cardRow
            spacing: Theme.space.sm
            StageIcon { kind: root.iconOf(root.server, "server") }
            Caption { text: ScanTexts.cardServer }
            Dots { visible: root.waiting(root.server) }
            TribeFlag {
                visible: !root.waiting(root.server)
                Layout.preferredWidth: 18; Layout.preferredHeight: 18
                code: root.serverCc
            }
            Word {
                visible: !root.waiting(root.server)
                Layout.fillWidth: true
                text: root.serverLabel
                color: Theme.color.text1
                font.pixelSize: Theme.font.bodyS
            }
            Text {
                visible: !root.waiting(root.server) && Number(root.card.server_ms ?? -1) >= 0
                text: ScanTexts.ms.arg(Number(root.card.server_ms))
                textFormat: Text.PlainText
                color: Theme.color.text3
                font.family: Theme.font.mono
                font.pixelSize: Theme.font.caption
            }
            Item { visible: root.waiting(root.server); Layout.fillWidth: true }
        }

        // ── Сервисы: the four home chips, or «?» + «по кнопке» ──
        RowLayout {
            visible: !root.off
            Layout.fillWidth: true
            Layout.minimumHeight: Theme.scan.cardRow
            spacing: Theme.space.sm
            readonly property bool ask: !root.waiting(root.services)
                                        && (root.services.needs_button === true || root.services.state === "unknown")
            StageIcon { kind: root.iconOf(root.services, "services") }
            Caption { text: ScanTexts.cardServices }
            Dots { visible: root.waiting(root.services) }
            TribeServiceChips {
                visible: !root.waiting(root.services)
                Layout.fillWidth: !parent.ask
                Layout.preferredHeight: chipH
                dense: true
                askMarks: parent.ask
                model: root.chipsModel(root.services.chips)
            }
            Word {
                visible: parent.ask
                text: ScanTexts.cardByButton
                color: Theme.color.text3
            }
            Item { visible: root.waiting(root.services) || parent.ask; Layout.fillWidth: true }
        }

        // ── Сайты РФ: RU + «работают» / «не открываются» / «выключено» ──
        RowLayout {
            visible: !root.off
            Layout.fillWidth: true
            Layout.minimumHeight: Theme.scan.cardRow
            spacing: Theme.space.sm
            readonly property bool sitesOff: root.sites.state === "off"
            StageIcon { kind: root.iconOf(root.sites, "sites") }
            Caption { text: ScanTexts.cardSites }
            Dots { visible: root.waiting(root.sites) || root.sites.state === "unknown" }
            RuMini {
                visible: !root.waiting(root.sites) && root.sites.state !== "unknown"
                on: !parent.sitesOff
                Layout.preferredWidth: 18; Layout.preferredHeight: 18
            }
            Word {
                visible: !root.waiting(root.sites) && root.sites.state !== "unknown"
                Layout.fillWidth: true
                text: parent.sitesOff ? ScanTexts.sitesOff : (root.sites.ok ? ScanTexts.sitesOk : ScanTexts.sitesBad)
                color: parent.sitesOff ? Theme.color.text3 : (root.sites.ok ? Theme.color.connected : Theme.color.danger)
            }
            Item { visible: root.waiting(root.sites) || root.sites.state === "unknown"; Layout.fillWidth: true }
        }

        // ── Скорость (the button's check only): bars + one word ──
        RowLayout {
            visible: !root.off && root.speedFact !== null
            Layout.fillWidth: true
            Layout.minimumHeight: Theme.scan.cardRow
            spacing: Theme.space.sm
            readonly property int level: root.speedFact ? Number(root.speedFact.bars || 0) : 0
            StageIcon { kind: root.iconOf(root.speedFact, "speed") }
            Caption { text: ScanTexts.cardSpeed }
            Dots { visible: root.waiting(root.speedFact) }
            LoadBars {
                visible: !root.waiting(root.speedFact)
                level: parent.level
            }
            Word {
                visible: !root.waiting(root.speedFact)
                Layout.fillWidth: true
                text: (root.speedFact && root.speedFact.word === "comfortable") ? ScanTexts.speedComfortable
                                                                                 : ScanTexts.speedSlow
                color: parent.level >= 3 ? Theme.color.connected : Theme.color.warning
            }
            Item { visible: root.waiting(root.speedFact); Layout.fillWidth: true }
        }

        TribeButton {
            visible: root.button !== "hidden" && !root.off
            Layout.fillWidth: true
            Layout.topMargin: 2
            variant: "glass"
            text: root.button === "busy" ? ScanTexts.cardChecking : ScanTexts.cardCheck
            // «disabled» = the report queue is full: the button stays pressable so the reason is one tap away
            // (plan §3.1, F12); only a running check disables it
            enabled: root.button !== "busy"
            onClicked: { Haptic.play("light"); root.checkTapped() }
        }
    }
}

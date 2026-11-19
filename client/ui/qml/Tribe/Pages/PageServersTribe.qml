pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN (server picker 2026-07-10): полноэкранный выбор сервера — замена шторки TribeNodeSheet.
// Поиск, «Авто (быстрейший)», строки локаций (флаг + бейджи транспортов + RTT + бары). Одна
// строка = одна ЛОКАЦИЯ: пинится ЛУЧШАЯ нода локации на момент тапа. Переключение — сигналами
// через PageStart (уход со страницы СНАЧАЛА, движок ПОТОМ — CONNECT-INVARIANTS §5);
// реконнект-семантика — в TribeEngine.pinAndReconnect (kill-switch features.picker_instant_reconnect).
// AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): у локации может быть несколько транспортов
// (Amnezia/Xray) — бейджи в строке + селектор режима «Авто / Amnezia / Xray» над списком.
// AVPN upstream nodes (release A, point 16; contract 1.10.0, owner 17.11): a provider profile (role `upstream`) is
// an ordinary row - our label (the engine never passes the server's text, never «Сервер N»), the Xray badge. A
// country profile («<страна> n») has its flag; a white-list profile («Белые списки n», role upstreamKind
// "whitelist") the kit's neutral globe tile; the provider's balancer ("auto") is never a row (the engine keeps it
// for Auto). Figures: the Scanner's latest result on this network (nodePool, no ICMP target), else none. The
// engine keys each as a location of its own (never merged with ours); provider country rows come after ours in
// the engine's order (tier, then pool order), white-list rows after them. Flag off: no such row exists.
// No measurement (owner's register, 11.11): «—» and the bars' idle track - never a health guess drawn as signal.
PageType {
    id: root

    signal back()
    signal pickNode(string nodeId)
    signal pickAuto()
    // AVPN awg31-xray-v1: смена режима транспорта — тоже через PageStart (движок может
    // переподнять туннель ⇒ инвариант §5 «уход с UI выбора сначала» действует и здесь).
    signal pickTransport(string mode)
    // AVPN (Scanner): the pinned «Запустить сканер» (the second entry into the Scanner; back returns here)
    signal requestScanner()
    // a short notice for the host (PageStart: the top shade, or the toast with the scanner switch off)
    signal pageNotice(string text)


    // iOS: PageController.safeArea* только для Android → max с SafeArea (как PageNotificationsTribe)
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property var pool: hasEngine ? (TribeEngine.nodePool || []) : []
    // гард undefined currentNode — как в PageLocationsTribe (страница до первой подписки)
    readonly property var cur: (hasEngine && TribeEngine.currentNode) ? TribeEngine.currentNode : ({})
    // Device test of 142 (second round): what the person CHOSE (Auto or a server) and what is CONNECTED now are two
    // facts. The engine's currentNode.choiceNodeId ("" = Auto) names the choice; the row of the choice is the
    // selected one (the Auto card's look), the connected row wears ONLINE. A binary without choiceNodeId: as before
    // (the shown node is both).
    readonly property bool hasChoice: cur.choiceNodeId !== undefined
    readonly property string choiceId: hasChoice ? String(cur.choiceNodeId) : ""
    readonly property bool autoMode: hasChoice ? choiceId === "" : !cur.pinned
    // ONLINE у строки текущей страны — то же свойство движка, что бейдж ONLINE на главной (5.1.108):
    // данные идут через туннель (живая проба или whoami works), от флага node_scan не зависит.
    readonly property bool onlineNow: hasEngine && TribeEngine.state === "connected"
                                      && TribeEngine.dataFlowing === true
    property string query: ""

    // AVPN awg31-xray-v1: режим транспорта — факт из движка (=== undefined на старом бинаре ⇒ "auto").
    readonly property string transportMode: (hasEngine && TribeEngine.transportMode)
                                            ? TribeEngine.transportMode : "auto"
    // Транспорты, реально представленные в пуле (живые ноды) и умеемые клиентом. Селектор
    // прячем, пока транспорт один — он нужен только там, где есть из чего выбирать (или когда
    // ручной режим уже включён и из него надо уметь выйти).
    readonly property bool xrayInPool: hasEnginePool("xray")
    readonly property bool awgInPool: hasEnginePool("awg")
    readonly property bool showTransportSelector: xrayInPool || root.transportMode !== "auto"

    function hasEnginePool(proto) {
        for (let i = 0; i < pool.length; ++i) {
            const n = pool[i]
            if (!n || n.alive !== true || n.transportSupported === false)
                continue
            if (String(n.proto || "awg") === proto)
                return true
        }
        return false
    }

    // Группировка alive-нод по ЛОКАЦИЯМ + фильтр + сортировка «быстрые СВЕРХУ» (страница читается
    // сверху вниз — осознанная инверсия шторочного rankFastestAtBottom). Лучшая нода локации:
    // min measuredRttMs; без замера — max health, потом max weight.
    // МЕМОИЗАЦИЯ (ревью 2026-07-10): движок эмитит общий changed() часто (тик ~4с, RTT-ответы по
    // одной ноде), а реассайн model новым JS-массивом = полный reset ListView (пересоздание
    // делегатов, сброс скролла). Пересобираем массив ТОЛЬКО при реальном изменении содержимого.
    property var countries: []
    property string countriesKey: ""
    // Device test of 142: the list re-sorted and jumped under the finger - every RTT answer or health tick
    // (changed(), ~4 s) reassigned the model, which resets the ListView to the top and re-sorts the rows. While the
    // list is being touched an update waits (rebuildPending) and is applied when the movement ends; an applied
    // update keeps the scroll position.
    property bool rebuildPending: false
    readonly property bool listTouched: list.moving || list.dragging

    function rebuildCountries() {
        if (root.listTouched) {
            root.rebuildPending = true
            return
        }
        root.rebuildPending = false
        const next = computeCountries()
        const key = JSON.stringify(next)
        if (key === root.countriesKey) return
        root.countriesKey = key
        const top = list.originY - list.topMargin
        const offset = list.contentY - top
        root.countries = next
        if (offset > 0) {
            // a new array resets the view to the top: put it back where the person left it (clamped to the end)
            const end = Math.max(0, list.contentHeight + list.topMargin + list.bottomMargin - list.height)
            list.contentY = list.originY - list.topMargin + Math.min(offset, end)
        }
    }
    onListTouchedChanged: if (!listTouched && rebuildPending) rebuildCountries()

    // AVPN awg31-xray-v1: ключ строки — движковый `location` (host_id, фолбэк country_code+region);
    // старый бинарь поля не отдаёт ⇒ фолбэк на страну, поведение как раньше.
    function locationKeyOf(n) {
        const loc = String(n.location || "")
        return loc.length > 0 ? loc : ("cc:" + String(n.countryCode || "??").toUpperCase())
    }

    // Лучшая нода из списка: min measuredRttMs; без замера — max health, потом max weight.
    function bestOf(nodes) {
        let best = nodes[0]
        for (let j = 1; j < nodes.length; ++j) {
            const a = nodes[j], b = best
            const am = a.measuredRttMs >= 0, bm = b.measuredRttMs >= 0
            if (am && (!bm || a.measuredRttMs < b.measuredRttMs)) { best = a; continue }
            if (!am && !bm && ((a.health || 0) > (b.health || 0)
                    || ((a.health || 0) === (b.health || 0) && (a.weight || 0) > (b.weight || 0))))
                best = a
        }
        return best
    }

    function computeCountries() {
        const byLoc = {}
        const firstAt = {}   // AVPN upstream nodes: the engine's order of a location (its first pool row)
        for (let i = 0; i < pool.length; ++i) {
            const n = pool[i]
            if (!n || n.alive !== true) continue
            // contract 1.10.0: the provider's balancer is an Auto candidate only (nodePool already leaves it out)
            if (n.upstream === true && n.upstreamKind === "auto") continue
            const key = root.locationKeyOf(n)
            if (!byLoc[key]) { byLoc[key] = []; firstAt[key] = i }
            byLoc[key].push(n)
        }
        const q = query.trim().toLowerCase()
        const mode = root.transportMode
        const out = []
        for (const key in byLoc) {
            const nodes = byLoc[key]
            // Пригодные для пина: клиент умеет протокол (transportSupported) И ручной режим его
            // разрешает. Task 10 остаётся в силе: неподдерживаемая нода «best» не становится —
            // тап по ней упирался бы в сторожа движка.
            const usable = []
            let anySupported = false
            for (let j = 0; j < nodes.length; ++j) {
                const n = nodes[j]
                const proto = String(n.proto || "awg")
                if (n.transportSupported === false) continue
                anySupported = true
                if (mode === "awg" && proto === "xray") continue
                if (mode === "xray" && proto !== "xray") continue
                usable.push(n)
            }
            const disabled = usable.length === 0
            const best = root.bestOf(disabled ? nodes : usable)
            // AVPN upstream nodes: a provider profile row (its location holds only itself); a white-list profile
            // has no country - no flag, the neutral tile (TribeFlag fallback).
            const isUp = best.upstream === true
            const isWl = isUp && best.upstreamKind === "whitelist"
            const cc = isWl ? "" : String(best.countryCode || "??").toUpperCase()
            // Имя локации: движок отдаёт подпись самой ноды, иначе подпись соседа по хосту (AWG),
            // иначе название страны (nodePool, pickerDisplay) — код региона («ee») не показываем.
            // A provider row always has the engine's name (upstreamRowName).
            const name = best.name || cc
            if (q && !(name.toLowerCase().includes(q) || cc.toLowerCase().includes(q)
                       || String(best.region || "").toLowerCase().includes(q)))
                continue
            let isCur = false, isChosen = false
            for (let k = 0; k < nodes.length; ++k) {
                if (cur.nodeId && nodes[k].nodeId === cur.nodeId) isCur = true
                if (root.choiceId !== "" && nodes[k].nodeId === root.choiceId) isChosen = true
            }
            if (!root.hasChoice) isChosen = isCur
            // Бейджи транспортов локации: порядок — из движкового `transports` (== transport_rank),
            // версия/поддержка — из представителя каждого протокола. Активный (поднятый) транспорт
            // движок кладёт в activeProto строк ЭТОЙ локации (пусто, если туннель не здесь).
            const byProto = {}
            for (let m = 0; m < nodes.length; ++m) {
                const p = String(nodes[m].proto || "awg")
                if (!byProto[p]) byProto[p] = nodes[m]
            }
            const order = (best.transports && best.transports.length > 0)
                          ? best.transports : Object.keys(byProto)
            const activeProto = String(nodes[0].activeProto || "")
            const badges = []
            for (let t = 0; t < order.length; ++t) {
                const p = String(order[t])
                const bn = byProto[p]
                if (!bn) continue
                badges.push({ proto: p,
                              version: String(bn.protoVersion || ""), // "2"/"3"/"3.1"; xray — пусто
                              supported: bn.transportSupported !== false,
                              active: activeProto.length > 0 && activeProto === p })
            }
            // The off-tunnel figure belongs to the location (its exit host), not to the transport the mode lets
            // through: a mode switch keeps it (coordinator 18.11) - the best row's own figure, else a sibling's.
            let figure = best
            if (!(best.measuredRttMs >= 0))
                for (let f = 0; f < nodes.length; ++f)
                    if (nodes[f].measuredRttMs >= 0) { figure = nodes[f]; break }
            out.push({ key: key, cc: cc, name: name, nodeId: best.nodeId,
                       rtt: figure.measuredRttMs,
                       // -1 = no measurement (own: no ICMP answer yet; provider: no Scanner result on this
                       // network): the idle track, never the server's health drawn as five green bars
                       bars: figure.measuredBars >= 0 ? figure.measuredBars : -1,
                       // order only (unmeasured own rows keep their old place): not shown
                       healthRank: Math.round((best.health || 0) * 5),
                       upstream: isUp,
                       // 0 own, 1 provider country, 2 white-list (no group in the artboard: placed last)
                       group: isWl ? 2 : (isUp ? 1 : 0),
                       tier: isUp ? Number(best.upstreamTier || 0) : 0,
                       order: isUp ? firstAt[key] : 0,
                       badges: badges,
                       disabled: disabled,
                       // greyed only by the transport mode (the client can raise it): a tap switches to «Авто» (V7)
                       modeOnly: disabled && anySupported,
                       // причина серой строки: транспорт есть, но не тот режим — или клиент его не умеет
                       reason: !disabled ? ""
                               : (anySupported ? qsTr("недоступно для этого режима")
                                               : qsTr("недоступно в этой версии")),
                       // V6: the engine's per-network evidence (nodePool lastAttemptFailed, undefined on older
                       // binaries): the last connect attempt through this row on THIS network failed
                       attemptFailed: best.lastAttemptFailed === true,
                       isCurrent: isCur,
                       isChosen: isChosen })
        }
        out.sort(function(a, b) {
            if (a.disabled !== b.disabled) return a.disabled ? 1 : -1   // серые — вниз
            // AVPN upstream nodes: provider country rows after ours, white-list rows after them, each in the
            // engine's order (tier, then pool)
            if (a.group !== b.group) return a.group - b.group
            if (a.upstream) return (a.tier - b.tier) || (a.order - b.order)
            const am = a.rtt >= 0, bm = b.rtt >= 0
            if (am !== bm) return am ? -1 : 1
            if (am) return a.rtt - b.rtt
            return b.healthRank - a.healthRank
        })
        return out
    }

    // V7: the beat between the mode switching to «Авто» (visible on this page) and selecting the tapped server
    Timer {
        id: modePick
        property string nodeId: ""
        interval: Theme.motion.slow * 2
        onTriggered: if (nodeId !== "") root.pickNode(nodeId)
    }

    onQueryChanged: rebuildCountries()
    onTransportModeChanged: rebuildCountries()   // AVPN awg31-xray-v1: смена режима меняет серые строки
    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onChanged() { root.rebuildCountries() }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // AVPN upstream nodes: placeholder of a row without a flag - the kit's "globe" stroke icon on the flag tile.
    Component {
        id: globeTile
        Rectangle {
            radius: width / 2
            color: Theme.color.surface3
            border.width: 1
            border.color: Theme.color.border
            TribeStrokeIcon {
                anchors.centerIn: parent
                width: parent.width * 0.5
                height: parent.height * 0.5
                icon: "globe"
                tint: Theme.color.text3
            }
        }
    }

    // свайп слева-направо = «назад» (жалоба 2026-07-11)
    TribeEdgeBack { onTriggered: root.back() }

    // Замер RTT всех нод при открытии (async ICMP; при connected — no-op, показываем кэш).
    Component.onCompleted: {
        rebuildCountries()
        if (hasEngine) TribeEngine.probeNodeRtt()
    }
    // refreshPool — СИНХРОННЫЙ nested-loop → ТОЛЬКО отложенно, не из кадра показа (как в шторке).
    Timer {
        interval: 350; running: root.hasEngine; repeat: false
        onTriggered: TribeEngine.refreshPool()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        TribeHeader {
            Layout.fillWidth: true
            title: qsTr("Выбор сервера")
            showBack: true
            // ТОЛЬКО root.back() → PageStart вернёт на Connect. НЕ PageController.closePage()
            // (страница открыта через replace, depth<=1 → closePage прячет окно).
            onBackClicked: root.back()
            rightItem: Text {
                anchors.verticalCenter: parent.verticalCenter
                text: qsTr("Локаций: %1").arg(root.countries.length)
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: Theme.font.caption
                font.weight: Theme.font.wSemibold
            }
        }

        // ── поиск ──
        TribeField {
            id: searchField
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.md
            placeholderText: qsTr("Поиск страны")
            leftPadding: Theme.space.xl + Theme.space.lg
            onTextChanged: root.query = text
            Shape {
                width: 18; height: 18
                anchors.left: parent.left
                anchors.leftMargin: Theme.space.md
                anchors.verticalCenter: parent.verticalCenter
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.text3; strokeWidth: 1.8
                    fillColor: "transparent"
                    capStyle: ShapePath.RoundCap
                    PathSvg { path: "M8.25 3a5.25 5.25 0 1 0 0 10.5a5.25 5.25 0 1 0 0-10.5M12.4 12.4L15.5 15.5" }
                }
            }
        }

        // ── карточка «Авто (быстрейший)» ──
        Rectangle {
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.md
            implicitHeight: 70
            radius: Theme.radius.lg
            color: root.autoMode ? Theme.color.chipSelected : Theme.color.surface1
            border.width: 1
            border.color: root.autoMode ? Theme.color.accent : Theme.color.border
            Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
            Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space.lg
                anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.md

                Rectangle {
                    Layout.preferredWidth: 42
                    Layout.preferredHeight: 42
                    radius: Theme.radius.md
                    gradient: Gradient {
                        GradientStop { position: 0; color: Theme.color.gradTop }
                        GradientStop { position: 1; color: Theme.color.gradBottom }
                    }
                    Shape {
                        anchors.centerIn: parent
                        width: 22; height: 22
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: "transparent"
                            fillColor: Theme.color.bg800
                            PathSvg { path: "M13 2L4.5 13.5H11L9.5 22L19 10.5H12.5Z" }
                        }
                        transform: Scale { xScale: 22 / 24; yScale: 22 / 24 }
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text {
                        Layout.fillWidth: true
                        // One text in every state, as the approved artboard's «Авто» card (kit autoCard): the
                        // former switch on lastSelectionMeasured flipped the card on every engine selection
                        // (device test of 142).
                        text: qsTr("Авто (быстрейший)")
                        textFormat: Text.PlainText
                        elide: Text.ElideRight
                        color: Theme.color.text1
                        font.family: Theme.font.display
                        font.pixelSize: Theme.font.bodyM
                        font.weight: Theme.font.wBold
                    }
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Сервис подберёт быстрейший узел")
                        textFormat: Text.PlainText
                        elide: Text.ElideRight
                        color: Theme.color.text2
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.caption
                    }
                }

                Rectangle {
                    Layout.preferredWidth: 22
                    Layout.preferredHeight: 22
                    radius: Theme.radius.pill
                    color: root.autoMode ? Theme.color.accent : Theme.color.surface3
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Shape {
                        anchors.centerIn: parent
                        width: 12; height: 12
                        visible: root.autoMode
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.bg800; strokeWidth: 2.6
                            fillColor: "transparent"
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M5 12.5L9.5 17L19 7" }
                        }
                        transform: Scale { xScale: 12 / 24; yScale: 12 / 24 }
                    }
                }
            }
            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    // AVPN (девайс-приёмка 2026-09-02): уже в авто — НИЧЕГО не делаем и остаёмся
                    // на экране. Раньше повторный тап уводил на главный, что читалось как
                    // «кнопка выключила авто».
                    if (root.autoMode) return
                    Haptic.play("selection"); Haptic.arm() // AVPN (haptics): итог реконнекта отыграет PageConnectTribe
                    root.pickAuto()
                }
            }
        }

        // ── AVPN awg31-xray-v1: режим транспорта («Авто / Amnezia / Xray») ──
        // Видим только когда есть из чего выбирать (в пуле больше одного транспорта) или когда
        // ручной режим уже включён — из него надо уметь выйти. Движок — авторитет: он может
        // отклонить режим (тост от фасада) и сам решает, переподнимать ли туннель.
        Text {
            visible: root.showTransportSelector
            Layout.leftMargin: Theme.space.xl
            Layout.topMargin: Theme.space.lg
            text: qsTr("РЕЖИМ СОЕДИНЕНИЯ")
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            font.letterSpacing: Theme.font.trackCaption * Theme.font.caption
        }

        TribeTransportSelector {
            visible: root.showTransportSelector
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.sm
            mode: root.transportMode
            awgAvailable: root.awgInPool
            xrayAvailable: root.xrayInPool
            // §5: страница движок не зовёт — сигнал уходит в PageStart
            onModeRequested: (m) => root.pickTransport(m)
        }

        // AVPN (Scanner, artboard 16.11): with the `scanner` switch on the hint under the mode is removed (the
        // mode is visible anyway); switch off = as before
        Text {
            visible: root.showTransportSelector && !ScanSwitches.scanner
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.sm
            text: root.transportMode === "awg"
                      ? qsTr("Только транспорт Amnezia (AmneziaWG)")
                      : (root.transportMode === "xray"
                             ? qsTr("Только транспорт Xray (VLESS Reality)")
                             : qsTr("Сервис выберет лучший транспорт"))
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
        }

        // ── заголовок секции ── (bottomMargin нет: воздух под лейблом — контент-инсет списка,
        // скроллится с ним; рамочный зазор давал мёртвую полосу при прокрутке — паттерн 2026-07-10) // AVPN
        Text {
            Layout.leftMargin: Theme.space.xl
            Layout.topMargin: Theme.space.lg
            text: root.query.trim().length > 0 ? qsTr("РЕЗУЛЬТАТЫ") : qsTr("ВСЕ ЛОКАЦИИ")
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            font.letterSpacing: Theme.font.trackCaption * Theme.font.caption
        }

        // ── список стран (обёртка Item: empty-state НЕ ребёнок ListView — дети Flickable
        // репарентятся в contentItem, чья высота при пустой модели 0 → centerIn ненадёжен) ──
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl

            ListView {
                id: list
                anchors.fill: parent
                clip: true
                topMargin: Theme.space.sm   // воздух под лейблом — скроллится со списком
                // AVPN (Scanner): air under the last row inside the scroll, above the pinned button
                bottomMargin: ScanSwitches.scanner ? Theme.space.lg : 0
                spacing: Theme.space.sm
                model: root.countries
                boundsBehavior: Flickable.StopAtBounds

                delegate: Rectangle {
                    id: row
                    required property var modelData
                    width: ListView.view.width
                    implicitHeight: 66
                    radius: Theme.radius.lg
                    // AVPN awg31-xray-v1: локация без транспорта под текущий режим — серая
                    opacity: row.modelData.disabled ? 0.5 : 1.0
                    color: row.modelData.isChosen ? Theme.color.chipSelected : Theme.color.surface1
                    border.width: 1
                    border.color: row.modelData.isChosen ? Theme.color.accent : Theme.color.border
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.md
                        anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md

                        TribeFlag {
                            Layout.preferredWidth: 38
                            Layout.preferredHeight: 38
                            code: row.modelData.cc
                            // AVPN upstream nodes: a provider row without a country - the kit's globe on a
                            // flag tile (own rows keep their previous look)
                            fallback: row.modelData.upstream ? globeTile : null
                            whitelist: row.modelData.group === 2   // a white-list profile: the white disc with a black globe
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 3
                            Text {
                                Layout.fillWidth: true
                                text: row.modelData.name
                                textFormat: Text.PlainText
                                elide: Text.ElideRight
                                color: Theme.color.text1
                                font.family: Theme.font.display
                                font.pixelSize: Theme.font.bodyS + 1
                                font.weight: Theme.font.wBold
                            }
                            // AVPN awg31-xray-v1: бейджи ТРАНСПОРТОВ локации — под именем, от начала
                            // строки, порядок = серверный transport_rank. Активный (поднятый)
                            // подсвечен акцентом; неподдерживаемый клиентом — приглушён.
                            // (Заменило одиночную пилюлю версии AWG; заодно чинит «3.1» — версия
                            // теперь приходит строкой, а не сравнивается с "2"/"3".)
                            RowLayout {
                                Layout.alignment: Qt.AlignLeft
                                spacing: Theme.space.xs
                                visible: row.modelData.badges.length > 0
                                Repeater {
                                    model: row.modelData.badges
                                    delegate: TribeTransportBadge {
                                        required property var modelData
                                        transport: modelData.proto
                                        version: modelData.version
                                        active: modelData.active
                                        supported: modelData.supported
                                        // xray «Подключено» только после пробы — пока идёт проверка,
                                        // бейдж честно жёлтый, а не зелёный/акцентный
                                        verifying: root.hasEngine && TribeEngine.verifying === true
                                    }
                                }
                                // Пройденная проверка данных через выход — тот же бейдж ONLINE, что на
                                // главной (малый вариант), только у строки, где поднят туннель
                                // (владелец, тест 5.1.102).
                                TribeLabelBadge {
                                    visible: row.modelData.isCurrent && root.onlineNow
                                    small: true
                                    label: qsTr("ONLINE")
                                    fg: Theme.color.connected
                                    fill: Theme.color.badgeOn
                                }
                            }

                            // серая строка: транспорта под текущий режим тут нет (или клиент его не умеет)
                            Text {
                                visible: row.modelData.disabled
                                Layout.fillWidth: true
                                text: row.modelData.reason
                                textFormat: Text.PlainText
                                elide: Text.ElideRight
                                color: Theme.color.text3
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.caption - 1
                            }
                        }

                        // AVPN: справа — палочки сигнала, под ними скорость (RTT). Палочки чуть
                        // уменьшены (scale) и подняты; скорость выровнена по их центру.
                        ColumnLayout {
                            id: sigCol
                            Layout.alignment: Qt.AlignVCenter
                            spacing: 3
                            // one rule with the Connect card (TribeEngine.nodeFigure): the row carrying the tunnel -
                            // own: the live probe, provider: its Scanner figure or none; other rows their figure
                            readonly property bool currentLive: row.modelData.isCurrent && root.hasEngine
                                                                && TribeEngine.state === "connected"
                            // a row whose last attempt on this network failed shows no figure (an ICMP answer is not
                            // a working path: device test of 142, «~34 мс» green on a node that never handshook)
                            // a row the mode cannot serve (greyed) or whose last attempt here failed: no figure
                            readonly property var fig: ((row.modelData.attemptFailed || row.modelData.disabled) && !sigCol.currentLive)
                                ? ({ ms: -1, bars: -1, failed: false })
                                : root.hasEngine
                                ? TribeEngine.nodeFigure(row.modelData.upstream === true, sigCol.currentLive,
                                                         TribeEngine.liveReachable === true, TribeEngine.liveDead === true,
                                                         Number(TribeEngine.liveRttMs), Number(TribeEngine.liveBars),
                                                         Number(row.modelData.rtt))
                                : ({ ms: Number(row.modelData.rtt), bars: Number(row.modelData.bars), failed: false })
                            LoadBars {
                                Layout.alignment: Qt.AlignHCenter
                                scale: 0.9
                                transformOrigin: Item.Bottom
                                // no measurement (bars -1): the idle track (UI-DESIGN §3, idle .4)
                                failed: sigCol.fig.failed === true
                                level: Math.max(0, Number(sigCol.fig.bars))
                            }
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: Number(sigCol.fig.ms) >= 0 ? qsTr("~%1 мс").arg(sigCol.fig.ms) : "—"
                                textFormat: Text.PlainText
                                color: Theme.color.text3
                                font.family: Theme.font.mono
                                font.pixelSize: Theme.font.caption
                            }
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            // Device test of 142 (second round), owner: a row the mode cannot serve is not a dead
                            // end. The tap switches the mode to «Авто» on this page first - the selector above moves,
                            // the rows lose their grey, a short notice says why - then selects the server.
                            if (row.modelData.modeOnly) {
                                root.pageNotice(qsTr("Режим соединения — «Авто»: у этого сервера нет транспорта %1")
                                                    .arg(root.transportMode === "xray" ? "Xray" : "Amnezia"))
                                Haptic.play("selection"); Haptic.arm()
                                modePick.nodeId = row.modelData.nodeId
                                root.pickTransport("auto")
                                modePick.restart()
                                return
                            }
                            // AVPN awg31-xray-v1: серая локация (клиент не умеет транспорт) — честный тост
                            if (row.modelData.disabled) {
                                if (typeof PageController !== "undefined")
                                    PageController.showNotificationMessage(row.modelData.reason)
                                return
                            }
                            // уже выбрана вручную — no-op (не дёргаем реконнект)
                            if (row.modelData.isChosen && !root.autoMode) { root.back(); return }
                            Haptic.play("selection"); Haptic.arm() // AVPN (haptics): итог реконнекта отыграет PageConnectTribe
                            root.pickNode(row.modelData.nodeId)
                        }
                    }
                }
            }

            // пустые состояния: пул не загружен / поиск без результатов (сиблинг ListView —
            // центрируется по вьюпорту, не по нулевому contentItem)
            Column {
                anchors.centerIn: parent
                width: parent.width - 2 * Theme.space.xl
                visible: list.count === 0
                spacing: Theme.space.md
                // AVPN (жалоба 2026-09-29): подписка ещё не пришла и попытки проваливаются —
                // честное «нет связи» + ручной повтор вместо вечного «загружаются».
                readonly property bool offline: root.pool.length === 0 && root.hasEngine
                                                && TribeEngine.subMissing !== true
                                                && TribeEngine.subOffline === true
                Text {
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    // AVPN (баг 2026-07-10): «нет подписки» ≠ «грузится» — при авторитетном пустом
                    // пуле (subMissing: бэк ответил 200 с nodes:[]) честный текст вместо вечной «загрузки».
                    text: root.pool.length === 0
                              ? ((root.hasEngine && TribeEngine.subMissing === true)
                                     ? qsTr("Нет активного доступа")
                                     : parent.offline
                                           ? qsTr("Нет связи с сервером Tribe. Повторяем автоматически")
                                           : qsTr("Загружаем серверы…"))
                              : qsTr("Ничего не найдено")
                    textFormat: Text.PlainText
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                }
                TribeButton {
                    visible: parent.offline
                    anchors.horizontalCenter: parent.horizontalCenter
                    variant: "glass"
                    text: qsTr("Повторить")
                    onClicked: TribeEngine.kickBootstrap()
                }
            }
        }

        // AVPN (Scanner, artboard «Экран выбора сервера»): «Запустить сканер» pinned on its own band above the
        // nav (border-top, bg800, padding 12 / 24 / 16), TribeButton primary full width with the radar icon
        Rectangle {
            visible: ScanSwitches.scanner
            Layout.fillWidth: true
            Layout.preferredHeight: scanButton.implicitHeight + Theme.space.md + Theme.space.lg
            color: Theme.color.bg800
            Rectangle { width: parent.width; height: 1; color: Theme.color.border }
            TribeButton {
                id: scanButton
                x: Theme.space.xl
                y: Theme.space.md
                width: parent.width - 2 * Theme.space.xl
                variant: "primary"
                strokeIcon: "radar"
                text: ScanTexts.serversButton
                onClicked: { Haptic.play("light"); root.requestScanner() }
            }
        }
    }
}

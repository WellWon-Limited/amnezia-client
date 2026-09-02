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
PageType {
    id: root

    signal back()
    signal pickNode(string nodeId)
    signal pickAuto()
    // AVPN awg31-xray-v1: смена режима транспорта — тоже через PageStart (движок может
    // переподнять туннель ⇒ инвариант §5 «уход с UI выбора сначала» действует и здесь).
    signal pickTransport(string mode)


    // iOS: PageController.safeArea* только для Android → max с SafeArea (как PageNotificationsTribe)
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property var pool: hasEngine ? (TribeEngine.nodePool || []) : []
    // гард undefined currentNode — как в PageLocationsTribe (страница до первой подписки)
    readonly property var cur: (hasEngine && TribeEngine.currentNode) ? TribeEngine.currentNode : ({})
    readonly property bool autoMode: !cur.pinned
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

    function rebuildCountries() {
        const next = computeCountries()
        const key = JSON.stringify(next)
        if (key === root.countriesKey) return
        root.countriesKey = key
        root.countries = next
    }

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
        for (let i = 0; i < pool.length; ++i) {
            const n = pool[i]
            if (!n || n.alive !== true) continue
            const key = root.locationKeyOf(n)
            if (!byLoc[key]) byLoc[key] = []
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
            const cc = String(best.countryCode || "??").toUpperCase()
            const name = best.name || best.region || cc
            if (q && !(name.toLowerCase().includes(q) || cc.toLowerCase().includes(q)
                       || String(best.region || "").toLowerCase().includes(q)))
                continue
            let isCur = false
            for (let k = 0; k < nodes.length; ++k)
                if (cur.nodeId && nodes[k].nodeId === cur.nodeId) { isCur = true; break }
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
            out.push({ key: key, cc: cc, name: name, nodeId: best.nodeId,
                       rtt: best.measuredRttMs,
                       bars: best.measuredBars >= 0 ? best.measuredBars
                                                    : Math.round((best.health || 0) * 5),
                       badges: badges,
                       disabled: disabled,
                       // причина серой строки: транспорт есть, но не тот режим — или клиент его не умеет
                       reason: !disabled ? ""
                               : (anySupported ? qsTr("недоступно для этого режима")
                                               : qsTr("недоступно в этой версии")),
                       isCurrent: isCur })
        }
        out.sort(function(a, b) {
            if (a.disabled !== b.disabled) return a.disabled ? 1 : -1   // серые — вниз
            const am = a.rtt >= 0, bm = b.rtt >= 0
            if (am !== bm) return am ? -1 : 1
            if (am) return a.rtt - b.rtt
            return b.bars - a.bars
        })
        return out
    }

    onQueryChanged: rebuildCountries()
    onTransportModeChanged: rebuildCountries()   // AVPN awg31-xray-v1: смена режима меняет серые строки
    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onChanged() { root.rebuildCountries() }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

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
                    if (root.autoMode) { root.back(); return }  // уже авто — no-op
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

        Text {
            visible: root.showTransportSelector
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
                    color: row.modelData.isCurrent ? Theme.color.chipSelected : Theme.color.surface1
                    border.width: 1
                    border.color: row.modelData.isCurrent ? Theme.color.accent : Theme.color.border
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
                            Layout.alignment: Qt.AlignVCenter
                            spacing: 3
                            LoadBars {
                                Layout.alignment: Qt.AlignHCenter
                                scale: 0.9
                                transformOrigin: Item.Bottom
                                // текущая страна при коннекте — живой замер через туннель
                                level: (row.modelData.isCurrent && root.hasEngine
                                        && TribeEngine.state === "connected")
                                       ? TribeEngine.liveBars : row.modelData.bars
                            }
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: row.modelData.rtt >= 0 ? qsTr("~%1 мс").arg(row.modelData.rtt) : "—"
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
                            // AVPN awg31-xray-v1: серая локация — честный тост, пин не трогаем
                            if (row.modelData.disabled) {
                                if (typeof PageController !== "undefined")
                                    PageController.showNotificationMessage(row.modelData.reason)
                                return
                            }
                            // уже выбрана вручную — no-op (не дёргаем реконнект)
                            if (row.modelData.isCurrent && !root.autoMode) { root.back(); return }
                            Haptic.play("selection"); Haptic.arm() // AVPN (haptics): итог реконнекта отыграет PageConnectTribe
                            root.pickNode(row.modelData.nodeId)
                        }
                    }
                }
            }

            // пустые состояния: пул не загружен / поиск без результатов (сиблинг ListView —
            // центрируется по вьюпорту, не по нулевому contentItem)
            Text {
                anchors.centerIn: parent
                visible: list.count === 0
                // AVPN (баг 2026-07-10): «нет подписки» ≠ «грузится» — при авторитетном пустом
                // пуле (subMissing: бэк ответил 200 с nodes:[]) честный текст вместо вечной «загрузки».
                text: root.pool.length === 0
                          ? ((root.hasEngine && TribeEngine.subMissing === true)
                                 ? qsTr("Нет активного доступа")
                                 : qsTr("Локации загружаются…"))
                          : qsTr("Ничего не найдено")
                textFormat: Text.PlainText
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
            }
        }
    }
}

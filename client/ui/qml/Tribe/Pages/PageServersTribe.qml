pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN (server picker 2026-07-10): полноэкранный выбор сервера — замена шторки TribeNodeSheet.
// Поиск по странам, «Авто (оптимальный)», строки стран (флаг + RTT + бары). Одна строка = одна
// страна: пинится ЛУЧШАЯ нода страны на момент тапа. Переключение — сигналами через PageStart
// (уход со страницы СНАЧАЛА, движок ПОТОМ — CONNECT-INVARIANTS §5); реконнект-семантика — в
// TribeEngine.pinAndReconnect (kill-switch features.picker_instant_reconnect).
PageType {
    id: root

    signal back()
    signal pickNode(string nodeId)
    signal pickAuto()
    signal pickLocation(string locationId)
    signal pickLocationAuto()
    signal requestTransportMode(string mode)


    // iOS: PageController.safeArea* только для Android → max с SafeArea (как PageNotificationsTribe)
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property bool hasCatalogConnection: (typeof TribeConnection !== "undefined")
    readonly property var catalogRows: hasCatalogConnection
                                               ? (TribeConnection.catalogLocations || []) : []
    // Shipping a binary that contains the facade is not itself a migration event: an existing
    // user must keep the proven v1 AWG path until this installation has accepted catalog v2.
    // The facade persists that acceptance monotonically; once authoritative, an empty/loading
    // catalog stays on v2 and must never silently reopen the legacy picker (downgrade).
    readonly property bool useCatalog: hasCatalogConnection
                                       && TribeConnection.v2Authoritative === true
    // The legacy v1 pool is AWG-only. Keep that fact visible instead of hiding the whole
    // protocol control until catalog v2 becomes authoritative. Availability, not component
    // existence, is server-driven: a legacy installation therefore shows AWG selected and
    // presents Auto/Xray as unavailable without breaking its proven server list.
    readonly property string connectionMode: useCatalog
                                               ? String(TribeConnection.connectionMode || "auto")
                                               : "awg"
    readonly property string selectedLocationMode: useCatalog
                                                    ? String(TribeConnection.selectedLocationMode || "auto")
                                                    : "auto"
    readonly property string catalogStage: useCatalog
                                            ? String(TribeConnection.connectionStage || "idle")
                                            : "idle"
    readonly property string catalogErrorCode: useCatalog
                                                ? String(TribeConnection.errorCode || "")
                                                : ""
    readonly property bool catalogLoading: useCatalog
                                            && ["resolving", "preparing", "renewing"].indexOf(catalogStage) >= 0
    readonly property var pool: hasEngine ? (TribeEngine.nodePool || []) : []
    // гард undefined currentNode — как в PageLocationsTribe (страница до первой подписки)
    readonly property var cur: (hasEngine && TribeEngine.currentNode) ? TribeEngine.currentNode : ({})
    readonly property bool autoMode: useCatalog ? selectedLocationMode === "auto" : !cur.pinned
    property string query: ""

    // Группировка alive-нод по странам + фильтр + сортировка «быстрые СВЕРХУ» (страница читается
    // сверху вниз — осознанная инверсия шторочного rankFastestAtBottom). Лучшая нода страны:
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

    function computeCountries() {
        if (root.useCatalog) return computeCatalogLocations()
        const byCc = {}
        for (let i = 0; i < pool.length; ++i) {
            const n = pool[i]
            if (!n || n.alive !== true) continue
            // Task 10 (форвард-совместимость proto): ноды неподдерживаемых протоколов (xray, ...)
            // непригодны для pin — скипаем, чтобы не стать «best» строки страны (тап = фейл).
            // Страна, где ВСЕ ноды такие, честно не показывается вовсе (byCc[cc] не создаётся).
            if (n.proto && n.proto !== "awg") continue
            const cc = String(n.countryCode || "??").toUpperCase()
            if (!byCc[cc]) byCc[cc] = []
            byCc[cc].push(n)
        }
        const q = query.trim().toLowerCase()
        const out = []
        for (const cc in byCc) {
            const nodes = byCc[cc]
            let best = nodes[0]
            for (let j = 1; j < nodes.length; ++j) {
                const a = nodes[j], b = best
                const am = a.measuredRttMs >= 0, bm = b.measuredRttMs >= 0
                if (am && (!bm || a.measuredRttMs < b.measuredRttMs)) { best = a; continue }
                if (!am && !bm && ((a.health || 0) > (b.health || 0)
                        || ((a.health || 0) === (b.health || 0) && (a.weight || 0) > (b.weight || 0))))
                    best = a
            }
            const name = best.name || best.region || cc
            if (q && !(name.toLowerCase().includes(q) || cc.toLowerCase().includes(q)
                       || String(best.region || "").toLowerCase().includes(q)))
                continue
            let isCur = false
            for (let k = 0; k < nodes.length; ++k)
                if (cur.nodeId && nodes[k].nodeId === cur.nodeId) { isCur = true; break }
            out.push({ cc: cc, name: name, nodeId: best.nodeId,
                       rtt: best.measuredRttMs,
                       bars: best.measuredBars >= 0 ? best.measuredBars
                                                    : Math.round((best.health || 0) * 5),
                       isCurrent: isCur })
        }
        out.sort(function(a, b) {
            const am = a.rtt >= 0, bm = b.rtt >= 0
            if (am !== bm) return am ? -1 : 1
            if (am) return a.rtt - b.rtt
            return b.bars - a.bars
        })
        return out
    }

    function transportFact(row, key) {
        if (!row) return ({ available: false, state: "unsupported", quality: -1,
                            predicted_quality: -1, predicted_age: -1, last_verified: -1,
                            age_anchor_catalog_age: -1 })
        const fact = row[key]
        return fact && typeof fact === "object"
                ? fact : ({ available: false, state: "unsupported", quality: -1,
                            predicted_quality: -1, predicted_age: -1, last_verified: -1,
                            age_anchor_catalog_age: -1 })
    }

    function boundedQuality(value) {
        if (value === null || value === undefined || value === "") return -1
        const number = Number(value)
        if (!isFinite(number) || number < 0) return -1
        return Math.max(0, Math.min(1, number))
    }

    function rowSelectable(row) {
        const awg = transportFact(row, "awg")
        const xray = transportFact(row, "xray")
        if (connectionMode === "awg") return awg.available === true
        if (connectionMode === "xray") return xray.available === true
        return awg.available === true || xray.available === true
    }

    function selectedCatalogRow() {
        if (selectedLocationMode === "auto") return undefined
        for (let i = 0; i < catalogRows.length; ++i) {
            const row = catalogRows[i]
            if (row && String(row.id || "") === selectedLocationMode) return row
        }
        return undefined
    }

    function modeAvailable(key) {
        const selected = selectedCatalogRow()
        if (selectedLocationMode === "auto" || !selected) {
            if (key === "awg") return TribeConnection.awgAvailable === true
            if (key === "xray") return TribeConnection.xrayAvailable === true
            return TribeConnection.autoAvailable === true
        }
        const awg = transportFact(selected, "awg").available === true
        const xray = transportFact(selected, "xray").available === true
        if (key === "awg") return awg
        if (key === "xray") return xray
        return awg || xray
    }

    function computeCatalogLocations() {
        const q = query.trim().toLowerCase()
        const out = []
        for (let i = 0; i < catalogRows.length; ++i) {
            const raw = catalogRows[i]
            if (!raw) continue
            const id = String(raw.id || "")
            const cc = String(raw.country || "??").toUpperCase()
            const name = raw.retained_pin === true
                         ? qsTr("Выбранная локация") : String(raw.name || cc)
            if (!id || (q && !(name.toLowerCase().includes(q)
                              || cc.toLowerCase().includes(q))))
                continue
            const awg = transportFact(raw, "awg")
            const xray = transportFact(raw, "xray")
            const awgMeasured = boundedQuality(awg.quality)
            const xrayMeasured = boundedQuality(xray.quality)
            const awgQuality = awg.available === true
                               ? (awgMeasured >= 0 ? awgMeasured
                                                   : boundedQuality(awg.predicted_quality)) : -1
            const xrayQuality = xray.available === true
                                ? (xrayMeasured >= 0 ? xrayMeasured
                                                     : boundedQuality(xray.predicted_quality)) : -1
            // Sorting and bars must follow the user's requested transport. In forced AWG mode an
            // excellent Xray candidate must not make the location look fast (and vice versa).
            const aggregate = connectionMode === "awg" ? awgQuality
                              : (connectionMode === "xray" ? xrayQuality
                                                           : Math.max(awgQuality, xrayQuality))
            out.push({
                id: id,
                cc: cc,
                name: name,
                // Intent and runtime fact are deliberately separate: Auto may have a live
                // location without pinning it, so it must not render as a second selected radio.
                pinned: id === selectedLocationMode,
                active: id === String(TribeConnection.currentLocationId || ""),
                awg: awg,
                xray: xray,
                retainedPin: raw.retained_pin === true,
                aggregateQuality: aggregate,
                bars: aggregate < 0 ? 0 : Math.max(1, Math.round(aggregate * 5)),
                selectable: rowSelectable(raw)
            })
        }
        out.sort(function(a, b) {
            if (a.selectable !== b.selectable) return a.selectable ? -1 : 1
            if (a.aggregateQuality >= 0 && b.aggregateQuality < 0) return -1
            if (a.aggregateQuality < 0 && b.aggregateQuality >= 0) return 1
            if (a.aggregateQuality !== b.aggregateQuality)
                return b.aggregateQuality - a.aggregateQuality
            return a.name.localeCompare(b.name)
        })
        return out
    }

    function qualityText(value) {
        const quality = boundedQuality(value)
        return quality < 0 ? qsTr("ещё не измерено")
                           : qsTr("качество %1%").arg(Math.round(quality * 100))
    }

    function verifiedAgeText(value) {
        if (value === null || value === undefined || value === "") return qsTr("не проверялось")
        const seconds = Number(value)
        if (!isFinite(seconds) || seconds < 0) return qsTr("не проверялось")
        if (seconds < 60) return qsTr("проверено недавно")
        if (seconds < 3600) return qsTr("проверено %1 мин назад").arg(Math.floor(seconds / 60))
        if (seconds < 86400) return qsTr("проверено %1 ч назад").arg(Math.floor(seconds / 3600))
        return qsTr("проверено более суток назад")
    }

    function mostRecentVerifiedAge(row) {
        const awg = currentVerifiedAge(transportFact(row, "awg"))
        const xray = currentVerifiedAge(transportFact(row, "xray"))
        const values = []
        if (connectionMode !== "xray" && isFinite(awg) && awg >= 0) values.push(awg)
        if (connectionMode !== "awg" && isFinite(xray) && xray >= 0) values.push(xray)
        return values.length === 0 ? -1 : Math.min.apply(Math, values)
    }

    function currentVerifiedAge(fact) {
        const base = fact.last_verified === null || fact.last_verified === undefined
                     ? -1 : Number(fact.last_verified)
        const anchor = fact.age_anchor_catalog_age === null
                       || fact.age_anchor_catalog_age === undefined
                       ? -1 : Number(fact.age_anchor_catalog_age)
        const catalogAge = root.hasCatalogConnection
                           ? Number(TribeConnection.catalogAgeSeconds) : -1
        if (!isFinite(base) || base < 0) return -1
        if (!isFinite(anchor) || anchor < 0 || !isFinite(catalogAge) || catalogAge < anchor)
            return base
        return base + (catalogAge - anchor)
    }

    function catalogEmptyText() {
        if (query.trim().length > 0 && catalogRows.length > 0) return qsTr("Ничего не найдено")
        if (catalogLoading) return qsTr("Совместимые локации загружаются…")
        if (catalogErrorCode === "signed_out") return qsTr("Нет активного доступа")
        if (catalogErrorCode.length > 0) return errorTextProvider.text
        return qsTr("Список серверов пока недоступен")
    }

    function retryCatalogRefresh() {
        if (!root.useCatalog || root.catalogLoading) return
        Haptic.play("light")
        if (!TribeConnection.refreshCatalog())
            PageController.showNotificationMessage(
                        errorTextProvider.failureText(
                            String(TribeConnection.errorCode || "")))
    }

    function selectAutoLocation() {
        if (autoMode) { root.back(); return }
        Haptic.play("selection")
        Haptic.arm()
        if (useCatalog) root.pickLocationAuto()
        else root.pickAuto()
    }

    function selectLocation(row) {
        if (useCatalog) {
            if (row.selectable !== true) {
                PageController.showNotificationMessage(
                            qsTr("В этой локации выбранный протокол сейчас недоступен"))
                return
            }
            if (row.pinned === true && !autoMode) { root.back(); return }
            Haptic.play("selection")
            Haptic.arm()
            root.pickLocation(row.id)
            return
        }
        if (row.isCurrent && !autoMode) { root.back(); return }
        Haptic.play("selection")
        Haptic.arm()
        root.pickNode(row.nodeId)
    }

    function catalogRowAccessibleDescription(row) {
        if (!useCatalog) return row.rtt >= 0 ? qsTr("~%1 мс").arg(row.rtt) : ""
        if (row.retainedPin === true)
            return qsTr("Выбранная локация временно недоступна. Выбор сохранён")
        if (row.selectable !== true)
            return qsTr("В этой локации выбранный протокол сейчас недоступен")
        const awg = transportFact(row, "awg")
        const xray = transportFact(row, "xray")
        const available = awg.available === true && xray.available === true
                          ? qsTr("AWG") + ", " + qsTr("Xray")
                          : (awg.available === true ? qsTr("AWG") : qsTr("Xray"))
        return available + ". " + verifiedAgeText(mostRecentVerifiedAge(row))
    }

    onQueryChanged: rebuildCountries()
    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onChanged() { root.rebuildCountries() }
    }
    Connections {
        target: root.hasCatalogConnection ? TribeConnection : null
        ignoreUnknownSignals: true
        function onChanged() { root.rebuildCountries() }
        function onCatalogLocationsChanged() { root.rebuildCountries() }
        function onConnectionModeChanged() { root.rebuildCountries() }
        function onCurrentLocationIdChanged() { root.rebuildCountries() }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // Reuse the central redacted typed-reason mapping (and its translation context) for an empty
    // catalog. Raw coordinator codes are never rendered to the user.
    TribeConnectionStage {
        id: errorTextProvider
        visible: false
        stage: "failed"
        typedReason: root.catalogErrorCode
    }

    // свайп слева-направо = «назад» (жалоба 2026-07-11)
    TribeEdgeBack { onTriggered: root.back() }

    // Замер RTT всех нод при открытии (async ICMP; при connected — no-op, показываем кэш).
    Component.onCompleted: {
        rebuildCountries()
        if (!root.useCatalog && hasEngine) TribeEngine.probeNodeRtt()
    }
    // refreshPool — СИНХРОННЫЙ nested-loop → ТОЛЬКО отложенно, не из кадра показа (как в шторке).
    Timer {
        interval: 350; running: root.hasEngine && !root.useCatalog; repeat: false
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

        Text {
            Layout.leftMargin: Theme.space.xl
            Layout.topMargin: Theme.space.md
            visible: true
            text: transportSelector.groupLabel.toUpperCase()
            textFormat: Text.PlainText
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            font.letterSpacing: Theme.font.trackCaption * Theme.font.caption
        }

        // AVPN catalog-v2: это намерение пользователя, не утверждение о реально
        // запущенном core. Фактический transport показывается отдельно после start.
        TribeTransportSelector {
            id: transportSelector
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.xs
            visible: true
            mode: root.connectionMode
            // A forced mode is available only if it is compatible with the current location
            // intent. Global availability here caused a valid Xray elsewhere to expose a control
            // that the coordinator then correctly rejected for a pinned AWG-only location.
            awgAvailable: root.useCatalog ? root.modeAvailable("awg") : true
            xrayAvailable: root.useCatalog && root.modeAvailable("xray")
            autoAvailable: root.useCatalog && root.modeAvailable("auto")
            unavailableReason: !root.useCatalog
                               ? qsTr("Для этого режима пока нет доступных серверов")
                               : root.selectedLocationMode === "auto"
                                 ? transportSelector.deviceUnavailableReason
                                 : qsTr("В этой локации выбранный протокол сейчас недоступен")
            interactive: !root.useCatalog
                         || String(TribeConnection.connectionStage || "idle") !== "disconnecting"
            onModeRequested: function(mode) { root.requestTransportMode(mode) }
        }

        // ── карточка «Авто (оптимальный)» ──
        Rectangle {
            id: autoLocationCard
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.md
            implicitHeight: 70
            radius: Theme.radius.lg
            color: root.autoMode ? Theme.color.chipSelected : Theme.color.surface1
            border.width: 1
            border.color: activeFocus ? Theme.color.text1
                                      : (root.autoMode ? Theme.color.accent : Theme.color.border)
            activeFocusOnTab: true
            Accessible.role: Accessible.RadioButton
            Accessible.name: qsTr("Авто (оптимальный)")
            Accessible.description: qsTr("Подберём локацию и проверим реальный трафик")
            Accessible.checked: root.autoMode
            Accessible.onPressAction: root.selectAutoLocation()
            Keys.onEnterPressed: root.selectAutoLocation()
            Keys.onReturnPressed: root.selectAutoLocation()
            Keys.onSpacePressed: function(event) {
                root.selectAutoLocation()
                event.accepted = true
            }
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
                        text: qsTr("Авто (оптимальный)")
                        textFormat: Text.PlainText
                        elide: Text.ElideRight
                        color: Theme.color.text1
                        font.family: Theme.font.display
                        font.pixelSize: Theme.font.bodyM
                        font.weight: Theme.font.wBold
                    }
                    Text {
                        Layout.fillWidth: true
                        text: root.useCatalog
                              ? qsTr("Подберём локацию и проверим реальный трафик")
                              : qsTr("Сервис подберёт быстрейший узел")
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
                onClicked: root.selectAutoLocation()
            }
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

        Text {
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.sm
            visible: root.useCatalog && root.countries.length > 0
                     && root.countries.every(function(row) { return row.selectable !== true })
            text: errorTextProvider.failureText("mode_location_pair_unavailable")
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.color.warning
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            Accessible.role: Accessible.StaticText
            Accessible.name: text
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
                    readonly property bool selected: root.useCatalog
                                                     ? row.modelData.pinned === true
                                                     : row.modelData.isCurrent === true
                    width: ListView.view.width
                    implicitHeight: root.useCatalog ? 84 : 62
                    radius: Theme.radius.lg
                    color: row.selected ? Theme.color.chipSelected : Theme.color.surface1
                    border.width: 1
                    border.color: activeFocus ? Theme.color.text1
                                              : (row.selected ? Theme.color.accent : Theme.color.border)
                    opacity: root.useCatalog && row.modelData.selectable !== true ? 0.52 : 1.0
                    activeFocusOnTab: true
                    Accessible.role: Accessible.RadioButton
                    Accessible.name: row.modelData.name
                    Accessible.description: root.catalogRowAccessibleDescription(row.modelData)
                    Accessible.checked: row.selected
                    Accessible.onPressAction: root.selectLocation(row.modelData)
                    Keys.onEnterPressed: root.selectLocation(row.modelData)
                    Keys.onReturnPressed: root.selectLocation(row.modelData)
                    Keys.onSpacePressed: function(event) {
                        root.selectLocation(row.modelData)
                        event.accepted = true
                    }
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.md
                        anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md

                        Item {
                            Layout.preferredWidth: 42
                            Layout.preferredHeight: 42
                            TribeFlag {
                                anchors.centerIn: parent
                                width: 38
                                height: 38
                                code: row.modelData.cc
                            }
                            Rectangle {
                                anchors.fill: parent
                                radius: width / 2
                                color: "transparent"
                                border.width: root.useCatalog && row.modelData.active === true ? 2 : 0
                                border.color: Theme.color.accent
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 3
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space.sm
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
                            }

                            RowLayout {
                                visible: root.useCatalog
                                spacing: Theme.space.sm

                                Rectangle {
                                    readonly property var fact: root.transportFact(row.modelData, "awg")
                                    Layout.preferredHeight: 20
                                    Layout.preferredWidth: awgText.implicitWidth + Theme.space.sm * 2
                                    radius: Theme.radius.pill
                                    color: Theme.color.surface2
                                    border.width: 1
                                    border.color: fact.available === true
                                                  ? Theme.color.accent : Theme.color.border
                                    Text {
                                        id: awgText
                                        anchors.centerIn: parent
                                        text: parent.fact.available === true
                                              ? (root.boundedQuality(parent.fact.quality) >= 0
                                                 ? qsTr("AWG · оценка %1%").arg(Math.round(root.boundedQuality(parent.fact.quality) * 100))
                                                 : (root.boundedQuality(parent.fact.predicted_quality) >= 0
                                                    ? qsTr("AWG · прогноз %1%").arg(Math.round(root.boundedQuality(parent.fact.predicted_quality) * 100))
                                                    : qsTr("AWG")))
                                              : qsTr("AWG · —")
                                        color: parent.fact.available === true
                                               ? Theme.color.accent : Theme.color.text3
                                        font.family: Theme.font.body
                                        font.pixelSize: Theme.font.caption - 1
                                        font.weight: Theme.font.wBold
                                    }
                                }

                                Rectangle {
                                    readonly property var fact: root.transportFact(row.modelData, "xray")
                                    Layout.preferredHeight: 20
                                    Layout.preferredWidth: xrayText.implicitWidth + Theme.space.sm * 2
                                    radius: Theme.radius.pill
                                    color: Theme.color.surface2
                                    border.width: 1
                                    border.color: fact.available === true
                                                  ? Theme.color.accent : Theme.color.border
                                    Text {
                                        id: xrayText
                                        anchors.centerIn: parent
                                        text: parent.fact.available === true
                                              ? (root.boundedQuality(parent.fact.quality) >= 0
                                                 ? qsTr("Xray · оценка %1%").arg(Math.round(root.boundedQuality(parent.fact.quality) * 100))
                                                 : (root.boundedQuality(parent.fact.predicted_quality) >= 0
                                                    ? qsTr("Xray · прогноз %1%").arg(Math.round(root.boundedQuality(parent.fact.predicted_quality) * 100))
                                                    : qsTr("Xray")))
                                              : qsTr("Xray · —")
                                        color: parent.fact.available === true
                                               ? Theme.color.accent : Theme.color.text3
                                        font.family: Theme.font.body
                                        font.pixelSize: Theme.font.caption - 1
                                        font.weight: Theme.font.wBold
                                    }
                                }
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
                                level: (!root.useCatalog && row.modelData.isCurrent && root.hasEngine
                                        && TribeEngine.state === "connected")
                                       ? TribeEngine.liveBars : row.modelData.bars
                                // Catalog quality mixes signed capacity hints with local history.
                                // It is useful for ranking but is not a fresh traffic receipt, so
                                // keep it neutral blue; green remains exclusive to verified runtime.
                                barColor: root.useCatalog ? Theme.color.accent
                                                          : Theme.color.connected
                            }
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: root.useCatalog
                                      ? root.verifiedAgeText(root.mostRecentVerifiedAge(row.modelData))
                                      : (row.modelData.rtt >= 0 ? qsTr("~%1 мс").arg(row.modelData.rtt) : "—")
                                textFormat: Text.PlainText
                                color: Theme.color.text3
                                font.family: Theme.font.mono
                                font.pixelSize: root.useCatalog ? Theme.font.caption - 2
                                                                : Theme.font.caption
                                Layout.maximumWidth: root.useCatalog ? 86 : 1000
                                elide: Text.ElideRight
                            }
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.selectLocation(row.modelData)
                    }
                }
            }

            // пустые состояния: пул не загружен / поиск без результатов (сиблинг ListView —
            // центрируется по вьюпорту, не по нулевому contentItem)
            Column {
                anchors.centerIn: parent
                visible: list.count === 0
                width: Math.min(parent.width, 300)
                spacing: Theme.space.md

                Text {
                    width: parent.width
                    // AVPN (баг 2026-07-10): «нет подписки» ≠ «грузится» — при авторитетном пустом
                    // пуле (subMissing: бэк ответил 200 с nodes:[]) честный текст вместо вечной «загрузки».
                    text: root.useCatalog ? root.catalogEmptyText()
                          : root.pool.length === 0
                              ? ((root.hasEngine && TribeEngine.subMissing === true)
                                     ? qsTr("Нет активного доступа")
                                     : qsTr("Локации загружаются…"))
                              : qsTr("Ничего не найдено")
                    textFormat: Text.PlainText
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }

                Rectangle {
                    id: retryCatalogButton
                    visible: root.useCatalog && !root.catalogLoading
                             && root.catalogErrorCode !== "signed_out"
                             && root.query.trim().length === 0
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: Math.min(parent.width, 210)
                    height: visible ? 44 : 0
                    radius: Theme.radius.md
                    color: retryCatalogMouse.pressed ? Theme.color.surface3
                                                     : Theme.color.surface2
                    border.width: activeFocus ? 2 : 1
                    border.color: activeFocus ? Theme.color.text1 : Theme.color.border2
                    activeFocusOnTab: visible
                    Accessible.role: Accessible.Button
                    Accessible.name: qsTr("Обновить список")
                    Accessible.onPressAction: root.retryCatalogRefresh()
                    Keys.onEnterPressed: root.retryCatalogRefresh()
                    Keys.onReturnPressed: root.retryCatalogRefresh()
                    Keys.onSpacePressed: function(event) {
                        root.retryCatalogRefresh()
                        event.accepted = true
                    }
                    Text {
                        anchors.centerIn: parent
                        text: qsTr("Обновить список")
                        textFormat: Text.PlainText
                        color: Theme.color.text1
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyS
                        font.weight: Theme.font.wSemibold
                    }
                    MouseArea {
                        id: retryCatalogMouse
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.retryCatalogRefresh()
                    }
                }
            }
        }
    }
}

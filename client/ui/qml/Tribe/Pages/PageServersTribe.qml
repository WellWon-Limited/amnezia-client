pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN (server picker 2026-07-10): полноэкранный выбор сервера — замена шторки TribeNodeSheet.
// Поиск по странам, «Авто (быстрейший)», строки стран (флаг + RTT + бары). Одна строка = одна
// страна: пинится ЛУЧШАЯ нода страны на момент тапа. Переключение — сигналами через PageStart
// (уход со страницы СНАЧАЛА, движок ПОТОМ — CONNECT-INVARIANTS §5); реконнект-семантика — в
// TribeEngine.pinAndReconnect (kill-switch features.picker_instant_reconnect).
PageType {
    id: root

    signal back()
    signal pickNode(string nodeId)
    signal pickAuto()

    // iOS: PageController.safeArea* только для Android → max с SafeArea (как PageNotificationsTribe)
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property var pool: hasEngine ? (TribeEngine.nodePool || []) : []
    // гард undefined currentNode — как в PageLocationsTribe (страница до первой подписки)
    readonly property var cur: (hasEngine && TribeEngine.currentNode) ? TribeEngine.currentNode : ({})
    readonly property bool autoMode: !cur.pinned
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
        const byCc = {}
        for (let i = 0; i < pool.length; ++i) {
            const n = pool[i]
            if (!n || n.alive !== true) continue
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

    onQueryChanged: rebuildCountries()
    Connections {
        target: root.hasEngine ? TribeEngine : null
        function onChanged() { root.rebuildCountries() }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

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
                    root.pickAuto()
                }
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
                    implicitHeight: 62
                    radius: Theme.radius.lg
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
                            spacing: 2
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
                            Text {
                                text: row.modelData.rtt >= 0 ? qsTr("~%1 мс").arg(row.modelData.rtt) : "—"
                                textFormat: Text.PlainText
                                color: Theme.color.text3
                                font.family: Theme.font.mono
                                font.pixelSize: Theme.font.caption
                            }
                        }

                        LoadBars {
                            // текущая страна при коннекте — живой замер через туннель
                            level: (row.modelData.isCurrent && root.hasEngine
                                    && TribeEngine.state === "connected")
                                   ? TribeEngine.liveBars : row.modelData.bars
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            // уже выбрана вручную — no-op (не дёргаем реконнект)
                            if (row.modelData.isCurrent && !root.autoMode) { root.back(); return }
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
                          ? ((typeof TribeEngine !== "undefined" && TribeEngine.subMissing === true)
                                 ? qsTr("Нет активной подписки")
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

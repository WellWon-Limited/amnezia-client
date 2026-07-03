import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme, Dev
import "../components"
import "../../Controls2" // PageType

// AVPN: «Панель администратора» (вход — низ настроек, гейт Dev.adminPanelVisible).
// Бенч соединения: меряет ТЕКУЩИЙ сетевой путь устройства (NE-туннель системный ⇒ подходит и для
// замера ванильной Amnezia, подключённой рядом с нашим ключом). Схема результата = schema:1
// (tools/connect-bench в репо tribe-front) — JSON копируется и сводится общим summarize.sh.
// Кнопки зависят от состояния туннеля, метки выводятся из ФАКТОВ (не выбираются руками):
//  • Tribe подключён → «Авто A/B байпаса» (пара bypass-on/off сама, движок сам переключает
//    тумблер и переподключается) + одиночный «Замер текущего пути» (авто-метка);
//  • отключён → baseline (без VPN) / amnezia (чужой туннель) — единственный ручной выбор,
//    различить их изнутри приложения нельзя.
// Полный отчёт: последние замеры всех 4 меток + парные сравнения одним JSON (buildFullReport).
PageType {
    id: root

    // назад — в настройки (goAvpnTab(3) в PageStart), НЕ на Connect: страница открыта из настроек
    signal requestSettings()

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property bool benchRunning: hasEngine ? TribeEngine.benchRunning : false
    readonly property string benchStage: hasEngine ? TribeEngine.benchStage : ""
    readonly property bool tunnelConnected: hasEngine && TribeEngine.state === "connected"

    property var lastSummary: null   // плоская мапа из benchFinished (+verdicts, vs_baseline, tribe_vs_amnezia)
    property string lastJson: ""
    property var sweepRows: null     // строки свипа нод из sweepFinished (лучшие сверху)
    property string sweepJson: ""
    property var abSummary: null     // пара on/off + cost из abFinished
    property string abJson: ""
    property var historyInfo: ({})   // метка → ts последнего замера (карточка «N/4»)

    readonly property bool sweepRunning: hasEngine ? TribeEngine.sweepRunning : false
    readonly property string sweepProgress: hasEngine ? TribeEngine.sweepProgress : ""
    readonly property bool abRunning: hasEngine ? TribeEngine.abRunning : false
    readonly property string abProgress: hasEngine ? TribeEngine.abProgress : ""
    readonly property bool anyBusy: benchRunning || sweepRunning || abRunning

    function stageTitle(st) {
        switch (st) {
        case "start": return qsTr("подготовка…")
        case "dns":   return qsTr("DNS-тайминги…")
        case "tls":   return qsTr("TCP/TLS-фазы…")
        case "http":  return qsTr("HTTP-тайминги (8 сайтов)…")
        case "ping":  return qsTr("ICMP-пинг…")
        case "rtt":   return qsTr("базовый RTT…")
        case "down":  return qsTr("загрузка 25 МБ…")
        case "up":    return qsTr("отдача 5 МБ…")
        case "done":  return qsTr("готово")
        default:      return st
        }
    }
    function fmt(v, suffix) {
        if (v === null || v === undefined || v < 0) return "—"
        return Math.round(Number(v) * 10) / 10 + suffix
    }
    function refreshHistory() {
        if (root.hasEngine)
            root.historyInfo = TribeEngine.benchHistoryInfo()
    }
    Component.onCompleted: refreshHistory()

    Connections {
        target: root.hasEngine ? TribeEngine : null
        function onBenchFinished(summary, json) {
            root.lastSummary = summary
            root.lastJson = json
            root.refreshHistory()
        }
        function onSweepFinished(rows, json) {
            root.sweepRows = rows
            root.sweepJson = json
        }
        function onAbFinished(summary, json) {
            root.abSummary = summary
            root.abJson = json
            root.refreshHistory()
        }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        TribeHeader {
            Layout.fillWidth: true
            title: qsTr("Панель администратора")
            showBack: true
            onBackClicked: root.requestSettings()
        }

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            contentHeight: adminCol.implicitHeight + Theme.space.xxl
            clip: true

            ColumnLayout {
                id: adminCol
                anchors.left: parent.left; anchors.right: parent.right
                spacing: Theme.space.md

                Text {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.md
                    text: qsTr("Бенчмарк соединения")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                }
                Text {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: root.tunnelConnected
                          ? qsTr("Tribe подключён. «Авто A/B» сам замерит пару с байпасом и без: тумблер и переподключение движок переключает сам, метки ставятся по факту. Твоих действий не нужно.")
                          : qsTr("Tribe отключён. Выбери, что меряем: чистую сеть (baseline) или путь через другой VPN — например, ванильную Amnezia с нашим ключом (amnezia).")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }

                // ── Tribe подключён: авто-A/B пары байпаса + одиночный замер текущего пути ──
                TribeButton {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    visible: root.tunnelConnected || root.abRunning
                    text: root.abRunning ? qsTr("Отменить A/B (%1)").arg(root.abProgress)
                                         : qsTr("Авто A/B байпаса (~90 МБ, ~5 мин)")
                    variant: root.abRunning ? "ghost" : "primary"
                    enabled: root.hasEngine && (root.abRunning || !root.anyBusy)
                    onClicked: {
                        if (!root.hasEngine)
                            return
                        if (root.abRunning)
                            TribeEngine.cancelBypassAb()
                        else
                            TribeEngine.startBypassAb()
                    }
                }
                Text {
                    Layout.fillWidth: true
                    visible: root.abRunning
                    wrapMode: Text.WordWrap
                    text: qsTr("Идёт авто-A/B: два полных замера и два переподключения. Не трогай VPN и тумблеры — всё вернётся как было само.")
                    color: Theme.color.warning
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }
                TribeButton {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    visible: root.tunnelConnected && !root.abRunning
                    text: root.benchRunning ? qsTr("Отменить (%1)").arg(root.stageTitle(root.benchStage))
                                            : qsTr("Замер текущего пути (~40 МБ)")
                    variant: root.benchRunning ? "ghost" : "glass"
                    enabled: root.hasEngine && !root.sweepRunning
                    onClicked: {
                        if (!root.hasEngine)
                            return
                        if (root.benchRunning)
                            TribeEngine.cancelBench()
                        else
                            TribeEngine.startBench("") // авто-метка по факту тумблера байпаса
                    }
                }

                // ── Tribe отключён: два ручных сценария (различить их изнутри нельзя) ──
                TribeButton {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    visible: !root.tunnelConnected && !root.abRunning
                    text: root.benchRunning ? qsTr("Отменить (%1)").arg(root.stageTitle(root.benchStage))
                                            : qsTr("Замер без VPN — baseline (~40 МБ)")
                    variant: root.benchRunning ? "ghost" : "primary"
                    enabled: root.hasEngine && !root.sweepRunning
                    onClicked: {
                        if (!root.hasEngine)
                            return
                        if (root.benchRunning)
                            TribeEngine.cancelBench()
                        else
                            TribeEngine.startBench("baseline")
                    }
                }
                TribeButton {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    visible: !root.tunnelConnected && !root.abRunning && !root.benchRunning
                    text: qsTr("Замер через другой VPN — amnezia (~40 МБ)")
                    variant: "glass"
                    enabled: root.hasEngine && !root.sweepRunning
                    onClicked: if (root.hasEngine) TribeEngine.startBench("amnezia")
                }
                Text {
                    Layout.fillWidth: true
                    visible: root.benchRunning && !root.abRunning
                    text: qsTr("Не переключай VPN во время замера (~2 мин)")
                    color: Theme.color.warning
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }

                // ── авто-свип всех нод ──────────────────────────────────────
                TribeButton {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    text: root.sweepRunning ? qsTr("Отменить проверку (%1)").arg(root.sweepProgress)
                                            : qsTr("Проверить все ноды (~1 мин и ~10 МБ на ноду)")
                    variant: root.sweepRunning ? "ghost" : "glass"
                    enabled: root.hasEngine && (root.sweepRunning || !root.anyBusy)
                    onClicked: {
                        if (!root.hasEngine)
                            return
                        if (root.sweepRunning)
                            TribeEngine.cancelNodeSweep()
                        else
                            TribeEngine.startNodeSweep()
                    }
                }
                Text {
                    Layout.fillWidth: true
                    visible: root.sweepRunning
                    wrapMode: Text.WordWrap
                    text: qsTr("VPN будет сам переключаться между всеми серверами: коннект (замер времени) → короткий бенч → следующий. В конце вернётся исходное подключение.")
                    color: Theme.color.warning
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }

                // результаты свипа: таблица нод (лучшие сверху)
                TribeCard {
                    Layout.fillWidth: true
                    visible: root.sweepRows !== null && !root.sweepRunning
                    implicitHeight: sweepCol.implicitHeight + 2 * Theme.space.lg
                    ColumnLayout {
                        id: sweepCol
                        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        anchors.topMargin: Theme.space.lg
                        spacing: Theme.space.sm

                        Text {
                            text: qsTr("Ноды (лучшие сверху)")
                            color: Theme.color.accent
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS
                        }
                        Repeater {
                            model: root.sweepRows === null ? [] : root.sweepRows
                            delegate: ColumnLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: 1
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space.sm
                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.label || modelData.node_id
                                        color: modelData.ok ? Theme.color.text1 : Theme.color.danger
                                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                                        elide: Text.ElideRight
                                    }
                                    Text {
                                        text: modelData.ok
                                              ? qsTr("%1 Мбит · %2 мс").arg(Math.round(modelData.down_mbit * 10) / 10)
                                                                       .arg(Math.round(modelData.base_rtt_ms))
                                              : qsTr("недоступна")
                                        color: Theme.color.text1
                                        font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                                    }
                                }
                                Text {
                                    Layout.fillWidth: true
                                    text: modelData.ok
                                          ? qsTr("коннект %1 с · ttfb %2 мс · %3")
                                                .arg(Math.round(modelData.connect_ms / 100) / 10)
                                                .arg(Math.round(modelData.ttfb_ms))
                                                .arg(modelData.verdict)
                                          : String(modelData.verdict)
                                    color: Theme.color.text3
                                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                                    elide: Text.ElideRight
                                }
                            }
                        }
                        TribeButton {
                            Layout.fillWidth: true
                            Layout.topMargin: Theme.space.xs
                            variant: "glass"
                            text: qsTr("Скопировать отчёт по нодам")
                            onClicked: {
                                sweepJsonEdit.selectAll(); sweepJsonEdit.copy(); sweepJsonEdit.deselect()
                                PageController.showNotificationMessage(qsTr("Отчёт скопирован"))
                            }
                        }
                        TextEdit {
                            id: sweepJsonEdit
                            Layout.preferredWidth: 1; Layout.preferredHeight: 1
                            visible: false; readOnly: true
                            text: root.sweepJson
                        }
                    }
                }

                // ── эксперимент «RU-DNS маскировка» (звонки vs стелс, реш. 2026-07-03) ──
                // Измерено: Яндекс-DNS с загран-egress подсовывает RU-гео edge → WhatsApp-инфра
                // +75% RTT. OFF = DNS 1.1.1.1 через туннель (честный гео), RU-маршруты сохраняются.
                TribeCard {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    implicitHeight: dnsMaskRow.implicitHeight + 2 * Theme.space.lg
                    RowLayout {
                        id: dnsMaskRow
                        anchors.left: parent.left; anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 1
                            Text {
                                text: qsTr("RU-DNS маскировка")
                                color: Theme.color.text1
                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                            }
                            Text {
                                Layout.fillWidth: true
                                wrapMode: Text.WordWrap
                                text: qsTr("macOS: ВКЛ = split-DNS (и стелс RU-сервисов, и честный гео для звонков — идеал). iOS/Android пока выбор: ВКЛ = стелс (Яндекс-DNS на всё), ВЫКЛ = лучше звонки (WhatsApp/FaceTime). Доступ к RU-сайтам сохраняется всегда.")
                                color: Theme.color.text3
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            }
                        }
                        TribeToggle {
                            checked: root.hasEngine ? TribeEngine.bypassDnsMaskOn() : true
                            onToggled: if (root.hasEngine) TribeEngine.setBypassDnsMaskOn(checked)
                        }
                    }
                }

                // ── «Li Auto» — китайские сервисы мимо VPN (реш. 2026-07-03) ──
                // Узкие /24 серверов Li Auto (команды авто + логин) идут direct через РФ-IP: из-за
                // границы команды управления авто не проходят, с прямого РФ-IP работают. Default ВКЛ.
                TribeCard {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    implicitHeight: liAutoRow.implicitHeight + 2 * Theme.space.lg
                    RowLayout {
                        id: liAutoRow
                        anchors.left: parent.left; anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 1
                            Text {
                                text: qsTr("Li Auto")
                                color: Theme.color.text1
                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                            }
                            Text {
                                Layout.fillWidth: true
                                wrapMode: Text.WordWrap
                                text: qsTr("ВКЛ = приложение Li Auto (理想) ходит напрямую через российский IP, минуя VPN — тогда проходят команды управления автомобилем. Затрагивает только серверы Li Auto, на другие сайты не влияет.")
                                color: Theme.color.text3
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            }
                        }
                        TribeToggle {
                            checked: root.hasEngine ? TribeEngine.bypassLiAutoOn() : true
                            onToggled: if (root.hasEngine) TribeEngine.setBypassLiAutoOn(checked)
                        }
                    }
                }

                // ── результат авто-A/B: пара bypass-on/off + «цена байпаса» ──
                TribeCard {
                    Layout.fillWidth: true
                    visible: root.abSummary !== null && !root.abRunning
                    implicitHeight: abCol.implicitHeight + 2 * Theme.space.lg
                    ColumnLayout {
                        id: abCol
                        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        anchors.topMargin: Theme.space.lg
                        spacing: Theme.space.xs

                        Text {
                            text: qsTr("A/B: байпас ВКЛ ↔ ВЫКЛ")
                            color: Theme.color.accent
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS
                        }
                        Repeater {
                            model: root.abSummary === null ? [] : [
                                { k: qsTr("TTFB медиана"),  on: root.fmt(root.abSummary.on.ttfb_ms, qsTr(" мс")),
                                                            off: root.fmt(root.abSummary.off.ttfb_ms, qsTr(" мс")) },
                                { k: qsTr("Загрузка"),      on: root.fmt(root.abSummary.on.down_mbit, qsTr(" Мбит")),
                                                            off: root.fmt(root.abSummary.off.down_mbit, qsTr(" Мбит")) },
                                { k: qsTr("Отдача"),        on: root.fmt(root.abSummary.on.up_mbit, qsTr(" Мбит")),
                                                            off: root.fmt(root.abSummary.off.up_mbit, qsTr(" Мбит")) },
                                { k: qsTr("RTT покоя"),     on: root.fmt(root.abSummary.on.base_rtt_ms, qsTr(" мс")),
                                                            off: root.fmt(root.abSummary.off.base_rtt_ms, qsTr(" мс")) },
                                { k: qsTr("Ошибки HTTP"),   on: String(root.abSummary.on.failures),
                                                            off: String(root.abSummary.off.failures) }
                            ]
                            delegate: RowLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: Theme.space.sm
                                Text {
                                    Layout.fillWidth: true
                                    text: modelData.k
                                    color: Theme.color.text3
                                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                }
                                Text {
                                    text: qsTr("ВКЛ %1 · ВЫКЛ %2").arg(modelData.on).arg(modelData.off)
                                    color: Theme.color.text1
                                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                                }
                            }
                        }
                        Text {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: (root.abSummary && root.abSummary.cost && root.abSummary.cost.length > 0)
                                  ? qsTr("Цена байпаса: ") + root.abSummary.cost.join("; ")
                                  : qsTr("Цена байпаса: незначима ✓")
                            color: (root.abSummary && root.abSummary.cost && root.abSummary.cost.length > 0)
                                   ? Theme.color.warning : Theme.color.connected
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                        }
                        TribeButton {
                            Layout.fillWidth: true
                            Layout.topMargin: Theme.space.sm
                            variant: "glass"
                            text: qsTr("Скопировать A/B-отчёт")
                            onClicked: {
                                abJsonEdit.selectAll(); abJsonEdit.copy(); abJsonEdit.deselect()
                                PageController.showNotificationMessage(qsTr("A/B-отчёт скопирован"))
                            }
                        }
                        TextEdit {
                            id: abJsonEdit
                            Layout.preferredWidth: 1; Layout.preferredHeight: 1
                            visible: false; readOnly: true
                            text: root.abJson
                        }
                    }
                }

                // ── полный отчёт: последние замеры всех меток + сравнения одним JSON ──
                TribeCard {
                    Layout.fillWidth: true
                    visible: Object.keys(root.historyInfo).length >= 2
                    implicitHeight: fullCol.implicitHeight + 2 * Theme.space.lg
                    ColumnLayout {
                        id: fullCol
                        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        anchors.topMargin: Theme.space.lg
                        spacing: Theme.space.xs

                        Text {
                            text: qsTr("Полный отчёт — собрано %1/4").arg(Object.keys(root.historyInfo).length)
                            color: Theme.color.accent
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS
                        }
                        Repeater {
                            model: ["baseline", "tribe-bypass-on", "tribe-bypass-off", "amnezia"]
                            delegate: RowLayout {
                                required property string modelData
                                Layout.fillWidth: true
                                spacing: Theme.space.sm
                                Text {
                                    Layout.fillWidth: true
                                    text: modelData
                                    color: Theme.color.text3
                                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                                }
                                Text {
                                    // ts свежести: несвежий замер видно по дате — перемерь его
                                    text: root.historyInfo[modelData] !== undefined
                                          ? root.historyInfo[modelData] : qsTr("нет замера")
                                    color: root.historyInfo[modelData] !== undefined
                                           ? Theme.color.text1 : Theme.color.text3
                                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                                }
                            }
                        }
                        TribeButton {
                            Layout.fillWidth: true
                            Layout.topMargin: Theme.space.sm
                            variant: "glass"
                            text: qsTr("Скопировать полный отчёт (все метки + сравнения)")
                            onClicked: {
                                fullJsonEdit.text = TribeEngine.buildFullReport()
                                if (fullJsonEdit.text === "") return
                                fullJsonEdit.selectAll(); fullJsonEdit.copy(); fullJsonEdit.deselect()
                                PageController.showNotificationMessage(qsTr("Полный отчёт скопирован — перешли его в чат разработки"))
                            }
                        }
                        TextEdit {
                            id: fullJsonEdit
                            Layout.preferredWidth: 1; Layout.preferredHeight: 1
                            visible: false; readOnly: true
                        }
                    }
                }

                // результат последнего замера
                TribeCard {
                    Layout.fillWidth: true
                    visible: root.lastSummary !== null
                    implicitHeight: resultCol.implicitHeight + 2 * Theme.space.lg
                    ColumnLayout {
                        id: resultCol
                        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        anchors.topMargin: Theme.space.lg
                        spacing: Theme.space.xs

                        Text {
                            text: root.lastSummary ? root.lastSummary.label : ""
                            color: Theme.color.accent
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS
                        }
                        Repeater {
                            model: root.lastSummary === null ? [] : [
                                { k: qsTr("DNS медиана"),        v: root.fmt(root.lastSummary.dns_ms, qsTr(" мс")) },
                                { k: qsTr("TTFB медиана"),       v: root.fmt(root.lastSummary.ttfb_ms, qsTr(" мс")) },
                                { k: qsTr("Страница целиком"),   v: root.fmt(root.lastSummary.total_ms, qsTr(" мс")) },
                                { k: qsTr("Загрузка"),           v: root.fmt(root.lastSummary.down_mbit, qsTr(" Мбит/с")) },
                                { k: qsTr("Отдача"),             v: root.fmt(root.lastSummary.up_mbit, qsTr(" Мбит/с")) },
                                { k: qsTr("RTT покоя"),          v: root.fmt(root.lastSummary.base_rtt_ms, qsTr(" мс")) },
                                { k: qsTr("RTT под нагрузкой"),  v: root.fmt(root.lastSummary.loaded_rtt_ms, qsTr(" мс")) },
                                { k: qsTr("Ошибки HTTP"),        v: String(root.lastSummary.failures) },
                                { k: qsTr("Egress"),             v: String(root.lastSummary.egress) }
                            ]
                            delegate: RowLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: Theme.space.sm
                                Text {
                                    Layout.fillWidth: true
                                    text: modelData.k
                                    color: Theme.color.text3
                                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                }
                                Text {
                                    text: modelData.v
                                    color: Theme.color.text1
                                    font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                                }
                            }
                        }

                        // авто-диагнозы замера (BenchAnalysis: bufferbloat, потери, низкий goodput…)
                        Repeater {
                            model: (root.lastSummary && root.lastSummary.verdicts) ? root.lastSummary.verdicts : []
                            delegate: Text {
                                required property string modelData
                                Layout.fillWidth: true
                                text: "⚠ " + modelData
                                wrapMode: Text.WordWrap
                                color: Theme.color.warning
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            }
                        }
                        // A/B против сохранённых меток: чем текущий замер существенно хуже
                        Text {
                            Layout.fillWidth: true
                            visible: !!(root.lastSummary && root.lastSummary.vs_baseline !== undefined)
                            text: (root.lastSummary && root.lastSummary.vs_baseline && root.lastSummary.vs_baseline.length > 0)
                                  ? qsTr("vs baseline: ") + root.lastSummary.vs_baseline.join("; ")
                                  : qsTr("vs baseline: без существенных потерь")
                            wrapMode: Text.WordWrap
                            color: Theme.color.text2
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                        }
                        Text {
                            Layout.fillWidth: true
                            visible: !!(root.lastSummary && root.lastSummary.tribe_vs_amnezia !== undefined)
                            text: (root.lastSummary && root.lastSummary.tribe_vs_amnezia && root.lastSummary.tribe_vs_amnezia.length > 0)
                                  ? qsTr("Tribe vs Amnezia: ") + root.lastSummary.tribe_vs_amnezia.join("; ")
                                  : qsTr("Tribe vs Amnezia: паритет ✓")
                            wrapMode: Text.WordWrap
                            color: (root.lastSummary && root.lastSummary.tribe_vs_amnezia && root.lastSummary.tribe_vs_amnezia.length > 0)
                                   ? Theme.color.warning : Theme.color.connected
                            font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                        }
                        TribeButton {
                            Layout.fillWidth: true
                            Layout.topMargin: Theme.space.sm
                            variant: "glass"
                            text: qsTr("Скопировать JSON замера")
                            onClicked: {
                                jsonEdit.selectAll()
                                jsonEdit.copy()
                                jsonEdit.deselect()
                                PageController.showNotificationMessage(qsTr("Замер скопирован — перешли его в чат разработки"))
                            }
                        }
                        // скрытый буфер для dependency-free копирования (паттерн форка: TextEdit.copy())
                        TextEdit {
                            id: jsonEdit
                            Layout.preferredWidth: 1
                            Layout.preferredHeight: 1
                            visible: false
                            readOnly: true
                            text: root.lastJson
                        }
                    }
                }
            }
        }
    }
}

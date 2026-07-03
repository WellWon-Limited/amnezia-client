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
// Методика (4 метки): baseline (VPN выкл) → tribe-bypass-on → tribe-bypass-off → amnezia.
PageType {
    id: root

    // назад — в настройки (goAvpnTab(3) в PageStart), НЕ на Connect: страница открыта из настроек
    signal requestSettings()

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property bool benchRunning: hasEngine ? TribeEngine.benchRunning : false
    readonly property string benchStage: hasEngine ? TribeEngine.benchStage : ""

    property string selectedLabel: "baseline"
    property var lastSummary: null   // плоская мапа из benchFinished
    property string lastJson: ""

    readonly property var labels: ["baseline", "tribe-bypass-on", "tribe-bypass-off", "amnezia"]

    function stageTitle(st) {
        switch (st) {
        case "start": return qsTr("подготовка…")
        case "dns":   return qsTr("DNS-тайминги…")
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

    Connections {
        target: root.hasEngine ? TribeEngine : null
        function onBenchFinished(summary, json) {
            root.lastSummary = summary
            root.lastJson = json
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
                    text: qsTr("Меряет текущий путь: DNS, TTFB, пинг, скорость, отклик под нагрузкой. Выбери метку по методике: без VPN — baseline; Tribe с «Доступом к сайтам РФ» — bypass-on; без него — bypass-off; ванильная Amnezia с нашим ключом — amnezia.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }

                // метка замера
                Flow {
                    Layout.fillWidth: true
                    spacing: Theme.space.sm
                    Repeater {
                        model: root.labels
                        delegate: Rectangle {
                            required property string modelData
                            readonly property bool selected: root.selectedLabel === modelData
                            width: chipText.implicitWidth + 2 * Theme.space.md
                            height: chipText.implicitHeight + 2 * Theme.space.sm
                            radius: Theme.radius.pill
                            color: selected ? Theme.color.accent : Theme.color.surface2
                            border.width: 1
                            border.color: selected ? Theme.color.accent : Theme.color.border
                            Text {
                                id: chipText
                                anchors.centerIn: parent
                                text: parent.modelData
                                color: selected ? Theme.color.bg800 : Theme.color.text2
                                font.family: Theme.font.mono; font.pixelSize: Theme.font.caption
                            }
                            MouseArea {
                                anchors.fill: parent
                                enabled: !root.benchRunning
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.selectedLabel = parent.modelData
                            }
                        }
                    }
                }

                TribeButton {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    text: root.benchRunning ? qsTr("Отменить (%1)").arg(root.stageTitle(root.benchStage))
                                            : qsTr("Запустить замер (~40 МБ трафика)")
                    variant: root.benchRunning ? "ghost" : "primary"
                    enabled: root.hasEngine
                    onClicked: {
                        if (!root.hasEngine)
                            return
                        if (root.benchRunning)
                            TribeEngine.cancelBench()
                        else
                            TribeEngine.startBench(root.selectedLabel)
                    }
                }
                Text {
                    Layout.fillWidth: true
                    visible: root.benchRunning
                    text: qsTr("Не переключай VPN во время замера (~2 мин)")
                    color: Theme.color.warning
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
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

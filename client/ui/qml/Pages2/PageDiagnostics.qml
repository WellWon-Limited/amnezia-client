import QtQuick
import QtQuick.Controls   // StackView attached property (root.StackView.view.pop)
import QtQuick.Layouts

import "../Controls2"

// AVPN диагностическая панель (скрытый developer-экран, 5 тапов по логотипу). Overlay, апстрим не трогаем.
// Источник данных — ServiceEngine.debugSnapshot() движка serviceEngine. Пока движок не зарегистрирован
// как QML context property ("TribeEngine"), используем заглушку → по готовности движка заменяем на реальные данные.
// Это НЕ админка бэкенда (та — веб-панель за Cloudflare Zero Trust). См. implimintation.md §7.
PageType {
    id: root

    readonly property color accent: "#34D399"
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined") && TribeEngine !== null

    // Снимок: реальный из движка, иначе демонстрационная заглушка (та же форма, что DebugSnapshot.h).
    readonly property var snap: hasEngine ? TribeEngine.debugSnapshot() : ({
        "state": "connected",
        "currentNodeId": "fra-01",
        "latestHandshakeAgeSec": 12,
        "rxBytes": 4825600,
        "txBytes": 1331200,
        "subStatus": "active",
        "lkgStale": false,
        "trafficUsed": 73400320,
        "trafficLimit": 104857600,
        "pool": [
            { "nodeId": "fra-01", "region": "eu-central", "scoreMs": 57, "healthy": true,  "reason": "current · rtt 57ms" },
            { "nodeId": "ams-02", "region": "eu-west",    "scoreMs": 64, "healthy": true,  "reason": "rtt 64ms" },
            { "nodeId": "waw-01", "region": "eu-east",    "scoreMs": 0,  "healthy": false, "reason": "TCP timeout" }
        ],
        "switchLog": [ "switch waw-01→fra-01: dead (no rx, tx grew)" ]
    })

    function fmtBytes(b) {
        if (b >= 1073741824) return (b / 1073741824).toFixed(2) + " GB"
        if (b >= 1048576)    return (b / 1048576).toFixed(1) + " MB"
        if (b >= 1024)       return (b / 1024).toFixed(0) + " KB"
        return b + " B"
    }

    Rectangle { anchors.fill: parent; color: "#0B0C10" }

    // ---- шапка с «назад» ----
    Item {
        id: header
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 16 + PageController.safeAreaTopMargin
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        height: 40

        Rectangle {
            id: backBtn
            width: 40; height: 40; radius: 20
            color: backMouse.pressed ? "#1C1F26" : "#13151B"
            border.color: "#262A33"; border.width: 1
            Text { anchors.centerIn: parent; text: "‹"; color: root.accent; font.pixelSize: 22; font.weight: Font.Bold }
            MouseArea {
                id: backMouse; anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                onClicked: { if (root.StackView.view) root.StackView.view.pop() }
            }
        }
        Text {
            anchors.left: backBtn.right; anchors.leftMargin: 12; anchors.verticalCenter: backBtn.verticalCenter
            text: "Диагностика"; color: "#F2F2F5"; font.pixelSize: 19; font.weight: Font.Bold
        }
        Rectangle { // бейдж источника данных
            anchors.right: parent.right; anchors.verticalCenter: backBtn.verticalCenter
            height: 22; width: srcText.width + 16; radius: 11
            color: root.hasEngine ? "#0F2A1E" : "#2A2410"
            Text { id: srcText; anchors.centerIn: parent
                text: root.hasEngine ? "engine" : "demo"
                color: root.hasEngine ? root.accent : "#E0B341"; font.pixelSize: 11; font.weight: Font.Bold }
        }
    }

    Flickable {
        anchors.top: header.bottom
        anchors.topMargin: 16
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        anchors.bottomMargin: 16 + PageController.safeAreaBottomMargin
        contentHeight: col.implicitHeight
        clip: true

        ColumnLayout {
            id: col
            width: parent.width
            spacing: 12

            // ---- состояние движка ----
            DiagCard {
                title: "Состояние"
                ColumnLayout {
                    width: parent.width; spacing: 6
                    DiagRow { k: "state";         v: root.snap.state;        accent: root.accent }
                    DiagRow { k: "current node";  v: root.snap.currentNodeId }
                    DiagRow { k: "handshake age"; v: root.snap.latestHandshakeAgeSec + " s" }
                    DiagRow { k: "rx / tx";       v: root.fmtBytes(root.snap.rxBytes) + " / " + root.fmtBytes(root.snap.txBytes) }
                }
            }

            // ---- подписка/трафик ----
            DiagCard {
                title: "Подписка"
                ColumnLayout {
                    width: parent.width; spacing: 6
                    DiagRow { k: "sub status"; v: root.snap.subStatus; accent: root.snap.subStatus === "active" ? root.accent : "#E0B341" }
                    DiagRow { k: "LKG";        v: root.snap.lkgStale ? "stale" : "fresh" }
                    DiagRow { k: "traffic";    v: root.fmtBytes(root.snap.trafficUsed) + " / " + (root.snap.trafficLimit > 0 ? root.fmtBytes(root.snap.trafficLimit) : "∞") }
                }
            }

            // ---- пул нод (score / health) ----
            DiagCard {
                title: "Пул нод (" + root.snap.pool.length + ")"
                ColumnLayout {
                    width: parent.width; spacing: 8
                    Repeater {
                        model: root.snap.pool
                        delegate: RowLayout {
                            Layout.fillWidth: true; spacing: 8
                            Rectangle { Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4
                                color: modelData.healthy ? root.accent : "#E0564E" }
                            Text { text: modelData.nodeId; color: "#F2F2F5"; font.pixelSize: 13; font.weight: Font.Bold
                                Layout.preferredWidth: 72 }
                            Text { text: modelData.region; color: "#9A9DA6"; font.pixelSize: 12; Layout.fillWidth: true }
                            Text { text: modelData.healthy ? (modelData.scoreMs + " ms") : "—"
                                color: modelData.healthy ? "#C9CDD6" : "#E0564E"; font.pixelSize: 12
                                font.family: "Menlo"; horizontalAlignment: Text.AlignRight }
                        }
                    }
                }
            }

            // ---- лог переключений ----
            DiagCard {
                title: "Переключения"
                visible: root.snap.switchLog.length > 0
                ColumnLayout {
                    width: parent.width; spacing: 4
                    Repeater {
                        model: root.snap.switchLog
                        delegate: Text { text: "• " + modelData; color: "#9A9DA6"; font.pixelSize: 12
                            wrapMode: Text.WordWrap; Layout.fillWidth: true }
                    }
                }
            }

            // ---- оверрайды (включаются с реальным движком) ----
            DiagCard {
                title: "Оверрайды"
                RowLayout {
                    width: parent.width; spacing: 8
                    DiagBtn { text: "Re-probe"; enabled: root.hasEngine; onTap: if (root.hasEngine) TribeEngine.reprobe() }
                    DiagBtn { text: "Switch";   enabled: root.hasEngine; onTap: if (root.hasEngine) TribeEngine.manualSwitch() }
                    DiagBtn { text: "Reset LKG";enabled: root.hasEngine; onTap: if (root.hasEngine) TribeEngine.resetLkg() }
                }
            }

            Text {
                Layout.fillWidth: true; Layout.topMargin: 4
                text: "Developer-панель клиента (состояние движка на этом устройстве). Управление пулом — в админке бэкенда."
                color: "#6B7078"; font.pixelSize: 11; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter
            }
        }
    }

    // ---- мини-компоненты (inline) ----
    component DiagCard: Rectangle {
        default property alias content: holder.data
        property string title: ""
        Layout.fillWidth: true
        radius: 14
        color: "#0E1118"
        border.color: "#181B22"; border.width: 1
        implicitHeight: inner.implicitHeight + 28
        ColumnLayout {
            id: inner
            anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
            anchors.margins: 14; spacing: 10
            Text { text: parent.parent.title; color: "#6B7078"; font.pixelSize: 11; font.weight: Font.Bold
                font.letterSpacing: 0.5 }
            Item { id: holder; Layout.fillWidth: true; implicitHeight: childrenRect.height }
        }
    }
    component DiagRow: RowLayout {
        property string k: ""
        property string v: ""
        property color accent: "#C9CDD6"
        width: parent ? parent.width : 0
        Text { text: k; color: "#9A9DA6"; font.pixelSize: 13; Layout.fillWidth: true }
        Text { text: v; color: accent; font.pixelSize: 13; font.family: "Menlo"; horizontalAlignment: Text.AlignRight }
    }
    component DiagBtn: Rectangle {
        property string text: ""
        property bool enabled: true
        signal tap()
        Layout.fillWidth: true
        Layout.preferredHeight: 36; radius: 10
        color: !enabled ? "#0E1118" : (m.pressed ? "#10B981" : "#13251D")
        border.color: enabled ? "#1E4A38" : "#1A1D24"; border.width: 1
        opacity: enabled ? 1 : 0.4
        Text { anchors.centerIn: parent; text: parent.text; color: parent.enabled ? "#34D399" : "#6B7078"
            font.pixelSize: 13; font.weight: Font.Bold }
        MouseArea { id: m; anchors.fill: parent; enabled: parent.enabled; cursorShape: Qt.PointingHandCursor
            onClicked: parent.tap() }
    }
}

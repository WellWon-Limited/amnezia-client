import QtQuick
import QtQuick.Layouts

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Locations (Auto + реальный пул из GET /v1/subscription). Движок авто-подбирает узел;
// список — реальные ноды подписки, текущая помечена. Ручной пин узла появится с расширением API.
PageType {
    id: root

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property var pool: hasEngine ? (TribeEngine.nodePool || []) : []
    // AVPN: гард на undefined currentNode (вкладка открыта до первой подписки → иначе TypeError/краш)
    readonly property string curId: (hasEngine && TribeEngine.currentNode) ? (TribeEngine.currentNode.nodeId || "") : ""

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: Theme.space.xl + PageController.safeAreaTopMargin // iOS: натив-инсет из pageController
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        Text {
            text: qsTr("РЕЖИМ")
            color: Theme.color.accent
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        // Авто — реальный режим (движок выбирает быстрейший узел); тап = пере-подбор
        TribeListRow {
            Layout.fillWidth: true
            title: qsTr("Авто (быстрейший)")
            subtitle: qsTr("Сервис подбирает узел автоматически")
            onClicked: if (root.hasEngine) TribeEngine.reprobe()
            rightItem: Text {
                text: "✓"; color: Theme.color.accent
                font.pixelSize: Theme.font.h3; anchors.verticalCenter: parent.verticalCenter
            }
        }

        // AVPN: админ-просмотр пула — реальный nodePool из движка (#5).
        Text {
            text: qsTr("УЗЛЫ (АДМИН)")
            color: Theme.color.accent
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.md
            visible: root.pool.length > 0
        }

        Repeater {
            model: root.pool
            delegate: TribeListRow {
                Layout.fillWidth: true
                interactive: false                       // информационно: ручной пин узла — позже
                // AVPN: слева КРУГЛЫЙ флаг по country_code (SVG из flagKit, не эмодзи);
                // пусто/невалид/нет страны → точка-фолбэк.
                leftItem: Item {
                    width: 30; height: parent ? parent.height : 60
                    TribeFlag {
                        width: 28; height: 28; anchors.centerIn: parent
                        code: modelData ? (modelData.countryCode || "") : ""
                        fallback: Component {
                            Rectangle { width: 8; height: 8; radius: 4
                                color: Theme.color.text3; anchors.centerIn: parent }
                        }
                    }
                }
                // регион/имя + (активная нода помечена)
                title: modelData ? ((modelData.name || modelData.region || "")
                                    + ((modelData.nodeId === root.curId) ? qsTr("  • активна") : "")) : ""
                // endpoint при наличии, иначе ip (гард на undefined в превью)
                subtitle: modelData ? (modelData.endpoint || ("IP: " + (modelData.ip || ""))) : ""
                // справа: сигнал/ping через LoadBars + галочка для текущей ноды
                rightItem: Row {
                    spacing: Theme.space.md
                    anchors.verticalCenter: parent.verticalCenter
                    LoadBars {
                        anchors.verticalCenter: parent.verticalCenter
                        // signal: ping/level из модели → 5-балльная шкала (как SignalQuality.barsForRtt),
                        // иначе 3 («неизвестно/средне» для админ-просмотра пула).
                        level: {
                            if (!modelData) return 3
                            if (modelData.level !== undefined) return Math.max(0, Math.min(5, modelData.level))
                            if (modelData.ping !== undefined) {
                                var p = Number(modelData.ping)
                                if (isNaN(p) || p < 0) return 0
                                return p < 50 ? 5 : (p < 100 ? 4 : (p < 150 ? 3 : (p < 300 ? 2 : 1)))
                            }
                            return 3
                        }
                        barColor: (modelData && modelData.nodeId === root.curId)
                                  ? Theme.color.connected : Theme.color.accent
                    }
                    Text {
                        text: (modelData && modelData.nodeId === root.curId) ? "✓" : ""
                        color: Theme.color.connected
                        width: 14
                        font.pixelSize: Theme.font.h3; anchors.verticalCenter: parent.verticalCenter
                    }
                }
            }
        }

        // пусто до первой подписки
        Text {
            visible: root.pool.length === 0
            text: qsTr("Узлы появятся после первого подключения")
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
            Layout.topMargin: Theme.space.sm
        }

        Item { Layout.fillHeight: true }
    }
}

import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (live-node picker): нижняя шторка выбора сервера. Паттерн seatSheet из PageAccountTribe:
// затемнение фона + перехват кликов + нижняя TribeCard (elevated) с грабером сверху.
// Содержимое: «Авто (быстрейший)» → TribeEngine.selectAuto() (авто-режим: уход в OFF + следующий
// Connect выберет быстрейший); ListView ТОЛЬКО живых узлов (modelData.alive) из TribeEngine.nodePool —
// TribeFlag + имя + сигнал-бары (текущий узел = реальные liveBars, остальные = backend-health 0..1→1..5);
// текущий (modelData.current) — акцент-рамка (БЕЗ галки: рамки достаточно). Тап по узлу → ЗАКРЫТЬ шторку
// СРАЗУ, затем TribeEngine.switchToNode(nodeId): задаёт цель + уводит орб в OFF (коннект — ВРУЧНУЮ).
// Без шевронов. open() → отложенный refreshPool() (Timer, НЕ из кадра показа — refreshPool синхронный
// nested-loop fetch, прямой вызов в onOpened крашит). Только токены Theme.qml.
Item {
    id: sheet
    anchors.fill: parent
    visible: opened
    z: 100

    property bool opened: false
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    // живые узлы из пула (фильтруем «только живые»). Гард на undefined-движок (dev-превью).
    readonly property var pool: hasEngine ? TribeEngine.nodePool : []

    function open() {
        opened = true
        // AVPN: refreshPool() на стороне движка СИНХРОННЫЙ (bootstrap → awaitReply, nested QEventLoop).
        // Звать его ПРЯМО здесь = nested loop во время показа/анимации шторки → re-entrancy SIGSEGV
        // (тот же класс краша, из-за которого bootstrap/refreshDevices деферят таймером). Список и так
        // рисуется из уже наполненного nodePool; обновление пула откладываем «после показа».
        poolRefreshTimer.restart()
    }
    function close() { opened = false; poolRefreshTimer.stop() }

    // AVPN: деферим синхронный refreshPool за пределы кадра показа шторки (см. open()).
    Timer {
        id: poolRefreshTimer
        interval: 350; repeat: false
        onTriggered: {
            if (sheet.hasEngine && typeof TribeEngine.refreshPool === "function")
                TribeEngine.refreshPool()
        }
    }

    // затемнение фона + перехват кликов (тап мимо карточки = закрыть)
    Rectangle {
        anchors.fill: parent
        color: "#CC000000"
        MouseArea { anchors.fill: parent; onClicked: sheet.close() }
    }

    // нижняя карточка
    TribeCard {
        id: panel
        elevated: true
        width: parent.width - 2 * Theme.space.xl
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
        // высота по контенту, но не выше ~70% экрана (длинный список скроллится внутри ListView)
        implicitHeight: Math.min(sheetCol.implicitHeight + 2 * Theme.space.lg,
                                 sheet.height * 0.7)
        MouseArea { anchors.fill: parent }   // клик по карточке не закрывает шторку

        ColumnLayout {
            id: sheetCol
            anchors.fill: parent
            anchors.margins: Theme.space.lg
            spacing: Theme.space.md

            // грабер-полоска сверху
            Rectangle {
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: 36; Layout.preferredHeight: 4
                radius: 2
                color: Theme.color.border3
            }

            // заголовок
            Text {
                text: qsTr("Выбор сервера")
                color: Theme.color.text1
                font.family: Theme.font.display
                font.pixelSize: Theme.font.h3
                font.weight: Theme.font.wBold
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }

            // строка «Авто (быстрейший)» → re-pick по weight/health и закрытие
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                radius: Theme.radius.md
                color: autoMa.pressed ? Theme.color.surface3
                     : autoMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
                border.width: 1; border.color: Theme.color.border
                Behavior on color { ColorAnimation { duration: Theme.motion.fast } }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.space.lg
                    anchors.rightMargin: Theme.space.lg
                    spacing: Theme.space.md

                    // иконка «авто» (Tabler bolt, inline-вектор)
                    Shape {
                        Layout.preferredWidth: 22; Layout.preferredHeight: 22
                        Layout.alignment: Qt.AlignVCenter
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M13 3 L4 14 h7 l-1 7 l9-11 h-7z" }
                        }
                    }
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Авто (быстрейший)")
                        color: Theme.color.text1
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyM
                        font.weight: Theme.font.wMedium
                        elide: Text.ElideRight
                    }
                }
                MouseArea {
                    id: autoMa
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        // СНАЧАЛА закрываем шторку (мгновенно, без ожидания движка — пользователь уже выбрал),
                        // затем переключаем в авто-режим: selectAuto уводит туннель в OFF (если был онлайн) и
                        // снимает закрепление → главный экран выходит из «подключено к <узлу>» в «Умный выбор
                        // сервера», следующий ручной Connect поднимет быстрейший по скорингу.
                        sheet.close()
                        if (sheet.hasEngine && typeof TribeEngine.selectAuto === "function")
                            TribeEngine.selectAuto()
                    }
                }
            }

            // тонкий разделитель
            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.color.border }

            // список узлов — ТОЛЬКО живых (modelData.alive). Скроллится внутри карточки.
            ListView {
                id: nodeList
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredHeight: contentHeight
                clip: true
                spacing: Theme.space.sm
                boundsBehavior: Flickable.StopAtBounds
                model: sheet.pool

                delegate: Item {
                    id: nodeRow
                    required property var modelData
                    width: nodeList.width
                    // невидим и нулевой высоты для мёртвых узлов (фильтр «только живые»)
                    readonly property bool isAlive: modelData && modelData.alive === true
                    readonly property bool isCurrent: modelData && modelData.current === true
                    visible: isAlive
                    height: isAlive ? 60 : 0

                    Rectangle {
                        anchors.fill: parent
                        radius: Theme.radius.md
                        color: nodeRow.isCurrent ? Theme.color.chipSelected
                             : rowMa.pressed ? Theme.color.surface3
                             : rowMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
                        border.width: 1
                        border.color: nodeRow.isCurrent ? Theme.color.accent : Theme.color.border
                        Behavior on color { ColorAnimation { duration: Theme.motion.fast } }

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.space.lg
                            anchors.rightMargin: Theme.space.lg
                            spacing: Theme.space.md

                            // круглый флаг по country_code (SVG, не эмодзи) с фолбэк-точкой
                            TribeFlag {
                                Layout.preferredWidth: 36; Layout.preferredHeight: 36
                                Layout.alignment: Qt.AlignVCenter
                                code: nodeRow.modelData ? (nodeRow.modelData.countryCode || "") : ""
                                fallback: Component {
                                    Rectangle {
                                        radius: width / 2
                                        color: Theme.color.surface3
                                        border.width: 1; border.color: Theme.color.border2
                                        Rectangle {
                                            anchors.centerIn: parent
                                            width: 8; height: 8; radius: 4
                                            color: Theme.color.text3
                                        }
                                    }
                                }
                            }

                            // имя сервера (name || region)
                            Text {
                                Layout.fillWidth: true
                                text: nodeRow.modelData
                                      ? (nodeRow.modelData.name || nodeRow.modelData.region || qsTr("Сервер"))
                                      : qsTr("Сервер")
                                color: nodeRow.isCurrent ? Theme.color.accent : Theme.color.text1
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.bodyM
                                font.weight: nodeRow.isCurrent ? Theme.font.wSemibold : Theme.font.wMedium
                                elide: Text.ElideRight
                            }

                            // сигнал-бары: тот же 5-баровый LoadBars, что и на карточке Connect.
                            // ТЕКУЩИЙ узел показывает РЕАЛЬНЫЕ измеренные палочки (TribeEngine.liveBars —
                            // app-layer RTT через туннель, см. SignalQuality.h). Для остальных живого RTT нет
                            // (AWG UDP-only ⇒ не пингуется), уровень берём из backend-агрегата health (0..1→1..5)
                            // БЕЗ искусственного пола (раньше max(3,…) делал всех ≥3 ⇒ «всегда зелёные»; теперь
                            // слабые ноды показывают меньше). health пусто = 1.0 (backend-контракт). // AVPN
                            LoadBars {
                                Layout.alignment: Qt.AlignVCenter
                                level: {
                                    var h = nodeRow.modelData ? Number(nodeRow.modelData.health) : NaN
                                    if (isNaN(h)) h = 1.0   // health отсутствует = здоров = 1.0 (backend-контракт)
                                    var fromHealth = Math.max(1, Math.min(5, Math.round(h * 5)))
                                    // текущий узел: реальный liveBars приоритетнее health; 0 = ещё не мерили → health-фолбэк.
                                    if (nodeRow.isCurrent && sheet.hasEngine) {
                                        var lb = Number(TribeEngine.liveBars)
                                        return lb > 0 ? lb : fromHealth
                                    }
                                    return fromHealth
                                }
                                // текущий узел — акцентные бары; остальные — стандартный зелёный «сигнал».
                                barColor: nodeRow.isCurrent ? Theme.color.accent : Theme.color.connected
                            }
                        }

                        MouseArea {
                            id: rowMa
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            enabled: nodeRow.isAlive
                            onClicked: {
                                var id = nodeRow.modelData ? (nodeRow.modelData.nodeId || "") : ""
                                // СНАЧАЛА закрываем шторку (мгновенно — выбор уже сделан), потом просим движок.
                                sheet.close()
                                if (id !== "" && sheet.hasEngine && typeof TribeEngine.switchToNode === "function")
                                    TribeEngine.switchToNode(id)   // «Выбрать» цель (НЕ коннектит; orb→OFF, ждём Connect)
                            }
                        }
                    }
                }
            }
        }
    }
}

pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (Доктор v1, спека 2026-07-17-doctor-v1-design.md): попап полной диагностики
// «У меня не работает». Хост — ГЛОБАЛЬНО в PageStart (z поверх вкладок, как
// TribeAnnouncementSheet): тест переживает смену вкладок. Управление императивное:
// show() (интро) -> «Запустить диагностику» -> TribeEngine.startDoctor() -> живые стадии
// с прогрессом -> финал «Отчёт отправлен в поддержку». Отчёт в тред шлёт ЭТОТ слой
// (TribeSupport.sendDiagReport(doctorDiagText())) по doctorFinished — движок чата не трогает.
// Интро — по скриншоту владельца: ОДНА кнопка, без «Отмены» (закрытие — тап мимо/назад).
// Во время теста тап мимо НЕ закрывает; «назад» = отмена теста (эскейп-хатч без кнопки).
Item {
    id: root
    anchors.fill: parent
    visible: opened

    property bool opened: false
    // "intro" | "running" | "done"
    property string mode: "intro"
    property bool sentToSupport: false

    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    readonly property bool hasChat: typeof TribeSupport !== "undefined"
    readonly property bool running: hasEngine && TribeEngine.doctorRunning === true

    // Фикс-порядок стадий (id движка -> подпись). Статусы доезжают в doctorStages.
    readonly property var stageDefs: [
        { id: "connection", label: qsTr("Проверяю подключение") },
        { id: "servers",    label: qsTr("Проверяю серверы") },
        { id: "operator",   label: qsTr("Проверяю оператора") },
        { id: "whitelist",  label: qsTr("Проверяю «белые списки»") },
        { id: "speed",      label: qsTr("Проверяю скорость") },
    ]

    property int depthIndex: 0
    function show() {
        if (opened)
            return
        mode = "intro"
        sentToSupport = false
        opened = true
        depthIndex = PageController.incrementDrawerDepth()
    }
    function close() {
        if (!opened)
            return
        if (root.running && root.hasEngine)
            TribeEngine.cancelDoctor()
        opened = false
        mode = "intro"
        if (depthIndex > 0) {
            depthIndex = 0
            PageController.decrementDrawerDepth()
        }
    }
    Connections {
        target: PageController
        enabled: root.opened
        // Системный «назад»/Escape: pageController после emit сам декрементит глубину —
        // закрываемся без повторного декремента (паттерн diagConfirm viaController).
        function onCloseTopDrawer() {
            if (root.depthIndex !== PageController.getDrawerDepth())
                return
            if (root.running && root.hasEngine)
                TribeEngine.cancelDoctor()
            root.opened = false
            root.mode = "intro"
            root.depthIndex = 0
        }
    }
    Component.onDestruction: if (opened && depthIndex > 0) PageController.decrementDrawerDepth()

    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onDoctorFinished() {
            if (!root.opened)
                return
            root.mode = "done"
            // отчёт в тред поддержки: человекочитаемый diag.log + секция DOCTOR
            if (root.hasChat && root.hasEngine) {
                TribeSupport.sendDiagReport(TribeEngine.doctorDiagText())
                root.sentToSupport = true
            }
        }
    }

    Rectangle { anchors.fill: parent; color: Qt.alpha(Theme.color.bg800, 0.85) }
    MouseArea {
        anchors.fill: parent
        // тап мимо карточки: в интро — закрыть (кнопки «Отмена» нет по скриншоту),
        // во время теста и на финале — глотаем (закрытие только «назад»/«Понятно»)
        onClicked: if (root.mode === "intro") root.close()
    }

    Rectangle {
        id: card
        anchors.centerIn: parent
        width: Math.min(parent.width - 2 * Theme.space.xl, 360)
        implicitHeight: col.implicitHeight + 2 * Theme.space.xl
        height: implicitHeight
        radius: Theme.radius.xl
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.border2
        MouseArea { anchors.fill: parent }   // клик по карточке не проваливается в фон

        ColumnLayout {
            id: col
            anchors.left: parent.left; anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
            spacing: Theme.space.md

            // Круглая иконка: стетоскоп-пульс (activity, Lucide 24-grid) — акцентная
            Rectangle {
                Layout.alignment: Qt.AlignHCenter
                implicitWidth: 52; implicitHeight: 52; radius: 26
                color: Qt.alpha(Theme.color.accent, 0.12)
                border.width: 1
                border.color: Qt.alpha(Theme.color.accent, 0.45)
                Item {
                    anchors.centerIn: parent
                    width: 26; height: 26
                    Shape {
                        width: 24; height: 24
                        transform: Scale { xScale: 26 / 24; yScale: 26 / 24 }
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.accent; fillColor: "transparent"
                            strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M22 12 L18 12 L15 21 L9 3 L6 12 L2 12" }
                        }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                text: root.mode === "done" ? qsTr("Диагностика завершена")
                    : root.mode === "running" ? qsTr("Провожу диагностику")
                    : qsTr("Запустить диагностику?")
                color: Theme.color.text1
                font.family: Theme.font.display
                font.pixelSize: Theme.font.h3
                font.weight: Theme.font.wBold
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            // ── ИНТРО (текст по скриншоту владельца 2026-07-17) ──────────────────────────
            Text {
                visible: root.mode === "intro"
                Layout.fillWidth: true
                text: qsTr("Диагностика запустит процесс проверки состояния подключений, скорости, лучших серверов, наличия ошибок и др. (полностью анонимно)")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                lineHeight: 1.25
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }
            Text {
                visible: root.mode === "intro"
                Layout.fillWidth: true
                text: qsTr("Займёт 1–2 минуты — не закрывайте приложение.")
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: Theme.font.caption
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
            }

            // ── ХОД ТЕСТА: стадии с живыми статусами ─────────────────────────────────────
            ColumnLayout {
                visible: root.mode === "running"
                Layout.fillWidth: true
                spacing: Theme.space.sm

                Repeater {
                    model: root.stageDefs
                    delegate: RowLayout {
                        id: stageRow
                        required property var modelData
                        required property int index
                        Layout.fillWidth: true
                        spacing: Theme.space.sm

                        // статус стадии: из doctorStages (завершена) / текущая / будущая
                        readonly property var doneInfo: {
                            if (!root.hasEngine) return undefined
                            const arr = TribeEngine.doctorStages || []
                            for (var i = 0; i < arr.length; ++i)
                                if (arr[i].id === modelData.id) return arr[i]
                            return undefined
                        }
                        readonly property bool isCurrent: root.hasEngine
                                                          && TribeEngine.doctorStage === modelData.id
                        readonly property int st: doneInfo !== undefined ? (doneInfo.status ?? 0) : -100

                        Item {
                            implicitWidth: 20; implicitHeight: 20
                            // завершена: галка/точка цветом статуса; текущая: пульсирующая точка
                            Rectangle {
                                anchors.centerIn: parent
                                width: 8; height: 8; radius: 4
                                visible: !stageRow.isCurrent && stageRow.st === -100
                                color: Theme.color.text3
                                opacity: 0.4
                            }
                            Rectangle {
                                id: pulseDot
                                anchors.centerIn: parent
                                width: 10; height: 10; radius: 5
                                visible: stageRow.isCurrent
                                color: Theme.color.accent
                                SequentialAnimation on opacity {
                                    running: stageRow.isCurrent && !Theme.motion.reduceMotion
                                    loops: Animation.Infinite
                                    NumberAnimation { from: 1.0; to: 0.35; duration: 600; easing.type: Easing.InOutSine }
                                    NumberAnimation { from: 0.35; to: 1.0; duration: 600; easing.type: Easing.InOutSine }
                                }
                            }
                            Shape {
                                anchors.centerIn: parent
                                width: 14; height: 14
                                visible: stageRow.st === 0
                                preferredRendererType: Shape.CurveRenderer
                                ShapePath {
                                    strokeColor: Theme.color.connected; fillColor: "transparent"
                                    strokeWidth: 2
                                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                    PathSvg { path: "M2 8 L6 12 L13 3" }
                                }
                            }
                            Rectangle {
                                anchors.centerIn: parent
                                width: 10; height: 10; radius: 5
                                visible: stageRow.st === 1 || stageRow.st === 2
                                color: stageRow.st === 2 ? Theme.color.danger : Theme.color.warning
                            }
                            Rectangle {
                                anchors.centerIn: parent
                                width: 8; height: 2; radius: 1
                                visible: stageRow.st === -1   // Skip
                                color: Theme.color.text3
                            }
                        }

                        Text {
                            Layout.fillWidth: true
                            text: stageRow.doneInfo !== undefined && (stageRow.doneInfo.note || "") !== ""
                                  ? stageRow.doneInfo.note : stageRow.modelData.label
                            color: stageRow.isCurrent ? Theme.color.text1
                                 : stageRow.st !== -100 ? Theme.color.text2 : Theme.color.text3
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            elide: Text.ElideRight
                        }
                    }
                }

                // прогресс-бар: трек + акцент-заполнение по doctorPercent
                Rectangle {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    height: 6
                    radius: Theme.radius.pill
                    color: Theme.color.surface3
                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        radius: Theme.radius.pill
                        width: parent.width * (root.hasEngine ? TribeEngine.doctorPercent : 0) / 100
                        color: Theme.color.accent
                        Behavior on width { NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic } }
                    }
                }
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Не закрывайте приложение — идёт проверка")
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    horizontalAlignment: Text.AlignHCenter
                }
            }

            // ── ФИНАЛ ────────────────────────────────────────────────────────────────────
            Text {
                visible: root.mode === "done"
                Layout.fillWidth: true
                text: root.hasEngine ? TribeEngine.doctorSummary : ""
                color: Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyM
                font.weight: Theme.font.wSemibold
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }
            Text {
                visible: root.mode === "done"
                Layout.fillWidth: true
                text: root.sentToSupport
                      ? qsTr("Отчёт отправлен в тех. поддержку. Ожидайте ответа.")
                      : qsTr("Отчёт готов — откройте чат поддержки, чтобы отправить его.")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                lineHeight: 1.25
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            // ── КНОПКА (одна: интро «Запустить диагностику» / финал «Понятно»; во время
            //    теста кнопки нет — только «назад» отменяет). Интро = CTA-золото (главное
            //    действие); финал = нейтральная серая (закрытие вторично, реш. владельца). ──
            Rectangle {
                readonly property bool isDone: root.mode === "done"
                visible: root.mode !== "running"
                Layout.fillWidth: true
                Layout.topMargin: Theme.space.sm
                height: 52
                radius: Theme.radius.lg
                // финал: плоская серая surface2 (+glassStrong на нажатии); интро: золото
                color: isDone ? (goMa.pressed ? Theme.color.surface3 : Theme.color.surface2)
                              : "transparent"
                border.width: isDone ? 1 : 0
                border.color: Theme.color.border2
                gradient: isDone ? null : goGrad
                scale: goMa.pressed ? 0.985 : 1.0
                Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
                Gradient {
                    id: goGrad
                    GradientStop { position: 0.0; color: goMa.pressed ? Theme.color.ctaDeep : Theme.color.cta }
                    GradientStop { position: 1.0; color: Theme.color.ctaDeep }
                }

                Text {
                    anchors.centerIn: parent
                    text: parent.isDone ? qsTr("Понятно") : qsTr("Запустить диагностику")
                    color: parent.isDone ? Theme.color.text1 : Theme.color.bg900
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wBold
                }
                MouseArea {
                    id: goMa
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        if (root.mode === "done") {
                            root.close()
                        } else if (root.hasEngine) {
                            Haptic.play("light")
                            root.mode = "running"
                            TribeEngine.startDoctor()
                        }
                    }
                }
            }
        }
    }
}

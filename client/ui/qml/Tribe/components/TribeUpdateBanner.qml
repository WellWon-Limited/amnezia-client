import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (Task 7): ненавязчивый баннер «доступно обновление» (TribeEngine.updateState === 1 —
// remote-config §Task 6, мягкая рекомендация обновиться, НЕ блокер). Дисмисс держится в памяти
// сессии (property, не Settings) — баннер вернётся при следующем запуске, если версия всё ещё
// устарела. Токены — только Theme; закрывающая иконка — inline-вектор (Lucide "x"), без эмодзи.
Item {
    id: root

    property bool dismissed: false

    // Тап по «Обновить»: на десктопном macOS приложение ставит новую версию САМО (SelfUpdate) —
    // хост открывает экран обновления. Там, где установки внутри приложения нет (iOS/Android/
    // Windows), поведение прежнее: открыть страницу загрузки/стор.
    signal updateRequested()
    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    // AVPN (self-update v2): четыре состояния одного баннера, по убыванию приоритета —
    // notice (после отката), busy (тихая установка идёт), blocked (текущая версия отозвана),
    // recommend (доступна версия, как раньше). Токены только из Theme.
    readonly property bool hasNotice: hasEngine && TribeEngine.rollbackNotice.length > 0
    readonly property bool busy: hasEngine && TribeEngine.selfUpdateBusy
    readonly property bool blocked: hasEngine && TribeEngine.updateState === 3
    readonly property bool recommend: hasEngine && TribeEngine.updateState === 1
    readonly property string mode: hasNotice ? "notice" : busy ? "busy" : blocked ? "blocked" : "recommend"
    readonly property bool shouldShow: hasNotice || busy || blocked || (recommend && !dismissed)
    readonly property int percent: hasEngine ? TribeEngine.selfUpdatePercent : -1

    visible: shouldShow
    // Item, не Layout-делегат: ширину задаёт место монтирования (anchors.left/right, как у
    // autoVpnCard на PageConnectTribe) — без предположений о родителе (Layout/Column/anchors).
    implicitHeight: shouldShow ? card.implicitHeight : 0
    height: implicitHeight
    clip: true
    Behavior on implicitHeight { NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic } }

    Rectangle {
        id: card
        width: parent.width
        implicitHeight: row.implicitHeight + 2 * Theme.space.md
        radius: Theme.radius.lg
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.border

        RowLayout {
            id: row
            anchors.left: parent.left; anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.md
            spacing: Theme.space.md

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.space.xs

                Text {
                    Layout.fillWidth: true
                    // Номер в баннере: «доступна версия 5.1.74» проверяемо, «доступна новая версия» — нет.
                    text: {
                        if (root.mode === "notice") return TribeEngine.rollbackNotice
                        if (root.mode === "busy")
                            return TribeEngine.selfUpdateTarget
                                   ? qsTr("Обновляем до %1…").arg(TribeEngine.selfUpdateTarget)
                                   : qsTr("Обновляем…")
                        if (root.mode === "blocked")
                            return qsTr("Версия %1 отозвана разработчиком").arg(TribeEngine.appVersion.split(".").slice(0, 3).join("."))
                        return (root.hasEngine && TribeEngine.availableVersion)
                               ? qsTr("Доступна версия %1").arg(TribeEngine.availableVersion)
                               : qsTr("Доступна новая версия Tribe VPN")
                    }
                    textFormat: Text.PlainText
                    color: root.mode === "blocked" ? Theme.color.warning : Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                    font.weight: Theme.font.wMedium
                    wrapMode: Text.WordWrap
                }

                // стадия + процент во время установки («Скачиваем обновление · 42%»)
                Text {
                    Layout.fillWidth: true
                    visible: root.mode === "busy" && TribeEngine.selfUpdateStage.length > 0
                    text: root.percent >= 0
                          ? TribeEngine.selfUpdateStage + " · " + root.percent + "%"
                          : TribeEngine.selfUpdateStage
                    textFormat: Text.PlainText
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    elide: Text.ElideRight
                }

                // тонкая полоса прогресса: определённая по проценту, «бегунок» пока процент неизвестен
                TribeProgressBar {
                    Layout.fillWidth: true
                    visible: root.mode === "busy"
                    percent: root.percent
                }
            }

            Text {
                visible: root.mode !== "busy"
                text: root.mode === "notice" ? qsTr("Скрыть")
                    : root.mode === "blocked" ? (TribeEngine.canRollback ? qsTr("Вернуть %1").arg(TribeEngine.previousVersion)
                                                                          : qsTr("Обновить"))
                    : qsTr("Обновить")
                color: Theme.color.accent
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                font.weight: Theme.font.wSemibold
                MouseArea {
                    anchors.fill: parent
                    anchors.margins: -Theme.space.sm   // увеличенная зона тапа для мелкого текста
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        if (root.mode === "notice") { TribeEngine.dismissRollbackNotice(); return }
                        if (root.mode === "blocked" && TribeEngine.canRollback) { TribeEngine.rollbackToPrevious(); return }
                        if (root.hasEngine && TribeEngine.canSelfUpdate === true) {
                            root.updateRequested()
                            return
                        }
                        var url = root.hasEngine ? TribeEngine.storeUrl : ""
                        if (url) Qt.openUrlExternally(url)
                    }
                }
            }

            // закрыть — inline-вектор Lucide "x" (24-grid → 16px), НЕ эмодзи (правило проекта).
            // Установку и отозванную версию не закрыть крестиком: там нечего «скрывать».
            Item {
                visible: root.mode === "recommend"
                Layout.preferredWidth: 28; Layout.preferredHeight: 28
                Shape {
                    anchors.centerIn: parent
                    width: 16; height: 16
                    transform: Scale { xScale: 16 / 24; yScale: 16 / 24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M18 6 L6 18 M6 6 L18 18" }
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.dismissed = true
                }
            }
        }
    }
}

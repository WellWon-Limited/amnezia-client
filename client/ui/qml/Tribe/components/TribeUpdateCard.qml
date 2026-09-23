import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN (реш. владельца 2026-09-23): обновление показывается НЕ баннером над экраном, а на месте
// карточки сервера на главном экране — пока новая версия доступна (macOS, iOS, Android, Windows).
// Та же геометрия, что у serverCard (80 / радиус 24 / фон и рамка соседа), чтобы нижний блок не
// прыгал. Состояния по убыванию приоритета:
//   notice    — после отката («вернули прежнюю версию»), кнопка «Скрыть»;
//   busy      — идёт установка (macOS): «Обновляем до X», процент в правом верхнем углу,
//               полоса во всю ширину карточки;
//   blocked   — текущая версия отозвана: «Вернуть Y» / «Обновить» (если есть новее);
//   recommend — «Доступна версия X» + золотая «Обновить». VPN выключать не нужно: macOS качает
//               и ставит через туннель (его держит служба), iOS обновляется в TestFlight.
// Токены — только Theme; иконки — inline-векторы Lucide, без эмодзи.
Item {
    id: root

    // Тап «Обновить» там, где приложение ставит себя само (десктопный macOS): хост открывает
    // экран обновления. Иначе — открыть ссылку обновления (iOS: TestFlight, с сервера urls.store_ios).
    signal updateRequested()

    // Подавить (например, режим белых списков: ссылка всё равно не откроется).
    property bool suppressed: false

    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    readonly property bool hasNotice: hasEngine && TribeEngine.rollbackNotice.length > 0
    readonly property bool busy: hasEngine && TribeEngine.selfUpdateBusy
    readonly property bool blocked: hasEngine && TribeEngine.updateState === 3
    readonly property bool recommend: hasEngine && TribeEngine.updateState === 1
    readonly property string mode: hasNotice ? "notice" : busy ? "busy" : blocked ? "blocked" : "recommend"
    readonly property bool shouldShow: !suppressed && (hasNotice || busy || blocked || recommend)
    readonly property int percent: hasEngine ? TribeEngine.selfUpdatePercent : -1
    readonly property bool selfInstall: hasEngine && TribeEngine.canSelfUpdate === true
    readonly property bool hasAction: mode === "notice" || mode === "recommend"
                                      || (mode === "blocked" && hasEngine
                                          && (TribeEngine.canRollback || TribeEngine.newerAvailable))

    visible: shouldShow
    implicitHeight: 80
    height: implicitHeight

    function act() {
        if (!hasEngine) return
        if (mode === "notice") { TribeEngine.dismissRollbackNotice(); return }
        if (mode === "blocked" && TribeEngine.canRollback) { TribeEngine.rollbackToPrevious(); return }
        if (selfInstall) { root.updateRequested(); return }
        var url = TribeEngine.storeUrl
        if (url) Qt.openUrlExternally(url)
    }

    Rectangle {
        id: card
        anchors.fill: parent
        radius: 24
        // фон и рамка — как у serverCard (сосед по нижнему блоку PageConnectTribe)
        color: Qt.rgba(0x1E/255, 0x29/255, 0x3B/255, 0.40)
        border.width: 1
        border.color: root.mode === "blocked" ? Theme.color.warning : Qt.rgba(0x33/255, 0x41/255, 0x55/255, 0.5)
        scale: cardMa.pressed ? 0.985 : 1.0
        Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

        // тап по всей карточке = главное действие (кроме установки — там нечего нажимать)
        MouseArea {
            id: cardMa
            anchors.fill: parent
            enabled: root.mode !== "busy" && root.hasAction
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: root.act()
        }

        // ── иконка: круг 52 (как флаг сервера), золотая стрелка вверх (Lucide "arrow-up") ──
        Rectangle {
            id: badge
            width: 52; height: 52; radius: 26
            anchors.left: parent.left; anchors.leftMargin: Theme.space.lg
            anchors.verticalCenter: parent.verticalCenter
            anchors.verticalCenterOffset: root.mode === "busy" ? -Theme.space.xs : 0
            color: root.mode === "blocked" ? Theme.color.badgeWarn : Qt.rgba(Theme.color.cta.r, Theme.color.cta.g, Theme.color.cta.b, 0.14)
            border.width: 1
            border.color: root.mode === "blocked" ? Theme.color.warning : Theme.color.cta
            Shape {
                anchors.centerIn: parent
                width: 22; height: 22
                transform: Scale { xScale: 22 / 24; yScale: 22 / 24 }
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: root.mode === "blocked" ? Theme.color.warning : Theme.color.cta
                    fillColor: "transparent"; strokeWidth: 2
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    // blocked: Lucide "rotate-ccw" (вернуть); иначе "arrow-up"
                    PathSvg {
                        path: root.mode === "blocked" && root.hasEngine && TribeEngine.canRollback
                              ? "M3 12 a9 9 0 1 0 9 -9 a9.75 9.75 0 0 0 -6.74 2.74 L3 8 M3 3 v5 h5"
                              : "M12 19 V5 M5 12 l7 -7 7 7"
                    }
                }
            }
        }

        // ── справа: процент (установка) или золотая кнопка действия ──
        Text {
            id: pct
            visible: root.mode === "busy" && root.percent >= 0
            anchors.right: parent.right; anchors.rightMargin: Theme.space.lg
            anchors.top: parent.top; anchors.topMargin: Theme.space.md + 2
            text: root.percent + "%"
            color: Theme.color.text1
            font.family: Theme.font.mono; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wSemibold
        }

        Rectangle {
            id: actionBtn
            visible: root.mode !== "busy" && root.hasAction
            anchors.right: parent.right; anchors.rightMargin: Theme.space.lg
            anchors.verticalCenter: parent.verticalCenter
            height: 36
            width: actionText.implicitWidth + 2 * Theme.space.lg
            radius: Theme.radius.pill
            // «Скрыть» — тихая кнопка; «Обновить»/«Вернуть» — золото CTA (как «Продлить доступ»)
            readonly property bool quiet: root.mode === "notice"
            color: quiet ? Theme.color.surface2 : "transparent"
            gradient: quiet ? null : goldGrad
            Gradient {
                id: goldGrad
                GradientStop { position: 0.0; color: btnMa.pressed ? Theme.color.ctaDeep : Theme.color.cta }
                GradientStop { position: 1.0; color: Theme.color.ctaDeep }
            }
            scale: btnMa.pressed ? 0.97 : 1.0
            Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }
            Text {
                id: actionText
                anchors.centerIn: parent
                text: root.mode === "notice" ? qsTr("Скрыть")
                    : (root.mode === "blocked" && root.hasEngine && TribeEngine.canRollback)
                      ? qsTr("Вернуть %1").arg(TribeEngine.previousVersion)
                    : qsTr("Обновить")
                color: actionBtn.quiet ? Theme.color.text1 : Theme.color.bg900
                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wBold
            }
            MouseArea {
                id: btnMa
                anchors.fill: parent
                anchors.margins: -Theme.space.sm   // зона тапа шире самой кнопки
                cursorShape: Qt.PointingHandCursor
                onClicked: root.act()
            }
        }

        // ── середина: заголовок + подпись ──
        Column {
            anchors.left: badge.right; anchors.leftMargin: Theme.space.md
            anchors.right: root.mode === "busy" ? pct.left : (actionBtn.visible ? actionBtn.left : parent.right)
            anchors.rightMargin: Theme.space.md
            anchors.verticalCenter: parent.verticalCenter
            anchors.verticalCenterOffset: root.mode === "busy" ? -Theme.space.sm : 0
            spacing: 2

            Text {
                width: parent.width
                text: {
                    if (!root.hasEngine) return ""
                    if (root.mode === "notice") return TribeEngine.rollbackNotice
                    if (root.mode === "busy")
                        return TribeEngine.selfUpdateTarget
                               ? qsTr("Обновляем до %1").arg(TribeEngine.selfUpdateTarget)
                               : qsTr("Обновляем")
                    if (root.mode === "blocked")
                        return qsTr("Версия %1 отозвана").arg(TribeEngine.appVersion.split(".").slice(0, 3).join("."))
                    return TribeEngine.availableVersion
                           ? qsTr("Доступна версия %1").arg(TribeEngine.availableVersion)
                           : qsTr("Доступна новая версия")
                }
                textFormat: Text.PlainText
                color: root.mode === "blocked" ? Theme.color.warning : Theme.color.text1
                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM; font.weight: Theme.font.wSemibold
                elide: Text.ElideRight
                maximumLineCount: root.mode === "notice" ? 2 : 1
                wrapMode: root.mode === "notice" ? Text.WordWrap : Text.NoWrap
            }
            Text {
                width: parent.width
                visible: root.mode === "recommend" || root.mode === "blocked"
                text: root.mode === "blocked"
                      ? (root.hasEngine && TribeEngine.canRollback ? qsTr("Вернём прежнюю версию")
                                                                   : qsTr("Поставьте новую версию"))
                      : (root.selfInstall
                         ? qsTr("VPN выключать не нужно")
                         : (Qt.platform.os === "ios" ? qsTr("Через TestFlight · VPN выключать не нужно")
                                                     : qsTr("VPN выключать не нужно")))
                textFormat: Text.PlainText
                color: Theme.color.text3
                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                elide: Text.ElideRight
            }
        }

        // ── полоса установки: во всю ширину карточки, у нижнего края ──
        TribeProgressBar {
            visible: root.mode === "busy"
            anchors.left: parent.left; anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
            anchors.bottomMargin: Theme.space.md
            thickness: 6
            percent: root.percent
        }
    }
}

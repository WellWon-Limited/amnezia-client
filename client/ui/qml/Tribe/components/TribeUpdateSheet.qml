import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (реш. владельца 2026-09-02): единый экран обновления — «Доступна новая версия» + список
// того, что человек получит. Используется и обязательным блокером (TribeUpdateGate), и мягким
// предложением. Тексты server-driven: strings.update_title/update_body/update_bullets_<lang>
// приезжают в TribeEngine.hotTexts (localizedOr), вкомпиленные строки — фолбэк для офлайна и
// старых конфигов. Буллеты — одна строка с переводами строк, по одному пункту на строку.
// Токены только из Theme.
Item {
    id: sheet

    // "blocking" — версия несовместима, закрыть нельзя; "soft" — можно отложить
    property string mode: "blocking"
    property bool busy: false                 // идёт установка (macOS: скачивание/проверка)
    property string busyText: ""              // подпись под кнопкой во время установки
    property string errorText: ""             // ошибка установки, если была

    signal updateRequested()
    signal laterRequested()

    readonly property var _hot: (typeof TribeEngine !== "undefined" && TribeEngine.hotTexts)
                                ? TribeEngine.hotTexts : ({})

    readonly property string titleText:
        _hot["update_title"] ? _hot["update_title"] : qsTr("Доступна новая версия")

    // «Было → стало»: без номеров человек не понимает, обновился он уже или экран показался зря
    // (реш. владельца 2026-09-02). Пусто с сервера — строку не показываем вовсе.
    readonly property string currentVersion:
        (typeof TribeEngine !== "undefined" && TribeEngine.appVersion) ? TribeEngine.appVersion : ""
    readonly property string newVersion:
        (typeof TribeEngine !== "undefined" && TribeEngine.availableVersion) ? TribeEngine.availableVersion : ""
    readonly property bool showVersions:
        sheet.currentVersion.length > 0 && sheet.newVersion.length > 0
        && sheet.newVersion !== sheet.currentVersion

    readonly property string bodyText:
        _hot["update_body"] ? _hot["update_body"]
                            : (sheet.mode === "blocking"
                               ? qsTr("Эта версия больше не работает с нашими серверами. Обновитесь, чтобы продолжить.")
                               : qsTr("Обновление уже готово — займёт меньше минуты."))

    // Фолбэк-буллеты держим короткими и про пользу, а не про внутренности.
    readonly property var bullets: {
        const raw = _hot["update_bullets"] ? String(_hot["update_bullets"]) : ""
        const fromServer = raw.split("\n").map(s => s.trim()).filter(s => s.length > 0)
        if (fromServer.length > 0)
            return fromServer
        return [
            qsTr("Новый протокол соединения — труднее заблокировать"),
            qsTr("Приложение само выбирает самый быстрый способ подключения"),
            qsTr("Список серверов обновляется без перезапуска"),
            qsTr("Меньше обрывов при смене сети и после сна")
        ]
    }

    implicitHeight: content.implicitHeight

    ColumnLayout {
        id: content
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Theme.space.lg

        // иконка обновления (Lucide "download", 24-grid) в круглой плашке
        Rectangle {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 72; Layout.preferredHeight: 72
            radius: Theme.radius.pill
            color: Theme.color.surface1
            border.width: 1; border.color: Theme.color.border2

            Shape {
                anchors.centerIn: parent
                width: 32; height: 32
                transform: Scale { xScale: 32 / 24; yScale: 32 / 24 }
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 1.8
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M21 15 v4 a2 2 0 0 1 -2 2 H5 a2 2 0 0 1 -2 -2 v-4 M7 10 L12 15 L17 10 M12 15 V3" }
                }
            }

            // во время установки иконка «дышит» — единственная анимация экрана
            SequentialAnimation on opacity {
                running: sheet.busy
                loops: Animation.Infinite
                NumberAnimation { to: 0.45; duration: Theme.motion.slow }
                NumberAnimation { to: 1.0;  duration: Theme.motion.slow }
            }
        }

        Text {
            Layout.fillWidth: true
            text: sheet.titleText
            textFormat: Text.PlainText
            color: Theme.color.text1
            font.family: Theme.font.display
            font.pixelSize: Theme.font.h1
            font.weight: Theme.font.wBold
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            text: sheet.bodyText
            textFormat: Text.PlainText
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyM
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        // «5.1.73 → 5.1.74» моноширинным, как номера в остальном интерфейсе
        Text {
            Layout.fillWidth: true
            visible: sheet.showVersions
            text: sheet.currentVersion + "  →  " + sheet.newVersion
            textFormat: Text.PlainText
            color: Theme.color.text3
            font.family: Theme.font.mono
            font.pixelSize: Theme.font.caption
            horizontalAlignment: Text.AlignHCenter
        }

        // ── что нового: карточка со списком пунктов (пусто = карточки нет) ──
        Rectangle {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.xs
            visible: sheet.bullets.length > 0
            implicitHeight: bulletsCol.implicitHeight + 2 * Theme.space.lg
            radius: Theme.radius.lg
            color: Theme.color.surface1
            border.width: 1; border.color: Theme.color.border2

            ColumnLayout {
                id: bulletsCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Theme.space.lg
                anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.md

                Repeater {
                    model: sheet.bullets
                    delegate: RowLayout {
                        required property string modelData
                        Layout.fillWidth: true
                        spacing: Theme.space.md

                        // галочка (Lucide "check", 24-grid → 16px)
                        Shape {
                            Layout.preferredWidth: 16
                            Layout.preferredHeight: 16
                            Layout.alignment: Qt.AlignTop
                            Layout.topMargin: 2
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 2.4
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                PathSvg { path: "M5 12.5L9.5 17L19 7" }
                            }
                            transform: Scale { xScale: 16 / 24; yScale: 16 / 24 }
                        }

                        Text {
                            Layout.fillWidth: true
                            text: modelData
                            textFormat: Text.PlainText
                            color: Theme.color.text1
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            wrapMode: Text.WordWrap
                        }
                    }
                }
            }
        }

        // ошибка установки — на месте, а не тостом: человек должен видеть, почему кнопка не сработала
        Text {
            Layout.fillWidth: true
            visible: sheet.errorText.length > 0
            text: sheet.errorText
            textFormat: Text.PlainText
            color: Theme.color.danger
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        TribeButton {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.xs
            variant: "primary"
            enabled: !sheet.busy
            text: sheet.busy ? qsTr("Обновляем…") : qsTr("Обновить")
            onClicked: sheet.updateRequested()
        }

        Text {
            Layout.fillWidth: true
            visible: sheet.busy && sheet.busyText.length > 0
            text: sheet.busyText
            textFormat: Text.PlainText
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: Theme.font.caption
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        TribeButton {
            Layout.fillWidth: true
            visible: sheet.mode !== "blocking" && !sheet.busy
            variant: "ghost"
            text: qsTr("Позже")
            onClicked: sheet.laterRequested()
        }
    }
}

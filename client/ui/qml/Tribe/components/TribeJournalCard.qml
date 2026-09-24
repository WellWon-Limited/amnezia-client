import QtQuick
import QtQuick.Layouts

import ".."   // Theme

// AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md):
// переключатель журнала + статус досылки + «Отправить накопленное». Одна карточка на Настройки
// (раздел «Диагностика») и панель администратора. Видимость решает страница
// (TribeEngine.journalVisible); удалённо включённый из /panel журнал пользователь не выключает.
TribeCard {
    id: card

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property bool forced: hasEngine && TribeEngine.journalForced === true
    readonly property bool active: hasEngine && TribeEngine.journalActive === true
    readonly property bool sending: hasEngine && TribeEngine.journalSending === true

    implicitHeight: col.implicitHeight + 2 * Theme.space.lg

    ColumnLayout {
        id: col
        anchors.left: parent.left; anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
        spacing: Theme.space.md

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space.md
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1
                Text {
                    text: qsTr("Журнал тестирования")
                    color: Theme.color.text1
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                }
                Text {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: card.forced
                          ? qsTr("Включён администратором. Приложение пишет технический журнал и само отправляет его разработчикам.")
                          : qsTr("Весь день пишет технический журнал приложения и туннеля и сам отправляет его разработчикам. Без адресов сайтов и содержимого трафика.")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }
            }
            TribeToggle {
                Layout.alignment: Qt.AlignVCenter
                enabled: !card.forced
                opacity: enabled ? 1.0 : 0.45
                checked: card.active
                onToggled: {
                    if (card.hasEngine) TribeEngine.setJournalUserOn(checked)
                    checked = Qt.binding(function() { return card.active }) // вернуть связь с движком
                }
            }
        }

        Text {
            Layout.fillWidth: true
            visible: card.active && text !== ""
            wrapMode: Text.WordWrap
            text: card.hasEngine ? TribeEngine.journalStatus : ""
            color: Theme.color.text2
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
        }

        TribeButton {
            Layout.fillWidth: true
            visible: card.active
            variant: "glass"
            loading: card.sending
            enabled: !card.sending
            text: qsTr("Отправить накопленное")
            onClicked: if (card.hasEngine) TribeEngine.sendJournalNow()
        }
    }
}

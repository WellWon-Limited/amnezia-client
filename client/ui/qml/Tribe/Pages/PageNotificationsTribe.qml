import QtQuick
import QtQuick.Layouts

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: центр уведомлений (#3). Открывается из колокола в шапке Connect.
// Сейчас mock-список; реальные пуши — #9 (APNs/FCM), бэкенд — #10.
PageType {
    id: root

    signal back()

    // iOS/Android/desktop: натив-инсет (safe area).
    readonly property real safeTop: PageController.safeAreaTopMargin

    // AVPN (#9): реальные пуши приходят через мост AvpnPush (APNs/FCM → C++ → QML). В dev-превью
    // моста нет → показываем только mock-данные.
    readonly property bool hasPush: (typeof AvpnPush !== "undefined")
    readonly property var pushItems: hasPush ? AvpnPush.items : []

    // mock-данные уведомлений (заголовок / текст / время / прочитано) — fallback/демо.
    readonly property var mockItems: [
        { title: qsTr("Подписка продлена"),       body: qsTr("Доступ активен ещё 12 дней. Спасибо, что остаётесь с Tribe."), time: qsTr("2 ч назад"),   read: false },
        { title: qsTr("Новая локация: Нидерланды"), body: qsTr("Добавлен быстрый сервер в Амстердаме — уже в пуле."),          time: qsTr("Вчера"),       read: false },
        { title: qsTr("Совет по скорости"),        body: qsTr("Нажмите «Обновить подключение», если сайт грузится медленно."), time: qsTr("3 дня назад"), read: true  }
    ]

    // Реальные пуши сверху, затем демо-данные.
    readonly property var items: pushItems.concat(mockItems)

    // При открытии центра уведомлений отмечаем все пуши прочитанными → бейдж на колоколе гаснет.
    Component.onCompleted: {
        if (hasPush && AvpnPush.markAllRead)
            AvpnPush.markAllRead()
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        TribeHeader {
            Layout.fillWidth: true
            title: qsTr("Уведомления")
            showBack: true
            onBackClicked: {
                root.back()
                if (typeof PageController !== "undefined" && PageController.closePage)
                    PageController.closePage()
            }
        }

        ListView {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            Layout.topMargin: Theme.space.sm
            clip: true
            spacing: Theme.space.md
            boundsBehavior: Flickable.StopAtBounds
            model: root.items

            delegate: Rectangle {
                width: ListView.view ? ListView.view.width : 0
                implicitHeight: col.implicitHeight + 2 * Theme.space.lg
                radius: Theme.radius.lg
                color: Theme.color.surface1
                border.width: 1; border.color: Theme.color.border

                // непрочитанные — точка accent в левом верхнем углу
                Rectangle {
                    visible: !modelData.read
                    width: 8; height: 8; radius: 4
                    color: Theme.color.accent
                    anchors.left: parent.left; anchors.top: parent.top
                    anchors.leftMargin: Theme.space.md; anchors.topMargin: Theme.space.lg + 4
                }

                Column {
                    id: col
                    anchors.left: parent.left; anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.leftMargin: Theme.space.xl
                    anchors.rightMargin: Theme.space.lg
                    anchors.topMargin: Theme.space.lg
                    spacing: Theme.space.xs

                    RowLayout {
                        width: parent.width
                        spacing: Theme.space.sm
                        Text {
                            Layout.fillWidth: true
                            text: modelData.title
                            color: Theme.color.text1
                            font.family: Theme.font.display
                            font.pixelSize: Theme.font.bodyM
                            font.weight: modelData.read ? Theme.font.wMedium : Theme.font.wBold
                            elide: Text.ElideRight
                        }
                        Text {
                            text: modelData.time
                            color: Theme.color.text3
                            font.family: Theme.font.mono
                            font.pixelSize: Theme.font.caption
                        }
                    }
                    Text {
                        width: parent.width
                        text: modelData.body
                        color: Theme.color.text2
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyS
                        wrapMode: Text.WordWrap
                    }
                }
            }
        }
    }
}

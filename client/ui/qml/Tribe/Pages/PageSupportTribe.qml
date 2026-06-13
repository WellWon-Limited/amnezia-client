import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Поддержка — чат с оператором. P-U: данные локальные (mock); реальный бэкенд чата —
// задача #10 (Tribe-Backend). Дизайн строго по Theme-токенам.
PageType {
    id: root

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // mock-тред поддержки (визуализация; бэкенд подключим позже)
    ListModel {
        id: thread
        ListElement { body: "Здравствуйте! Это поддержка Tribe VPN. Чем можем помочь?"; mine: false; t: "10:02" }
        ListElement { body: "Привет! Один сайт не открывается через VPN."; mine: true; t: "10:03" }
        ListElement { body: "Подскажите адрес сайта и ваш регион — проверим узел и маршрут."; mine: false; t: "10:03" }
    }

    function send() {
        var txt = input.text.trim()
        if (txt.length === 0)
            return
        thread.append({ body: txt, mine: true, t: Qt.formatTime(new Date(), "HH:mm") })
        input.clear()
        list.positionViewAtEnd()
        autoReply.restart()   // mock-ответ оператора
    }

    Timer {
        id: autoReply; interval: 1200
        onTriggered: {
            thread.append({ body: qsTr("Спасибо! Передал инженеру — ответим в течение нескольких минут."),
                            mine: false, t: Qt.formatTime(new Date(), "HH:mm") })
            list.positionViewAtEnd()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: PageController.safeAreaTopMargin
        spacing: 0

        TribeHeader {
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.md
            Layout.rightMargin: Theme.space.md
            title: qsTr("Поддержка")
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
            model: thread
            cacheBuffer: 4000
            delegate: ChatBubble {
                width: ListView.view ? ListView.view.width : 0
                text: body
                mine: model.mine
                time: t
            }
            onCountChanged: positionViewAtEnd()
            Component.onCompleted: positionViewAtEnd()
        }

        // composer: поле + круглая кнопка отправки
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: composerRow.implicitHeight + 2 * Theme.space.md
                            + Math.max(PageController.safeAreaBottomMargin, PageController.imeHeight)
            color: Theme.color.bg900

            Rectangle { width: parent.width; height: 1; color: Theme.color.border; anchors.top: parent.top }

            RowLayout {
                id: composerRow
                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                anchors.topMargin: Theme.space.md
                spacing: Theme.space.sm

                TribeField {
                    id: input
                    Layout.fillWidth: true
                    placeholderText: qsTr("Сообщение…")
                    onAccepted: root.send()
                }

                Rectangle {
                    Layout.preferredWidth: 46; Layout.preferredHeight: 46
                    radius: 23
                    color: input.text.length > 0 ? Theme.color.accent : Theme.color.surface2
                    Behavior on color { ColorAnimation { duration: 160 } }
                    Shape {
                        anchors.centerIn: parent; width: 22; height: 22
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: input.text.length > 0 ? Theme.color.bg900 : Theme.color.text3
                            fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M5 12 L19 12 M13 6 L19 12 L13 18" }
                        }
                    }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.send() }
                }
            }
        }
    }
}

import QtQuick
import QtQuick.Controls   // TextField (поле ввода композера)
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Поддержка — чат с оператором. P-U: данные локальные (mock); реальный бэкенд чата —
// задача #10 (Tribe-Backend). Дизайн строго по Theme-токенам.
PageType {
    id: root

    // iOS: PageController.safeArea* только для Android → max с SafeArea (Qt 6.9+, реактивный инсет).
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

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
        // заголовок «Поддержка» убран (вкладка уже подписана в нижней навигации). Отступ от чёлки. // AVPN
        anchors.topMargin: root.safeTop + Theme.space.lg
        spacing: 0

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

        // composer: поле-пилюля + круглая кнопка отправки. Контент над safe-area/клавиатурой
        // (нижний инсет уходит в ПАДДИНГ, не оставляет пустоту под полем → центрирование ок). // AVPN
        Rectangle {
            id: composer
            Layout.fillWidth: true
            color: Theme.color.bg900
            readonly property real bottomInset: Math.max(PageController.safeAreaBottomMargin, PageController.imeHeight)
            implicitHeight: composerRow.implicitHeight + 2 * Theme.space.md + bottomInset

            // хайрлайн-разделитель сверху
            Rectangle { width: parent.width; height: 1; color: Theme.color.border; anchors.top: parent.top }

            RowLayout {
                id: composerRow
                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                anchors.topMargin: Theme.space.md
                spacing: Theme.space.sm

                // поле ввода — пилюля; рамка подсвечивается акцентом в фокусе
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 48
                    Layout.alignment: Qt.AlignVCenter
                    radius: height / 2
                    color: Theme.color.surface1
                    border.width: 1
                    border.color: input.activeFocus ? Theme.color.accent : Theme.color.border
                    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

                    TextField {
                        id: input
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.lg
                        anchors.rightMargin: Theme.space.md
                        verticalAlignment: TextInput.AlignVCenter
                        placeholderText: qsTr("Сообщение…")
                        color: Theme.color.text1
                        placeholderTextColor: Theme.color.text3
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyM
                        background: null
                        selectionColor: Theme.color.accent
                        onAccepted: root.send()
                    }
                }

                // кнопка отправки — круг по центру поля; акцент при непустом вводе, press-scale
                Rectangle {
                    id: sendBtn
                    Layout.preferredWidth: 48; Layout.preferredHeight: 48
                    Layout.alignment: Qt.AlignVCenter
                    radius: height / 2
                    readonly property bool ready: input.text.trim().length > 0
                    color: ready ? Theme.color.accent : Theme.color.surface2
                    scale: (sendMa.pressed && ready) ? 0.92 : 1.0
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

                    Shape {
                        anchors.centerIn: parent; width: 22; height: 22
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: sendBtn.ready ? Theme.color.bg900 : Theme.color.text3
                            fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M5 12 L19 12 M13 6 L19 12 L13 18" }
                        }
                    }
                    MouseArea {
                        id: sendMa
                        anchors.fill: parent
                        enabled: sendBtn.ready
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.send()
                    }
                }
            }
        }
    }
}

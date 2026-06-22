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

        // composer (редизайн 2026-06-18, Telegram-стиль): капсула с авто-растущим вверх TextArea +
        // ОТДЕЛЬНАЯ круглая кнопка отправки СБОКУ справа (не налезает на текст). Кнопка прижата к низу
        // строки (Layout.alignment AlignBottom) — при росте капсулы остаётся на месте. Без тёмной
        // подложки (цвет страницы bg800). Тёмное контекст-меню как в TribeField. // AVPN
        Rectangle {
            id: composer
            Layout.fillWidth: true
            color: Theme.color.bg800
            readonly property real bottomInset: Math.max(PageController.safeAreaBottomMargin, PageController.imeHeight)
            // строка composer + по md-отступу сверху/снизу + safe-area/IME-инсет
            implicitHeight: composerRow.implicitHeight + 2 * Theme.space.md + bottomInset

            // хайрлайн-разделитель сверху
            Rectangle { width: parent.width; height: 1; color: Theme.color.border; anchors.top: parent.top }

            // реальные метрики шрифта поля — для ТОЧНОГО вертикального центрирования 1 строки. // AVPN
            FontMetrics { id: inputFm; font: input.font }

            RowLayout {
                id: composerRow
                anchors.left: parent.left; anchors.right: parent.right
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                // AVPN: прижато к НИЗУ над safe-area/IME-инсетом → острова капсулы сверху/снизу равны
                // (md и md), а инсет (home-indicator/клавиатура) уходит ПОД низ. Раньше ряд был прижат
                // к верху (topMargin md) + инсет снизу → на iOS капсула «висела высоко» (на маке инсет≈0,
                // потому там было нормально). implicitHeight = row + 2·md + inset ⇒ верхний остров = md.
                anchors.bottom: parent.bottom
                anchors.bottomMargin: Theme.space.md + composer.bottomInset
                spacing: Theme.space.sm

                // авто-растущая капсула с полем ввода (растёт вверх, кнопка остаётся на месте)
                Rectangle {
                    id: capsule
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignBottom

                    readonly property int minH: 44
                    readonly property int maxH: 132
                    // растёт по контенту до капа; при превышении — внутренний скролл TextArea. // AVPN
                    Layout.preferredHeight: Math.max(minH, Math.min(maxH, input.implicitHeight))
                    Behavior on Layout.preferredHeight { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }
                    radius: Math.min(height / 2, Theme.radius.xl)   // 1 строка → пилюля; при росте → скруглённый прямоугольник
                    color: Theme.color.surface1
                    border.width: 1
                    border.color: input.activeFocus ? Theme.color.accent : Theme.color.border
                    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

                    ScrollView {
                        id: scroller
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.lg
                        anchors.rightMargin: Theme.space.lg
                        clip: true
                        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                        TextArea {
                            id: input
                            width: scroller.availableWidth
                            wrapMode: TextArea.Wrap
                            // вертикальное центрирование 1 строки в капсуле minH по РЕАЛЬНОЙ высоте
                            // шрифта (inputFm.height), а не по хардкоду 11px (он врал — строка bodyM ≠ 22). // AVPN
                            topPadding: Math.max(6, Math.round((capsule.minH - inputFm.height) / 2))
                            bottomPadding: topPadding
                            leftPadding: 0; rightPadding: 0
                            placeholderText: qsTr("Сообщение…")
                            color: Theme.color.text1
                            placeholderTextColor: Theme.color.text3
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyM
                            background: null
                            selectionColor: Theme.color.accent
                            // тёмное контекст-меню вместо нативного белого iOS-меню (паттерн форка) // AVPN
                            ContextMenu.menu: ContextMenuType { textObj: input }
                            // Enter = перенос строки (мультистрочный composer); отправка только кнопкой. // AVPN
                        }
                    }
                }

                // круглая кнопка отправки — СБОКУ, прижата к низу строки. Акцент при непустом вводе. // AVPN
                Rectangle {
                    id: sendBtn
                    Layout.preferredWidth: 44; Layout.preferredHeight: 44
                    Layout.alignment: Qt.AlignBottom
                    radius: height / 2
                    readonly property bool ready: input.text.trim().length > 0
                    color: ready ? Theme.color.accent : Theme.color.surface3
                    opacity: ready ? 1.0 : 0.6
                    scale: (sendMa.pressed && ready) ? 0.92 : 1.0
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Behavior on opacity { NumberAnimation { duration: Theme.motion.fast } }
                    Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

                    // стрелка нарисована в сетке 24 (центр пути = 12,12). Шейп 24×24, масштаб к 20
                    // ВОКРУГ ЦЕНТРА (Item.scale + transformOrigin) — иначе 24-путь в 20-боксе уезжал
                    // вниз-вправо (центр контента 12 vs центр бокса 10). // AVPN
                    Shape {
                        anchors.centerIn: parent; width: 24; height: 24
                        scale: 20 / 24; transformOrigin: Item.Center
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

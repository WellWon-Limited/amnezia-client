import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: центр уведомлений (#3). Открывается из колокола в шапке Connect.
// Показывает РЕАЛЬНЫЕ пуши (APNs/FCM), сохранённые движком локально (переживают перезапуск).
// История между сессиями/устройствами с сервера — отдельная задача (бэкенд GET /v1/notifications).
PageType {
    id: root

    signal back()

    // iOS: PageController.safeArea* только для Android → max с SafeArea (Qt 6.9+, реактивный инсет).
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    // AVPN (#9): реальные пуши приходят через мост AvpnPush (APNs/FCM → C++ → QML), движок хранит их
    // локально (QSettings) → переживают перезапуск приложения. В dev-превью моста нет → пустой список.
    readonly property bool hasPush: (typeof AvpnPush !== "undefined")
    readonly property var pushItems: hasPush ? AvpnPush.items : []

    // Только РЕАЛЬНЫЕ уведомления — мок-демо убран (колокол показывает то, что действительно
    // приходило пользователю). Пусто → экран пустого состояния ниже. // AVPN
    readonly property var items: pushItems

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
            // AVPN: только сигнал back() → PageStart вернёт на Connect (goAvpnTab 0). НЕ зовём
            // PageController.closePage() — страница открыта через replace (depth=1), и closePage уходил
            // в hideWindow() (прятал окно) вместо возврата. Отсюда «кнопка назад не работает».
            onBackClicked: root.back()
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
                id: card
                width: ListView.view ? ListView.view.width : 0
                implicitHeight: row.implicitHeight + 2 * Theme.space.lg
                radius: Theme.radius.lg
                // AVPN (бонусы): типовой стиль по modelData.type (мост AvpnPushBridge кладёт type/days).
                // bonus_gift → «золотой подарок» (золотая рамка/подложка иконки); payment → accent; иначе нейтрально.
                readonly property string kind: modelData.type ? String(modelData.type) : "generic"
                readonly property bool isGift: kind === "bonus_gift"
                readonly property int giftDays: modelData.days ? Number(modelData.days) : 0
                color: isGift ? Qt.rgba(0xE8/255, 0xB2/255, 0x3A/255, 0.06) : Theme.color.surface1
                border.width: 1
                border.color: isGift ? Qt.rgba(0xE8/255, 0xB2/255, 0x3A/255, 0.45) : Theme.color.border

                // непрочитанные — точка (золотая у подарка) в левом верхнем углу
                Rectangle {
                    visible: !modelData.read
                    width: 8; height: 8; radius: 4
                    color: card.isGift ? Theme.color.cta : Theme.color.accent
                    anchors.left: parent.left; anchors.top: parent.top
                    anchors.leftMargin: Theme.space.md; anchors.topMargin: Theme.space.lg + 4
                }

                RowLayout {
                    id: row
                    anchors.left: parent.left; anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.leftMargin: Theme.space.xl
                    anchors.rightMargin: Theme.space.lg
                    anchors.topMargin: Theme.space.lg
                    spacing: Theme.space.md

                    // иконка-медальон: подарок (золото) для бонуса, галочка для оплаты, колокол иначе
                    Rectangle {
                        visible: card.isGift || card.kind === "payment"
                        Layout.alignment: Qt.AlignTop
                        width: 36; height: 36; radius: 18
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: card.isGift ? Theme.color.cta : Theme.color.accent }
                            GradientStop { position: 1.0; color: card.isGift ? Theme.color.ctaDeep : Theme.color.accentDeep }
                        }
                        // lucide gift (24-grid → 20px), белый контур
                        Shape {
                            anchors.centerIn: parent; width: 20; height: 20
                            transform: Scale { xScale: 20/24; yScale: 20/24 }
                            preferredRendererType: Shape.CurveRenderer
                            visible: card.isGift
                            ShapePath {
                                strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                PathSvg { path: "M20 12 v10 H4 V12 M2 7 h20 v5 H2 z M12 22 V7 M12 7 H7.5 a2.5 2.5 0 0 1 0 -5 C11 2 12 7 12 7z M12 7 h4.5 a2.5 2.5 0 0 0 0 -5 C13 2 12 7 12 7z" }
                            }
                        }
                        // галочка для payment
                        Shape {
                            anchors.centerIn: parent; width: 16; height: 16
                            preferredRendererType: Shape.CurveRenderer
                            visible: card.kind === "payment"
                            ShapePath {
                                strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2.2
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                PathSvg { path: "M3 8.5 L6.5 12 L13 4" }
                            }
                        }
                    }

                    Column {
                        Layout.fillWidth: true
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
                        // золотой чип «+N дней» для бонуса
                        Rectangle {
                            visible: card.isGift && card.giftDays > 0
                            implicitWidth: giftChip.implicitWidth + 2 * Theme.space.md
                            implicitHeight: giftChip.implicitHeight + Theme.space.xs
                            radius: height / 2
                            color: Qt.rgba(0xE8/255, 0xB2/255, 0x3A/255, 0.15)
                            border.width: 1; border.color: Qt.rgba(0xE8/255, 0xB2/255, 0x3A/255, 0.5)
                            Text {
                                id: giftChip
                                anchors.centerIn: parent
                                text: qsTr("+%1 дней").arg(card.giftDays)
                                color: Theme.color.cta
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                font.weight: Theme.font.wBold
                            }
                        }
                    }
                }
            }
        }
    }

    // пустое состояние: уведомлений ещё не приходило (мок-демо убран). // AVPN
    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.x3
        spacing: Theme.space.md
        visible: root.items.length === 0

        // иконка-колокол (Tabler bell, 24-grid → ×2 до 48px)
        Shape {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 48; height: 48
            preferredRendererType: Shape.CurveRenderer
            transform: Scale { xScale: 2; yScale: 2 }
            ShapePath {
                strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.6
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6 M9 17v1a3 3 0 0 0 6 0v-1" }
            }
        }

        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("Пока нет уведомлений")
            color: Theme.color.text1
            font.family: Theme.font.display
            font.pixelSize: Theme.font.bodyL
            font.weight: Theme.font.wBold
        }

        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            text: qsTr("Здесь появятся важные сообщения о подписке, новых серверах и состоянии сервиса.")
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyS
        }
    }
}

import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme, Haptic
import "../components"
import "../../Controls2" // PageType

// AVPN (read per-элемент, 2026-07-12): полноэкранная деталь ОДНОГО уведомления.
// Открывается из центра (PageNotificationsTribe) тапом по карточке: PageStart ловит
// requestNotificationDetail(notif) → goToTabBarPageUrl(..., { notif }) (паттерн PageLegalTribe
// с extraProps). Пометка «прочитано» уже сделана в момент тапа (AvpnPush.markItemRead) —
// здесь только отображение. «Назад» — в центр уведомлений (requestNotifications), не на Connect.
PageType {
    id: root

    // данные уведомления; снапшот передаёт список ({id, title, body, time, type, days})
    property var notif: ({})

    // назад — в центр уведомлений (PageStart: onRequestNotifications)
    signal requestNotifications()

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    readonly property string kind: (notif && notif.type) ? String(notif.type) : "generic"
    readonly property bool isGift: kind === "bonus_gift"
    readonly property bool isPayment: kind === "payment"
    readonly property int giftDays: (notif && notif.days) ? Number(notif.days) : 0

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // свайп слева-направо = «назад» (в центр уведомлений)
    TribeEdgeBack { onTriggered: root.requestNotifications() }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        TribeHeader {
            Layout.fillWidth: true
            title: qsTr("Уведомление")
            showBack: true
            onBackClicked: root.requestNotifications()
        }

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            topMargin: Theme.space.lg
            bottomMargin: Theme.space.x3
            contentWidth: width
            contentHeight: content.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Column {
                id: content
                width: parent.width
                spacing: Theme.space.lg

                // иконка-медальон по типу — тот же язык, что у карточек центра:
                // подарок (золото) для бонуса, галочка (accent) для оплаты, колокол иначе
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: 56; height: 56; radius: 28
                    gradient: (root.isGift || root.isPayment) ? medalGradient : null
                    color: (root.isGift || root.isPayment) ? "transparent" : Theme.color.surface1
                    border.width: (root.isGift || root.isPayment) ? 0 : 1
                    border.color: Theme.color.border

                    Gradient {
                        id: medalGradient
                        GradientStop { position: 0.0; color: root.isGift ? Theme.color.cta : Theme.color.accent }
                        GradientStop { position: 1.0; color: root.isGift ? Theme.color.ctaDeep : Theme.color.accentDeep }
                    }

                    // lucide gift (24-grid → 26px), белый контур
                    Shape {
                        anchors.centerIn: parent; width: 26; height: 26
                        transform: Scale { xScale: 26/24; yScale: 26/24 }
                        preferredRendererType: Shape.CurveRenderer
                        visible: root.isGift
                        ShapePath {
                            strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M20 12 v10 H4 V12 M2 7 h20 v5 H2 z M12 22 V7 M12 7 H7.5 a2.5 2.5 0 0 1 0 -5 C11 2 12 7 12 7z M12 7 h4.5 a2.5 2.5 0 0 0 0 -5 C13 2 12 7 12 7z" }
                        }
                    }
                    // галочка для payment
                    Shape {
                        anchors.centerIn: parent; width: 20; height: 20
                        preferredRendererType: Shape.CurveRenderer
                        visible: root.isPayment
                        ShapePath {
                            strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2.2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M4 10.5 L8.5 15 L16 5" }
                        }
                    }
                    // колокол (Tabler bell) для остальных типов
                    Shape {
                        anchors.centerIn: parent; width: 24; height: 24
                        preferredRendererType: Shape.CurveRenderer
                        visible: !root.isGift && !root.isPayment
                        ShapePath {
                            strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6 M9 17v1a3 3 0 0 0 6 0v-1" }
                        }
                    }
                }

                Text {
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    text: (root.notif && root.notif.title) ? root.notif.title : ""
                    color: Theme.color.text1
                    font.family: Theme.font.display
                    font.pixelSize: Theme.font.h3
                    font.weight: Theme.font.wBold
                    wrapMode: Text.WordWrap
                }

                Text {
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    visible: text !== ""
                    text: (root.notif && root.notif.time) ? root.notif.time : ""
                    color: Theme.color.text3
                    font.family: Theme.font.mono
                    font.pixelSize: Theme.font.caption
                }

                // золотой чип «+N дней» — как в карточке центра
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    visible: root.isGift && root.giftDays > 0
                    implicitWidth: giftChip.implicitWidth + 2 * Theme.space.md
                    implicitHeight: giftChip.implicitHeight + Theme.space.xs
                    radius: height / 2
                    color: Qt.rgba(0xE8/255, 0xB2/255, 0x3A/255, 0.15)
                    border.width: 1; border.color: Qt.rgba(0xE8/255, 0xB2/255, 0x3A/255, 0.5)
                    Text {
                        id: giftChip
                        anchors.centerIn: parent
                        text: qsTr("+%1 дней").arg(root.giftDays)
                        color: Theme.color.cta
                        font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                        font.weight: Theme.font.wBold
                    }
                }

                // полный текст — без elide, с переносами и прокруткой (ради этого страница и есть)
                Rectangle {
                    width: parent.width
                    implicitHeight: bodyText.implicitHeight + 2 * Theme.space.xl
                    radius: Theme.radius.lg
                    color: Theme.color.surface1
                    border.width: 1
                    border.color: Theme.color.border
                    Text {
                        id: bodyText
                        anchors.fill: parent
                        anchors.margins: Theme.space.xl
                        text: (root.notif && root.notif.body) ? root.notif.body : ""
                        color: Theme.color.text2
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.bodyM
                        lineHeight: 1.35
                        wrapMode: Text.WordWrap
                    }
                }
            }
        }
    }
}

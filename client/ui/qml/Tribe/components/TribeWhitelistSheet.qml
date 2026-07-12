import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (белые списки, спека 2026-07-12 §6): центрированный попап «Действуют "Белые списки"» —
// РКН-режим whitelist на сотовой (TribeEngine.whitelistMode && !whitelistAcked). Глобальный
// слой на PageStart — поверх любого экрана и нижней навигации. «Понятно» ->
// setWhitelistAcked(true), попап закрыт. Повторный показ: новый эпизод (движок сбрасывает
// acked при выходе из режима) ИЛИ тап по коннекту при активном режиме (PageConnectTribe зовёт
// setWhitelistAcked(false)); саму попытку подключения попап НЕ блокирует.
// Текст: суть -> кто виноват -> что сделать. Системный «назад»/Escape проглатывается
// (паттерн TribeAnnouncementSheet), тап мимо карточки не закрывает.
Item {
    id: root
    anchors.fill: parent

    readonly property bool shouldShow: (typeof TribeEngine !== "undefined")
                                        && TribeEngine.whitelistMode === true
                                        && TribeEngine.whitelistAcked !== true
    visible: shouldShow

    // Показ управляется биндингом (не show()/close()) — глубину drawer-стека ведём по факту
    // смены видимости, иначе «назад» после закрытия попапа сломается во всём приложении.
    property int depthIndex: 0
    onShouldShowChanged: {
        if (shouldShow) {
            depthIndex = PageController.incrementDrawerDepth()
        } else if (depthIndex > 0) {
            depthIndex = 0
            PageController.decrementDrawerDepth()
        }
    }
    Connections {
        target: PageController
        enabled: root.shouldShow
        // Системный «назад» НЕ закрывает: pageController после emit сам декрементит —
        // компенсируем инкрементом (глубина и попап остаются как были).
        function onCloseTopDrawer() {
            if (root.depthIndex === PageController.getDrawerDepth())
                PageController.incrementDrawerDepth()
        }
    }
    Component.onDestruction: {
        if (depthIndex > 0)
            PageController.decrementDrawerDepth()
    }

    Rectangle { anchors.fill: parent; color: Qt.alpha(Theme.color.bg800, 0.85) }
    MouseArea { anchors.fill: parent }   // тап мимо карточки НЕ закрывает

    Rectangle {
        id: card
        anchors.centerIn: parent
        width: Math.min(parent.width - 2 * Theme.space.xl, 360)
        implicitHeight: col.implicitHeight + 2 * Theme.space.xl
        height: implicitHeight
        radius: Theme.radius.xl
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.warning

        ColumnLayout {
            id: col
            anchors.left: parent.left; anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
            spacing: Theme.space.md

            // Круглая warning-иконка wifi-off (Lucide 24-grid) — stroke-вектор, НЕ эмодзи
            Rectangle {
                Layout.alignment: Qt.AlignHCenter
                implicitWidth: 52; implicitHeight: 52; radius: 26
                color: Theme.color.badgeWarn
                border.width: 1
                border.color: Theme.color.warning

                Item {
                    anchors.centerIn: parent
                    width: 26; height: 26
                    Shape {
                        width: 24; height: 24
                        transform: Scale { xScale: 26 / 24; yScale: 26 / 24 }
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.warning; fillColor: "transparent"
                            strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M12 20 L12.01 20 M8.5 16.5 a5 5 0 0 1 7 0 M5 12.86 a10 10 0 0 1 5.17 -2.69 M19 12.86 a10 10 0 0 0 -2.68 -1.71 M2 8.82 a15 15 0 0 1 4.17 -2.65 M22 8.82 a15 15 0 0 0 -11.29 -3.76 M2 2 L22 22" }
                        }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                text: qsTr("Действуют «Белые списки»")
                color: Theme.color.text1
                font.family: Theme.font.display
                font.pixelSize: Theme.font.h3
                font.weight: Theme.font.wBold
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            Text {
                Layout.fillWidth: true
                text: qsTr("Ваш мобильный оператор сейчас ограничивает интернет: работают только российские сайты из «белого списка» — Госуслуги, Яндекс, Ozon и подобные. Всё остальное, включая VPN, на этой сети недоступно.")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                lineHeight: 1.25
                wrapMode: Text.WordWrap
            }

            Text {
                Layout.fillWidth: true
                text: qsTr("Это ограничение на стороне оператора, а не сбой Tribe VPN — так бывает во время отключений мобильного интернета.")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                lineHeight: 1.25
                wrapMode: Text.WordWrap
            }

            Text {
                Layout.fillWidth: true
                textFormat: Text.StyledText
                text: qsTr("<b>Что сделать:</b> подключитесь к сети Wi-Fi — там VPN заработает как обычно. Или попробуйте позже: как только оператор снимет ограничение, приложение подключится само.")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                lineHeight: 1.25
                wrapMode: Text.WordWrap
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.topMargin: Theme.space.sm
                implicitHeight: okLabel.implicitHeight + 2 * Theme.space.md
                radius: Theme.radius.md
                color: Theme.color.warning

                Text {
                    id: okLabel
                    anchors.centerIn: parent
                    text: qsTr("Понятно")
                    color: Theme.color.bg800
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wBold
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: TribeEngine.setWhitelistAcked(true)
                }
            }
        }
    }
}

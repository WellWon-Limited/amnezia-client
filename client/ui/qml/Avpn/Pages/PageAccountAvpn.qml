import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Account / Subscription. P-U1 stub (static) — SubscriptionController wires it in P-U3.
// NO purchase button / price / payment link (Apple compliance, UI-DESIGN.md §10).
PageType {
    id: root

    // мост в полный интерфейс Amnezia (PageStart включает Dev.amneziaMode)
    signal requestAmnezia()

    // авторизация — мок до P-U3 (AuthController): false → кнопка «Войти»
    property bool authorized: false

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 8 + Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top) // iOS: PageController даёт 0
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        // верхняя строка: админ-кнопки справа (перенесены с главной), без заголовка
        RowLayout {
            Layout.fillWidth: true
            spacing: 2
            Item { Layout.fillWidth: true }
            // мост в Amnezia-UI — только в админ-режиме
            Item {
                Layout.preferredWidth: 36; Layout.preferredHeight: 36
                visible: Dev.adminMode
                Image {
                    anchors.centerIn: parent
                    source: "qrc:/images/controls/amnezia.svg"
                    sourceSize: Qt.size(22, 22)
                    opacity: amneziaMa.containsMouse ? 1.0 : 0.65
                }
                MouseArea { id: amneziaMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: root.requestAmnezia() }
            }
            // тумблер админ-режима (lucide shield)
            Item {
                Layout.preferredWidth: 36; Layout.preferredHeight: 36
                opacity: Dev.adminMode ? 1.0 : 0.55
                Shape {
                    anchors.centerIn: parent
                    width: 22; height: 22
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Dev.adminMode ? Theme.color.accent
                                                   : (adminMa.containsMouse ? Theme.color.text1 : Theme.color.text3)
                        fillColor: Dev.adminMode ? Theme.color.chipSelected : "transparent"
                        strokeWidth: 1.7
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }
                    }
                }
                MouseArea { id: adminMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: Dev.adminMode = !Dev.adminMode }
            }
        }

        // плашка пользователя + Войти/Выйти
        TribeCard {
            Layout.fillWidth: true
            implicitHeight: 64
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space.lg
                anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.md
                Rectangle {
                    width: 40; height: 40; radius: 20
                    color: Theme.color.surface2
                    // Tabler "user" (inline vector, без emoji)
                    Shape {
                        anchors.centerIn: parent
                        width: 24; height: 24
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.text2; fillColor: "transparent"; strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M12 12 a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" }
                            PathSvg { path: "M6 20 v-1 a6 6 0 0 1 12 0 v1" }
                        }
                    }
                }
                Text {
                    Layout.fillWidth: true
                    text: root.authorized ? qsTr("Аккаунт") : qsTr("Пробный доступ")
                    color: Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                }
                // Войти (не авторизованы) / Выйти (авторизованы) — действия в P-U3
                Rectangle {
                    Layout.preferredWidth: authText.width + 2 * Theme.space.lg
                    Layout.preferredHeight: 34
                    radius: Theme.radius.pill
                    color: root.authorized
                           ? (authMa.containsMouse ? Theme.color.surface2 : "transparent")
                           : (authMa.containsMouse ? Theme.color.accentBright : Theme.color.accent)
                    border.width: root.authorized ? 1 : 0
                    border.color: Theme.color.border2
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Text {
                        id: authText
                        anchors.centerIn: parent
                        text: root.authorized ? qsTr("Выйти") : qsTr("Войти")
                        color: root.authorized ? Theme.color.text1 : "white"
                        font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                        font.weight: Theme.font.wSemibold
                    }
                    MouseArea { id: authMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor }
                }
            }
        }

        Text {
            text: qsTr("ПОДПИСКА")
            color: Theme.color.accent
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
            Layout.topMargin: Theme.space.sm
        }

        TribeCard {
            Layout.fillWidth: true
            implicitHeight: planCol.implicitHeight + 2 * Theme.space.lg
            ColumnLayout {
                id: planCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Tribe Trial"); color: Theme.color.text1
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
                    }
                    TribeBadge { variant: "warn"; text: qsTr("Пробный") }
                }
                // traffic
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Трафик"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text { text: "1.8 / 5 ГБ"; color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData }
                }
                Rectangle {
                    Layout.fillWidth: true; height: 6; radius: 3; color: Theme.color.surface3
                    Rectangle { width: parent.width * 0.36; height: parent.height; radius: 3; color: Theme.color.accent }
                }
                // devices
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Устройства"); color: Theme.color.text2; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; Layout.fillWidth: true }
                    Text { text: "1 / 1"; color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData }
                }
            }
        }

        TribeListRow {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.sm
            title: qsTr("About Tribe VPN")
            rightItem: Text { text: "›"; color: Theme.color.text3; font.pixelSize: Theme.font.h3; anchors.verticalCenter: parent.verticalCenter }
        }

        // neutral account-management note (NO steering — §10)
        Text {
            Layout.fillWidth: true
            text: qsTr("Управление аккаунтом — в личном кабинете")
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            wrapMode: Text.WordWrap
        }

        Item { Layout.fillHeight: true }

        // как «Обновить подключение» на главной: рамка + иконка + текст по центру
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 52
            Layout.bottomMargin: Theme.space.lg   // = отступу «Обновить подключение» на главной
            radius: Theme.radius.lg
            color: quitMa.containsMouse ? Qt.rgba(0x1E / 255, 0x29 / 255, 0x3B / 255, 0.5) : "transparent"
            border.width: 1
            border.color: quitMa.containsMouse ? Qt.rgba(0x7C / 255, 0xA2 / 255, 0xD0 / 255, 0.5)
                                               : Qt.rgba(0x33 / 255, 0x41 / 255, 0x55 / 255, 0.8)
            Behavior on color { ColorAnimation { duration: 160 } }
            Row {
                anchors.centerIn: parent
                spacing: 10
                // иконка power (lucide, 24-grid → 20px)
                Shape {
                    width: 20; height: 20; anchors.verticalCenter: parent.verticalCenter
                    transform: Scale { xScale: 20 / 24; yScale: 20 / 24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M12 3 V12 M18.4 6.6 a9 9 0 1 1 -12.77 0.04" }
                    }
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: qsTr("Закрыть приложение")
                    color: Theme.color.text1
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                }
            }
            MouseArea { id: quitMa; anchors.fill: parent; hoverEnabled: true
                cursorShape: Qt.PointingHandCursor; onClicked: Qt.quit() }
        }
    }
}

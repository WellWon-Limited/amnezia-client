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

    // мост в полный интерфейс Amnezia (vanilla PageSettings внутри tabBar-стека:
    // наша нижняя навигация остаётся видимой — вернуться можно любым табом)
    signal requestAmnezia()

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 8 + PageController.safeAreaTopMargin
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        TribeHeader {
            Layout.fillWidth: true; title: qsTr("Аккаунт")
            rightItem: Item {
                width: 36; height: 36
                visible: Dev.adminMode   // мост виден только в админ-режиме (щит на Connect)
                Image {
                    anchors.centerIn: parent
                    source: "qrc:/images/controls/amnezia.svg"
                    sourceSize: Qt.size(26, 26)
                    opacity: amneziaMa.containsMouse ? 1.0 : 0.65
                }
                MouseArea {
                    id: amneziaMa
                    anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.requestAmnezia()
                }
            }
        }

        // account card
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
                    text: qsTr("Пробный доступ")
                    color: Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
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

        // neutral account-management note (NO steering — §10)
        Text {
            Layout.fillWidth: true
            text: qsTr("Управление аккаунтом — в личном кабинете")
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            wrapMode: Text.WordWrap
        }

        Item { Layout.fillHeight: true }

        TribeButton {
            Layout.fillWidth: true
            variant: "glass"
            text: qsTr("Выйти")
        }
        TribeButton {
            Layout.fillWidth: true
            variant: "ghost"
            text: qsTr("Удалить аккаунт")
            Layout.bottomMargin: Theme.space.sm
        }
    }
}

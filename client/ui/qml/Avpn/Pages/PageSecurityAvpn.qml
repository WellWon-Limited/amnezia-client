import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: «Анти-VPN» (вкладка nav) — обход VPN для РФ-ресурсов (порт функционала NeVPN).
// P-U2 мок на статичных данных; реальный движок (роутинг/пресеты с GitHub) — P-U6.
PageType {
    id: root

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // подпись секции: «ЗАГОЛОВОК · N» + опц. ссылка справа
    component SectionLabel: RowLayout {
        property string text: ""
        property string linkText: ""
        spacing: Theme.space.md
        Text {
            Layout.fillWidth: true
            text: parent.text
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
        }
        Text {
            visible: parent.linkText !== ""
            text: parent.linkText
            color: Theme.color.accent
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
        }
    }

    // иконка-чип (32×32) с вектором внутри (сабпасы — одной SVG-строкой через "M…")
    component IconChip: Rectangle {
        id: chip
        property string path: ""
        width: 32; height: 32; radius: Theme.radius.sm
        color: Theme.color.surface2
        Shape {
            anchors.centerIn: parent
            width: 18; height: 18
            transform: Scale { xScale: 18 / 24; yScale: 18 / 24 }
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: Theme.color.text2; fillColor: "transparent"; strokeWidth: 1.7
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: chip.path }
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 8 + PageController.safeAreaTopMargin
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        TribeHeader { Layout.fillWidth: true; title: qsTr("Анти-VPN") }

        Flickable {
            id: flick
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentHeight: content.height + Theme.space.xl
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Column {
                id: content
                width: parent.width
                spacing: Theme.space.md

                // ── мастер-тоггл ───────────────────────────────────────────
                Rectangle {
                    width: parent.width
                    height: 76
                    radius: Theme.radius.lg
                    color: Theme.color.surface1
                    border.width: 1; border.color: Theme.color.border
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.lg
                        anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md
                        // флаг РФ (круглый, как флаги серверов)
                        Rectangle {
                            Layout.preferredWidth: 44; Layout.preferredHeight: 44
                            radius: 22
                            color: Qt.rgba(0x0F / 255, 0x17 / 255, 0x2A / 255, 0.8)
                            border.width: 1; border.color: Qt.rgba(0x33 / 255, 0x41 / 255, 0x55 / 255, 0.5)
                            Item {
                                anchors.centerIn: parent; width: 28; height: 28
                                layer.enabled: true
                                layer.effect: Fx.OpacityMask { maskSource: Rectangle { width: 28; height: 28; radius: 14 } }
                                Column {
                                    anchors.fill: parent
                                    Rectangle { width: parent.width; height: parent.height / 3; color: "#EEF2F7" }
                                    Rectangle { width: parent.width; height: parent.height / 3; color: "#3A5BA0" }
                                    Rectangle { width: parent.width; height: parent.height / 3; color: "#B8434E" }
                                }
                            }
                        }
                        Column {
                            Layout.fillWidth: true
                            spacing: 2
                            Text {
                                text: qsTr("Доступ к сайтам РФ")
                                color: Theme.color.text1
                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                                font.weight: Theme.font.wSemibold
                            }
                            Text {
                                text: qsTr("напрямую, мимо VPN-туннеля")
                                color: Theme.color.text3
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            }
                        }
                        TribeToggle { checked: true }
                    }
                }

                // ── свои исключения ────────────────────────────────────────
                SectionLabel { width: parent.width; text: qsTr("СВОИ ИСКЛЮЧЕНИЯ") }

                RowLayout {
                    width: parent.width
                    spacing: Theme.space.sm
                    TribeField {
                        Layout.fillWidth: true
                        placeholderText: qsTr("Сайт, IP или подсеть 17.0.0.0/8…")
                    }
                    Rectangle {
                        Layout.preferredWidth: 46; Layout.preferredHeight: 46
                        radius: Theme.radius.sm
                        color: addMa.containsMouse ? Theme.color.accentBright : Theme.color.accent
                        Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                        Shape {
                            anchors.centerIn: parent
                            width: 18; height: 18
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2
                                capStyle: ShapePath.RoundCap
                                PathSvg { path: "M9 2 V16 M2 9 H16" }
                            }
                        }
                        MouseArea { id: addMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor }
                    }
                }

                // пользовательские записи (мок)
                Repeater {
                    model: [
                        { host: "wellwon.app", letter: "W" },
                        { host: "www.rusprofile.ru", letter: "R" }
                    ]
                    Rectangle {
                        required property var modelData
                        width: content.width
                        height: 56
                        radius: Theme.radius.md
                        color: Theme.color.surface1
                        border.width: 1; border.color: Theme.color.border
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.space.lg
                            anchors.rightMargin: Theme.space.lg
                            spacing: Theme.space.md
                            Rectangle { Layout.preferredWidth: 7; Layout.preferredHeight: 7; radius: 3.5; color: Theme.color.connected }
                            Rectangle {
                                Layout.preferredWidth: 28; Layout.preferredHeight: 28
                                radius: Theme.radius.sm; color: Theme.color.surface2
                                Text {
                                    anchors.centerIn: parent
                                    text: parent.parent.parent.modelData.letter
                                    color: Theme.color.text2
                                    font.family: Theme.font.display; font.pixelSize: Theme.font.caption; font.weight: Theme.font.wBold
                                }
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData.host
                                color: Theme.color.text1
                                font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                                elide: Text.ElideRight
                            }
                            // удалить (lucide trash)
                            Item {
                                Layout.preferredWidth: 28; Layout.preferredHeight: 28
                                Shape {
                                    anchors.centerIn: parent
                                    width: 17; height: 17
                                    transform: Scale { xScale: 17 / 24; yScale: 17 / 24 }
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        strokeColor: delMa.containsMouse ? Theme.color.danger : Theme.color.text3
                                        fillColor: "transparent"; strokeWidth: 1.7
                                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                        PathSvg { path: "M3 6 H21 M19 6 V20 a2 2 0 0 1 -2 2 H7 a2 2 0 0 1 -2 -2 V6 M8 6 V4 a2 2 0 0 1 2 -2 h4 a2 2 0 0 1 2 2 v2 M10 11 v6 M14 11 v6" }
                                    }
                                }
                                MouseArea { id: delMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor }
                            }
                            TribeToggle { checked: true }
                        }
                    }
                }

                // ── пресеты (с GitHub) ─────────────────────────────────────
                Repeater {
                    model: [
                        { name: qsTr("МАРКЕТПЛЕЙСЫ"), icon: "M6 2 L3 6 V20 a2 2 0 0 0 2 2 H19 a2 2 0 0 0 2 -2 V6 L18 2 Z M3 6 H21 M16 10 a4 4 0 0 1 -8 0",
                          items: ["Wildberries", "Ozon", "Avito", "Lamoda", "Яндекс Маркет", "Мегамаркет"] },
                        { name: qsTr("СОЦСЕТИ"), icon: "M9 11 a4 4 0 1 0 0 -8 4 4 0 0 0 0 8 z M17 21 v-2 a4 4 0 0 0 -4 -4 H5 a4 4 0 0 0 -4 4 v2 M16 3.1 a4 4 0 0 1 0 7.8 M23 21 v-2 a4 4 0 0 0 -3 -3.9",
                          items: ["ВКонтакте", "Одноклассники"] },
                        { name: qsTr("БАНКИ"), icon: "M12 3 L3 8.5 H21 Z M5 11 V18 M9.5 11 V18 M14.5 11 V18 M19 11 V18 M3 21 H21",
                          items: ["Сбербанк", "Альфа-Банк", "ВТБ", "Газпромбанк", "Т-Банк", "МКБ"] }
                    ]
                    Column {
                        id: presetSection
                        required property var modelData
                        width: content.width
                        spacing: Theme.space.md
                        SectionLabel {
                            width: parent.width
                            text: presetSection.modelData.name + " · " + presetSection.modelData.items.length
                            linkText: qsTr("всё вкл")
                        }
                        Rectangle {
                            width: parent.width
                            height: presetCol.height
                            radius: Theme.radius.lg
                            color: Theme.color.surface1
                            border.width: 1; border.color: Theme.color.border
                            Column {
                                id: presetCol
                                width: parent.width
                                Repeater {
                                    model: presetSection.modelData.items
                                    Item {
                                        required property string modelData
                                        required property int index
                                        width: presetCol.width; height: 54
                                        Rectangle {
                                            visible: index > 0
                                            anchors.top: parent.top
                                            anchors.left: parent.left; anchors.right: parent.right
                                            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                            height: 1; color: Theme.color.border
                                        }
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: Theme.space.lg
                                            anchors.rightMargin: Theme.space.lg
                                            spacing: Theme.space.md
                                            IconChip { path: presetSection.modelData.icon }
                                            Text {
                                                Layout.fillWidth: true
                                                text: modelData
                                                color: Theme.color.text1
                                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                                            }
                                            TribeToggle { checked: true }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ── конфигурация ───────────────────────────────────────────
                SectionLabel { width: parent.width; text: qsTr("КОНФИГУРАЦИЯ") }

                Rectangle {
                    width: parent.width
                    height: cfgCol.height
                    radius: Theme.radius.lg
                    color: Theme.color.surface1
                    border.width: 1; border.color: Theme.color.border
                    Column {
                        id: cfgCol
                        width: parent.width

                        // авто-обновление пресетов
                        Item {
                            width: parent.width; height: 62
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                spacing: Theme.space.md
                                IconChip { path: "M21 15 v4 a2 2 0 0 1 -2 2 H5 a2 2 0 0 1 -2 -2 v-4 M7 10 L12 15 L17 10 M12 15 V3" }
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text { text: qsTr("Обновлять списки"); color: Theme.color.text1; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium }
                                    Text { text: qsTr("пресеты с GitHub раз в сутки"); color: Theme.color.text3; font.family: Theme.font.body; font.pixelSize: Theme.font.caption }
                                }
                                TribeToggle { checked: true }
                            }
                        }

                        Rectangle { width: parent.width - 2 * Theme.space.lg; height: 1; color: Theme.color.border; anchors.horizontalCenter: parent.horizontalCenter }

                        // конфиг пресетов
                        Item {
                            width: parent.width; height: 62
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                spacing: Theme.space.md
                                IconChip { path: "M20 11 a8.1 8.1 0 0 0 -15.5 -2 M4 5 v4 h4 M4 13 a8.1 8.1 0 0 0 15.5 2 M20 19 v-4 h-4" }
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text { text: qsTr("Конфиг пресетов"); color: Theme.color.text1; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium }
                                    Text { text: qsTr("обновлён 2 ч назад"); color: Theme.color.text3; font.family: Theme.font.body; font.pixelSize: Theme.font.caption }
                                }
                                Rectangle {
                                    Layout.preferredWidth: updText.width + 2 * Theme.space.lg
                                    Layout.preferredHeight: 34
                                    radius: Theme.radius.pill
                                    color: updMa.containsMouse ? Theme.color.surface2 : "transparent"
                                    border.width: 1; border.color: Theme.color.border2
                                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                                    Text {
                                        id: updText
                                        anchors.centerIn: parent
                                        text: qsTr("Обновить")
                                        color: Theme.color.text1
                                        font.family: Theme.font.body; font.pixelSize: Theme.font.caption; font.weight: Theme.font.wSemibold
                                    }
                                    MouseArea { id: updMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor }
                                }
                            }
                        }

                        Rectangle { width: parent.width - 2 * Theme.space.lg; height: 1; color: Theme.color.border; anchors.horizontalCenter: parent.horizontalCenter }

                        // системная служба
                        Item {
                            width: parent.width; height: 62
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                spacing: Theme.space.md
                                IconChip { path: "M4 2 h16 a2 2 0 0 1 2 2 v4 a2 2 0 0 1 -2 2 H4 a2 2 0 0 1 -2 -2 V4 a2 2 0 0 1 2 -2 Z M4 14 h16 a2 2 0 0 1 2 2 v4 a2 2 0 0 1 -2 2 H4 a2 2 0 0 1 -2 -2 v-4 a2 2 0 0 1 2 -2 Z M6 6 h0.01 M6 18 h0.01" }
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text { text: qsTr("Системная служба"); color: Theme.color.text1; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium }
                                    Text { text: qsTr("применяет маршруты обхода"); color: Theme.color.text3; font.family: Theme.font.body; font.pixelSize: Theme.font.caption }
                                }
                                TribeBadge { variant: "on"; text: qsTr("активна") }
                            }
                        }
                    }
                }
            }
        }
    }
}

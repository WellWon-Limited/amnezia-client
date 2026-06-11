import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType
import "../data/presets.js" as Presets   // реальный конфиг NeVPN (см. data/presets.js)

// AVPN: «Анти-VPN» (вкладка nav) — обход VPN для РФ-ресурсов (порт функционала NeVPN).
// P-U2 мок на статичных данных; реальный движок (роутинг/пресеты с GitHub) — P-U6.
PageType {
    id: root

    // реальный конфиг пресетов NeVPN (тот же, что тянется с GitHub:
    // wellwon/anti-vpn-config/presets.json). Схема: categories[key,title,services[id,title,domains,prefixes]]
    readonly property var presetCategories: Presets.config.categories
    readonly property int presetsVersion: Presets.config.version
    readonly property int presetsServiceCount: {
        var n = 0
        for (var i = 0; i < Presets.config.categories.length; i++)
            n += Presets.config.categories[i].services.length
        return n
    }

    // иконки категорий по key (24-grid lucide, сабпасы одной строкой)
    readonly property var categoryIcons: ({
        market: "M6 2 L3 6 V20 a2 2 0 0 0 2 2 H19 a2 2 0 0 0 2 -2 V6 L18 2 Z M3 6 H21 M16 10 a4 4 0 0 1 -8 0",
        social: "M9 11 a4 4 0 1 0 0 -8 4 4 0 0 0 0 8 z M17 21 v-2 a4 4 0 0 0 -4 -4 H5 a4 4 0 0 0 -4 4 v2 M16 3.1 a4 4 0 0 1 0 7.8 M23 21 v-2 a4 4 0 0 0 -3 -3.9",
        bank: "M12 3 L3 8.5 H21 Z M5 11 V18 M9.5 11 V18 M14.5 11 V18 M19 11 V18 M3 21 H21",
        media: "M4 7 h16 a2 2 0 0 1 2 2 v9 a2 2 0 0 1 -2 2 H4 a2 2 0 0 1 -2 -2 V9 a2 2 0 0 1 2 -2 Z M8 3 L12 7 L16 3",
        gov: "M4 21 V5 a2 2 0 0 1 2 -2 h12 a2 2 0 0 1 2 2 v16 M9 8 h1 M14 8 h1 M9 12 h1 M14 12 h1 M9 16 h1 M14 16 h1 M3 21 H21",
        ved: "M21 16 V8 a2 2 0 0 0 -1 -1.73 l-7 -4 a2 2 0 0 0 -2 0 l-7 4 A2 2 0 0 0 3 8 v8 a2 2 0 0 0 1 1.73 l7 4 a2 2 0 0 0 2 0 l7 -4 A2 2 0 0 0 21 16 Z M3.3 7 L12 12 L20.7 7 M12 22 V12",
        wechat: "M21 11.5 a8.38 8.38 0 0 1 -.9 3.8 8.5 8.5 0 0 1 -7.6 4.7 8.38 8.38 0 0 1 -3.8 -.9 L3 21 l1.9 -5.7 a8.38 8.38 0 0 1 -.9 -3.8 8.5 8.5 0 0 1 4.7 -7.6 8.38 8.38 0 0 1 3.8 -.9 h.5 a8.48 8.48 0 0 1 8 8 v.5 z"
    })
    readonly property string fallbackIcon: "M12 21 a9 9 0 1 0 -0.01 0 z M3.6 9 H20.4 M3.6 15 H20.4 M12 3 a15 15 0 0 1 0 18 M12 3 a15 15 0 0 0 0 18"

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

                // ── пресеты (реальный конфиг, все категории) ───────────────
                Repeater {
                    model: root.presetCategories
                    Column {
                        id: presetSection
                        required property var modelData
                        width: content.width
                        spacing: Theme.space.md
                        SectionLabel {
                            width: parent.width
                            text: presetSection.modelData.title.toUpperCase() + " · " + presetSection.modelData.services.length
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
                                    model: presetSection.modelData.services
                                    Item {
                                        required property var modelData
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
                                            IconChip { path: root.categoryIcons[presetSection.modelData.key] || root.fallbackIcon }
                                            Column {
                                                Layout.fillWidth: true
                                                spacing: 1
                                                Text {
                                                    text: modelData.title
                                                    color: Theme.color.text1
                                                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                                                }
                                                Text {
                                                    text: (modelData.domains ? modelData.domains.length : 0)
                                                          + qsTr(" доменов")
                                                          + (modelData.prefixes && modelData.prefixes.length
                                                             ? " · " + modelData.prefixes.length + qsTr(" подсетей") : "")
                                                    color: Theme.color.text3
                                                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                                }
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
                                    Text {
                                        text: qsTr("версия %1 · %2 сервисов").arg(root.presetsVersion).arg(root.presetsServiceCount)
                                        color: Theme.color.text3; font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                    }
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

                    }
                }
            }
        }
    }
}

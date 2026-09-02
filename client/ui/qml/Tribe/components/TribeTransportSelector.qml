pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import ".."   // Theme

// AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): ручной выбор РЕЖИМА транспорта —
// «Авто / Amnezia / Xray». Компонент выражает только НАМЕРЕНИЕ пользователя (сигнал
// modeRequested); авторитет — движок: он может отклонить режим, для которого нет
// поднимаемого транспорта (тост придёт из фасада). Хранение режима — тоже в движке
// (QSettings avpn/transportMode), компонент состояния не держит.
Rectangle {
    id: root

    property string mode: "auto"          // auto | awg | xray (факт из движка)
    property bool awgAvailable: true
    property bool xrayAvailable: true
    // «Авто» доступно, пока есть хоть один транспорт: движок сам решит, какой поднять.
    readonly property bool autoAvailable: awgAvailable || xrayAvailable
    property bool interactive: true
    // Причина недоступности одна на оба конца (сервер не выдал транспорт ИЛИ клиент его не умеет) —
    // текст не гадает, какая сторона; подробности видны в Докторе.
    property string unavailableReason: qsTr("Этот режим сейчас недоступен")

    signal modeRequested(string mode)

    implicitHeight: 44
    implicitWidth: 320
    radius: Theme.radius.md
    color: Theme.color.surface1
    border.width: 1
    border.color: Theme.color.border

    readonly property var options: [
        { key: "auto", label: qsTr("Авто") },
        { key: "awg", label: qsTr("Amnezia") },
        { key: "xray", label: qsTr("Xray") }
    ]

    function optionAvailable(key) {
        if (key === "awg")
            return root.awgAvailable
        if (key === "xray")
            return root.xrayAvailable
        return root.autoAvailable
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 3
        spacing: 3

        Repeater {
            model: root.options

            delegate: AbstractButton {
                id: segment
                required property var modelData
                readonly property bool selected: root.mode === segment.modelData.key
                readonly property bool available: root.optionAvailable(segment.modelData.key)

                Layout.fillWidth: true
                Layout.fillHeight: true
                opacity: segment.available ? 1.0 : 0.48
                enabled: root.interactive
                focusPolicy: Qt.StrongFocus
                hoverEnabled: true

                Accessible.role: Accessible.RadioButton
                Accessible.name: segment.modelData.label
                Accessible.checked: segment.selected

                onClicked: {
                    if (!segment.available) {
                        if (typeof PageController !== "undefined")
                            PageController.showNotificationMessage(root.unavailableReason)
                        return
                    }
                    if (segment.selected)
                        return
                    Haptic.play("selection")
                    root.modeRequested(segment.modelData.key)
                }

                background: Rectangle {
                    radius: Theme.radius.sm
                    color: segment.selected ? Theme.color.chipSelected
                                            : (segment.hovered ? Theme.color.glass : "transparent")
                    border.width: segment.selected || segment.activeFocus ? 1 : 0
                    border.color: segment.activeFocus ? Theme.color.text1
                                                      : (segment.selected ? Theme.color.accent
                                                                          : "transparent")
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }
                }

                contentItem: Text {
                    text: segment.modelData.label
                    textFormat: Text.PlainText
                    elide: Text.ElideRight
                    color: segment.selected ? Theme.color.text1 : Theme.color.text2
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                    font.weight: segment.selected ? Theme.font.wBold : Theme.font.wSemibold
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }
}

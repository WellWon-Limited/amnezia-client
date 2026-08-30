pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import ".." // Theme

// Protocol-neutral connection preference. This component only emits user intent;
// the coordinator remains the authority and may reject a mode that has no compatible runtime.
Rectangle {
    id: root

    property string mode: "auto" // auto | awg | xray
    property bool awgAvailable: true
    property bool xrayAvailable: true
    // Availability of Auto is a coordinator decision. It may legitimately have
    // only one compatible candidate after capability/health filtering.
    property bool autoAvailable: awgAvailable || xrayAvailable
    property bool interactive: true
    // Keep the product label version-neutral. Exact audited core/config versions are shown in
    // Doctor from the runtime manifest, so a server-side compatible profile update cannot make
    // this selector stale or force a store release just to change copy.
    property string awgLabel: qsTr("AWG")
    property string xrayLabel: qsTr("Xray")
    readonly property string groupLabel: qsTr("Режим соединения")
    // Global availability is the intersection of signed server supply and local engine/runtime
    // capability, so the default copy must not guess which side made the mode unavailable.
    readonly property string deviceUnavailableReason: qsTr("Этот режим сейчас недоступен")
    property string unavailableReason: deviceUnavailableReason

    signal modeRequested(string mode)

    implicitHeight: 44
    implicitWidth: 320
    radius: Theme.radius.md
    color: Theme.color.surface1
    border.width: 1
    border.color: Theme.color.border

    readonly property var options: [
        { key: "auto", label: qsTr("Авто") },
        { key: "awg", label: root.awgLabel },
        { key: "xray", label: root.xrayLabel }
    ]

    function optionAvailable(key) {
        if (key === "awg") return root.awgAvailable
        if (key === "xray") return root.xrayAvailable
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
                readonly property bool selected: root.mode === modelData.key
                readonly property bool available: root.optionAvailable(modelData.key)

                Layout.fillWidth: true
                Layout.fillHeight: true
                opacity: available ? 1.0 : 0.48
                enabled: root.interactive
                focusPolicy: Qt.StrongFocus
                hoverEnabled: true

                Accessible.role: Accessible.RadioButton
                Accessible.name: modelData.label
                Accessible.description: available ? root.groupLabel
                                                  : root.unavailableReason
                Accessible.checked: selected

                onClicked: {
                    if (!available) {
                        if (typeof PageController !== "undefined")
                            PageController.showNotificationMessage(root.unavailableReason)
                        return
                    }
                    if (!selected) {
                        Haptic.play("selection")
                        root.modeRequested(modelData.key)
                    }
                }

                background: Rectangle {
                    radius: Theme.radius.sm
                    color: segment.selected ? Theme.color.chipSelected
                                            : (segment.hovered ? Theme.color.glass : "transparent")
                    border.width: segment.selected || segment.activeFocus ? 1 : 0
                    border.color: segment.activeFocus ? Theme.color.text1
                                                      : (segment.selected ? Theme.color.accent
                                                                          : "transparent")

                    Behavior on color {
                        ColorAnimation { duration: Theme.motion.fast }
                    }
                    Behavior on border.color {
                        ColorAnimation { duration: Theme.motion.fast }
                    }
                }

                contentItem: Text {
                    text: segment.modelData.label
                    textFormat: Text.PlainText
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

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Style 1.0

import "TextTypes"
import "../Config"
import "../Avpn"   // AVPN: Theme (тёмная тема Tribe для глобальных попапов)

Popup {
    id: root

    property string text
    property bool closeButtonVisible: true

    leftMargin: 25
    rightMargin: 25
    bottomMargin: 70 + PageController.safeAreaBottomMargin

    width: parent.width - leftMargin - rightMargin

    anchors.centerIn: parent
    modal: root.closeButtonVisible
    closePolicy: Popup.CloseOnEscape

    Overlay.modal: Rectangle {
        visible: root.closeButtonVisible
        color: AmneziaStyle.color.translucentMidnightBlack
    }

    onOpened: {
        timer.start()
    }

    onClosed: {
        FocusController.dropRootObject(root)
    }

    background: Rectangle {
        anchors.fill: parent

        color: Theme.color.surface1            // AVPN: было "white"
        radius: Theme.radius.lg
        border.width: 1
        border.color: Theme.color.border
    }

    Timer {
        id: timer
        interval: 200 // Milliseconds
        onTriggered: {
            FocusController.pushRootObject(root)
            FocusController.setFocusItem(closeButton)
        }
        repeat: false // Stop the timer after one trigger
        running: true // Start the timer
    }

    contentItem: Item {
        implicitWidth: content.implicitWidth
        implicitHeight: content.implicitHeight

        anchors.fill: parent

        RowLayout {
            id: content

            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16

            CaptionTextType {
                horizontalAlignment: Text.AlignLeft
                Layout.fillWidth: true

                color: Theme.color.text1               // AVPN: светлый текст на тёмном попапе

                onLinkActivated: function(link) {
                    Qt.openUrlExternally(LanguageUiController.getCurrentDocsUrl(link))
                }

                text: root.text

                MouseArea {
                    anchors.fill: parent
                    acceptedButtons: Qt.NoButton
                    cursorShape: parent.hoveredLink ? Qt.PointingHandCursor : Qt.ArrowCursor
                }
            }

            BasicButtonType {
                id: closeButton
                visible: closeButtonVisible

                implicitHeight: 32

                // AVPN: тёмная glass-кнопка вместо белой
                defaultColor: Theme.color.glassStrong
                hoveredColor: Theme.color.surface2
                pressedColor: Theme.color.surface3
                disabledColor: Theme.color.surface1

                textColor: Theme.color.text1
                borderWidth: 1
                borderColor: Theme.color.border2

                text: qsTr("Close")

                clickedFunc: function() {
                    root.close()
                }
            }
        }
    }
}

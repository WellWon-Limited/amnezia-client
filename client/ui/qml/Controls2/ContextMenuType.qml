import QtQuick
import QtQuick.Controls

Menu {
    property var textObj

    popupType: Popup.Native

    property Item inputBlocker: null

    Component {
        id: inputBlockerComponent

        MouseArea {
            anchors.fill: parent
            preventStealing: true
        }
    }

    onAboutToShow: {
        if (!textObj || !textObj.window) {
            return
        }

        const contentItem = textObj.window.contentItem
        if (!inputBlocker) {
            inputBlocker = inputBlockerComponent.createObject(contentItem)
        } else {
            inputBlocker.parent = contentItem
        }
    }

    onClosed: {
        if (inputBlocker) {
            inputBlocker.destroy()
            inputBlocker = null
        }
    }

    MenuItem {
        text: qsTr("C&ut")
        enabled: textObj.selectedText
        onTriggered: textObj.cut()
    }
    MenuItem {
        text: qsTr("&Copy")
        enabled: textObj.selectedText
        onTriggered: textObj.copy()
    }
    MenuItem {
        text: qsTr("&Paste")
        // Fix calling paste from clipboard when launching app on android
        // AVPN: на iOS canPaste читает UIPasteboard (mimeData->text) → системный промпт
        // «вставить из macOS» без действия пользователя; включаем без проверки, как на Android
        enabled: (Qt.platform.os === "android" || Qt.platform.os === "ios") ? true : textObj.canPaste
        onTriggered: textObj.paste()
    }

    MenuItem {
        text: qsTr("&SelectAll")
        enabled: textObj.length > 0
        onTriggered: textObj.selectAll()
    }
}

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
    // AVPN: пункт «Вставить» УБРАН по требованию пользователя — на iOS любое чтение буфера обмена
    // (canPaste/paste) вызывает системный промпт «Разрешить вставку», который раздражал. Без пункта
    // меню буфер не читается → промпт не появляется. (Если когда-то понадобится вставка ключа без
    // промпта — отдельная нативная кнопка UIPasteControl, а не пункт меню.)

    MenuItem {
        text: qsTr("&SelectAll")
        enabled: textObj.length > 0
        onTriggered: textObj.selectAll()
    }
}

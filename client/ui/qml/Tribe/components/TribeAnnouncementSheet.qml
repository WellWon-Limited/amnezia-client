import QtQuick
import QtQuick.Layouts

import ".."   // Theme

// AVPN (объявления P-ANN): полноэкранный попап ВАЖНОГО server-driven объявления поверх главного
// экрана: заголовок + markdown-текст + опциональная картинка + кнопки из JSON админки + всегда
// прикнопленная «Прочитал» (только она и кнопки-действия гасят объявление навсегда; «Позже» —
// вернётся при следующем запуске). Контент настраивается в админке — новые объявления НЕ требуют
// обновления приложения; кнопка с неизвестным action не рисуется (forward-compat).
// Back-логика — дровер (incrementDrawerDepth/closeTopDrawer, паттерн TribeResultSheet):
// аппаратный Back/Escape закрывает попап, а не страницу.
Item {
    id: sheet
    anchors.fill: parent
    visible: opened
    z: 220

    property bool opened: false
    property var  ann: null      // {id, kind, title, body, image_url, buttons:[{id,label,action,value}]}
    property int  depthIndex: 0
    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    readonly property var  knownActions: ["url", "weblink", "screen", "later"]

    // weblink/screen исполняет страница-хозяин (у неё гард ctaLinking и сигналы навигации).
    signal weblinkRequested(string value)
    signal screenRequested(string name)

    function show(a) {
        if (!a || opened)
            return
        ann = a
        opened = true
        depthIndex = PageController.incrementDrawerDepth()
        if (hasEngine)
            TribeEngine.ackAnnouncement(a.id, "shown", "")   // дедуп за сессию — в движке
    }
    function close() {
        if (!opened)
            return
        opened = false
        depthIndex = 0
        PageController.decrementDrawerDepth()
    }
    function markRead() {
        if (hasEngine && ann)
            TribeEngine.ackAnnouncement(ann.id, "read", "")
        close()
    }
    function handleButton(btn) {
        if (!ann)
            return
        if (hasEngine)
            TribeEngine.ackAnnouncement(ann.id, "clicked", btn.id || "")
        if (btn.action === "later") {   // отложить: НЕ read — попап вернётся
            close()
            return
        }
        if (hasEngine)
            TribeEngine.ackAnnouncement(ann.id, "read", "")  // кнопка-действие = прочитано
        if (btn.action === "url" && btn.value)
            Qt.openUrlExternally(btn.value)
        else if (btn.action === "weblink")
            sheet.weblinkRequested(btn.value || "")
        else if (btn.action === "screen")
            sheet.screenRequested(btn.value || "")
        close()
    }

    Connections {
        target: PageController
        enabled: sheet.opened
        function onCloseTopDrawer() {
            if (sheet.depthIndex === PageController.getDrawerDepth())
                sheet.close()   // системный «назад» = «Позже»: без read, вернётся при перезапуске
        }
    }

    // Страница может быть уничтожена (replace при смене вкладки) с открытым попапом — без
    // компенсации drawerDepth Back/Escape ломаются во всём приложении (см. TribeResultSheet).
    Component.onDestruction: {
        if (opened)
            PageController.decrementDrawerDepth()
    }

    Rectangle { anchors.fill: parent; color: Qt.alpha(Theme.color.bg800, 0.88) }
    MouseArea { anchors.fill: parent }   // важное сообщение: тап мимо карточки НЕ закрывает

    Rectangle {
        id: card
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.xl
        height: Math.min(content.implicitHeight + 2 * Theme.space.xl,
                         parent.height - 2 * Theme.space.xxl
                         - PageController.safeAreaTopMargin - PageController.safeAreaBottomMargin)
        radius: Theme.radius.xl
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.border2

        ColumnLayout {
            id: content
            anchors.fill: parent
            anchors.margins: Theme.space.xl
            spacing: Theme.space.md

            Text {
                Layout.fillWidth: true
                text: sheet.ann ? (sheet.ann.title || "") : ""
                color: Theme.color.text1
                wrapMode: Text.WordWrap
                font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wBold
            }

            Flickable {
                id: bodyFlick
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: Math.min(bodyCol.implicitHeight, 120)
                contentWidth: width
                contentHeight: bodyCol.implicitHeight
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                ColumnLayout {
                    id: bodyCol
                    width: bodyFlick.width
                    spacing: Theme.space.md

                    Image {
                        Layout.fillWidth: true
                        Layout.preferredHeight: status === Image.Ready
                                                ? width * (implicitHeight / Math.max(1, implicitWidth)) : 0
                        visible: status === Image.Ready   // ошибка/нет URL → секции нет
                        source: (sheet.ann && sheet.ann.image_url) ? sheet.ann.image_url : ""
                        asynchronous: true
                        fillMode: Image.PreserveAspectFit
                        sourceSize.width: 1024
                    }

                    Text {
                        Layout.fillWidth: true
                        text: sheet.ann ? (sheet.ann.body || "") : ""
                        color: Theme.color.text2
                        wrapMode: Text.WordWrap
                        textFormat: Text.MarkdownText
                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                        lineHeight: 1.25
                        onLinkActivated: function(link) { Qt.openUrlExternally(link) }
                    }
                }
            }

            Repeater {
                model: (sheet.ann && sheet.ann.buttons) ? sheet.ann.buttons : []
                delegate: TribeButton {
                    required property var modelData
                    required property int index
                    Layout.fillWidth: true
                    visible: sheet.knownActions.indexOf(modelData.action) !== -1
                    variant: index === 0 ? "primary" : "glass"
                    glow: false
                    text: modelData.label || ""
                    onClicked: sheet.handleButton(modelData)
                }
            }

            TribeButton {
                Layout.fillWidth: true
                variant: "ghost"
                text: qsTr("Прочитал")
                onClicked: sheet.markRead()
            }
        }
    }
}

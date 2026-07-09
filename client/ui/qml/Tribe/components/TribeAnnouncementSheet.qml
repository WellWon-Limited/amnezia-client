import QtQuick
import QtQuick.Layouts
import Qt5Compat.GraphicalEffects as Fx   // OpacityMask: скругление баннера (clip режет прямоугольником)

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
    // viaController=true — закрытие по Back/Escape: pageController декрементит depth САМ после
    // emit closeTopDrawer — второй декремент оставил бы нижний оверлей (при наложении) с depth=0.
    function close(viaController) {
        if (!opened)
            return
        opened = false
        depthIndex = 0
        if (!viaController)
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
                sheet.close(true)   // системный «назад» = «Позже»: без read, вернётся при перезапуске
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

    // Карточка почти во весь экран (от верха до низа страницы, нижняя навигация остаётся
    // видимой под страницей) — контент «дышит», кнопки прижаты к низу карточки.
    Rectangle {
        id: card
        anchors.fill: parent
        anchors.leftMargin: Theme.space.lg
        anchors.rightMargin: Theme.space.lg
        anchors.topMargin: PageController.safeAreaTopMargin + Theme.space.lg
        anchors.bottomMargin: PageController.safeAreaBottomMargin + Theme.space.lg
        radius: Theme.radius.xl
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.border2

        ColumnLayout {
            id: content
            anchors.fill: parent
            anchors.margins: Theme.space.lg
            spacing: Theme.space.md

            Text {
                Layout.fillWidth: true
                text: sheet.ann ? (sheet.ann.title || "") : ""
                color: Theme.color.text1
                wrapMode: Text.WordWrap
                font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
            }

            Flickable {
                id: bodyFlick
                Layout.fillWidth: true
                Layout.fillHeight: true
                contentWidth: width
                contentHeight: bodyCol.implicitHeight
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                ColumnLayout {
                    id: bodyCol
                    width: bodyFlick.width
                    spacing: Theme.space.md

                    // Картинка-баннер: кроп под ширину карточки, скругление — OpacityMask
                    // (QML clip режет прямоугольником, radius на клип не действует).
                    Item {
                        Layout.fillWidth: true
                        Layout.preferredHeight: banner.status === Image.Ready
                                                ? Math.round(width * 0.46) : 0
                        visible: banner.status === Image.Ready   // ошибка/нет URL → секции нет

                        Image {
                            id: banner
                            anchors.fill: parent
                            source: (sheet.ann && sheet.ann.image_url) ? sheet.ann.image_url : ""
                            asynchronous: true
                            fillMode: Image.PreserveAspectCrop
                            sourceSize.width: 1024
                            visible: false   // рисует OpacityMask
                        }
                        Rectangle {
                            id: bannerMask
                            anchors.fill: parent
                            radius: Theme.radius.md
                            visible: false
                        }
                        Fx.OpacityMask {
                            anchors.fill: parent
                            source: banner
                            maskSource: bannerMask
                        }
                    }

                    Text {
                        Layout.fillWidth: true
                        text: sheet.ann ? (sheet.ann.body || "") : ""
                        color: Theme.color.text2
                        wrapMode: Text.WordWrap
                        textFormat: Text.MarkdownText
                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                        lineHeight: 1.35
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

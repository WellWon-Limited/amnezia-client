import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Qt5Compat.GraphicalEffects as Fx   // OpacityMask: скругление баннера (clip режет прямоугольником)

import ".."   // Theme

// AVPN (рассылки P-ANN): полноэкранный попап ВАЖНОГО server-driven объявления поверх
// ЛЮБОГО экрана (хост — PageStart, живёт всегда). Контент настраивается в админке —
// новые рассылки НЕ требуют обновления приложения.
//
// Два режима:
//  - v2 (ann.slides непуст): карусель слайдов из блоков (hero/feature/iconrow/image/
//    text/footer; неизвестный type пропускается) + точки-пейджер + «Далее»; на последнем
//    слайде — кнопки из админки + «Прочитал» (без кнопок «Прочитал» = большая primary CTA);
//  - legacy (без slides): заголовок + markdown + опциональная картинка + кнопки.
//
// Закрыть попап можно ТОЛЬКО кнопками самого уведомления (реш. 2026-07-10): системный
// «назад»/Escape ПРОГЛАТЫВАЕТСЯ (см. onCloseTopDrawer — компенсация декремента), тап мимо
// карточки не закрывает. Кнопка с неизвестным action не рисуется (forward-compat).
Item {
    id: sheet
    anchors.fill: parent
    visible: opened
    z: 220

    property bool opened: false
    property var  ann: null      // {id, kind, title, body, image_url, buttons:[...], slides:[{blocks:[...]}]}
    property int  depthIndex: 0
    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    readonly property var  knownActions: ["url", "weblink", "screen", "later"]

    // v2: валидные слайды (объект с непустым blocks); пусто → legacy-рендер title/body.
    readonly property var richSlides: {
        if (!ann || !ann.slides) return []
        var out = []
        for (var i = 0; i < ann.slides.length; ++i) {
            var s = ann.slides[i]
            if (s && s.blocks && s.blocks.length)
                out.push(s)
        }
        return out
    }
    readonly property bool rich: richSlides.length > 0

    // weblink/screen исполняет хост (у него гард ссылки и роутер вкладок).
    signal weblinkRequested(string value)
    signal screenRequested(string name)

    function show(a) {
        if (!a || opened)
            return
        ann = a
        opened = true
        if (slideView.count > 0)
            slideView.setCurrentIndex(0)
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
        if (btn.action === "later") {   // отложить: НЕ read — попап вернётся при перезапуске
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

    // Иконка iconrow: "app:<ключ>" → вшитый бренд-SVG (Tribe/images), http(s) → как есть,
    // прочее/неизвестный бренд → пусто (плитка не рисуется).
    function iconSource(ref) {
        var s = String(ref || "")
        if (s.indexOf("app:") === 0) {
            var key = s.substring(4)
            var known = ["whatsapp", "telegram", "youtube", "claude", "gemini", "kinopoisk"]
            if (known.indexOf(key) !== -1)
                return "../images/brand-" + key + ".svg"
            if (key === "gosuslugi")
                return "../images/brand-gosuslugi.png"
            return ""
        }
        if (s.indexOf("http") === 0)
            return s
        return ""
    }

    // Системный «назад»/Escape НЕ закрывает попап: pageController после emit сам делает
    // decrement — компенсируем инкрементом, глубина и попап остаются как были. Закрытие —
    // только кнопками уведомления (у пользователя всегда есть «Прочитал»/«Далее»).
    Connections {
        target: PageController
        enabled: sheet.opened
        function onCloseTopDrawer() {
            if (sheet.depthIndex === PageController.getDrawerDepth())
                PageController.incrementDrawerDepth()
        }
    }

    // Хост (PageStart) живёт всегда, но страховка от уничтожения с открытым попапом
    // остаётся — иначе Back/Escape сломаются во всём приложении (см. TribeResultSheet).
    Component.onDestruction: {
        if (opened)
            PageController.decrementDrawerDepth()
    }

    Rectangle { anchors.fill: parent; color: Qt.alpha(Theme.color.bg800, 0.88) }
    MouseArea { anchors.fill: parent }   // важное сообщение: тап мимо карточки НЕ закрывает

    // Карточка почти во весь экран — контент «дышит», кнопки прижаты к низу карточки.
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

            // ---- legacy-режим: title + баннер + markdown ------------------------------
            Text {
                Layout.fillWidth: true
                visible: !sheet.rich
                text: sheet.ann ? (sheet.ann.title || "") : ""
                color: Theme.color.text1
                wrapMode: Text.WordWrap
                font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
            }

            Flickable {
                id: bodyFlick
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: !sheet.rich
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
                            source: (!sheet.rich && sheet.ann && sheet.ann.image_url) ? sheet.ann.image_url : ""
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

            // ---- v2-режим: карусель слайдов из блоков ---------------------------------
            SwipeView {
                id: slideView
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: sheet.rich
                clip: true
                interactive: sheet.richSlides.length > 1

                Repeater {
                    model: sheet.rich ? sheet.richSlides : []
                    delegate: Flickable {
                        required property var modelData
                        contentWidth: width
                        contentHeight: slideCol.implicitHeight
                        clip: true
                        boundsBehavior: Flickable.StopAtBounds

                        ColumnLayout {
                            id: slideCol
                            width: parent.width
                            spacing: Theme.space.md

                            Repeater {
                                model: modelData.blocks
                                delegate: Loader {
                                    required property var modelData
                                    readonly property var b: modelData
                                    Layout.fillWidth: true
                                    // неизвестный type → пустой Loader (блок из будущего)
                                    sourceComponent: b.type === "hero" ? heroBlock
                                                   : b.type === "feature" ? featureBlock
                                                   : b.type === "iconrow" ? iconrowBlock
                                                   : b.type === "image" ? imageBlock
                                                   : b.type === "text" ? textBlock
                                                   : b.type === "footer" ? footerBlock
                                                   : null
                                }
                            }
                        }
                    }
                }
            }

            // Точки-пейджер (паттерн PageOnboardingTribe): активная — «пилюля».
            Row {
                Layout.alignment: Qt.AlignHCenter
                visible: sheet.rich && sheet.richSlides.length > 1
                spacing: 7
                Repeater {
                    model: sheet.richSlides.length
                    Rectangle {
                        required property int index
                        width: slideView.currentIndex === index ? 24 : 8
                        height: 8
                        radius: Theme.radius.pill
                        color: slideView.currentIndex === index ? Theme.color.accent : Theme.color.surface3
                        Behavior on width { NumberAnimation { duration: Theme.motion.fast } }
                        Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                        TapHandler { onTapped: slideView.setCurrentIndex(parent.index) }
                    }
                }
            }

            // «Далее» между слайдами (v2, не последний слайд)
            TribeButton {
                Layout.fillWidth: true
                visible: sheet.rich && slideView.currentIndex < sheet.richSlides.length - 1
                variant: "primary"
                glow: false
                text: qsTr("Далее")
                onClicked: slideView.incrementCurrentIndex()
            }

            // Кнопки из админки — legacy всегда, v2 только на последнем слайде.
            Repeater {
                model: (sheet.ann && sheet.ann.buttons) ? sheet.ann.buttons : []
                delegate: TribeButton {
                    required property var modelData
                    required property int index
                    Layout.fillWidth: true
                    visible: (!sheet.rich || slideView.currentIndex === sheet.richSlides.length - 1)
                             && sheet.knownActions.indexOf(modelData.action) !== -1
                    variant: index === 0 ? "primary" : "glass"
                    glow: false
                    text: modelData.label || ""
                    onClicked: sheet.handleButton(modelData)
                }
            }

            // «Прочитал»: без кнопок админки в v2 — большая primary CTA (как в макете).
            TribeButton {
                Layout.fillWidth: true
                visible: !sheet.rich || slideView.currentIndex === sheet.richSlides.length - 1
                variant: (sheet.rich && (!sheet.ann || !(sheet.ann.buttons || []).length)) ? "primary" : "ghost"
                glow: false
                text: qsTr("Прочитал")
                onClicked: sheet.markRead()
            }
        }
    }

    // ---- блоки v2 (контекстное свойство b приходит из Loader'а) -------------------
    Component {
        id: heroBlock
        ColumnLayout {
            spacing: Theme.space.sm
            Text {
                Layout.fillWidth: true
                text: b.title || ""
                color: Theme.color.text1
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wExtra
            }
            Text {
                Layout.fillWidth: true
                visible: !!(b.subtitle && String(b.subtitle).trim())
                text: b.subtitle || ""
                color: Theme.color.text2
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                lineHeight: 1.35
            }
        }
    }

    Component {
        id: featureBlock
        Rectangle {
            implicitHeight: featureRow.implicitHeight + 2 * Theme.space.md
            radius: Theme.radius.lg
            color: Theme.color.surface2
            border.width: 1
            border.color: Theme.color.border

            RowLayout {
                id: featureRow
                anchors.fill: parent
                anchors.margins: Theme.space.md
                spacing: Theme.space.md

                Rectangle {
                    Layout.preferredWidth: 38
                    Layout.preferredHeight: 38
                    Layout.alignment: Qt.AlignTop
                    radius: Theme.radius.md
                    color: Theme.color.surface3

                    TribeStrokeIcon {
                        anchors.centerIn: parent
                        width: 20; height: 20
                        visible: !b.icon_url
                        icon: b.icon || ""
                    }
                    Image {
                        anchors.fill: parent
                        anchors.margins: 6
                        visible: !!b.icon_url
                        source: b.icon_url ? sheet.iconSource(b.icon_url) : ""
                        asynchronous: true
                        fillMode: Image.PreserveAspectFit
                        sourceSize.width: 64
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text {
                        Layout.fillWidth: true
                        text: b.title || ""
                        color: Theme.color.text1
                        wrapMode: Text.WordWrap
                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM; font.weight: Theme.font.wBold
                    }
                    Text {
                        Layout.fillWidth: true
                        visible: !!(b.text && String(b.text).trim())
                        text: b.text || ""
                        color: Theme.color.text2
                        wrapMode: Text.WordWrap
                        font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                        lineHeight: 1.3
                    }
                }
            }
        }
    }

    Component {
        id: iconrowBlock
        ColumnLayout {
            spacing: Theme.space.sm
            Text {
                Layout.fillWidth: true
                visible: !!(b.label && String(b.label).trim())
                text: b.label || ""
                color: Theme.color.accent
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                font.family: Theme.font.body; font.pixelSize: 10; font.weight: Theme.font.wBold
                font.letterSpacing: Theme.font.trackCaption * 10
            }
            Row {
                Layout.alignment: Qt.AlignHCenter
                spacing: Theme.space.sm

                Repeater {
                    model: b.icons || []
                    delegate: Rectangle {
                        required property var modelData
                        readonly property string src: sheet.iconSource(modelData)
                        visible: src !== "" && tileImg.status !== Image.Error
                        width: 42; height: 42
                        radius: Theme.radius.md
                        color: Theme.color.surface2
                        border.width: 1
                        border.color: Theme.color.border

                        Image {
                            id: tileImg
                            anchors.fill: parent
                            anchors.margins: 7
                            source: parent.src
                            asynchronous: true
                            fillMode: Image.PreserveAspectFit
                            sourceSize.width: 96
                        }
                    }
                }
            }
        }
    }

    Component {
        id: imageBlock
        Item {
            implicitHeight: blockImg.status === Image.Ready
                            ? Math.round(width * 0.46) : 0
            visible: blockImg.status === Image.Ready   // битый URL → секции нет

            Image {
                id: blockImg
                anchors.fill: parent
                source: b.url || ""
                asynchronous: true
                fillMode: Image.PreserveAspectCrop
                sourceSize.width: 1024
                visible: false
            }
            Rectangle { id: blockImgMask; anchors.fill: parent; radius: Theme.radius.md; visible: false }
            Fx.OpacityMask { anchors.fill: parent; source: blockImg; maskSource: blockImgMask }
        }
    }

    Component {
        id: textBlock
        Text {
            text: b.markdown || ""
            color: Theme.color.text2
            wrapMode: Text.WordWrap
            textFormat: Text.MarkdownText
            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
            lineHeight: 1.35
            onLinkActivated: function(link) { Qt.openUrlExternally(link) }
        }
    }

    Component {
        id: footerBlock
        Text {
            text: b.markdown || ""
            color: Theme.color.text3
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            textFormat: Text.MarkdownText
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            lineHeight: 1.3
            onLinkActivated: function(link) { Qt.openUrlExternally(link) }
        }
    }
}

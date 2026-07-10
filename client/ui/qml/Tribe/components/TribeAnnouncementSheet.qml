import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Qt5Compat.GraphicalEffects as Fx   // OpacityMask: скругление баннера (clip режет прямоугольником)

import ".."   // Theme

// AVPN (рассылки P-ANN): попап ВАЖНОГО server-driven объявления поверх ЛЮБОГО экрана
// (хост — PageStart, живёт всегда). Контент настраивается в админке — новые рассылки
// НЕ требуют обновления приложения.
//
// Два режима (референс — «Tribe VPN рассылка.html», приёмка 2026-07-10):
//  - v2 (ann.slides непуст): карусель слайдов из блоков (hero/feature/iconrow/image/
//    text/footer; неизвестный type пропускается) во весь экран + лого-строка + точки +
//    «Далее»; на последнем слайде — кнопки из админки + «Прочитал» (без кнопок —
//    «Прочитал» = большая primary CTA);
//  - legacy (без slides): ПЛАВАЮЩАЯ карточка ПО ВЫСОТЕ КОНТЕНТА — шапка-свечение с
//    бренд-барами, чип «ОБЪЯВЛЕНИЕ», крестик (закрыть-отложить), заголовок, текст,
//    опциональная картинка, кнопки сразу под текстом.
//
// Закрыть попап можно ТОЛЬКО элементами самого уведомления («Прочитал»/кнопки/крестик):
// системный «назад»/Escape ПРОГЛАТЫВАЕТСЯ (см. onCloseTopDrawer — компенсация
// декремента), тап мимо карточки не закрывает. Крестик и «назад»-семантика НЕ ставят
// read — попап вернётся при следующем запуске. Кнопка с неизвестным action не рисуется.
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

    // v2: валидные слайды (объект с непустым blocks); пусто → legacy-карточка title/body.
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

    // Типографика — В ПРОПОРЦИЯХ референса «Tribe VPN рассылка.html» (приёмка 2026-07-10):
    // размеры считаются от фактической ширины, а не фикс-токенами, чтобы попап выглядел
    // как макет на любом экране. kl — legacy-макет (окно 985px), ks — слайды (телефон 500px).
    readonly property real kl: Math.max(0.36, width / 985)
    readonly property real ks: Math.max(0.6, (width - 2 * Theme.space.lg) / 440)

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
    // только элементами уведомления (всегда есть «Прочитал»/«Далее»/крестик).
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

    // ════════════════════════════════ v2: карусель во весь экран ════════════════════
    Rectangle {
        id: richCard
        visible: sheet.rich
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
            anchors.fill: parent
            anchors.margins: Theme.space.lg
            spacing: Theme.space.md

            // Лого-строка (как в макете: бренд на каждом слайде)
            Row {
                Layout.alignment: Qt.AlignHCenter
                spacing: 10

                Row {
                    id: richBrandMark
                    anchors.bottom: richBrandText.baseline
                    spacing: 2
                    Rectangle { width: 3; height: 7;  radius: 1.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
                    Rectangle { width: 3; height: 12; radius: 1.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
                    Rectangle { width: 3; height: 16; radius: 1.5; color: Theme.color.accent; anchors.bottom: parent.bottom }
                    Rectangle { width: 3; height: 12; radius: 1.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
                    Rectangle { width: 3; height: 8;  radius: 1.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
                }
                Text {
                    id: richBrandText
                    text: "Tribe VPN"
                    color: Theme.color.text1
                    font.family: Theme.font.display
                    font.pixelSize: Math.round(20 * sheet.ks)
                    font.weight: Theme.font.wExtra
                    font.letterSpacing: Theme.font.trackTight * font.pixelSize
                }
            }

            SwipeView {
                id: slideView
                Layout.fillWidth: true
                Layout.fillHeight: true
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
                visible: sheet.richSlides.length > 1
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

            // «Далее» между слайдами; на последнем — кнопки из админки + «Прочитал».
            TribeButton {
                Layout.fillWidth: true
                visible: slideView.currentIndex < sheet.richSlides.length - 1
                variant: "primary"
                glow: false
                text: qsTr("Далее")
                onClicked: slideView.incrementCurrentIndex()
            }
            Repeater {
                model: (sheet.ann && sheet.ann.buttons) ? sheet.ann.buttons : []
                delegate: TribeButton {
                    required property var modelData
                    required property int index
                    Layout.fillWidth: true
                    visible: slideView.currentIndex === sheet.richSlides.length - 1
                             && sheet.knownActions.indexOf(modelData.action) !== -1
                    variant: index === 0 ? "primary" : "glass"
                    glow: false
                    text: modelData.label || ""
                    onClicked: sheet.handleButton(modelData)
                }
            }
            TribeButton {
                Layout.fillWidth: true
                visible: slideView.currentIndex === sheet.richSlides.length - 1
                variant: (!sheet.ann || !(sheet.ann.buttons || []).length) ? "primary" : "ghost"
                glow: false
                text: qsTr("Прочитал")
                onClicked: sheet.markRead()
            }
        }
    }

    // ═══════════════════ legacy: плавающая карточка по высоте контента ═══════════════
    // Длинный текст: карточка упирается в maxH, КАРТИНКА УЖИМАЕТСЯ (до 24% ширины),
    // отдавая место тексту, текст скроллится ВНУТРИ, кнопки прижаты к низу и видимы всегда.
    Rectangle {
        id: legacyCard
        visible: !sheet.rich
        anchors.centerIn: parent
        width: Math.min(sheet.width - 2 * Theme.space.lg, 420)
        readonly property real maxH: sheet.height - PageController.safeAreaTopMargin
                                     - PageController.safeAreaBottomMargin - 2 * Theme.space.xl
        // Раскладка высоты: фикс-части (шапка/заголовок/кнопки) + картинка + текст.
        readonly property int imgFull: banner.status === Image.Ready
                                       ? Math.round((width - 2 * Theme.space.xl) * 0.46) : 0
        readonly property int imgMin: Math.round((width - 2 * Theme.space.xl) * 0.24)
        readonly property real fixedH: Math.round(440 * sheet.kl) + annTitle.implicitHeight
                                       + btnCol.implicitHeight + legacyCol.spacing * 4 + Theme.space.xl
        readonly property real availH: maxH - fixedH
        readonly property int bodyFull: Math.ceil(annBody.implicitHeight)
        readonly property int imgH: imgFull === 0 ? 0
                                  : (imgFull + bodyFull <= availH) ? imgFull
                                  : Math.max(imgMin, Math.min(imgFull, Math.floor(availH - bodyFull)))
        height: Math.min(maxH, fixedH + imgH + bodyFull)
        radius: Theme.radius.xl
        color: Theme.color.bg700
        border.width: 1
        border.color: Theme.color.border2
        clip: true

        ColumnLayout {
            id: legacyCol
            anchors.fill: parent
            spacing: Theme.space.md

            // Шапка: свечение + крупные бренд-бары; чип «ОБЪЯВЛЕНИЕ» и крестик поверх.
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: Math.round(440 * sheet.kl)

                Rectangle {
                    anchors.fill: parent
                    radius: Theme.radius.xl   // верх совпадает с карточкой; низ прозрачен
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: Qt.alpha(Theme.color.accentBright, 0.34) }
                        GradientStop { position: 1.0; color: "transparent" }
                    }
                }

                // Бренд-бары (пропорции макета; центральный — ярче)
                Row {
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.verticalCenterOffset: Math.round(14 * sheet.kl)
                    spacing: Math.round(17 * sheet.kl)
                    readonly property real bw: Math.round(17 * sheet.kl)
                    Rectangle { width: parent.bw; height: Math.round(96 * sheet.kl);  radius: width / 2; color: Qt.alpha(Theme.color.text1, 0.75); anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: parent.bw; height: Math.round(150 * sheet.kl); radius: width / 2; color: Qt.alpha(Theme.color.text1, 0.85); anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: parent.bw; height: Math.round(230 * sheet.kl); radius: width / 2; color: Theme.color.text1;                 anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: parent.bw; height: Math.round(172 * sheet.kl); radius: width / 2; color: Qt.alpha(Theme.color.text1, 0.9);  anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: parent.bw; height: Math.round(134 * sheet.kl); radius: width / 2; color: Qt.alpha(Theme.color.text1, 0.8);  anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: parent.bw; height: Math.round(160 * sheet.kl); radius: width / 2; color: Qt.alpha(Theme.color.text1, 0.85); anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: parent.bw; height: Math.round(110 * sheet.kl); radius: width / 2; color: Qt.alpha(Theme.color.text1, 0.7);  anchors.verticalCenter: parent.verticalCenter }
                }

                // Чип «ОБЪЯВЛЕНИЕ»
                Rectangle {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    anchors.margins: Theme.space.lg
                    width: chipRow.width + 2 * Theme.space.md
                    height: Math.round(64 * sheet.kl)
                    radius: Theme.radius.pill
                    color: Qt.alpha(Theme.color.bg800, 0.55)
                    border.width: 1
                    border.color: Theme.color.border2

                    Row {
                        id: chipRow
                        anchors.centerIn: parent
                        spacing: 7
                        Rectangle {
                            width: 6; height: 6; radius: 3
                            color: Theme.color.accent
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        Text {
                            text: qsTr("ОБЪЯВЛЕНИЕ")
                            color: Theme.color.text1
                            font.family: Theme.font.body
                            font.pixelSize: Math.max(9, Math.round(20 * sheet.kl))
                            font.weight: Theme.font.wBold
                            font.letterSpacing: Theme.font.trackCaption * font.pixelSize
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }
                }

                // Крестик: закрыть-отложить (НЕ read — попап вернётся при перезапуске)
                Rectangle {
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: Theme.space.lg
                    width: Math.max(32, Math.round(64 * sheet.kl)); height: width
                    radius: Theme.radius.pill
                    color: Qt.alpha(Theme.color.bg800, 0.55)
                    border.width: 1
                    border.color: Theme.color.border2

                    TribeStrokeIcon {
                        anchors.centerIn: parent
                        width: Math.round(parent.width * 0.44); height: width
                        icon: "x"
                        tint: Theme.color.text1
                    }
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: sheet.close()
                    }
                }
            }

            Text {
                id: annTitle
                Layout.fillWidth: true
                Layout.leftMargin: Theme.space.xl
                Layout.rightMargin: Theme.space.xl
                text: sheet.ann ? (sheet.ann.title || "") : ""
                color: Theme.color.text1
                wrapMode: Text.WordWrap
                lineHeight: 1.15
                font.family: Theme.font.display
                font.pixelSize: Math.max(19, Math.round(46 * sheet.kl))
                font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * font.pixelSize
            }

            // Картинка-баннер (опционально): высота адаптивная (legacyCard.imgH) —
            // при длинном тексте ужимается, отдавая место тексту. Скругление — OpacityMask.
            Item {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.space.xl
                Layout.rightMargin: Theme.space.xl
                Layout.preferredHeight: legacyCard.imgH
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
                Rectangle { id: bannerMask; anchors.fill: parent; radius: Theme.radius.md; visible: false }
                Fx.OpacityMask { anchors.fill: parent; source: banner; maskSource: bannerMask }
            }

            // Текст: скроллится ВНУТРИ, когда не влезает (кнопки при этом всегда видны).
            Flickable {
                id: bodyFlick
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.leftMargin: Theme.space.xl
                Layout.rightMargin: Theme.space.xl
                contentWidth: width
                contentHeight: legacyCard.bodyFull
                clip: true
                interactive: contentHeight > height
                boundsBehavior: Flickable.StopAtBounds

                Text {
                    id: annBody
                    width: bodyFlick.width
                    text: sheet.ann ? (sheet.ann.body || "") : ""
                    color: Theme.color.text2
                    wrapMode: Text.WordWrap
                    textFormat: Text.MarkdownText
                    font.family: Theme.font.body
                    font.pixelSize: Math.max(12, Math.round(27 * sheet.kl))
                    lineHeight: 1.5
                    onLinkActivated: function(link) { Qt.openUrlExternally(link) }
                }
            }

            // Кнопки — прижаты к низу карточки, видимы всегда (текст скроллится над ними).
            ColumnLayout {
                id: btnCol
                Layout.fillWidth: true
                Layout.leftMargin: Theme.space.xl
                Layout.rightMargin: Theme.space.xl
                Layout.bottomMargin: Theme.space.xl
                spacing: Theme.space.md

                Repeater {
                    model: (!sheet.rich && sheet.ann && sheet.ann.buttons) ? sheet.ann.buttons : []
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
                    variant: "glass"
                    glow: false
                    text: qsTr("Прочитал")
                    onClicked: sheet.markRead()
                }
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
                lineHeight: 1.12
                font.family: Theme.font.display
                font.pixelSize: Math.round(34 * sheet.ks)
                font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * font.pixelSize
            }
            Text {
                Layout.fillWidth: true
                visible: !!(b.subtitle && String(b.subtitle).trim())
                text: b.subtitle || ""
                color: Theme.color.text2
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                font.family: Theme.font.body
                font.pixelSize: Math.round(17 * sheet.ks)
                lineHeight: 1.4
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
                    Layout.preferredWidth: Math.round(52 * sheet.ks)
                    Layout.preferredHeight: Math.round(52 * sheet.ks)
                    Layout.alignment: Qt.AlignTop
                    radius: Theme.radius.md
                    color: Theme.color.surface3

                    TribeStrokeIcon {
                        anchors.centerIn: parent
                        width: Math.round(26 * sheet.ks); height: width
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
                        font.family: Theme.font.body
                        font.pixelSize: Math.round(17 * sheet.ks)
                        font.weight: Theme.font.wBold
                    }
                    Text {
                        Layout.fillWidth: true
                        visible: !!(b.text && String(b.text).trim())
                        text: b.text || ""
                        color: Theme.color.text2
                        wrapMode: Text.WordWrap
                        font.family: Theme.font.body
                        font.pixelSize: Math.round(14.5 * sheet.ks)
                        lineHeight: 1.35
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
                font.family: Theme.font.body
                font.pixelSize: Math.max(9, Math.round(12 * sheet.ks))
                font.weight: Theme.font.wBold
                font.letterSpacing: Theme.font.trackCaption * font.pixelSize
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
                        width: Math.round(58 * sheet.ks); height: width
                        radius: Theme.radius.md
                        color: Theme.color.surface2
                        border.width: 1
                        border.color: Theme.color.border

                        Image {
                            id: tileImg
                            anchors.fill: parent
                            anchors.margins: Math.round(10 * sheet.ks)
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
            font.family: Theme.font.body
            font.pixelSize: Math.round(16 * sheet.ks)
            lineHeight: 1.45
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
            font.family: Theme.font.body
            font.pixelSize: Math.max(9, Math.round(12 * sheet.ks))
            lineHeight: 1.35
            onLinkActivated: function(link) { Qt.openUrlExternally(link) }
        }
    }
}

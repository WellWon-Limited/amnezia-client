import QtQuick
import QtQuick.Controls   // TextArea/ScrollView (композер)
import QtQuick.Dialogs    // FileDialog (десктоп; iOS/Android — системные пикеры)
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: Поддержка — живой чат с оператором через TribeSupport (serviceEngine/TribeSupportChat:
// поллинг /v1/support/*, оптимистичные эхо, вложения фото/видео). Дизайн строго по Theme-токенам.
PageType {
    id: root

    // «назад» из шапки/свайпа → PageStart (onRequestTab) вернёт на Главную.
    signal requestTab(int index)
    signal requestDoctor()   // AVPN (Доктор v1): карточка run_diag / пункт меню «+» → попап (хост PageStart)

    // PageStart читает у текущей страницы: фокус в поле → навбар скрывается СРАЗУ,
    // до анимации клавиатуры (убирает двухфазный дёрг iOS, жалоба 2026-07-11).
    readonly property bool inputFocused: input.activeFocus

    // Клавиатура: простая схема — margin анимируется Behavior'ом в PageStart (цель приходит
    // из willShow). Экспериментальные GPU-сдвиги (transform композера + contentY-глу по
    // живому imeShift) ОТКАЧЕНЫ 2026-07-12: замирание трекера оставляло сдвиг залипшим
    // («медиа вверху, внизу пустота»), большие прыжки contentY гоняли делегаты через пул
    // (мигание медиа). На 120 Гц (CADisableMinimumFrameDurationOnPhone) + точечной модели
    // Behavior-анимация лайаута плавная — кадр рендерится за 2-3мс (замер QSG_RENDER_TIMING).

    // iOS: PageController.safeArea* только для Android → max с SafeArea (Qt 6.9+, реактивный инсет).
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    // dev-превью без движка (qml с диска) — страница живёт на пустой модели, не падает.
    readonly property bool hasChat: typeof TribeSupport !== "undefined"
    // ID аккаунта в шапке (тап = копия): оператору поддержки нужен для поиска юзера.
    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    // AVPN (diag, Task 5 bff-3): отправка диагностики доступна (kill-switch features.support_diag,
    // default TRUE). false → пункт меню скрыт, «+» открывает пикер напрямую (поведение как раньше).
    readonly property bool diagEnabled: root.hasChat && root.hasEngine
                                        && TribeEngine.supportDiagEnabled === true
    readonly property string accountId: hasEngine && TribeEngine.account
                                        ? ("" + (TribeEngine.account.account_id || "")) : ""

    // AVPN (store-flow): черновик, подставляемый в composer при открытии (кнопка «Написать в
    // поддержку» из Настроек передаёт его через goToTabBarPageUrl). ТОЛЬКО подстановка в поле —
    // отправляет пользователь сам (диалог инициирует клиент, не приложение).
    property string prefillDraft: ""

    // Открытая страница → частый поллинг треда + mark-read на бэке; ушли — только счётчик.
    Component.onCompleted: {
        if (root.hasChat) TribeSupport.active = true
        if (root.prefillDraft !== "") {
            input.text = root.prefillDraft
            input.cursorPosition = input.text.length
        }
    }
    Component.onDestruction: if (root.hasChat) TribeSupport.active = false

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    // скрытый носитель для копирования ID (паттерн форка)
    TextEdit { id: acctCopyEdit; width: 0; height: 0; opacity: 0; readOnly: true }

    function send() {
        var txt = input.text.trim()
        if (txt.length === 0 || !root.hasChat)
            return
        Haptic.play("light") // AVPN (haptics): подтверждение отправки
        TribeSupport.sendText(txt)
        input.clear()
        list.stick = true
        list.positionViewAtEnd()
    }

    // выбор медиа: iOS — нативный PHPicker (фотоплёнка); прочие платформы — FileDialog
    function pickMedia() {
        if (root.hasChat && TribeSupport.pickMediaNative())
            return
        mediaDialog.open()
    }

    // AVPN (diag, Task 5 bff-3): отправить диагностику в тред (вызов ТОЛЬКО из diagConfirm —
    // пользователь видел, что уйдёт). Kill-switch продублирован и в C++ (sendDiagReport no-op).
    function sendDiag() {
        if (!root.hasChat || !root.hasEngine)
            return
        Haptic.play("light")
        TribeSupport.sendDiagReport(TribeEngine.buildDiagReport())
        list.stick = true
        list.positionViewAtEnd()
    }

    Connections {
        target: root.hasChat ? TribeSupport : null
        function onSendFailed(reason) { PageController.showErrorMessage(reason) }
        function onAttachmentReady(attachmentId, kind, fileUrl) {
            if (kind === "image") {
                // открытый лайтбокс = долистали свайпом (оригинал доехал) — обновить кадр;
                // иначе — первое открытие по тапу
                if (lightbox.opened)
                    lightbox.arrived(attachmentId, fileUrl)
                else
                    lightbox.show(attachmentId, fileUrl)
                return
            }
            // видео: iOS — нативный QuickLook-плеер (Qt.openUrlExternally с file:// на iOS
            // молча ничего не делает — видео «не игралось»); прочие платформы — системный плеер.
            if (!TribeSupport.presentMediaNative(fileUrl))
                Qt.openUrlExternally(fileUrl)
        }
        function onAttachmentFailed(attachmentId) {
            PageController.showErrorMessage(qsTr("Не удалось загрузить вложение"))
        }
        // Позицию при обновлениях больше НЕ трогаем: лента на TribeSupport.msgModel
        // (точечные dataChanged/insertRows) — позиция скролла сохраняется сама, делегаты
        // не пересоздаются (мигание медиа/сброс позиции ушли вместе с QVariantList-моделью).
    }

    FileDialog {
        id: mediaDialog
        title: qsTr("Фото или видео")
        nameFilters: [ qsTr("Фото и видео") + " (*.jpg *.jpeg *.png *.webp *.gif *.heic *.heif *.mp4 *.mov *.webm)" ]
        onAccepted: if (root.hasChat) TribeSupport.sendAttachmentFile(selectedFile)
    }

    ColumnLayout {
        anchors.fill: parent
        // В рамке ТОЛЬКО инсет чёлки — воздух скроллится с лентой (topMargin ListView ниже),
        // иначе прокрутка обрезала сообщения ниже плашки (мёртвая полоса, 2026-07-10). // AVPN
        anchors.topMargin: root.safeTop
        spacing: 0

        // ── шапка чата (жалоба 2026-07-11): назад + заголовок + ID аккаунта (тап = копия) ──
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 52
            color: Theme.color.bg700
            // хайрлайн-низ — граница с лентой
            Rectangle { width: parent.width; height: 1; color: Theme.color.border; anchors.bottom: parent.bottom }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space.xs
                anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.xs

                // назад (chevron-left, 24-сетка) → Главная
                Item {
                    Layout.preferredWidth: 44; Layout.preferredHeight: 44
                    Layout.alignment: Qt.AlignVCenter
                    Shape {
                        anchors.centerIn: parent; width: 24; height: 24
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M14.5 6 L8.5 12 L14.5 18" }
                        }
                    }
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        // AVPN (haptics): «назад» тикает как смена вкладки
                        onClicked: { Haptic.play("selection"); root.requestTab(0) }
                    }
                }

                Column {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    spacing: 1
                    Text {
                        text: qsTr("Поддержка")
                        color: Theme.color.text1
                        font.family: Theme.font.display
                        font.pixelSize: Theme.font.bodyM
                        font.weight: Theme.font.wSemibold
                    }
                    Text {
                        text: qsTr("Отвечаем прямо в чате")
                        color: Theme.color.text3
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.caption
                    }
                }

                // ID аккаунта: подпись «ID» и под ней КОРОТКИЙ номер (первые 8 знаков);
                // тап — копия полного. ColumnLayout, НЕ Column с anchors (прошлая версия
                // давала наложение строк — жалоба 2026-07-11).
                ColumnLayout {
                    visible: root.accountId !== ""
                    Layout.alignment: Qt.AlignVCenter
                    spacing: 1
                    Text {
                        Layout.alignment: Qt.AlignRight
                        text: qsTr("ID")
                        color: Theme.color.text3
                        font.family: Theme.font.body
                        font.pixelSize: Theme.font.caption
                    }
                    Text {
                        Layout.alignment: Qt.AlignRight
                        text: root.accountId.substring(0, 8)
                        color: idTap.pressed ? Theme.color.accent : Theme.color.text2
                        font.family: Theme.font.mono
                        font.pixelSize: Theme.font.caption
                    }
                    TapHandler {
                        id: idTap
                        onTapped: {
                            acctCopyEdit.text = root.accountId
                            acctCopyEdit.selectAll(); acctCopyEdit.copy(); acctCopyEdit.deselect()
                            PageController.showNotificationMessage(qsTr("ID аккаунта скопирован"))
                        }
                    }
                }
            }
        }

        ListView {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            // верхний воздух — контент-инсет ListView (скроллится с лентой), не рамка:
            // рамочный Layout.topMargin оставлял мёртвую полосу при прокрутке. Нижний отступ
            // от дивайдера композера — footer, НЕ bottomMargin: positionViewAtEnd() игнорирует
            // bottomMargin (QTBUG) — последний пузырь прилипал к композеру (жалоба 2026-07-12). // AVPN
            topMargin: Theme.space.lg + Theme.space.sm
            footer: Item { width: 1; height: Theme.space.md }
            clip: true
            spacing: Theme.space.md
            // Точечная модель (msgModel): dataChanged/insertRows вместо полного пересоздания
            // делегатов на каждый поллинг/превью — скролл не слетает, медиа не мигают.
            // Старый бинарь в dev-превью без msgModel → фолбэк на QVariantList.
            // reuseItems НЕ включать: пул + layered MultiEffect/async Image = мигание медиа
            // при больших смещениях (клавиатура), жалоба 2026-07-12.
            model: root.hasChat ? (TribeSupport.msgModel || TribeSupport.messages) : []
            cacheBuffer: 4000

            // прижатие к низу: пока пользователь не ушёл в историю — держим конец
            property bool stick: true
            property real savedY: 0
            onMovementEnded: {
                stick = atYEnd
                savedY = contentY
            }
            // клавиатура прячется по тапу в ленту и при скролле (жалоба 2026-07-11:
            // «тап вне поля не убирает клавиатуру»). TapHandler работает параллельно
            // MouseArea делегатов — тапы по вложениям/кнопкам не ломает.
            onMovementStarted: input.focus = false
            TapHandler { onTapped: input.focus = false }

            delegate: ChatBubble {
                // model.* — роли TribeSupportMsgModel (msgId вместо id: голый id в QML
                // зарезервирован); с фолбэком QVariantList роли резолвятся так же.
                width: ListView.view ? ListView.view.width : 0
                text: model.body
                mine: model.sender === "client"
                time: Qt.formatTime(new Date(model.atMs), "HH:mm")
                operatorName: model.operatorName
                isAuto: model.isAuto
                pending: model.pending
                failed: model.failed
                attachments: model.attachments
                card: model.card
                onAttachmentClicked: function(attachmentId, kind) {
                    if (root.hasChat) TribeSupport.openAttachment(attachmentId)
                }
                // AVPN (store-flow D): действия server-driven карточки. open_url — внешний браузер
                // (персональная ссылка из ответа поддержки); compose_send — отправить заготовленный
                // сервером текст ОТ ИМЕНИ пользователя (тап = действие юзера; кнопка Т-3 карточки
                // «Помочь с продлением»); run_diag / send_diag (Доктор v1) — запустить полную
                // диагностику (тап по кнопке карточки = согласие; попап ведёт стадии и сам шлёт
                // отчёт в тред). При выключенном diag_v2 send_diag падает на легаси-конфирм
                // (только лог+снапшот). Неизвестный action — задизейбленная кнопка (ChatBubble).
                onCardButtonClicked: function(btn) {
                    if (!btn || !root.hasChat) return
                    if (btn.action === "open_url" && (btn.url || "") !== "")
                        Qt.openUrlExternally(btn.url)
                    else if (btn.action === "compose_send" && (btn.send || "") !== "") {
                        TribeSupport.sendText(btn.send)
                        list.stick = true
                        list.positionViewAtEnd()
                    } else if (btn.action === "run_diag" || btn.action === "send_diag") {
                        if (root.hasEngine && TribeEngine.featureEnabled("diag_v2", true))
                            root.requestDoctor()
                        else if (btn.action === "send_diag" && root.diagEnabled)
                            diagConfirm.open()
                        else
                            PageController.showErrorMessage(qsTr("Функция временно недоступна"))
                    }
                }
                onRetryClicked: if (root.hasChat) TribeSupport.retryMessage(model.msgId)
                onDiscardClicked: if (root.hasChat) TribeSupport.discardMessage(model.msgId)
            }
            onCountChanged: if (stick) positionViewAtEnd()
            // Сжатие/рост зоны при клавиатуре (Behavior-анимация margin): читатель у низа
            // едет с композером. Ре-пин: жест закрытия клавиатуры мог чуть сдвинуть ленту
            // (stick слетал — история оставалась «вверху», жалоба 2026-07-12) — около низа
            // прижимаем обратно.
            onHeightChanged: {
                const nearBottom = (contentHeight - height - contentY) < height * 0.5
                if (!stick && !nearBottom) return
                stick = true
                positionViewAtEnd()
            }
            Component.onCompleted: positionViewAtEnd()

            // пустой диалог — приглашение вместо тишины
            Column {
                visible: list.count === 0 && (!root.hasChat || !TribeSupport.loading)
                anchors.centerIn: parent
                spacing: Theme.space.md
                width: parent.width * 0.8
                Shape {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: 40; height: 40
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.7
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        // Tabler message-circle в сетке 24, масштаб через Shape 40 (scale ниже)
                        PathSvg { path: "M5 6 a13 9 0 0 1 14 0 a8 8 0 0 1 1 12 l1 4 l-4 -1 a13 9 0 0 1 -13 -1 a8 8 0 0 1 1 -14z" }
                    }
                    scale: 40 / 24; transformOrigin: Item.Center
                }
                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    text: qsTr("Напишите нам — ответим прямо здесь.\nМожно приложить фото или видео.")
                    wrapMode: Text.Wrap
                    color: Theme.color.text2
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                }
            }

            Text {
                visible: root.hasChat && TribeSupport.loading && list.count === 0
                anchors.centerIn: parent
                text: qsTr("Загружаем диалог…")
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyM
            }
        }

        // composer (редизайн 2026-06-18, Telegram-стиль): капсула с авто-растущим вверх TextArea +
        // кнопка «+» (вложение) слева и круглая кнопка отправки справа. Кнопки прижаты к низу
        // строки (Layout.alignment AlignBottom) — при росте капсулы остаются на месте. Без тёмной
        // подложки (цвет страницы bg800). Тёмное контекст-меню как в TribeField. // AVPN
        Rectangle {
            id: composer
            Layout.fillWidth: true
            color: Theme.color.bg800
            // строка composer + по md-отступу сверху/снизу. БЕЗ safe-area/IME-инсетов: без
            // клавиатуры зона вкладки кончается на верхе навбара (он несёт home-indicator в
            // bottomInset), а ПРИ клавиатуре навбар СКРЫТ и низ зоны = верх клавиатуры
            // (PageStart: bottomMargin = imeHeight, handoff Занавеса 2026-07-08) — композер
            // прижат к ней без зазора. Дублирование инсетов здесь давало лишние ~34px. // AVPN
            implicitHeight: composerRow.implicitHeight + 2 * Theme.space.md

            // хайрлайн-разделитель сверху
            Rectangle { width: parent.width; height: 1; color: Theme.color.border; anchors.top: parent.top }
            // прогресс аплоада вложения (0..1; −1 = не идёт) — тонкая полоса поверх хайрлайна.
            // Без неё отправка видео выглядела как «ничего не происходит» (жалоба 2026-07-11).
            Rectangle {
                visible: root.hasChat && TribeSupport.uploadProgress >= 0
                anchors.top: parent.top
                height: 2
                width: parent.width * Math.max(0.03, root.hasChat ? TribeSupport.uploadProgress : 0)
                color: Theme.color.accent
            }

            // реальные метрики шрифта поля — для ТОЧНОГО вертикального центрирования 1 строки. // AVPN
            FontMetrics { id: inputFm; font: input.font }

            RowLayout {
                id: composerRow
                anchors.left: parent.left; anchors.right: parent.right
                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                anchors.bottom: parent.bottom
                anchors.bottomMargin: Theme.space.md
                spacing: Theme.space.sm

                // «+» — прикрепить фото/видео (десктоп: FileDialog; iOS/Android: системный пикер)
                Rectangle {
                    id: attachBtn
                    Layout.preferredWidth: 44; Layout.preferredHeight: 44
                    Layout.alignment: Qt.AlignBottom
                    radius: height / 2
                    color: attachMa.pressed ? Theme.color.surface2 : Theme.color.surface1
                    border.width: 1
                    border.color: Theme.color.border
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Shape {
                        anchors.centerIn: parent; width: 24; height: 24
                        scale: 20 / 24; transformOrigin: Item.Center
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.text2
                            fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M12 5 L12 19 M5 12 L19 12" }
                        }
                    }
                    MouseArea {
                        id: attachMa
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        // AVPN (diag, Task 5 bff-3): с включённой диагностикой «+» открывает меню
                        // вложений (фото/видео ИЛИ диагностика); выключена — пикер напрямую.
                        onClicked: {
                            if (root.diagEnabled) {
                                input.focus = false
                                attachMenu.open()
                            } else {
                                root.pickMedia()
                            }
                        }
                    }
                }

                // авто-растущая капсула с полем ввода (растёт вверх, кнопка остаётся на месте)
                Rectangle {
                    id: capsule
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignBottom

                    readonly property int minH: 44
                    readonly property int maxH: 132
                    // растёт по контенту до капа; при превышении — внутренний скролл TextArea. // AVPN
                    Layout.preferredHeight: Math.max(minH, Math.min(maxH, input.implicitHeight))
                    Behavior on Layout.preferredHeight { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }
                    radius: Math.min(height / 2, Theme.radius.xl)   // 1 строка → пилюля; при росте → скруглённый прямоугольник
                    color: Theme.color.surface1
                    border.width: 1
                    border.color: input.activeFocus ? Theme.color.accent : Theme.color.border
                    Behavior on border.color { ColorAnimation { duration: Theme.motion.fast } }

                    ScrollView {
                        id: scroller
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.lg
                        anchors.rightMargin: Theme.space.lg
                        clip: true
                        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                        TextArea {
                            id: input
                            width: scroller.availableWidth
                            wrapMode: TextArea.Wrap
                            // вертикальное центрирование 1 строки в капсуле minH по РЕАЛЬНОЙ высоте
                            // шрифта (inputFm.height), а не по хардкоду 11px (он врал — строка bodyM ≠ 22). // AVPN
                            topPadding: Math.max(6, Math.round((capsule.minH - inputFm.height) / 2))
                            bottomPadding: topPadding
                            leftPadding: 0; rightPadding: 0
                            placeholderText: qsTr("Сообщение…")
                            color: Theme.color.text1
                            placeholderTextColor: Theme.color.text3
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyM
                            background: null
                            selectionColor: Theme.color.accent
                            // тёмное контекст-меню вместо нативного белого iOS-меню (паттерн форка) // AVPN
                            ContextMenu.menu: ContextMenuType { textObj: input }
                            // Enter = перенос строки (мультистрочный composer); отправка только кнопкой. // AVPN
                        }
                    }
                }

                // круглая кнопка отправки — СБОКУ, прижата к низу строки. Акцент при непустом вводе. // AVPN
                Rectangle {
                    id: sendBtn
                    Layout.preferredWidth: 44; Layout.preferredHeight: 44
                    Layout.alignment: Qt.AlignBottom
                    radius: height / 2
                    readonly property bool ready: input.text.trim().length > 0
                    color: ready ? Theme.color.accent : Theme.color.surface3
                    opacity: ready ? 1.0 : 0.6
                    scale: (sendMa.pressed && ready) ? 0.92 : 1.0
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    Behavior on opacity { NumberAnimation { duration: Theme.motion.fast } }
                    Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

                    // стрелка нарисована в сетке 24 (центр пути = 12,12). Шейп 24×24, масштаб к 20
                    // ВОКРУГ ЦЕНТРА (Item.scale + transformOrigin) — иначе 24-путь в 20-боксе уезжал
                    // вниз-вправо (центр контента 12 vs центр бокса 10). // AVPN
                    Shape {
                        anchors.centerIn: parent; width: 24; height: 24
                        scale: 20 / 24; transformOrigin: Item.Center
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            // в покое стрелка того же цвета, что «+» слева (text2) — единый вид
                            strokeColor: sendBtn.ready ? Theme.color.bg900 : Theme.color.text2
                            fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M5 12 L19 12 M13 6 L19 12 L13 18" }
                        }
                    }
                    MouseArea {
                        id: sendMa
                        anchors.fill: parent
                        enabled: sendBtn.ready
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.send()
                    }
                }
            }
        }
    }

    // «Готовим видео…» — плашка над композером, пока нативный пикер чистит GPS/пережимает/
    // делает постер (секунды БЕЗ иного фидбека — жалоба 2026-07-11). // AVPN
    Rectangle {
        visible: root.hasChat && TribeSupport.mediaPreparing
        anchors.bottom: composer.top
        anchors.bottomMargin: Theme.space.sm
        anchors.horizontalCenter: parent.horizontalCenter
        width: prepRow.implicitWidth + 2 * Theme.space.lg
        height: 34
        radius: Theme.radius.pill
        color: Theme.color.surface2
        border.width: 1; border.color: Theme.color.border
        Row {
            id: prepRow
            anchors.centerIn: parent
            spacing: Theme.space.sm
            BusyIndicator {
                width: 16; height: 16; running: parent.parent.visible
                anchors.verticalCenter: parent.verticalCenter
            }
            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: qsTr("Готовим медиа…")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
            }
        }
    }

    // свайп слева-направо = назад на Главную (жалоба 2026-07-11)
    TribeEdgeBack { onTriggered: root.requestTab(0) }

    // ── AVPN (diag, Task 5 bff-3): меню «+» — фото/видео или диагностика ────────────
    // Показывается ТОЛЬКО при diagEnabled (иначе «+» открывает пикер напрямую).
    // Участвует в back-логике как дровер (4-частный drawerDepth-контракт, паттерн DrawerType2).
    Item {
        id: attachMenu
        anchors.fill: parent
        visible: opened
        z: 110
        property bool opened: false
        property int depthIndex: 0
        function open() { opened = true; depthIndex = PageController.incrementDrawerDepth() }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            opened = false; depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }
        Connections {
            target: PageController
            enabled: attachMenu.opened
            function onCloseTopDrawer() {
                if (attachMenu.depthIndex === PageController.getDrawerDepth())
                    attachMenu.close(true)
            }
        }
        // смена вкладки (replace) с открытым меню → деструкция без close(): компенсируем depth
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        // свайп слева направо = закрыть (единый жест «назад», 2026-07-11)
        TribeEdgeBack { onTriggered: attachMenu.close() }

        Rectangle {
            anchors.fill: parent
            color: "#CC000000"
            MouseArea { anchors.fill: parent; onClicked: attachMenu.close() }
        }

        TribeCard {
            elevated: true
            width: parent.width - 2 * Theme.space.xl
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
            implicitHeight: attachMenuCol.implicitHeight + 2 * Theme.space.md
            MouseArea { anchors.fill: parent } // не закрывать при клике по карточке

            ColumnLayout {
                id: attachMenuCol
                anchors.fill: parent
                anchors.margins: Theme.space.md
                spacing: 2

                // пункт: фото или видео
                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 48
                    radius: Theme.radius.md
                    color: mediaItemMa.pressed ? Theme.color.surface2 : "transparent"
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.sm
                        anchors.rightMargin: Theme.space.sm
                        spacing: Theme.space.md
                        Shape {
                            Layout.preferredWidth: 24; Layout.preferredHeight: 24
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: Theme.color.text2; fillColor: "transparent"; strokeWidth: 1.7
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                // lucide image (24-сетка)
                                PathSvg { path: "M4 6 a2 2 0 0 1 2 -2 h12 a2 2 0 0 1 2 2 v12 a2 2 0 0 1 -2 2 h-12 a2 2 0 0 1 -2 -2z M4 16 l5 -5 4 4 3 -3 4 4 M9 9 a1 1 0 1 0 0 -.01" }
                            }
                        }
                        Text {
                            Layout.fillWidth: true
                            text: qsTr("Фото или видео")
                            color: Theme.color.text1
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyM
                        }
                    }
                    MouseArea {
                        id: mediaItemMa
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            attachMenu.close()
                            root.pickMedia()
                        }
                    }
                }

                // пункт: отправить диагностику (гейт diagEnabled — само меню открывается
                // только при нём, но visible держим на случай флипа флага при открытом меню)
                Rectangle {
                    Layout.fillWidth: true
                    visible: root.diagEnabled
                    implicitHeight: 48
                    radius: Theme.radius.md
                    color: diagItemMa.pressed ? Theme.color.surface2 : "transparent"
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.sm
                        anchors.rightMargin: Theme.space.sm
                        spacing: Theme.space.md
                        Shape {
                            Layout.preferredWidth: 24; Layout.preferredHeight: 24
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: Theme.color.text2; fillColor: "transparent"; strokeWidth: 1.7
                                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                // lucide file-text (24-сетка)
                                PathSvg { path: "M14 2 L6 2 a2 2 0 0 0 -2 2 L4 20 a2 2 0 0 0 2 2 L18 22 a2 2 0 0 0 2 -2 L20 8 Z M14 2 L14 8 L20 8 M16 13 L8 13 M16 17 L8 17" }
                            }
                        }
                        Text {
                            Layout.fillWidth: true
                            text: qsTr("Запустить диагностику")
                            color: Theme.color.text1
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyM
                        }
                    }
                    MouseArea {
                        id: diagItemMa
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            attachMenu.close()
                            // AVPN (Доктор v1): полная диагностика; при выключенном diag_v2 —
                            // легаси-путь (лог+снапшот через конфирм)
                            if (root.hasEngine && TribeEngine.featureEnabled("diag_v2", true))
                                root.requestDoctor()
                            else
                                diagConfirm.open()
                        }
                    }
                }
            }
        }
    }

    // ── AVPN (diag, Task 5 bff-3): подтверждение отправки диагностики ───────────────
    // Пользователь ЯВНО видит, что уйдёт в чат; без подтверждения ничего не отправляется.
    // Тот же 4-частный drawerDepth-контракт, что у attachMenu/seatSheet.
    Item {
        id: diagConfirm
        anchors.fill: parent
        visible: opened
        z: 120
        property bool opened: false
        property int depthIndex: 0
        function open() { opened = true; depthIndex = PageController.incrementDrawerDepth() }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            opened = false; depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }
        Connections {
            target: PageController
            enabled: diagConfirm.opened
            function onCloseTopDrawer() {
                if (diagConfirm.depthIndex === PageController.getDrawerDepth())
                    diagConfirm.close(true)
            }
        }
        // смена вкладки (replace) с открытым подтверждением → компенсируем depth
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        // свайп слева направо = закрыть (единый жест «назад», 2026-07-11)
        TribeEdgeBack { onTriggered: diagConfirm.close() }

        Rectangle {
            anchors.fill: parent
            color: "#CC000000"
            MouseArea { anchors.fill: parent; onClicked: diagConfirm.close() }
        }

        TribeCard {
            elevated: true
            width: parent.width - 2 * Theme.space.xl
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
            implicitHeight: diagCol.implicitHeight + 2 * Theme.space.lg
            MouseArea { anchors.fill: parent } // не закрывать при клике по карточке

            ColumnLayout {
                id: diagCol
                anchors.fill: parent
                anchors.margins: Theme.space.lg
                spacing: Theme.space.md

                Text {
                    text: qsTr("Запустить диагностику?")
                    color: Theme.color.text1
                    font.family: Theme.font.display
                    font.pixelSize: Theme.font.h3
                    font.weight: Theme.font.wBold
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    text: qsTr("В чат уйдут лог приложения и состояние подключения — без ключей и личных данных.")
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                TribeButton {
                    Layout.fillWidth: true
                    variant: "primary"
                    text: qsTr("Запустить")
                    onClicked: {
                        diagConfirm.close()
                        root.sendDiag()
                    }
                }
                TribeButton {
                    Layout.fillWidth: true
                    variant: "glass"
                    text: qsTr("Отмена")
                    onClicked: diagConfirm.close()
                }
            }
        }
    }

    // лайтбокс: фото на весь экран поверх страницы, закрытие тапом/Back/свайпом вниз.
    // Участвует в back-логике (паттерн DrawerType2, аудит 2026-07-09): раньше Back при открытом
    // фото уходил в escapePressed → closePage → hideWindow (сворачивал приложение).
    Rectangle {
        id: lightbox
        anchors.fill: parent
        visible: opened
        color: Qt.rgba(0, 0, 0, 0.92)
        z: 100
        property bool opened: false
        property int  depthIndex: 0
        // листание между фото треда (телеграм-жест, жалоба 2026-07-12):
        // упорядоченный список серверных фото-вложений [{id, thumb}] + текущий id
        property var  gallery: []
        property int  curId: 0

        function buildGallery() {
            var out = []
            var msgs = root.hasChat ? TribeSupport.messages : []
            for (var i = 0; i < msgs.length; ++i) {
                var atts = msgs[i].attachments || []
                for (var j = 0; j < atts.length; ++j) {
                    var a = atts[j]
                    if (a.kind === "image" && a.id > 0)
                        out.push({ id: a.id, thumb: (a.localUrl || a.thumbUrl || "") })
                }
            }
            return out
        }

        function show(attId, fileUrl) {
            gallery = buildGallery()
            curId = attId
            lightboxImage.source = fileUrl
            opened = true
            depthIndex = PageController.incrementDrawerDepth()
        }

        // свайп влево/вправо: dir +1 = следующее фото, −1 = предыдущее. Мгновенно
        // показываем превью (диск/кэш), оригинал подъедет через attachmentReady.
        function step(dir) {
            var idx = -1
            for (var i = 0; i < gallery.length; ++i)
                if (gallery[i].id === curId) { idx = i; break }
            if (idx < 0) return
            var next = idx + dir
            if (next < 0 || next >= gallery.length) return
            curId = gallery[next].id
            if (gallery[next].thumb !== "")
                lightboxImage.source = gallery[next].thumb
            TribeSupport.openAttachment(curId)
        }

        // оригинал доехал: применяем ТОЛЬКО если это всё ещё текущий кадр
        // (быстрое листание — стейл-загрузки прошлых кадров игнорируются)
        function arrived(attId, fileUrl) {
            if (attId === curId)
                lightboxImage.source = fileUrl
        }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened) return
            Haptic.play("selection") // AVPN (haptics): закрытие просмотра = «назад»
            opened = false
            depthIndex = 0
            lightboxImage.source = ""
            if (!viaController)
                PageController.decrementDrawerDepth()
        }

        Connections {
            target: PageController
            enabled: lightbox.opened
            function onCloseTopDrawer() {
                if (lightbox.depthIndex === PageController.getDrawerDepth())
                    lightbox.close(true)
            }
        }
        // смена вкладки (replace) с открытым фото → деструкция без close(): компенсируем depth
        Component.onDestruction: if (opened) PageController.decrementDrawerDepth()

        Image {
            id: lightboxImage
            anchors.fill: parent
            anchors.margins: Theme.space.md
            fillMode: Image.PreserveAspectFit
            asynchronous: true
            autoTransform: true   // EXIF-поворот локальных фото (иначе лежат на боку)
            // без sourceSize 10-МБ фото декодируется в полный размер (GPU-память);
            // 2× экрана хватает и для пинч-зума в будущем
            sourceSize.width: root.width * 2
        }
        // Жесты галереи ОДНОЙ MouseArea + preventStealing (2026-07-12): TapHandler/DragHandler
        // берут жест ПАССИВНО — событие проваливалось в ListView под лайтбоксом, и тот
        // отбирал его эксклюзивным грабом при первом движении (свайпы «не работали», как
        // ранее в TribeEdgeBack). preventStealing запрещает красть нажатие.
        MouseArea {
            anchors.fill: parent
            preventStealing: true
            property real sx: 0
            property real sy: 0
            onPressed: function(mouse) { sx = mouse.x; sy = mouse.y }
            onReleased: function(mouse) {
                var dx = mouse.x - sx
                var dy = mouse.y - sy
                if (Math.abs(dx) < 12 && Math.abs(dy) < 12)       // тап = закрыть
                    lightbox.close()
                else if (dy > 80 && dy > Math.abs(dx))             // свайп вниз = закрыть
                    lightbox.close()
                else if (Math.abs(dx) > 60)                        // вбок = листание фото
                    lightbox.step(dx < 0 ? 1 : -1)
            }
        }
    }
}

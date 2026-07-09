import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN: пузырь сообщения чата поддержки. mine=true → справа (accent), иначе слева (surface1).
// Ширина пузыря = по контенту, но не шире 78% доступной ширины (перенос внутри).
// Медиа: вложение (фото/видео) рендерится карточкой над текстом — превью приходит
// data:-URL из TribeSupport (thumbUrl), у неотправленного эха — file:// (localUrl).
// pending/failed — статусы оптимистичного эха (отправка… / повторить / убрать).
Item {
    id: bubble
    property string text: ""
    property bool mine: false
    property string time: ""
    property string operatorName: ""
    property bool isAuto: false
    property bool pending: false
    property bool failed: false
    // [{id, kind: "image"|"video", mime, name, width, height, thumbUrl, localUrl}]
    property var attachments: []
    // AVPN (store-flow D): server-driven карточка {title, body, buttons:[{label, action, url, send}]}.
    // Есть card → рендерим её ВМЕСТО текстового пузыря (text = фолбэк старых клиентов).
    // Генерик-рендерер: весь контент (тексты/кнопки/URL) приходит с сервера, обработка
    // действий — у страницы (cardButtonClicked).
    property var card: undefined
    readonly property bool hasCard: !!card && ((card.title || "") !== "" || (card.body || "") !== "")
    signal attachmentClicked(int attachmentId, string kind)
    signal cardButtonClicked(var button)
    signal retryClicked()
    signal discardClicked()

    readonly property real pad: Theme.space.md
    readonly property real mediaWidth: Math.min(bubble.width * 0.66, 280)
    implicitHeight: col.implicitHeight

    Column {
        id: col
        spacing: 3
        anchors.left: bubble.mine ? undefined : parent.left
        anchors.right: bubble.mine ? parent.right : undefined

        // имя оператора над входящим пузырём (у автоответа помечаем)
        Text {
            visible: !bubble.mine && bubble.operatorName !== ""
            anchors.left: parent.left
            text: bubble.isAuto ? qsTr("%1 · авто").arg(bubble.operatorName) : bubble.operatorName
            color: Theme.color.text3
            font.family: Theme.font.body
            font.pixelSize: 11
        }

        // медиа-карточки (у сообщения-вложения body пустой)
        Repeater {
            model: bubble.attachments
            delegate: Rectangle {
                id: mediaCard
                required property var modelData
                // localUrl — ВСЕГДА картинка (фото или локальный постер-кадр видео из
                // TribeMediaPicker; сам видеофайл сюда не попадает — движок кладёт в
                // localUrl только <видео>.poster.jpg). Локальное превью непрерывно с
                // момента отправки; серверный WebP-thumb — тихий апгрейд следом.
                readonly property string previewUrl: modelData.localUrl !== ""
                                                     ? modelData.localUrl : modelData.thumbUrl
                // серверные width/height превью → честный aspect-ratio без прыжков;
                // нет данных (эхо/постер ещё не готов) → 4:3.
                readonly property real ratio: (modelData.width > 0 && modelData.height > 0)
                                              ? modelData.height / modelData.width : 0.75
                anchors.left: bubble.mine ? undefined : parent.left
                anchors.right: bubble.mine ? parent.right : undefined
                width: bubble.mediaWidth
                height: Math.round(width * ratio)
                radius: Theme.radius.lg
                color: Theme.color.surface1
                border.width: bubble.mine ? 0 : 1
                border.color: Theme.color.border
                clip: true
                opacity: bubble.pending ? 0.55 : 1.0

                Image {
                    anchors.fill: parent
                    source: mediaCard.previewUrl
                    fillMode: Image.PreserveAspectCrop
                    asynchronous: true
                    sourceSize.width: 560
                    visible: mediaCard.previewUrl !== ""
                }

                // плейсхолдер, пока превью не приехало (или постер видео в постпроцессе)
                Shape {
                    visible: mediaCard.previewUrl === ""
                    anchors.centerIn: parent
                    width: 24; height: 24
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.7
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: modelData.kind === "video"
                                        ? "M4 6 a2 2 0 0 1 2 -2 h8 a2 2 0 0 1 2 2 v12 a2 2 0 0 1 -2 2 h-8 a2 2 0 0 1 -2 -2z M16 10 l5 -3 v10 l-5 -3"
                                        : "M4 6 a2 2 0 0 1 2 -2 h12 a2 2 0 0 1 2 2 v12 a2 2 0 0 1 -2 2 h-12 a2 2 0 0 1 -2 -2z M4 16 l5 -5 4 4 3 -3 4 4 M9 9 a1 1 0 1 0 0 -.01" }
                    }
                }

                // видео: затемнение + треугольник play поверх постера
                Rectangle {
                    visible: modelData.kind === "video"
                    anchors.centerIn: parent
                    width: 44; height: 44; radius: 22
                    color: Qt.rgba(0, 0, 0, 0.45)
                    Shape {
                        anchors.centerIn: parent
                        width: 18; height: 18
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: "transparent"
                            fillColor: Theme.color.text1
                            PathSvg { path: "M6 4 L15 9 L6 14 Z" }
                        }
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    enabled: modelData.id > 0 && !bubble.pending  // эхо (id<0) ещё не открыть
                    cursorShape: Qt.PointingHandCursor
                    onClicked: bubble.attachmentClicked(modelData.id, modelData.kind)
                }
            }
        }

        // AVPN (store-flow D): server-driven карточка — рамка surface1 с заголовком/текстом и
        // кнопками во всю ширину. Первая кнопка primary (главное действие), остальные glass.
        Rectangle {
            id: cardBox
            visible: bubble.hasCard
            anchors.left: bubble.mine ? undefined : parent.left
            anchors.right: bubble.mine ? parent.right : undefined
            width: Math.min(bubble.width * 0.78, 320)
            implicitHeight: cardCol.implicitHeight + 2 * bubble.pad
            radius: Theme.radius.lg
            color: Theme.color.surface1
            border.width: 1
            border.color: Theme.color.border

            Column {
                id: cardCol
                x: bubble.pad
                y: bubble.pad
                width: cardBox.width - 2 * bubble.pad
                spacing: Theme.space.sm

                Text {
                    visible: bubble.hasCard && (bubble.card.title || "") !== ""
                    width: parent.width
                    text: bubble.hasCard ? (bubble.card.title || "") : ""
                    wrapMode: Text.Wrap
                    color: Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wMedium
                }
                Text {
                    visible: bubble.hasCard && (bubble.card.body || "") !== ""
                    width: parent.width
                    text: bubble.hasCard ? (bubble.card.body || "") : ""
                    wrapMode: Text.Wrap
                    color: Theme.color.text2
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                }
                Repeater {
                    model: bubble.hasCard ? (bubble.card.buttons || []) : []
                    delegate: TribeButton {
                        required property var modelData
                        required property int index
                        width: cardCol.width
                        variant: index === 0 ? "primary" : "glass"
                        text: modelData.label || ""
                        onClicked: bubble.cardButtonClicked(modelData)
                    }
                }
            }
        }

        Rectangle {
            id: box
            visible: bubble.text !== "" && !bubble.hasCard
            anchors.left: bubble.mine ? undefined : parent.left
            anchors.right: bubble.mine ? parent.right : undefined
            // implicitWidth текста — натуральная (без переноса) ширина → нет binding-loop с msg.width
            width: Math.min(msg.implicitWidth + 2 * bubble.pad, bubble.width * 0.78)
            implicitHeight: msg.implicitHeight + 2 * Theme.space.sm
            radius: Theme.radius.lg
            color: bubble.mine ? Theme.color.accent : Theme.color.surface1
            border.width: bubble.mine ? 0 : 1
            border.color: Theme.color.border
            opacity: bubble.pending ? 0.55 : 1.0

            Text {
                id: msg
                x: bubble.pad
                y: Theme.space.sm
                width: box.width - 2 * bubble.pad
                text: bubble.text
                wrapMode: Text.Wrap
                color: bubble.mine ? Theme.color.bg900 : Theme.color.text1
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
            }
        }

        // строка статуса: время / отправка… / не отправлено + действия
        Row {
            anchors.left: bubble.mine ? undefined : parent.left
            anchors.right: bubble.mine ? parent.right : undefined
            spacing: Theme.space.sm
            visible: bubble.time !== "" || bubble.pending || bubble.failed

            Text {
                visible: bubble.failed
                text: qsTr("Не отправлено")
                color: Theme.color.danger
                font.family: Theme.font.body
                font.pixelSize: 10
            }
            Text {
                visible: bubble.failed
                text: qsTr("Повторить")
                color: Theme.color.accent
                font.family: Theme.font.body
                font.pixelSize: 10
                font.weight: Theme.font.wMedium
                MouseArea {
                    anchors.fill: parent
                    anchors.margins: -6   // удобная зона тапа
                    cursorShape: Qt.PointingHandCursor
                    onClicked: bubble.retryClicked()
                }
            }
            Text {
                visible: bubble.failed
                text: qsTr("Убрать")
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: 10
                MouseArea {
                    anchors.fill: parent
                    anchors.margins: -6
                    cursorShape: Qt.PointingHandCursor
                    onClicked: bubble.discardClicked()
                }
            }
            Text {
                visible: !bubble.failed
                text: bubble.pending ? qsTr("отправка…") : bubble.time
                color: Theme.color.text3
                font.family: Theme.font.mono
                font.pixelSize: 10
            }
        }
    }
}

import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme, Haptic
import "../components"
import "../../Controls2" // PageType

// AVPN: центр уведомлений (#3) — реворк по эталону resources/«Tribe VPN Уведомления.html»
// (2026-07-12): секции по датам (Сегодня/Вчера/Ранее), фильтр «Все/Непрочитанные N»,
// иконки-плитки по типу, превью текста, свайп строки влево = «Прочитать⇄Не прочит.» +
// «Удалить», иконка «прочитать все» (двойная галочка) в шапке. Read-state ЧЕСТНЫЙ
// per-элемент: открытие центра ничего не помечает. Канон — docs NOTIFICATIONS.md.
PageType {
    id: root

    signal back()
    // тап по карточке → PageStart открывает полноэкранную деталь (снапшот данных в props)
    signal requestNotificationDetail(var notif)

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property bool hasPush: (typeof AvpnPush !== "undefined")
    readonly property var pushItems: hasPush ? AvpnPush.items : []
    readonly property int unreadTotal: hasPush ? Number(AvpnPush.unreadCount) : 0

    // "all" | "unread" — сегмент-фильтр (клиентский, как в эталоне)
    property string filter: "all"

    // Ширина зоны свайп-действий (2 кнопки × 76, эталон W=152)
    readonly property int actionsW: 152

    // Видимые элементы: фильтр + srcIndex (индекс в AvpnPush.items — для мостовых операций
    // при активном фильтре «Непрочитанные», где индексы делегатов сдвинуты).
    readonly property var visibleItems: {
        var out = []
        for (var i = 0; i < pushItems.length; i++) {
            var it = pushItems[i]
            if (filter === "unread" && it.read)
                continue
            out.push({
                "srcIndex": i,
                "id": it.id ? Number(it.id) : 0,
                "title": it.title || "",
                "body": it.body || "",
                "time": it.time || "",
                "group": it.group ? String(it.group) : "earlier",
                "dateFull": it.dateFull || "",
                "type": it.type ? String(it.type) : "generic",
                "days": it.days ? Number(it.days) : 0,
                "read": !!it.read
            })
        }
        return out
    }

    // При открытии центра подтягиваем СЕРВЕРНУЮ историю (замещает локальную ленту;
    // офлайн-ошибки её НЕ затирают). Ничего не помечаем — read-модель per-элемент.
    Component.onCompleted: {
        if (typeof TribeEngine !== "undefined" && typeof TribeEngine.refreshNotifications === "function")
            TribeEngine.refreshNotifications()
    }

    // Тинт/цвет/иконка по типу — язык эталона на токенах Theme (без hex).
    function typeTint(kind) {
        if (kind === "bonus_gift") return Qt.rgba(Theme.color.cta.r, Theme.color.cta.g, Theme.color.cta.b, 0.15)
        if (kind === "payment") return Qt.rgba(Theme.color.connected.r, Theme.color.connected.g, Theme.color.connected.b, 0.15)
        if (kind === "reminder") return Qt.rgba(Theme.color.warning.r, Theme.color.warning.g, Theme.color.warning.b, 0.15)
        return Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.16)
    }
    function typeColor(kind) {
        if (kind === "bonus_gift") return Theme.color.cta
        if (kind === "payment") return Theme.color.connected
        if (kind === "reminder") return Theme.color.warning
        return Theme.color.accentBright
    }
    // Путь иконки типа (24-сетка, stroke): рупор/подарок/галочка-круг/гарнитура/ключ/колокол
    function typePath(kind) {
        if (kind === "announcement") return "M3 10v4h3l5 4V6L6 10H3z M16 9a4 4 0 0 1 0 6 M19 6.5a8 8 0 0 1 0 11"
        if (kind === "bonus_gift") return "M20 12 v8 H4 V12 M2 7 h20 v5 H2 z M12 20 V7 M12 7 H7.5 a2.5 2.5 0 0 1 0 -5 C11 2 12 7 12 7z M12 7 h4.5 a2.5 2.5 0 0 0 0 -5 C13 2 12 7 12 7z"
        if (kind === "payment") return "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M8 12.2l2.6 2.6L16 9.5"
        if (kind === "support") return "M4 14v-2a8 8 0 0 1 16 0v2 M3 13.5 h2 a2 2 0 0 1 2 2 v2.5 a2 2 0 0 1 -2 2 h-2 z M21 13.5 h-2 a2 2 0 0 0 -2 2 v2.5 a2 2 0 0 0 2 2 h2 z"
        if (kind === "reminder") return "M8.5 10.7 a3.8 3.8 0 1 0 0 7.6 3.8 3.8 0 0 0 0 -7.6z M11.2 11.8 20 3 M16.4 6.6l2.6 2.6"
        return "M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6 M9 17v1a3 3 0 0 0 6 0v-1"
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // свайп слева-направо от края = «назад» (не конфликтует со свайпом строк: тот влево)
    TribeEdgeBack { onTriggered: root.back() }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        // ── шапка: круглая «назад» · заголовок · иконка «прочитать все» ──
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 58

            Rectangle {
                width: 44; height: 44; radius: 22
                anchors.left: parent.left; anchors.leftMargin: Theme.space.md
                anchors.verticalCenter: parent.verticalCenter
                color: backMa.pressed ? Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.1)
                                      : "transparent"
                Shape {
                    anchors.centerIn: parent; width: 24; height: 24
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 2.3
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M15 5l-7 7 7 7" }
                    }
                }
                MouseArea {
                    id: backMa
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: { Haptic.play("selection"); root.back() }
                }
            }

            Text {
                anchors.centerIn: parent
                text: qsTr("Уведомления")
                color: Theme.color.text1
                font.family: Theme.font.display
                font.pixelSize: 21
                font.weight: Theme.font.wExtra
            }

            // «Прочитать все» — двойная галочка (эталон), видна только при непрочитанных
            Rectangle {
                width: 44; height: 44; radius: 22
                anchors.right: parent.right; anchors.rightMargin: Theme.space.md
                anchors.verticalCenter: parent.verticalCenter
                visible: root.unreadTotal > 0
                color: allMa.pressed ? Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.1)
                                     : "transparent"
                Shape {
                    anchors.centerIn: parent; width: 24; height: 24
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M2 12.5l3.4 3.4L12.5 8 M10.5 15.9l1.5 1.5L21.5 8" }
                    }
                }
                MouseArea {
                    id: allMa
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        Haptic.play("selection")
                        if (root.hasPush && AvpnPush.markAllRead)
                            AvpnPush.markAllRead()
                    }
                }
            }
        }

        // ── сегмент-фильтр «Все / Непрочитанные N» ──
        Rectangle {
            Layout.fillWidth: true
            Layout.leftMargin: Theme.space.lg
            Layout.rightMargin: Theme.space.lg
            Layout.bottomMargin: Theme.space.xs
            implicitHeight: 50
            radius: 15
            color: Theme.color.bg700
            border.width: 1
            border.color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.12)

            RowLayout {
                anchors.fill: parent
                anchors.margins: 5
                spacing: 5

                Repeater {
                    model: [
                        { "key": "all", "label": qsTr("Все") },
                        { "key": "unread", "label": qsTr("Непрочитанные") }
                    ]
                    delegate: Rectangle {
                        required property var modelData
                        readonly property bool active: root.filter === modelData.key
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        radius: 12
                        color: active ? Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.16)
                                      : "transparent"
                        border.width: active ? 1 : 0
                        border.color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.3)

                        Row {
                            anchors.centerIn: parent
                            spacing: 7
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                text: modelData.label
                                color: Theme.color.text2
                                font.family: Theme.font.display
                                font.pixelSize: 14
                                font.weight: Theme.font.wBold
                            }
                            Rectangle {
                                visible: modelData.key === "unread" && root.unreadTotal > 0
                                anchors.verticalCenter: parent.verticalCenter
                                width: Math.max(19, cnt.implicitWidth + 10); height: 19; radius: 10
                                color: Theme.color.accentDeep
                                Text {
                                    id: cnt
                                    anchors.centerIn: parent
                                    text: String(root.unreadTotal)
                                    color: "white"
                                    font.family: Theme.font.display
                                    font.pixelSize: 11
                                    font.weight: Theme.font.wExtra
                                }
                            }
                        }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: { Haptic.play("selection"); root.filter = modelData.key }
                        }
                    }
                }
            }
        }

        // ── лента с секциями по датам ──
        ListView {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.sm + 2
            Layout.rightMargin: Theme.space.sm + 2
            clip: true
            spacing: 2
            boundsBehavior: Flickable.StopAtBounds
            model: root.visibleItems

            section.property: "group"
            section.criteria: ViewSection.FullString
            section.delegate: Text {
                required property string section
                width: ListView.view ? ListView.view.width : 0
                topPadding: 15; bottomPadding: 5
                leftPadding: Theme.space.sm
                text: section === "today" ? qsTr("СЕГОДНЯ")
                    : section === "yesterday" ? qsTr("ВЧЕРА") : qsTr("РАНЕЕ")
                color: Theme.color.text3
                font.family: Theme.font.display
                font.pixelSize: Theme.font.caption
                font.weight: Theme.font.wBold
                font.letterSpacing: Theme.font.caption * 0.09
            }

            delegate: Item {
                id: rowWrap
                required property var modelData
                required property int index
                width: ListView.view ? ListView.view.width : 0
                height: cardBody.implicitHeight

                // ── свайп-состояние ──
                property bool open: false
                property bool dragging: false
                property real dragX: 0
                readonly property real shiftX: dragging ? dragX : (open ? -root.actionsW : 0)

                Rectangle {
                    anchors.fill: parent
                    radius: 18
                    color: "transparent"
                    clip: true

                    // действия ПОД контентом (открываются свайпом влево).
                    // visible-гейт: clip режет по прямоугольнику, и без него красные/синие
                    // кнопки просвечивали в прозрачных углах скруглённой карточки.
                    Row {
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        visible: rowWrap.shiftX < -0.5

                        // «Прочитать ⇄ Не прочит.»
                        Rectangle {
                            width: 76; height: parent.height
                            color: Qt.rgba(Theme.color.accentDeep.r, Theme.color.accentDeep.g, Theme.color.accentDeep.b, 0.92)
                            Column {
                                anchors.centerIn: parent
                                spacing: 6
                                Shape {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    width: 21; height: 21
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        strokeColor: "#EAF1FA"; fillColor: "transparent"; strokeWidth: 2
                                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                        PathSvg {
                                            path: rowWrap.modelData.read
                                                  ? "M12 5a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M12 10.5 a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0 -3z"
                                                  : "M2 12.5l3.4 3.4L12.5 8 M10.5 15.9l1.5 1.5L21.5 8"
                                        }
                                    }
                                }
                                Text {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    text: rowWrap.modelData.read ? qsTr("Не прочит.") : qsTr("Прочитать")
                                    color: "#EAF1FA"
                                    font.family: Theme.font.display
                                    font.pixelSize: 12
                                    font.weight: Theme.font.wBold
                                }
                            }
                        }
                        // «Удалить»
                        Rectangle {
                            width: 76; height: parent.height
                            color: Qt.rgba(Theme.color.danger.r, Theme.color.danger.g, Theme.color.danger.b, 0.94)
                            Column {
                                anchors.centerIn: parent
                                spacing: 6
                                Shape {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    width: 21; height: 21
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        strokeColor: "#FCE3E1"; fillColor: "transparent"; strokeWidth: 2
                                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                        PathSvg { path: "M4 7h16 M9 7V5.2A1.2 1.2 0 0 1 10.2 4h3.6A1.2 1.2 0 0 1 15 5.2V7 M6 7l1 12.2A1.8 1.8 0 0 0 8.8 21h6.4a1.8 1.8 0 0 0 1.8-1.8L18 7 M10 11v6 M14 11v6" }
                                    }
                                }
                                Text {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    text: qsTr("Удалить")
                                    color: "#FCE3E1"
                                    font.family: Theme.font.display
                                    font.pixelSize: 12
                                    font.weight: Theme.font.wBold
                                }
                            }
                        }
                    }

                    // контент строки (едет влево)
                    Rectangle {
                        id: cardBody
                        width: parent.width
                        height: parent.height
                        x: rowWrap.shiftX
                        radius: 18
                        color: rowMa.pressed && !rowMa.dragActive
                               ? Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.1)
                               : Theme.color.bg800
                        implicitHeight: rowGrid.implicitHeight + 2 * Theme.space.md

                        Behavior on x {
                            enabled: !rowWrap.dragging
                            NumberAnimation { duration: 260; easing.type: Easing.OutCubic }
                        }

                        RowLayout {
                            id: rowGrid
                            anchors.left: parent.left; anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.leftMargin: Theme.space.md
                            anchors.rightMargin: Theme.space.md
                            spacing: Theme.space.md

                            // колонка: время + иконка типа
                            Column {
                                Layout.alignment: Qt.AlignTop
                                Layout.preferredWidth: 46
                                spacing: 8
                                Text {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    text: rowWrap.modelData.time
                                    color: Theme.color.text3
                                    font.family: Theme.font.mono
                                    font.pixelSize: 11
                                    font.weight: Theme.font.wSemibold
                                }
                                Rectangle {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    width: 44; height: 44; radius: 13
                                    color: root.typeTint(rowWrap.modelData.type)
                                    Shape {
                                        anchors.centerIn: parent; width: 22; height: 22
                                        transform: Scale { xScale: 22/24; yScale: 22/24 }
                                        preferredRendererType: Shape.CurveRenderer
                                        ShapePath {
                                            strokeColor: root.typeColor(rowWrap.modelData.type)
                                            fillColor: "transparent"; strokeWidth: 2
                                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                            PathSvg { path: root.typePath(rowWrap.modelData.type) }
                                        }
                                    }
                                }
                            }

                            // заголовок + превью
                            Column {
                                Layout.fillWidth: true
                                Layout.alignment: Qt.AlignVCenter
                                spacing: 4
                                Text {
                                    width: parent.width
                                    text: rowWrap.modelData.title
                                    color: rowWrap.modelData.read ? Theme.color.text2 : Theme.color.text1
                                    font.family: Theme.font.display
                                    font.pixelSize: 15
                                    font.weight: rowWrap.modelData.read ? Theme.font.wSemibold : Theme.font.wExtra
                                    elide: Text.ElideRight
                                }
                                Text {
                                    width: parent.width
                                    text: rowWrap.modelData.body
                                    color: Theme.color.text3
                                    font.family: Theme.font.body
                                    font.pixelSize: 13
                                    lineHeight: 1.42
                                    wrapMode: Text.WordWrap
                                    maximumLineCount: 2
                                    elide: Text.ElideRight
                                }
                            }

                            // точка непрочитанного с ореолом
                            Item {
                                Layout.preferredWidth: 9
                                Layout.alignment: Qt.AlignVCenter
                                implicitHeight: 9
                                Rectangle {
                                    visible: !rowWrap.modelData.read
                                    anchors.centerIn: parent
                                    width: 17; height: 17; radius: 8.5
                                    color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.14)
                                    Rectangle {
                                        anchors.centerIn: parent
                                        width: 9; height: 9; radius: 4.5
                                        color: Theme.color.accent
                                    }
                                }
                            }
                        }
                    }

                    // единый обработчик: тап/свайп/кнопки действий (ручной хит-тест — без войн
                    // за grab между MouseArea контента, действий и флика ListView)
                    MouseArea {
                        id: rowMa
                        anchors.fill: parent
                        preventStealing: dragActive
                        property real pressX: 0
                        property real pressY: 0
                        property real baseX: 0
                        property bool dragActive: false

                        onPressed: (mouse) => {
                            pressX = mouse.x; pressY = mouse.y
                            baseX = rowWrap.open ? -root.actionsW : 0
                            dragActive = false
                        }
                        onPositionChanged: (mouse) => {
                            var dx = mouse.x - pressX
                            if (!dragActive && Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(mouse.y - pressY)) {
                                dragActive = true
                                rowWrap.dragging = true
                            }
                            if (dragActive)
                                rowWrap.dragX = Math.max(-root.actionsW - 24, Math.min(0, baseX + dx))
                        }
                        onReleased: (mouse) => {
                            if (dragActive) {
                                rowWrap.open = rowWrap.dragX <= -root.actionsW / 2
                                rowWrap.dragging = false
                                dragActive = false
                                if (rowWrap.open) Haptic.play("selection")
                                return
                            }
                            // тап
                            if (rowWrap.open) {
                                var actionsLeft = rowWrap.width - root.actionsW
                                if (mouse.x >= actionsLeft && mouse.x < actionsLeft + 76) {
                                    Haptic.play("selection")
                                    if (root.hasPush && AvpnPush.setItemRead)
                                        AvpnPush.setItemRead(rowWrap.modelData.srcIndex, !rowWrap.modelData.read)
                                    rowWrap.open = false
                                    return
                                }
                                if (mouse.x >= actionsLeft + 76) {
                                    Haptic.play("impactMedium")
                                    if (root.hasPush && AvpnPush.removeItem)
                                        AvpnPush.removeItem(rowWrap.modelData.srcIndex)
                                    return
                                }
                                rowWrap.open = false
                                return
                            }
                            // тап по закрытой строке → пометить прочитанным + открыть деталь
                            Haptic.play("selection")
                            var n = rowWrap.modelData
                            if (root.hasPush && AvpnPush.markItemRead)
                                AvpnPush.markItemRead(n.srcIndex)
                            root.requestNotificationDetail(n)
                        }
                        onCanceled: { rowWrap.dragging = false; dragActive = false }
                    }
                }
            }
        }
    }

    // ── пустые состояния ──
    // 1) вообще нет уведомлений
    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.x3
        spacing: Theme.space.md
        visible: root.pushItems.length === 0

        Shape {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 48; height: 48
            preferredRendererType: Shape.CurveRenderer
            transform: Scale { xScale: 2; yScale: 2 }
            ShapePath {
                strokeColor: Theme.color.text3; fillColor: "transparent"; strokeWidth: 1.6
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: "M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6 M9 17v1a3 3 0 0 0 6 0v-1" }
            }
        }
        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("Пока нет уведомлений")
            color: Theme.color.text1
            font.family: Theme.font.display
            font.pixelSize: Theme.font.bodyL
            font.weight: Theme.font.wBold
        }
        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            text: qsTr("Здесь появятся важные сообщения о доступе, новых серверах и состоянии сервиса.")
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyS
        }
    }

    // 2) уведомления есть, но фильтр пуст («Всё прочитано», эталон)
    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.x3
        spacing: Theme.space.md
        visible: root.pushItems.length > 0 && root.visibleItems.length === 0

        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 66; height: 66; radius: 33
            color: Qt.rgba(Theme.color.connected.r, Theme.color.connected.g, Theme.color.connected.b, 0.14)
            Shape {
                anchors.centerIn: parent; width: 30; height: 30
                transform: Scale { xScale: 30/24; yScale: 30/24 }
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.connected; fillColor: "transparent"; strokeWidth: 2
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M8 12.2l2.6 2.6L16 9.5" }
                }
            }
        }
        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("Всё прочитано")
            color: Theme.color.text1
            font.family: Theme.font.display
            font.pixelSize: Theme.font.bodyL
            font.weight: Theme.font.wExtra
        }
        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            text: qsTr("Пока нет непрочитанных сообщений")
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyS
        }
    }
}

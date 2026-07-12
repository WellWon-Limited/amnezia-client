import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme, Haptic
import "../components"
import "../../Controls2" // PageType

// AVPN: полноэкранная деталь ОДНОГО уведомления — по эталону
// resources/«Tribe VPN Уведомления.html» (2026-07-12): пилюля «‹ Уведомления» + чип
// категории в шапке, плитка-иконка типа, крупный заголовок, моно-дата, абзацы,
// футер = CTA по типу (только store-safe: рефералка/чат — БЕЗ платёжных ссылок,
// Apple 3.1.1) + «Готово». Пометка «прочитано» уже сделана тапом в центре.
// Открытие: PageStart onRequestNotificationDetail → goToTabBarPageUrl({notif}).
PageType {
    id: root

    // снапшот уведомления: {id, title, body, time, group, dateFull, type, days, read}
    property var notif: ({})

    signal requestNotifications()   // «назад»/«Готово» → в центр
    signal requestTab(int index)    // CTA: 1 = чат поддержки, 2 = рефералка

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property string kind: (notif && notif.type) ? String(notif.type) : "generic"
    readonly property int giftDays: (notif && notif.days) ? Number(notif.days) : 0

    readonly property string catLabel: {
        if (kind === "announcement") return qsTr("Объявление")
        if (kind === "bonus_gift") return qsTr("Бонус")
        if (kind === "payment") return qsTr("Оплата")
        if (kind === "support") return qsTr("Поддержка")
        if (kind === "reminder") return qsTr("Напоминание")
        if (kind === "broadcast") return qsTr("Новости")
        return qsTr("Уведомление")
    }
    // CTA только на БЕЗОПАСНЫЕ внутренние действия (не платёжные ссылки — стор-правила):
    // бонус → рефералка (если не выключена kill-switch'ем), support → чат поддержки.
    readonly property bool referralOn: (typeof TribeEngine === "undefined")
                                       || TribeEngine.referralEnabled !== false
    readonly property string ctaLabel: {
        if (kind === "bonus_gift" && referralOn) return qsTr("Пригласить ещё")
        if (kind === "support") return qsTr("Открыть чат поддержки")
        return ""
    }
    function ctaClicked() {
        Haptic.play("selection")
        if (kind === "bonus_gift") root.requestTab(2)
        else if (kind === "support") root.requestTab(1)
    }

    // те же тинт/цвет/иконка, что в списке (единый язык эталона)
    function typeTint(k) {
        if (k === "bonus_gift") return Qt.rgba(Theme.color.cta.r, Theme.color.cta.g, Theme.color.cta.b, 0.15)
        if (k === "payment") return Qt.rgba(Theme.color.connected.r, Theme.color.connected.g, Theme.color.connected.b, 0.15)
        if (k === "reminder") return Qt.rgba(Theme.color.warning.r, Theme.color.warning.g, Theme.color.warning.b, 0.15)
        return Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.16)
    }
    function typeColor(k) {
        if (k === "bonus_gift") return Theme.color.cta
        if (k === "payment") return Theme.color.connected
        if (k === "reminder") return Theme.color.warning
        return Theme.color.accentBright
    }
    function typePath(k) {
        if (k === "announcement") return "M3 10v4h3l5 4V6L6 10H3z M16 9a4 4 0 0 1 0 6 M19 6.5a8 8 0 0 1 0 11"
        if (k === "bonus_gift") return "M20 12 v8 H4 V12 M2 7 h20 v5 H2 z M12 20 V7 M12 7 H7.5 a2.5 2.5 0 0 1 0 -5 C11 2 12 7 12 7z M12 7 h4.5 a2.5 2.5 0 0 0 0 -5 C13 2 12 7 12 7z"
        if (k === "payment") return "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M8 12.2l2.6 2.6L16 9.5"
        if (k === "support") return "M4 14v-2a8 8 0 0 1 16 0v2 M3 13.5 h2 a2 2 0 0 1 2 2 v2.5 a2 2 0 0 1 -2 2 h-2 z M21 13.5 h-2 a2 2 0 0 0 -2 2 v2.5 a2 2 0 0 0 2 2 h2 z"
        if (k === "reminder") return "M8.5 10.7 a3.8 3.8 0 1 0 0 7.6 3.8 3.8 0 0 0 0 -7.6z M11.2 11.8 20 3 M16.4 6.6l2.6 2.6"
        return "M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6 M9 17v1a3 3 0 0 0 6 0v-1"
    }
    // абзацы: тело режем по пустой строке (эталон: массив параграфов, pre-line)
    readonly property var paragraphs: {
        var b = (notif && notif.body) ? String(notif.body) : ""
        return b.length ? b.split("\n\n") : []
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // свайп слева-направо = «назад» (в центр уведомлений)
    TribeEdgeBack { onTriggered: root.requestNotifications() }

    ColumnLayout {
        id: page
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        // въезд справа (эталон ntIn: 14px + fade, .28s)
        opacity: 0
        transform: Translate { id: slideIn; x: 14 }
        Component.onCompleted: slideAnim.start()
        ParallelAnimation {
            id: slideAnim
            NumberAnimation { target: page; property: "opacity"; to: 1; duration: 280; easing.type: Easing.OutCubic }
            NumberAnimation { target: slideIn; property: "x"; to: 0; duration: 280; easing.type: Easing.OutCubic }
        }

        // ── шапка: пилюля «‹ Уведомления» + чип категории ──
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 58

            Rectangle {
                anchors.left: parent.left; anchors.leftMargin: Theme.space.md + 2
                anchors.verticalCenter: parent.verticalCenter
                height: 38; radius: 19
                width: backRow.implicitWidth + 24
                color: backMa.pressed
                       ? Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.16)
                       : Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.1)
                border.width: 1
                border.color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.18)

                Row {
                    id: backRow
                    anchors.centerIn: parent
                    spacing: 3
                    Shape {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 18; height: 18
                        transform: Scale { xScale: 18/24; yScale: 18/24 }
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.accentBright; fillColor: "transparent"; strokeWidth: 2.4
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M15 6l-6 6 6 6" }
                        }
                    }
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: qsTr("Уведомления")
                        color: Theme.color.accentBright
                        font.family: Theme.font.display
                        font.pixelSize: Theme.font.bodyS
                        font.weight: Theme.font.wBold
                    }
                }
                MouseArea {
                    id: backMa
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: { Haptic.play("selection"); root.requestNotifications() }
                }
            }

            // чип категории с точкой
            Rectangle {
                anchors.right: parent.right; anchors.rightMargin: Theme.space.md + 2
                anchors.verticalCenter: parent.verticalCenter
                height: 28; radius: 14
                width: catRow.implicitWidth + 24
                color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.12)
                border.width: 1
                border.color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.22)
                Row {
                    id: catRow
                    anchors.centerIn: parent
                    spacing: 7
                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 6; height: 6; radius: 3
                        color: Theme.color.accent
                    }
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.catLabel.toUpperCase()
                        color: Theme.color.accentBright
                        font.family: Theme.font.display
                        font.pixelSize: 11
                        font.weight: Theme.font.wBold
                        font.letterSpacing: 11 * 0.07
                    }
                }
            }
        }

        // ── контент ──
        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: width
            contentHeight: content.implicitHeight + Theme.space.lg
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                width: parent.width
                spacing: 0

                // плитка-иконка типа (слева, как в эталоне без hero)
                Rectangle {
                    Layout.leftMargin: 22
                    Layout.topMargin: 10
                    Layout.preferredWidth: 56
                    Layout.preferredHeight: 56
                    radius: 16
                    color: root.typeTint(root.kind)
                    Shape {
                        anchors.centerIn: parent; width: 28; height: 28
                        transform: Scale { xScale: 28/24; yScale: 28/24 }
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: root.typeColor(root.kind); fillColor: "transparent"; strokeWidth: 2
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: root.typePath(root.kind) }
                        }
                    }
                }

                Text {
                    Layout.fillWidth: true
                    Layout.leftMargin: 22
                    Layout.rightMargin: 22
                    Layout.topMargin: 14
                    text: (root.notif && root.notif.title) ? root.notif.title : ""
                    color: Theme.color.text1
                    font.family: Theme.font.display
                    font.pixelSize: 24
                    font.weight: Theme.font.wExtra
                    lineHeight: 1.22
                    wrapMode: Text.WordWrap
                }

                Text {
                    Layout.leftMargin: 22
                    Layout.topMargin: 9
                    visible: text !== ""
                    text: (root.notif && root.notif.dateFull) ? root.notif.dateFull
                         : ((root.notif && root.notif.time) ? root.notif.time : "")
                    color: Theme.color.text3
                    font.family: Theme.font.mono
                    font.pixelSize: 13
                    font.weight: Theme.font.wSemibold
                }

                // золотой чип «+N дней» у бонуса
                Rectangle {
                    Layout.leftMargin: 22
                    Layout.topMargin: 12
                    visible: root.kind === "bonus_gift" && root.giftDays > 0
                    implicitWidth: giftChip.implicitWidth + 2 * Theme.space.md
                    implicitHeight: giftChip.implicitHeight + Theme.space.xs + 2
                    radius: height / 2
                    color: Qt.rgba(Theme.color.cta.r, Theme.color.cta.g, Theme.color.cta.b, 0.15)
                    border.width: 1
                    border.color: Qt.rgba(Theme.color.cta.r, Theme.color.cta.g, Theme.color.cta.b, 0.5)
                    Text {
                        id: giftChip
                        anchors.centerIn: parent
                        text: qsTr("+%1 дней").arg(root.giftDays)
                        color: Theme.color.cta
                        font.family: Theme.font.display
                        font.pixelSize: Theme.font.caption
                        font.weight: Theme.font.wExtra
                    }
                }

                // абзацы тела (одиночные \n сохраняются внутри абзаца — pre-line)
                Repeater {
                    model: root.paragraphs
                    delegate: Text {
                        required property var modelData
                        Layout.fillWidth: true
                        Layout.leftMargin: 22
                        Layout.rightMargin: 22
                        Layout.topMargin: 14
                        text: modelData
                        color: Theme.color.text2
                        font.family: Theme.font.body
                        font.pixelSize: 15
                        lineHeight: 1.62
                        wrapMode: Text.WordWrap
                    }
                }
            }
        }

        // ── футер действий ──
        ColumnLayout {
            Layout.fillWidth: true
            Layout.leftMargin: 22
            Layout.rightMargin: 22
            Layout.topMargin: Theme.space.md
            Layout.bottomMargin: Theme.space.xl
            spacing: 10

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 54
                visible: root.ctaLabel !== ""
                radius: Theme.radius.lg
                color: Theme.color.accentDeep
                opacity: ctaMa.pressed ? 0.85 : 1
                Text {
                    anchors.centerIn: parent
                    text: root.ctaLabel
                    color: "white"
                    font.family: Theme.font.display
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wExtra
                }
                MouseArea {
                    id: ctaMa
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: root.ctaClicked()
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 52
                radius: Theme.radius.lg
                color: doneMa.pressed
                       ? Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.16)
                       : Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.1)
                border.width: 1
                border.color: Qt.rgba(Theme.color.accent.r, Theme.color.accent.g, Theme.color.accent.b, 0.16)
                Text {
                    anchors.centerIn: parent
                    text: qsTr("Прочитал")
                    color: Theme.color.text1
                    font.family: Theme.font.display
                    font.pixelSize: 16
                    font.weight: Theme.font.wBold
                }
                MouseArea {
                    id: doneMa
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: { Haptic.play("selection"); root.requestNotifications() }
                }
            }
        }
    }
}

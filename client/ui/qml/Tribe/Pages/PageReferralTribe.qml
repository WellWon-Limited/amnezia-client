import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Shapes

import ".."              // Theme
import "../components"   // TribeButton
import "../../Controls2" // PageType

// AVPN (#37 рефералы): вкладка «Рефералка». Делимся реальной реф-ссылкой (в ней зашит код → бонус
// начислится). Данные — из движка (TribeEngine.referral {code, link, invited, days_earned}). Apple-safe:
// только ссылка + статус, без цен/покупок-по-ссылке (§10). Перенесено из баннера Профиля.
PageType {
    id: root

    // iOS: PageController.safeArea* только для Android → max с SafeArea (Qt 6.9+, реактивный инсет).
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)

    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    readonly property var referralData: hasEngine ? TribeEngine.referral : ({})
    readonly property string referralLink: referralData && referralData.link ? ("" + referralData.link) : ""
    readonly property int invited: referralData && referralData.invited ? Number(referralData.invited) : 0
    readonly property int daysEarned: referralData && referralData.days_earned ? Number(referralData.days_earned) : 0
    readonly property int daysPerFriend: 7   // бонус за друга (константа оффера)

    function refreshReferral() {
        if (hasEngine && typeof TribeEngine.refreshReferral === "function")
            TribeEngine.refreshReferral()
    }
    // копирование в буфер (паттерн форка: скрытый TextEdit → selectAll()+copy()). Apple-safe.
    function copyLink() {
        if (root.referralLink.length > 0) {
            refLinkEdit.text = root.referralLink
            refLinkEdit.selectAll(); refLinkEdit.copy(); refLinkEdit.deselect()
            PageController.showNotificationMessage(qsTr("Ссылка скопирована — отправь другу"))
        } else {
            PageController.showNotificationMessage(qsTr("Ссылка ещё загружается…"))
        }
    }
    // TODO(native share): iOS share-лист не подключён — «Поделиться» пока тоже копирует (надёжно везде).
    function shareLink() {
        if (root.referralLink.length > 0) {
            refLinkEdit.text = root.referralLink
            refLinkEdit.selectAll(); refLinkEdit.copy(); refLinkEdit.deselect()
            PageController.showNotificationMessage(qsTr("Ссылка скопирована — вставь в мессенджер"))
        } else {
            PageController.showNotificationMessage(qsTr("Ссылка ещё загружается…"))
        }
    }

    Component.onCompleted: root.refreshReferral()

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    // скрытый носитель ссылки для копирования
    TextEdit { id: refLinkEdit; width: 0; height: 0; opacity: 0; readOnly: true }

    // карточка-статистика (значение + подпись)
    component StatCard: Rectangle {
        property string value: ""
        property string caption: ""
        radius: Theme.radius.md
        color: Theme.color.surface1
        border.width: 1; border.color: Theme.color.border
        implicitHeight: 76
        Column {
            anchors.centerIn: parent; spacing: 3
            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: parent.parent.value
                color: Theme.color.accent
                font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold
            }
            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: parent.parent.caption
                color: Theme.color.text3
                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: Theme.space.xl + root.safeTop
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        anchors.bottomMargin: Theme.space.lg
        spacing: Theme.space.lg

        // заголовок
        Text {
            Layout.fillWidth: true
            text: qsTr("Пригласи друзей")
            color: Theme.color.text1
            font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wBold
        }

        Flickable {
            Layout.fillWidth: true; Layout.fillHeight: true
            contentHeight: content.height + Theme.space.xl
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Column {
                id: content
                width: parent.width
                spacing: Theme.space.lg

                // ── БАННЕР «ПОДЕЛИТЬСЯ» с подарком (возвращён из Профиля, где жил до вкладки;
                //    дизайн v2 f313fa9c: тёмная плашка + золотой хайрлайн + анимированный подарок).
                //    Тап — копирует реф-ссылку (как раньше). // AVPN
                Rectangle {
                    id: shareBanner
                    width: parent.width
                    implicitHeight: bannerCol.implicitHeight + 2 * Theme.space.lg
                    radius: Theme.radius.lg
                    gradient: Gradient {
                        orientation: Gradient.Vertical
                        GradientStop { position: 0.0; color: Theme.color.surface2 }
                        GradientStop { position: 1.0; color: Theme.color.bg700 }
                    }
                    border.width: 0.5                     // золотая рамка — тонкий хайрлайн (Retina ~1px)
                    border.color: Theme.color.cta
                    scale: shareMa.pressed ? 0.99 : 1.0
                    Behavior on scale { NumberAnimation { duration: Theme.motion.fast; easing.type: Easing.OutCubic } }

                    ColumnLayout {
                        id: bannerCol
                        anchors.fill: parent
                        anchors.margins: Theme.space.lg
                        spacing: Theme.space.md

                        // верхний ряд: подарок + заголовок (2 строки)
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space.md

                            // ── бейдж «подарок»: светящийся круг + объёмный подарок + золотой «+» + блёстки;
                            // подарок периодически «вздрагивает» (наклон у основания). // AVPN
                            Item {
                                id: giftBadge
                                Layout.alignment: Qt.AlignVCenter
                                Layout.preferredWidth: 56; Layout.preferredHeight: 56

                                Rectangle {
                                    anchors.centerIn: parent
                                    width: 52; height: 52; radius: 26
                                    color: Qt.rgba(1, 1, 1, 0.20)
                                    border.width: 1; border.color: Qt.rgba(1, 1, 1, 0.28)
                                }
                                Shape {
                                    anchors.right: parent.right; anchors.top: parent.top
                                    anchors.rightMargin: 2; anchors.topMargin: 4
                                    width: 9; height: 9
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        fillColor: Qt.rgba(1, 1, 1, 0.85); strokeColor: "transparent"
                                        PathSvg { path: "M4.5 0 L5.6 3.4 L9 4.5 L5.6 5.6 L4.5 9 L3.4 5.6 L0 4.5 L3.4 3.4 Z" }
                                    }
                                }
                                Shape {
                                    anchors.left: parent.left; anchors.bottom: parent.bottom
                                    anchors.leftMargin: 1; anchors.bottomMargin: 8
                                    width: 6; height: 6
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        fillColor: Qt.rgba(1, 1, 1, 0.6); strokeColor: "transparent"
                                        PathSvg { path: "M3 0 L3.7 2.3 L6 3 L3.7 3.7 L3 6 L2.3 3.7 L0 3 L2.3 2.3 Z" }
                                    }
                                }
                                Shape {
                                    id: giftShape
                                    anchors.centerIn: parent
                                    width: 30; height: 30
                                    transformOrigin: Item.Bottom
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        fillColor: "#DCE8F7"; strokeColor: "transparent"
                                        PathSvg { path: "M6 14 H24 V25 a2 2 0 0 1 -2 2 H8 a2 2 0 0 1 -2 -2 Z" }
                                    }
                                    ShapePath {
                                        fillColor: "#FFFFFF"; strokeColor: "transparent"
                                        PathSvg { path: "M4 10 H26 V14 H4 Z" }
                                    }
                                    ShapePath {
                                        fillColor: Theme.color.cta; strokeColor: "transparent"
                                        PathSvg { path: "M13.4 10 H16.6 V27 H13.4 Z" }
                                    }
                                    ShapePath {
                                        fillColor: Theme.color.cta; strokeColor: "transparent"
                                        PathSvg { path: "M15 10 C12 5 8 5.5 9 8.6 C9.7 10.4 13 10.8 15 10 Z" }
                                    }
                                    ShapePath {
                                        fillColor: Theme.color.cta; strokeColor: "transparent"
                                        PathSvg { path: "M15 10 C18 5 22 5.5 21 8.6 C20.3 10.4 17 10.8 15 10 Z" }
                                    }
                                }
                                Rectangle {
                                    anchors.right: parent.right; anchors.bottom: parent.bottom
                                    anchors.rightMargin: 1; anchors.bottomMargin: 1
                                    width: 19; height: 19; radius: width / 2
                                    color: Theme.color.cta
                                    border.width: 2; border.color: Qt.darker(Theme.color.gradBottom, 1.6)
                                    Shape {
                                        anchors.centerIn: parent; width: 11; height: 11
                                        preferredRendererType: Shape.CurveRenderer
                                        ShapePath {
                                            strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2
                                            capStyle: ShapePath.RoundCap
                                            PathSvg { path: "M5.5 1.6 V9.4 M1.6 5.5 H9.4" }
                                        }
                                    }
                                }
                                SequentialAnimation {
                                    running: !Theme.motion.reduceMotion
                                    loops: Animation.Infinite
                                    PauseAnimation { duration: 2600 }
                                    NumberAnimation { target: giftShape; property: "rotation"; to: -9; duration: 90 }
                                    NumberAnimation { target: giftShape; property: "rotation"; to: 9;  duration: 150; easing.type: Easing.InOutSine }
                                    NumberAnimation { target: giftShape; property: "rotation"; to: -6; duration: 120; easing.type: Easing.InOutSine }
                                    NumberAnimation { target: giftShape; property: "rotation"; to: 0;  duration: 130; easing.type: Easing.OutBack }
                                }
                            }

                            // заголовок (2 строки)
                            Text {
                                Layout.fillWidth: true
                                Layout.alignment: Qt.AlignVCenter
                                Layout.leftMargin: Theme.space.xs
                                text: qsTr("Поделиться с друзьями\nЗа каждого друга — подарок!")
                                color: "white"
                                font.family: Theme.font.display
                                font.pixelSize: Theme.font.bodyS
                                font.weight: Theme.font.wSemibold
                                lineHeight: 1.15
                                wrapMode: Text.NoWrap
                            }
                        }

                        // пилюля во всю ширину: «7 дней + 3 ГБ» золотом / статистика, если уже приглашал
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: pillText.implicitHeight + 2 * Theme.space.sm
                            radius: Theme.radius.pill
                            color: Qt.rgba(0, 0, 0, 0.24)
                            border.width: 0.5
                            border.color: Theme.color.border3
                            Text {
                                id: pillText
                                anchors.centerIn: parent
                                textFormat: Text.StyledText
                                text: root.invited > 0
                                      ? "<font color='" + Theme.color.cta + "'>Приглашено " + root.invited
                                        + "</font> · +" + root.daysEarned + " дней"
                                      : "<font color='" + Theme.color.cta + "'>7 дней + 3 ГБ</font> бесплатно"
                                color: "white"
                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                                font.weight: Theme.font.wMedium
                            }
                        }
                    }
                    MouseArea {
                        id: shareMa
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.copyLink()
                    }
                }

                // ── карточка «Поделиться ссылкой» ──
                Rectangle {
                    width: parent.width
                    radius: Theme.radius.lg
                    color: Theme.color.surface1
                    border.width: 1; border.color: Theme.color.border
                    implicitHeight: shareCol.implicitHeight + 2 * Theme.space.lg
                    Column {
                        id: shareCol
                        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                        anchors.margins: Theme.space.lg
                        spacing: Theme.space.md

                        Text {
                            width: parent.width
                            text: qsTr("Делитесь ссылкой — за каждого, кто активирует ключ по ней, начисляем %1 бонусных дней.").arg(root.daysPerFriend)
                            color: Theme.color.text1; wrapMode: Text.WordWrap
                            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                        }

                        // ссылка (mono, в тёмном боксе)
                        Rectangle {
                            width: parent.width
                            implicitHeight: linkText.implicitHeight + 2 * Theme.space.md
                            radius: Theme.radius.md
                            color: Theme.color.bg800
                            border.width: 1; border.color: Theme.color.border
                            Text {
                                id: linkText
                                anchors.left: parent.left; anchors.right: parent.right
                                anchors.leftMargin: Theme.space.md; anchors.rightMargin: Theme.space.md
                                anchors.verticalCenter: parent.verticalCenter
                                text: root.referralLink.length > 0 ? root.referralLink : qsTr("Загрузка ссылки…")
                                color: Theme.color.text2; elide: Text.ElideMiddle
                                font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                            }
                        }

                        TribeButton {
                            width: parent.width
                            variant: "primary"
                            text: qsTr("Скопировать ссылку")
                            onClicked: root.copyLink()
                        }
                        TribeButton {
                            width: parent.width
                            variant: "glass"
                            text: qsTr("Поделиться")
                            onClicked: root.shareLink()
                        }
                    }
                }

                // ── 3 стата ──
                RowLayout {
                    width: parent.width
                    spacing: Theme.space.md
                    StatCard { Layout.fillWidth: true; value: "" + root.invited;      caption: qsTr("Приглашено") }
                    StatCard { Layout.fillWidth: true; value: "+" + root.daysEarned;  caption: qsTr("Бонус-дней") }
                    StatCard { Layout.fillWidth: true; value: "+" + root.daysPerFriend; caption: qsTr("Дней за друга") }
                }

                // ── футер-подсказка ──
                Text {
                    width: parent.width
                    text: qsTr("Друг засчитывается, когда активирует ключ по вашей ссылке. История по каждому появится позже.")
                    color: Theme.color.text3; wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                }
            }
        }
    }
}

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

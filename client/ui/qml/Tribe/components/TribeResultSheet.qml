import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN: полноэкранный результат операции (перенос подписки и т.п.): зелёная галочка + заголовок +
// пояснение + «Понятно». Не тост: терминальное событие должно быть невозможно пропустить.
// Участвует в back-логике как дровер (incrementDrawerDepth/closeTopDrawer — паттерн DrawerType2):
// аппаратный Back/Escape закрывает ЭТОТ оверлей, а не страницу под ним. done() эмитится на любом
// закрытии (кнопка/Back) — вызывающий делает навигацию там.
Item {
    id: sheet
    anchors.fill: parent
    visible: opened
    z: 200

    property bool   opened: false
    property string title: ""
    property string subtitle: ""
    property int    depthIndex: 0
    signal done()

    function show(t, s) {
        title = t
        subtitle = s || ""
        opened = true
        depthIndex = PageController.incrementDrawerDepth()
    }
    function close() {
        if (!opened)
            return
        opened = false
        depthIndex = 0
        PageController.decrementDrawerDepth()
        done()
    }

    Connections {
        target: PageController
        enabled: sheet.opened
        function onCloseTopDrawer() {
            if (sheet.depthIndex === PageController.getDrawerDepth())
                sheet.close()
        }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    MouseArea { anchors.fill: parent }   // глушим клики в страницу под оверлеем

    ColumnLayout {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.xxl
        spacing: Theme.space.lg

        Rectangle {
            Layout.alignment: Qt.AlignHCenter
            width: 96; height: 96; radius: Theme.radius.pill
            color: Qt.alpha(Theme.color.connected, 0.14)
            border.width: 1.5
            border.color: Qt.alpha(Theme.color.connected, 0.5)

            Shape {
                anchors.centerIn: parent
                width: 48; height: 48
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.connected; fillColor: "transparent"; strokeWidth: 4
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    // lucide "check" (24-grid → 48px)
                    PathSvg { path: "M40 12 L18 34 L8 24" }
                }
            }
        }

        Text {
            Layout.fillWidth: true
            text: sheet.title
            color: Theme.color.text1
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
            font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wBold
        }
        Text {
            Layout.fillWidth: true
            visible: sheet.subtitle !== ""
            text: sheet.subtitle
            color: Theme.color.text2
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
            font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
        }
    }

    TribeButton {
        variant: "primary"
        glow: false
        text: qsTr("Понятно")
        width: parent.width - 2 * Theme.space.xl
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: Theme.space.xl + PageController.safeAreaBottomMargin
        onClicked: sheet.close()
    }
}

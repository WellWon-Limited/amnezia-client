import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme

// AVPN (Task 7): полноэкранный force-update блокер. Показывается, когда control plane помечает
// текущую версию клиента как несовместимую (TribeEngine.updateState === 2 — remote-config §Task 6).
// Неснимаемый: аппаратный Back/Escape НЕ закрывает его — держим drawerDepth (паттерн
// TribeResultSheet/TribeAnnouncementSheet), но onCloseTopDrawer тут же возвращает глубину назад,
// чтобы Back не "провалился" на страницу под блокером и не свернул приложение. Токены — только Theme.
Item {
    id: gate
    anchors.fill: parent
    visible: (typeof TribeEngine !== "undefined") && TribeEngine.updateState === 2
    z: 9999

    property int depthIndex: 0

    onVisibleChanged: {
        if (visible)
            depthIndex = PageController.incrementDrawerDepth()
        else if (depthIndex !== 0) {
            PageController.decrementDrawerDepth()
            depthIndex = 0
        }
    }
    Component.onDestruction: if (visible && depthIndex !== 0) PageController.decrementDrawerDepth()

    Connections {
        target: PageController
        enabled: gate.visible
        function onCloseTopDrawer() {
            // блокер неснимаем: сразу восстанавливаем глубину, которую C++ decrementDrawerDepth()
            // снимет ПОСЛЕ этого сигнала (см. PageController::keyPressEvent) — иначе следующий
            // Back "проваливается" ниже нуля и уходит в escapePressed()/сворачивание приложения.
            if (gate.depthIndex === PageController.getDrawerDepth())
                gate.depthIndex = PageController.incrementDrawerDepth()
        }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }
    MouseArea { anchors.fill: parent }   // глушим клики в страницу под блокером

    ColumnLayout {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.xl
        spacing: Theme.space.lg

        // иконка обновления (Lucide "download", 24-grid → 40px) в круглой плашке — тот же язык
        // иконок, что refreshBtn/ctaBtn на PageConnectTribe.
        Rectangle {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 72; Layout.preferredHeight: 72
            radius: Theme.radius.pill
            color: Theme.color.surface1
            border.width: 1; border.color: Theme.color.border2
            Shape {
                anchors.centerIn: parent
                width: 32; height: 32
                transform: Scale { xScale: 32 / 24; yScale: 32 / 24 }
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.accent; fillColor: "transparent"; strokeWidth: 1.8
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M21 15 v4 a2 2 0 0 1 -2 2 H5 a2 2 0 0 1 -2 -2 v-4 M7 10 L12 15 L17 10 M12 15 V3" }
                }
            }
        }

        Text {
            Layout.fillWidth: true
            text: qsTr("Обновите приложение")
            color: Theme.color.text1
            font.family: Theme.font.display
            font.pixelSize: Theme.font.h1
            font.weight: Theme.font.wBold
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }
        Text {
            Layout.fillWidth: true
            text: qsTr("Эта версия больше не поддерживается. Установите свежую версию, чтобы продолжить пользоваться Tribe VPN.")
            color: Theme.color.text2
            font.family: Theme.font.body
            font.pixelSize: Theme.font.bodyM
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        TribeButton {
            Layout.fillWidth: true
            Layout.topMargin: Theme.space.sm
            variant: "primary"
            text: qsTr("Обновить")
            onClicked: {
                var url = (typeof TribeEngine !== "undefined") ? TribeEngine.storeUrl : ""
                if (url) Qt.openUrlExternally(url)
            }
        }
    }
}

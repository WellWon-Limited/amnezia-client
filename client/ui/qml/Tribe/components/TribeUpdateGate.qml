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
            // Back/Escape while the block is up: PageController::keyPressEvent does
            //     if (m_drawerDepth) { emit closeTopDrawer(); decrementDrawerDepth(); }
            // — this slot runs SYNCHRONOUSLY inside `emit`, BEFORE the pending decrement. So at
            // this instant m_drawerDepth is still the mount value and getDrawerDepth() === depthIndex.
            // We re-increment EXACTLY ONCE to cancel the decrement that keyPressEvent runs right after
            // → net zero per Back press: m_drawerDepth stays pinned at the mount value, the gate
            // remains the top drawer forever, and depth never falls to 0 (so the else-branch
            // escapePressed()/minimize is never reached). The block is truly un-escapable.
            //
            // CRITICAL: do NOT assign the return value back to depthIndex. depthIndex must stay pinned
            // at the mount value so the guard below holds on EVERY press. (The previous code did
            // `depthIndex = incrementDrawerDepth()`, which grew depthIndex while m_drawerDepth was
            // pinned → after 2 presses the guard went false, depth drifted to 0, and press #3
            // escaped the gate. That was the bug.)
            if (gate.depthIndex === PageController.getDrawerDepth())
                PageController.incrementDrawerDepth()   // discard return — depthIndex stays pinned
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

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

    // AVPN (реш. владельца 2026-09-02): содержимое вынесено в TribeUpdateSheet — один экран
    // обновления на все случаи (обязательное и мягкое), тексты и список пунктов server-driven.
    TribeUpdateSheet {
        id: sheet
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.space.xl
        mode: "blocking"
        busy: gate.installing
        busyText: gate.installText
        errorText: gate.installError
        onUpdateRequested: gate.startUpdate()
    }

    // Установка внутри приложения есть только на десктопном macOS (там мы сами шипим .dmg).
    // На остальных платформах кнопка ведёт в стор/на страницу загрузки, как раньше.
    property bool installing: false
    property string installText: ""
    property string installError: ""

    function startUpdate() {
        gate.installError = ""
        if (typeof TribeEngine !== "undefined" && TribeEngine.canSelfUpdate === true) {
            gate.installing = true
            gate.installText = qsTr("Скачиваем и проверяем подпись…")
            TribeEngine.startSelfUpdate()
            return
        }
        var url = (typeof TribeEngine !== "undefined") ? TribeEngine.storeUrl : ""
        if (url) Qt.openUrlExternally(url)
    }

    Connections {
        target: (typeof TribeEngine !== "undefined") ? TribeEngine : null
        ignoreUnknownSignals: true
        function onSelfUpdateProgress(text) { gate.installText = text }
        function onSelfUpdateFailed(reason) {
            gate.installing = false
            gate.installText = ""
            gate.installError = reason && reason.length > 0
                    ? reason : qsTr("Не удалось обновить. Попробуйте скачать вручную.")
        }
    }
}

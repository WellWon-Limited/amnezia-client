import QtQuick
import QtQuick.Controls

import ".."   // Theme

// AVPN: switch. 46×26, off surface3 → on accent, knob 20.
// ready-гард: первичная установка позиции/цвета индикатора (включая дефолт-checked при появлении
// на экране / смене вкладки) НЕ анимируется — Behaviors включаются только после первого кадра.
// Так «анимация включения» играет ИСКЛЮЧИТЕЛЬНО на пользовательское переключение, а не при заходе
// на вкладку Анти-VPN (баг: тумблер «сам включался» визуально). // AVPN
Switch {
    id: control
    implicitWidth: 46
    implicitHeight: 26

    // взводится через короткий таймер после построения + первой раскладки (ширина уже известна) →
    // гасит анимацию при первом показе. Timer надёжнее onCompleted (тот срабатывает до layout,
    // и settling ширины/checked в первом кадре всё равно дёрнул бы Behavior). // AVPN
    property bool animReady: false
    Component.onCompleted: readyTimer.start()
    Timer { id: readyTimer; interval: 60; onTriggered: control.animReady = true }

    indicator: Rectangle {
        width: control.width; height: control.height
        radius: height / 2
        color: control.checked ? Theme.color.accent : Theme.color.surface3
        Behavior on color { enabled: control.animReady; ColorAnimation { duration: 180 } }

        Rectangle {
            width: 20; height: 20; radius: 10
            color: "white"
            y: 3
            x: control.checked ? control.width - width - 3 : 3
            Behavior on x { enabled: control.animReady; NumberAnimation { duration: 180; easing.type: Easing.OutCubic } }
        }
    }
    contentItem: Item {}   // label handled externally (in list rows)
}

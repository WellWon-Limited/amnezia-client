// AVPN (haptics, спека 2026-07-11): тонкая QML-обёртка над C++ мостом TribeHaptics
// (context property из coreController). Гард typeof: в dev-превью со старым бинарём и в
// сборках без AVPN_ENGINE моста нет — отклик тихо пропускается.
// Виды: selection | light | medium | success | warning | error (карта — в спеке).
//
// arm()/playArmed(): гард «жужжания из фона». Терминальные отклики смены состояния
// (connected/disconnected/error) играются ТОЛЬКО если недавно (≤30 с) было действие
// пользователя (тап по орбу / выбор сервера) И приложение активно. Автофейловер и
// фоновые реконнекты — беззвучны.
pragma Singleton
import QtQuick

QtObject {
    property double _armedTs: 0

    function play(kind) {
        if (typeof TribeHaptics !== "undefined")
            TribeHaptics.play(kind)
    }

    // взводится тапом по орбу / сервером в пикере — «жду терминального перехода»
    function arm() { _armedTs = Date.now() }

    // терминальный переход состояния: играет один раз и только если взведено и app активно
    function playArmed(kind) {
        if (_armedTs <= 0 || Date.now() - _armedTs > 30000) return
        _armedTs = 0
        if (Qt.application.state !== Qt.ApplicationActive) return
        play(kind)
    }
}

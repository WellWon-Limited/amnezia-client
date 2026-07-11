// AVPN (haptics, спека 2026-07-11): тонкая QML-обёртка над C++ мостом TribeHaptics
// (context property из coreController). Единственная задача — гард typeof: в dev-превью
// со старым бинарём и в сборках без AVPN_ENGINE моста нет, отклик тихо пропускается.
// Виды: selection | light | medium | success | warning | error (карта — в спеке).
pragma Singleton
import QtQuick

QtObject {
    function play(kind) {
        if (typeof TribeHaptics !== "undefined")
            TribeHaptics.play(kind)
    }
}

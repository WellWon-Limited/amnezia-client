// AVPN (Task E) — реализация моста-консьюмера «намерений» App Intent авто-паузы. См. AvpnIntentBridge.h.
#include "AvpnIntentBridge.h"

#include <QMetaObject>
#include <QtGlobal> // Q_OS_IOS — выбор платформенной vs no-op реализации Avpn_consumeIntentFlags

namespace avpn {

AvpnIntentBridge::AvpnIntentBridge(QObject *parent) : QObject(parent) {}

AvpnIntentBridge *AvpnIntentBridge::instance()
{
    // Один экземпляр, живёт в Qt-главном потоке (создаётся из coreController).
    static AvpnIntentBridge *s_instance = new AvpnIntentBridge();
    return s_instance;
}

void AvpnIntentBridge::requestPause()
{
    // Маршалим в Qt-поток: сигнал может прилететь из натив-потока (хотя на iOS зовут из main).
    QMetaObject::invokeMethod(
        this, [this]() { emit pauseRequested(); }, Qt::QueuedConnection);
}

void AvpnIntentBridge::requestResume()
{
    QMetaObject::invokeMethod(
        this, [this]() { emit resumeRequested(); }, Qt::QueuedConnection);
}

} // namespace avpn

// На iOS реальная реализация Avpn_consumeIntentFlags() живёт в платформенном AvpnIntentController.mm
// (читает App Group NSUserDefaults). Здесь — кросс-платформенная заглушка для desktop/Android, где
// App Group нет: ничего не читаем, мост молчит. Через Q_OS_IOS, чтобы не было двойного определения.
#ifndef Q_OS_IOS
extern "C" void Avpn_consumeIntentFlags(void)
{
    // no-op: App Group (iOS NSUserDefaults suite) недоступен вне iOS.
}
#endif

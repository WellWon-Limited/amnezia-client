// AVPN (Task E) — мост-консьюмер «намерений» App Intent авто-паузы (Task 8) → движок.
//
// Сценарий: фоновый iOS App Intent (AvpnAppIntents.swift) не может позвать Q_INVOKABLE движка
// напрямую (Qt event loop в фоне не крутится). Поэтому интент пишет «намерение» в App Group
// UserDefaults(suiteName:"group.hk.wellwon.tribe") (ключи AvpnIntent/pauseRequested,
// AvpnIntent/resumeRequested, AvpnIntent/lastActionAt) и реально опускает/поднимает туннель сам.
// Движок согласует своё состояние (m_paused/failover) ПОЗЖЕ — когда приложение выходит в foreground.
//
// Этот мост — точка такого согласования. Натив-слой (iOS: QtAppDelegate.mm
// applicationDidBecomeActive → Avpn_consumeIntentFlags() → AvpnIntentController.mm читает App Group)
// дёргает СТАТИЧЕСКИЙ instance() из любого потока и эмитит pauseRequested()/resumeRequested(),
// маршаля в Qt-поток через QMetaObject::invokeMethod(Qt::QueuedConnection). AvpnEngineQml в
// конструкторе connect-ится к этим сигналам и зовёт pauseForShopping()/resumeFromPause().
//
// Почему отдельный мост, а не singleton-движок: AvpnEngineQml НЕ singleton (создаётся в coreController
// с зависимостями VpnConnection/store/NAM), и звать его методы из натив-потока небезопасно. Мост —
// потокобезопасный посредник.
//
// Overlay: апстрим не трогаем. На desktop App Group нет — consume-функция no-op, мост молчит.
#pragma once

#include <QObject>

namespace avpn {

class AvpnIntentBridge : public QObject {
    Q_OBJECT

public:
    static AvpnIntentBridge *instance();

    // Натив-слой (iOS), потокобезопасно (маршалят в Qt-поток). Зовётся из AvpnIntentController.mm
    // после чтения App Group: интент попросил паузу «для покупок» / выход из паузы.
    void requestPause();
    void requestResume();

signals:
    // AVPN (Task E): coreController/движок связывает это с AvpnEngineQml::pauseForShopping()
    // и resumeFromPause(), чтобы m_paused/failover совпали с тем, что интент уже сделал с туннелем.
    void pauseRequested();
    void resumeRequested();

private:
    explicit AvpnIntentBridge(QObject *parent = nullptr);
};

} // namespace avpn

// C-вход для ObjC++ (QtAppDelegate.mm applicationDidBecomeActive) — вызывается из main-потока iOS.
// Читает флаги App Group через AvpnIntentController.mm и эмитит сигналы моста; затем сбрасывает флаги.
// На desktop — no-op (App Group нет).
extern "C" void Avpn_consumeIntentFlags(void);

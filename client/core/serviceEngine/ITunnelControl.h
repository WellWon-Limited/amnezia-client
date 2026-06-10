// AVPN serviceEngine — граница с туннелем. Реализуется per-platform поверх ШТАТНОГО awg форка
// (desktop: daemon switchServer/updatePeer; iOS: WireGuardAdapter.update via sendProviderMessage;
//  android: JNI set/syncconf — см. план §6.4). Движок один, платформо-зависим только этот интерфейс.
#pragma once

#include "dto/Subscription.h"
#include <QString>

namespace avpn {

struct TunnelStats {
    qint64 latestHandshakeEpoch = 0;   // unix sec последнего хендшейка (0 = не было)
    qint64 rxBytes = 0;
    qint64 txBytes = 0;
    bool   valid = false;
};

struct TunnelResult {
    bool ok = false;
    QString error;
    static TunnelResult success() { return {true, {}}; }
    static TunnelResult fail(const QString &e) { return {false, e}; }
};

class ITunnelControl {
public:
    virtual ~ITunnelControl() = default;

    // Первый коннект к ноде (поднять tun + пир).
    virtual TunnelResult up(const Subscription &sub, const SubscriptionNode &node) = 0;

    // In-place peer swap БЕЗ пересоздания tun (быстрый reconnect). На стабильном /32 адрес не меняется.
    virtual TunnelResult applyPeer(const Subscription &sub, const SubscriptionNode &node) = 0;

    // Снять рантайм-статы (handshake age + rx/tx) для HealthLoop.
    virtual TunnelStats readStats() = 0;

    virtual void down() = 0;
};

} // namespace avpn

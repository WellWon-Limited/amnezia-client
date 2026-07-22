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

// Хелперы наполнения TunnelStats (ИНЦИДЕНТ 2026-07-11 «сам отключился и переподключился»):
// ложный DEAD HealthLoop сразу после коннекта → failover-ротация без действий юзера.
//
// 1) bytesChanged на ВСЕХ платформах несёт ДЕЛЬТЫ за период (vpnProtocol::setBytesChanged эмитит
//    diff, ios_controller.mm::checkStatus — тоже), а HealthLoop ждёт КУМУЛЯТИВЫ (rxStuck/txGrew
//    сравнивают соседние замеры). Прямая запись дельт делала «ровный rx-поток» (равные дельты)
//    неотличимым от «rx стоит» → аккумулируем.
//    Guard: абсурдный скачок (>1 ТБ за тик) = артефакт гонки счётчиков (iOS: стейл-ответ
//    checkStatus старой сессии перезаписал m_rxBytes → quint64-underflow «дельта» ~2^64) —
//    игнорируем, счётчики не портим (TDD: parse_check «tunnelstats-guard»).
inline void accumulateByteDelta(TunnelStats &s, quint64 rxDelta, quint64 txDelta)
{
    constexpr quint64 kAbsurdDelta = Q_UINT64_C(1) << 40; // 1 ТБ/тик — физически невозможно
    if (rxDelta < kAbsurdDelta)
        s.rxBytes += static_cast<qint64>(rxDelta);
    if (txDelta < kAbsurdDelta)
        s.txBytes += static_cast<qint64>(txDelta);
    s.valid = true;
}

// 2) возраст хендшейка: 0 = «НЕИЗВЕСТНО», а не «не было» — iOS шлёт handshakeChanged(0) до первого
//    отчёта wireguard-go даже на живом туннеле; нулём известное значение НЕ затираем (иначе
//    hsStale в HealthLoop защёлкивался в true в первые секунды после Connected).
//    Вызывающий на Connected сеет epoch≈now (паритет с desktop-UAPI: данные текут ⇒ handshake
//    только что состоялся) — это даёт естественный грейс maxAgeSec после подъёма туннеля.
inline void updateHandshakeEpoch(TunnelStats &s, qint64 hsEpochSec)
{
    if (hsEpochSec > 0)
        s.latestHandshakeEpoch = hsEpochSec;
}

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

    // AVPN (BUG-4 auto-heal, 2026-07-22): пересоздать UDP-сокет туннеля с НОВЫМ эфемерным
    // локальным портом (UAPI `listen_port=0` → BindUpdate в awg-go) БЕЗ рестарта туннеля.
    // Новый 5-tuple flow — эквивалент режима полёта: лечит сессионный блок ТСПУ по flow/CGNAT
    // (BUG-4: два телефона одного оператора, один жив, второй мёртв, режим полёта чинит).
    // true = команда отправлена (асинхронно; итог виден HealthLoop'у — rx/handshake оживут
    // или DEAD придёт снова); false = платформа примитива не имеет → сразу failover.
    virtual bool rebindSocket() { return false; }

    virtual void down() = 0;
};

} // namespace avpn

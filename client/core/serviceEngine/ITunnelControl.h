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
    // AVPN (iOS, awg-apple tribe.17, device round 24.11 B1): the extension's stall verdict (status `data_stall_s`):
    // while its stall ladder sees a stall right now, how long the path has gone without data that proved it; 0 = not
    // stalled now. -1 = unknown: every other platform, an extension before tribe.17, Xray. `dataStallAtMs` = when the
    // reply was applied (wall clock, ms; a reading is used only while fresh). Read only by the AmneziaWG probe rule.
    qint64 dataStallSec = -1;
    qint64 dataStallAtMs = 0;
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


    // Снять рантайм-статы (handshake age + rx/tx) для HealthLoop.
    virtual TunnelStats readStats() = 0;

    // AVPN (BUG-4 auto-heal, 2026-07-22): пересоздать UDP-сокет туннеля с НОВЫМ эфемерным
    // локальным портом (UAPI `listen_port=0` → BindUpdate в awg-go) БЕЗ рестарта туннеля.
    // Новый 5-tuple flow — эквивалент режима полёта: лечит сессионный блок ТСПУ по flow/CGNAT
    // (BUG-4: два телефона одного оператора, один жив, второй мёртв, режим полёта чинит).
    // true = команда отправлена (асинхронно; итог виден HealthLoop'у — rx/handshake оживут
    // или DEAD придёт снова); false = платформа примитива не имеет → сразу failover.
    // AVPN (фикс-волна 2026-09-22, K4/B7): iOS/MACOS_NE — «отправлена» ≠ «сделана»: NE отвечает
    // {"rebind":"performed"|"denied"}, IosController эмитит rebindFinished(bool), фасад передаёт
    // в ServiceEngine::onRebindResult — отказ пропускает шаг rebind на следующем DEAD.
    // GAP-2: причина отказа ("reason") доходит до onRebindResult(performed, reason); "offline"
    // (путь NE unsatisfied) — ожидание сети, а не провал шага (попытка не тратится).
    virtual bool rebindSocket() { return false; }

    virtual void down() = 0;

    // The native start will never happen for the leg that asked for it (Android: the person refused the VPN
    // permission): anything the adapter holds for it (a provider seat) goes back now - down() would wait for a stop
    // that never comes. Default: nothing held.
    virtual void startRefused() {}

    // Did the start of the provider leg that is running actually put anything on the network - a lease request or the
    // native start? A leg that ends without it (held by our own bookkeeping, refused locally, cancelled before the
    // start) says nothing about the path and is never recorded against it (review S3 of device round 10).
    // Default: yes (an own path's start is the up() call itself).
    virtual bool upstreamRequestSent() const { return true; }

    // Path engine (review E2 of 18.11): the native layer reports without a stamp, so the leg travels through the
    // native stream itself. beginNativeOp(leg) is called right before that leg's native start; the adapter puts a
    // marker into the native event stream ahead of the start, and nativeLegSeen() is the leg of the last marker
    // that came back - every native event delivered after it (and before the next one) belongs to that leg.
    // adoptNativeOp(leg): a tunnel this process did not start (adopted) - its events are that leg's at once.
    // Default (no native stream, tests): the marker is seen at once.
    // Legs are numbered upwards, so a marker that comes back late never moves the stream back.
    virtual void beginNativeOp(quint64 leg) { noteNativeLegSeen(leg); }
    virtual void adoptNativeOp(quint64 leg) { noteNativeLegSeen(leg); }
    quint64 nativeLegSeen() const { return m_nativeLegSeen; }

protected:
    void noteNativeLegSeen(quint64 leg) { m_nativeLegSeen = leg > m_nativeLegSeen ? leg : m_nativeLegSeen; }
    quint64 m_nativeLegSeen = 0;
};

} // namespace avpn

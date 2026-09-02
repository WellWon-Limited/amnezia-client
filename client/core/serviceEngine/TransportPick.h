// AVPN serviceEngine — выбор транспорта внутри локации (волна awg31-xray-v1, спека 2026-09-01
// §2.3 «Выбор транспорта (Auto)»). [чистая логика — только QtCore, тест tests/transport_pick_check.cpp]
//
// Модель: ЛОКАЦИЯ = листенеры одного хоста (NodeRotation.h::locationKeyOf). Порядок выбора:
//   1. локация — по измеренному off-tunnel RTT (кэш probeNodeRtt; минимум по нодам локации),
//      без замеров — верхний ярус по backend-weight (случайно среди равных, как pickByWeight);
//   2. транспорт внутри локации — серверный transport_rank (меньше = раньше; дефолт AWG 10 /
//      Xray 20 — «по умолчанию Amnezia», решение владельца) с поправкой на ЛОКАЛЬНУЮ ИСТОРИЮ
//      (TransportHistory: EWMA успеха и времени до «реального трафика» по паре локация×proto;
//      провальный транспорт демоутится, но не исключается — сервер всегда может вернуть его рангом);
//   3. при провале data-plane (verify/DEAD/probe) — другой транспорт ТОЙ ЖЕ локации (excluded =
//      провалившиеся в этой сессии), потом соседняя локация.
// Ручной режим (TransportMode::Awg/Xray) — hard-filter по proto. Kill-switch'и
// features.xray_client / features.transport_auto_pick — в NodeRotation.h (isAutoEligibleNode).
// Без I/O: только уже накопленный кэш RTT (CONNECT-INVARIANTS §1).
#pragma once

#include "NodeRotation.h"
#include "dto/Subscription.h"

#include <QByteArray>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <functional>

namespace avpn {

// История одной пары локация×транспорт. -1 = данных нет.
struct TransportHistoryEntry {
    double successEwma = -1.0; // 0..1: доля успешных подъёмов (EWMA, свежее весит больше)
    double ttfMsEwma = -1.0;   // время до «реального трафика» (Connected/verify), мс (EWMA)
    int    samples = 0;
    qint64 lastMs = 0;         // epoch ms последней записи (для вытеснения старых)
};

// Персистентная (через фасад: QSettings avpn/transportHistory) локальная история транспортов.
// Все входы клампятся: EWMA в [0,1] / [0,kMaxTtfMs], samples ≤ kMaxSamples, записей ≤ kMaxEntries
// (вытесняется самая старая) — стейл/битый JSON из настроек не может испортить выбор.
class TransportHistory {
public:
    static constexpr double kAlpha = 0.3;          // вес свежего сэмпла
    static constexpr int    kMaxEntries = 64;
    static constexpr int    kMaxSamples = 1000;
    static constexpr double kMaxTtfMs = 120000.0;
    // Демоушен: успех EWMA ниже порога при >=2 сэмплах → ранг +kDemoteRank (уходит ниже любого
    // серверного ранга, но остаётся кандидатом — «сервер всегда может вернуть»).
    static constexpr double kDemoteBelow = 0.5;
    static constexpr int    kDemoteRank = 100;
    static constexpr int    kDemoteMinSamples = 2;

    static QString key(const QString &location, const QString &proto)
    {
        return location + QLatin1Char('|') + proto;
    }

    void record(const QString &location, const QString &proto, bool ok, int ttfMs, qint64 nowMs)
    {
        if (location.isEmpty() || proto.isEmpty())
            return;
        TransportHistoryEntry &e = m_entries[key(location, proto)];
        const double s = ok ? 1.0 : 0.0;
        e.successEwma = (e.successEwma < 0.0) ? s : (kAlpha * s + (1.0 - kAlpha) * e.successEwma);
        e.successEwma = qBound(0.0, e.successEwma, 1.0);
        if (ok && ttfMs >= 0) {
            const double t = qBound(0.0, double(ttfMs), kMaxTtfMs);
            e.ttfMsEwma = (e.ttfMsEwma < 0.0) ? t : (kAlpha * t + (1.0 - kAlpha) * e.ttfMsEwma);
        }
        e.samples = qMin(e.samples + 1, kMaxSamples);
        e.lastMs = nowMs;
        evictIfNeeded();
    }

    TransportHistoryEntry entry(const QString &location, const QString &proto) const
    {
        return m_entries.value(key(location, proto));
    }
    bool has(const QString &location, const QString &proto) const
    {
        return m_entries.contains(key(location, proto));
    }
    int size() const { return m_entries.size(); }
    void clear() { m_entries.clear(); }

    // Поправка к transport_rank по истории: 0 = нет данных/транспорт здоров.
    int rankPenalty(const QString &location, const QString &proto) const
    {
        const TransportHistoryEntry e = entry(location, proto);
        if (e.samples >= kDemoteMinSamples && e.successEwma >= 0.0 && e.successEwma < kDemoteBelow)
            return kDemoteRank;
        return 0;
    }

    QJsonObject toJson() const
    {
        QJsonObject o;
        for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
            QJsonObject e;
            e.insert(QStringLiteral("s"), it.value().successEwma);
            e.insert(QStringLiteral("t"), it.value().ttfMsEwma);
            e.insert(QStringLiteral("n"), it.value().samples);
            e.insert(QStringLiteral("ts"), double(it.value().lastMs));
            o.insert(it.key(), e);
        }
        return o;
    }

    static TransportHistory fromJson(const QJsonObject &o)
    {
        TransportHistory h;
        for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
            if (!it.value().isObject() || !it.key().contains(QLatin1Char('|')))
                continue;
            const QJsonObject e = it.value().toObject();
            TransportHistoryEntry x;
            const double s = e.value(QStringLiteral("s")).toDouble(-1.0);
            x.successEwma = (s < 0.0) ? -1.0 : qBound(0.0, s, 1.0);
            const double t = e.value(QStringLiteral("t")).toDouble(-1.0);
            x.ttfMsEwma = (t < 0.0) ? -1.0 : qBound(0.0, t, kMaxTtfMs);
            x.samples = qBound(0, e.value(QStringLiteral("n")).toInt(0), kMaxSamples);
            x.lastMs = qMax<qint64>(0, qint64(e.value(QStringLiteral("ts")).toDouble(0.0)));
            h.m_entries.insert(it.key(), x);
        }
        h.evictIfNeeded();
        return h;
    }

    QByteArray serialize() const { return QJsonDocument(toJson()).toJson(QJsonDocument::Compact); }
    static TransportHistory deserialize(const QByteArray &bytes)
    {
        const QJsonDocument doc = QJsonDocument::fromJson(bytes);
        return doc.isObject() ? fromJson(doc.object()) : TransportHistory{};
    }

private:
    void evictIfNeeded()
    {
        while (m_entries.size() > kMaxEntries) {
            QString oldestKey;
            qint64 oldest = 0;
            for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
                if (oldestKey.isEmpty() || it.value().lastMs < oldest) {
                    oldestKey = it.key();
                    oldest = it.value().lastMs;
                }
            }
            m_entries.remove(oldestKey);
        }
    }

    QHash<QString, TransportHistoryEntry> m_entries;
};

struct TransportPickInput {
    TransportMode mode = TransportMode::Auto;
    QString exclA, exclB;         // как у pickBy*: мёртвая/текущая нода
    QSet<QString> excluded;       // провалившиеся в этой сессии (nodeId) — failover не ходит по кругу
    QString preferLocation;       // pin по локации: кандидаты ТОЛЬКО из неё (пусто = все локации)
    QString preferNodeId;         // tie-break внутри локации (сам закреплённый/случайно выбранный узел)
};

namespace detail {

struct TransportCand {
    const SubscriptionNode *node = nullptr;
    int    effRank = 0;
    double ttf = -1.0;
    int    rtt = -1;
};

inline bool candLess(const TransportCand &a, const TransportCand &b, const QString &preferNodeId)
{
    if (a.effRank != b.effRank)
        return a.effRank < b.effRank;
    // известное время до трафика раньше неизвестного; меньшее — раньше
    const bool at = a.ttf >= 0.0, bt = b.ttf >= 0.0;
    if (at != bt)
        return at;
    if (at && a.ttf != b.ttf)
        return a.ttf < b.ttf;
    const bool ap = (a.node->nodeId == preferNodeId), bp = (b.node->nodeId == preferNodeId);
    if (ap != bp)
        return ap;
    const bool ar = a.rtt >= 0, br = b.rtt >= 0;
    if (ar != br)
        return ar;
    if (ar && a.rtt != b.rtt)
        return a.rtt < b.rtt;
    if (a.node->weight != b.node->weight)
        return a.node->weight > b.node->weight;
    return a.node->nodeId < b.node->nodeId;
}

} // namespace detail

// Лучший транспорт внутри одной локации: transport_rank + демоушен по истории → EWMA времени до
// трафика → предпочтённый узел → измеренный RTT → weight → nodeId. nullptr при пустом входе.
inline const SubscriptionNode *bestInLocation(const QList<const SubscriptionNode *> &loc,
                                              const QHash<QString, int> &rtt,
                                              const TransportHistory &hist,
                                              const QString &preferNodeId = QString())
{
    QList<detail::TransportCand> cands;
    for (const SubscriptionNode *n : loc) {
        if (!n)
            continue;
        detail::TransportCand c;
        c.node = n;
        const QString locKey = locationKeyOf(*n);
        c.effRank = n->transportRank + hist.rankPenalty(locKey, protoOf(*n));
        c.ttf = hist.entry(locKey, protoOf(*n)).ttfMsEwma;
        c.rtt = rtt.value(n->nodeId, -1);
        cands.append(c);
    }
    if (cands.isEmpty())
        return nullptr;
    std::sort(cands.begin(), cands.end(), [&](const detail::TransportCand &a, const detail::TransportCand &b) {
        return detail::candLess(a, b, preferNodeId);
    });
    return cands.first().node;
}

// Транспорты (proto), представленные в локации среди живых нод — для бейджей пикера. Порядок —
// по transport_rank (AWG раньше Xray при дефолтных рангах), без дублей.
inline QStringList locationTransports(const QList<SubscriptionNode> &nodes, const QString &locKey)
{
    QList<const SubscriptionNode *> loc;
    for (const SubscriptionNode &n : nodes)
        if (locationKeyOf(n) == locKey && healthAggregate(n) > 0.0)
            loc.append(&n);
    std::sort(loc.begin(), loc.end(), [](const SubscriptionNode *a, const SubscriptionNode *b) {
        if (a->transportRank != b->transportRank)
            return a->transportRank < b->transportRank;
        return a->nodeId < b->nodeId;
    });
    QStringList out;
    for (const SubscriptionNode *n : loc)
        if (!out.contains(protoOf(*n)))
            out << protoOf(*n);
    return out;
}

// Полный выбор (см. шапку файла). pickIndex(size) — выбор индекса в ярусе равного weight
// (по умолчанию первый; движок передаёт QRandomGenerator — «авто реально чередует равноценные»).
// preferLocation задан → ТОЛЬКО эта локация (manual_only в ней разрешён — это pin), nullptr если в
// ней нет кандидатов (вызывающий падает в общий выбор). Иначе — два яруса (regular, manual-фолбэк),
// локация по RTT → weight, транспорт — bestInLocation.
inline const SubscriptionNode *pickTransportNode(const QList<SubscriptionNode> &nodes,
                                                 const QHash<QString, int> &rtt,
                                                 const TransportHistory &hist,
                                                 const TransportPickInput &in,
                                                 const std::function<int(int)> &pickIndex = {})
{
    QList<const SubscriptionNode *> eligible;
    for (const SubscriptionNode &n : nodes) {
        if (!in.exclA.isEmpty() && n.nodeId == in.exclA)
            continue;
        if (!in.exclB.isEmpty() && n.nodeId == in.exclB)
            continue;
        if (in.excluded.contains(n.nodeId))
            continue;
        if (!isSupportedProtoNode(n))
            continue;              // только реально поднимаемые протоколы (xray: гейт+kill-switch)
        if (!transportAllowed(n, in.mode))
            continue;
        // Авто-режим без pin — xray под kill-switch transport_auto_pick; ручной режим и pin —
        // явная воля пользователя, рубильник автоматики их не касается.
        if (in.mode == TransportMode::Auto && in.preferLocation.isEmpty() && !isAutoEligibleNode(n))
            continue;
        if (healthAggregate(n) <= 0.0)
            continue;
        eligible.append(&n);
    }
    if (eligible.isEmpty())
        return nullptr;

    if (!in.preferLocation.isEmpty()) {
        QList<const SubscriptionNode *> loc;
        for (const SubscriptionNode *n : eligible)
            if (locationKeyOf(*n) == in.preferLocation)
                loc.append(n);
        return bestInLocation(loc, rtt, hist, in.preferNodeId);
    }

    // Ярусы: regular (не manual_only) — основной; manual_only (вкл. RU) — только если regular пуст
    // (§14.3: мягкий fallback обязателен, иначе смерть failover).
    QList<const SubscriptionNode *> tier;
    for (const SubscriptionNode *n : eligible)
        if (!isManualOnlyNode(*n))
            tier.append(n);
    if (tier.isEmpty())
        tier = eligible;

    // Группировка по локации (порядок появления — стабильность выбора при равенстве).
    QStringList order;
    QHash<QString, QList<const SubscriptionNode *>> byLoc;
    for (const SubscriptionNode *n : tier) {
        const QString key = locationKeyOf(*n);
        if (!byLoc.contains(key))
            order << key;
        byLoc[key].append(n);
    }

    // 1) локация по минимальному измеренному RTT
    QString bestLoc;
    int bestRtt = -1;
    for (const QString &key : order) {
        for (const SubscriptionNode *n : byLoc.value(key)) {
            const int r = rtt.value(n->nodeId, -1);
            if (r < 0)
                continue;
            if (bestRtt < 0 || r < bestRtt) {
                bestRtt = r;
                bestLoc = key;
            }
        }
    }
    if (!bestLoc.isEmpty())
        return bestInLocation(byLoc.value(bestLoc), rtt, hist, in.preferNodeId);

    // 2) фолбэк: верхний ярус по weight (случайно среди равных → его локация)
    QList<const SubscriptionNode *> top;
    double maxW = -1.0;
    for (const SubscriptionNode *n : tier) {
        if (n->weight > maxW + 1e-9) {
            maxW = n->weight;
            top.clear();
            top.append(n);
        } else if (n->weight >= maxW - 1e-9) {
            top.append(n);
        }
    }
    if (top.isEmpty())
        return nullptr;
    int idx = 0;
    if (top.size() > 1 && pickIndex)
        idx = qBound(0, pickIndex(int(top.size())), int(top.size()) - 1);
    const SubscriptionNode *chosen = top.at(idx);
    return bestInLocation(byLoc.value(locationKeyOf(*chosen)), rtt, hist,
                          in.preferNodeId.isEmpty() ? chosen->nodeId : in.preferNodeId);
}

} // namespace avpn

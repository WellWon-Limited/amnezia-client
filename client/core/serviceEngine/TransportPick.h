// AVPN serviceEngine - locations x transports for the picker's badges, and the exit RTT of an Xray listener for the
// bars and the Doctor's alternatives (decision 2026-11-05). [pure, QtCore]
// The choice of a path is the path engine's (path/PathSelect.h through path/AttemptOwner.h): the RTT orders nothing
// there. The transport history and the location picker that lived here were removed with it (design 2026-11-17 §7).
#pragma once

#include "ConnectTunables.h"
#include "NodeRotation.h"
#include "dto/Subscription.h"

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

#include <algorithm>

namespace avpn {

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

// RTT of a node's EXIT host (decision 2026-11-05 after the owner test of 5.1.102). The off-tunnel
// ICMP of an Xray listener measures the RU entry that relays every listener (~14 ms for all of
// them), not its exit; the exit of a listener is the host it shares with an AWG node (location =
// host_id). So: a non-Xray node - its own measured RTT; an Xray listener - the min measured RTT
// of a non-Xray node on the same location. Absent = unknown. Upstream Amnezia does not rank
// servers at all (the choice is manual) - this lives only in our ranking layer.
inline QHash<QString, int> exitRtt(const QList<SubscriptionNode> &nodes, const QHash<QString, int> &measured)
{
    QHash<QString, int> byLocation;
    for (const SubscriptionNode &n : nodes) {
        const int r = measured.value(n.nodeId, -1);
        if (isXrayProto(n.proto) || r < 0)
            continue;
        const QString key = locationKeyOf(n);
        if (!byLocation.contains(key) || r < byLocation.value(key))
            byLocation.insert(key, r);
    }
    QHash<QString, int> out;
    for (const SubscriptionNode &n : nodes) {
        const int r = isXrayProto(n.proto) ? byLocation.value(locationKeyOf(n), -1) : measured.value(n.nodeId, -1);
        if (r >= 0)
            out.insert(n.nodeId, r);
    }
    return out;
}

// RTT for every "fastest" decision (automatic location, failover, Doctor alternatives): the exit
// RTT; an Xray listener without a measured exit ranks as its own (entry) RTT + penaltyMs
// (ConnectTunables.h::xrayExitRttPenaltyMsTuned) and never ahead of any measured exit
// (max(entry + penalty, worst measured exit + 1)): a listener never wins on the shared entry, and
// two listeners tie only when neither exit is measured (then the pool order decides, as for any
// equal RTT). Nodes without any measurement stay absent (unmeasured).
inline QHash<QString, int> rankingRtt(const QList<SubscriptionNode> &nodes, const QHash<QString, int> &measured,
                                      int penaltyMs)
{
    QHash<QString, int> out = exitRtt(nodes, measured);
    int worst = -1;
    for (auto it = out.constBegin(); it != out.constEnd(); ++it)
        worst = std::max(worst, it.value());
    for (const SubscriptionNode &n : nodes) {
        if (!isXrayProto(n.proto) || out.contains(n.nodeId))
            continue;
        const int entry = measured.value(n.nodeId, -1);
        if (entry >= 0)
            out.insert(n.nodeId, std::max(entry + std::max(0, penaltyMs), worst + 1));
    }
    return out;
}

// Ids ordered by ranking RTT: measured ascending, unmeasured last; equal values keep the input
// order (stable - the Doctor's alternatives queue and tests are deterministic).
inline QStringList orderByRankingRtt(const QStringList &ids, const QHash<QString, int> &rank)
{
    QStringList out = ids;
    std::stable_sort(out.begin(), out.end(), [&rank](const QString &a, const QString &b) {
        const int ra = rank.value(a, -1), rb = rank.value(b, -1);
        if ((ra < 0) != (rb < 0))
            return rb < 0;
        return ra >= 0 && ra < rb;
    });
    return out;
}

} // namespace avpn

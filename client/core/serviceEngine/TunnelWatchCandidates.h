// client/core/serviceEngine/TunnelWatchCandidates.h
//
// AVPN (iOS tunnel-side data watch, build 140, stage 2; design §5.3 and §0a item 8): the order in which the
// packet tunnel extension may switch to other nodes IN PLACE while the app sleeps. Pure: QtCore and the
// engine's own pick (TransportPick.h); test - tests/transport_pick_check.cpp.
//
// The order is the app's own failover ladder (ServiceEngine::onDead) with what the extension cannot do
// taken out:
//  * only AmneziaWG nodes: the extension cannot raise Xray in place (stage 3). The ladder's first step,
//    "another transport of the same location", therefore yields nothing here, and what is left is the
//    repeated pick of the best location with a growing list of exclusions;
//  * the transport mode in force: Xray-only - no candidates at all;
//  * never a manual-only node (the ladder keeps them as a last tier; a switch nobody watches does not);
//  * never a provider (upstream) node, whatever its transport: it runs on a seat lease that only the app
//    can take and renew (CONNECT-INVARIANTS 31), and a session that stands on one is not the watch's;
//  * never a node the server reports dead (pickTransportNode already skips health 0 - this is how a
//    drained node leaves), never one that already failed in this app session, never the current one.
// The pin. A pinned node that is proven dead is left - as the app's own ladder leaves it - but the
// candidates of the pinned COUNTRY come first, the rest only after them; the pin itself is never
// changed here (only a tap changes it). "Proven" is the extension's business: it switches only after
// a silent, undisturbed probe and its own same-node heals, on the network it judged.
#pragma once

#include "TransportPick.h"

#include <QHash>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

namespace avpn {

inline QStringList watchSwitchCandidateOrder(const QList<SubscriptionNode> &nodes, const QHash<QString, int> &rtt,
                                             const TransportHistory &hist, TransportMode mode,
                                             const QString &currentNodeId, const QString &pinCountry,
                                             const QSet<QString> &failedThisSession)
{
    QStringList out;
    if (mode == TransportMode::Xray)
        return out;
    const SubscriptionNode *current = nullptr;
    for (const SubscriptionNode &n : nodes)
        if (n.nodeId == currentNodeId)
            current = &n;
    if (!current || isXrayProto(current->proto) || isUpstreamNode(*current))
        return out; // the watch switches own AmneziaWG sessions only
    QList<SubscriptionNode> pool, pinned;
    for (const SubscriptionNode &n : nodes) {
        if (isXrayProto(n.proto) || isManualOnlyNode(n) || isUpstreamNode(n))
            continue;
        pool.append(n);
        if (!pinCountry.isEmpty() && n.countryCode == pinCountry)
            pinned.append(n);
    }
    const auto take = [&](const QList<SubscriptionNode> &from) {
        TransportPickInput in;
        in.mode = TransportMode::Awg;
        in.exclA = currentNodeId;
        in.excluded = failedThisSession;
        for (const QString &id : out)
            in.excluded.insert(id);
        while (const SubscriptionNode *c = pickTransportNode(from, rtt, hist, in)) {
            out.append(c->nodeId);
            in.excluded.insert(c->nodeId);
        }
    };
    take(pinned);
    take(pool);
    return out;
}

} // namespace avpn

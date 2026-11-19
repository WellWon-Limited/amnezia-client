// client/core/serviceEngine/EdgeWalk.h
// AVPN: чистая логика перебора фолбэк-входов control plane.
#pragma once
#include <QString>
#include <QtGlobal>
#include <QStringList>
#include <QUrl>

namespace avpn {

// R1a (device round 4, server-side finding): the API edge is a function of the route a request actually takes,
// evaluated for every request - never a sticky flag. From Russia any connection to the foreign edge (vpn.wellwon.hk)
// freezes after ~15 KB (a 29-52 KB seat answer stalled for 4 s; the server granted it in 20 ms), while through a
// tunnel whose exit is abroad the Russian entry (api.tribevpn.com) may be unreachable (a provider's exit times out on
// it). So:
//  - Direct: no tunnel carries the request now - the tunnel is down, a leg is being brought up (its seat request),
//    a release after a stop: the walk's direct edge, which starts every run at the Russian entry (the walk moves it
//    within the run only, as the fallback when that edge does not answer);
//  - Tunnel: a tunnel is up and in its carrying phase (being checked or connected) - its exit is abroad for every
//    tunnel we raise (our exits and the providers alike): the edge reachable from foreign exits.
// A pinned dev backend keeps its base for both. Empty result = the walk's direct edge.
enum class ApiRoute { Direct, Tunnel };

// 19.11.2026 (review of 141, R9): the fast failover (ConfigService, kFastEdgeFirstTryMs) leaves a silent edge after
// 2.5 s. One full round over all edges with no HTTP answer from any is evidence that the network cannot reach the API
// right now; after it the walk waits before the next round, the pause growing with every unsuccessful round
// (same shape as DataCheckRetry.h::dataCheckRetryDelayMs): base, 2*base, 4*base ... capped. Reset at once by any HTTP
// answer, a network change and the app coming to the foreground. Both numbers are server-driven
// (numbers.edge_round_pause_base_ms / edge_round_pause_cap_ms) next to edge_fail_threshold.
inline constexpr qint64 kEdgeRoundPauseBaseMs = 10000;
inline constexpr qint64 kEdgeRoundPauseCapMs = 120000;

// Pause after the n-th consecutive unsuccessful round (n >= 1).
inline qint64 edgeRoundPauseMs(int roundNumber, qint64 baseMs = kEdgeRoundPauseBaseMs,
                               qint64 capMs = kEdgeRoundPauseCapMs)
{
    const int n = qBound(1, roundNumber, 20);
    const qint64 base = qMax<qint64>(baseMs, 1);
    return qMin<qint64>(base << (n - 1), qMax<qint64>(capMs, base));
}
inline ApiRoute apiRouteNow(bool tunnelReportsConnected, bool engineCarrying)
{
    return tunnelReportsConnected && engineCarrying ? ApiRoute::Tunnel : ApiRoute::Direct;
}
inline QString apiSessionEdgeFor(ApiRoute route, bool pinned, const QString &abroadEdge)
{
    if (route == ApiRoute::Direct || pinned)
        return QString();
    return abroadEdge;
}

inline QString nextEdge(const QStringList &edges, const QString &current)
{
    if (edges.isEmpty())
        return current;
    const int i = edges.indexOf(current);
    if (i < 0)
        return edges.first();
    return edges.at((i + 1) % edges.size());
}

inline QStringList edgeCandidates(const QStringList &cached, const QStringList &baked)
{
    const QStringList src = cached.isEmpty() ? baked : cached;
    QStringList out;
    for (const QString &e : src)
        if (!out.contains(e))
            out << e;
    // primary (первый baked) обязан присутствовать — блокированный primary всё равно кандидат.
    if (!baked.isEmpty() && !out.contains(baked.first()))
        out << baked.first();
    return out;
}

// AVPN (разбор 2026-09-23): уникальные хосты edge-URL — фасад заранее резолвит их все в carve-out,
// чтобы смена edge никогда не требовала перезапуска живого туннеля. Литерал-IP сохраняется как есть.
inline QStringList edgeHosts(const QStringList &edges)
{
    QStringList out;
    for (const QString &e : edges) {
        const QString host = QUrl(e).host();
        if (!host.isEmpty() && !out.contains(host))
            out << host;
    }
    return out;
}

// Decision 2026-11-05: per-edge streak of /v1/subscription transport failures (classified by
// DebugSnapshot.h::classifySubscriptionEdgeOutcome; true = failure, false = delivered). Small calls
// never touch it. kSubscriptionEdgeFailSwitch failures in a row on the ACTIVE edge -> switch to the
// next edge (existing rotation); a delivered subscription on it resets; an outcome of a request sent
// to another edge (the active one changed meanwhile) does not count; a new active edge starts at 0.
constexpr int kSubscriptionEdgeFailSwitch = 2;
struct SubscriptionEdgeStreak {
    QString edge;
    int failures = 0;
    // Returns true when the active edge must be switched now.
    bool note(const QString &activeEdge, const QString &requestEdge, bool failed)
    {
        if (edge != activeEdge) {
            edge = activeEdge;
            failures = 0;
        }
        if (requestEdge != activeEdge)
            return false;
        if (!failed) {
            failures = 0;
            return false;
        }
        if (++failures < kSubscriptionEdgeFailSwitch)
            return false;
        failures = 0;
        return true;
    }
};

} // namespace avpn

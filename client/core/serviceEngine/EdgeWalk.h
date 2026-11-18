// client/core/serviceEngine/EdgeWalk.h
// AVPN: чистая логика перебора фолбэк-входов control plane.
#pragma once
#include <QString>
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

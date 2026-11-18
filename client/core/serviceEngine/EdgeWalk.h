// client/core/serviceEngine/EdgeWalk.h
// AVPN: чистая логика перебора фолбэк-входов control plane.
#pragma once
#include <QString>
#include <QStringList>
#include <QUrl>

namespace avpn {

// E10 (device rounds 2-3 of 18.11): which edge the control plane uses while a session runs. An app request enters
// the tunnel on every platform (iOS / MACOS_NE carve the API out of the RU split on purpose - incident 2026-07-05:
// a direct API path was cut by the operator; the macOS service runs Xray as a full tunnel). Through our own tunnels
// the active edge (api.tribevpn.com, the RU entry) is reachable - our exits and our Xray entry carry it. Through a
// PROVIDER tunnel the request leaves at the provider's foreign exit, whose profile may block or not route Russian
// destinations: api.tribevpn.com timed out there (14-15 s on subscription, scan manifest, seat requests) until the
// edge walk moved to the backup edge. So while a provider session is up the control plane uses the edge that is
// reachable from foreign exits (the one whoami already uses on Xray) at once - same requests, same tunnel, nothing
// more leaves the device directly; the stored active edge is not touched and comes back when the session ends.
// A pinned dev backend keeps its own base. Empty result = the active edge.
inline QString controlPlaneSessionEdge(bool providerSessionUp, bool pinned, const QString &providerEdge)
{
    if (!providerSessionUp || pinned)
        return QString();
    return providerEdge;
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

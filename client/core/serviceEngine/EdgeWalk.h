// client/core/serviceEngine/EdgeWalk.h
// AVPN: чистая логика перебора фолбэк-входов control plane.
#pragma once
#include <QString>
#include <QStringList>
#include <QUrl>

namespace avpn {

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

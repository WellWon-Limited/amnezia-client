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

} // namespace avpn

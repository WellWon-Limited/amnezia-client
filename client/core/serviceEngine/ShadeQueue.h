// client/core/serviceEngine/ShadeQueue.h
// AVPN serviceEngine - the queue of the full-width top notifications («шторки»). [header-only, QtCore;
// pure: no timers, no I/O]
//
// Plan scanner-client-plan.md §1.1 (Shade), §4.4; artboard SHADE_MS 1500, SHADE_ANIM 360. One queue for
// the whole app (hosted by the facade, shown by TribeShadeHost over every Tribe page). Rules (each one a
// test in tests/scan_core_check.cpp):
//  - One shade visible at a time. A shown shade stays holdMs (2.5 s, owner 19.11), then Hide; the slot is free again
//    animMs (360 ms, the slide-up) later. A tap hides it at once (then the same slide-up wait).
//  - No pre-emption: a shade that arrives while another is visible waits.
//  - Coalescing: a request whose key (empty key = tone + text key + args) is visible (incl. sliding up)
//    or already waiting is dropped.
//  - When the slot frees: info/success waiting longer than staleMs (3 s) are dropped as stale (warnings
//    never); then the oldest WARNING is shown first, else the oldest info/success (FIFO inside a tone
//    group).
//  - At most maxPending (3) waiting: on overflow the oldest info/success goes first; only when every
//    waiting shade is a warning does the oldest warning go.
//  - The machine never shows anything by itself: actions Show/Hide come out of enqueue/tap/tick, and
//    every step says when it wants the next tick (wakeAtMs). A `now` earlier than the last one is read
//    as the last one.
// Text keys and args are identifiers for the QML lane (Russian strings live in the .ts files).
//
// Upstream Amnezia has no counterpart (upstream toasts in main2.qml stay as they are).
#pragma once

#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVector>

#include <cmath>

namespace avpn {

enum class ShadeTone { Info, Success, Warning };

inline const char *shadeToneName(ShadeTone t)
{
    switch (t) {
    case ShadeTone::Success: return "success";
    case ShadeTone::Warning: return "warning";
    case ShadeTone::Info: break;
    }
    return "info";
}

inline ShadeTone shadeToneFrom(const QString &s)
{
    if (s == QLatin1String("success")) return ShadeTone::Success;
    if (s == QLatin1String("warning")) return ShadeTone::Warning;
    return ShadeTone::Info;
}

struct ShadeRequest {
    ShadeTone tone = ShadeTone::Info;
    QString textKey;      // e.g. "scan_found"
    QStringList args;     // e.g. {"10"}
    QString key;          // coalescing key; empty = tone + textKey + args

    QString coalesceKey() const
    {
        if (!key.isEmpty())
            return key;
        return QLatin1String(shadeToneName(tone)) + QLatin1Char('|') + textKey + QLatin1Char('|')
               + args.join(QLatin1Char('|'));
    }
    bool operator==(const ShadeRequest &o) const
    {
        return tone == o.tone && textKey == o.textKey && args == o.args && key == o.key;
    }
};

struct ShadeTiming {
    int holdMs = 2500;
    int animMs = 360;
    int staleMs = 3000;
    int maxPending = 3;
};

// The hold time from the last scan manifest's numbers (scan_shade_ms, 1500, 500..10000); without a manifest
// - the shade also shows before any scan - the compiled 1500 ms.
inline ShadeTiming shadeTimingFrom(const QMap<QString, double> &numbers)
{
    ShadeTiming t;
    const auto it = numbers.constFind(QStringLiteral("scan_shade_ms"));
    if (it != numbers.constEnd() && std::isfinite(it.value()))
        t.holdMs = int(qBound(500.0, it.value(), 10000.0));
    return t;
}

enum class ShadeActionKind { Show, Hide };

struct ShadeAction {
    ShadeActionKind kind = ShadeActionKind::Show;
    quint64 id = 0;
    ShadeRequest request;
};

struct ShadeStep {
    QVector<ShadeAction> actions;
    qint64 wakeAtMs = -1;
};

class ShadeQueue
{
public:
    explicit ShadeQueue(const ShadeTiming &t = ShadeTiming()) : m_t(t) {}

    ShadeStep enqueue(const ShadeRequest &r, qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ShadeStep s;
        settle(nowMs, s);
        const QString k = r.coalesceKey();
        bool dup = m_visible && m_visibleReq.coalesceKey() == k;
        for (const Pending &p : m_pending)
            dup = dup || p.req.coalesceKey() == k;
        if (!dup) {
            m_pending << Pending{r, nowMs};
            trimOverflow();
            showNextIfFree(nowMs, s);
        }
        s.wakeAtMs = wake();
        return s;
    }

    ShadeStep tapped(qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ShadeStep s;
        settle(nowMs, s);
        if (m_visible && !m_leaving)
            hide(nowMs, s);
        s.wakeAtMs = wake();
        return s;
    }

    ShadeStep tick(qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ShadeStep s;
        settle(nowMs, s);
        s.wakeAtMs = wake();
        return s;
    }

    bool visible() const { return m_visible; }
    bool leaving() const { return m_leaving; }
    quint64 visibleId() const { return m_visible ? m_id : 0; }
    ShadeRequest visibleRequest() const { return m_visibleReq; }
    int pendingCount() const { return m_pending.size(); }
    QList<ShadeRequest> pending() const
    {
        QList<ShadeRequest> out;
        for (const Pending &p : m_pending)
            out << p.req;
        return out;
    }

private:
    struct Pending {
        ShadeRequest req;
        qint64 atMs = 0;
    };

    qint64 clock(qint64 nowMs)
    {
        if (nowMs < m_last)
            nowMs = m_last;
        m_last = nowMs;
        return nowMs;
    }

    void hide(qint64 nowMs, ShadeStep &s)
    {
        s.actions << ShadeAction{ShadeActionKind::Hide, m_id, m_visibleReq};
        m_leaving = true;
        m_freeAt = nowMs + m_t.animMs;
    }

    // Applies everything due at nowMs: hide after hold, free the slot after the slide-up, show the next.
    void settle(qint64 nowMs, ShadeStep &s)
    {
        if (m_visible && !m_leaving && nowMs >= m_shownAt + m_t.holdMs)
            hide(m_shownAt + m_t.holdMs, s);
        if (m_visible && m_leaving && nowMs >= m_freeAt)
            m_visible = false;
        showNextIfFree(nowMs, s);
    }

    void showNextIfFree(qint64 nowMs, ShadeStep &s)
    {
        if (m_visible)
            return;
        for (int i = m_pending.size() - 1; i >= 0; --i)
            if (m_pending.at(i).req.tone != ShadeTone::Warning && nowMs - m_pending.at(i).atMs > m_t.staleMs)
                m_pending.removeAt(i);
        if (m_pending.isEmpty())
            return;
        int pick = -1;
        for (int i = 0; i < m_pending.size() && pick < 0; ++i)
            if (m_pending.at(i).req.tone == ShadeTone::Warning)
                pick = i;
        if (pick < 0)
            pick = 0;
        m_visibleReq = m_pending.takeAt(pick).req;
        m_visible = true;
        m_leaving = false;
        m_shownAt = nowMs;
        m_id = ++m_nextId;
        s.actions << ShadeAction{ShadeActionKind::Show, m_id, m_visibleReq};
    }

    void trimOverflow()
    {
        const int cap = qMax(1, m_t.maxPending);
        while (m_pending.size() > cap) {
            int drop = -1;
            for (int i = 0; i < m_pending.size() && drop < 0; ++i)
                if (m_pending.at(i).req.tone != ShadeTone::Warning)
                    drop = i;
            m_pending.removeAt(drop < 0 ? 0 : drop);
        }
    }

    qint64 wake() const
    {
        if (!m_visible)
            return -1;
        return m_leaving ? m_freeAt : m_shownAt + m_t.holdMs;
    }

    ShadeTiming m_t;
    QList<Pending> m_pending;
    bool m_visible = false;
    bool m_leaving = false;
    ShadeRequest m_visibleReq;
    qint64 m_shownAt = 0;
    qint64 m_freeAt = 0;
    quint64 m_id = 0;
    quint64 m_nextId = 0;
    qint64 m_last = 0;
};

} // namespace avpn

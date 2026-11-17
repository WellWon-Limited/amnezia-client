// client/core/serviceEngine/tests/path_world.h
// Scenario simulator of the path engine (design 2026-11-17 §9 "network scenarios in tests"): a scripted network
// model in virtual time that plays the platform side of AttemptOwner. Every path has a behaviour on every
// network (works after N ms with first byte at M ms, no handshake, up but no data, start error, no seat), a
// behaviour may change at given times (flapping, "blocked from T on"), and the test can inject events: a
// network change in the middle of an attempt, a late callback of an older leg, the app suspended for S seconds.
// The simulator applies the owner's effects the way the integration will: StartPath -> the scripted callbacks,
// StopPath -> a confirmation after stopMs, Report -> PathLedger::record (only for the current network
// generation), Finish -> the result list. Header-only, QtCore, no event loop.
#pragma once

#include "../path/AttemptOwner.h"

#include <QHash>
#include <QList>
#include <QString>

#include <functional>
#include <limits>
#include <map>
#include <utility>

namespace avpn::path::sim {

struct Behaviour {
    enum class Kind { Works, NoHandshake, NoData, StartError, NoSeat };
    Kind kind = Kind::NoHandshake;
    int upMs = 0;     // start -> tunnel up (Works, NoData)
    int checkMs = 0;  // data check start -> data proven (Works)
    int ttfbMs = -1;  // first byte inside the check (Works)
    bool attributable = true; // StartError: the server/config refused (true) or the device could not start (false)

    static Behaviour works(int upMs, int checkMs, int ttfbMs) { return { Kind::Works, upMs, checkMs, ttfbMs, true }; }
    static Behaviour noHandshake() { return { Kind::NoHandshake, 0, 0, -1, true }; }
    static Behaviour noData(int upMs) { return { Kind::NoData, upMs, 0, -1, true }; }
    static Behaviour startError(bool attributable) { return { Kind::StartError, 0, 0, -1, attributable }; }
    static Behaviour noSeat() { return { Kind::NoSeat, 0, 0, -1, true }; }
};

// Behaviour of one path on one network over time: the last segment whose start <= t applies.
struct PathScript {
    QList<std::pair<qint64, Behaviour>> segments;

    static PathScript always(const Behaviour &b) { return PathScript{ { { 0, b } } }; }
    PathScript then(qint64 fromMs, const Behaviour &b) const
    {
        PathScript s = *this;
        s.segments.append({ fromMs, b });
        return s;
    }
    Behaviour at(qint64 t) const
    {
        Behaviour b = Behaviour::noHandshake();
        for (const auto &seg : segments)
            if (seg.first <= t)
                b = seg.second;
        return b;
    }
};

// network local key -> path id -> script; a path without a script on a network does not handshake there.
struct World {
    QHash<QString, QHash<QString, PathScript>> scripts;

    void set(const QString &net, const QString &path, const PathScript &s) { scripts[net][path] = s; }
    void set(const QString &net, const QString &path, const Behaviour &b) { set(net, path, PathScript::always(b)); }
    Behaviour at(const QString &net, const QString &path, qint64 t) const
    {
        return scripts.value(net).contains(path) ? scripts.value(net).value(path).at(t) : Behaviour::noHandshake();
    }
};

struct LegTrace {
    PathStamp stamp;
    QString path;
    QString network;
    qint64 startedMs = 0;
};

class Sim {
public:
    static constexpr qint64 kWallBase = 1'800'000'000'000LL; // ledger wall clock = base + virtual time
    int stopMs = 500;
    int tickMs = 100;

    Sim(QList<PathCandidate> pool, World world, const NetworkObservation &net, AttemptTimings t = {},
        LedgerTunables lt = {})
        : owner(t), ledger(lt), m_pool(std::move(pool)), m_world(std::move(world))
    {
        tracker.observe(net);
    }

    AttemptOwner owner;
    PathLedger ledger;
    NetworkTracker tracker;
    QHash<QString, double> crowd;
    QList<LegTrace> legs;
    QList<OutcomeReport> reports;
    QList<AttemptResult> results;
    qint64 now = 0;

    qint64 wall() const { return kWallBase + now; }
    SelectionContext ctx() const { return SelectionContext{ m_pool, &ledger, wall(), crowd }; }
    void setPool(const QList<PathCandidate> &pool) { m_pool = pool; }

    // --- driving --------------------------------------------------------------------------------------------
    void deliver(const AttemptEvent &ev) { apply(owner.handle(ev, ctx())); }

    // A tap: UserStart now, then run until the attempt's terminal result (or maxMs of virtual time).
    AttemptResult tap(const UserChoice &c, TransportMode mode = TransportMode::Auto, qint64 maxMs = 120000)
    {
        m_tapAt = now;
        deliver(AttemptEvent::userStart(now, c, mode, tracker.current()));
        const quint64 attempt = owner.attempt(); // a tap during an attempt ends the old one first: wait for ours
        const auto done = [&] { return !results.isEmpty() && results.last().attempt == attempt; };
        run(done, maxMs);
        return done() ? results.last() : AttemptResult{};
    }
    qint64 lastTapWallMs() const { return now - m_tapAt; }

    // Scheduled actions in virtual time.
    void at(qint64 t, std::function<void()> fn) { m_queue.emplace(std::make_pair(t, m_seq++), std::move(fn)); }
    void changeNetworkAt(qint64 t, const NetworkObservation &o)
    {
        at(t, [this, o] {
            if (tracker.observe(o))
                deliver(AttemptEvent::networkChanged(now, tracker.current()));
        });
    }
    // The app is suspended in [from, from + forMs): no tick, every callback due inside is delivered on resume.
    void suspend(qint64 from, qint64 forMs) { m_suspend.append({ from, from + forMs }); }

    // Let virtual time pass (ticks and due callbacks).
    void idle(qint64 ms) { run([] { return false; }, ms); }

    void run(const std::function<bool()> &done, qint64 maxMs)
    {
        const qint64 end = now + maxMs;
        while (!done() && now < end) {
            if (!m_queue.empty() && m_queue.begin()->first.first <= now) {
                auto fn = std::move(m_queue.begin()->second);
                m_queue.erase(m_queue.begin());
                fn();
                continue;
            }
            const qint64 nextTick = (now / tickMs + 1) * tickMs;
            const qint64 nextItem = m_queue.empty() ? std::numeric_limits<qint64>::max() : m_queue.begin()->first.first;
            qint64 t = std::min(nextTick, nextItem);
            if (t > end) {
                now = end;
                break;
            }
            if (const qint64 resume = resumeAt(t); resume > t) {
                now = resume; // asleep: nothing happens until the resume, then the due callbacks run
                continue;
            }
            now = t;
            if (t == nextTick && t != nextItem)
                deliver(AttemptEvent::tick(now));
        }
    }

private:
    qint64 resumeAt(qint64 t) const
    {
        for (const auto &w : m_suspend)
            if (t >= w.first && t < w.second)
                return w.second;
        return t;
    }

    void schedule(qint64 t, const AttemptEvent &ev)
    {
        at(t, [this, ev] {
            AttemptEvent e = ev;
            e.nowMs = now;
            deliver(e);
        });
    }

    void apply(const QList<AttemptEffect> &effects)
    {
        for (const AttemptEffect &e : effects) {
            switch (e.type) {
            case EffectType::StartPath: {
                const QString net = tracker.current().local;
                legs.append({ e.stamp, e.path.id.id, net, now });
                const Behaviour b = m_world.at(net, e.path.id.id, now);
                m_legBehaviour.insert(e.stamp.leg, b);
                switch (b.kind) {
                case Behaviour::Kind::Works:
                case Behaviour::Kind::NoData: schedule(now + b.upMs, AttemptEvent::tunnelUp(0, e.stamp)); break;
                case Behaviour::Kind::NoHandshake: break; // the owner's start deadline judges it
                case Behaviour::Kind::StartError:
                    schedule(now + 50, AttemptEvent::pathFailed(0, e.stamp, b.attributable ? PathOutcome::Refused
                                                                                           : PathOutcome::Inconclusive));
                    break;
                case Behaviour::Kind::NoSeat:
                    schedule(now + 300, AttemptEvent::pathFailed(0, e.stamp, PathOutcome::NoSeat));
                    break;
                }
                break;
            }
            case EffectType::RunDataCheck: {
                const Behaviour b = m_legBehaviour.value(e.stamp.leg);
                if (b.kind == Behaviour::Kind::Works)
                    schedule(now + b.checkMs, AttemptEvent::dataChecked(0, e.stamp, PathOutcome::DataOk, b.ttfbMs));
                break; // no data: nothing comes, the owner's check deadline judges it
            }
            case EffectType::StopPath: schedule(now + stopMs, AttemptEvent::stopConfirmed(0, e.stamp)); break;
            case EffectType::Report:
                reports.append(e.report);
                if (tracker.isCurrent(e.report.networkGeneration))
                    ledger.record(e.report.network, e.report.path, e.report.outcome, wall(), e.report.connectMs,
                                  e.report.ttfbMs);
                break;
            case EffectType::Finish: results.append(e.result); break;
            case EffectType::Show: break;
            }
        }
    }

    QList<PathCandidate> m_pool;
    World m_world;
    std::map<std::pair<qint64, quint64>, std::function<void()>> m_queue;
    quint64 m_seq = 0;
    QList<std::pair<qint64, qint64>> m_suspend;
    QHash<quint64, Behaviour> m_legBehaviour;
    qint64 m_tapAt = 0;
};

} // namespace avpn::path::sim

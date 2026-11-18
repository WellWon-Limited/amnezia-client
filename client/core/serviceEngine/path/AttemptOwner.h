// client/core/serviceEngine/path/AttemptOwner.h
// AVPN path engine (design 2026-11-17, §4 "Connect attempt") - the single owner of one connect attempt, as an
// explicit state machine: events in, effects out. [header-only, QtCore; pure: no timers, no I/O]
//
// The owner numbers its attempts. One attempt has one state and one terminal result (Finish). It stops what it
// started and waits for the confirmation before the next path; an answer that arrives after a cancel changes
// nothing. Every path it brings up is a LEG stamped with (attempt, network generation, leg number); a callback
// is accepted only with the stamp of the current leg (or, for a stop confirmation, of the leg being stopped).
// Callbacks of an older attempt, an older network or an older leg are therefore ignored by construction - no
// timer, flag or generation check elsewhere is needed.
//
// Clock: every event carries the caller's monotonic now (an injected clock). The owner counts its deadlines in
// AWAKE time: a gap between two events longer than clockJumpMs (the app was suspended, the main thread stood)
// counts as clockJumpMs only, so a suspension never turns into "no handshake" (design Р12: "the check did not
// happen" is not a path outcome). The platform tick (<= 1 s) drives deadlines.
//
// Course of an attempt (stage 1, design §4 "no probe host": candidates one at a time with a short deadline):
//   UserStart -> select (PathSelect.h, ledger of the current network) -> StartPath(leg, start timeout)
//     -> TunnelUp -> RunDataCheck(leg, check timeout) -> DataChecked ok -> Report(data ok) + Finish(Connected)
//     -> failure (PathFailed / start deadline / check deadline / check failed): Report(outcome, if attributable)
//        + StopPath(leg) -> StopConfirmed -> select the next untried path ...
//   Budget (per network: a network change starts a new budget and a new "tried" set, the old network's results
//   say nothing about the new one) over -> the running leg is cut (NOT recorded: its check did not complete),
//   stopped, and the attempt ends Failed(nothing proven) - or Failed(exact node failed) for an exact node.
//   Also ends: maxPaths legs on one network, no candidate left, no network, the user's stop.
// Live session (after Connected): LiveLost reports what the loss proves and, with `restart`, begins the
// failover attempt (the lost path is not offered again in it when the loss is attributable); Adopted makes a
// tunnel found alive the first leg of a new attempt, already up, judged by the data check. A stop that is never
// confirmed ends the wait after stopConfirmMs (StopUnconfirmed; nothing recorded).
// Results: Connected(path) with fallbackNotice when a preferred country was unavailable and another path
// carried data; Failed(nothing proven / exact node failed / stopped by user / no candidate / no network).
// After Connected the owner keeps the leg as the live session: a later UserStart or UserStop stops it first
// (the owner is the only one that raised it). Keeping a live session healthy is NOT this class (design stage 3);
// a network change after Connected only updates the owner's network key.
//
// STAGE 2 (probe race) without changing this contract: the race is a separate component in front of the
// owner. It writes its results into the ledger as outcomes (probe ok / no handshake ...). The owner reads the
// ledger through PathSelect at EVERY choice (SelectionContext is passed with every event), so race winners
// are simply "working" paths of the current network and come first; a path the race found dead drops back.
// "Known path at once + race of the spares" (design §4 step 2) is: the facade sends UserStart at once (the
// known path is the first choice) and starts the race beside it; "no known path" is: the facade lets the race
// run first and sends UserStart when it has a winner or its own time is up. Neither needs a new event here.
#pragma once

#include "NetworkKey.h"
#include "PathLedger.h"
#include "PathSelect.h"
#include "PathTunables.h"

#include <QList>
#include <QSet>

#include <algorithm>
#include <optional>

namespace avpn::path {

struct PathStamp {
    quint64 attempt = 0;
    quint64 network = 0;
    quint64 leg = 0; // 0 = none

    bool isValid() const { return leg != 0; }
    bool operator==(const PathStamp &o) const { return attempt == o.attempt && network == o.network && leg == o.leg; }
    bool operator!=(const PathStamp &o) const { return !(*this == o); }
};

enum class AttemptPhase { Idle, Starting, Checking, Stopping, Connected };

inline const char *attemptPhaseName(AttemptPhase p)
{
    switch (p) {
    case AttemptPhase::Idle: return "idle";
    case AttemptPhase::Starting: return "starting";
    case AttemptPhase::Checking: return "checking";
    case AttemptPhase::Stopping: return "stopping";
    case AttemptPhase::Connected: return "connected";
    }
    return "";
}

enum class FailReason { None, NothingProven, ExactNodeFailed, StoppedByUser, NoCandidate, NoNetwork };

inline const char *failReasonName(FailReason r)
{
    switch (r) {
    case FailReason::None: return "none";
    case FailReason::NothingProven: return "nothing_proven";
    case FailReason::ExactNodeFailed: return "exact_node_failed";
    case FailReason::StoppedByUser: return "stopped_by_user";
    case FailReason::NoCandidate: return "no_candidate";
    case FailReason::NoNetwork: return "no_network";
    }
    return "";
}

struct AttemptResult {
    quint64 attempt = 0;
    bool connected = false;
    FailReason reason = FailReason::None;
    PathCandidate path;          // Connected: the path that carried data
    bool fallbackNotice = false; // preferred country unavailable, connected elsewhere ("<country> is unavailable on
                                 // this network - connected via <other>"); the preference is kept
    int paths = 0;               // legs brought up in this attempt
    qint64 elapsedMs = 0;        // awake time from the tap to the result
};

struct OutcomeReport {
    QString network;          // local network key
    quint64 networkGeneration = 0;
    PathId path;
    PathOutcome outcome = PathOutcome::Inconclusive;
    int connectMs = -1;       // start -> tunnel up
    int ttfbMs = -1;
};

// StopUnconfirmed: the stop of `stamp` was not confirmed within stopConfirmMs - the attempt went on (journal it;
// the platform layer keeps its own stop retries).
enum class EffectType { StartPath, StopPath, RunDataCheck, Report, Show, Finish, StopUnconfirmed };

struct AttemptEffect {
    EffectType type = EffectType::Show;
    PathStamp stamp;          // StartPath / StopPath / RunDataCheck: echo it in every callback
    PathCandidate path;
    int timeoutMs = 0;        // StartPath: start deadline; RunDataCheck: check deadline (for native timeouts)
    OutcomeReport report;     // Report: write into the ledger
    AttemptPhase phase = AttemptPhase::Idle; // Show
    AttemptResult result;     // Finish
};

enum class EventType {
    UserStart, UserStop, PathFailed, TunnelUp, DataChecked, Tick, NetworkChanged, StopConfirmed,
    // The live session (after Connected) stopped carrying data or went away. `outcome` - what it proves about the
    // path (attributable: recorded; Inconclusive: not); `tunnelGone` - the tunnel is already down (nothing to stop);
    // `restart` - a new attempt follows with `choice` / `mode` / `network` (design §4 "keep": failover is a new
    // attempt through the same owner). A path that failed here is not offered again in that attempt.
    LiveLost,
    // A live tunnel this process did not raise (found at launch, re-bound): it becomes the leg of a new attempt
    // with `choice` / `mode` / `network`, already up - one in-tunnel data check decides like for any leg.
    Adopted,
};

struct AttemptEvent {
    EventType type = EventType::Tick;
    qint64 nowMs = 0;
    PathStamp stamp;                                 // callbacks
    PathOutcome outcome = PathOutcome::Inconclusive; // PathFailed, DataChecked
    int ttfbMs = -1;                                 // DataChecked
    UserChoice choice;                               // UserStart
    TransportMode mode = TransportMode::Auto;        // UserStart
    NetworkKey network;                              // UserStart, NetworkChanged, LiveLost, Adopted
    PathCandidate path;                              // Adopted
    bool tunnelGone = false;                         // LiveLost, PathFailed
    bool restart = false;                            // LiveLost

    static AttemptEvent userStart(qint64 now, const UserChoice &c, TransportMode m, const NetworkKey &net)
    {
        AttemptEvent e = at(EventType::UserStart, now);
        e.choice = c;
        e.mode = m;
        e.network = net;
        return e;
    }
    static AttemptEvent userStop(qint64 now) { return at(EventType::UserStop, now); }
    static AttemptEvent liveLost(qint64 now, PathOutcome o, bool tunnelGone, bool restart, const UserChoice &c,
                                 TransportMode m, const NetworkKey &net)
    {
        AttemptEvent e = userStart(now, c, m, net);
        e.type = EventType::LiveLost;
        e.outcome = o;
        e.tunnelGone = tunnelGone;
        e.restart = restart;
        return e;
    }
    static AttemptEvent adopted(qint64 now, const PathCandidate &p, const UserChoice &c, TransportMode m,
                                const NetworkKey &net)
    {
        AttemptEvent e = userStart(now, c, m, net);
        e.type = EventType::Adopted;
        e.path = p;
        return e;
    }
    static AttemptEvent tick(qint64 now) { return at(EventType::Tick, now); }
    static AttemptEvent networkChanged(qint64 now, const NetworkKey &net)
    {
        AttemptEvent e = at(EventType::NetworkChanged, now);
        e.network = net;
        return e;
    }
    static AttemptEvent tunnelUp(qint64 now, const PathStamp &s) { return cb(EventType::TunnelUp, now, s); }
    static AttemptEvent stopConfirmed(qint64 now, const PathStamp &s) { return cb(EventType::StopConfirmed, now, s); }
    // tunnelGone: the platform already reports the tunnel down (nothing to stop, no confirmation to wait for).
    static AttemptEvent pathFailed(qint64 now, const PathStamp &s, PathOutcome o, bool tunnelGone = false)
    {
        AttemptEvent e = cb(EventType::PathFailed, now, s);
        e.outcome = o;
        e.tunnelGone = tunnelGone;
        return e;
    }
    static AttemptEvent dataChecked(qint64 now, const PathStamp &s, PathOutcome o, int ttfbMs = -1)
    {
        AttemptEvent e = cb(EventType::DataChecked, now, s);
        e.outcome = o;
        e.ttfbMs = ttfbMs;
        return e;
    }

private:
    static AttemptEvent at(EventType t, qint64 now)
    {
        AttemptEvent e;
        e.type = t;
        e.nowMs = now;
        return e;
    }
    static AttemptEvent cb(EventType t, qint64 now, const PathStamp &s)
    {
        AttemptEvent e = at(t, now);
        e.stamp = s;
        return e;
    }
};

// What the owner reads at every choice: the pool, the ledger (for the owner's current network), the wall
// clock of the ledger, the crowd prior. Passed with every event, never stored.
struct SelectionContext {
    QList<PathCandidate> pool;
    const PathLedger *ledger = nullptr;
    qint64 wallNowMs = 0;
    QHash<QString, double> crowd;
};

class AttemptOwner {
public:
    explicit AttemptOwner(AttemptTimings t = {}) : m_t(t) {}

    QList<AttemptEffect> handle(const AttemptEvent &ev, const SelectionContext &ctx)
    {
        advance(ev.nowMs);
        QList<AttemptEffect> out;
        checkDeadlines(ctx, out);
        switch (ev.type) {
        case EventType::UserStart: onUserStart(ev, ctx, out); break;
        case EventType::UserStop: onUserStop(out); break;
        case EventType::PathFailed:
            if (isLiveLeg(ev.stamp) && (m_phase == AttemptPhase::Starting || m_phase == AttemptPhase::Checking))
                failLeg(isSuccess(ev.outcome) ? PathOutcome::Inconclusive : ev.outcome, out, ev.tunnelGone ? &ctx : nullptr);
            break;
        case EventType::TunnelUp:
            if (isLiveLeg(ev.stamp) && m_phase == AttemptPhase::Starting) {
                m_phase = AttemptPhase::Checking;
                m_leg.upAt = m_awake;
                m_leg.deadline = m_awake + m_t.dataCheckMs;
                out << effect(EffectType::RunDataCheck, m_t.dataCheckMs) << show(AttemptPhase::Checking);
            }
            break;
        case EventType::DataChecked:
            if (isLiveLeg(ev.stamp) && m_phase == AttemptPhase::Checking) {
                if (ev.outcome == PathOutcome::DataOk)
                    connected(ev.ttfbMs, out);
                else
                    failLeg(ev.outcome == PathOutcome::Inconclusive ? PathOutcome::Inconclusive : PathOutcome::NoData, out);
            }
            break;
        case EventType::Tick: break;
        case EventType::NetworkChanged: onNetworkChanged(ev.network, ctx, out); break;
        case EventType::StopConfirmed:
            if (m_phase == AttemptPhase::Stopping && ev.stamp == m_stopping)
                onStopped(ctx, out);
            break;
        case EventType::LiveLost: onLiveLost(ev, ctx, out); break;
        case EventType::Adopted: onAdopted(ev, out); break;
        }
        return out;
    }

    AttemptPhase phase() const { return m_phase; }
    bool running() const { return m_running; }
    quint64 attempt() const { return m_attempt; }
    const NetworkKey &network() const { return m_net; }
    PathStamp currentLeg() const { return m_leg.stamp; }
    PathStamp stoppingLeg() const { return m_stopping; }
    const PathCandidate &currentPath() const { return m_leg.path; }
    const UserChoice &choice() const { return m_choice; }
    // "checked N of M" of the running attempt on this network: legs brought up, and those plus the candidates
    // still in the order at the last choice (both 0 before the first choice).
    int progressDone() const { return m_pathsThisNet; }
    int progressTotal() const { return m_progressTotal; }
    qint64 awakeMs() const { return m_awake; }
    const AttemptTimings &timings() const { return m_t; }
    // New numbers (the server may tune them): they apply from the next deadline that is set.
    void setTimings(const AttemptTimings &t) { m_t = t; }

    int startTimeoutMs(PathKind k) const
    {
        switch (k) {
        case PathKind::OwnAwg: return m_t.awgStartMs;
        case PathKind::OwnXray: return m_t.xrayStartMs;
        case PathKind::Provider: return m_t.providerStartMs;
        }
        return m_t.awgStartMs;
    }

private:
    struct Leg {
        PathStamp stamp;
        PathCandidate path;
        qint64 startedAt = 0;
        qint64 upAt = 0;
        qint64 deadline = 0;
    };

    void advance(qint64 now)
    {
        if (m_lastNow >= 0 && now > m_lastNow)
            m_awake += std::min<qint64>(now - m_lastNow, m_t.clockJumpMs);
        if (now > m_lastNow)
            m_lastNow = now;
    }

    bool isLiveLeg(const PathStamp &s) const { return s.isValid() && s == m_leg.stamp; }
    bool legActive() const { return m_phase == AttemptPhase::Starting || m_phase == AttemptPhase::Checking; }
    bool exact() const { return m_choice.kind == UserChoice::Kind::ExactPath; }

    AttemptEffect effect(EffectType t, int timeoutMs = 0) const
    {
        AttemptEffect e;
        e.type = t;
        e.stamp = m_leg.stamp;
        e.path = m_leg.path;
        e.timeoutMs = timeoutMs;
        return e;
    }
    AttemptEffect show(AttemptPhase p) const
    {
        AttemptEffect e = effect(EffectType::Show);
        e.phase = p;
        return e;
    }

    AttemptResult failure(FailReason r) const
    {
        AttemptResult res;
        res.reason = exact() && r == FailReason::NothingProven ? FailReason::ExactNodeFailed : r;
        return res;
    }

    void finish(AttemptResult res, QList<AttemptEffect> &out)
    {
        res.attempt = m_attempt;
        res.paths = m_pathsTotal;
        res.elapsedMs = m_awake - m_attemptStart;
        AttemptEffect e;
        e.type = EffectType::Finish;
        e.result = res;
        out << e;
        m_running = false;
        m_pending.reset();
    }

    void report(PathOutcome o, int connectMs, int ttfbMs, QList<AttemptEffect> &out) const
    {
        if (!isAttributable(o))
            return;
        AttemptEffect e = effect(EffectType::Report);
        e.report.network = m_net.local;
        e.report.networkGeneration = m_leg.stamp.network;
        e.report.path = m_leg.path.id;
        e.report.outcome = o;
        e.report.connectMs = connectMs;
        e.report.ttfbMs = ttfbMs;
        out << e;
    }

    void stopLeg(QList<AttemptEffect> &out)
    {
        out << effect(EffectType::StopPath);
        m_stopping = m_leg.stamp;
        m_stopDeadline = m_awake + m_t.stopConfirmMs;
        m_phase = AttemptPhase::Stopping;
    }

    // gone (non-null): the tunnel is already down - no stop, the next choice at once.
    void failLeg(PathOutcome o, QList<AttemptEffect> &out, const SelectionContext *gone = nullptr)
    {
        report(o, -1, -1, out);
        if (!gone) {
            stopLeg(out);
            return;
        }
        m_phase = AttemptPhase::Idle;
        m_leg = Leg{};
        if (m_running)
            beginNext(*gone, out);
    }

    void connected(int ttfbMs, QList<AttemptEffect> &out)
    {
        report(PathOutcome::DataOk, int(m_leg.upAt - m_leg.startedAt), ttfbMs, out);
        m_phase = AttemptPhase::Connected;
        AttemptResult res;
        res.connected = true;
        res.path = m_leg.path;
        res.fallbackNotice = m_choice.kind == UserChoice::Kind::PreferCountry && m_leg.path.country != m_choice.country;
        finish(res, out);
    }

    void checkDeadlines(const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        // A stop never confirmed: the platform is taken as stopped (its outcome, not the path's - nothing is
        // recorded) so the attempt never hangs on it.
        if (m_phase == AttemptPhase::Stopping && m_awake >= m_stopDeadline) {
            AttemptEffect e = effect(EffectType::StopUnconfirmed);
            e.stamp = m_stopping;
            out << e;
            onStopped(ctx, out);
        }
        if (!m_running)
            return;
        if (m_awake >= m_budgetEnd) {
            if (!m_pending)
                m_pending = failure(FailReason::NothingProven);
            if (legActive())
                stopLeg(out); // cut by the budget: its check did not complete - nothing is recorded
            else if (m_phase != AttemptPhase::Stopping)
                finish(*m_pending, out);
            return;
        }
        if (legActive() && m_awake >= m_leg.deadline)
            failLeg(m_phase == AttemptPhase::Starting ? PathOutcome::NoHandshake : PathOutcome::NoData, out);
    }

    void restartOnNetwork()
    {
        m_tried.clear();
        m_pathsThisNet = 0;
        m_budgetEnd = m_awake + m_t.budgetMs;
    }

    void onUserStart(const AttemptEvent &ev, const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        beginAttempt(ev, out);
        if (legActive() || m_phase == AttemptPhase::Connected)
            stopLeg(out); // what the previous attempt raised goes down first
        else if (m_phase != AttemptPhase::Stopping)
            beginNext(ctx, out);
    }

    void onUserStop(QList<AttemptEffect> &out)
    {
        if (m_running) {
            m_pending = failure(FailReason::StoppedByUser);
            if (legActive())
                stopLeg(out);
            else if (m_phase != AttemptPhase::Stopping)
                finish(*m_pending, out);
        } else if (m_phase == AttemptPhase::Connected) {
            stopLeg(out); // the live session; the confirmation shows Idle
        }
    }

    void onNetworkChanged(const NetworkKey &net, const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        if (net.generation <= m_net.generation)
            return; // an older observation
        m_net = net;
        if (!m_running)
            return;
        restartOnNetwork();
        if (!net.usable())
            m_pending = failure(FailReason::NoNetwork);
        else if (m_pending && m_pending->reason == FailReason::NoNetwork)
            m_pending.reset();
        if (legActive())
            stopLeg(out); // started on the old network: its result would describe the old network - not recorded
        else if (m_phase != AttemptPhase::Stopping)
            beginNext(ctx, out);
    }

    void beginAttempt(const AttemptEvent &ev, QList<AttemptEffect> &out)
    {
        if (m_running)
            finish(failure(FailReason::StoppedByUser), out); // the previous attempt ends here, once
        ++m_attempt;
        m_running = true;
        m_choice = ev.choice;
        m_mode = ev.mode;
        if (ev.network.generation >= m_net.generation)
            m_net = ev.network;
        m_pathsTotal = 0;
        m_attemptStart = m_awake;
        restartOnNetwork();
    }

    void onLiveLost(const AttemptEvent &ev, const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        if (m_phase != AttemptPhase::Connected)
            return; // nothing live is ours (a leg in flight is judged by its own deadlines)
        report(ev.outcome, -1, -1, out);
        const QString lost = m_leg.path.id.id;
        if (ev.restart) {
            beginAttempt(ev, out);
            if (isAttributable(ev.outcome))
                m_tried.insert(lost); // proven dead here a moment ago: not again in this attempt
        }
        if (!ev.tunnelGone) {
            stopLeg(out);
            return;
        }
        m_phase = AttemptPhase::Idle;
        m_leg = Leg{};
        if (m_running)
            beginNext(ctx, out);
        else
            out << show(AttemptPhase::Idle);
    }

    void onAdopted(const AttemptEvent &ev, QList<AttemptEffect> &out)
    {
        if (m_running || m_phase != AttemptPhase::Idle || !ev.path.id.isValid())
            return; // only a tunnel nobody here is driving
        beginAttempt(ev, out);
        m_tried.insert(ev.path.id.id);
        ++m_pathsThisNet;
        ++m_pathsTotal;
        m_leg = Leg{};
        m_leg.stamp = PathStamp{ m_attempt, m_net.generation, ++m_legSeq };
        m_leg.path = ev.path;
        m_leg.startedAt = m_awake;
        m_leg.upAt = m_awake;
        m_leg.deadline = m_awake + m_t.dataCheckMs;
        m_phase = AttemptPhase::Checking;
        m_progressTotal = 1;
        out << effect(EffectType::RunDataCheck, m_t.dataCheckMs) << show(AttemptPhase::Checking);
    }

    void onStopped(const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        m_stopping = PathStamp{};
        m_phase = AttemptPhase::Idle;
        m_leg = Leg{};
        if (m_running)
            beginNext(ctx, out);
        else
            out << show(AttemptPhase::Idle);
    }

    void beginNext(const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        if (m_pending)
            return finish(*m_pending, out);
        if (!m_net.usable())
            return finish(failure(FailReason::NoNetwork), out);
        if (m_pathsThisNet >= m_t.maxPaths)
            return finish(failure(FailReason::NothingProven), out);
        SelectInput in;
        in.pool = ctx.pool;
        if (ctx.ledger)
            in.evidence = ctx.ledger->viewOf(m_net.local, ctx.pool, ctx.wallNowMs);
        in.choice = m_choice;
        in.mode = m_mode;
        in.crowd = ctx.crowd;
        in.tried = m_tried;
        const QList<RankedPath> order = selectPaths(in);
        m_progressTotal = m_pathsThisNet + int(order.size());
        if (order.isEmpty()) {
            const bool nothingEver = m_pathsTotal == 0 && !exact();
            return finish(failure(nothingEver ? FailReason::NoCandidate : FailReason::NothingProven), out);
        }
        const PathCandidate &next = order.first().path;
        m_tried.insert(next.id.id);
        ++m_pathsThisNet;
        ++m_pathsTotal;
        m_leg = Leg{};
        m_leg.stamp = PathStamp{ m_attempt, m_net.generation, ++m_legSeq };
        m_leg.path = next;
        m_leg.startedAt = m_awake;
        m_leg.deadline = m_awake + startTimeoutMs(next.kind);
        m_phase = AttemptPhase::Starting;
        out << effect(EffectType::StartPath, startTimeoutMs(next.kind)) << show(AttemptPhase::Starting);
    }

    AttemptTimings m_t;
    qint64 m_awake = 0;
    qint64 m_lastNow = -1;
    quint64 m_attempt = 0;
    quint64 m_legSeq = 0;
    bool m_running = false;
    AttemptPhase m_phase = AttemptPhase::Idle;
    UserChoice m_choice;
    TransportMode m_mode = TransportMode::Auto;
    NetworkKey m_net;
    QSet<QString> m_tried;
    int m_pathsThisNet = 0;
    int m_pathsTotal = 0;
    qint64 m_attemptStart = 0;
    qint64 m_budgetEnd = 0;
    Leg m_leg;
    PathStamp m_stopping;
    std::optional<AttemptResult> m_pending;
    qint64 m_stopDeadline = 0;
    int m_progressTotal = 0;
};

} // namespace avpn::path

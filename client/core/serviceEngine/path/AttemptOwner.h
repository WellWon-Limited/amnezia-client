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
// does not count at all, so a suspension never turns into "no handshake" (design R12: "the check did not
// happen" is not a path outcome). After a suspension the leg in flight gets at least resumeGraceMs, and a data
// check that was running is run again on the same tunnel (RunDataCheck with `recheck`), nothing recorded.
// Every event is applied BEFORE the deadlines are evaluated: an answer the platform gave by now (a tunnel up, a
// completed payload) is evidence and wins over a deadline that expired at the same moment (review E3/E4 18.11).
// The platform tick (<= 1 s) drives deadlines.
//
// Local build: a leg's start deadline measures what the SERVER must do (answer the handshake / bring the session
// up). Time the device spends on its own - a system permission dialog (the facade delivers no tick meanwhile, see
// the Clock), building its own tunnel interface - is not part of it and is never evidence about the server. A
// platform that knows when it builds the interface reports LocalBuild(building) and LocalBuild(built) with the leg's
// stamp (Android: the VPN service from the start command until VpnService.Builder.establish() returned and the
// backend runs - with «Доступ к сайтам РФ» Android installs ~10 800 routes there, 7-10 s on the emulator 20.11).
// Between them the start deadline does not run; from "built" the leg has its full start deadline for the server's
// part. A build that does not finish within localBuildMs ends the leg with a LOCAL outcome (LocalBuildOverrun,
// Inconclusive: nothing recorded against the path), and the next candidate is tried. The local time is not part of
// the leg's connect time either. A platform that does not report builds (desktop) behaves exactly as before; iOS
// reports only a parked start (below).
// A platform that reports builds (setLocalBuildReported(true): Android with the service's build events) has the leg in
// LOCAL time from the start command on: between "start sent" and the service's "building" the start may still wait in
// the service, behind a previous build (android2 V2, 21.11: the service took a start 7.9 s after it was sent, the 4.5 s
// clock had already written "no handshake" against a server whose tunnel build never began). So the start deadline
// begins only at this leg's own "built"; until then the local bound applies (from the start), and a leg that never
// reports "built" ends with a LOCAL outcome. Which leg a report belongs to is the platform layer's business (it
// carries the leg number through the start and back: ServiceEngine::onLocalBuild) - the owner takes the stamp.
// iOS reports one local phase the same way: a start the native PARKS because the previous tunnel session is still
// tearing down (IosController::startAwaitsTeardown: "building" when it parks, "built" when the start goes out after the
// teardown). One tunnel session at a time: until then the start has not left the device (device round air-B 24.11:
// a leg sent after a stop that took 25 s was parked for 15 s, its 5 s clock wrote "no handshake" against a path the
// race had just proven). iOS reports only that phase; every other iOS leg is judged from its start as before.
// Invariant: a "no handshake" verdict needs a start that left the device - a leg in its local phase is never recorded
// no_handshake (report()), whatever ends it.
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
// a network change after Connected only updates the owner's network key - the session lives on, so what its loss
// proves (LiveLost) is recorded for the network it is on when it is lost (key and generation of that one network).
//
// STAGE 2 (probe race) without changing this contract: the race is a separate component in front of the
// owner. It writes its results into the ledger as outcomes (probe ok / no handshake ...). The owner reads the
// ledger through PathSelect at EVERY choice (SelectionContext is passed with every event), so race winners
// are simply "working" paths of the current network and come first; a path the race found dead drops back.
// "Known path at once + race of the spares" (design §4 step 2) is: the facade sends UserStart at once (the
// known path is the first choice) and starts the race beside it; "no known path" is: the facade lets the race
// run first and sends UserStart with the race's first proof as its LEAD, or without one when the race's wait is
// over (PathRace.h hedgeAfterMs) - only then is a first leg a blind bet.
// Lead: the path a proof named (AttemptEvent::lead). The next leg goes to THAT path, not to whatever ranks first
// by an unrelated key a moment later (device round 19.11: the leg after a proof of Finland 1 Xray was chosen after
// the ~1 s stop, when two AmneziaWG probe proofs had landed and outranked it by probe time). The lead is taken only
// when the ordinary choice could take it: it is in the order (mode, tried) as a working path of this network and
// no preferred path is ahead of it; otherwise the order decides as always. It is consumed by the next choice.
// A proof while a leg is in flight (ProofReady): the leg yields to the proven path (nothing is recorded for the leg)
// only when it has shown nothing of its own:
//  - it is up and its one data check got no first byte within its share (`starved`): it yields to a path the race of
//    THIS attempt proved on this network - the proof's own, else the first of the attempt's proofs the choice can
//    take (see "Lead"). The owner keeps those proofs itself (the lead of UserStart, the leads of ProofReady) and
//    forgets them with the attempt and with the network, so a winner of an earlier tap's race is never one of them.
//    With no such proof the leg keeps its whole data check and writes its own outcome: what the ledger remembers
//    about other paths ("works here") is history, not a proof that waits, and never ends a leg that is up (device
//    round 12 of 21.11, iPhone Air, Wi-Fi: the race was skipped for a known path, every tap left it and the next
//    working path 1 s into their checks for whatever the ledger ranked next, recorded nothing and repeated it:
//    4.8-6.9 s per connect, four taps in a row);
//  - it is not up yet and was raised without evidence: it yields to the proof's own path, else to the first working
//    path of the order. With a probe host that happens only after the race had its wait (PathRace.h hedgeAfterMs)
//    and proved nothing - the blind path's own probe included - or after the race ended: a bet against a network
//    that already proved hostile, and a proof is better evidence than that bet.
// A lead, a known path and a leg up and receiving bytes are never ended by a proof. Device round of 19.11 (iPhone
// Air, Auto, empty ledger): the blind leg raised AT ONCE beside the race yielded to the first proof ~1 s in and
// dropped a working Serbia 1 AmneziaWG leg on Wi-Fi (5.56 s to data, 3.7-3.9 s before); with the race first that leg
// is never raised blind - on both traces no leg yields (tests/path_engine_check.cpp, "trace 19.11").
#pragma once

#include "NetworkKey.h"
#include "PathLedger.h"
#include "PathSelect.h"
#include "PathTunables.h"

#include <QList>
#include <QSet>
#include <QStringList>

#include <algorithm>
#include <optional>
#include <utility>

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

// PermissionDenied: the person refused (or dismissed) the system's "allow VPN configuration" dialog (Android
// VpnService.prepare). Not a path outcome: the attempt ends once, nothing is recorded, no other leg is raised.
enum class FailReason { None, NothingProven, ExactNodeFailed, StoppedByUser, NoCandidate, NoNetwork, PermissionDenied };

inline const char *failReasonName(FailReason r)
{
    switch (r) {
    case FailReason::None: return "none";
    case FailReason::NothingProven: return "nothing_proven";
    case FailReason::ExactNodeFailed: return "exact_node_failed";
    case FailReason::StoppedByUser: return "stopped_by_user";
    case FailReason::NoCandidate: return "no_candidate";
    case FailReason::NoNetwork: return "no_network";
    case FailReason::PermissionDenied: return "permission_denied";
    }
    return "";
}

struct AttemptResult {
    quint64 attempt = 0;
    int startMode = -1;          // filled by the engine: the transport mode IN FORCE when the attempt began (K1)
    quint64 intentEpoch = 0;     // filled by the engine: the facade's intent epoch the attempt was begun under (H3)
    bool connected = false;
    FailReason reason = FailReason::None;
    PathCandidate path;          // Connected: the path that carried data
    bool preferredTried = false; // a preferred path was brought up in this attempt (the notice may say "does not work")
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
// Yield: the leg in flight gives way to a proven path (ProofReady) - journal it; the StopPath follows.
// LocalBuildOverrun: the device did not finish building the leg's tunnel within localBuildMs (`timeoutMs` = how
// long it built) - a local outcome, nothing recorded against the path; journal it, the StopPath follows.
enum class EffectType { StartPath, StopPath, RunDataCheck, Report, Show, Finish, StopUnconfirmed, Yield,
                        LocalBuildOverrun };

struct AttemptEffect {
    EffectType type = EffectType::Show;
    PathStamp stamp;          // StartPath / StopPath / RunDataCheck: echo it in every callback
    PathCandidate path;
    int timeoutMs = 0;        // StartPath: start deadline; RunDataCheck: the check's own limit (it answers by then)
    bool recheck = false;     // RunDataCheck: run the check again on the same tunnel (the previous one is void)
    bool lead = false;        // StartPath: the path a proof named (not the head of the order)
    QString toPath;           // Yield: the proven path the leg gives way to
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
    // The race proved a path of this network (`lead`: that path), or the running data check starves (`starved`: no
    // first byte within its share, no `lead`). A starving leg yields to a proof of this attempt (see the header).
    ProofReady,
    // The person refused the system's VPN permission dialog while this leg was starting (stamp = the leg). The
    // tunnel never started: the attempt ends PermissionDenied at once - nothing recorded, no other leg. (While the
    // dialog is pending the host delivers no ticks, so no deadline runs; see "Clock" above.)
    PermissionDenied,
    // The platform builds this leg's tunnel interface (`building`) or has built it (see "Local build" above).
    LocalBuild,
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
    bool starved = false;                            // ProofReady: the running data check has no first byte yet
    QString lead;                                    // UserStart, ProofReady: the path a proof named (see the header)
    bool building = false;                           // LocalBuild: true = building, false = built

    static AttemptEvent userStart(qint64 now, const UserChoice &c, TransportMode m, const NetworkKey &net,
                                  const QString &lead = {})
    {
        AttemptEvent e = at(EventType::UserStart, now);
        e.choice = c;
        e.mode = m;
        e.network = net;
        e.lead = lead;
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
    static AttemptEvent permissionDenied(qint64 now, const PathStamp &s) { return cb(EventType::PermissionDenied, now, s); }
    static AttemptEvent localBuild(qint64 now, const PathStamp &s, bool building)
    {
        AttemptEvent e = cb(EventType::LocalBuild, now, s);
        e.building = building;
        return e;
    }
    static AttemptEvent proofReady(qint64 now, bool starved, const QString &lead = {})
    {
        AttemptEvent e = at(EventType::ProofReady, now);
        e.starved = starved;
        e.lead = lead;
        return e;
    }
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
    ApiReach controlPlane = ApiReach::Unknown; // lane C: the direct control plane of the owner's network
};

class AttemptOwner {
public:
    explicit AttemptOwner(AttemptTimings t = {}) : m_t(t) {}

    QList<AttemptEffect> handle(const AttemptEvent &ev, const SelectionContext &ctx)
    {
        const bool resumed = advance(ev.nowMs);
        if (resumed)
            onResumed();
        QList<AttemptEffect> out;
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
                m_checkSuspended = false;
                endLocalBuild(); // up without "built" (the platform reports both at once): the build ends here
                m_leg.upAt = m_awake;
                m_leg.deadline = m_awake + checkDeadlineMs();
                out << effect(EffectType::RunDataCheck, m_t.dataCheckMs) << show(AttemptPhase::Checking);
            }
            break;
        case EventType::DataChecked:
            if (isLiveLeg(ev.stamp) && m_phase == AttemptPhase::Checking) {
                if (ev.outcome == PathOutcome::DataOk)
                    connected(ev.ttfbMs, out);
                else if (m_checkSuspended)
                    recheck(out); // the check spanned a suspension: it did not happen
                else if (ev.outcome == PathOutcome::Inconclusive && m_leg.rechecks < m_t.maxRechecks)
                    recheck(out);
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
        case EventType::ProofReady: onProofReady(ev, ctx, out); break;
        case EventType::PermissionDenied:
            if (m_running && isLiveLeg(ev.stamp) && m_phase == AttemptPhase::Starting) {
                // nothing was raised and nothing is judged: no report, no stop, no next choice
                m_phase = AttemptPhase::Idle;
                m_leg = Leg{};
                finish(failure(FailReason::PermissionDenied), out);
            }
            break;
        case EventType::LocalBuild: onLocalBuild(ev); break;
        }
        // A check that was running across a suspension and has not answered yet: void, run it again.
        if (m_checkSuspended && m_phase == AttemptPhase::Checking)
            recheck(out);
        checkDeadlines(ctx, out);
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
    // The running leg's own build ("Local build"): in progress, and the device's time spent on it so far.
    bool legBuilding() const { return m_leg.buildSince >= 0; }
    qint64 legLocalBuildMs() const { return m_leg.localMs + (m_leg.buildSince >= 0 ? m_awake - m_leg.buildSince : 0); }
    const AttemptTimings &timings() const { return m_t; }
    // New numbers (the server may tune them): they apply from the next deadline that is set.
    void setTimings(const AttemptTimings &t) { m_t = t; }
    // The platform reports its builds (see "Local build" in the header): from the next leg on, a leg is local until
    // its own "built". false (default: iOS, desktop): a leg is judged from its start unless a "building" of its own
    // arrives (iOS: a start parked behind a teardown).
    void setLocalBuildReported(bool on) { m_localBuildReported = on; }
    bool localBuildReported() const { return m_localBuildReported; }

    // A provider leg: the seat lease and the native start, each with its own share (review E6 of 18.11).
    int startTimeoutMs(PathKind k) const
    {
        switch (k) {
        case PathKind::OwnAwg: return m_t.awgStartMs;
        case PathKind::OwnXray: return m_t.xrayStartMs;
        case PathKind::Provider: return m_t.providerLeaseMs + m_t.providerStartMs;
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
        int rechecks = 0; // inconclusive checks run again on this leg
        qint64 buildSince = -1; // awake time the platform began building the leg's tunnel interface (-1: not building)
        qint64 localMs = 0;     // the device's own build time of this leg (not the server's; "Local build")
    };

    // "Local build" (see the header). Building: the start deadline stops, the local bound runs instead. Built: the
    // server's part begins - the leg has its full start deadline from now.
    void onLocalBuild(const AttemptEvent &ev)
    {
        if (!m_running || !isLiveLeg(ev.stamp) || m_phase != AttemptPhase::Starting)
            return;
        if (ev.building) {
            if (m_leg.buildSince < 0) {
                m_leg.buildSince = m_awake;
                m_leg.deadline = m_awake + m_t.localBuildMs;
            }
        } else if (m_leg.buildSince >= 0) {
            endLocalBuild();
            m_leg.deadline = m_awake + startTimeoutMs(m_leg.path.kind);
        }
    }
    void endLocalBuild()
    {
        if (m_leg.buildSince < 0)
            return;
        m_leg.localMs += m_awake - m_leg.buildSince;
        m_leg.buildSince = -1;
    }

    // true: the gap since the last event was a suspension (none of it counts).
    bool advance(qint64 now)
    {
        bool suspended = false;
        if (m_lastNow >= 0 && now > m_lastNow) {
            const qint64 gap = now - m_lastNow;
            suspended = gap > m_t.clockJumpMs;
            if (!suspended)
                m_awake += gap;
        }
        if (now > m_lastNow)
            m_lastNow = now;
        return suspended;
    }

    // Back from a suspension: what the platform did meanwhile arrives now - the leg in flight gets time for it;
    // a check that was running did not happen (its answer, if any, is not a verdict on the path).
    void onResumed()
    {
        if (m_phase == AttemptPhase::Starting)
            m_leg.deadline = std::max(m_leg.deadline, m_awake + m_t.resumeGraceMs);
        else if (m_phase == AttemptPhase::Checking)
            m_checkSuspended = true;
        else if (m_phase == AttemptPhase::Stopping)
            m_stopDeadline = std::max(m_stopDeadline, m_awake + m_t.resumeGraceMs);
    }

    int checkDeadlineMs() const { return m_t.dataCheckMs + m_t.checkGraceMs; }

    // The data check again on the same tunnel; the platform drops the previous one (nothing recorded).
    void recheck(QList<AttemptEffect> &out)
    {
        if (!m_checkSuspended)
            ++m_leg.rechecks;
        m_checkSuspended = false;
        m_leg.deadline = m_awake + checkDeadlineMs();
        AttemptEffect e = effect(EffectType::RunDataCheck, m_t.dataCheckMs);
        e.recheck = true;
        out << e;
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
        // A server's silence is evidence only after a start that left the device: a leg the platform still holds in
        // its local phase ("Local build": building, parked behind the previous session's teardown) is never judged
        // no_handshake (device round air-B 24.11).
        if (o == PathOutcome::NoHandshake && m_leg.buildSince >= 0)
            o = PathOutcome::Inconclusive;
        if (!isAttributable(o))
            return;
        AttemptEffect e = effect(EffectType::Report);
        // One network per report: the key and the generation are both the owner's current network's - the one the
        // outcome was observed on. A leg in flight never outlives its network (a change stops it, unrecorded), so for
        // it this is the leg's own network; a live session does (it stays up across a change), and its loss is
        // evidence about the network it was lost on. Device round 12: the new network's key went out with the old
        // leg's generation, the write was dropped as not current and the server stayed "working" there.
        e.report.network = m_net.local;
        e.report.networkGeneration = m_net.generation;
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
        // the server's part only: the device's own build time is not the path's connect time
        report(PathOutcome::DataOk, int(m_leg.upAt - m_leg.startedAt - m_leg.localMs), ttfbMs, out);
        m_phase = AttemptPhase::Connected;
        AttemptResult res;
        res.connected = true;
        res.path = m_leg.path;
        res.fallbackNotice = m_choice.kind == UserChoice::Kind::PreferCountry && !isPreferred(m_choice, m_leg.path);
        res.preferredTried = m_preferredTried;
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
        if (legActive() && m_awake >= m_leg.deadline) {
            if (m_phase == AttemptPhase::Starting && m_leg.buildSince >= 0) {
                // the device never finished building its own tunnel: a local outcome, nothing about the server
                AttemptEffect e = effect(EffectType::LocalBuildOverrun, int(legLocalBuildMs()));
                out << e;
                failLeg(PathOutcome::Inconclusive, out);
                return;
            }
            failLeg(m_phase == AttemptPhase::Starting ? PathOutcome::NoHandshake : PathOutcome::NoData, out);
        }
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
        m_lead = ev.lead;
        noteProof(ev.lead);
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
        m_lead.clear(); // a proof of the old network says nothing about this one
        m_proofs.clear();
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
        m_preferredTried = false;
        m_lead.clear();
        m_proofs.clear(); // the proofs of an earlier attempt's race are not this attempt's
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

    // The order of the next choice on the owner's network (what beginNext would pick now).
    QList<RankedPath> order(const SelectionContext &ctx) const
    {
        SelectInput in;
        in.pool = ctx.pool;
        if (ctx.ledger)
            in.evidence = ctx.ledger->viewOf(m_net.local, ctx.pool, ctx.wallNowMs);
        in.choice = m_choice;
        in.mode = m_mode;
        in.crowd = ctx.crowd;
        in.controlPlane = ctx.controlPlane;
        in.tried = m_tried;
        in.nowMs = ctx.wallNowMs;
        in.preferredRetryAfterMs = ctx.ledger ? ctx.ledger->tunables().quarantineMs[0] : 0;
        return selectPaths(in);
    }

    // The lead if the ordinary choice could take it (see the header), else -1. `ranked` = order(ctx).
    static int leadIndex(const QList<RankedPath> &ranked, const QString &lead)
    {
        if (lead.isEmpty() || ranked.isEmpty())
            return -1;
        for (int i = 0; i < ranked.size(); ++i) {
            if (ranked.at(i).path.id.id != lead)
                continue;
            if (ranked.at(i).view.state != PathState::Working)
                return -1;
            return ranked.first().preferred && !ranked.at(i).preferred ? -1 : i;
        }
        return -1;
    }

    // A path the race of this attempt proved on this network (kept in the order the proofs were named).
    void noteProof(const QString &pathId)
    {
        if (!pathId.isEmpty() && !m_proofs.contains(pathId))
            m_proofs << pathId;
    }

    void onProofReady(const AttemptEvent &ev, const SelectionContext &ctx, QList<AttemptEffect> &out)
    {
        if (!m_running)
            return;
        noteProof(ev.lead); // whatever the leg in flight does with it now
        if (!legActive() || exact())
            return;
        // The person's own choice gets its full try (device round 19.11: a chosen provider server was left 1 s
        // into its check for a proven path of another country). A fallback follows only its real failure.
        if (isPreferred(m_choice, m_leg.path))
            return;
        const bool proven = ctx.ledger
            && ctx.ledger->view(m_net.local, m_leg.path.id, ctx.wallNowMs).state == PathState::Working;
        const bool blind = m_phase == AttemptPhase::Starting && !proven;
        const bool starved = m_phase == AttemptPhase::Checking && ev.starved;
        if (!blind && !starved)
            return;
        const QList<RankedPath> next = order(ctx);
        int li = leadIndex(next, ev.lead);
        if (starved) {
            // Up and being checked: only a proof of THIS attempt ends it, never the ledger's history alone.
            for (int i = 0; li < 0 && i < m_proofs.size(); ++i)
                li = leadIndex(next, m_proofs.at(i));
            if (li < 0)
                return; // no proof waits: the leg keeps its whole data check and writes its own outcome
        } else if (li < 0 && (next.isEmpty() || next.first().view.state != PathState::Working)) {
            return;
        }
        const PathCandidate &to = next.at(li < 0 ? 0 : li).path;
        AttemptEffect y = effect(EffectType::Yield);
        y.phase = m_phase;
        y.toPath = to.id.id;
        out << y;
        m_lead = to.id.id; // the next leg goes to the path it yields to, whatever lands while it stops
        failLeg(PathOutcome::Inconclusive, out); // its check did not complete: nothing recorded
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
        m_leg.deadline = m_awake + checkDeadlineMs();
        m_phase = AttemptPhase::Checking;
        m_checkSuspended = false;
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
        const QList<RankedPath> ranked = order(ctx);
        m_progressTotal = m_pathsThisNet + int(ranked.size());
        if (ranked.isEmpty()) {
            const bool nothingEver = m_pathsTotal == 0 && !exact();
            return finish(failure(nothingEver ? FailReason::NoCandidate : FailReason::NothingProven), out);
        }
        const int li = leadIndex(ranked, std::exchange(m_lead, QString()));
        const PathCandidate next = ranked.at(li < 0 ? 0 : li).path;
        m_preferredTried = m_preferredTried || isPreferred(m_choice, next);
        m_tried.insert(next.id.id);
        ++m_pathsThisNet;
        ++m_pathsTotal;
        m_leg = Leg{};
        m_leg.stamp = PathStamp{ m_attempt, m_net.generation, ++m_legSeq };
        m_leg.path = next;
        m_leg.startedAt = m_awake;
        m_leg.deadline = m_awake + startTimeoutMs(next.kind);
        if (m_localBuildReported) {
            // the device's time until this leg's own "built" (the start may wait in the service): the local bound runs
            m_leg.buildSince = m_awake;
            m_leg.deadline = m_awake + m_t.localBuildMs;
        }
        m_phase = AttemptPhase::Starting;
        AttemptEffect start = effect(EffectType::StartPath, startTimeoutMs(next.kind));
        start.lead = li >= 0;
        out << start << show(AttemptPhase::Starting);
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
    bool m_checkSuspended = false; // the running data check spanned a suspension
    bool m_localBuildReported = false; // the platform reports its builds: a leg is local until its own "built"
    bool m_preferredTried = false; // a preferred path was brought up in this attempt
    QString m_lead;                // the path a proof named: the next choice takes it (see the header)
    QStringList m_proofs;          // the paths the race of THIS attempt proved on this network (see the header)
};

} // namespace avpn::path

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
#include "../path/PathRace.h"

#include <QHash>
#include <QList>
#include <QString>

#include <functional>
#include <limits>
#include <map>
#include <utility>

namespace avpn::path::sim {

struct Behaviour {
    // Works: up, the check proves data after checkMs (past the check's own limit = a late but complete payload).
    // NoData: up, the check answers "no data" at its own limit. Silent: up, the check never answers (the owner's
    // backstop deadline judges it).
    // ControlPlane: up, the check could not reach our endpoints while the tunnel carried data (R1 of device round 4:
    // the facade's attribution gate answers Inconclusive).
    enum class Kind { Works, NoHandshake, NoData, StartError, NoSeat, Silent, ControlPlane };
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
    static Behaviour silent(int upMs) { return { Kind::Silent, upMs, 0, -1, true }; }
    static Behaviour controlPlaneDown(int upMs) { return { Kind::ControlPlane, upMs, 0, -1, true }; }
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

// Stage 2: what a light probe of a path does on a network. Default (no probe script): derived from the tunnel
// behaviour - works -> probe ok, no data -> probe fails, no handshake -> the probe never answers, refusals fail.
struct ProbeBehaviour {
    enum class Kind { Ok, Fail, Silent };
    Kind kind = Kind::Silent;
    int ms = 900;
    qint64 bytes = 70 * 1024;
    bool loseAnswer = false; // provider: the batch API's answer is lost (the probe seat lives until the server's TTL)
    static ProbeBehaviour ok(int ms, qint64 bytes = 70 * 1024) { return { Kind::Ok, ms, bytes, false }; }
    static ProbeBehaviour fail(int ms, qint64 bytes = 4096) { return { Kind::Fail, ms, bytes, false }; }
    static ProbeBehaviour silent() { return { Kind::Silent, 0, 0, false }; }
    static ProbeBehaviour lostAnswer() { return { Kind::Silent, 0, 0, true }; }
};

// network local key -> path id -> script; a path without a script on a network does not handshake there.
struct World {
    QHash<QString, QHash<QString, PathScript>> scripts;

    void set(const QString &net, const QString &path, const PathScript &s) { scripts[net][path] = s; }
    void set(const QString &net, const QString &path, const Behaviour &b) { set(net, path, PathScript::always(b)); }
    QHash<QString, QHash<QString, ProbeBehaviour>> probes;
    void setProbe(const QString &net, const QString &path, const ProbeBehaviour &b) { probes[net][path] = b; }
    ProbeBehaviour probeAt(const QString &net, const QString &path, PathKind kind, qint64 t) const
    {
        if (probes.value(net).contains(path))
            return probes.value(net).value(path);
        const Behaviour b = at(net, path, t);
        switch (b.kind) {
        case Behaviour::Kind::Works:
            return ProbeBehaviour::ok(kind == PathKind::Provider ? 1500 : std::min(b.upMs + 300, 1100));
        case Behaviour::Kind::NoData: return ProbeBehaviour::fail(1500);
        case Behaviour::Kind::StartError:
        case Behaviour::Kind::NoSeat: return ProbeBehaviour::fail(300);
        case Behaviour::Kind::NoHandshake:
        case Behaviour::Kind::Silent:
        case Behaviour::Kind::ControlPlane: break;
        }
        return ProbeBehaviour::silent();
    }
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
    SelectionContext ctx() const
    {
        SelectionContext c{ m_pool, &ledger, wall(), crowd };
        c.controlPlane = controlPlane; // lane C (the engine's rule, ServiceEngine::ownerContext)
        const QHash<QString, double> prior = restrictedNetworkPrior(
            m_pool, ledger.viewOf(tracker.current().local, m_pool, wall()), controlPlane, tracker.current().cellular());
        for (auto it = prior.constBegin(); it != prior.constEnd(); ++it)
            c.crowd.insert(it.key(), it.value());
        for (const QString &id : raceFailed) // the engine's rule (ServiceEngine::ownerContext)
            c.crowd.insert(id, 0.0);
        if (race.running())
            for (const QString &id : race.inFlightPathIds())
                c.crowd.insert(id, 0.0);
        c.systemAsleep = systemAsleep; // the engine's rule (ServiceEngine::ownerContext, setSystemAwake)
        return c;
    }
    // "System asleep" (AttemptOwner.h; the macOS desktop app, SystemAwake.h): the platform says the system is not
    // fully awake - a Power Nap dark wake is a stretch of virtual time where ticks and callbacks run with this set
    // (deep sleep between them: suspend()). The platform side plays the facade: no data check starts meanwhile
    // (AvpnEngineQml::startDataPathVerification is held). The counters say what the owner did while asleep.
    bool systemAsleep = false;
    int startsAsleep = 0;  // StartPath effects
    int checksAsleep = 0;  // RunDataCheck effects (not run: the facade holds them)
    int reportsAsleep = 0; // Report effects
    int stopsAsleep = 0;   // StopPath effects
    // The engine's edge (ServiceEngine::setSystemAwake): the fact changes and the owner gets an event at once.
    void setSystemAsleep(bool asleep)
    {
        systemAsleep = asleep;
        deliver(AttemptEvent::tick(now));
    }
    ApiReach controlPlane = ApiReach::Unknown; // lane C: ConfigService::directApiReach of the current network
    QSet<QString> raceFailed; // paths whose probe failed in the race of this tap
    void setPool(const QList<PathCandidate> &pool) { m_pool = pool; }
    const QList<PathCandidate> &pool() const { return m_pool; }
    World &world() { return m_world; }
    int checksRun = 0;   // RunDataCheck effects (rechecks included)
    int rechecks = 0;    // of them, runs again on the same tunnel
    // The platform's own build of a leg's tunnel interface (AttemptOwner.h "Local build"; Android: the VPN service
    // until VpnService.Builder.establish() returned). -1 (default): the platform does not report it - no event, the
    // path's behaviour runs from the leg's start (iOS, desktop). >= 0: LocalBuild(building) at the leg's start and
    // LocalBuild(built) this long after it; the path's behaviour (upMs, refusals) counts from "built".
    // kBuildNever: the build never finishes (no "built", no callback of the path). Per path: buildMsFor.
    static constexpr int kBuildNever = std::numeric_limits<int>::max();
    int buildMs = -1;
    QHash<QString, int> buildMsFor;
    // The service that builds (android2 V2, 21.11): `buildReachMs` - the start command reaches it this long after it was
    // sent; `serialBuilds` - it builds one start at a time and a stop does not cut a build short, so a start sent during
    // the previous leg's build begins only when that build ends. Defaults: at once, independent (the model above).
    int buildReachMs = 0;
    bool serialBuilds = false;
    int localOverruns = 0; // LocalBuildOverrun effects
    // The iOS native (IosController + the extension; device round air-B 24.11): ONE tunnel session at a time. With `on`
    // a stop tears the session down for stopUpMs when the extension's start of that leg had finished (the path's
    // tunnel up, or extStartMs after the start for a path that never comes up), and for stopStartingMs when the stop
    // came while that start was still running (24.11: 25 s for an Xray leg stopped 0.2 s into its start; 0.4-1.0 s for
    // a leg already up). A start sent while a teardown runs is PARKED until it ends - the path's behaviour counts from
    // there; a stop of a parked start joins the teardown (its one Disconnected confirms both, as on the device). With
    // `parkReported` the native says so (IosController::startAwaitsTeardown -> LocalBuild building at the park, built
    // when the start goes out); without it, the build before the fix.
    struct IosNative {
        bool on = false;
        bool parkReported = false;
        int stopUpMs = 500;
        int stopStartingMs = 500;
        int extStartMs = 1300;            // the extension's own start of a path that never comes up
        QHash<QString, int> extStartMsFor; // per path; kBuildNever = that start never finishes (settings never call back)
    };
    IosNative ios;
    int parkedStarts = 0;

    // --- driving --------------------------------------------------------------------------------------------
    void deliver(const AttemptEvent &ev) { apply(owner.handle(ev, ctx())); }

    // --- stage 2: the race in front of the owner (the engine's rule: ServiceEngine::beginRaceForTap) ---------
    PathRace race;
    ProberCaps caps;            // available = false: no host (stage-1 behaviour)
    qint64 bytesLeft = -1;      // -1 = no cap (Wi-Fi); cellular: the Scanner's hour budget
    qint64 bytesSpent = 0;
    int probesStarted = 0;
    int providerProbes = 0;
    int lostSeatAnswers = 0;    // provider probe seats left to the server's TTL
    int yields = 0;             // legs that gave way to a proven path (ProofReady)
    // The facade's starving data check (WhoamiVerdict.h kWhoamiFirstByteShareMs): no first byte this long after the
    // check started -> ProofReady(starved), no path named (the engine's rule: ServiceEngine::noteCheckStarved - the
    // owner knows the proofs of its attempt itself). -1 = not modelled.
    int starveShareMs = -1;
    // The rule in front of the owner, for comparisons with the device rounds of 19.11 (test only; production = Proposed):
    //  Old     (build 086b20e0a): the first choice starts blind at once, only a starving check yields, no lead;
    //  Current (build 74da6399f): as Old, and a leg not up yet yields to any proof (the choice after the stop, no lead);
    //  Proposed: race first with no evidence, the first proof leads, only a starving check yields.
    enum class Rule { Proposed, Old, Current };
    Rule rule = Rule::Proposed;
    bool raceFirst = false;
    qint64 ownerStartedMs = -1;
    QStringList raceLog;

    AttemptResult raceTap(const UserChoice &c, TransportMode mode = TransportMode::Auto, qint64 maxMs = 120000)
    {
        m_tapAt = now;
        ownerStartedMs = -1;
        const quint64 before = owner.attempt();
        raceFirst = false;
        raceFailed.clear();
        // Lane C (C2): the race's session comes over the direct API; unreachable and no session -> no race, the owner
        // starts at once (ServiceEngine::beginRaceForTap)
        const bool noSession = !caps.ready && controlPlane == ApiReach::Unreachable;
        if (caps.available && !noSession && c.kind != UserChoice::Kind::ExactPath) {
            SelectInput in;
            in.pool = m_pool;
            in.evidence = ledger.viewOf(tracker.current().local, m_pool, wall());
            in.choice = c;
            in.mode = mode;
            in.controlPlane = controlPlane;
            in.crowd = ctx().crowd;
            const QList<RankedPath> order = selectPaths(in);
            const bool known = !order.isEmpty() && order.first().view.state == PathState::Working;
            QList<PathCandidate> list;
            for (int i = known ? 1 : 0; i < order.size(); ++i)
                list << order.at(i).path;
            if (rule == Rule::Proposed)
                list = raceSpread(list); // the engine's rule (ServiceEngine::beginRaceForTap)
            m_raceChoice = c;
            m_raceMode = mode;
            if (rule != Rule::Proposed) {
                RaceTimings t = race.timings();
                t.hedgeMs = 0; // the blind leg at once (the hedge of both earlier builds)
                race.setTimings(t);
            }
            raceFirst = !known && !list.isEmpty();
            applyRace(race.begin(now, list, tracker.current(), caps, bytesLeft, PathRace::Costs{}));
            if (raceFirst && !race.running())
                raceFirst = false;
        }
        if (!raceFirst && ownerStartedMs < 0) { // never a second start: the race may have started the owner already
            ownerStartedMs = now;
            deliver(AttemptEvent::userStart(now, c, mode, tracker.current()));
        }
        const auto done = [&] { return !results.isEmpty() && results.last().attempt > before; };
        run(done, maxMs);
        return done() ? results.last() : AttemptResult{};
    }

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
            {
                if (race.running())
                    applyRace(race.networkChanged(now, tracker.current()));
                deliver(AttemptEvent::networkChanged(now, tracker.current()));
            }
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
            {
                if (race.running())
                    applyRace(race.tick(now));
                deliver(AttemptEvent::tick(now));
            }
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
                if (systemAsleep)
                    ++startsAsleep;
                if (race.running()) // the leg's own path leaves the race (CONNECT-INVARIANTS §32 p. 3)
                    applyRace(race.legStarted(now, e.path.id.id));
                const QString net = tracker.current().local;
                legs.append({ e.stamp, e.path.id.id, net, now });
                const Behaviour b = m_world.at(net, e.path.id.id, now);
                m_legBehaviour.insert(e.stamp.leg, b);
                // the platform's own build (buildMs): the path's part starts when the interface is built
                const int build = buildMsFor.value(e.path.id.id, buildMs);
                qint64 base = now;
                if (build >= 0) {
                    qint64 begin = now + buildReachMs;
                    if (serialBuilds)
                        begin = std::max(begin, m_serviceFreeAt);
                    schedule(begin, AttemptEvent::localBuild(0, e.stamp, true));
                    if (build == kBuildNever) {
                        m_serviceFreeAt = std::numeric_limits<qint64>::max();
                        break;
                    }
                    base = begin + build;
                    m_serviceFreeAt = base;
                    schedule(base, AttemptEvent::localBuild(0, e.stamp, false));
                }
                if (ios.on) {
                    if (m_teardownEnd > now) { // parked behind the previous session's teardown
                        ++parkedStarts;
                        base = m_teardownEnd;
                        if (ios.parkReported) {
                            schedule(now, AttemptEvent::localBuild(0, e.stamp, true));
                            schedule(base, AttemptEvent::localBuild(0, e.stamp, false));
                        }
                    }
                    m_legGoesOut.insert(e.stamp.leg, base);
                    const bool comesUp = b.kind == Behaviour::Kind::Works || b.kind == Behaviour::Kind::NoData
                        || b.kind == Behaviour::Kind::Silent || b.kind == Behaviour::Kind::ControlPlane;
                    const int ext = ios.extStartMsFor.value(e.path.id.id, comesUp ? b.upMs : ios.extStartMs);
                    m_legExtStarted.insert(e.stamp.leg, ext == kBuildNever ? std::numeric_limits<qint64>::max() : base + ext);
                }
                switch (b.kind) {
                case Behaviour::Kind::Works:
                case Behaviour::Kind::NoData:
                case Behaviour::Kind::Silent:
                case Behaviour::Kind::ControlPlane: schedule(base + b.upMs, AttemptEvent::tunnelUp(0, e.stamp)); break;
                case Behaviour::Kind::NoHandshake: break; // the owner's start deadline judges it
                case Behaviour::Kind::StartError:
                    schedule(base + 50, AttemptEvent::pathFailed(0, e.stamp, b.attributable ? PathOutcome::Refused
                                                                                            : PathOutcome::Inconclusive));
                    break;
                case Behaviour::Kind::NoSeat:
                    schedule(base + 300, AttemptEvent::pathFailed(0, e.stamp, PathOutcome::NoSeat));
                    break;
                }
                break;
            }
            case EffectType::RunDataCheck: {
                if (systemAsleep) {
                    ++checksAsleep; // the facade holds the check while the system sleeps (the owner reruns it)
                    break;
                }
                // an adopted leg was never started here: the network's behaviour for that path decides
                // the first check: the behaviour the leg started with; a check run again: the network as it is now
                const Behaviour b = m_legBehaviour.contains(e.stamp.leg) && !e.recheck
                    ? m_legBehaviour.value(e.stamp.leg)
                    : m_world.at(tracker.current().local, e.path.id.id, now);
                ++checksRun;
                m_checkStarved = false;
                const bool firstByteLate = b.kind != Behaviour::Kind::Works || b.ttfbMs > starveShareMs;
                if (starveShareMs >= 0 && firstByteLate) {
                    const PathStamp st = e.stamp;
                    const int g = m_checkGen.value(e.stamp.leg) + 1; // the generation this check gets below
                    at(now + starveShareMs, [this, st, g] {
                        if (m_checkGen.value(st.leg) != g || owner.currentLeg() != st
                            || owner.phase() != AttemptPhase::Checking)
                            return;
                        m_checkStarved = true;
                        if (rule == Rule::Proposed)
                            deliver(AttemptEvent::proofReady(now, true));
                        else
                            yieldStarvedAsBefore();
                    });
                }
                rechecks += e.recheck ? 1 : 0;
                // a check run again voids the previous one on that leg (its answer is dropped, as the platform does)
                const int gen = ++m_checkGen[e.stamp.leg];
                const quint64 leg = e.stamp.leg;
                const auto answer = [this, leg, gen](qint64 t, const AttemptEvent &ev) {
                    at(t, [this, leg, gen, ev] {
                        if (m_checkGen.value(leg) != gen)
                            return;
                        AttemptEvent x = ev;
                        x.nowMs = now;
                        deliver(x);
                    });
                };
                if (b.kind == Behaviour::Kind::Works)
                    answer(now + b.checkMs, AttemptEvent::dataChecked(0, e.stamp, PathOutcome::DataOk, b.ttfbMs));
                else if (b.kind == Behaviour::Kind::NoData)
                    answer(now + e.timeoutMs, AttemptEvent::dataChecked(0, e.stamp, PathOutcome::NoData));
                else if (b.kind == Behaviour::Kind::ControlPlane)
                    answer(now + e.timeoutMs, AttemptEvent::dataChecked(0, e.stamp, PathOutcome::Inconclusive));
                break; // Silent: nothing comes, the owner's backstop deadline judges it
            }
            case EffectType::StopPath:
                if (systemAsleep)
                    ++stopsAsleep;
                if (ios.on) {
                    // a parked start that has not gone out: nothing of it runs, its stop joins the running teardown
                    if (m_legGoesOut.value(e.stamp.leg, 0) <= now) {
                        const bool starting = now < m_legExtStarted.value(e.stamp.leg, 0);
                        m_teardownEnd = std::max(m_teardownEnd, now + (starting ? ios.stopStartingMs : ios.stopUpMs));
                    }
                    schedule(std::max(m_teardownEnd, now), AttemptEvent::stopConfirmed(0, e.stamp));
                    break;
                }
                schedule(now + stopMs, AttemptEvent::stopConfirmed(0, e.stamp));
                break;
            case EffectType::Report:
                if (systemAsleep)
                    ++reportsAsleep;
                reports.append(e.report);
                if (tracker.isCurrent(e.report.networkGeneration))
                    ledger.record(e.report.network, e.report.path, e.report.outcome, wall(), e.report.connectMs,
                                  e.report.ttfbMs);
                break;
            case EffectType::Finish:
                results.append(e.result);
                if (race.running())
                    at(now, [this] { applyRace(race.stop(now)); });
                break;
            case EffectType::Show: break;
            case EffectType::StopUnconfirmed: break;
            case EffectType::LocalBuildOverrun: ++localOverruns; break;
            case EffectType::Yield:
                ++yields;
                raceLog << QStringLiteral("yield:%1").arg(e.path.id.id);
                break;
            }
        }
    }

    QList<PathCandidate> m_pool;
    World m_world;
    std::map<std::pair<qint64, quint64>, std::function<void()>> m_queue;
    quint64 m_seq = 0;
    QList<std::pair<qint64, qint64>> m_suspend;
    QHash<quint64, Behaviour> m_legBehaviour;
    qint64 m_serviceFreeAt = 0; // serialBuilds: the end of the build in progress
    qint64 m_teardownEnd = -1;            // ios: the end of the teardown in progress
    QHash<quint64, qint64> m_legGoesOut;  // ios: when the leg's start left the device (after a park)
    QHash<quint64, qint64> m_legExtStarted; // ios: when the extension's own start of the leg finished
    QHash<quint64, int> m_checkGen;
    UserChoice m_raceChoice;
    TransportMode m_raceMode = TransportMode::Auto;
    bool m_checkStarved = false; // the running check passed its first-byte share (the facade's m_checkStarved)

    // Rule::Old / Rule::Current only - the starve yield of those builds: a starving check gave way as soon as ANY
    // untried path was "working" in the ledger, and the choice after the stop took the head of the order (no lead).
    // The owner no longer has that rule (AttemptOwner.h: only a proof of its own attempt ends a leg that is up), so
    // the emulation of the earlier builds ends the leg itself, nothing recorded.
    void yieldStarvedAsBefore()
    {
        if (owner.phase() != AttemptPhase::Checking)
            return;
        QSet<QString> tried;
        for (const LegTrace &l : legs)
            if (l.stamp.attempt == owner.attempt())
                tried.insert(l.path);
        for (const PathCandidate &c : m_pool) {
            if (tried.contains(c.id.id) || ledger.view(tracker.current().local, c.id, wall()).state != PathState::Working)
                continue;
            ++yields;
            raceLog << QStringLiteral("yield:%1").arg(owner.currentPath().id.id);
            deliver(AttemptEvent::pathFailed(now, owner.currentLeg(), PathOutcome::Inconclusive));
            return;
        }
    }

    void startOwnerAfterRace(const char *why, const QString &lead = {})
    {
        if (!raceFirst)
            return;
        raceFirst = false;
        ownerStartedMs = now;
        raceLog << QStringLiteral("owner:%1").arg(QLatin1String(why));
        deliver(AttemptEvent::userStart(now, m_raceChoice, m_raceMode, tracker.current(), lead));
    }

    void applyRace(const QList<RaceEffect> &effects)
    {
        for (const RaceEffect &e : effects) {
            switch (e.type) {
            case RaceEffectType::StartProbe: {
                ++probesStarted;
                raceLog << QStringLiteral("probe:%1").arg(e.path.id.id);
                const ProbeBehaviour b = m_world.probeAt(tracker.current().local, e.path.id.id, e.path.kind, now);
                if (e.path.kind == PathKind::Provider)
                    ++providerProbes;
                if (b.loseAnswer)
                    ++lostSeatAnswers;
                if (b.kind == ProbeBehaviour::Kind::Silent)
                    break; // the race's own bound cancels it
                const ProbeStamp st = e.stamp;
                const PathOutcome o = b.kind == ProbeBehaviour::Kind::Ok ? PathOutcome::ProbeOk : PathOutcome::NoData;
                const qint64 bytes = b.bytes;
                at(now + b.ms, [this, st, o, bytes] {
                    race.spent(bytes); // the prober's real-byte stream (the engine puts it on the cap and the hour ledger)
                    bytesSpent += bytes;
                    if (bytesLeft >= 0)
                        bytesLeft = std::max<qint64>(0, bytesLeft - bytes);
                    applyRace(race.probeDone(now, st, o));
                });
                break;
            }
            case RaceEffectType::CancelProbe:
                race.settled(e.stamp); // the simulated host has no spend left after a cancel
                break;
            case RaceEffectType::Failed:
                raceFailed.insert(e.path.id.id); // the engine's rule: the worst prior for this attempt
                raceLog << QStringLiteral("failed:%1").arg(e.path.id.id);
                break;
            case RaceEffectType::Report:
                reports.append(OutcomeReport{ e.network, e.networkGeneration, e.path.id, e.outcome, -1, -1 });
                if (tracker.isCurrent(e.networkGeneration))
                    ledger.record(e.network, e.path.id, e.outcome, wall(), e.ms);
                if (rule == Rule::Current && owner.phase() == AttemptPhase::Starting
                    && ledger.view(tracker.current().local, owner.currentPath().id, wall()).state != PathState::Working
                    && ledger.view(tracker.current().local, e.path.id, wall()).state == PathState::Working) {
                    // the yield of build 74da6399f: a leg not up yet gave way to any proof, nothing recorded
                    ++yields;
                    raceLog << QStringLiteral("yield:%1").arg(owner.currentPath().id.id);
                    deliver(AttemptEvent::pathFailed(now, owner.currentLeg(), PathOutcome::Inconclusive));
                } else if (owner.running() && (rule != Rule::Old || m_checkStarved)) {
                    // a proof while a leg is in flight (the engine's rule; build 086b20e0a: only to a starving check)
                    if (rule != Rule::Proposed && m_checkStarved)
                        yieldStarvedAsBefore();
                    else
                        deliver(AttemptEvent::proofReady(now, m_checkStarved,
                                                         rule == Rule::Proposed ? e.path.id.id : QString()));
                }
                break;
            case RaceEffectType::Winner:
                if (ledger.view(tracker.current().local, e.path.id, wall()).state == PathState::Working) {
                    race.acceptWinner(e.path.id.id);
                    raceLog << QStringLiteral("winner:%1").arg(e.path.id.id);
                    startOwnerAfterRace("winner", rule == Rule::Proposed ? e.path.id.id : QString());
                }
                break;
            case RaceEffectType::Hedge:
                startOwnerAfterRace("hedge");
                break;
            case RaceEffectType::Done:
                raceLog << QStringLiteral("done:%1").arg(QLatin1String(raceDoneReasonName(e.reason)));
                if (e.reason != RaceDoneReason::Stopped)
                    startOwnerAfterRace(raceDoneReasonName(e.reason));
                break;
            }
        }
    }
    qint64 m_tapAt = 0;
};

} // namespace avpn::path::sim

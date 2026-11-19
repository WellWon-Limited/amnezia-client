// client/core/serviceEngine/path/PathRace.h
// AVPN path engine, stage 2 (design 2026-11-17 §4 "known path at once + race of the spares", §5) - the probe race
// in FRONT of the attempt owner, as an explicit state machine: events in, effects out. [header-only, QtCore; pure:
// no timers, no I/O, no platform types]
//
// Contract with the owner (AttemptOwner.h, unchanged): the race writes its results into the ledger as outcomes
// (Report effects; the engine records them like the owner's). The owner reads the ledger at every choice, so a
// probe-proven path is simply a "working (probe strength)" path of this network and comes first. The race never
// raises a tunnel and never says "Connected": the in-tunnel data check of the owner stays the final gate (device
// round of 18.11: own Xray node 15 on LTE probes fine and carries no data through the real tunnel).
//
// Course of a race (the engine decides when one runs - ServiceEngine::connect):
//   Begin(candidates in the owner's order, network, budget) -> a window of waveSize candidates; probes start one per
//   staggerMs, at most `parallelism` in flight (capped by the host: legs, one provider profile at a
//   time - the Go engine runs one full Xray instance - and two AmneziaWG), each bounded by probeTimeoutMs.
//   ProbeDone(stamp, outcome, bytes): ProbeOk -> Report(probe ok) and, the first time, Winner(path); a failure is
//   NOT recorded (a light probe never quarantines a path - its result says "not proven", the owner's own legs
//   decide); bytes are charged (Spent) to the one byte ledger the Scanner uses.
//   Byte cap (device round 19.11: two of three LTE races spent 0.28 MB against 256 KB): a probe starts only when its
//   projected cost (IPathProber::costs: all its parts, an upper bound) fits what is left; the projection is what it
//   costs the cap - real bytes go to the Scanner's ledger, never back into this race's cap. A candidate that does
//   not fit is left to the owner's walk and the next, cheaper ones still start.
//   The window refills as probes end (the next wave); nothing left, the race budget
//   (awake time) over or nothing more the byte cap can pay -> Done(reason). The engine then lets the
//   owner walk one path at a time (stage-1 behaviour).
//   Stop / NetworkChanged: every probe in flight is cancelled; its answer, if it still comes, is dropped.
// Stamps: every probe is (race number, network generation, probe number); a result with any other stamp is
// dropped (an older race, an older network, a cancelled probe) - the same discipline as the owner's legs.
// Provider probes take a PROBE seat through the batch API (the platform host does it, never a session seat); at
// most providerPerRace provider probes per race bound the damage of a lost batch answer (each such seat lives
// until the server's probe TTL, 60 s).
#pragma once

#include "NetworkKey.h"
#include "PathLedger.h"
#include "PathSelect.h"

#include <QHash>
#include <QList>
#include <QSet>

#include <algorithm>

namespace avpn::path {

// The race's numbers (server-tunable through TuningStore, ConnectTunables.h::raceTimingsTuned); to be calibrated
// on device. Measured on iPhone Air (18.11, lead-142-app-probe): first proven candidate 0.9-1.2 s on Wi-Fi, 1.5 s on
// LTE; own Xray 0.4-1.1 s; provider profiles 0.8-3.7 s, one at a time.
struct RaceTimings {
    int parallelism = 4;        // probes in flight at once (further capped by the host's caps)
    int staggerMs = 250;        // between two probe starts
    // Candidates per window: above the host's in-flight total, so a kind that is capped (two AmneziaWG, the provider
    // pool) or slow never keeps the next kinds out (T1b of device round 6: the first proof came at 5.3 s on LTE).
    int waveSize = 10;
    int raceBudgetMs = 8000;    // awake time of one race; then the owner walks without it
    int probeTimeoutMs = 4000;  // one probe's own bound (the host answers by then)
    int providerPerRace = 3;    // provider probes per race (probe seats a lost batch answer can strand)
    // The race runs only when the ledger holds no working path for this network (ServiceEngine::beginRaceForTap: a
    // known path starts at once and the race runs beside it). With no evidence the first leg is not a blind bet: the
    // owner waits for the race's FIRST proof and starts that path (the proof is its lead, AttemptOwner.h). Only when
    // nothing is proven by hedgeAfterMs() does the owner start its first choice blind, the race running on beside it.
    // Device round 19.11 (iPhone Air, empty ledger, Auto): with the blind leg at once (0) and a leg that yields to a
    // proof, the Wi-Fi start dropped a working leg ~1 s in and took 5.56 s (3.7-3.9 s before); a blind leg that is kept
    // costs 7.5-8.2 s on LTE where it carries nothing; the race's first proof came 1.0-1.7 s after the tap on both.
    // -1 (default) = derived from the race's own numbers (hedgeAfterMs); 0 = at once (the old hedge); > 0 = this many ms.
    int hedgeMs = -1;
    int spareProofs = 1;        // proofs kept after the winner, then the race stops (no probing on)
    int knownFreshMin = 30;     // a known path that carried data here this recently: no race at all
    // bytes one race may spend on cellular (the Scanner's hour budget stays its own). A probe RESERVES its upper bound
    // while it runs (AmneziaWG 54,572, our Xray with its burst 116,736, a provider profile 107,520) and is charged
    // what it really spent when it ends, so dead paths (a few KB each) do not use the cap up. The first window fits
    // one probe of each kind plus a second AmneziaWG server (333,400); measured races spent 11-165 KB.
    int cellularMaxBytes = 393216;

    // How long the owner waits for a first proof before it starts blind: the last probe of the first parallel wave has
    // started (stagger x (parallelism - 1)) and has had half of a probe's own bound to answer. Defaults: 750 + 2000 =
    // 2750 ms - a working candidate answered in 0.6-1.5 s on every network measured (provider profiles up to 3.7 s),
    // and it is about a third of the race budget, so a network where nothing proves still walks most of it.
    int hedgeAfterMs() const
    {
        if (hedgeMs >= 0)
            return hedgeMs;
        return staggerMs * std::max(0, parallelism - 1) + probeTimeoutMs / 2;
    }
};

// What the platform's probe host can run at once (IScanHost caps of the spike: 6 legs, 1 full Xray, 2 AmneziaWG).
struct ProberCaps {
    bool available = false; // false = no host on this platform / build / server switch: stage-1 behaviour
    int inFlight = 6;   // probes the host keeps in flight in total (any kind)
    int providerAtOnce = 1;
    int awgAtOnce = 2;
    // The host can send a probe NOW (ScanPathProber: its signed session - manifest and token - is in hand). A host
    // that needs none keeps the default. Not ready and `preparing` (the session is being fetched): the engine holds
    // the race for a short bound; not ready and not preparing (nothing will come): no race, the owner walks at once.
    // A probe that cannot leave is never started (nothing reserved, nothing reported failed).
    bool ready = true;
    bool preparing = false;
};

struct ProbeStamp {
    quint64 race = 0;
    quint64 network = 0;
    quint64 probe = 0;
    bool operator==(const ProbeStamp &o) const { return race == o.race && network == o.network && probe == o.probe; }
};

enum class RaceDoneReason { None, Exhausted, Budget, Bytes, NetworkChanged, Stopped, Proven };

inline const char *raceDoneReasonName(RaceDoneReason r)
{
    switch (r) {
    case RaceDoneReason::None: return "none";
    case RaceDoneReason::Exhausted: return "exhausted";
    case RaceDoneReason::Budget: return "budget";
    case RaceDoneReason::Bytes: return "bytes";
    case RaceDoneReason::NetworkChanged: return "network_changed";
    case RaceDoneReason::Stopped: return "stopped";
    case RaceDoneReason::Proven: return "proven";
    }
    return "";
}

// Hedge: nothing proven within hedgeAfterMs() - the engine starts the owner on its first choice, the race runs on beside it.
// Failed: a probe ended without a proof (path, outcome) - not a ledger outcome (a probe is weaker than a tunnel), only
// a hint for the order of this attempt: the walk does not start with a server the race has just seen fail.
enum class RaceEffectType { StartProbe, CancelProbe, Report, Spent, Winner, Done, Hedge, Failed };

struct RaceEffect {
    RaceEffectType type = RaceEffectType::Done;
    ProbeStamp stamp;          // StartProbe / CancelProbe
    PathCandidate path;        // StartProbe / Report / Winner
    int timeoutMs = 0;         // StartProbe
    PathOutcome outcome = PathOutcome::Inconclusive; // Report (always ProbeOk)
    QString network;           // Report: local network key
    quint64 networkGeneration = 0;
    qint64 bytes = 0;          // Spent
    int ms = -1;               // Report: the probe's time to proof (its start to its answer) - the ledger's probe speed
    RaceDoneReason reason = RaceDoneReason::None; // Done
};

class PathRace {
public:
    explicit PathRace(RaceTimings t = {}) : m_t(t) {}

    // Costs of one probe per kind, in bytes: upper bounds from the prober (IPathProber::costs).
    struct Costs {
        qint64 awg = 90 * 1024;
        qint64 xray = 160 * 1024;
        qint64 provider = 160 * 1024;
        // The part of each projection spent OUTSIDE the probe host (the API calls around a probe: opening the scan,
        // a provider's seat batch with its config, the release). The host's byte count does not include it, so a
        // finished probe is charged its reported bytes PLUS this part (second review of 141, F8: a provider probe was
        // refunded its API share and the race could pass its cap).
        qint64 awgFixed = 0;
        qint64 xrayFixed = 0;
        qint64 providerFixed = 0;
        // The part of each `fixed` the Scanner's ledger already holds from the API calls themselves (real bytes): the
        // Spent effect carries the cap's charge minus this, so no byte reaches the hour budget twice or not at all.
        qint64 awgOutside = 0;
        qint64 xrayOutside = 0;
        qint64 providerOutside = 0;
    };

    // A new race (an older one ends first, its probes cancelled). bytesLeft < 0 = no byte cap (Wi-Fi without a
    // device budget); otherwise the race stops starting probes it cannot pay.
    QList<RaceEffect> begin(qint64 now, const QList<PathCandidate> &order, const NetworkKey &net, const ProberCaps &caps,
                            qint64 bytesLeft, const Costs &costs)
    {
        QList<RaceEffect> out;
        if (m_running)
            finish(RaceDoneReason::Stopped, out);
        m_running = caps.available && net.usable() && !order.isEmpty();
        if (!m_running)
            return out;
        ++m_race;
        m_net = net;
        m_caps = caps;
        m_costs = costs;
        m_bytesLeft = bytesLeft;
        m_order = order;
        m_next = 0;
        m_pending.clear();
        m_deferred.clear();
        m_providersQueued = 0;
        m_inFlight.clear();
        m_winner.clear();
        m_providersStarted = 0;
        m_unpaid = false;
        m_proven = 0;      // B2: per race
        m_legs.clear();
        m_hedged = false;
        m_lastNow = now;
        m_awake = 0;
        m_budgetEnd = m_t.raceBudgetMs;
        m_nextStartAt = 0;
        // Hedge at once: the first candidate (the owner's first choice, the same order) is the leg the engine raises
        // now - it is never probed beside it (legStarted); a different first choice of the owner is excluded when
        // its leg starts. Otherwise the first choice is probed like any candidate (no tunnel runs yet) and leaves the
        // race when the owner raises it.
        const bool atOnce = m_t.hedgeAfterMs() <= 0;
        if (atOnce)
            m_legs.insert(order.first().id.id);
        pump(out);
        if (m_running && atOnce) {
            m_hedged = true;
            RaceEffect h;
            h.type = RaceEffectType::Hedge;
            out << h;
        }
        return out;
    }

    QList<RaceEffect> probeDone(qint64 now, const ProbeStamp &s, PathOutcome outcome, qint64 bytes)
    {
        QList<RaceEffect> out;
        advance(now);
        const auto it = m_inFlight.find(s.probe);
        if (!m_running || s.race != m_race || s.network != m_net.generation || it == m_inFlight.end())
            return out; // stale: an older race, an older network, a cancelled or unknown probe
        const PathCandidate path = it.value().path;
        const int tookMs = int(std::max<qint64>(0, m_awake - it.value().startedAt));
        const qint64 reserved = it.value().reserved;
        m_inFlight.erase(it);
        // The cap: the probe reserved its upper bound at the start; now it is charged what it spent (never less than
        // kMinProbeChargeBytes - a host that reports nothing still used the network; never more than it reserved).
        // Device round 19.11 (LTE, three dead first candidates): 11 KB were spent, 327 KB stayed reserved, the race
        // ended "bytes" with nothing proven and the working servers were never probed.
        // One number: what the cap is charged is what the hour ledger gets (less what the API calls already put there).
        // bytes < 0: no byte of this probe reached the host (a candidate refused locally, a start the host refused): the
        // host side costs nothing - the charge follows what was sent, not the kind - only the API part (seat batch,
        // config, release: `outside`, already in the hour ledger by its real bytes) stays on the cap.
        if (bytes < 0) {
            if (m_bytesLeft >= 0)
                m_bytesLeft += reserved - std::min(reserved, outsideOf(path));
        } else {
            const qint64 raw = bytes + fixedOf(path);
            const qint64 charge = reserved > 0 ? std::clamp<qint64>(raw, std::min(kMinProbeChargeBytes, reserved), reserved) : raw;
            if (m_bytesLeft >= 0)
                m_bytesLeft += reserved - charge;
            // (a probe that went past its reservation - the host cuts at cost_bytes, so rarely - is charged what it used)
            const qint64 ledger = std::max<qint64>(0, std::max(charge, raw) - outsideOf(path));
            if (ledger > 0) { // the Scanner's ledger
                RaceEffect e;
                e.type = RaceEffectType::Spent;
                e.bytes = ledger;
                out << e;
            }
        }
        if (outcome == PathOutcome::ProbeOk) {
            RaceEffect r;
            r.type = RaceEffectType::Report;
            r.path = path;
            r.outcome = PathOutcome::ProbeOk;
            r.ms = tookMs;
            r.network = m_net.local;
            r.networkGeneration = m_net.generation;
            out << r;
            ++m_proven;
            if (!m_winner.isEmpty() && m_proven > 1 + m_t.spareProofs) {
                finish(RaceDoneReason::Proven, out); // B3: the winner and its spares are enough
                return out;
            }
            if (m_winner.isEmpty()) {
                // the engine tells whether the ledger now holds it as working (a tunnel no-data outranks a probe ok)
                RaceEffect w;
                w.type = RaceEffectType::Winner;
                w.path = path;
                out << w;
            }
        } else {
            RaceEffect f;
            f.type = RaceEffectType::Failed;
            f.path = path;
            f.outcome = outcome;
            out << f;
        }
        pump(out);
        return out;
    }

    // The engine confirms a Winner the ledger accepted (it is "working" there); a refused one leaves the race open.
    void acceptWinner(const QString &pathId) { m_winner = pathId; }
    bool hasWinner() const { return !m_winner.isEmpty(); }
    // The first proof of this race the ledger accepted (empty: none yet) - the lead of a leg that yields later.
    const QString &winner() const { return m_winner; }

    QList<RaceEffect> tick(qint64 now)
    {
        QList<RaceEffect> out;
        advance(now);
        if (!m_running)
            return out;
        if (!m_hedged && m_winner.isEmpty() && m_awake >= m_t.hedgeAfterMs()) {
            m_hedged = true;
            RaceEffect h;
            h.type = RaceEffectType::Hedge;
            out << h;
        }
        // a probe past its own bound and the host's grace: the host did not answer - cancel it, nothing recorded
        for (auto it = m_inFlight.begin(); it != m_inFlight.end();) {
            if (m_awake >= it.value().deadline) {
                out << cancelEffect(it.key(), it.value().path);
                it = m_inFlight.erase(it);
            } else {
                ++it;
            }
        }
        pump(out);
        return out;
    }

    QList<RaceEffect> networkChanged(qint64 now, const NetworkKey &net)
    {
        QList<RaceEffect> out;
        advance(now);
        if (net.generation <= m_net.generation)
            return out;
        if (m_running)
            finish(RaceDoneReason::NetworkChanged, out);
        m_net = net;
        return out;
    }

    // The owner brings this path up now (a leg): it leaves the race - a probe of it in flight is cancelled, it is
    // never started again in this race. CONNECT-INVARIANTS §32 p. 3: the target of a connect attempt is never probed
    // with the device's key from another socket (an AmneziaWG handshake from the probe would move the server's peer
    // address away from the tunnel coming up). Device round 19.11: the hedged leg's own node was probe 1 of every race.
    QList<RaceEffect> legStarted(qint64 now, const QString &pathId)
    {
        QList<RaceEffect> out;
        advance(now);
        if (!m_running || pathId.isEmpty())
            return out;
        m_legs.insert(pathId);
        for (int i = m_pending.size() - 1; i >= 0; --i)
            if (m_pending.at(i).id.id == pathId)
                m_pending.removeAt(i);
        for (auto it = m_inFlight.begin(); it != m_inFlight.end();) {
            if (it.value().path.id.id == pathId) {
                out << cancelEffect(it.key(), it.value().path);
                it = m_inFlight.erase(it);
            } else {
                ++it;
            }
        }
        pump(out);
        return out;
    }

    QList<RaceEffect> stop(qint64 now)
    {
        QList<RaceEffect> out;
        advance(now);
        if (m_running)
            finish(RaceDoneReason::Stopped, out);
        return out;
    }

    bool running() const { return m_running; }
    // The paths this race is probing right now (started, no answer yet).
    QSet<QString> inFlightPathIds() const
    {
        QSet<QString> ids;
        for (const Flight &f : m_inFlight)
            ids.insert(f.path.id.id);
        return ids;
    }
    quint64 raceNumber() const { return m_race; }
    int inFlight() const { return int(m_inFlight.size()); }
    int proven() const { return m_proven; }
    const RaceTimings &timings() const { return m_t; }
    void setTimings(const RaceTimings &t) { m_t = t; }

private:
    struct Flight {
        PathCandidate path;
        qint64 deadline = 0;
        qint64 startedAt = 0; // awake time of its start
        qint64 reserved = 0;  // bytes of the cap it holds while it runs (0 = no cap)
    };
    // The least a finished probe is charged against the cap, whatever the host reports.
    static constexpr qint64 kMinProbeChargeBytes = 8 * 1024;

    void advance(qint64 now)
    {
        // the same awake clock as the owner: a gap longer than 2.5 s is a suspension and does not count
        if (now > m_lastNow) {
            const qint64 gap = now - m_lastNow;
            if (gap <= 2500)
                m_awake += gap;
            m_lastNow = now;
        }
    }

    qint64 costOf(const PathCandidate &c) const
    {
        switch (c.kind) {
        case PathKind::OwnAwg: return m_costs.awg;
        case PathKind::OwnXray: return m_costs.xray;
        case PathKind::Provider: return m_costs.provider;
        }
        return m_costs.xray;
    }

    qint64 outsideOf(const PathCandidate &c) const
    {
        switch (c.kind) {
        case PathKind::OwnAwg: return m_costs.awgOutside;
        case PathKind::OwnXray: return m_costs.xrayOutside;
        case PathKind::Provider: return m_costs.providerOutside;
        }
        return 0;
    }

    qint64 fixedOf(const PathCandidate &c) const
    {
        switch (c.kind) {
        case PathKind::OwnAwg: return m_costs.awgFixed;
        case PathKind::OwnXray: return m_costs.xrayFixed;
        case PathKind::Provider: return m_costs.providerFixed;
        }
        return 0;
    }

    bool affordable(const PathCandidate &c) const { return m_bytesLeft < 0 || costOf(c) <= m_bytesLeft; }

    int inFlightOf(PathKind k) const
    {
        int n = 0;
        for (const Flight &f : m_inFlight)
            n += f.path.kind == k ? 1 : 0;
        return n;
    }

    bool hostTakes(const PathCandidate &c) const
    {
        const int cap = std::min(m_t.parallelism, m_caps.inFlight);
        if (int(m_inFlight.size()) >= cap)
            return false;
        if (c.kind == PathKind::Provider)
            return inFlightOf(PathKind::Provider) < m_caps.providerAtOnce;
        if (c.kind == PathKind::OwnAwg)
            return inFlightOf(PathKind::OwnAwg) < m_caps.awgAtOnce;
        return true;
    }

    RaceEffect cancelEffect(quint64 probe, const PathCandidate &path) const
    {
        RaceEffect e;
        e.type = RaceEffectType::CancelProbe;
        e.stamp = ProbeStamp{ m_race, m_net.generation, probe };
        e.path = path;
        return e;
    }

    // Start what may start now. The wave is a window of waveSize candidates (pending + in flight) in the owner's
    // order: a candidate the host cannot take yet (one provider profile at a time, two AmneziaWG) waits in the window
    // while the next ones of other kinds start, so a slow kind never holds the others back; provider candidates over
    // providerPerRace are left to the owner's walk. Nothing pending, nothing in flight, nothing left -> Exhausted.
    void pump(QList<RaceEffect> &out)
    {
        if (!m_running)
            return;
        if (m_awake >= m_budgetEnd) {
            finish(RaceDoneReason::Budget, out);
            return;
        }
        // a candidate the cap cannot pay now waits (m_deferred) for a probe to end under its reservation; the window
        // refills with the ones behind it, so an expensive kind never blocks a cheaper one
        for (bool dropped = true; dropped;) {
            dropped = false;
            for (int i = 0; i < m_deferred.size() && int(m_pending.size() + m_inFlight.size()) < m_t.waveSize;) {
                const PathCandidate c = m_deferred.at(i);
                if (m_legs.contains(c.id.id)) {
                    m_deferred.removeAt(i);
                    continue;
                }
                if (!affordable(c) || (c.kind == PathKind::Provider && m_providersQueued >= m_t.providerPerRace)) {
                    ++i;
                    continue;
                }
                m_deferred.removeAt(i);
                m_providersQueued += c.kind == PathKind::Provider ? 1 : 0;
                m_pending << c;
            }
            while (m_next < int(m_order.size()) && int(m_pending.size() + m_inFlight.size()) < m_t.waveSize) {
                const PathCandidate &c = m_order.at(m_next++);
                if (m_legs.contains(c.id.id))
                    continue; // the owner raises it: never probed beside its own leg
                if (c.kind == PathKind::Provider && m_providersQueued >= m_t.providerPerRace)
                    continue; // over the probe-seat bound of this race: left to the owner's walk
                if (!affordable(c)) {
                    m_unpaid = true;
                    m_deferred << c;
                    continue;
                }
                m_providersQueued += c.kind == PathKind::Provider ? 1 : 0;
                m_pending << c;
            }
            for (int i = 0; i < m_pending.size() && m_awake >= m_nextStartAt;) {
                const PathCandidate c = m_pending.at(i);
                if (!affordable(c)) { // the probes started since it was queued took what it needed
                    m_pending.removeAt(i);
                    m_providersQueued -= c.kind == PathKind::Provider ? 1 : 0;
                    m_deferred << c;
                    m_unpaid = dropped = true;
                    continue;
                }
                if (!hostTakes(c)) {
                    ++i;
                    continue;
                }
                m_pending.removeAt(i);
                Flight f;
                f.path = c;
                f.deadline = m_awake + m_t.probeTimeoutMs + 1000; // the host's grace after its own bound
                f.startedAt = m_awake;
                const quint64 probe = ++m_probeSeq;
                if (m_bytesLeft >= 0) {
                    f.reserved = costOf(c); // held while it runs; probeDone charges what it spent
                    m_bytesLeft -= f.reserved;
                }
                m_inFlight.insert(probe, f);
                if (c.kind == PathKind::Provider)
                    ++m_providersStarted;
                RaceEffect e;
                e.type = RaceEffectType::StartProbe;
                e.stamp = ProbeStamp{ m_race, m_net.generation, probe };
                e.path = c;
                e.timeoutMs = m_t.probeTimeoutMs;
                out << e;
                // the stagger on a virtual schedule: a coarse platform tick (500 ms) still starts one per staggerMs
                m_nextStartAt = std::max(m_nextStartAt, m_awake - m_t.staggerMs) + m_t.staggerMs;
            }
        }
        if (m_pending.isEmpty() && m_inFlight.isEmpty() && m_next >= int(m_order.size()))
            finish(m_unpaid && m_proven == 0 ? RaceDoneReason::Bytes : RaceDoneReason::Exhausted, out);
    }

    void finish(RaceDoneReason reason, QList<RaceEffect> &out)
    {
        for (auto it = m_inFlight.constBegin(); it != m_inFlight.constEnd(); ++it)
            out << cancelEffect(it.key(), it.value().path);
        m_inFlight.clear();
        m_pending.clear();
        m_deferred.clear();
        m_running = false;
        RaceEffect e;
        e.type = RaceEffectType::Done;
        e.reason = reason;
        out << e;
    }

    RaceTimings m_t;
    ProberCaps m_caps;
    Costs m_costs;
    NetworkKey m_net;
    QList<PathCandidate> m_order;
    QHash<quint64, Flight> m_inFlight;
    QString m_winner;
    quint64 m_race = 0;
    quint64 m_probeSeq = 0;
    qint64 m_bytesLeft = -1;
    qint64 m_lastNow = 0;
    qint64 m_awake = 0;
    qint64 m_budgetEnd = 0;
    qint64 m_nextStartAt = 0;
    int m_next = 0;
    QList<PathCandidate> m_pending; // the window's candidates not started yet
    QList<PathCandidate> m_deferred; // candidates the cap could not pay yet, in the owner's order
    QSet<QString> m_legs;           // paths the owner raised during this race (legStarted): never probed
    int m_providersQueued = 0;
    int m_providersStarted = 0;
    int m_proven = 0;
    bool m_hedged = false;
    bool m_running = false;
    bool m_unpaid = false; // a candidate was left out because the byte cap could not pay it
};

} // namespace avpn::path

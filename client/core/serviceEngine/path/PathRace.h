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
//   The window refills as probes end (the next wave); nothing left, the race budget
//   (awake time) over or the byte budget unable to pay the next probe -> Done(reason). The engine then lets the
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

namespace avpn::path {

// The race's numbers (server-tunable through TuningStore, ConnectTunables.h::raceTimingsTuned); to be calibrated
// on device. Measured on iPhone Air (18.11, lead-142-app-probe): first proven candidate 0.9-1.2 s on Wi-Fi, 1.5 s on
// LTE; own Xray 0.4-1.1 s; provider profiles 0.8-3.7 s, one at a time.
struct RaceTimings {
    int parallelism = 4;        // probes in flight at once (further capped by the host's caps)
    int staggerMs = 250;        // between two probe starts
    int waveSize = 6;           // candidates per wave
    int raceBudgetMs = 8000;    // awake time of one race; then the owner walks without it
    int probeTimeoutMs = 4000;  // one probe's own bound (the host answers by then)
    int providerPerRace = 3;    // provider probes per race (probe seats a lost batch answer can strand)
};

// What the platform's probe host can run at once (IScanHost caps of the spike: 6 legs, 1 full Xray, 2 AmneziaWG).
struct ProberCaps {
    bool available = false; // false = no host on this platform / build / server switch: stage-1 behaviour
    int legs = 6;
    int providerAtOnce = 1;
    int awgAtOnce = 2;
};

struct ProbeStamp {
    quint64 race = 0;
    quint64 network = 0;
    quint64 probe = 0;
    bool operator==(const ProbeStamp &o) const { return race == o.race && network == o.network && probe == o.probe; }
};

enum class RaceDoneReason { None, Exhausted, Budget, Bytes, NetworkChanged, Stopped };

inline const char *raceDoneReasonName(RaceDoneReason r)
{
    switch (r) {
    case RaceDoneReason::None: return "none";
    case RaceDoneReason::Exhausted: return "exhausted";
    case RaceDoneReason::Budget: return "budget";
    case RaceDoneReason::Bytes: return "bytes";
    case RaceDoneReason::NetworkChanged: return "network_changed";
    case RaceDoneReason::Stopped: return "stopped";
    }
    return "";
}

enum class RaceEffectType { StartProbe, CancelProbe, Report, Spent, Winner, Done };

struct RaceEffect {
    RaceEffectType type = RaceEffectType::Done;
    ProbeStamp stamp;          // StartProbe / CancelProbe
    PathCandidate path;        // StartProbe / Report / Winner
    int timeoutMs = 0;         // StartProbe
    PathOutcome outcome = PathOutcome::Inconclusive; // Report (always ProbeOk)
    QString network;           // Report: local network key
    quint64 networkGeneration = 0;
    qint64 bytes = 0;          // Spent
    RaceDoneReason reason = RaceDoneReason::None; // Done
};

class PathRace {
public:
    explicit PathRace(RaceTimings t = {}) : m_t(t) {}

    // Costs of one probe per kind, in bytes (the engine fills them from ScanBudget.h::scanProbeCostBytes so the
    // race and the Scanner charge one ledger the same way).
    struct Costs {
        qint64 awg = 90 * 1024;
        qint64 xray = 160 * 1024;
        qint64 provider = 160 * 1024;
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
        m_providersQueued = 0;
        m_inFlight.clear();
        m_winner.clear();
        m_providersStarted = 0;
        m_lastNow = now;
        m_awake = 0;
        m_budgetEnd = m_t.raceBudgetMs;
        m_nextStartAt = 0;
        pump(out);
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
        m_inFlight.erase(it);
        if (bytes > 0) {
            RaceEffect e;
            e.type = RaceEffectType::Spent;
            e.bytes = bytes;
            out << e;
            if (m_bytesLeft >= 0)
                m_bytesLeft = std::max<qint64>(0, m_bytesLeft - bytes);
        }
        if (outcome == PathOutcome::ProbeOk) {
            RaceEffect r;
            r.type = RaceEffectType::Report;
            r.path = path;
            r.outcome = PathOutcome::ProbeOk;
            r.network = m_net.local;
            r.networkGeneration = m_net.generation;
            out << r;
            ++m_proven;
            if (m_winner.isEmpty()) {
                // the engine tells whether the ledger now holds it as working (a tunnel no-data outranks a probe ok)
                RaceEffect w;
                w.type = RaceEffectType::Winner;
                w.path = path;
                out << w;
            }
        }
        pump(out);
        return out;
    }

    // The engine confirms a Winner the ledger accepted (it is "working" there); a refused one leaves the race open.
    void acceptWinner(const QString &pathId) { m_winner = pathId; }
    bool hasWinner() const { return !m_winner.isEmpty(); }

    QList<RaceEffect> tick(qint64 now)
    {
        QList<RaceEffect> out;
        advance(now);
        if (!m_running)
            return out;
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

    QList<RaceEffect> stop(qint64 now)
    {
        QList<RaceEffect> out;
        advance(now);
        if (m_running)
            finish(RaceDoneReason::Stopped, out);
        return out;
    }

    bool running() const { return m_running; }
    quint64 raceNumber() const { return m_race; }
    int inFlight() const { return int(m_inFlight.size()); }
    int proven() const { return m_proven; }
    const RaceTimings &timings() const { return m_t; }
    void setTimings(const RaceTimings &t) { m_t = t; }

private:
    struct Flight {
        PathCandidate path;
        qint64 deadline = 0;
    };

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

    int inFlightOf(PathKind k) const
    {
        int n = 0;
        for (const Flight &f : m_inFlight)
            n += f.path.kind == k ? 1 : 0;
        return n;
    }

    bool hostTakes(const PathCandidate &c) const
    {
        const int cap = std::min(m_t.parallelism, m_caps.legs);
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
        while (m_next < int(m_order.size()) && int(m_pending.size() + m_inFlight.size()) < m_t.waveSize) {
            const PathCandidate &c = m_order.at(m_next++);
            if (c.kind == PathKind::Provider && m_providersQueued >= m_t.providerPerRace)
                continue; // over the probe-seat bound of this race: left to the owner's walk
            m_providersQueued += c.kind == PathKind::Provider ? 1 : 0;
            m_pending << c;
        }
        for (int i = 0; i < m_pending.size() && m_awake >= m_nextStartAt;) {
            const PathCandidate c = m_pending.at(i);
            if (!hostTakes(c)) {
                ++i;
                continue;
            }
            if (m_bytesLeft >= 0 && costOf(c) > m_bytesLeft) {
                if (m_inFlight.isEmpty()) {
                    finish(RaceDoneReason::Bytes, out); // the byte budget cannot pay a probe: one at a time
                    return;
                }
                break;
            }
            m_pending.removeAt(i);
            Flight f;
            f.path = c;
            f.deadline = m_awake + m_t.probeTimeoutMs + 1000; // the host's grace after its own bound
            const quint64 probe = ++m_probeSeq;
            m_inFlight.insert(probe, f);
            if (m_bytesLeft >= 0)
                m_bytesLeft = std::max<qint64>(0, m_bytesLeft - costOf(c)); // reserved; the real bytes come with Done
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
        if (m_pending.isEmpty() && m_inFlight.isEmpty() && m_next >= int(m_order.size()))
            finish(RaceDoneReason::Exhausted, out);
    }

    void finish(RaceDoneReason reason, QList<RaceEffect> &out)
    {
        for (auto it = m_inFlight.constBegin(); it != m_inFlight.constEnd(); ++it)
            out << cancelEffect(it.key(), it.value().path);
        m_inFlight.clear();
        m_pending.clear();
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
    int m_providersQueued = 0;
    int m_providersStarted = 0;
    int m_proven = 0;
    bool m_running = false;
};

} // namespace avpn::path

// client/core/serviceEngine/path/PathLedger.h
// AVPN path engine (design 2026-11-17, §3 "Evidence ledger") - the single persistent store of "how did this
// path do on this network". Keyed by (local network key, path identity); every entry carries the parameters
// revision it was recorded with, and a different revision resets it. [header-only, QtCore; pure]
//
// What is recorded - only outcomes that belong to the path itself (design Р12):
//   probe ok       a light check next to the tunnel passed (weak proof: may raise the path, never "Connected";
//                  it never clears a tunnel "no data" - only a data ok does);
//   data ok        data passed through the raised tunnel, with time to tunnel and time to first byte (strong);
//   no handshake   the path did not come up within its start deadline (AmneziaWG handshake, Xray connect);
//   no data        the tunnel came up, no data passed within the check deadline;
//   refused        the server refused this path (lease refused, config rejected);
//   no seat        the provider had no free seat.
// "The check did not happen" (offline, app asleep, cancelled, our API unreachable, the attempt budget cut the
// leg) is Inconclusive and is NOT recorded: record() returns false and nothing changes.
//
// State of a path on a network (view()):
//   working   the newest attributable outcome is a success and it is still fresh (data ok: dataOkTtlMs; probe
//             ok: probeOkTtlMs). Strength: data > probe;
//   unknown   nothing valid is known (no entry, another revision, everything expired);
//   suspect   one failure since the last success (one lost handshake must not kill a path - design §10);
//   dead      two or more failures in a row. Quarantine ladder from the second failure: 2 min -> 10 min ->
//             1 h -> 6 h (LedgerTunables), counted from the newest failure. A dead path whose quarantine is
//             over is offered again after the others (PathSelect.h), and its next failure climbs the ladder;
//             any success resets streak and ladder.
//   Refused / no seat do not touch the streak or the ladder (they say nothing about the network): they keep
//   the path "dead, in quarantine" for refusalCooldownMs only.
// Bounded: entries untouched for evidenceTtlMs are dropped, then the oldest beyond maxEntries.
// Persistence: toJson()/fromJson(), versioned ({"v":1,...}); another version or garbage reads as empty.
//
// Replaced (and removed with it): network memory (avpn/netMemory), transport history (avpn/transportHistory), the
// engine's failed-this-session and attempt
// exclusions, the AmneziaWG ban, the extension's watch evidence and the Scanner's failure caches
// (SELECTION-MAP M12, M15-M21).
#pragma once

#include "PathId.h"
#include "PathTunables.h"

#include <QByteArray>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QString>

#include <algorithm>
#include <vector>

namespace avpn::path {

enum class PathOutcome { Inconclusive, ProbeOk, DataOk, NoHandshake, NoData, Refused, NoSeat };

inline const char *pathOutcomeName(PathOutcome o)
{
    switch (o) {
    case PathOutcome::Inconclusive: return "inconclusive";
    case PathOutcome::ProbeOk: return "probe_ok";
    case PathOutcome::DataOk: return "data_ok";
    case PathOutcome::NoHandshake: return "no_handshake";
    case PathOutcome::NoData: return "no_data";
    case PathOutcome::Refused: return "refused";
    case PathOutcome::NoSeat: return "no_seat";
    }
    return "";
}

inline PathOutcome pathOutcomeFromName(const QString &s)
{
    for (PathOutcome o : { PathOutcome::ProbeOk, PathOutcome::DataOk, PathOutcome::NoHandshake, PathOutcome::NoData,
                           PathOutcome::Refused, PathOutcome::NoSeat })
        if (s == QLatin1String(pathOutcomeName(o)))
            return o;
    return PathOutcome::Inconclusive;
}

inline bool isAttributable(PathOutcome o) { return o != PathOutcome::Inconclusive; }
inline bool isSuccess(PathOutcome o) { return o == PathOutcome::ProbeOk || o == PathOutcome::DataOk; }

enum class PathState { Unknown, Working, Suspect, Dead };

inline const char *pathStateName(PathState s)
{
    switch (s) {
    case PathState::Unknown: return "unknown";
    case PathState::Working: return "working";
    case PathState::Suspect: return "suspect";
    case PathState::Dead: return "dead";
    }
    return "";
}

enum class EvidenceStrength { None, Probe, Data };

struct PathView {
    PathState state = PathState::Unknown;
    bool inQuarantine = false; // dead and still inside its quarantine (or a refusal cooldown)
    bool refused = false;      // a server refusal / no seat cooldown is running
    EvidenceStrength strength = EvidenceStrength::None;
    qint64 lastSuccessMs = 0;  // newest still-valid success
    int connectMs = -1;        // of the newest data ok
    int ttfbMs = -1;
    int failStreak = 0;
    qint64 lastFailureMs = 0;
    qint64 quarantineUntilMs = 0;
};

struct LedgerEntry {
    QString network;
    QString path;
    QString revision;
    qint64 dataOkMs = 0;
    qint64 probeOkMs = 0;
    qint64 noDataMs = 0;       // newest tunnel "no data" (stage 2: a probe ok does not clear it)
    int connectMs = -1;
    int ttfbMs = -1;
    int failStreak = 0;
    qint64 lastFailureMs = 0;
    PathOutcome lastFailure = PathOutcome::Inconclusive;
    qint64 quarantineUntilMs = 0;
    qint64 refusedUntilMs = 0;
    qint64 touchedMs = 0;
};

class PathLedger {
public:
    static constexpr int kJsonVersion = 1;

    explicit PathLedger(LedgerTunables t = {}) : m_t(t) {}

    const LedgerTunables &tunables() const { return m_t; }
    int size() const { return int(m_entries.size()); }

    // Records one attributable outcome; false = nothing recorded (inconclusive, no network, no path).
    bool record(const QString &network, const PathId &path, PathOutcome o, qint64 nowMs, int connectMs = -1,
                int ttfbMs = -1)
    {
        if (network.isEmpty() || !path.isValid() || !isAttributable(o))
            return false;
        LedgerEntry &e = m_entries[keyOf(network, path.id)];
        if (e.network.isEmpty() || e.revision != path.revision) {
            e = LedgerEntry{};
            e.network = network;
            e.path = path.id;
            e.revision = path.revision;
        }
        switch (o) {
        case PathOutcome::DataOk:
            e.dataOkMs = nowMs;
            e.connectMs = connectMs;
            e.ttfbMs = ttfbMs;
            e.refusedUntilMs = 0;
            [[fallthrough]];
        case PathOutcome::ProbeOk:
            if (o == PathOutcome::ProbeOk) {
                e.probeOkMs = nowMs;
                // Stage 2: a tunnel that came up and carried no data outranks a light probe (device round 18.11:
                // own Xray 15 on LTE probes fine, the real tunnel passes nothing). Only a data ok through the
                // tunnel clears such a failure; the probe is kept, the path stays suspect / dead, so the race
                // does not pick it again and again.
                if (e.failStreak > 0 && e.noDataMs > 0 && e.noDataMs >= e.dataOkMs)
                    break;
            }
            e.failStreak = 0;
            e.quarantineUntilMs = 0;
            break;
        case PathOutcome::NoHandshake:
        case PathOutcome::NoData: {
            ++e.failStreak;
            e.lastFailureMs = nowMs;
            e.lastFailure = o;
            if (o == PathOutcome::NoData)
                e.noDataMs = nowMs;
            if (e.failStreak >= 2) {
                const int level = std::min<int>(e.failStreak - 2, int(m_t.quarantineMs.size()) - 1);
                e.quarantineUntilMs = nowMs + m_t.quarantineMs[size_t(level)];
            }
            break;
        }
        case PathOutcome::Refused:
        case PathOutcome::NoSeat:
            e.lastFailure = o;
            e.refusedUntilMs = nowMs + m_t.refusalCooldownMs;
            break;
        case PathOutcome::Inconclusive: break;
        }
        e.touchedMs = nowMs;
        if (size() > m_t.maxEntries)
            prune(nowMs);
        return true;
    }

    PathView view(const QString &network, const PathId &path, qint64 nowMs) const
    {
        PathView v;
        const auto it = m_entries.constFind(keyOf(network, path.id));
        if (it == m_entries.constEnd())
            return v;
        const LedgerEntry &e = it.value();
        if (e.revision != path.revision || nowMs - e.touchedMs > m_t.evidenceTtlMs)
            return v;
        v.failStreak = e.failStreak;
        v.lastFailureMs = e.lastFailureMs;
        v.quarantineUntilMs = e.quarantineUntilMs;
        const bool dataValid = e.dataOkMs > 0 && nowMs - e.dataOkMs <= m_t.dataOkTtlMs;
        const bool probeValid = e.probeOkMs > 0 && nowMs - e.probeOkMs <= m_t.probeOkTtlMs;
        if (dataValid) {
            v.strength = EvidenceStrength::Data;
            v.connectMs = e.connectMs;
            v.ttfbMs = e.ttfbMs;
        } else if (probeValid) {
            v.strength = EvidenceStrength::Probe;
        }
        v.lastSuccessMs = std::max(dataValid ? e.dataOkMs : 0, probeValid ? e.probeOkMs : 0);
        if (e.failStreak >= 2) {
            v.state = PathState::Dead;
            v.inQuarantine = nowMs < e.quarantineUntilMs;
        } else if (e.failStreak == 1) {
            v.state = PathState::Suspect;
        } else if (v.strength != EvidenceStrength::None) {
            v.state = PathState::Working;
        }
        if (nowMs < e.refusedUntilMs) {
            v.refused = true;
            v.state = PathState::Dead;
            v.inQuarantine = true;
        }
        return v;
    }

    // The view of every path of the pool on one network, keyed by path identity (what PathSelect reads).
    QHash<QString, PathView> viewOf(const QString &network, const QList<PathCandidate> &pool, qint64 nowMs) const
    {
        QHash<QString, PathView> out;
        for (const PathCandidate &c : pool)
            out.insert(c.id.id, view(network, c.id, nowMs));
        return out;
    }

    const LedgerEntry *entry(const QString &network, const QString &pathId) const
    {
        const auto it = m_entries.constFind(keyOf(network, pathId));
        return it == m_entries.constEnd() ? nullptr : &it.value();
    }

    // Drops entries untouched for evidenceTtlMs, then the oldest beyond maxEntries.
    void prune(qint64 nowMs)
    {
        for (auto it = m_entries.begin(); it != m_entries.end();)
            it = nowMs - it->touchedMs > m_t.evidenceTtlMs ? m_entries.erase(it) : std::next(it);
        trimToSize();
    }

    QByteArray toJson() const
    {
        QJsonArray arr;
        for (const QString &k : sortedKeys()) {
            const LedgerEntry e = m_entries.value(k);
            arr.append(QJsonObject{
                { QStringLiteral("n"), e.network }, { QStringLiteral("p"), e.path }, { QStringLiteral("r"), e.revision },
                { QStringLiteral("d"), double(e.dataOkMs) }, { QStringLiteral("pr"), double(e.probeOkMs) }, { QStringLiteral("nd"), double(e.noDataMs) },
                { QStringLiteral("c"), e.connectMs }, { QStringLiteral("t"), e.ttfbMs }, { QStringLiteral("f"), e.failStreak },
                { QStringLiteral("lf"), double(e.lastFailureMs) },
                { QStringLiteral("lo"), QString::fromLatin1(pathOutcomeName(e.lastFailure)) },
                { QStringLiteral("q"), double(e.quarantineUntilMs) }, { QStringLiteral("ru"), double(e.refusedUntilMs) },
                { QStringLiteral("u"), double(e.touchedMs) } });
        }
        const QJsonObject root{ { QStringLiteral("v"), kJsonVersion }, { QStringLiteral("e"), arr } };
        return QJsonDocument(root).toJson(QJsonDocument::Compact);
    }

    static PathLedger fromJson(const QByteArray &json, LedgerTunables t = {})
    {
        PathLedger l(t);
        const QJsonDocument doc = QJsonDocument::fromJson(json);
        if (!doc.isObject() || doc.object().value(QStringLiteral("v")).toInt(-1) != kJsonVersion)
            return l;
        for (const QJsonValue &v : doc.object().value(QStringLiteral("e")).toArray()) {
            const QJsonObject o = v.toObject();
            LedgerEntry e;
            e.network = o.value(QStringLiteral("n")).toString();
            e.path = o.value(QStringLiteral("p")).toString();
            if (e.network.isEmpty() || e.path.isEmpty())
                continue;
            e.revision = o.value(QStringLiteral("r")).toString();
            e.dataOkMs = qint64(o.value(QStringLiteral("d")).toDouble());
            e.probeOkMs = qint64(o.value(QStringLiteral("pr")).toDouble());
            e.noDataMs = qint64(o.value(QStringLiteral("nd")).toDouble());
            e.connectMs = o.value(QStringLiteral("c")).toInt(-1);
            e.ttfbMs = o.value(QStringLiteral("t")).toInt(-1);
            e.failStreak = std::max(0, o.value(QStringLiteral("f")).toInt());
            e.lastFailureMs = qint64(o.value(QStringLiteral("lf")).toDouble());
            e.lastFailure = pathOutcomeFromName(o.value(QStringLiteral("lo")).toString());
            e.quarantineUntilMs = qint64(o.value(QStringLiteral("q")).toDouble());
            e.refusedUntilMs = qint64(o.value(QStringLiteral("ru")).toDouble());
            e.touchedMs = qint64(o.value(QStringLiteral("u")).toDouble());
            l.m_entries.insert(keyOf(e.network, e.path), e);
        }
        l.trimToSize();
        return l;
    }

private:
    static QString keyOf(const QString &network, const QString &pathId)
    {
        return network + QChar(0x1f) + pathId;
    }

    QStringList sortedKeys() const
    {
        QStringList keys = m_entries.keys();
        std::sort(keys.begin(), keys.end());
        return keys;
    }

    void trimToSize()
    {
        if (size() <= m_t.maxEntries)
            return;
        std::vector<std::pair<qint64, QString>> order;
        for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it)
            order.emplace_back(it->touchedMs, it.key());
        std::sort(order.begin(), order.end());
        const size_t drop = size_t(size() - std::max(0, m_t.maxEntries));
        for (size_t i = 0; i < drop; ++i)
            m_entries.remove(order[i].second);
    }

    LedgerTunables m_t;
    QHash<QString, LedgerEntry> m_entries;
};

} // namespace avpn::path

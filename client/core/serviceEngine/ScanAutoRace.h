// client/core/serviceEngine/ScanAutoRace.h
// AVPN serviceEngine - «Авто» racing of an automatic connect (design D9) as a pure decision module:
// candidates + probe events + the clock in, "probe these / cancel that / commit this one / tier exhausted /
// give up" out. [header-only, QtCore; no timers, no I/O]
//
// ==== CALL ONLY BEFORE A TUNNEL EXISTS FOR THE ATTEMPT ======================================================
// This module decides which candidate an automatic connect commits to. It must only be started while no
// tunnel exists for the attempt (before the first bring-up of an automatic connect). It never moves a live
// session: start() with liveWorkingSession = true refuses (CONNECT-INVARIANTS §26 "one authority", §32: the
// scan never switches the tunnel, D9: "a live session is never moved for a better score"). It does not touch
// the tunnel itself: Commit is a decision the engine applies through its own bring-up, then the normal
// data gate (upstream_verify_bytes, 128 KB; §29/§31.3) decides «Подключено». NOT PART OF THIS RELEASE (plan
// v2 C7): on iOS and Android no probe host exists before a tunnel, and the server publishes no switch. The
// client switch features.scan_auto_race is compiled OFF (kScanAutoRaceBuild): scanAutoRaceEnabled() stays
// false whatever the server sends until a release turns the constant on; nothing in ScanMachine.h calls this
// module. With the switch off start() does nothing and the engine keeps its ordinary pick. Wiring (which probe
// kind races, how StartProbe maps to the host) belongs to the engine lane.
// ===========================================================================================================
//
// Rules (each one a test in tests/scan_core_check.cpp, vectors in tests/vectors/scan_race_vectors.json):
//  - Only the best eligible tier races (D9 hard boundary): tier N+1 opens only when tier N has no candidate
//    left to start AND none still inside its limits ("a candidate still inside its limits blocks a lower
//    tier") -> TierExhausted{N}, then tier N+1 races. All tiers used up -> GiveUp.
//  - Inside a tier: the last-known-good candidate starts at once; then up to scan_auto_race_alternates
//    alternates, scan_auto_race_stagger_ms apart (at most 1 + alternates in flight). Order inside the tier:
//    last-known-good, then rank, then id - ranking and network memory never cross a tier.
//  - The first probe that delivers scan_auto_commit_bytes commits: Commit{id} and CancelProbe for every other
//    probe in flight. A probe that fails or passes scan_auto_race_total_ms frees its slot: the next candidate
//    starts no earlier than stagger after the previous start.
//  - commitFailed(id) (the engine's data gate refused the committed node): the race resumes in the same tier
//    without it.
//  - Events about a probe that is not in flight are ignored; a `now` earlier than the last one is read as the
//    last one.
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanTunables.h"
#include "TuningStore.h"

#include <QList>
#include <QSet>
#include <QString>
#include <QVector>

#include <algorithm>

namespace avpn {

inline constexpr char kScanAutoRaceFlag[] = "scan_auto_race";
inline constexpr bool kScanAutoRaceBuild = false;        // compiled off in this release (plan v2 C7)
inline constexpr int kScanAutoRaceProbeTotalMs = 5000;   // limit of one racing probe (compiled, no server key)

inline bool scanAutoRaceEnabled()
{
    return kScanAutoRaceBuild && TuningStore::flag(QLatin1String(kScanAutoRaceFlag), false);
}

struct ScanRaceConfig {
    bool enabled = false;
    int alternates = 3;
    int staggerMs = 250;
    int commitBytes = 24576;
    int probeTotalMs = 5000;
};

inline ScanRaceConfig scanRaceConfigFrom(const ScanTunables &t, bool enabled)
{
    ScanRaceConfig c;
    c.enabled = enabled;
    c.alternates = t.autoRaceAlternates;
    c.staggerMs = t.autoRaceStaggerMs;
    c.commitBytes = t.autoCommitBytes;
    c.probeTotalMs = kScanAutoRaceProbeTotalMs;
    return c;
}

struct ScanRaceCandidate {
    QString id;
    int tier = 0;
    int rank = 0;
    bool lastKnownGood = false;
    bool eligible = true;
};

enum class ScanRaceActionKind { StartProbe, CancelProbe, Commit, TierExhausted, GiveUp };

inline const char *scanRaceActionName(ScanRaceActionKind k)
{
    switch (k) {
    case ScanRaceActionKind::StartProbe: return "start_probe";
    case ScanRaceActionKind::CancelProbe: return "cancel_probe";
    case ScanRaceActionKind::Commit: return "commit";
    case ScanRaceActionKind::TierExhausted: return "tier_exhausted";
    case ScanRaceActionKind::GiveUp: break;
    }
    return "give_up";
}

struct ScanRaceAction {
    ScanRaceActionKind kind = ScanRaceActionKind::StartProbe;
    QString id;
    int tier = -1;
    QString reason;
};

struct ScanRaceStep {
    QVector<ScanRaceAction> actions;
    qint64 wakeAtMs = -1;
    bool has(ScanRaceActionKind k) const
    {
        for (const ScanRaceAction &a : actions)
            if (a.kind == k)
                return true;
        return false;
    }
};

enum class ScanRaceState { Idle, Disabled, Refused, Racing, Committed, GaveUp };

inline const char *scanRaceStateName(ScanRaceState s)
{
    switch (s) {
    case ScanRaceState::Idle: return "idle";
    case ScanRaceState::Disabled: return "disabled";
    case ScanRaceState::Refused: return "refused";
    case ScanRaceState::Racing: return "racing";
    case ScanRaceState::Committed: return "committed";
    case ScanRaceState::GaveUp: break;
    }
    return "gave_up";
}

class ScanAutoRace
{
public:
    // candidates: every candidate of the automatic pick (the engine's eligibility already applied; an
    // ineligible one is ignored). liveWorkingSession = a tunnel carries data now: the race refuses.
    ScanRaceStep start(const QList<ScanRaceCandidate> &candidates, bool liveWorkingSession, const ScanRaceConfig &cfg,
                       qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ScanRaceStep s;
        *this = ScanAutoRace();
        m_last = nowMs;
        m_cfg = cfg;
        if (!cfg.enabled) {
            m_state = ScanRaceState::Disabled;
            return s;
        }
        if (liveWorkingSession) {
            m_state = ScanRaceState::Refused;
            return s;
        }
        for (const ScanRaceCandidate &c : candidates)
            if (c.eligible && !c.id.isEmpty() && !hasId(c.id))
                m_all << c;
        std::stable_sort(m_all.begin(), m_all.end(), [](const ScanRaceCandidate &a, const ScanRaceCandidate &b) {
            if (a.tier != b.tier)
                return a.tier < b.tier;
            if (a.lastKnownGood != b.lastKnownGood)
                return a.lastKnownGood;
            if (a.rank != b.rank)
                return a.rank < b.rank;
            return a.id < b.id;
        });
        m_state = ScanRaceState::Racing;
        if (m_all.isEmpty()) {
            m_state = ScanRaceState::GaveUp;
            s.actions << ScanRaceAction{ScanRaceActionKind::GiveUp, QString(), -1, QStringLiteral("no_candidate")};
            return s;
        }
        m_tier = m_all.first().tier;
        m_nextStartAt = nowMs;
        advance(nowMs, s);
        return s;
    }

    // bytes = what this probe delivered so far (cumulative).
    ScanRaceStep probeProgress(const QString &id, qint64 bytes, qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ScanRaceStep s;
        if (m_state == ScanRaceState::Racing && m_inFlight.contains(id)) {
            if (bytes >= m_cfg.commitBytes) {
                m_committed = id;
                m_state = ScanRaceState::Committed;
                for (const QString &other : m_inFlight)
                    if (other != id) {
                        s.actions << ScanRaceAction{ScanRaceActionKind::CancelProbe, other, tierOf(other), QStringLiteral("other_committed")};
                        m_started.removeAll(other); // not failed: startable again if the commit fails
                    }
                m_inFlight.clear();
                m_deadline.clear();
                s.actions << ScanRaceAction{ScanRaceActionKind::Commit, id, tierOf(id), QString()};
                return s;
            }
        }
        s.wakeAtMs = wake();
        return s;
    }

    ScanRaceStep probeFailed(const QString &id, const QString &reason, qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ScanRaceStep s;
        if (m_state == ScanRaceState::Racing && m_inFlight.contains(id)) {
            dropFlight(id);
            m_failed.insert(id);
            Q_UNUSED(reason);
            advance(nowMs, s);
        }
        s.wakeAtMs = wake();
        return s;
    }

    // The engine's data gate refused the committed candidate: race on without it.
    ScanRaceStep commitFailed(const QString &id, qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ScanRaceStep s;
        if (m_state == ScanRaceState::Committed && id == m_committed) {
            m_failed.insert(id);
            m_committed.clear();
            m_state = ScanRaceState::Racing;
            m_nextStartAt = qMin(m_nextStartAt, nowMs);
            advance(nowMs, s);
        }
        s.wakeAtMs = wake();
        return s;
    }

    ScanRaceStep tick(qint64 nowMs)
    {
        nowMs = clock(nowMs);
        ScanRaceStep s;
        if (m_state == ScanRaceState::Racing) {
            QStringList expired;
            for (int i = 0; i < m_inFlight.size(); ++i)
                if (nowMs >= m_deadline.at(i))
                    expired << m_inFlight.at(i);
            for (const QString &id : expired) {
                s.actions << ScanRaceAction{ScanRaceActionKind::CancelProbe, id, tierOf(id), QStringLiteral("timeout")};
                dropFlight(id);
                m_failed.insert(id);
            }
            advance(nowMs, s);
        }
        s.wakeAtMs = wake();
        return s;
    }

    // The attempt was stopped by the user: every probe in flight is cancelled.
    ScanRaceStep cancel(qint64 nowMs)
    {
        clock(nowMs);
        ScanRaceStep s;
        if (m_state == ScanRaceState::Racing)
            for (const QString &id : m_inFlight)
                s.actions << ScanRaceAction{ScanRaceActionKind::CancelProbe, id, tierOf(id), QStringLiteral("cancelled")};
        m_inFlight.clear();
        m_deadline.clear();
        m_state = ScanRaceState::Idle;
        return s;
    }

    ScanRaceState state() const { return m_state; }
    int tier() const { return m_tier; }
    QString committed() const { return m_committed; }
    QStringList inFlight() const { return m_inFlight; }
    QSet<QString> failed() const { return m_failed; }
    QStringList started() const { return m_started; }

private:
    bool hasId(const QString &id) const
    {
        for (const ScanRaceCandidate &c : m_all)
            if (c.id == id)
                return true;
        return false;
    }

    int tierOf(const QString &id) const
    {
        for (const ScanRaceCandidate &c : m_all)
            if (c.id == id)
                return c.tier;
        return -1;
    }

    void dropFlight(const QString &id)
    {
        const int i = m_inFlight.indexOf(id);
        if (i >= 0) {
            m_inFlight.removeAt(i);
            m_deadline.removeAt(i);
        }
    }

    QString nextOfTier() const
    {
        for (const ScanRaceCandidate &c : m_all)
            if (c.tier == m_tier && !m_failed.contains(c.id) && !m_inFlight.contains(c.id) && !m_started.contains(c.id))
                return c.id;
        return QString();
    }

    // Starts what may start now; moves to the next tier only when the current one is used up and nothing of
    // it is still inside its limits.
    void advance(qint64 nowMs, ScanRaceStep &s)
    {
        while (m_state == ScanRaceState::Racing) {
            const int width = 1 + qMax(0, m_cfg.alternates);
            QString next = nextOfTier();
            while (!next.isEmpty() && m_inFlight.size() < width && nowMs >= m_nextStartAt) {
                m_inFlight << next;
                m_deadline << nowMs + m_cfg.probeTotalMs;
                m_started << next;
                m_nextStartAt = nowMs + m_cfg.staggerMs;
                s.actions << ScanRaceAction{ScanRaceActionKind::StartProbe, next, m_tier, QString()};
                next = nextOfTier();
            }
            if (!next.isEmpty() || !m_inFlight.isEmpty())
                break;
            // The tier is used up and nothing of it is in flight.
            s.actions << ScanRaceAction{ScanRaceActionKind::TierExhausted, QString(), m_tier, QString()};
            int nextTier = -1;
            for (const ScanRaceCandidate &c : m_all)
                if (c.tier > m_tier && !m_failed.contains(c.id)) {
                    nextTier = c.tier;
                    break;
                }
            if (nextTier < 0) {
                m_state = ScanRaceState::GaveUp;
                s.actions << ScanRaceAction{ScanRaceActionKind::GiveUp, QString(), m_tier, QStringLiteral("exhausted")};
                break;
            }
            m_tier = nextTier;
            m_nextStartAt = nowMs;
        }
        s.wakeAtMs = wake();
    }

    qint64 wake() const
    {
        if (m_state != ScanRaceState::Racing)
            return -1;
        qint64 w = -1;
        for (qint64 d : m_deadline)
            if (w < 0 || d < w)
                w = d;
        const int width = 1 + qMax(0, m_cfg.alternates);
        if (m_inFlight.size() < width && !nextOfTier().isEmpty() && (w < 0 || m_nextStartAt < w))
            w = m_nextStartAt;
        return w;
    }

    qint64 clock(qint64 nowMs)
    {
        if (nowMs < m_last)
            nowMs = m_last;
        m_last = nowMs;
        return nowMs;
    }

    ScanRaceConfig m_cfg;
    ScanRaceState m_state = ScanRaceState::Idle;
    QList<ScanRaceCandidate> m_all;
    int m_tier = -1;
    QStringList m_inFlight;
    QList<qint64> m_deadline;
    QStringList m_started;
    QSet<QString> m_failed;
    QString m_committed;
    qint64 m_nextStartAt = 0;
    qint64 m_last = 0;
};

} // namespace avpn

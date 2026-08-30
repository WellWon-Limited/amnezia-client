// Tribe serviceEngine v2 — immutable, I/O-free multi-transport selection/fallback policy.
#pragma once

#include "dto/Catalog.h"

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QSet>

#include <algorithm>
#include <cmath>

namespace avpn {

struct CandidateHistory {
    // History is valid only for the exact signed native material that produced it. Reusing an
    // old success/cooldown after either generation changes can suppress or boost newly rotated
    // credentials and makes rollback/fallback decisions depend on stale evidence.
    quint64 configGeneration = 0;
    quint64 bindingGeneration = 0;
    // Negative values mean "unknown". Only results from verified real tunnels belong here.
    double verifiedSuccessEwma = -1.0;
    double survival5mEwma = -1.0;
    double verifiedStartLatencyMs = -1.0;
    double weakProbeRttMs = -1.0;
    QDateTime lastVerifiedAtUtc;
    QDateTime cooldownUntil;
};

inline bool candidateHistoryMatches(const CatalogCandidate &candidate,
                                    const CandidateHistory &history)
{
    return history.configGeneration != 0 && history.bindingGeneration != 0
           && history.configGeneration == candidate.nativeProfile.configGeneration
           && history.bindingGeneration == candidate.nativeProfile.bindingGeneration;
}

struct CandidateSelectionRequest {
    ConnectionMode mode = ConnectionMode::Auto;
    QString fixedLocationId; // empty = fastest location
    QString currentProfileId;
    QString previousProfileId;
    QString previousLocationId;
    TransportKind previousTransport = TransportKind::Unknown;
    QString previousFailureDomain;
    QSet<QString> failedProfileIds;
    QSet<QString> failedFailureDomains;
    QDateTime nowUtc;
    quint32 deterministicSeed = 0;
    int maximumCandidates = 5;
};

struct RankedCandidate {
    CatalogCandidate candidate;
    int fallbackTier = 0;
    double score = 0.0; // lower is better
};

inline quint32 stableCandidateHash(const QString &value, quint32 seed)
{
    // FNV-1a, explicitly independent of Qt's process-randomized hash seed.
    quint32 hash = quint32(2166136261u) ^ seed;
    const QByteArray bytes = value.toUtf8();
    for (const unsigned char byte : bytes) {
        hash ^= byte;
        hash *= quint32(16777619u);
    }
    return hash;
}

inline double bounded01(double value, double fallback)
{
    return std::isfinite(value) && value >= 0.0 && value <= 1.0 ? value : fallback;
}

inline bool candidateHealthHintsFresh(const CatalogCandidate &candidate,
                                      const QDateTime &nowUtc,
                                      int maximumHealthHintAgeS = 300)
{
    if (!candidate.healthObservedAt.isValid() || !nowUtc.isValid())
        return false;
    const qint64 ageS = candidate.healthObservedAt.toUTC().secsTo(nowUtc.toUTC());
    return ageS >= 0 && ageS <= qBound(1, maximumHealthHintAgeS, 3600);
}

inline double candidateScore(const CatalogCandidate &candidate, const CandidateHistory &history,
                             quint32 seed, const QDateTime &nowUtc,
                             int maximumHealthHintAgeS = 300)
{
    // Server hints are priors, not proof. Verified local outcome/survival carry more weight;
    // no weak pre-probe is currently produced by the product coordinator. Keep the persisted
    // field for backwards-compatible state decoding, but deliberately do not let a decorative or
    // legacy value influence production ranking.
    // A future/stale signed hint is never allowed to boost ranking. It becomes a neutral prior;
    // real verified tunnel history remains authoritative.
    const bool hintsFresh = candidateHealthHintsFresh(candidate, nowUtc, maximumHealthHintAgeS);
    const double health = hintsFresh ? bounded01(candidate.serverHealth, 0.5) : 0.5;
    const double capacity = hintsFresh ? bounded01(candidate.capacityHeadroom, 0.5) : 0.5;
    const double healthPenalty = (1.0 - health) * 300.0;
    const double capacityPenalty = (1.0 - capacity) * 160.0;
    const double successPenalty = history.verifiedSuccessEwma < 0.0
                                      ? 100.0
                                      : (1.0 - bounded01(history.verifiedSuccessEwma, 0.0)) * 420.0;
    const double survivalPenalty = history.survival5mEwma < 0.0
                                       ? 50.0
                                       : (1.0 - bounded01(history.survival5mEwma, 0.0)) * 220.0;
    const double startPenalty = history.verifiedStartLatencyMs < 0.0
                                    ? 80.0
                                    : qBound(0.0, history.verifiedStartLatencyMs / 20.0, 300.0);
    const double jitter = double(stableCandidateHash(candidate.profileId, seed) % 1000) / 100.0;
    return healthPenalty + capacityPenalty + successPenalty + survivalPenalty + startPenalty
           + jitter;
}

inline bool hasVerifiedLocalQualityEvidence(const CatalogCandidate &candidate,
                                            const CandidateHistory &history)
{
    if (!candidateHistoryMatches(candidate, history))
        return false;
    return history.verifiedSuccessEwma >= 0.0 || history.survival5mEwma >= 0.0
           || history.verifiedStartLatencyMs >= 0.0 || history.lastVerifiedAtUtc.isValid();
}

inline double verifiedLocalQualityScore(const CandidateHistory &history)
{
    // Lower is better. This deliberately excludes signed server health/capacity hints and weak
    // reachability probes: neither proves that application traffic crossed this exact tunnel.
    const double successPenalty = history.verifiedSuccessEwma < 0.0
                                      ? 100.0
                                      : (1.0 - bounded01(history.verifiedSuccessEwma, 0.0)) * 420.0;
    const double survivalPenalty = history.survival5mEwma < 0.0
                                       ? 50.0
                                       : (1.0 - bounded01(history.survival5mEwma, 0.0)) * 220.0;
    const double startPenalty = history.verifiedStartLatencyMs < 0.0
                                    ? 80.0
                                    : qBound(0.0, history.verifiedStartLatencyMs / 20.0, 300.0);
    return successPenalty + survivalPenalty + startPenalty;
}

inline int fallbackTier(const CatalogCandidate &candidate,
                        const CandidateSelectionRequest &request)
{
    if (request.previousProfileId.isEmpty())
        return 0;
    if (candidate.locationId != request.previousLocationId)
        return 4; // other location only after exhausting the selected/previous location
    const bool otherTransport = candidate.transport != request.previousTransport;
    const bool otherDomain = candidate.failureDomain != request.previousFailureDomain;
    if (otherTransport && otherDomain)
        return 0;
    if (!otherTransport && otherDomain)
        return 1;
    if (otherTransport)
        return 2;
    return 3;
}

inline QList<RankedCandidate> rankCandidates(QList<CatalogCandidate> immutableSnapshot,
                                             const QHash<QString, CandidateHistory> &history,
                                             const CandidateSelectionRequest &request)
{
    QList<RankedCandidate> ranked;
    const QDateTime now = request.nowUtc.toUTC();
    if (!now.isValid())
        return ranked;
    for (const CatalogCandidate &candidate : immutableSnapshot) {
        if (!modeAllowsTransport(request.mode, candidate.transport))
            continue;
        if (!request.fixedLocationId.isEmpty()
            && candidate.locationId != request.fixedLocationId)
            continue;
        // Health and capacity are bounded score hints, never eligibility. The binding in this
        // catalog is already provisioned; zero capacity means no new admissions, while a sampled
        // zero health value is still not typed proof that this device's exact transport path is
        // unusable. Hard removal requires a future explicit signed availability state (and backend
        // resolver eligibility), not an overloaded ratio.
        if (request.failedProfileIds.contains(candidate.profileId)
            || request.failedFailureDomains.contains(candidate.failureDomain))
            continue;
        const CandidateHistory stored = history.value(candidate.profileId);
        const CandidateHistory local = candidateHistoryMatches(candidate, stored)
                                           ? stored : CandidateHistory{};
        if (local.cooldownUntil.isValid() && local.cooldownUntil.toUTC() > now)
            continue;
        ranked.append({candidate, fallbackTier(candidate, request),
                       candidateScore(candidate, local, request.deterministicSeed, now)});
    }

    std::stable_sort(ranked.begin(), ranked.end(), [](const RankedCandidate &left,
                                                       const RankedCandidate &right) {
        if (left.fallbackTier != right.fallbackTier)
            return left.fallbackTier < right.fallbackTier;
        if (left.score != right.score)
            return left.score < right.score;
        return left.candidate.profileId < right.candidate.profileId;
    });
    const int ceiling = qBound(1, request.maximumCandidates, 5);
    while (ranked.size() > ceiling)
        ranked.removeLast();
    return ranked;
}

inline bool keepHealthyCurrent(double currentScore, double challengerScore,
                               qint64 connectedForS, int minimumDwellS,
                               double requiredImprovement = 75.0)
{
    if (connectedForS < qMax(0, minimumDwellS))
        return true;
    return (currentScore - challengerScore) < qMax(0.0, requiredImprovement);
}

} // namespace avpn

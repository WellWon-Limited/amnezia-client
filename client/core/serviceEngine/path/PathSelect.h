// client/core/serviceEngine/path/PathSelect.h
// AVPN path engine (design 2026-11-17, §3 "Choice of candidates") - ONE pure function that orders the paths
// for the next bring-up. [header-only, QtCore; pure: no clock, no I/O, no globals]
//
// Inputs: the pool (server attributes), the ledger view for the current network, the user's choice, the
// transport mode, an optional crowd prior ("works for others on this operator", stage 4; may be empty) and the
// paths already tried in this attempt on this network.
//
// Rules, in order of strength:
//  1. The transport mode is stronger than any choice: "Amnezia" offers only our AmneziaWG paths, "Xray" only
//     our Xray listeners and provider profiles. A choice the mode cannot serve yields nothing (honest failure).
//  2. A path already tried in this attempt is never offered again.
//  3. Exact node (a Scanner row, an explicit server): only its paths (one row = one path; a server of the list =
//     the transports of that host, ordered by the rules below), whatever the ledger says - the person asked for
//     it. It never falls back to another server.
//  4. Preferred country or server of the list (UserChoice::preferServer: the transports of that host): all its
//     paths the mode allows come first (working, unknown, suspect, quarantine over),
//     manual_only ones included - a preference is a person's choice, as a pin of a location is today. Then the
//     rest in the Auto order; the attempt reports the fallback (AttemptResult::fallbackNotice).
//  5. Auto order:
//       a. working on this network: data proof before probe proof, newest proof first, then faster;
//       b. unknown, regular: by crowd prior, then server prior (tier: ours -> main provider -> reserve provider,
//          provider priority, transport rank, weight), INTERLEAVED by kind (AmneziaWG / our Xray / provider
//          country / provider whitelist / provider balancer) so that one blocked protocol cannot fill the
//          first places (the rounds hold across the legs of one attempt: a kind that had its turn waits for
//          the others). Inside each round of the interleave a kind that already carried data on this network
//          goes first and a kind that only failed here goes last (a blocked protocol yields its place to the
//          kinds not yet seen failing - the ledger of this network is the only input, refusals do not count);
//       c. last wave: manual_only paths with no proof on this network, interleaved the same way. Owner decision
//          (17.11): manual_only keeps today's meaning - Auto reaches it only when every regular path is
//          exhausted. "Exhausted" now means: tried in this attempt OR already failed on this network (suspect,
//          dead) - the ledger makes the failures of an earlier tap count, today's attempt exclusions did not;
//          a manual_only path PROVEN on this network is in group (a): this device's evidence on this network
//          outranks the server's prior;
//       d. suspect (one failure): regular before manual_only, the oldest failure first;
//       e. dead with the quarantine over: regular before manual_only, the earliest end first.
//  6. Dead and still in quarantine (or in a refusal cooldown): only after everything above - "a path dead on
//     this network is never offered while an untried non-dead candidate exists". The budget of the attempt
//     usually ends before them.
//
// Stage 2 (probe race) plugs in without touching this function: race results are ledger outcomes (probe ok,
// no handshake), and they move paths between the groups above.
#pragma once

#include "../NodeRotation.h" // TransportMode (the one enum of the mode in force)
#include "PathId.h"
#include "PathLedger.h"

#include <QHash>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <limits>
#include <tuple>
#include <utility>

namespace avpn::path {

struct UserChoice {
    enum class Kind { Auto, PreferCountry, ExactPath };
    Kind kind = Kind::Auto;
    QString country;     // PreferCountry: ISO alpha-2 (the whole country when pathIds is empty)
    QStringList pathIds; // PreferCountry: the preferred server of the list (the transports of its host);
                         // ExactPath: the paths of the exact choice (a Scanner row: one) - never anything else

    static UserChoice automatic() { return {}; }
    static UserChoice preferCountry(const QString &cc) { return { Kind::PreferCountry, cc.trimmed().toUpper(), {} }; }
    // A server of the list (owner decision of 17.11 / coordinator 18.11): its paths first, then the best available
    // path with a notice; the preference is kept.
    static UserChoice preferServer(const QString &cc, const QStringList &ids)
    {
        return { Kind::PreferCountry, cc.trimmed().toUpper(), ids };
    }
    static UserChoice exactPath(const QString &id) { return { Kind::ExactPath, {}, { id } }; }
    static UserChoice exactPaths(const QStringList &ids) { return { Kind::ExactPath, {}, ids }; }
    bool operator==(const UserChoice &o) const { return kind == o.kind && country == o.country && pathIds == o.pathIds; }
};

enum class SelectGroup { Exact, Working, Unknown, LastWave, Suspect, QuarantineOver, Quarantined };

inline const char *selectGroupName(SelectGroup g)
{
    switch (g) {
    case SelectGroup::Exact: return "exact";
    case SelectGroup::Working: return "working";
    case SelectGroup::Unknown: return "unknown";
    case SelectGroup::LastWave: return "last_wave";
    case SelectGroup::Suspect: return "suspect";
    case SelectGroup::QuarantineOver: return "quarantine_over";
    case SelectGroup::Quarantined: return "quarantined";
    }
    return "";
}

struct RankedPath {
    PathCandidate path;
    PathView view;
    SelectGroup group = SelectGroup::Unknown;
    bool preferred = false; // inside the preferred country
};

struct SelectInput {
    QList<PathCandidate> pool;
    QHash<QString, PathView> evidence; // PathLedger::viewOf(current network); missing = unknown
    UserChoice choice;
    TransportMode mode = TransportMode::Auto;
    QHash<QString, double> crowd;      // path id -> share of reporters it worked for, [0..1]; missing = neutral
    QSet<QString> tried;               // tried in this attempt on this network
};

// Inside the preference of a "prefer" choice: one of the preferred server's paths, or - for a country preference -
// a path of that country. Also the rule of the fallback notice (AttemptResult::fallbackNotice).
inline bool isPreferred(const UserChoice &choice, const PathCandidate &c)
{
    if (choice.kind != UserChoice::Kind::PreferCountry)
        return false;
    if (!choice.pathIds.isEmpty())
        return choice.pathIds.contains(c.id.id);
    return !c.country.isEmpty() && c.country == choice.country;
}

inline bool modeAllows(PathKind k, TransportMode mode)
{
    switch (mode) {
    case TransportMode::Auto: return true;
    case TransportMode::Awg: return k == PathKind::OwnAwg;
    case TransportMode::Xray: return k != PathKind::OwnAwg;
    }
    return true;
}

namespace detail {

constexpr double kNeutralCrowd = 0.5;

// Server prior (and crowd prior) of an unproven path: true = a before b.
inline bool priorLess(const RankedPath &a, const RankedPath &b, const QHash<QString, double> &crowd)
{
    const double ca = crowd.value(a.path.id.id, kNeutralCrowd), cb = crowd.value(b.path.id.id, kNeutralCrowd);
    if (ca != cb)
        return ca > cb;
    const auto ka = std::make_tuple(a.path.tier, a.path.priority, a.path.rank);
    const auto kb = std::make_tuple(b.path.tier, b.path.priority, b.path.rank);
    if (ka != kb)
        return ka < kb;
    if (a.path.weight != b.path.weight)
        return a.path.weight > b.path.weight;
    return a.path.id.id < b.path.id.id;
}

inline QString laneOf(const PathCandidate &c)
{
    if (c.kind == PathKind::Provider)
        return QStringLiteral("provider:") + QLatin1String(upstreamKindName(c.providerKind));
    return QLatin1String(pathKindName(c.kind));
}

// How a kind did on this network: 0 = carried data here, 1 = nothing known, 2 = only failed here.
inline QHash<QString, int> laneEvidence(const QList<PathCandidate> &pool, const QHash<QString, PathView> &evidence)
{
    QHash<QString, int> score;
    for (const PathCandidate &c : pool) {
        const PathView v = evidence.value(c.id.id);
        const QString lane = laneOf(c);
        if (v.state == PathState::Working)
            score[lane] = 0;
        else if (v.failStreak > 0 && score.value(lane, 1) != 0)
            score[lane] = 2;
    }
    return score;
}

// Round robin over kinds, stable across the legs of one attempt: a path's round is its place in its kind plus
// the paths of that kind already tried in this attempt, so after a kind had its turn the other kinds go first
// even though the order is computed afresh for every leg. Inside a round the kinds go by their evidence on
// this network, then by prior.
inline QList<RankedPath> interleaved(QList<RankedPath> in, const QHash<QString, double> &crowd,
                                     const QHash<QString, int> &laneScore, const QHash<QString, int> &laneTried)
{
    const auto less = [&crowd](const RankedPath &a, const RankedPath &b) { return priorLess(a, b, crowd); };
    std::sort(in.begin(), in.end(), less);
    QHash<QString, int> seen;
    QList<std::pair<int, RankedPath>> keyed;
    for (const RankedPath &r : in) {
        const QString lane = laneOf(r.path);
        keyed.append({ laneTried.value(lane) + seen[lane]++, r });
    }
    std::stable_sort(keyed.begin(), keyed.end(), [&](const auto &a, const auto &b) {
        if (a.first != b.first)
            return a.first < b.first;
        const int sa = laneScore.value(laneOf(a.second.path), 1), sb = laneScore.value(laneOf(b.second.path), 1);
        return sa != sb ? sa < sb : less(a.second, b.second);
    });
    QList<RankedPath> out;
    for (const auto &k : keyed)
        out << k.second;
    return out;
}

} // namespace detail

inline QList<RankedPath> selectPaths(const SelectInput &in)
{
    QList<RankedPath> exact, quarantined;
    // [preferred][group] for the sections before the quarantined tail
    QList<RankedPath> sec[2][5]; // 0 Working, 1 Unknown, 2 LastWave, 3 Suspect, 4 QuarantineOver
    for (const PathCandidate &c : in.pool) {
        if (!modeAllows(c.kind, in.mode) || in.tried.contains(c.id.id))
            continue;
        RankedPath r;
        r.path = c;
        r.view = in.evidence.value(c.id.id);
        if (in.choice.kind == UserChoice::Kind::ExactPath) {
            if (in.choice.pathIds.contains(c.id.id)) {
                r.group = SelectGroup::Exact;
                exact << r;
            }
            continue;
        }
        r.preferred = isPreferred(in.choice, c);
        const int p = r.preferred ? 0 : 1;
        switch (r.view.state) {
        case PathState::Working: r.group = SelectGroup::Working; sec[p][0] << r; break;
        case PathState::Unknown:
            if (c.manualOnly && !r.preferred) {
                r.group = SelectGroup::LastWave;
                sec[p][2] << r;
            } else {
                r.group = SelectGroup::Unknown;
                sec[p][1] << r;
            }
            break;
        case PathState::Suspect: r.group = SelectGroup::Suspect; sec[p][3] << r; break;
        case PathState::Dead:
            if (r.view.inQuarantine) {
                r.group = SelectGroup::Quarantined;
                quarantined << r;
            } else {
                r.group = SelectGroup::QuarantineOver;
                sec[p][4] << r;
            }
            break;
        }
    }
    if (in.choice.kind == UserChoice::Kind::ExactPath) {
        // the transports of the chosen server: proven first, then by kind and server prior; dead last
        std::stable_sort(exact.begin(), exact.end(), [&in](const RankedPath &a, const RankedPath &b) {
            const auto rank = [](const PathView &v) {
                return v.state == PathState::Working ? 0 : v.state == PathState::Unknown ? 1 : v.state == PathState::Suspect ? 2 : 3;
            };
            if (rank(a.view) != rank(b.view))
                return rank(a.view) < rank(b.view);
            return detail::priorLess(a, b, in.crowd);
        });
        return exact;
    }

    const auto &crowd = in.crowd;
    const QHash<QString, int> lanes = detail::laneEvidence(in.pool, in.evidence);
    QHash<QString, int> lanesTried;
    for (const PathCandidate &c : in.pool)
        if (in.tried.contains(c.id.id))
            ++lanesTried[detail::laneOf(c)];
    const auto prior = [&crowd](const RankedPath &a, const RankedPath &b) { return detail::priorLess(a, b, crowd); };
    const auto working = [&](const RankedPath &a, const RankedPath &b) {
        if (a.view.strength != b.view.strength)
            return a.view.strength > b.view.strength;
        if (a.view.lastSuccessMs != b.view.lastSuccessMs)
            return a.view.lastSuccessMs > b.view.lastSuccessMs;
        const auto speed = [](const PathView &v) {
            return v.connectMs < 0 || v.ttfbMs < 0 ? std::numeric_limits<int>::max() : v.connectMs + v.ttfbMs;
        };
        if (speed(a.view) != speed(b.view))
            return speed(a.view) < speed(b.view);
        return prior(a, b);
    };
    const auto byTime = [&](qint64 PathView::*field) {
        return [&, field](const RankedPath &a, const RankedPath &b) {
            if (a.path.manualOnly != b.path.manualOnly)
                return !a.path.manualOnly;
            if (a.view.*field != b.view.*field)
                return a.view.*field < b.view.*field;
            return prior(a, b);
        };
    };

    QList<RankedPath> out;
    for (auto &s : sec) {
        std::sort(s[0].begin(), s[0].end(), working);
        std::sort(s[3].begin(), s[3].end(), byTime(&PathView::lastFailureMs));
        std::sort(s[4].begin(), s[4].end(), byTime(&PathView::quarantineUntilMs));
        out << s[0] << detail::interleaved(s[1], crowd, lanes, lanesTried)
            << detail::interleaved(s[2], crowd, lanes, lanesTried) << s[3] << s[4];
    }
    const auto byQuarantine = byTime(&PathView::quarantineUntilMs);
    std::sort(quarantined.begin(), quarantined.end(), [&](const RankedPath &a, const RankedPath &b) {
        if (a.preferred != b.preferred)
            return a.preferred;
        return byQuarantine(a, b);
    });
    out << quarantined;
    return out;
}

} // namespace avpn::path

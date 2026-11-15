// client/core/serviceEngine/TunnelWatchStatus.h
//
// AVPN (iOS tunnel-side data watch, build 140; design docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md
// §0a item 6 and §5.4, contract C2): the app side of the extension's `watch` verdict.
//
//  * parseTunnelWatch - the `watch` object of the status reply ({"action":"status"}) as a plain struct.
//    Absent in a build 139 extension: present=false, and nothing in the app changes.
//  * decideResumeFreeze - on return to the foreground (or a thaw detected by an overdue tick) the app
//    first holds its own decisions (the health tick, the completion of a pending data check), asks the
//    extension for one snapshot through the existing status path and decides again only after the
//    snapshot or the timeout. Only with features.ios_tunnel_watch.
//  * decideWatchConsume - what an adopted snapshot means: no_data / unconfirmed for the session the app
//    believes it has = a reason to re-check the path at once with the full budget, never a verdict by
//    itself (it does not make "Connected" green, is not counted as a failure, does not return the heal
//    budget - CONNECT-INVARIANTS §29 item 9).
//
// Pure (QtCore value types only). Tests: tests/tunnel_watch_check.cpp.
#pragma once

#include "WhoamiVerdict.h" // timerFiredLate - one lateness rule for every timer

#include <QString>
#include <QVariant>
#include <QVariantMap>

namespace avpn {

enum class WatchVerdict { None, Suspect, NoData, Unconfirmed, Network, Captive, Unknown };

inline WatchVerdict watchVerdictFromString(const QString &s)
{
    if (s == QLatin1String("none")) return WatchVerdict::None;
    if (s == QLatin1String("suspect")) return WatchVerdict::Suspect;
    if (s == QLatin1String("no_data")) return WatchVerdict::NoData;
    if (s == QLatin1String("unconfirmed")) return WatchVerdict::Unconfirmed;
    if (s == QLatin1String("network")) return WatchVerdict::Network;
    if (s == QLatin1String("captive")) return WatchVerdict::Captive;
    return WatchVerdict::Unknown;
}

inline QString watchVerdictName(WatchVerdict v)
{
    switch (v) {
    case WatchVerdict::None: return QStringLiteral("none");
    case WatchVerdict::Suspect: return QStringLiteral("suspect");
    case WatchVerdict::NoData: return QStringLiteral("no_data");
    case WatchVerdict::Unconfirmed: return QStringLiteral("unconfirmed");
    case WatchVerdict::Network: return QStringLiteral("network");
    case WatchVerdict::Captive: return QStringLiteral("captive");
    case WatchVerdict::Unknown: break;
    }
    return QStringLiteral("unknown");
}

struct TunnelWatchSnapshot {
    bool present = false;  // the reply had a `watch` object
    bool valid = false;    // ...and it parsed: a known verdict and an `enabled` bool
    bool enabled = false;
    WatchVerdict verdict = WatchVerdict::Unknown;
    qint64 sinceMs = 0;
    QString passive;
    int cycles = 0;
    int epS = 0;
    qint64 tx = 0;
    qint64 rxData = 0;
    QString sanity;
    QString probe;
    QString probeReason;
    int probeMs = 0;
    qint64 probeAtMs = 0;
    int probesEpisode = 0;
    int probesHour = 0;
    int refuted = 0;
    int disturbed = 0;     // probes of the passive rule that could not be judged
    QString evidence;      // what confirmed no_data: "probe" / "handshake" / "none"
    bool wouldSwitch = false;
    bool appAlive = false;
    qint64 lastNoDataMs = 0;
    qint64 recoveredMs = 0;
    int switchSeq = 0;     // stage 1: always 0; carried so stage 2 does not change the protocol
    int switches = 0;      // number of entries of `switches` (stage 1: 0)
    QString lastSwitchWhy; // stage 2: the reason of the newest entry of `switches` (a label)
};

namespace watch_detail {
inline bool isNumber(const QVariant &v)
{
    switch (v.typeId()) {
    case QMetaType::Int: case QMetaType::UInt: case QMetaType::LongLong: case QMetaType::ULongLong:
    case QMetaType::Double: case QMetaType::Float: case QMetaType::Long: case QMetaType::ULong:
        return true;
    default:
        return false;
    }
}
inline qint64 i64(const QVariantMap &m, const char *k)
{
    const QVariant v = m.value(QLatin1String(k));
    return isNumber(v) ? v.toLongLong() : 0;
}
inline QString str(const QVariantMap &m, const char *k)
{
    const QVariant v = m.value(QLatin1String(k));
    return v.typeId() == QMetaType::QString ? v.toString() : QString();
}
} // namespace watch_detail

// `watch` as delivered by IosController::tunnelWatchSnapshot (JSON -> QVariantMap). Not a map - absent.
// A map without a known verdict or without a bool `enabled` - present but not valid (garbled: ignored).
inline TunnelWatchSnapshot parseTunnelWatch(const QVariant &watch)
{
    using namespace watch_detail;
    TunnelWatchSnapshot s;
    if (watch.typeId() != QMetaType::QVariantMap)
        return s;
    s.present = true;
    const QVariantMap m = watch.toMap();
    const QVariant enabled = m.value(QStringLiteral("enabled"));
    s.verdict = watchVerdictFromString(str(m, "verdict"));
    if (enabled.typeId() != QMetaType::Bool || s.verdict == WatchVerdict::Unknown)
        return s;
    s.valid = true;
    s.enabled = enabled.toBool();
    s.sinceMs = i64(m, "since_ms");
    s.passive = str(m, "passive");
    s.cycles = int(i64(m, "cycles"));
    s.epS = int(i64(m, "ep_s"));
    s.tx = i64(m, "tx");
    s.rxData = i64(m, "rx_data");
    s.sanity = str(m, "sanity");
    s.probe = str(m, "probe");
    s.probeReason = str(m, "probe_reason");
    s.probeMs = int(i64(m, "probe_ms"));
    s.probeAtMs = i64(m, "probe_at_ms");
    s.probesEpisode = int(i64(m, "probes_episode"));
    s.probesHour = int(i64(m, "probes_hour"));
    s.refuted = int(i64(m, "refuted"));
    s.disturbed = int(i64(m, "disturbed"));
    s.evidence = str(m, "evidence");
    s.wouldSwitch = m.value(QStringLiteral("would_switch")).toBool();
    s.appAlive = m.value(QStringLiteral("app_alive")).toBool();
    s.lastNoDataMs = i64(m, "last_no_data_ms");
    s.recoveredMs = i64(m, "recovered_ms");
    s.switchSeq = int(i64(m, "switch_seq"));
    const QVariantList switches = m.value(QStringLiteral("switches")).toList();
    s.switches = int(switches.size());
    if (!switches.isEmpty()) {
        // The reason of the last switch, for the journal: a short label, never free text.
        const QString why = switches.last().toMap().value(QStringLiteral("why")).toString();
        bool label = !why.isEmpty() && why.size() <= 32;
        for (const QChar c : why)
            label = label && (c.isLetterOrNumber() || c == QLatin1Char('_'));
        s.lastSwitchWhy = label ? why : QStringLiteral("unknown");
    }
    return s;
}

// ---- resume freeze --------------------------------------------------------------------------------
//
// One state, owned by the facade; the clock is the existing 1 s transition tick (no timer of its own).
// begin: flag on, the tunnel is Connected and a return to the foreground or a thaw was seen. While
// frozen the health tick and the completion of a pending data check wait. Released by: an accepted
// status reply after the freeze began (snapshot), the timeout, the flag going off, the tunnel leaving
// Connected. A tick that itself fired late (the app was suspended again during the wait) does not judge
// the timeout: the wait starts again from now and the snapshot is asked again (decideDeadlineTick spirit).
struct ResumeFreezeState {
    bool active = false;
    qint64 startMs = -1;
};

enum class FreezeStep {
    NotFrozen,     // nothing held
    Hold,          // keep holding
    HoldReask,     // keep holding, wait restarted (late tick): ask the extension again
    ReleaseSnapshot,
    ReleaseTimeout,
    ReleaseOff,    // flag off or tunnel not Connected: decide as before at once
};

inline bool freezeReleases(FreezeStep s)
{
    return s == FreezeStep::ReleaseSnapshot || s == FreezeStep::ReleaseTimeout || s == FreezeStep::ReleaseOff;
}

struct ResumeFreezeInputs {
    bool flagOn = false;
    bool tunnelConnected = false;
    qint64 nowMs = 0;
    bool snapshotArrived = false; // an accepted status reply after startMs
    qint64 timeoutMs = 3000;
    // The tick that evaluates: time since the previous tick and the tick period. A tick far later than its
    // period whose previous tick was already inside the wait = the app was frozen again while waiting.
    qint64 sinceLastTickMs = 1000;
    qint64 tickPeriodMs = 1000;
};

// A decision is about to run and the 1 s tick is overdue (the process has just thawed and the tick has not
// run yet) - the same lateness rule as every other late timer (WhoamiVerdict.h::timerFiredLate).
inline bool thawDetected(qint64 nowMs, qint64 lastTickMs, qint64 tickPeriodMs)
{
    return lastTickMs >= 0 && nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);
}

// Should a freeze begin now (a return to the foreground or a thaw was seen)?
inline bool resumeFreezeBegins(const ResumeFreezeState &st, bool flagOn, bool tunnelConnected)
{
    return !st.active && flagOn && tunnelConnected;
}

inline void beginResumeFreeze(ResumeFreezeState &st, qint64 nowMs)
{
    st.active = true;
    st.startMs = nowMs;
}

inline FreezeStep decideResumeFreeze(ResumeFreezeState &st, const ResumeFreezeInputs &in)
{
    if (!st.active)
        return FreezeStep::NotFrozen;
    const bool lateTick = in.sinceLastTickMs >= 0 && timerFiredLate(in.sinceLastTickMs, in.tickPeriodMs);
    const bool frozenDuringWait = lateTick && in.nowMs - in.sinceLastTickMs >= st.startMs;
    FreezeStep step;
    if (!in.flagOn || !in.tunnelConnected)
        step = FreezeStep::ReleaseOff;
    else if (in.snapshotArrived)
        step = FreezeStep::ReleaseSnapshot;
    else if (frozenDuringWait) {
        st.startMs = in.nowMs; // the frozen time is no waiting time
        return FreezeStep::HoldReask;
    } else if (in.nowMs < st.startMs) {
        st.startMs = in.nowMs; // wall clock went back: never stretch, restart the wait
        return FreezeStep::Hold;
    } else if (in.nowMs - st.startMs >= in.timeoutMs)
        step = FreezeStep::ReleaseTimeout;
    else
        return FreezeStep::Hold;
    st.active = false;
    st.startMs = -1;
    return step;
}

// ---- the extension moved the tunnel (stage 2) -----------------------------------------------------
// The reply says on which node the tunnel stands. The app takes another node than its own only when
// the extension says it made a switch (switch_seq > 0: an in-place switch, or a start by the system on
// another node), names the node, and the app has not adopted this very switch already. A build 139
// extension and one that never switched carry no switch number: nothing is adopted and the app's own
// identity rules (CONNECT-INVARIANTS §19) apply as before.
struct WatchAdoptInputs {
    int switchSeq = 0;           // the larger of watch.switch_seq and session_metadata.switch_seq
    QString snapshotNodeId;      // session_metadata.node_id of the reply: where the tunnel stands
    QString snapshotGeneration;  // session_metadata.generation: this run of the extension
    QString appNodeId;           // the node the engine believes is up
    int adoptedSeq = 0;          // the switch the app adopted last...
    QString adoptedGeneration;   // ...and in which run of the extension
};

inline bool decideWatchAdopt(const WatchAdoptInputs &in)
{
    if (in.switchSeq <= 0 || in.snapshotNodeId.isEmpty() || in.snapshotGeneration.isEmpty())
        return false;
    if (in.snapshotNodeId == in.appNodeId)
        return false; // the app is already there
    // Adopted before: since then the node differs only because the app moved by ITSELF (a tap, its own
    // ladder) - the extension's old switch must not pull it back.
    if (in.snapshotGeneration == in.adoptedGeneration && in.switchSeq <= in.adoptedSeq)
        return false;
    return true;
}

inline QString watchAdoptJournalLine(const QString &from, const QString &to, int seq, const QString &why, bool taken)
{
    return QStringLiteral("adopt_extension_switch from=%1 to=%2 seq=%3 why=%4 result=%5")
        .arg(from.isEmpty() ? QStringLiteral("-") : from, to)
        .arg(seq)
        .arg(why.isEmpty() ? QStringLiteral("unknown") : why, taken ? QStringLiteral("adopted") : QStringLiteral("unknown_node"));
}

// ---- what an adopted snapshot means ---------------------------------------------------------------
enum class WatchConsume {
    Nothing,         // no verdict to act on (absent, garbled, watch off, none/suspect/network/captive)
    OtherSession,    // a verdict about another session (node or generation differs): identity only, as today
    AlreadyConsumed, // this very verdict (same session, same since_ms) was acted on at an earlier return
    JournalOnly,     // features.node_scan is off: the app has no data check of its own for AmneziaWG
    Reverify,        // no_data / unconfirmed for the session the app has: re-check the path now
};

struct WatchConsumeInputs {
    TunnelWatchSnapshot snapshot;
    QString snapshotNodeId;      // session_metadata.node_id of the same reply
    QString snapshotGeneration;  // session_metadata.generation of the same reply
    QString appNodeId;           // the node the engine believes is up (empty = identity unknown)
    QString appGeneration;       // the generation the app saw before the freeze
    // features.node_scan (the honest "Connected" check). Off: the only check the app could start is the
    // Xray-style one, whose failure fails over at once - so the verdict is journaled and nothing else.
    bool nodeScanOn = false;
    // The verdict the app already acted on (0 / empty = none): a verdict stays in the extension until
    // 16 KiB arrive, and must not send the app into a re-check at every return to the screen.
    qint64 consumedSinceMs = 0;
    QString consumedGeneration;
};

inline WatchConsume decideWatchConsume(const WatchConsumeInputs &in)
{
    const TunnelWatchSnapshot &s = in.snapshot;
    if (!s.present || !s.valid || !s.enabled)
        return WatchConsume::Nothing;
    if (s.verdict != WatchVerdict::NoData && s.verdict != WatchVerdict::Unconfirmed)
        return WatchConsume::Nothing;
    if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()
        || in.snapshotGeneration != in.appGeneration)
        return WatchConsume::OtherSession;
    if (s.sinceMs > 0 && s.sinceMs == in.consumedSinceMs && in.snapshotGeneration == in.consumedGeneration)
        return WatchConsume::AlreadyConsumed;
    if (!in.nodeScanOn)
        return WatchConsume::JournalOnly;
    return WatchConsume::Reverify;
}

// What the re-check does with the engine's phase: a pending check is started again with its full budget;
// a completed one (Connected) goes back to Verifying first; any other phase is already moving.
enum class ReverifyAction { None, RestartPending, ReenterFromConnected };
inline ReverifyAction reverifyActionFor(bool engineVerifying, bool engineConnected)
{
    if (engineVerifying)
        return ReverifyAction::RestartPending;
    if (engineConnected)
        return ReverifyAction::ReenterFromConnected;
    return ReverifyAction::None;
}

// The per-network memory forgets the node only on a verdict the probe confirmed. `unconfirmed` (the
// probe could not be judged) is a reason to re-check and nothing more: if the app's own check then
// fails, the existing rule of a failed check forgets the node itself.
inline bool watchVerdictForgetsNode(WatchVerdict v)
{
    return v == WatchVerdict::NoData;
}

// `what`: "reverify" or "ignored why=node_scan_off".
inline QString watchConsumedJournalLine(const TunnelWatchSnapshot &s, const QString &nodeId, qint64 nowMs,
                                        const QString &what = QStringLiteral("reverify"))
{
    const qint64 age = s.sinceMs > 0 && nowMs >= s.sinceMs ? nowMs - s.sinceMs : -1;
    return QStringLiteral("data_watch_consumed verdict=%1 node=%2 age_ms=%3 probe=%4 evidence=%5 -> %6")
        .arg(watchVerdictName(s.verdict), nodeId)
        .arg(age)
        .arg(s.probe.isEmpty() ? QStringLiteral("-") : s.probe, s.evidence.isEmpty() ? QStringLiteral("-") : s.evidence, what);
}

} // namespace avpn

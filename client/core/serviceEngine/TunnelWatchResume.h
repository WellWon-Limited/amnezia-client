// client/core/serviceEngine/TunnelWatchResume.h
//
// AVPN (iOS tunnel-side data watch, build 140; design §0a item 6): the hand-over between the packet tunnel
// extension and the app when the app comes back - as ONE object with its effects handed in, so that the
// whole sequence runs in a test (tests/tunnel_watch_check.cpp) and the facade keeps only call sites.
//
// What it holds and why:
//  * the resume freeze (features.ios_tunnel_watch): on a thaw (the 1 s tick or a decision arrives overdue
//    - the process was suspended) the app holds its own decisions, asks the extension for one snapshot
//    and decides again only after adopting it, or after the timeout, or when the flag is off / the tunnel
//    is no longer Connected. A return to the screen needs no call of its own: a process that was
//    suspended is recognised by its overdue tick; one that kept running has nothing to catch up with;
//  * the background hold (features.ios_on_demand_bg_arm): while the app is in the background and nothing
//    of its own is in flight (the restart guard does not hold) it is awake only so that the On-Demand rule
//    gets armed. A decision that could start a failover there would be cut by iOS half-way: it waits for
//    the return to the screen, exactly as it did when the app was simply frozen (build 139);
//  * the decisions that had to wait, and the promise that every one of them runs exactly once when
//    nothing holds any more - on every way out (snapshot, timeout, flag off);
//  * what an adopted verdict means (TunnelWatchStatus.h::decideWatchConsume) and the re-check: only with
//    the engine's consent (ServiceEngine::reenterVerifying), only once per verdict, only with
//    features.node_scan.
//
// No timer of its own: the clock is the facade's existing 1 s transition tick.
#pragma once

#include "TunnelWatchStatus.h"

#include <QString>
#include <QVariantMap>

#include <functional>
#include <utility>
#include <vector>

namespace avpn {

struct TunnelWatchResumeOps {
    std::function<bool()> watchFlag;          // features.ios_tunnel_watch, default false
    std::function<bool()> nodeScanFlag;       // features.node_scan, default false
    std::function<bool()> tunnelConnected;    // the last observed native state is Connected
    // The app is in the background, features.ios_on_demand_bg_arm is on and no operation of its own is
    // in flight: it is awake only for the arming.
    std::function<bool()> backgroundArmOnly;
    std::function<qint64()> nowMs;
    std::function<qint64()> timeoutMs;        // ios_tw_resume_wait_ms, clamped
    std::function<void()> requestSnapshot;    // IosController::requestStatusSnapshot
    std::function<QString()> appNodeId;       // the node the engine believes is up
    std::function<QString()> sessionGeneration; // the generation of the session the app last saw
    std::function<void(const QString &)> journal;
    // The re-check.
    std::function<bool()> engineVerifying;
    std::function<bool()> engineConnected;
    std::function<bool()> reenterVerifying;   // ServiceEngine::reenterVerifying: Connected -> Verifying, or false
    std::function<void()> startVerification;  // the app's own data check, full budget
    std::function<void(const QString &nodeId)> forgetNode; // the per-network memory forgets the node
};

class TunnelWatchResume {
public:
    explicit TunnelWatchResume(TunnelWatchResumeOps ops) : m_ops(std::move(ops)) {}

    // A decision is about to be taken. true = it must wait. `lastTickMs` / `tickPeriodMs`: the facade's
    // 1 s tick - a decision that arrives while that tick is overdue has just seen a thaw.
    bool held(const char *site, qint64 lastTickMs, qint64 tickPeriodMs)
    {
        if (m_ops.backgroundArmOnly())
            return true;
        if (!m_ops.watchFlag())
            return false;
        if (!m_freeze.active && thawDetected(m_ops.nowMs(), lastTickMs, tickPeriodMs))
            begin(QString::fromLatin1(site));
        return m_freeze.active;
    }

    // As `held`, and when it must wait the decision is kept: `resume` runs once when nothing holds.
    bool defer(const char *site, qint64 lastTickMs, qint64 tickPeriodMs, std::function<void()> resume)
    {
        if (!held(site, lastTickMs, tickPeriodMs))
            return false;
        m_deferred.push_back(std::move(resume));
        return true;
    }

    // The facade's 1 s tick; sinceLastTickMs - time since its previous run (negative = the first one).
    void onTick(qint64 sinceLastTickMs, qint64 tickPeriodMs)
    {
        if (!m_freeze.active) {
            if (sinceLastTickMs >= 0 && timerFiredLate(sinceLastTickMs, tickPeriodMs))
                begin(QStringLiteral("thaw")); // begin() refuses with the flag off or without a tunnel
            if (!m_freeze.active)
                runDeferred(); // nothing of ours holds: what waited for the background hold goes on
            return;
        }
        ResumeFreezeInputs in;
        in.flagOn = m_ops.watchFlag();
        in.tunnelConnected = m_ops.tunnelConnected();
        in.nowMs = m_ops.nowMs();
        in.timeoutMs = m_ops.timeoutMs();
        in.sinceLastTickMs = sinceLastTickMs;
        in.tickPeriodMs = tickPeriodMs;
        const FreezeStep step = decideResumeFreeze(m_freeze, in);
        if (step == FreezeStep::HoldReask) {
            m_ops.journal(QStringLiteral("watch_resume_freeze reask why=frozen_while_waiting"));
            m_ops.requestSnapshot();
            return;
        }
        if (freezeReleases(step)) {
            journalRelease(step, nullptr);
            runDeferred();
        }
    }

    // The reply to the snapshot request: {"session": {...}, "watch": {...}?}. Acts only while frozen
    // (decideResumeFreeze answers NotFrozen otherwise).
    void onSnapshot(const QVariantMap &snapshot)
    {
        ResumeFreezeInputs in;
        in.flagOn = m_ops.watchFlag();
        in.tunnelConnected = m_ops.tunnelConnected();
        in.nowMs = m_ops.nowMs();
        in.snapshotArrived = true;
        in.timeoutMs = m_ops.timeoutMs();
        in.sinceLastTickMs = 0; // not a tick
        const FreezeStep step = decideResumeFreeze(m_freeze, in);
        if (!freezeReleases(step))
            return;
        if (step != FreezeStep::ReleaseSnapshot) {
            journalRelease(step, nullptr);
            runDeferred();
            return;
        }
        const TunnelWatchSnapshot w = parseTunnelWatch(snapshot.value(QStringLiteral("watch")));
        if (m_ops.backgroundArmOnly()) {
            // The app went to the background before the answer came: nothing is adopted and nothing
            // starts there; the verdict stays unconsumed for the next return.
            journalRelease(step, &w);
            return;
        }
        const QVariantMap session = snapshot.value(QStringLiteral("session")).toMap();
        WatchConsumeInputs ci;
        ci.snapshot = w;
        ci.snapshotNodeId = session.value(QStringLiteral("node_id")).toString();
        ci.snapshotGeneration = session.value(QStringLiteral("generation")).toString();
        ci.appNodeId = m_ops.appNodeId();
        ci.appGeneration = m_generation;
        ci.nodeScanOn = m_ops.nodeScanFlag();
        ci.consumedSinceMs = m_consumedSinceMs;
        ci.consumedGeneration = m_consumedGeneration;
        const WatchConsume consume = decideWatchConsume(ci);
        journalRelease(step, &w);
        if (consume == WatchConsume::Reverify || consume == WatchConsume::JournalOnly) {
            m_consumedSinceMs = w.sinceMs;
            m_consumedGeneration = ci.snapshotGeneration;
        }
        if (consume == WatchConsume::JournalOnly) {
            m_ops.journal(watchConsumedJournalLine(w, ci.appNodeId, in.nowMs, QStringLiteral("ignored why=node_scan_off")));
        } else if (consume == WatchConsume::Reverify) {
            reverify(w, ci.appNodeId, in.nowMs);
        }
        // The decisions that waited run after the snapshot was adopted; a re-check started above has a
        // new epoch, so a waiting completion of the old check returns without a verdict.
        runDeferred();
    }

    bool frozen() const { return m_freeze.active; }
    size_t deferredCount() const { return m_deferred.size(); }

private:
    void begin(const QString &why)
    {
        // In the background the app decides nothing anyway (held above): the hand-over is done at
        // the return to the screen.
        if (m_ops.backgroundArmOnly() || !resumeFreezeBegins(m_freeze, m_ops.watchFlag(), m_ops.tunnelConnected()))
            return;
        beginResumeFreeze(m_freeze, m_ops.nowMs());
        m_generation = m_ops.sessionGeneration();
        m_why = why;
        m_ops.journal(QStringLiteral("watch_resume_freeze begin why=%1 node=%2").arg(why, m_ops.appNodeId()));
        m_ops.requestSnapshot();
    }

    void journalRelease(FreezeStep step, const TunnelWatchSnapshot *snapshot)
    {
        const QString released = step == FreezeStep::ReleaseSnapshot ? QStringLiteral("snapshot")
                               : step == FreezeStep::ReleaseTimeout  ? QStringLiteral("timeout")
                                                                     : QStringLiteral("off");
        const QString verdict = !snapshot ? QStringLiteral("-")
                              : !snapshot->present ? QStringLiteral("absent")
                              : !snapshot->valid   ? QStringLiteral("garbled")
                                                   : watchVerdictName(snapshot->verdict);
        m_ops.journal(QStringLiteral("watch_resume_freeze released=%1 verdict=%2 why=%3 deferred=%4")
                          .arg(released, verdict, m_why)
                          .arg(m_deferred.size()));
    }

    // no_data / unconfirmed for the session the app has: a reason to re-check, never a verdict
    // (CONNECT-INVARIANTS §29 item 9: nothing here counts as a failure, proves data or returns heal budget).
    void reverify(const TunnelWatchSnapshot &w, const QString &nodeId, qint64 nowMs)
    {
        m_ops.journal(watchConsumedJournalLine(w, nodeId, nowMs));
        if (watchVerdictForgetsNode(w.verdict))
            m_ops.forgetNode(nodeId);
        switch (reverifyActionFor(m_ops.engineVerifying(), m_ops.engineConnected())) {
        case ReverifyAction::RestartPending:
            m_ops.startVerification(); // full budget, new epoch: the frozen check never completes as "limited"
            break;
        case ReverifyAction::ReenterFromConnected:
            if (m_ops.reenterVerifying()) // only with the engine's consent
                m_ops.startVerification();
            break;
        case ReverifyAction::None:
            break; // the engine is already moving (switch / start / stop)
        }
    }

    // Every decision that waited runs exactly once, unless something still holds (the background hold).
    void runDeferred()
    {
        if (m_deferred.empty() || m_freeze.active || m_ops.backgroundArmOnly())
            return;
        std::vector<std::function<void()>> deferred;
        deferred.swap(m_deferred);
        for (auto &fn : deferred)
            fn();
    }

    TunnelWatchResumeOps m_ops;
    ResumeFreezeState m_freeze;
    QString m_generation;
    QString m_why;
    std::vector<std::function<void()>> m_deferred;
    qint64 m_consumedSinceMs = 0;
    QString m_consumedGeneration;
};

} // namespace avpn

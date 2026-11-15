#!/usr/bin/env python3
"""Mutation test of the app's half and of the extension's glue of the iOS tunnel-side data watch
(build 140), and of its wiring.

Groups:
  pure    - one rule changed in a pure header (ConnectTunables.h, TunnelWatchPlan.h, TunnelWatchStatus.h,
            TunnelWatchResume.h, platforms/ios/BackgroundHoldBook.h, IosBackgroundArm.h), in
            ServiceEngine.cpp or in the extension's host-testable Swift (TribeWatchPlan.swift,
            TribeDataWatchRuntime.swift); killed when the BEHAVIOURAL test named with the mutant fails:
              watch   - tunnel_watch_check              plan - TribeWatchPlanTests.swift
              pick    - transport_pick_check            rt   - TribeDataWatchRuntimeTests.swift
              ios     - IosDataWatchTests.cpp           harness - the controller harness (the real
                                                                  ios_controller.mm)
  wiring  - one call site removed, moved or un-gated where no test reaches (the adapter patch, the
            provider's and the facade's call sites, the recipe, the CMake lists); killed when
            check_ios_data_watch_wiring.sh fails. These are the mutants ONLY the source-level check
            catches.
The verdict rule itself has its own run: recipes/awg-apple/replay/tribe_data_watch_mutants.py.

The mutants named "rev-..." are those of the independent review of stage 1 (its nine survivors were
glue proven by reading only); each is now killed by a behavioural test, or is listed under wiring
with the reason it stays there.

Nothing in the working tree is touched: the files the checks read are copied to a temporary tree,
mutated there and the checks run from the copy.
Usage: QT_ROOT=<Qt for macOS> python3 ios_data_watch_mutants.py [pure|wiring|anchors] [id-prefix ...]
  anchors - only check that every mutant's text occurs exactly once (fast).
Exit code 0 = every mutant killed (or listed in ACCEPTED with its reason).
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
QT = os.environ.get("QT_ROOT", os.path.expanduser("~/Qt/6.11.1/macos"))

ENG = "client/core/serviceEngine/"
IOS = "client/platforms/ios/"
PATCH = "recipes/awg-apple/patches/0012-tribe-data-watch.patch"

# (id, file, exact text occurring ONCE, replacement, test, what is broken)
PURE = [
    # ---- the table of numbers ----
    ("tun-01", ENG + "ConnectTunables.h", "std::isfinite(raw) ? qBound(spec.lo, raw, spec.hi) : spec.def", "std::isfinite(raw) ? raw : spec.def", "watch", "no clamp at all"),
    ("tun-02", ENG + "ConnectTunables.h", "std::isfinite(raw) ? qBound(spec.lo, raw, spec.hi) : spec.def", "qBound(spec.lo, raw, spec.hi)", "watch", "NaN / infinity are not replaced by the default"),
    ("tun-03", ENG + "ConnectTunables.h", '{"ios_tw_cycle_s",                       25,       10,', '{"ios_tw_cycle_s",                       15,       10,', "watch", "a default drifted from the registry"),
    ("tun-04", ENG + "ConnectTunables.h", '{"ios_on_demand_bg_arm_max_s",           25,        5,          28, false}', '{"ios_on_demand_bg_arm_max_s",           25,        5,          60, false}', "watch", "the background hold may outlive what iOS allows"),
    ("tun-05", ENG + "ConnectTunables.h", '{"ios_tw_resume_wait_ms",              3000,      500,       10000, false}', '{"ios_tw_resume_wait_ms",              3000,      500,       10000, true}', "watch", "an app-only number leaks into the plan"),
    ("tun-06", ENG + "ConnectTunables.h", "return std::llround(v);", "return static_cast<long long>(v);", "watch", "fractions are cut instead of rounded"),
    ("tun-07", ENG + "ConnectTunables.h", '{"ios_tw_probe_max_per_hour",            12,        1,          60, true},', '{"ios_tw_probe_max_per_hour",            60,        1,          60, true},', "watch", "rev-C2: probes per hour default 60"),
    ("tun-08", ENG + "ConnectTunables.h", '{"ios_tw_sanity_max_per_hour",           12,        1,          60, true},', '{"ios_tw_sanity_max_per_hour",           12,        1,        3600, true},', "watch", "the cap on requests outside the tunnel can be lifted by a typo"),
    # ---- the plan ----
    ("plan-01", ENG + "TunnelWatchPlan.h", "constexpr int kWatchPlanSchema = 2;", "constexpr int kWatchPlanSchema = 1;", "watch", "a schema the extension rejects"),
    ("plan-02", ENG + "TunnelWatchPlan.h", "double(in.nowMs + ttlH * 3600LL * 1000LL)", "double(in.nowMs)", "watch", "the plan expires at once"),
    ("plan-03", ENG + "TunnelWatchPlan.h", "double(policyH * 3600LL * 1000LL)", "double(policyH)", "watch", "policy max age in the wrong unit"),
    ("plan-04", ENG + "TunnelWatchPlan.h", '{QStringLiteral("ios_tunnel_watch"), in.watch}', '{QStringLiteral("ios_tunnel_watch"), true}', "watch", "the plan switches the watch on by itself"),
    ("plan-05", ENG + "TunnelWatchPlan.h", '{QStringLiteral("candidates"), QJsonArray{}}', '{QStringLiteral("candidates"), QJsonArray{1}}', "watch", "stage 1 hands candidates to the extension"),
    ("plan-06", ENG + "TunnelWatchPlan.h", '        if (e.key != QLatin1String("wifi") && e.key != in.cellularKey)\n            continue; // only the two keys of net_keys\n', "", "watch", "another network's memory entry is handed over"),
    ("plan-07", ENG + "TunnelWatchPlan.h", "if (!t.isDouble() || nowSec - qint64(t.toDouble()) > maxAgeSec)\n            return e;", "if (!t.isDouble())\n            return e;", "watch", "a memory entry older than 7 days is handed over"),
    ("plan-08", ENG + "TunnelWatchPlan.h", "return body.size() > kWatchPlanMaxBytes ? QByteArray() : body;", "return body.size() >= kWatchPlanMaxBytes ? QByteArray() : body;", "watch", "64 KB boundary"),
    ("plan-09", ENG + "TunnelWatchPlan.h", "return body.size() > kWatchPlanMaxBytes ? QByteArray() : body;", "return body;", "watch", "a plan over 64 KB is written"),
    ("plan-10", ENG + "TunnelWatchPlan.h", "const bool everOn = everOnBefore || flagNow;", "const bool everOn = flagNow;", "watch", "the kill switch never reaches the extension (file not rewritten with the flag off)"),
    ("plan-11", ENG + "TunnelWatchPlan.h", "const bool everOn = everOnBefore || flagNow;", "const bool everOn = true;", "watch", "rev-W2: the file is created on an install whose flag was never on"),
    ("plan-12", ENG + "TunnelWatchPlan.h", "if (i == 0 || (i < nodeId.size() && nodeId.at(i) != QLatin1Char(':')))", "if (i == 0)", "watch", "a junk node id is read as a node"),
    ("plan-13", ENG + "TunnelWatchPlan.h", 'if (engineMode == QLatin1String("awg"))\n        return QStringLiteral("amnezia");', 'if (engineMode == QLatin1String("awg"))\n        return QStringLiteral("auto");', "watch", "the Amnezia-only mode is handed over as auto"),
    ("plan-14", ENG + "TunnelWatchPlan.h", "double(in.configFetchedMs > 0 ? in.configFetchedMs : 0)", "double(in.configFetchedMs)", "watch", "a negative fetch time is written"),
    ("plan-15", ENG + "TunnelWatchPlan.h", "    if (!in.sanityTargets.isEmpty())\n        plan.insert(", "    plan.insert(", "watch", "an empty target list is written (the built-in targets are lost)"),
    ("plan-16", ENG + "TunnelWatchPlan.h", "        if (!s.toPlan)\n            continue;\n        out.append(", "        out.append(", "watch", "app-only numbers go into the plan"),
    ("plan-17", ENG + "TunnelWatchPlan.h", "in.pinNodeId.isEmpty() ? QString() : in.pinCountry", "in.pinCountry", "watch", "a pin country without a pinned node"),
    ("plan-18", ENG + "TunnelWatchPlan.h", "e.savedMs = e.nodeId ? qint64(t.toDouble()) * 1000 : 0;", "e.savedMs = e.nodeId ? qint64(t.toDouble()) : 0;", "watch", "memory time in the wrong unit"),
    ("plan-19", ENG + "TunnelWatchPlan.h", '{QStringLiteral("pool_revision"), double(in.poolRevision)}', '{QStringLiteral("pool_revision"), double(0)}', "watch", "rev-P1: pool revision not written"),
    ("plan-20", ENG + "TunnelWatchPlan.h", '{QStringLiteral("written_ms"), double(in.nowMs)}', '{QStringLiteral("written_ms"), double(in.nowMs / 1000)}', "watch", "rev-P2: written time in seconds"),
    ("plan-21", ENG + "TunnelWatchPlan.h", "    if (!w.write)\n        return out;\n    out.attempted = true;", "    out.attempted = true;", "watch", "rev-W2: the write goes ahead on an install whose flag was never on"),
    ("plan-22", ENG + "TunnelWatchPlan.h", "out.seqAfter = seqBefore < 0 ? 1 : seqBefore + 1;", "out.seqAfter = seqBefore < 0 ? 1 : seqBefore;", "watch", "two plans share one sequence number"),
    ("plan-23", ENG + "TunnelWatchPlan.h", "    in.seq = out.seqAfter;\n", "", "watch", "the file does not carry its sequence number"),
    ("plan-24", ENG + "TunnelWatchPlan.h", "    out.written = writeFile(body);\n", "    out.written = true;\n", "watch", "the plan is journaled as written without being written"),
    ("plan-25", ENG + "TunnelWatchPlan.h", "    if (!own.isEmpty()) {\n        for (const QString &u : own)\n            add(u);\n        return out;\n    }", "    for (const QString &u : own)\n        add(u);", "watch", "the operator's own targets are mixed with the default ones"),
    ("plan-26", ENG + "TunnelWatchPlan.h", "        if (out.size() >= kWatchPlanMaxSanityTargets - 1)\n            break; // one slot is kept for the anchor\n", "", "watch", "the anchor for a phone abroad is pushed out"),
    ("plan-27", ENG + "TunnelWatchPlan.h", "if (!t.isEmpty() && !out.contains(t) && out.size() < kWatchPlanMaxSanityTargets)", "if (!t.isEmpty() && !out.contains(t))", "watch", "more than four targets"),
    # ---- the status block and what a verdict means ----
    ("st-01", ENG + "TunnelWatchStatus.h", "if (enabled.typeId() != QMetaType::Bool || s.verdict == WatchVerdict::Unknown)", "if (s.verdict == WatchVerdict::Unknown)", "watch", "a block without a boolean `enabled` is valid"),
    ("st-02", ENG + "TunnelWatchStatus.h", "if (enabled.typeId() != QMetaType::Bool || s.verdict == WatchVerdict::Unknown)", "if (enabled.typeId() != QMetaType::Bool)", "watch", "an unknown verdict word is valid"),
    ("st-03", ENG + "TunnelWatchStatus.h", "if (s.verdict != WatchVerdict::NoData && s.verdict != WatchVerdict::Unconfirmed)", "if (s.verdict != WatchVerdict::NoData)", "watch", "unconfirmed is not a reason to re-check"),
    ("st-04", ENG + "TunnelWatchStatus.h", "if (s.verdict != WatchVerdict::NoData && s.verdict != WatchVerdict::Unconfirmed)", "if (s.verdict == WatchVerdict::None || s.verdict == WatchVerdict::Suspect)", "watch", "network / captive trigger a re-check"),
    ("st-05", ENG + "TunnelWatchStatus.h", "if (!s.present || !s.valid || !s.enabled)", "if (!s.present || !s.valid)", "watch", "rev-S4: a switched-off watch still triggers a re-check"),
    ("st-06", ENG + "TunnelWatchStatus.h", "if (!s.present || !s.valid || !s.enabled)", "if (!s.present || !s.enabled)", "watch", "a garbled block triggers a re-check"),
    ("st-07", ENG + "TunnelWatchStatus.h", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "if (in.appNodeId.isEmpty() || in.snapshotGeneration.isEmpty()", "watch", "a verdict about another node is taken for ours"),
    ("st-08", ENG + "TunnelWatchStatus.h", "|| in.snapshotGeneration != in.appGeneration)\n        return WatchConsume::OtherSession;", ")\n        return WatchConsume::OtherSession;", "watch", "rev-S3: a verdict of another extension session is taken for ours"),
    ("st-09", ENG + "TunnelWatchStatus.h", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "if (in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "watch", "an unknown app node matches"),
    ("st-10", ENG + "TunnelWatchStatus.h", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId", "watch", "two empty generations match"),
    ("st-11", ENG + "TunnelWatchStatus.h", "    if (!in.nodeScanOn)\n        return WatchConsume::JournalOnly;\n", "", "watch", "with node_scan off the verdict starts the Xray-style check"),
    ("st-12", ENG + "TunnelWatchStatus.h", "    if (s.sinceMs > 0 && s.sinceMs == in.consumedSinceMs && in.snapshotGeneration == in.consumedGeneration)\n        return WatchConsume::AlreadyConsumed;\n", "", "watch", "the same verdict is consumed at every return"),
    ("st-13", ENG + "TunnelWatchStatus.h", "if (s.sinceMs > 0 && s.sinceMs == in.consumedSinceMs && in.snapshotGeneration == in.consumedGeneration)", "if (s.sinceMs == in.consumedSinceMs && in.snapshotGeneration == in.consumedGeneration)", "watch", "a verdict without a time is taken for a consumed one"),
    ("st-14", ENG + "TunnelWatchStatus.h", "if (s.sinceMs > 0 && s.sinceMs == in.consumedSinceMs && in.snapshotGeneration == in.consumedGeneration)", "if (s.sinceMs > 0 && s.sinceMs == in.consumedSinceMs)", "watch", "a verdict of a new session is taken for a consumed one"),
    # ---- the resume freeze rule ----
    ("fr-01", ENG + "TunnelWatchStatus.h", "} else if (in.nowMs - st.startMs >= in.timeoutMs)", "} else if (in.nowMs - st.startMs > in.timeoutMs)", "watch", "timeout boundary"),
    ("fr-02", ENG + "TunnelWatchStatus.h", "} else if (in.nowMs - st.startMs >= in.timeoutMs)", "} else if (false)", "watch", "the freeze never times out"),
    ("fr-03", ENG + "TunnelWatchStatus.h", "if (!in.flagOn || !in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "if (!in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "watch", "the flag going off does not release"),
    ("fr-04", ENG + "TunnelWatchStatus.h", "if (!in.flagOn || !in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "if (!in.flagOn)\n        step = FreezeStep::ReleaseOff;", "watch", "rev-S1: a tunnel that went down does not release"),
    ("fr-05", ENG + "TunnelWatchStatus.h", "else if (in.snapshotArrived)\n        step = FreezeStep::ReleaseSnapshot;", "else if (false)\n        step = FreezeStep::ReleaseSnapshot;", "watch", "a snapshot does not release"),
    ("fr-06", ENG + "TunnelWatchStatus.h", "const bool frozenDuringWait = lateTick && in.nowMs - in.sinceLastTickMs >= st.startMs;", "const bool frozenDuringWait = false;", "watch", "time spent frozen is judged as the timeout"),
    ("fr-07", ENG + "TunnelWatchStatus.h", "const bool frozenDuringWait = lateTick && in.nowMs - in.sinceLastTickMs >= st.startMs;", "const bool frozenDuringWait = lateTick;", "watch", "rev-S2: the tick that revealed the thaw restarts the wait"),
    ("fr-08", ENG + "TunnelWatchStatus.h", "} else if (in.nowMs < st.startMs) {", "} else if (false) {", "watch", "a clock that went back stretches the wait"),
    ("fr-09", ENG + "TunnelWatchStatus.h", "return !st.active && flagOn && tunnelConnected;", "return !st.active && tunnelConnected;", "watch", "rev-W1: the freeze begins with the flag off"),
    ("fr-10", ENG + "TunnelWatchStatus.h", "return !st.active && flagOn && tunnelConnected;", "return !st.active && flagOn;", "watch", "the freeze begins without a tunnel"),
    ("fr-11", ENG + "TunnelWatchStatus.h", "return !st.active && flagOn && tunnelConnected;", "return flagOn && tunnelConnected;", "watch", "the freeze begins twice"),
    ("fr-12", ENG + "TunnelWatchStatus.h", "return lastTickMs >= 0 && nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);", "return nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);", "watch", "rev-S6: a thaw is seen before the first tick"),
    ("fr-13", ENG + "TunnelWatchStatus.h", "return lastTickMs >= 0 && nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);", "return lastTickMs >= 0 && nowMs >= lastTickMs && nowMs - lastTickMs > tickPeriodMs;", "watch", "an ordinary late tick is a thaw (no slack)"),
    ("fr-14", ENG + "TunnelWatchStatus.h", "    st.active = false;\n    st.startMs = -1;\n    return step;", "    return step;", "watch", "a released freeze stays active"),
    ("fr-15", ENG + "TunnelWatchStatus.h", "if (engineVerifying)\n        return ReverifyAction::RestartPending;", "if (engineVerifying)\n        return ReverifyAction::ReenterFromConnected;", "watch", "a pending check is not restarted"),
    ("fr-16", ENG + "TunnelWatchStatus.h", "if (engineConnected)\n        return ReverifyAction::ReenterFromConnected;", "if (engineConnected)\n        return ReverifyAction::None;", "watch", "a connected session is not re-checked"),
    ("fr-17", ENG + "TunnelWatchStatus.h", "const qint64 age = s.sinceMs > 0 && nowMs >= s.sinceMs ? nowMs - s.sinceMs : -1;", "const qint64 age = nowMs - s.sinceMs;", "watch", "a bogus verdict age in the journal"),
    ("fr-18", ENG + "TunnelWatchStatus.h", "        st.startMs = in.nowMs; // the frozen time is no waiting time\n        return FreezeStep::HoldReask;", "        return FreezeStep::HoldReask;", "watch", "rev-S7: the wait is not restarted after a second freeze"),
    ("fr-19", ENG + "TunnelWatchStatus.h", "    return v == WatchVerdict::NoData;\n}\n", "    return v == WatchVerdict::NoData || v == WatchVerdict::Unconfirmed;\n}\n", "watch", "rev-S5: an unconfirmed verdict wipes the network memory"),
    ("fr-20", ENG + "TunnelWatchStatus.h", "    return v == WatchVerdict::NoData;\n}\n", "    return false;\n}\n", "watch", "a confirmed verdict does not make the network memory forget the node"),
    ("fr-22", ENG + "TunnelWatchStatus.h", "    if (!st.active)\n        return FreezeStep::NotFrozen;\n    const bool lateTick", "    const bool lateTick", "watch", "rev-W9: a snapshot is consumed while not frozen"),
    ("fr-21", ENG + "TunnelWatchStatus.h", "    if (!in.flagOn || !in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;\n    else if (in.snapshotArrived)\n        step = FreezeStep::ReleaseSnapshot;", "    if (in.snapshotArrived)\n        step = FreezeStep::ReleaseSnapshot;\n    else if (!in.flagOn || !in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "watch", "rev-S8: a snapshot is adopted although the flag is off or the tunnel is down"),
    # ---- the hand-over object ----
    ("res-01", ENG + "TunnelWatchResume.h", "        if (m_ops.backgroundArmOnly())\n            return true;\n        if (!m_ops.watchFlag())\n            return false;", "        if (!m_ops.watchFlag())\n            return false;", "watch", "a decision is taken in the background while the app is awake only for the arming"),
    ("res-02", ENG + "TunnelWatchResume.h", "        if (!m_ops.watchFlag())\n            return false;\n        if (!m_freeze.active && thawDetected(", "        if (!m_freeze.active && thawDetected(", "watch", "rev-W1: with the flag off a late decision is held"),
    ("res-03", ENG + "TunnelWatchResume.h", "        if (!m_freeze.active && thawDetected(m_ops.nowMs(), lastTickMs, tickPeriodMs))\n            begin(QString::fromLatin1(site));\n", "", "watch", "a decision that runs before the overdue tick is not held"),
    ("res-04", ENG + "TunnelWatchResume.h", "        m_deferred.push_back(std::move(resume));\n        return true;", "        return true;", "watch", "a decision that had to wait is lost"),
    ("res-06", ENG + "TunnelWatchResume.h", "            if (!m_freeze.active)\n                runDeferred(); // nothing of ours holds: what waited for the background hold goes on\n", "", "watch", "what waited for the background hold never runs"),
    ("res-07", ENG + "TunnelWatchResume.h", "        if (freezeReleases(step)) {\n            journalRelease(step, nullptr);\n            runDeferred();\n        }", "        if (freezeReleases(step)) {\n            journalRelease(step, nullptr);\n        }", "watch", "rev-W13: deferred decisions dropped at a timeout release (stuck Verifying)"),
    ("res-08", ENG + "TunnelWatchResume.h", "        if (step == FreezeStep::HoldReask) {\n            m_ops.journal(QStringLiteral(\"watch_resume_freeze reask why=frozen_while_waiting\"));\n            m_ops.requestSnapshot();", "        if (step == FreezeStep::HoldReask) {\n            m_ops.journal(QStringLiteral(\"watch_resume_freeze reask why=frozen_while_waiting\"));", "watch", "after a second freeze the extension is not asked again"),
    ("res-10", ENG + "TunnelWatchResume.h", "        if (step != FreezeStep::ReleaseSnapshot) {\n            journalRelease(step, nullptr);\n            runDeferred();\n            return;\n        }", "        if (step != FreezeStep::ReleaseSnapshot) {\n            journalRelease(step, nullptr);\n            return;\n        }", "watch", "decisions dropped when the freeze ends because the tunnel went down"),
    ("res-11", ENG + "TunnelWatchResume.h", "        if (m_ops.backgroundArmOnly()) {\n            // The app went to the background before the answer came", "        if (false) {\n            // The app went to the background before the answer came", "watch", "a verdict is adopted and a re-check started in the background"),
    ("res-12", ENG + "TunnelWatchResume.h", "        ci.appGeneration = m_generation;", "        ci.appGeneration = ci.snapshotGeneration;", "watch", "the generation the app saw before the freeze is not compared"),
    ("res-13", ENG + "TunnelWatchResume.h", "        ci.nodeScanOn = m_ops.nodeScanFlag();", "        ci.nodeScanOn = true;", "watch", "with node_scan off the verdict starts a check"),
    ("res-14", ENG + "TunnelWatchResume.h", "        if (consume == WatchConsume::Reverify || consume == WatchConsume::JournalOnly) {\n            m_consumedSinceMs = w.sinceMs;\n            m_consumedGeneration = ci.snapshotGeneration;\n        }\n", "", "watch", "the same verdict is consumed at every return"),
    ("res-15", ENG + "TunnelWatchResume.h", "        } else if (consume == WatchConsume::Reverify) {\n            reverify(w, ci.appNodeId, in.nowMs);\n        }", "        }", "watch", "a verdict of our session starts no re-check"),
    ("res-16", ENG + "TunnelWatchResume.h", "        // The decisions that waited run after the snapshot was adopted; a re-check started above has a\n        // new epoch, so a waiting completion of the old check returns without a verdict.\n        runDeferred();", "", "watch", "decisions dropped at a snapshot release"),
    ("res-17", ENG + "TunnelWatchResume.h", "        if (m_ops.backgroundArmOnly() || !resumeFreezeBegins(m_freeze, m_ops.watchFlag(), m_ops.tunnelConnected()))", "        if (!resumeFreezeBegins(m_freeze, m_ops.watchFlag(), m_ops.tunnelConnected()))", "watch", "a hand-over is begun in the background"),
    ("res-18", ENG + "TunnelWatchResume.h", "        m_generation = m_ops.sessionGeneration();\n", "", "watch", "the freeze does not remember which session it began with"),
    ("res-19", ENG + "TunnelWatchResume.h", "        m_ops.journal(QStringLiteral(\"watch_resume_freeze begin why=%1 node=%2\").arg(why, m_ops.appNodeId()));\n        m_ops.requestSnapshot();", "        m_ops.journal(QStringLiteral(\"watch_resume_freeze begin why=%1 node=%2\").arg(why, m_ops.appNodeId()));", "watch", "the freeze begins and nobody asks the extension"),
    ("res-20", ENG + "TunnelWatchResume.h", "        if (watchVerdictForgetsNode(w.verdict))\n            m_ops.forgetNode(nodeId);", "        m_ops.forgetNode(nodeId);", "watch", "the network memory forgets the node on an unconfirmed verdict"),
    ("res-21", ENG + "TunnelWatchResume.h", "            if (m_ops.reenterVerifying()) // only with the engine's consent\n                m_ops.startVerification();", "            m_ops.reenterVerifying();\n            m_ops.startVerification();", "watch", "rev-W7: a re-check started without the engine agreeing"),
    ("res-22", ENG + "TunnelWatchResume.h", "        case ReverifyAction::RestartPending:\n            m_ops.startVerification();", "        case ReverifyAction::RestartPending:", "watch", "a pending check is not started again (it completes as limited)"),
    ("res-23", ENG + "TunnelWatchResume.h", "        if (m_deferred.empty() || m_freeze.active || m_ops.backgroundArmOnly())\n            return;", "        if (m_deferred.empty() || m_freeze.active)\n            return;", "watch", "what waited runs in the background"),
    ("res-24", ENG + "TunnelWatchResume.h", "        deferred.swap(m_deferred);\n        for (auto &fn : deferred)\n            fn();", "        for (auto &fn : m_deferred)\n            fn();", "watch", "a decision that waited runs again and again"),
    # ---- background time by reason ----
    ("hold-01", IOS + "BackgroundHoldBook.h", "return m_reasons == 0 ? Step::EndTask : Step::None;", "return Step::EndTask;", "ios", "one reason leaving ends the task another reason holds"),
    ("hold-02", IOS + "BackgroundHoldBook.h", "return first ? Step::BeginTask : Step::None;", "return Step::BeginTask;", "ios", "a second system task is started"),
    ("hold-03", IOS + "BackgroundHoldBook.h", "void expire() { m_reasons = 0; }", "void expire() {}", "ios", "rev-A9: expiry leaves the reasons holding"),
    ("hold-04", IOS + "BackgroundHoldBook.h", "        m_sys.end();\n        for (auto &cb : cbs)\n            if (cb)\n                cb();", "        for (auto &cb : cbs)\n            if (cb)\n                cb();\n        m_sys.end();", "ios", "rev-A2: owners are told before the task is ended"),
    ("hold-05", IOS + "BackgroundHoldBook.h", "        if (!already)\n            m_callbacks[unsigned(r)] = std::move(onExpired);", "        m_callbacks[unsigned(r)] = std::move(onExpired);", "ios", "rev-A3: a second acquire replaces the first callback"),
    ("hold-06", IOS + "BackgroundHoldBook.h", "            m_book.taskRefused();\n", "", "ios", "a refused task is booked as held"),
    ("hold-07", IOS + "BackgroundHoldBook.h", "cbs[i] = std::exchange(m_callbacks[i], nullptr);", "cbs[i] = m_callbacks[i];", "ios", "an expiry leaves the callbacks in place (told again at the next expiry)"),
    ("hold-08", IOS + "BackgroundHoldBook.h", "        if (!(m_reasons & bit))\n            return Step::None;\n", "", "ios", "releasing what is not held ends the task"),
    ("hold-09", IOS + "BackgroundHoldBook.h", "        m_callbacks[unsigned(r)] = nullptr;\n        if (m_book.release(r) == BackgroundHoldBook::Step::EndTask)", "        if (m_book.release(r) == BackgroundHoldBook::Step::EndTask)", "ios", "rev-A1: a released reason keeps its callback"),
    ("hold-10", IOS + "BackgroundHoldBook.h", "void taskRefused() { m_reasons = 0; }", "void taskRefused() {}", "ios", "a refusal leaves the reason holding"),
    ("hold-11", IOS + "BackgroundHoldBook.h", "            for (auto &cb : m_callbacks)\n                cb = nullptr;\n", "", "ios", "rev-A4: a refused request keeps its callback"),
    # ---- the arming in the background ----
    ("arm-01", IOS + "IosBackgroundArm.h", '    if (!in.flagOn) return {BgArmStart::NotNeeded, "flag_off"};\n', "", "ios", "the arming holds background time with the flag off"),
    ("arm-02", IOS + "IosBackgroundArm.h", '    if (!in.wireGuardBased) return {BgArmStart::NotNeeded, "xray"};\n', "", "ios", "rev-A7: an Xray session is held for arming"),
    ("arm-03", IOS + "IosBackgroundArm.h", '    if (in.armed) return {BgArmStart::NotNeeded, "armed"};\n', "", "ios", "an armed session is held again"),
    ("arm-04", IOS + "IosBackgroundArm.h", 'if (!in.handshakeAwaiting && !in.changePending) return {BgArmStart::NotNeeded, "arm_decided"};', 'if (!in.handshakeAwaiting) return {BgArmStart::NotNeeded, "arm_decided"};', "ios", "an arming save in flight is not waited for"),
    ("arm-05", IOS + "IosBackgroundArm.h", 'if (!in.haveTunnel || !in.sessionUp) return {BgArmStart::NotNeeded, "no_session"};', 'if (!in.haveTunnel) return {BgArmStart::NotNeeded, "no_session"};', "ios", "a session that is down is held"),
    ("arm-06", IOS + "IosBackgroundArm.h", '    if (in.localStopRequested) return {BgArmStart::NotNeeded, "stopping"};\n', "", "ios", "rev-A5: a session being stopped is held"),
    ("arm-07", IOS + "IosBackgroundArm.h", "if (in.nowMs - in.heldSinceMs >= in.maxHoldMs) return BgArmTick::ReleaseTimeout;", "if (in.nowMs - in.heldSinceMs > in.maxHoldMs) return BgArmTick::ReleaseTimeout;", "ios", "hold bound boundary"),
    ("arm-08", IOS + "IosBackgroundArm.h", "    if (in.armed) return BgArmTick::ReleaseArmed;\n    if (in.appActive)", "    if (in.appActive)", "ios", "an armed rule is not told as armed"),
    ("arm-09", IOS + "IosBackgroundArm.h", "if (!in.sessionUp || in.localStopRequested) return BgArmTick::ReleaseNotNeeded;", "if (!in.sessionUp) return BgArmTick::ReleaseNotNeeded;", "ios", "our own stop does not release the hold"),
    ("arm-10", IOS + "IosBackgroundArm.h", "    if (!in.handshakeAwaiting && !in.changePending) return BgArmTick::ReleaseNotNeeded;\n", "", "ios", "rev-A6: an arming that was skipped keeps the hold until the bound"),
    ("arm-11", IOS + "IosBackgroundArm.h", 's += !sessionUp ? "-" : (wireGuardBased ? "awg" : "xray");', 's += wireGuardBased ? "awg" : "xray";', "ios", "the state line names a protocol for a session that is down"),
    ("arm-12", IOS + "IosBackgroundArm.h", "    if (in.nowMs < in.heldSinceMs) return BgArmTick::ReleaseTimeout;\n", "", "ios", "rev-A8: a clock set back stretches the hold"),
    ("arm-13", IOS + "IosBackgroundArm.h", "    if (in.appActive) return BgArmTick::ReleaseNotNeeded;\n", "", "ios", "rev-W16: the hold is not given back on the screen"),
    # ---- the engine ----
    ("eng-01", ENG + "ServiceEngine.cpp", "    if (m_state != EngineState::Connected || m_currentNodeId.isEmpty())\n        return false;\n    m_state = EngineState::Verifying;", "    if (m_currentNodeId.isEmpty())\n        return false;\n    m_state = EngineState::Verifying;", "pick", "rev-E1: any phase can be thrown back to Verifying"),
    ("eng-02", ENG + "ServiceEngine.cpp", "    m_upFrozen = true;\n    return true;\n}", "    return true;\n}", "pick", "rev-E2: a re-check records a bogus time to traffic"),
    ("eng-03", ENG + "ServiceEngine.cpp", "    m_state = EngineState::Verifying;\n    // A success of this re-check", "    // A success of this re-check", "pick", "the engine does not go back to Verifying"),
    ("eng-04", ENG + "ServiceEngine.cpp", "    m_upFrozen = true;\n    return true;\n}", "    m_upFrozen = true;\n    m_dataPlaneFailStreak = 0;\n    return true;\n}", "pick", "rev-E3: a re-check returns the give-up streak"),
    # ---- the extension: the plan file ----
    ("xp-01", IOS + "TribeWatchPlan.swift", "other.seq >= seq || other.writtenMs > writtenMs", "other.seq >= seq", "plan", "after the app's counter starts over every plan is refused"),
    ("xp-02", IOS + "TribeWatchPlan.swift", "other.seq >= seq || other.writtenMs > writtenMs", "true", "plan", "an older plan is accepted"),
    ("xp-03", IOS + "TribeWatchPlan.swift", "        guard last.accepts(order) else { return .failure(.stale) }\n", "", "plan", "the order of plans is not checked at all"),
    ("xp-04", IOS + "TribeWatchPlan.swift", "        guard policyFresh || appAlive else { return .failure(.policyStale) }\n", "", "plan", "a policy older than its age is trusted while the app sleeps"),
    ("xp-05", IOS + "TribeWatchPlan.swift", "nowMs - fetched <= maxAge && fetched - nowMs <= futureSlackMs", "nowMs - fetched <= maxAge", "plan", "a config time from the future is fresh"),
    ("xp-06", IOS + "TribeWatchPlan.swift", "        if expires <= nowMs || candidates.isEmpty { policy.switchEnabled = false }\n", "", "plan", "the switch stays on with an expired or empty candidate list"),
    ("xp-07", IOS + "TribeWatchPlan.swift", "guard written > 0, written - nowMs <= futureSlackMs else { return .failure(.future) }", "guard written > 0 else { return .failure(.future) }", "plan", "a plan written in the future is accepted"),
    ("xp-08", IOS + "TribeWatchPlan.swift", "guard data.count <= maxBytes else { return .failure(.tooLarge) }", "guard data.count <= maxBytes * 4 else { return .failure(.tooLarge) }", "plan", "a plan over 64 KB is read"),
    ("xp-09", IOS + "TribeWatchPlan.swift", "        if status == 200 {\n            if text.contains(\"<TITLE>Success</TITLE>\") { return .ok }\n            return complete ? .captive : nil\n        }", "        if status == 200 {\n            if text.contains(\"<TITLE>Success</TITLE>\") { return .ok }\n            return .captive\n        }", "plan", "a 200 whose body has not arrived is called a login page"),
    ("xp-10", IOS + "TribeWatchPlan.swift", "        if status == 204 { return .ok }\n", "", "plan", "the 204 answer is not known"),
    ("xp-11", IOS + "TribeWatchPlan.swift", "ready ? .ok : (tlsFailure ? .captive : .noReply)", "ready ? .ok : .noReply", "plan", "a TLS failure is not told apart from silence"),
    ("xp-12", IOS + "TribeWatchPlan.swift", "        guard kind == .http || path == \"/\" else { return nil }\n", "", "plan", "a TLS target with a page is accepted"),
    ("xp-13", IOS + "TribeWatchPlan.swift", "              host.contains(where: { $0.isLetter }) else { return nil }", "              true else { return nil }", "plan", "an IPv4 literal is accepted as a target"),
    ("xp-14", IOS + "TribeWatchPlan.swift", 'case "state": state = pair[1] == "no_session" ? .staged : (TribeProbeResult(rawValue: String(pair[1])) ?? .unavailable)', 'case "state": state = pair[1] == "no_session" ? .silent : (TribeProbeResult(rawValue: String(pair[1])) ?? .unavailable)', "plan", "a staged packet is read as silence"),
    ("xp-15", IOS + "TribeWatchPlan.swift", "        return code == -2 ? .noSession : .unavailable", "        return .unavailable", "plan", "a refused start is not told apart from no probe"),
    ("xp-16", IOS + "TribeWatchPlan.swift", "        if results.contains(.captive) { return .captive }\n", "", "plan", "a foreign reply does not outweigh silence"),
    # ---- the extension: the runtime ----
    ("rt-01", IOS + "TribeDataWatchRuntime.swift", "        refreshPlan()\n        guard loggingEnabled else { return }", "        guard loggingEnabled else { return }\n        refreshPlan()", "rt", "rev-W11: the kill switch is read only while the file log is on"),
    ("rt-02", IOS + "TribeDataWatchRuntime.swift", "        guard enabled, let live else { completion(nil); return }", "        guard enabled, let live else { return }", "rt", "rev-W14: the status reply waits for the watch even when it is off"),
    ("rt-03", IOS + "TribeDataWatchRuntime.swift", "        guard enabled, let live else { completion(nil); return }", "        guard let live else { completion(nil); return }", "rt", "a switched-off watch still answers with a block"),
    ("rt-04", IOS + "TribeDataWatchRuntime.swift", "let available = (deps?.setProbe(clientIP, resolver, wanted) ?? -1) == 0 && wanted", "let available = (deps?.setProbe(clientIP, resolver, true) ?? -1) == 0 && wanted", "rt", "rev-W5: the probe wrapper is configured with the watch off"),
    ("rt-05", IOS + "TribeDataWatchRuntime.swift", "        let wanted = current.enabled && current.probeEnabled", "        let wanted = current.enabled", "rt", "the probe is configured although the plan switches it off"),
    ("rt-06", IOS + "TribeDataWatchRuntime.swift", "                data = nil\n                stamp = nil\n                unreadable = true", "                data = nil\n                unreadable = true", "rt", "a failed read is remembered under the file's stamp (never retried)"),
    ("rt-07", IOS + "TribeDataWatchRuntime.swift", "        if current != before { attached.setDataWatchPolicy(current) }", "        if current.enabled && current != before { attached.setDataWatchPolicy(current) }", "rt", "a plan that switches the watch off never reaches the adapter"),
    ("rt-08", IOS + "TribeDataWatchRuntime.swift", "        guard let attached else { return }\n        let current = reloadPlan()", "        let current = reloadPlan()\n        guard let attached else { return }", "rt", "the plan is read for a provider that has no watch attached"),
    ("rt-09", IOS + "TribeDataWatchRuntime.swift", "        if wasEnabled && !next.enabled {\n", "        if false {\n", "rt", "the shared file keeps the verdict of a watch that was switched off"),
    ("rt-10", IOS + "TribeDataWatchRuntime.swift", "        if !next.enabled { lastVerdict = .none }\n", "", "rt", "(masked by the suffix guard) the statistics suffix keeps a verdict after the watch went off"),
    ("rt-11", IOS + "TribeDataWatchRuntime.swift", "let state: TribeProbeResult = result.id == flying ? result.state : .notSent", "let state: TribeProbeResult = result.state", "rt", "the result of another probe is taken for ours"),
    ("rt-12", IOS + "TribeDataWatchRuntime.swift", "lateWatch = (state == .silent || state == .staged) ? (flying, now + Self.lateAnswerWatchSeconds) : nil", "lateWatch = nil", "rt", "a late answer is never looked for"),
    ("rt-13", IOS + "TribeDataWatchRuntime.swift", "            if now > late.until {\n", "            if false {\n", "rt", "the look-out for a late answer never ends"),
    ("rt-15", IOS + "TribeDataWatchRuntime.swift", "        case .noSession:\n            probeInFlight = 0\n            inputs.probe = .noSession", "        case .noSession:\n            probeInFlight = 0\n            inputs.probe = .silent", "rt", "a refused start is told as a silent probe"),
    ("rt-17", IOS + "TribeDataWatchRuntime.swift", "        if sanityRunning { lock.unlock(); return }\n", "", "rt", "a second bypass check is started while one runs"),
    ("rt-18", IOS + "TribeDataWatchRuntime.swift", "        lastVerdict = snapshot.verdict\n", "", "rt", "the statistics suffix never follows the verdict"),
    ("rt-19", IOS + "TribeDataWatchRuntime.swift", "        deps.writeState(state)\n    }", "    }", "rt", "the shared file is never written"),
    ("rt-20", IOS + "TribeDataWatchRuntime.swift", "        guard output.action == .report, let report = output.report else { return }", "        guard output.action == .report, let report = output.report, output.verdict != .none else { return }", "rt", "the end of a verdict is not told to the outputs (stale no_data)"),
    ("rt-21", IOS + "TribeDataWatchRuntime.swift", "        adapter = nil\n        policy = .disabled\n        probeInFlight = 0", "        adapter = nil\n        probeInFlight = 0", "rt", "a stopped session still answers the status with a block"),
    ("rt-22", IOS + "TribeDataWatchRuntime.swift", "nextTargets = (plan.sanityTargets.isEmpty ? TribeSanityTarget.builtIn : plan.sanityTargets).compactMap { TribeSanityTarget(url: $0) }", "nextTargets = TribeSanityTarget.builtIn.compactMap { TribeSanityTarget(url: $0) }", "rt", "the plan's own bypass targets are ignored"),
    ("rt-23", IOS + "TribeDataWatchRuntime.swift", "let alive = inputs.appSeenAt.map { deps.uptime() - $0 <= policy.appAliveSeconds } ?? false", "let alive = false", "rt", "a living app does not vouch for an old policy"),
    ("rt-24", IOS + "TribeDataWatchRuntime.swift", "        if let deps { inputs.appSeenAt = deps.uptime() }\n", "", "rt", "a status request does not mark the app alive"),
    # ---- the controller (the real ios_controller.mm in its harness) ----
    ("ctl-01", IOS + "ios_controller.mm", "    if (!bgArmFlag)\n        return; // build 139 behaviour: nothing held, nothing journaled\n", "", "harness", "rev-W3: the background transition acts with the flag off"),
    ("ctl-02", IOS + "ios_controller.mm", "        if (m_watchSnapshotWanted.load()) {", "        if (true) {", "harness", "rev-W4: the snapshot signal fires on every status reply"),
    ("ctl-07", IOS + "ios_controller.mm", "                m_watchSnapshotWanted.store(false); // one request - one snapshot\n", "", "harness", "one request gives a snapshot on every later reply"),
    ("ctl-03", IOS + "ios_controller.mm", "    m_watchSnapshotWanted.store(true);\n    m_statusRequests.invalidate();\n    checkStatus();", "    m_watchSnapshotWanted.store(true);\n    checkStatus();", "harness", "rev-W10: a stale reply answers the snapshot request"),
    ("ctl-04", IOS + "ios_controller.mm", "    tickBackgroundArmHold(); // AVPN (iOS data watch, 140): the hold's bound is judged on this poll's tick\n", "", "harness", "rev-W17: the hold's bound is never judged"),
    ("ctl-05", IOS + "ios_controller.mm", "    in.appActive = appIsActive();\n", "", "harness", "rev-W16: the controller does not ask whether the app is on the screen"),
    ("ctl-06", IOS + "ios_controller.mm", "AvpnBackgroundGuard_acquire(avpn_ios::BgReason::OnDemandArm, [this, token] {", "AvpnBackgroundGuard_acquire(avpn_ios::BgReason::TunnelRestart, [this, token] {", "harness", "the arming takes the restart guard's reason"),
]

WIRING = [
    ("w-e1a", PATCH, "+        self.dataWatchTick(sample, handle: handle) // tribe.13: the same sample, before the ladder acts on it\n         let outcome = self.recovery.tick(sample, pathSatisfied: self.lastPathSatisfiable, policy: self.roamingPolicy)\n", "         let outcome = self.recovery.tick(sample, pathSatisfied: self.lastPathSatisfiable, policy: self.roamingPolicy)\n+        self.dataWatchTick(sample, handle: handle) // tribe.13: the same sample, before the ladder acts on it\n", "the watch is fed after the ladder acted"),
    ("w-e1b", PATCH, "+    private func dataWatchTick(_ sample: TribeStallSample, handle: Int32) {\n", "+    private func dataWatchTick(_ sample: TribeStallSample, handle: Int32) {\n+        self.workQueue.asyncAfter(deadline: .now() + 1) { }\n", "the adapter patch grows a delayed block"),
    ("w-e2a", PATCH, "+        guard self.dataWatchPolicy.enabled else { return }\n+        self.dataWatch.notePathEvent(", "+        self.dataWatch.notePathEvent(", "a path event reaches a switched-off watch"),
    ("w-e2b", PATCH, "+            if self.dataWatchPolicy.enabled {\n+                self.dataWatch.noteBackendRestarted(", "+            do {\n+                self.dataWatch.noteBackendRestarted(", "a backend restart reaches a switched-off watch"),
    ("w-e2c", PATCH, "+        guard self.dataWatchPolicy.enabled else {\n+            if self.dataWatchActive {", "+        guard !self.dataWatchPolicy.enabled else {\n+            if self.dataWatchActive {", "rev-W6: the adapter's own guard is inverted (the rule itself still refuses a disabled policy - tested; this guard is the adapter's shortcut)"),
    ("w-e3", PATCH, "+\tif tribeProbeCfg == nil {\n+\t\ttribeProbeTun = nil\n+\t\treturn inner\n+\t}\n", "", "the probe wrapper is created without a configuration"),
    ("w-e4a", IOS + "PacketTunnelProvider+DataWatch.swift", "setProbe: { clientIP, resolver, enabled in wgSetTribeProbe(clientIP, resolver, enabled ? 1 : 0) },", "setProbe: { clientIP, resolver, _ in wgSetTribeProbe(clientIP, resolver, 1) },", "the Go call ignores the runtime's on/off"),
    ("w-e4b", IOS + "PacketTunnelProvider+WireGuard.swift", "        tribeDataWatch.noteAppStatusRequest() // AVPN (build 140, data watch): the app is alive\n", "", "a status request does not mark the app alive"),
    ("w-e4c", IOS + "PacketTunnelProvider+WireGuard.swift", 'if let watch { response["watch"] = watch }', 'response["watch"] = watch ?? [String: Any]()', "the status reply always carries a watch key"),
    ("w-e4d", IOS + "PacketTunnelProvider+WireGuard.swift", "        tribeDataWatch.detach() // AVPN (build 140, data watch)\n", "", "the runtime is not detached on stop"),
    ("w-e4e", IOS + "PacketTunnelProvider+WireGuard.swift", "            prepareTribeDataWatch(wgConfig)\n", "", "the runtime is never prepared (no probe, no plan at start)"),
    ("w-e5a", IOS + "PacketTunnelProvider+WireGuard.swift", "        tribeDataWatch.statsTick(isXray: protoType == .xray, loggingEnabled: Log.isLoggingEnabled,", "        guard Log.isLoggingEnabled else { return }\n        tribeDataWatch.statsTick(isXray: protoType == .xray, loggingEnabled: Log.isLoggingEnabled,", "rev-W11 at the call site: the whole statistics tick is gated on the file log"),
    ("w-e5b", IOS + "TribeDataWatchRuntime.swift", "        parameters.requiredInterface = interface\n", "", "the bypass request is not bound to the physical interface"),
    ("w-e5c", IOS + "TribeDataWatchRuntime.swift", "    /// Pick up a rewritten plan and let a policy that has grown too old lapse.", "    private var tick = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n    /// Pick up a rewritten plan and let a policy that has grown too old lapse.", "the runtime gets a timer of its own"),
    ("w-e6", IOS + "TribeDataWatchRuntime.swift", "        guard output.action == .report, let report = output.report else { return }", "        if output.action == .switchPeer { deps.log(\"reasserting\") }\n        guard output.action == .report, let report = output.report else { return }", "the runtime acts on a switching action"),
    ("w-e7a", "recipes/awg-apple/conandata.yml", '    - patch_file: "patches/0012-tribe-data-watch.patch"\n', '    - patch_file: "patches/0010-tribe-upstream-http.patch"\n    - patch_file: "patches/0012-tribe-data-watch.patch"\n', "tribe.13 pulls in a patch of the unmerged branch"),
    ("w-e7b", "client/macos/networkextension/CMakeLists.txt", "    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/TribeDataWatch.swift\n", "", "the macOS extension target does not compile the rule"),
    ("w-e7c", "conanfile.py", 'self.requires("awg-apple/3.1.4-tribe.13")', 'self.requires("awg-apple/3.1.4-tribe.11")', "the app still requires the package without the watch"),
    ("w-e7d", "recipes/awg-apple/conanfile.py", ' "{os.path.join(self.source_folder, "tests", "TribeDataWatchLadderTests.swift")}"', "", "the package is not gated on the vectors with the stall ladder"),
    ("w-e8", IOS + "PacketTunnelProvider+WireGuard.swift", "                                 logXray: { [weak self] in self?.logTribeXrayStats() },", "                                 logXray: { },", "the Xray statistics line is never written"),
    ("w-a1", ENG + "AvpnEngineQml.cpp", '#ifdef Q_OS_IOS\n    writeTunnelWatchPlan("start");', '#if 1\n    writeTunnelWatchPlan("start");', "a plan write outside Q_OS_IOS"),
    ("w-a2", ENG + "AvpnEngineQml.cpp", '    const bool watch = featureEnabled(QStringLiteral("ios_tunnel_watch"), false);\n    QSettings s;', '    const bool watch = featureEnabled(QStringLiteral("ios_tunnel_watch"), true);\n    QSettings s;', "the flag is read with the default true"),
    ("w-a3a", ENG + "AvpnEngineQml.cpp", '#ifdef Q_OS_IOS\n    writeTunnelWatchPlan("start"); // AVPN (iOS data watch, 140): before the queued up() reaches the extension\n#endif\n', "", "a start does not rewrite the plan"),
    ("w-a3b", ENG + "AvpnEngineQml.cpp", "    s.setValue(QLatin1String(avpn::kWatchPlanSeqSettingsKey), out.seqAfter);\n", "", "the plan's sequence number is not persisted (every plan would be number 1)"),
    ("w-a3c", ENG + "AvpnEngineQml.cpp", "                    writeTunnelWatchPlan(\"foreground\");\n", "", "a return to the screen does not refresh the plan (the kill switch waits for the next start)"),
    ("w-a5a", ENG + "AvpnEngineQml.cpp", "    } else if (m_engine.tick(QDateTime::currentSecsSinceEpoch())) {", "    }\n    if (m_engine.tick(QDateTime::currentSecsSinceEpoch())) {", "rev-W12: the health verdict does not wait for the hand-over"),
    ("w-a5b", ENG + "AvpnEngineQml.cpp", '    if (deferWhileTunnelWatchFrozen("whoami", [this, epoch]() { whoamiAttempt(epoch); }))\n        return;\n', "", "a late whoami attempt is judged before the extension was asked"),
    ("w-a5c", ENG + "AvpnEngineQml.cpp", '    ops.watchFlag = [this] { return featureEnabled(QStringLiteral("ios_tunnel_watch"), false); };', '    ops.watchFlag = [] { return true; };', "rev-W1 at the call site: the hand-over is given a flag that is always on"),
    ("w-a5d", ENG + "AvpnEngineQml.cpp", "        tickTunnelWatchFreeze(since); // AVPN (iOS data watch, 140): the resume freeze rides on this tick\n", "", "the hand-over is never driven (no thaw seen by the tick, no timeout)"),
    ("w-a5e", ENG + "AvpnEngineQml.cpp", "        return m_hiddenSeen && featureEnabled(QStringLiteral(\"ios_on_demand_bg_arm\"), false) && !m_restartGuard.held();", "        return m_hiddenSeen && featureEnabled(QStringLiteral(\"ios_on_demand_bg_arm\"), false);", "the background hold also stops the app's own restart in flight"),
    ("w-a5f", ENG + "AvpnEngineQml.cpp", "    setupTunnelWatchResume();\n", "", "the hand-over object is never built"),
    ("w-a7b", IOS + "ios_controller.mm", "    return [UIApplication sharedApplication].applicationState == UIApplicationStateActive;", "    return false;", "on the phone the controller never learns that the app is on the screen (the harness has no UIKit)"),
    ("w-a8a", ENG + "AvpnEngineQml.cpp", "    ops.startVerification = [this] {\n        refreshDataFlowing();\n        startDataPathVerification();", "    ops.startVerification = [this] {\n        refreshDataFlowing();\n        m_engine.verifyFailed(QStringLiteral(\"extension\"));", "the extension's verdict is taken as a failure of the node"),
    ("w-a8b", ENG + "AvpnEngineQml.cpp", "    ops.reenterVerifying = [this] { return m_engine.reenterVerifying(); };", "    ops.reenterVerifying = [this] { m_engine.reenterVerifying(); return true; };", "rev-W7 at the call site: the engine's answer is not passed on"),
    ("w-a8c", ENG + "AvpnEngineQml.cpp", "    ops.forgetNode = [this](const QString &nodeId) {\n        if (m_attemptNetKey.isEmpty())\n            return;", "    ops.forgetNode = [this](const QString &nodeId) {\n        m_savedPin.clear();\n        if (m_attemptNetKey.isEmpty())\n            return;", "the extension's verdict clears the pin"),
    ("w-x1a", "recipes/awg-apple/tribe/TribeDataWatch.swift", 'numbers["ios_tw_cycle_s"], fallback: policy.cycleSeconds, min: 10, max: 120)', 'numbers["ios_tw_cycle_s"], fallback: policy.cycleSeconds, min: 5, max: 120)', "the extension clamps a number to other bounds than the app"),
    ("w-x1b", ENG + "ConnectTunables.h", '{"ios_tw_probe_max_per_hour",            12,        1,          60, true}', '{"ios_tw_probe_max_per_hour",            12,        1,         600, true}', "the app lets through a value the extension cuts"),
    ("w-x1c", "recipes/awg-apple/tribe/TribeDataWatch.swift", '        policy.probeMaxPerHour = Int(number(numbers["ios_tw_probe_max_per_hour"], fallback: Double(policy.probeMaxPerHour), min: 1, max: 60))\n', "", "a number of the plan is not read by the extension"),
    ("w-x2", IOS + "TribeWatchPlan.swift", 'static let builtIn = ["https://www.ozon.ru", "https://www.wildberries.ru", "https://www.apple.com"]', 'static let builtIn = ["https://connectivitycheck.gstatic.com", "https://www.apple.com"]', "the built-in bypass targets are foreign hosts again (never an answer on a white-list network)"),
]

# Survivors that are accepted, with the reason no test of this group can or should kill them.
ACCEPTED = {}

COPY = [
    "conanfile.py",
    "recipes/awg-apple/conanfile.py", "recipes/awg-apple/conandata.yml", PATCH, "recipes/awg-apple/tribe/TribeDataWatch.swift",
    "recipes/awg-apple/tests/run_tribe_data_watch_tests.sh", "recipes/awg-apple/tests/TribeDataWatchLadderTests.swift",
    "client/ios/networkextension/CMakeLists.txt", "client/macos/networkextension/CMakeLists.txt",
]


def run(cmd, cwd=None, timeout=600):
    return subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)


def make_tree(dst):
    for rel in COPY:
        os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), os.path.join(dst, rel))
    # The two directories whole; everything else under client/ is linked (read only), because the
    # engine sources include their neighbours by relative paths.
    for rel_dir in (ENG, IOS):
        shutil.copytree(os.path.join(ROOT, rel_dir), os.path.join(dst, rel_dir), dirs_exist_ok=True)
    for rel_dir in ("client", "client/core", "client/platforms"):
        for name in os.listdir(os.path.join(ROOT, rel_dir)):
            link = os.path.join(dst, rel_dir, name)
            if not os.path.lexists(link):
                os.symlink(os.path.join(ROOT, rel_dir, name), link)


def test_command(kind, tree, work):
    eng_tests = os.path.join(tree, ENG, "tests")
    ios = os.path.join(tree, IOS)
    ios_tests = os.path.join(ios, "tests")
    rule = os.path.join(tree, "recipes/awg-apple/tribe/TribeDataWatch.swift")
    if kind == "watch":
        return ["bash", "-c", 'OUT="%s/tw" QT_ROOT="%s" bash "%s/build_tunnel_watch.sh"' % (work, QT, eng_tests)]
    if kind == "pick":
        # Headers outside the two copied directories come from the working tree (never mutated here).
        return ["bash", "-c", 'OUT="%s/tp" QT_ROOT="%s" AVPN_MAIN_CLIENT="%s" bash "%s/build_transport_pick.sh"'
                % (work, QT, os.path.join(ROOT, "client"), eng_tests)]
    if kind == "ios":
        return ["bash", "-c", 'xcrun clang++ -std=c++17 -pthread "%s/IosDataWatchTests.cpp" -o "%s/idw" && "%s/idw"' % (ios_tests, work, work)]
    if kind == "plan":
        return ["bash", "-c", 'xcrun --sdk macosx swiftc -Onone -parse-as-library -o "%s/plan" "%s" "%s/TribeWatchPlan.swift" '
                '"%s/TribeWatchPlanTests.swift" && "%s/plan"' % (work, rule, ios, ios_tests, work)]
    if kind == "rt":
        return ["bash", "-c", 'xcrun --sdk macosx swiftc -Onone -parse-as-library -o "%s/rt" "%s" "%s/TribeWatchPlan.swift" '
                '"%s/TribeDataWatchRuntime.swift" "%s/TribeDataWatchRuntimeTests.swift" && "%s/rt"' % (work, rule, ios, ios, ios_tests, work)]
    if kind == "harness":
        return ["bash", "-c", 'OUT="%s/harness" QT_ROOT="%s" bash "%s/build_ios_controller_harness.sh"' % (work, QT, ios_tests)]
    if kind == "wiring":
        return ["bash", os.path.join(eng_tests, "check_ios_data_watch_wiring.sh")]
    raise ValueError(kind)


def main():
    args = sys.argv[1:]
    anchors_only = "anchors" in args
    groups = [a for a in args if a in ("pure", "wiring")] or ["pure", "wiring"]
    wanted = [a for a in args if a not in ("pure", "wiring", "anchors")]
    mutants = []
    if "pure" in groups:
        mutants += [(i, f, o, n, t, w) for (i, f, o, n, t, w) in PURE]
    if "wiring" in groups:
        mutants += [(i, f, o, n, "wiring", w) for (i, f, o, n, w) in WIRING]
    if anchors_only:
        bad = 0
        for mutant_id, rel, old, _new, _kind, _what in mutants:
            count = open(os.path.join(ROOT, rel), encoding="utf-8").read().count(old)
            if count != 1:
                bad += 1
                print("INVALID  %-8s the text to mutate occurs %d times in %s" % (mutant_id, count, os.path.basename(rel)))
        print("anchors: %d mutants, %d invalid" % (len(mutants), bad))
        return 1 if bad else 0
    survivors, invalid, killed = [], [], 0
    with tempfile.TemporaryDirectory(prefix="ios-data-watch-mutants.") as work:
        tree = os.path.join(work, "tree")
        make_tree(tree)
        for kind in sorted({m[4] for m in mutants}):
            base = run(test_command(kind, tree, work))
            if base.returncode != 0:
                print("the unmutated tree does not pass its own check (%s):\n%s" % (kind, base.stdout.decode(errors="replace")[-1500:]))
                return 2
        for mutant_id, rel, old, new, kind, what in mutants:
            if wanted and not any(mutant_id.startswith(w) for w in wanted):
                continue
            path = os.path.normpath(os.path.join(tree, rel))
            if not os.path.realpath(path).startswith(os.path.realpath(tree) + os.sep):
                invalid.append((mutant_id, "%s is not a copy: refusing to mutate the working tree" % rel))
                continue
            original = open(path, encoding="utf-8").read()
            if original.count(old) != 1:
                invalid.append((mutant_id, "the text to mutate occurs %d times in %s" % (original.count(old), os.path.basename(path))))
                continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(original.replace(old, new))
            try:
                result = run(test_command(kind, tree, work))
                alive = result.returncode == 0
            except subprocess.TimeoutExpired:
                alive = False
            finally:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(original)
            if alive:
                survivors.append((mutant_id, what))
                print("SURVIVED %-8s [%s] %s" % (mutant_id, kind, what))
            else:
                killed += 1
                print("killed   %-8s [%s] %s" % (mutant_id, kind, what))
    unexpected = [s for s in survivors if s[0] not in ACCEPTED]
    print("\nmutants: %d killed, %d survived (%d accepted), %d invalid" % (killed, len(survivors), len(survivors) - len(unexpected), len(invalid)))
    for mutant_id, why in invalid:
        print("INVALID  %-8s %s" % (mutant_id, why))
    for mutant_id, what in survivors:
        if mutant_id in ACCEPTED:
            print("accepted %-8s %s -- %s" % (mutant_id, what, ACCEPTED[mutant_id]))
    return 1 if unexpected or invalid else 0


if __name__ == "__main__":
    sys.exit(main())

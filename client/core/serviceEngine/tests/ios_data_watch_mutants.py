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
              cfg     - config_cache_policy_check
  wiring  - one call site removed, moved or un-gated where no test reaches (the adapter patch, the
            provider's and the facade's call sites, the recipe, the CMake lists); killed when
            check_ios_data_watch_wiring.sh fails. These are the mutants ONLY the source-level check
            catches.
The verdict rule itself has its own run: recipes/awg-apple/replay/tribe_data_watch_mutants.py.

The mutants named "rev-..." are those of the independent review of stage 1 (its nine survivors were
glue proven by reading only); each is now killed by a behavioural test, or is listed under wiring
with the reason it stays there.
"second review R1..R8" / "rev2-G.." in the texts: the findings and the glue mutants of the second
independent review (stage 2, the server-change key).

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
    ("res-06", ENG + "TunnelWatchResume.h", "                if (m_replyAskedMs < 0)\n                    runDeferred(); // nothing of ours holds: what waited goes on\n", "", "watch", "what waited for the background hold never runs"),
    ("res-07", ENG + "TunnelWatchResume.h", "            // After a timeout the health verdict goes on; the data checks still wait for the reply.\n            if (!replyAwaited())\n                runDeferred();\n", "", "watch", "rev-W13: deferred decisions dropped when the freeze ends by the flag or the tunnel"),
    ("res-07b", ENG + "TunnelWatchResume.h", "            if (!replyAwaited())\n                runDeferred();\n        }\n    }\n\n    // Any status reply", "            runDeferred();\n        }\n    }\n\n    // Any status reply", "watch", "second review R3: after the timeout the data checks run before any reply said where the tunnel stands"),
    ("res-07c", ENG + "TunnelWatchResume.h", "            if (step != FreezeStep::ReleaseTimeout)\n                m_replyAskedMs = -1; // flag off or tunnel down: nobody is waited for\n", "", "watch", "a tunnel that went down and came back leaves the data checks waiting for a reply nobody was asked for"),
    ("res-08", ENG + "TunnelWatchResume.h", "            m_replyAskedMs = in.nowMs;\n            m_ops.requestSnapshot();\n            return;", "            m_replyAskedMs = in.nowMs;\n            return;", "watch", "after a second freeze the extension is not asked again"),
    ("res-08b", ENG + "TunnelWatchResume.h", "            m_replyAskedMs = in.nowMs;\n            m_ops.requestSnapshot();\n            return;", "            m_ops.requestSnapshot();\n            return;", "watch", "after a second freeze the wait for the reply is counted from the first request (it is over at once)"),
    ("res-10", ENG + "TunnelWatchResume.h", "        if (step != FreezeStep::ReleaseSnapshot) {\n            journalRelease(step, nullptr);\n            runDeferred();\n            return;\n        }", "        if (step != FreezeStep::ReleaseSnapshot) {\n            journalRelease(step, nullptr);\n            return;\n        }", "watch", "decisions dropped when the freeze ends because the tunnel went down"),
    ("res-11", ENG + "TunnelWatchResume.h", "        if (m_ops.backgroundArmOnly()) {\n            // The app went to the background before the answer came", "        if (false) {\n            // The app went to the background before the answer came", "watch", "a verdict is adopted and a re-check started in the background"),
    ("res-13", ENG + "TunnelWatchResume.h", "        ci.nodeScanOn = m_ops.nodeScanFlag();", "        ci.nodeScanOn = true;", "watch", "with node_scan off the verdict starts a check"),
    ("res-14", ENG + "TunnelWatchResume.h", "        if (consume == WatchConsume::Reverify || consume == WatchConsume::JournalOnly) {\n            m_consumedSinceMs = w.sinceMs;\n            m_consumedGeneration = ci.snapshotGeneration;\n        }\n", "", "watch", "the same verdict is consumed at every return"),
    ("res-15", ENG + "TunnelWatchResume.h", "        } else if (consume == WatchConsume::Reverify) {\n            reverify(w, ci.appNodeId, in.nowMs);\n        }", "        }", "watch", "a verdict of our session starts no re-check"),
    ("res-16", ENG + "TunnelWatchResume.h", "        // The decisions that waited run after the snapshot was adopted; a re-check started above has a\n        // new epoch, so a waiting completion of the old check returns without a verdict.\n        runDeferred();", "", "watch", "decisions dropped at a snapshot release"),
    ("res-17", ENG + "TunnelWatchResume.h", "        if (m_ops.backgroundArmOnly()\n            || !resumeFreezeBegins(", "        if (!resumeFreezeBegins(", "watch", "a hand-over is begun in the background"),
    ("res-18", ENG + "TunnelWatchResume.h", "        m_generation = m_ops.sessionGeneration();\n", "", "watch", "the freeze does not remember which session it began with"),
    ("res-19", ENG + "TunnelWatchResume.h", "        m_replyAskedMs = m_ops.nowMs();\n        m_ops.requestSnapshot();\n    }", "        m_replyAskedMs = m_ops.nowMs();\n    }", "watch", "the freeze begins and nobody asks the extension"),
    ("res-19b", ENG + "TunnelWatchResume.h", "        m_replyAskedMs = m_ops.nowMs();\n        m_ops.requestSnapshot();\n    }", "        m_ops.requestSnapshot();\n    }", "watch", "second review R3: after a resume the data checks do not wait for the status reply"),
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
    ("rt-20", IOS + "TribeDataWatchRuntime.swift", "        guard output.action == .report, let report = output.report else { return }", "        guard output.action == .report, let report = output.report, output.verdict != .none else { return }", "rt", "the end of a verdict is not told to the outputs (stale no_data)"),
    ("rt-21", IOS + "TribeDataWatchRuntime.swift", "        adapter = nil\n        policy = .disabled\n        probeInFlight = 0", "        adapter = nil\n        probeInFlight = 0", "rt", "a stopped session still answers the status with a block"),
    ("rt-22", IOS + "TribeDataWatchRuntime.swift", "nextTargets = (plan.sanityTargets.isEmpty ? TribeSanityTarget.builtIn : plan.sanityTargets).compactMap { TribeSanityTarget(url: $0) }", "nextTargets = TribeSanityTarget.builtIn.compactMap { TribeSanityTarget(url: $0) }", "rt", "the plan's own bypass targets are ignored"),
    ("rt-23", IOS + "TribeDataWatchRuntime.swift", "let alive = inputs.appSeenAt.map { deps.uptime() - $0 <= policy.appAliveSeconds } ?? false", "let alive = false", "rt", "a living app does not vouch for an old policy"),
    ("rt-24", IOS + "TribeDataWatchRuntime.swift", "        if let deps { inputs.appSeenAt = deps.uptime() }\n", "", "rt", "a status request does not mark the app alive"),
    # ---- stage 2: candidates, the plan, the switch the app finds made ----
    ("plan-05", ENG + "TunnelWatchPlan.h", "    if (in.watch && in.watchSwitch) {\n        for (const WatchPlanCandidate &c : in.candidates) {", "    if (in.watch) {\n        for (const WatchPlanCandidate &c : in.candidates) {", "watch", "a node's keys are written with the switch key off"),
    ("plan-28", ENG + "TunnelWatchPlan.h", "            if (candidates.size() >= kWatchPlanMaxCandidates)\n                break;\n", "", "watch", "more than five candidates are written"),
    ("plan-29", ENG + "TunnelWatchPlan.h", "if (node <= 0 || c.nodeId.contains(QLatin1Char(':')) || c.peer.isEmpty())", "if (node <= 0 || c.peer.isEmpty())", "watch", "an Xray listener is written as a candidate"),
    ("plan-30", ENG + "TunnelWatchPlan.h", "if (node <= 0 || c.nodeId.contains(QLatin1Char(':')) || c.peer.isEmpty())", "if (node <= 0 || c.nodeId.contains(QLatin1Char(':')))", "watch", "a candidate without a configuration is written"),
    ("plan-31", ENG + "TunnelWatchPlan.h", "        if (!text.isEmpty())\n            peer.insert(key, text);", "        peer.insert(key, text);", "watch", "empty values and absent keys are written"),
    ("plan-32", ENG + "TunnelWatchPlan.h", "if (current.isEmpty() || current != watchPlanSessionLines(candidateInner))", "if (current.isEmpty())", "watch", "a node with another DNS or MTU is offered for a switch in place"),
    ("plan-33", ENG + "TunnelWatchPlan.h", "for (const char *key : {\"mtu\", \"allowed_ips\", \"client_ip\"})", "for (const char *key : {\"mtu\"})", "watch", "other routed ranges or another tunnel address count as in place"),
    ("plan-34", ENG + "TunnelWatchPlan.h", "if (current.isEmpty() || current != watchPlanSessionLines(candidateInner))", "if (current != watchPlanSessionLines(candidateInner))", "watch", "two nodes with nothing to compare count as in place"),
    ("adopt-01", ENG + "TunnelWatchStatus.h", "if (in.switchSeq <= 0 || in.snapshotNodeId.isEmpty() || in.snapshotGeneration.isEmpty())", "if (in.snapshotNodeId.isEmpty() || in.snapshotGeneration.isEmpty())", "watch", "a node is adopted although the extension made no switch"),
    ("adopt-02", ENG + "TunnelWatchStatus.h", "    if (in.snapshotNodeId == in.appNodeId)\n        return false; // the app is already there\n", "", "watch", "the node the app is on is adopted again"),
    ("adopt-03", ENG + "TunnelWatchStatus.h", "if (in.snapshotGeneration == in.adoptedGeneration && in.switchSeq <= in.adoptedSeq)", "if (in.switchSeq <= in.adoptedSeq)", "watch", "a switch of another run of the extension is taken for an adopted one"),
    ("adopt-04", ENG + "TunnelWatchStatus.h", "if (in.snapshotGeneration == in.adoptedGeneration && in.switchSeq <= in.adoptedSeq)", "if (false)", "watch", "an adopted switch pulls the app back after a tap"),
    ("adopt-05", ENG + "TunnelWatchStatus.h", "if (in.switchSeq <= 0 || in.snapshotNodeId.isEmpty() || in.snapshotGeneration.isEmpty())", "if (in.switchSeq <= 0 || in.snapshotNodeId.isEmpty())", "watch", "a switch without a run of the extension is adopted"),
    ("adopt-06", ENG + "TunnelWatchStatus.h", "s.lastSwitchWhy = watchLabel(switches.last().toMap().value(QStringLiteral(\"why\")).toString());", "s.lastSwitchWhy = switches.last().toMap().value(QStringLiteral(\"why\")).toString();", "watch", "free text from the reply gets into the journal"),
    ("adopt-07", ENG + "TunnelWatchResume.h", "if (adopt(session, 0, watchLabel(session.value(QStringLiteral(\"switch_why\")).toString())) && m_ops.engineVerifying())", "if (adopt(session, 0, session.value(QStringLiteral(\"switch_why\")).toString()) && m_ops.engineVerifying())", "watch", "free text from an ordinary status reply gets into the journal"),
    ("adopt-08", ENG + "TunnelWatchStatus.h", "    if (raw.isEmpty() || raw.size() > 32)\n        return QStringLiteral(\"unknown\");", "    if (raw.isEmpty())\n        return QStringLiteral(\"unknown\");", "watch", "a label of any length is journaled"),
    ("adopt-09", ENG + "TunnelWatchStatus.h", "        if (!c.isLetterOrNumber() && c != QLatin1Char('_'))\n            return QStringLiteral(\"unknown\");", "        if (false)\n            return QStringLiteral(\"unknown\");", "watch", "spaces, '=' and line breaks pass as a label"),
    ("res-12", ENG + "TunnelWatchResume.h", "ci.appGeneration = ci.snapshotGeneration == m_adoptedGeneration ? ci.snapshotGeneration : m_generation;", "ci.appGeneration = ci.snapshotGeneration;", "watch", "the generation the app saw before the freeze is not compared"),
    ("res-25", ENG + "TunnelWatchResume.h", "        m_adoptedSeq = ai.switchSeq;\n        m_adoptedGeneration = ai.snapshotGeneration;\n        return taken;", "        return taken;", "watch", "a switch is adopted at every reply (a tap is undone)"),
    ("res-26", ENG + "TunnelWatchResume.h", "ai.switchSeq = qMax(watchSeq, session.value(QStringLiteral(\"switch_seq\")).toInt());", "ai.switchSeq = watchSeq;", "watch", "the session's own switch number is not read (nothing is adopted from an ordinary poll)"),
    ("res-26b", ENG + "TunnelWatchResume.h", "ai.switchSeq = qMax(watchSeq, session.value(QStringLiteral(\"switch_seq\")).toInt());", "ai.switchSeq = session.value(QStringLiteral(\"switch_seq\")).toInt();", "watch", "the switch number of the watch block is not read"),
    ("res-27", ENG + "TunnelWatchResume.h", "        } else if (adopted && m_ops.engineVerifying()) {", "        } else if (false) {", "watch", "the node the extension moved to is not checked by the app"),
    ("res-28", ENG + "TunnelWatchResume.h", "ci.appGeneration = ci.snapshotGeneration == m_adoptedGeneration ? ci.snapshotGeneration : m_generation;", "ci.appGeneration = m_generation;", "watch", "after a start by the system the verdict of the adopted session is another session's"),
    ("cand-01", ENG + "TunnelWatchCandidates.h", "    if (mode == TransportMode::Xray)\n        return out;\n", "", "pick", "Xray-only mode offers AmneziaWG candidates"),
    ("cand-02", ENG + "TunnelWatchCandidates.h", "if (isXrayProto(n.proto) || isManualOnlyNode(n))", "if (isXrayProto(n.proto))", "pick", "a manual-only node is offered"),
    ("cand-03", ENG + "TunnelWatchCandidates.h", "if (!current || isXrayProto(current->proto))", "if (!current)", "pick", "an Xray session gets candidates"),
    ("cand-04", ENG + "TunnelWatchCandidates.h", "        in.excluded = failedThisSession;\n", "", "pick", "a node that failed in this session is offered again"),
    ("cand-05", ENG + "TunnelWatchCandidates.h", "    take(pinned);\n", "", "pick", "the pinned country does not come first"),
    ("cand-06", ENG + "TunnelWatchCandidates.h", "        in.exclA = currentNodeId;\n", "", "pick", "the current node is offered as a candidate"),
    ("cand-07", ENG + "TunnelWatchCandidates.h", "if (isXrayProto(n.proto) || isManualOnlyNode(n))", "if (isManualOnlyNode(n))", "pick", "(the Awg mode filters them too) Xray listeners enter the pool"),
    ("eng-05", ENG + "ServiceEngine.cpp", "        if (!watchPlanInPlace(currentInner, inner))\n            continue; // another DNS, MTU or routed range: that switch is the app's own\n", "", "pick", "a node with another DNS is put into the plan"),
    ("eng-06", ENG + "ServiceEngine.cpp", "    if (m_state != EngineState::Connected && m_state != EngineState::Verifying)\n        return false;\n    if (nodeId == m_currentNodeId || !findNode(nodeId))", "    if (nodeId == m_currentNodeId || !findNode(nodeId))", "pick", "a switch is adopted while the app's own start is in flight"),
    ("eng-07", ENG + "ServiceEngine.cpp", "    if (nodeId == m_currentNodeId || !findNode(nodeId))\n        return false;", "    if (nodeId == m_currentNodeId)\n        return false;", "pick", "a node the pool does not know is adopted"),
    ("eng-08", ENG + "ServiceEngine.cpp", "        m_extEvidence.note(m_currentNodeId, netKey, nowMs());\n", "", "pick", "the node the extension left is offered and picked again at once"),
    ("eng-08b", ENG + "ServiceEngine.cpp", "    out.unite(m_extEvidence.freshNodes(m_extEvidenceNet, nowMs()));\n", "", "pick", "the extension's evidence excludes nothing"),
    ("eng-08c", ENG + "ServiceEngine.cpp", "    m_extEvidenceNet = netKey;\n    if (!m_currentNodeId.isEmpty()) {", "    if (!m_currentNodeId.isEmpty()) {", "pick", "the evidence is filed under one network and looked up under another"),
    ("eng-08d", ENG + "ServiceEngine.cpp", "        if (m_extOriginNodeId.isEmpty())\n            m_extOriginNodeId = m_currentNodeId; // where the user was", "        m_extOriginNodeId = m_currentNodeId; // where the user was", "pick", "the place to return to moves with every switch of the extension"),
    ("eng-08e", ENG + "ServiceEngine.cpp", "    if (nodeId == m_extOriginNodeId)\n        m_extOriginNodeId.clear(); // the extension itself came back\n", "", "pick", "after the extension itself came back, the app's own failover is undone as if it were the extension's"),
    ("eng-12", ENG + "ServiceEngine.cpp", "f.movedByExtension = locationKeyOf(*origin) == pinLocation && locationKeyOf(*current) != pinLocation;", "f.movedByExtension = locationKeyOf(*current) != pinLocation;", "pick", "a session that was outside the pinned location by the app's own doing is 'returned'"),
    ("eng-12b", ENG + "ServiceEngine.cpp", "f.movedByExtension = locationKeyOf(*origin) == pinLocation && locationKeyOf(*current) != pinLocation;", "f.movedByExtension = locationKeyOf(*origin) == pinLocation;", "pick", "a session that is in the pinned location again is restarted for nothing"),
    ("eng-13", ENG + "ServiceEngine.cpp", "f.evidenceFresh = m_extEvidence.fresh(m_extOriginNodeId, m_extEvidenceNet, nowMs());", "f.evidenceFresh = false;", "pick", "the way back is open while the extension's evidence is fresh"),
    ("eng-14", ENG + "ServiceEngine.cpp", "f.pinRaisable = pinnedCandidate() != nullptr;", "f.pinRaisable = true;", "pick", "a way back to a location that cannot be raised"),
    ("eng-15", ENG + "ServiceEngine.cpp", "    m_extOriginNodeId.clear(); // AVPN (iOS data watch): a start of the app's own is a new choice\n", "", "pick", "(a stop clears it as well; a start without a stop comes only after a lost tunnel) a start of the app's own keeps the old session's place to return to"),
    ("eng-16", ENG + "ServiceEngine.cpp", "    m_extOriginNodeId.clear(); // AVPN (iOS data watch): the session the extension moved is over (the evidence ages by itself)\n", "", "pick", "a tunnel found alive after a stop inherits the old session's place to return to"),
    ("eng-09", ENG + "ServiceEngine.cpp", "    if (verify) {\n        m_state = EngineState::Verifying;\n        m_upFrozen = true; // not a time to traffic: the rise was the extension's", "    if (true) {\n        m_state = EngineState::Verifying;\n        m_upFrozen = true; // not a time to traffic: the rise was the extension's", "pick", "without a check of its own the engine is left in Verifying"),
    ("eng-10", ENG + "ServiceEngine.cpp", "    m_currentNodeId = nodeId;\n    if (nodeId == m_extOriginNodeId)", "    if (nodeId == m_extOriginNodeId)", "pick", "the adopted node does not become the current one"),
    ("eng-11", ENG + "ServiceEngine.cpp", "        if (out.size() >= kWatchPlanMaxCandidates)\n            break;\n    }\n    return out;\n}\n\nQSet<QString> ServiceEngine::sessionExclusions", "    }\n    return out;\n}\n\nQSet<QString> ServiceEngine::sessionExclusions", "pick", "(the plan writer cuts to five as well) the engine's list is unbounded"),
    ("cfg-01", ENG + "ConfigCachePolicy.h", "    if (ios)\n        features.insert(QStringLiteral(\"ios_tunnel_watch_switch\"), false);", "    Q_UNUSED(ios);", "cfg", "the switch key is trusted from a cached config"),
    ("cfg-02", ENG + "ConfigCachePolicy.h", "    if (ios)\n        features.insert(QStringLiteral(\"ios_tunnel_watch_switch\"), false);", "    features.insert(QStringLiteral(\"ios_tunnel_watch_switch\"), false);", "cfg", "the freeze touches another platform's flag"),
    ("cfg-03", ENG + "ConfigCachePolicy.h", "    features.insert(QStringLiteral(\"node_scan\"), false);\n    if (ios)", "    if (ios)", "cfg", "node_scan is trusted from a cached config"),
    # ---- stage 2, the extension: the plan's candidates and the start by the system ----
    ("xp-06", IOS + "TribeWatchPlan.swift", "        if candidates.isEmpty { policy.switchEnabled = false }\n", "", "plan", "the switch stays on without a usable candidate"),
    ("xc-01", IOS + "TribeWatchPlan.swift", "if expires > nowMs && leaseAlive && policy.switchEnabled {", "if leaseAlive && policy.switchEnabled {", "plan", "an expired candidate list is used"),
    ("xl-01", IOS + "TribeWatchPlan.swift", "if expires > nowMs && leaseAlive && policy.switchEnabled {", "if expires > nowMs && policy.switchEnabled {", "plan", "second review R7: the switch lease is not checked"),
    ("xl-02", IOS + "TribeWatchPlan.swift", "if expires > nowMs && leaseAlive && policy.switchEnabled {", "if expires > nowMs && leaseAlive {", "plan", "the nodes' keys are parsed and kept with the switch key off"),
    ("xl-03", IOS + "TribeWatchPlan.swift", "let leaseAlive = lease > nowMs && lease - nowMs <= maxLeaseMs + futureSlackMs", "let leaseAlive = lease > nowMs", "plan", "a lease far in the future is believed (clock trouble, a forged plan)"),
    ("xl-04", IOS + "TribeWatchPlan.swift", "let leaseAlive = lease > nowMs && lease - nowMs <= maxLeaseMs + futureSlackMs", "let leaseAlive = lease >= nowMs && lease - nowMs <= maxLeaseMs + futureSlackMs", "plan", "lease boundary"),
    ("xl-05", IOS + "TribeWatchPlan.swift", "let leaseAlive = lease > nowMs && lease - nowMs <= maxLeaseMs + futureSlackMs", "let leaseAlive = lease - nowMs <= maxLeaseMs + futureSlackMs", "plan", "a lapsed lease is alive"),
    ("xl-06", IOS + "TribeWatchPlan.swift", "    static let maxLeaseMs: Int64 = 24 * 3600 * 1000\n", "    static let maxLeaseMs: Int64 = 240 * 3600 * 1000\n", "plan", "the longest lease is ten days"),
    ("xl-07", IOS + "TribeWatchPlan.swift", "holdsUnusableSecrets: !rawCandidates.isEmpty && candidates.isEmpty,", "holdsUnusableSecrets: false,", "plan", "the keys of a plan that may not switch are never taken out"),
    ("xl-08", IOS + "TribeWatchPlan.swift", "holdsUnusableSecrets: !rawCandidates.isEmpty && candidates.isEmpty,", "holdsUnusableSecrets: !rawCandidates.isEmpty,", "plan", "a usable candidate list is wiped"),
    ("xl-09", IOS + "TribeWatchPlan.swift", "        object[\"candidates\"] = [Any]()\n", "", "plan", "the plan is rewritten with the keys still in it"),
    ("xl-10", IOS + "TribeWatchPlan.swift", "              int(object[\"schema\"]) == Int64(schema) else { return nil }\n        object[\"candidates\"]", "              true else { return nil }\n        object[\"candidates\"]", "plan", "a file that is not a plan of this schema is rewritten"),
    ("xc-02", IOS + "TribeWatchPlan.swift", "                      !candidates.contains(where: { $0.nodeId == candidate.nodeId }) else { continue }", "                      true else { continue }", "plan", "a node is offered twice"),
    ("xc-03", IOS + "TribeWatchPlan.swift", "for raw in rawCandidates.prefix(maxCandidates) {", "for raw in rawCandidates {", "plan", "the list is not bounded"),
    ("xc-04", IOS + "TribeWatchPlan.swift", "!text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) })", "true", "plan", "a line break in a value gets into the wg-quick text"),
    ("xc-05", IOS + "TribeWatchPlan.swift", "        for key in Self.requiredInterfaceKeys + [\"hostName\", \"port\", \"server_pub_key\"] where peer[key] == nil { return nil }\n", "", "plan", "an entry without the whole AmneziaWG bundle is accepted"),
    ("xc-06", IOS + "TribeWatchPlan.swift", "let key = peer[\"server_pub_key\"], Data(base64Encoded: key)?.count == 32 else { return nil }", "let key = peer[\"server_pub_key\"], !key.isEmpty else { return nil }", "plan", "a key that is not 32 bytes is accepted"),
    ("xc-07", IOS + "TribeWatchPlan.swift", "(1...65535).contains(port),", "port >= 0,", "plan", "a port outside the range is accepted"),
    ("xc-08", IOS + "TribeWatchPlan.swift", "        if let psk = peer[\"psk_key\"], Data(base64Encoded: psk)?.count != 32 { return nil }\n", "", "plan", "a malformed preshared key is accepted"),
    ("xc-09", IOS + "TribeWatchPlan.swift", "            guard text.count <= Self.maxValueLength,", "            guard true,", "plan", "a value of any length is accepted"),
    ("xc-10", IOS + "TribeWatchPlan.swift", "        for key in Self.interfaceKeys + Self.peerKeys {\n            guard let value = fields[key] else { continue }", "        for key in fields.keys.sorted() {\n            guard let value = fields[key] else { continue }", "plan", "keys outside the node's own are taken into the configuration"),
    ("xc-11", IOS + "TribeWatchPlan.swift", "host.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == \".\" || $0 == \"-\" || $0 == \":\") }),", "true,", "plan", "anything is accepted as a host"),
    ("xc-12", IOS + "TribeWatchPlan.swift", "        guard let plan, plan.policy.enabled, plan.policy.switchEnabled, !plan.candidates.isEmpty else {", "        guard let plan, plan.policy.enabled, !plan.candidates.isEmpty else {", "plan", "a start by the system chooses a node with the switch key off"),
    ("xc-13", IOS + "TribeWatchPlan.swift", "failures.contains { $0.nodeId == node && $0.net == net && fresh($0, nowMs: nowMs) }", "failures.contains { $0.nodeId == node && fresh($0, nowMs: nowMs) }", "plan", "a failure on another network moves the start"),
    ("xc-14", IOS + "TribeWatchPlan.swift", "nowMs >= failure.wallMs && nowMs - failure.wallMs <= failureMemoryMs", "nowMs >= failure.wallMs", "plan", "an old failure is remembered for ever"),
    ("xc-14b", IOS + "TribeWatchPlan.swift", "failures.contains { $0.nodeId == node && $0.net == net && fresh($0, nowMs: nowMs) }", "failures.contains { $0.nodeId == node && $0.net == net }", "plan", "(the list handed in holds fresh records only) an aged record still moves the start"),
    ("xc-15", IOS + "TribeWatchPlan.swift", "nowMs >= failure.wallMs && nowMs - failure.wallMs <= failureMemoryMs", "nowMs - failure.wallMs <= failureMemoryMs", "plan", "a failure from the future is believed"),
    ("xs-01", IOS + "TribeWatchPlan.swift", "static func startedBySystem(source: String?) -> Bool { source == nil }", "static func startedBySystem(source: String?) -> Bool { true }", "plan", "second review R1: every start is a start by the system"),
    ("xs-02", IOS + "TribeWatchPlan.swift", "static func startedBySystem(source: String?) -> Bool { source == nil }", "static func startedBySystem(source: String?) -> Bool { source != \"app\" }", "plan", "a start by an intent or by an unknown source chooses a node itself"),
    ("xd-01", IOS + "TribeWatchPlan.swift", "fresh($0, nowMs: nowMs) && !($0.nodeId == failure.nodeId && $0.net == failure.net) }", "fresh($0, nowMs: nowMs) }", "plan", "a node judged twice takes two of the eight records"),
    ("xd-02", IOS + "TribeWatchPlan.swift", "var kept = failures.filter { fresh($0, nowMs: nowMs) && ", "var kept = failures.filter { ", "plan", "aged records are carried along for ever"),
    ("xd-03", IOS + "TribeWatchPlan.swift", "        return Array(kept.suffix(maxFailuresKept))\n", "        return kept\n", "plan", "the list of dead nodes grows without a bound"),
    ("xd-04", IOS + "TribeWatchPlan.swift", "        return Array(kept.suffix(maxFailuresKept))\n", "        return Array(kept.prefix(maxFailuresKept))\n", "plan", "the newest record is the one dropped"),
    ("xd-05", IOS + "TribeWatchPlan.swift", "        return out.filter { fresh($0, nowMs: nowMs) }\n", "        return out\n", "plan", "a record that aged in the file is read as fresh"),
    ("xd-06", IOS + "TribeWatchPlan.swift", "for raw in (state[\"dead\"] as? [Any] ?? []).prefix(maxFailuresKept * 2) {", "for raw in [Any]() {", "plan", "second review R6: the dead nodes of the previous run are not read"),
    ("xd-08", IOS + "TribeWatchPlan.swift", "failures.map { [\"node_id\": $0.nodeId, \"net\": $0.net, \"at_ms\": $0.wallMs] }", "failures.map { [\"node_id\": $0.nodeId, \"net\": $0.net, \"at_ms\": $0.wallMs / 1000] }", "plan", "the records are written in seconds and read in milliseconds"),
    ("xc-16", IOS + "TribeWatchPlan.swift", "        if !plan.pinNodeId.isEmpty, known.contains(plan.pinNodeId) { order.append((plan.pinNodeId, \"pin\")) }\n", "", "plan", "the pin does not come first at a start by the system"),
    ("xc-17", IOS + "TribeWatchPlan.swift", "        if let remembered = plan.memory[net], known.contains(remembered) { order.append((remembered, \"memory\")) }\n", "", "plan", "the app's memory of the network is not used"),
    ("xc-18", IOS + "TribeWatchPlan.swift", "if !plan.pinNodeId.isEmpty, known.contains(plan.pinNodeId) {", "if !plan.pinNodeId.isEmpty {", "plan", "a pin the extension cannot raise is chosen"),
    ("xc-19", IOS + "TribeWatchPlan.swift", "        for (node, why) in order where !failed(node) { return (node, why) }", "        for (node, why) in order { return (node, why) }", "plan", "a node proven dead on this network is started again"),
    ("xc-20", IOS + "TribeWatchPlan.swift", "state[\"verdict\"] as? String == TribeDataVerdict.noData.rawValue,", "state[\"verdict\"] != nil,", "plan", "any last verdict counts as a failure"),
    ("xc-21", IOS + "TribeWatchPlan.swift", "            if let value = peer[key] { lines.append(\"\\(key) = \\(value)\") }", "            lines.append(\"\\(key) = \\(peer[key] ?? \"\")\")", "plan", "absent keys leave empty lines in the configuration"),
    ("xc-22", IOS + "TribeWatchPlan.swift", "        lines.append(\"AllowedIPs = \\(base.allowedIPs)\")\n", "", "plan", "the switch text has no routed ranges"),
    # ---- stage 2, the extension runtime ----
    ("rt-19", IOS + "TribeDataWatchRuntime.swift", "        writeState(snapshot.asDictionary, net: net, deps: deps)\n    }\n\n    /// The journal of a command", "    }\n\n    /// The journal of a command", "rt", "the shared file is never written on a report"),
    ("rs-01", IOS + "TribeDataWatchRuntime.swift", "guard policy.enabled, policy.switchEnabled, switchBase != nil, let plan else { return [] }", "guard policy.enabled, switchBase != nil, let plan else { return [] }", "rt", "candidates are offered with the switch key off"),
    ("rs-02", IOS + "TribeDataWatchRuntime.swift", "guard policy.enabled, policy.switchEnabled, switchBase != nil, let plan else { return [] }", "guard policy.enabled, policy.switchEnabled, let plan else { return [] }", "rt", "candidates are offered for a session that cannot be rebuilt"),
    ("rs-03", IOS + "TribeDataWatchRuntime.swift", "        if nodeId != homeNodeId && !ids.contains(homeNodeId) { ids.append(homeNodeId) }\n", "", "rt", "there is no way back to the profile's node"),
    ("rs-04", IOS + "TribeDataWatchRuntime.swift", "var ids = plan.candidates.map { $0.nodeId }.filter { $0 != nodeId && !rejected.contains($0) }", "var ids = plan.candidates.map { $0.nodeId }.filter { !rejected.contains($0) }", "rt", "the node the tunnel is on is offered"),
    ("rj-01", IOS + "TribeDataWatchRuntime.swift", "var ids = plan.candidates.map { $0.nodeId }.filter { $0 != nodeId && !rejected.contains($0) }", "var ids = plan.candidates.map { $0.nodeId }.filter { $0 != nodeId }", "rt", "second review R5: a candidate whose configuration was rejected is offered again"),
    ("rj-02", IOS + "TribeDataWatchRuntime.swift", "        lock.lock()\n        rejected.insert(node)\n        lock.unlock()", "        lock.lock()\n        lock.unlock()", "rt", "a candidate the provider could not build is offered again"),
    ("rj-03", IOS + "TribeDataWatchRuntime.swift", "        if case .switchPeer(let to, _) = command, result == .rejected { rejected.insert(to) }\n", "", "rt", "a candidate the engine rejected is offered again"),
    ("rj-04", IOS + "TribeDataWatchRuntime.swift", "                planEpoch += 1\n                rejected = []\n", "                planEpoch += 1\n", "rt", "a rejected candidate stays rejected under a new plan"),
    ("rj-05", IOS + "TribeDataWatchRuntime.swift", "                planEpoch += 1\n                rejected = []\n", "                rejected = []\n", "rt", "a new plan is not told to the rule (the long pause is waited out)"),
    ("rj-06", IOS + "TribeDataWatchRuntime.swift", "            if plan.order != lastOrder {\n", "            if true {\n", "rt", "every re-read of the same plan counts as a new plan"),
    ("dd-01", IOS + "TribeDataWatchRuntime.swift", "        if output.verdict == .noData {\n            dead = TribeStartChoice.noting(", "        if false {\n            dead = TribeStartChoice.noting(", "rt", "a node judged dead is not remembered"),
    ("dd-02", IOS + "TribeDataWatchRuntime.swift", "        if case .switchPeer(_, .noData) = command, result != .denied {\n", "        if false {\n", "rt", "(the verdict's report noted it already; only the time is refreshed) the node being left is not noted again"),
    ("dd-03", IOS + "TribeDataWatchRuntime.swift", "        state[\"dead\"] = TribeStartChoice.encode(dead)\n", "", "rt", "second review R6: the dead nodes are lost at a rewrite of the state file"),
    ("dd-04", IOS + "TribeDataWatchRuntime.swift", "        state[\"engine\"] = engineDown ? \"down\" : \"up\"\n", "", "rt", "the state file does not say whether an engine runs"),
    ("dd-05", IOS + "TribeDataWatchRuntime.swift", "        state[\"switch_seq\"] = switchSeq\n        state[\"switches\"] = switches\n", "", "rt", "the state file loses the switches of the run"),
    ("dd-06", IOS + "TribeDataWatchRuntime.swift", "        guard !deadLoaded else { return }\n", "", "rt", "the previous run's file overwrites what this run has learned"),
    ("dd-07", IOS + "TribeDataWatchRuntime.swift", "            if next.switchEnabled { loadDeadLocked(deps) }\n", "            loadDeadLocked(deps)\n", "rt", "second review R8: with the switch key off the state file is read"),
    ("dd-08", IOS + "TribeDataWatchRuntime.swift", "            if next.switchEnabled { loadDeadLocked(deps) }\n", "", "rt", "the previous run's dead nodes are known only at a start by the system"),
    ("sb-01", IOS + "TribeDataWatchRuntime.swift", "guard TribeStartChoice.startedBySystem(source: source), let deps = currentDeps else { return nil }", "guard let deps = currentDeps else { return nil }", "rt", "second review R1 / rev2-G12: a start by the app may also choose another node"),
    ("sb-02", IOS + "TribeDataWatchRuntime.swift", "        guard policy.enabled, policy.switchEnabled, let base = switchBase, let plan, !plan.candidates.isEmpty else {\n            lock.unlock()\n            return nil\n        }", "        guard let base = switchBase, let plan, !plan.candidates.isEmpty else {\n            lock.unlock()\n            return nil\n        }", "rt", "(candidates are parsed only with both keys on: xl-02) the start choice does not ask the keys itself"),
    ("sb-03", IOS + "TribeDataWatchRuntime.swift", "        let choice = TribeStartChoice.choose(profileNodeId: home, plan: plan, net: net, failures: dead, nowMs: deps.nowMs())\n        guard choice.nodeId != home,", "        let choice = TribeStartChoice.choose(profileNodeId: home, plan: plan, net: net, failures: [], nowMs: deps.nowMs())\n        guard choice.nodeId != home,", "rt", "a start by the system raises a node judged dead on this network"),
    ("sc-01", IOS + "TribeDataWatchRuntime.swift", "if plan.holdsUnusableSecrets, !alive, let stamp, let data, scrubbedStampIs(not: stamp) {", "if plan.holdsUnusableSecrets, let stamp, let data, scrubbedStampIs(not: stamp) {", "rt", "second review R7: the extension rewrites the plan while the app is alive"),
    ("sc-02", IOS + "TribeDataWatchRuntime.swift", "if plan.holdsUnusableSecrets, !alive, let stamp, let data, scrubbedStampIs(not: stamp) {", "if !alive, let stamp, let data, scrubbedStampIs(not: stamp) {", "rt", "a plan that may switch loses its candidates"),
    ("sc-03", IOS + "TribeDataWatchRuntime.swift", "if plan.holdsUnusableSecrets, !alive, let stamp, let data, scrubbedStampIs(not: stamp) {", "if plan.holdsUnusableSecrets, !alive, let stamp, let data {", "rt", "a rewrite that failed is tried again on every tick"),
    ("sc-04", IOS + "TribeDataWatchRuntime.swift", "        guard let clean = TribeWatchPlan.scrubbed(data) else { return }\n", "        let clean = data\n", "rt", "the plan is rewritten as it was, keys included"),
    ("en-01", IOS + "TribeDataWatchRuntime.swift", "        let changed = engineDown != down\n        engineDown = down\n", "        let changed = engineDown != down\n", "rt", "second review R5: the runtime never learns that the engine is down"),
    ("en-02", IOS + "TribeDataWatchRuntime.swift", "        guard changed else { return }\n        deps.log(TribeDataWatchJournal.engineLine(", "        deps.log(TribeDataWatchJournal.engineLine(", "rt", "the same engine state is journaled again and again"),
    ("en-03", IOS + "TribeDataWatchRuntime.swift", "        writeState([\"enabled\": true, \"verdict\": verdict.rawValue], net: deps.uplinkKind(), deps: deps)\n    }\n\n    /// For the status reply: no engine runs", "    }\n\n    /// For the status reply: no engine runs", "rt", "the state file does not say that the engine went down"),
    ("en-04", IOS + "TribeDataWatchRuntime.swift", "        adapter.dataWatchEngineHandler = { [weak self] down in self?.noteEngine(down: down) }\n", "", "rt", "the adapter's word about its engine reaches nobody"),
    ("en-05", IOS + "TribeDataWatchRuntime.swift", "        return engineDown\n    }\n\n    // MARK: - The app", "        return false\n    }\n\n    // MARK: - The app", "rt", "the status reply of a tunnel without an engine does not say so"),
    ("nc-01", IOS + "TribeDataWatchRuntime.swift", "let choosing = !current.candidates.isEmpty ? (plan, homeNodeId, dead) : nil", "let choosing = !current.candidates.isEmpty ? (plan, homeNodeId, [TribeStartChoice.LastFailure]()) : nil", "rt", "second review R4: at a change of network a node judged dead on that network is chosen"),
    ("nc-02", IOS + "TribeDataWatchRuntime.swift", "        current.planEpoch = planEpoch\n", "", "rt", "the rule is not told that the app wrote a new plan"),
    ("nc-03", IOS + "TribeDataWatchRuntime.swift", "let choosing = !current.candidates.isEmpty ? (plan, homeNodeId, dead) : nil", "let choosing: (TribeWatchPlan?, String, [TribeStartChoice.LastFailure])? = nil", "rt", "the rule is never told where a start on this network would go"),
    ("sw-02", IOS + "TribeDataWatchRuntime.swift", "guard let endpoint = actualEndpoint else { return (switchSeq, why, nil, nil) }", "guard let endpoint = actualEndpoint else { return nil }", "rt", "second review R3: back on the profile's node the reply no longer carries the switch number (the app never adopts the way back)"),
    ("rs-05", IOS + "TribeDataWatchRuntime.swift", "        guard offeredLocked().contains(node), let base = switchBase else { return nil }", "        guard let base = switchBase else { return nil }", "rt", "a node that was not offered gets a configuration"),
    ("rs-06", IOS + "TribeDataWatchRuntime.swift", "if case .switchPeer(let to, let why) = command, result == .performed {", "if case .switchPeer(let to, let why) = command {", "rt", "a switch that failed changes the session's identity"),
    ("rs-07", IOS + "TribeDataWatchRuntime.swift", "ndpoint : nil\n            switchSeq += 1\n", "ndpoint : nil\n", "rt", "the switch number does not grow"),
    ("rs-08", IOS + "TribeDataWatchRuntime.swift", "            if switches.count > Self.maxSwitchesKept { switches.removeFirst(switches.count - Self.maxSwitchesKept) }\n", "", "rt", "the list of switches grows without a bound"),
    ("rs-09", IOS + "TribeDataWatchRuntime.swift", "        if let command = output.command, let result = output.commandResult {\n", "        if false, let command = output.command, let result = output.commandResult {\n", "rt", "executed commands are neither journaled nor reflected in the identity"),
    ("rs-10", IOS + "TribeDataWatchRuntime.swift", "        if output.exhausted {\n", "        if false {\n", "rt", "exhausted is not journaled"),
    ("rs-11", IOS + "TribeDataWatchRuntime.swift", "            block[\"switch_seq\"] = made.0\n", "            block[\"switch_seq\"] = 0\n", "rt", "the status reply does not carry the switch number"),
    ("rs-17", IOS + "TribeDataWatchRuntime.swift", "            actualEndpoint = handedOut?.node == to ? handedOut?.endpoint : nil\n", "", "rt", "the status reply names the profile's endpoint after a switch"),
    ("rs-19", IOS + "TribeDataWatchRuntime.swift", "actualEndpoint = handedOut?.node == to ? handedOut?.endpoint : nil", "actualEndpoint = handedOut?.endpoint", "rt", "back on the profile's node the reply still names another node's endpoint"),
    ("rs-18", IOS + "TribeDataWatchRuntime.swift", "        handedOut = (node, candidate.endpoint)\n", "", "rt", "the endpoint of the node switched to is not remembered"),
    ("rs-20", IOS + "TribeDataWatchRuntime.swift", "        nodeId = choice.nodeId\n        actualEndpoint = candidate.endpoint\n", "        nodeId = choice.nodeId\n", "rt", "a start by the system on another node keeps the profile's identity"),
    ("rs-13", IOS + "TribeDataWatchRuntime.swift", "        actualEndpoint = candidate.endpoint\n        switchSeq = 1\n", "        actualEndpoint = candidate.endpoint\n", "rt", "a start by the system on another node is not told as a switch"),
    ("rs-14", IOS + "TribeDataWatchRuntime.swift", "        guard switched else { return }\n", "        guard switched, false else { return }\n", "rt", "the shared file keeps the node the tunnel has left"),
    ("rs-15", IOS + "TribeDataWatchRuntime.swift", "        nodeId = homeNodeId\n        actualEndpoint = nil\n        switchSeq = 0\n        switches = []\n        lock.unlock()\n        currentDeps?.log(", "        lock.unlock()\n        currentDeps?.log(", "rt", "a dropped start choice still names the other node"),
    ("rs-16", IOS + "TribeDataWatchRuntime.swift", "        self.homeNodeId = nodeId\n        self.switchBase = base\n        self.plan = nil\n        self.switchSeq = 0\n        self.switches = []\n", "        self.homeNodeId = nodeId\n        self.switchBase = base\n        self.plan = nil\n", "rt", "(a new process starts from zero anyway) the switches of the previous session are kept"),
    # ---- second review, R3: adoption on any reply, and whose node is it until a reply came ----
    ("r3-01", ENG + "TunnelWatchResume.h", "if (!held(site, lastTickMs, tickPeriodMs) && !replyAwaited())", "if (!held(site, lastTickMs, tickPeriodMs))", "watch", "a data check attributes its result to a node before any reply said where the tunnel stands"),
    ("r3-02", ENG + "TunnelWatchResume.h", "        begin(QStringLiteral(\"reasserted\"), /*connectedNow=*/true); // begin() refuses", "        // begin() refuses", "watch", "a Reasserting -> Connected begins no hand-over"),
    ("t2-01", ENG + "TunnelWatchResume.h", "connectedNow || m_ops.tunnelConnected()))", "m_ops.tunnelConnected()))", "watch", "third review T2: the Reasserting hook asks the facade's cached tunnel state, which still says Connecting (the state of cdc7861ba)"),
    ("r3-03", ENG + "TunnelWatchResume.h", "        adoptPending();\n        if (!m_freeze.active) {", "        if (!m_freeze.active) {", "watch", "a switch seen in the background is never adopted on the screen"),
    ("r3-04", ENG + "TunnelWatchResume.h", "                if (m_replyAskedMs >= 0 && !replyAwaited()) {", "                if (false) {", "watch", "the wait for a reply that never comes has no end"),
    ("r3-05", ENG + "TunnelWatchResume.h", "                    m_replyAskedMs = -1;\n                    m_ops.journal(QStringLiteral(\"watch_identity_wait released=timeout", "                    m_ops.journal(QStringLiteral(\"watch_identity_wait released=timeout", "watch", "the wait is given up in the journal and goes on in fact"),
    ("r3-06", ENG + "TunnelWatchResume.h", "&& m_ops.engineVerifying())\n            m_ops.startVerification();\n    }\n\n    // The reply to the snapshot request", "&& m_ops.engineVerifying()) {\n        }\n    }\n\n    // The reply to the snapshot request", "watch", "a node adopted from an ordinary poll is not checked by the app"),
    ("r3-07", ENG + "TunnelWatchResume.h", "        m_replyAskedMs = -1; // a status reply asked after the resume has been processed\n", "", "watch", "the reply came and later data checks still wait for it"),
    ("r3-08", ENG + "TunnelWatchResume.h", "            if (adopted && m_ops.engineVerifying())\n                m_ops.startVerification();\n            if (awaited)", "            if (awaited)", "watch", "a node adopted from a late reply is not checked by the app"),
    ("r3-09", ENG + "TunnelWatchResume.h", ".arg(m_deferred.size()));\n            runDeferred();\n            return;\n        }\n        if (!freezeReleases(step))", ".arg(m_deferred.size()));\n            return;\n        }\n        if (!freezeReleases(step))", "watch", "the data checks that waited for the reply never run"),
    ("r3-10", ENG + "TunnelWatchResume.h", "        if (m_ops.backgroundArmOnly()) {\n            m_pendingSession = session;", "        if (false) {\n            m_pendingSession = session;", "watch", "rev2-G10: a switch is adopted while the app is only holding background time"),
    ("r3-11", ENG + "TunnelWatchResume.h", "            m_pendingSession.insert(QStringLiteral(\"switch_seq\"), ai.switchSeq);\n", "", "watch", "a switch told only in the watch block is lost while it waits for the screen"),
    ("r3-12", ENG + "TunnelWatchResume.h", "        if (ai.switchSeq > 0)\n            m_pendingSession.clear(); // a newer word", "        if (false)\n            m_pendingSession.clear(); // a newer word", "watch", "a switch that waited for the screen is replayed although the extension has moved on"),
    ("r3-14", ENG + "TunnelWatchResume.h", "        const bool adopted = adopt(session, w.switchSeq,", "        const bool adopted = adopt(session, 0,", "watch", "the switch number of the watch block is not passed on"),
    ("idw-01", ENG + "TunnelWatchStatus.h", "return askedMs >= 0 && nowMs >= askedMs && nowMs - askedMs < kIdentityWaitFactor * timeoutMs;", "return nowMs >= askedMs && nowMs - askedMs < kIdentityWaitFactor * timeoutMs;", "watch", "nobody was asked and the checks wait"),
    ("idw-02", ENG + "TunnelWatchStatus.h", "return askedMs >= 0 && nowMs >= askedMs && nowMs - askedMs < kIdentityWaitFactor * timeoutMs;", "return askedMs >= 0 && nowMs - askedMs < kIdentityWaitFactor * timeoutMs;", "watch", "a clock set back makes the wait endless"),
    ("idw-03", ENG + "TunnelWatchStatus.h", "return askedMs >= 0 && nowMs >= askedMs && nowMs - askedMs < kIdentityWaitFactor * timeoutMs;", "return askedMs >= 0 && nowMs >= askedMs && nowMs - askedMs <= kIdentityWaitFactor * timeoutMs;", "watch", "boundary of the wait for the reply"),
    ("idw-04", ENG + "TunnelWatchStatus.h", "constexpr int kIdentityWaitFactor = 4;", "constexpr int kIdentityWaitFactor = 40;", "watch", "the wait for a reply is two minutes"),
    ("idw-05", ENG + "TunnelWatchResume.h", "        return m_ops.watchFlag() && m_ops.tunnelConnected()\n            && identityReplyAwaited(", "        return m_ops.tunnelConnected()\n            && identityReplyAwaited(", "watch", "with the flag gone off the data checks still wait for a reply"),
    ("idw-06", ENG + "TunnelWatchResume.h", "        return m_ops.watchFlag() && m_ops.tunnelConnected()\n            && identityReplyAwaited(", "        return m_ops.watchFlag()\n            && identityReplyAwaited(", "watch", "without a tunnel the data checks still wait for a reply"),
    # ---- second review, R4: evidence per network instead of 'failed for the session', the way back ----
    ("ev-01", ENG + "TunnelWatchStatus.h", "static bool alive(const Entry &e, qint64 nowMs) { return nowMs >= e.atMs && nowMs - e.atMs < kWatchEvidenceTtlMs; }", "static bool alive(const Entry &e, qint64 nowMs) { return nowMs - e.atMs < kWatchEvidenceTtlMs; }", "watch", "a clock set back makes old evidence fresh"),
    ("ev-02", ENG + "TunnelWatchStatus.h", "static bool alive(const Entry &e, qint64 nowMs) { return nowMs >= e.atMs && nowMs - e.atMs < kWatchEvidenceTtlMs; }", "static bool alive(const Entry &e, qint64 nowMs) { return nowMs >= e.atMs; }", "watch", "the evidence never ages"),
    ("ev-03", ENG + "TunnelWatchStatus.h", "static bool alive(const Entry &e, qint64 nowMs) { return nowMs >= e.atMs && nowMs - e.atMs < kWatchEvidenceTtlMs; }", "static bool alive(const Entry &e, qint64 nowMs) { return nowMs >= e.atMs && nowMs - e.atMs <= kWatchEvidenceTtlMs; }", "watch", "boundary of the half hour"),
    ("ev-04", ENG + "TunnelWatchStatus.h", "constexpr qint64 kWatchEvidenceTtlMs = 30 * 60 * 1000;", "constexpr qint64 kWatchEvidenceTtlMs = 60 * 60 * 1000;", "watch", "the evidence is kept longer than the extension keeps its own"),
    ("ev-05", ENG + "TunnelWatchStatus.h", "if (e.nodeId == nodeId && e.netKey == netKey && alive(e, nowMs))", "if (e.nodeId == nodeId && alive(e, nowMs))", "watch", "evidence of one network holds on another"),
    ("ev-06", ENG + "TunnelWatchStatus.h", "if (e.nodeId == nodeId && e.netKey == netKey && alive(e, nowMs))", "if (e.nodeId == nodeId && e.netKey == netKey)", "watch", "aged evidence still holds"),
    ("ev-07", ENG + "TunnelWatchStatus.h", "if (e.nodeId == nodeId && e.netKey == netKey && alive(e, nowMs))", "if (e.netKey == netKey && alive(e, nowMs))", "watch", "evidence against one node holds against every node"),
    ("ev-08", ENG + "TunnelWatchStatus.h", "            if (e.netKey == netKey && alive(e, nowMs))\n                out.insert(e.nodeId);", "            if (alive(e, nowMs))\n                out.insert(e.nodeId);", "watch", "the picks skip nodes judged on another network"),
    ("ev-09", ENG + "TunnelWatchStatus.h", "            if (e.netKey == netKey && alive(e, nowMs))\n                out.insert(e.nodeId);", "            if (e.netKey == netKey)\n                out.insert(e.nodeId);", "watch", "the picks skip nodes whose evidence has aged"),
    ("ev-10", ENG + "TunnelWatchStatus.h", "        if (nodeId.isEmpty())\n            return;\n        prune(nowMs);", "        prune(nowMs);", "watch", "evidence against no node is kept"),
    ("ev-11", ENG + "TunnelWatchStatus.h", "            return;\n        prune(nowMs);\n", "            return;\n", "watch", "aged records are never dropped"),
    ("ev-12", ENG + "TunnelWatchStatus.h", "            if (m_entries.at(i).nodeId == nodeId && m_entries.at(i).netKey == netKey)\n                m_entries.removeAt(i);", "            if (false)\n                m_entries.removeAt(i);", "watch", "a node judged twice takes two records"),
    ("ev-13", ENG + "TunnelWatchStatus.h", "        while (m_entries.size() > kWatchEvidenceMax)\n            m_entries.removeFirst();", "        while (m_entries.size() > kWatchEvidenceMax)\n            m_entries.removeLast();", "watch", "the newest evidence is the one dropped"),
    ("ev-14", ENG + "TunnelWatchStatus.h", "        while (m_entries.size() > kWatchEvidenceMax)\n            m_entries.removeFirst();\n", "", "watch", "the evidence list grows without a bound"),
    ("ev-15", ENG + "TunnelWatchStatus.h", "            if (m_entries.at(i).nodeId == nodeId && m_entries.at(i).netKey == netKey)\n                m_entries.removeAt(i);", "            if (m_entries.at(i).nodeId == nodeId)\n                m_entries.removeAt(i);", "watch", "evidence on a second network erases the first network's"),
    ("ret-01", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "watch", "the way back is taken by a session nobody moved"),
    ("ret-02", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.movedByExtension && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "watch", "the way back to a location that cannot be raised"),
    ("ret-03", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.movedByExtension && in.pinRaisable && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "watch", "the way back while the extension's evidence is fresh"),
    ("ret-04", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh\n        && in.engineConnected && in.wantConnected && !in.busy;", "watch", "the way back without a data check of the app's own"),
    ("ret-05", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.wantConnected && !in.busy;", "watch", "the way back while the engine is verifying or switching"),
    ("ret-06", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && !in.busy;", "watch", "the way back for a session the user switched off"),
    ("ret-07", ENG + "TunnelWatchStatus.h", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected && !in.busy;", "return in.movedByExtension && in.pinRaisable && !in.evidenceFresh && in.nodeScanOn\n        && in.engineConnected && in.wantConnected;", "watch", "the way back on top of an operation in flight"),
    ("r4-01", ENG + "TunnelWatchResume.h", "if (consume != WatchConsume::Reverify && decideExtensionReturn(m_ops.returnFacts())) {", "if (decideExtensionReturn(m_ops.returnFacts())) {", "watch", "a verdict about this session and a way back share a hand-over"),
    ("r4-02", ENG + "TunnelWatchResume.h", "if (consume != WatchConsume::Reverify && decideExtensionReturn(m_ops.returnFacts())) {", "if (false) {", "watch", "the session never goes back to the user's choice"),
    ("r4-03", ENG + "TunnelWatchResume.h", "            m_ops.restartToChoice();\n", "", "watch", "the way back is journaled and not taken"),
    # ---- second review, R5: the tunnel has no engine; Reasserting ----
    ("ed-01", ENG + "TunnelWatchStatus.h", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "return !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "watch", "a session the user switched off is restarted"),
    ("ed-02", ENG + "TunnelWatchStatus.h", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "return in.wantConnected && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "watch", "a restart is asked on every reply"),
    ("ed-03", ENG + "TunnelWatchStatus.h", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "return in.wantConnected && !in.restartPending && !in.paused && in.foreground && in.tunnelConnected;", "watch", "a restart on top of an operation in flight"),
    ("ed-04", ENG + "TunnelWatchStatus.h", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "return in.wantConnected && !in.restartPending && !in.opInFlight && in.foreground && in.tunnelConnected;", "watch", "a paused session is restarted"),
    ("ed-05", ENG + "TunnelWatchStatus.h", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.tunnelConnected;", "watch", "a restart from the background (iOS cuts it half-way)"),
    ("ed-06", ENG + "TunnelWatchStatus.h", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground && in.tunnelConnected;", "return in.wantConnected && !in.restartPending && !in.opInFlight && !in.paused && in.foreground;", "watch", "a restart of a tunnel that is not Connected"),
    ("rea-01", ENG + "TunnelWatchStatus.h", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "return wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "watch", "any state after Connecting is a Reasserting"),
    ("rea-02", ENG + "TunnelWatchStatus.h", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "return nowConnected && true\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "watch", "every Connected is a Reasserting"),
    ("rea-03", ENG + "TunnelWatchStatus.h", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"verifying\"));", "watch", "a Reasserting of a connected session is not seen"),
    ("rea-04", ENG + "TunnelWatchStatus.h", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\"));", "watch", "a Reasserting during the app's check is not seen"),
    ("rea-05", ENG + "TunnelWatchStatus.h", "return nowConnected && wasConnecting\n        && (engineStateBefore == QLatin1String(\"connected\") || engineStateBefore == QLatin1String(\"verifying\"));", "return nowConnected && wasConnecting;", "watch", "a start or a switch of the app's own is taken for a Reasserting"),
    # ---- second review, R7: the switch lease; R6: the ceiling ----
    ("lease-01", ENG + "TunnelWatchPlan.h", "double(switching ? in.nowMs + leaseMin * 60LL * 1000LL : 0)", "double(in.nowMs + leaseMin * 60LL * 1000LL)", "watch", "a lease is written with the switch key off"),
    ("lease-02", ENG + "TunnelWatchPlan.h", "double(switching ? in.nowMs + leaseMin * 60LL * 1000LL : 0)", "double(switching ? in.nowMs + leaseMin * 1000LL : 0)", "watch", "the lease in the wrong unit"),
    ("lease-03", ENG + "TunnelWatchPlan.h", "const bool switching = in.watch && in.watchSwitch;", "const bool switching = in.watchSwitch;", "watch", "a lease is written with the watch off"),
    ("lease-04", ENG + "TunnelWatchPlan.h", "const bool switching = in.watch && in.watchSwitch;", "const bool switching = in.watch;", "watch", "a lease is written with only the watch on"),
    ("tun-09", ENG + "ConnectTunables.h", "{\"ios_tw_switch_lease_min\",             360,       10,        1440, true}", "{\"ios_tw_switch_lease_min\",             360,        0,        1440, true}", "watch", "the lease may be set to nothing by a typo"),
    ("tun-10", ENG + "ConnectTunables.h", "{\"ios_tw_switch_lease_min\",             360,       10,        1440, true}", "{\"ios_tw_switch_lease_min\",             360,       10,       14400, true}", "watch", "the lease may be ten days"),
    ("tun-11", ENG + "ConnectTunables.h", "{\"ios_tw_switch_max_per_hour\",            6,        1,          30, true}", "{\"ios_tw_switch_max_per_hour\",            6,        1,        3000, true}", "watch", "the ceiling of switches can be lifted by a typo"),
    # ---- second review: the controller ----
    ("ctl-08", IOS + "ios_controller.mm", "                emit tunnelEngineDown();\n                return; // no counters", "                return; // no counters", "harness", "second review R5: a reply without an engine is not told to the app"),
    ("ctl-09", IOS + "ios_controller.mm", "                emit tunnelEngineDown();\n                return; // no counters in this reply: nothing below may judge a handshake by it\n", "                emit tunnelEngineDown();\n", "harness", "a reply without counters is judged as a handshake timeout"),
    ("ctl-10", IOS + "ios_controller.mm", "const bool engineDown = [response[@\"engine_down\"] respondsToSelector:@selector(boolValue)] && [response[@\"engine_down\"] boolValue];", "const bool engineDown = response[@\"engine_down\"] != nil;", "harness", "any value of engine_down is the truth"),
    ("ctl-11", IOS + "ios_controller.mm", "    [url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];\n", "", "harness", "second review R7: the plan with the nodes' keys goes into device backups"),
    # ---- third review, T1 and T3: a verdict that was taken back, a late answer to the previous probe ----
    ("t1-01", IOS + "TribeDataWatchRuntime.swift", "        } else if report == .refuted || report == .trial || output.verdict == .recovered {\n            dead.removeAll { $0.nodeId == nodeId && $0.net == net }\n        }", "        }", "rt", "third review T1: a node stays dead for half an hour after its verdict was refuted (the state of cdc7861ba)"),
    ("t1-02", IOS + "TribeDataWatchRuntime.swift", "} else if report == .refuted || report == .trial || output.verdict == .recovered {", "} else if report == .trial || output.verdict == .recovered {", "rt", "a refutation leaves the record"),
    ("t1-03", IOS + "TribeDataWatchRuntime.swift", "} else if report == .refuted || report == .trial || output.verdict == .recovered {", "} else if report == .refuted || output.verdict == .recovered {", "rt", "an answered trial leaves the record"),
    ("t1-04", IOS + "TribeDataWatchRuntime.swift", "} else if report == .refuted || report == .trial || output.verdict == .recovered {", "} else if report == .refuted || report == .trial {", "rt", "returned data leave the record"),
    ("t1-05", IOS + "TribeDataWatchRuntime.swift", "dead.removeAll { $0.nodeId == nodeId && $0.net == net }", "dead.removeAll()", "rt", "a refutation forgets every dead node, not the one it is about"),
    ("t3-11", IOS + "TribeDataWatchRuntime.swift", "previousLateWatch = lateWatch.flatMap { $0.until > now && $0.id != id ? $0 : nil }", "previousLateWatch = nil", "rt", "third review T3: the previous probe's late answer is not listened for once the next probe started (the state of cdc7861ba)"),
    ("t3-12", IOS + "TribeDataWatchRuntime.swift", "                } else if result.latePrevious == previous.id {\n                    previousLateWatch = nil\n                    inputs.lateAnswerAt = now\n                }\n            }\n            if state != .pending, probeInFlight == flying {", "                }\n            }\n            if state != .pending, probeInFlight == flying {", "rt", "the late answer told with the flying probe's result is ignored"),
    ("t3-13", IOS + "TribeDataWatchRuntime.swift", "                if now > previous.until || result.id != flying {\n                    previousLateWatch = nil\n", "                if now > previous.until {\n                    previousLateWatch = nil\n", "rt", "a result line of another probe credits the previous one"),
    ("t3-14", IOS + "TribeWatchPlan.swift", "            case \"prev_late\": latePrevious = Int32(pair[1]) ?? 0\n", "", "plan", "the previous probe's late answer is not read from the result line"),
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
    ("w-e1a", PATCH, "+        if self.dataWatchTick(sample, handle: handle, settingsGenerator: settingsGenerator) { return }\n+        // One owner of recovery while the arbiter treats or leaves a confirmed dead node (never\n+        // with the switch key off): the ladder's steps would spend the budget the switch needs.\n+        if self.dataWatch.arbiterOwnsRecovery { return }\n         let outcome = self.recovery.tick(sample, pathSatisfied: self.lastPathSatisfiable, policy: self.roamingPolicy)\n", "         let outcome = self.recovery.tick(sample, pathSatisfied: self.lastPathSatisfiable, policy: self.roamingPolicy)\n+        if self.dataWatchTick(sample, handle: handle, settingsGenerator: settingsGenerator) { return }\n+        if self.dataWatch.arbiterOwnsRecovery { return }\n", "the watch is fed after the ladder acted on the sample"),
    ("w-e1c", PATCH, "+        if self.dataWatch.arbiterOwnsRecovery { return }\n", "", "second review R6: the ladder steps while the arbiter treats or leaves a node (it spends the budget the switch needs)"),
    ("w-e1b", PATCH, "+    private func dataWatchTick(_ sample: TribeStallSample, handle: Int32, settingsGenerator: PacketTunnelSettingsGenerator) -> Bool {\n", "+    private func dataWatchTick(_ sample: TribeStallSample, handle: Int32, settingsGenerator: PacketTunnelSettingsGenerator) -> Bool {\n+        self.workQueue.asyncAfter(deadline: .now() + 1) { }\n", "the adapter patch grows a delayed block"),
    ("w-s1", PATCH, "+        if self.dataWatchTick(sample, handle: handle, settingsGenerator: settingsGenerator) { return }\n", "+        _ = self.dataWatchTick(sample, handle: handle, settingsGenerator: settingsGenerator)\n", "the stall ladder acts on the tick the watch's arbiter acted on"),
    ("w-s2", PATCH, "+                self.packetTunnelProvider?.reasserting = true\n+                wgTurnOff(handle)\n", "+                self.packetTunnelProvider?.reasserting = true\n", "the old backend still runs while the network settings change (a peer routed into its own tunnel)"),
    ("w-s3", PATCH, "+                newGenerator = try? self.makeSettingsGenerator(with: tunnelConfiguration)\n", "+                wgTurnOff(handle)\n+                newGenerator = try? self.makeSettingsGenerator(with: tunnelConfiguration)\n", "the backend is stopped before the new endpoint is known to resolve"),
    ("w-s4", PATCH, "+            guard let configuration = self.dataWatchCandidate?(nodeId) else { return .rejected }\n", "+            guard let configuration = self.dataWatchCandidate?(nodeId) else { return .performed }\n", "a switch without a configuration is told as performed"),
    ("w-s5", PATCH, "+                return self.applySettingsConfirmed(generator.generateNetworkSettings())\n", "+                try? self.setNetworkSettings(generator.generateNetworkSettings())\n+                return true\n", "second review R5: settings count as applied without the system's confirmation"),
    ("w-s5b", PATCH, "+        guard done, systemError == nil else {\n", "+        guard systemError == nil else {\n", "a call the system never answered counts as applied"),
    ("w-s5c", PATCH, "+        return outcome.result\n", "+        return .performed\n", "second review R5: the adapter tells `performed` whatever the sequence said"),
    ("w-s5d", PATCH, "+            self.dataWatchEngineHandler?(true)\n", "", "a tunnel left without an engine tells nobody"),
    ("w-s5e", PATCH, "+        if self.dataWatchEngineDown != nil { self.dataWatchRetryEngine(); return } // tribe.13, stage 2\n", "", "with no engine the tick leaves on the missing handle and nothing is retried"),
    ("w-s5f", PATCH, "+        if !down.settingsInForce {\n+            down.settingsInForce = self.applySettingsConfirmed(down.generator.generateNetworkSettings())\n+        }\n", "", "the retry starts an engine on settings that are not in force"),
    ("w-s5g", PATCH, "+        guard self.lastPathSatisfiable, down.retry.due(at: now) else { return }\n", "+        guard self.lastPathSatisfiable else { return }\n", "the engine is retried on every tick, without the back-off"),
    ("w-s5h", PATCH, "+            self.state = .temporaryShutdown(oldGenerator)\n", "", "a tunnel without an engine is still marked as started"),
    ("w-s5i", PATCH, "+            guard self.recovery.requestPeerSwitch(sample, pathSatisfied: self.lastPathSatisfiable) == .performed else { return .denied }\n", "", "second review R6: a switch bypasses the shared recovery budget"),
    ("w-s5j", "recipes/awg-apple/tribe/TribeRoaming.swift", "        if let denial = budget.request(at: sample.at, kind: .softRestart, persistent: true) { return .budget(denial) }\n        return .performed\n    }\n}", "        return .performed\n    }\n}", "the switch's request to the budget asks nothing"),
    ("w-s6", PATCH, "+                self.packetTunnelProvider?.reasserting = true\n", "", "the switch is not announced to the system"),
    ("w-s7", IOS + "PacketTunnelProvider+DataWatch.swift", "guard let choice = tribeDataWatch.chooseStart(source: startSource) else { return profile }", "guard let choice = tribeDataWatch.chooseStart(source: nil) else { return profile }", "second review R1: every start is treated as a start by the system"),
    ("w-s7b", IOS + "PacketTunnelProvider.swift", "tribeStartSource = options?[\"tribeStartSource\"] as? String", "tribeStartSource = activationAttemptId == nil ? nil : \"app\"", "second review R1: the start source is guessed from the session id iOS gives to every start"),
    ("w-s7c", IOS + "PacketTunnelProvider+DataWatch.swift", "values.isExcludedFromBackup = true", "values.isExcludedFromBackup = false", "second review R7: the plan the extension rewrote goes into device backups"),
    ("w-s7d", IOS + "PacketTunnelProvider+DataWatch.swift", "options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])", "options: [.atomic])", "the plan the extension rewrote loses its file protection"),
    ("w-s7e", IOS + "TribeDataWatchRuntime.swift", "        guard now == stamp else { return }\n", "", "second review R7: the extension overwrites a plan the app wrote meanwhile"),
    ("w-s7f", IOS + "PacketTunnelProvider+WireGuard.swift", "                completionHandler(self.tribeEngineDownReply())\n", "                completionHandler(nil)\n", "second review R5: a tunnel without an engine answers the status request with nothing"),
    ("w-s8", IOS + "PacketTunnelProvider+WireGuard.swift", "adapter.start(tunnelConfiguration: startConfiguration)", "adapter.start(tunnelConfiguration: tunnelConfiguration)", "the node chosen for a start by the system is not the one raised"),
    ("w-s9", IOS + "PacketTunnelProvider+WireGuard.swift", "                self.tribeApplySessionOverride(&metadata) // AVPN (build 140, data watch stage 2)\n", "", "the status reply names the profile's node after a switch"),
    ("w-s10", IOS + "PacketTunnelProvider+WireGuard.swift", "startSource: tribeStartSource)", "startSource: nil)", "every start is treated as a start by the system"),
    ("w-s11", ENG + "AvpnEngineQml.cpp", "    if (in.watch && in.watchSwitch)\n        in.candidates = m_engine.extensionSwitchCandidates();", "    in.candidates = m_engine.extensionSwitchCandidates();", "candidates are collected with the switch key off"),
    ("w-s12", ENG + "AvpnEngineQml.cpp", "        if (!m_engine.adoptExtensionSwitch(nodeId, featureEnabled(QStringLiteral(\"node_scan\"), false),\n", "        if (!m_engine.adoptExtensionSwitch(nodeId, true,\n", "an adopted node is sent to a check the app does not have"),
    ("w-s12b", ENG + "AvpnEngineQml.cpp", "            m_watchResume->onSessionMetadata(metadata);\n", "", "second review R3: a switch told in an ordinary status reply never reaches the hand-over"),
    ("w-s12c", ENG + "AvpnEngineQml.cpp", "        m_watchResume->onReasserted();\n", "", "second review R3: a Reasserting asks for no fresh reply"),
    ("w-s12d", ENG + "AvpnEngineQml.cpp", "        m_startOrigin = StartOrigin::User;\n        m_needsRestart = true;\n        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch();\n        m_restartOrigin = QStringLiteral(\"extension_return\");", "        m_startOrigin = StartOrigin::User;\n        clearPin();\n        m_needsRestart = true;\n        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch();\n        m_restartOrigin = QStringLiteral(\"extension_return\");", "the way back touches the pin"),
    ("w-s12e", ENG + "AvpnEngineQml.cpp", "    if (!avpn::decideEngineDownRestart(in))\n        return;\n", "", "second review R5: an engine-down reply restarts the tunnel whatever the app is doing"),
    ("w-s12f", ENG + "AvpnEngineQml.cpp", "        in.busy = m_opInFlight || m_needsRestart || m_paused || !uiForeground();", "        in.busy = m_opInFlight || m_needsRestart || m_paused;", "the way back is taken from the background"),
    ("w-s12g", ENG + "ServiceEngine.cpp", "        m_extEvidence.note(m_currentNodeId, netKey, nowMs());", "        m_failedThisSession.insert(m_currentNodeId);", "second review R4: the node the extension left is failed for the whole app session again"),
    ("w-s13", ENG + "ConfigService.cpp", "            freezeCachedFeatures(c.features, /*ios=*/true);", "            freezeCachedFeatures(c.features, /*ios=*/false);", "on iOS the switch key is trusted from the cache"),
    ("w-s14", "recipes/awg-apple/tribe/TribeDataWatch.swift", "        if !policy.switchEnabled || policy.maxSwitches == 0 || appAlive {", "        if !policy.switchEnabled || policy.maxSwitches == 0 || appAlive || env.candidates.isEmpty {", "the arbiter's gate is rewritten (its conditions are pinned by the rule's own mutants)"),
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
ACCEPTED = {
    "cand-07": "equivalent: with Xray listeners in the pool the Awg mode of the pick still refuses them (transportAllowed)",
    "eng-11": "equivalent: buildWatchPlan cuts the list to five as well (plan-28); the engine's cut only saves work",
    "rs-16": "equivalent: prepare() runs once per process (a new extension process per session), where both are zero already",
    "rs-01": "equivalent: a second lock - the parse keeps candidates only with the switch key on and a live lease (xl-01, xl-02, xp-06), so a plan with candidates always has the key on",
    "sb-02": "equivalent: the same second lock at the start choice (the pure function's own lock is pinned by xc-12)",
}

COPY = [
    "conanfile.py",
    "recipes/awg-apple/conanfile.py", "recipes/awg-apple/conandata.yml", PATCH, "recipes/awg-apple/tribe/TribeDataWatch.swift",
    "recipes/awg-apple/tribe/TribeRoaming.swift",
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
    if kind == "cfg":
        return ["bash", "-c", 'OUT="%s/ccp" QT_ROOT="%s" bash "%s/build_config_cache_policy.sh"' % (work, QT, eng_tests)]
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
    # An id names ONE mutant: the accept list is keyed by it, so a repeated id could let an accepted
    # equivalent stand in for a different mutant that survived.
    every = [m[0] for m in PURE] + [m[0] for m in WIRING]
    repeated = sorted({i for i in every if every.count(i) > 1})
    unknown = sorted(set(ACCEPTED) - set(every))
    if repeated or unknown:
        print("the mutant list is not usable: repeated ids %s, accepted ids that name no mutant %s" % (repeated, unknown))
        return 2
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

#!/usr/bin/env python3
"""Mutation test of the app's half of the iOS tunnel-side data watch (build 140) and of its wiring.

Three groups:
  pure    - one rule changed in ConnectTunables.h / TunnelWatchPlan.h / TunnelWatchStatus.h,
            platforms/ios/BackgroundHoldBook.h / IosBackgroundArm.h, ServiceEngine.cpp; killed when the
            behavioural test named with the mutant fails (tunnel_watch_check, IosDataWatchTests,
            transport_pick_check);
  wiring  - one call site removed, moved or un-gated in the adapter patch, the provider, the facade,
            the controller, the recipe or the CMake lists; killed when check_ios_data_watch_wiring.sh
            fails. These are the mutants ONLY the source-level check catches.
The verdict rule itself has its own run: recipes/awg-apple/replay/tribe_data_watch_mutants.py.

Nothing in the working tree is touched: the files the checks read are copied to a temporary tree,
mutated there and the checks run from the copy.
Usage: QT_ROOT=<Qt for macOS> python3 ios_data_watch_mutants.py [pure|wiring] [id-prefix ...]
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
    ("tun-01", ENG + "ConnectTunables.h", "std::isfinite(raw) ? qBound(spec.lo, raw, spec.hi) : spec.def", "std::isfinite(raw) ? raw : spec.def", "watch", "no clamp at all"),
    ("tun-02", ENG + "ConnectTunables.h", "std::isfinite(raw) ? qBound(spec.lo, raw, spec.hi) : spec.def", "qBound(spec.lo, raw, spec.hi)", "watch", "NaN / infinity are not replaced by the default"),
    ("tun-03", ENG + "ConnectTunables.h", '{"ios_tw_cycle_s",                       25,       10,', '{"ios_tw_cycle_s",                       15,       10,', "watch", "a default drifted from the registry"),
    ("tun-04", ENG + "ConnectTunables.h", '{"ios_on_demand_bg_arm_max_s",           25,        5,          28, false}', '{"ios_on_demand_bg_arm_max_s",           25,        5,          60, false}', "watch", "the background hold may outlive what iOS allows"),
    ("tun-05", ENG + "ConnectTunables.h", '{"ios_tw_resume_wait_ms",              3000,      500,       10000, false}', '{"ios_tw_resume_wait_ms",              3000,      500,       10000, true}', "watch", "an app-only number leaks into the plan"),
    ("tun-06", ENG + "ConnectTunables.h", "return std::llround(v);", "return static_cast<long long>(v);", "watch", "fractions are cut instead of rounded"),
    ("plan-01", ENG + "TunnelWatchPlan.h", "constexpr int kWatchPlanSchema = 1;", "constexpr int kWatchPlanSchema = 2;", "watch", "a schema the extension rejects"),
    ("plan-02", ENG + "TunnelWatchPlan.h", "double(in.nowMs + ttlH * 3600LL * 1000LL)", "double(in.nowMs)", "watch", "the plan expires at once"),
    ("plan-03", ENG + "TunnelWatchPlan.h", "double(policyH * 3600LL * 1000LL)", "double(policyH)", "watch", "policy max age in the wrong unit"),
    ("plan-04", ENG + "TunnelWatchPlan.h", '{QStringLiteral("ios_tunnel_watch"), in.watch}', '{QStringLiteral("ios_tunnel_watch"), true}', "watch", "the plan switches the watch on by itself"),
    ("plan-05", ENG + "TunnelWatchPlan.h", '{QStringLiteral("candidates"), QJsonArray{}}', '{QStringLiteral("candidates"), QJsonArray{1}}', "watch", "stage 1 hands candidates to the extension"),
    ("plan-06", ENG + "TunnelWatchPlan.h", '        if (e.key != QLatin1String("wifi") && e.key != in.cellularKey)\n            continue; // only the two keys of net_keys\n', "", "watch", "another network's memory entry is handed over"),
    ("plan-07", ENG + "TunnelWatchPlan.h", "if (!t.isDouble() || nowSec - qint64(t.toDouble()) > maxAgeSec)\n            return e;", "if (!t.isDouble())\n            return e;", "watch", "a memory entry older than 7 days is handed over"),
    ("plan-08", ENG + "TunnelWatchPlan.h", "return body.size() > kWatchPlanMaxBytes ? QByteArray() : body;", "return body.size() >= kWatchPlanMaxBytes ? QByteArray() : body;", "watch", "64 KB boundary"),
    ("plan-09", ENG + "TunnelWatchPlan.h", "return body.size() > kWatchPlanMaxBytes ? QByteArray() : body;", "return body;", "watch", "a plan over 64 KB is written"),
    ("plan-10", ENG + "TunnelWatchPlan.h", "const bool everOn = everOnBefore || flagNow;", "const bool everOn = flagNow;", "watch", "the kill switch never reaches the extension (file not rewritten with the flag off)"),
    ("plan-11", ENG + "TunnelWatchPlan.h", "const bool everOn = everOnBefore || flagNow;", "const bool everOn = true;", "watch", "the file is created on an install whose flag was never on"),
    ("plan-12", ENG + "TunnelWatchPlan.h", "if (i == 0 || (i < nodeId.size() && nodeId.at(i) != QLatin1Char(':')))", "if (i == 0)", "watch", "a junk node id is read as a node"),
    ("plan-13", ENG + "TunnelWatchPlan.h", 'if (engineMode == QLatin1String("awg"))\n        return QStringLiteral("amnezia");', 'if (engineMode == QLatin1String("awg"))\n        return QStringLiteral("auto");', "watch", "the Amnezia-only mode is handed over as auto"),
    ("plan-14", ENG + "TunnelWatchPlan.h", "double(in.configFetchedMs > 0 ? in.configFetchedMs : 0)", "double(in.configFetchedMs)", "watch", "a negative fetch time is written"),
    ("plan-15", ENG + "TunnelWatchPlan.h", "if (in.sanityUrlsKnown && !in.sanityUrls.isEmpty())", "if (in.sanityUrlsKnown)", "watch", "an empty target list is written (the built-in targets are lost)"),
    ("plan-16", ENG + "TunnelWatchPlan.h", "        if (!s.toPlan)\n            continue;\n        out.append(", "        out.append(", "watch", "app-only numbers go into the plan"),
    ("plan-17", ENG + "TunnelWatchPlan.h", "in.pinNodeId.isEmpty() ? QString() : in.pinCountry", "in.pinCountry", "watch", "a pin country without a pinned node"),
    ("plan-18", ENG + "TunnelWatchPlan.h", "e.savedMs = e.nodeId ? qint64(t.toDouble()) * 1000 : 0;", "e.savedMs = e.nodeId ? qint64(t.toDouble()) : 0;", "watch", "memory time in the wrong unit"),
    ("st-01", ENG + "TunnelWatchStatus.h", "if (enabled.typeId() != QMetaType::Bool || s.verdict == WatchVerdict::Unknown)", "if (s.verdict == WatchVerdict::Unknown)", "watch", "a block without a boolean `enabled` is valid"),
    ("st-02", ENG + "TunnelWatchStatus.h", "if (enabled.typeId() != QMetaType::Bool || s.verdict == WatchVerdict::Unknown)", "if (enabled.typeId() != QMetaType::Bool)", "watch", "an unknown verdict word is valid"),
    ("st-03", ENG + "TunnelWatchStatus.h", "if (s.verdict != WatchVerdict::NoData && s.verdict != WatchVerdict::Unconfirmed)", "if (s.verdict != WatchVerdict::NoData)", "watch", "unconfirmed is not a reason to re-check"),
    ("st-04", ENG + "TunnelWatchStatus.h", "if (s.verdict != WatchVerdict::NoData && s.verdict != WatchVerdict::Unconfirmed)", "if (s.verdict == WatchVerdict::None || s.verdict == WatchVerdict::Suspect)", "watch", "network / captive trigger a re-check"),
    ("st-05", ENG + "TunnelWatchStatus.h", "if (!s.present || !s.valid || !s.enabled)", "if (!s.present || !s.valid)", "watch", "a switched-off watch still triggers a re-check"),
    ("st-06", ENG + "TunnelWatchStatus.h", "if (!s.present || !s.valid || !s.enabled)", "if (!s.present || !s.enabled)", "watch", "a garbled block triggers a re-check"),
    ("st-07", ENG + "TunnelWatchStatus.h", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "if (in.appNodeId.isEmpty() || in.snapshotGeneration.isEmpty()", "watch", "a verdict about another node is taken for ours"),
    ("st-08", ENG + "TunnelWatchStatus.h", "|| in.snapshotGeneration != in.appGeneration)", ")", "watch", "a verdict of another extension session is taken for ours"),
    ("st-09", ENG + "TunnelWatchStatus.h", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "if (in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "watch", "an unknown app node matches"),
    ("st-10", ENG + "TunnelWatchStatus.h", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId || in.snapshotGeneration.isEmpty()", "if (in.appNodeId.isEmpty() || in.snapshotNodeId != in.appNodeId", "watch", "two empty generations match"),
    ("fr-01", ENG + "TunnelWatchStatus.h", "} else if (in.nowMs - st.startMs >= in.timeoutMs)", "} else if (in.nowMs - st.startMs > in.timeoutMs)", "watch", "timeout boundary"),
    ("fr-02", ENG + "TunnelWatchStatus.h", "} else if (in.nowMs - st.startMs >= in.timeoutMs)", "} else if (false)", "watch", "the freeze never times out"),
    ("fr-03", ENG + "TunnelWatchStatus.h", "if (!in.flagOn || !in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "if (!in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "watch", "the flag going off does not release"),
    ("fr-04", ENG + "TunnelWatchStatus.h", "if (!in.flagOn || !in.tunnelConnected)\n        step = FreezeStep::ReleaseOff;", "if (!in.flagOn)\n        step = FreezeStep::ReleaseOff;", "watch", "a tunnel that went down does not release"),
    ("fr-05", ENG + "TunnelWatchStatus.h", "else if (in.snapshotArrived)\n        step = FreezeStep::ReleaseSnapshot;", "else if (false)\n        step = FreezeStep::ReleaseSnapshot;", "watch", "a snapshot does not release"),
    ("fr-06", ENG + "TunnelWatchStatus.h", "const bool frozenDuringWait = lateTick && in.nowMs - in.sinceLastTickMs >= st.startMs;", "const bool frozenDuringWait = false;", "watch", "time spent frozen is judged as the timeout"),
    ("fr-07", ENG + "TunnelWatchStatus.h", "const bool frozenDuringWait = lateTick && in.nowMs - in.sinceLastTickMs >= st.startMs;", "const bool frozenDuringWait = lateTick;", "watch", "the tick that revealed the thaw restarts the wait"),
    ("fr-08", ENG + "TunnelWatchStatus.h", "} else if (in.nowMs < st.startMs) {", "} else if (false) {", "watch", "a clock that went back stretches the wait"),
    ("fr-09", ENG + "TunnelWatchStatus.h", "return !st.active && flagOn && tunnelConnected;", "return !st.active && tunnelConnected;", "watch", "the freeze begins with the flag off"),
    ("fr-10", ENG + "TunnelWatchStatus.h", "return !st.active && flagOn && tunnelConnected;", "return !st.active && flagOn;", "watch", "the freeze begins without a tunnel"),
    ("fr-11", ENG + "TunnelWatchStatus.h", "return !st.active && flagOn && tunnelConnected;", "return flagOn && tunnelConnected;", "watch", "the freeze begins twice"),
    ("fr-12", ENG + "TunnelWatchStatus.h", "return lastTickMs >= 0 && nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);", "return nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);", "watch", "a thaw is seen before the first tick"),
    ("fr-13", ENG + "TunnelWatchStatus.h", "return lastTickMs >= 0 && nowMs >= lastTickMs && timerFiredLate(nowMs - lastTickMs, tickPeriodMs);", "return lastTickMs >= 0 && nowMs >= lastTickMs && nowMs - lastTickMs > tickPeriodMs;", "watch", "an ordinary late tick is a thaw (no slack)"),
    ("fr-14", ENG + "TunnelWatchStatus.h", "    st.active = false;\n    st.startMs = -1;\n    return step;", "    return step;", "watch", "a released freeze stays active"),
    ("fr-15", ENG + "TunnelWatchStatus.h", "if (engineVerifying)\n        return ReverifyAction::RestartPending;", "if (engineVerifying)\n        return ReverifyAction::ReenterFromConnected;", "watch", "a pending check is not restarted"),
    ("fr-16", ENG + "TunnelWatchStatus.h", "if (engineConnected)\n        return ReverifyAction::ReenterFromConnected;", "if (engineConnected)\n        return ReverifyAction::None;", "watch", "a connected session is not re-checked"),
    ("fr-17", ENG + "TunnelWatchStatus.h", "const qint64 age = s.sinceMs > 0 && nowMs >= s.sinceMs ? nowMs - s.sinceMs : -1;", "const qint64 age = nowMs - s.sinceMs;", "watch", "a bogus verdict age in the journal"),
    ("fr-18", ENG + "TunnelWatchStatus.h", "        st.startMs = in.nowMs; // the frozen time is no waiting time\n        return FreezeStep::HoldReask;", "        return FreezeStep::HoldReask;", "watch", "the wait is not restarted after a second freeze"),
    ("fr-19", ENG + "TunnelWatchStatus.h", "    return v == WatchVerdict::NoData;\n}\n\ninline QString watchConsumedJournalLine(", "    return v == WatchVerdict::NoData || v == WatchVerdict::Unconfirmed;\n}\n\ninline QString watchConsumedJournalLine(", "watch", "an unconfirmed verdict wipes the network memory"),
    ("fr-20", ENG + "TunnelWatchStatus.h", "    return v == WatchVerdict::NoData;\n}\n\ninline QString watchConsumedJournalLine(", "    return false;\n}\n\ninline QString watchConsumedJournalLine(", "watch", "a confirmed verdict does not make the network memory forget the node"),
    ("hold-01", IOS + "BackgroundHoldBook.h", "return m_reasons == 0 ? Step::EndTask : Step::None;", "return Step::EndTask;", "ios", "one reason leaving ends the task another reason holds"),
    ("hold-02", IOS + "BackgroundHoldBook.h", "return first ? Step::BeginTask : Step::None;", "return Step::BeginTask;", "ios", "a second system task is started"),
    ("hold-03", IOS + "BackgroundHoldBook.h", "void expire() { m_reasons = 0; }", "void expire() {}", "ios", "expiry leaves the reasons holding"),
    ("hold-04", IOS + "BackgroundHoldBook.h", "        m_sys.end();\n        for (auto &cb : cbs)\n            if (cb)\n                cb();", "        for (auto &cb : cbs)\n            if (cb)\n                cb();\n        m_sys.end();", "ios", "owners are told before the task is ended"),
    ("hold-05", IOS + "BackgroundHoldBook.h", "        if (!already)\n            m_callbacks[unsigned(r)] = std::move(onExpired);", "        m_callbacks[unsigned(r)] = std::move(onExpired);", "ios", "a second acquire replaces the first callback"),
    ("hold-06", IOS + "BackgroundHoldBook.h", "            m_book.taskRefused();\n", "", "ios", "a refused task is booked as held"),
    ("hold-07", IOS + "BackgroundHoldBook.h", "cbs[i] = std::exchange(m_callbacks[i], nullptr);", "cbs[i] = m_callbacks[i];", "ios", "an expiry leaves the callbacks in place (told again at the next expiry)"),
    ("hold-08", IOS + "BackgroundHoldBook.h", "        if (!(m_reasons & bit))\n            return Step::None;\n", "", "ios", "releasing what is not held ends the task"),
    ("hold-09", IOS + "BackgroundHoldBook.h", "        m_callbacks[unsigned(r)] = nullptr;\n        if (m_book.release(r) == BackgroundHoldBook::Step::EndTask)", "        if (m_book.release(r) == BackgroundHoldBook::Step::EndTask)", "ios", "a released reason keeps its callback"),
    ("hold-10", IOS + "BackgroundHoldBook.h", "void taskRefused() { m_reasons = 0; }", "void taskRefused() {}", "ios", "a refusal leaves the reason holding"),
    ("hold-11", IOS + "BackgroundHoldBook.h", "            for (auto &cb : m_callbacks)\n                cb = nullptr;\n", "", "ios", "a refused request keeps its callback"),
    ("arm-01", IOS + "IosBackgroundArm.h", '    if (!in.flagOn) return {BgArmStart::NotNeeded, "flag_off"};\n', "", "ios", "the arming holds background time with the flag off"),
    ("arm-02", IOS + "IosBackgroundArm.h", '    if (!in.wireGuardBased) return {BgArmStart::NotNeeded, "xray"};\n', "", "ios", "an Xray session is held for arming"),
    ("arm-03", IOS + "IosBackgroundArm.h", '    if (in.armed) return {BgArmStart::NotNeeded, "armed"};\n', "", "ios", "an armed session is held again"),
    ("arm-04", IOS + "IosBackgroundArm.h", 'if (!in.handshakeAwaiting && !in.changePending) return {BgArmStart::NotNeeded, "arm_decided"};', 'if (!in.handshakeAwaiting) return {BgArmStart::NotNeeded, "arm_decided"};', "ios", "an arming save in flight is not waited for"),
    ("arm-05", IOS + "IosBackgroundArm.h", 'if (!in.haveTunnel || !in.sessionUp) return {BgArmStart::NotNeeded, "no_session"};', 'if (!in.haveTunnel) return {BgArmStart::NotNeeded, "no_session"};', "ios", "a session that is down is held"),
    ("arm-06", IOS + "IosBackgroundArm.h", '    if (in.localStopRequested) return {BgArmStart::NotNeeded, "stopping"};\n', "", "ios", "a session being stopped is held"),
    ("arm-07", IOS + "IosBackgroundArm.h", "if (held >= in.maxHoldMs) return BgArmTick::ReleaseTimeout;", "if (held > in.maxHoldMs) return BgArmTick::ReleaseTimeout;", "ios", "hold bound boundary"),
    ("arm-08", IOS + "IosBackgroundArm.h", "    if (in.armed) return BgArmTick::ReleaseArmed;\n", "", "ios", "an armed rule does not release the hold"),
    ("arm-09", IOS + "IosBackgroundArm.h", "if (!in.sessionUp || in.localStopRequested) return BgArmTick::ReleaseNotNeeded;", "if (!in.sessionUp) return BgArmTick::ReleaseNotNeeded;", "ios", "our own stop does not release the hold"),
    ("arm-10", IOS + "IosBackgroundArm.h", "    if (!in.handshakeAwaiting && !in.changePending) return BgArmTick::ReleaseNotNeeded;\n", "", "ios", "an arming that was skipped keeps the hold until the bound"),
    ("arm-11", IOS + "IosBackgroundArm.h", 's += !sessionUp ? "-" : (wireGuardBased ? "awg" : "xray");', 's += wireGuardBased ? "awg" : "xray";', "ios", "the state line names a protocol for a session that is down"),
    ("eng-01", ENG + "ServiceEngine.cpp", "    if (m_state != EngineState::Connected || m_currentNodeId.isEmpty())\n        return false;\n    m_state = EngineState::Verifying;", "    if (m_currentNodeId.isEmpty())\n        return false;\n    m_state = EngineState::Verifying;", "pick", "any phase can be thrown back to Verifying"),
    ("eng-02", ENG + "ServiceEngine.cpp", "    m_upFrozen = true;\n    return true;\n}", "    return true;\n}", "pick", "a re-check records a bogus time to traffic"),
    ("eng-03", ENG + "ServiceEngine.cpp", "    m_state = EngineState::Verifying;\n    // A success of this re-check", "    // A success of this re-check", "pick", "the engine does not go back to Verifying"),
]

WIRING = [
    ("w-e1a", PATCH, "+        self.dataWatchTick(sample) // tribe.13: the same sample, before the ladder acts on it\n         let outcome = self.recovery.tick(sample, pathSatisfied: self.lastPathSatisfiable, policy: self.roamingPolicy)\n", "         let outcome = self.recovery.tick(sample, pathSatisfied: self.lastPathSatisfiable, policy: self.roamingPolicy)\n+        self.dataWatchTick(sample) // tribe.13: the same sample, before the ladder acts on it\n", "the watch is fed after the ladder acted"),
    ("w-e1b", PATCH, "+    private func dataWatchTick(_ sample: TribeStallSample) {\n", "+    private func dataWatchTick(_ sample: TribeStallSample) {\n+        self.workQueue.asyncAfter(deadline: .now() + 1) { }\n", "the adapter patch grows a delayed block"),
    ("w-e2a", PATCH, "+        guard self.dataWatchPolicy.enabled else { return }\n+        self.dataWatch.notePathEvent(", "+        self.dataWatch.notePathEvent(", "a path event reaches a switched-off watch"),
    ("w-e2b", PATCH, "+            if self.dataWatchPolicy.enabled { self.dataWatch.noteBackendRestarted() }\n", "+            self.dataWatch.noteBackendRestarted()\n", "a backend restart reaches a switched-off watch"),
    ("w-e3", PATCH, "+\tif tribeProbeCfg == nil {\n+\t\ttribeProbeTun = nil\n+\t\treturn inner\n+\t}\n", "", "the probe wrapper is created without a configuration"),
    ("w-e4a", IOS + "PacketTunnelProvider+DataWatch.swift", "wgSetTribeProbe(wgConfig.clientIP, wgConfig.dns1, wanted ? 1 : 0)", "wgSetTribeProbe(wgConfig.clientIP, wgConfig.dns1, 1)", "the probe is configured although the watch is off"),
    ("w-e4b", IOS + "PacketTunnelProvider+WireGuard.swift", "        tribeDataWatch.noteAppStatusRequest() // AVPN (build 140, data watch): the app is alive\n", "", "a status request does not mark the app alive"),
    ("w-e4c", IOS + "PacketTunnelProvider+WireGuard.swift", 'if let watch { response["watch"] = watch }', 'response["watch"] = watch ?? [String: Any]()', "the status reply always carries a watch key"),
    ("w-e4d", IOS + "PacketTunnelProvider+WireGuard.swift", "        tribeDataWatch.detach() // AVPN (build 140, data watch)\n", "", "the runtime is not detached on stop"),
    ("w-e4e", IOS + "TribeDataWatchRuntime.swift", "guard enabled, let live else { completion(nil); return }", "guard let live else { completion(nil); return }", "a switched-off watch still answers with a block"),
    ("w-e5a", IOS + "PacketTunnelProvider+WireGuard.swift", "        tribeDataWatch.refreshPlan()\n", "", "the plan is never re-read (no kill switch)"),
    ("w-e5b", IOS + "TribeDataWatchRuntime.swift", "        parameters.requiredInterface = interface\n", "", "the bypass request is not bound to the physical interface"),
    ("w-e5c", IOS + "TribeDataWatchRuntime.swift", "    private func finishSanity(", "    private var tick = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n    private func finishSanity(", "the runtime gets a timer of its own"),
    ("w-e6", IOS + "TribeDataWatchRuntime.swift", "        guard output.action == .report, let report = output.report else { return }", "        if output.action == .switchPeer { adapter?.update(tunnelConfiguration: nil) }\n        guard output.action == .report, let report = output.report else { return }", "the runtime acts on a switching action"),
    ("w-e7a", "recipes/awg-apple/conandata.yml", '    - patch_file: "patches/0012-tribe-data-watch.patch"\n', '    - patch_file: "patches/0010-tribe-upstream-http.patch"\n    - patch_file: "patches/0012-tribe-data-watch.patch"\n', "tribe.13 pulls in a patch of the unmerged branch"),
    ("w-e7b", "client/macos/networkextension/CMakeLists.txt", "    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/TribeDataWatch.swift\n", "", "the macOS extension target does not compile the rule"),
    ("w-e7c", "conanfile.py", 'self.requires("awg-apple/3.1.4-tribe.13")', 'self.requires("awg-apple/3.1.4-tribe.11")', "the app still requires the package without the watch"),
    ("w-e8", IOS + "PacketTunnelProvider+DataWatch.swift", "        guard Log.isLoggingEnabled else { return }\n        let snapshot = xrayRuntimeSession.snapshot()", "        let snapshot = xrayRuntimeSession.snapshot()", "the Xray statistics line is written with the log off"),
    ("w-a1", ENG + "AvpnEngineQml.cpp", '#ifdef Q_OS_IOS\n    writeTunnelWatchPlan("start");', '#if 1\n    writeTunnelWatchPlan("start");', "a plan write outside Q_OS_IOS"),
    ("w-a2", ENG + "AvpnEngineQml.cpp", '    const bool watch = featureEnabled(QStringLiteral("ios_tunnel_watch"), false);\n    QSettings s;', '    const bool watch = featureEnabled(QStringLiteral("ios_tunnel_watch"), true);\n    QSettings s;', "the flag is read with the default true"),
    ("w-a3a", ENG + "AvpnEngineQml.cpp", '#ifdef Q_OS_IOS\n    writeTunnelWatchPlan("start"); // AVPN (iOS data watch, 140): before the queued up() reaches the extension\n#endif\n', "", "a start does not rewrite the plan"),
    ("w-a3b", ENG + "AvpnEngineQml.cpp", "    if (!w.write)\n        return; // the flag has never been on here: no file, as build 139\n", "", "the plan file is created with the flag never on"),
    ("w-a4a", IOS + "ios_controller.mm", "if (m_statusGeneration.load() != gen || !m_statusRequests.lastAppliedIs(gen, request))\n                    return;\n                if (m_watchSnapshotWanted.exchange(false))", "if (m_statusGeneration.load() != gen)\n                    return;\n                if (m_watchSnapshotWanted.exchange(false))", "a stale reply's watch block reaches the facade"),
    ("w-a4b", IOS + "ios_controller.mm", "    m_statusRequests.invalidate();\n    checkStatus();\n}", "    checkStatus();\n}", "a snapshot request does not cancel older replies"),
    ("w-a4d", IOS + "ios_controller.mm", "                if (m_watchSnapshotWanted.exchange(false))\n                    emit tunnelWatchSnapshot(watchSnapshot);", "                emit tunnelWatchSnapshot(watchSnapshot);", "every status reply is passed to the facade"),
    ("w-a4e", IOS + "ios_controller.mm", "    m_watchSnapshotWanted.store(true);\n", "", "a snapshot request is never answered"),
    ("w-a4c", ENG + "AvpnEngineQml.cpp", "    if (!m_watchFreeze.active)\n        return;\n    avpn::ResumeFreezeInputs in;\n    in.flagOn = featureEnabled(QStringLiteral(\"ios_tunnel_watch\"), false);\n    in.tunnelConnected = m_lastTunnelState == Vpn::Connected;\n    in.nowMs = QDateTime::currentMSecsSinceEpoch();\n    in.snapshotArrived = true;", "    avpn::ResumeFreezeInputs in;\n    in.flagOn = featureEnabled(QStringLiteral(\"ios_tunnel_watch\"), false);\n    in.tunnelConnected = m_lastTunnelState == Vpn::Connected;\n    in.nowMs = QDateTime::currentMSecsSinceEpoch();\n    in.snapshotArrived = true;", "a snapshot acts outside a freeze"),
    ("w-a5a", ENG + "AvpnEngineQml.cpp", "    } else if (m_engine.tick(QDateTime::currentSecsSinceEpoch())) {", "    }\n    if (m_engine.tick(QDateTime::currentSecsSinceEpoch())) {", "the health verdict does not wait for the snapshot"),
    ("w-a5b", ENG + "AvpnEngineQml.cpp", '    if (deferWhileTunnelWatchFrozen("whoami", [this, epoch]() { whoamiAttempt(epoch); }))\n        return;\n', "", "a late whoami attempt is judged before the extension was asked"),
    ("w-a5c", ENG + "AvpnEngineQml.cpp", '    if (!featureEnabled(QStringLiteral("ios_tunnel_watch"), false))\n        return false;\n    if (!m_watchFreeze.active\n', "    if (!m_watchFreeze.active\n", "decisions can be frozen with the flag off"),
    ("w-a5d", ENG + "AvpnEngineQml.cpp", "        tickTunnelWatchFreeze(since); // AVPN (iOS data watch, 140): the resume freeze rides on this tick\n", "", "the freeze is never judged (no timeout)"),
    ("w-a6a", IOS + "ios_controller.mm", "    tickBackgroundArmHold(); // AVPN (iOS data watch, 140): the hold's bound is judged on this poll's tick\n", "", "the arming hold is never judged"),
    ("w-a6b", ENG + "AvpnEngineQml.cpp", "    IosController::Instance()->requestStatusSnapshot();\n#else\n    Q_UNUSED(why);\n#endif\n}\n\n// A decision consults", "    IosController::Instance()->requestStatusSnapshot();\n    QTimer::singleShot(3000, this, [this] { releaseTunnelWatchFreeze(0, nullptr); });\n#else\n    Q_UNUSED(why);\n#endif\n}\n\n// A decision consults", "the freeze gets a timer of its own"),
    ("w-a7a", IOS + "ios_controller.mm", "    if (!bgArmFlag)\n        return; // build 139 behaviour: nothing held, nothing journaled\n", "", "the background transition acts with the flag off"),
    ("w-a7b", IOS + "ios_controller.mm", "AvpnBackgroundGuard_acquire(avpn_ios::BgReason::OnDemandArm, [this, token] {", "AvpnBackgroundGuard_acquire(avpn_ios::BgReason::TunnelRestart, [this, token] {", "the arming takes the restart guard's reason"),
    ("w-a7c", IOS + "ios_controller.mm", "                    endBackgroundArmHold(saveFailed ? \"not_needed\" : \"armed\", saveFailed ? \"save_failed\" : \"\");\n", "", "the arming's result does not end the hold"),
    ("w-a8a", ENG + "AvpnEngineQml.cpp", "    reliabilityEvent(avpn::watchConsumedJournalLine(snapshot, nodeId, QDateTime::currentMSecsSinceEpoch()));\n", "    reliabilityEvent(avpn::watchConsumedJournalLine(snapshot, nodeId, QDateTime::currentMSecsSinceEpoch()));\n    m_savedPin.clear();\n", "the extension's verdict clears the pin"),
    ("w-a8b", ENG + "AvpnEngineQml.cpp", "        startDataPathVerification(); // full budget, new epoch: the frozen check never completes as \"limited\"\n", "        m_engine.verifyFailed(QStringLiteral(\"extension\"));\n", "the extension's verdict is taken as a failure of the node"),
    ("w-x1a", "recipes/awg-apple/tribe/TribeDataWatch.swift", 'numbers["ios_tw_cycle_s"], fallback: policy.cycleSeconds, min: 10, max: 120)', 'numbers["ios_tw_cycle_s"], fallback: policy.cycleSeconds, min: 5, max: 120)', "the extension clamps a number to other bounds than the app"),
    ("w-x1b", ENG + "ConnectTunables.h", '{"ios_tw_probe_max_per_hour",            12,        1,          60, true}', '{"ios_tw_probe_max_per_hour",            12,        1,         600, true}', "the app lets through a value the extension cuts"),
    ("w-x1c", "recipes/awg-apple/tribe/TribeDataWatch.swift", '        policy.probeMaxPerHour = Int(number(numbers["ios_tw_probe_max_per_hour"], fallback: Double(policy.probeMaxPerHour), min: 1, max: 60))\n', "", "a number of the plan is not read by the extension"),
    ("w-a8c", ENG + "AvpnEngineQml.cpp", "    if (avpn::watchVerdictForgetsNode(snapshot.verdict) && !m_attemptNetKey.isEmpty()) {", "    if (!m_attemptNetKey.isEmpty()) {", "the network memory forgets the node on an unconfirmed verdict"),
    ("w-a9", ENG + "AvpnEngineQml.cpp", "    if (healthHeld) {\n", "    if (healthHeld && m_engine.reenterVerifying()) {\n", "the engine is thrown back to Verifying from a second place"),
]

# Survivors that are accepted, with the reason no test of this group can or should kill them.
ACCEPTED = {}

COPY = [
    "conanfile.py",
    "recipes/awg-apple/conanfile.py", "recipes/awg-apple/conandata.yml", PATCH, "recipes/awg-apple/tribe/TribeDataWatch.swift",
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
    ios_tests = os.path.join(tree, IOS, "tests")
    if kind == "watch":
        return ["bash", "-c", 'OUT="%s/tw" QT_ROOT="%s" bash "%s/build_tunnel_watch.sh"' % (work, QT, eng_tests)]
    if kind == "pick":
        # Headers outside the two copied directories come from the working tree (never mutated here).
        return ["bash", "-c", 'OUT="%s/tp" QT_ROOT="%s" AVPN_MAIN_CLIENT="%s" bash "%s/build_transport_pick.sh"'
                % (work, QT, os.path.join(ROOT, "client"), eng_tests)]
    if kind == "ios":
        return ["bash", "-c", 'xcrun clang++ -std=c++17 -pthread "%s/IosDataWatchTests.cpp" -o "%s/idw" && "%s/idw"' % (ios_tests, work, work)]
    if kind == "wiring":
        return ["bash", os.path.join(eng_tests, "check_ios_data_watch_wiring.sh")]
    raise ValueError(kind)


def main():
    args = sys.argv[1:]
    groups = [a for a in args if a in ("pure", "wiring")] or ["pure", "wiring"]
    wanted = [a for a in args if a not in ("pure", "wiring")]
    mutants = []
    if "pure" in groups:
        mutants += [(i, f, o, n, t, w) for (i, f, o, n, t, w) in PURE]
    if "wiring" in groups:
        mutants += [(i, f, o, n, "wiring", w) for (i, f, o, n, w) in WIRING]
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

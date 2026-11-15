// Tribe data watch — executable unit test (no XCTest: compiled by plain swiftc inside the conan
// recipe build, so the adapter package cannot ship with a broken verdict rule).
// Every scenario is a named function; `run` prints the names that fail. The provider is modelled
// by `Sim`: it answers the bypass check one second after it is asked and reports the probe's
// outcome after the probe's own delay, exactly as the extension does.
import Foundation

var failures = 0
var currentTest = ""
func check(_ cond: @autoclosure () -> Bool, _ what: @autoclosure () -> String, line: Int = #line) {
    if !cond() { failures += 1; print("FAIL \(currentTest) line \(line): \(what())") }
}
func run(_ name: String, _ body: () -> Void) {
    currentTest = name
    body()
}

func basePolicy() -> TribeDataWatchPolicy {
    var p = TribeDataWatchPolicy()
    p.enabled = true
    return p
}

struct Sim {
    var watch = TribeDataWatch()
    var policy: TribeDataWatchPolicy
    var tx: UInt64 = 0
    var rx: UInt64 = 0
    var handshake: Int64 = 0
    var uptime: TimeInterval = 1000
    var wall: TimeInterval = 1_800_000_000
    var env = TribeDataWatchEnv(pathSatisfied: true)
    /// What the bypass check answers; nil = it is never answered.
    var sanityAnswer: TribeSanityResult? = .ok
    /// What the probe through the tunnel answers; nil = the provider never reports back.
    var probeAnswer: TribeProbeResult? = .silent
    var probeLatency: TimeInterval = 0.3
    /// false = the provider leaves whatever probe result it had (an older one) until the new one arrives.
    var marksProbePending = true
    private var sanityDue: TimeInterval?
    private var probeDue: TimeInterval?
    var sanityChecks = 0
    var probesStarted: [(at: TimeInterval, reason: TribeProbeReason)] = []
    var reports: [(at: TimeInterval, report: TribeDataWatchReport, verdict: TribeDataVerdict)] = []
    var verdicts: [TribeDataVerdict] = []
    var actions: [TribeDataWatchAction] = []
    var startedAt: TimeInterval = 1000

    init(_ policy: TribeDataWatchPolicy = basePolicy(), started: Bool = true) {
        self.policy = policy
        if started { watch.noteDeviceStarted(at: uptime, policy: policy) }
        startedAt = uptime
        _ = tick(0)
    }

    var elapsed: TimeInterval { uptime - startedAt }

    /// One sample `dt` seconds later. `sleep` = seconds the device slept inside the interval.
    @discardableResult
    mutating func tick(_ dt: TimeInterval = 1, tx addTx: UInt64 = 0, rx addRx: UInt64 = 0, handshake completed: Bool = false, sleep: TimeInterval = 0) -> TribeDataWatchOutput {
        uptime += dt
        wall += dt + sleep
        tx += addTx
        rx += addRx
        if completed {
            // A completed handshake: its initiation with junk goes out, its 92-byte response comes in.
            tx += 422
            rx += 92
            handshake = Int64(wall)
        }
        if let due = sanityDue, uptime >= due, let answer = sanityAnswer {
            env.sanity = answer
            env.sanityAt = due
            sanityDue = nil
        }
        if let due = probeDue, uptime >= due, let answer = probeAnswer {
            env.probe = answer
            env.probeAt = due
            env.probeLatencyMs = Int(probeLatency * 1000)
            probeDue = nil
        }
        let out = watch.step(TribeDataWatchSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: handshake, uptime: uptime, wall: wall),
                             env: env, policy: policy)
        if out.needsSanityCheck && sanityDue == nil {
            sanityDue = uptime + 1
            sanityChecks += 1
        }
        if let reason = out.startProbe {
            probesStarted.append((uptime, reason))
            if marksProbePending { env.probe = .pending }
            probeDue = uptime + (probeAnswer == .answered ? probeLatency : policy.probeTimeoutSeconds)
        }
        if out.action == .report, let report = out.report { reports.append((uptime, report, out.verdict)) }
        if out.action != .keep && out.report == nil { failures += 1; print("FAIL \(currentTest): report without a kind") }
        verdicts.append(out.verdict)
        actions.append(out.action)
        return out
    }

    /// The stall ladder performed a same-node heal step (fresh port or soft restart).
    mutating func heal(softRestart: Bool = false) {
        env.healSteps += 1
        if softRestart {
            watch.noteBackendRestarted()
            tx = 0
            rx = 0
            handshake = 0
        }
    }

    /// The dead path of 13.11: outbound demand, a handshake that completes every `handshakeEvery`
    /// seconds, not one transport packet back. The ladder's fresh port at 4 s and soft restart at 14 s.
    /// Later the ladder goes on as it does in the field: 30 s, 60 s, then every 120 s.
    mutating func deadPath(seconds: Int, txPerSecond: UInt64 = 390, handshakeEvery: Int = 17, ladder: Bool = true, firstSecond: Int = 1) {
        for second in firstSecond..<(firstSecond + seconds) {
            if ladder {
                if second == 4 || second == 44 || (second > 104 && (second - 104) % 240 == 120) { heal() }
                if second == 14 || second == 104 || (second > 104 && (second - 104) % 240 == 0) { heal(softRestart: true) }
            }
            tick(1, tx: txPerSecond, handshake: second % handshakeEvery == 0)
        }
    }

    func firstReport(_ verdict: TribeDataVerdict) -> TimeInterval? {
        reports.first { $0.report == .verdict && $0.verdict == verdict }.map { $0.at - startedAt }
    }
    func count(_ report: TribeDataWatchReport) -> Int { reports.filter { $0.report == report }.count }
    var everNoData: Bool { verdicts.contains(.noData) }
    var everJudged: Bool { verdicts.contains { $0 != .none } }
    var cycles: Int { watch.snapshot(policy: policy).cycles }
}

// MARK: - policy

run("policy_defaults_are_off") {
    let p = TribeDataWatchPolicy()
    check(!p.enabled && !p.switchEnabled, "everything is off by default")
    check(p == TribeDataWatchPolicy.disabled, "disabled is the default value")
    check(TribeDataWatchPolicy.fromPlan(features: [:], numbers: [:]) == TribeDataWatchPolicy.disabled, "an empty plan = disabled")
    check(p.cycleSeconds == 25 && p.deadCycles == 3 && p.cycleChainGapSeconds == 30, "cycle 25 s x 3, gap 30 s")
    check(p.cycleMinTxBytes == 1024 && p.minEpisodeTxBytes == 3072, "demand thresholds")
    check(p.recoverRxBytes == 16384 && p.handshakeRxAllowanceBytes == 148 && p.handshakeTxAllowanceBytes == 1024, "recover / handshake allowances")
    check(p.minHealSteps == 2 && p.pathStableSeconds == 20 && p.startGraceSeconds == 20 && p.wakeGraceSeconds == 10, "heal steps and graces")
    check(p.appAliveSeconds == 10 && p.maxSwitches == 5, "app alive 10 s, 5 switches")
    check(p.sanityRequired && p.probeEnabled, "both checks are on when the watch is on")
    check(p.suspectWindowSeconds == 60 && p.suspectMinTxBytes == 65536 && p.suspectMaxRxBytes == 4096, "low-inbound trigger")
    check(p.probeTimeoutSeconds == 4 && p.probeMaxPerEpisode == 3 && p.probeMaxPerHour == 12, "probe timeout and limits")
}

run("policy_flags") {
    func on(_ value: Any) -> Bool { TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": value], numbers: [:]).enabled }
    check(on(true) && on(1) && on("1") && on("true"), "true forms switch the watch on")
    check(!on(false) && !on(0) && !on("0") && !on("yes") && !on(2) && !on([1]) && !on(NSNull()), "anything else leaves it off")
    let both = TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": true, "ios_tunnel_watch_switch": true], numbers: [:])
    check(both.enabled && both.switchEnabled, "the switch flag is carried")
    let onlySwitch = TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch_switch": true], numbers: [:])
    check(!onlySwitch.enabled && onlySwitch.switchEnabled, "flags are independent")
}

run("policy_from_json") {
    // The plan arrives as JSON: 0 and 1 are numbers there, true and false are booleans. (Swift
    // casts the numbers 0 and 1 to Bool; a rule written with `is Bool` would lose every zero.)
    let json = #"{"features":{"ios_tunnel_watch":true,"ios_tunnel_watch_switch":0},"#
        + #""numbers":{"ios_tw_min_heal_steps":0,"ios_tw_probe":0,"ios_tw_sanity_required":1,"ios_tw_max_switches":1,"#
        + #""ios_tw_cycle_chain_gap_s":0,"ios_tw_wake_grace_s":true,"ios_tw_path_stable_s":false,"ios_tw_cycle_s":30.0}}"#
    let object = try! JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    let p = TribeDataWatchPolicy.fromPlan(features: object["features"] as! [String: Any], numbers: object["numbers"] as! [String: Any])
    check(p.enabled && !p.switchEnabled, "true is on, the number 0 is off")
    check(p.minHealSteps == 0 && !p.probeEnabled && p.sanityRequired && p.maxSwitches == 1 && p.cycleChainGapSeconds == 0, "zeros and ones stay numbers: \(p)")
    check(p.wakeGraceSeconds == 10 && p.pathStableSeconds == 20, "a boolean where a number belongs is junk: default")
    check(p.cycleSeconds == 30, "a float is a number")
    let on = try! JSONSerialization.jsonObject(with: Data(#"{"a":1,"b":"true","c":false,"d":2}"#.utf8)) as! [String: Any]
    func flag(_ key: String) -> Bool { TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": on[key] as Any], numbers: [:]).enabled }
    check(flag("a") && flag("b") && !flag("c") && !flag("d") && !flag("missing"), "flag forms from JSON")
}

run("policy_clamps") {
    let names = ["ios_tw_cycle_s", "ios_tw_cycle_min_tx_bytes", "ios_tw_dead_cycles", "ios_tw_cycle_chain_gap_s",
                 "ios_tw_recover_rx_bytes", "ios_tw_min_episode_tx_bytes", "ios_tw_hs_rx_allowance_bytes",
                 "ios_tw_hs_tx_allowance_bytes", "ios_tw_min_heal_steps", "ios_tw_path_stable_s", "ios_tw_start_grace_s",
                 "ios_tw_wake_grace_s", "ios_tw_app_alive_s", "ios_tw_max_switches", "ios_tw_suspect_window_s",
                 "ios_tw_suspect_min_tx_bytes", "ios_tw_suspect_max_rx_bytes", "ios_tw_probe_timeout_ms",
                 "ios_tw_probe_max_per_episode", "ios_tw_probe_max_per_hour", "ios_tw_sanity_required", "ios_tw_probe"]
    func all(_ value: Any) -> TribeDataWatchPolicy {
        TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": true], numbers: Dictionary(uniqueKeysWithValues: names.map { ($0, value) }))
    }
    let low = all(-1_000_000)
    check(low.cycleSeconds == 10 && low.cycleMinTxBytes == 1024 && low.deadCycles == 2 && low.cycleChainGapSeconds == 0, "lower clamps 1: \(low)")
    check(low.recoverRxBytes == 1024 && low.minEpisodeTxBytes == 2048 && low.handshakeRxAllowanceBytes == 92 && low.handshakeTxAllowanceBytes == 148, "lower clamps 2")
    check(low.minHealSteps == 0 && low.pathStableSeconds == 0 && low.startGraceSeconds == 5 && low.wakeGraceSeconds == 0, "lower clamps 3")
    check(low.appAliveSeconds == 3 && low.maxSwitches == 0 && low.suspectWindowSeconds == 30 && low.suspectMinTxBytes == 4096 && low.suspectMaxRxBytes == 0, "lower clamps 4")
    check(low.probeTimeoutSeconds == 1 && low.probeMaxPerEpisode == 1 && low.probeMaxPerHour == 1, "lower clamps 5")
    check(!low.sanityRequired && !low.probeEnabled, "0-clamped bits are off")
    let high = all(1e12)
    check(high.cycleSeconds == 120 && high.cycleMinTxBytes == 1_048_576 && high.deadCycles == 20 && high.cycleChainGapSeconds == 300, "upper clamps 1")
    check(high.recoverRxBytes == 1_048_576 && high.minEpisodeTxBytes == 1_048_576 && high.handshakeRxAllowanceBytes == 4096 && high.handshakeTxAllowanceBytes == 8192, "upper clamps 2")
    check(high.minHealSteps == 6 && high.pathStableSeconds == 120 && high.startGraceSeconds == 120 && high.wakeGraceSeconds == 60, "upper clamps 3")
    check(high.appAliveSeconds == 60 && high.maxSwitches == 5 && high.suspectWindowSeconds == 600 && high.suspectMinTxBytes == 16_777_216 && high.suspectMaxRxBytes == 1_048_576, "upper clamps 4")
    check(high.probeTimeoutSeconds == 15 && high.probeMaxPerEpisode == 10 && high.probeMaxPerHour == 60, "upper clamps 5")
    check(high.sanityRequired && high.probeEnabled, "1-clamped bits are on")
    var expected = basePolicy()
    for junk in ["abc", "", [1, 2], NSNull(), true, Double.nan, Double.infinity] as [Any] {
        check(all(junk) == expected, "junk \(junk) keeps every default")
    }
    expected.cycleSeconds = 40
    check(TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": true], numbers: ["ios_tw_cycle_s": "40"]) == expected, "a number as a string is accepted")
    check(TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": true], numbers: ["ios_tw_cycle_s": 40.9]) == expected, "fractions are cut, not rounded up")
}

// MARK: - the positive: the field case of 13.11.2026

run("megafon_13_11_replay") {
    // Handshake passes, data does not: rx stays at the handshake responses, tx grows ~390 B/s, the
    // engine re-handshakes every ~17 s, the ladder's fresh port and soft restart change nothing.
    var s = Sim()
    s.deadPath(seconds: 130)
    let passiveAt = s.probesStarted.first.map { $0.at - s.startedAt }
    let noDataAt = s.firstReport(.noData)
    // 20 s start grace + 3 cycles of 25 s, then the probe's 4 s timeout.
    check(passiveAt != nil && passiveAt! <= 96, "the passive rule is met by the 96th second: \(String(describing: passiveAt))")
    check(noDataAt != nil && noDataAt! <= 101, "no_data by the 101st second: \(String(describing: noDataAt))")
    check(s.probesStarted.count == 1 && s.probesStarted[0].reason == .passive, "exactly one probe, asked by the passive rule: \(s.probesStarted)")
    check(s.sanityChecks == 1, "one bypass check before the probe: \(s.sanityChecks)")
    check(s.watch.verdict == .noData, "the verdict stands")
    check(s.verdicts.last == .noData && s.count(.refuted) == 0, "never refuted")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.enabled && snap.verdict == .noData && snap.sinceWallMs > 0 && snap.lastNoDataWallMs >= snap.sinceWallMs, "snapshot carries the verdict: \(snap)")
    check(snap.probe == .silent && snap.probeReason == .passive && snap.probesInEpisode == 1 && snap.probesLastHour == 1, "snapshot carries the judge: \(snap)")
    check(snap.episodeRxData == 0 && snap.episodeTx > 16000 && snap.wouldSwitch, "episode numbers and the shadow mark: \(snap)")
    // Stage 1 never moves anybody.
    check(!s.actions.contains(.switchPeer) && !s.actions.contains(.exhausted), "no switching action in this version")
}

run("megafon_13_11_replay_cycle_15") {
    var p = basePolicy()
    p.cycleSeconds = 15
    var s = Sim(p)
    s.deadPath(seconds: 100)
    let noDataAt = s.firstReport(.noData)
    check(noDataAt != nil && noDataAt! <= 71, "20 s grace + 3 x 15 s + 4 s probe: \(String(describing: noDataAt))")
}

run("megafon_13_11_pocket_demand") {
    // The same path with the phone in the pocket: ~95 B/s in total, a third of it handshakes
    // (16:13-16:15 UTC in the field trace: 97 B/s). The demand left after the handshakes is
    // ~70 B/s, 1750 B per cycle: caught.
    var s = Sim()
    s.deadPath(seconds: 200, txPerSecond: 70, handshakeEvery: 15)
    check(s.firstReport(.noData) != nil && s.firstReport(.noData)! <= 101, "pocket demand is caught as fast: \(String(describing: s.firstReport(.noData)))")
    // 30 B/s (750 B per cycle) is what an idle tunnel may send by itself: never judged.
    var idle = Sim()
    idle.deadPath(seconds: 600, txPerSecond: 30, handshakeEvery: 15)
    check(!idle.everJudged && idle.cycles == 0, "below the idle floor nothing is counted")
}

run("field_case_is_quiet_when_the_watch_is_off") {
    var s = Sim(TribeDataWatchPolicy.disabled)
    s.deadPath(seconds: 200)
    check(!s.everJudged && s.reports.isEmpty && s.probesStarted.isEmpty && s.sanityChecks == 0, "a disabled watch says and asks nothing")
    check(s.watch == TribeDataWatch(), "and keeps no state")
    check(s.watch.snapshot(policy: s.policy) == TribeDataWatchSnapshot(), "the snapshot of a disabled watch is empty")
}

// MARK: - what must NOT be judged (the design's table of false cases)

run("idle_tunnel_never_judged") {
    // An hour of keepalives: 32 B (plus padding) every 25 s, a re-key every 2 minutes.
    var s = Sim()
    for second in 1...3600 {
        s.tick(1, tx: second % 25 == 0 ? 44 : 0, handshake: second % 120 == 0)
    }
    check(!s.everJudged && s.probesStarted.isEmpty && s.sanityChecks == 0 && s.cycles == 0, "an idle tunnel is never a cycle: \(s.reports)")
}

run("idle_rekey_with_junk") {
    // A burst of 6 KB every 150 s that no data answers (a handshake with a lot of junk): one cycle
    // may be counted, three in a row with a gap of at most 30 s never.
    var s = Sim()
    var maxCycles = 0
    for second in 1...1800 {
        s.tick(1, tx: second % 150 == 0 ? 6000 : 0)
        maxCycles = max(maxCycles, s.cycles)
    }
    check(maxCycles == 1, "single cycles only: \(maxCycles)")
    check(!s.verdicts.contains { $0 != .none && $0 != .suspect }, "never more than a suspicion")
    check(s.probesStarted.isEmpty && s.sanityChecks == 0, "nobody is asked")
}

run("rekey_bytes_are_not_demand") {
    // The same re-key seen as a completed handshake: its own bytes are deducted, no cycle at all.
    var s = Sim()
    for second in 1...1800 {
        s.tick(1, tx: second % 120 == 0 ? 500 : 0, handshake: second % 120 == 0)
    }
    check(s.cycles == 0 && !s.everJudged, "a handshake with 900 B of junk is not demand")
}

run("paused_download") {
    var s = Sim()
    for _ in 1...60 { s.tick(1, tx: 2000, rx: 400_000) }
    for _ in 1...600 { s.tick(1) }
    check(!s.everJudged && s.cycles == 0, "silence in both directions is not a cycle")
}

run("quiet_long_connection") {
    // A push connection: 120 B out every 20 s, the server's keepalive 10 s later.
    var s = Sim()
    for second in 1...1800 {
        s.tick(1, tx: second % 20 == 0 ? 120 : 0, rx: second % 20 == 10 ? 32 : 0)
    }
    check(!s.everJudged && s.cycles == 0, "a quiet connection is answered and is below the demand threshold")
}

run("healthy_slow_upload") {
    // 4 KB out every 15 s, an acknowledgement every 5 s.
    var s = Sim()
    for second in 1...900 {
        s.tick(1, tx: second % 15 == 0 ? 4096 : 0, rx: second % 5 == 0 ? 72 : 0, handshake: second % 120 == 0)
    }
    check(!s.everJudged && s.cycles == 0, "acknowledgements restart the cycle")
}

run("unresponsive_remote_host") {
    // The site is dead but the tunnel server is not: it answers our data with a keepalive.
    var s = Sim()
    for second in 1...600 {
        s.tick(1, tx: 600, rx: second % 10 == 0 ? 32 : 0)
    }
    check(!s.everNoData && s.cycles == 0, "a keepalive every 10 s is inbound data")
}

run("phone_asleep") {
    var s = Sim()
    // 20 s of grace, then 20 s of a dead path: a window is open but no cycle is complete.
    for second in 1...40 { s.tick(1, tx: 400, handshake: second % 17 == 0) }
    check(s.cycles == 0, "no cycle yet")
    // The phone sleeps two hours (uptime stands, wall runs), then a burst of outbound.
    s.tick(1, tx: 30_000, sleep: 7200)
    check(s.cycles == 0, "the burst after the sleep completes nothing")
    // The window restarted: 24 more seconds are not a cycle, the 25th is.
    for _ in 1...9 { s.tick(1, tx: 400) }
    check(s.cycles == 0, "wake grace: 10 s without counting")
    for _ in 1...24 { s.tick(1, tx: 400) }
    check(s.cycles == 0, "24 s after the grace: still no cycle")
    for _ in 1...3 { s.tick(1, tx: 400) }
    check(s.cycles == 1, "the cycle counts from the end of the grace: \(s.cycles)")
}

run("network_change") {
    var s = Sim()
    for second in 1...46 { s.tick(1, tx: 400, handshake: second % 17 == 0) }
    check(s.cycles == 1, "one cycle before the change")
    // The path is lost and comes back: the window restarts after `pathStableSeconds`.
    s.watch.notePathEvent(at: s.uptime, interfaceChanged: false, policy: s.policy)
    for _ in 1...19 { s.tick(1, tx: 400) }
    check(s.cycles == 1, "nothing is counted for 20 s after the change")
    for _ in 1...24 { s.tick(1, tx: 400) }
    check(s.cycles == 1, "the window started after the quiet period")
    for _ in 1...3 { s.tick(1, tx: 400) }
    check(s.cycles == 2, "and completes 25 s later: \(s.cycles)")
}

run("interface_change_voids_the_verdict") {
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.verdict == .noData, "no_data on the first network")
    s.watch.notePathEvent(at: s.uptime, interfaceChanged: true, policy: s.policy)
    check(s.watch.verdict == .none, "another network: the verdict is void")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.cycles == 0 && snap.episodeTx == 0 && !snap.wouldSwitch, "and so is the episode: \(snap)")
    let out = s.tick(1, tx: 400)
    check(out.verdict == .none && out.action == .keep, "nothing is reported for the reset")
}

run("path_flapping") {
    // Path events every 4 s for a minute on a dead path.
    var s = Sim()
    for second in 1...20 { s.tick(1, tx: 400, handshake: second % 17 == 0) }
    var cyclesDuringSeries = 0
    for second in 1...60 {
        if second % 4 == 0 { s.watch.notePathEvent(at: s.uptime, interfaceChanged: false, policy: s.policy) }
        s.tick(1, tx: 400, handshake: second % 17 == 0)
        if second <= 40 { cyclesDuringSeries = max(cyclesDuringSeries, s.cycles) }
    }
    check(cyclesDuringSeries == 0, "no cycle while the series holds the watch quiet (two windows at most)")
    check(!s.everNoData && s.probesStarted.isEmpty, "no verdict in the minute of flapping")
    // After the ceiling the events no longer reset the window: cycles are counted again, and a
    // path that keeps flapping every 4 s cannot blind the watch.
    for second in 1...70 {
        if second % 4 == 0 { s.watch.notePathEvent(at: s.uptime, interfaceChanged: false, policy: s.policy) }
        if second == 4 || second == 14 { s.heal() }
        s.tick(1, tx: 400)
    }
    check(s.cycles == 3 && s.probesStarted.count == 1, "a whole chain completed during the cool-down despite the events: \(s.cycles)")
    // A change of the physical interface is never ignored.
    s.watch.notePathEvent(at: s.uptime, interfaceChanged: true, policy: s.policy)
    check(s.cycles == 0, "another network voids the chain even in the cool-down")
}

run("path_unsatisfied") {
    var s = Sim()
    s.env.pathSatisfied = false
    for _ in 1...300 { s.tick(1, tx: 500) }
    check(s.cycles == 0 && !s.everJudged, "an unsatisfied path is never judged")
}

run("captive_network") {
    var s = Sim()
    s.sanityAnswer = .captive
    s.deadPath(seconds: 160)
    check(s.firstReport(.captive) != nil && !s.everNoData, "a login page is `captive`, not no_data: \(s.reports)")
    check(s.probesStarted.isEmpty, "no probe through the tunnel when the network itself is in question")
    check(!s.watch.snapshot(policy: s.policy).wouldSwitch, "nobody would be moved")
}

run("network_dead") {
    var s = Sim()
    s.sanityAnswer = .noReply
    s.deadPath(seconds: 160)
    check(s.firstReport(.network) != nil && !s.everNoData && s.probesStarted.isEmpty, "no reply past the tunnel is `network`: \(s.reports)")
    // The bypass check is repeated, but slowly.
    s.deadPath(seconds: 300, firstSecond: 161)
    check(s.sanityChecks >= 2 && s.sanityChecks <= 4, "re-asked, but no more often than every 2 minutes: \(s.sanityChecks)")
    // The network returns: the probe runs and judges.
    s.sanityAnswer = .ok
    s.deadPath(seconds: 200, firstSecond: 461)
    check(s.watch.verdict == .noData, "after the network returned the tunnel is judged: \(s.watch.verdict)")
}

run("sanity_never_answers") {
    var s = Sim()
    s.sanityAnswer = nil
    s.deadPath(seconds: 300)
    check(!s.everNoData && s.probesStarted.isEmpty && s.verdicts.last == .suspect, "without a bypass result there is only a suspicion")
}

run("sanity_not_required_bit") {
    var p = basePolicy()
    p.sanityRequired = false
    var s = Sim(p)
    s.sanityAnswer = nil
    s.deadPath(seconds: 130)
    check(s.sanityChecks == 0 && s.watch.verdict == .noData, "the policy bit lets the probe judge alone")
}

run("ipv6_only_cellular") {
    // The function takes counters only: no address, no family, no endpoint. The same counters on
    // an IPv6-only cellular network give the same verdict; nothing in the inputs could differ.
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.verdict == .noData, "counters alone decide")
    let fields = Mirror(reflecting: TribeDataWatchSample(txBytes: 0, rxBytes: 0, lastHandshakeSec: 0, uptime: 0, wall: 0)).children.compactMap { $0.label }
    check(fields == ["txBytes", "rxBytes", "lastHandshakeSec", "uptime", "wall"], "the sample has no address field: \(fields)")
    let envFields = Mirror(reflecting: TribeDataWatchEnv(pathSatisfied: true)).children.compactMap { $0.label }
    check(envFields == ["pathSatisfied", "healSteps", "sanity", "sanityAt", "probe", "probeAt", "probeLatencyMs", "appSeenAt"], "nor has the environment: \(envFields)")
}

run("start_grace") {
    var s = Sim()
    for _ in 1...44 { s.tick(1, tx: 1000) }
    check(s.cycles == 0, "20 s of grace, then 24 s of a window: no cycle")
    s.tick(1, tx: 1000)
    check(s.cycles == 1, "the first cycle ends 45 s after the start: \(s.cycles)")
}

run("counters_reset_after_swap") {
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.verdict == .noData, "no_data before the restart")
    let before = s.watch.snapshot(policy: s.policy)
    // The backend is restarted in place: the counters fall to zero.
    s.heal(softRestart: true)
    let out = s.tick(1)
    let after = s.watch.snapshot(policy: s.policy)
    check(out.verdict == .noData && out.action == .keep, "the drop is not progress: the verdict stays, nothing is reported")
    check(after.cycles == before.cycles && after.episodeTx == before.episodeTx && after.episodeRxData == 0, "no cycle, no bytes out of thin air: \(before) -> \(after)")
    // Without the adapter's notice the drop is still recognised (counters went down).
    var t = Sim()
    t.deadPath(seconds: 60, ladder: false)
    t.tx = 0; t.rx = 0; t.handshake = 0
    let silent = t.tick(1)
    check(silent.verdict != .recovered && t.cycles == 1, "an unannounced drop is neither data nor a cycle")
    // A new device's first handshake response is not data either.
    var u = Sim()
    u.deadPath(seconds: 130)
    u.heal(softRestart: true)
    u.tick(1, tx: 300, handshake: true)
    check(u.watch.verdict == .noData && u.count(.verdict) == 2, "the new device's handshake does not recover the verdict: \(u.reports)")
}

// MARK: - the pieces of the passive rule

run("handshake_is_not_data") {
    // 92 B together with a newer handshake time is the response itself.
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.everNoData, "handshake responses alone never restart the cycle")
    // 600 B with a newer handshake time is 88 B of data: the cycle restarts every time.
    var d = Sim()
    for second in 1...300 {
        if second == 4 { d.heal() }
        if second == 14 { d.heal() }
        d.tick(1, tx: 400, rx: second % 17 == 0 ? 508 : 0, handshake: second % 17 == 0)
    }
    check(d.cycles == 0 && !d.everJudged, "data next to a handshake is data: \(d.cycles)")
    // 148 B next to a handshake (a response, or the server's own initiation) is the handshake;
    // one byte more is data.
    var e = Sim()
    for second in 1...130 {
        if second == 4 { e.heal() }
        if second == 14 { e.heal() }
        e.tick(1, tx: 400, rx: second % 17 == 0 ? 56 : 0, handshake: second % 17 == 0)
    }
    check(e.everNoData, "the allowance covers 148 B")
    var g = Sim()
    for second in 1...300 {
        if second == 4 { g.heal() }
        if second == 14 { g.heal() }
        g.tick(1, tx: 400, rx: second % 17 == 0 ? 57 : 0, handshake: second % 17 == 0)
    }
    check(g.cycles == 0 && !g.everJudged, "149 B next to a handshake carry one byte of data")
    // Bytes WITHOUT a newer handshake time are always data, however few.
    var f = Sim()
    for second in 1...300 { f.tick(1, tx: 400, rx: second % 20 == 0 ? 1 : 0) }
    check(f.cycles == 0, "one byte of data restarts the cycle")
}

run("trickle_does_not_recover") {
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.verdict == .noData, "no_data first")
    // 200 B of data after every handshake for ten minutes: 7 KB in total (above the allowance).
    for second in 1...600 {
        s.tick(1, tx: 400, rx: second % 17 == 0 ? 200 : 0, handshake: second % 17 == 0)
    }
    check(s.watch.verdict == .noData && s.count(.verdict) == 2, "drops below 16 KiB do not end the verdict: \(s.reports)")
    check(!s.verdicts.contains(.recovered), "never reported as recovered")
}

run("sixteen_kib_recovers") {
    var s = Sim()
    s.deadPath(seconds: 130)
    s.tick(1, tx: 400, rx: 16383)
    check(s.watch.verdict == .noData, "one byte short of 16 KiB")
    let out = s.tick(1, tx: 400, rx: 1)
    check(out.verdict == .recovered && out.action == .report && out.report == .verdict, "16 KiB end the verdict: \(out)")
    check(s.watch.verdict == .none, "`recovered` is an event, the state is `none`")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.recoveredWallMs > 0 && snap.lastNoDataWallMs > 0 && snap.recoveredWallMs > snap.lastNoDataWallMs && snap.sinceWallMs == 0, "the snapshot remembers both moments: \(snap)")
    let next = s.tick(1, tx: 400, rx: 4000)
    check(next.verdict == .none && next.action == .keep, "reported once")
}

run("dead_cycles_must_be_consecutive") {
    // Two dead cycles, then a pause in demand longer than the chain gap, then two more.
    var p = basePolicy()
    p.minHealSteps = 0
    var s = Sim(p)
    for _ in 1...70 { s.tick(1, tx: 500) }
    check(s.cycles == 2, "two cycles: \(s.cycles)")
    for _ in 1...60 { s.tick(1) }
    for _ in 1...55 { s.tick(1, tx: 500) }
    check(s.cycles <= 2 && s.probesStarted.isEmpty, "the chain started over after the pause: \(s.cycles)")
    for _ in 1...25 { s.tick(1, tx: 500) }
    check(s.cycles == 3 && s.probesStarted.count == 1, "the third in a row asks the probe: \(s.cycles)")
}

run("chain_gap_boundary") {
    var p = basePolicy()
    p.minHealSteps = 0
    // A pause of exactly the gap keeps the chain; one tick more breaks it.
    for (pause, expected) in [(30, 2), (31, 1)] {
        var s = Sim(p)
        for _ in 1...45 { s.tick(1, tx: 500) }
        check(s.cycles == 1, "first cycle")
        // One byte of data restarts the window; the next window starts `pause` seconds later.
        for _ in 1...(pause - 1) { s.tick(1) }
        s.tick(1, rx: 1)
        for _ in 1...25 { s.tick(1, tx: 500) }
        check(s.cycles == expected, "pause \(pause) s -> chain \(s.cycles), expected \(expected)")
    }
}

run("demand_threshold_boundary") {
    var p = basePolicy()
    p.minHealSteps = 0
    var below = Sim(p)
    for _ in 1...200 { below.tick(1, tx: 40) }   // 1000 B per 25 s
    check(below.cycles == 0, "1000 B per cycle is not demand")
    var at = Sim(p)
    for _ in 1...45 { at.tick(1, tx: 41) }       // 1025 B per 25 s
    check(at.cycles == 1, "1025 B per cycle is")
}

run("episode_demand_required") {
    var p = basePolicy()
    p.minHealSteps = 0
    p.minEpisodeTxBytes = 20_000
    var s = Sim(p)
    for _ in 1...99 { s.tick(1, tx: 200) }       // three cycles of 5000 B, then 4 s for the checks
    check(s.cycles == 3 && s.probesStarted.isEmpty && s.sanityChecks == 0, "three cycles but under 20 KB sent: nobody is asked yet")
    for _ in 1...30 { s.tick(1, tx: 200) }
    check(s.probesStarted.count == 1, "the fourth cycle brings the episode over 20 KB")
}

run("heal_steps_required") {
    // Without the same-node treatment the node is not judged.
    var s = Sim()
    s.deadPath(seconds: 200, ladder: false)
    check(s.cycles >= 3 && s.probesStarted.isEmpty && !s.everNoData, "three dead cycles, no heal steps: no probe")
    check(s.verdicts.last == .suspect, "only a suspicion")
    // One step is not two.
    var one = Sim()
    one.heal()
    one.deadPath(seconds: 110, ladder: false)
    check(one.probesStarted.isEmpty, "one heal step is not enough")
    // The ladder's steps come at 4 s and 14 s of the stall, BEFORE the first 25 s cycle is
    // complete (and here before the start grace is over). Counted only from the end of the first
    // dead cycle they would never be seen: this is the test that fails with that counting.
    var early = Sim()
    early.deadPath(seconds: 100, ladder: true)
    check(early.probesStarted.count == 1, "steps done before the first cycle completed count: \(early.probesStarted)")
    check(early.probesStarted[0].at - early.startedAt <= 96, "as soon as the third cycle is complete: \(early.probesStarted[0].at - early.startedAt)")
    check(early.watch.snapshot(policy: early.policy).healSteps == 3, "the steps at 4 s, 14 s and 44 s are within the heal window")
    // Steps older than the heal window do not count as treatment of THIS stall.
    var old = Sim()
    old.heal(); old.heal()
    for _ in 1...260 { old.tick(1) }
    old.deadPath(seconds: 110, ladder: false, firstSecond: 261)
    check(old.cycles >= 3 && old.probesStarted.isEmpty, "heal steps older than five minutes are history: \(old.cycles)")
    var recent = Sim()
    recent.heal(); recent.heal()
    for _ in 1...190 { recent.tick(1) }
    recent.deadPath(seconds: 110, ladder: false, firstSecond: 191)
    check(recent.probesStarted.count == 1, "the same steps within five minutes count")
    // min_heal_steps = 0 switches the requirement off.
    var p = basePolicy()
    p.minHealSteps = 0
    var free = Sim(p)
    free.deadPath(seconds: 100, ladder: false)
    check(free.probesStarted.count == 1, "0 = no requirement")
}

// MARK: - the probe is the judge

run("probe_answered_refutes") {
    var s = Sim()
    s.probeAnswer = .answered
    s.deadPath(seconds: 100)
    check(s.probesStarted.count == 1, "the passive rule asked once: \(s.probesStarted)")
    check(s.count(.refuted) == 1 && !s.everNoData, "an answered probe refutes the passive rule: \(s.reports)")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.refuted == 1 && snap.probe == .answered && snap.probeLatencyMs == 300 && snap.cycles == 0 && !snap.passive, "counted, with the latency, and the chain starts over: \(snap)")
    check(snap.verdict == .suspect && !snap.wouldSwitch, "still only a suspicion")
    let refuted = s.reports.first { $0.report == .refuted }!
    check(refuted.verdict == .suspect, "the refutation is reported with the verdict it leaves")
}

run("one_way_upload_on_a_healthy_server") {
    // One-way UDP upload: the server answers handshakes only (its keepalive is cancelled by the
    // handshake response). The passive rule is met again and again; the probe answers every time.
    var s = Sim()
    s.probeAnswer = .answered
    for second in 1...1200 {
        if second % 40 == 4 { s.heal() }
        // The answer to the probe is itself a little inbound data.
        let reply: UInt64 = s.probesStarted.last.map { s.uptime - $0.at < 1 } ?? false ? 100 : 0
        s.tick(1, tx: 3000, rx: reply, handshake: second % 15 == 0)
    }
    check(!s.everNoData && !s.verdicts.contains(.unconfirmed), "a healthy path is never no_data: \(s.reports.map { $0.verdict })")
    check(s.count(.refuted) == s.probesStarted.count && s.probesStarted.count >= 1, "every probe was answered and counted")
    check(s.probesStarted.count <= 3, "the episode's probe limit holds: \(s.probesStarted.count)")
}

run("probe_silent_confirms") {
    var s = Sim()
    s.deadPath(seconds: 100)
    let asked = s.probesStarted[0].at
    let judged = s.reports.first { $0.report == .verdict && $0.verdict == .noData }!.at
    check(judged - asked >= 4 && judged - asked <= 5, "no_data comes with the probe's timeout: \(judged - asked)")
    check(!s.verdicts.prefix(while: { $0 != .noData }).contains(.unconfirmed), "nothing is called unconfirmed while the probe runs")
}

run("probe_started_once") {
    var s = Sim()
    s.probeAnswer = nil // the provider never reports back
    s.deadPath(seconds: 100)
    check(s.probesStarted.count == 1, "one request while the probe is in flight: \(s.probesStarted.count)")
    s.deadPath(seconds: 12, firstSecond: 101)
    check(s.verdicts.contains(.unconfirmed) && !s.everNoData, "a lost probe is written off after its timeout and slack: unconfirmed")
    check(s.probesStarted.count == 2 && s.watch.snapshot(policy: s.policy).probe == .pending, "and asked again, within the limits: \(s.probesStarted.count)")
}

run("probe_not_sent_is_not_silent") {
    var s = Sim()
    s.probeAnswer = .notSent
    s.deadPath(seconds: 200)
    check(!s.everNoData && s.watch.verdict == .unconfirmed, "a probe that never left is not evidence: \(s.watch.verdict)")
    check(s.probesStarted.count == 3, "retried up to the episode's limit: \(s.probesStarted.count)")
    check(!s.watch.snapshot(policy: s.policy).wouldSwitch, "an unconfirmed verdict never marks a switch")
}

run("probe_unavailable") {
    var s = Sim()
    s.env.probe = .unavailable
    s.deadPath(seconds: 130)
    check(s.probesStarted.isEmpty && s.watch.verdict == .unconfirmed, "no probe in this session: the passive verdict is labelled unconfirmed")
    check(s.firstReport(.unconfirmed) != nil && !s.everNoData, "and reported as such")
}

run("probe_off_by_policy") {
    var p = basePolicy()
    p.probeEnabled = false
    var s = Sim(p)
    s.deadPath(seconds: 130)
    check(s.probesStarted.isEmpty && s.watch.verdict == .unconfirmed, "probe off: unconfirmed, never no_data")
}

run("probe_result_from_before_the_request_is_ignored") {
    var s = Sim()
    s.marksProbePending = false
    s.env.probe = .silent
    s.env.probeAt = s.uptime // a result of some earlier probe, still lying in the provider
    s.probeAnswer = .answered
    s.probeLatency = 3
    s.deadPath(seconds: 105)
    check(s.count(.refuted) == 1 && !s.everNoData, "only the result of the probe this watch asked for counts: \(s.reports)")
}

run("probe_disturbed_wait_is_not_judged") {
    // Inbound data arrives while the probe is in flight and the probe is reported silent: the
    // wait was disturbed, the silence proves nothing.
    var s = Sim()
    s.deadPath(seconds: 97)
    check(s.probesStarted.count == 1 && s.watch.snapshot(policy: s.policy).probe == .pending, "the probe is in flight")
    s.tick(1, tx: 400, rx: 900)
    s.deadPath(seconds: 6, firstSecond: 99)
    check(s.count(.probe) == 1 && s.reports.first { $0.report == .probe }!.verdict == .suspect, "a disturbed wait is journaled and judges nothing: \(s.reports)")
    // The rule is still met, so the probe is asked again; its undisturbed silence does judge.
    check(s.probesStarted.count == 2 && s.watch.verdict == .noData, "the second, undisturbed probe judges: \(s.probesStarted.count) \(s.watch.verdict)")
    let second = s.reports.first { $0.verdict == .noData }!.at
    check(second - s.probesStarted[1].at >= 4, "with its own full timeout")
}

run("probe_limit_per_hour") {
    var p = basePolicy()
    p.probeMaxPerHour = 2
    p.probeMaxPerEpisode = 10
    var s = Sim(p)
    s.probeAnswer = .answered
    for second in 1...3000 {
        if second % 40 == 4 { s.heal() }
        s.tick(1, tx: 3000, handshake: second % 15 == 0)
    }
    check(s.probesStarted.count == 2, "two probes in the first hour: \(s.probesStarted.count)")
    for second in 3001...4000 {
        if second % 40 == 4 { s.heal() }
        s.tick(1, tx: 3000, handshake: second % 15 == 0)
    }
    check(s.probesStarted.count >= 3, "the limit frees up an hour after the first probe: \(s.probesStarted.count)")
    // The hourly limit survives a device start: it protects the battery, not a device.
    var t = Sim(p)
    t.probeAnswer = .answered
    for second in 1...600 {
        if second % 40 == 4 { t.heal() }
        t.tick(1, tx: 3000, handshake: second % 15 == 0)
    }
    check(t.probesStarted.count == 2, "limit reached")
    t.watch.noteDeviceStarted(at: t.uptime, policy: p)
    for second in 1...600 {
        if second % 40 == 4 { t.heal() }
        t.tick(1, tx: 3000, handshake: second % 15 == 0)
    }
    check(t.probesStarted.count == 2, "a restart does not refill the hour: \(t.probesStarted.count)")
}

run("probe_limit_without_an_answer_is_unconfirmed") {
    var p = basePolicy()
    p.probeMaxPerHour = 1
    var s = Sim(p)
    s.probeAnswer = .answered
    for second in 1...100 {
        if second == 4 || second == 14 { s.heal() }
        s.tick(1, tx: 3000, handshake: second % 15 == 0)
    }
    check(s.count(.refuted) == 1, "the only probe of the hour was answered")
    // 16 KiB closes the episode; a new dead episode begins and cannot be probed.
    s.tick(1, rx: 20_000)
    for second in 1...200 {
        if second == 4 || second == 14 { s.heal() }
        s.tick(1, tx: 3000, handshake: second % 15 == 0)
    }
    check(s.probesStarted.count == 1 && s.watch.verdict == .unconfirmed, "out of probes in a NEW episode: unconfirmed, not no_data: \(s.watch.verdict)")
}

run("low_inbound_trigger") {
    // Keepalives and drops arrive (the passive rule never fires), user data does not: 2 KB/s out,
    // 40 B in every 10 s.
    var s = Sim()
    for second in 1...146 { s.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    check(s.cycles == 0, "the passive rule sees inbound data and stays quiet")
    check(s.probesStarted.count == 2 && s.probesStarted.allSatisfy { $0.reason == .lowRx }, "one probe per suspect window: \(s.probesStarted)")
    check(s.count(.probe) == 2 && s.count(.verdict) == 0 && !s.everJudged, "its result is reported and is not a verdict: \(s.reports)")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.probe == .silent && snap.probeReason == .lowRx && snap.verdict == .none && snap.refuted == 0, "snapshot: \(snap)")
    // An ordinary download, an idle tunnel and a small upload with acknowledgements do not trigger it.
    var download = Sim()
    for _ in 1...200 { download.tick(1, tx: 3000, rx: 80_000) }
    var idle = Sim()
    for second in 1...600 { idle.tick(1, tx: second % 25 == 0 ? 44 : 0) }
    var upload = Sim()
    for _ in 1...200 { upload.tick(1, tx: 1000, rx: 26) } // 60 KB out a minute
    check(download.probesStarted.isEmpty && idle.probesStarted.isEmpty && upload.probesStarted.isEmpty, "no probe on healthy traffic")
    // The boundaries: 64 KiB out and under 4 KiB in.
    var p = basePolicy()
    p.suspectMinTxBytes = 60_000
    var edge = Sim(p)
    for second in 1...81 { edge.tick(1, tx: 1000, rx: second % 2 == 0 ? 136 : 0) } // 60 KB out, 4080 B in per minute
    check(edge.probesStarted.count == 1, "just under the inbound bound triggers: \(edge.probesStarted.count)")
    var over = Sim(p)
    for second in 1...81 { over.tick(1, tx: 1000, rx: second % 2 == 0 ? 137 : 0) } // 4110 B in per minute
    check(over.probesStarted.isEmpty, "just over it does not")
}

// MARK: - who acts

run("app_alive_defers_switch") {
    var s = Sim()
    s.env.appSeenAt = s.uptime
    for second in 1...130 {
        if second == 4 || second == 14 { s.heal() }
        s.env.appSeenAt = s.uptime + 1 // the app polls the status every second
        s.tick(1, tx: 400, handshake: second % 17 == 0)
    }
    check(s.watch.verdict == .noData, "the verdict does not depend on the app")
    var snap = s.watch.snapshot(policy: s.policy)
    check(!snap.wouldSwitch && snap.appAlive && s.count(.wouldSwitch) == 0, "while the app is alive it decides: \(snap)")
    // The app is suspended: after 10 s of silence the shadow mark turns on, once.
    for _ in 1...10 { s.tick(1, tx: 400) }
    check(!s.watch.snapshot(policy: s.policy).wouldSwitch, "exactly 10 s of silence: still alive")
    let out = s.tick(1, tx: 400)
    snap = s.watch.snapshot(policy: s.policy)
    check(out.action == .report && out.report == .wouldSwitch && out.wouldSwitch && snap.wouldSwitch && !snap.appAlive, "the mark is reported: \(out)")
    for _ in 1...30 { s.tick(1, tx: 400) }
    check(s.count(.wouldSwitch) == 1, "once")
}

run("shadow_mode") {
    // Layer 2 on or off, this version only reports.
    for switchOn in [false, true] {
        var p = basePolicy()
        p.switchEnabled = switchOn
        var s = Sim(p)
        s.deadPath(seconds: 400)
        check(s.watch.verdict == .noData && s.watch.snapshot(policy: p).wouldSwitch, "verdict and shadow mark (switch flag \(switchOn))")
        check(Set(s.actions.map { "\($0)" }) == ["keep", "report"], "only keep and report: \(Set(s.actions.map { "\($0)" }))")
    }
}

run("kill_switch_at_run_time") {
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.verdict == .noData, "no_data")
    s.policy = TribeDataWatchPolicy.disabled
    let out = s.tick(1, tx: 400)
    check(out == TribeDataWatchOutput.idle && s.watch == TribeDataWatch(), "the policy going off clears everything at the next sample")
    s.policy = basePolicy()
    for second in 1...80 { s.tick(1, tx: 400, handshake: second % 17 == 0) }
    check(s.watch.verdict != .noData, "and a later enable starts from scratch")
}

run("report_is_edge_triggered") {
    var s = Sim()
    s.deadPath(seconds: 600)
    check(s.count(.verdict) == 2, "suspect once, no_data once in ten minutes of the same dead path: \(s.reports)")
    check(s.reports.map { $0.verdict } == [.suspect, .noData], "in that order")
    check(s.probesStarted.count == 1 && s.sanityChecks == 1, "a standing no_data asks nobody again: \(s.probesStarted.count) probes, \(s.sanityChecks) checks")
}

run("suspect_ends_quietly") {
    // One dead cycle, then the demand ends: the suspicion goes away after the idle time, unreported.
    var s = Sim()
    for _ in 1...45 { s.tick(1, tx: 400) }
    check(s.watch.verdict == .suspect, "one cycle is a suspicion")
    for _ in 1...119 { s.tick(1) }
    check(s.watch.verdict == .suspect, "119 s without a new cycle: the episode is still open")
    for _ in 1...3 { s.tick(1) }
    check(s.watch.verdict == .none && s.count(.verdict) == 1, "after 120 s it is closed without a report: \(s.reports)")
}

run("stale_chain_is_not_judged") {
    // Three dead cycles, the node not treated; the demand ends; a minute later the ladder's steps
    // arrive. The chain is history by then: nobody is asked.
    var s = Sim()
    s.deadPath(seconds: 100, ladder: false)
    check(s.cycles == 3 && s.probesStarted.isEmpty, "three cycles, no heal steps")
    // The last seconds of demand complete a fourth cycle at 120 s; then nothing is sent.
    for _ in 1...90 { s.tick(1) }
    check(s.cycles == 4, "four cycles in the chain: \(s.cycles)")
    s.heal(); s.heal()
    for _ in 1...10 { s.tick(1) }
    check(s.probesStarted.isEmpty && s.sanityChecks == 0, "heal steps 70 s after the last cycle do not revive the chain")
    // The same steps while the chain is alive do.
    var live = Sim()
    live.deadPath(seconds: 100, ladder: false)
    live.heal(); live.heal()
    for _ in 1...4 { live.tick(1, tx: 390) }
    check(live.probesStarted.count == 1, "while the chain is alive they complete the rule")
}

run("restart_announced_by_the_adapter") {
    // The new device's counters may be HIGHER than the old ones (a short-lived old device): only
    // the adapter's notice tells that they start from zero.
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.verdict == .noData && s.rx >= 92 && s.rx < 1000, "no_data, a few handshake responses in rx: \(s.rx)")
    s.heal(softRestart: true)
    s.tx = 500_000          // above the old device's counters
    s.rx = 16_390           // just over 16 KiB received by the NEW device; less than that above the old rx
    let out = s.tick(1)
    check(out.verdict == .recovered, "the whole of the new device's rx is its delta: \(out.verdict)")
    // A new device's handshake is a handshake even when its time is not newer than the old one's
    // (same second, or the wall clock stepped back).
    var t = Sim()
    t.deadPath(seconds: 130)
    let oldHandshake = t.handshake
    t.heal(softRestart: true)
    t.tx = 400; t.rx = 92; t.handshake = oldHandshake
    for _ in 1...200 {
        t.tick(1, tx: 400)
    }
    check(t.watch.verdict == .noData && !t.verdicts.contains(.recovered), "92 B with the new device's first handshake are not data")
    check(t.watch.snapshot(policy: t.policy).episodeRxData == 0, "and are not counted as inbound data of the episode")
}

run("zero_graces") {
    // With the graces switched off the explicit restarts of the cycle are all that is left.
    var p = basePolicy()
    p.wakeGraceSeconds = 0
    p.pathStableSeconds = 0
    p.minHealSteps = 0
    var s = Sim(p)
    for _ in 1...40 { s.tick(1, tx: 400) }          // 20 s grace + 20 s of a window
    s.tick(1, tx: 400, sleep: 600)                   // the phone slept inside the window
    for _ in 1...10 { s.tick(1, tx: 400) }
    check(s.cycles == 0, "the window restarted at the wake-up: 11 s are not a cycle")
    for _ in 1...15 { s.tick(1, tx: 400) }
    check(s.cycles == 1, "25 s after the wake-up: \(s.cycles)")
    var t = Sim(p)
    for _ in 1...40 { t.tick(1, tx: 400) }
    t.watch.notePathEvent(at: t.uptime, interfaceChanged: false, policy: p)
    for _ in 1...10 { t.tick(1, tx: 400) }
    check(t.cycles == 0, "a path change restarts the window even with no quiet time")
    for _ in 1...16 { t.tick(1, tx: 400) }
    check(t.cycles == 1, "and the cycle counts from the change: \(t.cycles)")
}

run("snapshot_of_a_switched_off_watch") {
    var s = Sim()
    s.deadPath(seconds: 130)
    check(s.watch.snapshot(policy: s.policy).verdict == .noData, "no_data")
    // The policy went off; the adapter has not stepped yet. The status reply must already be empty.
    check(s.watch.snapshot(policy: TribeDataWatchPolicy.disabled) == TribeDataWatchSnapshot(), "a switched-off watch shows nothing")
}

run("snapshot_dictionary_contract") {
    var s = Sim()
    s.deadPath(seconds: 101)
    let d = s.watch.snapshot(policy: s.policy).asDictionary
    let keys = Set(d.keys)
    let expected: Set<String> = ["enabled", "verdict", "since_ms", "passive", "cycles", "ep_s", "tx", "rx_data", "heal_steps", "sanity",
                                 "probe", "probe_reason", "probe_ms", "probe_at_ms", "probes_episode", "probes_hour", "refuted",
                                 "would_switch", "app_alive", "last_no_data_ms", "recovered_ms"]
    check(keys == expected, "keys of the status block: \(keys.symmetricDifference(expected))")
    check(d["verdict"] as? String == "no_data" && d["passive"] as? String == "no_data" && d["probe"] as? String == "silent", "labels: \(d)")
    check(d["probe_reason"] as? String == "passive" && d["sanity"] as? String == "ok" && d["enabled"] as? Bool == true, "labels 2")
    check(JSONSerialization.isValidJSONObject(d), "the block is JSON")
    check(TribeDataVerdict.noData.rawValue == "no_data" && TribeDataVerdict.unconfirmed.rawValue == "unconfirmed"
          && TribeProbeResult.notSent.rawValue == "not_sent" && TribeProbeReason.lowRx.rawValue == "low_rx"
          && TribeSanityResult.noReply.rawValue == "no_reply" && TribeDataWatchReport.wouldSwitch.rawValue == "would_switch", "wire labels are pinned")
}

if failures == 0 {
    print("TribeDataWatch: all tests passed")
} else {
    print("TribeDataWatch: \(failures) check(s) FAILED")
    exit(1)
}

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
    /// `.noSession` is the refused start: it is known at once.
    var probeAnswer: TribeProbeResult? = .silent
    var probeLatency: TimeInterval = 0.3
    /// The answer to a probe told as silent arrives this long after the verdict; nil = never.
    var lateAnswerAfter: TimeInterval?
    private var lateDue: TimeInterval?
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
    /// Stage 2: the nodes of the world (id -> passes data), what the adapter answers to a command,
    /// and what the arbiter ordered.
    var nodes: [String: Bool] = [:]
    /// The plan's candidates in order, and the node of the profile (the provider offers the plan's
    /// nodes except the current one, and the profile's node whenever the tunnel is not on it).
    var plan: [String] = []
    var home = ""
    var healResult = TribeCommandResult.performed
    var switchResult = TribeCommandResult.performed
    var commands: [(at: TimeInterval, command: TribeWatchCommand)] = []
    var exhausted: [TimeInterval] = []

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
            if answer == .silent, let after = lateAnswerAfter { lateDue = due + after }
        }
        if let due = lateDue, uptime >= due {
            env.lateAnswerAt = due
            lateDue = nil
        }
        let out = watch.step(TribeDataWatchSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: handshake, uptime: uptime, wall: wall),
                             env: env, policy: policy)
        if out.needsSanityCheck {
            // The rule asks once per check (and again only when a check did not report back).
            sanityChecks += 1
            if sanityDue == nil { sanityDue = uptime + 1 }
        }
        if let reason = out.startProbe {
            probesStarted.append((uptime, reason))
            if marksProbePending { env.probe = .pending }
            probeDue = uptime + (probeAnswer == .answered ? probeLatency : probeAnswer == .noSession ? 0 : policy.probeTimeoutSeconds)
        }
        if out.action == .report, let report = out.report { reports.append((uptime, report, out.verdict)) }
        if out.action != .keep && out.report == nil { failures += 1; print("FAIL \(currentTest): report without a kind") }
        verdicts.append(out.verdict)
        actions.append(out.action)
        if out.exhausted { exhausted.append(uptime) }
        if let command = out.command {
            // The adapter executes a command on the same tick and tells the result back.
            commands.append((uptime, command))
            switch command {
            case .heal(let kind):
                if healResult == .performed && kind == .softRestart { heal(softRestart: true) }
                watch.noteCommandResult(command, result: healResult, at: uptime, policy: policy)
            case .switchPeer(let node, _):
                if switchResult == .performed {
                    env.nodeId = node
                    env.candidates = plan.filter { $0 != node } + (node != home && !plan.contains(home) ? [home] : [])
                    tx = 0
                    rx = 0
                    handshake = 0
                }
                watch.noteCommandResult(command, result: switchResult, at: uptime, policy: policy)
            }
        }
        return out
    }

    /// Stage 2 world: steady outbound demand. A node that passes data answers the probe and sends
    /// data back; a dead one completes handshakes (the 13.11 picture) and nothing else. A node
    /// listed in `mute` does not even shake hands.
    mutating func world(seconds: Int, txPerSecond: UInt64 = 400, mute: Set<String> = []) {
        for _ in 1...seconds {
            let alive = nodes[env.nodeId] ?? false
            let muted = mute.contains(env.nodeId)
            let second = Int(elapsed) + 1
            probeAnswer = alive ? .answered : (muted && handshake == 0 ? .noSession : .silent)
            tick(1, tx: txPerSecond, rx: alive ? 3000 : 0,
                 handshake: !muted && (handshake == 0 ? second % 3 == 0 : second % 17 == 0))
        }
    }
    var switches: [String] { commands.compactMap { if case .switchPeer(let node, _) = $0.command { return node } else { return nil } } }
    var heals: [TribeWatchHeal] { commands.compactMap { if case .heal(let kind) = $0.command { return kind } else { return nil } } }

    /// The stall ladder performed a same-node heal step. A fresh port is invisible to the watch;
    /// a soft restart is a new device on the same node (counters and handshake start over).
    mutating func heal(softRestart: Bool = false) {
        if softRestart {
            watch.noteBackendRestarted(at: uptime, policy: policy)
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
    check(p.pathStableSeconds == 20 && p.startGraceSeconds == 20 && p.wakeGraceSeconds == 10, "graces")
    check(p.appAliveSeconds == 10 && p.maxSwitches == 5, "app alive 10 s, 5 switches")
    check(p.sanityRequired && p.probeEnabled, "both checks are on when the watch is on")
    check(p.suspectWindowSeconds == 60 && p.suspectMinTxBytes == 65536 && p.suspectMaxRxBytes == 4096, "low-inbound trigger")
    check(p.probeTimeoutSeconds == 4 && p.probeMaxPerEpisode == 3 && p.probeMaxPerHour == 12, "probe timeout and limits")
    check(p.probeLowRxMaxPerHour == 2 && p.sanityMaxPerHour == 12, "the low-inbound trigger's own budget; bypass requests per hour")
    let labels = Mirror(reflecting: p).children.compactMap { $0.label }
    check(!labels.contains("minHealSteps"), "the verdict has no heal-step condition: \(labels)")
    check(p.switchHealSteps == 2 && p.trialProbeMaxPerHour == 30, "stage 2: two same-node heals before a switch, 30 trial probes an hour")
    check(TribeDataWatchPolicy.healTrialSeconds == 10 && TribeDataWatchPolicy.roundPauseSeconds == [300, 600, 1200, 1800], "stage 2: trial wait and the pauses between rounds")
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
        + #""numbers":{"ios_tw_probe_low_rx_max_per_hour":0,"ios_tw_probe":0,"ios_tw_sanity_required":1,"ios_tw_max_switches":1,"#
        + #""ios_tw_cycle_chain_gap_s":0,"ios_tw_wake_grace_s":true,"ios_tw_path_stable_s":false,"ios_tw_cycle_s":30.0}}"#
    let object = try! JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    let p = TribeDataWatchPolicy.fromPlan(features: object["features"] as! [String: Any], numbers: object["numbers"] as! [String: Any])
    check(p.enabled && !p.switchEnabled, "true is on, the number 0 is off")
    check(p.probeLowRxMaxPerHour == 0 && !p.probeEnabled && p.sanityRequired && p.maxSwitches == 1 && p.cycleChainGapSeconds == 0, "zeros and ones stay numbers: \(p)")
    check(p.wakeGraceSeconds == 10 && p.pathStableSeconds == 20, "a boolean where a number belongs is junk: default")
    check(p.cycleSeconds == 30, "a float is a number")
    let on = try! JSONSerialization.jsonObject(with: Data(#"{"a":1,"b":"true","c":false,"d":2}"#.utf8)) as! [String: Any]
    func flag(_ key: String) -> Bool { TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": on[key] as Any], numbers: [:]).enabled }
    check(flag("a") && flag("b") && !flag("c") && !flag("d") && !flag("missing"), "flag forms from JSON")
}

run("policy_clamps") {
    let names = ["ios_tw_cycle_s", "ios_tw_cycle_min_tx_bytes", "ios_tw_dead_cycles", "ios_tw_cycle_chain_gap_s",
                 "ios_tw_recover_rx_bytes", "ios_tw_min_episode_tx_bytes", "ios_tw_hs_rx_allowance_bytes",
                 "ios_tw_hs_tx_allowance_bytes", "ios_tw_path_stable_s", "ios_tw_start_grace_s",
                 "ios_tw_wake_grace_s", "ios_tw_app_alive_s", "ios_tw_max_switches", "ios_tw_suspect_window_s",
                 "ios_tw_suspect_min_tx_bytes", "ios_tw_suspect_max_rx_bytes", "ios_tw_probe_timeout_ms",
                 "ios_tw_probe_max_per_episode", "ios_tw_probe_max_per_hour", "ios_tw_probe_low_rx_max_per_hour",
                 "ios_tw_sanity_max_per_hour", "ios_tw_sanity_required", "ios_tw_probe",
                 "ios_tw_switch_heal_steps", "ios_tw_trial_probe_max_per_hour"]
    func all(_ value: Any) -> TribeDataWatchPolicy {
        TribeDataWatchPolicy.fromPlan(features: ["ios_tunnel_watch": true], numbers: Dictionary(uniqueKeysWithValues: names.map { ($0, value) }))
    }
    let low = all(-1_000_000)
    check(low.cycleSeconds == 10 && low.cycleMinTxBytes == 1024 && low.deadCycles == 2 && low.cycleChainGapSeconds == 0, "lower clamps 1: \(low)")
    check(low.recoverRxBytes == 1024 && low.minEpisodeTxBytes == 2048 && low.handshakeRxAllowanceBytes == 92 && low.handshakeTxAllowanceBytes == 148, "lower clamps 2")
    check(low.pathStableSeconds == 0 && low.startGraceSeconds == 5 && low.wakeGraceSeconds == 0, "lower clamps 3")
    check(low.appAliveSeconds == 3 && low.maxSwitches == 0 && low.suspectWindowSeconds == 30 && low.suspectMinTxBytes == 4096 && low.suspectMaxRxBytes == 0, "lower clamps 4")
    check(low.probeTimeoutSeconds == 1 && low.probeMaxPerEpisode == 1 && low.probeMaxPerHour == 1, "lower clamps 5")
    check(low.probeLowRxMaxPerHour == 0 && low.sanityMaxPerHour == 1, "lower clamps 6")
    check(low.switchHealSteps == 0 && low.trialProbeMaxPerHour == 1, "lower clamps 7")
    check(!low.sanityRequired && !low.probeEnabled, "0-clamped bits are off")
    let high = all(1e12)
    check(high.cycleSeconds == 120 && high.cycleMinTxBytes == 1_048_576 && high.deadCycles == 20 && high.cycleChainGapSeconds == 300, "upper clamps 1")
    check(high.recoverRxBytes == 1_048_576 && high.minEpisodeTxBytes == 1_048_576 && high.handshakeRxAllowanceBytes == 4096 && high.handshakeTxAllowanceBytes == 8192, "upper clamps 2")
    check(high.pathStableSeconds == 120 && high.startGraceSeconds == 120 && high.wakeGraceSeconds == 60, "upper clamps 3")
    check(high.appAliveSeconds == 60 && high.maxSwitches == 5 && high.suspectWindowSeconds == 600 && high.suspectMinTxBytes == 16_777_216 && high.suspectMaxRxBytes == 1_048_576, "upper clamps 4")
    check(high.probeTimeoutSeconds == 15 && high.probeMaxPerEpisode == 10 && high.probeMaxPerHour == 60, "upper clamps 5")
    check(high.probeLowRxMaxPerHour == 12 && high.sanityMaxPerHour == 60, "upper clamps 6")
    check(high.switchHealSteps == 2 && high.trialProbeMaxPerHour == 60, "upper clamps 7")
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
    // With the switch key off nobody is moved and nothing is treated.
    check(s.commands.isEmpty && s.exhausted.isEmpty, "no command without the switch key")
}

run("megafon_13_11_replay_cycle_15") {
    var p = basePolicy()
    p.cycleSeconds = 15
    var s = Sim(p)
    s.deadPath(seconds: 100)
    let noDataAt = s.firstReport(.noData)
    // 20 s grace + 3 x 15 s + 4 s probe; a handshake inside the wait voids the first probe once
    // (10 s pause, 4 s more).
    check(noDataAt != nil && noDataAt! <= 71 + 14, "about 70 s, one void probe later at most: \(String(describing: noDataAt))")
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
    // Review finding A7: the end of a verdict is told, or the status reply, the statistics line
    // and the shared file would keep `no_data` for a network the phone has left.
    let reportsBefore = s.reports.count
    let out = s.tick(1, tx: 400)
    check(out.verdict == .none && out.action == .report && out.report == .verdict, "the reset is reported at the next sample: \(out)")
    s.tick(1, tx: 400)
    check(s.reports.count == reportsBefore + 1, "once")
    // Review mutant M11: a probe asked on the previous network says nothing about the new one.
    var p = Sim()
    p.probeAnswer = .answered
    p.probeLatency = 3
    p.deadPath(seconds: 97, handshakeEvery: 1000)
    check(p.probesStarted.count == 1 && p.watch.snapshot(policy: p.policy).probe == .pending, "the probe is in flight")
    p.watch.notePathEvent(at: p.uptime, interfaceChanged: true, policy: p.policy)
    for _ in 1...5 { p.tick(1, tx: 400) }
    let ps = p.watch.snapshot(policy: p.policy)
    check(ps.refuted == 0 && p.count(.refuted) == 0 && ps.probe != .pending, "its answer is not counted on the new network: \(ps.refuted) \(ps.probe)")
    // The same for a device that was started anew (the first sample of a new device only primes).
    var d = Sim()
    d.deadPath(seconds: 130)
    d.watch.noteDeviceStarted(at: d.uptime, policy: d.policy)
    d.tx = 0; d.rx = 0; d.handshake = 0
    let before = d.reports.count
    d.tick(1, tx: 100)
    d.tick(1, tx: 100)
    check(d.reports.count == before + 1 && d.reports.last?.verdict == TribeDataVerdict.none, "a new device: the old verdict is taken back in the outputs: \(d.reports.suffix(2))")
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
    s.deadPath(seconds: 170)
    check(!s.everNoData && s.probesStarted.isEmpty && s.verdicts.last == .suspect, "without a bypass result there is only a suspicion")
    // Review finding A4: the request is not repeated without end. One per 15 s while unanswered,
    // 12 per hour at most; then the verdict is `unconfirmed` and nobody is asked any more.
    s.deadPath(seconds: 3000, firstSecond: 171)
    check(s.sanityChecks == 12, "twelve bypass requests in the hour, not one more: \(s.sanityChecks)")
    check(s.watch.verdict == .unconfirmed && s.probesStarted.isEmpty, "the network could not be checked: unconfirmed: \(s.watch.verdict)")
    var capped = basePolicy()
    capped.sanityMaxPerHour = 2
    var c = Sim(capped)
    c.sanityAnswer = nil
    c.deadPath(seconds: 400)
    check(c.sanityChecks == 2, "the cap is a policy number: \(c.sanityChecks)")
    check(c.watch.snapshot(policy: c.policy).sanityLastHour == 2, "and the snapshot shows what was spent")
    // The cap is per hour: an hour later a new dead episode may ask again.
    for _ in 1...3700 { c.tick(1) }
    check(c.watch.snapshot(policy: c.policy).sanityLastHour == 0, "the hour has passed")
    let before = c.sanityChecks
    c.deadPath(seconds: 120, ladder: false)
    check(c.sanityChecks > before, "the cap frees up after an hour: \(c.sanityChecks)")
    // Nothing is asked inside a quiet period: the request is not repeated while the path is gone.
    var q = Sim()
    q.sanityAnswer = nil
    q.deadPath(seconds: 97, ladder: false)
    check(q.sanityChecks == 1, "asked once when the rule was met: \(q.sanityChecks)")
    q.env.pathSatisfied = false
    for _ in 1...25 { q.tick(1, tx: 400) }
    check(q.sanityChecks == 1 && q.probesStarted.isEmpty, "no request while the path is not satisfied: \(q.sanityChecks)")
    check(!q.watch.snapshot(policy: q.policy).passive, "and the rule is not shown as met there")
}

run("unconfirmed_asks_nobody") {
    // Review vector V8b: a dead path for an hour with no probe in the session. The bypass request
    // used to be repeated every ~30 s (110 an hour, in plain HTTP outside the tunnel).
    var s = Sim()
    s.env.probe = .unavailable
    s.marksProbePending = false
    s.deadPath(seconds: 3600)
    check(s.watch.verdict == .unconfirmed && s.probesStarted.isEmpty, "no judge: unconfirmed")
    check(s.sanityChecks == 1, "one bypass request to tell the network from the node, then silence: \(s.sanityChecks)")
    // The same when the probes of the episode are spent without a judgement.
    var n = Sim()
    n.probeAnswer = .notSent
    n.deadPath(seconds: 3600)
    check(n.watch.verdict == .unconfirmed && n.probesStarted.count == 3, "three probes that never left: unconfirmed")
    check(n.sanityChecks <= 4, "a bypass request per probe at most, none after the last one: \(n.sanityChecks)")
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
    check(envFields == ["pathSatisfied", "sanity", "sanityAt", "probe", "probeAt", "probeLatencyMs", "lateAnswerAt", "appSeenAt", "nodeId", "candidates"], "nor has the environment (node ids are labels): \(envFields)")
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
    let p = basePolicy()
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
    let p = basePolicy()
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
    let p = basePolicy()
    var below = Sim(p)
    for _ in 1...200 { below.tick(1, tx: 40) }   // 1000 B per 25 s
    check(below.cycles == 0, "1000 B per cycle is not demand")
    var at = Sim(p)
    for _ in 1...45 { at.tick(1, tx: 41) }       // 1025 B per 25 s
    check(at.cycles == 1, "1025 B per cycle is")
}

run("episode_demand_required") {
    var p = basePolicy()
    p.minEpisodeTxBytes = 20_000
    var s = Sim(p)
    for _ in 1...99 { s.tick(1, tx: 200) }       // three cycles of 5000 B, then 4 s for the checks
    check(s.cycles == 3 && s.probesStarted.isEmpty && s.sanityChecks == 0, "three cycles but under 20 KB sent: nobody is asked yet")
    for _ in 1...30 { s.tick(1, tx: 200) }
    check(s.probesStarted.count == 1, "the fourth cycle brings the episode over 20 KB")
}

run("verdict_does_not_wait_for_the_ladder") {
    // Review finding A1: below ~270 B/s the stall ladder never steps (a completed handshake is
    // progress for it, and it needs 4096 B since the last progress). The verdict used to require
    // two ladder steps and stayed at `suspect` for half an hour on the very path of 13.11.
    // Now nothing of the ladder is an input: the judge is the probe.
    for rate in [60, 120, 200, 260] as [UInt64] {
        var s = Sim()
        s.deadPath(seconds: 1800, txPerSecond: rate, handshakeEvery: 15, ladder: false)
        check(s.watch.verdict == .noData, "\(rate) B/s for 30 min must be judged: \(s.watch.verdict)")
        check((s.firstReport(.noData) ?? 9999) <= 125, "\(rate) B/s: no_data within about two minutes, got \(String(describing: s.firstReport(.noData)))")
        check(s.probesStarted.count >= 1 && s.probesStarted.count <= 3, "\(rate) B/s: a few probes, not a storm: \(s.probesStarted.count)")
        check(s.watch.snapshot(policy: s.policy).evidence == .probe, "confirmed by the silent probe")
    }
    // The floor of the rule itself: under 1024 B per 25 s there is no demand to judge by.
    var idle = Sim()
    idle.deadPath(seconds: 1800, txPerSecond: 40, handshakeEvery: 15, ladder: false)
    check(!idle.everJudged, "40 B/s is below the demand of a cycle: nothing is judged")
    // With the ladder working (higher demand) the outcome is the same and no slower.
    var ladder = Sim()
    ladder.deadPath(seconds: 130, ladder: true)
    var plain = Sim()
    plain.deadPath(seconds: 130, ladder: false)
    check(ladder.watch.verdict == .noData && plain.watch.verdict == .noData, "with and without ladder steps")
    check(plain.firstReport(.noData) == ladder.firstReport(.noData), "the ladder's fresh port and its first restart (inside the start grace) change nothing: \(String(describing: plain.firstReport(.noData))) vs \(String(describing: ladder.firstReport(.noData)))")
}

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
    check(!s.everNoData && s.count(.probe) == 1 && s.watch.snapshot(policy: s.policy).probe == .notSent, "a lost probe is written off after its timeout and slack, as not sent: \(s.reports)")
    s.deadPath(seconds: 12, firstSecond: 113)
    check(s.probesStarted.count == 2 && s.watch.snapshot(policy: s.policy).probe == .pending, "and asked again after a short pause, within the limits: \(s.probesStarted.count)")
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
    // wait was disturbed, the silence proves nothing. It is counted apart from `refuted`.
    var s = Sim()
    s.deadPath(seconds: 97, handshakeEvery: 1000)
    check(s.probesStarted.count == 1 && s.watch.snapshot(policy: s.policy).probe == .pending, "the probe is in flight")
    s.tick(1, tx: 400, rx: 900)
    s.deadPath(seconds: 6, handshakeEvery: 1000, firstSecond: 99)
    check(s.count(.disturbed) == 1 && s.reports.first { $0.report == .disturbed }?.verdict == .suspect, "a disturbed wait is journaled and judges nothing: \(s.reports)")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.disturbed == 1 && snap.refuted == 0 && !s.everNoData, "counted as disturbed, not as refuted, and no verdict: \(snap.disturbed) \(snap.refuted)")
    // The rule is still met, so the probe is asked again after a short pause; its undisturbed
    // silence does judge.
    s.deadPath(seconds: 40, handshakeEvery: 1000, firstSecond: 105)
    check(s.probesStarted.count == 2 && s.watch.verdict == .noData, "the second, undisturbed probe judges: \(s.probesStarted.count) \(s.watch.verdict)")
    check(s.probesStarted.count == 2 && s.probesStarted[1].at - s.probesStarted[0].at >= 4 + 10, "not sooner than the pause after a void probe")
    let second = s.reports.first { $0.verdict == .noData }?.at ?? 0
    check(s.probesStarted.count == 2 && second - s.probesStarted[1].at >= 4, "with its own full timeout")
}

run("probe_void_when_the_session_changes_during_the_wait") {
    // Review finding A2: "silent" used to be taken at face value. A new handshake during the
    // wait means the engine began another session: the packet may have sat staged.
    var s = Sim()
    s.deadPath(seconds: 97, handshakeEvery: 1000)
    check(s.probesStarted.count == 1, "the probe is in flight")
    s.tick(1, tx: 400, handshake: true)                    // the engine re-keys during the wait
    s.deadPath(seconds: 5, handshakeEvery: 1000, firstSecond: 99)
    check(!s.everNoData && s.count(.disturbed) == 1, "a handshake during the wait voids the probe: \(s.reports)")
    // A device restart during the wait voids it too, and no probe is asked inside the grace.
    var r = Sim()
    r.deadPath(seconds: 97, handshakeEvery: 1000)
    r.heal(softRestart: true)
    let restartAt = r.uptime
    r.deadPath(seconds: 60, handshakeEvery: 1000, firstSecond: 98)
    check(r.count(.disturbed) == 1, "a restart during the wait voids the probe: \(r.reports)")
    check(r.probesStarted.count >= 2 && r.probesStarted[1].at - restartAt >= r.policy.startGraceSeconds, "the next probe waits out the start grace of the new device: \(r.probesStarted)")
    // A path event during the wait voids it as well.
    var pth = Sim()
    pth.deadPath(seconds: 97, handshakeEvery: 1000)
    pth.watch.notePathEvent(at: pth.uptime, interfaceChanged: false, policy: pth.policy)
    pth.deadPath(seconds: 5, handshakeEvery: 1000, firstSecond: 98)
    check(!pth.everNoData && pth.verdicts.last != .noData, "a path event during the wait: no verdict from that probe")
    // Review mutant M03: a quiet period that began and ended inside the wait (the path was gone
    // for a moment and no path event was delivered for it).
    var blink = Sim()
    blink.deadPath(seconds: 97, handshakeEvery: 1000)
    blink.env.pathSatisfied = false
    blink.tick(1, tx: 400)
    blink.env.pathSatisfied = true
    blink.deadPath(seconds: 5, handshakeEvery: 1000, firstSecond: 99)
    check(!blink.everNoData && blink.count(.disturbed) == 1, "a quiet moment during the wait voids the probe: \(blink.reports)")
    // A device that came up unannounced during the wait (the counters fell).
    var fell = Sim()
    fell.deadPath(seconds: 97, handshakeEvery: 1000)
    fell.tx = 0; fell.rx = 0; fell.handshake = 0
    fell.deadPath(seconds: 6, handshakeEvery: 1000, firstSecond: 98)
    check(!fell.everNoData && fell.count(.disturbed) == 1, "another device during the wait voids the probe: \(fell.reports)")
    // A path event inside the cool-down after a flapping path opens no quiet period; it voids
    // the probe all the same.
    var coolPolicy = basePolicy()
    coolPolicy.pathStableSeconds = 120
    var cool = Sim(coolPolicy)
    for _ in 1...30 { cool.tick(1, tx: 400) }
    cool.watch.notePathEvent(at: cool.uptime, interfaceChanged: false, policy: cool.policy)
    for _ in 1...119 { cool.tick(1, tx: 400) }
    cool.watch.notePathEvent(at: cool.uptime, interfaceChanged: false, policy: cool.policy)
    for _ in 1...11 { cool.tick(1, tx: 400) }
    cool.watch.notePathEvent(at: cool.uptime, interfaceChanged: false, policy: cool.policy) // the series hits its ceiling: cool-down
    for _ in 1...400 where cool.probesStarted.isEmpty { cool.tick(1, tx: 400) }
    check(cool.probesStarted.count == 1 && cool.elapsed < 360, "the probe is asked inside the cool-down that follows the quiet period: \(cool.elapsed)")
    cool.watch.notePathEvent(at: cool.uptime, interfaceChanged: false, policy: cool.policy)
    for _ in 1...6 { cool.tick(1, tx: 400) }
    check(!cool.everNoData && cool.count(.disturbed) == 1, "a path event in the cool-down voids the probe: \(cool.reports)")
    // The Go layer's own "staged" (the device took the packet without a usable keypair).
    var st = Sim()
    st.probeAnswer = .staged
    st.deadPath(seconds: 103, handshakeEvery: 1000)
    check(!st.everNoData && st.count(.disturbed) == 1 && st.watch.snapshot(policy: st.policy).disturbed == 1, "staged is not silent: \(st.reports)")
}

run("no_session_is_judged_by_the_handshake") {
    // The engine holds no keypair that may send: a probe cannot leave the phone. The start is
    // refused at once (nothing is injected, no budget is spent) and the judge is the engine's own
    // handshake - initiations going out for a whole chain of dead cycles and not one response.
    var s = Sim()
    s.probeAnswer = .noSession
    for _ in 1...130 { s.tick(1, tx: 100) }               // 2.5 KB of handshake retries per cycle, never a handshake
    let snap = s.watch.snapshot(policy: s.policy)
    check(s.watch.verdict == .noData && snap.evidence == .handshake, "no session for a whole chain: no_data by the handshake: \(s.watch.verdict) \(snap.evidence)")
    check(snap.probesInEpisode == 0 && snap.probesLastHour == 0, "a refused start spends no budget: \(snap.probesInEpisode) \(snap.probesLastHour)")
    check((s.firstReport(.noData) ?? 0) <= 100, "as soon as the passive rule is met: \(String(describing: s.firstReport(.noData)))")
    // Review vector V2d: healthy one-way upload, soft restart, the first handshake of the new
    // device takes 6 s. Asked 2 s after the restart the old code said no_data / would_switch.
    var v = Sim()
    v.probeAnswer = .answered
    for second in 1...93 { v.tick(1, tx: 50_000, handshake: second % 15 == 0) }
    v.heal(softRestart: true)                              // the ladder's second step
    v.probeAnswer = .noSession                             // no keypair yet
    for _ in 1...6 { v.tick(1, tx: 50_000) }
    v.tick(1, tx: 50_000, handshake: true)                 // the new device shook hands after 6 s
    v.probeAnswer = .answered
    for second in 101...400 { v.tick(1, tx: 50_000, handshake: second % 15 == 0) }
    let vs = v.watch.snapshot(policy: v.policy)
    check(!v.everNoData && !v.verdicts.contains(.unconfirmed), "a healthy upload is never no_data: \(v.reports)")
    check(v.reports.allSatisfy { !($0.report == .wouldSwitch) } && !vs.wouldSwitch, "and never would_switch")
    check(vs.refuted >= 1, "the answered probe refutes the passive rule: \(vs.refuted)")
    // No session yet, but the device is young (restarted 30 s ago): not a whole chain of silence.
    var young = Sim()
    young.probeAnswer = .noSession
    for second in 1...110 { young.tick(1, tx: 400, handshake: second == 40) }
    check(!young.everNoData && young.probesStarted.count >= 2, "70 s since the last handshake: the rule waits and asks again: \(young.probesStarted.count)")
    check(young.count(.disturbed) == 0 && young.watch.snapshot(policy: young.policy).disturbed == 0, "a refused start while the engine still tries is not a void probe")
    young.heal(softRestart: true)
    for _ in 1...40 { young.tick(1, tx: 400) }
    check(!young.everNoData, "40 s without a handshake after a restart is not yet the engine's verdict (the silence of the previous device does not count)")
    for _ in 1...60 { young.tick(1, tx: 400) }
    check(young.watch.verdict == .noData && young.watch.snapshot(policy: young.policy).evidence == .handshake, "75 s of unanswered handshakes is")
}

run("late_answer_refutes_the_verdict") {
    // Review vector V7: a slow healthy path - the probe is told silent, its reply arrives 2 s later.
    var s = Sim()
    s.lateAnswerAfter = 2
    s.deadPath(seconds: 101, handshakeEvery: 1000)
    check(s.watch.verdict == .noData, "silent in time: no_data")
    s.deadPath(seconds: 3, handshakeEvery: 1000, firstSecond: 102)
    let snap = s.watch.snapshot(policy: s.policy)
    check(s.watch.verdict != .noData && snap.refuted == 1 && s.count(.refuted) == 1, "the late answer takes the verdict back and counts as refuted: \(s.watch.verdict) \(snap.refuted)")
    check(!snap.wouldSwitch && snap.evidence == .none, "nothing to act on any more")
    // The provider goes on telling the time of that late answer. The path then really dies: the
    // next silent probe stands, the old late answer does not take it back.
    s.lateAnswerAfter = nil
    s.deadPath(seconds: 120, handshakeEvery: 1000, firstSecond: 105)
    check(s.watch.verdict == .noData && s.watch.snapshot(policy: s.policy).refuted == 1, "one late answer refutes one verdict: \(s.watch.verdict) \(s.watch.snapshot(policy: s.policy).refuted)")
    // A late answer does not touch a verdict the handshake confirmed (no probe was sent for it).
    var h = Sim()
    h.probeAnswer = .noSession
    for _ in 1...110 { h.tick(1, tx: 100) }
    h.env.lateAnswerAt = h.uptime
    h.tick(1, tx: 100)
    check(h.watch.verdict == .noData, "no probe was in the air for this verdict")
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
    check(s.probesStarted.count == 1 && s.probesStarted.allSatisfy { $0.reason == .lowRx }, "one probe, then the trigger backs off: \(s.probesStarted)")
    check(s.count(.probe) == 1 && s.count(.verdict) == 0 && !s.everJudged, "its result is reported and is not a verdict: \(s.reports)")
    for second in 147...760 { s.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    check(s.probesStarted.count == 2, "the next one ten minutes later: \(s.probesStarted.map { $0.at - s.startedAt })")
    for second in 761...3600 { s.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    check(s.probesStarted.count == 2 && s.watch.snapshot(policy: s.policy).lowRxProbesLastHour == 2, "two an hour is its whole budget: \(s.probesStarted.count)")
    check(s.watch.snapshot(policy: s.policy).probesLastHour == 0, "and none of them is charged to the dead-path budget")
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

run("low_rx_does_not_spend_the_dead_path_budget") {
    // Review vector V10 (finding A5): a steady slow upload, 1.2 KB/s out with acknowledgements only
    // coming back, for 20 minutes. The low-inbound trigger used to take a probe every minute: 12
    // in 20 minutes, the whole hourly budget, so that when the path then died the verdict was
    // `unconfirmed` for the rest of the hour.
    var s = Sim()
    s.probeAnswer = .answered
    for second in 1...1200 { s.tick(1, tx: 1200, rx: 40, handshake: second % 120 == 0) }
    let low = s.probesStarted.filter { $0.reason == .lowRx }.count
    check(low >= 1 && low <= 2, "one probe, then a back-off of ten minutes and more: \(low)")
    check(s.watch.snapshot(policy: s.policy).probesLastHour == 0, "the dead-path budget is untouched")
    check(!s.everJudged, "an answered low-inbound probe is no verdict")
    // The path dies: handshakes pass, nothing else comes back. The judge is still there.
    s.probeAnswer = .silent
    for second in 1201...1400 { s.tick(1, tx: 1200, handshake: second % 15 == 0) }
    check(s.watch.verdict == .noData, "the dead path is judged at once, not `unconfirmed` for an hour: \(s.watch.verdict)")
    check(s.firstReport(.noData).map { $0 - 1200 <= 110 } ?? false, "within the usual time: \(String(describing: s.firstReport(.noData)))")
    // The back-off doubles after every answered probe and starts over after one that was not.
    var b = Sim()
    b.policy.probeLowRxMaxPerHour = 12
    b.probeAnswer = .answered
    for second in 1...3600 { b.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    let gaps = zip(b.probesStarted.dropFirst(), b.probesStarted).map { $0.0.at - $0.1.at }
    check(b.probesStarted.count == 3 && gaps.count == 2 && gaps[0] >= 600 && gaps[0] < 720 && gaps[1] >= 1200 && gaps[1] < 1320, "10 min, then 20 (the third pause of 40 min ends after the hour): \(gaps)")
    // Five hours of it: the pause grows to an hour and no further, and the hourly budget frees up.
    var long = Sim()
    long.probeAnswer = .answered
    for second in 1...18_000 { long.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    let longGaps = zip(long.probesStarted.dropFirst(), long.probesStarted).map { $0.0.at - $0.1.at }
    check(long.probesStarted.count >= 5, "it goes on hour after hour: \(long.probesStarted.count)")
    check(longGaps.allSatisfy { $0 < 3720 } && (longGaps.last ?? 0) >= 3600, "the pause stops growing at an hour: \(longGaps)")
    // A probe that was not answered starts the back-off over.
    var reset = Sim()
    reset.policy.probeLowRxMaxPerHour = 12
    reset.probeAnswer = .answered
    for second in 1...700 { reset.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    reset.probeAnswer = .silent
    for second in 701...2400 where reset.probesStarted.count < 3 { reset.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    let resetGaps = zip(reset.probesStarted.dropFirst(), reset.probesStarted).map { $0.0.at - $0.1.at }
    check(resetGaps.count == 2 && resetGaps[1] >= 600 && resetGaps[1] < 720, "after a silent one the next comes ten minutes later, not twenty: \(resetGaps)")
    // The trigger can be switched off by its own budget.
    var off = Sim()
    off.policy.probeLowRxMaxPerHour = 0
    for second in 1...600 { off.tick(1, tx: 2000, rx: second % 10 == 0 ? 40 : 0) }
    check(off.probesStarted.isEmpty, "budget 0: no low-inbound probes")
}

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
    // The switch key off: only reports, whatever the plan offers. The key on with nothing to
    // switch to: the same.
    for (switchOn, candidates) in [(false, ["12", "9"]), (true, [])] as [(Bool, [String])] {
        var p = basePolicy()
        p.switchEnabled = switchOn
        var s = Sim(p)
        s.env.nodeId = "16"
        s.env.candidates = candidates
        s.deadPath(seconds: 400)
        check(s.watch.verdict == .noData && s.watch.snapshot(policy: p).wouldSwitch, "verdict and shadow mark (switch flag \(switchOn))")
        check(s.commands.isEmpty && s.exhausted.isEmpty, "nothing is treated and nobody is moved (switch flag \(switchOn))")
        let snap = s.watch.snapshot(policy: p)
        check(!snap.arbiterActive && snap.arbiterHeals == 0 && snap.trialProbesLastHour == 0, "the arbiter never woke up")
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

run("suspect_end_is_reported") {
    // One dead cycle, then the demand ends: the suspicion goes away after the idle time. Review
    // finding A7: that end is told too, so no output keeps a verdict that is no longer held.
    var s = Sim()
    for _ in 1...45 { s.tick(1, tx: 400) }
    check(s.watch.verdict == .suspect, "one cycle is a suspicion")
    for _ in 1...119 { s.tick(1) }
    check(s.watch.verdict == .suspect, "119 s without a new cycle: the episode is still open")
    for _ in 1...3 { s.tick(1) }
    check(s.watch.verdict == .none && s.count(.verdict) == 2 && s.reports.last?.verdict == TribeDataVerdict.none, "after 120 s it is closed and the outputs are told: \(s.reports)")
}

run("stale_chain_is_not_judged") {
    // Three dead cycles that do not yet make the rule (too little sent in the episode); the demand
    // ends; a minute later a burst brings the episode over its threshold. The chain is history by
    // then: nobody is asked.
    var p = basePolicy()
    p.minEpisodeTxBytes = 60_000
    var s = Sim(p)
    s.deadPath(seconds: 100, handshakeEvery: 1000, ladder: false)
    check(s.cycles == 3 && s.probesStarted.isEmpty && s.sanityChecks == 0, "three cycles, the episode still under its demand: \(s.cycles)")
    // The last seconds of demand complete a fourth cycle at 120 s; then nothing is sent.
    for _ in 1...90 { s.tick(1) }
    check(s.cycles == 4, "four cycles in the chain: \(s.cycles)")
    s.tick(1, tx: 60_000)
    for _ in 1...10 { s.tick(1) }
    check(s.probesStarted.isEmpty && s.sanityChecks == 0, "demand that arrives 70 s after the last cycle does not revive the chain")
    // The same burst while the chain is alive completes the rule.
    var live = Sim(p)
    live.deadPath(seconds: 100, handshakeEvery: 1000, ladder: false)
    live.tick(1, tx: 60_000)
    for _ in 1...4 { live.tick(1, tx: 390) }
    check(live.probesStarted.count == 1, "while the chain is alive it does")
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
    let expected: Set<String> = ["enabled", "verdict", "since_ms", "passive", "cycles", "ep_s", "tx", "rx_data", "sanity",
                                 "probe", "probe_reason", "probe_ms", "probe_at_ms", "probes_episode", "probes_hour",
                                 "probes_low_rx_hour", "sanity_hour", "refuted", "disturbed", "evidence",
                                 "would_switch", "app_alive", "last_no_data_ms", "recovered_ms",
                                 "arb_active", "arb_round", "arb_heals", "arb_switches", "arb_tried", "arb_trial",
                                 "arb_exhausted", "probes_trial_hour"]
    check(keys == expected, "keys of the status block: \(keys.symmetricDifference(expected))")
    check(d["verdict"] as? String == "no_data" && d["passive"] as? String == "no_data" && d["probe"] as? String == "silent", "labels: \(d)")
    check(d["probe_reason"] as? String == "passive" && d["sanity"] as? String == "ok" && d["enabled"] as? Bool == true, "labels 2")
    check(JSONSerialization.isValidJSONObject(d), "the block is JSON")
    check(TribeDataVerdict.noData.rawValue == "no_data" && TribeDataVerdict.unconfirmed.rawValue == "unconfirmed"
          && TribeProbeResult.notSent.rawValue == "not_sent" && TribeProbeReason.lowRx.rawValue == "low_rx"
          && TribeSanityResult.noReply.rawValue == "no_reply" && TribeDataWatchReport.wouldSwitch.rawValue == "would_switch", "wire labels are pinned")
    check(TribeProbeReason.trial.rawValue == "trial" && TribeWatchHeal.freshPort.rawValue == "fresh_port" && TribeWatchHeal.softRestart.rawValue == "soft_restart"
          && TribeSwitchReason.noData.rawValue == "no_data" && TribeSwitchReason.best.rawValue == "exhausted_best"
          && TribeCommandResult.performed.rawValue == "performed" && TribeDataWatchReport.trial.rawValue == "trial", "stage 2 labels are pinned")
}

// MARK: - stage 2: the arbiter

/// A phone in the pocket on node 16, the app asleep, the switch key on, the plan offers `candidates`.
func switching(_ candidates: [String] = ["12", "9"], alive: Set<String> = [], _ tune: (inout TribeDataWatchPolicy) -> Void = { _ in }) -> Sim {
    var p = basePolicy()
    p.switchEnabled = true
    tune(&p)
    var s = Sim(p)
    s.env.nodeId = "16"
    s.home = "16"
    s.plan = candidates
    s.env.candidates = candidates.filter { $0 != "16" }
    for node in ["16"] + candidates { s.nodes[node] = alive.contains(node) }
    return s
}

run("arbiter_heals_the_node_then_leaves_it") {
    // The 13.11 path with a working node in the plan: no_data by a silent probe, then the two
    // same-node heals the arbiter runs ITSELF (each judged by its own probe), then the switch; the
    // new node gets its own grace and its own probe before it is trusted.
    var s = switching(["12", "9"], alive: ["12"])
    s.world(seconds: 240)
    check(s.heals == [.freshPort, .softRestart], "both heals, in the ladder's order: \(s.heals)")
    check(s.switches == ["12"], "then the first candidate of the plan, once: \(s.switches)")
    let noDataAt = s.reports.first { $0.verdict == .noData }?.at ?? 0
    check(s.commands.count == 3 && s.commands[0].at == noDataAt, "the first heal on the tick of the verdict: \(s.commands.map { $0.at - s.startedAt })")
    check(s.commands.count == 3 && s.commands[1].at - s.commands[0].at >= TribeDataWatchPolicy.healTrialSeconds + s.policy.probeTimeoutSeconds,
          "the fresh port is given 10 s and a whole probe before the next step")
    check(s.commands.count == 3 && s.commands[2].at - s.commands[1].at >= s.policy.startGraceSeconds + s.policy.probeTimeoutSeconds,
          "the restarted device is given its start grace and a whole probe")
    let trials = s.probesStarted.filter { $0.reason == .trial }
    check(trials.count >= 3, "a trial probe after every action (a re-key during a wait voids one and it is asked again): \(trials.count)")
    let onNew = trials.filter { s.commands.count == 3 && $0.at > s.commands[2].at }
    check(onNew.count >= 1 && onNew[0].at - s.commands[2].at >= s.policy.startGraceSeconds, "the new node is not probed inside its start grace")
    check(s.count(.trial) == 1 && s.reports.last { $0.report == .trial }?.verdict != .noData, "the new node answered: it is trusted")
    let snap = s.watch.snapshot(policy: s.policy)
    check(s.watch.verdict != .noData && !snap.arbiterActive && !snap.arbiterTrial && snap.refuted == 0, "the round is over and nothing counts as a false decision: \(snap.refuted)")
    check(snap.probesLastHour == 1 && snap.trialProbesLastHour == trials.count, "trials have a budget of their own: \(snap.probesLastHour) \(snap.trialProbesLastHour)")
    check(s.env.nodeId == "12" && s.exhausted.isEmpty, "the tunnel stays on the node that works")
    let after = s.commands.count
    s.world(seconds: 600)
    check(s.commands.count == after, "and nothing more is done while it works")
}

run("heal_that_cures_keeps_the_node") {
    // The soft restart helps: the node answers its trial probe. Nobody is moved, the verdict is
    // taken back, and it is not a false decision of the passive rule.
    var s = switching(["12"])
    for _ in 1...400 where s.heals.count < 2 { s.world(seconds: 1) }
    check(s.heals == [.freshPort, .softRestart] && s.switches.isEmpty, "treated twice, not moved yet")
    // The node answers again, the user simply has nothing coming in right now.
    for second in 1...60 {
        s.probeAnswer = .answered
        s.tick(1, tx: 400, handshake: second == 2)
    }
    check(s.switches.isEmpty && s.env.nodeId == "16", "the cured node is kept")
    check(s.count(.trial) == 1 && s.watch.verdict != .noData, "the verdict is taken back by the trial probe")
    let snap = s.watch.snapshot(policy: s.policy)
    check(snap.refuted == 0 && !snap.arbiterActive, "a heal that worked is not a refuted verdict: \(snap.refuted)")
}

run("heals_the_shared_budget_refuses_are_not_waited_for") {
    // The stall ladder has already spent the episode's fresh port and restart: the adapter's shared
    // budget refuses, nothing changed, so there is nothing to wait for.
    var s = switching(["12"], alive: ["12"])
    s.healResult = .denied
    s.world(seconds: 130)
    check(s.heals == [.freshPort, .softRestart] && s.switches == ["12"], "both asked, both refused, then the switch: \(s.commands)")
    check(s.commands.count == 3 && s.commands[2].at - s.commands[0].at <= 2, "on consecutive ticks: \(s.commands.map { $0.at - s.startedAt })")
    var none = switching(["12"], alive: ["12"]) { $0.switchHealSteps = 0 }
    none.world(seconds: 130)
    check(none.heals.isEmpty && none.switches == ["12"], "ios_tw_switch_heal_steps = 0: the switch at once")
    var one = switching(["12"], alive: ["12"]) { $0.switchHealSteps = 1 }
    one.world(seconds: 160)
    check(one.heals == [.freshPort] && one.switches == ["12"], "one step = the fresh port only: \(one.heals)")
}

run("living_app_decides_itself") {
    // The app polls the status: the extension reports and does nothing.
    var s = switching(["12"], alive: ["12"])
    for second in 1...200 {
        s.env.appSeenAt = s.uptime
        s.probeAnswer = .silent
        s.tick(1, tx: 400, handshake: second % 17 == 0)
    }
    check(s.watch.verdict == .noData && s.commands.isEmpty, "verdict yes, command no")
    check(!s.watch.snapshot(policy: s.policy).arbiterActive, "the arbiter is not even started")
    // The app wakes up in the middle of a round: the round is forgotten at once.
    var w = switching(["12", "9", "3"])
    for _ in 1...400 where w.switches.count < 1 { w.world(seconds: 1) }
    check(w.switches == ["12"] && w.watch.snapshot(policy: w.policy).arbiterActive, "a round is in progress")
    let before = w.commands.count
    for _ in 1...200 {
        w.env.appSeenAt = w.uptime
        w.world(seconds: 1)
    }
    check(w.commands.count == before, "not one more command while the app is alive: \(w.commands.count - before)")
    let snap = w.watch.snapshot(policy: w.policy)
    check(!snap.arbiterActive && snap.arbiterTried == 0 && snap.arbiterHeals == 0 && !snap.arbiterTrial, "the round is forgotten: \(snap)")
    // The app falls asleep again and the node is still dead: a new round from the start.
    w.env.appSeenAt = w.uptime
    w.world(seconds: 300)
    check(w.commands.count > before, "asleep again: the arbiter starts over")
}

run("candidates_in_plan_order_each_with_its_own_trial") {
    var s = switching(["12", "9", "3"], alive: ["3"]) { $0.switchHealSteps = 0 }
    s.world(seconds: 400)
    check(s.switches == ["12", "9", "3"], "the plan's order, none twice: \(s.switches)")
    let at = s.commands.map { $0.at }
    check(at.count == 3 && at[1] - at[0] >= s.policy.startGraceSeconds + s.policy.probeTimeoutSeconds
          && at[2] - at[1] >= s.policy.startGraceSeconds + s.policy.probeTimeoutSeconds, "a node is left only after its grace and its own silent probe: \(at.map { $0 - s.startedAt })")
    check(s.env.nodeId == "3" && s.watch.verdict != .noData && s.exhausted.isEmpty, "stops at the first node that works")
    // The current node is never a candidate for itself, even if the plan lists it.
    var own = switching(["16", "12"], alive: ["12"]) { $0.switchHealSteps = 0 }
    own.world(seconds: 200)
    check(own.switches == ["12"], "the node the tunnel is on is skipped: \(own.switches)")
}

run("max_switches_bounds_a_round") {
    var s = switching(["12", "9", "3", "7", "5"]) { $0.switchHealSteps = 0; $0.maxSwitches = 2 }
    s.world(seconds: 400)
    check(s.switches.prefix(2) == ["12", "9"] && s.exhausted.count == 1, "two switches, then exhausted: \(s.switches) \(s.exhausted.count)")
    var zero = switching(["12"], alive: ["12"]) { $0.maxSwitches = 0 }
    zero.world(seconds: 400)
    check(zero.commands.isEmpty && zero.watch.verdict == .noData, "ios_tw_max_switches = 0: the arbiter does nothing at all")
}

run("exhausted_stays_on_the_best_and_waits_for_the_next_round") {
    // No node of the plan works (an operator that cuts all of AmneziaWG). The tunnel goes back to
    // where the round began and tries again after 5, 10, 20, 30, 30 minutes - silently.
    var s = switching(["12", "9"]) { $0.trialProbeMaxPerHour = 60 }
    for _ in 1...600 where s.exhausted.isEmpty { s.world(seconds: 1) }
    check(s.heals.count == 2 && s.switches == ["12", "9", "16"], "both candidates, then back to where it began: \(s.switches)")
    check(s.exhausted.count == 1, "exhausted is told once: \(s.exhausted.count)")
    if case .switchPeer(_, let why)? = s.commands.last?.command { check(why == .best, "the return is marked as such") } else { check(false, "the last command is the return") }
    var snap = s.watch.snapshot(policy: s.policy)
    check(snap.arbiterExhausted && snap.arbiterRound == 1, "waiting for the next round: \(snap)")
    let first = s.exhausted[0]
    let roundOne = s.commands.count
    s.world(seconds: 295)
    check(s.commands.count == roundOne && s.exhausted.count == 1, "nothing for five minutes: \(s.commands.count - roundOne)")
    check(s.watch.verdict == .noData && s.env.nodeId == "16", "the tunnel stands on the node it went back to, the verdict stands")
    for _ in 1...600 where s.exhausted.count < 2 { s.world(seconds: 1) }
    let roundTwo = Array(s.commands.dropFirst(roundOne))
    check(roundTwo.count == 3 && (roundTwo.first?.at ?? 0) - first >= 300 && (roundTwo.first?.at ?? 0) - first < 310, "the next round five minutes later: \(roundTwo.map { $0.at - first })")
    check(s.heals.count == 2, "a later round does not treat the node again: \(s.heals.count)")
    check(Array(s.switches.suffix(3)) == ["12", "9", "16"], "the same candidates again and back: \(s.switches)")
    let second = s.exhausted[1]
    let afterTwo = s.commands.count
    s.world(seconds: 595)
    check(s.commands.count == afterTwo, "then nothing for ten minutes")
    for _ in 1...60 where s.commands.count == afterTwo { s.world(seconds: 1) }
    check(s.commands.count > afterTwo && s.commands[afterTwo].at - second >= 600, "the third round ten minutes after the second: \(s.commands.last.map { $0.at - second } ?? -1)")
    snap = s.watch.snapshot(policy: s.policy)
    check(snap.arbiterRound == 2, "rounds are counted: \(snap.arbiterRound)")
    // The node that received some data in the round is the best one.
    var b = switching(["12", "9"]) { $0.switchHealSteps = 0 }
    for _ in 1...600 where b.exhausted.isEmpty {
        b.probeAnswer = .silent
        // node 12 lets a trickle through (not enough to recover), the others nothing
        b.tick(1, tx: 400, rx: b.env.nodeId == "12" ? 20 : 0, handshake: b.handshake == 0 ? Int(b.uptime) % 3 == 0 : Int(b.uptime) % 17 == 0)
    }
    check(b.switches == ["12", "9", "12"] && b.env.nodeId == "12", "back to the node that received the most data: \(b.switches)")
    // The best is the node the tunnel is already on: no extra switch.
    var last = switching(["12"]) { $0.switchHealSteps = 0 }
    for _ in 1...600 where last.exhausted.isEmpty {
        last.probeAnswer = .silent
        last.tick(1, tx: 400, rx: last.env.nodeId == "12" ? 20 : 0, handshake: last.handshake == 0 ? Int(last.uptime) % 3 == 0 : Int(last.uptime) % 17 == 0)
    }
    check(last.switches == ["12"] && last.exhausted.count == 1 && last.env.nodeId == "12", "already on the best: it stays: \(last.switches)")
}

run("switch_that_fails_leaves_the_tunnel_where_it_is") {
    var s = switching(["12", "9"], alive: ["9"]) { $0.switchHealSteps = 0 }
    s.switchResult = .failed
    for _ in 1...200 where s.switches.isEmpty { s.world(seconds: 1) }
    check(s.switches == ["12"] && s.env.nodeId == "16" && s.watch.verdict == .noData, "the tunnel is still on 16 with its verdict")
    s.switchResult = .performed
    s.world(seconds: 60)
    check(s.switches == ["12", "9"] && s.env.nodeId == "9", "the next candidate, the failed one is not asked twice: \(s.switches)")
    check(s.commands.count == 2 && s.commands[1].at - s.commands[0].at <= 1, "at the next sample: nothing changed, nothing to wait for")
}

run("candidate_that_never_shakes_hands_is_left_by_the_handshake") {
    // Node 12 is blocked by address: the engine never gets a session, a probe cannot leave. It is
    // judged by the handshake silence, 75 s, and left.
    var s = switching(["12", "9"], alive: ["9"]) { $0.switchHealSteps = 0 }
    s.world(seconds: 300, mute: ["12"])
    check(s.switches == ["12", "9"], "left for the next one: \(s.switches)")
    check(s.commands.count == 2 && s.commands[1].at - s.commands[0].at >= s.policy.cycleSeconds * Double(s.policy.deadCycles), "not before a whole chain of handshake silence: \(s.commands.map { $0.at - s.startedAt })")
    check(s.watch.snapshot(policy: s.policy).trialProbesLastHour <= 2, "refused starts spend no trial budget: \(s.watch.snapshot(policy: s.policy).trialProbesLastHour)")
}

run("trial_probes_have_an_hourly_limit") {
    var s = switching(["12", "9", "3"]) { $0.switchHealSteps = 0; $0.trialProbeMaxPerHour = 1 }
    s.world(seconds: 115)
    check(s.switches == ["12"], "the first switch: \(s.switches)")
    s.world(seconds: 30)
    check(s.probesStarted.filter { $0.reason == .trial }.count == 1 && s.switches == ["12", "9"], "its one trial probe judged node 12: \(s.switches)")
    // The budget is spent: node 9 is not judged by a trial. The passive rule still can (75 s of
    // dead cycles and its own probe), so the round goes on, slower.
    s.world(seconds: 60)
    check(s.probesStarted.filter { $0.reason == .trial }.count == 1 && s.switches.count == 2, "no second trial probe this hour, no blind switch")
    s.world(seconds: 120)
    check(s.switches == ["12", "9", "3"], "the passive rule judged node 9 instead: \(s.switches)")
}

run("disturbed_trial_is_asked_again") {
    var s = switching(["12", "9"]) { $0.switchHealSteps = 0 }
    for _ in 1...300 where s.switches.isEmpty { s.world(seconds: 1) }
    for _ in 1...60 where s.probesStarted.last?.reason != .trial { s.world(seconds: 1) }
    check(s.probesStarted.last?.reason == .trial, "the trial probe of node 12 is in flight")
    s.probeAnswer = .silent
    s.tick(1, tx: 400, handshake: true)               // the engine re-keys during the wait: the probe is void
    for _ in 1...5 { s.probeAnswer = .silent; s.tick(1, tx: 400) }
    check(s.switches == ["12"] && s.count(.disturbed) == 1, "a void trial moves nobody: \(s.switches)")
    s.world(seconds: 40)
    check(s.switches == ["12", "9"] && s.probesStarted.filter { $0.reason == .trial }.count >= 2, "asked again, then judged: \(s.switches)")
}

run("round_ends_with_the_data_and_with_the_network") {
    // Data comes back on the node under trial (16 KiB): the round is over.
    var s = switching(["12", "9"]) { $0.switchHealSteps = 0 }
    for _ in 1...300 where s.switches.isEmpty { s.world(seconds: 1) }
    s.nodes["12"] = true
    s.world(seconds: 120)
    check(s.switches == ["12"] && !s.watch.snapshot(policy: s.policy).arbiterActive, "node 12 works: the round is over")
    // Another network in the middle of a round: the round belonged to the old one.
    var n = switching(["12", "9"]) { $0.switchHealSteps = 0 }
    for _ in 1...300 where n.switches.isEmpty { n.world(seconds: 1) }
    n.watch.notePathEvent(at: n.uptime, interfaceChanged: true, policy: n.policy)
    let snap = n.watch.snapshot(policy: n.policy)
    check(!snap.arbiterActive && !snap.arbiterTrial && snap.arbiterTried == 0, "the round is forgotten with the network: \(snap)")
    let before = n.commands.count
    n.world(seconds: 60)
    check(n.commands.count == before, "nothing is done on the new network until it is judged itself")
    // The switch key goes off in the middle of a round.
    var k = switching(["12", "9"]) { $0.switchHealSteps = 0 }
    for _ in 1...300 where k.switches.isEmpty { k.world(seconds: 1) }
    k.policy.switchEnabled = false
    let kBefore = k.commands.count
    k.world(seconds: 300)
    check(k.commands.count == kBefore && !k.watch.snapshot(policy: k.policy).arbiterActive, "key off: not one more command")
    // A device started by somebody else (the app, the system) ends the round too.
    var d = switching(["12", "9"]) { $0.switchHealSteps = 0 }
    for _ in 1...300 where d.switches.isEmpty { d.world(seconds: 1) }
    d.watch.noteDeviceStarted(at: d.uptime, policy: d.policy)
    check(!d.watch.snapshot(policy: d.policy).arbiterActive && !d.watch.snapshot(policy: d.policy).arbiterTrial, "somebody else's start: the arbiter forgets its round")
}

run("arbiter_snapshot") {
    var s = switching(["12", "9"])
    for _ in 1...300 where s.heals.count < 1 { s.world(seconds: 1) }
    var snap = s.watch.snapshot(policy: s.policy)
    check(snap.arbiterActive && snap.arbiterRound == 0 && snap.arbiterHeals == 1 && snap.arbiterSwitches == 0 && snap.arbiterTried == 1 && snap.arbiterTrial && !snap.arbiterExhausted, "after the first heal: \(snap)")
    for _ in 1...300 where s.switches.count < 1 { s.world(seconds: 1) }
    snap = s.watch.snapshot(policy: s.policy)
    check(snap.arbiterHeals == 2 && snap.arbiterSwitches == 1 && snap.arbiterTried == 2 && snap.arbiterTrial, "after the first switch: \(snap)")
    let reportsBefore = s.reports.count
    s.world(seconds: 2) // the first sample of a new device only primes the counters
    check(snap.verdict == .none && s.verdicts.last == TribeDataVerdict.none, "the verdict about the previous node does not follow the tunnel to the new one")
    check(s.reports.count == reportsBefore + 1 && s.reports.last?.verdict == TribeDataVerdict.none, "and the outputs are told so")
    let d = snap.asDictionary
    check(d["arb_active"] as? Bool == true && d["arb_heals"] as? Int == 2 && d["arb_switches"] as? Int == 1 && d["arb_tried"] as? Int == 2
          && d["arb_trial"] as? Bool == true && d["arb_exhausted"] as? Bool == false && d["arb_round"] as? Int == 0, "the status block carries the arbiter: \(d)")
    check((d["probes_trial_hour"] as? Int ?? -1) == s.probesStarted.filter { $0.reason == .trial }.count && (d["probes_trial_hour"] as? Int ?? 0) >= 2, "and its probes: \(String(describing: d["probes_trial_hour"]))")
}

if failures == 0 {
    print("TribeDataWatch: all tests passed")
} else {
    print("TribeDataWatch: \(failures) check(s) FAILED")
    exit(1)
}

// Tribe seamless roaming — executable unit test (no XCTest: compiled by plain swiftc inside the
// conan recipe build, so the adapter package cannot ship with broken roaming logic).
import Foundation

var failures = 0
func check(_ cond: Bool, _ what: String, line: Int = #line) {
    if !cond { failures += 1; print("FAIL line \(line): \(what)") }
}

let seamless = TribeRoamingPolicy.seamless
let legacy = TribeRoamingPolicy.legacy

// --- policy defaults (pinned: these are the shipped fallbacks) ---
check(seamless.keepBackendOnPathLoss, "seamless keeps backend")
check(seamless.pauseAfterUnsatisfiedSeconds == 0, "seamless never pauses by default")
check(seamless.stallProbeSeconds == 4, "stall probe 4s")
check(seamless.stallRebindSeconds == 10, "stall rebind +10s")
check(seamless.stallMinTxBytes == 4096, "min tx 4 KiB")
check(seamless.rebindCoalesceSeconds == 0.1, "coalesce 100ms")
check(!legacy.keepBackendOnPathLoss && legacy.stallProbeSeconds == 0, "legacy = upstream behaviour")

// --- parsing from NE JSON (strings; absent = seamless defaults; junk = defaults; clamps) ---
let parsedDefault = TribeRoamingPolicy.fromConfig(keepBackend: nil, pauseAfterS: nil, stallProbeS: nil, stallRebindS: nil)
check(parsedDefault == seamless, "absent keys -> seamless")
let parsedLegacy = TribeRoamingPolicy.fromConfig(keepBackend: "0", pauseAfterS: nil, stallProbeS: nil, stallRebindS: nil)
check(!parsedLegacy.keepBackendOnPathLoss, "keep=0 -> legacy pause")
check(parsedLegacy.stallProbeSeconds == 4, "keep=0 does not disable watchdog by itself")
let parsedNums = TribeRoamingPolicy.fromConfig(keepBackend: "1", pauseAfterS: "30", stallProbeS: "6", stallRebindS: "0")
check(parsedNums.pauseAfterUnsatisfiedSeconds == 30 && parsedNums.stallProbeSeconds == 6 && parsedNums.stallRebindSeconds == 0, "numbers parsed")
let parsedClamp = TribeRoamingPolicy.fromConfig(keepBackend: "1", pauseAfterS: "99999", stallProbeS: "-5", stallRebindS: "abc")
check(parsedClamp.pauseAfterUnsatisfiedSeconds == 600, "pauseAfter clamped to 600")
check(parsedClamp.stallProbeSeconds == 0, "negative probe clamps to 0 (off)")
check(parsedClamp.stallRebindSeconds == 10, "junk rebind -> default")

// --- path-loss decision ---
check(TribeRoaming.pathLossDecision(policy: legacy, legacyWouldPause: true) == .pauseNow, "legacy pauses")
check(TribeRoaming.pathLossDecision(policy: legacy, legacyWouldPause: false) == .keepBackend, "legacy grace keeps")
check(TribeRoaming.pathLossDecision(policy: seamless, legacyWouldPause: true) == .keepBackend, "seamless never pauses")
var longOffline = seamless; longOffline.pauseAfterUnsatisfiedSeconds = 30
check(TribeRoaming.pathLossDecision(policy: longOffline, legacyWouldPause: true) == .pauseAfter(30), "long-offline fallback schedules pause")
check(TribeRoaming.pathLossDecision(policy: longOffline, legacyWouldPause: false) == .keepBackend, "fallback still honours bootstrap grace")

// --- UAPI sample parsing (sums peers; unknown handshake -> 0) ---
let uapi = "private_key=aa\nlisten_port=1234\npublic_key=bb\nrx_bytes=100\ntx_bytes=250\nlast_handshake_time_sec=1700000000\npublic_key=cc\nrx_bytes=5\ntx_bytes=7\nlast_handshake_time_sec=0\n"
let sample = TribeRoaming.parseSample(uapi: uapi, at: 12)
check(sample.rxBytes == 105 && sample.txBytes == 257, "peer counters summed: \(sample)")
check(sample.lastHandshakeSec == 1700000000 && sample.at == 12, "max handshake kept")
check(TribeRoaming.parseSample(uapi: "garbage", at: 1) == TribeStallSample(txBytes: 0, rxBytes: 0, lastHandshakeSec: 0, at: 1), "garbage -> zeros")

// --- stall watchdog ---
func s(_ tx: UInt64, _ rx: UInt64, _ hs: Int64 = 100, _ at: TimeInterval) -> TribeStallSample {
    TribeStallSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: hs, at: at)
}

// idle keepalive-only tunnel: 32 B every 25 s, rx frozen -> never a stall for 30 minutes
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var fired: [TribeStallAction] = []
    var tx: UInt64 = 0
    for i in 1...72 { tx += 32; let a = t.observe(s(tx, 0, 100, Double(i) * 25), pathSatisfied: true, policy: seamless); if a != .none { fired.append(a) } }
    check(fired.isEmpty, "idle keepalive never trips watchdog: \(fired)")
}

// real traffic dies: bump at 4 s, rebind at 14 s, then silence
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var actions: [(TimeInterval, TribeStallAction)] = []
    var tx: UInt64 = 0
    for i in 1...60 { tx += 1500; let at = Double(i); let a = t.observe(s(tx, 0, 100, at), pathSatisfied: true, policy: seamless); if a != .none { actions.append((at, a)) } }
    check(actions.count == 2, "exactly two escalation steps: \(actions)")
    check(actions.first?.0 == 4 && actions.first?.1 == .bumpSockets, "bump at 4 s: \(actions)")
    check(actions.last?.0 == 14 && actions.last?.1 == .rebindPort, "rebind at 14 s: \(actions)")
    check(t.stage == 2, "exhausted stage")
    // inbound progress re-arms
    check(t.observe(s(tx + 10, 1, 100, 61), pathSatisfied: true, policy: seamless) == .none, "progress = no action")
    check(t.stage == 0, "re-armed after rx progress")
}

// a fresh handshake counts as inbound progress (idle-but-healthy tunnel)
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    var fired = false
    for i in 1...20 { tx += 1500; let hs: Int64 = i == 3 ? 200 : (i >= 3 ? 200 : 100); if t.observe(s(tx, 0, hs, Double(i)), pathSatisfied: true, policy: seamless) != .none && i <= 6 { fired = true } }
    check(!fired, "handshake at t=3 postpones the bump past t=6")
}

// path unsatisfied: watchdog stays quiet no matter how stalled
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    var fired = false
    for i in 1...30 { tx += 1500; if t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: false, policy: seamless) != .none { fired = true } }
    check(!fired, "no action while path is unsatisfied")
}

// watchdog disabled by policy
do {
    var off = seamless; off.stallProbeSeconds = 0
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    var fired = false
    for i in 1...30 { tx += 1500; if t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: off) != .none { fired = true } }
    check(!fired, "probe=0 disables watchdog")
}

// rebind stage disabled: only the bump ever fires
do {
    var noRebind = seamless; noRebind.stallRebindSeconds = 0
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    var actions: [TribeStallAction] = []
    for i in 1...60 { tx += 1500; let a = t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: noRebind); if a != .none { actions.append(a) } }
    check(actions == [.bumpSockets], "rebind=0 -> bump only: \(actions)")
}

// counter reset (backend restarted) is progress, not a stall
do {
    var t = TribeStallTracker(first: s(100000, 5000, 100, 0))
    check(t.observe(s(10, 0, 0, 5), pathSatisfied: true, policy: seamless) == .none, "counter reset tolerated")
    check(t.stage == 0, "still armed after reset")
}

// rearm after a roam rebind postpones the watchdog by a full probe window
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    for i in 1...3 { tx += 1500; _ = t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: seamless) }
    t.rearm(s(tx, 0, 100, 3))
    var firstAt: TimeInterval = -1
    for i in 4...20 { tx += 1500; if t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: seamless) == .bumpSockets { firstAt = Double(i); break } }
    check(firstAt == 7, "bump 4 s after rearm, got \(firstAt)")
}

// counters summary is stable text for logs/diag
do {
    var c = TribeRoamingCounters()
    c.pathLost += 1; c.roamBumps += 2; c.stallRebinds += 1
    check(c.summary == "path_lost=1 path_restored=0 roam_bumps=2 stall_bumps=0 stall_rebinds=1 pauses=0 resumes=0", "summary format: \(c.summary)")
    check(c.asDictionary["roam_bumps"] == 2, "dictionary export")
}

// Autonomous bootstrap is bounded without assuming that the GUI exists.
do {
    var tracker = TribeStallTracker(first: s(0, 0, 0, 0))
    check(tracker.observe(s(1024, 0, 0, 4), pathSatisfied: true, policy: seamless) == .none, "bootstrap respects built-in retries")
    check(tracker.observe(s(1024, 0, 0, 12), pathSatisfied: false, policy: seamless) == .none, "offline never heals")
    check(tracker.observe(s(1024, 0, 0, 12), pathSatisfied: true, policy: seamless) == .bumpSockets, "bootstrap local bump after retry grace")
    check(tracker.observe(s(2048, 0, 0, 30), pathSatisfied: true, policy: seamless) == .rebindPort, "bootstrap fresh port after grace")
    for time in 31...600 {
        check(tracker.observe(s(UInt64(time * 1024), 0, 0, Double(time)), pathSatisfied: true, policy: seamless) == .none, "bootstrap exhausted stays quiet")
    }
}
do {
    var budget = TribeRecoveryBudget(jitter: 2)
    check(budget.permit(at: 0, freshPort: false), "NE bump accepted")
    // tribe.7: cooldown only between actions of the same kind; the fresh-port escalation after a
    // bump is not delayed by it (tribe.6 refused it here and burned the watchdog stage).
    check(budget.permit(at: 9, freshPort: true), "fresh port right after a bump is an escalation, not a repeat")
    check(!budget.permit(at: 10, freshPort: true), "one shared second stage per episode")
    check(budget.lastDenial == .episode, "second fresh port refused as already spent")
    check(!budget.permit(at: 100, freshPort: true), "elapsed time alone does not rearm dead peer")
    budget.observe(s(100, 0, 0, 110))
    check(!budget.permit(at: 110, freshPort: false), "tx/reset alone does not rearm recovery")
    check(budget.denied == 1, "one denial streak counted once: \(budget.denied)")
    budget.observe(s(100, 1, 0, 120))
    check(budget.permit(at: 120, freshPort: true), "real inbound progress rearms")
    check(!budget.permit(at: 140, freshPort: false), "GUI fresh-port repair consumes whole episode")
    check(budget.episodeUsed == 2, "fresh port closes the episode")
}
do {
    var budget = TribeRecoveryBudget()
    for n in 0..<4 {
        budget.observe(s(100, UInt64(n + 1), 0, Double(n * 10)))
        check(budget.permit(at: Double(n * 10), freshPort: true), "progress grants episode within rolling cap")
    }
    budget.observe(s(100, 10, 0, 40))
    check(!budget.permit(at: 40, freshPort: true), "progress cannot bypass rolling energy cap")
    check(budget.lastDenial == .rollingCap, "cap reason")
    check(budget.permit(at: 120, freshPort: true), "rolling cap expires")
}
do {
    // same-kind cooldown survives an episode reset
    var budget = TribeRecoveryBudget(jitter: 0)
    check(budget.request(at: 0, kind: .bump) == nil, "bump")
    budget.observe(s(100, 1, 0, 2))
    check(budget.request(at: 5, kind: .bump) == .cooldown, "second bump 5 s later refused by cooldown")
    check(budget.request(at: 8, kind: .bump) == nil, "bump after cooldown")
}

// --- D1: arbiter (tracker + budget) — the stage moves only on permit ---
func runStall(rate: Double, jitter: Double, from: Int = 1, horizon: Int = 90, stallFrom: Int = 0,
              pre: ((inout TribeRecoveryArbiter) -> Void)? = nil) -> (performed: [(Double, TribeStallAction)], arbiter: TribeRecoveryArbiter) {
    var arbiter = TribeRecoveryArbiter(jitter: jitter)
    pre?(&arbiter)
    var performed: [(Double, TribeStallAction)] = []
    var rx: UInt64 = 5000
    for tick in from...horizon {
        let at = Double(tick)
        if tick <= stallFrom { rx += 1000 }
        let tx = UInt64(rate * at)
        if case .perform(let action) = arbiter.tick(s(tx, rx, 100, at), pathSatisfied: true, policy: seamless) {
            performed.append((at, action))
        }
    }
    return (performed, arbiter)
}

// Matrix: outbound 300 B/s ... 50 KB/s x budget jitter 0..2. The fresh-port stage must be reached
// in the FIRST episode in every cell (tribe.6: at 450-1000 B/s the 8-10 s cooldown refused it and
// the stage was burned). VoIP-like rates (>= 1 KB/s) heal within ~15 s of the stall onset.
for rate in [300.0, 450, 600, 750, 1000, 2000, 5000, 20000, 50000] {
    for jitter in [0.0, 0.5, 1.0, 1.5, 2.0] {
        let run = runStall(rate: rate, jitter: jitter)
        let kinds = run.performed.map { $0.1 }
        if jitter == 2.0 { print("  matrix rate=\(Int(rate)) B/s: \(run.performed.map { "\($0.1)@\(Int($0.0))s" }.joined(separator: " "))") }
        check(kinds == [.bumpSockets, .rebindPort], "rate \(Int(rate)) jitter \(jitter): bump then fresh port, got \(run.performed)")
        if let fresh = run.performed.first(where: { $0.1 == .rebindPort }) {
            check(fresh.0 <= 30, "rate \(Int(rate)) jitter \(jitter): fresh port by 30 s, got \(fresh.0)")
            if rate >= 1000 { check(fresh.0 <= 16, "rate \(Int(rate)) jitter \(jitter): VoIP-rate heal <= ~15 s, got \(fresh.0)") }
        }
        check(run.arbiter.budget.denied == 0, "rate \(Int(rate)) jitter \(jitter): no refusal on the normal path")
    }
}

// Rolling cap refusal is retried after the window frees (tribe.6: stage burned, never healed).
do {
    let run = runStall(rate: 5000, jitter: 2, from: 31, horizon: 200, stallFrom: 35) { arbiter in
        // Four earlier GUI fresh ports, each after inbound progress: rolling window full until t=120.
        for at in [0.0, 10, 20, 30] {
            _ = arbiter.tick(s(0, UInt64(1000 + at), 100, at), pathSatisfied: true, policy: seamless)
            check(arbiter.requestFreshPort(s(0, UInt64(1000 + at), 100, at), pathSatisfied: true) == .performed, "GUI fresh port at \(at)")
        }
    }
    check(run.performed.map { $0.1 } == [.bumpSockets, .rebindPort], "cap refusal retried, both steps run: \(run.performed)")
    check(run.performed.first?.0 == 120, "bump as soon as the t=0 intervention leaves the window: \(run.performed)")
    check(run.performed.last?.0 == 130, "fresh port as soon as the t=10 intervention leaves the window: \(run.performed)")
    check(run.arbiter.budget.denied == 2, "two denial streaks, not one per tick: \(run.arbiter.budget.denied)")
}

// A refusal leaves the stage in place: the outcome says so, the next tick proposes again.
do {
    var arbiter = TribeRecoveryArbiter()
    for at in [0.0, 10, 20, 30] {
        _ = arbiter.tick(s(0, UInt64(1000 + at), 100, at), pathSatisfied: true, policy: seamless)
        _ = arbiter.requestFreshPort(s(0, UInt64(1000 + at), 100, at), pathSatisfied: true)
    }
    _ = arbiter.tick(s(0, 2000, 100, 31), pathSatisfied: true, policy: seamless)
    check(arbiter.tick(s(50000, 2000, 100, 40), pathSatisfied: true, policy: seamless) == .denied(.bumpSockets, .rollingCap), "cap refusal reported")
    check(arbiter.tracker?.stage == 0, "stage not burned by the refusal")
    check(arbiter.tick(s(51000, 2000, 100, 41), pathSatisfied: true, policy: seamless) == .denied(.bumpSockets, .rollingCap), "same step proposed again")
}

// GUI fresh port after an NE bump: allowed (escalation) and the watchdog does not ask again.
do {
    var arbiter = TribeRecoveryArbiter(jitter: 2)
    var outcomes: [TribeWatchdogOutcome] = []
    for tick in 1...40 {
        let at = Double(tick)
        let sample = s(UInt64(at * 5000), 5000, 100, at)
        let outcome = arbiter.tick(sample, pathSatisfied: true, policy: seamless)
        if outcome != .none { outcomes.append(outcome) }
        if tick == 8 { check(arbiter.requestFreshPort(sample, pathSatisfied: true) == .performed, "GUI escalation 3 s after NE bump") }
    }
    check(outcomes == [.perform(.bumpSockets)], "watchdog quiet after the GUI fresh port (no refusal spam): \(outcomes)")
    check(arbiter.requestFreshPort(s(300000, 5000, 100, 60), pathSatisfied: true) == .budget(.episode), "second GUI fresh port in the same episode refused")
    check(arbiter.requestFreshPort(s(300000, 5000, 100, 61), pathSatisfied: false) == .offline, "offline refusal")
    check(arbiter.requestFreshPort(nil, pathSatisfied: true) == .notStarted, "unreadable counters = not started")
}

// Roam rearm after an NE bump: the next step is the fresh port, not a second bump.
do {
    var arbiter = TribeRecoveryArbiter()
    var performed: [(Double, TribeStallAction)] = []
    for tick in 1...40 {
        let at = Double(tick)
        let sample = s(UInt64(at * 5000), 5000, 100, at)
        if tick == 7 { arbiter.rearmAfterRoam(sample); continue } // path event bumped the socket
        if case .perform(let action) = arbiter.tick(sample, pathSatisfied: true, policy: seamless) { performed.append((at, action)) }
    }
    check(performed.map { $0.1 } == [.bumpSockets, .rebindPort], "bump, roam, then fresh port: \(performed)")
    check(performed.last?.0 == 21, "fresh port probe+rebind after the rearm: \(performed)")
}

// Late bump (after a refusal) still gives the keepalive a few seconds before the fresh port.
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var allowBump = false
    var fired: [(Double, TribeStallAction)] = []
    for i in 1...40 {
        if i == 20 { allowBump = true }
        let a = t.observe(s(UInt64(i * 5000), 0, 100, Double(i)), pathSatisfied: true, policy: seamless) { step in step == .bumpSockets ? allowBump : true }
        if a != .none { fired.append((Double(i), a)) }
    }
    check(fired.count == 2 && fired[0].0 == 20 && fired[1].0 == 23, "min gap after a late bump: \(fired)")
}

// --- D7: every recovery step ends with a keepalive (server learns the new endpoint at once) ---
check(TribeRoaming.socketOps(for: .bumpSockets) == [.bumpWithKeepalive], "bump = BindUpdate + keepalive")
check(TribeRoaming.socketOps(for: .rebindPort) == [.freshListenPort, .bumpWithKeepalive], "fresh port followed by keepalive")
check(TribeRoaming.socketOps(for: .none).isEmpty, "no-op")

// --- D7: a short flap never pauses the device ---
let shortPause = TribeRoamingPolicy.fromConfig(keepBackend: "1", pauseAfterS: "3", stallProbeS: nil, stallRebindS: nil)
check(shortPause.pauseAfterUnsatisfiedSeconds == TribeRoamingPolicy.minPauseAfterSeconds, "positive pause below the floor lifted: \(shortPause.pauseAfterUnsatisfiedSeconds)")
check(TribeRoamingPolicy.fromConfig(keepBackend: "1", pauseAfterS: "0", stallProbeS: nil, stallRebindS: nil).pauseAfterUnsatisfiedSeconds == 0, "0 stays never")
check(TribeRoaming.pathLossDecision(policy: seamless, legacyWouldPause: true) == .keepBackend, "default: flap keeps the backend")

// --- D2/K4: provider-message reply for rebind ---
check(TribeRebindResult.performed.responsePayload == ["rebind": "performed"], "performed payload")
check(TribeRebindResult.budget(.rollingCap).responsePayload == ["rebind": "denied", "reason": "budget"], "budget payload")
check(TribeRebindResult.notStarted.responsePayload == ["rebind": "denied", "reason": "not_started"], "not started payload")
check(TribeRebindResult.offline.responsePayload == ["rebind": "denied", "reason": "offline"], "offline payload")

if failures == 0 { print("TribeRoamingTests: OK") } else { print("TribeRoamingTests: \(failures) failure(s)"); exit(1) }

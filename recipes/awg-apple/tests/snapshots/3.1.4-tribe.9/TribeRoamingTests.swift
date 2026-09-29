// Tribe seamless roaming — executable unit test (no XCTest: compiled by plain swiftc inside the
// conan recipe build, so the adapter package cannot ship with broken roaming logic).
// tribe.9: ladder fresh port -> soft restart -> backoff cycle; path events never restart the
// stall clock; a path that returns after a loss gets a fresh port.
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
check(seamless.stallRebindSeconds == 10, "stall second stage +10s")
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
check(parsedClamp.stallRebindSeconds == 10, "junk second stage -> default")

// --- path-loss decision ---
check(TribeRoaming.pathLossDecision(policy: legacy, legacyWouldPause: true) == .pauseNow, "legacy pauses")
check(TribeRoaming.pathLossDecision(policy: legacy, legacyWouldPause: false) == .keepBackend, "legacy grace keeps")
check(TribeRoaming.pathLossDecision(policy: seamless, legacyWouldPause: true) == .keepBackend, "seamless never pauses")
var longOffline = seamless; longOffline.pauseAfterUnsatisfiedSeconds = 30
check(TribeRoaming.pathLossDecision(policy: longOffline, legacyWouldPause: true) == .pauseAfter(30), "long-offline fallback schedules pause")
check(TribeRoaming.pathLossDecision(policy: longOffline, legacyWouldPause: false) == .keepBackend, "fallback still honours bootstrap grace")

// --- tribe.9: what a returning path gets ---
check(TribeRoaming.roamRebindAction(realLoss: false, interfaceChanged: false) == .bumpSockets, "path event without a loss = same-port bump (upstream)")
check(TribeRoaming.roamRebindAction(realLoss: true, interfaceChanged: false) == .rebindPort, "path returned after a loss = fresh port")
check(TribeRoaming.roamRebindAction(realLoss: false, interfaceChanged: true) == .rebindPort, "Wi-Fi <-> cellular = fresh port")

// --- UAPI sample parsing (sums peers; unknown handshake -> 0) ---
let uapi = "private_key=aa\nlisten_port=1234\npublic_key=bb\nrx_bytes=100\ntx_bytes=250\nlast_handshake_time_sec=1700000000\npublic_key=cc\nrx_bytes=5\ntx_bytes=7\nlast_handshake_time_sec=0\n"
let sample = TribeRoaming.parseSample(uapi: uapi, at: 12)
check(sample.rxBytes == 105 && sample.txBytes == 257, "peer counters summed: \(sample)")
check(sample.lastHandshakeSec == 1700000000 && sample.at == 12, "max handshake kept")
check(TribeRoaming.parseSample(uapi: "garbage", at: 1) == TribeStallSample(txBytes: 0, rxBytes: 0, lastHandshakeSec: 0, at: 1), "garbage -> zeros")

// --- stall watchdog (tracker alone: tribe.4/5 entry point = fresh port only) ---
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

// real traffic dies (1500 B/s): the FIRST step is the fresh port at 4 s; the plain entry point
// (tribe.4/5 API, persistent=false) does nothing after it.
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var actions: [(TimeInterval, TribeStallAction)] = []
    var tx: UInt64 = 0
    for i in 1...60 { tx += 1500; let at = Double(i); let a = t.observe(s(tx, 0, 100, at), pathSatisfied: true, policy: seamless); if a != .none { actions.append((at, a)) } }
    check(actions.count == 1, "exactly one step without persistent heal: \(actions)")
    check(actions.first?.0 == 4 && actions.first?.1 == .rebindPort, "fresh port at 4 s: \(actions)")
    check(t.stage == 2, "fresh port stage")
    // inbound progress re-arms
    check(t.observe(s(tx + 10, 1, 100, 61), pathSatisfied: true, policy: seamless) == .none, "progress = no action")
    check(t.stage == 0, "re-armed after rx progress")
}

// full ladder at 1500 B/s (persistent): fresh port 4 s, soft restart 14 s, then backoff 30/60/120
// alternating fresh port / soft restart.
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var actions: [(TimeInterval, TribeStallAction)] = []
    var tx: UInt64 = 0
    for i in 1...400 {
        tx += 1500; let at = Double(i)
        let a = t.observe(s(tx, 0, 100, at), pathSatisfied: true, policy: seamless, persistent: true) { _ in true }
        if a != .none { actions.append((at, a)) }
    }
    check(actions.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort, .softRestart, .rebindPort, .softRestart],
          "ladder fresh port -> soft restart -> cycle: \(actions)")
    check(actions.map { $0.0 } == [4, 14, 44, 104, 224, 344], "at 4, 14, +30, +60, +120, +120 s: \(actions)")
    check(t.stage == 3 && t.persistentSteps == 5, "stage 3 after five steps past the fresh port")
}

// a fresh handshake counts as inbound progress (idle-but-healthy tunnel)
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    var fired = false
    for i in 1...20 { tx += 1500; let hs: Int64 = i >= 3 ? 200 : 100; if t.observe(s(tx, 0, hs, Double(i)), pathSatisfied: true, policy: seamless) != .none && i <= 6 { fired = true } }
    check(!fired, "handshake at t=3 postpones the first step past t=6")
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

// second stage disabled: only the fresh port ever fires, even with persistent heal
do {
    var noSecond = seamless; noSecond.stallRebindSeconds = 0
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    var actions: [TribeStallAction] = []
    for i in 1...200 { tx += 1500; let a = t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: noSecond, persistent: true) { _ in true }; if a != .none { actions.append(a) } }
    check(actions == [.rebindPort], "second stage 0 -> fresh port only: \(actions)")
}

// counter reset (backend restarted) is progress, not a stall
do {
    var t = TribeStallTracker(first: s(100000, 5000, 100, 0))
    check(t.observe(s(10, 0, 0, 5), pathSatisfied: true, policy: seamless) == .none, "counter reset tolerated")
    check(t.stage == 0, "still armed after reset")
}

// tribe.9: a roam FRESH PORT is the episode's fresh port: the stall clock is not restarted, the next
// step is the soft restart at probe+second stage from the last inbound progress.
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    for i in 1...3 { tx += 1500; _ = t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: seamless, persistent: true) { _ in true } }
    t.noteExternalStep(.freshPort, at: 3, tx: tx)
    check(t.stage == 2, "roam fresh port recorded as the first step")
    var fired: [(TimeInterval, TribeStallAction)] = []
    for i in 4...30 { tx += 1500; let a = t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: seamless, persistent: true) { _ in true }; if a != .none { fired.append((Double(i), a)) } }
    check(fired.first?.1 == .softRestart && fired.first?.0 == 14, "soft restart at 14 s from the last progress, not from the roam: \(fired)")
}

// tribe.9: a same-port roam bump is not a step and does not move the clock either
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var tx: UInt64 = 0
    for i in 1...3 { tx += 1500; _ = t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: seamless) }
    t.noteExternalStep(.bump, at: 3, tx: tx)
    check(t.stage == 0, "bump is not a ladder step")
    var firstAt: TimeInterval = -1
    for i in 4...20 { tx += 1500; if t.observe(s(tx, 0, 100, Double(i)), pathSatisfied: true, policy: seamless) == .rebindPort { firstAt = Double(i); break } }
    check(firstAt == 4, "fresh port still at 4 s after a bump at 3 s, got \(firstAt)")
}

// counters summary is stable text for logs/diag
do {
    var c = TribeRoamingCounters()
    c.pathLost += 1; c.roamBumps += 2; c.roamFreshPorts += 1; c.stallRebinds += 1
    check(c.summary == "path_lost=1 path_restored=0 roam_bumps=2 roam_fresh_ports=1 stall_bumps=0 stall_rebinds=1 pauses=0 resumes=0", "summary format: \(c.summary)")
    check(c.asDictionary["roam_bumps"] == 2 && c.asDictionary["roam_fresh_ports"] == 1, "dictionary export")
}

// Autonomous bootstrap is bounded without assuming that the GUI exists: fresh port after AWG's own
// 12 s of retries, soft restart after 30 s, then the backoff cycle.
do {
    var tracker = TribeStallTracker(first: s(0, 0, 0, 0))
    check(tracker.observe(s(1024, 0, 0, 4), pathSatisfied: true, policy: seamless) == .none, "bootstrap respects built-in retries")
    check(tracker.observe(s(1024, 0, 0, 12), pathSatisfied: false, policy: seamless) == .none, "offline never heals")
    check(tracker.observe(s(1024, 0, 0, 12), pathSatisfied: true, policy: seamless) == .rebindPort, "bootstrap fresh port after retry grace")
    check(tracker.observe(s(2048, 0, 0, 29), pathSatisfied: true, policy: seamless, persistent: true) { _ in true } == .none, "second stage not before 30 s")
    check(tracker.observe(s(2048, 0, 0, 30), pathSatisfied: true, policy: seamless, persistent: true) { _ in true } == .softRestart, "bootstrap soft restart after grace")
    var later: [(Int, TribeStallAction)] = []
    for time in 31...200 {
        let a = tracker.observe(s(UInt64(time * 1024), 0, 0, Double(time)), pathSatisfied: true, policy: seamless, persistent: true) { _ in true }
        if a != .none { later.append((time, a)) }
    }
    check(later.map { $0.1 } == [.rebindPort, .softRestart] && later.map { $0.0 } == [60, 120],
          "bootstrap cycle after 30/60 s (next at 240): \(later)")
}
do {
    var budget = TribeRecoveryBudget(jitter: 2)
    check(budget.permit(at: 0, freshPort: false), "NE bump accepted")
    // tribe.7: cooldown only between actions of the same kind; the fresh-port escalation after a
    // bump is not delayed by it (tribe.6 refused it here and burned the watchdog stage).
    check(budget.permit(at: 9, freshPort: true), "fresh port right after a bump is an escalation, not a repeat")
    check(!budget.permit(at: 10, freshPort: true), "one shared fresh port per episode")
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
    check(budget.request(at: 0, kind: .freshPort) == nil, "fresh port")
    budget.observe(s(100, 1, 0, 2))
    check(budget.request(at: 5, kind: .freshPort) == .cooldown, "second fresh port 5 s later refused by cooldown")
    check(budget.request(at: 8, kind: .freshPort) == nil, "fresh port after cooldown")
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

// Matrix: outbound 300 B/s ... 50 KB/s x budget jitter 0..2. The fresh port must be the first step
// in every cell and come by 16 s; VoIP-like rates (>= 1 KB/s) get it within ~5 s of the onset. The
// soft restart follows once the demand doubles; a stage-3 step 30 s after it (horizon 90 s).
for rate in [300.0, 450, 600, 750, 1000, 2000, 5000, 20000, 50000] {
    for jitter in [0.0, 0.5, 1.0, 1.5, 2.0] {
        let run = runStall(rate: rate, jitter: jitter)
        let kinds = run.performed.map { $0.1 }
        if jitter == 2.0 { print("  matrix rate=\(Int(rate)) B/s: \(run.performed.map { "\($0.1)@\(Int($0.0))s" }.joined(separator: " "))") }
        check(Array(kinds.prefix(2)) == [.rebindPort, .softRestart], "rate \(Int(rate)) jitter \(jitter): fresh port then soft restart, got \(run.performed)")
        if let fresh = run.performed.first(where: { $0.1 == .rebindPort }) {
            check(fresh.0 <= 16, "rate \(Int(rate)) jitter \(jitter): fresh port by 16 s, got \(fresh.0)")
            if rate >= 1000 { check(fresh.0 <= 6, "rate \(Int(rate)) jitter \(jitter): VoIP-rate first step <= 6 s, got \(fresh.0)") }
        }
        if let soft = run.performed.first(where: { $0.1 == .softRestart }) {
            check(soft.0 <= 30, "rate \(Int(rate)) jitter \(jitter): soft restart by 30 s, got \(soft.0)")
            let persistent = run.performed.dropFirst(2)
            check(persistent.map { $0.1 } == [.rebindPort] && persistent.first?.0 == soft.0 + 30,
                  "rate \(Int(rate)) jitter \(jitter): stage-3 fresh port 30 s after the soft restart, got \(run.performed)")
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
    check(run.performed.prefix(2).map { $0.1 } == [.rebindPort, .softRestart], "cap refusal retried, both steps run: \(run.performed)")
    check(run.performed.first?.0 == 120, "fresh port as soon as the t=0 intervention leaves the window: \(run.performed)")
    check(run.performed.count > 1 && run.performed[1].0 == 130, "soft restart as soon as the t=10 intervention leaves the window: \(run.performed)")
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
    check(arbiter.tick(s(50000, 2000, 100, 40), pathSatisfied: true, policy: seamless) == .denied(.rebindPort, .rollingCap), "cap refusal reported")
    check(arbiter.tracker?.stage == 0, "stage not burned by the refusal")
    check(arbiter.tick(s(51000, 2000, 100, 41), pathSatisfied: true, policy: seamless) == .denied(.rebindPort, .rollingCap), "same step proposed again")
}

// GUI fresh port before the watchdog's own: recorded as the episode's step, the watchdog goes on to
// the soft restart (14 s from the stall onset) and does not ask for a second fresh port.
do {
    var arbiter = TribeRecoveryArbiter(jitter: 2)
    var outcomes: [(Double, TribeWatchdogOutcome)] = []
    for tick in 1...40 {
        let at = Double(tick)
        let sample = s(UInt64(at * 5000), 5000, 100, at)
        if tick == 2 { check(arbiter.requestFreshPort(sample, pathSatisfied: true) == .performed, "GUI fresh port at 2 s") }
        let outcome = arbiter.tick(sample, pathSatisfied: true, policy: seamless)
        if outcome != .none { outcomes.append((at, outcome)) }
    }
    check(outcomes.map { $0.1 } == [.perform(.softRestart)] && outcomes.first?.0 == 15, "only the soft restart after a GUI fresh port: \(outcomes)")
    check(arbiter.requestFreshPort(s(300000, 5000, 100, 60), pathSatisfied: true) == .budget(.episode), "second GUI fresh port in the same episode refused")
    check(arbiter.requestFreshPort(s(300000, 5000, 100, 61), pathSatisfied: false) == .offline, "offline refusal")
    check(arbiter.requestFreshPort(nil, pathSatisfied: true) == .notStarted, "unreadable counters = not started")
}

// tribe.9: a roam fresh port (path returned after a loss) is the episode's fresh port; the watchdog
// continues with the soft restart at 14 s and never restarts the clock on the path event.
do {
    var arbiter = TribeRecoveryArbiter()
    var performed: [(Double, TribeStallAction)] = []
    for tick in 1...40 {
        let at = Double(tick)
        let sample = s(UInt64(at * 5000), 5000, 100, at)
        if tick == 2 { arbiter.noteRoamRebind(sample, freshPort: true); continue }
        if case .perform(let action) = arbiter.tick(sample, pathSatisfied: true, policy: seamless) { performed.append((at, action)) }
    }
    check(performed.map { $0.1 } == [.softRestart], "roam fresh port, then the soft restart: \(performed)")
    check(performed.first?.0 == 15, "soft restart 14 s after the last inbound progress (tick 1): \(performed)")
}

// tribe.9: path events WITHOUT a loss (same-port bumps) every 4 s do not starve the ladder
// (tribe.4-8: every rearm zeroed the stall clock and the fresh port needed 14 quiet seconds).
do {
    var arbiter = TribeRecoveryArbiter()
    var performed: [(Double, TribeStallAction)] = []
    for tick in 1...60 {
        let at = Double(tick)
        let sample = s(UInt64(at * 5000), 5000, 100, at)
        if tick % 4 == 0 { arbiter.noteRoamRebind(sample, freshPort: false) }
        if case .perform(let action) = arbiter.tick(sample, pathSatisfied: true, policy: seamless) { performed.append((at, action)) }
    }
    check(performed.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort], "ladder runs under a flapping path: \(performed)")
    check(performed.map { $0.0 } == [5, 15, 45], "fresh port 4 s, soft restart 14 s, stage-3 fresh port +30 s after the last progress (tick 1): \(performed)")
}

// Late fresh port (after a refusal) still gives the keepalive a few seconds before the soft restart.
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var allowFresh = false
    var fired: [(Double, TribeStallAction)] = []
    for i in 1...40 {
        if i == 20 { allowFresh = true }
        let a = t.observe(s(UInt64(i * 5000), 0, 100, Double(i)), pathSatisfied: true, policy: seamless, persistent: true) { step in step == .rebindPort ? allowFresh : true }
        if a != .none { fired.append((Double(i), a)) }
    }
    check(fired.count == 2 && fired[0].0 == 20 && fired[1].0 == 23, "min gap after a late fresh port: \(fired)")
}

// --- D7: every recovery step ends with a keepalive (server learns the new endpoint at once) ---
check(TribeRoaming.socketOps(for: .bumpSockets) == [.bumpWithKeepalive], "bump = BindUpdate + keepalive")
// tribe.8 (REV-3): keepalive only after the fresh port, no second BindUpdate of the new socket.
check(TribeRoaming.socketOps(for: .rebindPort) == [.freshListenPort, .sendKeepalive], "fresh port followed by keepalive only")
check(TribeRoaming.socketOps(for: .softRestart) == [.restartBackend], "soft restart = backend restart on the same TUN")
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

// --- tribe.8/9: stage 3 keeps healing while the GUI sleeps (backoff 30/60/120 s, capped) ---
// Simulated device: outbound grows `rate` B/s, inbound frozen unless listed; a soft restart gives a
// new device whose counters start from zero (the adapter rebases the arbiter with its first sample).
func runPersistent(rate: UInt64, horizon: Int, progressAt: Set<Int> = [], idle: ClosedRange<Int>? = nil,
                   offline: ClosedRange<Int>? = nil, persistentHeal: Bool = true,
                   onTick: ((Int, inout TribeRecoveryArbiter, TribeStallSample) -> Void)? = nil)
    -> (performed: [(Double, TribeStallAction)], outcomes: [(Double, TribeWatchdogOutcome)], arbiter: TribeRecoveryArbiter) {
    var arbiter = TribeRecoveryArbiter(jitter: 2, persistentHeal: persistentHeal)
    var tx: UInt64 = 0
    var rx: UInt64 = 5000
    var hs: Int64 = 100
    var performed: [(Double, TribeStallAction)] = []
    var outcomes: [(Double, TribeWatchdogOutcome)] = []
    for tick in 1...horizon {
        let at = Double(tick)
        if !(idle?.contains(tick) ?? false) { tx += rate }
        if progressAt.contains(tick) { rx += 1000 }
        let sample = s(tx, rx, hs, at)
        let outcome = arbiter.tick(sample, pathSatisfied: !(offline?.contains(tick) ?? false), policy: seamless)
        if outcome != .none { outcomes.append((at, outcome)) }
        if case .perform(let action) = outcome {
            performed.append((at, action))
            if action == .softRestart {
                tx = 0; rx = 0; hs = 0
                arbiter.rebaseAfterBackendRestart(s(tx, rx, hs, at))
            }
        }
        onTick?(tick, &arbiter, sample)
    }
    return (performed, outcomes, arbiter)
}
func gaps(_ performed: [(Double, TribeStallAction)]) -> [Double] {
    zip(performed.dropFirst(), performed).map { $0.0 - $1.0 }
}

// 1 KB/s, rx frozen, path satisfied: fresh port at 5 s (4 KB demand), soft restart at 14 s, then
// +30 fresh port, +60 soft restart, +120 fresh port, +120 soft restart ...
do {
    let run = runPersistent(rate: 1000, horizon: 600)
    print("  persistent 1 KB/s: \(run.performed.map { "\($0.1)@\(Int($0.0))s" }.joined(separator: " "))")
    check(run.performed.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort, .softRestart, .rebindPort, .softRestart, .rebindPort, .softRestart],
          "fresh port -> soft restart -> alternating cycle: \(run.performed)")
    check(run.performed.count > 1 && run.performed[0].0 == 6 && run.performed[1].0 == 15, "fresh port at 6 s (4 KB demand), soft restart at 15 s: \(run.performed)")
    check(Array(gaps(run.performed).dropFirst()) == [30, 60, 120, 120, 120, 120], "backoff 30/60/120 s, capped at 120 s: \(gaps(run.performed))")
    check(run.arbiter.budget.denied == 0, "stage-3 pacing stays inside the rolling cap: denied=\(run.arbiter.budget.denied)")
    check(run.arbiter.tracker?.stage == 3 && run.arbiter.tracker?.persistentSteps == 7, "stage 3 with 7 steps past the fresh port")
}

// persistentHeal=false = exhausted after the fresh port.
do {
    let run = runPersistent(rate: 1000, horizon: 600, persistentHeal: false)
    check(run.performed.map { $0.1 } == [.rebindPort], "no persistent heal: nothing after the fresh port: \(run.performed)")
}

// Inbound progress at any point resets the stage AND the backoff: after progress the episode starts
// again (fresh port, soft restart) and the next stage-3 step is 30 s after that soft restart.
do {
    let run = runPersistent(rate: 1000, horizon: 200, progressAt: [130])
    let after = run.performed.filter { $0.0 > 130 }
    check(run.performed.filter { $0.0 <= 130 }.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort, .softRestart], "before progress: \(run.performed)")
    check(after.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort], "after progress: fresh port, soft restart, stage-3 fresh port: \(after)")
    check(after.first.map { $0.0 - 130 <= 6 } ?? false, "fresh episode starts at the probe window: \(after)")
    check(gaps(after).last == 30, "backoff restarted at 30 s: \(after)")
    var progressed = runPersistent(rate: 1000, horizon: 232, progressAt: [230]).arbiter
    check(progressed.tracker?.stage == 0 && progressed.tracker?.persistentSteps == 0, "progress: stage 0, backoff reset")
    _ = progressed.tick(s(1, 1, 1, 251), pathSatisfied: true, policy: seamless) // counters reset tolerated
}

// Stage 3 needs demand and a path: idle outbound or an unsatisfied path never triggers it; the step
// fires as soon as demand returns (the backoff has already elapsed).
do {
    let idleRun = runPersistent(rate: 1000, horizon: 200, idle: 15...150)
    check(idleRun.performed.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort], "idle: no stage-3 step: \(idleRun.performed)")
    check(idleRun.performed.last.map { $0.0 >= 151 && $0.0 <= 156 } ?? false, "step as soon as outbound grows again: \(idleRun.performed)")
    let offlineRun = runPersistent(rate: 1000, horizon: 200, offline: 16...150)
    check(offlineRun.performed.map { $0.1 } == [.rebindPort, .softRestart, .rebindPort], "offline: no stage-3 step: \(offlineRun.performed)")
    check(offlineRun.performed.last?.0 == 151, "step on the first satisfied tick: \(offlineRun.performed)")
}

// A rolling-cap refusal of a stage-3 step is retried every tick and fires once the window frees;
// the refusal does not advance the sequence or the backoff (rule D1).
do {
    var guiRefusedAt: [Double] = []
    let run = runPersistent(rate: 5000, horizon: 200, progressAt: Set(1...13)) { tick, arbiter, sample in
        // Two GUI fresh ports after inbound progress (10 s apart = the same-kind cooldown). The
        // watchdog's own fresh port falls due at 17 s and waits for the cooldown until 21 s, the
        // soft restart follows at 27 s: the rolling window then holds 4 interventions until t=121.
        if tick == 1 || tick == 11 {
            if arbiter.requestFreshPort(sample, pathSatisfied: true) != .performed { guiRefusedAt.append(sample.at) }
        }
        if tick == 119 {
            check(arbiter.tracker?.persistentSteps == 1 && arbiter.tracker?.stage == 3, "refusals did not burn the stage-3 step")
        }
    }
    check(guiRefusedAt.isEmpty, "GUI fresh ports performed: \(guiRefusedAt)")
    let persistent = run.performed.filter { $0.0 > 30 }
    check(run.performed.prefix(2).map { $0.1 } == [.rebindPort, .softRestart], "episode: \(run.performed)")
    check(persistent.first.map { $0.0 == 121 && $0.1 == .rebindPort } ?? false, "stage-3 fresh port as soon as the t=1 intervention leaves the window: \(run.performed)")
    check(persistent.count > 1 && persistent[1].0 == 181 && persistent[1].1 == .softRestart, "next step 60 s after the late one: \(run.performed)")
    let capDenials = run.outcomes.filter { if case .denied(_, .rollingCap) = $0.1 { return true } else { return false } }
    check(capDenials.first.map { $0.1 == .denied(.rebindPort, .rollingCap) } ?? false, "cap refusal reported when the step fell due: \(capDenials.first.map { "\($0)" } ?? "none")")
    check(run.arbiter.budget.denied == 2, "two denial streaks (cooldown, then cap), not one per tick: \(run.arbiter.budget.denied)")
}

// Tracker level: whatever refuses the step (budget), the step fires later and the backoff counts
// from the late step.
do {
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    var fired: [(Double, TribeStallAction)] = []
    for i in 1...200 {
        let at = Double(i)
        let persistentPhase = t.stage >= 3
        let a = t.observe(s(UInt64(i * 5000), 0, 100, at), pathSatisfied: true, policy: seamless, persistent: true) { _ in
            !(persistentPhase && at < 80)
        }
        if a != .none { fired.append((at, a)) }
    }
    check(fired.map { $0.0 } == [4, 14, 80, 140], "late stage-3 step at 80 s, next +60 s: \(fired)")
}

// --- tribe.8 U6: soft restart of the backend (provider message `soft_restart`) ---
do {
    var arbiter = TribeRecoveryArbiter()
    _ = arbiter.tick(s(0, 5000, 100, 0), pathSatisfied: true, policy: seamless)
    check(arbiter.requestSoftRestart(s(1000, 5000, 100, 1), pathSatisfied: false) == .offline, "offline refusal")
    check(arbiter.requestSoftRestart(nil, pathSatisfied: true) == .notStarted, "unreadable counters = not started")
    check(arbiter.requestSoftRestart(s(1000, 5000, 100, 2), pathSatisfied: true) == .performed, "GUI soft restart performed")
    check(arbiter.tracker?.stage == 3 && arbiter.tracker?.persistentSteps == 1, "GUI soft restart counts as the second step (stage 3)")
    arbiter.rebaseAfterBackendRestart(s(0, 0, 0, 2))
    check(arbiter.requestSoftRestart(s(500, 0, 0, 20), pathSatisfied: true) == .budget(.episode), "one GUI soft restart per episode")
    check(arbiter.requestFreshPort(s(500, 0, 0, 21), pathSatisfied: true) == .budget(.episode), "a soft restart consumes the fresh port too")
    // A counter drop is not progress; the new device's first inbound bytes are (tribe.7 missed them
    // until rx exceeded the OLD device's total).
    _ = arbiter.tick(s(600, 0, 0, 22), pathSatisfied: true, policy: seamless)
    check(arbiter.tracker?.stage == 3, "rebased counters: no false progress")
    _ = arbiter.tick(s(700, 40, 1_700_000_000, 23), pathSatisfied: true, policy: seamless)
    check(arbiter.tracker?.stage == 0 && arbiter.budget.episodeUsed == 0, "new device's handshake/rx = progress, episode re-armed")
    check(arbiter.requestSoftRestart(s(800, 40, 1_700_000_000, 40), pathSatisfied: true) == .performed, "re-armed after progress (cooldown elapsed)")
}
do {
    // Soft restart after the counters reset: stage and backoff survive the rebase.
    var t = TribeStallTracker(first: s(0, 0, 100, 0))
    for i in 1...14 { _ = t.observe(s(UInt64(i * 5000), 0, 100, Double(i)), pathSatisfied: true, policy: seamless, persistent: true) { _ in true } }
    check(t.stage == 3 && t.persistentSteps == 1, "fresh port and soft restart done")
    t.rebaseCounters(s(0, 0, 0, 15))
    check(t.observe(s(100, 0, 0, 16), pathSatisfied: true, policy: seamless, persistent: true) { _ in true } == .none && t.stage == 3,
          "rebase keeps the stage (a counter drop is not progress)")
}
do {
    // Budget: rebase on a counter drop; resume re-arms the episode (review note on tribe.7).
    var budget = TribeRecoveryBudget()
    budget.observe(s(100000, 90000, 100, 0))
    check(budget.request(at: 1, kind: .freshPort) == nil, "fresh port")
    budget.observe(s(10, 0, 0, 2))
    check(budget.episodeUsed == 2, "counter drop alone does not re-arm")
    budget.observe(s(20, 5, 0, 3))
    check(budget.episodeUsed == 0, "first inbound bytes of the new device re-arm the episode")
    check(budget.request(at: 20, kind: .freshPort) == nil, "fresh port after re-arm (cooldown elapsed)")
    budget.resetEpisode()
    check(budget.request(at: 40, kind: .freshPort) == nil, "resume re-arms the episode: fresh port permitted again (cooldown elapsed)")
    check(budget.request(at: 41, kind: .softRestart, persistent: true) == nil, "persistent step ignores the episode")
    var paced = TribeRecoveryBudget(jitter: 0)
    check(paced.request(at: 0, kind: .softRestart, persistent: true) == nil, "persistent soft restart")
    check(paced.request(at: 5, kind: .softRestart, persistent: true) == .cooldown, "same-kind cooldown applies to persistent steps")
    check(paced.request(at: 8, kind: .softRestart, persistent: true) == nil, "after the cooldown")
}
do {
    var arbiter = TribeRecoveryArbiter()
    let run = runPersistent(rate: 1000, horizon: 20).arbiter
    arbiter = run
    check(arbiter.budget.freshPortSpent, "episode spent")
    arbiter.noteBackendResumed()
    check(arbiter.tracker == nil && arbiter.budget.episodeUsed == 0, "resume: fresh tracker, episode re-armed")
    _ = arbiter.tick(s(0, 0, 0, 30), pathSatisfied: true, policy: seamless)
    var bootstrap: [TribeWatchdogOutcome] = []
    for i in 31...60 { let o = arbiter.tick(s(UInt64((i - 30) * 1000), 0, 0, Double(i)), pathSatisfied: true, policy: seamless); if o != .none { bootstrap.append(o) } }
    check(bootstrap.first == .perform(.rebindPort), "bootstrap fresh port permitted after resume: \(bootstrap)")
}
check(TribeSoftRestartResult.performed.responsePayload == ["soft_restart": "performed"], "soft restart payload")
check(TribeSoftRestartResult.budget(.episode).responsePayload == ["soft_restart": "denied", "reason": "budget"], "soft restart budget payload")
check(TribeSoftRestartResult.notStarted.responsePayload == ["soft_restart": "denied", "reason": "not_started"], "soft restart not started payload")
check(TribeSoftRestartResult.offline.responsePayload == ["soft_restart": "denied", "reason": "offline"], "soft restart offline payload")
check(TribeSoftRestartResult.failed.responsePayload == ["soft_restart": "denied", "reason": "failed"], "soft restart failure payload")

if failures == 0 { print("TribeRoamingTests: OK") } else { print("TribeRoamingTests: \(failures) failure(s)"); exit(1) }

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

if failures == 0 { print("TribeRoamingTests: OK") } else { print("TribeRoamingTests: \(failures) failure(s)"); exit(1) }

// Tribe data watch together with the REAL stall ladder (TribeRoaming.swift), wired the way
// WireGuardAdapter.stallTick wires them: the same sample, the watch first, the ladder second, one
// tick a second (five when idle). Executable test, compiled by plain swiftc as a package gate.
//
// Why this file exists: an independent review coupled the two and found what the watch's own
// tests could not show - below ~270 B/s of demand the ladder never steps (a completed handshake
// is progress for it), and the verdict, which then waited for two ladder steps, was never
// reached on the very path of 13.11. The verdict no longer looks at the ladder; these vectors
// keep it that way, and they keep a soft restart by the ladder from producing a false verdict.
import Foundation

var failures = 0
func check(_ cond: @autoclosure () -> Bool, _ what: @autoclosure () -> String, line: Int = #line) {
    if !cond() { failures += 1; print("FAIL line \(line): \(what())") }
}

/// The device and the path, one simulated second at a time.
final class World {
    var tx: UInt64 = 0
    var rx: UInt64 = 0
    var handshake: Int64 = 0
    var uptime: TimeInterval = 5000
    var wall: TimeInterval = 1_800_000_000
    /// Outbound user bytes per second.
    var demand: Double = 0
    /// A handshake completes this often (its 92-byte response is all that comes back); nil = never.
    var handshakeEvery: TimeInterval?
    /// Bytes of unanswered handshake initiations per second while no handshake completes.
    var retryTxPerSecond: Double = 0
    /// How long the first handshake of a restarted device takes; nil = it never completes.
    var handshakeAfterRestart: TimeInterval? = 0.5
    /// The path passes data (a probe sent under a keypair is answered).
    var healthy = false
    private var lastHandshakeAt: TimeInterval = -1e9
    private var restartHandshakeDue: TimeInterval?
    private var carry = 0.0
    /// The engine holds a keypair that may send.
    var hasSession: Bool { handshake > 0 && uptime - lastHandshakeAt < 175 }

    func second() {
        uptime += 1
        wall += 1
        carry += demand + (hasSession ? 0 : retryTxPerSecond)
        let whole = UInt64(carry)
        carry -= Double(whole)
        tx += whole
        if let due = restartHandshakeDue, uptime >= due {
            restartHandshakeDue = nil
            completeHandshake()
        } else if restartHandshakeDue == nil, let every = handshakeEvery, uptime - lastHandshakeAt >= every {
            completeHandshake()
        }
    }
    private func completeHandshake() {
        tx += 422
        rx += 92
        handshake = Int64(wall)
        lastHandshakeAt = uptime
    }
    func softRestart() {
        tx = 0
        rx = 0
        handshake = 0
        restartHandshakeDue = handshakeAfterRestart.map { uptime + $0 }
        if handshakeAfterRestart == nil { handshakeEvery = nil }
    }
}

final class Rig {
    let world: World
    var policy: TribeDataWatchPolicy
    var watch = TribeDataWatch()
    var arbiter = TribeRecoveryArbiter()
    var inputs = TribeDataWatchInputs()
    var previous: TribeStallSample?
    var nextTick: TimeInterval
    let startedAt: TimeInterval
    var freshPorts = 0
    var softRestarts = 0
    var probes: [(at: TimeInterval, result: TribeProbeResult)] = []
    var verdicts: [TribeDataVerdict] = []
    var wouldSwitchSeen = false
    var firstNoData: TimeInterval?
    private var probeDue: (at: TimeInterval, result: TribeProbeResult)?
    private var sanityDue: TimeInterval?

    init(_ world: World) {
        self.world = world
        var p = TribeDataWatchPolicy()
        p.enabled = true
        policy = p
        startedAt = world.uptime
        nextTick = world.uptime + 1
        watch.noteDeviceStarted(at: world.uptime, policy: p)
    }

    func run(seconds: Int) {
        for _ in 0..<seconds {
            world.second()
            if world.uptime + 1e-9 >= nextTick { tick() }
        }
    }

    private func tick() {
        let sample = TribeStallSample(txBytes: world.tx, rxBytes: world.rx, lastHandshakeSec: world.handshake, at: world.uptime)
        let idle = previous.map { $0.txBytes == sample.txBytes && $0.rxBytes == sample.rxBytes } ?? false
        previous = sample
        nextTick = world.uptime + (idle ? 5 : 1)
        if let due = sanityDue, world.uptime >= due {
            inputs.sanity = .ok
            inputs.sanityAt = world.uptime
            sanityDue = nil
        }
        if let due = probeDue, world.uptime >= due.at {
            inputs.probe = due.result
            inputs.probeAt = world.uptime
            inputs.probeLatencyMs = 80
            if due.result == .answered { world.rx += 120 } // the reply is a transport packet
            probeDue = nil
        }
        let out = watch.step(TribeDataWatchSample(txBytes: sample.txBytes, rxBytes: sample.rxBytes, lastHandshakeSec: sample.lastHandshakeSec,
                                                  uptime: sample.at, wall: world.wall),
                             env: inputs.env(pathSatisfied: true), policy: policy)
        if out.needsSanityCheck, sanityDue == nil { sanityDue = world.uptime + 1 }
        if out.startProbe != nil {
            // What tribeprobe.go does: no keypair - the start is refused and nothing is injected;
            // otherwise the packet leaves and is answered or not.
            let result: TribeProbeResult = !world.hasSession ? .noSession : world.healthy ? .answered : .silent
            probes.append((world.uptime - startedAt, result))
            switch result {
            case .noSession:
                inputs.probe = .noSession
                inputs.probeAt = world.uptime
            case .answered:
                inputs.probe = .pending
                probeDue = (world.uptime + 1, .answered)
            default:
                inputs.probe = .pending
                probeDue = (world.uptime + policy.probeTimeoutSeconds, .silent)
            }
        }
        verdicts.append(out.verdict)
        if out.wouldSwitch { wouldSwitchSeen = true }
        if out.verdict == .noData, firstNoData == nil { firstNoData = world.uptime - startedAt }
        switch arbiter.tick(sample, pathSatisfied: true, policy: .seamless) {
        case .perform(let action):
            switch action {
            case .rebindPort:
                freshPorts += 1
            case .softRestart:
                softRestarts += 1
                world.softRestart()
                // The probe in flight dies with the device (tribeprobe.go aborts it: not_sent).
                if probeDue != nil { probeDue = (world.uptime, .notSent) }
                watch.noteBackendRestarted(at: world.uptime, policy: policy)
                previous = nil
                arbiter.rebaseAfterBackendRestart(TribeStallSample(txBytes: world.tx, rxBytes: world.rx, lastHandshakeSec: world.handshake, at: world.uptime))
            default:
                break
            }
        default:
            break
        }
    }
}

// 1. The path of 13.11 (handshake passes every 15 s, not one data packet) at low demand: the
// ladder does not step at all, and the verdict is reached all the same.
for rate in [60.0, 120.0, 200.0, 260.0] {
    let world = World()
    world.demand = rate
    world.handshakeEvery = 15
    let rig = Rig(world)
    rig.run(seconds: 1800)
    check(rig.freshPorts + rig.softRestarts == 0, "\(Int(rate)) B/s: the ladder is expected to stay still (that is the point): \(rig.freshPorts) + \(rig.softRestarts)")
    check(rig.watch.verdict == .noData, "\(Int(rate)) B/s for 30 min: no_data, got \(rig.watch.verdict)")
    check((rig.firstNoData ?? 9999) <= 130, "\(Int(rate)) B/s: within about two minutes: \(String(describing: rig.firstNoData))")
    check(rig.probes.count <= 3 && rig.probes.contains { $0.result == .silent }, "\(Int(rate)) B/s: judged by a silent probe: \(rig.probes)")
}

// 2. The same path at the demand of the field case: the ladder works (fresh port, soft restart)
// and the verdict is not slower for it.
do {
    let world = World()
    world.demand = 390
    world.handshakeEvery = 15
    let rig = Rig(world)
    rig.run(seconds: 420)
    check(rig.freshPorts + rig.softRestarts >= 2, "at 390 B/s the ladder does step: \(rig.freshPorts) + \(rig.softRestarts)")
    check(rig.watch.verdict == .noData && (rig.firstNoData ?? 9999) <= 150, "no_data with the ladder running: \(String(describing: rig.firstNoData))")
}

// 3. A healthy one-way upload: the server answers with handshake responses only, so the ladder
// treats the node (fresh port, soft restarts) and the passive rule is met again and again. A
// restarted device needs 6 s for its first handshake: a probe in those seconds cannot leave the
// phone. Before the fix that read as `no_data, would_switch` - exactly what layer 2 would act on.
do {
    let world = World()
    world.demand = 50_000
    world.handshakeEvery = 15
    world.handshakeAfterRestart = 6
    world.healthy = true
    let rig = Rig(world)
    rig.run(seconds: 1800)
    let snapshot = rig.watch.snapshot(policy: rig.policy)
    check(rig.softRestarts >= 1, "the ladder soft-restarts a node that answers with handshakes only: \(rig.softRestarts)")
    check(!rig.verdicts.contains(.noData) && !rig.wouldSwitchSeen, "a healthy upload is never no_data: first at \(String(describing: rig.firstNoData)), probes \(rig.probes)")
    check(snapshot.refuted >= 1, "the answered probe refutes the passive rule: \(snapshot.refuted)")
    check(rig.probes.count <= 6, "and the probes stay within the limits: \(rig.probes.count)")
}

// 4. The node stops answering handshakes too (blocked address): the old keypair ages out, the
// ladder restarts the device and the new one never shakes hands. A probe cannot leave any more;
// the engine's own unanswered handshakes are the judge.
do {
    let world = World()
    world.demand = 390
    world.handshakeEvery = nil
    world.retryTxPerSecond = 100
    world.handshakeAfterRestart = nil
    let rig = Rig(world)
    rig.run(seconds: 600)
    let snapshot = rig.watch.snapshot(policy: rig.policy)
    check(rig.watch.verdict == .noData && snapshot.evidence == .handshake, "no session and no answer to the handshakes: no_data by the handshake: \(rig.watch.verdict) \(snapshot.evidence)")
    check(rig.probes.allSatisfy { $0.result == .noSession } && snapshot.probesLastHour == 0, "not one packet was injected and no budget spent: \(rig.probes)")
    check((rig.firstNoData ?? 9999) <= 200, "within about three minutes: \(String(describing: rig.firstNoData))")
}

// 5. An idle tunnel for six hours with the ladder attached: nothing is judged, nobody is asked.
do {
    let world = World()
    world.handshakeEvery = 120
    let rig = Rig(world)
    for _ in 0..<(6 * 3600) {
        world.demand = Int(world.uptime) % 25 == 0 ? 96 : 0
        rig.run(seconds: 1)
    }
    check(rig.verdicts.allSatisfy { $0 == .none } && rig.probes.isEmpty, "keepalives and re-keying are not demand")
    check(rig.freshPorts + rig.softRestarts == 0, "and the ladder stays still")
}

if failures > 0 {
    print("TribeDataWatch + ladder: \(failures) check(s) FAILED")
    exit(1)
}
print("TribeDataWatch + ladder: all vectors passed")

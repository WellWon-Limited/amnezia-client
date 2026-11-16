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

// MARK: - stage 2: the arbiter next to the real ladder and the real recovery budget
//
// The second independent review coupled the arbiter with the stall ladder and a lossy path and
// found that one silent probe moved a healthy session: the ladder has normally spent the
// episode's fresh port and restart, the arbiter's heals were refused, counted as done and not
// followed by a probe, and the switch came two seconds after the verdict. These vectors are the
// review's, with fixed seeds.

struct Lcg {
    var state: UInt64
    mutating func next() -> Double {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return Double((state >> 33) % 1_000_000) / 1_000_000
    }
}

/// One node as the phone sees it.
struct Node {
    /// Handshakes complete.
    var shakes = true
    /// Transport packets pass both ways (a probe can be answered).
    var data: (TimeInterval) -> Bool = { _ in true }
    /// Healthy, but nothing comes back for the user's traffic (a one-way upload).
    var oneWay = false
    /// Inbound user bytes per second while data passes and the node is not one-way.
    var inbound: Double = 4000
    /// The probe is answered only this long after its timeout.
    var lateBy: TimeInterval?
}

final class Net {
    var nodes: [String: Node] = [:]
    var current = "A"
    var tx: UInt64 = 0, rx: UInt64 = 0, handshake: Int64 = 0
    var uptime: TimeInterval = 5000, wall: TimeInterval = 1_800_000_000
    let t0: TimeInterval = 5000
    var demand: Double = 0
    /// Probability that one probe attempt (the query or its reply) is lost.
    var loss = 0.0
    var rng = Lcg(state: 1)
    private var lastHandshakeAt: TimeInterval = -1e9
    private var deviceStart: TimeInterval = 5000
    private var carry = 0.0, carryIn = 0.0
    var t: TimeInterval { uptime - t0 }
    var node: Node { nodes[current]! }
    var keypairUsable: Bool { handshake != 0 && uptime - lastHandshakeAt < 175 }

    func second() {
        uptime += 1
        wall += 1
        let n = node
        carry += demand
        let whole = UInt64(carry)
        carry -= Double(whole)
        tx += whole
        let flows = keypairUsable && n.data(t) && !n.oneWay && n.inbound > 0 && demand > 0
        // The engine shakes hands when it has no session, and again after 15 s of sending with
        // nothing received.
        let wants = demand > 0 && (!keypairUsable || (!flows && uptime - lastHandshakeAt >= 15))
        if wants {
            if n.shakes && uptime - deviceStart >= 0.5 {
                tx += 422
                rx += 92
                handshake = Int64(wall)
                lastHandshakeAt = uptime
            } else if Int(uptime) % 5 == 0 {
                tx += 500 // an initiation nobody answers
            }
        }
        if flows {
            carryIn += n.inbound
            let got = UInt64(carryIn)
            carryIn -= Double(got)
            rx += got
        }
    }
    func newDevice() {
        tx = 0
        rx = 0
        handshake = 0
        lastHandshakeAt = -1e9
        deviceStart = uptime
    }
}

/// The rule, the ladder and the budget wired as WireGuardAdapter.stallTick wires them, with the
/// provider's probe bookkeeping (TribeDataWatchRuntime) in miniature.
final class SwitchRig {
    let net: Net
    var policy: TribeDataWatchPolicy
    var watch = TribeDataWatch()
    var arbiter = TribeRecoveryArbiter()
    var inputs = TribeDataWatchInputs()
    let home: String
    var plan: [String]
    var previous: TribeStallSample?
    var nextTick: TimeInterval
    private var probe: (due: TimeInterval, handshakeAtStart: Int64, answered: Bool, lateAt: TimeInterval?)?
    private var lateWatch: (until: TimeInterval, answerAt: TimeInterval?)?
    private var sanityDue: TimeInterval?
    var switches: [(t: TimeInterval, to: String, why: TribeSwitchReason, result: TribeCommandResult)] = []
    var heals: [(t: TimeInterval, result: TribeCommandResult)] = []
    var trials: [TimeInterval] = []
    var firstNoData: TimeInterval?
    var exhausted: [TimeInterval] = []

    init(_ net: Net, candidates: [String], _ tune: (inout TribeDataWatchPolicy) -> Void = { _ in }) {
        self.net = net
        var p = TribeDataWatchPolicy()
        p.enabled = true
        p.switchEnabled = true
        tune(&p)
        policy = p
        plan = candidates
        home = net.current
        nextTick = net.uptime + 1
        watch.noteDeviceStarted(at: net.uptime, policy: p)
    }
    var performed: [String] { switches.filter { $0.result == .performed }.map { $0.to } }
    func offered() -> [String] {
        var ids = plan.filter { $0 != net.current }
        if net.current != home && !ids.contains(home) { ids.append(home) }
        return ids
    }
    func run(_ seconds: Int) {
        for _ in 0..<seconds {
            net.second()
            if net.uptime + 1e-9 >= nextTick { tick() }
        }
    }
    private func deviceReplaced() {
        // tribeprobe.go: the probe in flight dies with the device; no late answer can be credited.
        if probe != nil {
            probe = nil
            inputs.probe = .notSent
            inputs.probeAt = net.uptime
        }
        lateWatch = nil
        previous = nil
        arbiter.rebaseAfterBackendRestart(TribeStallSample(txBytes: 0, rxBytes: 0, lastHandshakeSec: 0, at: net.uptime))
    }
    private func currentInputs() -> TribeDataWatchInputs {
        let now = net.uptime
        if let p = probe, now >= p.due {
            if p.answered {
                inputs.probe = .answered
                inputs.probeLatencyMs = 80
                net.rx += 120
            } else {
                inputs.probe = net.handshake == p.handshakeAtStart ? .silent : .staged
                lateWatch = (now + 35, p.lateAt)
            }
            inputs.probeAt = now
            probe = nil
        } else if probe == nil, let late = lateWatch {
            if now > late.until {
                lateWatch = nil
            } else if let at = late.answerAt, now >= at {
                lateWatch = nil
                inputs.lateAnswerAt = now
                net.rx += 120
            }
        }
        if let due = sanityDue, now >= due {
            inputs.sanity = .ok
            inputs.sanityAt = now
            sanityDue = nil
        }
        var current = inputs
        current.nodeId = net.current
        current.candidates = offered()
        // The provider keeps the hourly history of switches (a refused one does not count).
        current.switchesLastHour = switches.filter { $0.result != .denied && net.t - $0.t < 3600 }.count
        return current
    }
    private func startProbe(_ reason: TribeProbeReason) {
        if reason == .trial { trials.append(net.t) }
        lateWatch = nil
        guard net.keypairUsable else {
            inputs.probe = .noSession
            inputs.probeAt = net.uptime
            return
        }
        let n = net.node
        var answered = false
        var due = net.uptime + policy.probeTimeoutSeconds
        var lateAt: TimeInterval?
        if n.data(net.t) {
            let first = net.rng.next() >= net.loss, second = net.rng.next() >= net.loss
            if let late = n.lateBy {
                lateAt = due + late
            } else if first {
                answered = true
                due = net.uptime + 0.08
            } else if second {
                answered = true
                due = net.uptime + 1.58
            }
        }
        probe = (due, net.handshake, answered, lateAt)
        inputs.probe = .pending
    }
    private func tick() {
        let sample = TribeStallSample(txBytes: net.tx, rxBytes: net.rx, lastHandshakeSec: net.handshake, at: net.uptime)
        let idle = previous.map { $0.txBytes == sample.txBytes && $0.rxBytes == sample.rxBytes } ?? false
        previous = sample
        nextTick = net.uptime + (idle ? 5 : 1)
        var out = watch.step(TribeDataWatchSample(txBytes: sample.txBytes, rxBytes: sample.rxBytes, lastHandshakeSec: sample.lastHandshakeSec,
                                                  uptime: sample.at, wall: net.wall),
                             env: currentInputs().env(pathSatisfied: true), policy: policy)
        if out.verdict == .noData, firstNoData == nil { firstNoData = net.t }
        var executed = false
        if !out.isQuiet {
            if let command = out.command {
                let result = perform(command, sample)
                watch.noteCommandResult(command, result: result, at: net.uptime, policy: policy)
                out.commandResult = result
                executed = true
            }
            if out.needsSanityCheck, sanityDue == nil { sanityDue = net.uptime + 0.5 }
            if let reason = out.startProbe { startProbe(reason) }
            if out.exhausted { exhausted.append(net.t) }
        }
        if executed { return } // one executor per tick: the ladder skips this sample
        if watch.arbiterOwnsRecovery { return } // and one owner of recovery while a round is in progress
        if case .perform(let action) = arbiter.tick(sample, pathSatisfied: true, policy: .seamless), action == .softRestart {
            net.newDevice()
            deviceReplaced()
            watch.noteBackendRestarted(at: net.uptime, policy: policy)
        }
    }
    private func perform(_ command: TribeWatchCommand, _ sample: TribeStallSample) -> TribeCommandResult {
        switch command {
        case .heal(.freshPort):
            let result: TribeCommandResult = arbiter.requestFreshPort(sample, pathSatisfied: true) == .performed ? .performed : .denied
            heals.append((net.t, result))
            return result
        case .heal(.softRestart):
            guard arbiter.requestSoftRestart(sample, pathSatisfied: true) == .performed else {
                heals.append((net.t, .denied))
                return .denied
            }
            net.newDevice()
            deviceReplaced()
            watch.noteBackendRestarted(at: net.uptime, policy: policy)
            heals.append((net.t, .performed))
            return .performed
        case .switchPeer(let to, let why):
            guard offered().contains(to), net.nodes[to] != nil,
                  arbiter.requestPeerSwitch(sample, pathSatisfied: true) == .performed else {
                switches.append((net.t, to, why, .denied))
                return .denied
            }
            net.current = to
            net.newDevice()
            deviceReplaced()
            if inputs.probe != .unavailable { inputs.probe = .none }
            inputs.probeAt = nil
            inputs.lateAnswerAt = nil
            switches.append((net.t, to, why, .performed))
            return .performed
        }
    }
}

func deadPath() -> Node { var n = Node(); n.data = { _ in false }; return n }
func blockedNode() -> Node { var n = Node(); n.shakes = false; n.data = { _ in false }; return n }
func oneWayNode() -> Node { var n = Node(); n.oneWay = true; return n }

// 6. The shared recovery budget for switches: not limited by the episode of the node being left,
// limited by the rolling cap (4 interventions in 120 s) and by the cooldown between new devices.
do {
    var a = TribeRecoveryArbiter()
    var at: TimeInterval = 1000
    func sample(_ t: TimeInterval) -> TribeStallSample { TribeStallSample(txBytes: 10_000, rxBytes: 92, lastHandshakeSec: 1, at: t) }
    check(a.requestSoftRestart(sample(at), pathSatisfied: true) == .performed, "the episode's soft restart")
    check(a.requestSoftRestart(sample(at + 20), pathSatisfied: true) != .performed, "a second one in the episode is refused")
    check(a.requestPeerSwitch(sample(at + 20), pathSatisfied: true) == .performed, "a switch is not limited by the episode")
    check(a.requestPeerSwitch(sample(at + 22), pathSatisfied: true) != .performed, "but by the cooldown between two new devices")
    at += 40
    check(a.requestPeerSwitch(sample(at), pathSatisfied: true) == .performed && a.requestPeerSwitch(sample(at + 20), pathSatisfied: true) == .performed, "third and fourth intervention")
    check(a.requestPeerSwitch(sample(at + 40), pathSatisfied: true) != .performed, "the fifth in 120 s is refused by the rolling cap")
    check(a.requestPeerSwitch(sample(at + 130), pathSatisfied: true) == .performed, "and allowed when the window has moved on")
    check(a.requestPeerSwitch(sample(at + 300), pathSatisfied: false) == .offline && a.requestPeerSwitch(nil, pathSatisfied: true) == .notStarted, "no path, no counters: nothing")
}

// 7. Review vector B1: the path of 13.11 at 120 B/s (the ladder never steps, so the arbiter's own
// heals ARE performed). 8. At the field demand the ladder has spent both steps: the heals are
// refused - and each is still followed by its own probe; the dead node is left after three
// silent probes, not after one.
do {
    let low = Net()
    low.nodes = ["A": deadPath(), "B": Node()]
    low.demand = 120
    let rig = SwitchRig(low, candidates: ["B"])
    rig.run(600)
    check(rig.heals.map { $0.result } == [.performed, .performed], "120 B/s: the ladder left the budget alone, both heals are done: \(rig.heals)")
    check(rig.performed == ["B"] && low.current == "B", "then the working node: \(rig.performed)")
    check(rig.trials.count >= 2 && (rig.switches.first?.t ?? 0) - (rig.firstNoData ?? 0) >= 10 + 4 + 20 + 4, "after a probe per heal: \(rig.switches.first.map { $0.t } ?? -1) vs \(rig.firstNoData ?? -1)")

    let field = Net()
    field.nodes = ["A": deadPath(), "B": Node()]
    field.demand = 2000
    let dead = SwitchRig(field, candidates: ["B"])
    dead.run(400)
    check(dead.heals.count == 2 && dead.heals.allSatisfy { $0.result == .denied }, "2 KB/s: the ladder has spent the episode, both heals are refused: \(dead.heals)")
    let left = dead.switches.first { $0.result == .performed }?.t ?? -1
    let verdict = dead.firstNoData ?? -1
    check(dead.performed == ["B"] && left - verdict >= 28 && left - verdict <= 60, "a truly dead node is left about half a minute after the verdict, not two seconds: \(verdict) -> \(left)")
    check(dead.trials.filter { $0 < left }.count == 2, "two more silent probes before it is left: \(dead.trials)")
    print("13.11 path: at 120 B/s verdict \(Int(rig.firstNoData ?? -1)) s, left \(Int(rig.switches.first { $0.result == .performed }?.t ?? -1)) s; at 2 KB/s verdict \(Int(verdict)) s, left \(Int(left)) s")
}

// 9. Review vector B2: a node blocked by address (no handshake at all).
do {
    let net = Net()
    net.nodes = ["A": blockedNode(), "B": Node()]
    net.demand = 400
    let rig = SwitchRig(net, candidates: ["B"])
    rig.run(600)
    check(rig.performed == ["B"], "left by the silence of its handshakes: \(rig.performed)")
    check(rig.watch.snapshot(policy: rig.policy).trialProbesLastHour <= 1, "a probe that cannot leave spends no budget")
}

// 10. Review vector B3: a healthy one-way upload whose node answers the probe 4 s after the
// timeout. It was left 2 s after the verdict; now the late answer refutes the verdict first.
do {
    let net = Net()
    var slow = oneWayNode()
    slow.lateBy = 4
    net.nodes = ["A": slow, "B": Node()]
    net.demand = 50_000
    let rig = SwitchRig(net, candidates: ["B"])
    rig.run(1800)
    check(rig.performed.isEmpty && net.current == "A", "a node that answers late is never left: \(rig.switches)")
    check(rig.watch.snapshot(policy: rig.policy).refuted >= 1, "its late answers refute the verdict")
}

// 11. The review's lossy path: a healthy one-way upload, the app asleep, one hour, every probe
// attempt lost with probability p. With one silent probe enough: 5, 21 and 52 of 300 sessions
// were moved at p = 10, 20 and 30 per cent. Fixed seeds; nobody may be moved.
for loss in [0.1, 0.2, 0.3] {
    var moved = 0, judged = 0, trials = 0
    for seed in 1...300 {
        let net = Net()
        net.nodes = ["A": oneWayNode(), "B": Node(), "C": Node()]
        net.demand = 50_000
        net.loss = loss
        net.rng = Lcg(state: UInt64(seed) &* 7919)
        let rig = SwitchRig(net, candidates: ["B", "C"])
        rig.run(3600)
        if rig.firstNoData != nil { judged += 1 }
        if !rig.performed.isEmpty { moved += 1 }
        trials += rig.trials.count
    }
    print("lossy one-way upload, loss \(Int(loss * 100)) %: false no_data in \(judged) of 300 runs, moved in \(moved), trial probes \(trials)")
    check(moved == 0, "loss \(Int(loss * 100)) %: a healthy session was moved in \(moved) of 300 runs")
    if loss >= 0.2 {
        // The vector has teeth: the single silent probe that used to be enough does occur.
        check(judged >= 5, "loss \(Int(loss * 100)) %: a false no_data is expected in some runs, got \(judged)")
        check(trials >= judged, "and each of them was followed by more probes: \(trials)")
    }
}

// 12. Review finding R6: every node blocked for six hours while the physical network is fine.
// 72 in-place switches (20 in the first hour) before; now a hard ceiling per hour and a pause that
// stays at half an hour after the second failed round.
do {
    let net = Net()
    net.nodes = ["A": deadPath(), "B": deadPath(), "C": deadPath()]
    net.demand = 400
    let rig = SwitchRig(net, candidates: ["B", "C"])
    rig.run(6 * 3600)
    let performed = rig.switches.filter { $0.result == .performed }
    var perHour = [Int](repeating: 0, count: 6)
    for s in performed { perHour[min(5, Int(s.t / 3600))] += 1 }
    print("six hours, every node dead: switches per hour \(perHour), total \(performed.count), exhausted \(rig.exhausted.count) times, trial probes \(rig.trials.count)")
    check(perHour.allSatisfy { $0 <= rig.policy.switchMaxPerHour }, "never more than the ceiling in a clock hour: \(perHour)")
    for s in performed {
        let inHour = performed.filter { $0.t > s.t - 3600 && $0.t <= s.t }.count
        check(inHour <= rig.policy.switchMaxPerHour, "never more than the ceiling in ANY hour: \(inHour) at \(s.t)")
    }
    check(performed.count <= 36, "at most six an hour: \(performed.count)")
    check(perHour[2...].allSatisfy { $0 <= 6 } && rig.exhausted.count >= 5, "the rounds go on at the long pause: \(rig.exhausted.count)")
    let gaps = zip(rig.exhausted.dropFirst(2), rig.exhausted.dropFirst(1)).map { $0 - $1 }
    check(gaps.allSatisfy { $0 >= 1800 }, "from the third round on at least half an hour between rounds: \(gaps)")
    check(net.current == "A", "between rounds the tunnel stands on the node the rounds began on: \(net.current)")
    // The budget is shared: no more than four interventions in any 120 s.
    let all = (rig.heals.filter { $0.result == .performed }.map { $0.t } + performed.map { $0.t }).sorted()
    for t in all { check(all.filter { $0 > t - 120 && $0 <= t }.count <= 4, "the rolling cap of the recovery budget holds at \(t)") }
}

// 13. Review finding R4, the rule's part: an outage that hits every node for five minutes while
// the bypass targets answer. The tunnel walks the candidates, comes back to the node it began on,
// asks it afresh after the pause and stays: it does not end on an arbitrary candidate.
do {
    let net = Net()
    let outage: (TimeInterval) -> Bool = { $0 < 60 || $0 > 360 }
    var a = Node(), b = Node(), c = Node()
    a.data = outage
    b.data = outage
    c.data = outage
    a.oneWay = true // nothing comes back for the user's traffic even when it works: only the probe tells
    b.oneWay = true
    c.oneWay = true
    net.nodes = ["A": a, "B": b, "C": c]
    net.demand = 2000
    let rig = SwitchRig(net, candidates: ["B", "C"])
    rig.run(3600)
    check(!rig.performed.isEmpty, "the outage is real: the tunnel does move: \(rig.switches.map { "\($0.t):\($0.to)" })")
    check(net.current == "A" || rig.watch.verdict != .noData, "after the outage the tunnel stands on a node that answers: \(net.current) \(rig.watch.verdict)")
    let after = rig.switches.filter { $0.result == .performed && $0.t > 420 }
    check(after.isEmpty, "and nobody is moved once the nodes answer again: \(after.map { "\($0.t):\($0.to)" })")
}

if failures > 0 {
    print("TribeDataWatch + ladder: \(failures) check(s) FAILED")
    exit(1)
}
print("TribeDataWatch + ladder: all vectors passed")

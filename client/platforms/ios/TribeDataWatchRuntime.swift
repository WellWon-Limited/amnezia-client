import Foundation
import Network

// AVPN (build 140, data watch): the provider's half of the tunnel-side data watch.
//
// The verdict rule is pure and lives in the awg-apple package (TribeDataWatch.swift); the adapter
// feeds it on its existing stall tick. This object does what needs I/O and belongs to the
// provider: it reads the policy from the plan file the app writes, runs the two checks the rule
// asks for (a request that bypasses the tunnel, a probe through the tunnel) and tells the result:
// a line in ne.log, an event in the extension's journal ring, the `watch` block of the status
// reply and TribeWatchState.json. It moves nobody: stage 1 reports only.
//
// No timer of its own: the plan is re-read on the provider's existing 10 s statistics tick, the
// probe's result is polled on the adapter's tick. With no plan, a rejected plan or the flag off
// nothing here runs and the status reply has no `watch` key: the extension behaves as build 139.
//
// Everything the provider and the Go layer give it comes through `TribeDataWatchDeps`, and the
// adapter through a protocol: Foundation and Network only, so the whole chain (plan file ->
// policy -> adapter, the kill switch, the status reply, the probe's outcomes, the state file)
// runs in a host test with fakes (tests/TribeDataWatchRuntimeTests.swift).

/// What the runtime needs from the adapter (WireGuardAdapter conforms in the provider's glue).
protocol TribeDataWatchAdapting: AnyObject {
    var dataWatchInputs: ((_ handle: Int32) -> TribeDataWatchInputs)? { get set }
    var dataWatchHandler: ((_ handle: Int32, TribeDataWatchOutput, TribeDataWatchSnapshot) -> Void)? { get set }
    func setDataWatchPolicy(_ policy: TribeDataWatchPolicy)
    func dataWatchSnapshot(completionHandler: @escaping (TribeDataWatchSnapshot) -> Void)
}

/// What the runtime needs from the provider and from the Go layer.
struct TribeDataWatchDeps {
    /// The App Group container; nil = not available.
    var containerDirectory: () -> URL?
    var log: (String) -> Void
    /// One event of the extension's journal ring (labels and numbers only).
    var record: (_ event: String, _ fields: [String: Any]) -> Void
    /// Replaces TribeWatchState.json (the extension is its only writer).
    var writeState: (_ state: [String: Any]) -> Void
    /// wgSetTribeProbe: 0 = the probe is available for the next device.
    var setProbe: (_ clientIP: String, _ resolver: String, _ enabled: Bool) -> Int32
    /// wgTribeProbeStart / wgTribeProbeResult of the device that is up.
    var probeStart: (_ handle: Int32, _ timeoutMs: Int32) -> Int32
    var probeResult: (_ handle: Int32) -> String?
    /// "wifi" / "cellular" / ... of the current path.
    var uplinkKind: () -> String
    /// One check of the physical network: asks the targets and calls back exactly once.
    var sanityCheck: (_ targets: [TribeSanityTarget], _ completion: @escaping (TribeSanityResult) -> Void) -> Void
    var uptime: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    var nowMs: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
}

final class TribeDataWatchRuntime {
    /// A probe told as silent may still be answered: its reply is looked for this long (the Go
    /// layer's own window is 30 s; a little slack for the tick).
    static let lateAnswerWatchSeconds: TimeInterval = 35

    private let lock = NSLock()
    private var deps: TribeDataWatchDeps?
    private weak var adapter: TribeDataWatchAdapting?

    // Policy (plan file).
    private var policy = TribeDataWatchPolicy.disabled
    private var targets: [TribeSanityTarget] = []
    private var planData: Data?
    private var planStamp: String?
    private var lastOrder = TribeWatchPlan.Order()
    private var lastPlanState = "none"

    // Inputs of the rule owned by the provider.
    private var inputs = TribeDataWatchInputs()
    private var sanityRunning = false
    private var probeInFlight: Int32 = 0
    /// The last probe told as silent and until when (uptime) its late answer is looked for.
    private var lateWatch: (id: Int32, until: TimeInterval)?

    // Session labels for the journal (never endpoints).
    private var nodeId = "unknown"
    private var proto = "unknown"
    private var generation = ""
    private var lastVerdict = TribeDataVerdict.none

    /// The provider gives its side once, before the first session.
    func configure(_ deps: TribeDataWatchDeps) {
        lock.lock()
        self.deps = deps
        lock.unlock()
    }

    private var currentDeps: TribeDataWatchDeps? {
        lock.lock(); defer { lock.unlock() }
        return deps
    }

    // MARK: - Session lifecycle (provider queue)

    /// Before the adapter starts: read the plan and configure the probe through the tunnel in the
    /// Go layer (the device wraps the tunnel when it comes up). With the watch or its probe off
    /// this is an explicit reset: the device then reads the tunnel exactly as in build 139.
    /// Returns true when the probe is available for this device.
    @discardableResult
    func prepare(nodeId: String, proto: String, generation: String, clientIP: String, resolver: String) -> Bool {
        lock.lock()
        self.nodeId = nodeId
        self.proto = proto
        self.generation = generation
        inputs = TribeDataWatchInputs()
        sanityRunning = false
        probeInFlight = 0
        lateWatch = nil
        lastVerdict = .none
        planStamp = nil
        planData = nil
        let deps = self.deps
        lock.unlock()
        let current = reloadPlan()
        let wanted = current.enabled && current.probeEnabled
        let available = (deps?.setProbe(clientIP, resolver, wanted) ?? -1) == 0 && wanted
        if wanted { deps?.log("Tribe watch: probe \(available ? "available" : "unavailable")") }
        lock.lock()
        if !available { inputs.probe = .unavailable }
        lock.unlock()
        return available
    }

    func attach(adapter: TribeDataWatchAdapting) {
        lock.lock()
        self.adapter = adapter
        let current = policy
        lock.unlock()
        adapter.dataWatchInputs = { [weak self] handle in self?.currentInputs(handle: handle) ?? TribeDataWatchInputs() }
        adapter.dataWatchHandler = { [weak self] handle, output, snapshot in self?.handle(handle: handle, output, snapshot) }
        adapter.setDataWatchPolicy(current)
    }

    func detach() {
        lock.lock()
        adapter = nil
        policy = .disabled
        probeInFlight = 0
        lateWatch = nil
        lock.unlock()
    }

    // MARK: - The provider's 10 s statistics tick

    /// The whole tick as one sequence, so that its order is a tested fact and not a habit of the
    /// call site: the plan is re-read FIRST and ALWAYS (this is how the server's kill switch
    /// reaches a running extension - it must not depend on the file log being on), then the
    /// statistics line of the transport, which is diagnostics and is written only with the log on.
    func statsTick(isXray: Bool, loggingEnabled: Bool, logXray: () -> Void, logWireGuard: () -> Void) {
        refreshPlan()
        guard loggingEnabled else { return }
        if isXray { logXray() } else { logWireGuard() }
    }

    /// Pick up a rewritten plan and let a policy that has grown too old lapse.
    func refreshPlan() {
        lock.lock()
        let attached = adapter
        let before = policy
        lock.unlock()
        guard let attached else { return }
        let current = reloadPlan()
        if current != before { attached.setDataWatchPolicy(current) }
    }

    @discardableResult
    private func reloadPlan() -> TribeDataWatchPolicy {
        guard let deps = currentDeps, let directory = deps.containerDirectory() else { return .disabled }
        let url = directory.appendingPathComponent(TribeWatchPlan.fileName)
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        var stamp = attributes.map { "\(($0[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)/\(($0[.size] as? NSNumber)?.intValue ?? 0)" }
        lock.lock()
        var data = planData
        let changed = stamp != planStamp
        let alive = inputs.appSeenAt.map { deps.uptime() - $0 <= policy.appAliveSeconds } ?? false
        let seen = lastOrder
        lock.unlock()
        var unreadable = false
        if changed {
            // Never read more than the limit: a larger file is rejected by its size alone.
            let size = (attributes?[.size] as? NSNumber)?.intValue ?? 0
            if stamp == nil {
                data = nil
            } else if size > TribeWatchPlan.maxBytes {
                data = Data(count: TribeWatchPlan.maxBytes + 1)
            } else if let read = try? Data(contentsOf: url) {
                data = read
            } else {
                // The file is there and cannot be read (a tunnel started by iOS before the first
                // unlock: the file is protected until then). Not remembered under the file's
                // stamp: the next tick tries again.
                data = nil
                stamp = nil
                unreadable = true
            }
        }
        let parsed = TribeWatchPlan.parse(data, nowMs: deps.nowMs(), appAlive: alive, last: seen)
        var next = TribeDataWatchPolicy.disabled
        var nextTargets: [TribeSanityTarget] = []
        var state: String
        switch parsed {
        case .success(let plan):
            next = plan.policy
            nextTargets = (plan.sanityTargets.isEmpty ? TribeSanityTarget.builtIn : plan.sanityTargets).compactMap { TribeSanityTarget(url: $0) }
            state = next.enabled ? "on" : "off"
            lock.lock()
            lastOrder = plan.order
            lock.unlock()
        case .failure(let rejection):
            state = unreadable ? "unreadable" : rejection.rawValue
        }
        lock.lock()
        planStamp = stamp
        planData = data
        let wasEnabled = policy.enabled
        policy = next
        targets = nextTargets
        let previousState = lastPlanState
        let stateChanged = state != previousState
        lastPlanState = state
        if !next.enabled { lastVerdict = .none }
        let labels = (generation, nodeId, proto)
        lock.unlock()
        // "missing" is the normal state of an install whose flag was never on: nothing is written
        // for it, so such an extension leaves no trace of the watch at all.
        if stateChanged && !(state == "missing" && (previousState == "none" || previousState == "missing")) {
            deps.log("Tribe watch: plan=\(state)")
            deps.record("data_watch_plan", ["state": state, "generation": labels.0, "node_id": labels.1])
        }
        // The watch went off: the shared file must not keep the verdict of a watch that is gone.
        if wasEnabled && !next.enabled {
            deps.writeState(["schema": 1, "enabled": false, "verdict": TribeDataVerdict.none.rawValue, "generation": labels.0,
                             "node_id": labels.1, "proto": labels.2, "updated_ms": deps.nowMs(), "switch_seq": 0, "switches": [Any]()])
        }
        return next
    }

    // MARK: - The app

    /// The app asked for the status: it is alive (it polls once a second while it runs).
    func noteAppStatusRequest() {
        lock.lock()
        if let deps { inputs.appSeenAt = deps.uptime() }
        lock.unlock()
    }

    /// The `watch` block of the status reply; nil = no block at all (the watch is off: the reply
    /// is byte-for-byte the one of build 139). The completion is ALWAYS called: the status reply
    /// waits for it.
    func statusBlock(completion: @escaping ([String: Any]?) -> Void) {
        lock.lock()
        let enabled = policy.enabled
        let live = adapter
        lock.unlock()
        guard enabled, let live else { completion(nil); return }
        live.dataWatchSnapshot { snapshot in
            var block = snapshot.asDictionary
            // Stage 2 (in-place switch) fills these; the protocol already carries them.
            block["switch_seq"] = 0
            block["switches"] = [Any]()
            completion(snapshot.enabled ? block : nil)
        }
    }

    /// For the statistics line.
    var statsSuffix: String {
        lock.lock(); defer { lock.unlock() }
        return policy.enabled ? " node=\(nodeId) watch=\(lastVerdict.rawValue)" : ""
    }

    // MARK: - The rule's side (adapter workQueue: field reads and cheap C calls)

    private func currentInputs(handle: Int32) -> TribeDataWatchInputs {
        lock.lock()
        let flying = probeInFlight
        let late = lateWatch
        let deps = self.deps
        lock.unlock()
        guard let deps else { return TribeDataWatchInputs() }
        let now = deps.uptime()
        if flying != 0 {
            let result = TribeDataWatchJournal.parseProbeResult(deps.probeResult(handle) ?? "")
            // Another id or "none" means our probe is gone (a new device): it was never judged.
            let state: TribeProbeResult = result.id == flying ? result.state : .notSent
            if state != .pending {
                lock.lock()
                if probeInFlight == flying {
                    probeInFlight = 0
                    inputs.probe = state == .none ? .notSent : state
                    inputs.probeAt = now
                    inputs.probeLatencyMs = result.latencyMs
                    // A probe judged silent (or staged) may still get its answer.
                    lateWatch = (state == .silent || state == .staged) ? (flying, now + Self.lateAnswerWatchSeconds) : nil
                }
                lock.unlock()
            }
        } else if let late {
            if now > late.until {
                lock.lock()
                if lateWatch?.id == late.id { lateWatch = nil }
                lock.unlock()
            } else {
                let result = TribeDataWatchJournal.parseProbeResult(deps.probeResult(handle) ?? "")
                // (A new probe ends this look-out in startProbe, so the result is still that probe's.)
                if result.state == .answered {
                    lock.lock()
                    if lateWatch?.id == late.id {
                        lateWatch = nil
                        inputs.lateAnswerAt = now
                        inputs.probeLatencyMs = result.latencyMs
                    }
                    lock.unlock()
                }
            }
        }
        lock.lock(); defer { lock.unlock() }
        return inputs
    }

    private func handle(handle: Int32, _ output: TribeDataWatchOutput, _ snapshot: TribeDataWatchSnapshot) {
        guard let deps = currentDeps else { return }
        if output.needsSanityCheck { startSanityCheck(deps) }
        if output.startProbe != nil { startProbe(deps, handle: handle) }
        guard output.action == .report, let report = output.report else { return }
        lock.lock()
        lastVerdict = snapshot.verdict
        let labels = (nodeId, proto, generation)
        lock.unlock()
        let net = deps.uplinkKind()
        deps.log(TribeDataWatchJournal.line(report: report, verdict: output.verdict, snapshot: snapshot,
                                            nodeId: labels.0, proto: labels.1, net: net))
        deps.record("data_watch", TribeDataWatchJournal.fields(report: report, verdict: output.verdict, snapshot: snapshot,
                                                               nodeId: labels.0, proto: labels.1, net: net, generation: labels.2))
        // Every report rewrites the file: it always holds the verdict the rule holds now (a
        // verdict that ended is a report too).
        var state = snapshot.asDictionary
        state["schema"] = 1
        state["generation"] = labels.2
        state["node_id"] = labels.0
        state["proto"] = labels.1
        state["net"] = net
        state["updated_ms"] = deps.nowMs()
        state["switch_seq"] = 0
        state["switches"] = [Any]()
        deps.writeState(state)
    }

    // MARK: - The probe through the tunnel

    private func startProbe(_ deps: TribeDataWatchDeps, handle: Int32) {
        lock.lock()
        let timeout = policy.probeTimeoutSeconds
        lock.unlock()
        // A probe that was not configured has no wrapper: the Go layer answers 0 (unavailable).
        let outcome = TribeDataWatchJournal.startOutcome(deps.probeStart(handle, Int32(timeout * 1000)))
        let now = deps.uptime()
        lock.lock()
        lateWatch = nil // a new question: the old probe's late answer is not waited for any more
        switch outcome {
        case .started(let id):
            probeInFlight = id
            inputs.probe = .pending
        case .noSession:
            probeInFlight = 0
            inputs.probe = .noSession
            inputs.probeAt = now
        case .unavailable:
            probeInFlight = 0
            inputs.probe = .unavailable
            inputs.probeAt = now
        }
        lock.unlock()
    }

    // MARK: - The request that bypasses the tunnel

    /// One check at a time; the runner calls back exactly once (TribeSanityRunner bounds every
    /// request with its own deadline).
    private func startSanityCheck(_ deps: TribeDataWatchDeps) {
        lock.lock()
        if sanityRunning { lock.unlock(); return }
        sanityRunning = true
        let list = targets
        lock.unlock()
        deps.sanityCheck(list) { [weak self] result in
            guard let self else { return }
            self.lock.lock()
            self.sanityRunning = false
            self.inputs.sanity = result
            self.inputs.sanityAt = deps.uptime()
            self.lock.unlock()
        }
    }
}

/// The request that bypasses the tunnel, for real. Every connection is REQUIRED to use the
/// physical interface of the current path (NWParameters.requiredInterface =
/// nw_parameters_require_interface; the SDK routes a provider's connection through the tunnel only
/// when it is given the virtual interface the same way, NEPacketTunnelProvider.h
/// `virtualInterface`), so the request cannot travel through the tunnel it is judging.
/// The targets are asked one after another until one gives the known answer; every request has
/// its own deadline, so the completion is always called.
enum TribeSanityRunner {
    static let requestDeadlineSeconds: TimeInterval = 3
    private static let queue = DispatchQueue(label: "hk.wellwon.tribe.data-watch", qos: .utility)

    static func run(_ targets: [TribeSanityTarget], interface: @escaping () -> NWInterface?,
                    completion: @escaping (TribeSanityResult) -> Void) {
        queue.async {
            // No physical interface at all: there is no network to ask.
            guard let physical = interface(), !targets.isEmpty else { completion(.noReply); return }
            ask(targets, index: 0, interface: physical, results: [], completion: completion)
        }
    }

    private static func ask(_ list: [TribeSanityTarget], index: Int, interface: NWInterface, results: [TribeSanityResult],
                            completion: @escaping (TribeSanityResult) -> Void) {
        guard index < list.count, !results.contains(.ok) else {
            let combined = TribeSanityTarget.combine(results)
            completion(combined == .unknown ? .noReply : combined)
            return
        }
        let target = list[index]
        let parameters: NWParameters = target.kind == .tls ? NWParameters(tls: NWProtocolTLS.Options(), tcp: NWProtocolTCP.Options()) : .tcp
        parameters.requiredInterface = interface
        parameters.preferNoProxies = true
        guard let port = NWEndpoint.Port(rawValue: target.port) else {
            ask(list, index: index + 1, interface: interface, results: results + [.noReply], completion: completion)
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(target.host), port: port, using: parameters)
        var finished = false
        let finish: (TribeSanityResult) -> Void = { result in
            guard !finished else { return }
            finished = true
            connection.cancel()
            ask(list, index: index + 1, interface: interface, results: results + [result], completion: completion)
        }
        var received = Data()
        func readMore() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, error in
                if let data { received.append(data) }
                let complete = isComplete || error != nil || received.count >= 4096
                if let result = TribeSanityTarget.classify(received, complete: complete) {
                    finish(result)
                } else {
                    readMore() // a 200 whose body has not arrived yet
                }
            }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if target.kind == .tls {
                    // The handshake completed and the certificate check passed: the real host.
                    finish(TribeSanityTarget.classifyTLS(ready: true, tlsFailure: false))
                    return
                }
                connection.send(content: target.request, completion: .contentProcessed { error in
                    if error != nil { finish(.noReply); return }
                    readMore()
                })
            case .failed(let error), .waiting(let error):
                var tlsFailure = false
                if case .tls = error { tlsFailure = true }
                if tlsFailure {
                    finish(TribeSanityTarget.classifyTLS(ready: false, tlsFailure: true))
                } else if case .failed = state {
                    finish(.noReply)
                }
                // waiting without a TLS failure: the deadline below decides.
            case .cancelled:
                finish(.noReply)
            default:
                break
            }
        }
        // The deadline of this one request (also covers a path that stays "waiting"). It ends a
        // request; it decides nothing about the tunnel.
        queue.asyncAfter(deadline: .now() + requestDeadlineSeconds) { finish(.noReply) }
        connection.start(queue: queue)
    }
}

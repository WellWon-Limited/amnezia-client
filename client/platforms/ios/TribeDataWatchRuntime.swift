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
final class TribeDataWatchRuntime {
    private let lock = NSLock()
    private let ioQueue = DispatchQueue(label: "hk.wellwon.tribe.data-watch", qos: .utility)
    private weak var adapter: WireGuardAdapter?

    // Policy (plan file).
    private var policy = TribeDataWatchPolicy.disabled
    private var targets: [TribeSanityTarget] = []
    private var planData: Data?
    private var planStamp: String?
    private var lastPoolRevision: Int64 = 0
    private var lastPlanState = "none"

    // Inputs of the rule owned by the provider.
    private var inputs = TribeDataWatchInputs()
    private var sanityRunning = false
    private var probeInFlight: Int32 = 0
    private var probeConfigured = false

    // Session labels for the journal (never endpoints).
    private var nodeId = "unknown"
    private var proto = "unknown"
    private var generation = ""
    private var lastVerdict = TribeDataVerdict.none

    /// The physical interface of the current path and its kind ("wifi" / "cellular" / ...): the
    /// provider's own path monitor answers both.
    var physicalInterface: (() -> NWInterface?)?
    var uplinkKind: (() -> String)?

    private static var uptime: TimeInterval { ProcessInfo.processInfo.systemUptime }
    private static var nowMs: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: - Session lifecycle (provider queue)

    /// Before the adapter starts: read the plan. Returns true when the probe through the tunnel
    /// should be configured for this device (the watch and its probe are on).
    func prepare(nodeId: String, proto: String, generation: String) -> Bool {
        lock.lock()
        self.nodeId = nodeId
        self.proto = proto
        self.generation = generation
        inputs = TribeDataWatchInputs()
        sanityRunning = false
        probeInFlight = 0
        probeConfigured = false
        lastVerdict = .none
        planStamp = nil
        planData = nil
        lock.unlock()
        let current = reloadPlan()
        return current.enabled && current.probeEnabled
    }

    /// `probeConfigured`: wgSetTribeProbe accepted the session's addresses.
    func attach(adapter: WireGuardAdapter, probeConfigured: Bool) {
        lock.lock()
        self.adapter = adapter
        self.probeConfigured = probeConfigured
        if !probeConfigured { inputs.probe = .unavailable }
        let current = policy
        lock.unlock()
        adapter.dataWatchInputs = { [weak self] in self?.currentInputs() ?? TribeDataWatchInputs() }
        adapter.dataWatchHandler = { [weak self] output, snapshot in self?.handle(output, snapshot) }
        adapter.setDataWatchPolicy(current)
    }

    func detach() {
        lock.lock()
        adapter = nil
        policy = .disabled
        probeInFlight = 0
        lock.unlock()
    }

    // MARK: - Policy

    /// The provider's 10 s statistics tick: pick up a rewritten plan (the kill switch reaches the
    /// extension here) and let a policy that has grown too old lapse.
    func refreshPlan() {
        lock.lock()
        let attached = adapter != nil
        let before = policy
        lock.unlock()
        guard attached else { return }
        let current = reloadPlan()
        if current != before { adapterIfAttached()?.setDataWatchPolicy(current) }
    }

    private func adapterIfAttached() -> WireGuardAdapter? {
        lock.lock(); defer { lock.unlock() }
        return adapter
    }

    @discardableResult
    private func reloadPlan() -> TribeDataWatchPolicy {
        guard let store = TribeSharedState.appGroup else { return .disabled }
        let url = store.directory.appendingPathComponent(TribeWatchPlan.fileName)
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let stamp = attributes.map { "\(($0[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)/\(($0[.size] as? NSNumber)?.intValue ?? 0)" }
        lock.lock()
        var data = planData
        let changed = stamp != planStamp
        let alive = inputs.appSeenAt.map { Self.uptime - $0 <= policy.appAliveSeconds } ?? false
        let seenRevision = lastPoolRevision
        lock.unlock()
        if changed {
            // Never read more than the limit: a larger file is rejected by its size alone.
            let size = (attributes?[.size] as? NSNumber)?.intValue ?? 0
            data = stamp == nil ? nil : (size > TribeWatchPlan.maxBytes ? Data(count: TribeWatchPlan.maxBytes + 1) : try? Data(contentsOf: url))
        }
        let parsed = TribeWatchPlan.parse(data, nowMs: Self.nowMs, appAlive: alive, lastPoolRevision: seenRevision)
        var next = TribeDataWatchPolicy.disabled
        var nextTargets: [TribeSanityTarget] = []
        var state: String
        switch parsed {
        case .success(let plan):
            next = plan.policy
            nextTargets = (plan.sanityURLs.isEmpty ? TribeSanityTarget.builtIn : plan.sanityURLs).compactMap { TribeSanityTarget(url: $0) }
            state = next.enabled ? "on" : "off"
            lock.lock()
            lastPoolRevision = max(lastPoolRevision, plan.poolRevision)
            lock.unlock()
        case .failure(let rejection):
            state = rejection.rawValue
        }
        lock.lock()
        planStamp = stamp
        planData = data
        policy = next
        targets = nextTargets
        let previousState = lastPlanState
        let stateChanged = state != previousState
        lastPlanState = state
        let labels = (generation, nodeId)
        lock.unlock()
        // "missing" is the normal state of an install whose flag was never on: nothing is written
        // for it, so such an extension leaves no trace of the watch at all.
        if stateChanged && !(state == "missing" && (previousState == "none" || previousState == "missing")) {
            wg_log(.info, message: "Tribe watch: plan=\(state)")
            TribeSharedState.appGroup?.recordAsync(source: "ne", event: "data_watch_plan",
                                                   fields: ["state": state, "generation": labels.0, "node_id": labels.1])
        }
        return next
    }

    // MARK: - The app

    /// The app asked for the status: it is alive (it polls once a second while it runs).
    func noteAppStatusRequest() {
        lock.lock()
        inputs.appSeenAt = Self.uptime
        lock.unlock()
    }

    /// The `watch` block of the status reply; nil = no block at all (the watch is off: the reply
    /// is byte-for-byte the one of build 139).
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

    // MARK: - The rule's side (adapter workQueue: only field reads and one cheap C call)

    private func currentInputs() -> TribeDataWatchInputs {
        lock.lock()
        let flying = probeInFlight
        lock.unlock()
        if flying != 0, let raw = wgTribeProbeResult() {
            let result = TribeDataWatchJournal.parseProbeResult(String(cString: raw))
            free(raw)
            // Another id or "none" means our probe is gone (a new session): it was never judged.
            let state: TribeProbeResult = result.id == flying ? result.state : .notSent
            if state != .pending {
                lock.lock()
                if probeInFlight == flying {
                    probeInFlight = 0
                    inputs.probe = state == .none ? .notSent : state
                    inputs.probeAt = Self.uptime
                    inputs.probeLatencyMs = result.latencyMs
                }
                lock.unlock()
            }
        }
        lock.lock(); defer { lock.unlock() }
        return inputs
    }

    private func handle(_ output: TribeDataWatchOutput, _ snapshot: TribeDataWatchSnapshot) {
        if output.needsSanityCheck { startSanityCheck() }
        if output.startProbe != nil { startProbe() }
        guard output.action == .report, let report = output.report else { return }
        lock.lock()
        lastVerdict = snapshot.verdict
        let labels = (nodeId, proto, generation)
        lock.unlock()
        let net = uplinkKind?() ?? "unknown"
        wg_log(.info, message: TribeDataWatchJournal.line(report: report, verdict: output.verdict, snapshot: snapshot,
                                                          nodeId: labels.0, proto: labels.1, net: net))
        guard let store = TribeSharedState.appGroup else { return }
        store.recordAsync(source: "ne", event: "data_watch",
                          fields: TribeDataWatchJournal.fields(report: report, verdict: output.verdict, snapshot: snapshot,
                                                               nodeId: labels.0, proto: labels.1, net: net, generation: labels.2))
        var state = snapshot.asDictionary
        state["schema"] = 1
        state["generation"] = labels.2
        state["node_id"] = labels.0
        state["proto"] = labels.1
        state["net"] = net
        state["updated_ms"] = Self.nowMs
        state["switch_seq"] = 0
        state["switches"] = [Any]()
        // The extension is the only writer and write() replaces the file atomically: no lock.
        TribeSharedState.journalQueue.async { try? store.write(state, TribeWatchPlan.stateFileName) }
    }

    // MARK: - The probe through the tunnel

    private func startProbe() {
        lock.lock()
        let configured = probeConfigured
        let timeout = policy.probeTimeoutSeconds
        lock.unlock()
        let id = configured ? wgTribeProbeStart(Int32(timeout * 1000)) : 0
        lock.lock()
        if id > 0 {
            probeInFlight = id
            inputs.probe = .pending
        } else {
            probeInFlight = 0
            inputs.probe = .unavailable
            inputs.probeAt = Self.uptime
        }
        lock.unlock()
    }

    // MARK: - The request that bypasses the tunnel

    /// One check at a time. Every connection is REQUIRED to use the physical interface of the
    /// current path (NWParameters.requiredInterface = nw_parameters_require_interface; the SDK
    /// routes a provider's connection through the tunnel only when it is given the virtual
    /// interface the same way, NEPacketTunnelProvider.h `virtualInterface`), so the request cannot
    /// travel through the tunnel it is judging.
    private func startSanityCheck() {
        lock.lock()
        if sanityRunning { lock.unlock(); return }
        sanityRunning = true
        let list = targets
        lock.unlock()
        ioQueue.async { [weak self] in
            guard let self else { return }
            guard let interface = self.physicalInterface?(), !list.isEmpty else {
                self.finishSanity(interface: false, results: [])
                return
            }
            self.ask(list, index: 0, interface: interface, results: [])
        }
    }

    private func ask(_ list: [TribeSanityTarget], index: Int, interface: NWInterface, results: [TribeSanityResult]) {
        guard index < list.count, !results.contains(.ok) else {
            finishSanity(interface: true, results: results)
            return
        }
        let target = list[index]
        let parameters = NWParameters.tcp
        parameters.requiredInterface = interface
        parameters.preferNoProxies = true
        guard let port = NWEndpoint.Port(rawValue: target.port) else {
            ask(list, index: index + 1, interface: interface, results: results + [.noReply])
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(target.host), port: port, using: parameters)
        var finished = false
        let finish: (TribeSanityResult) -> Void = { [weak self] result in
            guard !finished else { return }
            finished = true
            connection.cancel()
            self?.ask(list, index: index + 1, interface: interface, results: results + [result])
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: target.request, completion: .contentProcessed { error in
                    if error != nil { finish(.noReply); return }
                    connection.receive(minimumIncompleteLength: 12, maximumLength: 2048) { data, _, _, _ in
                        finish(data.map { TribeSanityTarget.classify($0) } ?? .noReply)
                    }
                })
            case .failed, .cancelled:
                finish(.noReply)
            default:
                break
            }
        }
        // The deadline of this one request (also covers a path that stays "waiting").
        ioQueue.asyncAfter(deadline: .now() + 3) { finish(.noReply) }
        connection.start(queue: ioQueue)
    }

    private func finishSanity(interface: Bool, results: [TribeSanityResult]) {
        // No physical interface at all is "no reply": there is no network to ask.
        let result = interface ? TribeSanityTarget.combine(results) : .noReply
        lock.lock()
        sanityRunning = false
        inputs.sanity = result == .unknown ? .noReply : result
        inputs.sanityAt = Self.uptime
        lock.unlock()
    }
}

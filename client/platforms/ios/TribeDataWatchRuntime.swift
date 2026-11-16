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
    /// Stage 2: no engine runs after a failed switch (true) / one runs again (false).
    var dataWatchEngineHandler: ((_ down: Bool) -> Void)? { get set }
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
    /// Stage 2: TribeWatchState.json as the previous run of the extension left it (its list of
    /// nodes judged dead); nil = no file. Read only when the plan permits switching.
    var readState: () -> [String: Any]? = { nil }
    /// Stage 2: replaces TribeWatchPlan.json with the given bytes (the same protection class,
    /// excluded from backups); false = could not. Used for one thing only: to take the candidates'
    /// keys out of the file when the permission to switch is gone.
    var writePlan: (_ plan: Data) -> Bool = { _ in false }
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
    /// The probe before the one in flight, while its reply may still come (third review, T3): a
    /// path that answers later than one whole wait must refute the verdict, not disturb the next probe.
    private var previousLateWatch: (id: Int32, until: TimeInterval)?

    // Session labels for the journal (never endpoints). `nodeId` is the node the tunnel stands on
    // NOW: after an in-place switch (stage 2) it is not the profile's node any more.
    private var nodeId = "unknown"
    private var proto = "unknown"
    private var generation = ""
    private var lastVerdict = TribeDataVerdict.none

    // Stage 2 (features.ios_tunnel_watch_switch): the node of the profile, what a switch keeps of the
    // session, the plan's candidates, and the switches made in this run of the extension.
    private var homeNodeId = "unknown"
    private var switchBase: TribeSwitchBase?
    private var plan: TribeWatchPlan?
    private var switchSeq = 0
    private var switches: [[String: Any]] = []
    static let maxSwitchesKept = 8
    /// Nodes this extension judged dead, per kind of network, for half an hour (TribeStartChoice).
    /// They survive every rewrite of the shared file and the end of the session: the next start
    /// by the system and a change of network skip them.
    private var dead: [TribeStartChoice.LastFailure] = []
    private var deadLoaded = false
    /// Candidates whose configuration could not be used (it does not parse, or the engine did not
    /// start on it): not offered again while this plan lives.
    private var rejected: Set<String> = []
    /// Grows with every new plan the app wrote (the arbiter's long pause ends with one).
    private var planEpoch = 0
    /// No engine runs after a failed switch: the status reply and the shared file say so.
    private var engineDown = false
    /// The stamp of the plan file the candidates were last taken out of (once per file).
    private var scrubbedStamp: String?
    /// "host:port" of the node the tunnel stands on when that is not the profile's node. Kept apart
    /// from the plan: a plan that is rewritten, rejected or expires later must not change what the
    /// status reply says about a switch already made.
    private var actualEndpoint: String?
    /// The candidate last handed to the adapter (it becomes `actualEndpoint` if the switch is performed).
    private var handedOut: (node: String, endpoint: String)?

    /// What the adapter needs to move the tunnel to `nodeId`.
    enum SwitchTarget: Equatable {
        /// The node of the profile: the configuration the session started with.
        case home
        /// A candidate of the plan: its wg-quick text.
        case candidate(String)
    }

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
    func prepare(nodeId: String, proto: String, generation: String, clientIP: String, resolver: String,
                 base: TribeSwitchBase? = nil) -> Bool {
        lock.lock()
        self.nodeId = nodeId
        self.homeNodeId = nodeId
        self.switchBase = base
        self.plan = nil
        self.switchSeq = 0
        self.switches = []
        self.actualEndpoint = nil
        self.handedOut = nil
        self.dead = []
        self.deadLoaded = false
        self.rejected = []
        self.engineDown = false
        self.scrubbedStamp = nil
        self.proto = proto
        self.generation = generation
        inputs = TribeDataWatchInputs()
        sanityRunning = false
        probeInFlight = 0
        lateWatch = nil
        previousLateWatch = nil
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
        adapter.dataWatchEngineHandler = { [weak self] down in self?.noteEngine(down: down) }
        adapter.setDataWatchPolicy(current)
    }

    func detach() {
        lock.lock()
        adapter = nil
        policy = .disabled
        probeInFlight = 0
        lateWatch = nil
        previousLateWatch = nil
        lock.unlock()
    }

    // MARK: - Stage 2: where the tunnel stands and where it may go

    /// The nodes offered to the arbiter: the plan's candidates except the node the tunnel is on,
    /// and the profile's node whenever the tunnel has left it. Empty unless the switch key is on, the
    /// lease and the list are alive and the provider told what a switch keeps. A candidate whose
    /// configuration was rejected is not offered again while the plan lives.
    private func offeredLocked() -> [String] {
        guard policy.enabled, policy.switchEnabled, switchBase != nil, let plan else { return [] }
        var ids = plan.candidates.map { $0.nodeId }.filter { $0 != nodeId && !rejected.contains($0) }
        if nodeId != homeNodeId && !ids.contains(homeNodeId) { ids.append(homeNodeId) }
        return ids
    }

    /// For the adapter's question "what is the configuration of this node"; nil = not a node the
    /// arbiter was offered.
    func switchTarget(_ node: String) -> SwitchTarget? {
        lock.lock(); defer { lock.unlock() }
        guard offeredLocked().contains(node), let base = switchBase else { return nil }
        if node == homeNodeId { return .home }
        guard let candidate = plan?.candidates.first(where: { $0.nodeId == node }) else { return nil }
        handedOut = (node, candidate.endpoint)
        return .candidate(candidate.wgQuick(base: base))
    }

    /// The provider could not build a configuration from this candidate (the package's strict
    /// parse refused it): never offered again while the plan lives.
    func markRejected(_ node: String) {
        lock.lock()
        rejected.insert(node)
        lock.unlock()
    }

    /// What the status reply says about switches of this run of the extension - on EVERY reply,
    /// so that the app learns of a switch from an ordinary poll too. nil = no switch was made (the
    /// reply is then the one of build 139). `nodeId` / `endpoint` are set while the tunnel is NOT
    /// on the profile's node: the app recognises a node by its id and its "host:port".
    func sessionSwitch() -> (seq: Int, why: String, nodeId: String?, endpoint: String?)? {
        lock.lock(); defer { lock.unlock() }
        guard switchSeq > 0 else { return nil }
        let why = switches.last?["why"] as? String ?? "unknown"
        guard let endpoint = actualEndpoint else { return (switchSeq, why, nil, nil) }
        return (switchSeq, why, nodeId, endpoint)
    }

    /// The node dead-node records and the choice are about: read from the previous run's file
    /// once, and only when the plan permits switching (with the keys off nothing is read).
    private func loadDeadLocked(_ deps: TribeDataWatchDeps) {
        guard !deadLoaded else { return }
        deadLoaded = true
        dead = TribeStartChoice.failures(state: deps.readState(), nowMs: deps.nowMs())
    }

    /// The node to come up on at a start, when it is not the profile's. `source` is what the
    /// start carried (`tribeStartSource`): the app and our own commands always name themselves,
    /// and a start that names anybody raises the profile's node - only a start by the system
    /// (no source at all) may choose (TribeStartChoice). Call after `prepare`. The choice is
    /// recorded as the first switch of this run, so the app adopts it like any other.
    /// nil = the profile's node; nothing is read and nothing is written in that case unless the
    /// plan permits switching.
    func chooseStart(source: String?) -> (nodeId: String, why: String, wgQuick: String)? {
        guard TribeStartChoice.startedBySystem(source: source), let deps = currentDeps else { return nil }
        lock.lock()
        guard policy.enabled, policy.switchEnabled, let base = switchBase, let plan, !plan.candidates.isEmpty else {
            lock.unlock()
            return nil
        }
        lock.unlock()
        let net = deps.uplinkKind()
        lock.lock()
        loadDeadLocked(deps)
        let home = homeNodeId
        let choice = TribeStartChoice.choose(profileNodeId: home, plan: plan, net: net, failures: dead, nowMs: deps.nowMs())
        guard choice.nodeId != home, let candidate = plan.candidates.first(where: { $0.nodeId == choice.nodeId }) else {
            lock.unlock()
            return nil
        }
        nodeId = choice.nodeId
        actualEndpoint = candidate.endpoint
        switchSeq = 1
        switches = [["from": home, "to": choice.nodeId, "why": "os_start_\(choice.why)", "utc_ms": deps.nowMs(), "net": net]]
        let labels = (generation, proto)
        lock.unlock()
        deps.log("Tribe watch: start candidate=\(choice.nodeId) why=\(choice.why) profile=\(home) net=\(net)")
        deps.record("peer_switch", ["from": home, "to": choice.nodeId, "why": "os_start_\(choice.why)", "seq": 1, "net": net,
                                    "result": TribeCommandResult.performed.rawValue, "generation": labels.0])
        return (choice.nodeId, choice.why, candidate.wgQuick(base: base))
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
            if plan.order != lastOrder {
                // A new plan from the app: the arbiter's long pause ends, rejected candidates
                // get another chance (the app may have new data for them).
                planEpoch += 1
                rejected = []
            }
            lastOrder = plan.order
            self.plan = plan
            if next.switchEnabled { loadDeadLocked(deps) }
            lock.unlock()
            // The permission to switch is gone (key off, lease lapsed, list expired) and the file
            // still holds the candidates' keys: take them out. Not while the app is alive (it is
            // the writer and may be writing a new plan), once per file, and only if the file is
            // still the one that was read.
            if plan.holdsUnusableSecrets, !alive, let stamp, let data, scrubbedStampIs(not: stamp) {
                scrub(data, stamp: stamp, url: url, deps: deps)
            }
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
            writeState(["enabled": false, "verdict": TribeDataVerdict.none.rawValue], net: nil, deps: deps)
        }
        return next
    }

    private func scrubbedStampIs(not stamp: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return scrubbedStamp != stamp
    }

    private func scrub(_ data: Data, stamp: String, url: URL, deps: TribeDataWatchDeps) {
        lock.lock()
        scrubbedStamp = stamp
        lock.unlock()
        guard let clean = TribeWatchPlan.scrubbed(data) else { return }
        // The app may have written a newer plan since the read: then the file is not ours to touch.
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let now = attributes.map { "\(($0[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)/\(($0[.size] as? NSNumber)?.intValue ?? 0)" }
        guard now == stamp else { return }
        let done = deps.writePlan(clean)
        deps.log("Tribe watch: plan candidates removed (switch permission is gone) result=\(done ? "done" : "failed")")
    }

    /// TribeWatchState.json, every time in full: the session's labels, the switches of this run,
    /// the nodes judged dead and whether an engine runs. `fields` is the verdict part.
    private func writeState(_ fields: [String: Any], net: String?, deps: TribeDataWatchDeps) {
        var state = fields
        lock.lock()
        state["schema"] = 1
        state["generation"] = generation
        state["node_id"] = nodeId
        state["proto"] = proto
        state["switch_seq"] = switchSeq
        state["switches"] = switches
        state["dead"] = TribeStartChoice.encode(dead)
        state["engine"] = engineDown ? "down" : "up"
        lock.unlock()
        if let net { state["net"] = net }
        state["updated_ms"] = deps.nowMs()
        deps.writeState(state)
    }

    /// Stage 2: the adapter lost its engine after a failed switch, or got one back.
    private func noteEngine(down: Bool) {
        guard let deps = currentDeps else { return }
        lock.lock()
        let changed = engineDown != down
        engineDown = down
        let labels = (nodeId, generation)
        let verdict = lastVerdict
        lock.unlock()
        guard changed else { return }
        deps.log(TribeDataWatchJournal.engineLine(down: down, nodeId: labels.0))
        deps.record("watch_engine", ["state": down ? "down" : "up", "node_id": labels.0, "generation": labels.1])
        writeState(["enabled": true, "verdict": verdict.rawValue], net: deps.uplinkKind(), deps: deps)
    }

    /// For the status reply: no engine runs (the adapter cannot answer with counters). The app
    /// that sees it restarts the tunnel itself.
    var engineIsDown: Bool {
        lock.lock(); defer { lock.unlock() }
        return engineDown
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
        live.dataWatchSnapshot { [weak self] snapshot in
            var block = snapshot.asDictionary
            // The switches of this run (stage 2); read here, on the adapter's queue, AFTER the
            // snapshot: a switch executed on that queue just before is already counted.
            let made = self?.switchesMade() ?? (0, [])
            block["switch_seq"] = made.0
            block["switches"] = made.1
            completion(snapshot.enabled ? block : nil)
        }
    }

    /// For the statistics line.
    var statsSuffix: String {
        lock.lock(); defer { lock.unlock() }
        return policy.enabled ? " node=\(nodeId) watch=\(lastVerdict.rawValue)" : ""
    }

    private func switchesMade() -> (Int, [[String: Any]]) {
        lock.lock(); defer { lock.unlock() }
        return (switchSeq, switches)
    }

    /// The configuration of the node chosen at a start by the system could not be built: the
    /// tunnel comes up on the profile's node after all.
    func cancelStartChoice() {
        lock.lock()
        nodeId = homeNodeId
        actualEndpoint = nil
        switchSeq = 0
        switches = []
        lock.unlock()
        currentDeps?.log("Tribe watch: start candidate dropped (configuration rejected), the profile's node is used")
    }

    // MARK: - The rule's side (adapter workQueue: field reads and cheap C calls)

    private func currentInputs(handle: Int32) -> TribeDataWatchInputs {
        lock.lock()
        let flying = probeInFlight
        let late = lateWatch
        let previousLate = previousLateWatch
        let deps = self.deps
        lock.unlock()
        guard let deps else { return TribeDataWatchInputs() }
        let now = deps.uptime()
        if flying != 0 {
            let result = TribeDataWatchJournal.parseProbeResult(deps.probeResult(handle) ?? "")
            // Another id or "none" means our probe is gone (a new device): it was never judged.
            let state: TribeProbeResult = result.id == flying ? result.state : .notSent
            lock.lock()
            // The reply to the probe before this one came in while this one flies: a late answer.
            if let previous = previousLateWatch {
                if now > previous.until || result.id != flying {
                    previousLateWatch = nil
                } else if result.latePrevious == previous.id {
                    previousLateWatch = nil
                    inputs.lateAnswerAt = now
                }
            }
            if state != .pending, probeInFlight == flying {
                probeInFlight = 0
                inputs.probe = state == .none ? .notSent : state
                inputs.probeAt = now
                inputs.probeLatencyMs = result.latencyMs
                // A probe judged silent (or staged) may still get its answer.
                lateWatch = (state == .silent || state == .staged) ? (flying, now + Self.lateAnswerWatchSeconds) : nil
            }
            lock.unlock()
        } else if late != nil || previousLate != nil {
            // No probe in flight: the reply to the last one (and to the one before it) may still come.
            let result = TribeDataWatchJournal.parseProbeResult(deps.probeResult(handle) ?? "")
            lock.lock()
            if let late, lateWatch?.id == late.id {
                if now > late.until {
                    lateWatch = nil
                } else if result.state == .answered, result.id == late.id {
                    lateWatch = nil
                    inputs.lateAnswerAt = now
                    inputs.probeLatencyMs = result.latencyMs
                }
            }
            if let previous = previousLate, previousLateWatch?.id == previous.id {
                if now > previous.until {
                    previousLateWatch = nil
                } else if result.latePrevious == previous.id {
                    previousLateWatch = nil
                    inputs.lateAnswerAt = now
                }
            }
            lock.unlock()
        }
        lock.lock()
        var current = inputs
        current.nodeId = nodeId
        current.candidates = offeredLocked()
        current.planEpoch = planEpoch
        let choosing = !current.candidates.isEmpty ? (plan, homeNodeId, dead) : nil
        lock.unlock()
        // Where a start on the network the phone is on NOW would go (the rule uses it only right
        // after a change of network, for a node that has not proved itself).
        if let (plan, home, dead) = choosing {
            current.networkChoice = TribeStartChoice.choose(profileNodeId: home, plan: plan, net: deps.uplinkKind(),
                                                            failures: dead, nowMs: deps.nowMs()).nodeId
        }
        return current
    }

    private func handle(handle: Int32, _ output: TribeDataWatchOutput, _ snapshot: TribeDataWatchSnapshot) {
        guard let deps = currentDeps else { return }
        if output.needsSanityCheck { startSanityCheck(deps) }
        if output.startProbe != nil { startProbe(deps, handle: handle) }
        let net = deps.uplinkKind()
        // Stage 2: what the arbiter ordered and the adapter has already executed on this tick.
        if let command = output.command, let result = output.commandResult {
            noteCommand(command, result: result, snapshot: snapshot, net: net, deps: deps)
        }
        if output.exhausted {
            lock.lock()
            let labels = (nodeId, generation)
            lock.unlock()
            deps.log(TribeDataWatchJournal.exhaustedLine(snapshot: snapshot, nodeId: labels.0, net: net))
            deps.record("watch_exhausted", ["tried": snapshot.arbiterTried, "round": snapshot.arbiterRound, "node_id": labels.0,
                                            "net": net, "generation": labels.1])
        }
        guard output.action == .report, let report = output.report else { return }
        lock.lock()
        lastVerdict = snapshot.verdict
        let labels = (nodeId, proto, generation)
        // A node judged dead is remembered for this kind of network for half an hour - unless the
        // verdict is taken back: a refutation (a late answer too), an answered trial or returned
        // data prove that the node passes data here, and the record goes with the verdict.
        if output.verdict == .noData {
            dead = TribeStartChoice.noting(TribeStartChoice.LastFailure(nodeId: nodeId, net: net, wallMs: deps.nowMs()),
                                           in: dead, nowMs: deps.nowMs())
        } else if report == .refuted || report == .trial || output.verdict == .recovered {
            dead.removeAll { $0.nodeId == nodeId && $0.net == net }
        }
        lock.unlock()
        deps.log(TribeDataWatchJournal.line(report: report, verdict: output.verdict, snapshot: snapshot,
                                            nodeId: labels.0, proto: labels.1, net: net))
        deps.record("data_watch", TribeDataWatchJournal.fields(report: report, verdict: output.verdict, snapshot: snapshot,
                                                               nodeId: labels.0, proto: labels.1, net: net, generation: labels.2))
        // Every report rewrites the file: it always holds the verdict the rule holds now (a
        // verdict that ended is a report too).
        writeState(snapshot.asDictionary, net: net, deps: deps)
    }

    /// The journal of a command, and after a performed switch the new identity of the session: the
    /// node the tunnel stands on, the number of the switch (`switch_seq` - the app adopts a switch
    /// by it), the last eight switches. The shared file is rewritten at once: the verdict it held
    /// was about the node the tunnel has left.
    private func noteCommand(_ command: TribeWatchCommand, result: TribeCommandResult, snapshot: TribeDataWatchSnapshot,
                             net: String, deps: TribeDataWatchDeps) {
        lock.lock()
        let from = nodeId
        var switched = false
        // A candidate whose configuration cannot be used is not offered again while the plan lives.
        if case .switchPeer(let to, _) = command, result == .rejected { rejected.insert(to) }
        // The node being left for want of data is a node judged dead on this network - whatever
        // came of the switch.
        if case .switchPeer(_, .noData) = command, result != .denied {
            dead = TribeStartChoice.noting(TribeStartChoice.LastFailure(nodeId: from, net: net, wallMs: deps.nowMs()),
                                           in: dead, nowMs: deps.nowMs())
        }
        if case .switchPeer(let to, let why) = command, result == .performed {
            switched = true
            nodeId = to
            // The way back to the profile's node hands out no candidate: its endpoint is the profile's.
            actualEndpoint = handedOut?.node == to ? handedOut?.endpoint : nil
            switchSeq += 1
            switches.append(["from": from, "to": to, "why": why.rawValue, "utc_ms": deps.nowMs(), "net": net])
            if switches.count > Self.maxSwitchesKept { switches.removeFirst(switches.count - Self.maxSwitchesKept) }
            // A new device on another node: what was learned through the old one is void.
            lastVerdict = .none
            probeInFlight = 0
            lateWatch = nil
            previousLateWatch = nil
            if inputs.probe != .unavailable { inputs.probe = .none }
            inputs.probeAt = nil
            inputs.lateAnswerAt = nil
        }
        let seq = switchSeq
        let labels = (nodeId, proto, generation)
        lock.unlock()
        deps.log(TribeDataWatchJournal.commandLine(command, result: result, from: from, seq: seq, net: net))
        switch command {
        case .heal(let kind):
            deps.record("watch_heal", ["step": kind.rawValue, "result": result.rawValue, "node_id": from, "net": net,
                                       "generation": labels.2])
        case .switchPeer(let to, let why):
            deps.record("peer_switch", ["from": from, "to": to, "why": why.rawValue, "seq": seq, "net": net,
                                        "result": result.rawValue, "generation": labels.2])
        }
        guard switched else { return }
        writeState(snapshot.asDictionary, net: net, deps: deps)
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
        switch outcome {
        case .started(let id):
            // A new question. The old probe's late answer is still looked for while this one flies
            // (the Go layer tells it as " prev_late=<id>").
            previousLateWatch = lateWatch.flatMap { $0.until > now && $0.id != id ? $0 : nil }
            lateWatch = nil
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

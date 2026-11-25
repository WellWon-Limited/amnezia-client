import Foundation

// AVPN (build 141, data watch): host test of the provider's half (TribeDataWatchRuntime.swift) with
// fakes for the adapter, the Go layer, the shared container and the bypass check. The fake adapter
// runs the REAL rule the way WireGuardAdapter.dataWatchTick does, so every scenario goes the whole
// way: plan file -> policy -> rule -> checks -> log line, journal event, status block, state file.
//
// Written after an independent review found that this glue was proven only by reading: the kill
// switch (read with the file log off too), the status reply (always answered), the probe's
// configuration with the watch off, the outputs after a verdict ended.
@main
enum TribeDataWatchRuntimeTests {
    static var failures = 0
    static var current = ""
    static func check(_ cond: @autoclosure () -> Bool, _ what: @autoclosure () -> String, line: Int = #line) {
        if !cond() { failures += 1; print("FAIL \(current) line \(line): \(what())") }
    }
    static func run(_ name: String, _ body: () -> Void) {
        current = name
        body()
    }

    /// What WireGuardAdapter does for the watch, with the real rule inside.
    final class FakeAdapter: TribeDataWatchAdapting {
        var dataWatchInputs: ((_ handle: Int32) -> TribeDataWatchInputs)?
        var dataWatchHandler: ((_ handle: Int32, TribeDataWatchOutput, TribeDataWatchSnapshot) -> Void)?
        var dataWatchEngineHandler: ((_ down: Bool) -> Void)?
        var policy = TribeDataWatchPolicy.disabled
        var policiesSet: [TribeDataWatchPolicy] = []
        var watch = TribeDataWatch()
        let handle: Int32 = 3
        var tx: UInt64 = 0
        var rx: UInt64 = 0
        var handshake: Int64 = 0
        var snapshotCalls = 0
        /// Stage 2: the adapter executes the arbiter's commands on the tick, as the real one does
        /// (WireGuardAdapter.dataWatchTick): it asks the provider for the node's configuration.
        var switchTarget: ((String) -> TribeDataWatchRuntime.SwitchTarget?)?
        var healResult = TribeCommandResult.denied
        /// The switch itself fails in the adapter (the endpoint does not resolve, the settings are refused).
        var switchFails = false
        /// Nodes on whose configuration the engine does not start (the adapter rolls back: rejected).
        var engineRejects: Set<String> = []
        var commands: [(command: TribeWatchCommand, result: TribeCommandResult)] = []
        var switched: [(node: String, target: TribeDataWatchRuntime.SwitchTarget)] = []
        var lastInputs = TribeDataWatchInputs()

        func setDataWatchPolicy(_ policy: TribeDataWatchPolicy) {
            self.policy = policy
            policiesSet.append(policy)
        }
        func dataWatchSnapshot(completionHandler: @escaping (TribeDataWatchSnapshot) -> Void) {
            snapshotCalls += 1
            completionHandler(watch.snapshot(policy: policy))
        }
        func start(at uptime: TimeInterval) {
            if policy.enabled { watch.noteDeviceStarted(at: uptime, policy: policy) }
        }
        func tick(uptime: TimeInterval, wall: TimeInterval) {
            guard policy.enabled else {
                watch = TribeDataWatch()
                return
            }
            let inputs = dataWatchInputs?(handle) ?? TribeDataWatchInputs()
            lastInputs = inputs
            var output = watch.step(TribeDataWatchSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: handshake, uptime: uptime, wall: wall),
                                    env: inputs.env(pathSatisfied: true), policy: policy)
            guard !output.isQuiet else { return }
            if let command = output.command {
                var result = TribeCommandResult.performed
                switch command {
                case .heal(let kind):
                    result = healResult
                    if result == .performed && kind == .softRestart {
                        watch.noteBackendRestarted(at: uptime, policy: policy)
                        tx = 0; rx = 0; handshake = 0
                    }
                case .switchPeer(let node, _):
                    // As WireGuardAdapter.performDataWatchCommand: no configuration = rejected.
                    if let target = switchTarget?(node) {
                        if switchFails {
                            result = .failed
                        } else if engineRejects.contains(node) {
                            result = .rejected
                        } else {
                            switched.append((node, target))
                            tx = 0; rx = 0; handshake = 0
                        }
                    } else {
                        result = .rejected
                    }
                }
                watch.noteCommandResult(command, result: result, at: uptime, policy: policy)
                output.commandResult = result
                commands.append((command, result))
            }
            dataWatchHandler?(handle, output, watch.snapshot(policy: policy))
        }
    }

    /// The provider's side, in memory.
    final class Bench {
        let directory: URL
        var uptime: TimeInterval = 1000
        var wallMs: Int64 = 1_800_000_000_000
        var logs: [String] = []
        var records: [(event: String, fields: [String: Any])] = []
        var states: [[String: Any]] = []
        var setProbeCalls: [(client: String, resolver: String, enabled: Bool)] = []
        var setProbeResult: Int32 = 0
        var probeStarts: [(handle: Int32, timeoutMs: Int32)] = []
        var probeStartCode: Int32 = 5
        var probeResult: String? = "state=pending id=5 ms=0 late=0"
        var probeResultPolls = 0
        var sanityAsked: [[TribeSanityTarget]] = []
        var sanityAnswer: TribeSanityResult? = .ok
        var planSeq: Int64 = 0
        /// Stage 2: what the previous run of the extension left in TribeWatchState.json.
        var previousState: [String: Any]?
        var stateReads = 0
        var uplinkReads = 0
        var uplink = "cellular"
        /// awg-apple tribe.17: the session's own handshake bytes (WGConfig.serviceTraffic in the provider).
        var sessionHandshakeTx: UInt64 = 0
        /// What the extension wrote into the plan file itself (only ever a scrubbed copy).
        var plansWritten: [Data] = []
        /// The write of the extension fails (a full disk, a locked file).
        var planWriteFails = false
        /// Runs between the extension's check of the file and its write (the test of the two writers).
        var betweenCheckAndWrite: (() -> Void)?
        let runtime = TribeDataWatchRuntime()
        let adapter = FakeAdapter()

        init() {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent("tribe-watch-runtime-\(UUID().uuidString)")
            try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            runtime.configure(TribeDataWatchDeps(
                containerDirectory: { [unowned self] in self.directory },
                log: { [unowned self] in self.logs.append($0) },
                record: { [unowned self] event, fields in self.records.append((event, fields)) },
                writeState: { [unowned self] in self.states.append($0) },
                setProbe: { [unowned self] client, resolver, enabled in
                    self.setProbeCalls.append((client, resolver, enabled))
                    return self.setProbeResult
                },
                probeStart: { [unowned self] handle, timeoutMs in
                    self.probeStarts.append((handle, timeoutMs))
                    return self.probeStartCode
                },
                probeResult: { [unowned self] _ in
                    self.probeResultPolls += 1
                    return self.probeResult
                },
                uplinkKind: { [unowned self] in self.uplinkReads += 1; return self.uplink },
                sanityCheck: { [unowned self] targets, completion in
                    self.sanityAsked.append(targets)
                    if let answer = self.sanityAnswer { completion(answer) }
                },
                uptime: { [unowned self] in self.uptime },
                sessionHandshakeTxBytes: { [unowned self] in self.sessionHandshakeTx },
                nowMs: { [unowned self] in self.wallMs },
                readState: { [unowned self] in self.stateReads += 1; return self.previousState },
                replacePlan: { [unowned self] expected, clean in
                    self.plansWritten.append(clean)
                    if self.planWriteFails { return .failed }
                    return TribeWatchPlanFile.replaceIfUnchanged(in: self.directory, expected: expected, with: clean, afterCheck: self.betweenCheckAndWrite)
                }))
            adapter.switchTarget = { [unowned self] node in self.runtime.switchTarget(node) }
        }

        static let key32 = Data(repeating: 9, count: 32).base64EncodedString()
        /// A candidate entry as the app writes it.
        static func candidate(_ node: Int) -> [String: Any] {
            ["node_id": node, "country": "FI",
             "peer": ["hostName": "198.51.100.\(node)", "port": "585", "server_pub_key": key32, "persistent_keep_alive": "25",
                      "Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "55", "S2": "66", "H1": "1", "H2": "2", "H3": "3", "H4": "4"]]
        }
        static let base = TribeSwitchBase(address: "10.8.1.7/32", dns: "1.1.1.1, 1.0.0.1", mtu: "1280", privateKey: "PRIVATE", allowedIPs: "0.0.0.0/0, ::/0")
        deinit { try? FileManager.default.removeItem(at: directory) }

        var planURL: URL { directory.appendingPathComponent(TribeWatchPlan.fileName) }

        /// The app writes a plan (atomically, a new sequence number every time).
        func writePlan(watch: Bool = true, numbers: [String: Any] = [:], poolRevision: Int64 = 1_763_190_000_000,
                       fetchedAgoMs: Int64 = 60_000, targets: [String]? = nil,
                       switchOn: Bool = false, candidates: [Int] = [], expiresInMs: Int64 = 86_400_000,
                       pin: Int = 0, memory: [String: Int] = [:], leaseInMs: Int64 = 6 * 3600 * 1000) {
            planSeq += 1
            var object: [String: Any] = [
                "schema": 2, "seq": planSeq, "written_ms": wallMs, "config_fetched_ms": wallMs - fetchedAgoMs,
                "policy_max_age_ms": 86_400_000, "expires_ms": wallMs + expiresInMs, "pool_revision": poolRevision,
                "switch_lease_until_ms": switchOn ? wallMs + leaseInMs : 0,
                "features": ["ios_tunnel_watch": watch, "ios_tunnel_watch_switch": switchOn, "ios_on_demand_bg_arm": false],
                "numbers": numbers, "candidates": candidates.map { Bench.candidate($0) },
                "pin": ["country": pin > 0 ? "FI" : "", "node_id": pin],
                "net_keys": ["wifi": "wifi", "cellular": "cellular:250-02"],
                "net_memory": Dictionary(uniqueKeysWithValues: memory.map { (($0.key == "cellular" ? "cellular:250-02" : $0.key), ["node_id": $0.value, "saved_ms": 1] as [String: Any]) }),
            ]
            if let targets { object["sanity_targets"] = targets }
            try! JSONSerialization.data(withJSONObject: object).write(to: planURL, options: .atomic)
        }

        /// A session comes up the way startWireguard does it.
        @discardableResult
        func startSession(nodeId: String = "16", base: TribeSwitchBase? = Bench.base) -> Bool {
            let available = runtime.prepare(nodeId: nodeId, proto: "awg", generation: "gen-1", clientIP: "10.8.1.7/32", resolver: "1.1.1.1",
                                            base: base)
            runtime.attach(adapter: adapter)
            adapter.start(at: uptime)
            return available
        }

        func second(tx: UInt64 = 0, rx: UInt64 = 0, handshake: Bool = false) {
            uptime += 1
            wallMs += 1000
            adapter.tx += tx
            adapter.rx += rx
            if handshake {
                adapter.tx += 422
                adapter.rx += 92
                adapter.handshake = wallMs / 1000
            }
            adapter.tick(uptime: uptime, wall: Double(wallMs) / 1000)
        }

        /// Outbound demand, a handshake now and then, not one transport packet back.
        func deadPath(seconds: Int, handshakeEvery: Int = 1000) {
            for second in 1...seconds { self.second(tx: 400, handshake: second % handshakeEvery == 0) }
        }

        var lastState: [String: Any] { states.last ?? [:] }
        func statusBlock() -> (called: Int, block: [String: Any]?) {
            var called = 0
            var block: [String: Any]?
            runtime.statusBlock { called += 1; block = $0 }
            return (called, block)
        }
    }

    /// Stage 2: the arbiter's commands through the whole extension - the plan's candidates, the
    /// adapter executing on the tick, the identity of the session and the journal.
    static func stageTwo() {
        /// The world of these scenarios: every probe is silent until told otherwise, the heals are
        /// refused by the shared budget.
        func dead(_ b: Bench, seconds: Int) {
            for second in 1...seconds { b.second(tx: 400, handshake: b.adapter.handshake == 0 ? second % 3 == 0 : false) }
        }
        func untilSwitched(_ b: Bench, _ count: Int = 1, limit: Int = 600) {
            for _ in 1...limit where b.adapter.switched.count < count { dead(b, seconds: 1) }
        }
        func prepared(_ tune: (Bench) -> Void = { _ in }, source: String?) -> (Bench, (nodeId: String, why: String, wgQuick: String)?) {
            let b = Bench()
            tune(b)
            _ = b.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            return (b, b.runtime.chooseStart(source: source))
        }
        func deadRecords(_ state: [String: Any]) -> [String] { (state["dead"] as? [[String: Any]] ?? []).compactMap { $0["node_id"] as? String } }
        /// Pin and profile are node 12, the plan offers 16 and 9; the probe is silent up to the verdict.
        func judgedOnTwelve() -> Bench {
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [16, 9], pin: 12)
            b.startSession(nodeId: "12")
            b.probeResult = "state=silent id=5 ms=0 late=0"
            for second in 1...200 where b.adapter.watch.verdict != .noData {
                b.second(tx: 400, handshake: b.adapter.handshake == 0 ? second % 3 == 0 : false)
            }
            return b
        }
        /// iOS raises the tunnel again `minutes` later with the same plan and what the previous run left.
        func startBySystem(after b: Bench, minutes: Int64) -> String {
            let next = Bench()
            next.wallMs = b.wallMs + minutes * 60_000
            next.writePlan(switchOn: true, candidates: [16, 9], pin: 12)
            next.previousState = b.lastState
            _ = next.runtime.prepare(nodeId: "12", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            return next.runtime.chooseStart(source: nil)?.nodeId ?? "12"
        }
        run("refuted_verdict_takes_its_dead_record_back") {
            // Third review, T1 (the reviewer's sequence on the real runtime): pin and profile are
            // node 12; one silent probe; the answer arrives 6 s later; ten minutes later iOS restarts
            // the tunnel. It came up on node 16: the record written at the verdict was never removed.
            let b = judgedOnTwelve()
            check(b.adapter.watch.verdict == .noData && deadRecords(b.lastState) == ["12"], "a verdict: node 12 is on record: \(deadRecords(b.lastState))")
            check(startBySystem(after: b, minutes: 10) == "16", "while the verdict stands a start by the system avoids the node")
            dead(b, seconds: 5)
            b.probeResult = "state=answered id=5 ms=6000 late=1"
            dead(b, seconds: 2)
            check(b.logs.contains { $0.contains("event=refuted") } && b.adapter.watch.verdict != .noData, "the late answer refutes the verdict: \(b.logs.suffix(2))")
            check(deadRecords(b.lastState).isEmpty, "and the record goes with it: \(deadRecords(b.lastState))")
            check(startBySystem(after: b, minutes: 10) == "12", "ten minutes later iOS restarts the tunnel: the pinned node 12")
            // Only the record of that node on that network goes: what was judged about another node, or
            // about this node on another network, stands.
            let k = Bench()
            k.writePlan(switchOn: true, candidates: [16, 9], pin: 12)
            k.previousState = ["verdict": "none", "dead": [["node_id": "9", "net": "cellular", "at_ms": k.wallMs - 60_000],
                                                             ["node_id": "12", "net": "wifi", "at_ms": k.wallMs - 60_000]]]
            k.startSession(nodeId: "12")
            k.probeResult = "state=silent id=5 ms=0 late=0"
            for second in 1...200 where k.adapter.watch.verdict != .noData { k.second(tx: 400, handshake: k.adapter.handshake == 0 ? second % 3 == 0 : false) }
            func pairs(_ state: [String: Any]) -> Set<String> { Set((state["dead"] as? [[String: Any]] ?? []).map { "\($0["node_id"] ?? "")@\($0["net"] ?? "")" }) }
            check(pairs(k.lastState) == ["9@cellular", "12@wifi", "12@cellular"], "three records at the verdict: \(pairs(k.lastState))")
            dead(k, seconds: 5)
            k.probeResult = "state=answered id=5 ms=6000 late=1"
            dead(k, seconds: 2)
            check(pairs(k.lastState) == ["9@cellular", "12@wifi"], "the refutation takes back its own record only: \(pairs(k.lastState))")
            // An answered trial takes the record back as well.
            let t = judgedOnTwelve()
            let starts = t.probeStarts.count
            for _ in 1...30 where t.probeStarts.count == starts { dead(t, seconds: 1) }
            t.probeResult = "state=answered id=5 ms=40 late=0"
            dead(t, seconds: 2)
            check(t.logs.contains { $0.contains("event=trial") } && deadRecords(t.lastState).isEmpty && startBySystem(after: t, minutes: 10) == "12",
                  "an answered second probe: no record, the next start by the system raises node 12: \(deadRecords(t.lastState))")
            // Returned data (16 KiB) ends the verdict and the record too.
            let r = judgedOnTwelve()
            for _ in 1...3 { r.second(tx: 400, rx: 8000) }
            check(r.adapter.watch.verdict != .noData && deadRecords(r.lastState).isEmpty, "data came back: no record: \(deadRecords(r.lastState))")
        }
        run("late_answer_to_the_previous_probe_is_a_refutation") {
            // Third review, T3: the reply to the confirming probe arrives while the next probe is
            // already in flight (the Go layer tells it as prev_late=<id>).
            let b = judgedOnTwelve()
            let starts = b.probeStarts.count
            b.probeStartCode = 6
            for _ in 1...30 where b.probeStarts.count == starts { dead(b, seconds: 1) }
            check(b.probeStarts.count == starts + 1, "the second probe is in flight")
            b.probeResult = "state=pending id=6 ms=0 late=0"
            dead(b, seconds: 1)
            check(b.adapter.watch.verdict == .noData, "nothing yet")
            b.probeResult = "state=pending id=6 ms=0 late=0 prev_late=5"
            dead(b, seconds: 1)
            var snap = b.adapter.watch.snapshot(policy: b.adapter.policy)
            check(b.logs.contains { $0.contains("event=refuted") } && b.adapter.watch.verdict != .noData && snap.refuted == 1,
                  "the previous probe's late answer is a refutation: \(b.logs.suffix(2))")
            check(deadRecords(b.lastState).isEmpty && b.adapter.switched.isEmpty, "no record of a dead node, nobody is moved")
            b.probeResult = "state=silent id=6 ms=0 late=0 prev_late=5"
            dead(b, seconds: 5)
            snap = b.adapter.watch.snapshot(policy: b.adapter.policy)
            check(snap.disturbed == 0 && snap.trialProbesLastHour == 0 && !b.logs.contains { $0.contains("event=disturbed") },
                  "the probe that was in flight is neither a disturbed probe nor a spent one: \(snap.disturbed) \(snap.trialProbesLastHour)")
            check(b.adapter.watch.verdict != .noData && b.logs.filter { $0.contains("event=refuted") }.count == 1, "told once: \(b.logs.suffix(6)) starts \(b.probeStarts.count - starts)")
            // Outside its window the previous probe is not listened for.
            let old = judgedOnTwelve()
            let before = old.probeStarts.count
            old.probeStartCode = 6
            for _ in 1...30 where old.probeStarts.count == before { dead(old, seconds: 1) }
            old.probeResult = "state=pending id=7 ms=0 late=0 prev_late=5" // another probe's line (a new device)
            dead(old, seconds: 1)
            check(!old.logs.contains { $0.contains("event=refuted") }, "a result line of another probe credits nobody")
        }
        run("hourly_ceiling_survives_a_policy_toggle_and_a_restart") {
            // Third review, T5: the ceiling of switches per hour was forgotten when the watch policy
            // went off and on inside one run (the rule forgets everything at the kill switch) and at
            // every restart of the extension - 36 switches an hour were reached. The history is the
            // provider's now, and it lies in the state file.
            let numbers: [String: Any] = ["ios_tw_switch_max_per_hour": 2, "ios_tw_trial_probe_max_per_hour": 60]
            let b = Bench()
            b.writePlan(numbers: numbers, switchOn: true, candidates: [12, 9, 3])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b, 2)
            check(b.adapter.switched.count == 2 && (b.lastState["switch_times"] as? [Int64])?.count == 2, "two switches, both in the state file: \(b.lastState["switch_times"] ?? "-")")
            dead(b, seconds: 400)
            check(b.adapter.switched.count == 2 && b.adapter.lastInputs.switchesLastHour == 2, "the ceiling holds: \(b.adapter.switched.count)")
            // The watch goes off and on (a plan rewrite): the rule starts from nothing, the ceiling does not.
            b.writePlan(watch: false)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(b, seconds: 5)
            check(!b.adapter.policy.enabled, "the watch is off")
            b.writePlan(numbers: numbers, switchOn: true, candidates: [12, 9, 3])
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(b, seconds: 900)
            check(b.adapter.policy.switchEnabled && b.adapter.watch.verdict == .noData && b.adapter.switched.count == 2,
                  "off and on inside the hour: not one more switch: \(b.adapter.switched.count)")
            // The extension is restarted (iOS, a crash): the new run reads the history.
            let next = Bench()
            next.wallMs = b.wallMs + 60_000
            next.writePlan(numbers: numbers, switchOn: true, candidates: [12, 9, 3])
            next.previousState = b.lastState
            next.startSession()
            next.probeResult = "state=silent id=5 ms=0 late=0"
            dead(next, seconds: 900)
            check(next.adapter.watch.verdict == .noData && next.adapter.switched.isEmpty && next.adapter.lastInputs.switchesLastHour == 2,
                  "a new run inside the hour: the ceiling of the previous run holds: \(next.adapter.switched.count) \(next.adapter.lastInputs.switchesLastHour)")
            // An hour after the first two the ceiling frees up.
            for _ in 1...3000 where next.adapter.switched.isEmpty { dead(next, seconds: 1) }
            check(next.adapter.switched.count == 1 && next.wallMs - b.wallMs < 3_600_000, "the hour of the old switches has passed: the next one is made: \(next.adapter.switched.count)")
            // An attempt that failed counts and is written at once; one the budget refused is not the runtime's to count.
            let f = Bench()
            f.writePlan(numbers: numbers, switchOn: true, candidates: [12, 9])
            f.startSession()
            f.adapter.switchFails = true
            f.probeResult = "state=silent id=5 ms=0 late=0"
            for _ in 1...600 where !f.logs.contains(where: { $0.contains("result=failed") }) { dead(f, seconds: 1) }
            check((f.lastState["switch_times"] as? [Int64])?.count == 1 && f.adapter.switched.isEmpty, "a failed attempt is in the file: \(f.lastState["switch_times"] ?? "-")")
            // With the switch key off the previous run's file is not read at all (build 139).
            let off = Bench()
            off.writePlan()
            off.previousState = b.lastState
            off.startSession()
            dead(off, seconds: 30)
            check(off.stateReads == 0 && off.adapter.lastInputs.switchesLastHour == 0, "key off: nothing is read")
        }
        run("switch_goes_through_the_whole_extension") {
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b)
            // On the very tick of the switch: the shared file already names the new node and holds
            // no verdict of the node the tunnel has left (nothing waits for the next report).
            check(b.adapter.switched.count == 1 && b.lastState["node_id"] as? String == "12" && b.lastState["switch_seq"] as? Int == 1
                  && b.lastState["verdict"] as? String == "none", "the shared file follows the switch at once: \(b.lastState["node_id"] ?? "-") \(b.lastState["verdict"] ?? "-")")
            dead(b, seconds: 8)
            check(b.adapter.commands.map { "\($0.command)" }.prefix(2).allSatisfy { $0.contains("heal") } && b.adapter.switched.first?.node == "12",
                  "two heals (refused by the shared budget), then the plan's first candidate: \(b.adapter.commands)")
            if case .candidate(let text)? = b.adapter.switched.first?.target {
                check(text.contains("Endpoint = 198.51.100.12:585\n") && text.contains("PrivateKey = PRIVATE\n") && text.contains("Address = 10.8.1.7/32\n")
                      && text.contains("AllowedIPs = 0.0.0.0/0, ::/0\n") && text.contains("H4 = 4\n"),
                      "the adapter got the candidate's peer on the session's own interface: \(text)")
            } else {
                check(false, "the adapter must get the candidate's configuration text")
            }
            check(b.logs.contains("Tribe watch: heal step=fresh_port result=denied node=16 net=cellular")
                  && b.logs.contains("Tribe watch: heal step=soft_restart result=denied node=16 net=cellular"), "the heals are journaled with their result: \(b.logs.suffix(6))")
            check(b.logs.filter { $0.contains("trigger=trial") || $0.contains("probe=silent") }.count >= 1, "and the probes between them leave their lines")
            check(b.logs.contains("Tribe watch: peer_switch from=16 to=12 why=no_data seq=1 net=cellular result=performed"), "the switch is journaled with both nodes and the reason: \(b.logs.suffix(4))")
            let event = b.records.last { $0.event == "peer_switch" }?.fields
            check(event?["from"] as? String == "16" && event?["to"] as? String == "12" && event?["why"] as? String == "no_data"
                  && event?["seq"] as? Int == 1 && event?["result"] as? String == "performed" && event?["generation"] as? String == "gen-1",
                  "and in the journal ring: \(String(describing: event))")
            // Where the tunnel stands now, for everybody who asks - on every status reply.
            let made = b.runtime.sessionSwitch()
            check(made?.seq == 1 && made?.why == "no_data" && made?.nodeId == "12" && made?.endpoint == "198.51.100.12:585", "the status reply's session: the new node and the switch number: \(String(describing: made))")
            let switchedAt = (b.lastState["switches"] as? [[String: Any]])?.last?["utc_ms"] as? Int64 ?? -1
            check(made?.atMs == switchedAt && switchedAt > 0 && made?.net == "cellular", "and when and on which kind of network the switch was made: \(String(describing: made?.atMs)) \(String(describing: made?.net))")
            dead(b, seconds: 3)
            check(b.runtime.sessionSwitch()?.atMs == switchedAt, "the time of the switch does not move with the clock")
            check(b.runtime.statsSuffix.hasPrefix(" node=12 "), "the statistics line names the new node: \(b.runtime.statsSuffix)")
            let list = b.lastState["switches"] as? [[String: Any]]
            check(list?.count == 1 && list?.first?["from"] as? String == "16" && list?.first?["to"] as? String == "12"
                  && list?.first?["why"] as? String == "no_data" && list?.first?["net"] as? String == "cellular" && (list?.first?["utc_ms"] as? Int64 ?? 0) > 0,
                  "the list of switches: \(String(describing: list))")
            let block = b.statusBlock().block
            check(block?["switch_seq"] as? Int == 1 && (block?["switches"] as? [[String: Any]])?.count == 1, "the status block carries the switch number: \(String(describing: block?["switch_seq"]))")
            // The new node answers its trial probe: it is trusted and nobody is moved again.
            b.probeResult = "state=answered id=5 ms=40 late=0"
            dead(b, seconds: 60)
            check(b.adapter.switched.count == 1 && b.adapter.lastInputs.nodeId == "12", "trusted: no second switch")
            check(b.adapter.lastInputs.candidates == ["9", "16"], "what is offered from the new node: the rest of the plan and the profile's node: \(b.adapter.lastInputs.candidates)")
            // The plan is rewritten without that node, then without the key, then it is rejected:
            // what the status reply says about the switch already made does not change.
            b.writePlan(switchOn: true, candidates: [9])
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.runtime.sessionSwitch()?.nodeId == "12" && b.runtime.sessionSwitch()?.endpoint == "198.51.100.12:585", "a plan without the node: the identity stands")
            b.writePlan(switchOn: false)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.runtime.sessionSwitch()?.endpoint == "198.51.100.12:585" && b.runtime.sessionSwitch()?.seq == 1, "the key off: the identity stands")
            try! Data("not a plan".utf8).write(to: b.planURL, options: .atomic)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.runtime.sessionSwitch()?.nodeId == "12" && b.runtime.sessionSwitch()?.endpoint == "198.51.100.12:585", "a rejected plan: the identity stands")
            check(b.runtime.switchTarget("9") == nil && b.runtime.switchTarget("16") == nil, "and with no usable plan no configuration is handed out")
        }
        run("nothing_is_offered_without_the_key_a_live_list_and_the_base") {
            // The switch key off: the plan may hold candidates, the arbiter is offered nothing.
            let off = Bench()
            off.writePlan(switchOn: false, candidates: [12, 9])
            off.startSession()
            off.probeResult = "state=silent id=5 ms=0 late=0"
            dead(off, seconds: 200)
            check(off.adapter.watch.verdict == .noData && off.adapter.commands.isEmpty && off.adapter.lastInputs.candidates.isEmpty, "key off: verdict only")
            check(off.runtime.switchTarget("12") == nil && off.runtime.sessionSwitch() == nil, "and no configuration is handed out, no switch is told")
            check(off.statusBlock().block?["switch_seq"] as? Int == 0, "switch_seq stays 0")
            check(off.adapter.lastInputs.networkChoice.isEmpty && off.stateReads == 0, "with the key off the previous run's file is not read and no choice is computed")
            // An expired list.
            let expired = Bench()
            expired.writePlan(switchOn: true, candidates: [12], expiresInMs: 30_000)
            expired.startSession()
            expired.probeResult = "state=silent id=5 ms=0 late=0"
            dead(expired, seconds: 20)
            check(expired.adapter.lastInputs.candidates == ["12"], "offered while the list is alive")
            dead(expired, seconds: 20)
            expired.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(expired, seconds: 200)
            check(expired.adapter.lastInputs.candidates.isEmpty && expired.adapter.switched.isEmpty && expired.runtime.switchTarget("12") == nil,
                  "the list expired: nothing is offered, nobody is moved: \(expired.adapter.commands)")
            // The provider did not say what a switch keeps (a session this code cannot rebuild).
            let bare = Bench()
            bare.writePlan(switchOn: true, candidates: [12])
            bare.startSession(base: nil)
            bare.probeResult = "state=silent id=5 ms=0 late=0"
            dead(bare, seconds: 200)
            check(bare.adapter.lastInputs.candidates.isEmpty && bare.adapter.commands.isEmpty, "no base: no switch")
            // A node that was not offered gets no configuration, whatever asks for it.
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12])
            b.startSession()
            check(b.runtime.switchTarget("99") == nil && b.runtime.switchTarget("16") == nil && b.runtime.switchTarget("12") != nil,
                  "only an offered node has a configuration (the current one is never offered)")
        }
        run("switch_lease_lapses_and_the_keys_leave_the_file") {
            // Review finding R7: with the app not running a server-side "off" reached the extension
            // only when the candidate list expired (24 h). The permission to switch is a lease the
            // app renews with every plan; after it lapses the verdict works on, switching does not,
            // and the candidates' keys are taken out of the file.
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9], leaseInMs: 60_000)
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            dead(b, seconds: 30)
            check(b.adapter.lastInputs.candidates == ["12", "9"] && b.adapter.policy.switchEnabled, "inside the lease: candidates are offered")
            check(b.plansWritten.isEmpty, "and the file is left alone")
            dead(b, seconds: 40)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.adapter.policy.enabled && !b.adapter.policy.switchEnabled, "the lease lapsed: the watch is on, the switch is off")
            dead(b, seconds: 300)
            check(b.adapter.watch.verdict == .noData && b.adapter.commands.isEmpty && b.adapter.lastInputs.candidates.isEmpty, "a verdict, and nobody is treated or moved: \(b.adapter.commands)")
            check(b.plansWritten.count == 1, "the candidates were taken out of the file, once: \(b.plansWritten.count)")
            let clean = (try? JSONSerialization.jsonObject(with: b.plansWritten.first ?? Data())) as? [String: Any]
            check((clean?["candidates"] as? [Any])?.isEmpty == true && clean?["seq"] as? Int64 == b.planSeq
                  && (clean?["features"] as? [String: Any])?["ios_tunnel_watch"] as? Bool == true, "everything else of the plan stays as the app wrote it: \(String(describing: clean?["seq"]))")
            check(!String(decoding: b.plansWritten.first ?? Data(), as: UTF8.self).contains(Bench.key32), "no node key is left in the file")
            check(b.logs.contains("Tribe watch: plan candidates removed (switch permission is gone) result=done"), "journaled: \(b.logs.suffix(3))")
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.plansWritten.count == 1 && b.adapter.policy.enabled, "and the scrubbed file is read as the same plan: nothing more is written")
            // The extension cannot write the file: one attempt per file, not one per tick.
            let stuck = Bench()
            stuck.planWriteFails = true
            stuck.writePlan(switchOn: true, candidates: [12], leaseInMs: 60_000)
            stuck.startSession()
            dead(stuck, seconds: 70)
            for _ in 1...4 { stuck.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {}) }
            check(stuck.plansWritten.count == 1 && stuck.logs.filter { $0.contains("plan candidates removed") }
                    == ["Tribe watch: plan candidates removed (switch permission is gone) result=failed"],
                  "a write that failed is told once and not retried on every tick: \(stuck.plansWritten.count) \(stuck.logs.filter { $0.contains("plan candidates") })")
            dead(stuck, seconds: 2)
            check(!stuck.adapter.policy.switchEnabled && stuck.adapter.lastInputs.candidates.isEmpty, "and switching is off all the same")
            // Third review, T4 (the reviewer's interleaving on the real runtime): while the extension
            // takes the keys out of plan 1, the app writes plan 2 with the watch OFF. The app's writer
            // takes the same lock, so its plan lands after the extension's write and is what stays.
            let race = Bench()
            race.writePlan(switchOn: true, candidates: [12], leaseInMs: 60_000)
            race.startSession()
            dead(race, seconds: 70)
            let appDone = DispatchSemaphore(value: 0)
            race.betweenCheckAndWrite = {
                DispatchQueue.global().async {
                    _ = TribeWatchPlanFile.withLock(in: race.directory, wait: true) { race.writePlan(watch: false) }
                    appDone.signal()
                }
                Thread.sleep(forTimeInterval: 0.2)
            }
            race.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            appDone.wait()
            race.betweenCheckAndWrite = nil
            let afterRace = (try? JSONSerialization.jsonObject(with: Data(contentsOf: race.planURL))) as? [String: Any]
            check(afterRace?["seq"] as? Int64 == 2 && (afterRace?["features"] as? [String: Any])?["ios_tunnel_watch"] as? Bool == false,
                  "the app's fresh plan (seq 2, the watch off) is what the file holds: seq \(String(describing: afterRace?["seq"]))")
            race.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(race, seconds: 2)
            check(!race.adapter.policy.enabled, "and the kill switch reaches the extension")
            // The app wrote before the extension looked again: the file is not the judged one, nothing is written.
            let moved = Bench()
            moved.writePlan(switchOn: true, candidates: [12], leaseInMs: 60_000)
            moved.startSession()
            dead(moved, seconds: 70)
            moved.betweenCheckAndWrite = { check(false, "a file that changed must not reach the write") }
            let judged = try! Data(contentsOf: moved.planURL)
            moved.writePlan(switchOn: true, candidates: [12, 9])
            check(TribeWatchPlanFile.replaceIfUnchanged(in: moved.directory, expected: judged, with: TribeWatchPlan.scrubbed(judged)!, afterCheck: moved.betweenCheckAndWrite) == .changed,
                  "the judged bytes are gone: the extension's write is refused")
            // The app holds the lock (it is writing): the extension steps back and tries again at the next tick.
            let busy = Bench()
            busy.writePlan(switchOn: true, candidates: [12], leaseInMs: 60_000)
            busy.startSession()
            dead(busy, seconds: 70)
            let holding = DispatchSemaphore(value: 0), letGo = DispatchSemaphore(value: 0), released = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                _ = TribeWatchPlanFile.withLock(in: busy.directory, wait: true) { holding.signal(); letGo.wait() }
                released.signal()
            }
            holding.wait()
            busy.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(String(decoding: try! Data(contentsOf: busy.planURL), as: UTF8.self).contains(Bench.key32)
                  && !busy.logs.contains { $0.contains("plan candidates removed") }, "the lock is taken: nothing is written and nothing is told")
            letGo.signal()
            released.wait()
            busy.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(!String(decoding: try! Data(contentsOf: busy.planURL), as: UTF8.self).contains(Bench.key32)
                  && busy.logs.filter { $0.contains("plan candidates removed") } == ["Tribe watch: plan candidates removed (switch permission is gone) result=done"],
                  "the next tick: the keys are taken out: \(busy.logs.filter { $0.contains("plan candidates") })")
            // A plan rejected as policy_stale (the config is older than allowed and the app sleeps)
            // permits nothing: its keys leave the file too.
            let staleBench = Bench()
            staleBench.writePlan(fetchedAgoMs: 90_000_000, switchOn: true, candidates: [12, 9])
            staleBench.startSession()
            dead(staleBench, seconds: 2)
            check(staleBench.logs.contains("Tribe watch: plan=policy_stale") && staleBench.plansWritten.count == 1
                  && !String(decoding: (try? Data(contentsOf: staleBench.planURL)) ?? Data(), as: UTF8.self).contains(Bench.key32),
                  "a rejected plan: the keys are taken out: \(staleBench.logs.suffix(2))")
            for _ in 1...3 { staleBench.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {}) }
            check(staleBench.plansWritten.count == 1, "once")
            // The tunnel is stopped by the user: no session is left that may use the keys.
            let stopped = Bench()
            stopped.writePlan(switchOn: true, candidates: [12, 9])
            stopped.startSession()
            dead(stopped, seconds: 5)
            stopped.runtime.noteStop(userInitiated: false)
            check(stopped.plansWritten.isEmpty && String(decoding: try! Data(contentsOf: stopped.planURL), as: UTF8.self).contains(Bench.key32),
                  "a stop by the system: the plan is left as it is (the start that follows chooses from it)")
            stopped.runtime.noteStop(userInitiated: true)
            let afterStop = (try? JSONSerialization.jsonObject(with: Data(contentsOf: stopped.planURL))) as? [String: Any]
            check((afterStop?["candidates"] as? [Any])?.isEmpty == true && afterStop?["seq"] as? Int64 == stopped.planSeq
                  && (afterStop?["features"] as? [String: Any])?["ios_tunnel_watch_switch"] as? Bool == true,
                  "a stop by the user: the keys leave the file, the rest stays as the app wrote it")
            let noSwitch = Bench()
            noSwitch.writePlan()
            noSwitch.startSession()
            noSwitch.runtime.noteStop(userInitiated: true)
            check(noSwitch.plansWritten.isEmpty, "a plan without candidates is not touched at a stop")
            // The app renews the lease with its next plan: switching works again.
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(b, seconds: 2)
            check(b.adapter.policy.switchEnabled && b.adapter.lastInputs.candidates == ["12", "9"], "a new plan from the app: the lease is alive again")
            // The key switched off by the server and written by the app: the keys leave the file too -
            // but never while the app is alive (it is the writer and may be writing).
            let k = Bench()
            k.writePlan(switchOn: true, candidates: [12])
            k.startSession()
            var raw = (try! JSONSerialization.jsonObject(with: Data(contentsOf: k.planURL))) as! [String: Any]
            raw["features"] = ["ios_tunnel_watch": true, "ios_tunnel_watch_switch": false]
            raw["seq"] = k.planSeq + 1
            k.planSeq += 1
            try! JSONSerialization.data(withJSONObject: raw).write(to: k.planURL, options: .atomic)
            k.runtime.noteAppStatusRequest()
            k.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(k.plansWritten.isEmpty, "the app is alive: the file is the app's")
            k.uptime += 60
            k.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(k.plansWritten.count == 1, "the app sleeps: the keys of a plan that may not switch are taken out")
            // A plan without a lease field at all cannot switch.
            let old = Bench()
            old.writePlan(switchOn: true, candidates: [12], leaseInMs: 0)
            old.startSession()
            check(!old.adapter.policy.switchEnabled && old.adapter.policy.enabled, "no lease: no switching")
        }
        run("start_by_the_app_always_raises_the_profile_node") {
            // Review finding R1: every start was treated as a start by the system (the provider
            // looked at an option the app never passes). The app taps node 16 - it must come up on
            // 16 whatever the plan's pin, memory or the previous run's verdict say.
            let failed: [String: Any] = ["verdict": "no_data", "node_id": "16", "net": "cellular", "last_no_data_ms": Int64(1_800_000_000_000) - 300_000]
            for source in ["app", "intent", "", "something-new"] {
                let (b, choice) = prepared({ b in
                    b.writePlan(switchOn: true, candidates: [12, 9], pin: 9, memory: ["cellular": 12])
                    b.previousState = failed
                }, source: source)
                check(choice == nil, "source '\(source)': the profile's node, got \(String(describing: choice?.nodeId))")
                check(b.runtime.sessionSwitch() == nil && b.logs.allSatisfy { !$0.contains("start candidate") }, "source '\(source)': no switch is told, nothing is journaled")
                check(b.uplinkReads == 0, "source '\(source)': the choice is not even computed")
            }
            // The same facts at a start by the system: now the plan decides.
            let (os, chosen) = prepared({ b in
                b.writePlan(switchOn: true, candidates: [12, 9], pin: 9, memory: ["cellular": 12])
                b.previousState = failed
            }, source: nil)
            check(chosen?.nodeId == "9" && chosen?.why == "pin", "a start by the system: the pinned node first: \(String(describing: chosen?.nodeId))")
            check(os.runtime.sessionSwitch()?.seq == 1 && os.runtime.sessionSwitch()?.nodeId == "9", "and it is told as the first switch of the run")
            check(TribeStartChoice.startedBySystem(source: nil) && !TribeStartChoice.startedBySystem(source: "app")
                  && !TribeStartChoice.startedBySystem(source: "intent") && !TribeStartChoice.startedBySystem(source: "os"), "only a start that names nobody is the system's")
        }
        run("start_by_the_system_chooses_from_the_plan") {
            // The previous run judged the profile's node dead on this network 5 minutes ago.
            let judged: (Bench) -> [String: Any] = { ["verdict": "no_data", "node_id": "16", "net": "cellular", "last_no_data_ms": $0.wallMs - 300_000] }
            let (b, choice) = prepared({ b in
                b.writePlan(switchOn: true, candidates: [12, 9])
                b.previousState = judged(b)
            }, source: nil)
            check(choice?.nodeId == "12" && choice?.why == "plan_order" && (choice?.wgQuick.contains("Endpoint = 198.51.100.12:585\n") ?? false),
                  "the plan's first candidate instead of the node that failed here: \(String(describing: choice?.nodeId))")
            check(b.logs.contains("Tribe watch: start candidate=12 why=plan_order profile=16 net=cellular"), "journaled: \(b.logs)")
            check(b.records.contains { $0.event == "peer_switch" && $0.fields["why"] as? String == "os_start_plan_order" && $0.fields["seq"] as? Int == 1 }, "and in the ring")
            b.runtime.attach(adapter: b.adapter)
            check(b.runtime.sessionSwitch()?.nodeId == "12" && b.runtime.sessionSwitch()?.why == "os_start_plan_order", "the session's identity is the chosen node")
            b.adapter.start(at: b.uptime)
            let block = b.statusBlock().block
            let list = block?["switches"] as? [[String: Any]]
            check(block?["switch_seq"] as? Int == 1 && list?.first?["why"] as? String == "os_start_plan_order" && list?.first?["from"] as? String == "16",
                  "the app is told as about any switch: \(String(describing: list))")
            // The configuration could not be built: the profile's node after all.
            b.runtime.cancelStartChoice()
            check(b.runtime.sessionSwitch() == nil && b.statusBlock().block?["switch_seq"] as? Int == 0, "a dropped choice leaves no trace of a switch")
            // A healthy profile node, another network, no key: nothing is chosen.
            let (healthy, none) = prepared({ $0.writePlan(switchOn: true, candidates: [12]) }, source: nil)
            check(none == nil && healthy.logs.allSatisfy { !$0.contains("start candidate") }, "no failure known: the profile's node, silently")
            let (_, wifi) = prepared({ b in
                b.writePlan(switchOn: true, candidates: [12])
                b.uplink = "wifi"
                b.previousState = judged(b)
            }, source: nil)
            check(wifi == nil, "the failure was on another network")
            let (off, offChoice) = prepared({ b in
                b.writePlan(switchOn: false, candidates: [12])
                b.previousState = judged(b)
            }, source: nil)
            check(offChoice == nil, "the switch key off: the profile's node, as build 139")
            check(off.stateReads == 0 && off.uplinkReads == 0, "and with the key off a start reads neither the previous run's file nor the path: \(off.stateReads) \(off.uplinkReads)")
            let (noPlan, noChoice) = prepared({ _ in }, source: nil)
            check(noChoice == nil && noPlan.stateReads == 0 && noPlan.uplinkReads == 0, "no plan at all: nothing is read")
            let (lapsed, lapsedChoice) = prepared({ b in
                b.writePlan(switchOn: true, candidates: [12], leaseInMs: -1000)
                b.previousState = judged(b)
            }, source: nil)
            check(lapsedChoice == nil && lapsed.stateReads == 0, "the lease has lapsed: the profile's node")
        }
        run("dead_nodes_survive_every_rewrite_and_the_next_start") {
            // Review finding R6: a performed switch rewrote the shared file from the snapshot after
            // the switch, so the node just proved dead was not skipped at the next start.
            let b = Bench()
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            b.startSession()
            for _ in 1...3 { b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {}) }
            check(b.stateReads == 1, "the previous run's file is read once per run, not at every re-read of the plan: \(b.stateReads)")
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b)
            func deadNodes(_ state: [String: Any]) -> [String] { (state["dead"] as? [[String: Any]] ?? []).compactMap { $0["node_id"] as? String } }
            // A verdict alone is a record - also when nobody is moved (the app is alive and decides itself).
            let watched = Bench()
            watched.writePlan(switchOn: true, candidates: [12])
            watched.startSession()
            watched.probeResult = "state=silent id=5 ms=0 late=0"
            for second in 1...200 {
                watched.runtime.noteAppStatusRequest()
                watched.second(tx: 400, handshake: watched.adapter.handshake == 0 ? second % 3 == 0 : false)
            }
            check(watched.adapter.watch.verdict == .noData && watched.adapter.commands.isEmpty && deadNodes(watched.lastState) == ["16"],
                  "a verdict with a living app: nobody is moved, the node is on record: \(deadNodes(watched.lastState))")
            // A session started by the APP knows what the previous run judged, and keeps it in the file
            // it rewrites (the next start by the system needs it).
            let byApp = Bench()
            byApp.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            byApp.previousState = ["verdict": "none", "dead": [["node_id": "9", "net": "cellular", "at_ms": byApp.wallMs - 60_000]]]
            byApp.startSession()
            check(byApp.runtime.chooseStart(source: "app") == nil, "a start by the app: the profile's node")
            byApp.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(byApp)
            check(Set(deadNodes(byApp.lastState)) == ["9", "16"], "the previous run's record is carried through this run's rewrites: \(deadNodes(byApp.lastState))")
            // A node left long after its verdict (the half-hour pause between rounds) is noted at the
            // moment it is left: the record must not have aged by then.
            let slow = Bench()
            slow.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12])
            slow.startSession()
            slow.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(slow, 5, limit: 4500)
            check(slow.adapter.switched.map { $0.node } == ["12", "16", "12", "16", "12"], "two rounds and the first switch of the third: \(slow.adapter.switched.map { $0.node })")
            let left = (slow.lastState["dead"] as? [[String: Any]])?.last { $0["node_id"] as? String == "16" }
            check(slow.wallMs - (left?["at_ms"] as? Int64 ?? 0) <= 1000, "the node is on record as of the moment it was left: \(slow.wallMs - (left?["at_ms"] as? Int64 ?? 0)) ms")
            check(deadNodes(b.lastState) == ["16"] && (b.lastState["dead"] as? [[String: Any]])?.first?["net"] as? String == "cellular",
                  "the node the tunnel left is in the file written after the switch: \(b.lastState["dead"] ?? "-")")
            untilSwitched(b, 2)
            check(deadNodes(b.lastState) == ["16", "12"], "and the next one joins it: \(deadNodes(b.lastState))")
            let since = b.states.firstIndex { deadNodes($0).contains("16") } ?? 0
            check(b.states.count - since >= 4 && b.states[since...].allSatisfy { deadNodes($0).contains("16") }, "every rewrite of the file from the verdict on carries the record: \(b.states[since...].map { deadNodes($0) })")
            // The watch is switched off: the file keeps them too.
            b.writePlan(watch: false)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.lastState["enabled"] as? Bool == false && deadNodes(b.lastState) == ["16", "12"], "the 'watch off' rewrite keeps the records: \(deadNodes(b.lastState))")
            // The next run of the extension, started by the system on the same network, 2 minutes
            // later: neither dead node is raised.
            let next = Bench()
            next.wallMs = b.wallMs + 120_000
            next.writePlan(switchOn: true, candidates: [12, 9])
            next.previousState = b.lastState
            _ = next.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            let choice = next.runtime.chooseStart(source: nil)
            check(choice?.nodeId == "9", "the profile's node and the first candidate are known dead here: the second candidate: \(String(describing: choice?.nodeId))")
            // Half an hour later the records have expired.
            let later = Bench()
            later.wallMs = b.wallMs + 31 * 60_000
            later.writePlan(switchOn: true, candidates: [12, 9])
            later.previousState = b.lastState
            _ = later.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-3", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            check(later.runtime.chooseStart(source: nil) == nil, "half an hour later: forgotten, the profile's node")
        }
        run("rejected_candidate_is_never_offered_again_while_the_plan_lives") {
            // Review finding R5: a candidate the engine does not start on (or whose configuration
            // does not parse) is rolled back and never retried.
            let b = Bench()
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            b.startSession()
            b.adapter.engineRejects = ["12"]
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b)
            check(b.logs.contains("Tribe watch: peer_switch from=16 to=12 why=no_data seq=0 net=cellular result=rejected"), "the rejection is journaled, and it is not 'performed': \(b.logs.filter { $0.contains("peer_switch") })")
            check(b.adapter.switched.map { $0.node } == ["9"], "the next candidate is taken: \(b.adapter.switched.map { $0.node })")
            check(b.runtime.sessionSwitch()?.seq == 1, "only the switch that happened is counted")
            dead(b, seconds: 900)
            check(!b.adapter.commands.dropFirst(3).contains { if case .switchPeer(let to, _) = $0.command { return to == "12" } else { return false } },
                  "node 12 is not asked again in later rounds: \(b.adapter.commands.map { "\($0.command)" }.suffix(6))")
            check(!b.adapter.lastInputs.candidates.contains("12"), "it is not on offer")
            // The plan is re-read every 10 s: the same plan is not a new plan.
            let epoch = b.adapter.lastInputs.planEpoch
            for _ in 1...3 { b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {}) }
            dead(b, seconds: 2)
            check(b.adapter.lastInputs.planEpoch == epoch && !b.adapter.lastInputs.candidates.contains("12"),
                  "re-reading the same plan neither tells the rule of a new plan nor offers the rejected node: \(b.adapter.lastInputs.planEpoch) \(b.adapter.lastInputs.candidates)")
            // The provider's own parse refused a candidate: the same.
            b.runtime.markRejected("9")
            dead(b, seconds: 2)
            check(!b.adapter.lastInputs.candidates.contains("9"), "a candidate the provider could not build is not on offer either")
            // A new plan from the app gives both another chance.
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(b, seconds: 2)
            check(Set(b.adapter.lastInputs.candidates).isSuperset(of: ["12"]), "a new plan: on offer again: \(b.adapter.lastInputs.candidates)")
            check(b.adapter.lastInputs.planEpoch >= 2, "and the rule is told that the plan is new: \(b.adapter.lastInputs.planEpoch)")
        }
        run("engine_down_is_told_to_everybody") {
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12])
            b.startSession()
            check(!b.runtime.engineIsDown && b.lastState["engine"] == nil, "an engine runs: nothing is said")
            b.adapter.dataWatchEngineHandler?(true)
            check(b.runtime.engineIsDown, "the status reply will say the engine is down")
            check(b.lastState["engine"] as? String == "down" && b.lastState["node_id"] as? String == "16", "the shared file says so: \(b.lastState)")
            check(b.logs.contains("Tribe watch: engine=down node=16") && b.records.contains { $0.event == "watch_engine" && $0.fields["state"] as? String == "down" }, "and the journal")
            let writes = b.states.count
            b.adapter.dataWatchEngineHandler?(true)
            check(b.states.count == writes, "told once")
            b.adapter.dataWatchEngineHandler?(false)
            check(!b.runtime.engineIsDown && b.lastState["engine"] as? String == "up" && b.logs.contains("Tribe watch: engine=up node=16"), "and taken back when an engine runs again")
        }
        run("engine_down_after_a_restart_is_told_with_the_watch_off_too") {
            // awg-apple tribe.22 (review R53 2): an in-place restart of a roam or of the stall ladder whose retries
            // are spent raises the same fact; no plan is needed for it, and the shared file does not claim a watch.
            let b = Bench()
            b.startSession()
            check(!b.runtime.engineIsDown, "an engine runs")
            b.adapter.dataWatchEngineHandler?(true)
            check(b.runtime.engineIsDown, "no plan, no watch: the status reply still says the engine is down")
            check(b.lastState["engine"] as? String == "down" && b.lastState["enabled"] as? Bool == false, "the shared file: engine down, watch off: \(b.lastState)")
            check(b.records.contains { $0.event == "watch_engine" && $0.fields["state"] as? String == "down" }, "and the journal")
            b.adapter.dataWatchEngineHandler?(false)
            check(!b.runtime.engineIsDown && b.lastState["engine"] as? String == "up", "taken back when a backend is up again")
            let on = Bench()
            on.writePlan(switchOn: true, candidates: [12])
            on.startSession()
            on.adapter.dataWatchEngineHandler?(true)
            check(on.lastState["enabled"] as? Bool == true, "with the watch on the file says so: \(on.lastState)")
        }
        run("network_change_moves_an_unproven_node_to_the_choice_for_that_network") {
            // Review finding R4: a round dropped at a change of network left the tunnel on whatever
            // candidate it stood on.
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b)
            dead(b, seconds: 2)
            check(b.adapter.lastInputs.nodeId == "12" && b.adapter.lastInputs.networkChoice == "12", "on cellular a start would skip the dead 16 and take the plan's first - where the tunnel stands: \(b.adapter.lastInputs.networkChoice)")
            b.uplink = "wifi"
            b.adapter.watch.notePathEvent(at: b.uptime, interfaceChanged: true, policy: b.adapter.policy)
            dead(b, seconds: 2)
            check(b.adapter.switched.map { $0.node } == ["12", "16"] && b.adapter.switched.last?.target == .home, "on Wi-Fi nothing is known against the profile's node: back to it: \(b.adapter.switched.map { $0.node })")
            check(b.logs.contains("Tribe watch: peer_switch from=12 to=16 why=network_change seq=2 net=wifi result=performed"), "journaled with its reason: \(b.logs.filter { $0.contains("peer_switch") })")
            let deadNodes = (b.lastState["dead"] as? [[String: Any]] ?? []).compactMap { $0["node_id"] as? String }
            check(deadNodes == ["16"], "a node left for the network's sake is not recorded as dead: \(deadNodes)")
        }
        run("exhausted_goes_back_to_the_profile_node_and_says_so") {
            let b = Bench()
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b, 3)
            check(b.adapter.switched.map { $0.node } == ["12", "9", "16"], "both candidates, then back: \(b.adapter.switched.map { $0.node })")
            check(b.adapter.switched.last?.target == .home, "the way back is the configuration the session started with")
            check(b.logs.contains("Tribe watch: exhausted tried=3 round=1 stay=16 net=cellular"), "exhausted is journaled with the node the tunnel stays on: \(b.logs.filter { $0.contains("exhausted") })")
            check(b.logs.contains("Tribe watch: peer_switch from=9 to=16 why=exhausted_best seq=3 net=cellular result=performed"), "the return is journaled as such")
            check(b.records.contains { $0.event == "watch_exhausted" && $0.fields["tried"] as? Int == 3 }, "and in the ring")
            let made = b.runtime.sessionSwitch()
            check(made?.seq == 3 && made?.nodeId == nil && made?.endpoint == nil && made?.why == "exhausted_best", "back on the profile's node: its own identity, and the reply still carries the switch number: \(String(describing: made))")
            check(b.runtime.statsSuffix.hasPrefix(" node=16 ") && b.statusBlock().block?["switch_seq"] as? Int == 3, "three switches were made")
            let before = b.adapter.commands.count
            dead(b, seconds: 150)
            check(b.adapter.commands.count == before, "silent until the next round")
        }
        run("switch_that_fails_changes_nothing_of_the_session") {
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.startSession()
            b.adapter.switchFails = true
            b.probeResult = "state=silent id=5 ms=0 late=0"
            for _ in 1...600 where !b.logs.contains(where: { $0.contains("peer_switch") }) { dead(b, seconds: 1) }
            check(b.logs.contains("Tribe watch: peer_switch from=16 to=12 why=no_data seq=0 net=cellular result=failed"), "a failed switch is journaled as failed: \(b.logs.suffix(3))")
            check(b.runtime.sessionSwitch() == nil && b.runtime.statsSuffix.hasPrefix(" node=16 "), "the session is still the profile's node")
            check(b.statusBlock().block?["switch_seq"] as? Int == 0 && (b.statusBlock().block?["switches"] as? [[String: Any]])?.isEmpty == true, "no switch is counted")
            check(b.states.allSatisfy { $0["node_id"] as? String == "16" }, "the shared file never named another node")
            check(b.records.contains { $0.event == "peer_switch" && $0.fields["result"] as? String == "failed" }, "and the ring has the attempt")
        }
        run("switch_list_keeps_the_last_eight") {
            let b = Bench()
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60, "ios_tw_switch_max_per_hour": 30], switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b, 9, limit: 9000)
            let block = b.statusBlock().block
            let seq = block?["switch_seq"] as? Int ?? 0
            let list = block?["switches"] as? [[String: Any]] ?? []
            check(seq >= 9 && list.count == TribeDataWatchRuntime.maxSwitchesKept, "the number goes on, the list is bounded: \(seq) \(list.count)")
            check(list.last?["to"] as? String == b.adapter.switched.last?.node, "the newest is the last")
        }
        run("plan_without_the_key_stops_a_round") {
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9, 3])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            untilSwitched(b)
            check(b.adapter.switched.count == 1, "a round is in progress")
            b.writePlan(switchOn: false, candidates: [12, 9, 3]) // the server switched the key off; the app rewrote the plan
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(b, seconds: 300)
            check(b.adapter.switched.count == 1 && !b.adapter.watch.snapshot(policy: b.adapter.policy).arbiterActive, "not one more switch after the key went off")
            check(b.runtime.sessionSwitch()?.nodeId == "12", "the tunnel stays where it is")
        }
    }

    static func main() {
        run("session_handshake_raises_the_tx_allowance") {
            // awg-apple tribe.17 (review of tribe.16, F2): the watch deducts at least the session's own handshake
            // (a heavy-junk session sends 3726 B), never less than the plan says.
            let heavy = Bench()
            heavy.sessionHandshakeTx = 3726
            heavy.writePlan()
            _ = heavy.startSession()
            check(heavy.adapter.policy.enabled && heavy.adapter.policy.handshakeTxAllowanceBytes == 3726,
                  "heavy session: allowance 3726: \(heavy.adapter.policy.handshakeTxAllowanceBytes)")
            let plain = Bench()
            plain.sessionHandshakeTx = 180
            plain.writePlan()
            _ = plain.startSession()
            check(plain.adapter.policy.handshakeTxAllowanceBytes == TribeDataWatchPolicy().handshakeTxAllowanceBytes,
                  "a small session keeps the plan's allowance: \(plain.adapter.policy.handshakeTxAllowanceBytes)")
        }
        run("flag_never_on_leaves_no_trace") {
            // No plan file at all: the install has never seen the flag. Exactly build 139.
            let b = Bench()
            check(!b.startSession(), "no plan: no probe")
            check(b.setProbeCalls.count == 1 && b.setProbeCalls[0].enabled == false, "the probe is explicitly reset, not configured: \(b.setProbeCalls)")
            check(b.adapter.policiesSet.count == 1 && b.adapter.policiesSet[0] == .disabled, "the adapter is given the disabled policy")
            b.deadPath(seconds: 200)
            let status = b.statusBlock()
            check(status.called == 1 && status.block == nil, "the status reply is answered at once and has no watch block")
            check(b.runtime.statsSuffix.isEmpty, "the statistics line has no extra fields")
            b.runtime.statsTick(isXray: false, loggingEnabled: true, logXray: {}, logWireGuard: {})
            check(b.logs.isEmpty && b.records.isEmpty && b.states.isEmpty && b.probeStarts.isEmpty && b.sanityAsked.isEmpty,
                  "nothing is logged, journaled, written or asked: \(b.logs) \(b.records.count) \(b.states.count)")
        }

        run("plan_switches_the_watch_on") {
            let b = Bench()
            b.writePlan()
            check(b.startSession(), "the probe is available")
            check(b.setProbeCalls.count == 1 && b.setProbeCalls[0].enabled && b.setProbeCalls[0].client == "10.8.1.7/32" && b.setProbeCalls[0].resolver == "1.1.1.1",
                  "the probe is configured from the session's own addresses: \(b.setProbeCalls)")
            check(b.adapter.policy.enabled && b.adapter.policy.cycleSeconds == 25, "the adapter got the plan's policy")
            check(b.logs.contains("Tribe watch: plan=on") && b.logs.contains("Tribe watch: probe available"), "both facts are in the log: \(b.logs)")
            check(b.statusBlock().block?["verdict"] as? String == "none", "the status reply carries the block")
            check(b.runtime.statsSuffix == " node=16 watch=none", "the statistics suffix: \(b.runtime.statsSuffix)")
            // The probe cannot be configured (the client address is not IPv4): the watch still runs.
            let c = Bench()
            c.writePlan()
            c.setProbeResult = -1
            check(!c.startSession() && c.adapter.policy.enabled, "no probe, watch on")
            check(c.logs.contains("Tribe watch: probe unavailable"), "and it says so")
            // The probe is switched off by the plan: it is reset, not configured.
            let d = Bench()
            d.writePlan(numbers: ["ios_tw_probe": 0])
            check(!d.startSession() && d.setProbeCalls.last?.enabled == false && d.adapter.policy.enabled, "ios_tw_probe=0: the wrapper is not created")
        }

        run("kill_switch_reaches_the_extension_with_the_log_off") {
            // Review mutant W11: the plan used to be re-read only on the path that writes the
            // statistics line, i.e. only while the file log was on.
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.deadPath(seconds: 110)
            check(b.adapter.watch.verdict == .noData || b.adapter.watch.verdict == .suspect, "the watch is working: \(b.adapter.watch.verdict)")
            b.writePlan(watch: false)                       // the server switched it off; the app rewrote the plan
            var xray = 0, wireGuard = 0
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: { xray += 1 }, logWireGuard: { wireGuard += 1 })
            check(!b.adapter.policy.enabled, "the adapter got the disabled policy with the file log OFF")
            check(xray == 0 && wireGuard == 0, "and no statistics line is written with the log off")
            b.second(tx: 400)
            check(b.adapter.watch == TribeDataWatch(), "the rule forgot everything at the next tick")
            check(b.logs.contains("Tribe watch: plan=off"), "the change is in the log")
            check(b.lastState["enabled"] as? Bool == false && b.lastState["verdict"] as? String == "none", "the shared file no longer holds a verdict: \(b.lastState)")
            let snapshotCalls = b.adapter.snapshotCalls
            check(b.statusBlock().block == nil && b.runtime.statsSuffix.isEmpty, "no watch block, no statistics fields")
            check(b.adapter.snapshotCalls == snapshotCalls, "with the watch off the status reply does not go through the adapter's queue (build 139)")
            // And back on.
            b.writePlan()
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.adapter.policy.enabled, "switched on again by the next plan")
            check(b.runtime.statsSuffix == " node=16 watch=none", "and the statistics line does not show the verdict from before the switch-off: \(b.runtime.statsSuffix)")
        }

        run("stats_tick_order") {
            let b = Bench()
            b.writePlan()
            b.startSession()
            var order: [String] = []
            b.writePlan(numbers: ["ios_tw_cycle_s": 40])
            b.runtime.statsTick(isXray: false, loggingEnabled: true, logXray: { order.append("xray") },
                                logWireGuard: { order.append("wg cycle=\(Int(b.adapter.policy.cycleSeconds))") })
            check(order == ["wg cycle=40"], "the plan is re-read BEFORE the statistics line: \(order)")
            order = []
            b.runtime.statsTick(isXray: true, loggingEnabled: true, logXray: { order.append("xray") }, logWireGuard: { order.append("wg") })
            check(order == ["xray"], "the Xray path has its own line")
            order = []
            b.runtime.statsTick(isXray: true, loggingEnabled: false, logXray: { order.append("xray") }, logWireGuard: { order.append("wg") })
            check(order.isEmpty, "diagnostics only with the file log on")
            // Before a session is attached (the Xray path never attaches) the tick reads no file.
            let x = Bench()
            x.writePlan()
            x.runtime.statsTick(isXray: true, loggingEnabled: true, logXray: {}, logWireGuard: {})
            check(x.logs.isEmpty, "nothing is read for a provider without the watch attached")
        }

        run("plan_order_is_the_apps_not_the_pools") {
            // Review finding A3: the app rewrites the plan after a node was deleted - the pool
            // revision goes DOWN. The watch must stay on.
            let b = Bench()
            b.writePlan(poolRevision: 1_763_190_000_000)
            b.startSession()
            b.writePlan(poolRevision: 1_763_100_000_000)
            b.runtime.refreshPlan()
            check(b.adapter.policy.enabled && !b.logs.contains { $0.hasPrefix("Tribe watch: plan=") && $0 != "Tribe watch: plan=on" },
                  "a lower pool revision is a valid plan: \(b.logs)")
            // An older plan that reappears (lower sequence, earlier writing) is refused.
            let older: [String: Any] = ["schema": 2, "seq": 1, "written_ms": b.wallMs - 10_000, "config_fetched_ms": b.wallMs - 60_000,
                                        "policy_max_age_ms": 86_400_000, "expires_ms": b.wallMs + 86_400_000, "pool_revision": 5,
                                        "features": ["ios_tunnel_watch": true], "numbers": [String: Any](), "candidates": [Any]()]
            try! JSONSerialization.data(withJSONObject: older).write(to: b.planURL, options: .atomic)
            b.runtime.refreshPlan()
            check(!b.adapter.policy.enabled && b.logs.contains("Tribe watch: plan=stale"), "a plan from the past switches the watch off: \(b.logs)")
        }

        run("unreadable_plan_is_retried") {
            // Review finding A8: a tunnel started by iOS before the first unlock cannot read the
            // file. The failure used to be remembered under the file's stamp, so the watch stayed
            // off until the app rewrote the file.
            let b = Bench()
            b.writePlan()
            try! FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: b.planURL.path)
            b.startSession()
            check(!b.adapter.policy.enabled && b.logs.contains("Tribe watch: plan=unreadable"), "cannot be read: off, and it says why: \(b.logs)")
            // The phone is unlocked: the same file, the same stamp, now readable.
            try! FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: b.planURL.path)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.adapter.policy.enabled && b.logs.contains("Tribe watch: plan=on"), "the next tick reads it: \(b.logs)")
        }

        run("stale_policy_lapses_while_the_app_sleeps") {
            let b = Bench()
            b.writePlan(fetchedAgoMs: 86_400_000 - 30_000)   // the config is almost a day old
            b.startSession()
            check(b.adapter.policy.enabled, "still within its age")
            b.wallMs += 60_000
            b.runtime.refreshPlan()
            check(!b.adapter.policy.enabled && b.logs.contains("Tribe watch: plan=policy_stale"), "older than its age and nobody renews it: off")
            b.runtime.noteAppStatusRequest()                // the app is back and polls the status
            b.runtime.refreshPlan()
            check(b.adapter.policy.enabled, "a living app vouches for what lies in the file")
        }

        run("dead_path_silent_probe_is_told_everywhere") {
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.deadPath(seconds: 96)
            check(b.sanityAsked.count == 1 && b.sanityAsked[0].map { $0.host } == ["www.ozon.ru", "www.wildberries.ru", "www.apple.com"],
                  "the built-in targets answer inside Russia: \(b.sanityAsked.map { $0.map { $0.host } })")
            b.deadPath(seconds: 2)
            check(b.probeStarts.count == 1 && b.probeStarts[0].handle == 3 && b.probeStarts[0].timeoutMs == 4000, "one probe on the device that is up: \(b.probeStarts)")
            b.probeResult = "state=silent id=5 ms=0 late=0"
            b.deadPath(seconds: 2)
            check(b.adapter.watch.verdict == .noData, "silent under a keypair: no_data")
            let line = b.logs.last ?? ""
            check(line.hasPrefix("Tribe watch: event=verdict verdict=no_data passive=no_data probe=silent trigger=passive")
                  && line.contains(" node=16 proto=awg net=cellular ") && line.contains(" evidence=probe would_switch=1 app_alive=0 "), "the log line: \(line)")
            check(b.records.last?.event == "data_watch" && b.records.last?.fields["verdict"] as? String == "no_data"
                  && b.records.last?.fields["generation"] as? String == "gen-1", "the journal event")
            check(b.lastState["verdict"] as? String == "no_data" && b.lastState["node_id"] as? String == "16" && b.lastState["net"] as? String == "cellular"
                  && b.lastState["enabled"] as? Bool == true && b.lastState["switch_seq"] as? Int == 0, "the shared file: \(b.lastState)")
            check(b.runtime.statsSuffix == " node=16 watch=no_data", "the statistics suffix: \(b.runtime.statsSuffix)")
            let block = b.statusBlock().block
            check(block?["verdict"] as? String == "no_data" && block?["evidence"] as? String == "probe" && block?["would_switch"] as? Bool == true
                  && block?["switch_seq"] as? Int == 0, "the status block: \(String(describing: block))")
            // The app comes back and polls: it is alive, the shadow mark goes off.
            b.runtime.noteAppStatusRequest()
            b.deadPath(seconds: 2)
            check(b.statusBlock().block?["app_alive"] as? Bool == true && b.statusBlock().block?["would_switch"] as? Bool == false, "a living app: no would_switch")
        }

        run("outputs_follow_a_verdict_that_ends") {
            // Review finding A7 (vectors V16, V17): a verdict that ended without a report left
            // `no_data` in the shared file and in the statistics line.
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            b.deadPath(seconds: 105)
            check(b.lastState["verdict"] as? String == "no_data", "no_data is written")
            b.adapter.watch.notePathEvent(at: b.uptime, interfaceChanged: true, policy: b.adapter.policy)   // another network
            b.second()
            check(b.lastState["verdict"] as? String == "none" && b.runtime.statsSuffix == " node=16 watch=none",
                  "another network: the file and the statistics line are told: \(b.lastState["verdict"] ?? "?") \(b.runtime.statsSuffix)")
            check(b.logs.last?.contains("event=verdict verdict=none") == true, "and the log: \(b.logs.last ?? "")")
            // A suspicion that goes idle.
            let s = Bench()
            s.writePlan()
            s.startSession()
            s.deadPath(seconds: 46)
            check(s.lastState["verdict"] as? String == "suspect", "one dead cycle: suspect")
            for _ in 1...125 { s.second() }
            check(s.lastState["verdict"] as? String == "none", "the suspicion ended: the file says so: \(s.lastState["verdict"] ?? "?")")
        }

        run("refused_start_is_not_a_probe") {
            // No keypair that may send: nothing is injected, the rule judges by the handshake.
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.probeStartCode = -2
            b.deadPath(seconds: 110)
            check(b.adapter.watch.verdict == .noData && b.lastState["evidence"] as? String == "handshake", "no_data by the engine's unanswered handshakes: \(b.lastState)")
            check(b.probeResultPolls == 0, "nothing is in flight: the result is never polled")
            check(b.statusBlock().block?["probes_hour"] as? Int == 0, "and no budget is spent")
            // The resolver cannot be reached through the tunnel in this session: no judge at all.
            let u = Bench()
            u.writePlan()
            u.startSession()
            u.probeStartCode = -1
            u.deadPath(seconds: 400)
            check(u.adapter.watch.verdict == .unconfirmed && u.probeStarts.count == 1, "one refused start, then unconfirmed and nobody is asked: \(u.probeStarts.count)")
            check(u.sanityAsked.count == 1, "no more bypass requests either: \(u.sanityAsked.count)")
        }

        run("staged_packet_is_not_silence") {
            // The Go layer found the packet staged (its "no_session" result): disturbed, not no_data.
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.deadPath(seconds: 98)
            b.probeResult = "state=no_session id=5 ms=0 late=0"
            b.deadPath(seconds: 3)
            check(b.adapter.watch.verdict != .noData && b.logs.last?.contains("event=disturbed") == true && b.logs.last?.contains("probe=staged") == true,
                  "a staged packet judges nothing: \(b.logs.last ?? "")")
            check(b.lastState["disturbed"] as? Int == 1 && b.lastState["refuted"] as? Int == 0, "counted apart from refuted: \(b.lastState)")
            // A result with another id is a probe of another device: never judged.
            let o = Bench()
            o.writePlan()
            o.startSession()
            o.deadPath(seconds: 98)
            o.probeResult = "state=silent id=9 ms=0 late=0"
            o.deadPath(seconds: 3)
            check(o.adapter.watch.verdict != .noData, "the silence of another probe is not ours")
        }

        run("late_answer_takes_the_verdict_back") {
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.deadPath(seconds: 98)
            b.probeResult = "state=silent id=5 ms=0 late=0"
            b.deadPath(seconds: 2)
            check(b.adapter.watch.verdict == .noData, "silent in time")
            let pollsBefore = b.probeResultPolls
            b.deadPath(seconds: 2)
            check(b.probeResultPolls > pollsBefore, "the answer is still looked for after the verdict")
            b.probeResult = "state=answered id=5 ms=6100 late=1"
            b.deadPath(seconds: 2)
            check(b.adapter.watch.verdict != .noData && b.lastState["verdict"] as? String != "no_data" && b.lastState["refuted"] as? Int == 1,
                  "the late answer refutes: \(b.adapter.watch.verdict) \(b.lastState)")
            check(b.logs.contains { $0.contains("event=refuted") }, "and it is in the log as refuted")
            // The look-out is bounded: after its window the result is not polled any more.
            let w = Bench()
            w.writePlan()
            w.startSession()
            w.deadPath(seconds: 98)
            w.probeResult = "state=silent id=5 ms=0 late=0"
            w.deadPath(seconds: 2 + Int(TribeDataWatchRuntime.lateAnswerWatchSeconds) + 2)
            let polls = w.probeResultPolls
            w.deadPath(seconds: 20)
            check(w.probeResultPolls == polls, "no polling after the late window: \(w.probeResultPolls - polls)")
        }

        run("bypass_check_outcomes") {
            let n = Bench()
            n.writePlan()
            n.sanityAnswer = .noReply
            n.startSession()
            n.deadPath(seconds: 110)
            check(n.adapter.watch.verdict == .network && n.probeStarts.isEmpty && n.lastState["sanity"] as? String == "no_reply",
                  "no network: the node is not judged and no probe is sent: \(n.adapter.watch.verdict)")
            let c = Bench()
            c.writePlan(targets: ["https://ya.ru", "http://captive.example/x"])
            c.sanityAnswer = .captive
            c.startSession()
            c.deadPath(seconds: 110)
            check(c.adapter.watch.verdict == .captive && c.sanityAsked.first?.map { $0.host } == ["ya.ru", "captive.example"], "the plan's own targets: \(c.sanityAsked.first?.map { $0.host } ?? [])")
            // A check that is still running is not started twice.
            let r = Bench()
            r.writePlan()
            r.sanityAnswer = nil
            r.startSession()
            r.deadPath(seconds: 200)
            check(r.sanityAsked.count == 1, "one check at a time: \(r.sanityAsked.count)")
        }

        run("detach_stops_everything") {
            let b = Bench()
            b.writePlan()
            b.startSession()
            b.runtime.detach()
            check(b.statusBlock().called == 1 && b.statusBlock().block == nil, "after stop the status reply has no block and is still answered")
            check(b.runtime.statsSuffix.isEmpty, "and the statistics line has no fields of the watch")
            b.writePlan(watch: false)
            let before = b.logs.count
            b.runtime.statsTick(isXray: false, loggingEnabled: true, logXray: {}, logWireGuard: {})
            check(b.logs.count == before, "and the plan is not read for a stopped session")
        }

        stageTwo()
        if failures == 0 { print("TribeDataWatchRuntime: all tests passed") } else { print("TribeDataWatchRuntime: \(failures) check(s) FAILED"); exit(1) }
    }
}

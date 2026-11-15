import Foundation

// AVPN (build 140, data watch): host test of the provider's half (TribeDataWatchRuntime.swift) with
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
                    if let target = switchTarget?(node), switchFails {
                        _ = target
                        result = .failed
                    } else if let target = switchTarget?(node) {
                        switched.append((node, target))
                        tx = 0; rx = 0; handshake = 0
                    } else {
                        result = .denied
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
        var uplink = "cellular"
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
                uplinkKind: { [unowned self] in self.uplink },
                sanityCheck: { [unowned self] targets, completion in
                    self.sanityAsked.append(targets)
                    if let answer = self.sanityAnswer { completion(answer) }
                },
                uptime: { [unowned self] in self.uptime },
                nowMs: { [unowned self] in self.wallMs },
                readState: { [unowned self] in self.previousState }))
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
                       pin: Int = 0, memory: [String: Int] = [:]) {
            planSeq += 1
            var object: [String: Any] = [
                "schema": 2, "seq": planSeq, "written_ms": wallMs, "config_fetched_ms": wallMs - fetchedAgoMs,
                "policy_max_age_ms": 86_400_000, "expires_ms": wallMs + expiresInMs, "pool_revision": poolRevision,
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
        /// refused by the shared budget (so a round goes straight to the switches).
        func dead(_ b: Bench, seconds: Int) {
            for second in 1...seconds { b.second(tx: 400, handshake: b.adapter.handshake == 0 ? second % 3 == 0 : false) }
        }
        run("switch_goes_through_the_whole_extension") {
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            for _ in 1...200 where b.adapter.switched.isEmpty { dead(b, seconds: 1) }
            // On the very tick of the switch: the shared file already names the new node and holds
            // no verdict of the node the tunnel has left (nothing waits for the next report).
            check(b.adapter.switched.count == 1 && b.lastState["node_id"] as? String == "12" && b.lastState["switch_seq"] as? Int == 1
                  && b.lastState["verdict"] as? String == "none", "the shared file follows the switch at once: \(b.lastState["node_id"] ?? "-") \(b.lastState["verdict"] ?? "-")")
            dead(b, seconds: 8)
            check(b.adapter.lastInputs.nodeId == "12" || b.adapter.switched.count == 1, "the first switch happened: \(b.adapter.commands)")
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
            check(b.logs.contains("Tribe watch: peer_switch from=16 to=12 why=no_data seq=1 net=cellular result=performed"), "the switch is journaled with both nodes and the reason: \(b.logs.suffix(4))")
            let event = b.records.last { $0.event == "peer_switch" }?.fields
            check(event?["from"] as? String == "16" && event?["to"] as? String == "12" && event?["why"] as? String == "no_data"
                  && event?["seq"] as? Int == 1 && event?["result"] as? String == "performed" && event?["generation"] as? String == "gen-1",
                  "and in the journal ring: \(String(describing: event))")
            // Where the tunnel stands now, for everybody who asks.
            check(b.runtime.sessionOverride()?.nodeId == "12" && b.runtime.sessionOverride()?.endpoint == "198.51.100.12:585", "the status reply's session is the new node")
            check(b.runtime.statsSuffix.hasPrefix(" node=12 "), "the statistics line names the new node: \(b.runtime.statsSuffix)")
            check(b.lastState["node_id"] as? String == "12" && b.lastState["switch_seq"] as? Int == 1 && b.lastState["verdict"] as? String == "none",
                  "the shared file: the new node, the switch number, and no verdict of the node it left: \(b.lastState)")
            let made = b.lastState["switches"] as? [[String: Any]]
            check(made?.count == 1 && made?.first?["from"] as? String == "16" && made?.first?["to"] as? String == "12"
                  && made?.first?["why"] as? String == "no_data" && made?.first?["net"] as? String == "cellular" && (made?.first?["utc_ms"] as? Int64 ?? 0) > 0,
                  "the list of switches: \(String(describing: made))")
            let block = b.statusBlock().block
            check(block?["switch_seq"] as? Int == 1 && (block?["switches"] as? [[String: Any]])?.count == 1, "the status block carries the switch number: \(String(describing: block?["switch_seq"]))")
            check(b.adapter.lastInputs.nodeId == "12" || b.adapter.lastInputs.nodeId == "16", "inputs follow")
            // The new node answers its trial probe: it is trusted and nobody is moved again.
            b.probeResult = "state=answered id=5 ms=40 late=0"
            dead(b, seconds: 60)
            check(b.adapter.switched.count == 1 && b.adapter.lastInputs.nodeId == "12", "trusted: no second switch")
            check(b.adapter.lastInputs.candidates == ["9", "16"], "what is offered from the new node: the rest of the plan and the profile's node: \(b.adapter.lastInputs.candidates)")
            // The plan is rewritten without that node, then without the key, then it is rejected:
            // what the status reply says about the switch already made does not change.
            b.writePlan(switchOn: true, candidates: [9])
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.runtime.sessionOverride()?.nodeId == "12" && b.runtime.sessionOverride()?.endpoint == "198.51.100.12:585", "a plan without the node: the identity stands")
            b.writePlan(switchOn: false)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.runtime.sessionOverride()?.endpoint == "198.51.100.12:585", "the key off: the identity stands")
            try! Data("not a plan".utf8).write(to: b.planURL, options: .atomic)
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            check(b.runtime.sessionOverride()?.nodeId == "12" && b.runtime.sessionOverride()?.endpoint == "198.51.100.12:585", "a rejected plan: the identity stands")
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
            check(off.runtime.switchTarget("12") == nil && off.runtime.sessionOverride() == nil, "and no configuration is handed out")
            check(off.statusBlock().block?["switch_seq"] as? Int == 0, "switch_seq stays 0")
            // An expired list.
            let expired = Bench()
            expired.writePlan(switchOn: true, candidates: [12], expiresInMs: 30_000)
            expired.startSession()
            expired.probeResult = "state=silent id=5 ms=0 late=0"
            dead(expired, seconds: 20)
            check(expired.adapter.lastInputs.candidates == ["12"], "offered while the list is alive")
            dead(expired, seconds: 20)
            expired.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(expired, seconds: 160)
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
        run("exhausted_goes_back_to_the_profile_node_and_says_so") {
            let b = Bench()
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            dead(b, seconds: 260)
            check(b.adapter.switched.map { $0.node } == ["12", "9", "16"], "both candidates, then back: \(b.adapter.switched.map { $0.node })")
            check(b.adapter.switched.last?.target == .home, "the way back is the configuration the session started with")
            check(b.logs.contains("Tribe watch: exhausted tried=3 round=1 stay=16 net=cellular"), "exhausted is journaled with the node the tunnel stays on: \(b.logs.filter { $0.contains("exhausted") })")
            check(b.logs.contains("Tribe watch: peer_switch from=9 to=16 why=exhausted_best seq=3 net=cellular result=performed"), "the return is journaled as such")
            check(b.records.contains { $0.event == "watch_exhausted" && $0.fields["tried"] as? Int == 3 }, "and in the ring")
            check(b.runtime.sessionOverride() == nil && b.runtime.statsSuffix.hasPrefix(" node=16 "), "back on the profile's node: its own identity again")
            check(b.statusBlock().block?["switch_seq"] as? Int == 3, "three switches were made")
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
            dead(b, seconds: 110)
            check(b.logs.contains("Tribe watch: peer_switch from=16 to=12 why=no_data seq=0 net=cellular result=failed"), "a failed switch is journaled as failed: \(b.logs.suffix(3))")
            check(b.runtime.sessionOverride() == nil && b.runtime.statsSuffix.hasPrefix(" node=16 "), "the session is still the profile's node")
            check(b.statusBlock().block?["switch_seq"] as? Int == 0 && (b.statusBlock().block?["switches"] as? [[String: Any]])?.isEmpty == true, "no switch is counted")
            check(b.states.allSatisfy { $0["node_id"] as? String == "16" }, "the shared file never named another node")
            check(b.records.contains { $0.event == "peer_switch" && $0.fields["result"] as? String == "failed" }, "and the ring has the attempt")
        }
        run("switch_list_keeps_the_last_eight") {
            let b = Bench()
            b.writePlan(numbers: ["ios_tw_trial_probe_max_per_hour": 60], switchOn: true, candidates: [12, 9])
            b.startSession()
            b.probeResult = "state=silent id=5 ms=0 late=0"
            dead(b, seconds: 2700) // rounds at 5, 10, 20 minutes: 4 rounds x 3 switches
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
            dead(b, seconds: 110)
            check(b.adapter.switched.count == 1, "a round is in progress")
            b.writePlan(switchOn: false, candidates: [12, 9, 3]) // the server switched the key off; the app rewrote the plan
            b.runtime.statsTick(isXray: false, loggingEnabled: false, logXray: {}, logWireGuard: {})
            dead(b, seconds: 300)
            check(b.adapter.switched.count == 1 && !b.adapter.watch.snapshot(policy: b.adapter.policy).arbiterActive, "not one more switch after the key went off")
            check(b.runtime.sessionOverride()?.nodeId == "12" || b.runtime.sessionOverride() == nil, "the tunnel stays where it is")
        }
        run("start_by_the_system_chooses_from_the_plan") {
            // The previous run judged the profile's node dead on this network 5 minutes ago.
            let b = Bench()
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.previousState = ["verdict": "no_data", "node_id": "16", "net": "cellular", "last_no_data_ms": b.wallMs - 300_000]
            _ = b.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            let choice = b.runtime.chooseStartBySystem()
            check(choice?.nodeId == "12" && choice?.why == "plan_order" && (choice?.wgQuick.contains("Endpoint = 198.51.100.12:585\n") ?? false),
                  "the plan's first candidate instead of the node that failed here: \(String(describing: choice?.nodeId))")
            check(b.logs.contains("Tribe watch: start candidate=12 why=plan_order profile=16 net=cellular"), "journaled: \(b.logs)")
            check(b.records.contains { $0.event == "peer_switch" && $0.fields["why"] as? String == "os_start_plan_order" && $0.fields["seq"] as? Int == 1 }, "and in the ring")
            b.runtime.attach(adapter: b.adapter)
            check(b.runtime.sessionOverride()?.nodeId == "12", "the session's identity is the chosen node")
            b.writePlan(switchOn: true, candidates: [12, 9])
            b.adapter.start(at: b.uptime)
            let block = b.statusBlock().block
            let list = block?["switches"] as? [[String: Any]]
            check(block?["switch_seq"] as? Int == 1 && list?.first?["why"] as? String == "os_start_plan_order" && list?.first?["from"] as? String == "16",
                  "the app is told as about any switch: \(String(describing: list))")
            // The configuration could not be built: the profile's node after all.
            b.runtime.cancelStartChoice()
            check(b.runtime.sessionOverride() == nil && b.statusBlock().block?["switch_seq"] as? Int == 0, "a dropped choice leaves no trace of a switch")
            // A healthy profile node, another network, no key: nothing is chosen.
            let healthy = Bench()
            healthy.writePlan(switchOn: true, candidates: [12])
            _ = healthy.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            check(healthy.runtime.chooseStartBySystem() == nil && healthy.logs.allSatisfy { !$0.contains("start candidate") }, "no failure known: the profile's node, silently")
            let wifi = Bench()
            wifi.writePlan(switchOn: true, candidates: [12])
            wifi.uplink = "wifi"
            wifi.previousState = ["verdict": "no_data", "node_id": "16", "net": "cellular", "last_no_data_ms": wifi.wallMs - 300_000]
            _ = wifi.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            check(wifi.runtime.chooseStartBySystem() == nil, "the failure was on another network")
            let off = Bench()
            off.writePlan(switchOn: false, candidates: [12])
            off.previousState = ["verdict": "no_data", "node_id": "16", "net": "cellular", "last_no_data_ms": off.wallMs - 300_000]
            _ = off.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            check(off.runtime.chooseStartBySystem() == nil, "the switch key off: the profile's node, as build 139")
            // The pin of the plan comes first.
            let pinned = Bench()
            pinned.writePlan(switchOn: true, candidates: [12, 9], pin: 9)
            _ = pinned.runtime.prepare(nodeId: "16", proto: "awg", generation: "gen-2", clientIP: "10.8.1.7/32", resolver: "1.1.1.1", base: Bench.base)
            check(pinned.runtime.chooseStartBySystem()?.nodeId == "9" && pinned.logs.contains("Tribe watch: start candidate=9 why=pin profile=16 net=cellular"), "the pinned node first")
        }
    }

    static func main() {
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

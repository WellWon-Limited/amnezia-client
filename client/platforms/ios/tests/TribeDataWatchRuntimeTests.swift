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
            let output = watch.step(TribeDataWatchSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: handshake, uptime: uptime, wall: wall),
                                    env: inputs.env(pathSatisfied: true), policy: policy)
            guard output.action != .keep || output.needsSanityCheck || output.startProbe != nil else { return }
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
                uplinkKind: { "cellular" },
                sanityCheck: { [unowned self] targets, completion in
                    self.sanityAsked.append(targets)
                    if let answer = self.sanityAnswer { completion(answer) }
                },
                uptime: { [unowned self] in self.uptime },
                nowMs: { [unowned self] in self.wallMs }))
        }
        deinit { try? FileManager.default.removeItem(at: directory) }

        var planURL: URL { directory.appendingPathComponent(TribeWatchPlan.fileName) }

        /// The app writes a plan (atomically, a new sequence number every time).
        func writePlan(watch: Bool = true, numbers: [String: Any] = [:], poolRevision: Int64 = 1_763_190_000_000,
                       fetchedAgoMs: Int64 = 60_000, targets: [String]? = nil) {
            planSeq += 1
            var object: [String: Any] = [
                "schema": 2, "seq": planSeq, "written_ms": wallMs, "config_fetched_ms": wallMs - fetchedAgoMs,
                "policy_max_age_ms": 86_400_000, "expires_ms": wallMs + 86_400_000, "pool_revision": poolRevision,
                "features": ["ios_tunnel_watch": watch, "ios_tunnel_watch_switch": false, "ios_on_demand_bg_arm": false],
                "numbers": numbers, "candidates": [Any](),
            ]
            if let targets { object["sanity_targets"] = targets }
            try! JSONSerialization.data(withJSONObject: object).write(to: planURL, options: .atomic)
        }

        /// A session comes up the way startWireguard does it.
        @discardableResult
        func startSession(nodeId: String = "16") -> Bool {
            let available = runtime.prepare(nodeId: nodeId, proto: "awg", generation: "gen-1", clientIP: "10.8.1.7/32", resolver: "1.1.1.1")
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

        if failures == 0 { print("TribeDataWatchRuntime: all tests passed") } else { print("TribeDataWatchRuntime: \(failures) check(s) FAILED"); exit(1) }
    }
}

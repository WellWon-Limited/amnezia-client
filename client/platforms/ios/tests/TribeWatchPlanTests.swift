import Foundation

// AVPN (build 140, data watch): host test of the extension's Foundation-only half - the plan file
// the app writes (TribeWatchPlan.swift), the meaning of the bypass check's reply and the journal
// line. Compiled with the pure rule of the awg-apple package (TribeDataWatch.swift).
@main
enum TribeWatchPlanTests {
    static var failures = 0
    static func check(_ cond: @autoclosure () -> Bool, _ what: @autoclosure () -> String, line: Int = #line) {
        if !cond() { failures += 1; print("FAIL line \(line): \(what())") }
    }

    static let now: Int64 = 1_800_000_000_000
    static let hour: Int64 = 3_600_000

    static func plan(_ change: (inout [String: Any]) -> Void = { _ in }) -> Data {
        var object: [String: Any] = [
            "schema": 2, "seq": 5, "written_ms": now - 1000, "config_fetched_ms": now - hour, "expires_ms": now + 24 * hour,
            "policy_max_age_ms": 24 * hour, "pool_revision": 100, "transport_mode": "auto",
            "pin": ["country": "", "node_id": 0], "session": ["node_id": 12, "proto": "awg", "country": "EE"],
            "net_keys": ["wifi": "wifi", "cellular": "cellular:250-02"], "net_memory": [String: Any](),
            "features": ["ios_tunnel_watch": true, "ios_tunnel_watch_switch": false, "ios_on_demand_bg_arm": false],
            "numbers": ["ios_tw_cycle_s": 25, "ios_tw_cycle_min_tx_bytes": 2048],
            "candidates": [Any](),
        ]
        change(&object)
        return try! JSONSerialization.data(withJSONObject: object)
    }

    /// A candidate entry as the app writes it (TunnelWatchPlan.h): the node's part of the tunnel
    /// configuration, strings by the provider configuration's keys.
    static let key32 = Data(repeating: 7, count: 32).base64EncodedString()
    static func candidate(_ node: Int, host: String = "198.51.100.7", _ change: (inout [String: Any]) -> Void = { _ in }) -> [String: Any] {
        var peer: [String: Any] = ["hostName": host, "port": "585", "server_pub_key": key32, "psk_key": key32,
                                   "persistent_keep_alive": "25", "Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "55", "S2": "66",
                                   "S3": "12", "S4": "8", "H1": "101", "H2": "102", "H3": "103", "H4": "104", "I1": "<b 0xc0ffee>"]
        change(&peer)
        return ["node_id": node, "country": "FI", "peer": peer]
    }

    typealias Order = TribeWatchPlan.Order
    static func parse(_ data: Data?, alive: Bool = false, last: Order = Order()) -> Result<TribeWatchPlan, TribeWatchPlan.Rejection> {
        TribeWatchPlan.parse(data, nowMs: now, appAlive: alive, last: last)
    }
    static func rejection(_ data: Data?, alive: Bool = false, last: Order = Order()) -> TribeWatchPlan.Rejection? {
        if case .failure(let r) = parse(data, alive: alive, last: last) { return r }
        return nil
    }
    static func accepted(_ data: Data?, alive: Bool = false, last: Order = Order()) -> TribeWatchPlan? {
        if case .success(let p) = parse(data, alive: alive, last: last) { return p }
        return nil
    }

    /// Stage 2: the candidates of the plan, the text of a switch, the node of a start by the system.
    static func stageTwo() {
        let switchOn: (inout [String: Any]) -> Void = {
            $0["features"] = ["ios_tunnel_watch": true, "ios_tunnel_watch_switch": true]
            $0["switch_lease_until_ms"] = now + 6 * hour
        }
        func parsed(_ entries: [Any], _ more: (inout [String: Any]) -> Void = { _ in }) -> TribeWatchPlan? {
            accepted(plan { switchOn(&$0); $0["candidates"] = entries; more(&$0) })
        }
        // --- the list ---
        let three = parsed([candidate(12), candidate(9, host: "node9.example.org"), candidate(3)])
        check(three?.candidates.map { $0.nodeId } == ["12", "9", "3"] && three?.policy.switchEnabled == true, "the plan's order is kept: \(String(describing: three?.candidates.map { $0.nodeId }))")
        check(three?.candidates.first?.country == "FI" && three?.candidates.first?.endpoint == "198.51.100.7:585", "labels and the endpoint as the app knows it")
        check(parsed([candidate(12), candidate(12), candidate(9)])?.candidates.map { $0.nodeId } == ["12", "9"], "a node is offered once")
        check(parsed((1...9).map { candidate($0) })?.candidates.count == TribeWatchPlan.maxCandidates, "at most six entries are read")
        check(parsed([candidate(12)]) { $0["expires_ms"] = now }?.candidates.isEmpty == true, "an expired list is empty, not stale")
        check(parsed(["junk", 7, ["node_id": 5]])?.candidates.isEmpty == true && parsed(["junk"])?.policy.switchEnabled == false, "junk entries are dropped and switch nothing on")
        // --- the strict check of one entry ---
        func ok(_ change: @escaping (inout [String: Any]) -> Void) -> Bool { TribeWatchCandidate(candidate(12, change)) != nil }
        check(ok { _ in }, "a full entry passes")
        check(TribeWatchCandidate(["node_id": 0, "peer": candidate(1)["peer"]!]) == nil && TribeWatchCandidate(["node_id": "x", "peer": candidate(1)["peer"]!]) == nil, "a node id is a positive number")
        for missing in ["hostName", "port", "server_pub_key", "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"] {
            check(!ok { $0[missing] = nil }, "without \(missing) the entry is rejected")
            check(!ok { $0[missing] = "  " }, "an empty \(missing) is a missing one")
        }
        check(ok { $0["psk_key"] = nil; $0["S3"] = nil; $0["I1"] = nil; $0["persistent_keep_alive"] = nil }, "the optional keys are optional")
        check(!ok { $0["port"] = "0" } && !ok { $0["port"] = "65536" } && !ok { $0["port"] = "5a" } && ok { $0["port"] = 585 }, "the port is a port (a number is accepted)")
        check(!ok { $0["hostName"] = "198.51.100.7\nEndpoint = evil:1" } && !ok { $0["H1"] = "1\n[Peer]" } && !ok { $0["I1"] = "a\rb" }, "a line break in any value rejects the entry")
        check(!ok { $0["hostName"] = "host name" } && !ok { $0["hostName"] = "h/../x" } && !ok { $0["hostName"] = String(repeating: "a", count: 254) }, "a host is a host name or an address")
        check(!ok { $0["server_pub_key"] = "c2hvcnQ=" } && !ok { $0["server_pub_key"] = "not base64 at all" } && !ok { $0["psk_key"] = "c2hvcnQ=" }, "keys are 32 bytes of base64")
        check(!ok { $0["Jc"] = true } && !ok { $0["H1"] = ["1"] }, "a value is a string or a number")
        check(!ok { $0["I1"] = String(repeating: "f", count: 4097) } && ok { $0["I1"] = String(repeating: "f", count: 4096) }, "a value is bounded")
        let extra = TribeWatchCandidate(candidate(12) { $0["client_priv_key"] = "secret"; $0["dns1"] = "9.9.9.9"; $0["Table"] = "off" })
        check(extra != nil && extra?.peer["client_priv_key"] == nil && extra?.peer["dns1"] == nil && extra?.peer["Table"] == nil, "keys outside the node's own are not taken")
        // --- the text of the session on that node ---
        let base = TribeSwitchBase(address: "10.8.1.7/32", dns: "100.100.100.53", mtu: "1280", privateKey: "PRIVATE", allowedIPs: "0.0.0.0/0, ::/0")
        let text = TribeWatchCandidate(candidate(12))!.wgQuick(base: base)
        let expected = ["[Interface]", "Address = 10.8.1.7/32", "DNS = 100.100.100.53", "MTU = 1280", "PrivateKey = PRIVATE",
                        "Jc = 4", "Jmin = 10", "Jmax = 50", "S1 = 55", "S2 = 66", "H1 = 101", "H2 = 102", "H3 = 103", "H4 = 104",
                        "S3 = 12", "S4 = 8", "I1 = <b 0xc0ffee>", "[Peer]", "PublicKey = \(key32)", "PresharedKey = \(key32)",
                        "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = 198.51.100.7:585", "PersistentKeepalive = 25", ""]
        check(text.components(separatedBy: "\n") == expected, "the wg-quick text, line by line: \(text)")
        let bare = TribeWatchCandidate(candidate(12) { $0["psk_key"] = nil; $0["persistent_keep_alive"] = nil; $0["S3"] = nil; $0["S4"] = nil; $0["I1"] = nil })!.wgQuick(base: base)
        check(!bare.contains("PresharedKey") && !bare.contains("PersistentKeepalive") && !bare.contains("S3") && !bare.contains("I1"), "absent keys leave no line")
        let v3 = TribeWatchCandidate(candidate(12) { $0["HeaderProtectionKey"] = key32; $0["RandomTrailers"] = "1"; $0["DisableCookies"] = "0"; $0["RekeyAfterTime"] = "100-120" })!.wgQuick(base: base)
        check(v3.contains("HeaderProtectionKey = \(key32)\n") && v3.contains("RandomTrailers = 1\n") && v3.contains("DisableCookies = 0\n") && v3.contains("RekeyAfterTime = 100-120\n"), "the AmneziaWG 3.x keys of the node are carried")
        // --- pin, mode and the network memory of the plan ---
        let pinned = parsed([candidate(12)]) {
            $0["pin"] = ["country": "FI", "node_id": 12]
            $0["transport_mode"] = "amnezia"
            $0["net_memory"] = ["wifi": ["node_id": 9, "saved_ms": 1], "cellular:250-02": ["node_id": 3, "saved_ms": 1], "cellular:250-99": ["node_id": 4, "saved_ms": 1]]
        }
        check(pinned?.pinNodeId == "12" && pinned?.pinCountry == "FI" && pinned?.transportMode == "amnezia", "pin and mode of the plan")
        check(pinned?.memory == ["wifi": "9", "cellular": "3"], "the memory of the two networks the plan names: \(String(describing: pinned?.memory))")
        check(parsed([candidate(12)])?.pinNodeId == "" && parsed([candidate(12)])?.memory.isEmpty == true, "no pin, no memory")
        // --- a start by the system ---
        typealias Choice = TribeStartChoice
        func choose(_ plan: TribeWatchPlan?, net: String = "cellular", failed: Choice.LastFailure? = nil) -> String {
            let c = Choice.choose(profileNodeId: "16", plan: plan, net: net, failures: failed.map { [$0] } ?? [], nowMs: now)
            return "\(c.nodeId)/\(c.why)"
        }
        let twoSpare = parsed([candidate(12), candidate(9)])
        check(choose(nil) == "16/profile", "no plan: the profile's node, as build 139")
        check(choose(accepted(plan { $0["candidates"] = [candidate(12)] })) == "16/profile", "the switch key off: the profile's node")
        check(choose(accepted(plan { $0["candidates"] = [candidate(12)] }), failed: Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now - 60_000)) == "16/profile",
              "the switch key off: the profile's node even when it failed here a minute ago (build 139)")
        check(choose(parsed([])) == "16/profile", "nothing to choose from: the profile's node")
        // The function's own lock, whatever the struct holds: with the switch key off in the policy
        // it returns the profile's node (a parsed plan never has candidates then - that is the other lock).
        var forged = parsed([candidate(12), candidate(9)])
        forged?.policy.switchEnabled = false
        check(forged?.candidates.count == 2 && choose(forged, failed: Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now - 60_000)) == "16/profile",
              "the key off in the policy: the profile's node even with candidates in hand")
        check(choose(twoSpare) == "16/profile", "a healthy profile node is kept")
        let recently = Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now - 10 * 60 * 1000)
        check(choose(twoSpare, failed: recently) == "12/plan_order", "the profile's node failed here ten minutes ago: the plan's first")
        check(choose(twoSpare, net: "wifi", failed: recently) == "16/profile", "it failed on ANOTHER network: that proves nothing here")
        check(choose(twoSpare, failed: Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now - 31 * 60 * 1000)) == "16/profile", "older than half an hour: forgotten")
        check(choose(twoSpare, failed: Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now + 60_000)) == "16/profile", "a failure from the future is not believed")
        check(choose(twoSpare, failed: Choice.LastFailure(nodeId: "12", net: "cellular", wallMs: now - 1000)) == "16/profile", "another node's failure does not move the start")
        // the pin comes first; it is left only for a failure proven on this network
        let pinOn9 = parsed([candidate(12), candidate(9)]) { $0["pin"] = ["country": "FI", "node_id": 9] }
        check(choose(pinOn9) == "9/pin", "the pinned node first, even when the profile holds another")
        check(choose(pinOn9, failed: Choice.LastFailure(nodeId: "9", net: "cellular", wallMs: now - 1000)) == "16/profile", "the pinned node is proven dead here: the next source")
        check(choose(parsed([candidate(12)]) { $0["pin"] = ["country": "US", "node_id": 77] }) == "16/profile", "a pin the extension cannot raise is not invented")
        // the app's memory of this network
        let remembered = parsed([candidate(12), candidate(9)]) { $0["net_memory"] = ["cellular:250-02": ["node_id": 9, "saved_ms": 1], "wifi": ["node_id": 12, "saved_ms": 1]] }
        check(choose(remembered) == "9/memory" && choose(remembered, net: "wifi") == "12/memory", "the node the app remembers for this kind of network")
        check(choose(remembered, net: "unknown") == "16/profile", "an unknown network has no memory")
        check(choose(remembered, failed: Choice.LastFailure(nodeId: "9", net: "cellular", wallMs: now - 1000)) == "16/profile", "a remembered node that failed here is skipped")
        // everything failed that could be told: the profile's node
        check(choose(parsed([candidate(16)]), failed: recently) == "16/profile", "nothing else to raise: the profile's node")
        // --- its own last verdict, read back from the shared file ---
        let state: [String: Any] = ["verdict": "no_data", "node_id": "16", "net": "cellular", "last_no_data_ms": now - 5000]
        check(Choice.failures(state: state, nowMs: now) == [Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now - 5000)], "the last verdict of the previous run")
        var other = state
        other["verdict"] = "none"
        check(Choice.failures(state: other, nowMs: now).isEmpty && Choice.failures(state: nil, nowMs: now).isEmpty
              && Choice.failures(state: ["verdict": "no_data"], nowMs: now).isEmpty, "no verdict, no file, half a record: nothing")
        check(Choice.failureMemoryMs == 30 * 60 * 1000, "half an hour")
        // --- the list of nodes judged dead: it survives every rewrite of the file (review R6) ---
        let f16 = Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now - 20 * 60_000)
        let f12 = Choice.LastFailure(nodeId: "12", net: "cellular", wallMs: now - 60_000)
        var list = Choice.noting(f16, in: [], nowMs: now)
        list = Choice.noting(f12, in: list, nowMs: now)
        check(list == [f16, f12], "records accumulate")
        list = Choice.noting(Choice.LastFailure(nodeId: "16", net: "cellular", wallMs: now), in: list, nowMs: now)
        check(list.map { $0.nodeId } == ["12", "16"] && list.last?.wallMs == now, "a node judged again: its newest record only")
        list = Choice.noting(Choice.LastFailure(nodeId: "16", net: "wifi", wallMs: now), in: list, nowMs: now)
        check(list.count == 3, "the same node on another kind of network is another record")
        check(Choice.noting(f12, in: [Choice.LastFailure(nodeId: "3", net: "wifi", wallMs: now - 31 * 60_000)], nowMs: now) == [f12], "expired records are dropped")
        var many: [Choice.LastFailure] = []
        for n in 1...12 { many = Choice.noting(Choice.LastFailure(nodeId: String(n), net: "wifi", wallMs: now - Int64(n)), in: many, nowMs: now) }
        check(many.count == Choice.maxFailuresKept && many.last?.nodeId == "12", "at most eight are kept, the newest stay")
        let encoded = Choice.encode([f16, f12])
        check(JSONSerialization.isValidJSONObject(encoded) && Choice.failures(state: ["dead": encoded, "verdict": "none"], nowMs: now) == [f16, f12], "they lie in the file and come back from it")
        check(Choice.failures(state: ["dead": encoded, "verdict": "no_data", "node_id": "9", "net": "wifi", "last_no_data_ms": now - 1], nowMs: now).map { $0.nodeId } == ["16", "12", "9"],
              "the verdict the file ends with joins the list")
        check(Choice.failures(state: ["dead": encoded], nowMs: now + 25 * 60_000) == [f12], "read back half an hour after the older one: it is gone")
        check(Choice.failures(state: ["dead": Choice.encode([f12, f16])], nowMs: now + 25 * 60_000) == [f12], "also when the aged record is the last one in the file")
        check(Choice.failures(state: ["dead": Choice.encode([f16])], nowMs: now + 25 * 60_000).isEmpty, "and when it is the only one")
        check(Choice.failures(state: ["dead": [["node_id": "7", "net": "wifi", "at_ms": 0], ["node_id": "8", "net": "wifi", "at_ms": -5]]], nowMs: now).isEmpty, "a record without a real time is an aged one")
        check(Choice.failures(state: ["dead": ["junk", ["node_id": "", "net": "wifi", "at_ms": 5], ["node_id": "7", "net": "wi fi", "at_ms": 5], ["node_id": "7", "net": "wifi"]]], nowMs: now).isEmpty, "junk entries are dropped")
        let twoDead = Choice.choose(profileNodeId: "16", plan: twoSpare, net: "cellular", failures: [f16, f12], nowMs: now)
        check(twoDead.nodeId == "9" && twoDead.why == "plan_order", "with two nodes known dead here the third is chosen: \(twoDead)")
        // --- who started the tunnel (review R1) ---
        check(Choice.startedBySystem(source: nil), "no source at all: the system")
        for named in ["app", "intent", "os", "", "anything"] { check(!Choice.startedBySystem(source: named), "'\(named)' names somebody: not the system") }
        // --- the lease of the switch permission (review R7) ---
        let leased = parsed([candidate(12)])
        check(leased?.policy.switchEnabled == true && leased?.switchLeaseUntilMs == now + 6 * hour && leased?.holdsUnusableSecrets == false, "inside the lease: switching is permitted")
        let lapsed = parsed([candidate(12)]) { $0["switch_lease_until_ms"] = now }
        check(lapsed?.policy.enabled == true && lapsed?.policy.switchEnabled == false && lapsed?.candidates.isEmpty == true, "the lease lapsed: the watch works, switching does not, no candidate is kept")
        check(lapsed?.holdsUnusableSecrets == true, "and the file is known to hold keys nothing may be done with")
        check(parsed([candidate(12)]) { $0["switch_lease_until_ms"] = now + 1 }?.policy.switchEnabled == true, "the lease boundary")
        check(parsed([candidate(12)]) { $0["switch_lease_until_ms"] = nil }?.policy.switchEnabled == false, "no lease in the plan: no switching")
        check(parsed([candidate(12)]) { $0["switch_lease_until_ms"] = now + 25 * hour }?.policy.switchEnabled == false, "a lease longer than a day is not a lease (the clock, or a broken writer)")
        check(parsed([candidate(12)]) { $0["switch_lease_until_ms"] = now + 24 * hour }?.policy.switchEnabled == true, "a day is the longest")
        check(accepted(plan { $0["candidates"] = [candidate(12)] })?.holdsUnusableSecrets == true, "the key off with candidates in the file: keys nothing may be done with")
        let keyOff = accepted(plan { $0["candidates"] = [candidate(12)]; $0["switch_lease_until_ms"] = now + 6 * hour })
        check(keyOff?.candidates.isEmpty == true && keyOff?.holdsUnusableSecrets == true && keyOff?.policy.switchEnabled == false,
              "the key off inside a live lease: no node's keys are kept in memory either, and the file is known to hold them")
        check(accepted(plan())?.holdsUnusableSecrets == false, "no candidates: nothing to take out")
        check(parsed([candidate(12)]) { $0["expires_ms"] = now }?.holdsUnusableSecrets == true, "an expired list: the same")
        let full = plan { switchOn(&$0); $0["candidates"] = [candidate(12), candidate(9)] }
        let clean = TribeWatchPlan.scrubbed(full)
        let cleanObject = clean.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        check((cleanObject?["candidates"] as? [Any])?.isEmpty == true && cleanObject?["seq"] as? Int == 5 && cleanObject?["written_ms"] as? Int64 == now - 1000
              && (cleanObject?["numbers"] as? [String: Any])?["ios_tw_cycle_s"] as? Int == 25, "scrubbed: no candidates, everything else as it was")
        check(clean.map { !String(decoding: $0, as: UTF8.self).contains(key32) } == true, "no key is left")
        check(accepted(clean, last: accepted(full)!.order)?.policy.enabled == true, "and it is the same plan for the order of plans")
        check(TribeWatchPlan.scrubbed(Data("junk".utf8)) == nil && TribeWatchPlan.scrubbed(plan { $0["schema"] = 1 }) == nil, "what is not a plan is not rewritten")
        check(TribeDataWatchJournal.engineLine(down: true, nodeId: "16") == "Tribe watch: engine=down node=16"
              && TribeDataWatchJournal.engineLine(down: false, nodeId: "16") == "Tribe watch: engine=up node=16", "the engine line")
        // --- the journal lines of a command ---
        check(TribeDataWatchJournal.commandLine(.switchPeer(to: "12", why: .noData), result: .performed, from: "16", seq: 3, net: "cellular")
              == "Tribe watch: peer_switch from=16 to=12 why=no_data seq=3 net=cellular result=performed", "the switch line")
        check(TribeDataWatchJournal.commandLine(.switchPeer(to: "16", why: .best), result: .failed, from: "9", seq: 3, net: "wifi")
              == "Tribe watch: peer_switch from=9 to=16 why=exhausted_best seq=3 net=wifi result=failed", "the return line")
        check(TribeDataWatchJournal.commandLine(.heal(.softRestart), result: .denied, from: "16", seq: 0, net: "cellular")
              == "Tribe watch: heal step=soft_restart result=denied node=16 net=cellular", "the heal line")
        var snapshot = TribeDataWatchSnapshot()
        snapshot.arbiterTried = 3
        snapshot.arbiterRound = 2
        check(TribeDataWatchJournal.exhaustedLine(snapshot: snapshot, nodeId: "16", net: "cellular")
              == "Tribe watch: exhausted tried=3 round=2 stay=16 net=cellular", "the exhausted line")
    }

    static func main() {
        // --- the plan is accepted as written ---
        let good = accepted(plan())
        check(good != nil, "a well-formed plan is accepted")
        check(good?.policy.enabled == true && good?.policy.cycleSeconds == 25 && good?.policy.cycleMinTxBytes == 2048, "policy from the plan: \(String(describing: good?.policy))")
        check(good?.poolRevision == 100 && good?.candidates.isEmpty == true && good?.sanityTargets.isEmpty == true, "revision, no candidates, built-in targets")
        check(good?.order == Order(seq: 5, writtenMs: now - 1000), "the plan's place in the app's own order")
        check(good?.policy.switchEnabled == false, "stage 1: nothing to switch to")

        // --- no plan, a broken plan: the watch is off (build 139 behaviour) ---
        check(rejection(nil) == .missing && rejection(Data()) == .missing, "no file")
        check(rejection(Data(repeating: 0x20, count: TribeWatchPlan.maxBytes + 1)) == .tooLarge, "over 64 KB")
        check(rejection(Data("not json".utf8)) == .notJSON && rejection(Data("[1,2]".utf8)) == .notJSON, "not a JSON object")
        check(rejection(plan { $0["schema"] = 1 }) == .schema && rejection(plan { $0["schema"] = 3 }) == .schema, "another schema")
        check(rejection(plan { $0.removeValue(forKey: "schema") }) == .schema, "no schema")
        check(rejection(plan { $0["schema"] = true }) == .schema, "a boolean is not a schema number")

        // --- time ---
        check(accepted(plan { $0["written_ms"] = now + 5 * 60_000 }) != nil, "5 minutes in the future is tolerated")
        check(rejection(plan { $0["written_ms"] = now + 5 * 60_000 + 1 }) == .future, "more is rejected")
        check(rejection(plan { $0.removeValue(forKey: "written_ms") }) == .future, "no write time")

        // --- the order of plans is the app's own sequence and time of writing (review finding A3) ---
        // The server's pool revision is NOT monotonic (deleting a node lowers it): a plan with a
        // lower revision used to be rejected and the watch stayed off until the tunnel restarted.
        let seen = Order(seq: 5, writtenMs: now - 1000)
        check(accepted(plan { $0["pool_revision"] = 1 }, last: seen)?.poolRevision == 1, "a lower pool revision is a valid plan")
        check(accepted(plan { $0["pool_revision"] = 1; $0["seq"] = 6; $0["written_ms"] = now - 500 }, last: seen) != nil, "the next plan, lower revision")
        check(accepted(plan(), last: seen) != nil, "the same plan read again")
        check(rejection(plan { $0["seq"] = 4; $0["written_ms"] = now - 2000 }, last: seen) == .stale, "an older plan than one already seen")
        check(rejection(plan { $0["seq"] = 4 }, last: seen) == .stale, "a lower sequence written at the same moment is older")
        check(accepted(plan { $0["seq"] = 1; $0["written_ms"] = now - 100 }, last: seen) != nil, "the app's counter started over: later writing wins")
        check(accepted(plan { $0.removeValue(forKey: "seq") }, last: Order()) != nil, "no sequence at all is sequence 0")
        check(Order(seq: 3, writtenMs: 10).accepts(Order(seq: 3, writtenMs: 5)) && !Order(seq: 3, writtenMs: 10).accepts(Order(seq: 2, writtenMs: 10)), "order rule")

        // --- the policy's age ---
        check(accepted(plan { $0["config_fetched_ms"] = now - 24 * hour }) != nil, "exactly at the limit")
        check(rejection(plan { $0["config_fetched_ms"] = now - 24 * hour - 1 }) == .policyStale, "a policy older than its limit lapses")
        check(accepted(plan { $0["config_fetched_ms"] = now - 48 * hour }, alive: true) != nil, "but not while the app is alive")
        check(rejection(plan { $0["policy_max_age_ms"] = 0 }) == .policyStale, "max age 0: only while the app is alive")
        check(accepted(plan { $0["policy_max_age_ms"] = 0 }, alive: true) != nil, "max age 0 with a living app")
        check(rejection(plan { $0["config_fetched_ms"] = 0 }) == .policyStale, "unknown fetch time is not fresh")
        check(rejection(plan { $0["config_fetched_ms"] = now + hour }) == .policyStale, "a fetch time from the future is not fresh")

        // --- flags and numbers go through the rule's own clamps ---
        check(accepted(plan { $0["features"] = ["ios_tunnel_watch": false] })?.policy.enabled == false, "flag off: accepted, watch off")
        check(accepted(plan { $0.removeValue(forKey: "features") })?.policy == TribeDataWatchPolicy.fromPlan(features: [:], numbers: ["ios_tw_cycle_s": 25, "ios_tw_cycle_min_tx_bytes": 2048]), "no features: off")
        check(accepted(plan { $0["numbers"] = ["ios_tw_cycle_s": 5, "ios_tw_dead_cycles": 999] })?.policy.cycleSeconds == 10, "numbers are clamped again in the extension")
        check(accepted(plan { $0["numbers"] = ["ios_tw_cycle_s": 5, "ios_tw_dead_cycles": 999] })?.policy.deadCycles == 20, "upper clamp")
        check(accepted(plan { $0["unknown_key"] = ["x": 1]; $0["numbers"] = ["ios_tw_future_knob": 7] }) != nil, "unknown keys are ignored")

        // --- the switch flag needs a live candidate list (stage 2) ---
        let withCandidates: (inout [String: Any]) -> Void = {
            $0["features"] = ["ios_tunnel_watch": true, "ios_tunnel_watch_switch": true]
            $0["switch_lease_until_ms"] = now + hour
            $0["candidates"] = [candidate(16)]
        }
        check(accepted(plan(withCandidates))?.policy.switchEnabled == true, "switch flag with candidates is carried")
        check(accepted(plan { withCandidates(&$0); $0["expires_ms"] = now })?.policy.switchEnabled == false, "an expired list switches it off")
        check(accepted(plan { withCandidates(&$0); $0["expires_ms"] = now })?.policy.enabled == true, "but the watch itself goes on")
        check(accepted(plan { withCandidates(&$0); $0["candidates"] = [Any]() })?.policy.switchEnabled == false, "no candidates: nothing to switch to")

        // --- targets of the bypass check ---
        let targets = accepted(plan { $0["sanity_targets"] = ["http://a.example/x", "https://b.example/", "http://1.2.3.4/", "http://u:p@c.example/",
                                                               "ftp://d.example/", "www.e.example", 7, "https://f.example/path", "http://g.example/", "http://h.example/"] })?.sanityTargets
        check(targets == ["http://a.example/x", "https://b.example/", "www.e.example", "http://g.example/"], "http or https, host names, no credentials, at most four: \(String(describing: targets))")
        // Review finding A4: the built-in targets answer inside Russia also on a mobile network in
        // white-list mode (the marketplace tier of the white-list detector), plus one host for
        // phones abroad. They are TLS handshakes: no plain HTTP request leaves the phone.
        check(TribeSanityTarget.builtIn == ["https://www.ozon.ru", "https://www.wildberries.ru", "https://www.apple.com"], "built-in targets")
        check(TribeSanityTarget.builtIn.allSatisfy { TribeSanityTarget(url: $0)?.kind == .tls }, "all of them are TLS handshakes")
        let tls = TribeSanityTarget(url: "https://www.ozon.ru")!
        check(tls.kind == .tls && tls.host == "www.ozon.ru" && tls.port == 443 && tls.path == "/", "a TLS target")
        check(TribeSanityTarget(url: "ya.ru")?.kind == .tls && TribeSanityTarget(url: "ya.ru")?.port == 443, "a bare host name is a TLS target")
        check(TribeSanityTarget(url: "https://ya.ru:8443/")?.port == 8443, "with its own port")
        check(TribeSanityTarget(url: "https://ya.ru/some/page") == nil, "a TLS target is a handshake, it has no page")
        let target = TribeSanityTarget(url: "http://connectivitycheck.gstatic.com/generate_204")!
        check(target.kind == .http && target.host == "connectivitycheck.gstatic.com" && target.port == 80 && target.path == "/generate_204", "an http target")
        check(String(data: target.request, encoding: .utf8)!.hasPrefix("GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n"), "request line and host")
        check(TribeSanityTarget(url: "http://[2001:db8::1]/") == nil && TribeSanityTarget(url: "http://exa mple/") == nil && TribeSanityTarget(url: "") == nil
              && TribeSanityTarget(url: "1.2.3.4") == nil, "literals and junk are refused")

        // --- what a reply means ---
        func reply(_ text: String, complete: Bool = true) -> TribeSanityResult? { TribeSanityTarget.classify(Data(text.utf8), complete: complete) }
        check(reply("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n") == .ok, "204 is the real Internet")
        check(reply("HTTP/1.1 204 No Content\r\n", complete: false) == .ok, "and is known from the status line alone")
        check(reply("HTTP/1.0 200 OK\r\n\r\n<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>") == .ok, "the Success page too")
        check(reply("HTTP/1.1 200 OK\r\n\r\n<html><title>Sign in to Wi-Fi</title>") == .captive, "another 200 page is a login page")
        // Review finding A4: the headers and the body of captive.apple.com arrive in two reads; the
        // first read alone used to be called a login page.
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 68\r\n\r\n"
        check(reply(headers, complete: false) == nil, "a 200 whose body has not arrived says nothing yet: read on")
        check(reply(headers + "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>", complete: false) == .ok, "with the body it is the real page")
        check(reply(headers, complete: true) == .captive, "a 200 that ends without the page is a foreign reply")
        check(reply("HTT", complete: false) == nil && reply("HTTP/1.1 20", complete: false) == nil, "half a status line: read on")
        check(reply("HTTP/1.1 302 Found\r\nLocation: http://portal.example/\r\n\r\n") == .captive, "a redirect is a portal")
        check(reply("HTTP/1.1 511 Network Authentication Required\r\n\r\n", complete: false) == .captive, "511 is a portal")
        check(reply("SSH-2.0-OpenSSH") == .noReply && reply("") == .noReply && reply("HTTP/1.1") == .noReply
              && reply("SSH-2.0-OpenSSH", complete: false) == .noReply, "not HTTP is no reply")
        check(TribeSanityTarget.classifyTLS(ready: true, tlsFailure: false) == .ok && TribeSanityTarget.classifyTLS(ready: false, tlsFailure: true) == .captive
              && TribeSanityTarget.classifyTLS(ready: false, tlsFailure: false) == .noReply, "TLS: handshake done / somebody else answered / nobody answered")
        check(TribeSanityTarget.combine([.noReply, .ok]) == .ok && TribeSanityTarget.combine([.captive, .noReply]) == .captive
              && TribeSanityTarget.combine([.noReply, .noReply]) == .noReply && TribeSanityTarget.combine([]) == .unknown, "one known answer is enough; a foreign reply outweighs silence")

        // --- the journal line: fixed labels and numbers only ---
        var snapshot = TribeDataWatchSnapshot()
        snapshot.enabled = true; snapshot.verdict = .noData; snapshot.passive = true; snapshot.cycles = 3; snapshot.episodeSeconds = 78
        snapshot.episodeTx = 25224; snapshot.sanity = .ok; snapshot.probe = .silent; snapshot.probeReason = .passive
        snapshot.wouldSwitch = true; snapshot.evidence = .probe; snapshot.disturbed = 2
        let line = TribeDataWatchJournal.line(report: .verdict, verdict: .noData, snapshot: snapshot, nodeId: "12", proto: "awg", net: "cellular")
        check(line == "Tribe watch: event=verdict verdict=no_data passive=no_data probe=silent trigger=passive probe_ms=0 node=12 proto=awg net=cellular cycles=3 ep=78s tx=25224 rx_data=0 sanity=ok evidence=probe would_switch=1 app_alive=0 refuted=0 disturbed=2", "the line: \(line)")
        snapshot.probe = .answered; snapshot.probeLatencyMs = 143; snapshot.refuted = 1; snapshot.passive = false; snapshot.wouldSwitch = false
        let refuted = TribeDataWatchJournal.line(report: .refuted, verdict: .suspect, snapshot: snapshot, nodeId: "12", proto: "awg", net: "wifi")
        check(refuted.contains("event=refuted verdict=suspect passive=none probe=answered trigger=passive probe_ms=143") && refuted.hasSuffix("refuted=1 disturbed=2"), "a refuted passive rule and the void probes are countable from the line: \(refuted)")
        let fields = TribeDataWatchJournal.fields(report: .refuted, verdict: .suspect, snapshot: snapshot, nodeId: "12", proto: "awg", net: "wifi", generation: "g")
        check(Set(fields.keys) == ["event", "verdict", "passive", "probe", "trigger", "probe_ms", "node_id", "proto", "net", "cycles", "ep_s", "tx",
                                   "rx_data", "sanity", "evidence", "would_switch", "app_alive", "refuted", "disturbed", "generation"], "journal fields: \(fields.keys.sorted())")
        check(JSONSerialization.isValidJSONObject(fields) && fields["event"] as? String == "refuted" && fields["probe"] as? String == "answered", "journal fields are JSON")

        // --- the probe's result string from the Go layer ---
        let answered = TribeDataWatchJournal.parseProbeResult("state=answered id=7 ms=180 late=0")
        check(answered.state == .answered && answered.id == 7 && answered.latencyMs == 180 && !answered.late, "answered")
        check(TribeDataWatchJournal.parseProbeResult("state=answered id=7 ms=6000 late=1").late, "answered late")
        check(TribeDataWatchJournal.parseProbeResult("state=not_sent id=9 ms=0 late=0").state == .notSent, "not_sent")
        check(TribeDataWatchJournal.parseProbeResult("state=silent id=9 ms=0 late=0").state == .silent, "silent")
        check(TribeDataWatchJournal.parseProbeResult("state=no_session id=9 ms=0 late=0").state == .staged, "an injected packet found without a session was only staged")
        check(TribeDataWatchJournal.parseProbeResult("state=pending id=9 ms=0 late=0").state == .pending, "pending")
        check(TribeDataWatchJournal.parseProbeResult("state=none id=0 ms=0 late=0").state == TribeProbeResult.none, "none")
        check(TribeDataWatchJournal.parseProbeResult("state=unavailable id=0 ms=0 late=0").state == .unavailable, "unavailable")
        check(TribeDataWatchJournal.parseProbeResult("garbage").state == .unavailable && TribeDataWatchJournal.parseProbeResult("state=bogus id=x").id == 0
              && TribeDataWatchJournal.parseProbeResult("").state == .unavailable, "junk is unavailable")
        // --- what the start of a probe returned ---
        check(TribeDataWatchJournal.startOutcome(7) == .started(7) && TribeDataWatchJournal.startOutcome(0) == .unavailable
              && TribeDataWatchJournal.startOutcome(-1) == .unavailable && TribeDataWatchJournal.startOutcome(-2) == .noSession
              && TribeDataWatchJournal.startOutcome(-9) == .unavailable, "id / no probe / no route / no session")

        stageTwo()
        if failures == 0 { print("TribeWatchPlan: all tests passed") } else { print("TribeWatchPlan: \(failures) check(s) FAILED"); exit(1) }
    }
}

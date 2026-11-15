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
            "schema": 1, "written_ms": now - 1000, "config_fetched_ms": now - hour, "expires_ms": now + 24 * hour,
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

    static func parse(_ data: Data?, alive: Bool = false, revision: Int64 = 0) -> Result<TribeWatchPlan, TribeWatchPlan.Rejection> {
        TribeWatchPlan.parse(data, nowMs: now, appAlive: alive, lastPoolRevision: revision)
    }
    static func rejection(_ data: Data?, alive: Bool = false, revision: Int64 = 0) -> TribeWatchPlan.Rejection? {
        if case .failure(let r) = parse(data, alive: alive, revision: revision) { return r }
        return nil
    }
    static func accepted(_ data: Data?, alive: Bool = false, revision: Int64 = 0) -> TribeWatchPlan? {
        if case .success(let p) = parse(data, alive: alive, revision: revision) { return p }
        return nil
    }

    static func main() {
        // --- the plan is accepted as written ---
        let good = accepted(plan())
        check(good != nil, "a well-formed plan is accepted")
        check(good?.policy.enabled == true && good?.policy.cycleSeconds == 25 && good?.policy.cycleMinTxBytes == 2048, "policy from the plan: \(String(describing: good?.policy))")
        check(good?.poolRevision == 100 && good?.candidates.isEmpty == true && good?.sanityURLs.isEmpty == true, "revision, no candidates, built-in targets")
        check(good?.policy.switchEnabled == false, "stage 1: nothing to switch to")

        // --- no plan, a broken plan: the watch is off (build 139 behaviour) ---
        check(rejection(nil) == .missing && rejection(Data()) == .missing, "no file")
        check(rejection(Data(repeating: 0x20, count: TribeWatchPlan.maxBytes + 1)) == .tooLarge, "over 64 KB")
        check(rejection(Data("not json".utf8)) == .notJSON && rejection(Data("[1,2]".utf8)) == .notJSON, "not a JSON object")
        check(rejection(plan { $0["schema"] = 2 }) == .schema, "unknown schema")
        check(rejection(plan { $0.removeValue(forKey: "schema") }) == .schema, "no schema")
        check(rejection(plan { $0["schema"] = true }) == .schema, "a boolean is not a schema number")

        // --- time ---
        check(accepted(plan { $0["written_ms"] = now + 5 * 60_000 }) != nil, "5 minutes in the future is tolerated")
        check(rejection(plan { $0["written_ms"] = now + 5 * 60_000 + 1 }) == .future, "more is rejected")
        check(rejection(plan { $0.removeValue(forKey: "written_ms") }) == .future, "no write time")

        // --- pool revision never goes back within one process ---
        check(accepted(plan(), revision: 100) != nil, "the same revision is fine")
        check(rejection(plan(), revision: 101) == .oldRevision, "an older revision is rejected")

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
            $0["candidates"] = [["node_id": 16, "proto": "awg", "inplace": true]]
        }
        check(accepted(plan(withCandidates))?.policy.switchEnabled == true, "switch flag with candidates is carried")
        check(accepted(plan { withCandidates(&$0); $0["expires_ms"] = now })?.policy.switchEnabled == false, "an expired list switches it off")
        check(accepted(plan { withCandidates(&$0); $0["expires_ms"] = now })?.policy.enabled == true, "but the watch itself goes on")
        check(accepted(plan { withCandidates(&$0); $0["candidates"] = [Any]() })?.policy.switchEnabled == false, "no candidates: nothing to switch to")

        // --- targets of the bypass check ---
        let urls = accepted(plan { $0["sanity_urls"] = ["http://a.example/x", "https://b.example/", "http://1.2.3.4/", "http://u:p@c.example/",
                                                         "ftp://d.example/", "http://e.example/ok?x=1", 7, "http://f.example/", "http://g.example/", "http://h.example/"] })?.sanityURLs
        check(urls == ["http://a.example/x", "http://e.example/ok?x=1", "http://f.example/", "http://g.example/"], "plain http, host names, no credentials, at most four: \(String(describing: urls))")
        check(TribeSanityTarget.builtIn.count == 2 && TribeSanityTarget.builtIn.allSatisfy { TribeSanityTarget(url: $0) != nil }, "the built-in targets are valid")
        let target = TribeSanityTarget(url: "http://connectivitycheck.gstatic.com/generate_204")!
        check(target.host == "connectivitycheck.gstatic.com" && target.port == 80 && target.path == "/generate_204", "target fields")
        check(String(data: target.request, encoding: .utf8)!.hasPrefix("GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n"), "request line and host")
        check(TribeSanityTarget(url: "http://[2001:db8::1]/") == nil && TribeSanityTarget(url: "http://exa mple/") == nil && TribeSanityTarget(url: "") == nil, "literals and junk are refused")

        // --- what a reply means ---
        func reply(_ text: String) -> TribeSanityResult { TribeSanityTarget.classify(Data(text.utf8)) }
        check(reply("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n") == .ok, "204 is the real Internet")
        check(reply("HTTP/1.0 200 OK\r\n\r\n<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>") == .ok, "the Success page too")
        check(reply("HTTP/1.1 200 OK\r\n\r\n<html><title>Sign in to Wi-Fi</title>") == .captive, "another 200 page is a login page")
        check(reply("HTTP/1.1 302 Found\r\nLocation: http://portal.example/\r\n\r\n") == .captive, "a redirect is a portal")
        check(reply("HTTP/1.1 511 Network Authentication Required\r\n\r\n") == .captive, "511 is a portal")
        check(reply("SSH-2.0-OpenSSH") == .noReply && reply("") == .noReply && reply("HTTP/1.1") == .noReply, "not HTTP is no reply")
        check(TribeSanityTarget.combine([.noReply, .ok]) == .ok && TribeSanityTarget.combine([.captive, .noReply]) == .captive
              && TribeSanityTarget.combine([.noReply, .noReply]) == .noReply && TribeSanityTarget.combine([]) == .unknown, "one known answer is enough; a foreign reply outweighs silence")

        // --- the journal line: fixed labels and numbers only ---
        var snapshot = TribeDataWatchSnapshot()
        snapshot.enabled = true; snapshot.verdict = .noData; snapshot.passive = true; snapshot.cycles = 3; snapshot.episodeSeconds = 78
        snapshot.episodeTx = 25224; snapshot.healSteps = 2; snapshot.sanity = .ok; snapshot.probe = .silent; snapshot.probeReason = .passive
        snapshot.wouldSwitch = true
        let line = TribeDataWatchJournal.line(report: .verdict, verdict: .noData, snapshot: snapshot, nodeId: "12", proto: "awg", net: "cellular")
        check(line == "Tribe watch: event=verdict verdict=no_data passive=no_data probe=silent trigger=passive probe_ms=0 node=12 proto=awg net=cellular cycles=3 ep=78s tx=25224 rx_data=0 heal=2 sanity=ok would_switch=1 app_alive=0 refuted=0", "ne.log line: \(line)")
        snapshot.probe = .answered; snapshot.probeLatencyMs = 143; snapshot.refuted = 1; snapshot.passive = false; snapshot.wouldSwitch = false
        let refuted = TribeDataWatchJournal.line(report: .refuted, verdict: .suspect, snapshot: snapshot, nodeId: "12", proto: "awg", net: "wifi")
        check(refuted.contains("event=refuted verdict=suspect passive=none probe=answered trigger=passive probe_ms=143") && refuted.hasSuffix("refuted=1"), "a refuted passive rule is countable from the line: \(refuted)")
        let fields = TribeDataWatchJournal.fields(report: .refuted, verdict: .suspect, snapshot: snapshot, nodeId: "12", proto: "awg", net: "wifi", generation: "g")
        check(Set(fields.keys) == ["event", "verdict", "passive", "probe", "trigger", "probe_ms", "node_id", "proto", "net", "cycles", "ep_s", "tx",
                                   "rx_data", "heal_steps", "sanity", "would_switch", "app_alive", "refuted", "generation"], "journal fields: \(fields.keys.sorted())")
        check(JSONSerialization.isValidJSONObject(fields) && fields["event"] as? String == "refuted" && fields["probe"] as? String == "answered", "journal fields are JSON")

        // --- the probe's result string from the Go layer ---
        let answered = TribeDataWatchJournal.parseProbeResult("state=answered id=7 ms=180")
        check(answered.state == .answered && answered.id == 7 && answered.latencyMs == 180, "answered")
        check(TribeDataWatchJournal.parseProbeResult("state=not_sent id=9 ms=0").state == .notSent, "not_sent")
        check(TribeDataWatchJournal.parseProbeResult("state=silent id=9 ms=0").state == .silent, "silent")
        check(TribeDataWatchJournal.parseProbeResult("state=pending id=9 ms=0").state == .pending, "pending")
        check(TribeDataWatchJournal.parseProbeResult("state=none id=0 ms=0").state == TribeProbeResult.none, "none")
        check(TribeDataWatchJournal.parseProbeResult("state=unavailable id=0 ms=0").state == .unavailable, "unavailable")
        check(TribeDataWatchJournal.parseProbeResult("garbage").state == .unavailable && TribeDataWatchJournal.parseProbeResult("state=bogus id=x").id == 0, "junk is unavailable")

        if failures == 0 { print("TribeWatchPlan: all tests passed") } else { print("TribeWatchPlan: \(failures) check(s) FAILED"); exit(1) }
    }
}

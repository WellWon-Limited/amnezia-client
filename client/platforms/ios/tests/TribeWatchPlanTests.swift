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
            $0["candidates"] = [["node_id": 16, "proto": "awg", "inplace": true]]
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

        if failures == 0 { print("TribeWatchPlan: all tests passed") } else { print("TribeWatchPlan: \(failures) check(s) FAILED"); exit(1) }
    }
}

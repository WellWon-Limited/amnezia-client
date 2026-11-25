import Foundation

// AVPN upstream nodes (lane L3): host Swift test (macOS, no device) of the extension's lease logic -
// UpstreamLeaseMachine.swift, UpstreamLeaseWire.swift, UpstreamLeaseRenewer.swift, XrayTunables.swift,
// XrayConfig.swift. Run by tests/run_ios_swift_checks.sh; argument 1 = the directory of the shared
// vectors (client/core/serviceEngine/tests/vectors, recorded from the C++ code).
//
// Replayed: every scenario of upstream_lease_vectors.json except app_only (the schema allows the Swift
// twin to skip them: provisional starts happen only in the app process; the extension only ever
// receives an already granted lease), and every `renew` case of upstream_wire_vectors.json (acquire
// answers are verified by the app; the extension never parses one).

private var failures = 0
private var checks = 0

private func expect(_ condition: @autoclosure () -> Bool, _ message: @autoclosure () -> String) {
    checks += 1
    if !condition() {
        failures += 1
        fputs("FAIL: \(message())\n", stderr)
    }
}

private func canonical(_ value: Any) -> String {
    guard JSONSerialization.isValidJSONObject(value),
          let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else {
        return "\(value)"
    }
    return String(decoding: data, as: UTF8.self)
}

private func i64(_ v: Any?) -> Int64 { (v as? NSNumber)?.int64Value ?? 0 }
private func int(_ v: Any?, _ def: Int = 0) -> Int { (v as? NSNumber)?.intValue ?? def }
private func str(_ v: Any?) -> String { v as? String ?? "" }
private func bool(_ v: Any?) -> Bool { (v as? NSNumber)?.boolValue ?? false }

// MARK: - vector replay (the C++ serialization, key for key)

private func meterJSON(_ m: UpstreamMeter) -> [String: Any] {
    ["seq": m.seq, "rx": m.rxDelta, "tx": m.txDelta, "scope": m.scope.rawValue, "epoch": m.epoch]
}

private func actionJSON(_ a: UpstreamLeaseAction) -> [String: Any] {
    var o: [String: Any] = ["kind": a.kind.rawValue]
    switch a.kind {
    case .sendAcquire:
        o["request_id"] = a.requestId
        o["profile_id"] = a.profileId
        o["lease_kind"] = a.leaseKind.rawValue
        o["standby"] = a.standby
        o["config_sha256"] = a.configSha256
        o["renew_token"] = a.route.renewToken
        o["api_base"] = a.route.apiBase
    case .sendRenew, .sendRelease:
        o["request_id"] = a.requestId
        o["lease_id"] = a.leaseId
        o["meter"] = meterJSON(a.meter)
        o["renew_token"] = a.route.renewToken
        o["api_base"] = a.route.apiBase
    case .leaseReady:
        o["provisional"] = a.provisional
        o["lease_id"] = a.leaseId
        o["renew_token"] = a.route.renewToken
        o["api_base"] = a.route.apiBase
    case .leaseConfirmed:
        o["lease_id"] = a.leaseId
        o["renew_token"] = a.route.renewToken
        o["api_base"] = a.route.apiBase
    case .leaveNode, .tryNextCandidate:
        o["reason"] = a.reason
    case .revisionChanged:
        o["upstream_revision"] = a.upstreamRevision
    default:
        break
    }
    return o
}

private func stateJSON(_ m: UpstreamLeaseMachine) -> [String: Any] {
    ["phase": m.phase.rawValue, "lease_id": m.leaseId, "last_seq": m.lastAcceptedSeq,
     "epoch": m.accountingEpoch, "known_revision": m.knownRevision, "deadline_ms": m.deadlineMs,
     "report_in_doubt": m.reportInDoubt, "unreported_rx": m.unreportedRx, "unreported_tx": m.unreportedTx,
     "meter_scope": m.meterScope.rawValue, "renew_token": m.route.renewToken, "api_base": m.route.apiBase]
}

private func expectJSON(_ step: UpstreamLeaseStep?, _ m: UpstreamLeaseMachine) -> [String: Any] {
    ["actions": (step?.actions ?? []).map(actionJSON),
     "wake_at_ms": step.map { $0.wakeAtMs as Any } ?? NSNull(),
     "state": stateJSON(m)]
}

private func errorFrom(_ e: [String: Any]) -> UpstreamErrorReply {
    UpstreamErrorReply(code: UpstreamErrorCode(code: str(e["code"])), retryAfterS: int(e["retry_after_s"], -1),
                       upstreamRevision: i64(e["upstream_revision"]))
}

private func acquireFrom(_ o: [String: Any]) -> UpstreamAcquireReply {
    var r = UpstreamAcquireReply()
    switch str(o["kind"]) {
    case "granted":
        let g = o["grant"] as? [String: Any] ?? [:]
        r.kind = .granted
        r.grant = UpstreamLeaseGrant(
            leaseId: str(g["lease_id"]), profileId: str(g["profile_id"]),
            kind: str(g["kind"]) == "probe" ? .probe : .session, expiresAtMs: i64(g["expires_at_ms"]),
            ttlS: int(g["ttl_s"]), renewAfterS: int(g["renew_after_s"]), seq: i64(g["seq"]),
            upstreamRevision: i64(g["upstream_revision"]), accountingEpoch: i64(g["traffic_accounting_epoch"]),
            renewToken: str(g["renew_token"]), tunnelApiBase: str(g["tunnel_api_base"]),
            configSha256: str(g["config_sha256"]), configChanged: bool(g["config_changed"]))
    case "refused":
        r.kind = .refused
        r.error = errorFrom(o["error"] as? [String: Any] ?? [:])
    default:
        r.kind = .failed
        r.why = str(o["why"])
    }
    return r
}

private func renewFrom(_ o: [String: Any]) -> UpstreamRenewReply {
    var r = UpstreamRenewReply()
    switch str(o["kind"]) {
    case "granted":
        let w = o["renewal"] as? [String: Any] ?? [:]
        r.kind = .granted
        r.renewal = UpstreamRenewal(
            rebaseline: str(w["status"]) == "rebaseline", leaseId: str(w["lease_id"]),
            expiresAtMs: i64(w["expires_at_ms"]), renewAfterS: int(w["renew_after_s"]), seq: i64(w["seq"]),
            upstreamRevision: i64(w["upstream_revision"]), accountingEpoch: i64(w["traffic_accounting_epoch"]),
            configChanged: bool(w["config_changed"]), appliedBytes: i64(w["applied_bytes"]),
            shadowBytes: i64(w["shadow_bytes"]))
    case "refused":
        r.kind = .refused
        r.error = errorFrom(o["error"] as? [String: Any] ?? [:])
    default:
        r.kind = .failed
        r.why = str(o["why"])
    }
    return r
}

private func apply(_ m: inout UpstreamLeaseMachine, _ step: [String: Any]) -> [String: Any]? {
    let a = step["args"] as? [String: Any] ?? [:]
    let now = i64(step["now_ms"])
    var s: UpstreamLeaseStep
    switch str(step["event"]) {
    case "start":
        s = m.start(profileId: str(a["profile_id"]), kind: str(a["kind"]) == "probe" ? .probe : .session,
                    scope: str(a["meter_scope"]) == "proxy" ? .proxy : .tunnel,
                    knownRevision: i64(a["known_revision"]), nowMs: now)
    case "acquire_reply":
        s = m.onAcquireReply(requestId: UInt64(i64(a["request_id"])),
                             reply: acquireFrom(a["reply"] as? [String: Any] ?? [:]), nowMs: now)
    case "renew_reply":
        s = m.onRenewReply(requestId: UInt64(i64(a["request_id"])),
                           reply: renewFrom(a["reply"] as? [String: Any] ?? [:]), nowMs: now)
    case "tick":
        s = m.tick(nowMs: now)
    case "disconnect":
        s = m.disconnect(nowMs: now)
    case "tunnel_bytes":
        m.onTunnelBytes(rxTotal: i64(a["rx"]), txTotal: i64(a["tx"]))
        return expectJSON(nil, m)
    case "baseline_bytes":
        m.baselineBytes(rxTotal: i64(a["rx"]), txTotal: i64(a["tx"]))
        return expectJSON(nil, m)
    default:
        return nil
    }
    return expectJSON(s, m)
}

// TODO(upstream epoch, contract addition 14.11): the vectors in this branch were recorded before the
// meter carried `epoch`; until the engine lane re-records them, a send action whose expected meter has
// no `epoch` is compared without it. Re-run this test against the final vectors at integration.
private func stripEpochWhereExpectedLacksIt(actual: inout [String: Any], expected: [String: Any]) -> Int {
    guard var acts = actual["actions"] as? [[String: Any]],
          let exp = expected["actions"] as? [[String: Any]] else { return 0 }
    var stripped = 0
    for i in acts.indices where i < exp.count {
        guard var meter = acts[i]["meter"] as? [String: Any] else { continue }
        let expMeter = exp[i]["meter"] as? [String: Any] ?? [:]
        if expMeter["epoch"] == nil, meter["epoch"] != nil {
            meter.removeValue(forKey: "epoch")
            acts[i]["meter"] = meter
            stripped += 1
        }
    }
    actual["actions"] = acts
    return stripped
}

private func timing(from doc: [String: Any]) -> UpstreamLeaseTiming {
    let t = doc["timing"] as? [String: Any] ?? [:]
    return UpstreamLeaseTiming(maxTtlS: int(t["max_ttl_s"], 3600), minRenewS: int(t["min_renew_s"], 30),
                               defaultRenewS: int(t["default_renew_s"], 300), retryBaseS: int(t["retry_base_s"], 15),
                               retryMaxS: int(t["retry_max_s"], 120), maxRetryAfterS: int(t["max_retry_after_s"], 900))
}

private func replayLeaseVectors(_ dir: String) {
    let url = URL(fileURLWithPath: dir).appendingPathComponent("upstream_lease_vectors.json")
    guard let data = try? Data(contentsOf: url),
          let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let scenarios = doc["scenarios"] as? [[String: Any]] else {
        expect(false, "cannot read \(url.path)")
        return
    }
    expect(int(doc["schema"]) == 1, "lease vectors schema 1")
    let t = timing(from: doc)
    var replayed = 0, skipped = [String](), steps = 0, epochStripped = 0
    for scenario in scenarios {
        let name = str(scenario["name"])
        if bool(scenario["app_only"]) {
            skipped.append(name)
            continue
        }
        var m = UpstreamLeaseMachine(timing: t, expiryPolicy: .reacquire)
        for (index, step) in (scenario["steps"] as? [[String: Any]] ?? []).enumerated() {
            let expected = step["expect"] as? [String: Any] ?? [:]
            guard var actual = apply(&m, step) else {
                expect(false, "\(name) step \(index): unknown event \(str(step["event"]))")
                break
            }
            epochStripped += stripEpochWhereExpectedLacksIt(actual: &actual, expected: expected)
            let a = canonical(actual), e = canonical(expected)
            expect(a == e, "\(name) step \(index) (\(str(step["event"]))):\n  expected \(e)\n  actual   \(a)")
            steps += 1
        }
        replayed += 1
    }
    print("lease vectors: \(replayed) scenarios / \(steps) steps replayed; skipped (app_only, provisional): \(skipped.count) [\(skipped.joined(separator: ", "))]; meters compared without epoch (TODO re-record): \(epochStripped)")
}

private func replayWireVectors(_ dir: String) {
    let url = URL(fileURLWithPath: dir).appendingPathComponent("upstream_wire_vectors.json")
    guard let data = try? Data(contentsOf: url),
          let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let cases = doc["cases"] as? [[String: Any]] else {
        expect(false, "cannot read \(url.path)")
        return
    }
    var replayed = 0, skippedAcquire = 0
    for c in cases {
        let name = str(c["name"])
        guard str(c["op"]) == "renew" else {
            skippedAcquire += 1
            continue
        }
        let r = UpstreamLeaseWire.classifyRenewReply(httpStatus: int(c["http_status"]), body: Data(str(c["body"]).utf8))
        let e = c["expect"] as? [String: Any] ?? [:]
        let kind: String = r.kind == .granted ? "granted" : (r.kind == .refused ? "refused" : "failed")
        expect(kind == str(e["kind"]), "wire \(name): kind \(kind) != \(str(e["kind"]))")
        switch kind {
        case "failed":
            expect(r.why == str(e["why"]), "wire \(name): why \(r.why) != \(str(e["why"]))")
        case "refused":
            let actual: [String: Any] = ["code": r.error.code.rawValue, "retry_after_s": r.error.retryAfterS,
                                         "upstream_revision": r.error.upstreamRevision]
            expect(canonical(actual) == canonical(e["error"] ?? [:]), "wire \(name): error \(canonical(actual))")
        default:
            let w = r.renewal
            let actual: [String: Any] = [
                "status": w.rebaseline ? "rebaseline" : "ok", "lease_id": w.leaseId, "expires_at_ms": w.expiresAtMs,
                "renew_after_s": w.renewAfterS, "seq": w.seq, "upstream_revision": w.upstreamRevision,
                "traffic_accounting_epoch": w.accountingEpoch, "config_changed": w.configChanged,
                "applied_bytes": w.appliedBytes, "shadow_bytes": w.shadowBytes]
            expect(canonical(actual) == canonical(e["renewal"] ?? [:]), "wire \(name): renewal \(canonical(actual))")
        }
        replayed += 1
    }
    print("wire vectors: \(replayed) renew cases replayed; skipped \(skippedAcquire) acquire cases (the extension never parses an acquire answer)")
}

// MARK: - extension mode (adopt + renewUntilGone)

private let kLease = "leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private let kT: Int64 = 1_000_000
private let kS0: Int64 = 1_763_117_000_000

private func lease(seq: Int64 = 5, epoch: Int64 = 7, renewAfter: Int = 300, ttl: Int = 900,
                   expiresIn: Int64 = 900_000, scope: UpstreamMeterScope = .tunnel) -> UpstreamLeaseEnvelope {
    UpstreamLeaseEnvelope(leaseId: kLease, renewToken: "tlr1.TOKEN", apiBase: "https://t.example.net",
                          renewAfterS: renewAfter, ttlS: ttl, expiresInMs: expiresIn, seq: seq, epoch: epoch,
                          revision: 100, meterScope: scope)
}

private func renewOk(seq: Int64, expiresServer: Int64, rebaseline: Bool = false, epoch: Int64 = 7,
                     configChanged: Bool = false, revision: Int64 = 100, applied: Int64 = 0,
                     shadow: Int64 = 0) -> UpstreamRenewReply {
    var r = UpstreamRenewReply()
    r.kind = .granted
    r.renewal = UpstreamRenewal(rebaseline: rebaseline, leaseId: kLease, expiresAtMs: expiresServer, renewAfterS: 300,
                                seq: seq, upstreamRevision: revision, accountingEpoch: epoch,
                                configChanged: configChanged, appliedBytes: applied, shadowBytes: shadow)
    return r
}

private func refused(_ code: String, retryAfter: Int = -1) -> UpstreamRenewReply {
    var r = UpstreamRenewReply()
    r.kind = .refused
    r.error = UpstreamErrorReply(code: UpstreamErrorCode(code: code), retryAfterS: retryAfter, upstreamRevision: 0)
    return r
}

private func transportFailure() -> UpstreamRenewReply {
    var r = UpstreamRenewReply()
    r.why = "transport"
    return r
}

private func testAdoptAndRenew() {
    var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
    var s = m.adopt(lease: lease(), profileId: "3f9c2a7b1d4e8f60", nowMs: kT)
    expect(s.actions.isEmpty, "adopt sends nothing")
    expect(m.phase == .active && m.lastAcceptedSeq == 5 && m.accountingEpoch == 7, "adopt state")
    expect(m.deadlineMs == kT + 900_000, "deadline = now + expires_in")
    expect(s.wakeAtMs == kT + 300_000, "first renewal after renew_after_s, got \(s.wakeAtMs)")
    m.onTunnelBytes(rxTotal: 1000, txTotal: 200)
    s = m.tick(nowMs: kT + 299_999)
    expect(s.actions.isEmpty, "not due yet")
    s = m.tick(nowMs: kT + 300_000)
    guard let renew = s.find(.sendRenew) else { expect(false, "renew due"); return }
    expect(renew.meter == UpstreamMeter(seq: 6, rxDelta: 1000, txDelta: 200, scope: .tunnel, epoch: 7), "report 6 with deltas and epoch")
    expect(renew.route == UpstreamLeaseRoute(renewToken: "tlr1.TOKEN", apiBase: "https://t.example.net"), "route from envelope")
    expect(s.wakeAtMs == -1, "nothing scheduled while in flight")
    // The first answer anchors the server clock: deadline = sent + ttl.
    s = m.onRenewReply(requestId: renew.requestId, reply: renewOk(seq: 6, expiresServer: kS0 + 900_000, applied: 900, shadow: 300), nowMs: kT + 300_100)
    expect(m.deadlineMs == kT + 300_000 + 900_000, "re-anchored deadline, got \(m.deadlineMs)")
    expect(m.lastAcceptedSeq == 6 && m.lastRenewOkMs == kT + 300_100, "seq 6 accepted")
    expect(m.appliedBytesTotal == 900 && m.shadowBytesTotal == 300, "applied/shadow totals")
    expect(s.wakeAtMs == kT + 300_100 + 300_000, "next renewal scheduled")
    // Later renewals move the deadline by the difference of two server times (a skewed device clock
    // does not matter).
    m.onTunnelBytes(rxTotal: 1500, txTotal: 260)
    s = m.tick(nowMs: kT + 600_100)
    guard let renew2 = s.find(.sendRenew) else { expect(false, "second renew"); return }
    expect(renew2.meter.seq == 7 && renew2.meter.rxDelta == 500 && renew2.meter.txDelta == 60, "second deltas")
    _ = m.onRenewReply(requestId: renew2.requestId, reply: renewOk(seq: 7, expiresServer: kS0 + 1_200_000), nowMs: kT + 600_200)
    expect(m.deadlineMs == kT + 1_500_000, "deadline moved by the server delta (+300 s), got \(m.deadlineMs)")
}

private func testRenewUntilGonePastDeadline() {
    var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
    _ = m.adopt(lease: lease(), profileId: "p", nowMs: kT)
    m.onTunnelBytes(rxTotal: 10, txTotal: 5)
    var s = m.tick(nowMs: kT + 300_000)
    var req = s.find(.sendRenew)!
    var now = kT + 300_000
    var sentSeqs = [Int64]()
    // The API is unreachable: the same report is retried (15, 30, 60, 120 s ...) and NEVER an acquire.
    while now < kT + 1_500_000 {
        sentSeqs.append(req.meter.seq)
        s = m.onRenewReply(requestId: req.requestId, reply: transportFailure(), nowMs: now + 10)
        expect(s.find(.sendAcquire) == nil && s.find(.leaveNode) == nil, "transport never leaves or acquires")
        guard s.wakeAtMs >= 0 else { expect(false, "retry scheduled"); return }
        now = s.wakeAtMs
        m.onTunnelBytes(rxTotal: 10 + (now - kT), txTotal: 5)
        s = m.tick(nowMs: now)
        expect(s.find(.sendAcquire) == nil, "no acquire past the deadline (renewUntilGone)")
        guard let next = s.find(.sendRenew) else { expect(false, "retry sends at \(now)"); return }
        req = next
    }
    expect(Set(sentSeqs) == [6], "every retry carries the same seq, got \(Set(sentSeqs))")
    expect(req.meter.rxDelta == 10 && req.meter.txDelta == 5, "retries carry the same deltas")
    expect(m.phase == .active, "still active past the deadline")
    // One of the retries went out exactly at the deadline (once, at once).
    // Now the server answers: the lease is gone -> terminal.
    s = m.onRenewReply(requestId: req.requestId, reply: refused("lease_gone"), nowMs: now + 50)
    expect(s.find(.leaveNode)?.reason == "lease_gone", "lease_gone is terminal")
    expect(m.phase == .left && m.leaveReason == "lease_gone", "phase left")
    s = m.tick(nowMs: now + 1_000_000)
    expect(s.actions.isEmpty && s.wakeAtMs == -1, "nothing after terminal")
    s = m.disconnect(nowMs: now + 1_000_001)
    // Round 17 R2: no more renewals, but the final report is still owed: one release, the in-doubt report (same seq), once.
    let fin = s.find(.sendRelease)
    expect(fin != nil && fin?.meter.seq == 6 && (fin?.meter.rxDelta ?? 0) >= 10 && (fin?.meter.txDelta ?? 0) >= 5,
           "the final report is still released after a terminal answer")
    expect(m.disconnect(nowMs: now + 1_000_002).find(.sendRelease) == nil, "released once")
}

private func testImmediateResendAtDeadline() {
    var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
    _ = m.adopt(lease: lease(renewAfter: 450, expiresIn: 900_000), profileId: "p", nowMs: kT)
    var s = m.tick(nowMs: kT + 450_000)
    let first = s.find(.sendRenew)!
    // retry_after 900 s would land past the deadline (kT + 900 000): the report still goes out AT it.
    s = m.onRenewReply(requestId: first.requestId, reply: refused("rate_limited", retryAfter: 900), nowMs: kT + 450_100)
    expect(s.wakeAtMs == kT + 900_000, "wake at the deadline, got \(s.wakeAtMs)")
    s = m.tick(nowMs: kT + 900_000)
    let atDeadline = s.find(.sendRenew)
    expect(atDeadline?.meter.seq == first.meter.seq, "resent once at the deadline, same seq")
    s = m.onRenewReply(requestId: atDeadline!.requestId, reply: transportFailure(), nowMs: kT + 900_010)
    expect(s.wakeAtMs == kT + 900_010 + 30_000, "then the normal backoff (2nd failure = 30 s), got \(s.wakeAtMs)")
    // A late renewal answer past the deadline keeps the session and moves the deadline.
    s = m.tick(nowMs: kT + 930_010)
    let late = s.find(.sendRenew)!
    s = m.onRenewReply(requestId: late.requestId, reply: renewOk(seq: 6, expiresServer: kS0 + 1_830_000), nowMs: kT + 930_100)
    expect(m.phase == .active && m.lastAcceptedSeq == 6, "renewal past the deadline keeps the session")
    expect(m.deadlineMs > kT + 930_010, "deadline moved past now")
}

private func testTerminalCodes() {
    for code in ["not_entitled", "over_quota", "disabled", "lease_gone"] {
        var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
        _ = m.adopt(lease: lease(), profileId: "p", nowMs: kT)
        let r = m.tick(nowMs: kT + 300_000).find(.sendRenew)!
        let s = m.onRenewReply(requestId: r.requestId, reply: refused(code), nowMs: kT + 300_100)
        expect(s.find(.leaveNode)?.reason == code && m.phase == .left, "\(code) is terminal")
    }
    for code in ["rate_limited", "upstream_unavailable", "no_seat", "unknown"] {
        var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
        _ = m.adopt(lease: lease(), profileId: "p", nowMs: kT)
        let r = m.tick(nowMs: kT + 300_000).find(.sendRenew)!
        let s = m.onRenewReply(requestId: r.requestId, reply: refused(code, retryAfter: 42), nowMs: kT + 300_100)
        expect(s.find(.leaveNode) == nil && m.phase == .active, "\(code) is retried")
        expect(s.wakeAtMs == kT + 300_100 + 42_000, "\(code): retry_after honoured")
    }
}

private func testRebaselineEpochAndRelease() {
    var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
    _ = m.adopt(lease: lease(epoch: 7), profileId: "p", nowMs: kT)
    m.onTunnelBytes(rxTotal: 100, txTotal: 10)
    var r = m.tick(nowMs: kT + 300_000).find(.sendRenew)!
    expect(r.meter.epoch == 7, "report carries the envelope epoch")
    var s = m.onRenewReply(requestId: r.requestId, reply: renewOk(seq: 6, expiresServer: kS0 + 900_000, rebaseline: true, epoch: 8), nowMs: kT + 300_050)
    expect(s.find(.restartByteCounters) != nil, "rebaseline restarts the counters")
    expect(m.accountingEpoch == 8, "rebaseline epoch kept")
    m.baselineBytes(rxTotal: 150, txTotal: 15)
    m.onTunnelBytes(rxTotal: 400, txTotal: 40)
    r = m.tick(nowMs: kT + 600_050).find(.sendRenew)!
    expect(r.meter == UpstreamMeter(seq: 7, rxDelta: 250, txDelta: 25, scope: .tunnel, epoch: 8), "after rebaseline: new epoch, bytes from the baseline")
    // Disconnect with that report unanswered: one release under its seq with the newer bytes added.
    m.onTunnelBytes(rxTotal: 500, txTotal: 45)
    s = m.disconnect(nowMs: kT + 600_100)
    let rel = s.find(.sendRelease)
    expect(rel?.meter == UpstreamMeter(seq: 7, rxDelta: 350, txDelta: 30, scope: .tunnel, epoch: 8), "release merges the in-doubt report")
    expect(m.phase == .released, "released")
    var clean = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
    _ = clean.adopt(lease: lease(seq: 9), profileId: "p", nowMs: kT)
    clean.onTunnelBytes(rxTotal: 77, txTotal: 7)
    let rel2 = clean.disconnect(nowMs: kT + 1000).find(.sendRelease)
    expect(rel2?.meter == UpstreamMeter(seq: 10, rxDelta: 77, txDelta: 7, scope: .tunnel, epoch: 7), "clean release = seq + 1")
}

private func testPendingHandOver() {
    var m = UpstreamLeaseMachine(expiryPolicy: .renewUntilGone)
    m.beginPending(profileId: "p", nowMs: kT)
    expect(m.phase == .provisional, "pending")
    var s = m.tick(nowMs: kT + 10_000)
    expect(s.actions.isEmpty && s.wakeAtMs == -1, "pending sends nothing")
    m.onTunnelBytes(rxTotal: 4000, txTotal: 300)
    s = m.adopt(lease: lease(seq: 0), profileId: "p", nowMs: kT + 20_000)
    expect(m.phase == .active, "hand-over activates")
    m.onTunnelBytes(rxTotal: 5000, txTotal: 400)
    let r = m.tick(nowMs: kT + 320_000).find(.sendRenew)
    expect(r?.meter.seq == 1 && r?.meter.rxDelta == 5000 && r?.meter.txDelta == 400, "first report includes the bytes since tunnel start")
    s = m.adopt(lease: lease(seq: 50), profileId: "p", nowMs: kT + 330_000)
    expect(m.lastAcceptedSeq == 0, "a second hand-over while active is ignored")
}

// The extension path against the recorded C++ behaviour: scenarios that start with a granted acquire
// and never reach the lease deadline are replayed through adopt() (renewUntilGone) instead of
// start + acquire_reply; request ids are one lower (adopt sends no acquire).
private func replayThroughAdopt(_ dir: String) {
    let url = URL(fileURLWithPath: dir).appendingPathComponent("upstream_lease_vectors.json")
    guard let data = try? Data(contentsOf: url),
          let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let scenarios = doc["scenarios"] as? [[String: Any]] else { return }
    let t = timing(from: doc)
    let skewedServerClock: Set<String> = ["clock_skew_and_backwards"]
    var replayed = [String](), notEligible = 0
    scenarioLoop: for scenario in scenarios where !bool(scenario["app_only"]) {
        let steps = scenario["steps"] as? [[String: Any]] ?? []
        guard steps.count > 2, str(steps[0]["event"]) == "start",
              let args = steps[0]["args"] as? [String: Any], str(args["kind"]) == "session",
              str(steps[1]["event"]) == "acquire_reply",
              let reply = (steps[1]["args"] as? [String: Any])?["reply"] as? [String: Any],
              str(reply["kind"]) == "granted",
              let grant = reply["grant"] as? [String: Any], str(grant["profile_id"]) == str(args["profile_id"]),
              str(grant["kind"]) == "session" else { notEligible += 1; continue }
        // Only scenarios that stay before the deadline and never acquire again.
        for step in steps.dropFirst(2) {
            let e = step["expect"] as? [String: Any] ?? [:]
            let kinds = (e["actions"] as? [[String: Any]] ?? []).map { str($0["kind"]) }
            if kinds.contains("send_acquire") || str(step["event"]) == "acquire_reply" { notEligible += 1; continue scenarioLoop }
        }
        let startNow = i64(steps[0]["now_ms"]), replyNow = i64(steps[1]["now_ms"])
        let env = UpstreamLeaseEnvelope(
            leaseId: str(grant["lease_id"]), renewToken: str(grant["renew_token"]), apiBase: str(grant["tunnel_api_base"]),
            renewAfterS: int(grant["renew_after_s"]), ttlS: int(grant["ttl_s"]),
            expiresInMs: startNow + Int64(min(int(grant["ttl_s"]), t.maxTtlS)) * 1000 - replyNow,
            seq: i64(grant["seq"]), epoch: i64(grant["traffic_accounting_epoch"]),
            revision: max(i64(args["known_revision"]), i64(grant["upstream_revision"])),
            meterScope: str(args["meter_scope"]) == "proxy" ? .proxy : .tunnel)
        var m = UpstreamLeaseMachine(timing: t, expiryPolicy: .renewUntilGone)
        _ = m.adopt(lease: env, profileId: str(args["profile_id"]), nowMs: replyNow)
        for (index, step) in steps.enumerated().dropFirst(2) {
            var shifted = step
            if var a = step["args"] as? [String: Any], let id = a["request_id"] as? NSNumber {
                a["request_id"] = id.int64Value - 1
                shifted["args"] = a
            }
            guard var actual = apply(&m, shifted) else { continue }
            var expected = step["expect"] as? [String: Any] ?? [:]
            if var acts = expected["actions"] as? [[String: Any]] {
                for i in acts.indices { if let id = acts[i]["request_id"] as? NSNumber { acts[i]["request_id"] = id.int64Value - 1 } }
                expected["actions"] = acts
            }
            _ = stripEpochWhereExpectedLacksIt(actual: &actual, expected: expected)
            if skewedServerClock.contains(str(scenario["name"])),
               var aState = actual["state"] as? [String: Any], var eState = expected["state"] as? [String: Any] {
                // Known divergence: the envelope has no server expires_at, so adopt() anchors the server
                // clock at the first renewal (sent + ttl) instead of at the grant. With a skewed server
                // clock the local deadline differs by the skew - bounded here to 1 s.
                let diff = abs(i64(aState["deadline_ms"]) - i64(eState["deadline_ms"]))
                expect(diff <= 1000, "adopt \(str(scenario["name"])) step \(index): deadline off by \(diff) ms")
                aState.removeValue(forKey: "deadline_ms")
                eState.removeValue(forKey: "deadline_ms")
                actual["state"] = aState
                expected["state"] = eState
            }
            let a = canonical(actual), e = canonical(expected)
            expect(a == e, "adopt \(str(scenario["name"])) step \(index):\n  expected \(e)\n  actual   \(a)")
        }
        replayed.append(str(scenario["name"]))
    }
    print("adopt replay (extension path vs C++ recording): \(replayed.count) scenarios [\(replayed.joined(separator: ", "))]; \(notEligible) not eligible (first acquire not granted, or they reach the deadline / acquire again)")
}

// MARK: - wire + envelope

private func testWire() {
    expect(UpstreamLeaseWire.meterBody(UpstreamMeter(seq: 6, rxDelta: 10, txDelta: 2, scope: .tunnel, epoch: 7))
           == #"{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":10,"seq":6,"tx_bytes_delta":2}"#, "meter body")
    expect(UpstreamLeaseWire.meterBody(UpstreamMeter(seq: 1, rxDelta: -5, txDelta: Int64.max, scope: .proxy, epoch: 0))
           == #"{"epoch":0,"meter_scope":"proxy","rx_bytes_delta":0,"seq":1,"tx_bytes_delta":1099511627776}"#, "meter body clamps, epoch always sent (lab D2)")
    // Round 9 R1: the release carries the renew token of the grant it undoes (the server ends the lease only for the
    // current one); no token = the body as before; a quote or backslash in a token is escaped.
    expect(UpstreamLeaseWire.releaseBody(UpstreamMeter(seq: 6, rxDelta: 10, txDelta: 2, scope: .tunnel, epoch: 7), renewToken: "tlr1.abc")
           == #"{"epoch":7,"meter_scope":"tunnel","renew_token":"tlr1.abc","rx_bytes_delta":10,"seq":6,"tx_bytes_delta":2}"#, "release body with token")
    expect(UpstreamLeaseWire.releaseBody(UpstreamMeter(seq: 6, rxDelta: 10, txDelta: 2, scope: .tunnel, epoch: 7), renewToken: "")
           == UpstreamLeaseWire.meterBody(UpstreamMeter(seq: 6, rxDelta: 10, txDelta: 2, scope: .tunnel, epoch: 7)), "release body without token")
    expect(UpstreamLeaseWire.releaseBody(UpstreamMeter(seq: 1, rxDelta: 0, txDelta: 0, scope: .tunnel, epoch: 0), renewToken: "a\"b\\c")
           .contains(#""renew_token":"a\"b\\c","#), "release body escapes the token")
    // Lab 14.11 D2: 422 invalid_request is its own code; a 422 without one is "rejected" too.
    let bad = UpstreamLeaseWire.classifyRenewReply(httpStatus: 422, body: Data(#"{"code":"invalid_request"}"#.utf8))
    expect(bad.kind == .refused && bad.error.code == .invalidRequest && !bad.error.code.isTerminal, "422 invalid_request")
    expect(UpstreamLeaseWire.renewRejected(bad), "invalid_request rejected")
    expect(UpstreamLeaseWire.renewRejected(UpstreamLeaseWire.classifyRenewReply(httpStatus: 422, body: Data("{}".utf8))), "bare 422 rejected")
    expect(!UpstreamLeaseWire.renewRejected(UpstreamLeaseWire.classifyRenewReply(httpStatus: 0, body: Data())), "transport not rejected")
    expect(!UpstreamLeaseWire.renewRejected(UpstreamLeaseWire.classifyRenewReply(httpStatus: 400, body: Data("{}".utf8))), "400 not rejected")
    expect(UpstreamLeaseWire.parseTimeMs("2025-11-14T11:03:20.000Z") == 1_763_118_200_000, "iso time")
    expect(UpstreamLeaseWire.parseTimeMs("2025-11-14T14:03:20+03:00") == 1_763_118_200_000, "iso offset")
    expect(UpstreamLeaseWire.parseTimeMs("garbage") == nil, "bad time")
    let http = UpstreamLeaseWire.parseHTTPResult(#"{"status":404,"headers":{},"body_base64":"eyJjb2RlIjoibGVhc2VfZ29uZSJ9","error":"","error_code":""}"#)
    expect(http.status == 404 && String(decoding: http.body, as: UTF8.self) == #"{"code":"lease_gone"}"#, "http result")
    expect(UpstreamLeaseWire.classifyRenewReply(httpStatus: http.status, body: http.body).error.code == .leaseGone, "http -> refused")
    let timeout = UpstreamLeaseWire.parseHTTPResult(#"{"status":0,"headers":{},"body_base64":"","error":"x","error_code":"timeout"}"#)
    expect(timeout.status == 0 && timeout.errorCode == "timeout", "timeout")
    expect(UpstreamLeaseWire.parseHTTPResult("").status == 0, "empty answer = transport")
    expect(UpstreamLeaseWire.apiBaseNormalized("https://t.example.net/") == "https://t.example.net", "base trailing slash")
    expect(UpstreamLeaseWire.apiBaseNormalized("http://t.example.net").isEmpty, "base http refused")
    expect(UpstreamLeaseWire.apiBaseNormalized("https://u:p@t.example.net").isEmpty, "base userinfo refused")
    expect(UpstreamLeaseWire.apiBaseNormalized("https://t.example.net/?q=1").isEmpty, "base query refused")
}

private func envelopeDict() -> [String: Any] {
    ["lease_id": kLease, "renew_token": "tlr1.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde",
     "api_base": "https://t.example.net/", "renew_after_s": NSNumber(value: 300), "ttl_s": NSNumber(value: 900),
     "expires_in_ms": NSNumber(value: 900_000), "seq": NSNumber(value: 1), "epoch": NSNumber(value: 7),
     "revision": NSNumber(value: Int64(1_763_123_456_789)), "meter_scope": "tunnel"]
}

private func testEnvelope() {
    let (ok, why) = UpstreamLeaseWire.parseLeaseEnvelope(envelopeDict())
    expect(ok != nil && why.isEmpty, "valid envelope (\(why))")
    expect(ok?.apiBase == "https://t.example.net" && ok?.revision == 1_763_123_456_789 && ok?.meterScope == .tunnel, "envelope fields")
    func refusedField(_ key: String, _ value: Any?) -> String {
        var d = envelopeDict()
        d[key] = value
        return UpstreamLeaseWire.parseLeaseEnvelope(d).1
    }
    expect(refusedField("renew_token", nil) == "renew_token", "token required")
    expect(refusedField("renew_token", "tlr1.has space") == "renew_token", "token charset")
    expect(refusedField("api_base", "http://x") == "api_base", "https only")
    expect(refusedField("lease_id", "short") == "lease_id", "lease id")
    expect(refusedField("seq", NSNumber(value: true)) == "seq", "bool is not a number")
    expect(refusedField("seq", NSNumber(value: 1.5)) == "seq", "fraction refused")
    expect(refusedField("epoch", NSNumber(value: 0)) == "epoch", "epoch >= 1")
    expect(refusedField("meter_scope", "bytes") == "meter_scope", "scope enum")
    var noScope = envelopeDict()
    noScope.removeValue(forKey: "meter_scope")
    expect(UpstreamLeaseWire.parseLeaseEnvelope(noScope).0?.meterScope == .tunnel, "absent scope = tunnel")
    expect(UpstreamLeaseWire.parseLeaseEnvelope("x").1 == "not_object", "not an object")
    // tribeSessionMetadata: only `upstream: 1` makes an upstream session.
    expect(UpstreamLeaseWire.upstreamProfileId(fromMetadata: ["node_id": "9", "proto": "awg"]) == nil, "AWG metadata")
    expect(UpstreamLeaseWire.upstreamProfileId(fromMetadata: ["upstream": NSNumber(value: 0)]) == nil, "upstream 0")
    expect(UpstreamLeaseWire.upstreamProfileId(fromMetadata: nil) == nil, "no metadata (own Xray)")
    expect(UpstreamLeaseWire.upstreamProfileId(fromMetadata: ["upstream": NSNumber(value: 1), "profile_id": "3f9c2a7b1d4e8f60"]) == "3f9c2a7b1d4e8f60", "upstream 1")
    expect(UpstreamLeaseWire.upstreamProfileId(fromMetadata: ["upstream": NSNumber(value: true), "profile_id": "p"]) == "p", "upstream true")
}

// MARK: - tunables + geo + XrayConfig

private func decodeConfig(_ json: String) -> XrayConfig? {
    try? JSONDecoder().decode(XrayConfig.self, from: Data(json.utf8))
}

private func testTunables() {
    let legacy = decodeConfig(#"{"config":"{}","xray_connect_timeout_ms":5000}"#)
    expect(legacy != nil && legacy?.tunables == nil, "old blob: no tunables")
    expect(XrayTunables.goMemoryLimitBytes(legacy?.tunables) == Int64.max, "absent memory key = Int64.max (before)")
    expect(XrayTunables.hevMiscLines(legacy?.tunables) == ["task-stack-size: 20480"], "absent hev keys = the old YAML line")
    let empty = decodeConfig(#"{"config":"{}","xray_tunables":{}}"#)
    expect(XrayTunables.goMemoryLimitBytes(empty?.tunables) == Int64.max, "empty tunables = before")
    let full = decodeConfig(#"{"config":"{}","xray_tunables":{"memory_limit_mib":30,"hev_tcp_buffer_size":4096,"hev_max_session_count":1200,"hev_task_stack_size":24576}}"#)
    expect(XrayTunables.goMemoryLimitBytes(full?.tunables) == 30 * 1024 * 1024, "30 MiB")
    expect(XrayTunables.hevMiscLines(full?.tunables) == ["task-stack-size: 24576", "tcp-buffer-size: 4096", "max-session-count: 1200"], "hev lines")
    let clamped = decodeConfig(#"{"config":"{}","xray_tunables":{"memory_limit_mib":100,"hev_tcp_buffer_size":1,"hev_max_session_count":1e9,"hev_task_stack_size":8}}"#)
    expect(clamped?.tunables == XrayTunables(memoryLimitMiB: 40, hevTcpBufferSize: 4096, hevMaxSessionCount: 65535, hevTaskStackSize: 20480), "clamped")
    let low = decodeConfig(#"{"config":"{}","xray_tunables":{"memory_limit_mib":5}}"#)
    expect(low?.tunables?.memoryLimitMiB == 20, "memory floor 20")
    let invalid = decodeConfig(#"{"config":"{}","xray_tunables":{"memory_limit_mib":"lots","hev_tcp_buffer_size":null}}"#)
    expect(invalid?.tunables?.memoryLimitMiB == 30, "present but invalid = default 30")
    expect(invalid?.tunables?.hevTcpBufferSize == 4096, "present but null = default")
    expect(invalid?.tunables?.hevMaxSessionCount == nil, "absent stays absent")
}

// AVPN (round air-H 25.11): the core inbound's UDP idle level - the same rule and shape as the backend normalizer's
// (tests/test_upstream_inbound_udp_idle.py); before the change the type did not exist and no start bounded the
// inbound's UDP associations (the device round's killed provider sessions).
private func testInboundUdpIdle() {
    expect(XrayTunables.inboundUdpIdleSeconds(nil) == 5, "absent tunables = 5 s default")
    expect(XrayTunables.inboundUdpIdleSeconds(decodeConfig(#"{"config":"{}","xray_tunables":{}}"#)?.tunables) == 5,
           "absent key = 5 s default")
    expect(decodeConfig(#"{"config":"{}","xray_tunables":{"udp_idle_s":0}}"#)?.tunables?.udpIdleSeconds == 0, "0 = off")
    expect(decodeConfig(#"{"config":"{}","xray_tunables":{"udp_idle_s":-3}}"#)?.tunables?.udpIdleSeconds == 0, "negative = off")
    expect(decodeConfig(#"{"config":"{}","xray_tunables":{"udp_idle_s":1}}"#)?.tunables?.udpIdleSeconds == 2, "floor 2")
    expect(decodeConfig(#"{"config":"{}","xray_tunables":{"udp_idle_s":9999}}"#)?.tunables?.udpIdleSeconds == 300, "cap 300")
    expect(decodeConfig(#"{"config":"{}","xray_tunables":{"udp_idle_s":"x"}}"#)?.tunables?.udpIdleSeconds == 5,
           "present but invalid = default")

    func cfg(_ json: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
    }
    // Own config shape (XrayConfigBuilder + ensureInboundAuth): socks inbound, one VLESS outbound, policy level 0.
    var own = cfg(#"{"inbounds":[{"protocol":"socks","listen":"::1","port":1080,"settings":{"udp":true,"auth":"password"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"users":[{"id":"u"}]}]}}],"policy":{"levels":{"0":{"handshake":5,"connIdle":300,"uplinkOnly":2,"downlinkOnly":5}}}}"#)
    expect(XrayInboundUdpIdle.apply(to: &own, seconds: 5) == "applied:5s", "own config applied")
    let ib = (own["inbounds"] as? [[String: Any]])?.first?["settings"] as? [String: Any]
    expect((ib?["userLevel"] as? Int) == 9, "inbound userLevel 9")
    let levels = (own["policy"] as? [String: Any])?["levels"] as? [String: Any]
    expect(canonical(levels?["9"] ?? [:]) == canonical(["handshake": 5, "connIdle": 5, "uplinkOnly": 2, "downlinkOnly": 5]),
           "level 9 = level 0 with connIdle 5 \(canonical(levels?["9"] ?? [:]))")
    expect(canonical(levels?["0"] ?? [:]) == canonical(["handshake": 5, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5]),
           "level 0 untouched (outbounds keep their TCP idle)")
    let once = canonical(own)
    expect(XrayInboundUdpIdle.apply(to: &own, seconds: 5) == "kept:level_in_config" && canonical(own) == once,
           "idempotent: a config whose inbound names a level is left as it is")
    // A provider profile from a 1.21.2 server already carries the level: kept byte for byte.
    var served = cfg(#"{"inbounds":[{"tag":"tribe-in","protocol":"socks","settings":{"auth":"password","userLevel":9}}],"outbounds":[{"protocol":"vless"}],"policy":{"levels":{"9":{"connIdle":5}}}}"#)
    let servedBefore = canonical(served)
    expect(XrayInboundUdpIdle.apply(to: &served, seconds: 30) == "kept:level_in_config" && canonical(served) == servedBefore,
           "server's level wins")
    // A provider profile without policy (an older server): policy created with level 9 only.
    var bare = cfg(#"{"inbounds":[{"tag":"tribe-in","protocol":"socks","settings":{"auth":"password"}}],"outbounds":[{"protocol":"vless"},{"protocol":"freedom"}]}"#)
    expect(XrayInboundUdpIdle.apply(to: &bare, seconds: 5) == "applied:5s", "bare profile applied")
    expect(canonical((bare["policy"] as? [String: Any])?["levels"] ?? [:]) == canonical(["9": ["connIdle": 5]]), "only level 9")
    // A level an outbound already uses is never taken.
    var used = cfg(#"{"inbounds":[{"protocol":"socks","settings":{"auth":"password"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"users":[{"id":"u","level":9}]}]}}]}"#)
    let usedBefore = canonical(used)
    expect(XrayInboundUdpIdle.apply(to: &used, seconds: 5) == "skipped:level_in_use" && canonical(used) == usedBefore,
           "level in use: unchanged")
    var off = cfg(#"{"inbounds":[{"protocol":"socks","settings":{}}],"outbounds":[]}"#)
    let offBefore = canonical(off)
    expect(XrayInboundUdpIdle.apply(to: &off, seconds: 0) == "off" && canonical(off) == offBefore, "0 = off, unchanged")
    var odd = cfg(#"{"inbounds":[{"protocol":"socks","settings":{}}],"outbounds":[],"policy":[1]}"#)
    expect(XrayInboundUdpIdle.apply(to: &odd, seconds: 5) == "skipped:shape", "non-object policy left alone")
    var noSocks = cfg(#"{"inbounds":[{"protocol":"http"}],"outbounds":[]}"#)
    expect(XrayInboundUdpIdle.apply(to: &noSocks, seconds: 5) == "skipped:no_socks_inbound", "no socks inbound")
}

private func testGeo() {
    let config = #"{"routing":{"rules":[{"domain":["geosite:category-ru","ext:custom.dat:x"],"outboundTag":"direct"},{"ip":["geoip:ru","!geoip:private"],"outboundTag":"direct"}]},"dns":{"servers":[{"domains":["notgeosite:x"]}]}}"#
    expect(XrayGeoAssets.files(inConfig: config) == ["custom.dat", "geoip.dat", "geosite.dat"], "geo files \(XrayGeoAssets.files(inConfig: config))")
    expect(XrayGeoAssets.files(inConfig: #"{"outbounds":[{"protocol":"vless"}]}"#).isEmpty, "no geo")
    let dir = NSTemporaryDirectory() + "tribe-geo-\(UUID().uuidString)"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: dir) }
    expect(XrayGeoAssets.missing(inConfig: config, dir: dir) == ["custom.dat", "geoip.dat", "geosite.dat"], "all missing")
    FileManager.default.createFile(atPath: dir + "/geosite.dat", contents: Data([1]))
    FileManager.default.createFile(atPath: dir + "/geoip.dat", contents: Data([1]))
    expect(XrayGeoAssets.missing(inConfig: config, dir: dir) == ["custom.dat"], "only the ext file missing")
    expect(XrayGeoAssets.missing(inConfig: #"["ext:../geoip.dat:x"]"#, dir: dir) == ["../geoip.dat"], "a path is never a plain file")
}

// MARK: - renewer (fake transport, test clock)

private final class FakeTransport: UpstreamLeaseTransport {
    struct Request { let method: String; let url: String; let headers: [String: String]; let body: String; let timeoutMs: Int64 }
    private let lock = NSLock()
    private var queued: [UpstreamLeaseWire.HTTPResult] = []
    private(set) var requests: [Request] = []
    var delaySeconds: Double = 0

    func answer(_ status: Int, _ body: String) {
        lock.lock(); queued.append(UpstreamLeaseWire.HTTPResult(status: status, body: Data(body.utf8), errorCode: "")); lock.unlock()
    }

    func send(method: String, url: String, headers: [String: String], body: String, timeoutMs: Int64) -> UpstreamLeaseWire.HTTPResult {
        lock.lock()
        requests.append(Request(method: method, url: url, headers: headers, body: body, timeoutMs: timeoutMs))
        let r = queued.isEmpty ? UpstreamLeaseWire.HTTPResult(status: 0, body: Data(), errorCode: "timeout") : queued.removeFirst()
        let delay = delaySeconds
        lock.unlock()
        if delay > 0 { Thread.sleep(forTimeInterval: delay) }
        return r
    }

    var snapshot: [Request] { lock.lock(); defer { lock.unlock() }; return requests }
}

private final class TestClock {
    private let lock = NSLock()
    private var value: Int64 = 5_000_000
    var now: Int64 { lock.lock(); defer { lock.unlock() }; return value }
    func advance(_ ms: Int64) { lock.lock(); value += ms; lock.unlock() }
}

private final class Bytes {
    private let lock = NSLock()
    private var rx: Int64 = 0, tx: Int64 = 0
    func set(_ r: Int64, _ t: Int64) { lock.lock(); rx = r; tx = t; lock.unlock() }
    var totals: (rx: Int64, tx: Int64) { lock.lock(); defer { lock.unlock() }; return (rx, tx) }
}

private func renewBody(seq: Int64, status: String = "ok", epoch: Int64 = 7, expires: String = "2025-11-14T11:18:20.000Z") -> String {
    #"{"applied_bytes":0,"config_changed":false,"expires_at":"\#(expires)","lease_id":"\#(kLease)","renew_after_s":300,"seq":\#(seq),"shadow_bytes":1234,"status":"\#(status)","traffic_accounting_epoch":\#(epoch),"upstream_revision":100}"#
}

private func makeRenewer(_ transport: FakeTransport, _ clock: TestClock, _ bytes: Bytes,
                         terminal: @escaping (String) -> Void = { _ in }) -> UpstreamLeaseRenewer {
    UpstreamLeaseRenewer(profileId: "3f9c2a7b1d4e8f60", transport: transport, nowMs: { clock.now },
                         byteTotals: { _, _ in bytes.totals }, onTerminal: terminal)
}

private func testRenewerFlow() {
    let transport = FakeTransport(), clock = TestClock(), bytes = Bytes()
    let terminalCodes = NSMutableArray()
    let terminalDone = DispatchSemaphore(value: 0)
    let renewer = makeRenewer(transport, clock, bytes) { code in terminalCodes.add(code); terminalDone.signal() }
    renewer.startActive(lease: lease(seq: 5, epoch: 7))
    var st = renewer.status()
    expect(st.state == "active" && st.seq == 5 && st.renewedMsAgo == -1 && st.expiresInMs == 900_000 && st.meterScope == .tunnel, "status active \(st)")
    bytes.set(2048, 512)
    clock.advance(299_000)
    renewer.fireForTest()
    expect(transport.snapshot.isEmpty, "not due before renew_after_s")
    clock.advance(1_000)
    transport.answer(200, renewBody(seq: 6))
    renewer.fireForTest()
    renewer.drainForTest()
    let reqs = transport.snapshot
    expect(reqs.count == 1, "one renewal")
    if let r = reqs.first {
        expect(r.method == "POST" && r.url == "https://t.example.net/v1/upstream/lease/\(kLease)/renew", "renew url \(r.url)")
        expect(r.headers["Authorization"] == "Bearer tlr1.TOKEN", "lease-scoped token")
        expect(r.body == #"{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":2048,"seq":6,"tx_bytes_delta":512}"#, "renew body \(r.body)")
        expect(r.timeoutMs == UpstreamLeaseRenewer.renewTimeoutMs, "bounded timeout")
    }
    st = renewer.status()
    expect(st.seq == 6 && st.renewedMsAgo == 0 && st.shadowBytes == 1234, "status after renewal \(st)")
    let dict = st.dictionary
    expect(Set(dict.keys) == ["state", "code", "seq", "renewed_ms_ago", "expires_in_ms", "revision", "config_changed",
                              "applied_bytes", "shadow_bytes", "meter_scope"], "status keys = contract section 5")
    // A transport failure: retried later with the same seq.
    bytes.set(4096, 1024)
    clock.advance(300_000)
    renewer.fireForTest()
    renewer.drainForTest()
    clock.advance(15_000)
    transport.answer(404, #"{"code":"lease_gone"}"#)
    renewer.fireForTest()
    renewer.drainForTest()
    let all = transport.snapshot
    expect(all.count == 3, "renewal + retry, got \(all.count)")
    if all.count == 3 {
        expect(all[1].body == all[2].body, "retry resends the same report")
        expect(all[2].body.contains(#""seq":7"#), "seq 7")
    }
    expect(terminalDone.wait(timeout: .now() + 2) == .success, "terminal handler ran")
    expect(terminalCodes == ["lease_gone"], "terminal code")
    st = renewer.status()
    expect(st.state == "terminal" && st.code == "lease_gone" && st.expiresInMs == 0, "status terminal \(st)")
    expect(renewer.isTerminal, "core restart blocked")
    clock.advance(1_000_000)
    renewer.fireForTest()
    let released = DispatchSemaphore(value: 0)
    renewer.release { released.signal() }
    expect(released.wait(timeout: .now() + 1) == .success, "release completion after terminal")
    expect(transport.snapshot.count == 4 && transport.snapshot.last?.method == "DELETE"
           && transport.snapshot.last?.body.contains(#""renew_token":"tlr1.TOKEN""#) == true,
           "after a terminal answer: no renew, exactly one release with the token")
}

// Review E5 of 18.11: the final report is read before the core stops, the DELETE goes later through the direct
// transport given - never through the renewer's own (tunnel) transport.
private func testRenewerReleaseAfterStopDirect() {
    let tunnel = FakeTransport(), direct = FakeTransport(), clock = TestClock(), bytes = Bytes()
    let renewer = makeRenewer(tunnel, clock, bytes)
    renewer.startActive(lease: lease(seq: 1, epoch: 3))
    bytes.set(900, 90)
    guard let prepared = renewer.prepareRelease() else {
        expect(false, "a live lease has a release to send")
        return
    }
    let sentBefore = tunnel.snapshot.count
    bytes.set(5000, 500) // the core is gone: later counters do not change the final report
    direct.answer(204, "")
    let done = DispatchSemaphore(value: 0)
    renewer.sendRelease(prepared, via: direct) { done.signal() }
    expect(done.wait(timeout: .now() + 3) == .success, "direct release completes")
    expect(tunnel.snapshot.count == sentBefore, "nothing through the tunnel transport")
    let r = direct.snapshot.last
    expect(r?.method == "DELETE" && r?.body == #"{"epoch":3,"meter_scope":"tunnel","renew_token":"tlr1.TOKEN","rx_bytes_delta":900,"seq":2,"tx_bytes_delta":90}"#,
           "direct release carries the report read before the stop and the grant's own token \(r?.body ?? "")")
    expect(renewer.prepareRelease() == nil, "one release only")
}

private func testRenewerRelease() {
    let transport = FakeTransport(), clock = TestClock(), bytes = Bytes()
    let renewer = makeRenewer(transport, clock, bytes)
    renewer.startActive(lease: lease(seq: 1, epoch: 3))
    bytes.set(900, 90)
    transport.answer(204, "")
    let done = DispatchSemaphore(value: 0)
    renewer.release { done.signal() }
    expect(done.wait(timeout: .now() + 3) == .success, "release completes")
    let r = transport.snapshot.last
    expect(r?.method == "DELETE" && r?.url == "https://t.example.net/v1/upstream/lease/\(kLease)", "release url")
    expect(r?.body == #"{"epoch":3,"meter_scope":"tunnel","renew_token":"tlr1.TOKEN","rx_bytes_delta":900,"seq":2,"tx_bytes_delta":90}"#, "final report \(r?.body ?? "")")
    expect(r?.timeoutMs == 1500, "release bounded to 1.5 s")
    // A hanging network: the completion still runs at the bound.
    let slow = FakeTransport(); slow.delaySeconds = 5
    let renewer2 = makeRenewer(slow, clock, bytes)
    renewer2.startActive(lease: lease())
    let start = Date()
    let done2 = DispatchSemaphore(value: 0)
    renewer2.release { done2.signal() }
    expect(done2.wait(timeout: .now() + 3) == .success, "bounded release")
    let elapsed = Date().timeIntervalSince(start)
    expect(elapsed < 2.0 && elapsed >= 1.4, "release gave up at ~1.6 s, took \(elapsed)")
    // Pending session, stopped before the hand-over: nothing to release.
    let none = FakeTransport()
    let renewer3 = makeRenewer(none, clock, bytes)
    renewer3.startPending()
    let done3 = DispatchSemaphore(value: 0)
    renewer3.release { done3.signal() }
    expect(done3.wait(timeout: .now() + 1) == .success && none.snapshot.isEmpty, "no release without a lease")
}

private func testRenewerPendingAndScope() {
    let transport = FakeTransport(), clock = TestClock(), bytes = Bytes()
    let renewer = makeRenewer(transport, clock, bytes)
    renewer.startPending()
    var st = renewer.status()
    expect(st.state == "pending" && st.renewedMsAgo == -1, "pending status")
    bytes.set(10_000, 1_000)
    clock.advance(20_000)
    st = renewer.handOver(lease: lease(seq: 0, scope: .proxy))
    expect(st.state == "active", "handed over")
    expect(st.meterScope == .tunnel, "proxy without meter_tags / stats -> tunnel")
    st = renewer.handOver(lease: lease(seq: 40))
    expect(st.seq == 0, "a second hand-over is ignored")
    clock.advance(300_000)
    transport.answer(200, renewBody(seq: 1))
    renewer.fireForTest()
    renewer.drainForTest()
    let body = transport.snapshot.first?.body ?? ""
    expect(body == #"{"epoch":7,"meter_scope":"tunnel","rx_bytes_delta":10000,"seq":1,"tx_bytes_delta":1000}"#, "first report has the bytes since start: \(body)")
    renewer.stop()
}

// MARK: - proxy metering (UpstreamProxyMeter.swift)

private func testScopeDecision() {
    // requested x tags x stats -> scope; proxy only when all three hold.
    for requested in [UpstreamMeterScope.proxy, .tunnel] {
        for tags in [[String](), ["proxy"]] {
            for stats in [false, true] {
                let got = UpstreamMeterPlan.scope(requested: requested, meterTags: tags, statsAvailable: stats)
                let want: UpstreamMeterScope = (requested == .proxy && !tags.isEmpty && stats) ? .proxy : .tunnel
                expect(got == want, "scope(\(requested), tags \(tags.count), stats \(stats)) = \(got)")
            }
        }
    }
    var l = lease(scope: .proxy)
    l.meterTags = ["proxy"]
    expect(UpstreamMeterPlan.wantsStats(.active(profileId: "p", lease: l)), "active proxy lease merges stats")
    l.meterTags = []
    expect(!UpstreamMeterPlan.wantsStats(.active(profileId: "p", lease: l)), "proxy without tags: no stats keys")
    expect(!UpstreamMeterPlan.wantsStats(.active(profileId: "p", lease: lease(scope: .tunnel))), "tunnel lease: no stats keys")
    expect(UpstreamMeterPlan.wantsStats(.pending(profileId: "p")), "provisional start: stats keys (lease may ask proxy)")
    expect(!UpstreamMeterPlan.wantsStats(.none), "own Xray / AWG untouched")
}

private func testStatsMerge() {
    var empty: [String: Any] = ["outbounds": [["tag": "proxy", "protocol": "vless"]]]
    expect(XrayStatsConfig.merge(into: &empty), "merge into a config without policy")
    expect(canonical(empty["stats"] ?? "") == "{}", "stats added")
    expect(canonical(empty["policy"] ?? "") == #"{"system":{"statsOutboundDownlink":true,"statsOutboundUplink":true}}"#, "policy added")
    var provider: [String: Any] = [
        "stats": ["keep": 1],
        "policy": ["levels": ["0": ["handshake": 4, "connIdle": 300]],
                   "system": ["statsInboundUplink": false, "statsOutboundUplink": false]]]
    expect(XrayStatsConfig.merge(into: &provider), "merge into a provider policy")
    let once = canonical(provider)
    expect(once == #"{"policy":{"levels":{"0":{"connIdle":300,"handshake":4}},"system":{"statsInboundUplink":false,"statsOutboundDownlink":true,"statsOutboundUplink":true}},"stats":{"keep":1}}"#,
           "existing policy/levels/system keys and stats kept: \(once)")
    XrayStatsConfig.merge(into: &provider)
    expect(canonical(provider) == once, "idempotent")
    var bad: [String: Any] = ["policy": "nope"]
    expect(!XrayStatsConfig.merge(into: &bad) && (bad["policy"] as? String) == "nope" && bad["stats"] == nil, "non-object policy left untouched")
    var badSystem: [String: Any] = ["policy": ["system": 5]]
    expect(!XrayStatsConfig.merge(into: &badSystem), "non-object policy.system refused")
}

private func statsJSON(_ outbounds: [String: (Int64, Int64)], running: Bool = true, code: String = "") -> String {
    let o = outbounds.map { "\"\($0.key)\":{\"uplink\":\($0.value.0),\"downlink\":\($0.value.1)}" }.joined(separator: ",")
    return #"{"running":\#(running),"outbounds":{\#(o)},"error":"","error_code":"\#(code)"}"#
}

private func testStatsRead() {
    let r = XrayOutboundStatsRead.parse(statsJSON(["proxy": (150034, 250002), "direct": (7, 9)]))
    expect(r.usable && r.outbounds["proxy"] == XrayOutboundTraffic(uplink: 150034, downlink: 250002), "parse")
    expect(!XrayOutboundStatsRead.parse(statsJSON([:], running: false)).usable, "running false")
    let disabled = XrayOutboundStatsRead.parse(statsJSON([:], code: "stats_disabled"))
    expect(!disabled.usable && disabled.errorCode == "stats_disabled", "stats_disabled")
    expect(XrayOutboundStatsRead.parse("garbage").errorCode == "bad_answer", "bad answer")
}

private func testProxyAccumulator() {
    let tags = ["proxy", "proxy-b"]
    var a = UpstreamProxyMeterAccumulator()
    a.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (100, 1000), "hop": (100, 1000), "direct": (5, 50)])))
    expect(a.totals(tags: tags) == (rx: 1000, tx: 100), "only meter_tags (no hop, no direct)")
    a.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (300, 3000), "proxy-b": (10, 20)])))
    expect(a.totals(tags: tags) == (rx: 3020, tx: 310), "cumulative within one core")
    // Network change: the read before the stop moves this core's counters into the base.
    a.coreWillStop(XrayOutboundStatsRead.parse(statsJSON(["proxy": (400, 4000), "proxy-b": (10, 20)])))
    expect(a.totals(tags: tags) == (rx: 4020, tx: 410), "final read before the stop")
    a.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (0, 0)]))) // new core from zero
    expect(a.totals(tags: tags) == (rx: 4020, tx: 410), "restart from zero keeps the total")
    a.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (50, 500)])))
    expect(a.totals(tags: tags) == (rx: 4520, tx: 460), "new core adds on top")
    // A failed read (stopped core, no answer) loses nothing and adds nothing.
    a.record(XrayOutboundStatsRead.parse(statsJSON([:], running: false)))
    a.record(XrayOutboundStatsRead.parse("garbage"))
    expect(a.totals(tags: tags) == (rx: 4520, tx: 460) && a.failedReads == 2, "failed reads change nothing")
    a.coreWillStop(XrayOutboundStatsRead.parse(statsJSON([:], running: false)))
    expect(a.totals(tags: tags) == (rx: 4520, tx: 460), "stop with a failed read keeps the last good one")
    // A restart that was not read before its stop: the drop is detected, the last read kept.
    a.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (70, 700)])))
    a.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (5, 60)])))
    expect(a.totals(tags: tags) == (rx: 4520 + 700 + 60, tx: 460 + 70 + 5), "unread restart: monotonic, nothing lost")
    var prev: (rx: Int64, tx: Int64) = (0, 0)
    var b = UpstreamProxyMeterAccumulator()
    for (i, v) in [(10, 100), (20, 200), (0, 0), (3, 30), (1, 10), (8, 80)].enumerated() {
        if i == 2 || i == 4 {
            b.coreWillStop(XrayOutboundStatsRead.parse(statsJSON([:], running: false)))
        }
        b.record(XrayOutboundStatsRead.parse(statsJSON(["proxy": (Int64(v.0), Int64(v.1))])))
        let t = b.totals(tags: ["proxy"])
        expect(t.rx >= prev.rx && t.tx >= prev.tx, "monotonic at step \(i)")
        prev = t
    }
    expect(b.totals(tags: ["nope"]) == (rx: 0, tx: 0), "a tag outside meter_tags never counts")
}

private func testMeterTagsEnvelope() {
    var d = envelopeDict()
    d["meter_scope"] = "proxy"
    d["meter_tags"] = ["proxy", "proxy-b", "proxy"]
    let (e, why) = UpstreamLeaseWire.parseLeaseEnvelope(d)
    expect(e?.meterTags == ["proxy", "proxy-b"] && e?.meterScope == .proxy, "meter_tags parsed, deduplicated (\(why))")
    d["meter_tags"] = [NSNumber(value: 1)]
    expect(UpstreamLeaseWire.parseLeaseEnvelope(d).1 == "meter_tags", "non-string tag refused")
    d["meter_tags"] = [""]
    expect(UpstreamLeaseWire.parseLeaseEnvelope(d).1 == "meter_tags", "empty tag refused")
    d["meter_tags"] = "proxy"
    expect(UpstreamLeaseWire.parseLeaseEnvelope(d).1 == "meter_tags", "not a list refused")
    d.removeValue(forKey: "meter_tags")
    expect(UpstreamLeaseWire.parseLeaseEnvelope(d).0?.meterTags == [], "absent = no tags")
}

private func testRenewerProxyScope() {
    final class ScopeLog { var calls: [(UpstreamMeterScope, [String])] = [] }
    let transport = FakeTransport(), clock = TestClock(), log = ScopeLog()
    let lock = NSLock()
    func make(stats: Bool) -> UpstreamLeaseRenewer {
        UpstreamLeaseRenewer(profileId: "p", transport: transport, nowMs: { clock.now },
                             byteTotals: { scope, tags in
                                 lock.lock(); log.calls.append((scope, tags)); lock.unlock()
                                 return scope == .proxy ? (rx: 777, tx: 33) : (rx: 1, tx: 1)
                             },
                             statsAvailable: { stats }, onTerminal: { _ in })
    }
    var l = lease(seq: 0, scope: .proxy)
    l.meterTags = ["proxy"]
    let r = make(stats: true)
    r.startActive(lease: l)
    expect(r.status().meterScope == .proxy, "proxy with tags and stats")
    clock.advance(300_000)
    transport.answer(200, renewBody(seq: 1))
    r.fireForTest()
    r.drainForTest()
    expect(transport.snapshot.last?.body == #"{"epoch":7,"meter_scope":"proxy","rx_bytes_delta":777,"seq":1,"tx_bytes_delta":33}"#,
           "proxy report from the tag sum: \(transport.snapshot.last?.body ?? "")")
    lock.lock()
    expect(log.calls.allSatisfy { $0.0 == .proxy && $0.1 == ["proxy"] }, "meter read with scope proxy over meter_tags")
    lock.unlock()
    r.stop()
    let r2 = make(stats: false) // stats_disabled after start
    r2.startActive(lease: l)
    expect(r2.status().meterScope == .tunnel, "stats_disabled -> tunnel")
    r2.stop()
}

// The status after the renewer object is gone: a terminal answer keeps its code for the rest of the tunnel
// session (before: `state: terminal` with an empty code once the renewer was torn down).
// R2 (round 17): a terminal renewal answer (the lease was replaced by the next start) ends renewing, not the final report: the ordinary
// stop still prepares ONE release with the tenure's token and the bytes since the last accepted renewal; a second stop sends nothing.
private func testReleaseAfterTerminalRenewal() {
    let transport = FakeTransport(), clock = TestClock(), bytes = Bytes()
    let terminalDone = DispatchSemaphore(value: 0)
    let renewer = makeRenewer(transport, clock, bytes) { _ in terminalDone.signal() }
    renewer.startActive(lease: lease(seq: 1, epoch: 3))
    bytes.set(700, 70)
    clock.advance(300_000)
    transport.answer(404, #"{"code":"lease_gone"}"#)
    renewer.fireForTest()
    renewer.drainForTest()
    expect(terminalDone.wait(timeout: .now() + 2) == .success && renewer.isTerminal, "terminal handler ran")
    bytes.set(900, 90) // traffic after the answer, before the core stops
    guard let prepared = renewer.prepareRelease() else {
        expect(false, "a terminal renewal answer must not cancel the final release")
        return
    }
    expect(prepared.body.contains(#""renew_token":"tlr1.TOKEN""#) && prepared.body.contains(#""rx_bytes_delta":900"#)
           && prepared.body.contains(#""tx_bytes_delta":90"#),
           "release carries the token and the bytes since the last accepted renewal \(prepared.body)")
    expect(renewer.prepareRelease() == nil, "second stop sends nothing")
    // An ended-without-release renewer (stop()) sends nothing.
    let r2 = makeRenewer(FakeTransport(), clock, bytes)
    r2.startActive(lease: lease(seq: 1, epoch: 3))
    r2.stop()
    expect(r2.prepareRelease() == nil, "stop() ends without a release")
}

private func testTerminalMemoAfterRenewerGone() {
    var memo = UpstreamTerminalMemo()
    expect(memo.status == nil, "no terminal answer -> no status object")
    // The terminal answer arrives through the real renewer, then the renewer is torn down (stop/release).
    let transport = FakeTransport(), clock = TestClock(), bytes = Bytes()
    let terminalDone = DispatchSemaphore(value: 0)
    var renewer: UpstreamLeaseRenewer? = makeRenewer(transport, clock, bytes) { code in
        memo.record(code)
        terminalDone.signal()
    }
    renewer?.startActive(lease: lease(seq: 1, epoch: 2))
    clock.advance(300_000)
    transport.answer(403, #"{"code":"not_entitled"}"#)
    renewer?.fireForTest()
    renewer?.drainForTest()
    expect(terminalDone.wait(timeout: .now() + 2) == .success, "terminal handler ran")
    renewer?.stop()
    renewer = nil
    let st = memo.status
    expect(st?.state == "terminal" && st?.code == "not_entitled", "terminal code persists after the renewer: \(String(describing: st))")
    expect(str(st?.dictionary["code"]) == "not_entitled" && str(st?.dictionary["state"]) == "terminal", "status dictionary carries the code")
    expect(st?.expiresInMs == 0 && st?.seq == 0, "no lease data after the renewer is gone")
    // A later terminal code in the same session does not overwrite the first one.
    memo.record("lease_gone")
    expect(memo.status?.code == "not_entitled", "first terminal answer wins")
    // A fresh tunnel start clears it.
    memo.reset()
    expect(memo.status == nil, "fresh tunnel start: no terminal status")
    memo.record("")
    expect(memo.status?.state == "terminal" && memo.status?.code == "", "an empty code is still terminal")
}

@main
struct UpstreamLeaseTestsMain {
    static func main() {
        let dir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
        replayLeaseVectors(dir)
        replayWireVectors(dir)
        replayThroughAdopt(dir)
        testAdoptAndRenew()
        testRenewUntilGonePastDeadline()
        testImmediateResendAtDeadline()
        testTerminalCodes()
        testRebaselineEpochAndRelease()
        testPendingHandOver()
        testWire()
        testEnvelope()
        testTunables()
        testInboundUdpIdle()
        testGeo()
        testRenewerFlow()
        testRenewerRelease()
        testRenewerReleaseAfterStopDirect()
        testRenewerPendingAndScope()
        testScopeDecision()
        testStatsMerge()
        testStatsRead()
        testProxyAccumulator()
        testMeterTagsEnvelope()
        testRenewerProxyScope()
        testReleaseAfterTerminalRenewal()
        testTerminalMemoAfterRenewerGone()
        if failures > 0 {
            fputs("Upstream lease tests: \(failures) of \(checks) checks FAILED\n", stderr)
            exit(1)
        }
        print("Upstream lease tests passed (\(checks) checks)")
    }
}

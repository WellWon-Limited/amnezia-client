import Darwin
import Foundation

// AVPN (Scanner, lane L4): host Swift test (macOS, no device) of the extension's probe host relay -
// TribeScanHost.swift (+ XraySocketCallbackLifecycle.swift for the lifecycle gate). Run by
// tests/run_ios_swift_checks.sh; argument 1 = the directory of the shared vectors
// (client/core/serviceEngine/tests/vectors, scan_host_vectors.json from the C++ contract).
//
// The engine is a pair of stub C-ABI functions (@convention(c), the types of LibXrayTribeScanMessage /
// LibXrayTribeScanStopAll) that record what they receive and hand out malloc'd replies; the test counts that
// every reply is released exactly once.
//
// Covered: the relay round trip (request bytes unchanged; host option `gen` with every message, the
// interface index and the live AWG peer only with scan_start), the live-peer parse, cancel then polls until
// "final", the awg_mini pool by headroom, the refusal of awg_mini without the live AmneziaWG peer, unknown scan
// actions, the refusal without a physical path, stop-all ordering under the lifecycle gate, the generation
// element, `gen` of progress / caps / access attempts, caps lowered by memory headroom, the JSON splice, and the
// byte-for-byte replay of every request and reply of scan_host_vectors.json through the relay. Not covered
// here: the byte_gate vectors (the engine's gate, replayed by Go's TestTribeScanSharedVectors; this layer has
// no byte gate) and the provider glue (PacketTunnelProvider+Scan.swift: typechecked by --ne-typecheck, wiring
// checked by check_ios_scan_wiring.sh).

private var failures = 0
private var checks = 0

private func expect(_ condition: @autoclosure () -> Bool, _ message: @autoclosure () -> String) {
    checks += 1
    if !condition() {
        failures += 1
        fputs("FAIL: \(message())\n", stderr)
    }
}

private func text(_ b: [UInt8]) -> String { String(decoding: b, as: UTF8.self) }
private func text(_ d: Data) -> String { String(decoding: d, as: UTF8.self) }
private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

private func jsonObject(_ b: [UInt8]) -> NSDictionary? {
    (try? JSONSerialization.jsonObject(with: Data(b))) as? NSDictionary
}

private func now() -> Double { Date().timeIntervalSince1970 }

// MARK: - stub engine (C ABI)

private struct EngineCall {
    let kind: String          // "message" | "stop_all"
    let request: [UInt8]
    let options: String?
    let waitMs: Int64
    let at: Double
}

private enum Stub {
    static let lock = NSLock()
    static var calls: [EngineCall] = []
    static var reply: [UInt8] = bytes(#"{"type":"scan_ack","scan_id":"s","accepted":0,"mem_mb":null}"#)
    static var stopReply: [UInt8] = bytes(#"{"stopped":true}"#)
    static var messageDelayMs: UInt32 = 0
    static var returnNull = false
    static var oldEngine = false // an engine without the scan_stop_all message (answers unknown_action)
    static var stopDelayMs: UInt32 = 0 // a slow (or hung) engine stop
    static var handedOut = Set<UInt>()
    static var releasedTwice = 0

    static func reset() {
        lock.lock()
        calls = []
        reply = bytes(#"{"type":"scan_ack","scan_id":"s","accepted":0,"mem_mb":null}"#)
        stopReply = bytes(#"{"stopped":true}"#)
        messageDelayMs = 0
        returnNull = false
        oldEngine = false
        stopDelayMs = 0
        lock.unlock()
    }

    static func record(_ call: EngineCall) {
        lock.lock()
        calls.append(call)
        lock.unlock()
    }

    static func handOut(_ b: [UInt8]) -> UnsafeMutablePointer<CChar>? {
        let p = UnsafeMutablePointer<CChar>.allocate(capacity: b.count + 1)
        b.withUnsafeBufferPointer { src in
            src.withMemoryRebound(to: CChar.self) { p.initialize(from: $0.baseAddress!, count: b.count) }
        }
        p[b.count] = 0
        lock.lock()
        handedOut.insert(UInt(bitPattern: p))
        lock.unlock()
        return p
    }

    static func release(_ p: UnsafeMutablePointer<CChar>) {
        lock.lock()
        if handedOut.remove(UInt(bitPattern: p)) == nil { releasedTwice += 1 }
        lock.unlock()
        p.deallocate()
    }

    static var outstanding: Int {
        lock.lock()
        defer { lock.unlock() }
        return handedOut.count
    }

    static func snapshot() -> [EngineCall] {
        lock.lock()
        defer { lock.unlock() }
        return calls
    }
}

private let stubMessage: TribeScanEngine.MessageFn = { request, options in
    let req = request.map { Array(UnsafeBufferPointer(start: UnsafeRawPointer($0).assumingMemoryBound(to: UInt8.self), count: strlen($0))) } ?? []
    let opts = options.map { String(cString: $0) }
    Stub.lock.lock()
    let delay = Stub.messageDelayMs
    let reply = Stub.reply
    let null = Stub.returnNull
    Stub.lock.unlock()
    // The host-only stop through the message channel: {"action":"scan_stop_all","wait_ms":n} + {"host_epoch":E}.
    if text(req).hasPrefix(#"{"action":"scan_stop_all""#) {
        Stub.lock.lock()
        let old = Stub.oldEngine
        let stopReply = Stub.stopReply
        let stopDelay = Stub.stopDelayMs
        Stub.lock.unlock()
        if old { return Stub.handOut(bytes(#"{"error":"unknown_action"}"#)) }
        if stopDelay > 0 { usleep(stopDelay * 1000) }
        let o = (try? JSONSerialization.jsonObject(with: Data(req))) as? [String: Any]
        Stub.record(EngineCall(kind: "stop_all", request: req, options: opts, waitMs: Int64((o?["wait_ms"] as? Int) ?? -1), at: now()))
        return Stub.handOut(stopReply)
    }
    let started = now()
    if delay > 0 { usleep(delay * 1000) }
    Stub.record(EngineCall(kind: "message", request: req, options: opts, waitMs: 0, at: started))
    return null ? nil : Stub.handOut(reply)
}

private let stubStopAll: TribeScanEngine.StopAllFn = { waitMs in
    Stub.lock.lock()
    let reply = Stub.stopReply
    Stub.lock.unlock()
    Stub.record(EngineCall(kind: "stop_all_plain", request: [], options: nil, waitMs: waitMs, at: now()))
    return Stub.handOut(reply)
}

private let stubEngine = TribeScanEngine(messageFn: stubMessage, stopAllFn: stubStopAll, release: { Stub.release($0) })

// MARK: - host fixture

private final class Fixture {
    var bindIndex: UInt32 = 7
    var satisfied = true
    var availableMB: Double?
    var live: TribeScanHost.LivePeer = .notAmneziaWG
    var livePeerAsked = 0
    var peerReadDelayUs: UInt32 = 0
    let peerReadStarted = DispatchSemaphore(value: 0)
    let generation = TribeScanPathGeneration(epoch: 0x5eed_0000_0000_00ab)
    let gate = XrayNativeLifecycleGate()
    var logs: [String] = []
    let logLock = NSLock()
    let lifecycle = TribeScanLifecycle()
    lazy var host = TribeScanHost(
        engine: stubEngine, gate: gate, lifecycle: lifecycle,
        path: { [unowned self] in
            TribeScanPathInfo(bindIndex: self.bindIndex, satisfied: self.satisfied, element: self.generation.element)
        },
        availableMB: { [unowned self] in self.availableMB },
        liveAwgPeer: { [unowned self] in
            self.livePeerAsked += 1
            self.peerReadStarted.signal()
            if self.peerReadDelayUs > 0 { usleep(self.peerReadDelayUs) }
            return self.live
        },
        log: { [unowned self] line in self.logLock.lock(); self.logs.append(line); self.logLock.unlock() })

    init() {
        Stub.reset()
        generation.observe(signature: "baseline")
    }

    func send(_ json: String) -> String { send(bytes(json)) }

    func send(_ b: [UInt8], receivedEpoch: UInt64? = nil) -> String {
        guard let m = TribeScanHost.scanMessage(of: Data(b)) else { return "<not a scan message>" }
        return text(host.handle(m.bytes, action: m.action, receivedEpoch: receivedEpoch))
    }

    /// The host options the relay must pass now.
    func options(start: Bool = false, peer: String? = nil, epoch: UInt64? = nil) -> String {
        TribeScanHost.hostOptions(element: generation.element, epoch: epoch ?? lifecycle.epoch, bindIndex: start ? bindIndex : nil,
                                  awgLivePeer: peer)
    }
}

private let startJSON = #"{"action":"scan_start","version":"tribe-scan-v1","scan_id":"s1","deadline_ms":9000,"max_bytes":1572864,"limits":{},"probe":{"base":"https://api.example","token":"tsc1.secret-token"},"candidates":[{"id":"2:xray","kind":"xray_full","config":"{\"secret\":\"config\"}","entry":null}]}"#

private func insertingAtClose(_ input: [UInt8], _ insert: String) -> [UInt8] {
    guard let close = input.lastIndex(of: UInt8(ascii: "}")) else { return input }
    var out = input
    out.insert(contentsOf: bytes(insert), at: close)
    return out
}

// MARK: - tests

private func testRelayRoundTrip() {
    let f = Fixture()
    let element = f.generation.element.json

    Stub.reply = bytes(#"{"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":1,"max_leg_concurrent":6,"max_awg_concurrent":0,"can_verify_composite":false,"dns_plan":true,"reach_stage":true,"needs_vpn":true,"kinds":["xray_full","xray_leg"],"mem_mb":11,"platform":"ios"}"#)
    let capsRequest = bytes(#"{"action":"scan_caps"}"#)
    let caps = f.send(capsRequest)
    var calls = Stub.snapshot()
    expect(calls.count == 1 && calls[0].request == capsRequest, "caps: the engine got the request bytes unchanged")
    let genOption = "{\"gen\":\(element),\"host_epoch\":1}"
    expect(calls.first?.options == genOption, "caps: host options carry gen and host_epoch, got \(calls.first?.options ?? "nil")")
    expect(caps == text(insertingAtClose(Stub.reply, ",\"gen\":\(element)")), "caps: engine bytes + gen only, got \(caps)")

    Stub.reply = bytes(#"{"type":"scan_ack","scan_id":"s1","accepted":1,"mem_mb":31}"#)
    let start = f.send(startJSON)
    calls = Stub.snapshot()
    expect(calls.count == 2 && calls[1].request == bytes(startJSON), "start: request bytes unchanged (token and config included)")
    expect(calls.last?.options == "{\"bind_interface_index\":7,\"gen\":\(element),\"host_epoch\":1}",
           "start: host options carry the physical interface index and gen, got \(calls.last?.options ?? "nil")")
    expect(f.livePeerAsked == 1, "start: the live AWG peer asked once")
    expect(start == #"{"type":"scan_ack","scan_id":"s1","accepted":1,"mem_mb":31}"#, "start: the ack comes back unchanged")

    Stub.reply = bytes(#"{"type":"scan_progress","scan_id":"s1","seq":0,"phase":"reach","items":[],"bytes_spent":0,"mem_mb":31,"done":false,"reason":"","access":null}"#)
    let poll = f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#)
    expect(poll == text(insertingAtClose(Stub.reply, ",\"gen\":\(element)")), "poll: progress gets gen, nothing else changes")
    expect(Stub.snapshot().last?.options == genOption, "poll: host options carry gen")

    for (action, reply) in [("scan_add", #"{"type":"scan_ack","scan_id":"s1","accepted":2,"mem_mb":null}"#),
                            ("scan_freeze", #"{"type":"scan_freeze_ack","scan_id":"s1","spent":1,"reserved":2}"#),
                            ("scan_cancel", #"{"type":"scan_ack","scan_id":"s1","accepted":0,"mem_mb":null,"final":true,"bytes_spent":9}"#)] {
        Stub.reply = bytes(reply)
        let request = "{\"action\":\"\(action)\",\"scan_id\":\"s1\",\"candidates\":[]}"
        let out = f.send(request)
        expect(out == reply, "\(action): reply unchanged, got \(out)")
        expect(Stub.snapshot().last?.request == bytes(request), "\(action): request unchanged")
        expect(Stub.snapshot().last?.options == genOption, "\(action): host options carry gen")
    }

    expect(Stub.outstanding == 0 && Stub.releasedTwice == 0, "every engine reply released exactly once (outstanding \(Stub.outstanding), twice \(Stub.releasedTwice))")
    expect(f.livePeerAsked == 1, "the live AWG peer is asked by scan_start only")

    // Secrets never reach the log; ids, sizes and codes do.
    let logs = f.logs.joined(separator: "\n")
    expect(!logs.contains("secret") && !logs.contains("api.example") && !logs.contains("tsc1"), "no token, host or config in the log: \(logs)")
    expect(logs.contains("start scan=s1") && logs.contains("bind_if=7"), "the start line names the scan id and the interface index")

    // An engine that broke the ABI (NULL) is answered as internal, never crashes the relay.
    Stub.returnNull = true
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == #"{"error":"internal"}"#, "NULL from the engine = internal")
    Stub.returnNull = false

    // A NUL inside the request never reaches the C string.
    var withNul = bytes(#"{"action":"scan_poll","scan_id":"s1","since":0}"#)
    withNul.insert(0, at: 5)
    let before = Stub.snapshot().count
    let nulReply = f.host.handle(withNul, action: "scan_poll")
    expect(text(nulReply) == #"{"error":"bad_request","detail":"json"}"# && Stub.snapshot().count == before, "a NUL byte is refused before the engine")
}

private func testDispatch() {
    let yes = [#"{"action":"scan_caps"}"#, #"  {"scan_id":"s","action":"scan_poll","since":1}"#,
               #"{"action":"scan_teleport"}"#, "{\"action\":\"scan_caps\",\"x\":\"\\\"}\"}"]
    for m in yes {
        expect(TribeScanHost.scanMessage(of: Data(m.utf8))?.action.hasPrefix("scan_") == true, "dispatch takes \(m)")
    }
    let no = [#"{"action":"status","tunnelId":"t"}"#, #"{"action":"upstream_lease_set","upstream_lease":{"x":"scan_"}}"#,
              #"{"action":"rebind"}"#, "[interface]\nPrivateKey = scan_", #"{nope "scan_caps""#, #"{"action":"scan_caps"} trailing"#,
              #"{"action":1,"x":"scan_"}"#, ""]
    for m in no {
        expect(TribeScanHost.scanMessage(of: Data(m.utf8)) == nil, "dispatch leaves \(m.debugDescription) to the provider")
    }
    expect(TribeScanHost.scanMessage(of: Data([0])) == nil, "the WireGuard runtime-config byte is not a scan message")
}

private func testUnknownAction() {
    let f = Fixture()
    for action in ["scan_teleport", "scan_", "scan_caps2"] {
        let out = f.send("{\"action\":\"\(action)\"}")
        expect(out == #"{"error":"unknown_action"}"#, "\(action) -> unknown_action, got \(out)")
    }
    expect(Stub.snapshot().isEmpty, "unknown scan actions never reach the engine")
    // The host-local stop-all of the app adapter: answered here, no engine call while nothing was started.
    let ack = f.send(#"{"action":"scan_stop_all"}"#)
    expect(ack == #"{"type":"scan_stop_all_ack","stopped":true}"#, "scan_stop_all answered by the host, got \(ack)")
    expect(Stub.snapshot().isEmpty, "scan_stop_all before any scan_start: no engine call")
}

private func testNoPhysicalPath() {
    let f = Fixture()
    f.bindIndex = 0
    expect(f.send(startJSON) == #"{"error":"bad_request","detail":"host_options.bind_interface"}"#, "no interface index: refused")
    f.bindIndex = 7
    f.satisfied = false
    expect(f.send(startJSON) == #"{"error":"bad_request","detail":"host_options.bind_interface"}"#, "unsatisfied path: refused")
    expect(Stub.snapshot().isEmpty, "a refused start never reaches the engine")
    expect(f.host.stopAll(reason: "test") && Stub.snapshot().isEmpty, "a refused start does not arm stop-all")
    f.satisfied = true
    _ = f.send(startJSON)
    expect(Stub.snapshot().count == 1, "with a path back, the start goes through")
}

private func testStopAllOrdering() {
    // 1. No scan ever started: nothing to stop, no engine call.
    var f = Fixture()
    expect(f.host.stopAll(reason: "core_stop"), "stop-all with nothing started reports stopped")
    expect(Stub.snapshot().isEmpty, "stop-all with nothing started does not call the engine")

    // 2. After a start: StopAll(2000), its answer parsed.
    _ = f.send(startJSON)
    expect(f.host.stopAll(reason: "core_stop"), "stop-all after a start")
    var calls = Stub.snapshot()
    expect(calls.last?.kind == "stop_all" && calls.last?.waitMs == 2000, "stop-all waits up to 2000 ms in the engine")
    expect(calls.last?.options == "{\"host_epoch\":\(f.lifecycle.epoch)}", "the stop carries the epoch it moved to (\(calls.last?.options ?? "nil"))")
    Stub.oldEngine = true
    expect(f.host.stopAll(reason: "core_stop") && Stub.snapshot().last?.kind == "stop_all_plain" && Stub.snapshot().last?.waitMs == 2000,
           "an engine without the scan_stop_all message: the plain LibXrayTribeScanStopAll")
    Stub.oldEngine = false
    Stub.stopReply = bytes(#"{"stopped":false,"instances":1,"jobs":2,"closers":1,"attempts":3,"awg":4,"children":5}"#)
    expect(!f.host.stopAll(reason: "core_stop"), "stopped:false (the engine's flat live counts) reaches the caller")
    expect(f.logs.contains { $0.hasPrefix("Tribe scan: stop-all reason=core_stop stopped=false") }, "stop-all is logged with its reason")

    // 3. The gate is held (a tunnel core stop in progress elsewhere): stop-all waits for it.
    f = Fixture()
    _ = f.send(startJSON)
    let held = DispatchSemaphore(value: 0)
    var releasedAt = 0.0
    DispatchQueue.global().async {
        f.gate.withExclusive {
            held.signal()
            usleep(200_000)
            releasedAt = now()
        }
    }
    held.wait()
    f.host.stopAll(reason: "core_stop")
    calls = Stub.snapshot()
    expect(calls.last?.kind == "stop_all" && (calls.last?.at ?? 0) >= releasedAt, "stop-all runs only once the gate is free")

    // 4. A scan_start inside the engine: stop-all waits until it returned, then stops it.
    f = Fixture()
    Stub.messageDelayMs = 300
    let startDone = DispatchSemaphore(value: 0)
    var startReturnedAt = 0.0
    DispatchQueue.global().async {
        _ = f.send(startJSON)
        startReturnedAt = now()
        startDone.signal()
    }
    usleep(60_000)
    f.host.stopAll(reason: "core_stop")
    startDone.wait()
    calls = Stub.snapshot()
    expect(calls.map(\.kind) == ["message", "stop_all"], "order: the start, then stop-all (got \(calls.map(\.kind)))")
    expect(calls.count == 2 && calls[1].at >= calls[0].at + 0.29 && startReturnedAt > 0,
           "stop-all called only after the start left the engine (300 ms inside it)")
    Stub.messageDelayMs = 0

    // 5. scan_add is serialized with the gate too; scan_poll is not (it never launches an instance).
    f = Fixture()
    _ = f.send(startJSON)
    let gateHeld = DispatchSemaphore(value: 0)
    let gateFree = DispatchSemaphore(value: 0)
    var gateReleasedAt = 0.0
    DispatchQueue.global().async {
        f.gate.withExclusive {
            gateHeld.signal()
            usleep(250_000)
            gateReleasedAt = now()
        }
        gateFree.signal()
    }
    gateHeld.wait()
    let pollStart = now()
    _ = f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#)
    let pollTook = now() - pollStart
    expect(pollTook < 0.2, "scan_poll is not held by the gate (took \(pollTook) s)")
    _ = f.send(#"{"action":"scan_add","scan_id":"s1","candidates":[]}"#)
    calls = Stub.snapshot()
    gateFree.wait()
    expect((calls.last?.at ?? 0) >= gateReleasedAt, "scan_add waits for the gate")

    // 6. scan_stop_all after a start: the engine's StopAll under the gate.
    f = Fixture()
    _ = f.send(startJSON)
    expect(f.send(#"{"action":"scan_stop_all"}"#) == #"{"type":"scan_stop_all_ack","stopped":true}"#, "scan_stop_all ack")
    expect(Stub.snapshot().last?.kind == "stop_all", "scan_stop_all calls the engine's StopAll")
    expect(Stub.outstanding == 0 && Stub.releasedTwice == 0, "stop-all replies released exactly once")
}

private func testGeneration() {
    let g = TribeScanPathGeneration(epoch: 0xab)
    expect(g.element == TribeScanNetElement(epoch: 0xab, counter: 0), "a new source: counter 0")
    expect(!g.observe(signature: "A"), "the first path is the baseline")
    expect(g.element.counter == 0, "baseline keeps counter 0")
    expect(!g.observe(signature: "A") && g.element.counter == 0, "the same path: no change")
    expect(g.observe(signature: "B") && g.element.counter == 1, "another path: counter 1")
    expect(g.observe(signature: "A") && g.element.counter == 2, "back to the first path is a change too (counter 2, never back)")
    expect(g.element.json == #"{"source":"ne","epoch":"00000000000000ab","counter":2}"#, "wire form, got \(g.element.json)")
    let big = TribeScanNetElement(epoch: 0xfedc_ba98_7654_3210, counter: 5)
    expect(big.epochHex == "fedcba9876543210", "epoch: 16 lowercase hex")
    let epochs = Set((0..<8).map { _ in TribeScanPathGeneration().epoch })
    expect(epochs.count == 8, "every monitor start picks its own random epoch")

    let a = TribeScanPathFacts(satisfied: true, interfaces: ["wifi:en0:4", "cellular:pdp_ip0:2"],
                               addresses: ["en0/192.0.2.4", "en0/fe80::1"], gateways: ["192.0.2.1"])
    var b = a
    b.interfaces.reverse()
    b.addresses.reverse()
    expect(a.signature == b.signature, "the signature ignores the order of the facts")
    var c = a
    c.satisfied = false
    expect(c.signature != a.signature, "an unusable path changes the signature")
    var d = a
    d.addresses = ["en0/192.0.2.5"]
    expect(d.signature != a.signature, "a new address changes the signature")
    var e = a
    e.gateways = ["192.0.2.254"]
    expect(e.signature != a.signature, "a new gateway changes the signature")
    var i = a
    i.interfaces = ["wifi:en0:5"]
    expect(i.signature != a.signature, "a new interface index changes the signature")
    let loopback = TribeScanPathFacts.addresses(ofInterfaces: ["lo0"])
    expect(loopback.contains("lo0/127.0.0.1"), "getifaddrs: addresses of the named interfaces (\(loopback))")
    expect(TribeScanPathFacts.addresses(ofInterfaces: []).isEmpty, "no interface, no address")
}

private func testProgressGen() {
    let f = Fixture()
    let e1 = f.generation.element
    let progress = { (body: String) in "{\"type\":\"scan_progress\",\"scan_id\":\"s1\",\"seq\":1,\"phase\":\"data\",\"items\":[],\"bytes_spent\":0,\"done\":false,\"reason\":\"\"\(body)}" }

    // Top-level gen: absent -> appended; null -> replaced; the engine's own -> kept.
    Stub.reply = bytes(progress(""))
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == progress(",\"gen\":\(e1.json)"), "absent gen appended")
    Stub.reply = bytes(progress(",\"gen\":null"))
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == progress(",\"gen\":\(e1.json)"), "null gen replaced")
    let own = ",\"gen\":{\"source\":\"ne\",\"epoch\":\"0000000000000001\",\"counter\":9}"
    Stub.reply = bytes(progress(own))
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == progress(own), "the engine's own gen is kept")

    // Access attempts of a scan started through this host, element unchanged since its scan_start.
    Stub.reply = bytes(#"{"type":"scan_ack","scan_id":"s1","accepted":1,"mem_mb":null}"#)
    _ = f.send(startJSON)
    let attempts = ",\"access\":{\"attempted\":true,\"http_answered\":false,\"asn\":null,\"net_token\":null,\"at_ms\":0,\"gen\":null}"
        + ",\"access_close\":{\"attempted\":true,\"http_answered\":true,\"asn\":64500,\"net_token\":\"n}\\\"t\",\"at_ms\":900}"
    Stub.reply = bytes(progress(attempts))
    let filled = f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#)
    let expected = progress(",\"access\":{\"attempted\":true,\"http_answered\":false,\"asn\":null,\"net_token\":null,\"at_ms\":0,\"gen\":\(e1.json)}"
        + ",\"access_close\":{\"attempted\":true,\"http_answered\":true,\"asn\":64500,\"net_token\":\"n}\\\"t\",\"at_ms\":900,\"gen\":\(e1.json)}"
        + ",\"gen\":\(e1.json)")
    expect(filled == expected, "both attempts get the element (unchanged since scan_start), got \(filled)")
    expect(jsonObject(bytes(filled)) != nil, "the spliced reply is valid JSON")

    // An attempt not made, and an attempt that already carries the engine's gen, stay as they are.
    let untouched = ",\"access\":{\"attempted\":false},\"access_close\":{\"attempted\":true,\"http_answered\":false,\"gen\":{\"source\":\"x\",\"epoch\":\"0000000000000002\",\"counter\":1}}"
    Stub.reply = bytes(progress(untouched))
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == progress(untouched + ",\"gen\":\(e1.json)"), "attempted:false and an own attempt gen untouched")

    // The path moved after scan_start: the attempts' state is no longer known exactly - no attempt gen.
    f.generation.observe(signature: "moved")
    let e2 = f.generation.element
    expect(e2.counter == e1.counter + 1, "path moved")
    Stub.reply = bytes(progress(attempts))
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == progress(attempts + ",\"gen\":\(e2.json)"), "moved path: attempts untouched, progress carries the new element")

    // A scan this host never started: attempts untouched.
    let other = progress(attempts).replacingOccurrences(of: "\"scan_id\":\"s1\"", with: "\"scan_id\":\"s9\"")
    Stub.reply = bytes(other)
    expect(f.send(#"{"action":"scan_poll","scan_id":"s9","since":0}"#) == text(insertingAtClose(bytes(other), ",\"gen\":\(e2.json)")), "unknown scan id: attempts untouched")

    // Errors, acks and freeze acks never get gen.
    for reply in [#"{"error":"unknown_scan","scan_id":"s1"}"#, #"{"type":"scan_freeze_ack","scan_id":"s1","spent":0,"reserved":0}"#] {
        Stub.reply = bytes(reply)
        expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#) == reply, "\(reply) unchanged")
    }
}

private func testCapsByHeadroom() {
    typealias P = TribeScanCapsPolicy.Pools
    let engine = P(full: 1, leg: 6, awg: 2)
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: nil) == engine, "unknown headroom: the engine's pools")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 11.9) == P(), "below the start guard: no pool")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 0) == P(), "0 MB: no pool")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 12) == P(full: 1, leg: 0, awg: 0), "12 MB: a full probe only")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 13.4) == P(full: 1, leg: 1, awg: 0), "13.4 MB: no room for an AWG session")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 13.5) == P(full: 1, leg: 2, awg: 1), "13.5 MB: 2 legs, 1 AWG session")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 15.4) == P(full: 1, leg: 3, awg: 1), "15.4 MB: 1 AWG session")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 16) == P(full: 1, leg: 4, awg: 2), "16 MB: 4 legs, 2 AWG sessions")
    expect(TribeScanCapsPolicy.pools(engine: engine, availableMB: 40) == engine, "plenty: the engine's pools")
    expect(TribeScanCapsPolicy.pools(engine: P(full: 1, leg: 6, awg: 0), availableMB: 40).awg == 0, "never more than the engine offers")

    let caps = #"{"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":1,"max_leg_concurrent":6,"max_awg_concurrent":0,"can_verify_composite":false,"dns_plan":true,"reach_stage":true,"needs_vpn":true,"kinds":["xray_full","xray_leg"],"mem_mb":20,"platform":"ios"}"#
    let f = Fixture()
    let gen = f.generation.element.json
    Stub.reply = bytes(caps)
    f.availableMB = 40
    expect(f.send(#"{"action":"scan_caps"}"#) == text(insertingAtClose(bytes(caps), ",\"gen\":\(gen)")), "plenty of headroom: pools as the engine says")

    f.availableMB = 16
    let mid = f.send(#"{"action":"scan_caps"}"#)
    let midObj = jsonObject(bytes(mid))
    expect((midObj?["max_leg_concurrent"] as? Int) == 4 && (midObj?["max_full_concurrent"] as? Int) == 1, "16 MB: legs lowered to 4 (\(mid))")
    expect((midObj?["kinds"] as? [String]) == ["xray_full", "xray_leg"] && (midObj?["dns_plan"] as? Bool) == true, "16 MB: both kinds kept")
    expect((midObj?["mem_available_mb"] as? Int) == 16, "lowered caps say the headroom")

    f.availableMB = 10
    let low = f.send(#"{"action":"scan_caps"}"#)
    let lowObj = jsonObject(bytes(low))
    expect((lowObj?["max_full_concurrent"] as? Int) == 0 && (lowObj?["max_leg_concurrent"] as? Int) == 0, "10 MB: no pool")
    expect((lowObj?["kinds"] as? [String]) == [], "10 MB: no kind offered")
    expect((lowObj?["dns_plan"] as? Bool) == false && (lowObj?["can_verify_composite"] as? Bool) == false, "10 MB: no DNS plan, no composite")
    expect((lowObj?["version"] as? String) == "tribe-scan-v1" && (lowObj?["needs_vpn"] as? Bool) == true && (lowObj?["platform"] as? String) == "ios",
           "lowered caps keep the rest")
    expect((lowObj?["gen"] as? NSDictionary)?["source"] as? String == "ne", "caps carry the ne element")
}

private func testLivePeerAndCancel() {
    // The live AWG peer of a UAPI runtime configuration: the first peer only, the private key never in the result.
    let uapi = "private_key=" + String(repeating: "a", count: 64) + "\nlisten_port=51820\n"
        + "public_key=" + String(repeating: "B", count: 64) + "\npreshared_key=" + String(repeating: "c", count: 64)
        + "\nendpoint=203.0.113.7:51820\nallowed_ip=0.0.0.0/0\nlast_handshake_time_sec=1\n"
        + "public_key=" + String(repeating: "d", count: 64) + "\nendpoint=198.51.100.1:1\n"
    let peer = TribeScanHost.awgLivePeerJSON(fromUAPI: uapi)
    expect(peer == "{\"endpoint\":\"203.0.113.7:51820\",\"public_key\":\"" + String(repeating: "b", count: 64) + "\"}",
           "the first peer's key (lower-case hex) and endpoint, got \(peer ?? "nil")")
    expect(!(peer ?? "").contains("aaaa") && !(peer ?? "").contains("cccc"), "neither the private nor the preshared key")
    let v6 = TribeScanHost.awgLivePeerJSON(fromUAPI: "public_key=" + String(repeating: "e", count: 64) + "\nendpoint=[2001:db8::1]:443\n")
    expect(v6?.contains("[2001:db8::1]:443") == true, "an IPv6 endpoint")
    let keyOnly = TribeScanHost.awgLivePeerJSON(fromUAPI: "public_key=" + String(repeating: "f", count: 64) + "\n")
    expect(keyOnly == "{\"public_key\":\"" + String(repeating: "f", count: 64) + "\"}", "a peer without an endpoint: the key alone")
    expect(TribeScanHost.awgLivePeerJSON(fromUAPI: "private_key=" + String(repeating: "a", count: 64) + "\n") == nil, "no peer: nil")
    expect(TribeScanHost.awgLivePeerJSON(fromUAPI: "public_key=short\nendpoint=1.2.3.4:5\n") == nil, "a malformed key: nil")
    expect(TribeScanHost.awgLivePeerJSON(fromUAPI: "") == nil, "empty: nil")

    // scan_start on an AWG tunnel carries it; nothing else does.
    let f = Fixture()
    f.live = .known(keyOnly ?? "")
    let element = f.generation.element.json
    _ = f.send(startJSON)
    expect(Stub.snapshot().last?.options == f.options(start: true, peer: keyOnly),
           "start on an AWG tunnel: awg_live_peer, got \(Stub.snapshot().last?.options ?? "nil")")
    _ = f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#)
    expect(Stub.snapshot().last?.options == f.options(), "a poll never carries the live peer")
    expect(f.livePeerAsked == 1, "the live peer is read for scan_start only")
    expect(!f.logs.joined().contains("ffff"), "the live peer's key is never logged")

    // scan_cancel answers at once; the polls after it are relayed until the final progress (and after it).
    Stub.reply = bytes(#"{"type":"scan_ack","scan_id":"s1","accepted":0,"mem_mb":20}"#)
    expect(f.send(#"{"action":"scan_cancel","scan_id":"s1"}"#) == #"{"type":"scan_ack","scan_id":"s1","accepted":0,"mem_mb":20}"#,
           "the cancel ack as the engine sent it")
    for final in [false, true, true] {
        let progress = "{\"type\":\"scan_progress\",\"scan_id\":\"s1\",\"seq\":3,\"phase\":\"done\",\"items\":[],\"bytes_spent\":9000,"
            + "\"bytes_reserved\":\(final ? 0 : 10240),\"done\":\(final),\"final\":\(final),\"reason\":\"cancelled\",\"gen\":\(element)}"
        Stub.reply = bytes(progress)
        expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":3}"#) == progress, "poll after cancel (final \(final)) relayed unchanged")
    }

    // The engine's awg_mini pool passes through, lowered by headroom; no headroom for one session = no kind.
    expect(TribeScanHost.awgMiniOffered, "awg_mini is offered by this build")
    let caps = #"{"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":1,"max_leg_concurrent":6,"max_awg_concurrent":2,"can_verify_composite":false,"dns_plan":true,"reach_stage":true,"needs_vpn":true,"kinds":["xray_full","xray_leg","awg_mini"],"mem_mb":12,"platform":"ios"}"#
    Stub.reply = bytes(caps)
    f.availableMB = 40
    expect(f.send(#"{"action":"scan_caps"}"#) == text(insertingAtClose(bytes(caps), ",\"gen\":\(element)")),
           "plenty of headroom: the engine's awg_mini pool as it is")
    f.availableMB = 14
    var out = jsonObject(bytes(f.send(#"{"action":"scan_caps"}"#)))
    expect((out?["max_awg_concurrent"] as? Int) == 1 && ((out?["kinds"] as? [String]) ?? []).contains("awg_mini"),
           "14 MB: one AWG session (\(out ?? [:]))")
    f.availableMB = 13
    out = jsonObject(bytes(f.send(#"{"action":"scan_caps"}"#)))
    expect((out?["max_awg_concurrent"] as? Int) == 0 && (out?["kinds"] as? [String]) == ["xray_full", "xray_leg"],
           "13 MB: no AWG session, the kind is gone")
}

private func testLivePeerUnknown() {
    let awgStart = startJSON.replacingOccurrences(of: #""kind":"xray_full""#, with: #""kind":"awg_mini""#)
    expect(TribeScanHost.hasAwgMini(bytes(awgStart)) && !TribeScanHost.hasAwgMini(bytes(startJSON)), "awg_mini candidates detected")
    expect(!TribeScanHost.hasAwgMini(bytes(#"{"action":"scan_add","scan_id":"s","candidates":[{"id":"x","kind":"xray_leg","config":"{\"kind\":\"awg_mini\"}"}]}"#)),
           "an awg_mini text inside a config is not a candidate kind")
    let refusal = #"{"error":"internal","detail":"awg_live_peer_unknown"}"#

    // AmneziaWG tunnel, peer not readable: a start with awg_mini candidates is refused before the engine.
    var f = Fixture()
    f.live = .unknown
    expect(f.send(awgStart) == refusal, "awg_mini start without the live peer refused")
    expect(Stub.snapshot().isEmpty, "the refused start never reaches the engine")
    expect(f.logs.contains { $0.contains("refused: awg_mini without the live AmneziaWG peer") }, "the refusal is logged")

    // The same scan without awg_mini goes through (no live peer in the options); a later add with awg_mini is
    // refused, an add without it relayed.
    _ = f.send(startJSON)
    expect(Stub.snapshot().count == 1 && !(Stub.snapshot().last?.options ?? "").contains("awg_live_peer"), "start without awg_mini relayed")
    let awgAdd = #"{"action":"scan_add","scan_id":"s1","candidates":[{"id":"9","kind":"awg_mini","config":"{}","entry":null}]}"#
    expect(f.send(awgAdd) == refusal && Stub.snapshot().count == 1, "awg_mini add for that scan refused")
    _ = f.send(#"{"action":"scan_add","scan_id":"s1","candidates":[{"id":"8:xray","kind":"xray_full","config":"{}","entry":null}]}"#)
    expect(Stub.snapshot().count == 2, "an add without awg_mini relayed")

    // Known peer: the awg_mini start carries it, the add is relayed.
    f = Fixture()
    f.live = .known(#"{"public_key":"00"}"#)
    _ = f.send(awgStart)
    expect((Stub.snapshot().last?.options ?? "").contains(#""awg_live_peer":{"public_key":"00"}"#), "awg_mini start with the live peer")
    _ = f.send(awgAdd)
    expect(Stub.snapshot().count == 2, "awg_mini add relayed once the scan carries the live peer")

    // Not an AmneziaWG tunnel: nothing to protect, awg_mini relayed without the option.
    f = Fixture()
    f.live = .notAmneziaWG
    _ = f.send(awgStart)
    expect(Stub.snapshot().count == 1 && !(Stub.snapshot().last?.options ?? "").contains("awg_live_peer"), "Xray tunnel: awg_mini relayed")
}

// Review F1: the tunnel-change epoch, the closed host, a start waiting for the peer read; F3: an unfinished stop.
private func testTunnelLifecycle() {
    // A start received before a stop and run after it (queued): refused, never in the engine.
    var f = Fixture()
    let e0 = f.lifecycle.epoch
    expect(f.host.stopAll(reason: "core_restart") && f.lifecycle.epoch == e0 + 1, "every stop-all moves the epoch (also with no scan ever started)")
    expect(f.send(bytes(startJSON), receivedEpoch: e0) == #"{"error":"tunnel_changed"}"#, "a start received before the stop: tunnel_changed")
    expect(Stub.snapshot().isEmpty, "the stale start never reaches the engine")
    _ = f.send(startJSON)
    expect(Stub.snapshot().last?.options == f.options(start: true), "a start of the current epoch carries it as host_epoch")

    // A start waiting for the live-peer read when the tunnel stops: refused after the read.
    f = Fixture()
    f.live = .known(#"{"public_key":"00"}"#)
    f.peerReadDelayUs = 300_000
    let done = DispatchSemaphore(value: 0)
    var answer = ""
    let received = f.lifecycle.epoch
    DispatchQueue.global().async {
        answer = f.send(bytes(startJSON), receivedEpoch: received)
        done.signal()
    }
    f.peerReadStarted.wait()
    f.host.stopAll(reason: "tunnel_stop", close: true)
    done.wait()
    expect(answer == #"{"error":"no_vpn"}"# || answer == #"{"error":"tunnel_changed"}"#, "the start that waited for the peer read is refused: \(answer)")
    expect(Stub.snapshot().filter { $0.kind == "message" }.isEmpty, "it never reached the engine")

    // Closed from stopTunnel until a successful startTunnel; everything but a start still relays.
    expect(f.lifecycle.closed, "stopTunnel closed the host")
    f.peerReadDelayUs = 0
    expect(f.send(startJSON) == #"{"error":"no_vpn"}"#, "closed: a new start is refused no_vpn")
    Stub.reply = bytes(#"{"type":"scan_progress","scan_id":"s1","seq":1,"phase":"done","items":[],"bytes_spent":0,"done":true,"final":true,"reason":"tunnel_stopped","gen":null}"#)
    expect(f.send(#"{"action":"scan_poll","scan_id":"s1","since":0}"#).contains("\"final\":true"), "closed: polls still settle the old scan")
    f.lifecycle.reopen(token: f.lifecycle.reopenToken)
    Stub.reply = bytes(#"{"type":"scan_ack","scan_id":"s1","accepted":1,"mem_mb":null}"#)
    expect(f.send(startJSON) == #"{"type":"scan_ack","scan_id":"s1","accepted":1,"mem_mb":null}"#, "reopened: the start goes through")

    // An add for a scan of an older epoch: refused; of the current one: relayed.
    let add = #"{"action":"scan_add","scan_id":"s1","candidates":[{"id":"8:xray","kind":"xray_full","config":"{}","entry":null}]}"#
    let before = Stub.snapshot().count
    _ = f.send(add)
    expect(Stub.snapshot().count == before + 1 && Stub.snapshot().last?.options == f.options(), "an add of the current epoch: relayed with host_epoch")
    f.host.stopAll(reason: "peer_change")
    let afterStop = Stub.snapshot().count
    expect(f.send(add) == #"{"error":"tunnel_changed"}"# && Stub.snapshot().count == afterStop, "an add for a scan started before the stop: refused")

    // A stop-all while a start is inside the engine: the stop reads "started" under the gate and stops it.
    f = Fixture()
    Stub.messageDelayMs = 250
    let startDone = DispatchSemaphore(value: 0)
    DispatchQueue.global().async { _ = f.send(startJSON); startDone.signal() }
    usleep(60_000)
    f.host.stopAll(reason: "tunnel_stop", close: true)
    startDone.wait()
    Stub.messageDelayMs = 0
    expect(Stub.snapshot().map(\.kind) == ["message", "stop_all"], "the first scan, still inside the engine, is stopped (\(Stub.snapshot().map(\.kind)))")

    // F3: "stopped":false keeps new scans out until a stop check says stopped; the tunnel change is not held.
    f = Fixture()
    _ = f.send(startJSON)
    Stub.stopReply = bytes(#"{"stopped":false}"#)
    let t0 = now()
    expect(!f.host.stopAll(reason: "core_restart") && now() - t0 < 1, "an unfinished stop is reported at once, not waited for here")
    expect(f.lifecycle.unclean && f.logs.contains { $0.contains("stopped=false; teardown continues") }, "journalled, host refuses new scans")
    var calls = Stub.snapshot().count
    expect(f.send(startJSON) == #"{"error":"internal","detail":"stop_pending"}"#, "a start while the engine still tears down: stop_pending")
    expect(Stub.snapshot().count == calls + 1 && Stub.snapshot().last?.kind == "stop_all" && Stub.snapshot().last?.waitMs == 0,
           "the refusal came from a stop check (scan_stop_all wait 0), not a start")
    Stub.stopReply = bytes(#"{"stopped":true}"#)
    calls = Stub.snapshot().count
    _ = f.send(startJSON)
    expect(Stub.snapshot().dropFirst(calls).map(\.kind) == ["stop_all", "message"] && !f.lifecycle.unclean,
           "the stop check says stopped: the start goes through")
}

// Review F2: the adapter's backend stop / pause / restart waits for the engine's stop (never for the gate), bounded.
private func testBackendRestartStop() {
    var f = Fixture()
    _ = f.send(startJSON)
    // A gate holder (a scan start sitting in the engine): the backend stop does not wait for it.
    let held = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    var releasedAt = 0.0
    DispatchQueue.global().async { f.gate.withExclusive { held.signal(); release.wait(); releasedAt = now() } }
    held.wait()
    let e0 = f.lifecycle.epoch
    let t0 = now()
    let stopped = f.host.stopForBackendRestart(reason: "backend_restart")
    let returnedAt = now()
    release.signal()
    let stop = Stub.snapshot().last
    expect(stopped && returnedAt - t0 < 0.1, "the backend stop returns once the engine said stopped, gate held elsewhere (\(returnedAt - t0) s)")
    expect(stop?.kind == "stop_all" && stop?.waitMs == 500 && (stop?.at ?? .infinity) <= returnedAt,
           "the engine's stop (wait 500 ms) ran BEFORE the call returned, i.e. before the backend operation")
    expect(stop?.options == "{\"host_epoch\":\(e0 + 1)}" && f.lifecycle.epoch == e0 + 1, "it carries the epoch it moved to")
    while releasedAt == 0 { usleep(1000) }
    expect(releasedAt > returnedAt, "the gate was still held by the other thread when it returned (no gate taken)")
    expect(f.send(bytes(startJSON), receivedEpoch: e0) == #"{"error":"tunnel_changed"}"#, "a start of the old epoch is stale")
    // Idempotent: a second call for the same step stops again (nothing left) and returns.
    expect(f.host.stopForBackendRestart(reason: "backend_restart") && f.lifecycle.epoch == e0 + 2, "a repeated call is harmless")

    // A hung engine: the adapter's queue is let go within the bound; "not stopped" is journalled and kept.
    f = Fixture()
    _ = f.send(startJSON)
    Stub.stopDelayMs = 3000
    let t1 = now()
    let hungStopped = f.host.stopForBackendRestart(reason: "backend_pause")
    let took = now() - t1
    expect(!hungStopped && took >= 0.55 && took < 0.9, "a hung engine: the call returns within the bound, not stopped (\(took) s)")
    expect(f.lifecycle.unclean && f.logs.contains { $0.contains("engine did not answer within 600 ms") }, "journalled, new scans refused")
    Stub.stopDelayMs = 0
    usleep(2_600_000) // let the hung stub call finish before the next test resets the stub
}

// Review R1: the host reopens only for the start that asked, and never after a stopTunnel that came since.
private func testReopenBoundToStart() {
    let lifecycle = TribeScanLifecycle()
    // Start #1 succeeds: nothing was closed, the host stays open.
    let t1 = lifecycle.reopenToken
    expect(lifecycle.reopen(token: t1) && !lifecycle.closed, "a start with no stop in between: open")
    // stopTunnel; start #2 begins; it succeeds: open again.
    lifecycle.bump(close: true)
    let t2 = lifecycle.reopenToken
    expect(lifecycle.closed && lifecycle.reopen(token: t2) && !lifecycle.closed, "a start after the stop reopens the host")
    // Start #3 pending -> stopTunnel -> its late success: the host stays closed (a stop always wins).
    let t3 = lifecycle.reopenToken
    lifecycle.bump(close: true)
    expect(!lifecycle.reopen(token: t3) && lifecycle.closed, "start pending, stop, late success: the host stays closed")
    // The adapter's own stop callback (close: false) neither reopens nor changes that.
    lifecycle.bump(close: false)
    expect(lifecycle.closed && !lifecycle.reopen(token: t3), "a non-closing bump does not reopen it either")
    // The host behind it: a start after that late success is refused no_vpn.
    let f = Fixture()
    let token = f.lifecycle.reopenToken
    f.host.stopAll(reason: "tunnel_stop", close: true)
    f.lifecycle.reopen(token: token)
    expect(f.send(startJSON) == #"{"error":"no_vpn"}"#, "late success after stopTunnel: starts still refused")
}

private func testJSONSpans() {
    let b = bytes(#" { "a" : 1 , "s":"x}\"{", "o":{"k":[1,{"z":"]"}],"n":null}, "t":true, "neg":-12, "f":1.5 } "#)
    guard let o = TribeScanJSON.topLevel(b) else {
        expect(false, "top-level object parsed")
        return
    }
    expect(o.members.map(\.key) == ["a", "s", "o", "t", "neg", "f"], "members in order: \(o.members.map(\.key))")
    expect(TribeScanJSON.string(b, o.value("s")!) == "x}\"{", "escaped string decoded")
    expect(TribeScanJSON.int(b, o.value("neg")!) == -12 && TribeScanJSON.int(b, o.value("f")!) == nil, "integers only")
    expect(TribeScanJSON.isLiteral(b, o.value("t")!, "true"), "literal true")
    let inner = TribeScanJSON.object(b, in: o.value("o")!)
    expect(inner?.members.map(\.key) == ["k", "n"], "nested object")
    expect(TribeScanJSON.topLevel(bytes(#"{"a":1} x"#)) == nil && TribeScanJSON.topLevel(bytes(#"{"a":1"#)) == nil
           && TribeScanJSON.topLevel(bytes("[1]")) == nil && TribeScanJSON.topLevel(bytes(#"{"a" 1}"#)) == nil,
           "not one object: nil (the relay then leaves the bytes alone)")
    let empty = bytes("{}")
    let edited = TribeScanJSON.apply(empty, TribeScanJSON.setMembers(TribeScanJSON.topLevel(empty)!, [("gen", "1"), ("x", "2")]))
    expect(text(edited) == #"{"gen":1,"x":2}"#, "appending into an empty object, got \(text(edited))")
    let one = bytes(#"{"gen":null,"a":3}"#)
    let replaced = TribeScanJSON.apply(one, TribeScanJSON.setMembers(TribeScanJSON.topLevel(one)!, [("gen", "7"), ("b", "4")]))
    expect(text(replaced) == #"{"gen":7,"a":3,"b":4}"#, "replace + append, got \(text(replaced))")
}

// MARK: - shared vectors, byte for byte

private func vectorBytes(_ value: Any) -> [UInt8] {
    if let s = value as? String { return bytes(s) }
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) else { return [] }
    return [UInt8](data)
}

private func replayVectors(_ dir: String) {
    let path = (dir as NSString).appendingPathComponent("scan_host_vectors.json")
    guard let data = FileManager.default.contents(atPath: path),
          let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let requests = root["requests"] as? [[String: Any]], let replies = root["replies"] as? [[String: Any]] else {
        expect(false, "scan_host_vectors.json readable at \(path)")
        return
    }
    expect(root["version"] as? String == "tribe-scan-v1", "vectors of tribe-scan-v1")

    var relayed = 0, local = 0, provider = 0
    for v in requests {
        let name = v["name"] as? String ?? "?"
        let input = vectorBytes(v["json"] as Any)
        let expectError = (v["expect"] as? [String: Any])?["error"] as? String ?? ""
        let f = Fixture()
        Stub.reply = bytes(#"{"type":"scan_ack","scan_id":"v","accepted":0,"mem_mb":null}"#)
        guard let m = TribeScanHost.scanMessage(of: Data(input)) else {
            // Not a scan message: the provider's own dispatch answers it ("status" has its branch there, a
            // non-JSON message is the WireGuard configuration path) - this layer must not claim it.
            provider += 1
            expect(name == "other_channel_action" || name == "not_json", "request \(name): only non-scan messages fall through")
            continue
        }
        let out = text(f.host.handle(m.bytes, action: m.action))
        let calls = Stub.snapshot()
        if TribeScanHost.relayedActions.contains(m.action) {
            relayed += 1
            expect(calls.count == 1 && calls[0].request == input, "request \(name): the engine got the vector bytes unchanged")
            let opts = calls.first?.options ?? ""
            expect(opts == f.options(start: m.action == "scan_start"), "request \(name): host options \(opts)")
            expect(out == #"{"type":"scan_ack","scan_id":"v","accepted":0,"mem_mb":null}"#, "request \(name): the engine's answer unchanged")
        } else {
            local += 1
            expect(calls.isEmpty && out == #"{"error":"unknown_action"}"# && expectError == "unknown_action",
                   "request \(name): an unknown scan action is answered here as the vector says (\(expectError))")
        }
    }
    expect(relayed + local + provider == requests.count && relayed >= 15, "requests: \(relayed) relayed, \(local) local, \(provider) provider")

    var unchanged = 0, spliced = 0, masked = 0
    for v in replies {
        let name = v["name"] as? String ?? "?"
        let input = vectorBytes(v["json"] as Any)
        let f = Fixture()
        let element = f.generation.element
        Stub.reply = input
        let out = vectorPoll(f)
        guard let o = TribeScanJSON.topLevel(input), o.value("error") == nil, let tr = o.value("type"),
              let type = TribeScanJSON.string(input, tr), type == "scan_caps" || type == "scan_progress" else {
            unchanged += 1
            expect(out == input, "reply \(name): relayed byte for byte")
            continue
        }
        if let gr = o.value("gen"), !TribeScanJSON.isLiteral(input, gr, "null") {
            unchanged += 1
            expect(out == input, "reply \(name): the engine's own gen kept, byte for byte")
            continue
        }
        spliced += 1
        let awgOffered = !TribeScanHost.awgMiniOffered && type == "scan_caps"
            && ((o.value("max_awg_concurrent").flatMap { TribeScanJSON.int(input, $0) } ?? 0) > 0)
        if o.value("gen") == nil && !awgOffered {
            expect(out == insertingAtClose(input, ",\"gen\":\(element.json)"), "reply \(name): exactly the engine's bytes + gen")
        }
        if let inObj = jsonObject(input)?.mutableCopy() as? NSMutableDictionary,
           let outObj = jsonObject(out)?.mutableCopy() as? NSMutableDictionary {
            let gen = outObj["gen"] as? NSDictionary
            expect(gen?["source"] as? String == "ne" && gen?["epoch"] as? String == element.epochHex
                   && (gen?["counter"] as? Int) == Int(element.counter), "reply \(name): gen = the ne element")
            inObj.removeObject(forKey: "gen")
            outObj.removeObject(forKey: "gen")
            if awgOffered {
                // The awg_mini pool is closed on iOS (TribeScanHost.awgMiniOffered): pool 0, kind gone, rest as sent.
                expect((outObj["max_awg_concurrent"] as? Int) == 0 && !((outObj["kinds"] as? [String]) ?? []).contains("awg_mini"),
                       "reply \(name): awg_mini masked")
                inObj["max_awg_concurrent"] = 0
                inObj["kinds"] = ((inObj["kinds"] as? [String]) ?? []).filter { $0 != "awg_mini" }
                masked += 1
            }
            expect(inObj == outObj, "reply \(name): nothing but gen (and the masked awg pool) differs")
        } else {
            expect(false, "reply \(name): JSON before and after")
        }
    }
    expect(unchanged + spliced == replies.count && spliced >= 5, "replies: \(unchanged) byte for byte, \(spliced) + gen")
    expect(Stub.outstanding == 0 && Stub.releasedTwice == 0, "vector replay: every engine reply released once")
    print("scan host vectors: \(requests.count) requests (\(relayed) relayed unchanged, \(local) answered here, \(provider) left to the provider), "
          + "\(replies.count) replies (\(unchanged) byte for byte, \(spliced) + gen, \(masked) of them with the awg pool masked); "
          + "byte_gate cases are the engine's (Go)")
}

private func vectorPoll(_ f: Fixture) -> [UInt8] {
    let request = bytes(#"{"action":"scan_poll","scan_id":"v","since":0}"#)
    return [UInt8](f.host.handle(request, action: "scan_poll"))
}

@main
struct ScanBridgeTests {
    static func main() {
        let args = CommandLine.arguments
        guard args.count >= 2 else {
            fputs("usage: scan_bridge_tests <vectors dir>\n", stderr)
            exit(2)
        }
        testRelayRoundTrip()
        testDispatch()
        testUnknownAction()
        testNoPhysicalPath()
        testStopAllOrdering()
        testGeneration()
        testProgressGen()
        testCapsByHeadroom()
        testLivePeerAndCancel()
        testLivePeerUnknown()
        testTunnelLifecycle()
        testBackendRestartStop()
        testReopenBoundToStart()
        testJSONSpans()
        replayVectors(args[1])
        if failures > 0 {
            fputs("Scan bridge tests: \(failures) of \(checks) checks FAILED\n", stderr)
            exit(1)
        }
        print("Scan bridge tests passed (\(checks) checks)")
    }
}

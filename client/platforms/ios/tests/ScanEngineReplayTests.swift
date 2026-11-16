import Darwin
import Foundation

// AVPN (Scanner, lane L4): the extension's probe host relay (TribeScanHost.swift) against the REAL Go engine -
// awg-apple's libwg-go.a for macOS (the same tribescan package and C exports LibXrayTribeScanMessage /
// LibXrayTribeScanStopAll as the iOS extension links; the platform is "macos-ne"). Built and run by
// run_scan_engine_replay.sh; argument 1 = the vectors directory (client/core/serviceEngine/tests/vectors).
//
// No packet leaves this Mac: no vector scan_start reaches a running scan (each is sent without the interface
// index, so the engine decodes it and then refuses it for that reason alone); the live scans below bind every
// socket to lo0 and point everything at 127.0.0.1 (access checks to :9, AmneziaWG peers to a closed UDP port).
//
// Known differences engine vs contract (none now): listed in knownDifferences and asserted as they are, so that a
// change on either side shows here.

private var failures = 0
private var checks = 0

private func expect(_ condition: @autoclosure () -> Bool, _ message: @autoclosure () -> String) {
    checks += 1
    if !condition() {
        failures += 1
        fputs("FAIL: \(message())\n", stderr)
    }
}

private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }
private func object(_ b: [UInt8]) -> [String: Any]? { (try? JSONSerialization.jsonObject(with: Data(b))) as? [String: Any] }
private func object(_ d: Data) -> [String: Any]? { object([UInt8](d)) }

private func vectorBytes(_ value: Any) -> [UInt8] {
    if let s = value as? String { return bytes(s) }
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) else { return [] }
    return [UInt8](data)
}

private let engine = TribeScanEngine(messageFn: LibXrayTribeScanMessage, stopAllFn: LibXrayTribeScanStopAll)

private final class Fixture {
    let generation = TribeScanPathGeneration(epoch: 0x0123_4567_89ab_cdef)
    let gate = XrayNativeLifecycleGate()
    let loopback = UInt32(if_nametoindex("lo0"))
    var live: TribeScanHost.LivePeer = .notAmneziaWG
    // One lifecycle for the process, as in the extension: the engine's stop epoch is process-wide.
    static let lifecycle = TribeScanLifecycle()
    lazy var host = TribeScanHost(
        engine: engine, gate: gate, lifecycle: Fixture.lifecycle,
        path: { [unowned self] in TribeScanPathInfo(bindIndex: self.loopback, satisfied: true, element: self.generation.element) },
        availableMB: { nil }, liveAwgPeer: { [unowned self] in self.live }, log: { _ in })

    init() { generation.observe(signature: "baseline") }

    func send(_ json: [UInt8]) -> [String: Any]? {
        guard let m = TribeScanHost.scanMessage(of: Data(json)) else { return nil }
        return object(host.handle(m.bytes, action: m.action))
    }

    func send(_ json: String) -> [String: Any]? { send(bytes(json)) }
}

private func genOf(_ v: Any?) -> TribeScanNetElement? {
    guard let g = v as? [String: Any], g["source"] as? String == "ne", let e = g["epoch"] as? String,
          let epoch = UInt64(e, radix: 16), let c = g["counter"] as? Int else { return nil }
    return TribeScanNetElement(epoch: epoch, counter: Int64(c))
}

private func replayRequests(_ dir: String, _ f: Fixture) {
    let path = (dir as NSString).appendingPathComponent("scan_host_vectors.json")
    guard let data = FileManager.default.contents(atPath: path),
          let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let requests = root["requests"] as? [[String: Any]] else {
        expect(false, "scan_host_vectors.json readable at \(path)")
        return
    }
    let knownDifferences: [String: (code: String, detail: String)] = [:]
    var replayed = 0, differences = 0
    for v in requests {
        let name = v["name"] as? String ?? "?"
        let input = vectorBytes(v["json"] as Any)
        let want = v["expect"] as? [String: Any] ?? [:]
        let wantError = want["error"] as? String ?? ""
        let wantDetail = want["detail"] as? String ?? ""
        guard let m = TribeScanHost.scanMessage(of: Data(input)) else { continue } // the provider's, not the host's
        replayed += 1
        let answer: [String: Any]?
        if m.action == "scan_start" {
            // Straight to the engine with gen and no interface index: decoded, then refused for the index only.
            answer = object(engine.message(input, hostOptions: TribeScanHost.hostOptions(element: f.generation.element, epoch: f.host.lifecycle.epoch)))
        } else {
            answer = f.send(input)
        }
        let code = answer?["error"] as? String ?? ""
        let detail = answer?["detail"] as? String ?? ""
        if let known = knownDifferences[name] {
            differences += 1
            expect(code == known.code && detail == known.detail,
                   "request \(name): the known engine difference holds (\(known.code)/\(known.detail)), got \(code)/\(detail)")
        } else if !wantError.isEmpty {
            expect(code == wantError && (wantDetail.isEmpty || detail == wantDetail),
                   "request \(name): the real engine answers \(wantError)/\(wantDetail), got \(code)/\(detail)")
        } else if m.action == "scan_start" {
            expect(code == "bad_request" && detail == "host_options.bind_interface",
                   "request \(name): decoded by the real engine (refused only for the missing interface), got \(code)/\(detail)")
        } else if m.action == "scan_caps" {
            expect(answer?["type"] as? String == "scan_caps", "request \(name): caps")
        } else {
            expect(code == "unknown_scan", "request \(name): decoded by the real engine (no such scan), got \(code)/\(detail)")
        }
    }
    expect(replayed >= 16, "request vectors replayed against the real engine: \(replayed)")
    print("real engine: \(replayed) request vectors replayed through the relay (\(differences) known engine differences)")
}

private func testCaps(_ f: Fixture) {
    let caps = f.send(#"{"action":"scan_caps"}"#)
    expect(caps?["type"] as? String == "scan_caps" && caps?["version"] as? String == "tribe-scan-v1", "real caps: \(caps ?? [:])")
    expect(genOf(caps?["gen"]) == f.generation.element, "real caps carry the ne element")
    expect(((caps?["max_awg_concurrent"] as? Int) ?? 0) > 0 && ((caps?["kinds"] as? [String]) ?? []).contains("awg_mini"),
           "real caps: the engine's awg_mini pool offered (patch 0014): \(caps?["max_awg_concurrent"] ?? "nil")")
    expect(((caps?["kinds"] as? [String]) ?? []).contains("xray_full"), "real caps: full probes offered")
}

private func testLiveScan(_ f: Fixture) {
    // A scan with no candidate, bound to lo0, access checks to 127.0.0.1:9 (refused at once).
    let start = """
    {"action":"scan_start","version":"tribe-scan-v1","scan_id":"replay-1","deadline_ms":4000,"max_bytes":65536,\
    "limits":{"stage1_sockets":4,"stage1_stagger_ms":0,"per_entry_ip":1,"entry_ip_spacing_ms":0,"stage1_timeout_ms":500,\
    "concurrency":1,"leg_concurrency":0,"awg_concurrency":0,"ttfb_ms":1000,"stall_ms":500,"stall_after_bytes":16384,\
    "total_ms":2000,"netinfo_cost_bytes":10240},"probe":{"base":"https://127.0.0.1:9","path":"/v1/probe",\
    "netinfo_path":"/v1/netinfo","token":"replay-token","warm_bytes":1024,"bytes":65536,"access_asn":null,\
    "access_net_token":null},"candidates":[]}
    """
    let e1 = f.generation.element
    let ack = f.send(start)
    expect(ack?["type"] as? String == "scan_ack" && ack?["scan_id"] as? String == "replay-1", "live scan accepted: \(ack ?? [:])")

    // The opening access attempt: made, no HTTP answer, stamped by the engine with the element of the host options.
    var progress: [String: Any]?
    let until = Date().addingTimeInterval(3)
    repeat {
        usleep(100_000)
        progress = f.send(#"{"action":"scan_poll","scan_id":"replay-1","since":0}"#)
    } while (progress?["access"] as? [String: Any]) == nil && Date() < until
    let opening = progress?["access"] as? [String: Any]
    expect(opening?["attempted"] as? Bool == true && opening?["http_answered"] as? Bool == false,
           "opening attempt made, no HTTP answer: \(opening ?? [:])")
    expect(genOf(opening?["gen"]) == e1, "the opening attempt carries the ne element (engine stamp)")
    expect(genOf(progress?["gen"]) == e1, "progress gen = the element sent with the poll")

    // The path moves: the next poll carries the new element; the attempt keeps the one of its start.
    f.generation.observe(signature: "moved")
    let e2 = f.generation.element
    progress = f.send(#"{"action":"scan_poll","scan_id":"replay-1","since":0}"#)
    expect(genOf(progress?["gen"]) == e2 && e2 != e1, "after a path change the progress carries the new element")
    expect(genOf((progress?["access"] as? [String: Any])?["gen"]) == e1, "the attempt's gen stays the one of its start")

    // Freeze, then cancel: both answered at once; the final total arrives by poll.
    let freeze = f.send(#"{"action":"scan_freeze","scan_id":"replay-1"}"#)
    expect(freeze?["type"] as? String == "scan_freeze_ack" && freeze?["spent"] is Int && freeze?["reserved"] is Int,
           "freeze ack with spent/reserved: \(freeze ?? [:])")
    let t0 = Date()
    let cancel = f.send(#"{"action":"scan_cancel","scan_id":"replay-1"}"#)
    let cancelTook = Date().timeIntervalSince(t0)
    expect(cancel?["type"] as? String == "scan_ack", "cancel ack: \(cancel ?? [:])")
    expect(cancelTook < 1.0, "scan_cancel answered at once (\(cancelTook) s)")
    var final: [String: Any]?
    let finalUntil = Date().addingTimeInterval(4)
    repeat {
        final = f.send(#"{"action":"scan_poll","scan_id":"replay-1","since":0}"#)
        if final?["final"] as? Bool == true { break }
        usleep(100_000)
    } while Date() < finalUntil
    expect(final?["final"] as? Bool == true && final?["done"] as? Bool == true, "polls after the cancel reach the final progress")
    expect((final?["bytes_reserved"] as? Int) == 0 && final?["bytes_spent"] is Int, "final: nothing reserved, the total spent")
    expect(genOf(final?["gen"]) == e2, "the final progress carries the latest element")
    let again = f.send(#"{"action":"scan_poll","scan_id":"replay-1","since":0}"#)
    expect(again?["final"] as? Bool == true && (again?["bytes_spent"] as? Int) == (final?["bytes_spent"] as? Int),
           "every later poll answers the same final")

    // Stop-all through the host (under the gate) after a scan was started: the engine reports stopped.
    expect(f.host.stopAll(reason: "replay"), "stop-all through the real engine")
}

private func hex(_ first: UInt8) -> String { (0..<32).map { String(format: "%02x", first &+ UInt8($0)) }.joined() }

private func awgCandidate(id: String, peerKey: String, port: Int, boundIf: UInt32) -> [String: Any] {
    let uapi = "private_key=\(hex(1))\nlisten_port=0\nreplace_peers=true\npublic_key=\(peerKey)\n"
        + "endpoint=127.0.0.1:\(port)\nreplace_allowed_ips=true\nallowed_ip=127.0.0.2/32\n"
    let config: [String: Any] = ["uapi": uapi, "address": "10.8.0.2/32", "mtu": 1280, "bound_if": Int(boundIf),
                                 "prime_echo_target": NSNull(),
                                 "probe": ["host": "probe.test", "ip": "127.0.0.2", "port": 9] as [String: Any]]
    let data = (try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])) ?? Data()
    return ["id": id, "kind": "awg_mini", "config": String(decoding: data, as: UTF8.self), "entry": NSNull(),
            "reach_at_ms": -1, "profile_id": NSNull(), "early_retry": false, "dns_plan": false, "cost_bytes": 85292]
}

/// Two AmneziaWG mini-sessions on loopback: one for the live tunnel's peer (awg_live_peer: refused, never opened),
/// one for another node behind a closed UDP port of 127.0.0.1 (the handshake never comes: error dial).
private func testAwgMiniLoopback() {
    let f = Fixture()
    let livePeerKey = hex(0x40)
    f.live = .known("{\"public_key\":\"\(livePeerKey)\"}")
    var udp = sockaddr_in()
    let closedPort: Int = {
        // A port that was free a moment ago: bind, read it, close (nothing listens there afterwards).
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(fd) }
        udp.sin_family = sa_family_t(AF_INET)
        udp.sin_addr.s_addr = inet_addr("127.0.0.1")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafePointer(to: &udp) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
        _ = withUnsafeMutablePointer(to: &udp) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: udp.sin_port))
    }()
    let start: [String: Any] = [
        "action": "scan_start", "version": "tribe-scan-v1", "scan_id": "replay-awg", "deadline_ms": 5000, "max_bytes": 400000,
        "limits": ["stage1_sockets": 4, "stage1_stagger_ms": 0, "per_entry_ip": 1, "entry_ip_spacing_ms": 0,
                   "stage1_timeout_ms": 500, "concurrency": 1, "leg_concurrency": 0, "awg_concurrency": 2,
                   "awg_handshake_ms": 400, "awg_prime_echoes": 0, "awg_spacing_ms": 50, "ttfb_ms": 1000, "stall_ms": 500,
                   "stall_after_bytes": 16384, "total_ms": 2000, "netinfo_cost_bytes": 10240] as [String: Any],
        "probe": ["base": "https://127.0.0.1:9", "path": "/v1/probe", "netinfo_path": "/v1/netinfo", "token": "replay-token",
                  "warm_bytes": 1024, "bytes": 65536, "access_asn": NSNull(), "access_net_token": NSNull()] as [String: Any],
        "candidates": [awgCandidate(id: "live-node", peerKey: livePeerKey, port: closedPort, boundIf: f.loopback),
                       awgCandidate(id: "other-node", peerKey: hex(0x80), port: closedPort, boundIf: f.loopback)],
    ]
    let request = [UInt8]((try? JSONSerialization.data(withJSONObject: start, options: [.sortedKeys])) ?? Data())
    let ack = f.send(request)
    expect(ack?["type"] as? String == "scan_ack" && (ack?["accepted"] as? Int) == 2, "awg_mini start accepted: \(ack ?? [:])")

    var items: [[String: Any]] = []
    let until = Date().addingTimeInterval(4)
    repeat {
        usleep(150_000)
        let p = f.send(#"{"action":"scan_poll","scan_id":"replay-awg","since":0}"#)
        items = (p?["items"] as? [[String: Any]] ?? []).filter { $0["stage"] as? String == "data" }
    } while items.count < 2 && Date() < until
    let live = items.first { $0["id"] as? String == "live-node" }
    let other = items.first { $0["id"] as? String == "other-node" }
    expect(live?["error"] as? String == "config", "the live tunnel's peer is refused by the runner (\(live?["error"] ?? "none"))")
    expect(other?["error"] as? String == "dial" && (other?["handshake_ok"] as? Bool ?? false) == false,
           "another node without an answer: no handshake, error dial (\(other?["error"] ?? "none"))")
    _ = f.send(#"{"action":"scan_freeze","scan_id":"replay-awg"}"#)
    _ = f.send(#"{"action":"scan_cancel","scan_id":"replay-awg"}"#)
    var final: [String: Any]?
    let finalUntil = Date().addingTimeInterval(4)
    repeat {
        final = f.send(#"{"action":"scan_poll","scan_id":"replay-awg","since":0}"#)
        if final?["final"] as? Bool == true { break }
        usleep(100_000)
    } while Date() < finalUntil
    expect(final?["final"] as? Bool == true && (final?["bytes_reserved"] as? Int) == 0, "the awg scan ends final, nothing reserved")
    expect(f.host.stopAll(reason: "replay"), "stop-all after the awg scan")
}

/// UDP and TCP sockets this process holds now (libproc): the engine's live probe instances and AmneziaWG sessions
/// hold sockets; the engine's own instance counters (tribescan.LiveInstances) are Go-only, not C exports.
private func socketCounts() -> (udp: Int, tcp: Int) {
    let pid = getpid()
    let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    guard size > 0 else { return (-1, -1) }
    var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / MemoryLayout<proc_fdinfo>.stride)
    let n = Int(proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)) / MemoryLayout<proc_fdinfo>.stride
    var udp = 0, tcp = 0
    for fd in fds.prefix(max(0, n)) where fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
        var info = socket_fdinfo()
        guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, Int32(MemoryLayout<socket_fdinfo>.size)) > 0 else { continue }
        if info.psi.soi_protocol == IPPROTO_UDP { udp += 1 } else if info.psi.soi_protocol == IPPROTO_TCP { tcp += 1 }
    }
    return (udp, tcp)
}

private func legCandidate(id: String) -> [String: Any] {
    let config = #"{"outbound":{"protocol":"freedom","tag":"leg-out"},"dns":[]}"#
    return ["id": id, "kind": "xray_leg", "config": config, "entry": NSNull(), "reach_at_ms": -1, "profile_id": NSNull(),
            "early_retry": false, "dns_plan": false, "cost_bytes": 83456]
}

private func liveStartRequest(scanId: String, candidates: [[String: Any]], awgHandshakeMs: Int) -> [UInt8] {
    let start: [String: Any] = [
        "action": "scan_start", "version": "tribe-scan-v1", "scan_id": scanId, "deadline_ms": 9000, "max_bytes": 400000,
        "limits": ["stage1_sockets": 4, "stage1_stagger_ms": 0, "per_entry_ip": 1, "entry_ip_spacing_ms": 0,
                   "stage1_timeout_ms": 500, "concurrency": 1, "leg_concurrency": 2, "awg_concurrency": 2,
                   "awg_handshake_ms": awgHandshakeMs, "awg_prime_echoes": 0, "awg_spacing_ms": 50, "ttfb_ms": 1000,
                   "stall_ms": 500, "stall_after_bytes": 16384, "total_ms": 6000,
                   // above max_bytes: the grant cannot cover an access attempt, so none is made (its TCP socket is
                   // not a probe's and may outlive StopAll by design) - every socket counted below is a probe's
                   "netinfo_cost_bytes": 1048576] as [String: Any],
        "probe": ["base": "https://127.0.0.1:9", "path": "/v1/probe", "netinfo_path": "/v1/netinfo", "token": "replay-token",
                  "warm_bytes": 1024, "bytes": 65536, "access_asn": NSNull(), "access_net_token": NSNull()] as [String: Any],
        "candidates": candidates,
    ]
    return [UInt8]((try? JSONSerialization.data(withJSONObject: start, options: [.sortedKeys])) ?? Data())
}

/// Review F3: stop-all during an AmneziaWG session that is waiting for its handshake, and right after a leg
/// probe ended (its instance cleanup), on loopback. When StopAll says stopped, nothing of the scan may be alive:
/// asserted here through the process's sockets at the moment of the answer (the engine's own LiveInstances counter
/// is asserted by the engine's Go tests, it is not a C export).
/// StopAll answered stopped: nothing of the scan may be open at that moment (review F3; strict).
private func expectNothingLeft(_ ok: Bool, _ message: String) { expect(ok, message) }

private func testStopAllLeavesNothing() {
    let base = socketCounts()

    // 1. An AmneziaWG session alive (handshake wait 5 s to a closed UDP port of 127.0.0.1), stopped 10 times:
    //    rounds 1-5 by the stop-all hooks (under the gate), rounds 6-10 by the adapter's backend-restart path
    //    (stopForBackendRestart: no gate, synchronous, bounded) - when it returns, the backend operation runs.
    var f = Fixture()
    for round in 1...10 {
        f = Fixture()
        f.live = .known("{\"public_key\":\"\(hex(0x40))\"}")
        let port = closedUDPPort()
        let ack = f.send(liveStartRequest(scanId: "stop-awg-\(round)",
                                          candidates: [awgCandidate(id: "awg-1", peerKey: hex(0x90), port: port, boundIf: f.loopback)],
                                          awgHandshakeMs: 5000))
        expect(ack?["type"] as? String == "scan_ack", "stop test \(round): awg scan accepted \(ack ?? [:])")
        var during = socketCounts()
        let until = Date().addingTimeInterval(2)
        while during.udp <= base.udp && Date() < until {
            usleep(20_000)
            during = socketCounts()
        }
        expect(during.udp > base.udp, "stop test \(round): the AmneziaWG session holds its UDP socket (\(base.udp) -> \(during.udp))")
        let t0 = Date()
        let backendPath = round > 5
        let stopped = backendPath ? f.host.stopForBackendRestart(reason: "replay_backend_restart") : f.host.stopAll(reason: "replay_awg")
        let after = socketCounts()
        let bound = backendPath ? 0.7 : 2.5
        expect(stopped && Date().timeIntervalSince(t0) < bound,
               "stop test \(round) (\(backendPath ? "backend restart" : "stop-all")): stopped within \(bound) s")
        expectNothingLeft(!stopped || after.udp <= base.udp,
                          "stop test \(round): StopAll said stopped with AmneziaWG sockets open (udp \(base.udp) -> \(after.udp))")
        // Whatever it said, the sockets close shortly after (no leak).
        let leakUntil = Date().addingTimeInterval(2)
        while socketCounts().udp > base.udp && Date() < leakUntil { usleep(20_000) }
        expect(socketCounts().udp <= base.udp, "stop test \(round): the AmneziaWG sockets are closed within 2 s")
    }

    // 2. Right after a leg probe ended: the leg instance's cleanup is in flight.
    f = Fixture()
    let ack2 = f.send(liveStartRequest(scanId: "stop-leg", candidates: [legCandidate(id: "leg-1")], awgHandshakeMs: 1500))
    expect(ack2?["type"] as? String == "scan_ack", "stop test: leg scan accepted \(ack2 ?? [:])")
    var item: [String: Any]?
    let legUntil = Date().addingTimeInterval(4)
    repeat {
        usleep(20_000)
        let p = f.send(#"{"action":"scan_poll","scan_id":"stop-leg","since":0}"#)
        item = (p?["items"] as? [[String: Any]] ?? []).first { $0["stage"] as? String == "data" }
    } while item == nil && Date() < legUntil
    expect(item != nil, "the leg probe ended (\(item?["error"] ?? "no item"))")
    let stoppedLeg = f.host.stopForBackendRestart(reason: "replay_leg_backend_restart")
    let afterLeg = socketCounts()
    expect(stoppedLeg, "StopAll during the leg cleanup: stopped")
    expectNothingLeft(!stoppedLeg || (afterLeg.udp <= base.udp && afterLeg.tcp <= base.tcp),
                      "StopAll said stopped with leg sockets open (udp \(base.udp) -> \(afterLeg.udp), tcp \(base.tcp) -> \(afterLeg.tcp))")
    // The host's stop check (wait 0) after a finished stop: always stopped, every time (no timer race).
    var checksStopped = 0
    for _ in 0..<200 where TribeScanHost.stopped(engine.stopAll(waitMs: TribeScanHost.stopCheckWaitMs, epoch: f.host.lifecycle.epoch)) {
        checksStopped += 1
    }
    expect(checksStopped == 200, "200 stop checks with wait 0 after a finished stop: all stopped (\(checksStopped))")

    // A start older than the last stop: the engine itself refuses it (its own safety net, stale_epoch).
    let staleEpoch = f.host.lifecycle.epoch - 1
    let stale = object(engine.message(liveStartRequest(scanId: "stale", candidates: [], awgHandshakeMs: 1500),
                                      hostOptions: TribeScanHost.hostOptions(element: f.generation.element, epoch: staleEpoch,
                                                                             bindIndex: f.loopback)))
    expect(stale?["error"] as? String == "stale_epoch" && stale?["detail"] as? String == "host_epoch",
           "the engine refuses a start older than the last stop: \(stale ?? [:])")
}

private func closedUDPPort() -> Int {
    var udp = sockaddr_in()
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    defer { close(fd) }
    udp.sin_family = sa_family_t(AF_INET)
    udp.sin_addr.s_addr = inet_addr("127.0.0.1")
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafePointer(to: &udp) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
    _ = withUnsafeMutablePointer(to: &udp) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
    return Int(UInt16(bigEndian: udp.sin_port))
}

@main
struct ScanEngineReplayTests {
    static func main() {
        let args = CommandLine.arguments
        guard args.count >= 2 else {
            fputs("usage: scan_engine_replay <vectors dir>\n", stderr)
            exit(2)
        }
        let f = Fixture()
        testCaps(f)
        replayRequests(args[1], f)
        testLiveScan(f)
        testAwgMiniLoopback()
        testStopAllLeavesNothing()
        if failures > 0 {
            fputs("Scan engine replay: \(failures) of \(checks) checks FAILED\n", stderr)
            exit(1)
        }
        print("Scan engine replay passed (\(checks) checks, real engine)")
    }
}

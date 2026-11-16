import Darwin
import Foundation

// AVPN (Scanner, lane L4; plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md v2.2 §2.2-§2.3, §2.11a):
// the extension's side of the probe host contract `tribe-scan-v1` (owner: client/core/serviceEngine/
// ScanHostContract.h). The Go engine (awg-apple patch 0013, ABI libxray-tribe-scan-v1) answers every contract
// message; this layer relays them and adds only what the extension alone knows:
//  - host options: with EVERY relayed message the extension's generation element (`gen`, the engine stamps
//    progress and access attempts with the latest one); with scan_start also the physical interface index (Go
//    binds every probe socket to it itself; nothing here touches a probe socket, the tunnel's socket callback
//    or the tunnel's failure path) and, on an AmneziaWG tunnel, the live peer (`awg_live_peer`: the AWG runner
//    refuses that node). A start or add with awg_mini candidates on an AmneziaWG tunnel whose live peer is not
//    known is refused here ({"error":"internal","detail":"awg_live_peer_unknown"}): the runner never runs blind;
//  - the extension's element of the strict network generation tuple ({"source":"ne", epoch, counter},
//    ScanNetworkGeneration.h) as `gen` of scan_progress, of each access attempt made while the path did not move
//    since scan_start, and of scan_caps (a host addition: the app learns the element before its first scan);
//  - the pools of scan_caps lowered to the memory headroom of this moment (os_proc_available_memory; the
//    awg_mini pool too: no headroom for one session = pool 0 and no awg_mini kind);
//  - stop-all under the lifecycle gate before the tunnel core stops, restarts or changes peer, with the provider's
//    tunnel-change epoch (TribeScanLifecycle, review F1): every stop bumps it, a start carries the epoch of its
//    receipt and is refused ("tunnel_changed") when it moved before the engine call, the host is closed ("no_vpn")
//    from stopTunnel until the next successful startTunnel, and a stop the engine did not finish ("stopped":false)
//    keeps new scans out until a later stop check says stopped (review F3). Every message carries host_epoch.
// Reply bytes stay the engine's bytes: an addition is a splice into the top-level JSON object (or into an
// access attempt object), nothing else changes. No logging of configs, hosts or tokens: action names, scan ids,
// sizes and codes only.
//
// Foundation/Darwin only, host-tested by tests/ScanBridgeTests.swift (run_ios_swift_checks.sh). The provider
// glue (C symbols, path monitor, call sites) is PacketTunnelProvider+Scan.swift.

// MARK: - network generation element

/// One element of the strict generation tuple: the extension's own path monitor.
struct TribeScanNetElement: Equatable {
    static let source = "ne"
    let epoch: UInt64
    let counter: Int64

    var epochHex: String { String(format: "%016llx", epoch) }
    /// Wire form (ScanNetworkGeneration.h::scanNetSourceToJson): the epoch is a 16-hex string.
    var json: String { "{\"source\":\"\(Self.source)\",\"epoch\":\"\(epochHex)\",\"counter\":\(max(0, counter))}" }
}

/// What the path monitor saw, reduced to the facts the counter follows (plan §2.11a): whether the path is
/// usable, the physical interfaces it uses, their addresses and the gateways. Kept in memory as a hash only.
struct TribeScanPathFacts: Equatable {
    var satisfied: Bool
    var interfaces: [String]   // "type:name:index"
    var addresses: [String]    // "name/numeric address"
    var gateways: [String]

    var signature: String {
        "s=\(satisfied ? 1 : 0)|i=\(interfaces.sorted().joined(separator: ","))"
            + "|a=\(addresses.sorted().joined(separator: ","))|g=\(gateways.sorted().joined(separator: ","))"
    }

    /// Numeric addresses of the named interfaces (getifaddrs), "name/address".
    static func addresses(ofInterfaces names: Set<String>) -> [String] {
        guard !names.isEmpty else { return [] }
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var out: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let addr = entry.pointee.ifa_addr else { continue }
            let family = Int32(addr.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            let name = String(cString: entry.pointee.ifa_name)
            guard names.contains(name) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let length = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(addr, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            out.append("\(name)/\(String(cString: host))")
        }
        return out
    }
}

/// The extension's generation source: a random 64-bit epoch chosen when it starts, a counter that grows on
/// every change of the path signature (the first update is the baseline). The counter never goes back, so an
/// unchanged element between two moments proves the path did not move in between. Thread-safe.
final class TribeScanPathGeneration {
    let epoch: UInt64
    private let lock = NSLock()
    private var counter: Int64 = 0
    private var lastSignature: Int?

    init(epoch: UInt64 = UInt64.random(in: UInt64.min...UInt64.max)) {
        self.epoch = epoch
    }

    /// One path update. true = the counter moved.
    @discardableResult
    func observe(signature: String) -> Bool {
        let hash = signature.hashValue
        lock.lock()
        defer { lock.unlock() }
        guard let last = lastSignature else {
            lastSignature = hash
            return false
        }
        guard last != hash else { return false }
        lastSignature = hash
        counter += 1
        return true
    }

    var element: TribeScanNetElement {
        lock.lock()
        defer { lock.unlock() }
        return TribeScanNetElement(epoch: epoch, counter: counter)
    }
}

// MARK: - memory headroom -> pools of scan_caps

/// The pools this extension can afford now. The engine (Go) has its own guard: no instance below 12 MB of
/// headroom, the scan ends below 8 MB while one runs; these pools keep a scan inside it instead of failing.
/// From the Mac measurements of recipes/awg-apple/README.md: one leg instance +3.4 MB with 12 legs ("Memory");
/// awg_mini sessions RSS +5.1-5.5 MB with 1, +6.9-7.2 with 2, +10.2-10.3 with 4 on 18 cores ("awg_mini":
/// amneziawg-go runs 3 workers per CPU, an iPhone has 6 - an upper bound). Device gates G1/G2/G5 replace them.
enum TribeScanCapsPolicy {
    static let startFloorMB = 12.0   // = the engine's start guard (os_proc_available_memory before an instance)
    static let runFloorMB = 8.0      // = the engine's run guard
    static let legInstanceMB = 3.5   // one shared leg instance
    static let perLegMB = 1.0        // one leg probe in flight (TLS state and buffers), conservative
    static let firstAwgSessionMB = 5.5 // the first awg_mini session (its device, netstack and workers)
    static let perAwgSessionMB = 2.0   // each further session

    struct Pools: Equatable {
        var full = 0
        var leg = 0
        var awg = 0
    }

    /// nil headroom (not an iOS extension, e.g. the host test) = the engine's pools as they are.
    static func pools(engine: Pools, availableMB: Double?) -> Pools {
        guard let mb = availableMB, mb.isFinite else { return engine }
        guard mb >= startFloorMB else { return Pools() }
        let spare = mb - runFloorMB
        let legs = Int(((spare - legInstanceMB) / perLegMB).rounded(.down))
        let awg = spare >= firstAwgSessionMB ? 1 + Int(((spare - firstAwgSessionMB) / perAwgSessionMB).rounded(.down)) : 0
        return Pools(full: max(0, engine.full),
                     leg: max(0, min(engine.leg, legs)),
                     awg: max(0, min(engine.awg, awg)))
    }
}

// MARK: - JSON spans (read and splice the engine's reply without re-encoding it)

enum TribeScanJSON {
    struct Member {
        let key: String
        let value: Range<Int>
    }

    struct Object {
        let open: Int   // index of "{"
        let close: Int  // index of "}"
        let members: [Member]

        func value(_ key: String) -> Range<Int>? { members.first { $0.key == key }?.value }
    }

    struct Edit {
        let range: Range<Int>
        let bytes: [UInt8]
    }

    private static let quote = UInt8(ascii: "\"")
    private static let backslash = UInt8(ascii: "\\")
    private static let openBrace = UInt8(ascii: "{")
    private static let closeBrace = UInt8(ascii: "}")
    private static let openBracket = UInt8(ascii: "[")
    private static let closeBracket = UInt8(ascii: "]")
    private static let colon = UInt8(ascii: ":")
    private static let comma = UInt8(ascii: ",")

    private static func isSpace(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D }

    private static func skipSpace(_ b: [UInt8], _ from: Int, _ end: Int) -> Int {
        var i = from
        while i < end, isSpace(b[i]) { i += 1 }
        return i
    }

    /// `start` at an opening quote; the index after the closing quote.
    private static func stringEnd(_ b: [UInt8], _ start: Int, _ end: Int) -> Int? {
        var i = start + 1
        while i < end {
            if b[i] == backslash { i += 2; continue }
            if b[i] == quote { return i + 1 }
            i += 1
        }
        return nil
    }

    private static func valueEnd(_ b: [UInt8], _ start: Int, _ end: Int) -> Int? {
        guard start < end else { return nil }
        let c = b[start]
        if c == quote { return stringEnd(b, start, end) }
        if c == openBrace || c == openBracket {
            var depth = 0
            var i = start
            while i < end {
                let x = b[i]
                if x == quote {
                    guard let e = stringEnd(b, i, end) else { return nil }
                    i = e
                    continue
                }
                if x == openBrace || x == openBracket {
                    depth += 1
                } else if x == closeBrace || x == closeBracket {
                    depth -= 1
                    if depth == 0 { return i + 1 }
                }
                i += 1
            }
            return nil
        }
        var i = start
        while i < end, !isSpace(b[i]), b[i] != comma, b[i] != closeBrace, b[i] != closeBracket { i += 1 }
        return i > start ? i : nil
    }

    /// The object whose "{" is the first non-space byte of `range`, its members in order.
    static func object(_ b: [UInt8], in range: Range<Int>) -> Object? {
        let end = range.upperBound
        var i = skipSpace(b, range.lowerBound, end)
        guard i < end, b[i] == openBrace else { return nil }
        let open = i
        var members: [Member] = []
        i = skipSpace(b, i + 1, end)
        guard i < end else { return nil }
        if b[i] == closeBrace { return Object(open: open, close: i, members: []) }
        while true {
            guard i < end, b[i] == quote, let keyEnd = stringEnd(b, i, end),
                  let key = string(b, i..<keyEnd) else { return nil }
            i = skipSpace(b, keyEnd, end)
            guard i < end, b[i] == colon else { return nil }
            i = skipSpace(b, i + 1, end)
            guard let vEnd = valueEnd(b, i, end) else { return nil }
            members.append(Member(key: key, value: i..<vEnd))
            i = skipSpace(b, vEnd, end)
            guard i < end else { return nil }
            if b[i] == comma {
                i = skipSpace(b, i + 1, end)
                continue
            }
            guard b[i] == closeBrace else { return nil }
            return Object(open: open, close: i, members: members)
        }
    }

    /// The element value ranges of the array whose "[" is the first non-space byte of `range` ([] when it is not
    /// an array).
    static func elements(_ b: [UInt8], in range: Range<Int>) -> [Range<Int>] {
        let end = range.upperBound
        var i = skipSpace(b, range.lowerBound, end)
        guard i < end, b[i] == openBracket else { return [] }
        var out: [Range<Int>] = []
        i = skipSpace(b, i + 1, end)
        if i < end, b[i] == closeBracket { return [] }
        while i < end {
            guard let vEnd = valueEnd(b, i, end) else { return [] }
            out.append(i..<vEnd)
            i = skipSpace(b, vEnd, end)
            guard i < end else { return [] }
            if b[i] == comma {
                i = skipSpace(b, i + 1, end)
                continue
            }
            return b[i] == closeBracket ? out : []
        }
        return []
    }

    /// The top-level object of a whole message (only spaces may follow it).
    static func topLevel(_ b: [UInt8]) -> Object? {
        guard let o = object(b, in: 0..<b.count), skipSpace(b, o.close + 1, b.count) == b.count else { return nil }
        return o
    }

    /// A string value (with its quotes in `range`) decoded; nil when it is not a string.
    static func string(_ b: [UInt8], _ range: Range<Int>) -> String? {
        guard range.count >= 2, b[range.lowerBound] == quote, b[range.upperBound - 1] == quote else { return nil }
        let inner = b[(range.lowerBound + 1)..<(range.upperBound - 1)]
        if !inner.contains(backslash) { return String(decoding: inner, as: UTF8.self) }
        return (try? JSONSerialization.jsonObject(with: Data(b[range]), options: [.fragmentsAllowed])) as? String
    }

    static func isLiteral(_ b: [UInt8], _ range: Range<Int>, _ literal: String) -> Bool {
        Array(b[range]) == Array(literal.utf8)
    }

    /// An integer value; nil for anything else (fraction, exponent, string, null).
    static func int(_ b: [UInt8], _ range: Range<Int>) -> Int? {
        guard !range.isEmpty, range.count <= 19 else { return nil }
        var i = range.lowerBound
        let negative = b[i] == UInt8(ascii: "-")
        if negative { i += 1 }
        guard i < range.upperBound else { return nil }
        var v = 0
        while i < range.upperBound {
            let c = b[i]
            guard c >= UInt8(ascii: "0"), c <= UInt8(ascii: "9") else { return nil }
            v = v * 10 + Int(c - UInt8(ascii: "0"))
            i += 1
        }
        return negative ? -v : v
    }

    /// Absent or null.
    static func isAbsentOrNull(_ o: Object, _ b: [UInt8], _ key: String) -> Bool {
        guard let r = o.value(key) else { return true }
        return isLiteral(b, r, "null")
    }

    /// Edits that set members of `o`: a present member gets its value replaced, absent ones are appended in
    /// one insertion before "}" (in the order given).
    static func setMembers(_ o: Object, _ pairs: [(key: String, raw: String)]) -> [Edit] {
        var edits: [Edit] = []
        var appended: [String] = []
        for pair in pairs {
            if let r = o.value(pair.key) {
                edits.append(Edit(range: r, bytes: Array(pair.raw.utf8)))
            } else {
                appended.append("\"\(pair.key)\":\(pair.raw)")
            }
        }
        if !appended.isEmpty {
            let text = (o.members.isEmpty ? "" : ",") + appended.joined(separator: ",")
            edits.append(Edit(range: o.close..<o.close, bytes: Array(text.utf8)))
        }
        return edits
    }

    /// Non-overlapping edits applied from the end, so earlier ranges stay valid.
    static func apply(_ b: [UInt8], _ edits: [Edit]) -> [UInt8] {
        var out = b
        for e in edits.sorted(by: { $0.range.lowerBound > $1.range.lowerBound }) {
            out.replaceSubrange(e.range, with: e.bytes)
        }
        return out
    }
}

// MARK: - the engine (C ABI libxray-tribe-scan-v1)

/// The two C exports of the engine. Each returns malloc'd JSON (never NULL by the ABI) that is released here,
/// exactly once, after it was copied.
struct TribeScanEngine {
    typealias MessageFn = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    typealias StopAllFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?

    let messageFn: MessageFn
    let stopAllFn: StopAllFn
    var release: (UnsafeMutablePointer<CChar>) -> Void = { free($0) }

    static let internalError = Array(#"{"error":"internal"}"#.utf8)

    /// The request bytes go to the engine exactly as given (plus the terminating NUL of a C string).
    func message(_ request: [UInt8], hostOptions: String?) -> [UInt8] {
        var buffer = request
        buffer.append(0)
        let raw: UnsafeMutablePointer<CChar>? = buffer.withUnsafeBufferPointer { bytes in
            bytes.withMemoryRebound(to: CChar.self) { chars in
                guard let hostOptions else { return messageFn(chars.baseAddress, nil) }
                return hostOptions.withCString { messageFn(chars.baseAddress, $0) }
            }
        }
        return take(raw)
    }

    /// The host-only stop through the message channel (engine >= 462177993): the engine remembers `epoch` first
    /// (a later scan_start / scan_add with a lower host_epoch is refused stale_epoch), ends every scan and waits up
    /// to waitMs until nothing of it is alive: {"stopped":true}, or {"stopped":false} with the live counts as flat
    /// top-level numbers (instances, jobs, closers, attempts, awg, children; read: only "stopped"). An engine that
    /// does not know the action (an older
    /// package: unknown_action) gets the plain LibXrayTribeScanStopAll instead.
    func stopAll(waitMs: Int64, epoch: UInt64) -> [UInt8] {
        let reply = message(Array("{\"action\":\"scan_stop_all\",\"wait_ms\":\(max(0, waitMs))}".utf8),
                            hostOptions: "{\"host_epoch\":\(epoch)}")
        if let o = TribeScanJSON.topLevel(reply), let er = o.value("error"),
           TribeScanJSON.string(reply, er) == "unknown_action" {
            return take(stopAllFn(waitMs))
        }
        return reply
    }

    private func take(_ raw: UnsafeMutablePointer<CChar>?) -> [UInt8] {
        guard let raw else { return Self.internalError }
        defer { release(raw) }
        let count = strlen(raw)
        return raw.withMemoryRebound(to: UInt8.self, capacity: count + 1) {
            Array(UnsafeBufferPointer(start: $0, count: count))
        }
    }
}

// MARK: - the provider's tunnel lifecycle as the scan host sees it (review F1, F3)

/// The tunnel-change epoch, the closed state and the "not stopped" state, owned by the provider (one per provider,
/// made before any host). Thread-safe. Every stop-all hook bumps the epoch under the lifecycle gate; a start
/// compares the epoch of its receipt under the gate right before the engine call.
final class TribeScanLifecycle {
    private let lock = NSLock()
    private var epochStorage: UInt64 = 1
    private var closedStorage = false
    private var uncleanStorage = false
    private var closesStorage: UInt64 = 0 // closing stops (stopTunnel) so far

    var epoch: UInt64 { lock.lock(); defer { lock.unlock() }; return epochStorage }
    /// From stopTunnel until the next successful startTunnel: every start is refused (no_vpn).
    var closed: Bool { lock.lock(); defer { lock.unlock() }; return closedStorage }
    /// The engine's last stop-all said "stopped":false: no new scan until a stop check says stopped.
    var unclean: Bool { lock.lock(); defer { lock.unlock() }; return uncleanStorage }

    /// A tunnel change: every start received before it is stale. close = stopTunnel.
    @discardableResult
    func bump(close: Bool) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        epochStorage &+= 1
        if close {
            closedStorage = true
            closesStorage &+= 1
        }
        return epochStorage
    }

    /// Taken when a tunnel start begins (review R1): its success may reopen the host only if no stopTunnel came
    /// in between.
    var reopenToken: UInt64 { lock.lock(); defer { lock.unlock() }; return closesStorage }

    /// The tunnel start that took `token` succeeded: the host opens again - unless a stopTunnel closed it after the
    /// token was taken (a stop always wins over a late start completion). true = opened.
    @discardableResult
    func reopen(token: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard closesStorage == token else { return false }
        closedStorage = false
        return true
    }

    func setUnclean(_ unclean: Bool) {
        lock.lock()
        uncleanStorage = unclean
        lock.unlock()
    }
}

/// The engine's stop answer, handed from its helper thread to the waiting adapter queue.
final class TribeScanStopBox {
    private let lock = NSLock()
    private var storage = false
    func set(_ v: Bool) { lock.lock(); storage = v; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return storage }
}

// MARK: - the relay

/// What the provider knows about its path when a scan starts.
struct TribeScanPathInfo {
    let bindIndex: UInt32   // the physical interface the tunnel's own sockets use (0 = none known)
    let satisfied: Bool     // the path is usable now
    let element: TribeScanNetElement
}

final class TribeScanHost {
    static let relayedActions: Set<String> = ["scan_caps", "scan_start", "scan_add", "scan_poll", "scan_freeze",
                                              "scan_cancel"]
    /// Host-local action of the app adapter's IScanHost::stopAll (not a contract action; the engine never sees it).
    static let stopAllAction = "scan_stop_all"
    static let stopAllWaitMs: Int64 = 2000
    /// The AWG mini runner (awg-apple patch 0014) is offered: caps pass the engine's awg_mini pool through, lowered
    /// by TribeScanCapsPolicy. The app gates it (server switch, concurrency number, manifest flag). false would
    /// close the pool and drop the kind whatever the engine says.
    static let awgMiniOffered = true

    static let unknownActionReply = Data(#"{"error":"unknown_action"}"#.utf8)
    static let noPathReply = Data(#"{"error":"bad_request","detail":"host_options.bind_interface"}"#.utf8)
    static let badJSONReply = Data(#"{"error":"bad_request","detail":"json"}"#.utf8)
    /// A start or add with awg_mini candidates on an AmneziaWG tunnel whose live peer could not be read: never
    /// relayed (the runner could not refuse the live node). Contract pattern: internal + a detail naming the cause.
    static let livePeerUnknownReply = Data(#"{"error":"internal","detail":"awg_live_peer_unknown"}"#.utf8)
    /// The tunnel stopped, restarted or changed peer after this start (or add) was received: never relayed.
    static let tunnelChangedReply = Data(#"{"error":"tunnel_changed"}"#.utf8)
    /// The host is closed: stopTunnel ran and no startTunnel succeeded since.
    static let noVpnReply = Data(#"{"error":"no_vpn"}"#.utf8)
    /// The engine's last stop-all did not finish and a stop check still says not stopped: no new scan yet.
    static let stopPendingReply = Data(#"{"error":"internal","detail":"stop_pending"}"#.utf8)
    /// The wait of the stop check before a start after an unfinished stop-all: 0 - the engine answers at once and
    /// deterministically (a finished teardown is pruned before its wait; nothing to race with).
    static let stopCheckWaitMs: Int64 = 0

    /// The live tunnel as the AWG runner must know it.
    enum LivePeer: Equatable {
        case notAmneziaWG           // Xray / OpenVPN: no AmneziaWG peer to protect
        case known(String)          // the awg_live_peer object (JSON text)
        case unknown                // AmneziaWG, but its current peer could not be read
    }

    private let engine: TribeScanEngine
    private let gate: XrayNativeLifecycleGate
    private let path: () -> TribeScanPathInfo
    private let availableMB: () -> Double?
    private let liveAwgPeer: () -> LivePeer
    private let log: (String) -> Void
    let lifecycle: TribeScanLifecycle

    private let lock = NSLock()
    private var startedAny = false
    private var startElements: [(scanId: String, element: TribeScanNetElement)] = []
    private var livePeerUnknownScans: [String] = [] // scans started on AmneziaWG without a known live peer
    private var startEpochs: [(scanId: String, epoch: UInt64)] = [] // the epoch each relayed start was received in

    /// liveAwgPeer: the live tunnel's AmneziaWG peer; asked once per scan_start, before the lifecycle gate (it may
    /// wait for the WireGuard adapter).
    init(engine: TribeScanEngine, gate: XrayNativeLifecycleGate, lifecycle: TribeScanLifecycle = TribeScanLifecycle(),
         path: @escaping () -> TribeScanPathInfo, availableMB: @escaping () -> Double?,
         liveAwgPeer: @escaping () -> LivePeer = { .notAmneziaWG }, log: @escaping (String) -> Void) {
        self.lifecycle = lifecycle
        self.engine = engine
        self.gate = gate
        self.path = path
        self.availableMB = availableMB
        self.liveAwgPeer = liveAwgPeer
        self.log = log
    }

    /// Host options of one relayed message: `gen` and `host_epoch` always, the start-only fields when given.
    static func hostOptions(element: TribeScanNetElement, epoch: UInt64, bindIndex: UInt32? = nil,
                            awgLivePeer: String? = nil) -> String {
        var parts: [String] = []
        if let bindIndex { parts.append("\"bind_interface_index\":\(bindIndex)") }
        parts.append("\"gen\":\(element.json)")
        parts.append("\"host_epoch\":\(epoch)")
        if let awgLivePeer { parts.append("\"awg_live_peer\":\(awgLivePeer)") }
        return "{" + parts.joined(separator: ",") + "}"
    }

    /// The live peer of a WireGuard runtime configuration (UAPI text of WireGuardAdapter.getRuntimeConfiguration):
    /// the first peer's public key (64 hex) and endpoint, as the `awg_live_peer` object; nil when there is no
    /// usable peer. The private key and everything else in the text are ignored; nothing of it is logged.
    static func awgLivePeerJSON(fromUAPI uapi: String) -> String? {
        var key: String?
        var endpoint: String?
        for raw in uapi.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            guard let eq = raw.firstIndex(of: "=") else { continue }
            let name = raw[..<eq]
            let value = String(raw[raw.index(after: eq)...])
            if name == "public_key" {
                if key != nil { break } // the next peer: only the first one is the live tunnel's
                guard value.count == 64, value.allSatisfy({ $0.isHexDigit }) else { return nil }
                key = value.lowercased()
            } else if name == "endpoint", key != nil, endpoint == nil, !value.isEmpty, value.count <= 64 {
                endpoint = value
            }
        }
        guard let key else { return nil }
        var peer: [String: String] = ["public_key": key]
        if let endpoint { peer["endpoint"] = endpoint }
        guard let data = try? JSONSerialization.data(withJSONObject: peer, options: [.sortedKeys, .withoutEscapingSlashes])
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// A scan message of the app: a JSON object whose "action" is a string starting with "scan_". Anything else
    /// is not this host's (nil): the provider's own dispatch handles it.
    static func scanMessage(of data: Data) -> (action: String, bytes: [UInt8])? {
        guard data.count >= 16, data.range(of: Data("\"scan_".utf8)) != nil else { return nil }
        let bytes = [UInt8](data)
        guard let o = TribeScanJSON.topLevel(bytes), let r = o.value("action"),
              let action = TribeScanJSON.string(bytes, r), action.hasPrefix("scan_") else { return nil }
        return (action, bytes)
    }

    /// Whether a scan_start / scan_add carries an awg_mini candidate.
    static func hasAwgMini(_ request: [UInt8]) -> Bool {
        guard let o = TribeScanJSON.topLevel(request), let cr = o.value("candidates") else { return false }
        for element in TribeScanJSON.elements(request, in: cr) {
            if let c = TribeScanJSON.object(request, in: element), let kr = c.value("kind"),
               TribeScanJSON.string(request, kr) == "awg_mini" { return true }
        }
        return false
    }

    /// One scan message, answered synchronously (the provider runs it off its message handler). receivedEpoch = the
    /// lifecycle epoch when the provider received it (nil = now).
    func handle(_ request: [UInt8], action: String, receivedEpoch: UInt64? = nil) -> Data {
        let received = receivedEpoch ?? lifecycle.epoch
        if action == Self.stopAllAction {
            let stopped = stopAll(reason: "app")
            return Data("{\"type\":\"scan_stop_all_ack\",\"stopped\":\(stopped)}".utf8)
        }
        guard Self.relayedActions.contains(action) else {
            log("Tribe scan: unknown action \(Self.safeToken(action))")
            return Self.unknownActionReply
        }
        guard !request.contains(0) else { return Self.badJSONReply }
        switch action {
        case "scan_start":
            return start(request, received: received)
        case "scan_add":
            let scanId = Self.requestScanId(request)
            if let scanId, livePeerUnknown(scanId), Self.hasAwgMini(request) {
                log("Tribe scan: add scan=\(Self.safeToken(scanId)) refused: awg_mini without the live AmneziaWG peer")
                return Self.livePeerUnknownReply
            }
            // May launch probe instances: never inside a stop sequence, never into a scan of another tunnel state.
            let reply: [UInt8]? = gate.withExclusive {
                if lifecycle.closed || lifecycle.unclean { return nil }
                let epochNow = lifecycle.epoch
                if let scanId, let started = startEpoch(of: scanId), started != epochNow { return nil }
                if received != epochNow { return nil }
                return engine.message(request, hostOptions: Self.hostOptions(element: path().element, epoch: epochNow))
            }
            guard let reply else {
                log("Tribe scan: add scan=\(Self.safeToken(scanId ?? "")) refused: the tunnel changed or the host is closed")
                return lifecycle.closed ? Self.noVpnReply : Self.tunnelChangedReply
            }
            log("Tribe scan: add request_bytes=\(request.count) reply=\(Self.replyKind(reply))")
            return Data(decorate(reply))
        default:
            let reply = engine.message(request, hostOptions: Self.hostOptions(element: path().element, epoch: lifecycle.epoch))
            if action != "scan_poll" {
                log("Tribe scan: \(action) reply=\(Self.replyKind(reply))")
            }
            return Data(decorate(reply))
        }
    }

    private enum StartRefusal { case closed, changed, stopPending, noPath }

    private func start(_ request: [UInt8], received: UInt64) -> Data {
        let scanId = Self.requestScanId(request)
        if lifecycle.closed { return refuse(scanId, .closed) }
        if lifecycle.epoch != received { return refuse(scanId, .changed) }
        let live = liveAwgPeer() // before the gate: it may wait for the WireGuard adapter's queue
        if live == .unknown && Self.hasAwgMini(request) {
            log("Tribe scan: start scan=\(Self.safeToken(scanId ?? "")) refused: awg_mini without the live AmneziaWG peer")
            return Self.livePeerUnknownReply
        }
        var livePeer: String?
        if case .known(let peer) = live { livePeer = peer }
        // Under the gate: a start never interleaves with a stop sequence of the tunnel core, and a stop that came
        // while it waited (for the peer read or for the gate) makes it stale.
        let result: Result<(reply: [UInt8], bindIndex: UInt32), StartRefusalError> = gate.withExclusive {
            if lifecycle.closed { return .failure(StartRefusalError(.closed)) }
            if lifecycle.epoch != received { return .failure(StartRefusalError(.changed)) }
            if lifecycle.unclean {
                // A stop check: the last stop-all did not finish; only a "stopped" answer lets a new scan in.
                guard Self.stopped(engine.stopAll(waitMs: Self.stopCheckWaitMs, epoch: lifecycle.epoch)) else {
                    return .failure(StartRefusalError(.stopPending))
                }
                lifecycle.setUnclean(false)
                log("Tribe scan: stop check stopped=true; new scans allowed again")
            }
            let info = path()
            guard info.satisfied, info.bindIndex > 0 else { return .failure(StartRefusalError(.noPath)) }
            lock.lock()
            startedAny = true
            if let scanId {
                startElements.removeAll { $0.scanId == scanId }
                startElements.append((scanId, info.element))
                if startElements.count > 4 { startElements.removeFirst(startElements.count - 4) }
                livePeerUnknownScans.removeAll { $0 == scanId }
                if live == .unknown { livePeerUnknownScans.append(scanId) }
                if livePeerUnknownScans.count > 4 { livePeerUnknownScans.removeFirst(livePeerUnknownScans.count - 4) }
                startEpochs.removeAll { $0.scanId == scanId }
                startEpochs.append((scanId, received))
                if startEpochs.count > 4 { startEpochs.removeFirst(startEpochs.count - 4) }
            }
            lock.unlock()
            let options = Self.hostOptions(element: info.element, epoch: received, bindIndex: info.bindIndex,
                                           awgLivePeer: livePeer)
            return .success((engine.message(request, hostOptions: options), info.bindIndex))
        }
        let outcome: (reply: [UInt8], bindIndex: UInt32)
        switch result {
        case .failure(let refusal): return refuse(scanId, refusal.kind)
        case .success(let value): outcome = value
        }
        log("Tribe scan: start scan=\(Self.safeToken(scanId ?? "")) request_bytes=\(request.count) "
            + "bind_if=\(outcome.bindIndex) awg_live_peer=\(livePeer != nil) reply=\(Self.replyKind(outcome.reply))")
        return Data(decorate(outcome.reply))
    }

    private struct StartRefusalError: Error {
        let kind: StartRefusal
        init(_ kind: StartRefusal) { self.kind = kind }
    }

    private func refuse(_ scanId: String?, _ why: StartRefusal) -> Data {
        let id = Self.safeToken(scanId ?? "")
        switch why {
        case .closed:
            log("Tribe scan: start scan=\(id) refused: the tunnel is stopped (host closed)")
            return Self.noVpnReply
        case .changed:
            log("Tribe scan: start scan=\(id) refused: the tunnel changed after it was received")
            return Self.tunnelChangedReply
        case .stopPending:
            log("Tribe scan: start scan=\(id) refused: the last stop-all has not finished")
            return Self.stopPendingReply
        case .noPath:
            log("Tribe scan: start scan=\(id) refused: no physical path")
            return Self.noPathReply
        }
    }

    static func stopped(_ reply: [UInt8]) -> Bool {
        guard let o = TribeScanJSON.topLevel(reply), let r = o.value("stopped") else { return false }
        return TribeScanJSON.isLiteral(reply, r, "true")
    }

    /// Ends every running scan (engine reason tunnel_stopped) and waits up to 2 s for its probe instances, under
    /// the lifecycle gate, after bumping the tunnel-change epoch there (every start received before is stale;
    /// close = stopTunnel: no start until the next successful startTunnel). Called before the tunnel core stops,
    /// restarts or changes peer. The engine is asked only when a start ever reached it (read under the gate, so a
    /// start inside the engine at this moment is covered). "stopped":false = teardown goes on in the engine: the
    /// host refuses new scans until a later stop check says stopped; the tunnel change is never held past the
    /// 2 s bound.
    @discardableResult
    func stopAll(reason: String, close: Bool = false) -> Bool {
        let stopped: Bool = gate.withExclusive {
            lifecycle.bump(close: close)
            lock.lock()
            let started = startedAny
            lock.unlock()
            guard started else { return true }
            return Self.stopped(engine.stopAll(waitMs: Self.stopAllWaitMs, epoch: lifecycle.epoch))
        }
        lifecycle.setUnclean(!stopped)
        log("Tribe scan: stop-all reason=\(Self.safeToken(reason)) stopped=\(stopped)"
            + (stopped ? "" : "; teardown continues in the engine, new scans refused until a stop check says stopped"))
        return stopped
    }

    /// The engine wait of the WireGuard adapter's backend-restart stop (review F2), and the bound after which the
    /// adapter's queue is let go whatever the engine does.
    static let backendStopWaitMs: Int64 = 500
    static let backendStopBoundMs = 600

    /// The stop for the WireGuard adapter's own backend stop / pause / restart, on the adapter's work queue, right
    /// before the backend operation: WITHOUT the lifecycle gate (a gate holder may sit in the engine for seconds;
    /// the adapter's queue must not wait behind it), but synchronously, so the operation runs only after the
    /// engine reported nothing alive. The epoch moves first (a plain lock); the engine's scan_stop_all carries it,
    /// so a start inside the gate at this moment is refused by the engine (stale_epoch). The engine call runs on a
    /// helper thread and is awaited at most backendStopBoundMs: a hung engine never holds the adapter. Idempotent
    /// (the adapter may call several times per step). false = not stopped within the bound: journalled, new scans
    /// refused until a stop check says stopped.
    @discardableResult
    func stopForBackendRestart(reason: String) -> Bool {
        let epoch = lifecycle.bump(close: false)
        let engine = self.engine
        let done = DispatchSemaphore(value: 0)
        let box = TribeScanStopBox()
        DispatchQueue.global(qos: .userInitiated).async {
            box.set(Self.stopped(engine.stopAll(waitMs: Self.backendStopWaitMs, epoch: epoch)))
            done.signal()
        }
        let answered = done.wait(timeout: .now() + .milliseconds(Self.backendStopBoundMs)) == .success
        let stopped = answered && box.value
        lifecycle.setUnclean(!stopped)
        log("Tribe scan: stop-all reason=\(Self.safeToken(reason)) stopped=\(stopped)"
            + (answered ? "" : " (engine did not answer within \(Self.backendStopBoundMs) ms)")
            + (stopped ? "" : "; new scans refused until a stop check says stopped"))
        return stopped
    }

    // MARK: reply additions

    /// The engine's reply with the extension's additions (see the file comment); every other byte unchanged.
    func decorate(_ reply: [UInt8]) -> [UInt8] {
        guard let o = TribeScanJSON.topLevel(reply), o.value("error") == nil, let tr = o.value("type"),
              let type = TribeScanJSON.string(reply, tr) else { return reply }
        let element = path().element
        switch type {
        case "scan_caps":
            return TribeScanJSON.apply(reply, capsEdits(o, reply, element: element))
        case "scan_progress":
            return TribeScanJSON.apply(reply, progressEdits(o, reply, element: element))
        default:
            return reply
        }
    }

    private func capsEdits(_ o: TribeScanJSON.Object, _ b: [UInt8], element: TribeScanNetElement) -> [TribeScanJSON.Edit] {
        func pool(_ key: String) -> Int { o.value(key).flatMap { TribeScanJSON.int(b, $0) } ?? 0 }
        let engine = TribeScanCapsPolicy.Pools(full: pool("max_full_concurrent"), leg: pool("max_leg_concurrent"),
                                               awg: pool("max_awg_concurrent"))
        let headroom = availableMB()
        var offered = engine
        if !Self.awgMiniOffered { offered.awg = 0 }
        let now = TribeScanCapsPolicy.pools(engine: offered, availableMB: headroom)
        var pairs: [(key: String, raw: String)] = []
        if now != engine {
            pairs.append(("max_full_concurrent", "\(now.full)"))
            pairs.append(("max_leg_concurrent", "\(now.leg)"))
            pairs.append(("max_awg_concurrent", "\(now.awg)"))
            if let kr = o.value("kinds"),
               let kinds = (try? JSONSerialization.jsonObject(with: Data(b[kr]))) as? [String] {
                let keep = kinds.filter {
                    !(($0 == "xray_full" && now.full == 0) || ($0 == "xray_leg" && now.leg == 0)
                      || ($0 == "awg_mini" && now.awg == 0))
                }
                if let data = try? JSONSerialization.data(withJSONObject: keep) {
                    pairs.append(("kinds", String(decoding: data, as: UTF8.self)))
                }
            }
            if now.leg == 0 { pairs.append(("dns_plan", "false")) }
            if now.full == 0 { pairs.append(("can_verify_composite", "false")) }
            if let headroom, now != offered { pairs.append(("mem_available_mb", "\(Int(max(0, headroom)))")) }
        }
        if TribeScanJSON.isAbsentOrNull(o, b, "gen") { pairs.append(("gen", element.json)) }
        return TribeScanJSON.setMembers(o, pairs)
    }

    private func progressEdits(_ o: TribeScanJSON.Object, _ b: [UInt8], element: TribeScanNetElement) -> [TribeScanJSON.Edit] {
        var edits: [TribeScanJSON.Edit] = []
        if TribeScanJSON.isAbsentOrNull(o, b, "gen") {
            edits += TribeScanJSON.setMembers(o, [("gen", element.json)])
        }
        // ATTEMPT.gen = the element when the attempt started: known exactly only when the element did not move
        // since this scan's scan_start (the counter never goes back). Otherwise the attempt keeps no gen and
        // the app's exclusion rule says "host_gen" (never a false proof).
        guard let sr = o.value("scan_id"), let scanId = TribeScanJSON.string(b, sr),
              startElement(of: scanId) == element else { return edits }
        for key in ["access", "access_close"] {
            guard let r = o.value(key), let attempt = TribeScanJSON.object(b, in: r),
                  let att = attempt.value("attempted"), TribeScanJSON.isLiteral(b, att, "true"),
                  TribeScanJSON.isAbsentOrNull(attempt, b, "gen") else { continue }
            edits += TribeScanJSON.setMembers(attempt, [("gen", element.json)])
        }
        return edits
    }

    private func startEpoch(of scanId: String) -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return startEpochs.last { $0.scanId == scanId }?.epoch
    }

    private func livePeerUnknown(_ scanId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return livePeerUnknownScans.contains(scanId)
    }

    private func startElement(of scanId: String) -> TribeScanNetElement? {
        lock.lock()
        defer { lock.unlock() }
        return startElements.last { $0.scanId == scanId }?.element
    }

    // MARK: log helpers (never a config, host or token)

    static func safeToken(_ s: String) -> String {
        guard !s.isEmpty, s.count <= 64, s.unicodeScalars.allSatisfy({
            ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || "._:-".unicodeScalars.contains($0)
        }) else { return "#" }
        return s
    }

    static func replyKind(_ reply: [UInt8]) -> String {
        guard let o = TribeScanJSON.topLevel(reply) else { return "raw/\(reply.count)" }
        if let er = o.value("error") { return "error/\(safeToken(TribeScanJSON.string(reply, er) ?? ""))" }
        guard let tr = o.value("type") else { return "untyped/\(reply.count)" }
        return "\(safeToken(TribeScanJSON.string(reply, tr) ?? ""))/\(reply.count)"
    }

    static func requestScanId(_ request: [UInt8]) -> String? {
        guard let o = TribeScanJSON.topLevel(request), let r = o.value("scan_id") else { return nil }
        return TribeScanJSON.string(request, r)
    }
}

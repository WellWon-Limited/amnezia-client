import Foundation

// AVPN (build 140, data watch): the plan file the app writes for the tunnel extension.
//
// `TribeWatchPlan.json` lies in the App Group container (written by the app only, atomically, with
// protection "until first user authentication"). It carries the server-driven policy of the data
// watch (TribeDataWatch.swift in the awg-apple package) and, from stage 2 on, the ordered list of
// candidates for an in-place switch. This file only reads and validates it: Foundation, no
// NetworkExtension, so the rules run in a host test (tests/TribeWatchPlanTests.swift).
// Plans are ordered by the app's own sequence number and time of writing, never by the pool
// revision (the server's revision is not monotonic: deleting a node lowers it).
//
// A plan that is missing or rejected switches the watch OFF: the extension then behaves as
// build 139. The file is NOT signed: the container is reachable only by our app and its
// extensions; the server's flags stay signed where they are signed today (the app takes them from
// the verified /v1/config).
struct TribeWatchPlan {
    static let fileName = "TribeWatchPlan.json"
    static let stateFileName = "TribeWatchState.json"
    static let schema = 2
    static let maxBytes = 64 * 1024
    /// A plan written "in the future" by more than this is rejected (clock trouble).
    static let futureSlackMs: Int64 = 5 * 60 * 1000
    static let maxSanityTargets = 4
    /// Stage 2: the app writes up to five spare nodes; one more is tolerated, the rest is cut.
    static let maxCandidates = 6
    /// The longest switch lease the app may write (numbers.ios_tw_switch_lease_min is clamped to a day).
    static let maxLeaseMs: Int64 = 24 * 3600 * 1000

    /// The same plan without its candidates: what the extension leaves in the shared file when the
    /// permission to switch is gone, so that the nodes' keys do not lie there for nothing. Every
    /// other field - the order of plans too - stays as the app wrote it. nil = not a plan.
    static func scrubbed(_ data: Data) -> Data? {
        guard var object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              int(object["schema"]) == Int64(schema) else { return nil }
        object["candidates"] = [Any]()
        return try? JSONSerialization.data(withJSONObject: object)
    }

    enum Rejection: String, Error, Equatable {
        case missing
        case tooLarge = "too_large"
        case notJSON = "not_json"
        case schema
        case future
        /// The policy came from a config received too long ago and the app is not alive to renew it.
        case policyStale = "policy_stale"
        /// An older plan than one already seen in this process (by the app's own sequence).
        case stale
    }

    /// The order of plans: the app's own monotonic sequence, then the time of writing. The pool
    /// revision is NOT an order: the server's revision goes down when a node is deleted.
    struct Order: Equatable {
        var seq: Int64 = 0
        var writtenMs: Int64 = 0

        /// `other` is the same plan or a newer one. A lower sequence with a later time of writing
        /// is a newer plan too: the app's counter started over (reinstall, wiped settings).
        func accepts(_ other: Order) -> Bool {
            other.seq >= seq || other.writtenMs > writtenMs
        }
    }

    var policy: TribeDataWatchPolicy
    /// Targets of the request that bypasses the tunnel; empty = the built-in ones.
    var sanityTargets: [String]
    var order: Order
    /// Carried for the journal only.
    var poolRevision: Int64
    var configFetchedMs: Int64
    /// The candidate list is usable until this moment (stage 2). The policy has its own age rule.
    var expiresMs: Int64
    /// Stage 2: the nodes the extension may switch to in place, in the order the app's own
    /// ladder would try them (the pinned country first). Entries that do not pass the strict check
    /// are dropped here; an expired list, or one whose switch lease has lapsed, is empty.
    var candidates: [TribeWatchCandidate]
    /// Stage 2: the permission to switch is a LEASE the app renews with every plan it writes
    /// (`switch_lease_until_ms`, numbers.ios_tw_switch_lease_min). After it lapses the verdict goes
    /// on working and switching does not: this is how a server-side "off" reaches a phone whose
    /// app is not running, hours and not a day later.
    var switchLeaseUntilMs: Int64
    /// The file still holds candidates (their keys) although nothing may be done with them: the
    /// switch key is off, the lease has lapsed or the list has expired.
    var holdsUnusableSecrets: Bool
    /// Stage 2, for a start by the system: the pin in force when the plan was written (labels;
    /// empty = no pin), the transport mode, and the node the app's network memory holds for
    /// "wifi" and for "cellular".
    var pinNodeId: String
    var pinCountry: String
    var transportMode: String
    var memory: [String: String]

    /// `appAlive`: the app asked for the status recently. A policy older than its allowed age is
    /// still trusted while the app is alive: a living app rewrites the plan as soon as it gets a
    /// fresh config, so what lies in the file is what the app holds.
    static func parse(_ data: Data?, nowMs: Int64, appAlive: Bool, last: Order) -> Result<TribeWatchPlan, Rejection> {
        guard let data, !data.isEmpty else { return .failure(.missing) }
        guard data.count <= maxBytes else { return .failure(.tooLarge) }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return .failure(.notJSON) }
        guard int(object["schema"]) == Int64(schema) else { return .failure(.schema) }
        let written = int(object["written_ms"]) ?? 0
        guard written > 0, written - nowMs <= futureSlackMs else { return .failure(.future) }
        let order = Order(seq: int(object["seq"]) ?? 0, writtenMs: written)
        guard last.accepts(order) else { return .failure(.stale) }
        let fetched = int(object["config_fetched_ms"]) ?? 0
        let maxAge = max(0, int(object["policy_max_age_ms"]) ?? 0)
        let policyFresh = fetched > 0 && maxAge > 0 && nowMs - fetched <= maxAge && fetched - nowMs <= futureSlackMs
        guard policyFresh || appAlive else { return .failure(.policyStale) }
        let features = object["features"] as? [String: Any] ?? [:]
        let numbers = object["numbers"] as? [String: Any] ?? [:]
        var policy = TribeDataWatchPolicy.fromPlan(features: features, numbers: numbers)
        let expires = int(object["expires_ms"]) ?? 0
        let lease = int(object["switch_lease_until_ms"]) ?? 0
        let rawCandidates = object["candidates"] as? [Any] ?? []
        var candidates: [TribeWatchCandidate] = []
        // A lease from the future beyond the clock slack is not a lease (clock trouble).
        let leaseAlive = lease > nowMs && lease - nowMs <= maxLeaseMs + futureSlackMs
        if expires > nowMs && leaseAlive && policy.switchEnabled {
            for raw in rawCandidates.prefix(maxCandidates) {
                guard let entry = raw as? [String: Any], let candidate = TribeWatchCandidate(entry),
                      !candidates.contains(where: { $0.nodeId == candidate.nodeId }) else { continue }
                candidates.append(candidate)
            }
        }
        // The candidate list has its own term; without a usable list there is nothing to switch to.
        if candidates.isEmpty { policy.switchEnabled = false }
        let pin = object["pin"] as? [String: Any] ?? [:]
        var memory: [String: String] = [:]
        let keys = object["net_keys"] as? [String: Any] ?? [:]
        let saved = object["net_memory"] as? [String: Any] ?? [:]
        for kind in ["wifi", "cellular"] {
            guard let key = keys[kind] as? String, let entry = saved[key] as? [String: Any],
                  let node = int(entry["node_id"]), node > 0 else { continue }
            memory[kind] = String(node)
        }
        let targets = (object["sanity_targets"] as? [Any] ?? []).compactMap { $0 as? String }
            .filter { TribeSanityTarget(url: $0) != nil }
        return .success(TribeWatchPlan(policy: policy, sanityTargets: Array(targets.prefix(maxSanityTargets)), order: order,
                                       poolRevision: int(object["pool_revision"]) ?? 0, configFetchedMs: fetched,
                                       expiresMs: expires, candidates: candidates,
                                       switchLeaseUntilMs: lease,
                                       holdsUnusableSecrets: !rawCandidates.isEmpty && candidates.isEmpty,
                                       pinNodeId: (int(pin["node_id"]) ?? 0) > 0 ? String(int(pin["node_id"]) ?? 0) : "",
                                       pinCountry: TribeWatchCandidate.label(pin["country"]) ?? "",
                                       transportMode: TribeWatchCandidate.label(object["transport_mode"]) ?? "",
                                       memory: memory))
    }

    fileprivate static func int(_ raw: Any?) -> Int64? {
        if let n = raw as? NSNumber { return TribeDataWatchPolicy.isBoolean(n) ? nil : n.int64Value }
        if let s = raw as? String { return Int64(s) }
        return nil
    }
}

/// What a switch keeps from the running session: the interface half of its configuration. The app
/// offers only candidates whose DNS, MTU and routed ranges are the same, and the tunnel address and
/// the private key are one per device - so nothing of this changes when the peer does.
struct TribeSwitchBase: Equatable {
    var address: String
    var dns: String
    var mtu: String
    var privateKey: String
    var allowedIPs: String
}

/// One node the extension may switch to in place (stage 2): the node's half of the tunnel
/// configuration, by the keys of the provider configuration (WGConfig.swift). Strictly checked:
/// only the known keys, string values without a line break (the values go into a wg-quick text),
/// the whole AmneziaWG bundle present. A candidate that fails is not offered at all.
struct TribeWatchCandidate: Equatable {
    let nodeId: String
    let country: String
    let peer: [String: String]

    /// [Interface] keys of the node (AmneziaWG), in the order WGConfig.swift writes them.
    static let interfaceKeys = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4", "S3", "S4",
                                "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
                                "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
                                "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"]
    static let requiredInterfaceKeys = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
    static let peerKeys = ["hostName", "port", "server_pub_key", "psk_key", "persistent_keep_alive"]
    static let maxValueLength = 4096

    init?(_ raw: [String: Any]) {
        guard let node = TribeWatchPlan.int(raw["node_id"]), node > 0,
              let fields = raw["peer"] as? [String: Any] else { return nil }
        var peer: [String: String] = [:]
        for key in Self.interfaceKeys + Self.peerKeys {
            guard let value = fields[key] else { continue }
            let text: String
            if let string = value as? String {
                text = string.trimmingCharacters(in: .whitespaces)
            } else if let number = value as? NSNumber, !TribeDataWatchPolicy.isBoolean(number) {
                text = number.stringValue
            } else {
                return nil
            }
            guard !text.isEmpty else { continue }
            guard text.count <= Self.maxValueLength,
                  !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) })
            else { return nil }
            peer[key] = text
        }
        for key in Self.requiredInterfaceKeys + ["hostName", "port", "server_pub_key"] where peer[key] == nil { return nil }
        guard let port = Int(peer["port"] ?? ""), (1...65535).contains(port),
              let host = peer["hostName"], host.count <= 253,
              host.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == ":") }),
              let key = peer["server_pub_key"], Data(base64Encoded: key)?.count == 32 else { return nil }
        if let psk = peer["psk_key"], Data(base64Encoded: psk)?.count != 32 { return nil }
        self.nodeId = String(node)
        self.country = Self.label(raw["country"]) ?? ""
        self.peer = peer
    }

    /// "host:port" as the app knows the node (the app recognises the session by it).
    var endpoint: String { "\(peer["hostName"] ?? ""):\(peer["port"] ?? "")" }

    /// The wg-quick text of the session on this node: the base's interface, the node's own
    /// AmneziaWG parameters and peer. The same shape WGConfig.swift produces at a start.
    func wgQuick(base: TribeSwitchBase) -> String {
        var lines = ["[Interface]", "Address = \(base.address)", "DNS = \(base.dns)", "MTU = \(base.mtu)",
                     "PrivateKey = \(base.privateKey)"]
        for key in Self.interfaceKeys {
            if let value = peer[key] { lines.append("\(key) = \(value)") }
        }
        lines.append("[Peer]")
        lines.append("PublicKey = \(peer["server_pub_key"] ?? "")")
        if let psk = peer["psk_key"] { lines.append("PresharedKey = \(psk)") }
        lines.append("AllowedIPs = \(base.allowedIPs)")
        lines.append("Endpoint = \(endpoint)")
        if let keepalive = peer["persistent_keep_alive"] { lines.append("PersistentKeepalive = \(keepalive)") }
        return lines.joined(separator: "\n") + "\n"
    }

    /// A short label (country code, mode): letters, digits, "-" and "_", at most 16.
    static func label(_ raw: Any?) -> String? {
        guard let text = raw as? String, !text.isEmpty, text.count <= 16,
              text.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
        return text
    }
}

/// Stage 2: which node the tunnel should stand on for a given network. Used in two places only: a
/// start by the SYSTEM (not by the app), and a change of network while a node reached by a switch
/// has not proved itself. The profile holds the node of the last start by the app; the plan holds
/// what the app knew last. Order (design 0a item 8): the pinned node first -> the node the app's
/// network memory holds for this kind of network -> the profile's node -> the plan's order. A node
/// this extension itself judged dead on this kind of network within the last half hour is skipped -
/// that is the "proven failure in this network" which alone lets the choice leave the pin. Only
/// nodes the extension can raise: the profile's node and the plan's candidates (AmneziaWG, the mode
/// in force, never manual-only - the app wrote no others). Without a usable plan or with the switch
/// permission off: the profile's node, as build 139.
enum TribeStartChoice {
    /// The extension judged this node dead (`no_data`) on this kind of network at this moment.
    struct LastFailure: Equatable {
        var nodeId: String
        var net: String
        var wallMs: Int64
    }
    static let failureMemoryMs: Int64 = 30 * 60 * 1000
    static let maxFailuresKept = 8

    /// Who started the tunnel. The app and our own commands pass `tribeStartSource` ("app",
    /// "intent"); iOS (Settings, On-Demand after a stop by the system) passes nothing. Only a start
    /// that carries no source at all is a start by the system: anything else - also a value this
    /// build does not know - raises the profile's node, the one the user or the app asked for.
    static func startedBySystem(source: String?) -> Bool { source == nil }

    static func choose(profileNodeId: String, plan: TribeWatchPlan?, net: String,
                       failures: [LastFailure], nowMs: Int64) -> (nodeId: String, why: String) {
        guard let plan, plan.policy.enabled, plan.policy.switchEnabled, !plan.candidates.isEmpty else {
            return (profileNodeId, "profile")
        }
        let known = [profileNodeId] + plan.candidates.map { $0.nodeId }
        func failed(_ node: String) -> Bool {
            failures.contains { $0.nodeId == node && $0.net == net && fresh($0, nowMs: nowMs) }
        }
        var order: [(String, String)] = []
        if !plan.pinNodeId.isEmpty, known.contains(plan.pinNodeId) { order.append((plan.pinNodeId, "pin")) }
        if let remembered = plan.memory[net], known.contains(remembered) { order.append((remembered, "memory")) }
        order.append((profileNodeId, "profile"))
        order += plan.candidates.map { ($0.nodeId, "plan_order") }
        for (node, why) in order where !failed(node) { return (node, why) }
        return (profileNodeId, "profile")
    }

    static func fresh(_ failure: LastFailure, nowMs: Int64) -> Bool {
        nowMs >= failure.wallMs && nowMs - failure.wallMs <= failureMemoryMs
    }

    /// One more node judged dead: the newest record per node and network, the expired ones
    /// dropped, at most eight kept.
    static func noting(_ failure: LastFailure, in failures: [LastFailure], nowMs: Int64) -> [LastFailure] {
        var kept = failures.filter { fresh($0, nowMs: nowMs) && !($0.nodeId == failure.nodeId && $0.net == failure.net) }
        kept.append(failure)
        return Array(kept.suffix(maxFailuresKept))
    }

    /// The records as they lie in TribeWatchState.json (`dead`), and back.
    static func encode(_ failures: [LastFailure]) -> [[String: Any]] {
        failures.map { ["node_id": $0.nodeId, "net": $0.net, "at_ms": $0.wallMs] }
    }

    /// What the previous run of the extension left in the shared file: its list of dead nodes,
    /// and the verdict the file ends with (a `no_data` standing when that run stopped).
    static func failures(state: [String: Any]?, nowMs: Int64) -> [LastFailure] {
        guard let state else { return [] }
        var out: [LastFailure] = []
        for raw in (state["dead"] as? [Any] ?? []).prefix(maxFailuresKept * 2) {
            guard let entry = raw as? [String: Any], let node = entry["node_id"] as? String, !node.isEmpty, node.count <= 16,
                  let net = TribeWatchCandidate.label(entry["net"]), let at = TribeWatchPlan.int(entry["at_ms"]), at > 0 else { continue }
            out = noting(LastFailure(nodeId: node, net: net, wallMs: at), in: out, nowMs: nowMs)
        }
        if state["verdict"] as? String == TribeDataVerdict.noData.rawValue,
           let node = state["node_id"] as? String, !node.isEmpty,
           let net = state["net"] as? String,
           let at = TribeWatchPlan.int(state["last_no_data_ms"]), at > 0 {
            out = noting(LastFailure(nodeId: node, net: net, wallMs: at), in: out, nowMs: nowMs)
        }
        return out.filter { fresh($0, nowMs: nowMs) }
    }
}

/// One target of the request that bypasses the tunnel. It answers one question: is the physical
/// network a real path to the Internet right now (and not absent, and not a login page)?
///
/// Two kinds, by the scheme of the entry:
///  - `https://host[:port]` (or a bare host name): a TLS handshake with the ordinary certificate
///    check and nothing else - no HTTP request is sent. A completed handshake is the real host; a
///    TLS failure means somebody else answered (a login page, an intercepting box); no answer
///    means no network. Works with any site, so the targets can be hosts that answer INSIDE
///    Russia also on a mobile network in white-list mode (the project's own white-list probe
///    domains, REMOTE-TUNING `lists.whitelist_probe_domains`).
///  - `http://host[:port]/path`: one plain GET with a known answer (204, or 200 with the
///    "Success" page). Kept for networks where the operator wants the classic check.
/// Always a host NAME: an IPv4 literal does not work on an IPv6-only cellular network.
///
/// What a request reveals, to whom (it leaves from the phone's own address, outside the tunnel):
/// the local network and the operator see a DNS query for the name and a connection to it (the
/// name again in the TLS hello; for http also the path and the User-Agent "CaptiveNetworkSupport");
/// the target sees the phone's address and that connection. No account, device or app identifier
/// is sent. At most `ios_tw_sanity_max_per_hour` checks an hour, each to at most these targets.
struct TribeSanityTarget: Equatable {
    enum Kind: Equatable { case tls, http }
    let kind: Kind
    let host: String
    let port: UInt16
    let path: String

    static let builtIn = ["https://www.ozon.ru", "https://www.wildberries.ru", "https://www.apple.com"]

    init?(url raw: String) {
        let text = raw.contains("://") ? raw : "https://" + raw
        guard text.utf8.count <= 256, let components = URLComponents(string: text),
              let scheme = components.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = components.host, !host.isEmpty, components.user == nil, components.password == nil,
              host.rangeOfCharacter(from: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-").inverted) == nil,
              host.contains(where: { $0.isLetter }) else { return nil }
        let port = components.port ?? (scheme == "https" ? 443 : 80)
        guard port > 0 && port <= 65535 else { return nil }
        self.kind = scheme == "https" ? .tls : .http
        self.host = host
        self.port = UInt16(port)
        var path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        if let query = components.percentEncodedQuery { path += "?" + query }
        guard path.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else { return nil }
        // A TLS target is a handshake only: a path would promise a request that is never made.
        guard kind == .http || path == "/" else { return nil }
        self.path = path
    }

    var request: Data {
        Data("GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: CaptiveNetworkSupport\r\nAccept: */*\r\nConnection: close\r\n\r\n".utf8)
    }

    /// The reply bytes of an http target read SO FAR. nil = cannot be told yet (a 200 whose body
    /// has not arrived: the "Success" page comes after the headers, often in a second read):
    /// read on. `complete` = the peer closed or the read limit is reached: decide now.
    /// `ok` = the known answer of the real target (204, or 200 with the "Success" page);
    /// anything else that parses as HTTP is a foreign reply.
    static func classify(_ reply: Data, complete: Bool) -> TribeSanityResult? {
        guard let text = String(data: reply.prefix(4096), encoding: .utf8) ?? String(data: reply.prefix(4096), encoding: .isoLatin1) else {
            return complete ? .noReply : nil
        }
        guard text.hasPrefix("HTTP/") else {
            // Not HTTP at all, or not even the status line yet.
            if !complete && text.count < 5 && "HTTP/".hasPrefix(text) { return nil }
            return .noReply
        }
        // The status line ends at the first line break (CR LF is ONE Character in Swift).
        let lineEnd = text.firstIndex(where: { $0.isNewline })
        guard lineEnd != nil || complete else { return nil } // the status line is not whole yet
        let statusLine = text[..<(lineEnd ?? text.endIndex)]
        let parts = statusLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2, let status = Int(parts[1]) else { return .noReply }
        if status == 204 { return .ok }
        if status == 200 {
            if text.contains("<TITLE>Success</TITLE>") { return .ok }
            return complete ? .captive : nil
        }
        return .captive
    }

    /// The outcome of a TLS target: the handshake completed (the certificate check passed), or
    /// failed in TLS (somebody else answered), or never got an answer.
    static func classifyTLS(ready: Bool, tlsFailure: Bool) -> TribeSanityResult {
        ready ? .ok : (tlsFailure ? .captive : .noReply)
    }

    /// Several targets were asked: one known answer is enough; a foreign reply outweighs silence.
    static func combine(_ results: [TribeSanityResult]) -> TribeSanityResult {
        if results.contains(.ok) { return .ok }
        if results.contains(.captive) { return .captive }
        return results.isEmpty ? .unknown : .noReply
    }
}

/// The one line of ne.log and the journal fields for a report of the data watch. Labels and
/// numbers only: no endpoint, key or address can get in (the snapshot has none).
enum TribeDataWatchJournal {
    static func fields(report: TribeDataWatchReport, verdict: TribeDataVerdict, snapshot: TribeDataWatchSnapshot,
                       nodeId: String, proto: String, net: String, generation: String) -> [String: Any] {
        ["event": report.rawValue, "verdict": verdict.rawValue, "passive": snapshot.passive ? "no_data" : "none",
         "probe": snapshot.probe.rawValue, "trigger": snapshot.probeReason?.rawValue ?? "none", "probe_ms": snapshot.probeLatencyMs,
         "node_id": nodeId, "proto": proto, "net": net, "cycles": snapshot.cycles, "ep_s": snapshot.episodeSeconds,
         "tx": Int64(clamping: snapshot.episodeTx), "rx_data": Int64(clamping: snapshot.episodeRxData),
         "sanity": snapshot.sanity.rawValue, "evidence": snapshot.evidence.rawValue, "would_switch": snapshot.wouldSwitch,
         "app_alive": snapshot.appAlive, "refuted": snapshot.refuted, "disturbed": snapshot.disturbed,
         "generation": generation]
    }

    static func line(report: TribeDataWatchReport, verdict: TribeDataVerdict, snapshot: TribeDataWatchSnapshot,
                     nodeId: String, proto: String, net: String) -> String {
        "Tribe watch: event=\(report.rawValue) verdict=\(verdict.rawValue) passive=\(snapshot.passive ? "no_data" : "none")"
            + " probe=\(snapshot.probe.rawValue) trigger=\(snapshot.probeReason?.rawValue ?? "none") probe_ms=\(snapshot.probeLatencyMs)"
            + " node=\(nodeId) proto=\(proto) net=\(net) cycles=\(snapshot.cycles) ep=\(snapshot.episodeSeconds)s"
            + " tx=\(snapshot.episodeTx) rx_data=\(snapshot.episodeRxData) sanity=\(snapshot.sanity.rawValue)"
            + " evidence=\(snapshot.evidence.rawValue) would_switch=\(snapshot.wouldSwitch ? 1 : 0) app_alive=\(snapshot.appAlive ? 1 : 0)"
            + " refuted=\(snapshot.refuted) disturbed=\(snapshot.disturbed)"
    }

    /// Stage 2: the journal line of a command the arbiter ordered and the adapter executed.
    static func commandLine(_ command: TribeWatchCommand, result: TribeCommandResult, from: String, seq: Int, net: String) -> String {
        switch command {
        case .heal(let kind):
            return "Tribe watch: heal step=\(kind.rawValue) result=\(result.rawValue) node=\(from) net=\(net)"
        case .switchPeer(let node, let why):
            return "Tribe watch: peer_switch from=\(from) to=\(node) why=\(why.rawValue) seq=\(seq) net=\(net) result=\(result.rawValue)"
        }
    }

    /// `stay` = the node the tunnel stands on until the next round (after the way back, if one was made).
    static func engineLine(down: Bool, nodeId: String) -> String {
        "Tribe watch: engine=\(down ? "down" : "up") node=\(nodeId)"
    }

    static func exhaustedLine(snapshot: TribeDataWatchSnapshot, nodeId: String, net: String) -> String {
        "Tribe watch: exhausted tried=\(snapshot.arbiterTried) round=\(snapshot.arbiterRound) stay=\(nodeId) net=\(net)"
    }

    /// "state=<s> id=<n> ms=<n> late=<0|1>" from wgTribeProbeResult. The Go layer's "no_session"
    /// here is a packet that WAS injected and found only staged: `.staged` for the rule (a start
    /// that was refused is told by the start's own return value, see `startOutcome`).
    static func parseProbeResult(_ raw: String) -> (state: TribeProbeResult, id: Int32, latencyMs: Int, late: Bool) {
        var state = TribeProbeResult.unavailable
        var id: Int32 = 0
        var ms = 0
        var late = false
        for part in raw.split(separator: " ") {
            let pair = part.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            switch pair[0] {
            case "state": state = pair[1] == "no_session" ? .staged : (TribeProbeResult(rawValue: String(pair[1])) ?? .unavailable)
            case "id": id = Int32(pair[1]) ?? 0
            case "ms": ms = Int(pair[1]) ?? 0
            case "late": late = pair[1] == "1"
            default: break
            }
        }
        return (state, id, ms, late)
    }

    /// What wgTribeProbeStart returned: an id (the probe is in flight), or why nothing was sent.
    enum StartOutcome: Equatable {
        case started(Int32)
        /// No probe in this session, or its resolver cannot be reached through the tunnel.
        case unavailable
        /// The engine holds no keypair that may send now: nothing was injected.
        case noSession
    }
    static func startOutcome(_ code: Int32) -> StartOutcome {
        if code > 0 { return .started(code) }
        return code == -2 ? .noSession : .unavailable
    }
}

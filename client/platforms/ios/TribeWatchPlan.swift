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
    /// Stage 2: opaque here. Stage 1 never reads the entries.
    var candidates: [[String: Any]]

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
        let candidates = object["candidates"] as? [[String: Any]] ?? []
        // The candidate list has its own term; without a usable list there is nothing to switch to.
        if expires <= nowMs || candidates.isEmpty { policy.switchEnabled = false }
        let targets = (object["sanity_targets"] as? [Any] ?? []).compactMap { $0 as? String }
            .filter { TribeSanityTarget(url: $0) != nil }
        return .success(TribeWatchPlan(policy: policy, sanityTargets: Array(targets.prefix(maxSanityTargets)), order: order,
                                       poolRevision: int(object["pool_revision"]) ?? 0, configFetchedMs: fetched,
                                       expiresMs: expires, candidates: candidates))
    }

    private static func int(_ raw: Any?) -> Int64? {
        if let n = raw as? NSNumber { return TribeDataWatchPolicy.isBoolean(n) ? nil : n.int64Value }
        if let s = raw as? String { return Int64(s) }
        return nil
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

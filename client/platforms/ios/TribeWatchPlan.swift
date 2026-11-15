import Foundation

// AVPN (build 140, data watch): the plan file the app writes for the tunnel extension.
//
// `TribeWatchPlan.json` lies in the App Group container (written by the app only, atomically, with
// protection "until first user authentication"). It carries the server-driven policy of the data
// watch (TribeDataWatch.swift in the awg-apple package) and, from stage 2 on, the ordered list of
// candidates for an in-place switch. This file only reads and validates it: Foundation, no
// NetworkExtension, so the rules run in a host test (tests/TribeWatchPlanTests.swift).
//
// A plan that is missing or rejected switches the watch OFF: the extension then behaves as
// build 139. The file is NOT signed: the container is reachable only by our app and its
// extensions; the server's flags stay signed where they are signed today (the app takes them from
// the verified /v1/config).
struct TribeWatchPlan {
    static let fileName = "TribeWatchPlan.json"
    static let stateFileName = "TribeWatchState.json"
    static let schema = 1
    static let maxBytes = 64 * 1024
    /// A plan written "in the future" by more than this is rejected (clock trouble).
    static let futureSlackMs: Int64 = 5 * 60 * 1000
    static let maxSanityURLs = 4

    enum Rejection: String, Error, Equatable {
        case missing
        case tooLarge = "too_large"
        case notJSON = "not_json"
        case schema
        case future
        /// The policy came from a config received too long ago and the app is not alive to renew it.
        case policyStale = "policy_stale"
        /// An older pool revision than one already seen in this process.
        case oldRevision = "old_revision"
    }

    var policy: TribeDataWatchPolicy
    /// Targets of the request that bypasses the tunnel; empty = the built-in two.
    var sanityURLs: [String]
    var poolRevision: Int64
    var writtenMs: Int64
    var configFetchedMs: Int64
    /// The candidate list is usable until this moment (stage 2). The policy has its own age rule.
    var expiresMs: Int64
    /// Stage 2: opaque here. Stage 1 never reads the entries.
    var candidates: [[String: Any]]

    /// `appAlive`: the app asked for the status recently. A policy older than its allowed age is
    /// still trusted while the app is alive: a living app rewrites the plan as soon as it gets a
    /// fresh config, so what lies in the file is what the app holds.
    static func parse(_ data: Data?, nowMs: Int64, appAlive: Bool, lastPoolRevision: Int64) -> Result<TribeWatchPlan, Rejection> {
        guard let data, !data.isEmpty else { return .failure(.missing) }
        guard data.count <= maxBytes else { return .failure(.tooLarge) }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return .failure(.notJSON) }
        guard int(object["schema"]) == Int64(schema) else { return .failure(.schema) }
        let written = int(object["written_ms"]) ?? 0
        guard written > 0, written - nowMs <= futureSlackMs else { return .failure(.future) }
        let revision = int(object["pool_revision"]) ?? 0
        guard revision >= lastPoolRevision else { return .failure(.oldRevision) }
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
        let urls = (object["sanity_urls"] as? [Any] ?? []).compactMap { $0 as? String }
            .filter { TribeSanityTarget(url: $0) != nil }
        return .success(TribeWatchPlan(policy: policy, sanityURLs: Array(urls.prefix(maxSanityURLs)), poolRevision: revision,
                                       writtenMs: written, configFetchedMs: fetched, expiresMs: expires, candidates: candidates))
    }

    private static func int(_ raw: Any?) -> Int64? {
        if let n = raw as? NSNumber { return TribeDataWatchPolicy.isBoolean(n) ? nil : n.int64Value }
        if let s = raw as? String { return Int64(s) }
        return nil
    }
}

/// One target of the request that bypasses the tunnel: plain HTTP only (a captive portal answers
/// plain HTTP; TLS would hide it), a host NAME (an IPv4 literal does not work on an IPv6-only
/// cellular network) and a known "this is the real Internet" answer.
struct TribeSanityTarget: Equatable {
    let host: String
    let port: UInt16
    let path: String

    static let builtIn = ["http://connectivitycheck.gstatic.com/generate_204", "http://captive.apple.com/hotspot-detect.html"]

    init?(url raw: String) {
        guard raw.utf8.count <= 256, let components = URLComponents(string: raw), components.scheme?.lowercased() == "http",
              let host = components.host, !host.isEmpty, components.user == nil, components.password == nil,
              host.rangeOfCharacter(from: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-").inverted) == nil,
              host.contains(where: { $0.isLetter }) else { return nil }
        let port = components.port ?? 80
        guard port > 0 && port <= 65535 else { return nil }
        self.host = host
        self.port = UInt16(port)
        var path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        if let query = components.percentEncodedQuery { path += "?" + query }
        guard path.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else { return nil }
        self.path = path
    }

    var request: Data {
        Data("GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: CaptiveNetworkSupport\r\nAccept: */*\r\nConnection: close\r\n\r\n".utf8)
    }

    /// What the first bytes of the reply mean. `ok` = the known answer of the real target (204, or
    /// 200 with the "Success" page); anything else that parses as HTTP is a foreign reply.
    static func classify(_ reply: Data) -> TribeSanityResult {
        guard let text = String(data: reply.prefix(2048), encoding: .utf8) ?? String(data: reply.prefix(2048), encoding: .isoLatin1),
              text.hasPrefix("HTTP/") else { return .noReply }
        let statusLine = text.prefix { $0 != "\r" && $0 != "\n" }
        let parts = statusLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2, let status = Int(parts[1]) else { return .noReply }
        if status == 204 { return .ok }
        if status == 200 && text.contains("<TITLE>Success</TITLE>") { return .ok }
        return .captive
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
         "heal_steps": snapshot.healSteps, "sanity": snapshot.sanity.rawValue, "would_switch": snapshot.wouldSwitch,
         "app_alive": snapshot.appAlive, "refuted": snapshot.refuted, "generation": generation]
    }

    static func line(report: TribeDataWatchReport, verdict: TribeDataVerdict, snapshot: TribeDataWatchSnapshot,
                     nodeId: String, proto: String, net: String) -> String {
        "Tribe watch: event=\(report.rawValue) verdict=\(verdict.rawValue) passive=\(snapshot.passive ? "no_data" : "none")"
            + " probe=\(snapshot.probe.rawValue) trigger=\(snapshot.probeReason?.rawValue ?? "none") probe_ms=\(snapshot.probeLatencyMs)"
            + " node=\(nodeId) proto=\(proto) net=\(net) cycles=\(snapshot.cycles) ep=\(snapshot.episodeSeconds)s"
            + " tx=\(snapshot.episodeTx) rx_data=\(snapshot.episodeRxData) heal=\(snapshot.healSteps) sanity=\(snapshot.sanity.rawValue)"
            + " would_switch=\(snapshot.wouldSwitch ? 1 : 0) app_alive=\(snapshot.appAlive ? 1 : 0) refuted=\(snapshot.refuted)"
    }

    /// "state=<s> id=<n> ms=<n>" from wgTribeProbeResult.
    static func parseProbeResult(_ raw: String) -> (state: TribeProbeResult, id: Int32, latencyMs: Int) {
        var state = TribeProbeResult.unavailable
        var id: Int32 = 0
        var ms = 0
        for part in raw.split(separator: " ") {
            let pair = part.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            switch pair[0] {
            case "state": state = TribeProbeResult(rawValue: String(pair[1])) ?? .unavailable
            case "id": id = Int32(pair[1]) ?? 0
            case "ms": ms = Int(pair[1]) ?? 0
            default: break
            }
        }
        return (state, id, ms)
    }
}

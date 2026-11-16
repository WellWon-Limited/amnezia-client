import Foundation

// AVPN upstream nodes (plan provider-pool, release A, lane L3; contract section 4): metering scope
// "proxy" in the iOS extension - bytes summed over the lease's `meter_tags` from the running core's own
// per-outbound counters (LibXrayTribeOutboundStats, ABI libxray-tribe-stats-v1, awg-apple tribe.12
// patch 0011). Foundation-only and pure (host test: tests/UpstreamLeaseTests.swift).
//
// - The counters exist only when the config carries `stats` and policy.system.statsOutbound*: merged
//   into the provider's config before the core starts (never replacing an existing policy).
// - They count from zero on every core start (a network change restarts the core inside one tunnel
//   session): the accumulator keeps a per-tag base of the instances that ended, read just before every
//   stop, so the session total only grows. A failed read changes nothing.
// - Only `meter_tags` are summed: the server lists the user-facing proxy outbounds; dialer-only hops
//   (they count the same bytes again) and direct outbounds are left out by the server.

enum UpstreamMeterPlan {
    // Scope of a lease (fixed for its life): "proxy" only when the envelope asks for it, names its tags
    // and the running core really has its stats feature; anything else is "tunnel", exactly as before.
    static func scope(requested: UpstreamMeterScope, meterTags: [String], statsAvailable: Bool) -> UpstreamMeterScope {
        requested == .proxy && !meterTags.isEmpty && statsAvailable ? .proxy : .tunnel
    }

    // Whether the core of this start gets the stats keys: an active lease that may meter "proxy", or a
    // provisional start (its lease, handed over later, may ask for "proxy"). Own Xray / AWG: never.
    static func wantsStats(_ plan: UpstreamStartPlan) -> Bool {
        switch plan {
        case .pending: return true
        case .active(_, let lease): return lease.meterScope == .proxy && !lease.meterTags.isEmpty
        case .none, .invalid: return false
        }
    }
}

enum XrayStatsConfig {
    // Merges `"stats": {}` and policy.system.statsOutboundUplink/Downlink = true into a core config.
    // Every existing key is kept (an existing `stats` object as it is, `policy.levels`, other `system`
    // keys); idempotent. false = the config has a `policy`/`policy.system`/`stats` that is not an object
    // (left untouched: the counters then stay off and the session meters "tunnel").
    @discardableResult
    static func merge(into config: inout [String: Any]) -> Bool {
        if let stats = config["stats"], !(stats is [String: Any]) { return false }
        var policy: [String: Any] = [:]
        if let existing = config["policy"] {
            guard let dict = existing as? [String: Any] else { return false }
            policy = dict
        }
        var system: [String: Any] = [:]
        if let existing = policy["system"] {
            guard let dict = existing as? [String: Any] else { return false }
            system = dict
        }
        if config["stats"] == nil { config["stats"] = [String: Any]() }
        system["statsOutboundUplink"] = true
        system["statsOutboundDownlink"] = true
        policy["system"] = system
        config["policy"] = policy
        return true
    }
}

struct XrayOutboundTraffic: Equatable {
    var uplink: Int64 = 0
    var downlink: Int64 = 0
}

// One answer of LibXrayTribeOutboundStats:
// {"running":bool,"outbounds":{"<tag>":{"uplink":n,"downlink":n}},"error":"","error_code":""}.
struct XrayOutboundStatsRead: Equatable {
    var running = false
    var outbounds: [String: XrayOutboundTraffic] = [:]
    var errorCode = ""

    // Counters of a running core that has its stats feature.
    var usable: Bool { running && errorCode.isEmpty }

    static func parse(_ json: String) -> XrayOutboundStatsRead {
        guard let o = UpstreamLeaseWire.jsonObject(Data(json.utf8)) else {
            return XrayOutboundStatsRead(running: false, outbounds: [:], errorCode: "bad_answer")
        }
        var r = XrayOutboundStatsRead()
        r.running = UpstreamLeaseWire.jsonBool(o["running"]) ?? false
        r.errorCode = o["error_code"] as? String ?? ""
        for (tag, value) in o["outbounds"] as? [String: Any] ?? [:] {
            guard let c = value as? [String: Any] else { continue }
            r.outbounds[tag] = XrayOutboundTraffic(
                uplink: UpstreamLeaseWire.jsonInt(c["uplink"], 0, UpstreamLeaseWire.maxInteger) ?? 0,
                downlink: UpstreamLeaseWire.jsonInt(c["downlink"], 0, UpstreamLeaseWire.maxInteger) ?? 0)
        }
        return r
    }
}

// Per-tag session totals over core restarts. Not thread-safe: the owner serializes calls.
struct UpstreamProxyMeterAccumulator {
    private(set) var base: [String: XrayOutboundTraffic] = [:]   // instances that ended
    private(set) var current: [String: XrayOutboundTraffic] = [:] // the running instance, last read
    private(set) var failedReads = 0

    // A read of the running instance. A counter below the last read means the core restarted without
    // a read before its stop: the last read is moved to the base (nothing already counted is lost).
    mutating func record(_ read: XrayOutboundStatsRead) {
        guard read.usable else {
            failedReads += 1
            return
        }
        for (tag, value) in read.outbounds {
            let last = current[tag] ?? XrayOutboundTraffic()
            if value.uplink < last.uplink || value.downlink < last.downlink {
                base[tag] = Self.add(base[tag] ?? XrayOutboundTraffic(), last)
            }
            current[tag] = value
        }
    }

    // Just before the core stops (network-change restart, tunnel stop): the final read of this
    // instance, then its counters become base; the next instance starts from zero.
    mutating func coreWillStop(_ read: XrayOutboundStatsRead) {
        record(read)
        for (tag, value) in current {
            base[tag] = Self.add(base[tag] ?? XrayOutboundTraffic(), value)
        }
        current = [:]
    }

    // Session totals over exactly `tags` (a tag outside the list never counts): rx = downlink, tx = uplink.
    func totals(tags: [String]) -> (rx: Int64, tx: Int64) {
        var rx: Int64 = 0, tx: Int64 = 0
        for tag in Set(tags) {
            let t = Self.add(base[tag] ?? XrayOutboundTraffic(), current[tag] ?? XrayOutboundTraffic())
            rx = Self.sat(rx, t.downlink)
            tx = Self.sat(tx, t.uplink)
        }
        return (rx, tx)
    }

    private static func add(_ a: XrayOutboundTraffic, _ b: XrayOutboundTraffic) -> XrayOutboundTraffic {
        XrayOutboundTraffic(uplink: sat(a.uplink, b.uplink), downlink: sat(a.downlink, b.downlink))
    }

    private static func sat(_ a: Int64, _ b: Int64) -> Int64 {
        let r = a.addingReportingOverflow(b)
        return r.overflow ? Int64.max : r.partialValue
    }
}

import Foundation

// AVPN upstream nodes (plan provider-pool, release A, lane L3): wire formats the iOS extension needs,
// the Swift twin of the renew/release half of client/core/serviceEngine/UpstreamLeaseWire.h plus the
// start-envelope decode (contract client-envelope-contract.md sections 1-3). Foundation-only and pure:
// replayed against tests/vectors/upstream_wire_vectors.json (the renew cases; acquire answers are
// verified by the app, the extension never sees one). `why` strings are the C++ ones, exactly.
//
// Secrets: renew_token and the profile config are never logged; callers log codes and field names.

// What one tunnel start is, from its start envelope (PacketTunnelProvider+Upstream.swift).
enum UpstreamStartPlan {
    case none                                           // AWG, own Xray: nothing of the upstream lane applies
    case pending(profileId: String)                     // provisional start: the lease comes by app message
    case active(profileId: String, lease: UpstreamLeaseEnvelope)
    case invalid(why: String)                           // fail the start: never run unaccounted provider traffic
}

enum UpstreamLeaseWire {
    // Contract cap of one delta (UpstreamMeter.*_bytes_delta maximum, 1 TiB).
    static let maxDeltaBytes: Int64 = 1_099_511_627_776
    // Largest integer a JSON number carries exactly (2^53 - 1).
    static let maxInteger: Int64 = 9_007_199_254_740_991

    // MARK: - JSON primitives (QJsonValue semantics)

    // A JSON number (never a bool) with no fraction part, inside [lo, hi].
    static func jsonInt(_ value: Any?, _ lo: Int64, _ hi: Int64) -> Int64? {
        guard let number = value as? NSNumber, !isBool(number) else { return nil }
        let d = number.doubleValue
        guard d.isFinite, d.rounded(.down) == d, d >= Double(lo), d <= Double(hi) else { return nil }
        return Int64(d)
    }

    static func jsonBool(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, isBool(number) else { return nil }
        return number.boolValue
    }

    static func isBool(_ number: NSNumber) -> Bool {
        CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID()
    }

    static func isAbsent(_ value: Any?) -> Bool {
        value == nil || value is NSNull
    }

    static func jsonObject(_ body: Data) -> [String: Any]? {
        guard !body.isEmpty else { return nil }
        return (try? JSONSerialization.jsonObject(with: body, options: [])) as? [String: Any]
    }

    // MARK: - validators (UpstreamLeaseWire.h)

    static func leaseIdValid(_ id: String) -> Bool {
        id.range(of: "^[A-Za-z0-9_-]{32,64}$", options: .regularExpression) != nil
    }

    // An opaque header-safe token (visible ASCII, 1..1024 characters).
    static func renewTokenValid(_ token: String) -> Bool {
        guard (1...1024).contains(token.utf8.count) else { return false }
        return token.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }

    // An https URL with a host, no user info, query or fragment; without trailing slashes. "" = invalid.
    static func apiBaseNormalized(_ s: String) -> String {
        guard let c = URLComponents(string: s),
              c.scheme?.lowercased() == "https",
              let host = c.host, !host.isEmpty,
              c.user == nil, c.password == nil, c.query == nil, c.fragment == nil,
              !s.contains("?"), !s.contains("#") else { return "" }
        var out = s
        while out.hasSuffix("/") { out.removeLast() }
        return out
    }

    // ISO 8601 date-time as Qt::ISODateWithMs reads it (seconds and fraction optional, offset Z or
    // +hh:mm / +hhmm). A value without an offset is read as UTC (Qt reads local time; the server always
    // sends Z, and only differences of two server times are used).
    static func parseTimeMs(_ value: Any?) -> Int64? {
        guard let text = value as? String else { return nil }
        let pattern = #"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(Z|[+-]\d{2}:?\d{2})?$"#
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else { return nil }
        func group(_ i: Int) -> String? {
            guard let r = Range(m.range(at: i), in: text) else { return nil }
            return String(text[r])
        }
        guard let year = Int(group(1) ?? ""), let month = Int(group(2) ?? ""), let day = Int(group(3) ?? ""),
              let hour = Int(group(4) ?? ""), let minute = Int(group(5) ?? "") else { return nil }
        let second = Int(group(6) ?? "0") ?? 0
        guard (1...12).contains(month), (1...31).contains(day), (0...23).contains(hour),
              (0...59).contains(minute), (0...59).contains(second) else { return nil }
        var millis = 0
        if let fraction = group(7) {
            let digits = String((fraction + "000").prefix(3))
            millis = Int(digits) ?? 0
        }
        var offsetS = 0
        if let tz = group(8), tz != "Z" {
            let sign = tz.hasPrefix("-") ? -1 : 1
            let digits = tz.dropFirst().replacingOccurrences(of: ":", with: "")
            guard digits.count == 4, let hh = Int(digits.prefix(2)), let mm = Int(digits.suffix(2)),
                  hh <= 23, mm <= 59 else { return nil }
            offsetS = sign * (hh * 3600 + mm * 60)
        }
        var comps = DateComponents()
        comps.year = year
        comps.month = month
        comps.day = day
        comps.hour = hour
        comps.minute = minute
        comps.second = second
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        guard let date = calendar.date(from: comps),
              calendar.component(.day, from: date) == day else { return nil } // 31 Feb etc.
        return Int64(date.timeIntervalSince1970.rounded()) * 1000 + Int64(millis) - Int64(offsetS) * 1000
    }

    // MARK: - renew / release

    // Renew / release body (UpstreamMeter); keys in the order QJsonDocument writes them. `epoch` (the
    // owner's accounting epoch, contract addition 14.11) is ALWAYS sent, also as 0: the backend requires
    // the field (a missing one is a 422; lab 14.11 D2) and answers an unknown epoch with `rebaseline`.
    static func meterBody(_ m: UpstreamMeter) -> String {
        let rx = max(0, min(m.rxDelta, maxDeltaBytes))
        let tx = max(0, min(m.txDelta, maxDeltaBytes))
        let epoch = "\"epoch\":\(max(0, min(m.epoch, maxInteger))),"
        return "{\(epoch)\"meter_scope\":\"\(m.scope.rawValue)\",\"rx_bytes_delta\":\(rx),\"seq\":\(m.seq),\"tx_bytes_delta\":\(tx)}"
    }

    // The release's body: the final report plus the renew token of the grant being released (round 9 R1). The server
    // ends the lease only when that token is the lease's CURRENT one (a re-acquire rotates it) and drops the report
    // otherwise, so a late release of an old session never ends the seat of a newer one. Mirror of the app's
    // upstreamReleaseBody (UpstreamLeaseWire.h): the same field, "renew_token"; no token (an older server's grant) = the
    // body as before. Keys stay in the order QJsonDocument writes them (renew_token sorts between meter_scope and
    // rx_bytes_delta).
    static let releaseTokenField = "renew_token"
    static func releaseBody(_ m: UpstreamMeter, renewToken: String) -> String {
        let plain = meterBody(m)
        guard !renewToken.isEmpty else { return plain }
        var escaped = ""
        for ch in renewToken.unicodeScalars {
            if ch == "\"" || ch == "\\" { escaped.append("\\") }
            escaped.unicodeScalars.append(ch)
        }
        let marker = "\"rx_bytes_delta\""
        guard let at = plain.range(of: marker) else { return plain }
        var out = plain
        out.insert(contentsOf: "\"\(releaseTokenField)\":\"\(escaped)\",", at: at.lowerBound)
        return out
    }

    static func parseRenewal(_ body: Data) -> (UpstreamRenewal?, String) {
        guard let o = jsonObject(body) else { return (nil, "not_object") }
        var r = UpstreamRenewal()
        let status = o["status"] as? String ?? ""
        if status == "rebaseline" {
            r.rebaseline = true
        } else if status != "ok" {
            return (nil, "status")
        }
        r.leaseId = o["lease_id"] as? String ?? ""
        guard leaseIdValid(r.leaseId) else { return (nil, "lease_id") }
        guard let expires = parseTimeMs(o["expires_at"]) else { return (nil, "expires_at") }
        r.expiresAtMs = expires
        guard let renewAfter = jsonInt(o["renew_after_s"], 0, 86400) else { return (nil, "renew_after_s") }
        r.renewAfterS = Int(renewAfter)
        guard let seq = jsonInt(o["seq"], 0, maxInteger) else { return (nil, "seq") }
        r.seq = seq
        guard let rev = jsonInt(o["upstream_revision"], 0, maxInteger) else { return (nil, "upstream_revision") }
        r.upstreamRevision = rev
        guard let epoch = jsonInt(o["traffic_accounting_epoch"], 1, maxInteger) else {
            return (nil, "traffic_accounting_epoch")
        }
        r.accountingEpoch = epoch
        guard let changed = jsonBool(o["config_changed"]) else { return (nil, "config_changed") }
        r.configChanged = changed
        guard let applied = jsonInt(o["applied_bytes"], 0, maxInteger) else { return (nil, "applied_bytes") }
        r.appliedBytes = applied
        let shadow = o["shadow_bytes"]
        if !isAbsent(shadow) {
            guard let value = jsonInt(shadow, 0, maxInteger) else { return (nil, "shadow_bytes") }
            r.shadowBytes = value
        }
        return (r, "")
    }

    // An error body. Only the body's code counts - the HTTP status alone never makes an answer terminal.
    static func parseError(_ body: Data) -> UpstreamErrorReply {
        var e = UpstreamErrorReply()
        let o = jsonObject(body) ?? [:]
        if let code = o["code"] as? String { e.code = UpstreamErrorCode(code: code) }
        if let retry = jsonInt(o["retry_after_s"], 0, 86400) { e.retryAfterS = Int(retry) }
        if let rev = jsonInt(o["upstream_revision"], 1, maxInteger) { e.upstreamRevision = rev }
        return e
    }

    // httpStatus 0 = no HTTP answer (transport failure / timeout).
    static func classifyRenewReply(httpStatus: Int, body: Data) -> UpstreamRenewReply {
        var r = UpstreamRenewReply()
        if httpStatus <= 0 {
            r.why = "transport"
            return r
        }
        if httpStatus < 200 || httpStatus >= 300 {
            r.error = parseError(body)
            if r.error.code == .unknown {
                r.why = "http_\(httpStatus)"
                return r
            }
            r.kind = .refused
            return r
        }
        let (renewal, why) = parseRenewal(body)
        guard let renewal else {
            r.why = why
            return r
        }
        r.kind = .granted
        r.renewal = renewal
        return r
    }

    // A renewal our server refused as a malformed request (422 `invalid_request`, or a 422 without a known
    // code): a contract bug, counted by the machine (UpstreamLeaseMachine.renewRejectedLimit).
    static func renewRejected(_ r: UpstreamRenewReply) -> Bool {
        (r.kind == .refused && r.error.code == .invalidRequest) || (r.kind == .failed && r.why == "http_422")
    }

    // MARK: - LibXrayTribeHTTP answer (ABI libxray-tribe-http-v1)

    struct HTTPResult: Equatable {
        var status = 0          // 0 = no HTTP response
        var body = Data()
        var errorCode = ""      // bad_request | socks_auth | socks | timeout | tls | redirect_refused | ...
    }

    static func parseHTTPResult(_ json: String) -> HTTPResult {
        guard let o = jsonObject(Data(json.utf8)) else { return HTTPResult(status: 0, body: Data(), errorCode: "transport") }
        var r = HTTPResult()
        r.status = Int(jsonInt(o["status"], 0, 999) ?? 0)
        if let b64 = o["body_base64"] as? String, let data = Data(base64Encoded: b64) { r.body = data }
        r.errorCode = o["error_code"] as? String ?? ""
        return r
    }

    // MARK: - start envelope

    // `upstream_lease` (contract section 1) from the provider configuration or the app message.
    // why = the field name only (never a value).
    static func parseLeaseEnvelope(_ value: Any?) -> (UpstreamLeaseEnvelope?, String) {
        guard let o = value as? [String: Any] else { return (nil, "not_object") }
        var e = UpstreamLeaseEnvelope()
        e.leaseId = o["lease_id"] as? String ?? ""
        guard leaseIdValid(e.leaseId) else { return (nil, "lease_id") }
        e.renewToken = o["renew_token"] as? String ?? ""
        guard renewTokenValid(e.renewToken) else { return (nil, "renew_token") }
        e.apiBase = apiBaseNormalized(o["api_base"] as? String ?? "")
        guard !e.apiBase.isEmpty else { return (nil, "api_base") }
        guard let renewAfter = jsonInt(o["renew_after_s"], 0, 86400) else { return (nil, "renew_after_s") }
        e.renewAfterS = Int(renewAfter)
        guard let ttl = jsonInt(o["ttl_s"], 1, 86400) else { return (nil, "ttl_s") }
        e.ttlS = Int(ttl)
        guard let expiresIn = jsonInt(o["expires_in_ms"], 0, maxInteger) else { return (nil, "expires_in_ms") }
        e.expiresInMs = expiresIn
        guard let seq = jsonInt(o["seq"], 0, maxInteger) else { return (nil, "seq") }
        e.seq = seq
        guard let epoch = jsonInt(o["epoch"], 1, maxInteger) else { return (nil, "epoch") }
        e.epoch = epoch
        guard let revision = jsonInt(o["revision"], 0, maxInteger) else { return (nil, "revision") }
        e.revision = revision
        let scope = o["meter_scope"]
        if !isAbsent(scope) {
            guard let text = scope as? String, let parsed = UpstreamMeterScope(rawValue: text) else {
                return (nil, "meter_scope")
            }
            e.meterScope = parsed
        }
        // meter_tags (added 14.11 evening): the only outbound tags summed for scope "proxy"; absent or
        // empty = the owner meters "tunnel".
        let tags = o["meter_tags"]
        if !isAbsent(tags) {
            guard let list = tags as? [Any], list.count <= 64 else { return (nil, "meter_tags") }
            var out: [String] = []
            for item in list {
                guard let tag = item as? String, (1...128).contains(tag.utf8.count),
                      tag.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else {
                    return (nil, "meter_tags")
                }
                if !out.contains(tag) { out.append(tag) }
            }
            e.meterTags = out
        }
        return (e, "")
    }

    // `tribeSessionMetadata` of an upstream session: {upstream: 1, profile_id, config_sha256, ...}.
    // nil = not an upstream session (AWG, own Xray): nothing of this lane applies.
    static func upstreamProfileId(fromMetadata value: Any?) -> String? {
        guard let o = value as? [String: Any] else { return nil }
        let flag = o["upstream"]
        let on = (jsonInt(flag, 0, 1) == 1) || (jsonBool(flag) == true)
        guard on else { return nil }
        return o["profile_id"] as? String ?? ""
    }
}

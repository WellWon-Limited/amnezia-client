import Foundation

// AVPN upstream nodes (plan provider-pool, release A, lane L3): server-tunable memory and tun2socks
// sizes of the Xray path, plus the geo-asset check. Foundation-only and pure (host test:
// tests/UpstreamLeaseTests.swift). Applies to own Xray sessions too (contract section 3).
//
// `xray_tunables` travels inside the `xray` provider-configuration blob (XrayConfig) and is written
// by IosController::setupXray / setupSSXray from the /v1/config numbers. Rule per key: ABSENT = the
// behaviour before this change (Go memory limit Int64.max, hev task-stack-size 20480, hev defaults
// for the buffer and the session cap); PRESENT = clamped here again (defence in depth, the app clamps
// first); present but not a number = the key's default.
struct XrayTunables: Decodable, Equatable {
    // Go soft memory limit of the core: 20..40 MiB, default 30 (UpstreamNode.h::xrayMemoryLimitMiBFrom).
    static let memoryLimitRange = 20...40
    static let memoryLimitDefaultMiB = 30
    // hev-socks5-tunnel 2.15 `misc` keys (hev-config.c). hev's own defaults: tcp-buffer-size 65536,
    // max-session-count 0 (unlimited), task-stack-size 86016; this NE has written 20480 since D3.
    static let tcpBufferRange = 4096...65536
    static let tcpBufferDefault = 4096
    static let maxSessionRange = 128...65535
    static let maxSessionDefault = 1200
    static let taskStackRange = 20480...131072
    static let taskStackDefault = 24576
    // The literal written before this change (setupAndRunTun2socks).
    static let legacyTaskStackSize = 20480

    var memoryLimitMiB: Int?
    var hevTcpBufferSize: Int?
    var hevMaxSessionCount: Int?
    var hevTaskStackSize: Int?

    init(memoryLimitMiB: Int? = nil, hevTcpBufferSize: Int? = nil, hevMaxSessionCount: Int? = nil,
         hevTaskStackSize: Int? = nil) {
        self.memoryLimitMiB = memoryLimitMiB
        self.hevTcpBufferSize = hevTcpBufferSize
        self.hevMaxSessionCount = hevMaxSessionCount
        self.hevTaskStackSize = hevTaskStackSize
    }

    private enum CodingKeys: String, CodingKey {
        case memoryLimitMiB = "memory_limit_mib"
        case hevTcpBufferSize = "hev_tcp_buffer_size"
        case hevMaxSessionCount = "hev_max_session_count"
        case hevTaskStackSize = "hev_task_stack_size"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func value(_ key: CodingKeys, _ range: ClosedRange<Int>, _ def: Int) -> Int? {
            guard c.contains(key) else { return nil }
            guard let raw = try? c.decode(Double.self, forKey: key), raw.isFinite else { return def }
            return Self.clamp(raw, range)
        }
        memoryLimitMiB = value(.memoryLimitMiB, Self.memoryLimitRange, Self.memoryLimitDefaultMiB)
        hevTcpBufferSize = value(.hevTcpBufferSize, Self.tcpBufferRange, Self.tcpBufferDefault)
        hevMaxSessionCount = value(.hevMaxSessionCount, Self.maxSessionRange, Self.maxSessionDefault)
        hevTaskStackSize = value(.hevTaskStackSize, Self.taskStackRange, Self.taskStackDefault)
    }

    static func clamp(_ raw: Double, _ range: ClosedRange<Int>) -> Int {
        if raw < Double(range.lowerBound) { return range.lowerBound }
        if raw > Double(range.upperBound) { return range.upperBound }
        return Int(raw)
    }

    // maxMemory argument of LibXrayRunXray: Int64.max (no limit) when the key is absent.
    static func goMemoryLimitBytes(_ tunables: XrayTunables?) -> Int64 {
        guard let mib = tunables?.memoryLimitMiB else { return Int64.max }
        return Int64(mib) * 1024 * 1024
    }

    // The hev `misc:` lines this config adds, in order (each line without indentation).
    static func hevMiscLines(_ tunables: XrayTunables?) -> [String] {
        var lines = ["task-stack-size: \(tunables?.hevTaskStackSize ?? legacyTaskStackSize)"]
        if let size = tunables?.hevTcpBufferSize { lines.append("tcp-buffer-size: \(size)") }
        if let count = tunables?.hevMaxSessionCount { lines.append("max-session-count: \(count)") }
        return lines
    }
}

// Geo files a core config would open (the Swift twin of service/server/xrayassets.h): geosite.dat for
// `geosite:`, geoip.dat for `geoip:`, <file> for `ext:<file>:<code>` / `ext-ip:` / `ext-domain:` /
// `ext-site:`. The extension passes its own resource directory as datDir; a rule whose file is not
// there must fail the start with a named reason (CONNECT-INVARIANTS §22.13), never fall back.
enum XrayGeoAssets {
    static func files(inConfig config: String) -> [String] {
        var files = Set<String>()
        let range = NSRange(config.startIndex..., in: config)
        if let geo = try? NSRegularExpression(pattern: #"(?:^|[^A-Za-z0-9_-])(geosite|geoip):"#) {
            for m in geo.matches(in: config, range: range) {
                if let r = Range(m.range(at: 1), in: config) { files.insert(String(config[r]) + ".dat") }
            }
        }
        if let ext = try? NSRegularExpression(pattern: #"(?:^|[^A-Za-z0-9_-])ext(?:-ip|-domain|-site)?:([^:"\\]+):"#) {
            for m in ext.matches(in: config, range: range) {
                if let r = Range(m.range(at: 1), in: config) { files.insert(String(config[r])) }
            }
        }
        return files.sorted()
    }

    // Files from files(inConfig:) that are not regular files directly inside `dir`. A name that is not a
    // plain file name (a path, `..`) counts as missing.
    static func missing(inConfig config: String, dir: String,
                        isFile: (String) -> Bool = { path in
                            var isDirectory: ObjCBool = false
                            return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
                                && !isDirectory.boolValue
                        }) -> [String] {
        files(inConfig: config).filter { name in
            let plain = !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\\")
            return !plain || !isFile((dir as NSString).appendingPathComponent(name))
        }
    }
}

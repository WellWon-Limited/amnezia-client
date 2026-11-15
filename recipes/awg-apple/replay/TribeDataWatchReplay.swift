// SPDX-License-Identifier: MIT
// Offline replay of tester journals through the REAL TribeDataWatch (stage 0 of the design
// docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md in the backend repository).
//
// Input: a TSV export of the tester journal (device_id, app_ver, UTC timestamp, kind, message).
// The journal is private tester data: this tool reads it where it lies and prints AGGREGATES only
// (`--cases` prints one line of numbers per trigger for the analyst; never a journal line).
//
// What the journal gives: one `Tribe stats` line of the extension about every 10 s (cumulative
// rx/tx, handshake age, path status and interface kind) plus the adapter's own lines about path
// events and heal steps. What it cannot give, and how the replay stands in for it:
//  - resolution is ~10 s, not the adapter's 1 s tick: a cycle closes only on a stats line, so every
//    time below is late by up to one stats interval, and a pause in inbound data shorter than the
//    interval is invisible. `--tick 1s` spreads outbound bytes evenly over the interval and puts
//    the inbound bytes and the handshake at its end (the latest they can be);
//  - uptime is not logged: the stats timer runs on the uptime clock, so a gap above 12.5 s between
//    two stats lines is taken as sleep (10 s awake, the rest asleep);
//  - no probe ever ran in these builds: `--probe answered|silent` assumes one outcome for every
//    probe that could leave the phone; a probe asked while the journal shows no handshake younger
//    than a keypair lives (175 s) is refused as the Go layer refuses it (`no_session`), and the
//    rule then judges by the handshake;
//  - the bypass check of the physical network never ran: the replay judges without it;
//  - "the app is alive" is known only from the app's own journal lines.
import Foundation

struct Options {
    var path = ""
    var policy = TribeDataWatchPolicy()
    var probe = TribeProbeResult.silent
    var tick1s = false
    var cases = false
    var focusDevice: String?
    /// Analyst aid: print the watch's counters at every sample in this UTC window (epoch seconds).
    var traceFrom = Double.infinity
    var traceTo = -Double.infinity
}

func parseOptions() -> Options {
    var o = Options()
    o.policy.enabled = true
    o.policy.sanityRequired = false
    var args = Array(CommandLine.arguments.dropFirst())
    func value(_ name: String) -> String {
        guard !args.isEmpty else { fatalError("missing value for \(name)") }
        return args.removeFirst()
    }
    while !args.isEmpty {
        let a = args.removeFirst()
        switch a {
        case "--cycle": o.policy.cycleSeconds = Double(value(a))!
        case "--min-tx": o.policy.cycleMinTxBytes = UInt64(value(a))!
        case "--episode-tx": o.policy.minEpisodeTxBytes = UInt64(value(a))!
        case "--dead": o.policy.deadCycles = Int(value(a))!
        case "--gap": o.policy.cycleChainGapSeconds = Double(value(a))!
        case "--hs-rx": o.policy.handshakeRxAllowanceBytes = UInt64(value(a))!
        case "--hs-tx": o.policy.handshakeTxAllowanceBytes = UInt64(value(a))!
        case "--recover": o.policy.recoverRxBytes = UInt64(value(a))!
        case "--per-episode": o.policy.probeMaxPerEpisode = Int(value(a))!
        case "--per-hour": o.policy.probeMaxPerHour = Int(value(a))!
        case "--suspect-tx": o.policy.suspectMinTxBytes = UInt64(value(a))!
        case "--suspect-rx": o.policy.suspectMaxRxBytes = UInt64(value(a))!
        case "--suspect-window": o.policy.suspectWindowSeconds = Double(value(a))!
        case "--probe":
            let v = value(a)
            if v == "none" { o.policy.probeEnabled = false } else { o.probe = TribeProbeResult(rawValue: v)! }
        case "--tick": o.tick1s = value(a) == "1s"
        case "--cases": o.cases = true
        case "--device": o.focusDevice = value(a)
        case "--trace":
            o.traceFrom = epoch(Substring(value(a)))!
            o.traceTo = epoch(Substring(value(a)))!
        default:
            if a.hasPrefix("--") { fatalError("unknown option \(a)") }
            o.path = a
        }
    }
    if o.path.isEmpty { fatalError("usage: replay <journal.tsv> [options]") }
    return o
}

enum Event {
    case stats(rx: UInt64, tx: UInt64, hsAge: Int64?, satisfied: Bool, kind: String)
    case start
    case softRestart
    case freshPort
    case pathLost
    case pathReturned
    case appLine
    case whoami(String)
    case userStop
    case appStop
}

struct Row {
    var t: Double
    var order: Int
    var event: Event
}

func epoch(_ s: Substring) -> Double? {
    // 2026-11-13T16:09:05.000Z
    let u = Array(s.utf8)
    guard u.count >= 19 else { return nil }
    func n(_ a: Int, _ b: Int) -> Int? {
        var v = 0
        for i in a..<b { let c = Int(u[i]) - 48; if c < 0 || c > 9 { return nil }; v = v * 10 + c }
        return v
    }
    guard let y = n(0, 4), let mo = n(5, 7), let d = n(8, 10), let h = n(11, 13), let mi = n(14, 16), let se = n(17, 19) else { return nil }
    var ms = 0
    if u.count >= 23, u[19] == 46, let f = n(20, 23) { ms = f }
    // days from civil (Howard Hinnant)
    let yy = mo <= 2 ? y - 1 : y
    let era = (yy >= 0 ? yy : yy - 399) / 400
    let yoe = yy - era * 400
    let doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    let days = era * 146097 + doe - 719468
    return Double(days * 86400 + h * 3600 + mi * 60 + se) + Double(ms) / 1000
}

func field(_ message: Substring, _ key: String) -> Substring? {
    guard let r = message.range(of: key) else { return nil }
    let rest = message[r.upperBound...]
    return rest.prefix { $0 != " " }
}

func loadJournal(_ path: String) -> [String: [Row]] {
    guard let data = FileManager.default.contents(atPath: path), let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
        fatalError("cannot read \(path)")
    }
    var devices: [String: [Row]] = [:]
    var order = 0
    text.enumerateLines { line, _ in
        order += 1
        let parts = line.split(separator: "\t", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 5, let t = epoch(parts[2]) else { return }
        let device = String(parts[0])
        let kind = parts[3]
        let message = parts[4]
        var event: Event?
        if kind == "log" {
            if message.contains("NE: WG: Tribe stats:") {
                guard let rx = field(message, "rx=").flatMap({ UInt64($0) }), let tx = field(message, "tx=").flatMap({ UInt64($0) }),
                      let hs = field(message, "hs_age="), let uplink = field(message, "uplink=") else { return }
                let age: Int64? = hs == "never" ? nil : Int64(hs.dropLast())
                let bits = uplink.split(separator: "/")
                event = .stats(rx: rx, tx: tx, hsAge: age, satisfied: bits.first == "satisfied", kind: bits.count > 1 ? String(bits[1]) : "none")
            } else if message.contains("NE: WG: Tribe roaming policy:") {
                event = .start
            } else if message.contains("NE: WG: Tribe roaming:") {
                if message.contains("soft-restarted in place") {
                    event = .softRestart
                } else if message.contains("path returned") {
                    event = .pathReturned
                } else if message.contains("path lost") {
                    event = .pathLost
                } else if message.contains("denied by budget") || message.contains("path restored") || message.contains("still stalled after the fresh port") {
                    event = nil // the restore is followed by "path returned"; the soft restart has its own line
                } else if message.contains("fresh local port") || (message.contains("persistent heal step") && message.contains("(fresh port)")) {
                    event = .freshPort
                }
            } else if message.contains("] [INFO] AVPN") {
                event = .appLine
            }
        } else if kind == "ring" {
            if message.hasPrefix("whoami verdict=") {
                event = .whoami(String(field(message, "verdict=") ?? ""))
            } else if message.hasPrefix("guarded_stop why=user") || (message.hasPrefix("orb_tap") && message.contains("decision=stop")) {
                event = .userStop
            } else if message.hasPrefix("guarded_stop why=") {
                event = .appStop
            } else {
                event = .appLine
            }
        } else if kind == "tunnel" || kind == "net" {
            event = .appLine
        }
        if let event { devices[device, default: []].append(Row(t: t, order: order, event: event)) }
    }
    for key in devices.keys {
        devices[key]!.sort { $0.t != $1.t ? $0.t < $1.t : $0.order < $1.order }
    }
    return devices
}

struct Trigger {
    var device: String
    var t: Double
    var reason: TribeProbeReason
    var net: String
    var hsAge: Int64?
    var sinceStart: Double
    var appAlive: Bool
    var episodeTx: UInt64
    var episodeRx: UInt64
    /// The start was refused: the engine had no session, nothing was sent.
    var refused: Bool
    var rxNext30: UInt64 = 0
    var rxNext60: UInt64 = 0
    var rxNext120: UInt64 = 0
    var rxBefore300: UInt64 = 0
    var whoamiNoData = false
    var whoamiWorks = false
    var userStopAfter: Double?
    var endedWithin120 = false
}

struct DeviceResult {
    var awakeSeconds = 0.0
    var statsLines = 0
    var triggers: [Trigger] = []
    var verdicts: [String: Int] = [:]
    var refuted = 0
    var disturbed = 0
    var byHandshake = 0
    var recovered = 0
    var noDataSeconds = 0.0
    var firstByDay: [Int: Int] = [:]
}

func replay(device: String, rows: [Row], options: Options) -> DeviceResult {
    var result = DeviceResult()
    let policy = options.policy
    var watch = TribeDataWatch()
    var uptime = 0.0
    var lastStatsWall: Double?
    var lastStatsUptime = 0.0
    var pathSatisfied = true
    var lastKind: String?
    var appSeen: Double?   // wall
    var appSeenUptime: Double?
    var probe = TribeProbeResult.none
    var probeAt: Double?
    var pendingProbeDue: Double?
    var sessionStartWall = rows.first?.t ?? 0
    var lastRx: UInt64 = 0, lastTx: UInt64 = 0
    var lastHsWall: Double?
    var noDataSinceWall: Double?
    var statsSinceStart = false

    // Per-stats-line inbound data for the look-around columns (wall time, data bytes, reset flag).
    var dataSeries: [(t: Double, rx: UInt64)] = []
    var whoami: [(t: Double, verdict: String)] = []
    var userStops: [Double] = []
    var starts: [Double] = []

    func clock(_ t: Double) -> Double {
        guard let wall = lastStatsWall else { return uptime }
        return lastStatsUptime + min(max(0, t - wall), 10)
    }

    func feed(_ sample: TribeDataWatchSample, kind: String, hsAge: Int64?) {
        if let due = pendingProbeDue, sample.uptime >= due {
            probe = options.probe
            probeAt = due
            pendingProbeDue = nil
        }
        let env = TribeDataWatchEnv(pathSatisfied: pathSatisfied, probe: probe, probeAt: probeAt,
                                    probeLatencyMs: 120, appSeenAt: appSeenUptime)
        let out = watch.step(sample, env: env, policy: policy)
        if sample.wall >= options.traceFrom && sample.wall <= options.traceTo {
            let snap = watch.snapshot(policy: policy)
            print("trace \(utc(sample.wall)) tx=\(sample.txBytes) rx=\(sample.rxBytes) hs=\(sample.lastHandshakeSec % 100000) sat=\(pathSatisfied ? 1 : 0) -> verdict=\(out.verdict.rawValue) passive=\(snap.passive ? 1 : 0) cycles=\(snap.cycles) ep_s=\(snap.episodeSeconds) ep_tx=\(snap.episodeTx) ep_rx=\(snap.episodeRxData) evidence=\(snap.evidence.rawValue) probe=\(out.startProbe?.rawValue ?? "-") report=\(out.report?.rawValue ?? "-")")
        }
        if let reason = out.startProbe {
            // What tribeprobe.go does: no keypair that may send - the start is refused at once.
            let refused = hsAge.map { $0 >= 175 } ?? true
            if refused {
                probe = .noSession
                probeAt = sample.uptime
                pendingProbeDue = nil
            } else {
                pendingProbeDue = sample.uptime + (options.probe == .answered ? 0.2 : policy.probeTimeoutSeconds)
                probe = .pending
            }
            let snap = watch.snapshot(policy: policy)
            let alive = appSeen.map { sample.wall - $0 <= policy.appAliveSeconds } ?? false
            result.triggers.append(Trigger(device: device, t: sample.wall, reason: reason, net: kind, hsAge: hsAge,
                                           sinceStart: sample.wall - sessionStartWall, appAlive: alive,
                                           episodeTx: snap.episodeTx, episodeRx: snap.episodeRxData, refused: refused))
        }
        if out.action == .report, let report = out.report {
            switch report {
            case .verdict:
                result.verdicts[out.verdict.rawValue, default: 0] += 1
                if out.verdict == .recovered { result.recovered += 1 }
                if out.verdict == .noData && watch.snapshot(policy: policy).evidence == .handshake { result.byHandshake += 1 }
            case .refuted: result.refuted += 1
            case .disturbed: result.disturbed += 1
            case .probe, .wouldSwitch, .trial: break // the replay runs with the switch key off: no trial
            }
        }
        if watch.verdict == .noData || watch.verdict == .unconfirmed {
            if noDataSinceWall == nil { noDataSinceWall = sample.wall }
        } else if let since = noDataSinceWall {
            result.noDataSeconds += sample.wall - since
            noDataSinceWall = nil
        }
    }

    for row in rows {
        switch row.event {
        case .appLine:
            appSeen = row.t
            appSeenUptime = clock(row.t)
        case .whoami(let verdict):
            appSeen = row.t
            appSeenUptime = clock(row.t)
            whoami.append((row.t, verdict))
        case .userStop:
            appSeen = row.t
            appSeenUptime = clock(row.t)
            userStops.append(row.t)
        case .appStop:
            appSeen = row.t
            appSeenUptime = clock(row.t)
        case .start:
            uptime = clock(row.t)
            watch.noteDeviceStarted(at: uptime, policy: policy)
            if let since = noDataSinceWall { result.noDataSeconds += row.t - since; noDataSinceWall = nil }
            sessionStartWall = row.t
            starts.append(row.t)
            // The start is a clock anchor like a stats line (the tunnel was down before it).
            lastStatsWall = row.t
            lastStatsUptime = uptime
            statsSinceStart = false
            lastKind = nil
            pathSatisfied = true
            lastRx = 0; lastTx = 0; lastHsWall = nil
            probe = .none; probeAt = nil; pendingProbeDue = nil
        case .softRestart:
            watch.noteBackendRestarted(at: clock(row.t), policy: policy)
        case .freshPort:
            break // invisible to the watch
        case .pathLost:
            pathSatisfied = false
            watch.notePathEvent(at: clock(row.t), interfaceChanged: false, policy: policy)
        case .pathReturned:
            pathSatisfied = true
            watch.notePathEvent(at: clock(row.t), interfaceChanged: false, policy: policy)
        case .stats(let rx, let tx, let hsAge, let satisfied, let kind):
            result.statsLines += 1
            var gapWall = 10.0
            var slept = false
            if let wall = lastStatsWall {
                gapWall = row.t - wall
                slept = gapWall > 12.5
            }
            let step = lastStatsWall == nil ? 0 : (slept ? 10 : gapWall)
            let fromUptime = lastStatsUptime
            uptime = lastStatsWall == nil ? uptime : lastStatsUptime + step
            if lastStatsWall != nil { result.awakeSeconds += step }
            let firstOfSession = !statsSinceStart
            statsSinceStart = true
            if let previous = lastKind, previous != kind, kind != "none", previous != "none" {
                watch.notePathEvent(at: uptime, interfaceChanged: true, policy: policy)
            }
            lastKind = kind
            pathSatisfied = satisfied
            let hsWall = hsAge.map { row.t - Double($0) }
            let hsSec = hsWall.map { Int64($0) } ?? 0
            let reset = rx < lastRx || tx < lastTx
            // Inbound data of this stats interval for the look-around columns.
            var deltaRx = reset ? rx : rx - lastRx
            if let h = hsWall, lastHsWall.map({ h - $0 > 2 }) ?? true || reset {
                deltaRx = deltaRx > policy.handshakeRxAllowanceBytes ? deltaRx - policy.handshakeRxAllowanceBytes : 0
            }
            dataSeries.append((row.t, deltaRx))

            if options.tick1s, lastStatsWall != nil, !slept, !reset, !firstOfSession, step >= 2 {
                // Outbound bytes evenly; inbound bytes and the handshake at the end of the interval.
                let n = Int(step.rounded(.down))
                for i in 1..<n {
                    let frac = Double(i) / Double(n)
                    let s = TribeDataWatchSample(txBytes: lastTx + UInt64(Double(tx - lastTx) * frac), rxBytes: lastRx,
                                                 lastHandshakeSec: lastHsWall.map { Int64($0) } ?? 0,
                                                 uptime: fromUptime + step * frac, wall: (lastStatsWall ?? row.t) + gapWall * frac)
                    feed(s, kind: kind, hsAge: hsAge)
                }
            }
            feed(TribeDataWatchSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: hsSec, uptime: uptime, wall: row.t), kind: kind, hsAge: hsAge)
            lastStatsWall = row.t
            lastStatsUptime = uptime
            lastRx = rx; lastTx = tx; lastHsWall = hsWall
        }
    }
    if let since = noDataSinceWall, let lastWall = lastStatsWall { result.noDataSeconds += lastWall - since }

    // Look-around columns.
    for i in result.triggers.indices {
        let t = result.triggers[i].t
        let nextStart = starts.first { $0 > t } ?? Double.infinity
        for (at, rx) in dataSeries {
            if at > t && at <= t + 30 && at < nextStart { result.triggers[i].rxNext30 += rx }
            if at > t && at <= t + 60 && at < nextStart { result.triggers[i].rxNext60 += rx }
            if at > t && at <= t + 120 && at < nextStart { result.triggers[i].rxNext120 += rx }
            if at <= t && at > t - 300 { result.triggers[i].rxBefore300 += rx }
        }
        result.triggers[i].whoamiNoData = whoami.contains { abs($0.t - t) <= 120 && $0.verdict == "no_data" }
        result.triggers[i].whoamiWorks = whoami.contains { abs($0.t - t) <= 120 && $0.verdict == "works" }
        result.triggers[i].userStopAfter = userStops.first { $0 > t && $0 <= t + 300 }.map { $0 - t }
        result.triggers[i].endedWithin120 = nextStart <= t + 120
    }
    return result
}

func utc(_ t: Double) -> String {
    let f = DateFormatter()
    f.timeZone = TimeZone(identifier: "UTC")
    f.dateFormat = "MM-dd HH:mm:ss"
    return f.string(from: Date(timeIntervalSince1970: t))
}

let options = parseOptions()
let journal = loadJournal(options.path)
let p = options.policy
print("policy: cycle=\(Int(p.cycleSeconds))s min_tx=\(p.cycleMinTxBytes) dead=\(p.deadCycles) gap=\(Int(p.cycleChainGapSeconds))s episode_tx=\(p.minEpisodeTxBytes) hs_rx=\(p.handshakeRxAllowanceBytes) hs_tx=\(p.handshakeTxAllowanceBytes) recover=\(p.recoverRxBytes) probe=\(p.probeEnabled ? options.probe.rawValue : "off") per_episode=\(p.probeMaxPerEpisode) per_hour=\(p.probeMaxPerHour) tick=\(options.tick1s ? "1s" : "raw")")
print("device  awake_h  stats  passive  low_rx  no_data  by_hs  unconf  refuted  disturbed  recovered  no_data_min  asked/day  sent/day")
var all: [Trigger] = []
var totalAwake = 0.0
var totals = (passive: 0, lowRx: 0, noData: 0, byHandshake: 0, unconfirmed: 0, refuted: 0, disturbed: 0, recovered: 0, minutes: 0.0)
for device in journal.keys.sorted(by: { (Int($0) ?? 0) < (Int($1) ?? 0) }) {
    if let focus = options.focusDevice, focus != device { continue }
    let r = replay(device: device, rows: journal[device]!, options: options)
    let passive = r.triggers.filter { $0.reason == .passive }.count
    let lowRx = r.triggers.count - passive
    let days = max(r.awakeSeconds / 86400, 0.0001)
    let sent = r.triggers.filter { !$0.refused }.count
    print(String(format: "%6@ %8.1f %6d %8d %7d %8d %6d %7d %8d %10d %10d %12.1f %10.1f %9.1f", device as NSString, r.awakeSeconds / 3600, r.statsLines,
                 passive, lowRx, r.verdicts["no_data"] ?? 0, r.byHandshake, r.verdicts["unconfirmed"] ?? 0, r.refuted, r.disturbed, r.recovered,
                 r.noDataSeconds / 60, Double(r.triggers.count) / days, Double(sent) / days))
    all += r.triggers
    totalAwake += r.awakeSeconds
    totals.passive += passive; totals.lowRx += lowRx
    totals.noData += r.verdicts["no_data"] ?? 0; totals.unconfirmed += r.verdicts["unconfirmed"] ?? 0
    totals.refuted += r.refuted; totals.recovered += r.recovered; totals.minutes += r.noDataSeconds / 60
    totals.byHandshake += r.byHandshake; totals.disturbed += r.disturbed
}
print(String(format: " total %8.1f %6@ %8d %7d %8d %6d %7d %8d %10d %10d %12.1f %10.1f %9.1f", totalAwake / 3600, "" as NSString, totals.passive, totals.lowRx,
             totals.noData, totals.byHandshake, totals.unconfirmed, totals.refuted, totals.disturbed, totals.recovered, totals.minutes,
             Double(all.count) / max(totalAwake / 86400, 0.0001), Double(all.filter { !$0.refused }.count) / max(totalAwake / 86400, 0.0001)))

func table(_ title: String, _ list: [Trigger]) {
    guard !list.isEmpty else { print("\(title): none"); return }
    let n = list.count
    func c(_ f: (Trigger) -> Bool) -> Int { list.filter(f).count }
    print("\(title): \(n)")
    print("  by network: wifi=\(c { $0.net == "wifi" }) cellular=\(c { $0.net == "cellular" }) other=\(c { $0.net != "wifi" && $0.net != "cellular" })")
    print("  handshake at the trigger: fresh(<180s)=\(c { ($0.hsAge ?? 9999) < 180 }) old=\(c { ($0.hsAge ?? -1) >= 180 }) never=\(c { $0.hsAge == nil })")
    print("  refused (no session, nothing sent): \(c { $0.refused })")
    print("  app alive at the trigger: \(c { $0.appAlive })")
    print("  whoami no_data within 2 min: \(c { $0.whoamiNoData })   whoami works within 2 min: \(c { $0.whoamiWorks })")
    print("  user stop within 5 min after: \(c { $0.userStopAfter != nil })")
    print("  inbound data after the trigger: none in 30 s=\(c { $0.rxNext30 == 0 })  none in 60 s=\(c { $0.rxNext60 == 0 })  none in 120 s=\(c { $0.rxNext120 == 0 })")
    print("  >=16 KiB in the next 30 s=\(c { $0.rxNext30 >= 16384 })  60 s=\(c { $0.rxNext60 >= 16384 })  120 s=\(c { $0.rxNext120 >= 16384 })")
    print("  session ended within 120 s after: \(c { $0.endedWithin120 })")
    print("  >=1 MiB inbound in the 5 min before: \(c { $0.rxBefore300 >= 1_048_576 })")
}
table("passive triggers", all.filter { $0.reason == .passive })
table("low-inbound triggers", all.filter { $0.reason == .lowRx })
if options.cases {
    for t in all {
        print("case dev=\(t.device) at=\(utc(t.t)) why=\(t.reason.rawValue) net=\(t.net) hs_age=\(t.hsAge.map(String.init) ?? "never") since_start=\(Int(t.sinceStart))s app=\(t.appAlive ? 1 : 0) ep_tx=\(t.episodeTx) ep_rx=\(t.episodeRx) refused=\(t.refused ? 1 : 0) rx30=\(t.rxNext30) rx60=\(t.rxNext60) rx120=\(t.rxNext120) rx_before5m=\(t.rxBefore300) whoami_nd=\(t.whoamiNoData ? 1 : 0) whoami_ok=\(t.whoamiWorks ? 1 : 0) user_stop=\(t.userStopAfter.map { String(Int($0)) } ?? "-") ended120=\(t.endedWithin120 ? 1 : 0)")
    }
}

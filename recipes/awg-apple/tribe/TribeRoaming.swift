// SPDX-License-Identifier: MIT
// Tribe seamless roaming (mesh Wi-Fi handoff, Wi-Fi <-> cellular): pure policy + decision logic.
//
// Why this file exists: upstream wireguard-apple turns the WireGuard device OFF on the first
// NWPath.unsatisfied (commit 9f8d0e2, no rationale) and, on return, re-applies tunnel network
// settings + starts a NEW device with a NEW handshake. A 1-2 s mesh reassociation thus becomes a
// 3-10 s dead tunnel and every flow in the tunnel is reset. Tailscale, ProtonVPN, sing-box and the
// official WireGuard Android app never stop the device; they rebind the socket on return.
//
// tribe.9 (2026-09-29, field data 24-28.09, 4 devices / 9 device-days): a path that RETURNS after a
// real loss (or moves to another interface) gets a FRESH local port + keepalive, not a same-port bump:
// the carrier NAT/DPI had killed the old 5-tuple in 38 of 44 long "connected but no data" episodes,
// and a fresh port healed 31 of 82 stalls against 4 of 27 for the same-port bump. The stall ladder
// is fresh port -> soft restart -> (30/60/120 s backoff) fresh port / soft restart, and a path event
// never restarts the stall clock (tribe.4-8 zeroed it on every event, ~200/h on cellular, so the
// fresh-port step was almost never reached: 14 s + 8 KB without a path event).
//
// tribe.10 (review of tribe.9): a roam fresh port is also the episode's fresh port in the BUDGET
// (the GUI `rebind` then gets `.episode` and moves on to its soft restart); at stage 2 an external
// fresh port postpones the soft restart only when the previous step is older than the second stage
// (so a path flapping every 4 s cannot starve the ladder), at stage 3 it never touches the backoff;
// the second stage keeps a full `stallRebindSeconds` after the last step (a fresh port right after a
// long outage got 3 s before the soft restart); an `.episode` refusal below stage 3 re-syncs the
// tracker with the budget instead of asking forever.
//
// tribe.16 (device round 24.11, case B1: LTE -> Wi-Fi with an AmneziaWG session): after the roam fresh
// port the path passed about 1 s of data after every new port and then nothing, for 8 minutes. That
// burst (and every completed handshake) reset the ladder to its first step, so it rebound the port 17
// times and never restarted the engine. One definition of "data is flowing" now (TribeDataFlow):
// inbound DATA bytes (a handshake's bytes deducted) that still arrive a full second stage after the
// last repair step. The burst right after a step is the echo of that step: it restarts the stall
// clock but keeps the escalation, so a fresh port that does not restore lasting data is followed by
// the soft restart. The same judgment is what the app's failover reads (`dataQuietSeconds`).
//
// tribe.18 (second review): a handshake only by its time moving; RandomTrailers read as the engine reads
// it, a trailer bounded by the UDP window; a handshake's bytes settled over the whole window since the
// previous handshake, one initiation held back while unanswered.
//
// tribe.17 (review of tribe.16): demand never counts the session's own service traffic (computed from
// its AmneziaWG configuration, `TribeServiceTraffic`), at every stage; a minute without demand ends an
// open episode; a sampling gap is not silence; the export for the app is reported only while the
// ladder sees a stall right now (a path whose data has just returned inside a repair's echo window is
// not reported as quiet).
//
// This file has NO NetworkExtension/Go dependency: the conan recipe compiles it together with
// tests/TribeRoamingTests.swift under plain swiftc, so the package cannot ship with broken logic.
import Foundation

/// tribe.16: what "data is flowing" means for the stall ladder, its recovery budget and the app's
/// failover (the extension exports its judgment as `data_quiet_s`, see `dataQuietSeconds`).
public enum TribeDataFlow {
    /// A handshake message is counted in rx_bytes and is not data: a response is exactly 92 B, an
    /// initiation the server starts (it re-keys) 148 B, whatever S1/S2 (amneziawg-go v3.1.20260828
    /// device/receive.go strips the padding before `peer.rxBytes.Add(len(elem.packet))`). The data
    /// watch deducts the same amount (`TribeDataWatchPolicy.handshakeRxAllowanceBytes`, pinned to this
    /// value by its ladder test: the data watch file is compiled alone in its own gates).
    public static let handshakeRxBytes: UInt64 = 148
    /// tribe.17: a pause between two samples longer than this is not an observation (the watchdog
    /// ticks every 1 s, every 5 s while idle or offline; the extension may be suspended while the
    /// system is awake, and systemUptime goes on). After it the stall clock, the demand count and
    /// the exported quiet time start again: the gap is neither silence nor data.
    public static let samplingGapSeconds: TimeInterval = 10
    /// tribe.17: no outbound demand (the session's own service traffic not counted) for this long =
    /// the tunnel is idle. The demand count starts over and an open repair episode ends: without user
    /// traffic nothing can prove or disprove a repair, and an idle tunnel must not keep a stage.
    public static let idleSeconds: TimeInterval = 60

    /// Inbound data of one sample: the rx growth, minus one handshake when the handshake time moved.
    /// tribe.18 (second review, G2): a handshake is recognised by its TIME moving, never by a byte count:
    /// a padded TCP ACK is 148 B in rx_bytes too (52 + content padding 64 + 32; receive.go counts before
    /// trimming to the IP length), and tribe.17 took a steady upload's ACKs for handshakes. A server's
    /// initiation (148 B counted before the time moves on its first transport packet) is therefore data
    /// in its sample - rare (the server re-keys only when it has data for us), and harmless: the next
    /// sample deducts a handshake from that first transport packet.
    /// An incoming keepalive IS counted (counters see bytes, not packets): the server sends one only
    /// after it received our data and had nothing to send (passive keepalive), so it proves the path
    /// both ways; a lone keepalive and a lone TCP ACK cannot be told apart by size, and not counting
    /// them would make an ACK-only upload look stalled.
    public static func dataBytes(rxDelta: UInt64, handshakeChanged: Bool) -> UInt64 {
        guard handshakeChanged else { return rxDelta }
        return rxDelta > handshakeRxBytes ? rxDelta - handshakeRxBytes : 0
    }

    /// Inbound data proves the path only when it still arrives `window` seconds after the last repair
    /// step (fresh port, soft restart; watchdog, GUI or roam): the burst right after a step is the
    /// echo of that step (the server learns the new port and flushes what it had), not a repaired
    /// path. No step yet (`lastRepairAt` nil) or `window` 0: every data byte counts, as before.
    public static func provesFlow(dataAt: TimeInterval, lastRepairAt: TimeInterval?, window: TimeInterval) -> Bool {
        guard let repair = lastRepairAt, window > 0 else { return true }
        return dataAt - repair >= window
    }
}

/// tribe.17: what the session sends by itself, without any user traffic, computed from its own
/// AmneziaWG configuration (the extension has it), so that it is never taken for demand. Upper bounds
/// of what amneziawg-go v3.1.20260828 counts in tx_bytes (peer.go SendBuffers adds every buffer):
/// - one handshake the client starts (send.go SendHandshakeInitiation): the special junk packets
///   I1-I5 (the lengths of their tags), Jc junk packets of Jmin..Jmax-1 bytes (JunkPackets), S1 + the
///   148-byte initiation (+ a random trailer with RandomTrailers), and the keepalive that confirms it;
/// - one keepalive (RoutineEncryption): S4 + 16 B header + 16 B tag + the content padding addition's
///   maximum, or without it the random trailer; an empty payload is padded by nothing else.
/// A handshake that needs retries sends its initiation again: the retries are counted as demand (an
/// unanswered session is what the ladder is for).
public struct TribeServiceTraffic: Equatable {
    public var handshakeTxBytes: UInt64
    public var keepaliveTxBytes: UInt64
    /// Persistent keepalive interval (0 = none: keepalives only answer received data).
    public var keepaliveIntervalSeconds: TimeInterval

    public init(handshakeTxBytes: UInt64, keepaliveTxBytes: UInt64, keepaliveIntervalSeconds: TimeInterval) {
        self.handshakeTxBytes = handshakeTxBytes
        self.keepaliveTxBytes = keepaliveTxBytes
        self.keepaliveIntervalSeconds = keepaliveIntervalSeconds
    }

    /// Plain WireGuard (no obfuscation): initiation 148 + its confirming keepalive 32; keepalive 32; 25 s.
    public static let plain = TribeServiceTraffic(handshakeTxBytes: 148 + 32, keepaliveTxBytes: 32, keepaliveIntervalSeconds: 25)

    /// tribe.18 (G3): how the engine reads RandomTrailers: the pinned PacketTunnelSettingsGenerator.swift
    /// `uapiBool` (trimmed, lower-cased: "on", "1", "true", "t", "yes" = on; anything else off). Our app
    /// writes "1"; tribe.17 accepted "on" only. tests/check_engine_spellings.sh pins this set to the
    /// generator's (a package gate).
    public static let engineTrueSpellings: Set<String> = ["on", "1", "true", "t", "yes"]
    public static func engineBool(_ raw: String?) -> Bool {
        guard let raw else { return false }
        return engineTrueSpellings.contains(raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }

    /// tribe.18 (G3): with random trailers a packet grows up to the peer's UDP window (send.go
    /// randomTrailer: fastrandn(udpWindow - size)), and the window is the largest datagram the peer has
    /// sent (S4 + 32 + up to the MTU + content padding) or received (the server's, whose MTU this side does
    /// not know): bounded here by that or a 1500-byte path, whichever is larger.
    static func udpWindowBound(mtu: Int, s4: Int, contentPadding: Int) -> Int { Swift.max(mtu + s4 + 32 + contentPadding, 1500) }

    /// From the session's configuration strings (WGConfig of the provider). Junk = absent/unparseable
    /// values are 0 (the engine refuses a config it cannot parse); a special junk spec this parser does
    /// not know counts as one MTU-sized packet.
    public static func fromConfig(jc: String?, jmax: String?, s1: String?, s4: String?, specialJunk: [String?],
                                  contentPaddingAddition: String?, randomTrailers: String?, mtu: String?,
                                  persistentKeepalive: String?) -> TribeServiceTraffic {
        func int(_ raw: String?) -> Int {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines), let v = Int(raw), v > 0 else { return 0 }
            return v
        }
        let mtuBytes = int(mtu) > 0 ? int(mtu) : 1280
        let trailers = engineBool(randomTrailers)
        let contentPadding = rangeMax(contentPaddingAddition)
        let window = udpWindowBound(mtu: mtuBytes, s4: int(s4), contentPadding: contentPadding)
        // RoutineEncryption: the content padding addition when set, else the random trailer (the whole
        // datagram then stays below the UDP window), else nothing for an empty payload.
        let keepalive = contentPadding > 0 ? int(s4) + 32 + contentPadding : (trailers ? window : int(s4) + 32)
        var special = 0
        for spec in specialJunk {
            guard let spec = spec?.trimmingCharacters(in: .whitespacesAndNewlines), !spec.isEmpty else { continue }
            special += specialJunkLength(spec) ?? mtuBytes
        }
        // SendHandshakeInitiation: special junk, junk, then S1 + 148 (+ a trailer: the datagram stays below
        // the UDP window).
        let initiation = special + int(jc) * int(jmax) + (trailers ? window : int(s1) + 148)
        return TribeServiceTraffic(handshakeTxBytes: UInt64(initiation + keepalive), keepaliveTxBytes: UInt64(keepalive),
                                   keepaliveIntervalSeconds: TimeInterval(int(persistentKeepalive)))
    }

    /// Length of one special junk packet (I1-I5) with no payload, as the engine builds it (obf*.go
    /// ObfuscatedLen(0)): <b 0x..> its bytes, <t> 4, <r N> / <rc N> / <rd N> / <dz N> N, <d> / <ds> 0.
    /// nil = a tag this parser does not know.
    public static func specialJunkLength(_ spec: String) -> Int? {
        var total = 0
        var rest = Substring(spec)
        while let open = rest.firstIndex(of: "<") {
            guard let close = rest[open...].firstIndex(of: ">") else { return nil }
            let parts = rest[rest.index(after: open)..<close].split(separator: " ", omittingEmptySubsequences: true)
            rest = rest[rest.index(after: close)...]
            guard let key = parts.first else { return nil }
            let value = parts.count > 1 ? String(parts[1]) : ""
            switch key {
            case "b":
                let hex = value.hasPrefix("0x") ? value.dropFirst(2) : Substring(value)
                guard hex.count % 2 == 0 else { return nil }
                total += hex.count / 2
            case "t": total += 4
            case "r", "rc", "rd", "dz":
                guard let n = Int(value), n >= 0 else { return nil }
                total += n
            case "d", "ds": break
            default: return nil
            }
        }
        return total
    }

    /// "10-100" -> 100, "50" -> 50, absent -> 0.
    static func rangeMax(_ raw: String?) -> Int {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return 0 }
        let bounds = raw.split(separator: "-").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        return bounds.max() ?? 0
    }

    /// Demand of one sample: its outbound growth minus the keepalives, paid from `credit`, which grows by
    /// one keepalive per interval (`elapsed`) and holds at most two. A handshake is NOT settled here
    /// (tribe.18, G4): its initiation leaves in one sample and its response arrives in a later one, so the
    /// tracker settles `handshakeTxBytes` against everything sent since the previous handshake.
    public func demand(txDelta: UInt64, elapsed: TimeInterval, credit: inout UInt64) -> UInt64 {
        if keepaliveIntervalSeconds > 0 && elapsed > 0 {
            let grown = Double(keepaliveTxBytes) * elapsed / keepaliveIntervalSeconds
            credit = Swift.min(2 * keepaliveTxBytes, credit &+ UInt64(grown.rounded(.up)))
        }
        let paid = Swift.min(txDelta, credit)
        credit -= paid
        return txDelta - paid
    }
}

public struct TribeRoamingPolicy: Equatable {
    /// true: `.unsatisfied` never turns the device off (rebind-on-return only).
    /// false: upstream behaviour (pause on loss, restart with new handshake on return).
    public var keepBackendOnPathLoss: Bool
    /// > 0: a path loss that PERSISTS this many seconds still pauses the device (long true-offline
    /// fallback, e.g. airplane mode); 0 = never pause. Ignored when keepBackendOnPathLoss is false.
    public var pauseAfterUnsatisfiedSeconds: TimeInterval
    /// Coalescing window for rebind-on-return: bursts of path events become ONE socket step.
    public var rebindCoalesceSeconds: TimeInterval
    /// Stall watchdog: outbound grows while inbound (rx bytes / handshake) is frozen this long on a
    /// satisfied path -> fresh local port + keepalive (tribe.9; tribe.4-8: same-port bump). 0 = off.
    public var stallProbeSeconds: TimeInterval
    /// Still stalled this long AFTER the first step -> soft restart of the backend (tribe.9;
    /// tribe.4-8: listen_port=0). 0 = no second stage.
    public var stallRebindSeconds: TimeInterval
    /// Outbound bytes required since the last inbound progress before a stall is believed
    /// (filters keepalive-only idle: 32 B every 25 s).
    public var stallMinTxBytes: UInt64
    /// tribe.17: the session's own outbound service traffic (handshakes with their junk, keepalives with
    /// their padding), never counted as demand. The provider sets it from the session's configuration.
    public var serviceTraffic: TribeServiceTraffic = .plain

    public init(keepBackendOnPathLoss: Bool,
                pauseAfterUnsatisfiedSeconds: TimeInterval,
                rebindCoalesceSeconds: TimeInterval,
                stallProbeSeconds: TimeInterval,
                stallRebindSeconds: TimeInterval,
                stallMinTxBytes: UInt64) {
        self.keepBackendOnPathLoss = keepBackendOnPathLoss
        self.pauseAfterUnsatisfiedSeconds = pauseAfterUnsatisfiedSeconds
        self.rebindCoalesceSeconds = rebindCoalesceSeconds
        self.stallProbeSeconds = stallProbeSeconds
        self.stallRebindSeconds = stallRebindSeconds
        self.stallMinTxBytes = stallMinTxBytes
    }

    /// Shipped default (server can override every number; see fromConfig).
    public static let seamless = TribeRoamingPolicy(keepBackendOnPathLoss: true,
                                                    pauseAfterUnsatisfiedSeconds: 0,
                                                    rebindCoalesceSeconds: 0.1,
                                                    stallProbeSeconds: 4,
                                                    stallRebindSeconds: 10,
                                                    stallMinTxBytes: 4096)

    /// Upstream wireguard-apple behaviour, byte-for-byte (kill-switch target).
    public static let legacy = TribeRoamingPolicy(keepBackendOnPathLoss: false,
                                                  pauseAfterUnsatisfiedSeconds: 0,
                                                  rebindCoalesceSeconds: 0,
                                                  stallProbeSeconds: 0,
                                                  stallRebindSeconds: 0,
                                                  stallMinTxBytes: 4096)

    /// Values arrive from the app as STRINGS inside the NE provider configuration (JSONDecoder
    /// rejects mixed number types in WGConfig — a known trap). Absent/junk = seamless defaults;
    /// numbers are clamped so an operator typo on the backend cannot disable or storm the tunnel.
    public static func fromConfig(keepBackend: String?,
                                  pauseAfterS: String?,
                                  stallProbeS: String?,
                                  stallRebindS: String?) -> TribeRoamingPolicy {
        var policy = TribeRoamingPolicy.seamless
        if let keep = keepBackend?.trimmingCharacters(in: .whitespacesAndNewlines), keep == "0" {
            policy.keepBackendOnPathLoss = false
        }
        policy.pauseAfterUnsatisfiedSeconds = clamped(pauseAfterS, fallback: policy.pauseAfterUnsatisfiedSeconds, min: 0, max: 600)
        // A long-offline pause must never fire on a short flap (mesh reassociation, Wi-Fi <-> LTE
        // on a staircase is 1-8 s): any positive value below the floor is lifted to the floor.
        if policy.pauseAfterUnsatisfiedSeconds > 0 {
            policy.pauseAfterUnsatisfiedSeconds = Swift.max(minPauseAfterSeconds, policy.pauseAfterUnsatisfiedSeconds)
        }
        policy.stallProbeSeconds = clamped(stallProbeS, fallback: policy.stallProbeSeconds, min: 0, max: 60)
        policy.stallRebindSeconds = clamped(stallRebindS, fallback: policy.stallRebindSeconds, min: 0, max: 120)
        return policy
    }

    /// Shortest long-offline pause accepted from the server (tribe.7): shorter outages are flaps.
    public static let minPauseAfterSeconds: TimeInterval = 15

    private static func clamped(_ raw: String?, fallback: TimeInterval, min: TimeInterval, max: TimeInterval) -> TimeInterval {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty,
              let value = Double(raw), value.isFinite else { return fallback }
        return Swift.min(max, Swift.max(min, value))
    }
}

public enum TribePathLossDecision: Equatable {
    case keepBackend
    case pauseNow
    case pauseAfter(TimeInterval)
}

public struct TribeStallSample: Equatable {
    public var txBytes: UInt64
    public var rxBytes: UInt64
    public var lastHandshakeSec: Int64
    public var at: TimeInterval

    public init(txBytes: UInt64, rxBytes: UInt64, lastHandshakeSec: Int64, at: TimeInterval) {
        self.txBytes = txBytes
        self.rxBytes = rxBytes
        self.lastHandshakeSec = lastHandshakeSec
        self.at = at
    }
}

public enum TribeStallAction: Equatable {
    case none
    /// wgBumpSockets: BindUpdate on the SAME local port + keepalive. tribe.9: only the reaction to
    /// a path event without a real loss (interface order change); no longer a stall-ladder step.
    case bumpSockets
    /// listen_port=0 + keepalive: a fresh local port = a new 5-tuple through the carrier NAT.
    case rebindPort
    /// tribe.8 (U6): wgTurnOff + wgTurnOn on the SAME TUN fd with the same configuration, no
    /// setTunnelNetworkSettings: new device, new socket, new handshake; utun and app flows survive.
    case softRestart

    /// Fixed step name for adapter log lines (never carries endpoints or config values).
    public var logName: String {
        switch self {
        case .none: return "none"
        case .bumpSockets: return "bump"
        case .rebindPort: return "fresh port"
        case .softRestart: return "soft restart"
        }
    }
}

/// Why the shared recovery budget refused an action.
public enum TribeRecoveryDenial: String, Equatable {
    /// This step was already spent in the current stall episode; only inbound progress re-arms it.
    case episode
    /// Rolling energy cap: at most `TribeRecoveryBudget.rollingCap` interventions per window.
    case rollingCap = "rolling_cap"
    /// The same kind of action ran moments ago.
    case cooldown
}

public enum TribeRecoveryKind: Equatable {
    /// wgBumpSockets: same local port, keepalive burst.
    case bump
    /// listen_port=0: fresh local port (new 5-tuple).
    case freshPort
    /// tribe.8: backend restarted in place on the same TUN fd (new device, socket and handshake).
    case softRestart
}

/// Stall watchdog on top of the device's own counters. tribe.16: inbound progress = DATA bytes
/// (TribeDataFlow: a handshake's bytes deducted); a handshake alone is not progress. Data within a
/// second stage after a repair step is the echo of that step: it restarts the stall clock, the stage
/// stays; data after that ends the episode.
/// tribe.17: demand = outbound bytes minus the session's own service traffic (`policy.serviceTraffic`:
/// handshakes with their junk, keepalives with their padding), for every stage, so an idle healthy
/// tunnel shows none at all. `TribeDataFlow.idleSeconds` without demand ends an open episode (and starts
/// the demand count over); a sampling gap is not observed silence.
///
/// tribe.9 ladder: stage 0 armed -> (stalled `stallProbeSeconds`, demand `stallMinTxBytes`)
/// FRESH PORT -> stage 2 -> (stalled `stallProbeSeconds + stallRebindSeconds`, demand x2) SOFT
/// RESTART -> stage 3: while the path is satisfied and outbound keeps growing without any inbound
/// progress, `persistentSequence` continues (fresh port, soft restart, ...) with a backoff of 30, 60,
/// 120 s from the previous step, then 120 s. Inbound progress resets the stage and the backoff.
///
/// A path event (roam) does NOT reset the stall clock: a roam fresh port is recorded as this
/// episode's fresh port (`noteExternalStep`), a same-port roam bump is not recorded at all. tribe.4-8
/// `rearm` zeroed the clock and the stage on every path event, which on cellular (~200 events/h)
/// starved the ladder. The app engine's failover (HealthLoop DEAD) still sits above this.
public struct TribeStallTracker: Equatable {
    /// 0 = armed, 2 = fresh port done (first step), 3 = two or more steps done (persistent phase).
    public private(set) var stage: Int = 0
    /// Steps committed after the first fresh port (the soft restart is step 1). 0 at stage <= 2.
    public private(set) var persistentSteps: Int = 0
    /// Time of the last inbound data (echo included): the stall clock counts from here.
    private var lastProgressAt: TimeInterval
    private var lastRx: UInt64
    private var lastTx: UInt64
    private var lastHandshake: Int64
    private var lastSampleAt: TimeInterval
    /// tribe.17: demand (service traffic not counted) since the last inbound data / since the last step,
    /// and when demand was last seen; the keepalive allowance of `TribeServiceTraffic.demand`.
    private var demandSinceProgress: UInt64 = 0
    private var demandSinceStep: UInt64 = 0
    private var lastDemandAt: TimeInterval
    private var keepaliveCredit: UInt64 = 0
    /// tribe.18 (G4): demand added since the previous completed handshake - the window in which this
    /// handshake's initiation was sent - and `lastDemandAt` as it was when that window began.
    private var demandSinceHandshake: UInt64 = 0
    private var lastDemandAtBeforeWindow: TimeInterval
    /// Time of the last committed step (watchdog, GUI or roam): the second-stage gap, the stage-3
    /// backoff and its demand evidence count from here.
    private var lastStepAt: TimeInterval?
    /// tribe.16: time of the last repair step of any origin (also a roam fresh port the stage-3 cycle
    /// does not count): inbound data closer to it than a second stage is its echo (TribeDataFlow).
    private var lastRepairAt: TimeInterval?
    /// tribe.16: the sample that just ran proved the path (TribeDataFlow); the arbiter keeps its time
    /// for `dataQuietSeconds` (the budget judges the same sample by the same rule itself).
    public private(set) var flowProvedNow = false
    /// tribe.17: the sample that just ran ended an open episode because nobody sent anything for
    /// `TribeDataFlow.idleSeconds` (the arbiter re-arms the budget on it).
    public private(set) var idleEndedNow = false
    /// tribe.17: stalled right now as the ladder judges it: the path is satisfied, nothing came in for
    /// `stallProbeSeconds` and at least `stallMinTxBytes` of demand went out since the last inbound data.
    public private(set) var stalledNow = false

    /// Stage-3 order after the soft restart (persistentSteps = 1 -> index 1 = fresh port first).
    public static let persistentSequence: [TribeStallAction] = [.softRestart, .rebindPort]

    /// Stage-3 backoff before persistent step `index` (0-based): 30, 60, 120 s, capped at 120 s.
    public static func persistentBackoff(_ index: Int) -> TimeInterval {
        let steps: [TimeInterval] = [30, 60, 120]
        return steps[Swift.min(Swift.max(0, index), steps.count - 1)]
    }

    public init(first: TribeStallSample) {
        lastProgressAt = first.at
        lastRx = first.rxBytes
        lastTx = first.txBytes
        lastHandshake = first.lastHandshakeSec
        lastSampleAt = first.at
        lastDemandAt = first.at
        lastDemandAtBeforeWindow = first.at
    }

    /// tribe.8: the backend was restarted in place (soft restart): the counters start from zero on
    /// the new device. Rebase them WITHOUT treating the drop as progress; the stall clock, the stage
    /// and the stage-3 backoff keep running (only real data on the new device resets them). The demand
    /// evidence starts again on the new device.
    public mutating func rebaseCounters(_ sample: TribeStallSample) {
        lastRx = sample.rxBytes
        lastTx = sample.txBytes
        lastHandshake = sample.lastHandshakeSec
        lastSampleAt = sample.at
        demandSinceProgress = 0
        demandSinceStep = 0
        demandSinceHandshake = 0
    }

    /// tribe.10: an external fresh port at stage 2 moves the second-stage clock only when the previous
    /// step is at least this old (roam fresh ports every 4 s must not postpone the soft restart forever).
    public static let externalStepMinGap: TimeInterval = 10

    /// A step done outside the watchdog: a GUI fresh port / soft restart (provider messages) or a
    /// roam fresh port (path returned after a loss). It counts as the episode's step of that kind
    /// and the next watchdog step counts its gap/backoff from it. The stall clock is NOT touched
    /// (rule of tribe.9: only inbound progress restarts it). A same-port bump is not a step.
    /// tribe.10: at stage 2 a fresh port postpones the soft restart only if the previous step is
    /// >= `externalStepMinGap` old; at stage 3 it counts as the due fresh-port step when that is the
    /// next one in the cycle (a socket that just got a new port needs no second one; the same-kind
    /// cooldown would otherwise refuse the watchdog's fresh port forever on a flapping path and the
    /// soft restart would never come), and is ignored when the next step is the soft restart.
    /// `tx` is kept for the callers of tribe.10-16; tribe.17 counts demand from the samples.
    public mutating func noteExternalStep(_ kind: TribeRecoveryKind, at: TimeInterval, tx: UInt64) {
        if kind != .bump { lastRepairAt = at } // tribe.16: its echo is not data, whatever the cycle does with it
        switch kind {
        case .bump:
            return
        case .freshPort:
            if stage < 2 {
                stage = 2
                persistentSteps = 0
            } else if stage >= 3 {
                let next = TribeStallTracker.persistentSequence[persistentSteps % TribeStallTracker.persistentSequence.count]
                guard next == .rebindPort else { return }
                persistentSteps += 1
            } else if let last = lastStepAt, at - last < TribeStallTracker.externalStepMinGap {
                return
            }
        case .softRestart:
            stage = 3
            persistentSteps = Swift.max(persistentSteps, 1)
        }
        lastStepAt = at
        demandSinceStep = 0
    }

    /// tribe.4/tribe.5 entry point: every proposed step is committed immediately; no steps after the
    /// first fresh port.
    public mutating func observe(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy) -> TribeStallAction {
        step(sample, pathSatisfied: pathSatisfied, policy: policy, minGapAfterStep: 0, persistent: false) { _ in true }
    }

    /// tribe.7: the escalation stage moves ONLY when `permit` accepts the proposed action. A refusal
    /// (shared recovery budget: rolling cap, cooldown) leaves the stage where it was, so the same
    /// step is proposed again on the next tick and fires as soon as the budget frees up.
    /// `persistent` (tribe.8/9): steps after the first fresh port; false = fresh port only.
    public mutating func observe(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy,
                                 persistent: Bool = false,
                                 permit: (TribeStallAction) -> Bool) -> TribeStallAction {
        step(sample, pathSatisfied: pathSatisfied, policy: policy,
             minGapAfterStep: TribeStallTracker.minGapAfterStep(policy), persistent: persistent, permit: permit)
    }

    /// tribe.10: the soft restart waits a full second stage after the LAST step (watchdog, GUI or
    /// roam fresh port), not only after the last inbound progress: after a 20 s outage the roam
    /// fresh port on return got 3 s before the soft restart (tribe.9 used min(3, rebind)).
    public static func minGapAfterStep(_ policy: TribeRoamingPolicy) -> TimeInterval {
        policy.stallRebindSeconds
    }

    private mutating func endEpisode(at: TimeInterval) {
        stage = 0
        persistentSteps = 0
        lastStepAt = nil
        lastRepairAt = nil
        demandSinceStep = 0
    }

    private mutating func step(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy,
                               minGapAfterStep: TimeInterval, persistent: Bool,
                               permit: (TribeStallAction) -> Bool) -> TribeStallAction {
        flowProvedNow = false
        idleEndedNow = false
        stalledNow = false
        // Without a first handshake, let AWG's built-in retries run for at least 12 seconds.
        // Handshake-only traffic is smaller than data traffic; still require evidence of demand.
        let bootstrap = sample.lastHandshakeSec == 0 && sample.rxBytes == 0
        let requiredTx = bootstrap ? UInt64(256) : policy.stallMinTxBytes
        let elapsed = sample.at - lastSampleAt
        // counters reset = backend restarted (not announced through rebaseCounters), not a stall
        let countersReset = sample.txBytes < lastTx || sample.rxBytes < lastRx
        let handshakeChanged = sample.lastHandshakeSec > lastHandshake
        let data = countersReset ? 0 : TribeDataFlow.dataBytes(rxDelta: sample.rxBytes - lastRx,
                                                                handshakeChanged: handshakeChanged)
        let demand = countersReset ? 0 : policy.serviceTraffic.demand(txDelta: sample.txBytes - lastTx,
                                                                      elapsed: elapsed, credit: &keepaliveCredit)
        lastRx = sample.rxBytes
        lastTx = sample.txBytes
        lastHandshake = sample.lastHandshakeSec
        lastSampleAt = sample.at
        if elapsed > TribeDataFlow.samplingGapSeconds {
            // tribe.17: nothing was observed in between (the extension was suspended): neither silence
            // nor data. The stall clock and the demand count start again from here; no step on it.
            lastProgressAt = sample.at
            demandSinceProgress = 0
            demandSinceStep = 0
            demandSinceHandshake = 0
            lastDemandAt = sample.at
            lastDemandAtBeforeWindow = sample.at
            return .none
        }
        if countersReset || (data > 0 && TribeDataFlow.provesFlow(dataAt: sample.at, lastRepairAt: lastRepairAt,
                                                                   window: policy.stallRebindSeconds)) {
            // tribe.16: data is flowing (or a new device): the episode is over.
            lastProgressAt = sample.at
            demandSinceProgress = 0
            endEpisode(at: sample.at)
            flowProvedNow = !countersReset
            return .none
        }
        if data > 0 {
            // tribe.16: the echo of the last repair step. The stall clock and the demand count start
            // again from here; the stage, the stage-3 backoff and the last step stay, so a stall that
            // returns goes on with the NEXT step instead of repeating the first one.
            lastProgressAt = sample.at
            demandSinceProgress = 0
            return .none
        }
        demandSinceProgress &+= demand
        demandSinceStep &+= demand
        demandSinceHandshake &+= demand
        if demand > 0 { lastDemandAt = sample.at }
        let handshakeTx = policy.serviceTraffic.handshakeTxBytes
        if handshakeChanged {
            // tribe.18 (G4): the handshake's own bytes are settled against everything sent since the previous
            // handshake (its initiation may have left samples earlier than its response came in); when that
            // was all there was, it was not demand at all.
            let window = demandSinceHandshake
            let settled = Swift.min(handshakeTx, window)
            demandSinceProgress = demandSinceProgress > settled ? demandSinceProgress - settled : 0
            demandSinceStep = demandSinceStep > settled ? demandSinceStep - settled : 0
            if window <= handshakeTx { lastDemandAt = lastDemandAtBeforeWindow }
            demandSinceHandshake = 0
            lastDemandAtBeforeWindow = lastDemandAt
            // A completed handshake while less than a stall's demand went out since a count began: the
            // session answers, and at that rate the ladder cannot judge the path - the count starts over
            // (tribe.15's floor, ~270 B/s on a path that re-keys every 15 s; the data watch judges such
            // paths). Never the stall clock or the stage: a handshake is not data. tribe.17: for both
            // counts, and the handshake's own bytes are the session's (`serviceTraffic`).
            if demandSinceProgress < requiredTx { demandSinceProgress = 0 }
            if demandSinceStep < requiredTx { demandSinceStep = 0 }
        }
        if sample.at - Swift.max(lastDemandAt, lastStepAt ?? lastDemandAt) >= TribeDataFlow.idleSeconds {
            // tribe.17: nobody sends anything: no stall to judge, and no repair to prove. The demand count
            // starts over; an open episode ends (the next stall starts at the first step again).
            demandSinceProgress = 0
            if stage != 0 || lastStepAt != nil {
                endEpisode(at: sample.at)
                idleEndedNow = true
            }
        }
        guard pathSatisfied, policy.stallProbeSeconds > 0 else { return .none }
        let stalledFor = sample.at - lastProgressAt
        let probeSeconds = bootstrap ? max(12, policy.stallProbeSeconds) : policy.stallProbeSeconds
        let rebindSeconds = bootstrap ? max(18, policy.stallRebindSeconds) : policy.stallRebindSeconds
        // tribe.18 (G4): what went out since the last handshake may hold one initiation still waiting for its
        // response (a re-key, a retry): one handshake's worth of it is not demand until that is settled.
        let held = Swift.min(demandSinceHandshake, handshakeTx)
        let demandNow = demandSinceProgress > held ? demandSinceProgress - held : 0
        let demandNowSinceStep = demandSinceStep > held ? demandSinceStep - held : 0
        stalledNow = stalledFor >= probeSeconds && demandNow >= requiredTx
        switch stage {
        case 0, 1:
            if stalledNow, permit(.rebindPort) {
                stage = 2
                persistentSteps = 0
                lastStepAt = sample.at
                lastRepairAt = sample.at
                demandSinceStep = 0
                return .rebindPort
            }
        case 2:
            guard persistent, policy.stallRebindSeconds > 0, let last = lastStepAt else { return .none }
            if stalledFor >= probeSeconds + rebindSeconds && demandNow >= requiredTx * 2
                && sample.at - last >= max(minGapAfterStep, rebindSeconds), permit(.softRestart) {
                stage = 3
                persistentSteps = 1
                lastStepAt = sample.at
                lastRepairAt = sample.at
                demandSinceStep = 0
                return .softRestart
            }
        default:
            // Stage 3: a refusal leaves every field untouched, so the same step is proposed again on
            // the next tick (rule D1).
            guard persistent, policy.stallRebindSeconds > 0, let last = lastStepAt else { return .none }
            let sinceStep = sample.at - last
            // tribe.16: and a stall NOW (the echo of the previous step may have moved the clock).
            // tribe.17: the demand since the step is service-traffic free too (an idle repaired tunnel).
            guard sinceStep >= TribeStallTracker.persistentBackoff(persistentSteps - 1), demandNowSinceStep >= requiredTx,
                  stalledNow else {
                return .none
            }
            let next = TribeStallTracker.persistentSequence[persistentSteps % TribeStallTracker.persistentSequence.count]
            if permit(next) {
                persistentSteps += 1
                lastStepAt = sample.at
                lastRepairAt = sample.at
                demandSinceStep = 0
                return next
            }
        }
        return .none
    }
}

/// One owner (adapter workQueue) arbitrates GUI and autonomous repairs. An episode holds at most
/// one fresh port and one soft restart; only inbound progress re-arms it. Path notifications alone
/// do not grant another repair budget, while the rolling cap remains in force.
///
/// tribe.7: the cooldown only separates actions of the SAME kind. tribe.6 applied an 8-10 s cooldown
/// between ANY two actions, which is longer than the watchdog's own first -> second step at low
/// outbound rates, so the second stage was refused.
public struct TribeRecoveryBudget: Equatable {
    public static let rollingWindow: TimeInterval = 120
    public static let rollingCap = 4

    /// Denial streaks (a refusal repeated on every watchdog tick counts once until a permit/progress).
    public private(set) var denied: UInt64 = 0
    public private(set) var interventions: UInt64 = 0
    public private(set) var lastDenial: TribeRecoveryDenial?
    public private(set) var bumpSpent = false
    public private(set) var freshPortSpent = false
    public private(set) var softRestartSpent = false
    private var recent: [TimeInterval] = []
    private var lastBumpAt: TimeInterval?
    private var lastFreshPortAt: TimeInterval?
    private var lastSoftRestartAt: TimeInterval?
    private var lastRx: UInt64 = 0
    private var lastTx: UInt64 = 0
    private var lastHandshake: Int64 = 0
    private var inDenialStreak = false
    private let cooldown: TimeInterval

    public init(jitter: TimeInterval = 0) { cooldown = 8 + min(2, max(0, jitter)) }

    public var episodeUsed: Int { (bumpSpent ? 1 : 0) + (freshPortSpent ? 1 : 0) + (softRestartSpent ? 1 : 0) }

    /// tribe.8: counters that go DOWN belong to a new device (soft restart, resume): rebase them
    /// without calling it progress. tribe.7 kept the old rx and saw no progress on the new device
    /// until it had moved more bytes than the old one.
    /// tribe.16: the episode re-arms on DATA (TribeDataFlow: a handshake's bytes deducted) and only
    /// when it is not the echo of this budget's own last repair (`proofWindow` after it, the
    /// arbiter passes its policy's second stage); a handshake alone no longer re-arms it.
    public mutating func observe(_ sample: TribeStallSample, proofWindow: TimeInterval = 0) {
        let countersReset = sample.rxBytes < lastRx || sample.txBytes < lastTx
        if !countersReset {
            let data = TribeDataFlow.dataBytes(rxDelta: sample.rxBytes - lastRx,
                                               handshakeChanged: sample.lastHandshakeSec > lastHandshake)
            if data > 0 && TribeDataFlow.provesFlow(dataAt: sample.at, lastRepairAt: lastRepairAt, window: proofWindow) {
                resetEpisode()
            }
        }
        lastRx = sample.rxBytes
        lastTx = sample.txBytes
        lastHandshake = sample.lastHandshakeSec
    }

    /// tribe.16: the newest repair this budget committed or was told about (bumps are not repairs).
    private var lastRepairAt: TimeInterval? {
        [lastFreshPortAt, lastSoftRestartAt].compactMap { $0 }.max()
    }

    /// Re-arm the episode (inbound progress, or a resumed backend after a long-offline pause).
    /// The rolling cap and the same-kind cooldowns stay in force.
    public mutating func resetEpisode() {
        bumpSpent = false
        freshPortSpent = false
        softRestartSpent = false
        inDenialStreak = false
    }

    /// nil = permitted and committed; otherwise the reason nothing was done. `persistent` = a
    /// stage-3 watchdog step (tribe.8): it is not limited by the episode (its own 30/60/120 s
    /// backoff paces it), but the rolling cap and the same-kind cooldown still apply.
    public mutating func request(at: TimeInterval, kind: TribeRecoveryKind, persistent: Bool = false) -> TribeRecoveryDenial? {
        recent.removeAll { at - $0 >= TribeRecoveryBudget.rollingWindow }
        let spent: Bool
        let lastSameKind: TimeInterval?
        switch kind {
        case .bump:
            spent = bumpSpent || freshPortSpent
            lastSameKind = lastBumpAt
        case .freshPort:
            spent = freshPortSpent
            lastSameKind = lastFreshPortAt
        case .softRestart:
            spent = softRestartSpent
            lastSameKind = lastSoftRestartAt
        }
        let denial: TribeRecoveryDenial?
        if spent && !persistent {
            denial = .episode
        } else if recent.count >= TribeRecoveryBudget.rollingCap {
            denial = .rollingCap
        } else if let last = lastSameKind, at - last < cooldown {
            denial = .cooldown
        } else {
            denial = nil
        }
        if let denial {
            if !inDenialStreak { denied += 1 }
            inDenialStreak = true
            lastDenial = denial
            return denial
        }
        inDenialStreak = false
        switch kind {
        case .bump:
            bumpSpent = true
            lastBumpAt = at
        case .freshPort:
            // A new socket consumes the whole episode: no same-port bump after it.
            bumpSpent = true
            freshPortSpent = true
            lastFreshPortAt = at
        case .softRestart:
            // A new device (new socket, new handshake) consumes everything smaller too.
            bumpSpent = true
            freshPortSpent = true
            softRestartSpent = true
            lastSoftRestartAt = at
        }
        recent.append(at)
        interventions += 1
        return nil
    }

    /// tribe.6 API (kept for callers that only need yes/no).
    public mutating func permit(at: TimeInterval, freshPort: Bool) -> Bool {
        request(at: at, kind: freshPort ? .freshPort : .bump) == nil
    }

    /// tribe.10: a roam fresh port (path returned after a loss / interface change) is not gated by
    /// the cap, but it IS the episode's fresh port: the GUI `rebind` afterwards gets `.episode` and
    /// the engine moves on to its next step instead of rebinding the socket a second time.
    public mutating func noteExternalFreshPort(at: TimeInterval) {
        bumpSpent = true
        freshPortSpent = true
        lastFreshPortAt = at
        inDenialStreak = false
    }
}

/// Outcome of one stall-watchdog tick after budget arbitration.
public enum TribeWatchdogOutcome: Equatable {
    case none
    case perform(TribeStallAction)
    case denied(TribeStallAction, TribeRecoveryDenial)
}

/// Result of a GUI-requested fresh-port rebind (provider message `rebind`, contract K4).
public enum TribeRebindResult: Equatable {
    case performed
    case notStarted
    case offline
    case budget(TribeRecoveryDenial)

    /// Reply body for the provider message: {"rebind":"performed"} |
    /// {"rebind":"denied","reason":"budget"|"not_started"|"offline"}.
    public var responsePayload: [String: String] {
        switch self {
        case .performed: return ["rebind": "performed"]
        case .notStarted: return ["rebind": "denied", "reason": "not_started"]
        case .offline: return ["rebind": "denied", "reason": "offline"]
        case .budget: return ["rebind": "denied", "reason": "budget"]
        }
    }

    public var logDescription: String {
        switch self {
        case .performed: return "performed"
        case .notStarted: return "denied (adapter not started)"
        case .offline: return "denied (path unsatisfied)"
        case .budget(let reason): return "denied by recovery budget (\(reason.rawValue))"
        }
    }
}

/// Result of a GUI-requested soft restart of the backend (provider message `soft_restart`, tribe.8).
public enum TribeSoftRestartResult: Equatable {
    case performed
    case notStarted
    case offline
    case budget(TribeRecoveryDenial)
    /// wgTurnOn on the same TUN fd failed; the adapter is paused until the path is re-evaluated.
    case failed

    /// Reply body: {"soft_restart":"performed"} |
    /// {"soft_restart":"denied","reason":"budget"|"not_started"|"offline"|"failed"}.
    public var responsePayload: [String: String] {
        switch self {
        case .performed: return ["soft_restart": "performed"]
        case .notStarted: return ["soft_restart": "denied", "reason": "not_started"]
        case .offline: return ["soft_restart": "denied", "reason": "offline"]
        case .budget: return ["soft_restart": "denied", "reason": "budget"]
        case .failed: return ["soft_restart": "denied", "reason": "failed"]
        }
    }

    public var logDescription: String {
        switch self {
        case .performed: return "performed"
        case .notStarted: return "denied (adapter not started)"
        case .offline: return "denied (path unsatisfied)"
        case .budget(let reason): return "denied by recovery budget (\(reason.rawValue))"
        case .failed: return "denied (backend restart failed)"
        }
    }
}

/// Stall tracker + shared recovery budget under one owner (the adapter's workQueue). Pure logic:
/// the adapter feeds samples and executes whatever `.perform` says.
public struct TribeRecoveryArbiter: Equatable {
    public private(set) var budget: TribeRecoveryBudget
    public private(set) var tracker: TribeStallTracker?
    /// Steps after the first fresh port (soft restart, then the stage-3 cycle). false = fresh port only.
    public let persistentHeal: Bool
    /// tribe.16: the second stage of the last policy seen by `tick` (the echo window of TribeDataFlow
    /// for the budget's samples outside the tick).
    private var proofWindow: TimeInterval = TribeRoamingPolicy.seamless.stallRebindSeconds
    /// tribe.16: when inbound data last proved the path (TribeDataFlow), and the last sample seen;
    /// survives tracker resets (watchdog restart, resume), not the adapter.
    /// tribe.17: `observedSince` = the first sample after the start or after a sampling gap: what was
    /// not observed is never counted as quiet time.
    private var lastFlowAt: TimeInterval?
    private var observedSince: TimeInterval?
    private var lastSampleAt: TimeInterval?

    public init(jitter: TimeInterval = 0, persistentHeal: Bool = true) {
        budget = TribeRecoveryBudget(jitter: jitter)
        self.persistentHeal = persistentHeal
    }

    /// tribe.16: samples older than this make `dataQuietSeconds` unknown (the watchdog ticks every
    /// 1 s, every 5 s while idle or offline; a paused backend or a stopped watchdog sends none).
    public static let quietSampleMaxAgeSeconds: TimeInterval = 12

    /// The extension's verdict for the app's failover (exported as `data_stall_s`): how long the path
    /// has gone without inbound data that proved it (TribeDataFlow: not a handshake, not the echo of a
    /// repair step), reported ONLY while the ladder sees a stall right now (`TribeStallTracker.stalledNow`:
    /// nothing in for `stallProbeSeconds` while `stallMinTxBytes` of demand, service traffic not counted,
    /// went out). 0 = not stalled now: data is coming in (also inside a repair's echo window, so a path
    /// that has just recovered is never reported), or nobody sends anything (an idle phone whose probes
    /// fail locally). Counted from the first observed sample, never across a sampling gap. -1 = unknown
    /// (no sample yet, or the last one is older than `quietSampleMaxAgeSeconds`).
    /// (tribe.16 exported the proven-flow age alone, also while data was already returning.)
    public func dataQuietSeconds(at now: TimeInterval) -> Int64 {
        guard let last = lastSampleAt, now - last <= TribeRecoveryArbiter.quietSampleMaxAgeSeconds,
              let observed = observedSince else { return -1 }
        guard tracker?.stalledNow == true else { return 0 }
        let since = Swift.max(lastFlowAt ?? observed, observed)
        return Int64(Swift.max(0, now - since).rounded(.down))
    }

    /// tribe.8: the backend was restarted in place and its counters start from zero.
    public mutating func rebaseAfterBackendRestart(_ sample: TribeStallSample) {
        budget.observe(sample, proofWindow: proofWindow)
        tracker?.rebaseCounters(sample)
    }

    /// tribe.8: the backend came back from a long-offline pause (new device, new handshake):
    /// the episode re-arms, the rolling cap stays. The next sample seeds a fresh tracker.
    public mutating func noteBackendResumed() {
        budget.resetEpisode()
        tracker = nil
    }

    /// Watchdog (re)start or pause: the next sample seeds a fresh tracker. The budget persists.
    public mutating func resetTracker() { tracker = nil }

    /// tribe.9: a path event just rebound the socket. `freshPort` = the path returned after a real
    /// loss or moved to another interface (new local port + keepalive): recorded as the episode's
    /// fresh port, so the watchdog's next step is the soft restart, not another fresh port. A
    /// same-port bump (path event without a loss) is not a ladder step. Neither touches the stall
    /// clock (tribe.4-8 `rearmAfterRoam` restarted it on every path event and starved the ladder).
    public mutating func noteRoamRebind(_ sample: TribeStallSample, freshPort: Bool) {
        budget.observe(sample, proofWindow: proofWindow)
        if tracker == nil {
            tracker = TribeStallTracker(first: sample)
        }
        if freshPort {
            budget.noteExternalFreshPort(at: sample.at) // tribe.10: the episode's fresh port
            tracker?.noteExternalStep(.freshPort, at: sample.at, tx: sample.txBytes)
        }
    }

    public mutating func tick(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy) -> TribeWatchdogOutcome {
        proofWindow = policy.stallRebindSeconds
        budget.observe(sample, proofWindow: proofWindow)
        if observedSince == nil || sample.at - (lastSampleAt ?? sample.at) > TribeDataFlow.samplingGapSeconds {
            observedSince = sample.at // tribe.17: the start, or the end of a sampling gap
        }
        lastSampleAt = sample.at
        guard var current = tracker else {
            tracker = TribeStallTracker(first: sample)
            return .none
        }
        var proposed = TribeStallAction.none
        var denial: TribeRecoveryDenial?
        var budget = self.budget
        // Stage 3 proposes persistent steps (not limited by the episode; its own backoff paces it).
        let persistentPhase = current.stage >= 3
        let action = current.observe(sample, pathSatisfied: pathSatisfied, policy: policy,
                                     persistent: persistentHeal) { step in
            proposed = step
            denial = budget.request(at: sample.at, kind: TribeRecoveryArbiter.kind(of: step), persistent: persistentPhase)
            return denial == nil
        }
        self.budget = budget
        if current.flowProvedNow { lastFlowAt = sample.at }
        if current.idleEndedNow { self.budget.resetEpisode() } // tribe.17: the episode ended, nobody sent anything
        if action == .none, let denial, denial == .episode, current.stage < 3 {
            // tribe.10: the budget already spent this step (counters dropped without a rebase reset
            // the tracker to stage 0): re-sync so the ladder continues instead of asking forever.
            current.noteExternalStep(budget.softRestartSpent ? .softRestart : .freshPort,
                                     at: sample.at, tx: sample.txBytes)
        }
        tracker = current
        if action != .none { return .perform(action) }
        guard proposed != .none, let denial else { return .none }
        return .denied(proposed, denial)
    }

    private static func kind(of step: TribeStallAction) -> TribeRecoveryKind {
        switch step {
        case .rebindPort: return .freshPort
        case .softRestart: return .softRestart
        case .none, .bumpSockets: return .bump
        }
    }

    /// GUI-requested fresh port (`rebindListenPort`). `sample` nil = counters unreadable.
    public mutating func requestFreshPort(_ sample: TribeStallSample?, pathSatisfied: Bool) -> TribeRebindResult {
        guard pathSatisfied else { return .offline }
        guard let sample else { return .notStarted }
        budget.observe(sample, proofWindow: proofWindow)
        if let denial = budget.request(at: sample.at, kind: .freshPort) { return .budget(denial) }
        if tracker == nil { tracker = TribeStallTracker(first: sample) }
        tracker?.noteExternalStep(.freshPort, at: sample.at, tx: sample.txBytes)
        return .performed
    }

    /// tribe.8 (U6): GUI-requested soft restart (provider message `soft_restart`). One per episode
    /// through the shared budget; on `.performed` the caller restarts the backend and then calls
    /// `rebaseAfterBackendRestart` with the new device's first sample.
    public mutating func requestSoftRestart(_ sample: TribeStallSample?, pathSatisfied: Bool) -> TribeSoftRestartResult {
        guard pathSatisfied else { return .offline }
        guard let sample else { return .notStarted }
        budget.observe(sample, proofWindow: proofWindow)
        if let denial = budget.request(at: sample.at, kind: .softRestart) { return .budget(denial) }
        if tracker == nil { tracker = TribeStallTracker(first: sample) }
        tracker?.noteExternalStep(.softRestart, at: sample.at, tx: sample.txBytes)
        return .performed
    }

    /// tribe.14 (data watch, stage 2): an in-place switch of the peer. It is a new device like a
    /// soft restart, but on ANOTHER node, so the episode of the node being left does not limit it;
    /// the rolling cap of interventions and the cooldown between two new devices do. On
    /// `.performed` the caller replaces the backend and then calls `rebaseAfterBackendRestart`
    /// with the new device's first sample.
    public mutating func requestPeerSwitch(_ sample: TribeStallSample?, pathSatisfied: Bool) -> TribeSoftRestartResult {
        guard pathSatisfied else { return .offline }
        guard let sample else { return .notStarted }
        budget.observe(sample, proofWindow: proofWindow)
        if let denial = budget.request(at: sample.at, kind: .softRestart, persistent: true) { return .budget(denial) }
        return .performed
    }
}

public struct TribeRoamingCounters: Equatable {
    public var pathLost: UInt64 = 0
    public var pathRestored: UInt64 = 0
    public var roamBumps: UInt64 = 0
    /// tribe.9: fresh local port on a path that returned after a loss / moved to another interface.
    public var roamFreshPorts: UInt64 = 0
    public var stallBumps: UInt64 = 0
    public var stallRebinds: UInt64 = 0
    public var pauses: UInt64 = 0
    public var resumes: UInt64 = 0
    public var recoveryUsed: UInt64 = 0
    public var recoveryDenied: UInt64 = 0
    public var recoveryInterventions: UInt64 = 0
    /// tribe.8: stage-3 watchdog steps (U9) and in-place backend restarts (U6, NE or GUI).
    public var stallPersistent: UInt64 = 0
    public var softRestarts: UInt64 = 0
    /// tribe.16: `TribeRecoveryArbiter.dataQuietSeconds` at the moment of the read (-1 = unknown).
    /// A reading, not a counter: never in `asDictionary` / `summary` (they are journaled on change).
    public var dataQuietSeconds: Int64 = -1

    public init() {}

    public var asDictionary: [String: UInt64] {
        ["path_lost": pathLost, "path_restored": pathRestored, "roam_bumps": roamBumps, "roam_fresh_ports": roamFreshPorts,
         "stall_bumps": stallBumps, "stall_rebinds": stallRebinds, "pauses": pauses, "resumes": resumes,
         "recovery_used": recoveryUsed, "recovery_denied": recoveryDenied, "recovery_interventions": recoveryInterventions,
         "stall_persistent": stallPersistent, "soft_restarts": softRestarts]
    }

    public var summary: String {
        "path_lost=\(pathLost) path_restored=\(pathRestored) roam_bumps=\(roamBumps) roam_fresh_ports=\(roamFreshPorts) stall_bumps=\(stallBumps) stall_rebinds=\(stallRebinds) pauses=\(pauses) resumes=\(resumes)"
    }
}

/// Socket operations the adapter performs for a stall step, in order.
public enum TribeSocketOp: Equatable {
    /// UAPI listen_port=0: close the UDP socket and reopen it on a NEW ephemeral port.
    case freshListenPort
    /// wgBumpSockets: BindUpdate on the current port + keepalive to every peer with a live keypair.
    case bumpWithKeepalive
    /// tribe.8: wgSendKeepalives: keepalive to every peer with a live keypair, no BindUpdate.
    case sendKeepalive
    /// tribe.8: wgTurnOff + wgTurnOn on the same TUN fd (no setTunnelNetworkSettings).
    case restartBackend
}

public enum TribeRoaming {
    /// Every socket step ends with a keepalive: `listen_port=0` alone sends nothing, so until our
    /// next data packet the server keeps our OLD outer address and inbound traffic (a VoIP call) is
    /// lost. tribe.8: after the fresh port only the keepalive goes out (tribe.7 re-bound the new
    /// socket a second time through wgBumpSockets). A soft restart needs no keepalive: the new
    /// device has no keypair yet, the first queued packet starts its handshake.
    public static func socketOps(for action: TribeStallAction) -> [TribeSocketOp] {
        switch action {
        case .none: return []
        case .bumpSockets: return [.bumpWithKeepalive]
        case .rebindPort: return [.freshListenPort, .sendKeepalive]
        case .softRestart: return [.restartBackend]
        }
    }

    /// tribe.9: what a (re)appearing path gets. After a REAL loss (the path was unsatisfied) or a
    /// move to another interface (Wi-Fi <-> cellular) the old 5-tuple is dead or foreign to the new
    /// NAT: a fresh local port + keepalive (upstream restarts the whole device here and gets a new
    /// port as a side effect). A path event without a loss on the same interface (interface order,
    /// DNS, expensive flag) keeps the upstream reaction: a same-port bump.
    public static func roamRebindAction(realLoss: Bool, interfaceChanged: Bool) -> TribeStallAction {
        (realLoss || interfaceChanged) ? .rebindPort : .bumpSockets
    }

    /// `legacyWouldPause` = upstream's own gates (12 s grace after applying routes, first handshake
    /// seen). They stay in force for the long-offline fallback so a pause never fires during bootstrap.
    public static func pathLossDecision(policy: TribeRoamingPolicy, legacyWouldPause: Bool) -> TribePathLossDecision {
        guard policy.keepBackendOnPathLoss else {
            return legacyWouldPause ? .pauseNow : .keepBackend
        }
        if policy.pauseAfterUnsatisfiedSeconds > 0 && legacyWouldPause {
            return .pauseAfter(policy.pauseAfterUnsatisfiedSeconds)
        }
        return .keepBackend
    }

    /// Sum tx/rx over all peers of a wgGetConfig UAPI dump; newest handshake wins; junk -> zeros.
    public static func parseSample(uapi: String, at: TimeInterval) -> TribeStallSample {
        var tx: UInt64 = 0
        var rx: UInt64 = 0
        var handshake: Int64 = 0
        for line in uapi.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("tx_bytes="), let v = UInt64(line.dropFirst("tx_bytes=".count)) {
                tx &+= v
            } else if line.hasPrefix("rx_bytes="), let v = UInt64(line.dropFirst("rx_bytes=".count)) {
                rx &+= v
            } else if line.hasPrefix("last_handshake_time_sec="), let v = Int64(line.dropFirst("last_handshake_time_sec=".count)) {
                handshake = max(handshake, v)
            }
        }
        return TribeStallSample(txBytes: tx, rxBytes: rx, lastHandshakeSec: handshake, at: at)
    }
}

// MARK: - Backend restart hook (tribe.12, patch 0015)

/// What the adapter is about to do to its WireGuard backend by itself (or on the provider's stop).
public enum TribeBackendRestart: String, Equatable {
    /// pauseBackend: wgTurnOff, the adapter goes to temporaryShutdown (a lost path).
    case pause
    /// restartBackendInPlace: wgTurnOff + wgTurnOn (soft restart, stall watchdog ladder).
    case restart
    /// The device's UDP socket is rebound or the endpoints re-set (roam, stall ladder, fresh port).
    case rebind
    /// stop(): the provider's own stop.
    case stop
}

/// Runs the adapter's `tribeBackendWillRestart` callback (when set) synchronously, then the
/// backend operation. nil = only the operation (the behaviour without the hook). A provider may see
/// more than one call for one recovery step (a roam re-sets endpoints and rebinds the port); its
/// reaction (stop the probes next to the backend) must be idempotent.
public enum TribeBackendHook {
    @discardableResult
    public static func before<T>(_ reason: TribeBackendRestart, _ willRestart: ((TribeBackendRestart) -> Void)?,
                                 _ operation: () throws -> T) rethrows -> T {
        willRestart?(reason)
        return try operation()
    }
}

// SPDX-License-Identifier: MIT
// Tribe data watch (awg-apple tribe.13, iOS build 140): pure verdict logic, no clocks and no I/O.
//
// Why this file exists: on an iPhone the data-path check and the failover live in the app, and iOS
// suspends the app. Field case 13.11.2026: the AmneziaWG handshake passes, data does not; for
// 6 min 50 s nothing judged the node while the screen said Connected (`rx=92 tx=25224`). The stall
// watchdog in TribeRoaming.swift cannot see that path: a new handshake is inbound progress for it,
// and the engine re-handshakes every ~15 s on such a path, so its stage keeps resetting.
//
// Two parts, one owner (the adapter's EXISTING stall tick, WireGuardAdapter.stallTick, workQueue):
//
// 1. The PASSIVE rule decides WHEN to ask. It is about data only. A handshake response adds
//    exactly 92 bytes to rx_bytes (amneziawg-go v3.1.20260828 device/receive.go:
//    `peer.rxBytes.Add(len(elem.packet))` for MessageResponseType) and is not data; a completed
//    handshake also costs outbound bytes that are not demand (special packets, junk, padding and
//    the 148-byte initiation, device/send.go SendHandshakeInitiation). The rule is "several cycle
//    windows in a row we kept sending and not one transport packet came back".
// 2. The ACTIVE probe is the judge. The passive rule alone can be wrong on a healthy path: with
//    one-way upload the server may answer with handshake responses only (a handshake response
//    cancels its pending keepalive, device/timers.go; the fleet's keepalive timeout is 5-15 s
//    against the client's 15 s new-handshake timer). So the provider sends a small packet THROUGH
//    the tunnel (tribeprobe.go) and `no_data` needs a silent probe. An answered probe refutes the
//    passive rule and is journaled as such: that count is the gate for layer 2.
//    "Silent" is told by the Go layer only for a packet the device took while a keypair could
//    send. When the engine holds no such keypair (no handshake completed, or the last one is
//    older than a keypair lives) a probe cannot leave the phone at all; the judge is then the
//    engine's own handshake: initiations going out for a whole chain of dead cycles with not one
//    response (`evidence=handshake`). A probe whose wait was disturbed (device restart, new
//    handshake, path event, inbound data) judges nothing and is counted as `disturbed`.
//
// The verdict does NOT depend on what the stall ladder did: below ~270 B/s of demand the ladder
// never steps (a completed handshake is progress for it), and the 13.11 path stayed unjudged.
//
// There is no timer here and nothing is executed here: stage 1 (layer 1) only reports.
// `TribeDataWatchAction.switchPeer` / `.exhausted` are reserved for stage 2 and are never
// returned by this version.
//
// This file has NO NetworkExtension/Go dependency: the conan recipe compiles it together with
// tests/TribeDataWatchTests.swift under plain swiftc (build gate), like TribeRoaming.swift.
import Foundation

public enum TribeDataVerdict: String, Equatable {
    /// Nothing to say: healthy, idle, or not judged.
    case none
    /// An episode is open (dead cycles seen); the passive rule is not met, or it was refuted by an
    /// answered probe, or its checks are still running.
    case suspect
    /// The passive rule is met, the physical network answers, and the judge confirmed it: the
    /// probe through the tunnel is silent, or the engine has no session and its handshakes have
    /// gone unanswered for a whole chain of dead cycles.
    case noData = "no_data"
    /// The passive rule is met but nothing could judge it (probe off, unavailable, not sent or
    /// rate-limited). A shadow verdict only: layer 2 never acts on it.
    case unconfirmed
    /// The passive rule is met, but the request that bypasses the tunnel got no reply.
    case network
    /// The passive rule is met, but the bypass request got a foreign reply (a login page).
    case captive
    /// Reported once when inbound data ends a no_data / unconfirmed / network / captive.
    case recovered
}

public enum TribeDataWatchAction: Equatable {
    case keep
    /// Something worth a journal line happened (see `TribeDataWatchOutput.report`). Nobody is moved.
    case report
    /// Reserved for stage 2 (in-place peer switch). Never returned by this version.
    case switchPeer
    /// Reserved for stage 2 (candidates exhausted). Never returned by this version.
    case exhausted
}

/// What a `.report` is about (the journal line carries it as `event=`).
public enum TribeDataWatchReport: String, Equatable {
    /// The verdict changed.
    case verdict
    /// The passive rule was met and the probe was ANSWERED: a false decision of the passive rule.
    case refuted
    /// Result of a probe that changes no verdict: the low-inbound trigger, or a passive rule that
    /// was no longer met when the result arrived.
    case probe
    /// A probe asked by the passive rule could not be judged: its wait was disturbed (device
    /// restart, new handshake, path event, inbound data) or the packet was only staged. Counted
    /// apart from `refuted` so that the shadow period can see how often the judge is void.
    case disturbed
    /// The app fell silent while the verdict was no_data: the shadow mark turned on.
    case wouldSwitch = "would_switch"
}

/// Result of the request that bypasses the tunnel (bound to the physical interface).
public enum TribeSanityResult: String, Equatable {
    case unknown
    case ok
    case noReply = "no_reply"
    case captive
}

/// State of the probe sent through the tunnel, as the provider knows it.
public enum TribeProbeResult: String, Equatable {
    case none
    case pending
    /// A reply came back through the tunnel.
    case answered
    /// The device took the packet while a keypair could send, and nothing came back in time.
    case silent
    /// The probe was not started: the engine holds no keypair that may send now (no handshake
    /// completed, or the last one is too old). Nothing was injected.
    case noSession = "no_session"
    /// The packet was injected but cannot be judged: the device took it without a usable keypair
    /// (it was only staged) or a new session began during the wait.
    case staged
    /// The packet never reached the device (nothing read the tunnel within the timeout).
    case notSent = "not_sent"
    /// There is no probe in this session (no wrapper, no IPv4 client address, no resolver).
    case unavailable
}

public enum TribeProbeReason: String, Equatable {
    /// The passive rule is met.
    case passive
    /// A lot was sent and very little data came back within the suspect window.
    case lowRx = "low_rx"
}

/// What confirmed a `no_data` verdict.
public enum TribeVerdictEvidence: String, Equatable {
    case none
    /// A probe through the tunnel left under a keypair and stayed unanswered.
    case probe
    /// The engine has no session: its handshake initiations went unanswered for a whole chain.
    case handshake
}

/// Server-driven policy (REMOTE-TUNING: `features.ios_tunnel_watch*`, `numbers.ios_tw_*`). The app
/// clamps the values once (ConnectTunables.h) and writes them into the plan file; the extension
/// clamps them again here, so a typo on the backend cannot storm or blind the watch.
public struct TribeDataWatchPolicy: Equatable {
    /// Layer 1. false = the watch does nothing at all (build 139 behaviour).
    public var enabled = false
    /// Layer 2 (stage 2). Carried only; this version never switches.
    public var switchEnabled = false
    /// The verdict needs a fresh successful bypass request. false = judge without it.
    public var sanityRequired = true
    /// false = never probe: a met passive rule stays `unconfirmed`.
    public var probeEnabled = true
    /// Length of one cycle window. Above the fleet's upper keepalive bound (15 s) with a margin.
    public var cycleSeconds: TimeInterval = 25
    /// Outbound demand a window needs (the bytes of a COMPLETED handshake already deducted). It
    /// sits above what a healthy idle tunnel sends by itself in one cycle: two keepalives (at most
    /// 96 B each with the fleet's padding) and one handshake initiation that is not completed in
    /// that sample (special packet + 6 junk packets of 50 B + 64 B padding + 148 B = 559 B at the
    /// fleet's maxima), 751 B in all; measured on 138 journals an idle tunnel sends 250-550 B per
    /// 25 s. A tunnel whose handshakes FAIL retries every 5 s (2.0-2.5 KB per 25 s, measured) and
    /// does reach the threshold: that tunnel passes nothing, and it is meant to be judged.
    public var cycleMinTxBytes: UInt64 = 1024
    /// Dead cycles in a row before the passive rule is met.
    public var deadCycles = 3
    /// Largest pause between the end of one dead cycle and the start of the next in a chain.
    public var cycleChainGapSeconds: TimeInterval = 30
    /// Inbound data that closes an episode / ends a verdict as recovered.
    public var recoverRxBytes: UInt64 = 16384
    /// Outbound demand of the episode before the passive rule is met.
    public var minEpisodeTxBytes: UInt64 = 3072
    /// Subtracted from the rx growth of a sample in which the handshake time changed: a handshake
    /// response is exactly 92 B in rx_bytes, an initiation (the server re-keys) 148 B. Anything
    /// above that next to a handshake is data.
    public var handshakeRxAllowanceBytes: UInt64 = 148
    /// Subtracted from the tx growth of a sample in which the handshake time changed.
    public var handshakeTxAllowanceBytes: UInt64 = 1024
    /// Quiet time after a path change.
    public var pathStableSeconds: TimeInterval = 20
    /// Quiet time after a device start or a peer switch.
    public var startGraceSeconds: TimeInterval = 20
    /// Quiet time after the device slept.
    public var wakeGraceSeconds: TimeInterval = 10
    /// A status request from the app within this many seconds = the app is alive.
    public var appAliveSeconds: TimeInterval = 10
    /// Stage 2: peer switches per episode. Carried only.
    public var maxSwitches = 5
    /// Low-inbound trigger (a probe, never a verdict): window length.
    public var suspectWindowSeconds: TimeInterval = 60
    /// Low-inbound trigger: at least this much demand in the window...
    public var suspectMinTxBytes: UInt64 = 65536
    /// ...and less than this much inbound data.
    public var suspectMaxRxBytes: UInt64 = 4096
    /// How long the provider waits for the probe's answer.
    public var probeTimeoutSeconds: TimeInterval = 4
    /// Hard limits on the probes the passive rule asks for: battery and data.
    public var probeMaxPerEpisode = 3
    public var probeMaxPerHour = 12
    /// The low-inbound trigger has a small budget of its own: it never spends the one above.
    public var probeLowRxMaxPerHour = 2
    /// Hard limit on the requests that bypass the tunnel (they are visible to the local network).
    public var sanityMaxPerHour = 12

    /// An episode with no new dead cycle for this long is closed (demand ended).
    public static let episodeIdleSeconds: TimeInterval = 120
    /// A bypass result older than this is not evidence.
    public static let sanityMaxAgeSeconds: TimeInterval = 30
    /// While the verdict is network / captive the bypass check is repeated no more often than this.
    public static let sanityRecheckSeconds: TimeInterval = 120
    /// Wall clock running ahead of uptime by more than this within one sample = the device slept.
    public static let sleepJumpSeconds: TimeInterval = 2
    /// A bypass check that did not report back this long after it was asked is asked again.
    public static let sanityAskTimeoutSeconds: TimeInterval = 15
    /// After a probe that judged nothing the next one is not asked sooner than this.
    public static let probeRetryGapSeconds: TimeInterval = 10
    /// The low-inbound trigger backs off after an answered probe: 10 min, doubling up to an hour.
    public static let lowRxBackoffBaseSeconds: TimeInterval = 600
    public static let lowRxBackoffMaxSeconds: TimeInterval = 3600
    /// A probe whose result did not arrive this long after its timeout is written off.
    public static let probeLostSlackSeconds: TimeInterval = 6
    public static let probeHourSeconds: TimeInterval = 3600

    public init() {}

    /// Everything off: the shipped default and the kill-switch target.
    public static let disabled = TribeDataWatchPolicy()

    /// `features` / `numbers` of the plan file, keyed by the server key names. Absent or junk =
    /// default; every number is clamped to the range of the REMOTE-TUNING registry.
    public static func fromPlan(features: [String: Any], numbers: [String: Any]) -> TribeDataWatchPolicy {
        var policy = TribeDataWatchPolicy()
        policy.enabled = flag(features["ios_tunnel_watch"])
        policy.switchEnabled = flag(features["ios_tunnel_watch_switch"])
        policy.sanityRequired = number(numbers["ios_tw_sanity_required"], fallback: 1, min: 0, max: 1) >= 1
        policy.probeEnabled = number(numbers["ios_tw_probe"], fallback: 1, min: 0, max: 1) >= 1
        policy.cycleSeconds = number(numbers["ios_tw_cycle_s"], fallback: policy.cycleSeconds, min: 10, max: 120)
        policy.cycleMinTxBytes = UInt64(number(numbers["ios_tw_cycle_min_tx_bytes"], fallback: Double(policy.cycleMinTxBytes), min: 1024, max: 1_048_576))
        policy.deadCycles = Int(number(numbers["ios_tw_dead_cycles"], fallback: Double(policy.deadCycles), min: 2, max: 20))
        policy.cycleChainGapSeconds = number(numbers["ios_tw_cycle_chain_gap_s"], fallback: policy.cycleChainGapSeconds, min: 0, max: 300)
        policy.recoverRxBytes = UInt64(number(numbers["ios_tw_recover_rx_bytes"], fallback: Double(policy.recoverRxBytes), min: 1024, max: 1_048_576))
        policy.minEpisodeTxBytes = UInt64(number(numbers["ios_tw_min_episode_tx_bytes"], fallback: Double(policy.minEpisodeTxBytes), min: 2048, max: 1_048_576))
        policy.handshakeRxAllowanceBytes = UInt64(number(numbers["ios_tw_hs_rx_allowance_bytes"], fallback: Double(policy.handshakeRxAllowanceBytes), min: 92, max: 4096))
        policy.handshakeTxAllowanceBytes = UInt64(number(numbers["ios_tw_hs_tx_allowance_bytes"], fallback: Double(policy.handshakeTxAllowanceBytes), min: 148, max: 8192))
        policy.pathStableSeconds = number(numbers["ios_tw_path_stable_s"], fallback: policy.pathStableSeconds, min: 0, max: 120)
        policy.startGraceSeconds = number(numbers["ios_tw_start_grace_s"], fallback: policy.startGraceSeconds, min: 5, max: 120)
        policy.wakeGraceSeconds = number(numbers["ios_tw_wake_grace_s"], fallback: policy.wakeGraceSeconds, min: 0, max: 60)
        policy.appAliveSeconds = number(numbers["ios_tw_app_alive_s"], fallback: policy.appAliveSeconds, min: 3, max: 60)
        policy.maxSwitches = Int(number(numbers["ios_tw_max_switches"], fallback: Double(policy.maxSwitches), min: 0, max: 5))
        policy.suspectWindowSeconds = number(numbers["ios_tw_suspect_window_s"], fallback: policy.suspectWindowSeconds, min: 30, max: 600)
        policy.suspectMinTxBytes = UInt64(number(numbers["ios_tw_suspect_min_tx_bytes"], fallback: Double(policy.suspectMinTxBytes), min: 4096, max: 16_777_216))
        policy.suspectMaxRxBytes = UInt64(number(numbers["ios_tw_suspect_max_rx_bytes"], fallback: Double(policy.suspectMaxRxBytes), min: 0, max: 1_048_576))
        policy.probeTimeoutSeconds = number(numbers["ios_tw_probe_timeout_ms"], fallback: policy.probeTimeoutSeconds * 1000, min: 1000, max: 15000) / 1000
        policy.probeMaxPerEpisode = Int(number(numbers["ios_tw_probe_max_per_episode"], fallback: Double(policy.probeMaxPerEpisode), min: 1, max: 10))
        policy.probeMaxPerHour = Int(number(numbers["ios_tw_probe_max_per_hour"], fallback: Double(policy.probeMaxPerHour), min: 1, max: 60))
        policy.probeLowRxMaxPerHour = Int(number(numbers["ios_tw_probe_low_rx_max_per_hour"], fallback: Double(policy.probeLowRxMaxPerHour), min: 0, max: 12))
        policy.sanityMaxPerHour = Int(number(numbers["ios_tw_sanity_max_per_hour"], fallback: Double(policy.sanityMaxPerHour), min: 1, max: 60))
        return policy
    }

    /// Only a JSON boolean true (or 1 / "1" / "true") switches a flag on; anything else is off.
    private static func flag(_ raw: Any?) -> Bool {
        if let value = raw as? NSNumber { return isBoolean(value) ? value.boolValue : value.intValue == 1 }
        if let value = raw as? String {
            let text = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return text == "1" || text == "true"
        }
        return false
    }

    /// A JSON `true` / `false`. `raw is Bool` cannot tell: Swift casts the NUMBERS 0 and 1 to Bool
    /// as well, and a plan that says `"ios_tw_min_heal_steps": 0` must stay a zero.
    static func isBoolean(_ number: NSNumber) -> Bool {
        CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    private static func number(_ raw: Any?, fallback: Double, min: Double, max: Double) -> Double {
        var value: Double?
        if let n = raw as? NSNumber {
            value = isBoolean(n) ? nil : n.doubleValue // a JSON boolean is not a number here
        } else if let s = raw as? String {
            value = Double(s.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        guard let parsed = value, parsed.isFinite else { return fallback }
        return Swift.min(max, Swift.max(min, parsed.rounded(.towardZero)))
    }
}

/// One reading of the device counters (the same UAPI dump the stall watchdog reads).
public struct TribeDataWatchSample: Equatable {
    public var txBytes: UInt64
    public var rxBytes: UInt64
    public var lastHandshakeSec: Int64
    /// systemUptime: does not advance while the device sleeps.
    public var uptime: TimeInterval
    /// Seconds since 1970: advances while the device sleeps.
    public var wall: TimeInterval

    public init(txBytes: UInt64, rxBytes: UInt64, lastHandshakeSec: Int64, uptime: TimeInterval, wall: TimeInterval) {
        self.txBytes = txBytes
        self.rxBytes = rxBytes
        self.lastHandshakeSec = lastHandshakeSec
        self.uptime = uptime
        self.wall = wall
    }
}

/// What the adapter and the provider know at the moment of a sample.
public struct TribeDataWatchEnv: Equatable {
    public var pathSatisfied: Bool
    public var sanity: TribeSanityResult
    /// Uptime of the bypass result; nil = never checked.
    public var sanityAt: TimeInterval?
    /// State of the probe through the tunnel.
    public var probe: TribeProbeResult
    /// Uptime the probe's result became known; nil = no result yet.
    public var probeAt: TimeInterval?
    /// Round trip of an answered probe, milliseconds.
    public var probeLatencyMs: Int
    /// Uptime at which the answer to an already judged (silent) probe arrived after all; nil = none.
    public var lateAnswerAt: TimeInterval?
    /// Uptime of the last status request from the app; nil = none in this session.
    public var appSeenAt: TimeInterval?

    public init(pathSatisfied: Bool, sanity: TribeSanityResult = .unknown,
                sanityAt: TimeInterval? = nil, probe: TribeProbeResult = .none, probeAt: TimeInterval? = nil,
                probeLatencyMs: Int = 0, lateAnswerAt: TimeInterval? = nil, appSeenAt: TimeInterval? = nil) {
        self.pathSatisfied = pathSatisfied
        self.sanity = sanity
        self.sanityAt = sanityAt
        self.probe = probe
        self.probeAt = probeAt
        self.probeLatencyMs = probeLatencyMs
        self.lateAnswerAt = lateAnswerAt
        self.appSeenAt = appSeenAt
    }
}

/// The provider's half of the environment: what it learned from the bypass check, from the probe
/// and from the app's status requests. The adapter adds its own half (the path).
public struct TribeDataWatchInputs: Equatable {
    public var sanity: TribeSanityResult
    public var sanityAt: TimeInterval?
    public var probe: TribeProbeResult
    public var probeAt: TimeInterval?
    public var probeLatencyMs: Int
    public var lateAnswerAt: TimeInterval?
    public var appSeenAt: TimeInterval?

    public init(sanity: TribeSanityResult = .unknown, sanityAt: TimeInterval? = nil, probe: TribeProbeResult = .none,
                probeAt: TimeInterval? = nil, probeLatencyMs: Int = 0, lateAnswerAt: TimeInterval? = nil,
                appSeenAt: TimeInterval? = nil) {
        self.sanity = sanity
        self.sanityAt = sanityAt
        self.probe = probe
        self.probeAt = probeAt
        self.probeLatencyMs = probeLatencyMs
        self.lateAnswerAt = lateAnswerAt
        self.appSeenAt = appSeenAt
    }

    public func env(pathSatisfied: Bool) -> TribeDataWatchEnv {
        TribeDataWatchEnv(pathSatisfied: pathSatisfied, sanity: sanity, sanityAt: sanityAt,
                          probe: probe, probeAt: probeAt, probeLatencyMs: probeLatencyMs,
                          lateAnswerAt: lateAnswerAt, appSeenAt: appSeenAt)
    }
}

public struct TribeDataWatchOutput: Equatable {
    public var verdict: TribeDataVerdict
    public var action: TribeDataWatchAction
    /// What the report is about; nil when `action` is `.keep`.
    public var report: TribeDataWatchReport?
    /// Run ONE request that bypasses the tunnel now. Set on exactly one step per check: the
    /// hourly limit is already charged.
    public var needsSanityCheck: Bool
    /// Start ONE probe through the tunnel now. Set on exactly one step per probe: the limits
    /// are already charged.
    public var startProbe: TribeProbeReason?
    /// Shadow mark for layer 2: no_data (confirmed) and the app shows no sign of life.
    public var wouldSwitch: Bool

    public init(verdict: TribeDataVerdict, action: TribeDataWatchAction, report: TribeDataWatchReport? = nil,
                needsSanityCheck: Bool = false, startProbe: TribeProbeReason? = nil, wouldSwitch: Bool = false) {
        self.verdict = verdict
        self.action = action
        self.report = report
        self.needsSanityCheck = needsSanityCheck
        self.startProbe = startProbe
        self.wouldSwitch = wouldSwitch
    }

    public static let idle = TribeDataWatchOutput(verdict: .none, action: .keep)
}

/// Labels and numbers for the journal line, the status reply and the shared file. No endpoints,
/// keys or addresses can get in here: the struct holds counters and fixed labels only.
public struct TribeDataWatchSnapshot: Equatable {
    public var enabled = false
    public var verdict = TribeDataVerdict.none
    /// Wall time (ms since 1970) the current verdict was first reached; 0 = no verdict.
    public var sinceWallMs: Int64 = 0
    /// The passive rule is met right now.
    public var passive = false
    public var cycles = 0
    public var episodeSeconds = 0
    public var episodeTx: UInt64 = 0
    public var episodeRxData: UInt64 = 0
    public var sanity = TribeSanityResult.unknown
    /// Result of the last probe this watch asked for (none = never asked).
    public var probe = TribeProbeResult.none
    public var probeReason: TribeProbeReason?
    public var probeLatencyMs = 0
    /// Wall time of that result; 0 = none.
    public var probeWallMs: Int64 = 0
    /// Probes charged to the current episode / to the last hour (the passive rule's budget).
    public var probesInEpisode = 0
    public var probesLastHour = 0
    /// The low-inbound trigger's own probes and the bypass requests of the last hour.
    public var lowRxProbesLastHour = 0
    public var sanityLastHour = 0
    /// Passive rule met and probe answered, counted over the session (the layer 2 gate).
    public var refuted = 0
    /// Probes of the passive rule that could not be judged, counted over the session.
    public var disturbed = 0
    /// What confirmed the current no_data.
    public var evidence = TribeVerdictEvidence.none
    public var wouldSwitch = false
    public var appAlive = false
    /// Wall time of the last sample at which the verdict was no_data; 0 = never in this session.
    public var lastNoDataWallMs: Int64 = 0
    /// Wall time inbound data last ended a verdict as recovered; 0 = never in this session.
    public var recoveredWallMs: Int64 = 0

    public init() {}

    /// The `watch` block of the status reply and the body of TribeWatchState.json.
    public var asDictionary: [String: Any] {
        ["enabled": enabled, "verdict": verdict.rawValue, "since_ms": sinceWallMs,
         "passive": passive ? "no_data" : "none", "cycles": cycles,
         "ep_s": episodeSeconds, "tx": Int64(clamping: episodeTx), "rx_data": Int64(clamping: episodeRxData),
         "sanity": sanity.rawValue,
         "probe": probe.rawValue, "probe_reason": probeReason?.rawValue ?? "none",
         "probe_ms": probeLatencyMs, "probe_at_ms": probeWallMs,
         "probes_episode": probesInEpisode, "probes_hour": probesLastHour,
         "probes_low_rx_hour": lowRxProbesLastHour, "sanity_hour": sanityLastHour,
         "refuted": refuted, "disturbed": disturbed, "evidence": evidence.rawValue,
         "would_switch": wouldSwitch, "app_alive": appAlive,
         "last_no_data_ms": lastNoDataWallMs, "recovered_ms": recoveredWallMs]
    }
}

/// The watch itself. Feed it every sample of the stall tick; it never looks at a clock.
public struct TribeDataWatch: Equatable {
    // Counters of the previous sample (deltas are taken against them).
    private var last: TribeDataWatchSample?
    private var lastHandshake: Int64 = 0
    /// The backend was restarted in place: the next sample's counters are its own deltas.
    private var restartPending = false

    // The cycle window: a stretch without inbound data on a satisfied, settled path.
    private var windowStart: TimeInterval?
    private var windowTx: UInt64 = 0

    /// Uptime of the last completed handshake this watch saw, or of the device's (re)start: since
    /// then the engine has had at most this one session. nil = not known yet.
    private var sessionEpoch: TimeInterval?

    // The chain of dead cycles.
    private var chain = 0
    private var lastDeadCycleEnd: TimeInterval?

    // The episode: opened by the first dead cycle, closed by recovery or by idleness.
    private var episodeStart: TimeInterval?
    private var episodeTx: UInt64 = 0
    private var episodeRxData: UInt64 = 0
    private var probesInEpisode = 0
    private var answeredInEpisode = false

    // The low-inbound trigger window (tumbling).
    private var suspectStart: TimeInterval?
    private var suspectTx: UInt64 = 0
    private var suspectRxData: UInt64 = 0

    // Quiet periods.
    private var startGraceUntil: TimeInterval = 0
    private var wakeGraceUntil: TimeInterval = 0
    private var pathGraceUntil: TimeInterval = 0
    /// First event of the current series of path changes; the series cannot keep the watch quiet
    /// longer than two `pathStableSeconds` windows.
    private var pathSeriesStart: TimeInterval?
    /// After a capped series: path changes neither open a quiet period nor reset the window, for
    /// long enough to count a whole chain of dead cycles (a flapping path cannot blind the watch).
    private var pathCoolUntil: TimeInterval = 0

    // The probe this watch asked for and is waiting on.
    private var probeRequestedAt: TimeInterval?
    private var probeRequestReason = TribeProbeReason.passive
    /// Inbound data seen since the probe was asked for, and whether the wait was disturbed (quiet
    /// period, device restart, new handshake, path event): a result other than "answered" judges
    /// only an undisturbed wait.
    private var rxDataSinceProbe: UInt64 = 0
    private var disturbedSinceProbe = false
    /// After a probe that judged nothing: no new one before this uptime.
    private var nextProbeNotBefore: TimeInterval = 0
    /// Uptimes of the passive rule's probes of the last hour (the hourly limit).
    private var probeTimes: [TimeInterval] = []
    /// The low-inbound trigger's own budget and back-off.
    private var lowRxProbeTimes: [TimeInterval] = []
    private var lowRxNotBefore: TimeInterval = 0
    private var lowRxBackoff = TribeDataWatchPolicy.lowRxBackoffBaseSeconds
    /// The bypass checks of the last hour, and the one that has not reported back yet.
    private var sanityTimes: [TimeInterval] = []
    private var sanityAskedAt: TimeInterval?
    private var lateAnswerSeenAt: TimeInterval = 0
    private var lastProbe = TribeProbeResult.none
    private var lastProbeReason: TribeProbeReason?
    private var lastProbeLatencyMs = 0
    private var lastProbeWall: TimeInterval = 0
    private var refutedCount = 0
    private var disturbedCount = 0

    // The verdict.
    public private(set) var verdict = TribeDataVerdict.none
    private var evidence = TribeVerdictEvidence.none
    /// What the outputs (journal, status reply, shared file) were last told: every change of the
    /// verdict is reported, also one that happens between two samples (another network, a new device).
    private var lastReported = TribeDataVerdict.none
    private var verdictSinceWall: TimeInterval = 0
    private var rxDataSinceVerdict: UInt64 = 0
    private var lastWouldSwitch = false
    private var lastNoDataWall: TimeInterval = 0
    private var recoveredWall: TimeInterval = 0
    private var lastEnv = TribeDataWatchEnv(pathSatisfied: true)
    private var lastAppAlive = false
    private var lastPassive = false

    public init() {}

    /// The device was started, resumed after a long-offline pause, or (stage 2) moved to another
    /// peer: everything known about the previous device is void and a start grace begins.
    /// What survives: the hourly limits (they protect the battery and the network, not a device),
    /// the session's gate counters, and what the outputs were last told.
    public mutating func noteDeviceStarted(at uptime: TimeInterval, policy: TribeDataWatchPolicy) {
        let kept = (probeTimes, lowRxProbeTimes, lowRxNotBefore, lowRxBackoff, sanityTimes, refutedCount, disturbedCount, lastReported)
        self = TribeDataWatch()
        (probeTimes, lowRxProbeTimes, lowRxNotBefore, lowRxBackoff, sanityTimes, refutedCount, disturbedCount, lastReported) = kept
        startGraceUntil = uptime + policy.startGraceSeconds
        sessionEpoch = uptime
    }

    /// The backend was restarted in place on the same node (a heal step): its counters start from
    /// zero and it has no session yet. That drop is neither inbound progress nor a cycle; the
    /// episode, the chain of dead cycles and the verdict stay (the cycles go on being counted: the
    /// path did not change). A probe in flight is void (the next sample sees the reset through
    /// `restartPending`), and no probe is asked for one start grace: the new device has to shake
    /// hands first.
    public mutating func noteBackendRestarted(at uptime: TimeInterval, policy: TribeDataWatchPolicy) {
        restartPending = true
        nextProbeNotBefore = Swift.max(nextProbeNotBefore, uptime + policy.startGraceSeconds)
        sessionEpoch = uptime
    }

    /// A real path change: the path was lost, came back after a loss, or moved to another physical
    /// interface. Path updates that change neither (interface order, DNS, cost) are not passed in:
    /// on cellular there are hundreds per hour.
    public mutating func notePathEvent(at uptime: TimeInterval, interfaceChanged: Bool, policy: TribeDataWatchPolicy) {
        // A probe in flight crossed a path change: whatever it says is about no one path.
        if probeRequestedAt != nil { disturbedSinceProbe = true }
        if interfaceChanged {
            // Another network: what was judged belongs to the previous one. The outputs are told
            // at the next sample (`lastReported` still holds the old verdict).
            closeEpisode()
            probeRequestedAt = nil
            if verdict != .none {
                verdict = .none
                evidence = .none
                verdictSinceWall = 0
                rxDataSinceVerdict = 0
                lastWouldSwitch = false
            }
        }
        guard uptime >= pathCoolUntil else { return }
        if pathSeriesStart == nil || uptime >= pathGraceUntil {
            pathSeriesStart = uptime
        }
        let seriesStart = pathSeriesStart ?? uptime
        let ceiling = seriesStart + 2 * policy.pathStableSeconds
        if uptime + policy.pathStableSeconds >= ceiling {
            pathGraceUntil = ceiling
            pathCoolUntil = ceiling + Swift.max(policy.pathStableSeconds, policy.cycleSeconds * Double(policy.deadCycles))
            pathSeriesStart = nil
        } else {
            pathGraceUntil = uptime + policy.pathStableSeconds
        }
        windowStart = nil
        windowTx = 0
        suspectStart = nil
    }

    public mutating func step(_ sample: TribeDataWatchSample, env: TribeDataWatchEnv, policy: TribeDataWatchPolicy) -> TribeDataWatchOutput {
        guard policy.enabled else {
            // Kill switch: forget everything, so a later enable starts clean.
            if self != TribeDataWatch() { self = TribeDataWatch() }
            return .idle
        }
        lastEnv = env
        guard let previous = last else {
            last = sample
            lastHandshake = sample.lastHandshakeSec
            if sessionEpoch == nil {
                // Switched on in the middle of a session: the session is as old as its handshake.
                let age = sample.lastHandshakeSec > 0 ? Swift.max(0, sample.wall - TimeInterval(sample.lastHandshakeSec)) : 0
                sessionEpoch = sample.uptime - age
            }
            return .idle
        }

        // 1. Deltas. Counters that go down (or an announced in-place restart) belong to a new
        // device: its counters are the deltas, its handshake is new.
        let countersReset = restartPending || sample.txBytes < previous.txBytes || sample.rxBytes < previous.rxBytes
        let announcedRestart = restartPending
        restartPending = false
        let deltaTx = countersReset ? sample.txBytes : sample.txBytes - previous.txBytes
        let deltaRx = countersReset ? sample.rxBytes : sample.rxBytes - previous.rxBytes
        let handshakeChanged = sample.lastHandshakeSec > (countersReset ? 0 : lastHandshake)
        // A handshake is not data (its response is counted in rx_bytes) and not demand (its
        // initiation with special packets, junk and padding is counted in tx_bytes).
        let rxData = handshakeChanged ? TribeDataWatch.minus(deltaRx, policy.handshakeRxAllowanceBytes) : deltaRx
        let txDemand = handshakeChanged ? TribeDataWatch.minus(deltaTx, policy.handshakeTxAllowanceBytes) : deltaTx
        let slept = (sample.wall - previous.wall) - (sample.uptime - previous.uptime) > TribeDataWatchPolicy.sleepJumpSeconds
        last = sample
        lastHandshake = sample.lastHandshakeSec
        let now = sample.uptime
        // The engine's session: a new handshake begins one; a device that came up unannounced
        // (counters fell) has none yet.
        if handshakeChanged || (countersReset && !announcedRestart) { sessionEpoch = now }

        // 2. Sleep: the cycle starts over and a wake grace begins.
        if slept {
            windowStart = nil
            windowTx = 0
            suspectStart = nil
            wakeGraceUntil = now + policy.wakeGraceSeconds
        }
        let quiet = !env.pathSatisfied || now < startGraceUntil || now < wakeGraceUntil || now < pathGraceUntil

        if probeRequestedAt != nil {
            rxDataSinceProbe &+= rxData
            // What makes the wait worthless: the watch looked away, the device is another one, or
            // the engine began a new session (the packet may have been only staged).
            if quiet || countersReset || handshakeChanged { disturbedSinceProbe = true }
        }

        var justRecovered = false
        if episodeStart != nil { episodeTx &+= txDemand }

        // 3. Inbound data restarts the cycle; enough of it closes the episode and the verdict.
        if rxData > 0 {
            windowStart = quiet ? nil : now
            windowTx = 0
            if episodeStart != nil {
                episodeRxData &+= rxData
                if episodeRxData >= policy.recoverRxBytes { closeEpisode() }
            }
            if TribeDataWatch.isFinal(verdict) {
                rxDataSinceVerdict &+= rxData
                if rxDataSinceVerdict >= policy.recoverRxBytes { justRecovered = true }
            }
        } else if quiet {
            windowStart = nil
            windowTx = 0
        } else if let start = windowStart {
            windowTx &+= txDemand
            if now - start >= policy.cycleSeconds {
                if windowTx >= policy.cycleMinTxBytes {
                    noteDeadCycle(start: start, end: now, policy: policy)
                }
                windowStart = now
                windowTx = 0
            }
        } else {
            windowStart = now
            windowTx = 0
        }

        // 4. An episode with no new dead cycle for a long time is over: the demand ended.
        if let end = lastDeadCycleEnd, episodeStart != nil, now - end >= TribeDataWatchPolicy.episodeIdleSeconds {
            closeEpisode()
        }

        // 5. The low-inbound trigger: a lot sent, very little data back. A reason to probe only.
        var lowRxDue = false
        if quiet {
            suspectStart = nil
        } else if let start = suspectStart {
            suspectTx &+= txDemand
            suspectRxData &+= rxData
            if now - start >= policy.suspectWindowSeconds {
                lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes
                suspectStart = now
                suspectTx = 0
                suspectRxData = 0
            }
        } else {
            suspectStart = now
            suspectTx = 0
            suspectRxData = 0
        }

        // 6. The passive rule. It does not look at what the stall ladder did: the judge is the probe.
        let chainLive = lastDeadCycleEnd.map { now - $0 <= policy.cycleChainGapSeconds + policy.cycleSeconds } ?? false
        var passive = episodeStart != nil
            && chain >= policy.deadCycles && chainLive
            && episodeTx >= policy.minEpisodeTxBytes
            && !quiet

        let hour = TribeDataWatchPolicy.probeHourSeconds
        probeTimes.removeAll { now - $0 >= hour }
        lowRxProbeTimes.removeAll { now - $0 >= hour }
        sanityTimes.removeAll { now - $0 >= hour }
        var report: TribeDataWatchReport?

        // 7. An answer that came after its probe had been judged silent: the verdict was wrong.
        if let late = env.lateAnswerAt, late > lateAnswerSeenAt {
            lateAnswerSeenAt = late
            if verdict == .noData && evidence == .probe {
                refutedCount += 1
                report = .refuted
                lastProbe = .answered
                chain = 0
                passive = false
                if episodeStart != nil { answeredInEpisode = true }
                verdict = episodeStart != nil ? .suspect : .none
                evidence = .none
                verdictSinceWall = verdict == .none ? 0 : sample.wall
                rxDataSinceVerdict = 0
            }
        }

        // 8. The probe this watch is waiting for.
        /// What confirmed the passive rule on this step.
        var judged = TribeVerdictEvidence.none
        if let requested = probeRequestedAt {
            var outcome: TribeProbeResult?
            if let at = env.probeAt, at >= requested, TribeDataWatch.isOutcome(env.probe) {
                outcome = env.probe
            } else if now - requested > policy.probeTimeoutSeconds + TribeDataWatchPolicy.probeLostSlackSeconds {
                outcome = .notSent // the provider never reported back
            }
            if let outcome {
                let reason = probeRequestReason
                probeRequestedAt = nil
                lastProbe = outcome
                lastProbeReason = reason
                lastProbeLatencyMs = outcome == .answered ? env.probeLatencyMs : 0
                lastProbeWall = sample.wall
                if outcome == .noSession { refundProbe(reason) } // nothing was injected
                if reason == .lowRx {
                    // Answered: the path is fine, come back later and later (10 min, 20, 40, an hour).
                    if outcome != .answered { lowRxBackoff = TribeDataWatchPolicy.lowRxBackoffBaseSeconds }
                    lowRxNotBefore = now + lowRxBackoff
                    if outcome == .answered {
                        lowRxBackoff = Swift.min(lowRxBackoff * 2, TribeDataWatchPolicy.lowRxBackoffMaxSeconds)
                    }
                }
                // A result judges the passive rule only if the rule asked for it; the low-inbound
                // trigger's own result is reported and the rule, if met, asks for its own probe.
                let concerned = reason == .passive
                // A result other than "answered" judges only an undisturbed wait. The chain itself
                // may have aged during the wait, so the rule is held as met for this one step.
                let undisturbed = rxDataSinceProbe == 0 && !disturbedSinceProbe && !quiet && episodeStart != nil
                // No session and no response to the handshakes for a whole chain of dead cycles.
                let handshakeSilent = sessionEpoch.map { now - $0 >= policy.cycleSeconds * Double(policy.deadCycles) } ?? false
                if !concerned {
                    report = .probe // the low-inbound trigger's own result
                } else if outcome == .answered {
                    // The path passes data: the passive rule was wrong. Count it and start over.
                    refutedCount += 1
                    report = .refuted
                    chain = 0
                    passive = false
                    if episodeStart != nil { answeredInEpisode = true }
                } else if outcome == .silent && undisturbed {
                    passive = true
                    judged = .probe
                } else if outcome == .noSession && undisturbed && handshakeSilent {
                    passive = true
                    judged = .handshake
                } else if outcome == .noSession && undisturbed {
                    // The engine is still trying its first handshakes: wait for a whole chain.
                    nextProbeNotBefore = now + TribeDataWatchPolicy.probeRetryGapSeconds
                } else if outcome == .silent || outcome == .staged || outcome == .noSession {
                    disturbedCount += 1
                    report = .disturbed
                    nextProbeNotBefore = now + TribeDataWatchPolicy.probeRetryGapSeconds
                } else {
                    report = .probe // not sent / unavailable: nothing to judge with
                    nextProbeNotBefore = now + TribeDataWatchPolicy.probeRetryGapSeconds
                }
            }
        }

        var needsSanity = false
        var startProbe: TribeProbeReason?
        var next = verdict
        /// There is a probe at all (the policy allows it and the provider has one configured).
        let probeUsable = policy.probeEnabled && env.probe != .unavailable
        let canProbe = probeUsable
            && probesInEpisode < policy.probeMaxPerEpisode && probeTimes.count < policy.probeMaxPerHour

        if justRecovered {
            next = .recovered
        } else if passive && judged != .none {
            next = .noData
            evidence = judged
        } else if passive && verdict == .noData {
            // Already judged; stays until inbound data, a device start or another network.
        } else if passive && verdict == .unconfirmed && !canProbe {
            // Nothing can judge it: nobody is asked again (no bypass request either).
        } else if passive && !canProbe && answeredInEpisode && probeRequestedAt == nil {
            // Out of probes, and the last word of this episode was "it answers": start the chain
            // over and ask nobody (no bypass request either: nothing could follow it).
            chain = 0
            passive = false
            if !TribeDataWatch.isFinal(verdict) { next = .suspect }
        } else if passive {
            // 9a. Is the physical network there at all? network / captive are re-asked at a
            // slower pace; every request is charged to the hourly limit.
            var sanityOk = !policy.sanityRequired
            if !sanityOk {
                let maxAge = (verdict == .network || verdict == .captive)
                    ? TribeDataWatchPolicy.sanityRecheckSeconds : TribeDataWatchPolicy.sanityMaxAgeSeconds
                let usable = env.sanityAt.map { now >= $0 && now - $0 <= maxAge } ?? false
                let waiting = sanityAskedAt.map { now - $0 < TribeDataWatchPolicy.sanityAskTimeoutSeconds } ?? false
                if usable && env.sanity != .unknown {
                    switch env.sanity {
                    case .ok: sanityOk = true
                    case .noReply: next = .network
                    case .captive: next = .captive
                    case .unknown: break
                    }
                } else if waiting {
                    if verdict == .none { next = .suspect }
                } else if sanityTimes.count < policy.sanityMaxPerHour {
                    needsSanity = true
                    sanityAskedAt = now
                    sanityTimes.append(now)
                    if verdict == .none { next = .suspect }
                } else if !TribeDataWatch.isFinal(verdict) {
                    next = .unconfirmed // the network cannot be checked any more this hour
                }
            }
            // 9b. The judge.
            if sanityOk {
                if probeRequestedAt != nil {
                    if verdict == .none { next = .suspect } // waiting for the probe
                } else if !probeUsable {
                    next = .unconfirmed
                } else if now < nextProbeNotBefore {
                    if verdict == .none { next = .suspect } // the last probe judged nothing: a short pause
                } else if canProbe {
                    startProbe = .passive
                    chargeProbe(at: now, reason: .passive)
                    if verdict == .none { next = .suspect }
                } else {
                    next = .unconfirmed // out of probes and nothing ever answered
                }
            }
        } else {
            switch verdict {
            case .noData, .unconfirmed:
                break // stays until inbound data, a device start or another network ends it
            case .network, .captive, .suspect:
                if episodeStart == nil { next = .none }
            case .none:
                if episodeStart != nil { next = .suspect }
            case .recovered:
                next = .none
            }
        }

        // 9c. The low-inbound trigger may start a probe of its own: its result is only reported.
        // Not while an episode is open: no inbound data at all is the passive rule's business,
        // and it will ask for the probe itself. Its budget and back-off are its own.
        if lowRxDue && episodeStart == nil && startProbe == nil && probeRequestedAt == nil && !TribeDataWatch.isFinal(next)
            && probeUsable
            && lowRxProbeTimes.count < policy.probeLowRxMaxPerHour && now >= lowRxNotBefore {
            startProbe = .lowRx
            chargeProbe(at: now, reason: .lowRx)
        }
        lastPassive = passive

        // 10. What to tell.
        let appAlive = env.appSeenAt.map { now >= $0 && now - $0 <= policy.appAliveSeconds } ?? false
        lastAppAlive = appAlive
        let wouldSwitch = next == .noData && !appAlive
        if next != verdict {
            if next == .recovered {
                recoveredWall = sample.wall
            } else if next == .none {
                verdictSinceWall = 0
            } else {
                verdictSinceWall = sample.wall
            }
            if !(TribeDataWatch.isFinal(verdict) && TribeDataWatch.isFinal(next)) { rxDataSinceVerdict = 0 }
        }
        if next != lastReported {
            // Every change is told, also the end of a verdict (the outputs must never keep a
            // verdict that is no longer held) and a change made between two samples.
            report = report == .refuted ? .refuted : .verdict
        } else if wouldSwitch && !lastWouldSwitch && report == nil {
            report = .wouldSwitch // the app fell asleep after the verdict: the shadow mark turns on
        }
        if next == .noData { lastNoDataWall = sample.wall }
        lastWouldSwitch = wouldSwitch
        let reported = next
        // `recovered` is an event, not a state: the next sample starts from `none`.
        verdict = next == .recovered ? .none : next
        lastReported = verdict
        if next == .recovered { verdictSinceWall = 0 }
        return TribeDataWatchOutput(verdict: reported, action: report == nil ? .keep : .report, report: report,
                                    needsSanityCheck: needsSanity, startProbe: startProbe, wouldSwitch: wouldSwitch)
    }

    /// Counters for the journal line, the status reply and the shared file (state after the last step).
    public func snapshot(policy: TribeDataWatchPolicy) -> TribeDataWatchSnapshot {
        var snapshot = TribeDataWatchSnapshot()
        snapshot.enabled = policy.enabled
        guard policy.enabled else { return snapshot }
        snapshot.verdict = verdict
        snapshot.sinceWallMs = Int64(verdictSinceWall * 1000)
        snapshot.passive = lastPassive
        snapshot.cycles = chain
        if let start = episodeStart, let sample = last {
            snapshot.episodeSeconds = Int(Swift.max(0, sample.uptime - start))
        }
        snapshot.episodeTx = episodeTx
        snapshot.episodeRxData = episodeRxData
        let sanityFresh = lastEnv.sanityAt.flatMap { at in last.map { $0.uptime - at <= TribeDataWatchPolicy.sanityMaxAgeSeconds } } ?? false
        snapshot.sanity = sanityFresh ? lastEnv.sanity : .unknown
        snapshot.probe = probeRequestedAt != nil ? .pending : lastProbe
        snapshot.probeReason = probeRequestedAt != nil ? probeRequestReason : lastProbeReason
        snapshot.probeLatencyMs = lastProbeLatencyMs
        snapshot.probeWallMs = Int64(lastProbeWall * 1000)
        snapshot.probesInEpisode = probesInEpisode
        snapshot.probesLastHour = probeTimes.count
        snapshot.lowRxProbesLastHour = lowRxProbeTimes.count
        snapshot.sanityLastHour = sanityTimes.count
        snapshot.refuted = refutedCount
        snapshot.disturbed = disturbedCount
        snapshot.evidence = verdict == .noData ? evidence : .none
        snapshot.wouldSwitch = lastWouldSwitch
        snapshot.appAlive = lastAppAlive
        snapshot.lastNoDataWallMs = Int64(lastNoDataWall * 1000)
        snapshot.recoveredWallMs = Int64(recoveredWall * 1000)
        return snapshot
    }

    private static func minus(_ value: UInt64, _ allowance: UInt64) -> UInt64 {
        value > allowance ? value - allowance : 0
    }

    /// Verdicts that stand until inbound data, a device start or another network ends them.
    private static func isFinal(_ verdict: TribeDataVerdict) -> Bool {
        verdict == .noData || verdict == .unconfirmed || verdict == .network || verdict == .captive
    }

    private static func isOutcome(_ probe: TribeProbeResult) -> Bool {
        probe == .answered || probe == .silent || probe == .noSession || probe == .staged
            || probe == .notSent || probe == .unavailable
    }

    private mutating func chargeProbe(at now: TimeInterval, reason: TribeProbeReason) {
        probeRequestedAt = now
        probeRequestReason = reason
        rxDataSinceProbe = 0
        disturbedSinceProbe = false
        switch reason {
        case .passive:
            probeTimes.append(now)
            if episodeStart != nil { probesInEpisode += 1 }
        case .lowRx:
            lowRxProbeTimes.append(now)
        }
    }

    /// The start was refused (no session): no packet was injected, so no budget is spent.
    private mutating func refundProbe(_ reason: TribeProbeReason) {
        switch reason {
        case .passive:
            if !probeTimes.isEmpty { probeTimes.removeLast() }
            if probesInEpisode > 0 { probesInEpisode -= 1 }
        case .lowRx:
            if !lowRxProbeTimes.isEmpty { lowRxProbeTimes.removeLast() }
        }
    }

    private mutating func noteDeadCycle(start: TimeInterval, end: TimeInterval, policy: TribeDataWatchPolicy) {
        if let previousEnd = lastDeadCycleEnd, chain > 0, start - previousEnd <= policy.cycleChainGapSeconds {
            chain += 1
        } else {
            chain = 1
        }
        lastDeadCycleEnd = end
        if episodeStart == nil {
            // The episode includes its first dead cycle: the bytes of that window count.
            episodeStart = start
            episodeTx = windowTx
            episodeRxData = 0
            probesInEpisode = 0
            answeredInEpisode = false
        }
    }

    private mutating func closeEpisode() {
        episodeStart = nil
        episodeTx = 0
        episodeRxData = 0
        probesInEpisode = 0
        answeredInEpisode = false
        chain = 0
        lastDeadCycleEnd = nil
    }
}

// SPDX-License-Identifier: MIT
// Tribe seamless roaming (mesh Wi-Fi handoff, Wi-Fi <-> cellular): pure policy + decision logic.
//
// Why this file exists: upstream wireguard-apple turns the WireGuard device OFF on the first
// NWPath.unsatisfied (commit 9f8d0e2, no rationale) and, on return, re-applies tunnel network
// settings + starts a NEW device with a NEW handshake. A 1-2 s mesh reassociation thus becomes a
// 3-10 s dead tunnel and every flow in the tunnel is reset. Tailscale, ProtonVPN, sing-box and the
// official WireGuard Android app never stop the device; they rebind the socket on return.
//
// This file has NO NetworkExtension/Go dependency: the conan recipe compiles it together with
// tests/TribeRoamingTests.swift under plain swiftc, so the package cannot ship with broken logic.
import Foundation

public struct TribeRoamingPolicy: Equatable {
    /// true: `.unsatisfied` never turns the device off (rebind-on-return only).
    /// false: upstream behaviour (pause on loss, restart with new handshake on return).
    public var keepBackendOnPathLoss: Bool
    /// > 0: a path loss that PERSISTS this many seconds still pauses the device (long true-offline
    /// fallback, e.g. airplane mode); 0 = never pause. Ignored when keepBackendOnPathLoss is false.
    public var pauseAfterUnsatisfiedSeconds: TimeInterval
    /// Coalescing window for rebind-on-return: bursts of path events become ONE socket bump.
    public var rebindCoalesceSeconds: TimeInterval
    /// Stall watchdog: outbound grows while inbound (rx bytes / handshake) is frozen this long on a
    /// satisfied path -> wgBumpSockets (same port, keepalive burst). 0 = watchdog off.
    public var stallProbeSeconds: TimeInterval
    /// Still stalled this long AFTER the bump -> listen_port=0 (fresh 5-tuple). 0 = no second stage.
    public var stallRebindSeconds: TimeInterval
    /// Outbound bytes required since the last inbound progress before a stall is believed
    /// (filters keepalive-only idle: 32 B every 25 s).
    public var stallMinTxBytes: UInt64

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
        policy.stallProbeSeconds = clamped(stallProbeS, fallback: policy.stallProbeSeconds, min: 0, max: 60)
        policy.stallRebindSeconds = clamped(stallRebindS, fallback: policy.stallRebindSeconds, min: 0, max: 120)
        return policy
    }

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
    case bumpSockets
    case rebindPort
}

/// Two-stage stall watchdog on top of the device's own counters. Inbound progress = rx bytes grew
/// OR a newer handshake (handshake responses are not counted in rx_bytes, so an idle-but-healthy
/// tunnel that keeps re-keying must not look stalled). Stage 0 armed -> stage 1 bumped (same port)
/// -> stage 2 rebound (new port) -> exhausted until inbound progress re-arms. Anything beyond that
/// is the app engine's job (HealthLoop DEAD -> failover).
public struct TribeStallTracker: Equatable {
    public private(set) var stage: Int = 0
    private var lastProgressAt: TimeInterval
    private var txAtProgress: UInt64
    private var lastRx: UInt64
    private var lastHandshake: Int64

    public init(first: TribeStallSample) {
        lastProgressAt = first.at
        txAtProgress = first.txBytes
        lastRx = first.rxBytes
        lastHandshake = first.lastHandshakeSec
    }

    /// Reset the stall clock without touching the escalation stage semantics (used right after a
    /// roam rebind so the watchdog does not double-bump the socket that was just bumped).
    public mutating func rearm(_ sample: TribeStallSample) {
        lastProgressAt = sample.at
        txAtProgress = sample.txBytes
        lastRx = sample.rxBytes
        lastHandshake = sample.lastHandshakeSec
        stage = 0
    }

    public mutating func observe(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy) -> TribeStallAction {
        let progressed = sample.rxBytes > lastRx
            || sample.lastHandshakeSec > lastHandshake
            || sample.txBytes < txAtProgress // counters reset = backend restarted, not a stall
        lastRx = sample.rxBytes
        lastHandshake = sample.lastHandshakeSec
        if progressed {
            lastProgressAt = sample.at
            txAtProgress = sample.txBytes
            stage = 0
            return .none
        }
        guard pathSatisfied, policy.stallProbeSeconds > 0 else { return .none }
        let stalledFor = sample.at - lastProgressAt
        let txSince = sample.txBytes - txAtProgress
        // Without a first handshake, let AWG's built-in retries run for at least 12 seconds.
        // Handshake-only traffic is smaller than data traffic; still require evidence of demand.
        let bootstrap = sample.lastHandshakeSec == 0 && sample.rxBytes == 0
        let probeSeconds = bootstrap ? max(12, policy.stallProbeSeconds) : policy.stallProbeSeconds
        let rebindSeconds = bootstrap ? max(18, policy.stallRebindSeconds) : policy.stallRebindSeconds
        let requiredTx = bootstrap ? UInt64(256) : policy.stallMinTxBytes
        switch stage {
        case 0:
            if stalledFor >= probeSeconds && txSince >= requiredTx {
                stage = 1
                return .bumpSockets
            }
        case 1:
            guard policy.stallRebindSeconds > 0 else { return .none }
            if stalledFor >= probeSeconds + rebindSeconds && txSince >= requiredTx * 2 {
                stage = 2
                return .rebindPort
            }
        default:
            break
        }
        return .none
    }
}

/// One owner (adapter workQueue) arbitrates GUI and autonomous repairs. A new socket consumes
/// the entire two-step episode; path notifications alone do not grant another repair budget.
/// Genuine inbound progress rearms an episode, while the rolling cap remains in force.
public struct TribeRecoveryBudget: Equatable {
    public private(set) var episodeUsed = 0
    public private(set) var denied: UInt64 = 0
    public private(set) var interventions: UInt64 = 0
    private var recent: [TimeInterval] = []
    private var lastActionAt: TimeInterval?
    private var lastRx: UInt64 = 0
    private var lastHandshake: Int64 = 0
    private let cooldown: TimeInterval

    public init(jitter: TimeInterval = 0) { cooldown = 8 + min(2, max(0, jitter)) }

    public mutating func observe(_ sample: TribeStallSample) {
        if sample.rxBytes > lastRx || sample.lastHandshakeSec > lastHandshake { episodeUsed = 0 }
        lastRx = sample.rxBytes
        lastHandshake = sample.lastHandshakeSec
    }

    public mutating func permit(at: TimeInterval, freshPort: Bool) -> Bool {
        recent.removeAll { at - $0 >= 120 }
        let cost = freshPort && episodeUsed == 0 ? 2 : 1
        guard episodeUsed + cost <= 2, recent.count < 4,
              lastActionAt.map({ at - $0 >= cooldown }) ?? true else { denied += 1; return false }
        episodeUsed += cost
        recent.append(at)
        lastActionAt = at
        interventions += 1
        return true
    }
}

public struct TribeRoamingCounters: Equatable {
    public var pathLost: UInt64 = 0
    public var pathRestored: UInt64 = 0
    public var roamBumps: UInt64 = 0
    public var stallBumps: UInt64 = 0
    public var stallRebinds: UInt64 = 0
    public var pauses: UInt64 = 0
    public var resumes: UInt64 = 0
    public var recoveryUsed: UInt64 = 0
    public var recoveryDenied: UInt64 = 0
    public var recoveryInterventions: UInt64 = 0

    public init() {}

    public var asDictionary: [String: UInt64] {
        ["path_lost": pathLost, "path_restored": pathRestored, "roam_bumps": roamBumps,
         "stall_bumps": stallBumps, "stall_rebinds": stallRebinds, "pauses": pauses, "resumes": resumes,
         "recovery_used": recoveryUsed, "recovery_denied": recoveryDenied, "recovery_interventions": recoveryInterventions]
    }

    public var summary: String {
        "path_lost=\(pathLost) path_restored=\(pathRestored) roam_bumps=\(roamBumps) stall_bumps=\(stallBumps) stall_rebinds=\(stallRebinds) pauses=\(pauses) resumes=\(resumes)"
    }
}

public enum TribeRoaming {
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

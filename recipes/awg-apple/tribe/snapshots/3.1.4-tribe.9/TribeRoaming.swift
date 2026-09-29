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

/// Stall watchdog on top of the device's own counters. Inbound progress = rx bytes grew OR a newer
/// handshake (handshake responses are not counted in rx_bytes, so an idle-but-healthy tunnel that
/// keeps re-keying must not look stalled).
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
    private var lastProgressAt: TimeInterval
    private var txAtProgress: UInt64
    private var lastRx: UInt64
    private var lastHandshake: Int64
    /// Time and tx counter of the last committed step (watchdog, GUI or roam): the second-stage
    /// gap, the stage-3 backoff and its demand evidence count from here.
    private var lastStepAt: TimeInterval?
    private var txAtLastStep: UInt64 = 0

    /// Stage-3 order after the soft restart (persistentSteps = 1 -> index 1 = fresh port first).
    public static let persistentSequence: [TribeStallAction] = [.softRestart, .rebindPort]

    /// Stage-3 backoff before persistent step `index` (0-based): 30, 60, 120 s, capped at 120 s.
    public static func persistentBackoff(_ index: Int) -> TimeInterval {
        let steps: [TimeInterval] = [30, 60, 120]
        return steps[Swift.min(Swift.max(0, index), steps.count - 1)]
    }

    public init(first: TribeStallSample) {
        lastProgressAt = first.at
        txAtProgress = first.txBytes
        lastRx = first.rxBytes
        lastHandshake = first.lastHandshakeSec
    }

    /// tribe.8: the backend was restarted in place (soft restart): the counters start from zero on
    /// the new device. Rebase them WITHOUT treating the drop as progress; the stall clock, the stage
    /// and the stage-3 backoff keep running (only a real rx/handshake on the new device resets them).
    public mutating func rebaseCounters(_ sample: TribeStallSample) {
        txAtProgress = sample.txBytes
        lastRx = sample.rxBytes
        lastHandshake = sample.lastHandshakeSec
        txAtLastStep = sample.txBytes
    }

    /// A step done outside the watchdog: a GUI fresh port / soft restart (provider messages) or a
    /// roam fresh port (path returned after a loss). It counts as the episode's step of that kind
    /// and the next watchdog step counts its gap/backoff from it. The stall clock is NOT touched
    /// (rule of tribe.9: only inbound progress restarts it). A same-port bump is not a step.
    public mutating func noteExternalStep(_ kind: TribeRecoveryKind, at: TimeInterval, tx: UInt64) {
        switch kind {
        case .bump:
            return
        case .freshPort:
            if stage < 2 { stage = 2; persistentSteps = 0 }
        case .softRestart:
            stage = 3
            persistentSteps = Swift.max(persistentSteps, 1)
        }
        lastStepAt = at
        txAtLastStep = tx
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

    /// A soft restart right after a late (budget-delayed) fresh port would give its keepalive no
    /// chance to be answered; keep a small gap, never longer than the configured second stage.
    public static func minGapAfterStep(_ policy: TribeRoamingPolicy) -> TimeInterval {
        min(3, policy.stallRebindSeconds)
    }

    private mutating func step(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy,
                               minGapAfterStep: TimeInterval, persistent: Bool,
                               permit: (TribeStallAction) -> Bool) -> TribeStallAction {
        let progressed = sample.rxBytes > lastRx
            || sample.lastHandshakeSec > lastHandshake
            || sample.txBytes < txAtProgress // counters reset = backend restarted, not a stall
        lastRx = sample.rxBytes
        lastHandshake = sample.lastHandshakeSec
        if progressed {
            lastProgressAt = sample.at
            txAtProgress = sample.txBytes
            stage = 0
            persistentSteps = 0
            lastStepAt = nil
            txAtLastStep = sample.txBytes
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
        case 0, 1:
            if stalledFor >= probeSeconds && txSince >= requiredTx, permit(.rebindPort) {
                stage = 2
                persistentSteps = 0
                lastStepAt = sample.at
                txAtLastStep = sample.txBytes
                return .rebindPort
            }
        case 2:
            guard persistent, policy.stallRebindSeconds > 0, let last = lastStepAt else { return .none }
            if stalledFor >= probeSeconds + rebindSeconds && txSince >= requiredTx * 2
                && sample.at - last >= minGapAfterStep, permit(.softRestart) {
                stage = 3
                persistentSteps = 1
                lastStepAt = sample.at
                txAtLastStep = sample.txBytes
                return .softRestart
            }
        default:
            // Stage 3: a refusal leaves every field untouched, so the same step is proposed again on
            // the next tick (rule D1).
            guard persistent, policy.stallRebindSeconds > 0, let last = lastStepAt else { return .none }
            let sinceStep = sample.at - last
            let txSinceStep = sample.txBytes >= txAtLastStep ? sample.txBytes - txAtLastStep : 0
            guard sinceStep >= TribeStallTracker.persistentBackoff(persistentSteps - 1), txSinceStep >= requiredTx else {
                return .none
            }
            let next = TribeStallTracker.persistentSequence[persistentSteps % TribeStallTracker.persistentSequence.count]
            if permit(next) {
                persistentSteps += 1
                lastStepAt = sample.at
                txAtLastStep = sample.txBytes
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
    public mutating func observe(_ sample: TribeStallSample) {
        let countersReset = sample.rxBytes < lastRx || sample.txBytes < lastTx
        if !countersReset && (sample.rxBytes > lastRx || sample.lastHandshakeSec > lastHandshake) {
            resetEpisode()
        }
        lastRx = sample.rxBytes
        lastTx = sample.txBytes
        lastHandshake = sample.lastHandshakeSec
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

    public init(jitter: TimeInterval = 0, persistentHeal: Bool = true) {
        budget = TribeRecoveryBudget(jitter: jitter)
        self.persistentHeal = persistentHeal
    }

    /// tribe.8: the backend was restarted in place and its counters start from zero.
    public mutating func rebaseAfterBackendRestart(_ sample: TribeStallSample) {
        budget.observe(sample)
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
        budget.observe(sample)
        if tracker == nil {
            tracker = TribeStallTracker(first: sample)
        }
        if freshPort {
            tracker?.noteExternalStep(.freshPort, at: sample.at, tx: sample.txBytes)
        }
    }

    public mutating func tick(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy) -> TribeWatchdogOutcome {
        budget.observe(sample)
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
        budget.observe(sample)
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
        budget.observe(sample)
        if let denial = budget.request(at: sample.at, kind: .softRestart) { return .budget(denial) }
        if tracker == nil { tracker = TribeStallTracker(first: sample) }
        tracker?.noteExternalStep(.softRestart, at: sample.at, tx: sample.txBytes)
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

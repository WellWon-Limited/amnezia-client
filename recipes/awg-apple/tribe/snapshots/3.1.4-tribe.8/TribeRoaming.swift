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
    case bumpSockets
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

/// Stall watchdog on top of the device's own counters. Inbound progress = rx bytes grew OR a newer
/// handshake (handshake responses are not counted in rx_bytes, so an idle-but-healthy tunnel that
/// keeps re-keying must not look stalled). Stage 0 armed -> stage 1 bumped (same port) -> stage 2
/// rebound (new port). tribe.4-7: exhausted there until inbound progress re-arms. tribe.8 (U9,
/// `persistent`): stage 3 keeps healing while the GUI sleeps -- the next step of `persistentSequence`
/// after `persistentBackoff` (30/60/120 s, then 120 s) from the previous step, only while the path is
/// satisfied and outbound grew since that step without any inbound progress. Progress resets the
/// stage and the backoff. The app engine's failover (HealthLoop DEAD) still sits above this.
public struct TribeStallTracker: Equatable {
    public private(set) var stage: Int = 0
    /// tribe.8: persistent (stage 3) steps committed since the last inbound progress.
    public private(set) var persistentSteps: Int = 0
    private var lastProgressAt: TimeInterval
    private var txAtProgress: UInt64
    private var lastRx: UInt64
    private var lastHandshake: Int64
    /// Time and tx counter of the last committed step at stage >= 2 (fresh port, persistent step,
    /// or an external GUI step): the stage-3 backoff and its demand evidence count from here.
    private var lastStepAt: TimeInterval?
    private var txAtLastStep: UInt64 = 0

    /// Stage-3 order: same-port bump, fresh port, then a soft restart of the backend.
    public static let persistentSequence: [TribeStallAction] = [.bumpSockets, .rebindPort, .softRestart]

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

    /// Reset the stall clock without touching the escalation stage semantics (used right after a
    /// roam rebind so the watchdog does not double-bump the socket that was just bumped).
    /// tribe.8: the stage-3 backoff (persistentSteps, last step time) survives a rearm: a path
    /// event is not inbound progress, so a flapping path cannot restart the 30 s backoff.
    public mutating func rearm(_ sample: TribeStallSample) {
        lastProgressAt = sample.at
        txAtProgress = sample.txBytes
        lastRx = sample.rxBytes
        lastHandshake = sample.lastHandshakeSec
        stage = 0
        bumpedAt = nil
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

    /// tribe.8: a step was done outside the watchdog (GUI soft restart): at least stage 2, and the
    /// stage-3 backoff counts from this step.
    public mutating func noteExternalStep(at: TimeInterval, tx: UInt64) {
        if stage == 0 { bumpedAt = at }
        stage = Swift.max(stage, 2)
        lastStepAt = at
        txAtLastStep = tx
    }

    /// tribe.4/tribe.5 semantics, unchanged: every proposed step is committed immediately.
    public mutating func observe(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy) -> TribeStallAction {
        step(sample, pathSatisfied: pathSatisfied, policy: policy, minGapAfterBump: 0, persistent: false) { _ in true }
    }

    /// tribe.7: the escalation stage moves ONLY when `permit` accepts the proposed action. A refusal
    /// (shared recovery budget: rolling cap, cooldown) leaves the stage where it was, so the same
    /// step is proposed again on the next tick and fires as soon as the budget frees up. The
    /// tribe.6 order (commit stage, then ask the budget) burned the step on every refusal.
    /// tribe.8: `persistent` = stage 3 after the fresh port (U9); false = tribe.7 (exhausted at stage 2).
    public mutating func observe(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy,
                                 persistent: Bool = false,
                                 permit: (TribeStallAction) -> Bool) -> TribeStallAction {
        step(sample, pathSatisfied: pathSatisfied, policy: policy,
             minGapAfterBump: TribeStallTracker.minGapAfterBump(policy), persistent: persistent, permit: permit)
    }

    /// A fresh port right after a late (budget-delayed) bump would give the bump's keepalive no
    /// chance to be answered; keep a small gap, never longer than the configured rebind step.
    public static func minGapAfterBump(_ policy: TribeRoamingPolicy) -> TimeInterval {
        min(3, policy.stallRebindSeconds)
    }

    /// Mark steps as already spent in this episode (a GUI fresh-port rebind, or a bump the budget
    /// says was spent before a roam rearm). Never moves the stage backwards.
    public mutating func advance(toStage target: Int, at: TimeInterval, tx: UInt64? = nil) {
        guard target > stage else { return }
        if stage == 0 { bumpedAt = at }
        stage = min(2, target)
        if stage == 2 && lastStepAt == nil {
            lastStepAt = at
            txAtLastStep = tx ?? txAtLastStep
        }
    }

    private var bumpedAt: TimeInterval?

    private mutating func step(_ sample: TribeStallSample, pathSatisfied: Bool, policy: TribeRoamingPolicy,
                               minGapAfterBump: TimeInterval, persistent: Bool,
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
            bumpedAt = nil
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
        case 0:
            if stalledFor >= probeSeconds && txSince >= requiredTx, permit(.bumpSockets) {
                stage = 1
                bumpedAt = sample.at
                return .bumpSockets
            }
        case 1:
            guard policy.stallRebindSeconds > 0 else { return .none }
            let sinceBump = bumpedAt.map { sample.at - $0 } ?? .infinity
            if stalledFor >= probeSeconds + rebindSeconds && txSince >= requiredTx * 2
                && sinceBump >= minGapAfterBump, permit(.rebindPort) {
                stage = 2
                lastStepAt = sample.at
                txAtLastStep = sample.txBytes
                return .rebindPort
            }
        default:
            // Stage 3 (tribe.8, U9): never on the tribe.4-7 entry points; a refusal leaves every
            // field untouched, so the same step is proposed again on the next tick (rule D1).
            guard persistent, policy.stallRebindSeconds > 0, let last = lastStepAt else { return .none }
            let sinceStep = sample.at - last
            let txSinceStep = sample.txBytes >= txAtLastStep ? sample.txBytes - txAtLastStep : 0
            guard sinceStep >= TribeStallTracker.persistentBackoff(persistentSteps), txSinceStep >= requiredTx else {
                return .none
            }
            let next = TribeStallTracker.persistentSequence[persistentSteps % TribeStallTracker.persistentSequence.count]
            if permit(next) {
                stage = 3
                persistentSteps += 1
                lastStepAt = sample.at
                txAtLastStep = sample.txBytes
                return next
            }
        }
        return .none
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

/// One owner (adapter workQueue) arbitrates GUI and autonomous repairs. An episode holds at most
/// one bump and one fresh port; a fresh port (from the NE watchdog or the GUI) closes the episode.
/// Path notifications alone do not grant another repair budget; genuine inbound progress re-arms an
/// episode, while the rolling cap remains in force.
///
/// tribe.7: the cooldown only separates actions of the SAME kind. tribe.6 applied an 8-10 s cooldown
/// between ANY two actions, which is longer than the watchdog's own bump -> fresh-port step at low
/// outbound rates (600 B/s: bump at 7 s, fresh port due at 14 s), so the second stage was refused.
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
    /// tribe.8 (U9): stage 3 after the fresh port. false = tribe.7 behaviour (exhausted at stage 2).
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

    /// A roam rebind (path event) just bumped the socket: restart the stall clock, but steps the
    /// budget already spent in this episode stay spent (a path event is not inbound progress).
    public mutating func rearmAfterRoam(_ sample: TribeStallSample) {
        budget.observe(sample)
        if tracker == nil {
            tracker = TribeStallTracker(first: sample)
        } else {
            tracker?.rearm(sample)
        }
        syncTrackerWithBudget(sample)
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
        // Stages 2/3 can only propose a persistent step (the tracker's own backoff paces it).
        let persistentPhase = current.stage >= 2
        let action = current.observe(sample, pathSatisfied: pathSatisfied, policy: policy,
                                     persistent: persistentHeal) { step in
            proposed = step
            if !persistentPhase && step == .bumpSockets && budget.bumpSpent && !budget.freshPortSpent {
                // The bump of this episode already ran (before a roam rearm): go straight to the
                // fresh-port step instead of asking for a second bump forever.
                return false
            }
            denial = budget.request(at: sample.at, kind: TribeRecoveryArbiter.kind(of: step), persistent: persistentPhase)
            return denial == nil
        }
        self.budget = budget
        tracker = current
        if action != .none { return .perform(action) }
        guard proposed != .none else { return .none }
        if let denial {
            if denial == .episode { syncTrackerWithBudget(sample) }
            return .denied(proposed, denial)
        }
        syncTrackerWithBudget(sample) // skipped an already-spent bump
        return .none
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
        syncTrackerWithBudget(sample)
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
        tracker?.noteExternalStep(at: sample.at, tx: sample.txBytes)
        return .performed
    }

    private mutating func syncTrackerWithBudget(_ sample: TribeStallSample) {
        let spentStage = budget.freshPortSpent ? 2 : (budget.bumpSpent ? 1 : 0)
        tracker?.advance(toStage: spentStage, at: sample.at, tx: sample.txBytes)
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
    /// tribe.8: stage-3 watchdog steps (U9) and in-place backend restarts (U6, NE or GUI).
    public var stallPersistent: UInt64 = 0
    public var softRestarts: UInt64 = 0

    public init() {}

    public var asDictionary: [String: UInt64] {
        ["path_lost": pathLost, "path_restored": pathRestored, "roam_bumps": roamBumps,
         "stall_bumps": stallBumps, "stall_rebinds": stallRebinds, "pauses": pauses, "resumes": resumes,
         "recovery_used": recoveryUsed, "recovery_denied": recoveryDenied, "recovery_interventions": recoveryInterventions,
         "stall_persistent": stallPersistent, "soft_restarts": softRestarts]
    }

    public var summary: String {
        "path_lost=\(pathLost) path_restored=\(pathRestored) roam_bumps=\(roamBumps) stall_bumps=\(stallBumps) stall_rebinds=\(stallRebinds) pauses=\(pauses) resumes=\(resumes)"
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

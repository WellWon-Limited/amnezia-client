import Foundation

// AVPN upstream nodes (plan provider-pool, release A, lane L3; contract client-envelope-contract.md):
// the seat-lease owner inside the iOS Network Extension (decision B: the app is suspended in the
// background, only the extension lives). Owns one UpstreamLeaseMachine (.renewUntilGone), feeds it the
// tunnel's cumulative byte counters and a sleep-proof clock, sends its renew/release reports through
// an injected transport (PacketTunnelProvider+Upstream.swift: LibXrayTribeHTTP through the core's own
// SOCKS inbound - decision C) and reports the status object of contract section 5.
//
// One timer source, on the renewer's own serial queue: a one-shot DispatchSourceTimer re-armed to the
// machine's next wake-up (at most 60 s ahead, on the wall clock so a sleeping device does not stretch
// it; the machine decides on its own ContinuousClock `now`, so an early or late wake-up only costs a
// no-op tick). It is not a health watchdog: it never stops, restarts or reconnects the tunnel. The only
// thing it can end is the provider's core, and only on a terminal server answer (decision E). The AWG
// stall watchdog (TribeRoaming.swift, CONNECT-INVARIANTS §23) does not run on the Xray path; the app's
// HealthLoop is untouched. Requests never run on the packet path (hev has its own thread) nor on the
// renewer's state queue: renewals on a serial I/O queue, the final release on its own bounded task.
//
// Secrets: the renew token and the URL path (lease id) are never logged; logs carry codes and seq only.

protocol UpstreamLeaseTransport: AnyObject {
    // Blocking; one HTTPS exchange through the tunnel. Never called on the state queue.
    func send(method: String, url: String, headers: [String: String], body: String,
              timeoutMs: Int64) -> UpstreamLeaseWire.HTTPResult
}

struct UpstreamLeaseStatus: Equatable {
    var state = "none"        // none | pending | active | terminal
    var code = ""
    var seq: Int64 = 0
    var renewedMsAgo: Int64 = -1
    var expiresInMs: Int64 = 0
    var revision: Int64 = 0
    var configChanged = false
    var appliedBytes: Int64 = 0
    var shadowBytes: Int64 = 0
    var meterScope: UpstreamMeterScope = .tunnel

    // Contract section 5, key for key.
    var dictionary: [String: Any] {
        [
            "state": state,
            "code": code,
            "seq": seq,
            "renewed_ms_ago": renewedMsAgo,
            "expires_in_ms": expiresInMs,
            "revision": revision,
            "config_changed": configChanged,
            "applied_bytes": appliedBytes,
            "shadow_bytes": shadowBytes,
            "meter_scope": meterScope.rawValue
        ]
    }
}

// The terminal lease answer of this tunnel session, kept after the renewer object is gone (stopped or
// released): the status reply keeps `state: terminal` WITH the server's code for the rest of the session,
// so the app's journal and its leave path see why the core was stopped. A fresh tunnel start clears it.
struct UpstreamTerminalMemo: Equatable {
    private(set) var code: String?

    // A fresh tunnel start (not a core restart): no terminal answer yet.
    mutating func reset() { code = nil }

    // The first terminal answer of the session wins; an empty code is still a terminal answer.
    mutating func record(_ terminalCode: String) {
        if code == nil { code = terminalCode }
    }

    // The status object for a session whose renewer is gone; nil = no terminal answer in this session.
    var status: UpstreamLeaseStatus? {
        guard let code else { return nil }
        var s = UpstreamLeaseStatus()
        s.state = "terminal"
        s.code = code
        return s
    }
}

enum UpstreamLeaseClock {
    // Milliseconds of a clock that keeps running while the device sleeps (contract section 7):
    // CLOCK_MONOTONIC_RAW = mach_continuous_time (ContinuousClock on iOS 16+). Never DispatchTime,
    // systemUptime or mach_absolute_time - they stop during sleep.
    static func nowMs() -> Int64 {
        Int64(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1_000_000)
    }
}

final class UpstreamLeaseRenewer {
    static let renewTimeoutMs: Int64 = 12_000
    static let releaseTimeoutMs: Int64 = 1_500
    static let maxTimerAheadMs: Int64 = 60_000

    let profileId: String
    private let queue: DispatchQueue
    private let ioQueue: DispatchQueue
    private let transport: UpstreamLeaseTransport
    private let nowMs: () -> Int64
    // Cumulative session totals of the lease's scope: "tunnel" = the tunnel interface, "proxy" = the
    // core's counters summed over the given tags (UpstreamProxyMeter.swift).
    private let byteTotals: (UpstreamMeterScope, [String]) -> (rx: Int64, tx: Int64)?
    // Whether the running core has its per-outbound counters (read once when a lease is adopted).
    private let statsAvailable: () -> Bool
    private let onTerminal: (String) -> Void
    private let log: (String) -> Void
    private var machine: UpstreamLeaseMachine
    private var timer: DispatchSourceTimer?
    private var stopped = false
    private var scope: UpstreamMeterScope = .tunnel
    private var meterTags: [String] = []

    init(profileId: String,
         transport: UpstreamLeaseTransport,
         queue: DispatchQueue = DispatchQueue(label: "hk.wellwon.vpn.upstream-lease"),
         ioQueue: DispatchQueue = DispatchQueue(label: "hk.wellwon.vpn.upstream-lease.io"),
         timing: UpstreamLeaseTiming = UpstreamLeaseTiming(),
         nowMs: @escaping () -> Int64 = UpstreamLeaseClock.nowMs,
         byteTotals: @escaping (UpstreamMeterScope, [String]) -> (rx: Int64, tx: Int64)?,
         statsAvailable: @escaping () -> Bool = { false },
         onTerminal: @escaping (String) -> Void,
         log: @escaping (String) -> Void = { _ in }) {
        self.profileId = profileId
        self.transport = transport
        self.queue = queue
        self.ioQueue = ioQueue
        self.nowMs = nowMs
        self.byteTotals = byteTotals
        self.statsAvailable = statsAvailable
        self.onTerminal = onTerminal
        self.log = log
        machine = UpstreamLeaseMachine(timing: timing, expiryPolicy: .renewUntilGone)
    }

    // MARK: - lifecycle (any thread)

    // A start envelope with `upstream_lease`: the session is accounted from now on.
    func startActive(lease: UpstreamLeaseEnvelope) {
        queue.sync { adoptLocked(lease) }
    }

    // A provisional start (no `upstream_lease` yet): "pending", bytes counted from tunnel start.
    func startPending() {
        queue.sync {
            machine.beginPending(profileId: profileId, nowMs: nowMs())
            log("Tribe upstream: pending (provisional start)")
        }
    }

    // App message `upstream_lease_set`. Accepted only while pending (a second hand-over, or one after a
    // terminal answer, changes nothing). Returns the status after the hand-over.
    @discardableResult
    func handOver(lease: UpstreamLeaseEnvelope) -> UpstreamLeaseStatus {
        queue.sync {
            if machine.phase == .provisional {
                adoptLocked(lease)
            } else {
                log("Tribe upstream: lease hand-over ignored (state \(statusLocked().state))")
            }
            return statusLocked()
        }
    }

    func status() -> UpstreamLeaseStatus {
        queue.sync { statusLocked() }
    }

    // The core is stopped for a terminal answer: the provider must not restart it on a network change.
    var isTerminal: Bool {
        queue.sync { machine.phase == .left }
    }

    // The final report of a user disconnect (contract section 6), read while the core still counts. Review E5 of
    // 18.11: the DELETE itself goes AFTER the core stopped, over the extension's direct path (sendRelease) - a
    // release through the tunnel being abandoned hangs when that tunnel carries no data (owner's iPhone, rounds
    // 1-2). nil: nothing to send (a terminal answer, no lease yet).
    struct PreparedRelease {
        let url: String
        let headers: [String: String]
        let body: String
    }

    func prepareRelease() -> PreparedRelease? {
        queue.sync {
            guard !stopped else { return nil }
            stopped = true
            cancelTimerLocked()
            feedBytesLocked()
            let step = machine.disconnect(nowMs: nowMs())
            guard let action = step.find(.sendRelease) else { return nil }
            log("Tribe upstream: release seq=\(action.meter.seq)")
            return PreparedRelease(url: leaseURL(action), headers: headers(action),
                                   body: UpstreamLeaseWire.meterBody(action.meter))
        }
    }

    // Sends a prepared release through `via` (the direct transport after the core stopped; the renewer's own
    // transport when nil), bounded to releaseTimeoutMs; `completion` runs exactly once (on an answer, on a
    // failure or at the bound). Only an HTTP answer is logged as released.
    func sendRelease(_ request: PreparedRelease, via: UpstreamLeaseTransport? = nil, completion: @escaping () -> Void) {
        let once = UpstreamOnce(completion)
        let bound = DispatchTime.now() + .milliseconds(Int(Self.releaseTimeoutMs) + 100)
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: bound) { once.run() }
        // Own task, not the renewal I/O queue: a renewal in flight must not delay the release.
        let transport: UpstreamLeaseTransport = via ?? self.transport
        let log = log
        DispatchQueue.global(qos: .userInitiated).async {
            let result = transport.send(method: "DELETE", url: request.url, headers: request.headers,
                                        body: request.body, timeoutMs: Self.releaseTimeoutMs)
            log(result.status > 0 ? "Tribe upstream: release answered status=\(result.status)"
                                  : "Tribe upstream: release not confirmed error=\(result.errorCode) (seat left to the server TTL)")
            once.run()
        }
    }

    // prepareRelease + sendRelease through the renewer's own transport (tests; nothing in the provider).
    func release(completion: @escaping () -> Void) {
        guard let request = prepareRelease() else {
            completion()
            return
        }
        sendRelease(request, completion: completion)
    }

    // Ends the renewer without a release (after a terminal answer, or a stop without a lease).
    func stop() {
        queue.sync {
            stopped = true
            cancelTimerLocked()
        }
    }

    // MARK: - test hooks

    // Runs the tick a timer would run (tests drive time through `nowMs`).
    func fireForTest() {
        queue.sync { tickLocked() }
    }

    // Waits until the renewal in flight was answered and applied.
    func drainForTest() {
        ioQueue.sync {}
        queue.sync {}
    }

    // MARK: - state queue only

    private func adoptLocked(_ lease: UpstreamLeaseEnvelope) {
        // Scope fixed here for the life of the lease (contract section 4).
        var effective = lease
        let available = lease.meterScope == .proxy && !lease.meterTags.isEmpty && statsAvailable()
        effective.meterScope = UpstreamMeterPlan.scope(requested: lease.meterScope, meterTags: lease.meterTags,
                                                       statsAvailable: available)
        if effective.meterScope != lease.meterScope {
            log("Tribe upstream: meter_scope proxy not measurable (tags=\(lease.meterTags.count) stats=\(available)), reporting tunnel")
        }
        scope = effective.meterScope
        meterTags = scope == .proxy ? lease.meterTags : []
        let step = machine.adopt(lease: effective, profileId: profileId, nowMs: nowMs())
        log("Tribe upstream: active seq=\(lease.seq) epoch=\(lease.epoch) scope=\(scope.rawValue)")
        apply(step)
    }

    private func statusLocked() -> UpstreamLeaseStatus {
        let now = nowMs()
        var s = UpstreamLeaseStatus()
        switch machine.phase {
        case .active: s.state = "active"
        case .provisional: s.state = "pending"
        case .left: s.state = "terminal"
        default: s.state = "none"
        }
        s.code = machine.phase == .left ? machine.leaveReason : ""
        s.seq = machine.lastAcceptedSeq
        s.renewedMsAgo = machine.lastRenewOkMs >= 0 ? max(0, now - machine.lastRenewOkMs) : -1
        s.expiresInMs = machine.phase == .active ? max(0, machine.deadlineMs - now) : 0
        s.revision = machine.knownRevision
        s.configChanged = machine.configChangedNoted
        s.appliedBytes = machine.appliedBytesTotal
        s.shadowBytes = machine.shadowBytesTotal
        s.meterScope = machine.phase == .idle ? .tunnel : scope
        return s
    }

    private func feedBytesLocked() {
        guard let totals = byteTotals(scope, meterTags) else { return }
        machine.onTunnelBytes(rxTotal: totals.rx, txTotal: totals.tx)
    }

    private func tickLocked() {
        guard !stopped else { return }
        feedBytesLocked()
        apply(machine.tick(nowMs: nowMs()))
    }

    private func apply(_ step: UpstreamLeaseStep) {
        for action in step.actions {
            switch action.kind {
            case .sendRenew:
                sendRenew(action)
            case .leaveNode:
                log("Tribe upstream: terminal code=\(action.reason)")
                stopped = true
                cancelTimerLocked()
                let code = action.reason
                let onTerminal = onTerminal
                DispatchQueue.global(qos: .userInitiated).async { onTerminal(code) }
            case .restartByteCounters:
                // rebaseline: zero bytes of the report were charged; restart from the current totals.
                if let totals = byteTotals(scope, meterTags) {
                    machine.baselineBytes(rxTotal: totals.rx, txTotal: totals.tx)
                }
                log("Tribe upstream: rebaseline epoch=\(machine.accountingEpoch)")
            case .revisionChanged:
                log("Tribe upstream: revision \(action.upstreamRevision)")
            case .configChanged:
                log("Tribe upstream: config changed (applies at the next connect)")
            case .sendAcquire, .sendRelease, .leaseReady, .leaseConfirmed, .tryNextCandidate:
                // The extension never acquires (renewUntilGone); a release only comes from release().
                break
            }
        }
        if !stopped { schedule(step.wakeAtMs) }
    }

    private func sendRenew(_ action: UpstreamLeaseAction) {
        let url = leaseURL(action) + "/renew"
        let headers = headers(action)
        let body = UpstreamLeaseWire.meterBody(action.meter)
        let requestId = action.requestId
        let seq = action.meter.seq
        let transport = transport
        ioQueue.async { [weak self] in
            let result = transport.send(method: "POST", url: url, headers: headers, body: body,
                                        timeoutMs: Self.renewTimeoutMs)
            self?.queue.async { [weak self] in
                guard let self, !self.stopped else { return }
                let reply = UpstreamLeaseWire.classifyRenewReply(httpStatus: result.status, body: result.body)
                self.log("Tribe upstream: renew seq=\(seq) -> \(Self.describe(reply, result))")
                self.feedBytesLocked()
                self.apply(self.machine.onRenewReply(requestId: requestId, reply: reply, nowMs: self.nowMs()))
            }
        }
    }

    private func leaseURL(_ action: UpstreamLeaseAction) -> String {
        // lease_id is validated ([A-Za-z0-9_-]{32,64}) and api_base normalized at parse time.
        action.route.apiBase + "/v1/upstream/lease/" + action.leaseId
    }

    private func headers(_ action: UpstreamLeaseAction) -> [String: String] {
        ["Authorization": "Bearer " + action.route.renewToken, "Content-Type": "application/json"]
    }

    private func schedule(_ wakeAtMs: Int64) {
        if timer == nil {
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.setEventHandler { [weak self] in self?.tickLocked() }
            t.schedule(wallDeadline: .distantFuture)
            t.resume()
            timer = t
        }
        guard wakeAtMs >= 0 else {
            // A renewal is in flight: its answer re-arms the timer.
            timer?.schedule(wallDeadline: .distantFuture)
            return
        }
        let delayMs = max(0, min(wakeAtMs - nowMs(), Self.maxTimerAheadMs))
        timer?.schedule(wallDeadline: .now() + .milliseconds(Int(delayMs)), leeway: .milliseconds(500))
    }

    private func cancelTimerLocked() {
        timer?.cancel()
        timer = nil
    }

    private static func describe(_ reply: UpstreamRenewReply, _ result: UpstreamLeaseWire.HTTPResult) -> String {
        switch reply.kind {
        case .granted: return reply.renewal.rebaseline ? "rebaseline" : "ok"
        case .refused: return "refused code=\(reply.error.code.rawValue)"
        case .failed:
            return result.errorCode.isEmpty ? "failed \(reply.why)" : "failed \(reply.why) error=\(result.errorCode)"
        }
    }
}

// Runs a closure at most once, from any thread.
final class UpstreamOnce {
    private let lock = NSLock()
    private var body: (() -> Void)?

    init(_ body: @escaping () -> Void) {
        self.body = body
    }

    func run() {
        lock.lock()
        let b = body
        body = nil
        lock.unlock()
        b?()
    }
}

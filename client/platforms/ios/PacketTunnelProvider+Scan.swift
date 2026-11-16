import Darwin
import Foundation
import Network
import NetworkExtension
import ObjectiveC
import os

// AVPN (Scanner, lane L4; plan scanner-client-plan.md v2.2 §2.3, CONNECT-INVARIANTS §32): the provider glue of
// the probe host (TribeScanHost.swift). Own file: the upstream Amnezia files only call in here at `// AVPN`
// points - PacketTunnelProvider.swift (the scan dispatch, the reply for actions without a branch, the host
// reopened by a successful startTunnel, the stop-all that closes it on stopTunnel), PacketTunnelProvider+Xray.swift
// (stop-all inside stopXray's gate, before the core stops), PacketTunnelProvider+WireGuard.swift (the adapter's
// backend-restart callback when the adapter is made, stop-all before a soft restart and before a configuration
// switch) and our PacketTunnelProvider+Upstream.swift (stop-all before a terminal lease answer stops the core).
//
// Every stop-all moves the provider's tunnel-change epoch (TribeScanLifecycle, review F1): a scan message carries
// the epoch of its receipt, a start that waited (peer read, gate) across a stop is refused "tunnel_changed", and
// from stopTunnel until the next successful startTunnel every start is refused "no_vpn".
//
// Until the app sends its first scan_* message there is no monitor, no host and no engine call (a stop hook only
// makes the small lifecycle record). Nothing here acts on the tunnel: no connect, stop, restart, route or socket of
// the tunnel; probe sockets are bound by the engine itself to the index passed in the host options, so a probe's
// failure stays the probe's.
//
// AWG mini probe (patch 0014): this host passes what the runner needs - the physical interface index and, on an
// AmneziaWG tunnel, `awg_live_peer` (the adapter's current peer) with scan_start; it refuses awg_mini candidates
// when that peer cannot be read, and stops every scan before a peer change of the live tunnel. Its pool is
// offered (lowered by memory headroom); the app gates it. Build 140's in-place peer switch must call
// tribeScanStopAllIfUsed first (PacketTunnelProvider+DataWatch.swift tribeSwitchConfiguration). The adapter's own
// backend stops, pauses and replacements (review F2) end every scan through the adapter's tribeBackendWillRestart
// callback (awg-apple patch 0015, tribeScanAttachAdapter): a synchronous engine stop bounded to 600 ms, without the
// lifecycle gate - see tribeScanBackendWillRestart. A socket rebind keeps scans.

/// The adapter's backend-restart callback (awg-apple patch 0015: `tribeBackendWillRestart`, called synchronously on
/// the adapter's work queue right before stop / pause / restart / rebind; nil = no callback). Reached through this
/// protocol so the wiring stays one conformance line; run_ios_swift_checks.sh --ne-typecheck requires the
/// conformance exactly when the package's adapter has the property.
protocol TribeBackendRestartObservable: AnyObject {
    var tribeBackendWillRestart: ((TribeBackendRestart) -> Void)? { get set }
}

extension WireGuardAdapter: TribeBackendRestartObservable {}

/// Per provider: the tunnel lifecycle record, the host (made on the first scan message) and the scan's own path
/// monitor ("ne" source).
final class TribeScanProviderState {
    let lifecycle = TribeScanLifecycle()
    let generation = TribeScanPathGeneration()
    let messageQueue = DispatchQueue(label: Constants.processQueueName + ".tribe-scan", attributes: .concurrent)
    private let monitorQueue = DispatchQueue(label: Constants.processQueueName + ".tribe-scan-path")
    private let lock = NSLock()
    private var hostStorage: TribeScanHost?
    private var monitor: NWPathMonitor?
    private var satisfiedStorage: Bool?

    var host: TribeScanHost? {
        lock.lock()
        defer { lock.unlock() }
        return hostStorage
    }

    /// nil until the monitor delivered its first path.
    var satisfied: Bool? {
        lock.lock()
        defer { lock.unlock() }
        return satisfiedStorage
    }

    func host(orMake make: () -> TribeScanHost) -> TribeScanHost {
        lock.lock()
        defer { lock.unlock() }
        if let hostStorage { return hostStorage }
        let made = make()
        hostStorage = made
        // The tunnel's own utun (and any other VPN) is type .other: the path seen here is the physical one.
        let pathMonitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        pathMonitor.pathUpdateHandler = { [weak self] path in self?.observe(path) }
        pathMonitor.start(queue: monitorQueue)
        monitor = pathMonitor
        return made
    }

    private func observe(_ path: Network.NWPath) {
        let facts = Self.facts(of: path)
        lock.lock()
        satisfiedStorage = facts.satisfied
        lock.unlock()
        generation.observe(signature: facts.signature)
    }

    static func facts(of path: Network.NWPath) -> TribeScanPathFacts {
        let physical = path.availableInterfaces.filter {
            $0.type != .loopback && $0.type != .other && !PacketTunnelProvider.isVirtualInterfaceName($0.name)
                && path.usesInterfaceType($0.type)
        }
        let interfaces = physical.map { "\(typeName($0.type)):\($0.name):\($0.index)" }
        let addresses = TribeScanPathFacts.addresses(ofInterfaces: Set(physical.map(\.name)))
        return TribeScanPathFacts(satisfied: path.status == .satisfied, interfaces: interfaces,
                                  addresses: addresses, gateways: path.gateways.map { "\($0)" })
    }

    private static func typeName(_ type: NWInterface.InterfaceType) -> String {
        switch type {
        case .wifi: return "wifi"
        case .cellular: return "cellular"
        case .wiredEthernet: return "wired"
        case .loopback: return "loopback"
        case .other: return "other"
        @unknown default: return "unknown"
        }
    }
}

/// The adapter's answer, handed from its work queue to the waiting scan queue.
private final class TribeScanPeerBox {
    private let lock = NSLock()
    private var storage: String?
    func set(_ v: String?) { lock.lock(); storage = v; lock.unlock() }
    var value: String? { lock.lock(); defer { lock.unlock() }; return storage }
}

private var tribeScanStateKey: UInt8 = 0
private let tribeScanStateLock = NSLock()

extension PacketTunnelProvider {
    /// Actions handleAppMessage has a branch for. An action outside this set is answered with
    /// {"error":"unknown_action"} before the branches (plan §2.3, risk R4): add every new branch's action here
    /// (run_ios_swift_checks.sh fails when a branch is missing from the set).
    static let tribeAppActionsWithBranch: Set<String> = [
        Constants.kActionStatus,
        Constants.kActionRebind,
        Constants.kActionSoftRestart,
        UpstreamProviderKeys.actionLeaseSet,
    ]

    func tribeAppActionHasBranch(_ action: String) -> Bool {
        Self.tribeAppActionsWithBranch.contains(action)
    }

    func tribeAnswerUnknownAction(_ action: String, completionHandler: (Data?) -> Void) {
        neLog(.info, message: "App message: no branch for action \(TribeScanHost.safeToken(action)); unknown_action")
        completionHandler(TribeScanHost.unknownActionReply)
    }

    private var tribeScanStateIfMade: TribeScanProviderState? {
        tribeScanStateLock.lock()
        defer { tribeScanStateLock.unlock() }
        return objc_getAssociatedObject(self, &tribeScanStateKey) as? TribeScanProviderState
    }

    private var tribeScanState: TribeScanProviderState {
        tribeScanStateLock.lock()
        defer { tribeScanStateLock.unlock() }
        if let state = objc_getAssociatedObject(self, &tribeScanStateKey) as? TribeScanProviderState { return state }
        let state = TribeScanProviderState()
        objc_setAssociatedObject(self, &tribeScanStateKey, state, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        return state
    }

    /// The dispatch of handleAppMessage: true = a scan message, answered here (off the provider's message
    /// handler: a scan_start that replaces a running scan may wait up to 3 s, a scan_cancel up to 1.5 s). The
    /// bytes are never logged (they carry the scan token and the candidates' configs).
    func tribeHandleScanMessageIfScan(_ messageData: Data, completionHandler: ((Data?) -> Void)?) -> Bool {
        guard let message = TribeScanHost.scanMessage(of: messageData) else { return false }
        let state = tribeScanState
        let host = state.host(orMake: { makeTribeScanHost(state: state) })
        let received = state.lifecycle.epoch // the epoch of its receipt: a stop after this point makes a start stale
        state.messageQueue.async {
            let reply = host.handle(message.bytes, action: message.action, receivedEpoch: received)
            completionHandler?(reply)
        }
        return true
    }

    private func makeTribeScanHost(state: TribeScanProviderState) -> TribeScanHost {
        let generation = state.generation
        return TribeScanHost(
            engine: TribeScanEngine(messageFn: LibXrayTribeScanMessage, stopAllFn: LibXrayTribeScanStopAll),
            gate: xrayNativeLifecycleGate,
            lifecycle: state.lifecycle,
            path: { [weak self, weak state] in
                // The index the tunnel's own sockets are bound to (the provider's path, never the utun).
                let index = self?.activeIfaceIdx ?? 0
                let satisfied = state?.satisfied ?? (index != 0)
                return TribeScanPathInfo(bindIndex: index, satisfied: satisfied, element: generation.element)
            },
            availableMB: { Self.tribeScanAvailableMB() },
            liveAwgPeer: { [weak self] in self?.tribeScanLiveAwgPeer() ?? .unknown },
            log: { neLog(.info, message: $0) })
    }

    /// The live AmneziaWG tunnel's peer for the scan_start host option `awg_live_peer`: the adapter's CURRENT
    /// peer from its runtime configuration (UAPI), so a peer the tunnel moved to is the one refused.
    /// notAmneziaWG on an Xray / OpenVPN tunnel; unknown on AmneziaWG without a running adapter, without a peer in
    /// its answer, or when it does not answer within 500 ms (the host then refuses awg_mini candidates). The UAPI
    /// text (it carries the private key) is parsed here and dropped, never logged or kept.
    func tribeScanLiveAwgPeer() -> TribeScanHost.LivePeer {
        guard protoType == .wireguard else { return .notAmneziaWG }
        guard let adapter = wgAdapter else { return .unknown }
        let done = DispatchSemaphore(value: 0)
        let box = TribeScanPeerBox()
        adapter.getRuntimeConfiguration { uapi in
            box.set(uapi.flatMap { TribeScanHost.awgLivePeerJSON(fromUAPI: $0) })
            done.signal()
        }
        guard done.wait(timeout: .now() + .milliseconds(500)) == .success, let peer = box.value else { return .unknown }
        return .known(peer)
    }

    static func tribeScanAvailableMB() -> Double? {
#if os(iOS)
        return Double(os_proc_available_memory()) / 1_048_576
#else
        return nil
#endif
    }

    /// Before the tunnel core stops, restarts or changes peer, and on sleep: under xrayNativeLifecycleGate the
    /// tunnel-change epoch moves (close = stopTunnel: the host stays closed until a successful startTunnel), every
    /// scan ends (reason tunnel_stopped) and its probe instances close (engine wait <= 2 s). The engine is not
    /// called while no start ever reached it.
    func tribeScanStopAllIfUsed(reason: String, close: Bool = false) {
        let state = tribeScanState
        if let host = state.host {
            host.stopAll(reason: reason, close: close)
        } else {
            xrayNativeLifecycleGate.withExclusive { _ = state.lifecycle.bump(close: close) }
        }
    }

    /// startTunnel's completion, wrapped: a successful start opens the host again (stopTunnel closed it) - only the
    /// start that asked for it, and only if no stopTunnel came since it began (review R1: a stop always wins over
    /// a late success, e.g. startWireguard's asynchronous completion after the tunnel was already stopping).
    func tribeScanReopenOnSuccess(_ completion: @escaping ((any Error)?) -> Void) -> ((any Error)?) -> Void {
        let lifecycle = tribeScanState.lifecycle
        let token = lifecycle.reopenToken
        return { error in
            if error == nil { lifecycle.reopen(token: token) }
            completion(error)
        }
    }

    /// When the WireGuard adapter is made: its own backend restarts end every scan first (review F2).
    func tribeScanAttachAdapter(_ adapter: WireGuardAdapter) {
        guard let observable = (adapter as AnyObject) as? TribeBackendRestartObservable else { return } // recipe without the callback
        observable.tribeBackendWillRestart = { [weak self] reason in self?.tribeScanBackendWillRestart(reason) }
    }

    /// Called on the adapter's work queue right before it stops, pauses, replaces or rebinds its backend; may come
    /// several times per recovery step (idempotent: an epoch bump and an engine stop that finds nothing the second
    /// time). For stop / pause / restart the backend operation waits for the engine's stop, at most 600 ms
    /// (TribeScanHost.stopForBackendRestart), and never for the lifecycle gate: a gate holder may sit in the engine
    /// for seconds (a replacing start 3 s, a stop-all 2 s).
    /// No deadlock with this queue: the engine's teardown never needs it - the AmneziaWG runner's devices log to
    /// their own silent logger (patch 0014, device.Logger with DiscardLogf), Xray probe instances and dials log
    /// into their own scope (core 0011 log.ContextWithScope, scopeHandler drops them), and the one summary line per
    /// probe goes through the extension's C logger to the adapter's logHandler, which only calls wg_log (os_log and
    /// a file append) and journalQueue.async. The only code of the scan host that waits on this queue is the
    /// live-peer read (getRuntimeConfiguration), on the scan queue, before the gate and bounded to 500 ms: while this
    /// callback holds the queue it simply waits (or answers unknown), it holds nothing this callback needs.
    /// .rebind (wgBumpSockets, endpoints re-set, listen_port=0): the device, its peer and its memory stay, only the
    /// tunnel's own UDP socket is recreated - probes keep running (the same decision as on desktop).
    func tribeScanBackendWillRestart(_ reason: TribeBackendRestart) {
        switch reason {
        case .rebind:
            return
        case .stop, .pause, .restart:
            break
        }
        guard let state = tribeScanStateIfMade else { return } // no scan message ever: nothing to stop
        if let host = state.host {
            host.stopForBackendRestart(reason: "backend_\(reason.rawValue)")
        } else {
            state.lifecycle.bump(close: false)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        tribeScanStopAllIfUsed(reason: "sleep")
        completionHandler()
    }
}

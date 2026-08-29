import HevSocks5Tunnel
import NetworkExtension

public enum Socks5Tunnel {

    private static let lifecycleLock = NSLock()
    private static let nativeQueue = DispatchQueue(label: "org.amnezia.hev.native")
    private static let readinessQueue = DispatchQueue(label: "org.amnezia.hev.readiness")
    private static var lifecycle = Socks5TunnelLifecycle()
    private static var token: UInt64 = 0
    private static var readinessWorkItem: DispatchWorkItem?
    private static var stopTimeoutWorkItem: DispatchWorkItem?
    private static var startCompletion: ((Result<Void, StartError>) -> Void)?
    private static var stopCompletions = [((StopResult) -> Void)]()
    private static var exitHandler: ((Int32) -> Void)?

    public enum StartError: Error, Equatable {
        case noTunnelFileDescriptor
        case busy
        case native(Int32)
        case cancelled
        case timedOut
    }

    public enum StopResult: Equatable {
        case stopped
        case timedOut
    }

    public struct TrafficStats: Equatable {
        public let txPackets: UInt64
        public let txBytes: UInt64
        public let rxPackets: UInt64
        public let rxBytes: UInt64
    }

    private static var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    private static var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))
        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else {
                return nil
            }
            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize
            )
            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    public static func start(withConfig filePath: String,
                             completion: @escaping (Result<Void, StartError>) -> Void,
                             onExit: @escaping (Int32) -> Void) {
        guard let fileDescriptor = self.tunnelFileDescriptor else {
            completion(.failure(.noTunnelFileDescriptor))
            return
        }

        lifecycleLock.lock()
        guard lifecycle.beginStart() else {
            lifecycleLock.unlock()
            completion(.failure(.busy))
            return
        }
        token = token == UInt64.max ? 1 : token + 1
        let startToken = token
        startCompletion = completion
        stopCompletions.removeAll()
        exitHandler = onExit
        lifecycleLock.unlock()

        scheduleReadinessPoll(token: startToken, deadline: .now() + 5.0)

        nativeQueue.async {
            let result = hev_socks5_tunnel_main(filePath.cString(using: .utf8), fileDescriptor)
            process(token: startToken) { state in
                state.observeNativeReturn(result)
            }
        }
    }

    public static func stop(completion: @escaping (StopResult) -> Void) {
        lifecycleLock.lock()
        stopCompletions.append(completion)
        let stopToken = token
        let actions = lifecycle.requestStop()
        let needsTimeout = lifecycle.phase == .stopping
        lifecycleLock.unlock()

        perform(actions, token: stopToken)
        guard needsTimeout else { return }

        let timeoutItem = DispatchWorkItem {
            process(token: stopToken) { state in
                state.stopTimedOut()
            }
        }
        lifecycleLock.lock()
        stopTimeoutWorkItem?.cancel()
        stopTimeoutWorkItem = timeoutItem
        lifecycleLock.unlock()
        readinessQueue.asyncAfter(deadline: .now() + 2.0, execute: timeoutItem)
    }

    // hev-socks5-tunnel exposes process-local counters.  They reset when
    // hev_socks5_tunnel_main starts; TunnelRuntimeSession turns those raw
    // values into reset-safe cumulative counters for the current NE session.
    public static func trafficStats() -> TrafficStats? {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard lifecycle.phase == .running,
              hev_socks5_tunnel_is_ready() != 0 else { return nil }
        var txPackets: Int = 0
        var txBytes: Int = 0
        var rxPackets: Int = 0
        var rxBytes: Int = 0
        hev_socks5_tunnel_stats(&txPackets, &txBytes, &rxPackets, &rxBytes)
        return TrafficStats(
            txPackets: UInt64(max(0, txPackets)),
            txBytes: UInt64(max(0, txBytes)),
            rxPackets: UInt64(max(0, rxPackets)),
            rxBytes: UInt64(max(0, rxBytes))
        )
    }

    private static func scheduleReadinessPoll(token expectedToken: UInt64,
                                              deadline: DispatchTime) {
        let item = DispatchWorkItem {
            lifecycleLock.lock()
            let isCurrent = token == expectedToken
            let phase = lifecycle.phase
            lifecycleLock.unlock()
            guard isCurrent, phase == .starting else { return }

            let nativeReady = hev_socks5_tunnel_is_ready() != 0
            // Idle Xray does not create its first outbound socket until HEV
            // forwards user traffic.  Socket protection is installed before
            // this point and failures cancel the provider asynchronously; it
            // must not be a pre-completion gate that deadlocks an idle start.
            if nativeReady {
                process(token: expectedToken) { state in
                    state.observeReady()
                }
                return
            }

            if DispatchTime.now() >= deadline {
                process(token: expectedToken) { state in
                    state.startTimedOut()
                }
                return
            }

            scheduleReadinessPoll(token: expectedToken, deadline: deadline)
        }

        lifecycleLock.lock()
        readinessWorkItem = item
        lifecycleLock.unlock()
        readinessQueue.asyncAfter(deadline: .now() + 0.01, execute: item)
    }

    private static func process(token expectedToken: UInt64,
                                event: (inout Socks5TunnelLifecycle) -> [Socks5TunnelLifecycleAction]) {
        lifecycleLock.lock()
        guard token == expectedToken else {
            lifecycleLock.unlock()
            return
        }
        let actions = event(&lifecycle)
        let terminal = lifecycle.phase == .stopped || lifecycle.phase == .failed
        if terminal {
            readinessWorkItem?.cancel()
            readinessWorkItem = nil
            stopTimeoutWorkItem?.cancel()
            stopTimeoutWorkItem = nil
        }
        lifecycleLock.unlock()
        perform(actions, token: expectedToken)
    }

    private static func perform(_ actions: [Socks5TunnelLifecycleAction], token expectedToken: UInt64) {
        for action in actions {
            switch action {
            case .requestNativeStop:
                // Local HEV API: records cancellation even before readiness and
                // never waits for the native event fd.
                _ = hev_socks5_tunnel_try_quit()
            case .reportStarted:
                takeStartCompletion(token: expectedToken)?(.success(()))
            case .reportStartFailure(let failure):
                let error: StartError
                switch failure {
                case .native(let code): error = .native(code)
                case .cancelled: error = .cancelled
                case .timedOut: error = .timedOut
                }
                takeStartCompletion(token: expectedToken)?(.failure(error))
            case .reportStopped:
                takeStopCompletions(token: expectedToken).forEach { $0(.stopped) }
            case .reportStopTimedOut:
                takeStopCompletions(token: expectedToken).forEach { $0(.timedOut) }
            case .reportUnexpectedExit(let code):
                takeExitHandler(token: expectedToken)?(code)
            }
        }
    }

    private static func takeStartCompletion(token expectedToken: UInt64) -> ((Result<Void, StartError>) -> Void)? {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard token == expectedToken else { return nil }
        let callback = startCompletion
        startCompletion = nil
        return callback
    }

    private static func takeStopCompletions(
        token expectedToken: UInt64
    ) -> [((StopResult) -> Void)] {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard token == expectedToken else { return [] }
        let callbacks = stopCompletions
        stopCompletions.removeAll()
        return callbacks
    }

    private static func takeExitHandler(token expectedToken: UInt64) -> ((Int32) -> Void)? {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard token == expectedToken else { return nil }
        return exitHandler
    }
}

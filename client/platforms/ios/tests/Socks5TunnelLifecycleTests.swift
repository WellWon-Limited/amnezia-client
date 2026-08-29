import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}

private func testImmediateNativeFailures() {
    for code: Int32 in [-1, -5] {
        var lifecycle = Socks5TunnelLifecycle()
        expect(lifecycle.beginStart(), "begin start for native \(code)")
        expect(
            lifecycle.observeNativeReturn(code) == [.reportStartFailure(.native(code))],
            "immediate native \(code) must fail start",
        )
        expect(lifecycle.observeReady().isEmpty, "late readiness after native failure")
        expect(lifecycle.observeNativeReturn(code).isEmpty, "native failure callback exactly once")
    }
}

private func testStopDuringStart() {
    var lifecycle = Socks5TunnelLifecycle()
    expect(lifecycle.beginStart(), "begin start")
    expect(
        lifecycle.requestStop() == [.reportStartFailure(.cancelled), .requestNativeStop],
        "stop during start cancels start and requests cooperative native stop",
    )
    expect(lifecycle.observeReady() == [.requestNativeStop], "readiness race repeats nonblocking stop")
    expect(lifecycle.observeNativeReturn(0) == [.reportStopped], "native return proves stopped")
    expect(lifecycle.observeNativeReturn(0).isEmpty, "stop completion exactly once")
}

private func testExactlyOnceReadyAndTimeout() {
    var lifecycle = Socks5TunnelLifecycle()
    expect(lifecycle.beginStart(), "begin ready start")
    expect(lifecycle.observeReady() == [.reportStarted], "first readiness completes start")
    expect(lifecycle.observeReady().isEmpty, "duplicate readiness ignored")
    expect(lifecycle.requestStop() == [.requestNativeStop], "running stop requests native stop")
    expect(lifecycle.observeNativeReturn(0) == [.reportStopped], "running stop completes")
    expect(lifecycle.requestStop() == [.reportStopped],
           "a later provider teardown receives the already-stopped proof")
    expect(lifecycle.requestStop() == [.reportStopped],
           "every later stopped waiter completes deterministically")

    var timeout = Socks5TunnelLifecycle()
    expect(timeout.beginStart(), "begin timeout start")
    expect(
        timeout.startTimedOut() == [.reportStartFailure(.timedOut), .requestNativeStop],
        "start timeout is fail closed",
    )
    expect(timeout.stopTimedOut() == [.reportStopTimedOut], "bounded stop timeout")
    expect(timeout.stopTimedOut().isEmpty, "timeout completion exactly once")
    expect(timeout.requestStop() == [.reportStopTimedOut],
           "every later stop waiter receives deterministic quarantined timeout")
    expect(timeout.requestStop() == [.reportStopTimedOut],
           "quarantined recovery stop can never hang on a consumed completion")
    expect(!timeout.beginStart(), "timed-out native singleton remains quarantined")
}

private func testIdleReadinessDoesNotRequireFirstUserPacket() {
    var lifecycle = Socks5TunnelLifecycle()
    expect(lifecycle.beginStart(), "begin idle start")
    // Native HEV readiness is sufficient to complete start.  The Xray socket
    // callback cannot run until the first later user packet and therefore is
    // deliberately not represented as a prerequisite here.
    expect(lifecycle.observeReady() == [.reportStarted],
           "idle native readiness must complete without outbound traffic")
}

private func testCounterResetAndDecimalWireFormat() {
    var accumulator = ResetSafeTrafficAccumulator()
    _ = accumulator.record(TunnelTrafficSample(rxBytes: 10, txBytes: 20, rxPackets: 2, txPackets: 3))
    let reset = accumulator.record(TunnelTrafficSample(rxBytes: 1, txBytes: 4, rxPackets: 1, txPackets: 1))
    expect(reset.resetDetected, "backward native counters detect reset")
    expect(reset.sample == .zero, "reset cannot underflow")

    let session = TunnelRuntimeSession()
    let generation = session.beginSession(protocolName: "xray")
    expect(session.transition(to: .running, generation: generation), "runtime enters running")
    expect(
        session.record(
            TunnelTrafficSample(
                rxBytes: UInt64.max,
                txBytes: 9_007_199_254_740_993,
                rxPackets: UInt64.max,
                txPackets: 0
            ),
            generation: generation
        ),
        "record max counters",
    )
    let payload = session.payload(core: [:])
    let counters = payload["counters"] as? [String: Any]
    expect(counters?["rx_bytes"] as? String == String(UInt64.max), "UInt64.max stays exact")
    expect(counters?["tx_bytes"] as? String == "9007199254740993", ">2^53 stays exact")
    expect(payload["rx_bytes"] is String, "flat compatibility counter is also a decimal string")
    expect(JSONSerialization.isValidJSONObject(payload), "typed payload serializes")
}

@main
private struct RuntimeSmokeTests {
    static func main() {
        testImmediateNativeFailures()
        testStopDuringStart()
        testExactlyOnceReadyAndTimeout()
        testIdleReadinessDoesNotRequireFirstUserPacket()
        testCounterResetAndDecimalWireFormat()
        print("Apple Xray lifecycle/runtime smoke tests passed")
    }
}

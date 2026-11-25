import Foundation

// AVPN (review R43 F3): the order of startTunnel's answer and stopTunnel's answer (TunnelStartSlot,
// TunnelRuntimeStatus.swift), on the slot's own API as the provider calls it (begin at startTunnel, abortForStop when
// the native stop is done, right before the stop's own answer). Host test, run by run_ios_swift_checks.sh.
//   1. A start's answer already being delivered when the stop finishes: the stop's answer comes after it, never before.
//   2. A second begin() on the same slot: the first start still gets its one answer.

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}

private final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [String] = []
    func add(_ e: String) { lock.lock(); events.append(e); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return events }
}

@main
private struct TunnelStartSlotOrderTests {
    static func main() {
        // 1. The start thread has taken its answer and is inside the system's completion (slow: 300 ms) when the stop's
        //    native part is done. The stop must not answer the system before that answer has been delivered.
        do {
            let rec = Recorder()
            let slot = TunnelStartSlot()
            let entered = DispatchSemaphore(value: 0)
            let startAnswer = slot.begin { error in
                entered.signal()
                Thread.sleep(forTimeInterval: 0.3)
                rec.add(error == nil ? "start:ok" : "start:error")
            }
            DispatchQueue.global().async { startAnswer(nil) }
            expect(entered.wait(timeout: .now() + 2) == .success, "the start's answer began")
            _ = slot.abortForStop()
            rec.add("stop")
            expect(rec.all == ["start:ok", "stop"],
                   "the stop answered while the start's answer was still being delivered: \(rec.all)")
        }
        // 2. Two starts on one slot, the first unanswered: it gets its answer (an error), the second is the one the stop
        //    answers.
        do {
            let rec = Recorder()
            let slot = TunnelStartSlot()
            _ = slot.begin { rec.add($0 == nil ? "first:ok" : "first:error") }
            _ = slot.begin { rec.add($0 == nil ? "second:ok" : "second:error") }
            expect(rec.all == ["first:error"], "the first start was left without its answer: \(rec.all)")
            _ = slot.abortForStop()
            expect(rec.all == ["first:error", "second:error"], "each start answered once: \(rec.all)")
        }
        print("TunnelStartSlot order tests passed")
    }
}

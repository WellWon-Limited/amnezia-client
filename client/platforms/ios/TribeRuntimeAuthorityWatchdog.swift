import Foundation

enum TribeRuntimeAuthorityWatchdogPlanner {
    static func remaining(
        snapshot: TribeRuntimeAuthorityLeaseSnapshot,
        wallUtc: Date,
        monotonic: TimeInterval
    ) throws -> TimeInterval {
        guard monotonic.isFinite, monotonic >= snapshot.capturedMonotonic else {
            throw TribeRuntimeAuthorityLeaseError.clockRollback
        }
        let elapsed = monotonic - snapshot.capturedMonotonic
        let trustedLowerBound = snapshot.trustedUtcAtDispatch.addingTimeInterval(elapsed)
        guard wallUtc >= trustedLowerBound.addingTimeInterval(-300) else {
            throw TribeRuntimeAuthorityLeaseError.clockRollback
        }
        let remaining = snapshot.hardDeadline.timeIntervalSince(max(wallUtc, trustedLowerBound))
        guard remaining > 0 else { throw TribeRuntimeAuthorityLeaseError.expired }
        return remaining
    }
}

/// Each renewal gets a new one-shot token. consume() is the exact fence that makes an old timer
/// harmless even if Dispatch delivers its already-queued handler after cancellation.
final class TribeRuntimeAuthorityWatchdogFence {
    private let lock = NSLock()
    private var generation: UInt64 = 0

    func arm() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        generation = next(generation)
        return generation
    }

    func cancel() {
        lock.lock(); defer { lock.unlock() }
        generation = next(generation)
    }

    func consume(_ expected: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard generation == expected else { return false }
        generation = next(generation)
        return true
    }

    private func next(_ value: UInt64) -> UInt64 {
        value == UInt64.max ? 1 : value + 1
    }
}

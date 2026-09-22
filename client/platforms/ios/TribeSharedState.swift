import Foundation
import Darwin

enum TribeSharedStateError: Error {
    /// Another process (GUI, App Intents, NE) holds the lock longer than the caller's budget.
    case lockBusy
}

/// Small, credential-free records shared by GUI, App Intents and NE. Atomic replacement plus
/// flock prevents a late acknowledgement from deleting a newer action in another process.
///
/// The lock is NEVER waited on without a bound (H10): a peer suspended inside its critical section
/// (iOS freezes the NE or the GUI at any instruction) must not freeze the caller. `LOCK_NB` is
/// retried until `timeout`, then the call fails with `lockBusy`; journal writes are best effort and
/// are simply dropped.
struct TribeSharedState {
    let directory: URL

    /// Default wait for state transitions (begin/update/last-stop).
    static let defaultLockTimeout: TimeInterval = 0.25
    /// Journal records are diagnostics: bounded tightly (NE writes run on `journalQueue`).
    static let journalLockTimeout: TimeInterval = 0.1
    /// Repeated identical path-change records within this window are merged into one entry.
    static let coalesceWindowMs: Int64 = 60_000

    /// The App Group URL does not change during the process lifetime: resolve it once.
    /// macOS NE (H11): its App Group is group.org.amnezia.AmneziaVPN, the Tribe group is not in its
    /// entitlements, so every record is a deliberate no-op there instead of a sandbox violation.
    #if os(macOS)
    static let appGroup: TribeSharedState? = nil
    #else
    static let appGroup: TribeSharedState? =
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.hk.wellwon.tribe")
            .map { TribeSharedState(directory: $0) }
    #endif

    /// NE-side serial queue for journal writes: callers on the adapter's workQueue hop here, so the
    /// tunnel's own queue never touches the shared file lock at all.
    static let journalQueue = DispatchQueue(label: "hk.wellwon.tribe.shared-state.journal", qos: .utility)

    func locked<T>(timeout: TimeInterval = TribeSharedState.defaultLockTimeout, _ body: () throws -> T) throws -> T {
        let fd = open(directory.appendingPathComponent("TribeIntentState.lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        let deadline = ProcessInfo.processInfo.systemUptime + max(0, timeout)
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            let failure = errno
            guard failure == EWOULDBLOCK || failure == EINTR else { throw CocoaError(.fileWriteUnknown) }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw TribeSharedStateError.lockBusy }
            usleep(2_000)
        }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    func read(_ name: String) -> [String: Any] {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(name)),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return value
    }

    func write(_ value: [String: Any], _ name: String) throws {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            .write(to: directory.appendingPathComponent(name), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    func begin(action: String, now: Date = Date(),
               lockTimeout: TimeInterval = TribeSharedState.defaultLockTimeout) throws -> String {
        try locked(timeout: lockTimeout) {
            let generation = UUID().uuidString
            try write(["schema_version": 1, "generation": generation, "action": action,
                       "source": "intent", "applied": false,
                       "created_ms": Int64(now.timeIntervalSince1970 * 1000),
                       "deadline_ms": Int64(now.addingTimeInterval(90).timeIntervalSince1970 * 1000)],
                      "TribeIntentState.json")
            return generation
        }
    }

    func isCurrent(_ generation: String) -> Bool {
        read("TribeIntentState.json")["generation"] as? String == generation
    }

    @discardableResult
    func update(_ generation: String, fields: [String: Any],
                lockTimeout: TimeInterval = TribeSharedState.defaultLockTimeout) throws -> Bool {
        try locked(timeout: lockTimeout) {
            var value = read("TribeIntentState.json")
            guard value["generation"] as? String == generation else { return false }
            fields.forEach { value[$0.key] = $0.value }
            try write(value, "TribeIntentState.json")
            return true
        }
    }

    /// Appends one lifecycle entry (ring of 128). Events listed in `TribeNEJournal.coalescedEvents`
    /// that repeat the previous entry within `coalesceWindowMs` update it in place (`repeat` count,
    /// `first_utc_ms`) instead of evicting useful history on a flapping network.
    /// Returns false when the entry was dropped (lock busy / write failed). `lockTimeout` exists for
    /// tests that need a deterministic outcome under CPU load; production callers keep the default.
    @discardableResult
    func record(source: String, event: String, fields: [String: Any] = [:], now: Date = Date(),
                lockTimeout: TimeInterval = TribeSharedState.journalLockTimeout) -> Bool {
        // Call sites supply only lifecycle labels/counters/opaque generations, never configs.
        let result: Void? = try? locked(timeout: lockTimeout) {
            let name = source == "ne" ? "TribeNELifecycle.json" : "TribeIntentLifecycle.json"
            var entries = read(name)["entries"] as? [[String: Any]] ?? []
            let utcMs = Int64(now.timeIntervalSince1970 * 1000)
            var entry: [String: Any] = ["event": event, "source": source, "fields": fields,
                                        "utc_ms": utcMs,
                                        "monotonic_ms": Int64(ProcessInfo.processInfo.systemUptime * 1000),
                                        "build": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"]
            if TribeNEJournal.coalescedEvents.contains(event), let last = entries.last,
               last["event"] as? String == event, last["source"] as? String == source,
               let lastMs = last["utc_ms"] as? Int64, utcMs - lastMs >= 0,
               utcMs - lastMs < TribeSharedState.coalesceWindowMs {
                entry["repeat"] = (last["repeat"] as? Int ?? 1) + 1
                entry["first_utc_ms"] = last["first_utc_ms"] as? Int64 ?? lastMs
                entries[entries.count - 1] = entry
            } else {
                entries.append(entry)
            }
            try write(["schema_version": 1, "entries": Array(entries.suffix(128))], name)
        }
        return result != nil
    }

    /// NE callers on the adapter's workQueue: same record, off that queue (see `journalQueue`).
    func recordAsync(source: String, event: String, fields: [String: Any] = [:]) {
        let now = Date()
        TribeSharedState.journalQueue.async { self.record(source: source, event: event, fields: fields, now: now) }
    }
}

/// Which adapter log lines become NE journal events, and under what name. Only these fixed labels
/// are persisted; the native log text itself (endpoints, config values) never is.
enum TribeNEJournal {
    static let coalescedEvents: Set<String> = ["path_change"]

    static func event(forAdapterLog message: String) -> String? {
        if message.hasPrefix("rebindListenPort:") {
            if message.contains("adapter not started") { return "gui_rebind_not_started" }
            if message.contains("denied") { return "gui_rebind_denied" }
            return "gui_rebind"
        }
        // awg-apple tribe.8 (U6): GUI-requested in-place backend restart.
        if message.hasPrefix("softRestartBackend:") {
            if message.contains("adapter not started") { return "gui_soft_restart_not_started" }
            if message.contains("denied") { return "gui_soft_restart_denied" }
            return "gui_soft_restart"
        }
        guard message.hasPrefix("Tribe roaming:") else { return nil }
        if message.contains("stall recovery denied") { return "stall_denied" }
        // tribe.8: stage-3 watchdog step (U9) and the in-place restart itself (NE or GUI).
        if message.contains("persistent heal") { return "stall_persistent" }
        if message.contains("soft restart") && message.contains("failed") { return "soft_restart_failed" }
        if message.contains("soft-restarted in place") { return "soft_restart" }
        if message.contains("pausing backend") { return "pause" }
        if message.contains("still stalled") { return "stall_rebind" }
        if message.contains("inbound stalled") { return "stall_bump" }
        return "path_change"
    }
}

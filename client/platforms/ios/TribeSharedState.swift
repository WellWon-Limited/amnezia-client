import Foundation
import Darwin

/// Small, credential-free records shared by GUI, App Intents and NE. Atomic replacement plus
/// flock prevents a late acknowledgement from deleting a newer action in another process.
struct TribeSharedState {
    let directory: URL

    static var appGroup: TribeSharedState? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.hk.wellwon.tribe")
            .map { TribeSharedState(directory: $0) }
    }

    func locked<T>(_ body: () throws -> T) throws -> T {
        let fd = open(directory.appendingPathComponent("TribeIntentState.lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw CocoaError(.fileWriteUnknown) }
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

    func begin(action: String, now: Date = Date()) throws -> String {
        try locked {
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
    func update(_ generation: String, fields: [String: Any]) throws -> Bool {
        try locked {
            var value = read("TribeIntentState.json")
            guard value["generation"] as? String == generation else { return false }
            fields.forEach { value[$0.key] = $0.value }
            try write(value, "TribeIntentState.json")
            return true
        }
    }

    func record(source: String, event: String, fields: [String: Any] = [:]) {
        // Call sites supply only lifecycle labels/counters/opaque generations, never configs.
        try? locked {
            let name = source == "ne" ? "TribeNELifecycle.json" : "TribeIntentLifecycle.json"
            var entries = read(name)["entries"] as? [[String: Any]] ?? []
            entries.append(["event": event, "source": source, "fields": fields,
                            "utc_ms": Int64(Date().timeIntervalSince1970 * 1000),
                            "monotonic_ms": Int64(ProcessInfo.processInfo.systemUptime * 1000),
                            "build": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"])
            try write(["schema_version": 1, "entries": Array(entries.suffix(128))], name)
        }
    }
}

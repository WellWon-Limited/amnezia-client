import Foundation

@main
enum SharedStateTests {
    static func main() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let gui = TribeSharedState(directory: directory)
        let intent = TribeSharedState(directory: directory)
        let enable = try intent.begin(action: "resume")
        let pause = try gui.begin(action: "pause")
        precondition(!intent.isCurrent(enable))
        let staleApplied = try intent.update(enable, fields: ["applied": true])
        precondition(!staleApplied)
        let pauseApplied = try gui.update(pause, fields: ["applied": true, "was_active": true])
        precondition(pauseApplied)
        let off = try gui.begin(action: "off")
        let staleAck = try intent.update(pause, fields: ["ack_generation": pause])
        precondition(!staleAck)
        precondition(gui.isCurrent(off))
        precondition(gui.read("TribeIntentState.json")["applied"] as? Bool == false)
        // Independently created stores emulate processes sharing the same flock/atomic files.
        DispatchQueue.concurrentPerform(iterations: 40) { n in
            let store = TribeSharedState(directory: directory)
            let generation = try! store.begin(action: n % 2 == 0 ? "pause" : "resume")
            _ = try! store.update(generation, fields: ["applied": true])
            store.record(source: "intent", event: "race", fields: ["generation": generation])
        }
        let entries = intent.read("TribeIntentLifecycle.json")["entries"] as! [[String: Any]]
        precondition(entries.count == 40)
        for n in 0..<140 { gui.record(source: "ne", event: "sample", fields: ["request_id": n]) }
        let ring = gui.read("TribeNELifecycle.json")["entries"] as! [[String: Any]]
        precondition(ring.count == 128)
        precondition((ring.first?["fields"] as? [String: Any])?["request_id"] as? Int == 12)
        try Data("corrupt".utf8).write(to: directory.appendingPathComponent("TribeIntentState.json"), options: .atomic)
        precondition(!gui.isCurrent(off)) // corrupted storage cannot authorize an old start
        print("TribeSharedStateTests: supersession, conditional ack, 40 concurrent writers, ring bounds passed")
    }
}

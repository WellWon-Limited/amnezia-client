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
        // The production bounds (0.25 s / 0.1 s) drop work under CPU load BY DESIGN (H10); this block
        // checks mutual exclusion, not the bound, so it waits generously and counts what landed. The
        // 0.1 s drop path is covered by the frozen-peer block below.
        let stressTimeout: TimeInterval = 30
        let successes = NSLock()
        var recorded = 0
        DispatchQueue.concurrentPerform(iterations: 40) { n in
            let store = TribeSharedState(directory: directory)
            let generation = try! store.begin(action: n % 2 == 0 ? "pause" : "resume", lockTimeout: stressTimeout)
            _ = try! store.update(generation, fields: ["applied": true], lockTimeout: stressTimeout)
            if store.record(source: "intent", event: "race", fields: ["generation": generation],
                            lockTimeout: stressTimeout) {
                successes.lock(); recorded += 1; successes.unlock()
            }
        }
        let entries = intent.read("TribeIntentLifecycle.json")["entries"] as! [[String: Any]]
        // No lost update: every record that reported success is in the file, and none vanished.
        precondition(recorded > 0 && entries.count == recorded, "entries \(entries.count) vs recorded \(recorded)")
        precondition(recorded == 40, "a 30 s lock budget must not drop records (\(recorded)/40)")
        for n in 0..<140 { gui.record(source: "ne", event: "sample", fields: ["request_id": n]) }
        let ring = gui.read("TribeNELifecycle.json")["entries"] as! [[String: Any]]
        precondition(ring.count == 128)
        precondition((ring.first?["fields"] as? [String: Any])?["request_id"] as? Int == 12)
        try Data("corrupt".utf8).write(to: directory.appendingPathComponent("TribeIntentState.json"), options: .atomic)
        precondition(!gui.isCurrent(off)) // corrupted storage cannot authorize an old start

        // H10/D4: a peer frozen inside its critical section (iOS suspends the NE or the GUI at any
        // instruction) must not freeze the caller. Another fd = another lock owner, as in a peer
        // process. Before tribe.7 `record()` waited on LOCK_EX without a bound (here: 1.5 s).
        let holderIn = DispatchSemaphore(value: 0)
        let holderDone = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            _ = try? TribeSharedState(directory: directory).locked(timeout: 5) {
                holderIn.signal()
                Thread.sleep(forTimeInterval: 1.5)
            }
            holderDone.signal()
        }
        holderIn.wait()
        let recordStart = ProcessInfo.processInfo.systemUptime
        gui.record(source: "ne", event: "while_frozen_peer")
        let recordElapsed = ProcessInfo.processInfo.systemUptime - recordStart
        precondition(recordElapsed < 0.5, "record() blocked \(recordElapsed) s behind a frozen peer")
        let lockStart = ProcessInfo.processInfo.systemUptime
        var busy = false
        do { _ = try gui.locked(timeout: 0.1) { true } } catch TribeSharedStateError.lockBusy { busy = true }
        precondition(busy, "bounded lock reports lockBusy")
        precondition(ProcessInfo.processInfo.systemUptime - lockStart < 0.5, "bounded lock honours its timeout")
        holderDone.wait()
        let usableAgain = try gui.locked { true }
        precondition(usableAgain, "lock usable again once the peer is gone")
        let afterFreeze = gui.read("TribeNELifecycle.json")["entries"] as! [[String: Any]]
        precondition(!afterFreeze.contains { $0["event"] as? String == "while_frozen_peer" }, "journal entry dropped, not blocked")

        // D8: a flapping path is ONE journal entry with a repeat count, not 128 evicting history.
        let journal = TribeSharedState(directory: directory.appendingPathComponent("j", isDirectory: true))
        try FileManager.default.createDirectory(at: journal.directory, withIntermediateDirectories: true)
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        journal.record(source: "ne", event: "start", now: t0)
        for n in 0..<50 { journal.record(source: "ne", event: "path_change", fields: ["n": n], now: t0.addingTimeInterval(Double(n))) }
        journal.record(source: "ne", event: "stall_bump", now: t0.addingTimeInterval(51))
        journal.record(source: "ne", event: "path_change", now: t0.addingTimeInterval(52))
        journal.record(source: "ne", event: "path_change", now: t0.addingTimeInterval(200)) // outside the window
        let flaps = journal.read("TribeNELifecycle.json")["entries"] as! [[String: Any]]
        precondition(flaps.map { $0["event"] as! String } == ["start", "path_change", "stall_bump", "path_change", "path_change"], "\(flaps.map { $0["event"]! })")
        precondition(flaps[1]["repeat"] as? Int == 50, "repeat count \(String(describing: flaps[1]["repeat"]))")
        precondition(flaps[1]["first_utc_ms"] as? Int64 == 1_800_000_000_000, "first timestamp kept")
        precondition((flaps[1]["fields"] as? [String: Any])?["n"] as? Int == 49, "latest fields kept")
        precondition(flaps[3]["repeat"] == nil && flaps[4]["repeat"] == nil, "no merge across another event or the window")
        journal.record(source: "ne", event: "stall_denied", now: t0.addingTimeInterval(300))
        journal.record(source: "ne", event: "stall_denied", now: t0.addingTimeInterval(301))
        precondition((journal.read("TribeNELifecycle.json")["entries"] as! [[String: Any]]).count == 7, "only path_change is merged")

        // D8: honest labels for adapter log lines (only fixed labels are ever persisted).
        let labels: [(String, String?)] = [
            ("rebindListenPort: socket rebound to a new ephemeral port, keepalive sent", "gui_rebind"),
            ("rebindListenPort: denied by recovery budget (rolling_cap)", "gui_rebind_denied"),
            ("rebindListenPort: denied (path unsatisfied)", "gui_rebind_denied"),
            ("rebindListenPort: adapter not started (state=stopped)", "gui_rebind_not_started"),
            ("Tribe roaming: stall recovery denied by budget (step=bump reason=rolling_cap) (path_lost=0)", "stall_denied"),
            ("Tribe roaming: inbound stalled (tx=1 rx=2), bumping socket on the same port (x)", "stall_bump"),
            ("Tribe roaming: still stalled after bump, rebinding to a new local port (x)", "stall_rebind"),
            ("Tribe roaming: still offline after 30s, pausing backend (long-offline fallback).", "pause"),
            ("Tribe roaming: path lost, keeping backend alive (device, keys, endpoint and TUN untouched).", "path_change"),
            ("Tribe roaming: path restored after 900 ms, rebinding socket on the live device (x)", "path_change"),
            ("Network change detected with satisfied route", nil),
            // awg-apple tribe.8 (U6/U9): exact adapter strings from patch 0006.
            ("Tribe roaming: persistent heal step 3 (soft restart) after backoff, inbound frozen (tx=1 rx=2) (x)", "stall_persistent"),
            ("Tribe roaming: persistent heal step 1 (bump) after backoff, inbound frozen (tx=1 rx=2) (x)", "stall_persistent"),
            ("Tribe roaming: backend soft-restarted in place (same TUN, no network settings change) (x)", "soft_restart"),
            ("Tribe roaming: backend soft-restarted in place after a retry (x)", "soft_restart"),
            ("Tribe roaming: soft restart failed (startWireGuardBackend(-1)), backend left paused; retrying in place", "soft_restart_failed"),
            ("Tribe roaming: soft restart retry failed (startWireGuardBackend(-1)), 0 left", "soft_restart_failed"),
            ("softRestartBackend: performed (same TUN, no network settings change)", "gui_soft_restart"),
            ("softRestartBackend: denied by recovery budget (episode)", "gui_soft_restart_denied"),
            ("softRestartBackend: denied (backend restart failed)", "gui_soft_restart_denied"),
            ("softRestartBackend: adapter not started (state=stopped)", "gui_soft_restart_not_started"),
        ]
        for (message, expected) in labels {
            precondition(TribeNEJournal.event(forAdapterLog: message) == expected, "label for \(message)")
        }
        print("TribeSharedStateTests: supersession, conditional ack, 40 concurrent writers, ring bounds, bounded lock, path_change coalescing, journal labels passed")
    }
}

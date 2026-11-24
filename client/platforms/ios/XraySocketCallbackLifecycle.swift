import Darwin
import Foundation

// AVPN (волна AWG 3.1 + Xray, этап D3): жизненный цикл protect-колбэка ядра Xray в NE.
// Изолированный файл (Darwin/Foundation-only), покрыт хостовым тестом
// tests/XraySocketCallbackLifecycleTests.swift. Использование — PacketTunnelProvider+Xray.swift.
//
// Инварианты: (1) колбэк ставится ДО старта ядра; (2) слот колбэка держит ровно один сырой
// Swift-контекст, освобождать его можно только после LibXraySetSockCallback(nil, nil) —
// он синхронно берёт write-lock и дожидается колбэков в полёте (иначе UAF в Go-потоке);
// (3) старт/стоп нативных движков сериализованы одним gate'ом.

/// C-ABI libxray в awg-apple 3.1.4-tribe.3 (патч 0002): регистрация колбэка на успех
/// возвращает nil, Run/Stop — аллоцированную пустую C-строку. Любая непустая строка —
/// ошибка. Потребитель освобождает каждый non-nil результат ровно один раз.
enum XrayNativeCStringResult {
    static func consume(_ result: UnsafeMutablePointer<CChar>?) -> Bool {
        message(result) == nil
    }

    /// Текст ошибки ядра (nil = успех). Конвенция libxray та же, что на Android
    /// (`Xray.kt::isNotNullOrBlank`): непустая строка = отказ. Волна 2026-09-02: раньше
    /// сообщение молча освобождалось, и «Xray не стартовал» приходило на устройство без
    /// единой причины — диагностировать было нечем.
    static func message(_ result: UnsafeMutablePointer<CChar>?) -> String? {
        guard let result else { return nil }
        defer { free(result) }
        let text = String(cString: result).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }
}

/// Счётчики protect-колбэка. Колбэк зовётся из Go-потоков ядра, поэтому доступ под замком.
/// bound — сокет привязан к физическому интерфейсу; unbound — интерфейс ещё неизвестен и дозвон
/// разрешён без привязки (апстримная семантика); rejected — привязка провалилась (туннель гасим).
final class XrayProtectCounters {
    struct Snapshot: Equatable {
        let bound: Int
        let unbound: Int
        let rejected: Int
    }

    private let lock = NSLock()
    private var bound = 0
    private var unbound = 0
    private var rejected = 0

    func countBound() { lock.lock(); bound += 1; lock.unlock() }
    func countUnbound() { lock.lock(); unbound += 1; lock.unlock() }
    func countRejected() { lock.lock(); rejected += 1; lock.unlock() }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        bound = 0; unbound = 0; rejected = 0
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(bound: bound, unbound: unbound, rejected: rejected)
    }
}

struct XraySocketCallbackIdentity: Hashable {
    let generation: UInt64
    let sessionId: String

    init?(generation: UInt64, sessionId: String) {
        guard generation > 0,
              sessionId == sessionId.lowercased(),
              UUID(uuidString: sessionId)?.uuidString.lowercased() == sessionId else {
            return nil
        }
        self.generation = generation
        self.sessionId = sessionId
    }
}

/// Нативный слот колбэка владеет не более чем одним сырым Swift-контекстом. Удаление законно
/// только после того, как LibXraySetSockCallback(nil, nil) синхронно осушил нативные вызовы.
final class XraySocketCallbackRegistry<Value: AnyObject> {
    private let lock = NSLock()
    private var entry: (identity: XraySocketCallbackIdentity, value: Value)?

    func install(_ value: Value, identity: XraySocketCallbackIdentity) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard entry == nil else { return false }
        entry = (identity, value)
        return true
    }

    func value(for identity: XraySocketCallbackIdentity) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        guard entry?.identity == identity else { return nil }
        return entry?.value
    }

    @discardableResult
    func remove(identity: XraySocketCallbackIdentity) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        guard entry?.identity == identity else { return nil }
        let value = entry?.value
        entry = nil
        return value
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entry == nil ? 0 : 1
    }
}

final class XraySocketCallbackFence {
    private let lock = NSLock()
    let identity: XraySocketCallbackIdentity
    private var active = true

    init(identity: XraySocketCallbackIdentity) {
        self.identity = identity
    }

    func accepts(currentGeneration: UInt64, currentSessionId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return active && identity.generation == currentGeneration
            && identity.sessionId == currentSessionId
    }

    @discardableResult
    func deactivate(expected: XraySocketCallbackIdentity) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard active, identity == expected else { return false }
        active = false
        return true
    }
}

/// Один рекурсивный process-local gate сериализует точные нативные старт/стоп Xray. Перепроверка
/// TunnelRuntimeSession делается внутри gate'а непосредственно перед нативной мутацией, поэтому
/// стоп, уже инвалидировавший поколение, не может быть догнан поздним стартом ядра или tun2socks.
final class XrayNativeLifecycleGate {
    private let lock = NSRecursiveLock()

    func withExclusive<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

enum XraySocketCallbackTeardown {
    /// StopXray синхронно закрывает ядро, пока protect-колбэк ещё взведён. Затем очистка
    /// берёт нативный write-lock и осушает колбэки в полёте. Сырой контекст отпускается только
    /// после обеих операций — без окна незащищённого dial'а и без UAF.
    static func execute(stopCore: () -> Bool, drain: () -> Bool,
                        retireContext: () -> Bool) -> Bool {
        // Провальное/неоднозначное синхронное закрытие не даёт права чистить protect-слот:
        // ядро ещё может создавать сокеты. Колбэк и контекст остаются взведёнными — внешний
        // гард остаётся fail-closed, а поздняя попытка восстановления повторит точный teardown.
        guard stopCore() else { return false }
        let drained = drain()
        guard drained else { return false }
        return retireContext()
    }
}

// AVPN (review R43 F1, R46 R1/R2): the hev (tun2socks) part of an Xray stop.
//
// hev 2.15.0's quit (hev_socks5_tunnel_quit -> hev_socks5_tunnel_stop) loops `for (;;)` until hev's event fd exists,
// sleeping 100 ms: a stop that came before hev ran (24.11: 0.2 s into an Xray start) waited there for ever, inside the
// native gate. The non-blocking request of recipes/hev-socks5-tunnel (patches 0001 + 0002, hev_socks5_tunnel_try_quit)
// "never blocks" and, since 0002, "belongs to the run in progress and never survives it": 0 = queued to the running
// tunnel, -EAGAIN = a run is in progress but not running yet (kept for that run, taken as it runs), -ESRCH = no run in
// progress (nothing kept). Its set-and-check and the run's publish-and-take share one mutex (review R46 R2).
// The rule (R46 R1):
//  - hev not entered (no worker, or one still queued - TunnelRuntimeSession.enterHev refuses it after the generation
//    move): nothing to stop, no wait;
//  - hev entered (initialising or running): the request is driven for THAT run (its epoch, XrayHevRuns) - again every
//    retry interval, since one taken before the run reached the library is not kept - until that run has returned;
//    the stop completes only then, bounded by exitLimitSeconds (a loud log line if hev never returns);
//  - no worker enters a new run while an earlier run of the process has not returned (XrayHevRuns.enter).
// The blocking quit is never called from a stop. Everything after it (the core stop, the callback teardown) is reached
// on every path. Measured on the real library (recipes/hev-socks5-tunnel/test): a running hev returns 0.08 ms after
// the request (median of 50, max 0.10 ms), so a stop of a running tunnel waits for practically nothing more than before.
protocol XrayHevControl {
    /// hev_socks5_tunnel_try_quit (never blocks).
    func tryQuit() -> Int32
    /// hev_socks5_tunnel_quit: blocks until hev's event fd exists - never from a stop.
    func quitBlocking()
}

/// The hev runs of this process (hev is process-global): one at a time, each with its epoch.
final class XrayHevRuns {
    static let shared = XrayHevRuns()
    private let cond = NSCondition()
    private var running: UInt64 = 0 // the epoch of the run in progress, 0 = none
    private var last: UInt64 = 0

    /// The worker, right before Socks5Tunnel.run: this run's epoch once no earlier run is in progress; nil = an
    /// earlier run did not return within `waitSeconds` - this one must not run (two runs would share hev's state).
    func enter(waitSeconds: TimeInterval) -> UInt64? {
        cond.lock()
        defer { cond.unlock() }
        let deadline = Date().addingTimeInterval(waitSeconds)
        while running != 0 && cond.wait(until: deadline) {}
        guard running == 0 else { return nil }
        last = last == UInt64.max ? 1 : last + 1
        running = last
        return last
    }

    /// The worker, when Socks5Tunnel.run returned (or when it entered and then did not run).
    func exit(_ epoch: UInt64) {
        cond.lock()
        if running == epoch {
            running = 0
            cond.broadcast()
        }
        cond.unlock()
    }

    func inProgress(_ epoch: UInt64) -> Bool {
        cond.lock()
        defer { cond.unlock() }
        return epoch != 0 && running == epoch
    }

    /// Waits until run `epoch` is no longer in progress, at most until `deadline`. true = it returned.
    func waitReturn(_ epoch: UInt64, until deadline: Date) -> Bool {
        cond.lock()
        defer { cond.unlock() }
        while epoch != 0 && running == epoch && cond.wait(until: deadline) {}
        return !(epoch != 0 && running == epoch)
    }
}

enum XrayHevStop: Equatable {
    case notRunning                              // no hev of this session entered: nothing to stop, no wait
    case returned(requests: Int)                 // the run returned; how many requests it took
    case exitTimedOut(lastRc: Int32, requests: Int) // the run did not return within the limit (logged loudly)

    static let exitLimitSeconds: TimeInterval = 2
    static let retrySeconds: TimeInterval = 0.005

    /// Inside stopXray's native gate, right after TunnelRuntimeSession.beginStopReportingHev(): `run` = the epoch of
    /// the session's hev run (0 = none entered).
    static func execute(run: UInt64, runs: XrayHevRuns, hev: XrayHevControl,
                        limitSeconds: TimeInterval = exitLimitSeconds,
                        retrySeconds: TimeInterval = retrySeconds) -> XrayHevStop {
        guard run != 0 else { return .notRunning }
        let deadline = Date().addingTimeInterval(limitSeconds)
        var requests = 0
        var lastRc: Int32 = 0
        while runs.inProgress(run) {
            lastRc = hev.tryQuit()
            requests += 1
            let next = min(deadline, Date().addingTimeInterval(retrySeconds))
            if runs.waitReturn(run, until: next) { break }
            if Date() >= deadline { return .exitTimedOut(lastRc: lastRc, requests: requests) }
        }
        return .returned(requests: requests)
    }
}

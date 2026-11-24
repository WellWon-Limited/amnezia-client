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

// AVPN (review R43 F1): the hev (tun2socks) part of an Xray stop.
//
// hev 2.15.0's quit (hev_socks5_tunnel_quit -> hev_socks5_tunnel_stop) loops `for (;;)` until hev's event fd exists,
// sleeping 100 ms - it waits for a hev that was started and has initialised. A stop that came before hev ran (24.11:
// 0.2 s into an Xray start, the start still waiting for its network settings) waited there for ever, inside the native
// gate, and after the stop's generation move hev may never start: neither the start nor the stop answered (the
// session reached Disconnected 25 s later, most likely when the system gave up on the stuck extension). The recipe's
// patch 0001 (recipes/hev-socks5-tunnel) adds hev_socks5_tunnel_try_quit: "Request tunnel shutdown without waiting for
// asynchronous initialization. This function never blocks. Callers may retry while initialization is in progress.
// Returns: zero when the request was queued, -EAGAIN when the tunnel is not ready, otherwise a negative errno value."
// It first sets stop_requested, which hev_socks5_tunnel_run checks right after `run = 1` (a stop during hev's own
// initialisation is kept, hev quits as soon as it runs), and hev_socks5_tunnel_fini / a failed init clear it.
// The decision: hev not started (no worker, or one still queued - enterHev refuses it after the generation move) ->
// nothing to quit; hev entered (initialising or running) -> the non-blocking quit, once. The blocking quit is never
// called from a stop. Everything after it (the core stop, the callback teardown) is reached on every path.
protocol XrayHevControl {
    /// hev_socks5_tunnel_try_quit (never blocks).
    func tryQuit() -> Int32
    /// hev_socks5_tunnel_quit: blocks until hev's event fd exists - never from a stop.
    func quitBlocking()
}

enum XrayHevStop: Equatable {
    case notRunning       // no hev of this session to stop
    case quitQueued       // hev was running: its event loop ends now
    case quitDeferred(Int32) // hev still initialising (-EAGAIN) or another refusal: kept in stop_requested, it quits as it runs

    /// Inside stopXray's native gate, right after TunnelRuntimeSession.beginStopReportingHev().
    static func execute(hevRunning: Bool, hev: XrayHevControl) -> XrayHevStop {
        guard hevRunning else { return .notRunning }
        let rc = hev.tryQuit()
        return rc == 0 ? .quitQueued : .quitDeferred(rc)
    }
}

// AVPN (Task 8): iOS App Intents — быстрые команды Tribe для Shortcuts/«Команды».
//
// Назначение: пользователь вручную собирает ДВЕ автоматизации Shortcuts (системного триггера
// «открылось РФ-приложение» нет, поэтому привязку «приложение → действие» делает сам пользователь):
//   • открытие РФ-приложений  → «Tribe: пауза»   (туннель реально опускается, трафик покупки мимо VPN);
//   • открытие не-РФ           → «Tribe: включить» (туннель поднимается обратно).
//
// Оба интента:
//   • openAppWhenRun = false — работают из ФОНА, приложение не выводится на передний план;
//   • управляют туннелем напрямую через NETunnelProviderManager.loadAllFromPreferences()
//     → connection.startVPNTunnel() / stopVPNTunnel() (как ios_controller.mm);
//   • кладут «мост к движку» (#7, pauseForShopping/resume) в App Group UserDefaults — Qt-движок
//     (AvpnEngineQml) подхватит флаг при следующем foreground и синхронизирует своё m_paused/failover.
//     Прямой вызов C++ Q_INVOKABLE из фонового интента невозможен (Qt event loop не крутится в фоне),
//     поэтому реальный эффект (туннель вверх/вниз) делаем здесь, а движок согласует состояние позже.
//
// iOS 16+ (AppIntents framework). Регистрируется через AppShortcutsProvider.
// Проверка рантайма/сборки — только на устройстве через Xcode (см. notes).

import Foundation
import AppIntents
import NetworkExtension

// MARK: - Versioned, cancellable ownership across GUI and App Intents

@available(iOS 16.0, *)
private enum AvpnTunnelError: Error, CustomLocalizedStringResourceConvertible {
    case noManager, superseded, timeout, unavailable, ambiguousManager
    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .ambiguousManager: return "Найдено несколько профилей Tribe. Откройте приложение и подключитесь один раз."
        case .noManager: return "Туннель Tribe ещё не настроен. Откройте приложение и подключитесь один раз."
        case .superseded: return "Команда отменена более новым действием."
        case .timeout: return "iOS не завершила изменение VPN. Проверьте состояние в Tribe."
        case .unavailable: return "Не удалось сохранить состояние команды. Откройте Tribe."
        }
    }
}

private final class AvpnCompletion<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    init(_ continuation: CheckedContinuation<T, Error>) { self.continuation = continuation }
    func finish(_ result: Result<T, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

@available(iOS 16.0, *)
private struct AvpnIntentOperation {
    let store: TribeSharedState
    let generation: String
    let expires = ProcessInfo.processInfo.systemUptime + 15

    func check() throws {
        try Task.checkCancellation()
        guard store.isCurrent(generation) else { throw AvpnTunnelError.superseded }
        guard ProcessInfo.processInfo.systemUptime < expires else { throw AvpnTunnelError.timeout }
    }
    func wait<T>(_ work: (@escaping (Result<T, Error>) -> Void) -> Void) async throws -> T {
        try check()
        let value: T = try await withCheckedThrowingContinuation { continuation in
            let once = AvpnCompletion(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + max(0, expires - ProcessInfo.processInfo.systemUptime)) {
                once.finish(.failure(AvpnTunnelError.timeout))
            }
            work { once.finish($0) }
        }
        try check() // every await is a cancellation boundary, including save/load preferences
        return value
    }
}

@available(iOS 16.0, *)
@MainActor
private func avpnPerform(pause: Bool) async throws {
    guard let store = TribeSharedState.appGroup else { throw AvpnTunnelError.unavailable }
    let generation = try store.begin(action: pause ? "pause" : "resume")
    let operation = AvpnIntentOperation(store: store, generation: generation)
    do {
        let managers: [NETunnelProviderManager] = try await operation.wait { finish in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error = error { finish(.failure(error)) }
                else { finish(.success(managers ?? [])) }
            }
        }
        let appID = (Bundle.main.bundleIdentifier ?? "hk.wellwon.vpn.AppIntentsExtension")
            .replacingOccurrences(of: ".AppIntentsExtension", with: "")
        let own = managers.filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == appID + ".network-extension"
        }
        func rank(_ manager: NETunnelProviderManager) -> Int {
            switch manager.connection.status {
            case .connected, .reasserting: return 3
            case .connecting: return 2
            case .disconnecting: return 1
            default: return 0
            }
        }
        guard let manager = own.max(by: { rank($0) < rank($1) }) else { throw AvpnTunnelError.noManager }
        guard own.filter({ rank($0) == rank(manager) }).count == 1 else { throw AvpnTunnelError.ambiguousManager }
        let _: Void = try await operation.wait { finish in
            manager.loadFromPreferences { error in finish(error.map { .failure($0) } ?? .success(())) }
        }
        let wasActive = manager.connection.status == .connected || manager.connection.status == .connecting || manager.connection.status == .reasserting
        guard try store.update(generation, fields: ["was_active": wasActive]) else { throw AvpnTunnelError.superseded }
        if !pause && !manager.isEnabled {
            manager.isEnabled = true
            let _: Void = try await operation.wait { finish in
                manager.saveToPreferences { error in finish(error.map { .failure($0) } ?? .success(())) }
            }
            let _: Void = try await operation.wait { finish in
                manager.loadFromPreferences { error in finish(error.map { .failure($0) } ?? .success(())) }
            }
        }
        if !pause {
            // A previous stop must actually reach terminal; .reasserting is an active session.
            while manager.connection.status == .disconnecting {
                try await Task.sleep(nanoseconds: 100_000_000)
                try operation.check()
            }
        }
        try store.locked {
            try operation.check()
            if pause { manager.connection.stopVPNTunnel() }
            else if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                try manager.connection.startVPNTunnel()
            }
        }
        if pause {
            while manager.connection.status != .disconnected && manager.connection.status != .invalid {
                try await Task.sleep(nanoseconds: 100_000_000)
                try operation.check()
            }
        }
        guard try store.update(generation, fields: ["applied": true]) else { throw AvpnTunnelError.superseded }
        store.record(source: "intent", event: pause ? "pause_applied" : "resume_applied", fields: ["generation": generation, "was_active": wasActive])
    } catch {
        // A failed command is not replayed as a successful GUI action. Its generation still
        // cancels older starts, and a requested OFF remains fail-closed until a newer action.
        _ = try? store.update(generation, fields: ["applied": false, "failed": true])
        store.record(source: "intent", event: "action_failed", fields: ["generation": generation])
        throw error
    }
}

// MARK: - Intent: Tribe — включить

@available(iOS 16.0, *)
struct TribeEnableIntent: AppIntent {
    // AVPN: «VPN» в заголовке — иначе поиск в «Командах» по слову «VPN» не находит (ищет по title).
    static var title: LocalizedStringResource = "Tribe VPN: включить"
    static var description = IntentDescription(
        "Поднимает VPN-туннель Tribe (для выхода из паузы «для покупок» или ручного включения)."
    )

    /// Работаем из фона — приложение не выводим на передний план.
    static var openAppWhenRun: Bool = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        // Сообщаем движку (#7): запрошен resume — он снимет m_paused/перезапустит failover при foreground.
        try await avpnPerform(pause: false)
        return .result(dialog: "Tribe включён")
    }
}

// MARK: - Intent: Tribe — пауза (для покупок, #7)

@available(iOS 16.0, *)
struct TribePauseIntent: AppIntent {
    // AVPN: «VPN» в заголовке для поиска в «Командах» (см. TribeEnableIntent).
    static var title: LocalizedStringResource = "Tribe VPN: пауза"
    static var description = IntentDescription(
        "Ставит Tribe на паузу «для покупок»: туннель реально опускается, трафик идёт мимо VPN."
    )

    static var openAppWhenRun: Bool = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        // Мост к движку pauseForShopping (#7): движок при foreground выставит m_paused и погасит failover,
        // чтобы прилетевший Disconnected не переподнял ноду. Реальный эффект (туннель вниз) — сразу здесь.
        try await avpnPerform(pause: true)
        return .result(dialog: "Tribe на паузе для покупок")
    }
}

// MARK: - App Shortcuts registration

@available(iOS 16.0, *)
struct AvpnAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: TribeEnableIntent(),
            // AVPN: Apple требует \(.applicationName) в КАЖДОЙ фразе (Xcode 26.5 — halting error
            // "Invalid Utterance"). Бесток-фраза "Tribe включить" убрана (applicationName = "Tribe VPN").
            phrases: [
                "Включить \(.applicationName)",
                "\(.applicationName) включить"
            ],
            shortTitle: "Tribe VPN: включить",
            // AVPN: фирменный SF-символ под наш бренд-щит (filled — солиднее тонкого дефолта).
            // App Intents даёт только SF-символы (своё лого на плитку нельзя — by design), см. ресёрч.
            systemImageName: "lock.shield.fill"
        )
        AppShortcut(
            intent: TribePauseIntent(),
            // AVPN: каждая фраза должна содержать \(.applicationName) (см. выше). Убрана "Tribe пауза…".
            phrases: [
                "Пауза \(.applicationName)",
                "\(.applicationName) пауза"
            ],
            shortTitle: "Tribe VPN: пауза",
            // AVPN: filled-вариант в тон «включить» (единый стиль пары команд).
            systemImageName: "pause.circle.fill"
        )
    }
}

// MARK: - ExtensionKit entry point (точка входа appex)

// AVPN: явная @main-точка входа App Intents Extension. Генерирует секцию __swift5_entry, которую
// требует валидатор Apple («The __swift5_entry section is missing… prevents the extension from
// running»). Xcode-шаблон вставляет её неявно; CMake-сборка — нет, поэтому объявляем сами.
// Протокол AppIntentsExtension (refines ExtensionFoundation.AppExtension) предоставляет @main по
// умолчанию; тело пустое — интенты и AppShortcutsProvider фреймворк находит по извлечённым
// метаданным (Metadata.appintents). Компилируется ТОЛЬКО в extension-таргете (target iOS 16+).
@available(iOS 16.0, *)
@main
struct TribeAppIntentsEntryPoint: AppIntentsExtension {
}

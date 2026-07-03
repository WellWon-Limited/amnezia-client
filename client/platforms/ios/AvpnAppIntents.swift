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

// MARK: - App Group bridge (#7)

/// Общий контейнер с приложением и network-extension. Совпадает с Log.swift / main.entitlements.
private let kAvpnAppGroupID = "group.hk.wellwon.tribe"

/// Ключи, которые читает Qt-движок (AvpnEngineQml) при следующем выходе в foreground, чтобы
/// синхронизировать своё состояние паузы с тем, что интент уже сделал с туннелем.
private enum AvpnIntentBridgeKey {
    /// bool: интент попросил паузу «для покупок». Движок вызовет pauseForShopping/учтёт m_paused.
    static let pauseRequested = "AvpnIntent/pauseRequested"
    /// bool: интент попросил включить туннель обратно (resume).
    static let resumeRequested = "AvpnIntent/resumeRequested"
    /// Double (timeIntervalSince1970): когда интент последний раз сработал — для дедупликации/дебага.
    static let lastActionAt = "AvpnIntent/lastActionAt"
}

private func avpnSharedDefaults() -> UserDefaults? {
    UserDefaults(suiteName: kAvpnAppGroupID)
}

/// Записывает «намерение» интента в App Group, чтобы движок согласовал состояние при foreground.
private func avpnPostBridge(pause: Bool) {
    guard let defaults = avpnSharedDefaults() else { return }
    defaults.set(pause, forKey: AvpnIntentBridgeKey.pauseRequested)
    defaults.set(!pause, forKey: AvpnIntentBridgeKey.resumeRequested)
    defaults.set(Date().timeIntervalSince1970, forKey: AvpnIntentBridgeKey.lastActionAt)
}

// MARK: - Tunnel control (фон, без UI)

@available(iOS 16.0, *)
private enum AvpnTunnelError: Error, CustomLocalizedStringResourceConvertible {
    case noManager

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .noManager:
            return "Туннель Tribe ещё не настроен. Откройте приложение и подключитесь один раз."
        }
    }
}

/// Берём первый сконфигурированный туннель Tribe из системных префов.
/// В этом приложении один NETunnelProviderManager (packet-tunnel-provider), как в ios_controller.mm.
@available(iOS 16.0, *)
private func avpnLoadManager() async throws -> NETunnelProviderManager {
    let managers = try await NETunnelProviderManager.loadAllFromPreferences()
    guard let manager = managers.first else {
        throw AvpnTunnelError.noManager
    }
    return manager
}

/// Поднять туннель из фона. Грузим префы (иначе connection может быть stale) → startVPNTunnel().
@available(iOS 16.0, *)
private func avpnStartTunnel() async throws {
    let manager = try await avpnLoadManager()
    // loadAllFromPreferences уже даёт «загруженный» объект, но повторный load гарантирует свежий
    // connection после внешних изменений (как делает ios_controller перед startTunnel).
    try await manager.loadFromPreferences()
    if !manager.isEnabled {
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
    }
    guard let session = manager.connection as? NETunnelProviderSession else { return }
    // Не дёргаем повторно, если уже поднят/поднимается — startVPNTunnel в этом случае кинул бы ошибку.
    if session.status != .connected && session.status != .connecting {
        try session.startVPNTunnel()
    }
}

/// Опустить туннель из фона (пауза «для покупок»). stopVPNTunnel() — мягкая остановка сессии.
@available(iOS 16.0, *)
private func avpnStopTunnel() async throws {
    let manager = try await avpnLoadManager()
    try await manager.loadFromPreferences()
    manager.connection.stopVPNTunnel()
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
        avpnPostBridge(pause: false)
        try await avpnStartTunnel()
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
        avpnPostBridge(pause: true)
        try await avpnStopTunnel()
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

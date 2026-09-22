#pragma once
// AVPN (фикс-волна 2026-09-22, зона CL-C): чистая логика iOS-натива без NetworkExtension/Qt —
// чтобы решения IosController/AvpnIntentController проверялись юнит-тестами на macOS
// (client/platforms/ios/tests/IosNativePolicyTests.cpp). ObjC-слой только собирает входы и
// исполняет решение.
#include <cerrno>
#include <cstdint>
#include <deque>
#include <string>
#include <sys/file.h>
#include <unistd.h>

namespace avpn_ios {

// ---------------------------------------------------------------------------------------------
// Тайминги натива. Значения по умолчанию — боевые; тестовый харнесс может их сжать.
struct NativeTimings {
    int reconcileDeadlineMs = 3000;      // ответ loadAllFromPreferences (реконсил/поиск для стопа)
    int retryBaseMs = 1000;              // повтор после «нет наблюдения»: base, 2*base, 4*base
    int retryMaxAttempts = 3;            // затем честное «статус неизвестен», без синтетического Error
    int connectDeadlineMs = 10000;       // дедлайн фазы load/save/start существующего профиля
    int permissionPromptCapMs = 120000;  // потолок ожидания системного диалога «Разрешить VPN»
    int rebindReplyDeadlineMs = 3000;    // K4: нет ответа NE на rebind за 3 с = rebindFinished(false)
    int statusDeadlineMs = 3000;         // владение заявкой status (IosStatusRequest)
};
inline NativeTimings &nativeTimings()
{
    static NativeTimings timings;
    return timings;
}

// Задержка повтора №attempt (0-based) или -1, если бюджет повторов исчерпан.
inline int retryDelayMs(int attempt)
{
    const NativeTimings &t = nativeTimings();
    if (attempt < 0 || attempt >= t.retryMaxAttempts) return -1;
    return t.retryBaseMs << attempt;
}

// ---------------------------------------------------------------------------------------------
// K2: причина и «намеренность» перехода в Disconnected.
struct NeStopRecord {
    bool present = false;
    std::string generation;               // runtime-поколение NE-запуска
    std::string configurationGeneration;  // поколение конфигурации (prefs) этого запуска
    int reason = 0;                       // NEProviderStopReason
    bool intentional = false;
    long long utcMs = 0;
};

struct DisconnectInputs {
    bool localStopRequested = false;      // стоп запросило приложение (disconnectVpn / 3 таймаута)
    bool appStoppedGeneration = false;    // поколение сессии в множестве «погашено приложением»
    std::string sessionGeneration;        // m_sessionMetadata.generation
    std::string sessionConfigurationGeneration; // m_sessionMetadata.configuration_generation
    std::string intentAction;             // TribeIntentState.action
    std::string intentGeneration;         // TribeIntentState.generation
    bool haveLiveBaseline = false;        // видели живую фазу этой сессии
    std::string intentGenerationAtLive;   // поколение intent в момент, когда сессию увидели живой
    long long liveSinceMs = 0;            // UTC мс первого живого наблюдения этой сессии (0 — не видели)
    NeStopRecord neStop;
    long long nowMs = 0;
};

struct DisconnectDecision {
    std::string reason;
    bool intentional = false;
};

// Запись NE о стопе относится к этой сессии.
//   * runtime-поколение сессии известно (m_sessionMetadata из status-ответа NE, у неё есть
//     configuration_generation) — ТОЛЬКО точное совпадение runtime-поколения. Ревью CL-C REV-1:
//     фолбэк по поколению конфигурации приписывал новой сессии свежую запись ПРОШЛОГО запуска того
//     же профиля (пауза Shortcut → resume ≤2 мин → NE убит jetsam без своей записи → «ne_stop_1
//     intentional» → фасад снимал намерение: «VPN сам выключается»);
//   * известно только поколение конфигурации (статус-ответа ещё не было) — свежая (≤120 с) запись
//     той же конфигурации, НЕ старше первого живого наблюдения этой сессии (если оно было).
inline bool neStopMatchesSession(const DisconnectInputs &in)
{
    const NeStopRecord &s = in.neStop;
    if (!s.present) return false;
    const bool runtimeKnown = !in.sessionConfigurationGeneration.empty();
    if (runtimeKnown) return !in.sessionGeneration.empty() && s.generation == in.sessionGeneration;
    if (!in.sessionGeneration.empty() && s.generation == in.sessionGeneration) return true;
    const bool fresh = s.utcMs > 0 && in.nowMs > 0 && in.nowMs - s.utcMs <= 120000 && in.nowMs >= s.utcMs;
    if (!fresh || s.configurationGeneration.empty() || s.configurationGeneration == "legacy") return false;
    if (in.liveSinceMs > 0 && s.utcMs < in.liveSinceMs) return false; // запись раньше живой фазы — прошлый запуск
    return s.configurationGeneration == in.sessionGeneration;
}

inline DisconnectDecision decideDisconnect(const DisconnectInputs &in)
{
    // 1. Стоп запросило само приложение для этого поколения: это не решение пользователя.
    //    NE-овский TribeLastStop игнорируем — .userInitiated приходит и на stopVPNTunnel самого
    //    приложения (иначе наш собственный стоп снимал бы намерение в фасаде).
    if (in.localStopRequested || in.appStoppedGeneration)
        return {"expected_app_stop", false};
    // 2. Намерение «off/pause» — только если оно НОВЕЕ живой фазы сессии. Запись "off", оставшаяся
    //    с прошлого выключения в приложении, при туннеле, поднятом потом из Настроек/Shortcuts,
    //    — «липкая»: её внешний обрыв не является решением пользователя.
    const bool intentOff = in.intentAction == "off" || in.intentAction == "pause";
    if (intentOff && (!in.haveLiveBaseline || in.intentGeneration != in.intentGenerationAtLive))
        return {"user_intent", true};
    // 3. NE записал причину стопа этой сессии (Настройки iOS, другой VPN, сбой провайдера).
    if (neStopMatchesSession(in))
        return {"ne_stop_" + std::to_string(in.neStop.reason), in.neStop.intentional};
    return {"unknown_external", false};
}

// Не более одного disconnectReason на переход в Disconnected (K2) + множество поколений,
// которые погасило приложение (ограничено, чтобы не расти бесконечно).
class DisconnectReasonGate {
public:
    // Сессия наблюдалась НЕ в Disconnected — следующий Disconnected будет новым переходом.
    void noteNotDisconnected() { m_reported = false; }
    // Новый старт туннеля (startVPNTunnel вызван успешно) — тоже новый переход впереди.
    void noteStartIssued() { m_reported = false; }
    // true — причину для текущего перехода ещё не сообщали; помечает сообщённой.
    bool claimReport()
    {
        if (m_reported) return false;
        m_reported = true;
        return true;
    }
    bool reported() const { return m_reported; }

    void noteAppStop(const std::string &generation)
    {
        if (generation.empty() || isAppStopped(generation)) return;
        m_appStopped.push_back(generation);
        while (m_appStopped.size() > 16) m_appStopped.pop_front();
    }
    bool isAppStopped(const std::string &generation) const
    {
        if (generation.empty()) return false;
        for (const std::string &g : m_appStopped)
            if (g == generation) return true;
        return false;
    }

    // Базовая линия intent для «липкости»: фиксируется один раз на живую фазу сессии.
    // nowMs — UTC мс наблюдения (та же шкала, что utc_ms записи NE): запись о стопе старше живой
    // фазы сессии принадлежит прошлому запуску (REV-1).
    void noteLive(const std::string &intentGeneration, long long nowMs = 0)
    {
        if (m_haveLive) return;
        m_haveLive = true;
        m_intentAtLive = intentGeneration;
        m_liveSinceMs = nowMs;
    }
    void clearLive()
    {
        m_haveLive = false;
        m_intentAtLive.clear();
        m_liveSinceMs = 0;
    }
    bool haveLive() const { return m_haveLive; }
    const std::string &intentAtLive() const { return m_intentAtLive; }
    long long liveSinceMs() const { return m_liveSinceMs; }

private:
    bool m_reported = false;
    bool m_haveLive = false;
    std::string m_intentAtLive;
    long long m_liveSinceMs = 0;
    std::deque<std::string> m_appStopped;
};

// ---------------------------------------------------------------------------------------------
// K3 (ревью REV-2): что делать connectVpn, застав СВОЙ существующий профиль.
//   Down (Disconnected/Invalid) — обычный старт;
//   Starting/Live (Connecting/Connected/Reasserting) — живая сессия: liveSessionFound + адопт;
//   TearingDown (Disconnecting) — профиль гасится (стоп из Настроек/Shortcut или хвост нашего
//   стопа). Это НЕ живая сессия: liveSessionFound заставил бы фасад ждать Connected, а пришёл бы
//   Disconnected → «внешний обрыв», нажатие Connect молча терялось. Ждём реальный Disconnected
//   (в пределах дедлайна коннекта) и продолжаем обычный старт.
enum class SessionPhase { Down, Starting, Live, TearingDown };
enum class ConnectOverExisting { StartNew, AdoptLive, AwaitTeardown };
inline ConnectOverExisting decideConnectOverExisting(SessionPhase phase)
{
    switch (phase) {
    case SessionPhase::Down: return ConnectOverExisting::StartNew;
    case SessionPhase::TearingDown: return ConnectOverExisting::AwaitTeardown;
    case SessionPhase::Starting:
    case SessionPhase::Live: return ConnectOverExisting::AdoptLive;
    }
    return ConnectOverExisting::StartNew;
}

// ---------------------------------------------------------------------------------------------
// K2 (ревью REV-3): флаг «стоп запросило приложение» (m_localStopRequested) принадлежит ОДНОЙ
// сессии. Снимается наблюдением её Disconnected; но если GUI был в фоне и этот Disconnected
// пропустил, а следующую сессию подняли Настройками, флаг доживал до её обрыва и пользовательский
// стоп из Настроек приходил как expected_app_stop (intentional=false). Доказательство новой сессии:
//   * runtime-поколение наблюдаемой сессии известно, не в множестве «погашено приложением» и
//     отличается от runtime-поколения погашенной (если его знали);
//   * либо фаза Connecting после того, как гасили живую (Connected/Reasserting) сессию: погашенная
//     сессия идёт только Disconnecting → Disconnected, Connecting — это уже новый старт.
// Поколение уровня конфигурации (из prefs) у новой сессии Настроек то же, что у погашенной, —
// по нему «новизну» не решаем (иначе флаг снимался бы ещё до того, как стоп дошёл).
struct LocalStopInfo {
    std::string generation;           // m_sessionMetadata.generation на момент стопа
    bool generationIsRuntime = false; // метаданные были runtime-уровня (из status-ответа NE)
    bool stoppedLiveSession = false;  // гасили Connected/Reasserting (не Connecting/неизвестно)
};
inline bool localStopSupersededByNewSession(const LocalStopInfo &stop, bool observedConnecting,
                                            const std::string &sessionGeneration,
                                            bool sessionGenerationIsRuntime, bool sessionGenerationAppStopped)
{
    if (sessionGenerationIsRuntime && !sessionGeneration.empty()) {
        if (sessionGenerationAppStopped) return false;
        if (stop.generationIsRuntime && !stop.generation.empty() && sessionGeneration != stop.generation)
            return true;
    }
    return observedConnecting && stop.stoppedLiveSession;
}

// ---------------------------------------------------------------------------------------------
// K4: ответ NE на {"action":"rebind"}.
//   {"rebind":"performed"} → true; {"rebind":"denied","reason":...} → false.
//   Совместимость со старым NE того же бандла: {"ok":Bool} без ключа rebind.
inline bool rebindPerformed(bool hasResponse, bool hasRebindKey, const std::string &rebind,
                            bool hasLegacyOk, bool legacyOk)
{
    if (!hasResponse) return false;
    if (hasRebindKey) return rebind == "performed";
    return hasLegacyOk && legacyOk;
}

// ---------------------------------------------------------------------------------------------
// C8: какие события lifecycle-журнала схлопываются, если идут подряд (счётчик повторов вместо
// новых записей — иначе status_timeout вымывает 128-записное кольцо за пару минут роуминга).
inline bool lifecycleCollapsible(const std::string &previousEvent, const std::string &event)
{
    return previousEvent == event && event == "status_timeout";
}

// ---------------------------------------------------------------------------------------------
// C6/H10: flock без бесконечного ожидания. LOCK_NB с ограниченными повторами (по умолчанию
// 20×5 мс ≈ 100 мс). true — лок взят; false — занят (или ошибка), вызывающий решает сам,
// главный поток не блокируется на suspend-нутом NE, держащем лок.
inline bool tryLockExclusive(int fd, int attempts = 20, useconds_t sleepMicros = 5000)
{
    if (fd < 0) return false;
    for (int i = 0; i < attempts; ++i) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return true;
        if (errno != EWOULDBLOCK && errno != EINTR) return false;
        if (i + 1 < attempts) usleep(sleepMicros);
    }
    return false;
}

} // namespace avpn_ios

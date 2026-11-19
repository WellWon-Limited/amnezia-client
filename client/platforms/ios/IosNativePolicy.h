#pragma once
// AVPN (фикс-волна 2026-09-22, зона CL-C): чистая логика iOS-натива без NetworkExtension/Qt —
// чтобы решения IosController/AvpnIntentController проверялись юнит-тестами на macOS
// (client/platforms/ios/tests/IosNativePolicyTests.cpp). ObjC-слой только собирает входы и
// исполняет решение.
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>
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

// Холодный старт (разбор журнала 25.09): iOS выгрузила приложение, туннель жил; при запуске
// Connected ждал ответа NE на status (~1–1.5 с), и UI мигал «выключено → подключаемся → подключено».
// Сессию, которую iOS держит Connected не меньше kEstablishedSessionMs, увиденную живой впервые
// (прошлое эмитированное состояние — не живое) и не во время нашего подъёма, показываем Connected
// сразу; проверка рукопожатия (m_handshakeAwaiting и её таймауты) идёт как раньше, в фоне.
// connectedForMs < 0 — время подключения неизвестно: по-старому ждём подтверждения.
inline constexpr long long kEstablishedSessionMs = 15000;
inline bool showEstablishedAsConnected(bool connectPending, bool previouslyLive, long long connectedForMs)
{
    return !connectPending && !previouslyLive && connectedForMs >= kEstablishedSessionMs;
}

// Floor of "tap -> data" (19.11.2026): AmneziaWG is Connected only when the status poll sees the handshake
// (last_handshake_time_sec > 0 or rx above the threshold), and the extension cannot tell the app about a handshake
// (the Go engine has no handshake event; the NE's own Connected comes before it). With the 1 s poll of upstream
// Amnezia (VpnConnection::m_checkTimer) the app saw the handshake up to 1 s late - 0.3-0.65 s on Wi-Fi, up to
// 1.45 s on LTE in the iPhone Air logs of 18-19.11. So the existing poll runs at kStartStatusPollMs while a start is
// in flight (the observed state is Connecting: before the NE's Connected a tick reads the NE status and sends
// nothing; after it, one status message per tick - one in flight at most, IosStatusRequest) and at the normal
// cadence in every other state (Connected, Reconnecting, Disconnected). The fast window ends with the handshake,
// with the attempt owner's leg deadline (AmneziaWG 4.5 s) or with the handshake budget (Reconnecting). Each status
// message is one IPC to the extension: a wg UAPI read, the roaming counters and a small JSON reply.
inline constexpr int kStartStatusPollMs = 125;
inline int statusPollIntervalMs(bool startInFlight, int normalMs)
{
    return (startInFlight && normalMs > kStartStatusPollMs) ? kStartStatusPollMs : normalMs;
}

// Owner test 06.11 (device 36, build 135): the app was relaunched while the NE held a session that
// had NEVER completed a handshake (node unreachable from that Wi-Fi: tx=1493 rx=0 for ~2 min). iOS
// reported it Connected, the cold-start rule above showed it Connected, the app adopted it - and every
// API call and all the phone's traffic went into a dead tunnel ("nothing works"). A session that is
// not our start (adopted) used to stay Reconnecting forever after the handshake budget (wave-3: do not
// switch off a live session on a false handshake timeout). Here the NE has ANSWERED the status (stats
// present) and says the session never completed a handshake (last_handshake_time_sec == 0) and no data
// came back (rx below the handshake threshold): that is not a false timeout - the tunnel never worked.
// Such an adopted session is stopped as the app's own stop (expected_app_stop) once the budget is out.
// Only a session the cold-start rule showed Connected before any handshake check (adopted): our own
// start of this process stays with the facade's start watchdog and ladder (wave-3).
// Review of 136: also only when the same status reply shows the session was never revived - awg-apple
// tribe.11 soft restart (wgTurnOff/On after ~225 s stall) recreates the engine and resets handshake/rx
// to 0 inside a session that worked before (roam.soft_restarts > 0 / roam.resumes > 0; counters absent
// = unknown = keep) - and while the device has a network path (a session On-Demand raised while offline
// never handshook because there was no network).
struct DeadAdoptedSession {
    bool shownConnectedBeforeHandshake = false;
    bool connectPending = false;
    bool statsAnswered = false;               // the NE answered the status with handshake data
    long long lastHandshakeSec = -1;          // last_handshake_time_sec (0 = never)
    unsigned long long rxBytes = 0;
    unsigned long long rxThreshold = 0;
    long long softRestarts = -1;              // roam.soft_restarts of the same reply, -1 = absent
    long long resumes = -1;                   // roam.resumes of the same reply, -1 = absent
    bool uplinkUp = false;                    // a physical network path exists (unknown = false)
};
inline bool stopNeverConnectedAdoptedSession(const DeadAdoptedSession &s)
{
    return s.shownConnectedBeforeHandshake && !s.connectPending && s.statsAnswered && s.lastHandshakeSec == 0
        && s.rxBytes < s.rxThreshold && s.softRestarts == 0 && s.resumes == 0 && s.uplinkUp;
}

// 5.1.109 (device check IOS-UP35): why the rule above did not fire - the first unmet condition, in
// the rule's order; "" when it fires. Journal only: the decision stays stopNeverConnectedAdoptedSession.
inline const char *deadAdoptedSessionBlocker(const DeadAdoptedSession &s)
{
    if (!s.shownConnectedBeforeHandshake) return "not_adopted";
    if (s.connectPending) return "connect_pending";
    if (!s.statsAnswered) return "no_answer";
    if (s.lastHandshakeSec != 0) return "had_handshake";
    if (s.rxBytes >= s.rxThreshold) return "rx_above_threshold";
    if (s.softRestarts < 0 || s.resumes < 0) return "no_roam_counters";
    if (s.softRestarts != 0) return "soft_restarted";
    if (s.resumes != 0) return "resumed";
    if (!s.uplinkUp) return "no_physical_uplink";
    return "";
}

// One journal line with every input of the decision (ios_controller.mm logs it where the rule is
// evaluated). physical_up = UplinkMonitor::physicalUp() through setUplinkProbe.
inline std::string describeDeadAdoptedSession(const DeadAdoptedSession &s)
{
    const char *why = deadAdoptedSessionBlocker(s);
    std::string line = "adopted_dead_check stop=";
    line += stopNeverConnectedAdoptedSession(s) ? "1" : "0";
    line += " why=";
    line += *why ? why : "-";
    line += " shown=" + std::to_string(s.shownConnectedBeforeHandshake ? 1 : 0);
    line += " pending=" + std::to_string(s.connectPending ? 1 : 0);
    line += " answered=" + std::to_string(s.statsAnswered ? 1 : 0);
    line += " hs=" + std::to_string(s.lastHandshakeSec);
    line += " rx=" + std::to_string(s.rxBytes);
    line += " rx_threshold=" + std::to_string(s.rxThreshold);
    line += " soft_restarts=" + std::to_string(s.softRestarts);
    line += " resumes=" + std::to_string(s.resumes);
    line += " physical_up=" + std::to_string(s.uplinkUp ? 1 : 0);
    return line;
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
    // Стоп приложения отменён до stopTunnel (новый Connect адоптировал сессию, пока снималось
    // правило On-Demand): её будущий внешний обрыв — не «наш стоп».
    void forgetAppStop(const std::string &generation)
    {
        for (auto it = m_appStopped.begin(); it != m_appStopped.end(); ++it)
            if (*it == generation) { m_appStopped.erase(it); return; }
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
// On-Demand (2026-09-30, план docs/plans/2026-09-30-ios-internal-error-stop-plan.md). iOS сама
// останавливает туннель с причиной internalError (17): jetsam убивает системный nesessionmanager.
// Приложение в этот момент приостановлено и поднять туннель не может; поднять его может только
// сама iOS по правилу On-Demand. Правило — это сохранённое в системе намерение «VPN включён»:
//   * взводим ТОЛЬКО для сессии с подтверждённым рукопожатием (иначе iOS бесконечно поднимала бы
//     туннель к мёртвой ноде, а приложение в фоне его не переключит);
//   * снимаем ПЕРЕД любым стопом приложения и ждём сохранения — иначе iOS тут же поднимет туннель
//     заново (документация NEVPNConnection.stopVPNTunnel);
//   * стоп при уже опущенном туннеле тоже снимает правило (пользователь нажал «выключить», пока
//     iOS собиралась поднять туннель сама).
// Так же делают Mullvad и WireGuard для iOS; у апстрима Amnezia правила нет.
// Попытку взвода начинаем всегда со свежей загрузки профиля: экземпляр менеджера в памяти мог быть
// загружен до того, как дошло наше же снятие правила, и его onDemandEnabled верить нельзя.
// Xray-путь не взводим: его расширение само гасит туннель при отказе ядра, iOS поднимала бы заново.
inline bool shouldStartOnDemandArm(bool haveTunnel, bool sessionConnected, bool wireGuardBased,
                                   bool localStopRequested, bool changePending)
{
    return haveTunnel && sessionConnected && wireGuardBased && !localStopRequested && !changePending;
}

// Решение по СВЕЖЕЙ загрузке. intentOff — в общем состоянии намерение «выкл/пауза» (приложение или
// команда из другого процесса): взводить нельзя. disarmInFlight — наше снятие ещё не дошло до
// системы: свежая загрузка покажет старое YES; взвод повторит завершение снятия.
enum class OnDemandArm { Arm, AlreadyArmed, Skip };
inline OnDemandArm decideOnDemandArm(bool loadFailed, bool operationStillCurrent, bool sessionConnected,
                                     bool localStopRequested, bool intentOff, bool disarmInFlight,
                                     bool freshSaysEnabled)
{
    if (loadFailed || !operationStillCurrent || !sessionConnected || localStopRequested || intentOff
        || disarmInFlight)
        return OnDemandArm::Skip;
    return freshSaysEnabled ? OnDemandArm::AlreadyArmed : OnDemandArm::Arm;
}

// Пока сохранялся взвод, пришла пауза/выключение (команда читает профиль до нашего сохранения и
// правила не видит): правило снять сразу, поднятую по нему сессию погасить.
inline bool armNeedsCleanup(bool saveFailed, bool intentOff)
{
    return !saveFailed && intentOff;
}

// Стоп идёт через загрузку/сохранение профиля, если правило МОЖЕТ быть взведено: так говорит
// экземпляр, так помнит процесс, взвод в полёте — или в профиле вообще есть правила (взвести мог
// другой процесс: команда «включить», переключатель в Настройках iOS). Правил нет и не было —
// stopTunnel сразу, как до On-Demand.
inline bool stopNeedsOnDemandDisarm(bool managerSaysEnabled, bool profileHasRules, bool armedByThisProcess,
                                    bool changePending)
{
    return managerSaysEnabled || profileHasRules || armedByThisProcess || changePending;
}

// AppStop — гасим живую сессию; AppStopWasDown — туннель уже опущен, снять правило и погасить
// только сессию, которую iOS подняла за время сохранения; IntentCleanup — правило взвелось уже
// после паузы/выключения из другого процесса: снять и погасить, НЕ помечая стоп своим (причина
// обрыва остаётся решением пользователя).
enum class OnDemandStop { AppStop, AppStopWasDown, IntentCleanup };

// После снятия правила: гасим, только если стоп всё ещё актуален (не пришла новая операция; для
// IntentCleanup — намерение всё ещё «выкл») и сессия не опущена сама.
inline bool stopAfterOnDemandDisarm(bool stopStillWanted, SessionPhase phase)
{
    return stopStillWanted && phase != SessionPhase::Down;
}

// Стоп отменён более новым Connect (сессию адоптировали), а правило мы уже сняли: вернуть его
// доказанно рабочей сессии.
inline bool rearmAfterCancelledStop(bool stopPerformed, bool handshakeConfirmed, bool sessionConnected)
{
    return !stopPerformed && handshakeConfirmed && sessionConnected;
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
// Разделение «РФ мимо туннеля» внутри расширения (CONNECT-INVARIANTS §28, awg-apple tribe.11).
// Список исключений (режим VpnAllExceptSites = 2) уходит расширению файлом в общем контейнере:
// в профиль VPN и в системные маршруты он не попадает — и то и другое держит системный демон
// nesessionmanager, который iOS убивает по памяти (причина остановки 17). Решение «напрямую или
// в туннель» принимает само расширение по адресу назначения пакета, как клиенты на xray.
// Флаг с сервера (features.ios_userspace_split, по умолчанию выключен); без списка или в других
// режимах разделения остаётся путь апстрима — маршруты.
constexpr int kSplitTunnelExceptSites = 2;
constexpr const char *kDirectSplitFileName = "direct-split.txt";
inline bool useUserspaceSplit(bool flagOn, int splitTunnelType, int siteCount)
{
    return flagOn && splitTunnelType == kSplitTunnelExceptSites && siteCount > 0;
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

// ---------------------------------------------------------------------------------------------
// AVPN upstream nodes (plan provider-pool, release A, lane L3; contract client-envelope-contract.md).
// The plain structs the engine lane fills for the iOS bridge (IosController::setUpstreamStart /
// sendUpstreamLeaseSet) and the decode of the extension's `upstream` status object (section 5).

// Whether this iOS build measures the scope "proxy": per-outbound counters of the running core
// (LibXrayTribeOutboundStats, awg-apple tribe.12 patch 0011), summed over the lease's meter_tags in the
// extension (UpstreamProxyMeter.swift). The extension still falls back to "tunnel" when the lease has
// no meter_tags or the running core reports stats_disabled (UpstreamMeterPlan.scope).
inline constexpr bool kUpstreamProxyMeterSupported = true;

// `upstream_lease` (section 1): the lease the app got from POST /v1/upstream/lease (signature, type,
// sha and sanitizer already checked by the app). expiresInMs is relative to the moment the struct is
// handed to the bridge (the extension anchors it to its own sleep-proof clock at receipt).
struct UpstreamLeaseEnvelope {
    std::string leaseId;      // [A-Za-z0-9_-]{32,64}
    std::string renewToken;   // "tlr1.<...>", secret: never logged
    std::string apiBase;      // tunnel_api_base, https, no trailing slash
    long long renewAfterS = 0;
    long long ttlS = 0;
    long long expiresInMs = 0;
    long long seq = 0;        // last value returned by the server
    long long epoch = 0;      // traffic_accounting_epoch (>= 1)
    long long revision = 0;   // upstream_revision at acquire
    std::string meterScope = "tunnel"; // "proxy" | "tunnel"
    // meter_tags of the lease answer: the only outbound tags summed for "proxy" (empty = "tunnel").
    std::vector<std::string> meterTags;
};

// One upstream start: tribeSessionMetadata fields + the lease (hasLease = false: provisional start
// from the standby pack; the lease follows by sendUpstreamLeaseSet).
struct UpstreamStartEnvelope {
    std::string nodeId;       // "up:<profile_id>" - must equal rawConfig.tribeSessionMetadata.node_id
    std::string profileId;
    std::string configSha256; // 64 hex
    bool hasLease = false;
    UpstreamLeaseEnvelope lease;
};

inline bool upstreamCharsAre(const std::string &s, bool (*ok)(unsigned char))
{
    for (unsigned char c : s)
        if (!ok(c)) return false;
    return true;
}
inline bool upstreamIdChar(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}
inline bool upstreamHexChar(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
inline bool upstreamVisibleChar(unsigned char c) { return c >= 0x21 && c <= 0x7e; }

// https://<host>[:port][/path], no user info, query or fragment, no trailing slash.
inline bool upstreamApiBaseValid(const std::string &base)
{
    static const std::string scheme = "https://";
    if (base.size() <= scheme.size() || base.compare(0, scheme.size(), scheme) != 0) return false;
    if (base.back() == '/') return false;
    if (base.find_first_of("?#@ \t\r\n") != std::string::npos) return false;
    const std::string rest = base.substr(scheme.size());
    const std::string host = rest.substr(0, rest.find_first_of(":/"));
    return !host.empty();
}

// At most 64 tags of 1..128 bytes without control characters (the extension parses the same rule).
inline bool upstreamMeterTagsValid(const std::vector<std::string> &tags)
{
    if (tags.size() > 64) return false;
    for (const std::string &t : tags) {
        if (t.empty() || t.size() > 128) return false;
        for (unsigned char c : t)
            if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

// why = the field name only (never a value).
inline bool upstreamLeaseEnvelopeValid(const UpstreamLeaseEnvelope &l, std::string &why)
{
    const long long maxInt = 9007199254740991LL;
    if (l.leaseId.size() < 32 || l.leaseId.size() > 64 || !upstreamCharsAre(l.leaseId, upstreamIdChar)) why = "lease_id";
    else if (l.renewToken.empty() || l.renewToken.size() > 1024 || !upstreamCharsAre(l.renewToken, upstreamVisibleChar)) why = "renew_token";
    else if (!upstreamApiBaseValid(l.apiBase)) why = "api_base";
    else if (l.renewAfterS < 0 || l.renewAfterS > 86400) why = "renew_after_s";
    else if (l.ttlS < 1 || l.ttlS > 86400) why = "ttl_s";
    else if (l.expiresInMs < 0 || l.expiresInMs > maxInt) why = "expires_in_ms";
    else if (l.seq < 0 || l.seq > maxInt) why = "seq";
    else if (l.epoch < 1 || l.epoch > maxInt) why = "epoch";
    else if (l.revision < 0 || l.revision > maxInt) why = "revision";
    else if (l.meterScope != "proxy" && l.meterScope != "tunnel") why = "meter_scope";
    else if (!upstreamMeterTagsValid(l.meterTags)) why = "meter_tags";
    else { why.clear(); return true; }
    return false;
}

inline bool upstreamStartEnvelopeValid(const UpstreamStartEnvelope &s, std::string &why)
{
    if (s.profileId.empty() || s.profileId.size() > 64 || !upstreamCharsAre(s.profileId, upstreamIdChar)) why = "profile_id";
    else if (s.nodeId != "up:" + s.profileId) why = "node_id";
    else if (s.configSha256.size() != 64 || !upstreamCharsAre(s.configSha256, upstreamHexChar)) why = "config_sha256";
    else if (s.hasLease) return upstreamLeaseEnvelopeValid(s.lease, why);
    else { why.clear(); return true; }
    return false;
}

// The envelope's meter scope: "proxy" only when this build can measure it and the lease names its tags
// (contract section 1: empty or missing meter_tags -> "tunnel").
inline std::string upstreamEnvelopeScope(const std::string &requested, const std::vector<std::string> &meterTags)
{
    return requested == "proxy" && kUpstreamProxyMeterSupported && !meterTags.empty() ? "proxy" : "tunnel";
}

// hev-socks5-tunnel sizes (xray_tunables, section 3; /v1/config numbers xray_hev_*): the same ranges
// as XrayTunables.swift in the extension. A non-finite value = the key's default.
inline int upstreamClampInt(double v, int def, int lo, int hi)
{
    if (!std::isfinite(v)) return def;
    if (v < lo) return lo;
    if (v > hi) return hi;
    return int(v);
}
inline int hevTcpBufferSizeFrom(double v) { return upstreamClampInt(v, 4096, 4096, 65536); }
inline int hevMaxSessionCountFrom(double v) { return upstreamClampInt(v, 1200, 128, 65535); }
inline int hevTaskStackSizeFrom(double v) { return upstreamClampInt(v, 24576, 20480, 131072); }

// The `upstream` object of a status reply / of the upstream_lease_set reply, as extracted by the
// ObjC layer (present = the reply had it). normalizeUpstreamStatus keeps only contract values:
// an unknown state reads as "none", a code outside the contract list (or on a non-terminal state)
// as "", negative byte totals as 0.
struct UpstreamStatusFields {
    bool present = false;
    std::string state = "none";
    std::string code;
    long long seq = 0;
    long long renewedMsAgo = -1;
    long long expiresInMs = 0;
    long long revision = 0;
    bool configChanged = false;
    long long appliedBytes = 0;
    long long shadowBytes = 0;
    std::string meterScope = "tunnel";
};

// The terminal codes the tunnel owner may send (contract section 5) - the same list as
// UpstreamStatusWire.h::upstreamStatusTerminalCodeKnown, incl. renew_rejected (the shared lease machine ends a
// renewing session with it after kUpstreamRenewRejectedLimit 422 answers in a row). Without it the code read as
// "" here: the app left the node with no notice and no journal code (parity test:
// core/serviceEngine/tests/build_ios_terminal_codes.sh).
inline bool upstreamTerminalCodeKnown(const std::string &c)
{
    return c == "disabled" || c == "lease_gone" || c == "not_entitled" || c == "over_quota"
           || c == "no_seat_reacquire" || c == "standby_unconfirmed" || c == "renew_rejected";
}

inline UpstreamStatusFields normalizeUpstreamStatus(UpstreamStatusFields f)
{
    if (f.state != "none" && f.state != "pending" && f.state != "active" && f.state != "terminal") f.state = "none";
    if (f.state != "terminal" || !upstreamTerminalCodeKnown(f.code)) f.code.clear();
    if (f.seq < 0) f.seq = 0;
    if (f.renewedMsAgo < -1) f.renewedMsAgo = -1;
    if (f.expiresInMs < 0) f.expiresInMs = 0;
    if (f.revision < 0) f.revision = 0;
    if (f.appliedBytes < 0) f.appliedBytes = 0;
    if (f.shadowBytes < 0) f.shadowBytes = 0;
    if (f.meterScope != "proxy") f.meterScope = "tunnel";
    return f;
}

// upstreamLeaseEvent is emitted when the reply says something the engine acts on: another state or
// code, a newer seq (a renewal landed), a newer revision (refresh /v1/subscription), config_changed.
// Status polls in between (only the ms counters moved) stay quiet.
inline bool upstreamStatusChanged(const UpstreamStatusFields &prev, const UpstreamStatusFields &next)
{
    if (!next.present) return false;
    if (!prev.present) return true;
    return prev.state != next.state || prev.code != next.code || prev.seq != next.seq
           || prev.revision != next.revision || prev.configChanged != next.configChanged
           || prev.meterScope != next.meterScope;
}

} // namespace avpn_ios

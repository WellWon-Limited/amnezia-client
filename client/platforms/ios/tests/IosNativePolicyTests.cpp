// AVPN (фикс-волна 2026-09-22, зона CL-C): юнит-тесты чистой логики iOS-натива
// (IosNativePolicy.h + accept() в IosStatusRequest.h). Сборка — run_ios_reliability_checks.sh.
#include "../IosNativePolicy.h"
#include "../IosStatusRequest.h"
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace avpn_ios;

static void testRetryBudget()
{
    assert(retryDelayMs(0) == 1000);
    assert(retryDelayMs(1) == 2000);
    assert(retryDelayMs(2) == 4000);
    assert(retryDelayMs(3) == -1); // ограниченно: затем «статус неизвестен», не бесконечная петля
    assert(retryDelayMs(-1) == -1);
}

static DisconnectInputs liveSession()
{
    DisconnectInputs in;
    in.sessionGeneration = "run-2";
    in.sessionConfigurationGeneration = "cfg-1";
    in.haveLiveBaseline = true;
    in.intentAction = "resume";
    in.intentGeneration = "i-resume";
    in.intentGenerationAtLive = "i-resume";
    in.nowMs = 1000000;
    return in;
}

static void testDisconnectDecision()
{
    // K2: собственный стоп приложения — никогда не intentional, даже если NE записал userInitiated
    // (stopVPNTunnel самого приложения тоже даёт .userInitiated) и intent стал "off" (фасад пишет его).
    DisconnectInputs in = liveSession();
    in.localStopRequested = true;
    in.intentAction = "off";
    in.intentGeneration = "i-off";
    in.neStop = {true, "run-2", "cfg-1", 1, true, 999000};
    DisconnectDecision d = decideDisconnect(in);
    assert(d.reason == "expected_app_stop" && !d.intentional);

    // То же по множеству «погашено приложением» (флаг уже снят другим путём).
    in.localStopRequested = false;
    in.appStoppedGeneration = true;
    d = decideDisconnect(in);
    assert(d.reason == "expected_app_stop" && !d.intentional);

    // «Липкий intent»: "off" записан ДО живой фазы сессии (туннель подняли из Настроек после OFF
    // в приложении). Внешний обрыв (NE: providerFailed) — не решение пользователя.
    in = liveSession();
    in.intentAction = "off";
    in.intentGeneration = "i-off-old";
    in.intentGenerationAtLive = "i-off-old";
    in.neStop = {true, "run-2", "cfg-1", 2, false, 999000};
    d = decideDisconnect(in);
    assert(d.reason == "ne_stop_2" && !d.intentional);
    in.neStop = {};
    d = decideDisconnect(in);
    assert(d.reason == "unknown_external" && !d.intentional);

    // Настоящее намерение: pause записан ПОСЛЕ живой фазы (Shortcut/App Intent) — intentional.
    in = liveSession();
    in.intentAction = "pause";
    in.intentGeneration = "i-pause-new";
    d = decideDisconnect(in);
    assert(d.reason == "user_intent" && d.intentional);

    // Без базовой линии (первое наблюдение уже Disconnected) — прежнее поведение по intent.
    in = liveSession();
    in.haveLiveBaseline = false;
    in.intentGenerationAtLive.clear();
    in.intentAction = "off";
    in.intentGeneration = "i-off";
    d = decideDisconnect(in);
    assert(d.reason == "user_intent" && d.intentional);

    // Пользователь выключил VPN в Настройках iOS: NE записал userInitiated для ЭТОЙ сессии.
    in = liveSession();
    in.neStop = {true, "run-2", "cfg-1", 1, true, 999000};
    d = decideDisconnect(in);
    assert(d.reason == "ne_stop_1" && d.intentional);

    // Запись NE чужой сессии не применяется; по configuration_generation — только свежая.
    in = liveSession();
    in.neStop = {true, "run-1", "cfg-other", 1, true, 999000};
    d = decideDisconnect(in);
    assert(d.reason == "unknown_external" && !d.intentional);
    in.sessionGeneration = "cfg-1"; // статус-ответа ещё не было: известна только конфигурация
    in.sessionConfigurationGeneration.clear();
    in.neStop = {true, "run-9", "cfg-1", 1, true, 999000};
    d = decideDisconnect(in);
    assert(d.reason == "ne_stop_1" && d.intentional);
    in.neStop.utcMs = in.nowMs - 600000; // запись 10-минутной давности — прошлый запуск той же конфигурации
    d = decideDisconnect(in);
    assert(d.reason == "unknown_external" && !d.intentional);

    // Ревью CL-C REV-1: runtime-поколение сессии известно (G2) — свежая запись ПРОШЛОГО запуска (G1)
    // той же конфигурации (C1) не приписывается ей. Сценарий: пауза Shortcut (NE пишет userInitiated),
    // resume того же профиля ≤2 мин, затем NE убит в фоне без своей записи. Прежний фолбэк по
    // configuration_generation давал ne_stop_1 intentional=1 → фасад снимал намерение.
    in = liveSession();
    in.sessionGeneration = "G2";
    in.sessionConfigurationGeneration = "C1";
    in.neStop = {true, "G1", "C1", 1, true, in.nowMs - 60000};
    d = decideDisconnect(in);
    assert(d.reason == "unknown_external" && !d.intentional);
    in.neStop.generation = "G2"; // запись этой сессии — по-прежнему применяется
    d = decideDisconnect(in);
    assert(d.reason == "ne_stop_1" && d.intentional);

    // Известна только конфигурация: запись старше первого живого наблюдения сессии — прошлый запуск.
    in = liveSession();
    in.sessionGeneration = "C1";
    in.sessionConfigurationGeneration.clear();
    in.liveSinceMs = in.nowMs - 30000;
    in.neStop = {true, "G1", "C1", 1, true, in.nowMs - 60000};
    d = decideDisconnect(in);
    assert(d.reason == "unknown_external" && !d.intentional);
    in.neStop.utcMs = in.nowMs - 10000; // записана во время этой живой фазы — её стоп
    d = decideDisconnect(in);
    assert(d.reason == "ne_stop_1" && d.intentional);
}

static void testDisconnectGate()
{
    DisconnectReasonGate gate;
    assert(gate.claimReport());
    assert(!gate.claimReport()); // повторный реконсил того же Disconnected — без переэмиссии
    assert(!gate.claimReport());
    gate.noteNotDisconnected(); // Connecting/Connected — впереди новый переход
    assert(gate.claimReport());
    assert(!gate.claimReport());
    gate.noteStartIssued();
    assert(gate.claimReport());

    for (int i = 0; i < 40; ++i) gate.noteAppStop("g" + std::to_string(i));
    assert(gate.isAppStopped("g39") && gate.isAppStopped("g24"));
    assert(!gate.isAppStopped("g0")); // ограниченный размер
    assert(!gate.isAppStopped(""));

    gate.noteLive("i1", 5000);
    gate.noteLive("i2", 9000); // базовая линия фиксируется один раз на живую фазу
    assert(gate.haveLive() && gate.intentAtLive() == "i1" && gate.liveSinceMs() == 5000);
    gate.clearLive();
    assert(!gate.haveLive() && gate.liveSinceMs() == 0);
}

// Ревью REV-2 (K3): Disconnecting — не живая сессия; Connect ждёт терминал.
static void testConnectOverExisting()
{
    assert(decideConnectOverExisting(SessionPhase::Down) == ConnectOverExisting::StartNew);
    assert(decideConnectOverExisting(SessionPhase::Starting) == ConnectOverExisting::AdoptLive);
    assert(decideConnectOverExisting(SessionPhase::Live) == ConnectOverExisting::AdoptLive);
    assert(decideConnectOverExisting(SessionPhase::TearingDown) == ConnectOverExisting::AwaitTeardown);
}

// Ревью REV-3 (K2): флаг стопа приложения не переживает смену сессии.
static void testLocalStopSuperseded()
{
    LocalStopInfo runtimeStop{"run-1", true, true};
    // Та же NE-сессия (ответ status до того, как стоп дошёл) — флаг держим.
    assert(!localStopSupersededByNewSession(runtimeStop, false, "run-1", true, true));
    assert(!localStopSupersededByNewSession(runtimeStop, false, "run-1", true, false));
    // Новый runtime-запуск (Настройки подняли после нашего стопа) — флаг снят.
    assert(localStopSupersededByNewSession(runtimeStop, false, "run-2", true, false));
    // Поколение, погашенное приложением, новым не считается.
    assert(!localStopSupersededByNewSession(runtimeStop, false, "run-2", true, true));
    // Поколение уровня конфигурации — не доказательство новизны.
    assert(!localStopSupersededByNewSession(runtimeStop, false, "cfg-1", false, false));
    // Connecting после стопа ЖИВОЙ сессии — это уже новый старт.
    assert(localStopSupersededByNewSession(runtimeStop, true, "cfg-1", false, true));
    // Стоп был посреди Connecting (или сессия неизвестна): Connecting может быть той же сессией.
    LocalStopInfo startingStop{"cfg-1", false, false};
    assert(!localStopSupersededByNewSession(startingStop, true, "cfg-1", false, true));
    // Runtime-поколение погашенной неизвестно — «другое» runtime-поколение не доказывает новизну.
    assert(!localStopSupersededByNewSession(startingStop, false, "run-7", true, false));
    LocalStopInfo cfgLive{"cfg-1", false, true};
    assert(!localStopSupersededByNewSession(cfgLive, false, "run-7", true, false));
    assert(localStopSupersededByNewSession(cfgLive, true, "run-7", true, false));
}

static void testRebindReply()
{
    assert(rebindPerformed(true, true, "performed", false, false));
    assert(!rebindPerformed(true, true, "denied", true, true)); // новый формат главнее legacy ok
    assert(!rebindPerformed(true, true, "", false, false));
    assert(rebindPerformed(true, false, "", true, true));   // старый NE того же бандла: {"ok":true}
    assert(!rebindPerformed(true, false, "", true, false));
    assert(!rebindPerformed(true, false, "", false, false));
    assert(!rebindPerformed(false, false, "", false, false)); // nil-ответ / ошибка отправки
}

static void testLifecycleCollapse()
{
    assert(lifecycleCollapsible("status_timeout", "status_timeout"));
    assert(!lifecycleCollapsible("os_state", "status_timeout"));
    assert(!lifecycleCollapsible("os_state", "os_state")); // смены состояния не схлопываем
    assert(!lifecycleCollapsible("disconnect_reason", "disconnect_reason"));
}

static void testStatusAccept()
{
    // C5/H7: дедлайн освобождает слот, но поздний ответ той же заявки применяется.
    IosStatusRequest gate;
    auto first = gate.begin(7);
    assert(first);
    assert(gate.complete(7, *first));        // дедлайн выиграл владение
    assert(!gate.complete(7, *first));       // поздний ответ владение не получает…
    assert(gate.accept(7, *first));          // …но его handshake/rx/tx применяются
    assert(!gate.accept(7, *first));         // повторно — нет

    // Обгон: заявка 2 применена раньше опоздавшей заявки 1 → старая не откатывает данные.
    IosStatusRequest race;
    auto r1 = race.begin(1);
    assert(race.complete(1, *r1)); // дедлайн r1
    auto r2 = race.begin(1);
    assert(r2 && *r2 > *r1);
    assert(race.complete(1, *r2) && race.accept(1, *r2));
    assert(!race.accept(1, *r1));

    // invalidate (стоп/реконнект/не-Connected статус): ответы старых заявок не применяются.
    IosStatusRequest inv;
    auto a = inv.begin(3);
    inv.invalidate();
    assert(!inv.accept(3, *a));
    auto b = inv.begin(3);
    assert(b && inv.accept(3, *b));
    // Другая сессия / будущий id / нулевой id — нет.
    assert(!inv.accept(4, *b + 0));
    assert(!inv.accept(3, *b + 5));
    assert(!inv.accept(3, 0));
    // Новая сессия начинает свою шкалу.
    auto c = inv.begin(4);
    assert(!c); // слот b ещё занят
    assert(inv.complete(3, *b));
    c = inv.begin(4);
    assert(c && inv.accept(4, *c));
}

static void testTryLock()
{
    char path[] = "/tmp/avpn-lock-test.XXXXXX";
    const int tmp = mkstemp(path);
    assert(tmp >= 0);
    close(tmp);
    const int holder = open(path, O_RDWR);
    const int waiter = open(path, O_RDWR);
    assert(holder >= 0 && waiter >= 0);
    assert(flock(holder, LOCK_EX) == 0);
    const auto t0 = std::chrono::steady_clock::now();
    const bool got = tryLockExclusive(waiter); // 20×5 мс
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    assert(!got);
    assert(ms < 1000); // ограниченное ожидание, а не бесконечный LOCK_EX
    flock(holder, LOCK_UN);
    assert(tryLockExclusive(waiter));
    flock(waiter, LOCK_UN);
    assert(!tryLockExclusive(-1));
    close(holder);
    close(waiter);
    unlink(path);
}

// Разбор журнала 25.09: холодный старт при давно живой сессии — Connected сразу, без
// «выключено → подключаемся»; свежий подъём и повторное Connected после Reasserting — как раньше.
static void testEstablishedSession()
{
    using namespace avpn_ios;
    assert(showEstablishedAsConnected(false, false, kEstablishedSessionMs));
    assert(showEstablishedAsConnected(false, false, 10 * 60 * 1000));
    assert(!showEstablishedAsConnected(false, false, kEstablishedSessionMs - 1)); // только что поднялась
    assert(!showEstablishedAsConnected(true, false, 10 * 60 * 1000));  // наш подъём в полёте
    assert(!showEstablishedAsConnected(false, true, 10 * 60 * 1000));  // уже видели живой (Reasserting)
    assert(!showEstablishedAsConnected(false, false, -1));             // время подключения неизвестно
}

// On-Demand (2026-09-30): правило — только для доказанно рабочей сессии; любой стоп его снимает.
static void testOnDemandPolicy()
{
    using namespace avpn_ios;
    // Начало попытки: только живая WireGuard-сессия, без стопа и без уже идущей попытки.
    assert(shouldStartOnDemandArm(true, true, true, false, false));
    assert(!shouldStartOnDemandArm(false, true, true, false, false)); // нет профиля
    assert(!shouldStartOnDemandArm(true, false, true, false, false)); // сессия уже не Connected
    assert(!shouldStartOnDemandArm(true, true, false, false, false)); // Xray: расширение само гасит туннель
    assert(!shouldStartOnDemandArm(true, true, true, true, false));   // приложение гасит туннель
    assert(!shouldStartOnDemandArm(true, true, true, false, true));   // попытка уже идёт

    // Решение по свежей загрузке.
    assert(decideOnDemandArm(false, true, true, false, false, false, false) == OnDemandArm::Arm);
    assert(decideOnDemandArm(false, true, true, false, false, false, true) == OnDemandArm::AlreadyArmed);
    assert(decideOnDemandArm(true, true, true, false, false, false, false) == OnDemandArm::Skip);  // загрузка не удалась
    assert(decideOnDemandArm(false, false, true, false, false, false, false) == OnDemandArm::Skip); // новая операция
    assert(decideOnDemandArm(false, true, false, false, false, false, false) == OnDemandArm::Skip); // сессия упала
    assert(decideOnDemandArm(false, true, true, true, false, false, false) == OnDemandArm::Skip);   // стоп приложения
    assert(decideOnDemandArm(false, true, true, false, true, false, false) == OnDemandArm::Skip);   // пауза/выкл из другого процесса
    // Наше снятие ещё не дошло до системы: «уже взведено» в свежей загрузке — старое значение.
    assert(decideOnDemandArm(false, true, true, false, false, true, true) == OnDemandArm::Skip);

    assert(armNeedsCleanup(false, true));   // взвод сохранился после паузы — снять
    assert(!armNeedsCleanup(false, false));
    assert(!armNeedsCleanup(true, true));   // взвод не сохранился — снимать нечего

    assert(!stopNeedsOnDemandDisarm(false, false, false, false)); // правил нет и не было — стоп сразу
    assert(stopNeedsOnDemandDisarm(true, false, false, false));
    assert(stopNeedsOnDemandDisarm(false, true, false, false));   // правила есть: взвести мог другой процесс
    assert(stopNeedsOnDemandDisarm(false, false, true, false));
    assert(stopNeedsOnDemandDisarm(false, false, false, true));

    assert(stopAfterOnDemandDisarm(true, SessionPhase::Live));
    assert(stopAfterOnDemandDisarm(true, SessionPhase::Starting)); // iOS подняла туннель, пока снимали правило
    assert(stopAfterOnDemandDisarm(true, SessionPhase::TearingDown));
    assert(!stopAfterOnDemandDisarm(true, SessionPhase::Down));    // гасить нечего
    assert(!stopAfterOnDemandDisarm(false, SessionPhase::Live));   // стоп уже не нужен (новый Connect)

    DisconnectReasonGate gate;
    gate.noteAppStop("run-1");
    gate.noteAppStop("run-2");
    gate.forgetAppStop("run-1"); // стоп отменён новым Connect
    assert(!gate.isAppStopped("run-1") && gate.isAppStopped("run-2"));

    assert(rearmAfterCancelledStop(false, true, true));
    assert(!rearmAfterCancelledStop(true, true, true));   // стоп выполнен
    assert(!rearmAfterCancelledStop(false, false, true)); // рукопожатие ещё не подтверждено — взведёт checkStatus
    assert(!rearmAfterCancelledStop(false, true, false));
}

static void testUserspaceSplitPolicy()
{
    assert(useUserspaceSplit(true, kSplitTunnelExceptSites, 10850));
    assert(!useUserspaceSplit(false, kSplitTunnelExceptSites, 10850)); // флаг с сервера выключен
    assert(!useUserspaceSplit(true, 0, 0));                            // разделение выключено
    assert(!useUserspaceSplit(true, 1, 12));                           // «только эти сайты» — маршрутами
    assert(!useUserspaceSplit(true, kSplitTunnelExceptSites, 0));      // список пуст
}

int main()
{
    testOnDemandPolicy();
    testUserspaceSplitPolicy();
    testRetryBudget();
    testDisconnectDecision();
    testDisconnectGate();
    testConnectOverExisting();
    testLocalStopSuperseded();
    testRebindReply();
    testLifecycleCollapse();
    testStatusAccept();
    testTryLock();
    testEstablishedSession();
    std::cout << "IosNativePolicyTests: all checks passed\n";
    return 0;
}

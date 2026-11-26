// AVPN (фикс-волна 2026-09-22, зона CL-A): чистые решения фасада AvpnEngineQml
// (DebugSnapshot.h / ReportDelivery.h). Каждый блок — сценарий из ревью реализации; на коде до
// фикса он либо не собирается (решения не было — фасад делал дефектное действие инлайн), либо
// падает на утверждении (canAdoptObservedTunnel «manual OFF»).
#include <QTemporaryDir>
#include "../DebugSnapshot.h"
#include "../DoctorReport.h"
#include "../NodeRanking.h" // nodeFigure (U7)
#include "../ReportDelivery.h"
#include "../UplinkMonitor.h"
#include "../UpstreamEngine.h" // upstreamNetworkKey (Scanner item 7)
#include "../path/NetworkKey.h" // NetworkTracker: the generation the Scanner notice compares

#include <QByteArray>
#include <QJsonArray>
#include <QVariantMap>
#include <cstdio>

using namespace avpn;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static void a1ErrorDoesNotLatchAdoption()
{
    // Сценарий §2.1: холодный старт при живой NE-сессии, синтетический Error (дедлайн loadAll),
    // следом реальный Connected. До фикса Error взводил единый латч → адопт запрещён, health
    // выключен, reconcile только перечитывал статус («иконка есть, кнопка серая»).
    TeardownLatch latch;
    observeTunnelState(latch, ObservedTunnel::Error, /*errorProvesTeardown=*/false);
    CHECK(latch.needStatusBeforeStart);
    CHECK(!latch.awaitingStopConfirm);
    CHECK(decideTunnelAdoption(true, false, false, false, latch.awaitingStopConfirm, true)
          == TunnelAdoption::AdoptExistingIntent);
    CHECK(canAdoptObservedTunnel(true, false, false, false, latch.awaitingStopConfirm, true));
    CHECK(healthTickAllowed(latch, true, false));
    observeTunnelState(latch, ObservedTunnel::Connected, false);
    CHECK(!latch.needStatusBeforeStart); // наблюдённый Connected = туннель жив, латч снят

    // (b) перед НОВЫМ стартом нужен наблюдаемый терминал: Error → запрос статуса, не старт.
    TeardownLatch err;
    observeTunnelState(err, ObservedTunnel::Error, false);
    CHECK(reconcileGate(err, ObservedTunnel::Error, true, true) == ReconcileGate::AwaitStatus);
    CHECK(!reconcileActionable(ObservedTunnel::Error, err));
    // Бюджет запросов исчерпан — не вечное «серое» состояние: старт разрешён (натив проверит профиль).
    CHECK(reconcileGate(err, ObservedTunnel::Error, true, false) == ReconcileGate::Proceed);
    // OFF + Error: ничего не делаем, статус не нужен.
    CHECK(reconcileGate(err, ObservedTunnel::Error, false, true) == ReconcileGate::Proceed);
    observeTunnelState(err, ObservedTunnel::Disconnected, false);
    CHECK(!err.needStatusBeforeStart && reconcileActionable(ObservedTunnel::Disconnected, err));

    // (a) МЫ просили стоп: не адоптить, не стартовать, health выключен до Disconnected.
    TeardownLatch stop;
    stop.awaitingStopConfirm = true;
    CHECK(!healthTickAllowed(stop, true, false));
    CHECK(decideTunnelAdoption(true, true, true, false, stop.awaitingStopConfirm, true)
          == TunnelAdoption::Reject);
    CHECK(reconcileGate(stop, ObservedTunnel::Connected, false, true) == ReconcileGate::AwaitStatus);
    CHECK(reconcileGate(stop, ObservedTunnel::Connected, false, false) == ReconcileGate::Wait);
    observeTunnelState(stop, ObservedTunnel::Error, false); // Error не подтверждает наш стоп на iOS
    CHECK(stop.awaitingStopConfirm);
    observeTunnelState(stop, ObservedTunnel::Connected, false); // и Connected тоже
    CHECK(stop.awaitingStopConfirm);
    observeTunnelState(stop, ObservedTunnel::Disconnected, false);
    CHECK(!stop.awaitingStopConfirm && !stop.needStatusBeforeStart);

    // Кросс-платформа: на Android/macOS-демоне/Windows Error — терминал (база 3c8cc74e).
    TeardownLatch desk;
    desk.awaitingStopConfirm = true;
    observeTunnelState(desk, ObservedTunnel::Error, /*errorProvesTeardown=*/true);
    CHECK(!desk.awaitingStopConfirm && !desk.needStatusBeforeStart);
    CHECK(reconcileActionable(ObservedTunnel::Error, desk));

    // Повторы ограничены (без бесконечной петли).
    CHECK(statusRequestDelayMs(0) == 1000 && statusRequestDelayMs(1) == 2000
          && statusRequestDelayMs(2) == 4000 && statusRequestDelayMs(3) < 0);
    CHECK(stopRetryDelayMs(0) == 2000 && stopRetryDelayMs(1) == 4000 && stopRetryDelayMs(2) < 0);
}

static void a4AdoptNewSessionAfterOff()
{
    // Сценарий A4: пользователь выключил VPN в приложении (намерение OFF, стоп подтверждён
    // Disconnected), затем включил в Настройках iOS/Shortcuts. До фикса гейт запрещал адопт при
    // intentKnown && !want, и reconcile сам гасил VPN.
    CHECK(canAdoptObservedTunnel(true, true, false, false, false, true));
    CHECK(decideTunnelAdoption(true, true, false, false, false, true) == TunnelAdoption::AdoptNewIntent);
    // Стоп ещё в пути, наблюдаем ТО ЖЕ runtime-поколение → не адоптим.
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, QStringLiteral("g1"),
                               QStringLiteral("g1")) == TunnelAdoption::Reject);
    // Поколение неизвестно (метаданные ещё не пришли) при незавершённом стопе → тоже ждём.
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, QStringLiteral("g1"), QString())
          == TunnelAdoption::Reject);
    // Стоп в пути, но runtime-поколение ДРУГОЕ → новая сессия ОС/пользователя → адопт с намерением.
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, QStringLiteral("g1"),
                               QStringLiteral("g2")) == TunnelAdoption::AdoptNewIntent);
    // Пауза и наша операция в полёте по-прежнему запрещают адопт.
    CHECK(decideTunnelAdoption(true, true, false, true, false, true) == TunnelAdoption::Reject);
    CHECK(decideTunnelAdoption(true, true, true, false, false, false) == TunnelAdoption::Reject);
    CHECK(decideTunnelAdoption(false, true, true, false, false, true) == TunnelAdoption::Reject);
}

static void rev1UnconfirmedStopIsDriven()
{
    // Ревью CL-A r2 (REV-1): guardedStop → натив присылает Connected терминалом раньше Disconnected
    // (или iOS теряет стоп) → терминальный блок снимает m_op и сторож. Раньше повтор взводился
    // только сторожем, reconcile после ~7 с запросов статуса навсегда уходил в Wait: туннель поднят,
    // движок Disconnected, health выключен, Connect мёртв (жалоба 2). Модель фасада на решениях.
    TeardownLatch latch;
    latch.awaitingStopConfirm = true;                                       // guardedStop()
    observeTunnelState(latch, ObservedTunnel::Connected, /*errorProvesTeardown iOS=*/false);
    CHECK(latch.awaitingStopConfirm);
    bool opIdle = true, retryArmed = false; // терминал: m_op=None, m_watchdog.stop(), повтора нет
    int retries = 0, stopsIssued = 0;
    bool resolved = false;
    for (int round = 0; round < 10 && !resolved; ++round) {
        int statusAttempts = 0;
        for (;;) { // reconcile: AwaitStatus до исчерпания бюджета статуса
            const ReconcileGate g = reconcileGate(latch, ObservedTunnel::Connected, false,
                                                  statusRequestDelayMs(statusAttempts) >= 0);
            if (g != ReconcileGate::AwaitStatus) {
                CHECK(g == ReconcileGate::Wait);
                break;
            }
            ++statusAttempts;
        }
        switch (decideUnconfirmedStop(latch, ObservedTunnel::Connected, opIdle, retryArmed, retries)) {
        case UnconfirmedStopStep::RetryStop:
            CHECK(stopRetryDelayMs(retries) > 0);
            ++retries;
            ++stopsIssued; // onStopRetryTimer → guardedStop → снова Connected-терминал
            break;
        case UnconfirmedStopStep::Resolve:
            latch.awaitingStopConfirm = false; // resolveUnconfirmedStop: честное «подключено»
            resolved = true;
            break;
        case UnconfirmedStopStep::None:
            CHECK(false && "unconfirmed stop left without a driver");
            resolved = true;
            break;
        }
    }
    CHECK(stopsIssued == 2 && resolved && !latch.awaitingStopConfirm);
    CHECK(healthTickAllowed(latch, true, false));
    CHECK(decideTunnelAdoption(true, true, false, false, latch.awaitingStopConfirm, true)
          != TunnelAdoption::Reject);
    // Стоп ведёт кто-то другой — не вмешиваемся.
    TeardownLatch busy;
    busy.awaitingStopConfirm = true;
    CHECK(decideUnconfirmedStop(busy, ObservedTunnel::Connected, /*idle=*/false, false, 0)
          == UnconfirmedStopStep::None);
    CHECK(decideUnconfirmedStop(busy, ObservedTunnel::Connected, true, /*armed=*/true, 0)
          == UnconfirmedStopStep::None);
    CHECK(decideUnconfirmedStop(busy, ObservedTunnel::Disconnected, true, false, 0)
          == UnconfirmedStopStep::None);
    // iOS: стоп закончился терминалом Error при живом профиле — тоже повтор, не вечный Wait.
    observeTunnelState(busy, ObservedTunnel::Error, false);
    CHECK(decideUnconfirmedStop(busy, ObservedTunnel::Error, true, false, 0)
          == UnconfirmedStopStep::RetryStop);
    CHECK(decideUnconfirmedStop(busy, ObservedTunnel::Error, true, false, 2)
          == UnconfirmedStopStep::Resolve);
    // Не-iOS: Connected после нашего стопа — терминал как в базе 3c8cc74e: латч снят, reconcile
    // не гейтится и при want=false и connected сам даёт guardedStop.
    TeardownLatch desk;
    desk.awaitingStopConfirm = true;
    observeTunnelState(desk, ObservedTunnel::Connected, /*errorProvesTeardown=*/true);
    CHECK(!desk.awaitingStopConfirm);
    CHECK(reconcileGate(desk, ObservedTunnel::Connected, false, false) == ReconcileGate::Proceed);
}

static void rev3GenerationKinds()
{
    // Ревью CL-A r2 (REV-3): стоп запрошен до первого status-ответа — в метаданных поколение
    // КОНФИГУРАЦИИ C1 (restoreSessionMetadata). Первый runtime-ответ ТОЙ ЖЕ сессии: generation=R1,
    // configuration_generation=C1. Раньше строки сравнивались напрямую («C1» != «R1») → «новая
    // сессия» → AdoptNewIntent: выключение пользователя отменялось («VPN сам подключается»).
    QVariantMap configOnly;
    configOnly.insert(QStringLiteral("schema_version"), 1);
    configOnly.insert(QStringLiteral("generation"), QStringLiteral("C1"));
    QVariantMap runtimeSame;
    runtimeSame.insert(QStringLiteral("schema_version"), 1);
    runtimeSame.insert(QStringLiteral("generation"), QStringLiteral("R1"));
    runtimeSame.insert(QStringLiteral("configuration_generation"), QStringLiteral("C1"));
    const SessionGeneration stopped = sessionGenerationFrom(configOnly);
    CHECK(stopped.runtime.isEmpty() && stopped.configuration == QStringLiteral("C1"));
    const SessionGeneration observed = sessionGenerationFrom(runtimeSame);
    CHECK(observed.runtime == QStringLiteral("R1") && observed.configuration == QStringLiteral("C1"));
    CHECK(!isDifferentSession(stopped, observed));
    CHECK(decideTunnelAdoption(true, true, false, false, /*awaitingStopConfirm=*/true, true, stopped,
                               observed) == TunnelAdoption::Reject);
    // Профиль пересохранён (другая конфигурация) — доказанно новая сессия.
    QVariantMap runtimeOtherConfig = runtimeSame;
    runtimeOtherConfig.insert(QStringLiteral("configuration_generation"), QStringLiteral("C2"));
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, stopped,
                               sessionGenerationFrom(runtimeOtherConfig))
          == TunnelAdoption::AdoptNewIntent);
    // Оба runtime: то же — стоп в пути, другое — новая сессия ОС/пользователя.
    const SessionGeneration stoppedRuntime = sessionGenerationFrom(runtimeSame);
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, stoppedRuntime,
                               sessionGenerationFrom(runtimeSame)) == TunnelAdoption::Reject);
    QVariantMap runtimeNew = runtimeSame;
    runtimeNew.insert(QStringLiteral("generation"), QStringLiteral("R2"));
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, stoppedRuntime,
                               sessionGenerationFrom(runtimeNew)) == TunnelAdoption::AdoptNewIntent);
    // Стоп runtime R1(C1), наблюдаем только поколение конфигурации C1 — не доказано, ждём.
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, stoppedRuntime,
                               sessionGenerationFrom(configOnly)) == TunnelAdoption::Reject);
    // Метаданных нет — ждём; стоп подтверждён (латч снят) — адопт по A4.
    CHECK(decideTunnelAdoption(true, true, false, false, true, true, stopped, SessionGeneration{})
          == TunnelAdoption::Reject);
    CHECK(decideTunnelAdoption(true, true, false, false, false, true, stopped, observed)
          == TunnelAdoption::AdoptNewIntent);
}

static void a2EmptyIssuanceKeepsPoolAndLkg()
{
    // §2.2: nodes:[] при живом пуле шло в loadSubscription → пул 2→0, LKG перезаписывался пустым.
    CHECK(routeSubscriptionBody(false, true, 7) == SubscriptionBodyRoute::KeepPoolUpdateMeta);
    CHECK(routeSubscriptionBody(false, false, 7) == SubscriptionBodyRoute::LoadFull); // без пула — как было
    CHECK(routeSubscriptionBody(true, false, 7) == SubscriptionBodyRoute::LoadFull);
    CHECK(routeSubscriptionBody(true, true, 0) == SubscriptionBodyRoute::LoadFull);
    CHECK(routeSubscriptionBody(true, true, 3) == SubscriptionBodyRoute::Reseed); // меньшая ревизия — тоже reseed
    CHECK(!shouldPersistLkgBody(false, true)); // пустое тело не затирает LKG с нодами
    CHECK(shouldPersistLkgBody(false, false));
    CHECK(shouldPersistLkgBody(true, true));
}

static void a6a7PinPersistence()
{
    // A6: неявные pin'ы («Заменить сервер», Доктор, свип) — только в памяти.
    CHECK(pinOriginPersists(PinOrigin::UserChoice));
    CHECK(!pinOriginPersists(PinOrigin::Rotate));
    CHECK(!pinOriginPersists(PinOrigin::Doctor));
    CHECK(!pinOriginPersists(PinOrigin::Sweep));

    // A7: движок перенёс явный pin на соседа той же локации — сохраняем НОВЫЙ id, а не стираем.
    const QString ee1 = QStringLiteral("9:awg"), ee2 = QStringLiteral("11:awg"), us = QStringLiteral("10:awg");
    CHECK(decidePinRestore(ee1, ee1, ee2) == PinRestoreAction::PersistMigrated);
    CHECK(decidePinRestore(ee1, ee1, ee1) == PinRestoreAction::Nothing);
    // В памяти неявный pin (rotate на US) — не персистим его и не трогаем сохранённый.
    CHECK(decidePinRestore(ee1, us, us) == PinRestoreAction::Nothing);
    // pin в памяти пуст — пробуем сохранённый (неудача сохранённое не стирает).
    CHECK(decidePinRestore(ee1, ee1, QString()) == PinRestoreAction::ApplySaved);
    CHECK(decidePinRestore(QString(), us, us) == PinRestoreAction::Nothing);
}

// 5.1.109 (review R3): the facade's decision on a transport mode change (pin vs mode, live tunnel).
static void pinOnTransportModeChange()
{
    const QString rs = QStringLiteral("16:awg"), de = QStringLiteral("9:xray");
    // Serbia (AWG only) pinned, mode -> Xray, tunnel down: cleared (+ persisted by the facade), journal
    PinModeDecision d = decidePinOnTransportMode(QStringLiteral("xray"), rs, true, false, QString());
    CHECK(d.clearPin && !d.restartTunnel);
    CHECK(d.journal == QLatin1String("pin_cleared why=transport_mode mode=xray node=16:awg"));
    // ... tunnel up on Serbia's AWG: cleared and the tunnel restarted (then Auto picks an Xray node)
    d = decidePinOnTransportMode(QStringLiteral("xray"), rs, true, true, QStringLiteral("awg"));
    CHECK(d.clearPin && d.restartTunnel);
    // Auto never clears and never restarts, whatever the predicate says
    d = decidePinOnTransportMode(QStringLiteral("auto"), rs, true, true, QStringLiteral("awg"));
    CHECK(!d.clearPin && !d.restartTunnel && d.journal.isEmpty());
    // no pin: nothing to clear; a live Xray tunnel under "Amnezia" is still restarted (as before)
    d = decidePinOnTransportMode(QStringLiteral("awg"), QString(), false, true, QStringLiteral("xray"));
    CHECK(!d.clearPin && d.restartTunnel && d.journal.isEmpty());
    // pin the mode serves (DE has both): kept; the live Xray tunnel restarts on DE's AWG
    d = decidePinOnTransportMode(QStringLiteral("awg"), de, false, true, QStringLiteral("xray"));
    CHECK(!d.clearPin && d.restartTunnel);
    // the tunnel already on an allowed transport: untouched
    d = decidePinOnTransportMode(QStringLiteral("xray"), de, false, true, QStringLiteral("xray"));
    CHECK(!d.clearPin && !d.restartTunnel);
    // adopted session, node not identified (proto unknown): no restart on a guess
    d = decidePinOnTransportMode(QStringLiteral("xray"), QString(), false, true, QString());
    CHECK(!d.restartTunnel);
    // tunnel down: never a restart
    d = decidePinOnTransportMode(QStringLiteral("awg"), de, false, false, QStringLiteral("xray"));
    CHECK(!d.restartTunnel);
}

// 5.1.109 (S4.1; reviews of d5d739403 and 3dbe0361f): how the tunnel looks to the transport-mode gate
// (AvpnEngineQml::modeActivity -> TransportModeGate.h; the rule itself - transport_mode_gate_check,
// on a real engine - transport_pick_check §17).
static void tunnelAsTheTransportModeGateSeesIt()
{
    const TeardownLatch clean;
    // no status seen in this run yet: NOT "down" - a session of an earlier process may be alive
    CHECK(modeTunnelOf(ObservedTunnel::Unknown, clean) == ModeTunnel::NotObserved);
    CHECK(modeTunnelOf(ObservedTunnel::Disconnected, clean) == ModeTunnel::Down);
    CHECK(modeTunnelOf(ObservedTunnel::Connected, clean) == ModeTunnel::Up);
    CHECK(modeTunnelOf(ObservedTunnel::Transitional, clean) == ModeTunnel::Moving);
    // our own stop is not confirmed yet: moving, whatever the state reads
    TeardownLatch stopping; stopping.awaitingStopConfirm = true;
    CHECK(modeTunnelOf(ObservedTunnel::Disconnected, stopping) == ModeTunnel::Moving);
    CHECK(modeTunnelOf(ObservedTunnel::Unknown, stopping) == ModeTunnel::Moving);
    CHECK(modeTunnelOf(ObservedTunnel::Error, stopping) == ModeTunnel::Moving);
    CHECK(modeTunnelOf(ObservedTunnel::Connected, stopping) == ModeTunnel::Up);
    // an error a start may act from is down; one that needs a status first (iOS) is still moving
    CHECK(modeTunnelOf(ObservedTunnel::Error, clean) == ModeTunnel::Down);
    TeardownLatch afterError; afterError.needStatusBeforeStart = true;
    CHECK(modeTunnelOf(ObservedTunnel::Error, afterError) == ModeTunnel::Moving);
    CHECK(modeTunnelOf(ObservedTunnel::Disconnected, afterError) == ModeTunnel::Down);
    // the journal line of a pin dropped by a tap on a mode (decidePinOnTransportMode)
    CHECK(pinClearedByModeJournal(QStringLiteral("xray"), QStringLiteral("16:awg"))
          == QLatin1String("pin_cleared why=transport_mode mode=xray node=16:awg"));
    CHECK(decidePinOnTransportMode(QStringLiteral("xray"), QStringLiteral("16:awg"), true, false, QString()).journal
          == pinClearedByModeJournal(QStringLiteral("xray"), QStringLiteral("16:awg")));
}

// 5.1.109 (R7): a deadline timer that fires late = the process was frozen (iOS suspended the app, a
// laptop slept) - that tick must not judge the deadline; the start watchdog re-arms once and asks status.
static void lateDeadlineTick()
{
    DeadlineTick t = decideDeadlineTick(1000, 1000);              // normal 1 s tick
    CHECK(t.evaluate && t.frozenMs == 0);
    t = decideDeadlineTick(3000, 1000);                           // tolerance edge: period + 2 s
    CHECK(t.evaluate && t.frozenMs == 0);
    t = decideDeadlineTick(3001, 1000);
    CHECK(!t.evaluate && t.frozenMs == 2001);
    const qint64 night = 11LL * 3600 * 1000 + 36LL * 60 * 1000;    // device 35: 21:02 -> 08:38
    t = decideDeadlineTick(night, 1000);
    CHECK(!t.evaluate && t.frozenMs == night - 1000);
    t = decideDeadlineTick(-5000, 1000);                          // wall clock went backwards (R7c):
    CHECK(t.evaluate && t.frozenMs == 0);                         // judged; expireSwitch clamps the start
    t = decideDeadlineTick(0, 1000);                              // two ticks at once (coalesced)
    CHECK(t.evaluate);
    // start watchdog (one-shot, 15 s): on time -> judge; late -> re-arm once without spending the grace
}

static void a8a9a15InternalSwitch()
{
    // A8: дедлайн свитча — повтор старта, намерение снимается только при исчерпании попыток.

    // A9: до фикса решение принималось по состоянию движка ПОСЛЕ onTunnelError (всегда "error") →
    // Error посреди внутреннего failover снимал намерение без тоста. Теперь — по состоянию ДО.

    // A15: наш собственный стоп в свитче не отменяет свитч; пользовательский — отменяет.
    CHECK(!intentionalStopCancelsSwitch(QStringLiteral("expected_app_stop"), true));
    CHECK(intentionalStopCancelsSwitch(QStringLiteral("user_intent"), true));
    CHECK(intentionalStopCancelsSwitch(QStringLiteral("expected_app_stop"), false));
}

static void a10a11Selection()
{
    // A10: свежая установка (пула нет) — 6 с не снимают намерение, потолок ~20 с.
    CHECK(decideSelectionBudget(false, 6000) == SelectionBudget::KeepWaiting);
    CHECK(decideSelectionBudget(false, 19999) == SelectionBudget::KeepWaiting);
    CHECK(decideSelectionBudget(false, 20000) == SelectionBudget::GiveUp);
    // Волна «как апстрим» (2026-09-28): с пулом мягкий бюджет 2 с — ждём только ICMP-раунд (1,5 с),
    // не ответ refresh (после гашения туннеля он висел до 15 с, и каждый Connect ждал 6 с).
    CHECK(kStartPrepSoftBudgetMs == 2000);
    CHECK(decideSelectionBudget(true, 1999) == SelectionBudget::KeepWaiting);
    CHECK(decideSelectionBudget(true, 2000) == SelectionBudget::Finish);

    // A11: без pin ICMP-раунд сразу (параллельно refresh), а не по таймеру 4 с.
    // Прошлый RTT не очищается в начале раунда и не затирается «нет ответа».
    QHash<QString, int> cache{{QStringLiteral("9:awg"), 40}};
    mergeRttSample(cache, QStringLiteral("9:awg"), -1);
    CHECK(cache.value(QStringLiteral("9:awg")) == 40);
    mergeRttSample(cache, QStringLiteral("9:awg"), 35);
    CHECK(cache.value(QStringLiteral("9:awg")) == 35);
    mergeRttSample(cache, QStringLiteral("10:awg"), -1);
    CHECK(cache.value(QStringLiteral("10:awg")) == -1);
}

static void parityConnectDoesNotWaitForNetwork()
{
    // Волна «как апстрим» (2026-09-28, CONNECT-INVARIANTS §1: кнопка Connect в сеть не ходит).
    // Журнал Mac владельца 26–28.09: все 11 ручных Connect ждали 5,7–6,4 с (selection_wait_fresh_pool
    // → selection_budget_expired), хотя локация была закреплена, а handshake занимает 0,7 с.
    // Пул есть + пригодный pin → подключаемся сразу.
    // Пул есть + свежий замер RTT, покрывающий все авто-ноды и сделанный после последней смены
    // сети → «Авто» выбирает по нему сразу.
    // Волна-2 (ревью 5.1.95, находка 2): свежесть замера = после последней смены сети И покрытие
    // всех авто-нод; частичный замер или замер из прошлой сети → обычный раунд (≤ 1,5 с).
    // Пул есть, pin нет, замера нет → только ICMP-раунд (≤ 1,5 с), без ожидания refresh.
    // Пула нет (свежая установка) → ждём bootstrap, как раньше (потолок 20 с).
    // Path engine (design 2026-11-17 §7): a pool in hand starts at once - no ICMP round is waited for;
    // no pool (a fresh install) waits for bootstrap as before.
    CHECK(decideStartPreparation(true) == StartPrep::ConnectNow);
    CHECK(decideStartPreparation(false) == StartPrep::AwaitPool);
    // Смена сети во время подготовки: refresh нужен только без пула.
    CHECK(!prepRefreshOnNetworkChange(true));
    CHECK(prepRefreshOnNetworkChange(false));
}

static void parityBackgroundPollingOnlyWhenActive()
{
    // Волна «как апстрим» (2026-09-28): у апстрима нет ни одного периодического сетевого таймера.
    // Mac владельца: 13,3 тыс. HEAD /v1/ping за 2,3 сут (каждые 4 с) и /v1/subscription каждые 20 с —
    // при окне в фоне. Палочки RTT — только при активном окне (их никто не видит в фоне).
    // Волна-2 (ревью 5.1.95, находка 1): в фоне пробу НЕ выключаем, а разрежаем до ~60 с —
    // удачная проба через туннель единственная сбрасывает счётчик провалов data-plane
    // (ServiceEngine::feedProbeResult), без неё 4 failover за сессию = «сдаёмся» и intent off.
    CHECK(liveProbeDue(/*flag=*/true, /*connected=*/true, /*uiActive=*/true, /*bgTick=*/1));
    CHECK(liveProbeDue(true, true, true, 7));
    CHECK(!liveProbeDue(true, true, false, 1));
    CHECK(!liveProbeDue(true, true, false, 14));
    CHECK(liveProbeDue(true, true, false, 15));
    CHECK(liveProbeDue(true, true, false, 30));
    CHECK(!liveProbeDue(false, true, true, 15));
    CHECK(!liveProbeDue(true, false, true, 15));
    CHECK(kBackgroundProbeEveryTicks == 15);
    // Синк трафика: на экране — как настроено (дефолт 5 тиков ≈ 20 с), в фоне — не чаще ~5 мин
    // (expiry всё равно режет сервер; клиенту — только бейдж).
    CHECK(trafficSyncTicks(5, true) == 5);
    CHECK(trafficSyncTicks(5, false) == kBackgroundTrafficSyncTicks);
    CHECK(kBackgroundTrafficSyncTicks == 75);
    CHECK(trafficSyncTicks(200, false) == 200); // сервер просит реже — не учащаем
}

static void wave3StartAndLossPolicy()
{
    // Волна-3 (2026-09-28): попытка старта без физического аплинка не считается — ждём сеть.
    // Исчерпание попыток при живой сети — не снятие намерения, а пауза с ростом 30/60/120 с.
    // Классификация обрыва (вместо голого «внешний / не внешний»).
    CHECK(classifyLoss(/*weOperate=*/true, QStringLiteral("connected"), false, false, true) == LossClass::Own);
    CHECK(classifyLoss(false, QStringLiteral("switching"), false, false, true) == LossClass::Own);
    CHECK(classifyLoss(false, QStringLiteral("connected"), /*interrupted=*/true, false, true) == LossClass::Own);
    CHECK(classifyLoss(false, QStringLiteral("connected"), false, /*componentLost=*/true, true) == LossClass::Component);
    CHECK(classifyLoss(false, QStringLiteral("connected"), false, false, /*uplinkUp=*/false) == LossClass::NoNetwork);
    CHECK(classifyLoss(false, QStringLiteral("connected"), false, false, true) == LossClass::External);
    CHECK(classifyLoss(false, QStringLiteral("error"), false, false, true) == LossClass::External);
    // Только External снимает намерение (§13); остальные классы держат его.
    CHECK(lossDropsIntent(LossClass::External));
    CHECK(!lossDropsIntent(LossClass::Own));
    CHECK(!lossDropsIntent(LossClass::Component));
    CHECK(!lossDropsIntent(LossClass::NoNetwork));
    // Сторож §16: демон ответил на status (эхо байтов) → остаёмся в Reconnecting и перевзводим
    // (не больше 3 раз), не ответил → демон мёртв → честный Disconnected.
    CHECK(decideReconnectWatchdog(/*daemonAnswered=*/true, /*rearms=*/0) == ReconnectWatchdog::Rearm);
    CHECK(decideReconnectWatchdog(true, 2) == ReconnectWatchdog::Rearm);
    CHECK(decideReconnectWatchdog(true, 3) == ReconnectWatchdog::ForceDisconnectedAlive);
    CHECK(decideReconnectWatchdog(false, 0) == ReconnectWatchdog::ForceDisconnectedDead);
}

static void wave4UpstreamBehaviour()
{
    // P1-4 (revised 2026-11-04): the tap does what the orb shows. Args: engineConnected, busy,
    // wantConnected, ownStopping, ownOpInFlight, preparingStart, liveSessionPending.
    CHECK(decideOrbTap(false, false, false, false, false, false, false) == OrbTap::Start); // "Connect"
    // F1 (round 2): the wait for the network is a pending state - a tap is a Stop, never a new walk without a network
    CHECK(decideOrbTap(false, false, true, false, false, false, false) == OrbTap::Start);  // before: the wait read as idle
    CHECK(decideOrbTap(false, false, true, false, false, false, false, /*waitingUplink=*/true) == OrbTap::Stop);
    CHECK(decideOrbTap(false, false, false, false, false, false, false, true) == OrbTap::Start); // intent off: nothing waits
    CHECK(decideOrbTap(false, true, false, true, true, false, false, true) == OrbTap::StopAgain); // a stop in flight wins
    CHECK(decideOrbTap(false, true, true, false, false, false, true) == OrbTap::Ignore);   // "Checking…", status not yet in
    CHECK(decideOrbTap(true, true, true, false, false, false, true) == OrbTap::Ignore);    // still pending while busy
    // Tap 1 s after adoption with the orb showing "Connected" stops (the old 2.5 s grace swallowed it;
    // a dead data path is still "Connected" on the orb).
    CHECK(decideOrbTap(true, false, true, false, false, false, false) == OrbTap::Stop);
    CHECK(decideOrbTap(false, true, true, false, false, true, false) == OrbTap::Stop);    // cancel our own start preparation
    CHECK(decideOrbTap(false, true, true, false, true, true, true) == OrbTap::Stop);      // our op in flight: stop is legitimate
    CHECK(decideOrbTap(false, true, true, false, false, false, false) == OrbTap::Stop);   // "Connecting…" (upstream: in progress -> close)
    // A second tap during our own stop ("Disconnecting…") never restarts the tunnel (device journals:
    // pinned_location_ready + NE start 0.2-1.0 s after guarded_stop why=user); it re-issues the stop.
    CHECK(ownStopInFlight(false, true, false));
    CHECK(ownStopInFlight(false, false, true));   // stop retry pending: still our stop
    CHECK(!ownStopInFlight(true, true, false));   // a start() during our stop: not "Disconnecting…"
    CHECK(decideOrbTap(false, true, false, ownStopInFlight(false, true, true), true, false, false) == OrbTap::StopAgain);
    CHECK(decideOrbTap(true, true, false, true, false, false, false) == OrbTap::StopAgain);
    // Observed foreign Connecting with intent off (tunnel started from Settings / by the system, or a
    // redeem flow keeps busy): not our stop, the label is not "Disconnecting…", the tap starts.
    CHECK(!ownStopInFlight(false, false, false));
    CHECK(decideOrbTap(false, true, false, ownStopInFlight(false, false, false), false, false, false) == OrbTap::Start);
    CHECK(QByteArray(orbTapName(OrbTap::StopAgain)) == "stop_again");
    CHECK(QByteArray(orbTapName(OrbTap::Ignore)) == "ignored");
    // P1-5: сторож старта ждёт натив, пока тот сообщает живую сессию, но не дольше 4 перевзводов.
    // P2-2: классификация отказа API.
    const qint64 now = 1'000'000;
    CHECK(classifyApiOutcome(200, false, false, now - 100, -1, -1, now) == ApiOutcome::Success);
    CHECK(classifyApiOutcome(401, false, false, now - 100, -1, -1, now) == ApiOutcome::Success); // вход жив
    CHECK(classifyApiOutcome(0, true, false, now - 100, -1, -1, now) == ApiOutcome::Ignore);     // наш abort (регресс 126)
    CHECK(classifyApiOutcome(0, true, true, now - 16000, -1, -1, now) == ApiOutcome::Failure);  // таймаут — честный отказ
    CHECK(classifyApiOutcome(0, false, false, now - 100, -1, -1, now) == ApiOutcome::Failure);  // сокет не подключился
    CHECK(classifyApiOutcome(503, false, false, now - 100, -1, -1, now) == ApiOutcome::Failure); // 5xx = шагнуть
    CHECK(classifyApiOutcome(0, true, true, now - 20000, now - 1000, -1, now) == ApiOutcome::Ignore); // начат до разморозки
    CHECK(classifyApiOutcome(0, true, true, now - 16000, -1, now - 3000, now) == ApiOutcome::Ignore); // рядом со своим переходом
    CHECK(classifyApiOutcome(0, true, true, now - 16000, -1, now - 9000, now) == ApiOutcome::Failure); // окно вышло
    // One owner of "the API path changed" (android5 H1/H3, review R1 of 5c354b603): a new API generation on a real
    // transition and on every Connected (where upstream cleared); never on a first non-Connected status or a repeat.
    {
        const auto gen = [](ObservedTunnel p, ObservedTunnel n) { return newApiGeneration(p, n); };
        CHECK(gen(ObservedTunnel::Transitional, ObservedTunnel::Connected));  // tunnel up
        CHECK(gen(ObservedTunnel::Disconnected, ObservedTunnel::Connected));
        CHECK(gen(ObservedTunnel::Connected, ObservedTunnel::Disconnected));  // tunnel down
        CHECK(gen(ObservedTunnel::Transitional, ObservedTunnel::Disconnected));
        CHECK(!gen(ObservedTunnel::Unknown, ObservedTunnel::Disconnected));   // cold start, tunnel off
        CHECK(gen(ObservedTunnel::Unknown, ObservedTunnel::Connected));       // adoption
        CHECK(gen(ObservedTunnel::Connected, ObservedTunnel::Connected));     // repeat
        CHECK(!gen(ObservedTunnel::Connected, ObservedTunnel::Transitional));
        CHECK(!gen(ObservedTunnel::Disconnected, ObservedTunnel::Disconnected));
    }
    CHECK(reissueAfterOwnAbort(true, false));   // our abort on a transition -> re-issue once
    CHECK(!reissueAfterOwnAbort(true, true));   // our 15 s timeout -> no
    CHECK(!reissueAfterOwnAbort(false, false)); // answered / failed by the network -> no
    // 5.1.108: ONLINE without node_scan - the live in-tunnel probe proves data; whoami only
    // accelerates (works) or forbids (no_data / bypass); a confirmed dead probe always forbids.
    CHECK(!dataFlowingNow(true, false, QString(), LiveProof::None));                      // nothing proven yet
    CHECK(dataFlowingNow(true, false, QString(), LiveProof::Proven));                     // flag off, live probe ok
    CHECK(dataFlowingNow(true, false, QStringLiteral("works"), LiveProof::None));         // whoami first
    CHECK(dataFlowingNow(true, false, QStringLiteral("limited"), LiveProof::Proven));     // limited + live probe
    CHECK(!dataFlowingNow(true, false, QStringLiteral("limited"), LiveProof::None));
    CHECK(!dataFlowingNow(true, false, QStringLiteral("no_data"), LiveProof::Proven));    // whoami forbids
    CHECK(!dataFlowingNow(true, false, QStringLiteral("bypass"), LiveProof::Proven));
    CHECK(!dataFlowingNow(true, true, QStringLiteral("works"), LiveProof::Proven));       // dead live probe
    CHECK(!dataFlowingNow(false, false, QStringLiteral("works"), LiveProof::Proven));     // tunnel not up
    // 5.1.108: the iOS uplink fallback answers "physical path known" strictly (§25 stop input).
    CHECK(fallbackPhysicalUp(UplinkReach::Online, UplinkMedium::WiFi));
    CHECK(fallbackPhysicalUp(UplinkReach::Site, UplinkMedium::Cellular));
    CHECK(!fallbackPhysicalUp(UplinkReach::Unknown, UplinkMedium::WiFi));      // backend cannot tell
    CHECK(!fallbackPhysicalUp(UplinkReach::Disconnected, UplinkMedium::WiFi));
    CHECK(!fallbackPhysicalUp(UplinkReach::Online, UplinkMedium::Unknown));    // e.g. only our utun
    CHECK(!fallbackPhysicalUp(UplinkReach::Online, UplinkMedium::Bluetooth));
    // Decision 2026-11-05: /v1/subscription per-edge streak classification (QNetworkReply errors).
    CHECK(classifySubscriptionEdgeOutcome(0, false, now - 100, -1, -1, now) == SubscriptionEdgeOutcome::Delivered);
    CHECK(classifySubscriptionEdgeOutcome(204, false, now - 100, -1, -1, now) == SubscriptionEdgeOutcome::Delivered); // 401
    CHECK(classifySubscriptionEdgeOutcome(401, false, now - 100, -1, -1, now) == SubscriptionEdgeOutcome::Delivered); // 500
    CHECK(classifySubscriptionEdgeOutcome(5, true, now - 15000, -1, -1, now) == SubscriptionEdgeOutcome::Failure);   // our timeout
    CHECK(classifySubscriptionEdgeOutcome(2, false, now - 3000, -1, -1, now) == SubscriptionEdgeOutcome::Failure);   // body cut
    CHECK(classifySubscriptionEdgeOutcome(399, false, now - 3000, -1, -1, now) == SubscriptionEdgeOutcome::Failure); // protocol
    CHECK(classifySubscriptionEdgeOutcome(5, false, now - 100, -1, -1, now) == SubscriptionEdgeOutcome::Ignore);     // our abort
    CHECK(classifySubscriptionEdgeOutcome(5, true, now - 20000, now - 1000, -1, now) == SubscriptionEdgeOutcome::Ignore); // freeze
    CHECK(classifySubscriptionEdgeOutcome(5, true, now - 16000, -1, now - 3000, now) == SubscriptionEdgeOutcome::Ignore); // transition
    // P2-3: эффекты Connected — только новая сессия и только на экране.
    CHECK(decideConnectEffects(false, -1, true) == ConnectEffects::RunNow);
    CHECK(decideConnectEffects(true, 60000, true) == ConnectEffects::Skip);      // та же нода, минуту назад
    CHECK(decideConnectEffects(true, kConnectEffectsRepeatMs, true) == ConnectEffects::RunNow);
    CHECK(decideConnectEffects(false, 1000, false) == ConnectEffects::Defer);    // новая нода, экран в фоне
    // P1-6: липкий запрос рестарта старше 2 минут сбрасывается.
    CHECK(!restartRequestStale(now - 5000, now));
    CHECK(restartRequestStale(now - kRestartRequestTtlMs - 1, now));
    CHECK(!restartRequestStale(-1, now));
    // P1-5: give-up свитча — поднятый/переходный туннель гасим (намерение держим), лежачий — бэкофф.
    // P2-6: своё событие сети.
    CHECK(networkChangeIsOwnTunnel(true, -1, now));
    CHECK(networkChangeIsOwnTunnel(false, now - 2000, now));
    CHECK(!networkChangeIsOwnTunnel(false, now - 6000, now));
    CHECK(!networkChangeIsOwnTunnel(false, -1, now));
    // Scanner notices (coordinator 18.11 (c), device round air9 19.11 10:08, device round 11 iPhone Air 20.11 13:05):
    // another network = a new generation or a new cache identity (the physical network); the reporting key moving
    // alone (the access ASN a row's seat grant names) is the same network refined; nothing new - no notice.
    {
        using N = ScanNetNotice;
        const QString x = QStringLiteral("wifi|wifi:5f3a00c1b2d4|"), xGw = QStringLiteral("wifi|wifi:5f3a00c1b2d4|a1b2c3d4e5f60718");
        const QString y = QStringLiteral("wifi|wifi:0d9e77a1c3f0|"), air = QStringLiteral("unknown|wifi:5f3a00c1b2d4|");
        const QString bare = QStringLiteral("wifi"), asn = QStringLiteral("wifi:asn:64500");
        CHECK(scanNetworkNotice(3, 4, x, x, bare, bare) == N::Changed);       // the engine's generation moved
        CHECK(scanNetworkNotice(4, 4, x, xGw, bare, bare) == N::Changed);     // the identity completed, the same generation (air9)
        CHECK(scanNetworkNotice(4, 4, x, x, bare, bare) == N::None);          // our own tunnel up / a path event: nothing physical
        CHECK(scanNetworkNotice(4, 4, x, x, bare, asn) == N::Refined);        // the row connect's grant named the ASN: no new network
        CHECK(scanNetworkNotice(4, 4, x, x, asn, bare) == N::Refined);        // ... and an older answer the other way: still none
        CHECK(scanNetworkNotice(4, 4, QString(), x, QString(), bare) == N::Changed); // the Scanner never got a notice
        CHECK(scanNetworkNotice(4, 5, x, y, asn, asn) == N::Changed);         // another Wi-Fi of the same operator
        CHECK(scanNetworkNotice(5, 5, x, air, asn, QStringLiteral("unknown")) == N::Changed); // airplane mode
        CHECK(scanNetworkNotice(5, 5, air, x, QStringLiteral("unknown"), asn) == N::Changed); // ... and back on X
    }
    // The generation those notices compare is the path engine's (path/NetworkKey.h NetworkTracker): physical facts
    // only - the ASN learned later, the medium unknown while a VPN is up (iOS) - our own tunnel never bumps it.
    {
        using namespace avpn::path;
        NetworkTracker t;
        NetworkObservation x;
        x.medium = NetMedium::Wifi;
        x.subnet = QStringLiteral("192.168.1.0/24");
        CHECK(t.observe(x));
        const quint64 g = t.current().generation;
        NetworkObservation xAsn = x;
        xAsn.asn = 64500;
        CHECK(!t.observe(xAsn) && t.current().generation == g);   // the ASN learned on the same network
        CHECK(!t.observe(NetworkObservation()) && t.current().generation == g); // Unknown medium (our VPN up, airplane)
        CHECK(!t.observe(x) && t.current().generation == g);
        NetworkObservation y = x;
        y.subnet = QStringLiteral("10.0.0.0/24");
        CHECK(t.observe(y) && t.current().generation == g + 1);   // another Wi-Fi
        NetworkObservation cell;
        cell.medium = NetMedium::Cellular;
        cell.radio = QStringLiteral("lte");
        CHECK(t.observe(cell) && t.current().generation == g + 2); // Wi-Fi -> LTE
        CHECK(t.observe(x) && t.current().generation == g + 3);    // LTE -> Wi-Fi X
    }
    // ScanNetworkNotifier (review of 3d3cdc686): the Scanner never reads its identity from a path engine that has not
    // been told the platform network now. The host: ServiceEngine's tracker (its constructor's "unknown" placeholder),
    // the platform's reading, the Scanner's facts as ScanEngineAdapter::network() builds them (kind from the platform,
    // the physical network from the tracker).
    {
        using namespace avpn::path;
        struct Host {
            NetworkTracker t;
            NetworkObservation platform;
            bool scannerOn = false;
            int notified = 0;
            QString told;     // the identity the Scanner was handed (what read() gave)
            QString lastRead;
            QStringList journal;
            ScanNetworkNotifier n;
            QString identity() const
            {
                const QString kind = platform.medium == NetMedium::Wifi ? QStringLiteral("wifi")
                                     : platform.medium == NetMedium::Cellular ? QStringLiteral("cellular") : QStringLiteral("unknown");
                return kind + QLatin1Char('|') + t.current().local + QLatin1Char('|');
            }
            Host()
            {
                t.observe(NetworkObservation()); // ServiceEngine(): "unknown" until the platform tells the network
                n.generation = [this]() { return t.current().generation; };
                n.observe = [this]() { t.observe(platform); };
                n.read = [this]() {
                    ScanNetRead r;
                    if (!scannerOn)
                        return r;
                    r.scannerOn = true;
                    r.identity = identity();
                    lastRead = r.identity;
                    r.report = QStringLiteral("wifi");
                    return r;
                };
                n.notify = [this]() { ++notified; told = lastRead; };
                n.journal = [this](const QString &l) { journal << l; };
            }
        };
        NetworkObservation x;
        x.medium = NetMedium::Wifi;
        x.subnet = QStringLiteral("192.168.1.0/24");
        NetworkObservation y = x;
        y.subnet = QStringLiteral("10.0.0.0/24");
        // (control) the defect without the one notice: a host that never emits a first event (Windows' QNetworkInformation
        // published it before we subscribed) - the Scanner reads the placeholder, the first connect observes, and the list
        // scanned under the placeholder is "another network" (device round 11 by another door)
        {
            Host h;
            h.platform = x;
            h.scannerOn = true;
            const QString scanned = h.identity();
            CHECK(scanned.contains(QLatin1String("|unknown|")));
            h.t.observe(h.platform); // the connect's observation (AvpnEngineQml::guardedStart)
            CHECK(h.identity() != scanned);
        }
        // (A, B) the same host with the start-up notice: told before the Scanner exists; a scan, a connect and our own
        // tunnel's notice leave the identity and the generation as they were - the list stays
        {
            Host h;
            h.platform = x;
            h.n.notice(); // the engine's constructor, right after subscribing; no Scanner yet
            CHECK(h.t.current().local == localNetworkKey(x));
            CHECK(h.notified == 0);
            h.scannerOn = true;
            h.n.noticeAfresh(); // the Scanner attached and switched on
            CHECK(h.notified == 1);
            const QString scanned = h.identity();
            CHECK(h.told == scanned);
            const quint64 g = h.t.current().generation;
            h.t.observe(h.platform); // the row's connect
            h.n.notice();            // our own tunnel came up: a platform notice
            CHECK(h.identity() == scanned && h.t.current().generation == g && h.notified == 1);
            CHECK(!h.journal.isEmpty() && h.journal.last() == QStringLiteral("scan_network_unchanged net_gen=%1").arg(g));
            h.platform = y; // a real change still reaches it
            h.n.notice();
            CHECK(h.notified == 2 && h.told.contains(localNetworkKey(y)) && h.t.current().generation == g + 1);
        }
        // (C) the first platform notice comes while the Scanner is off (its switches come with the config): the path
        // engine is told anyway; then the facts change with no notice at all (iOS: the app's path monitor is hooked only
        // with the Scanner) - switching on observes first and tells the Scanner the network as it is then
        {
            Host h;
            h.platform = NetworkObservation(); // iOS before the first path-monitor update: the medium unknown
            h.n.notice();                      // start-up
            CHECK(h.t.current().local == QStringLiteral("unknown"));
            h.platform = x;
            h.n.notice(); // QNetworkInformation's first event, the Scanner still off
            CHECK(h.t.current().local == localNetworkKey(x));
            CHECK(h.notified == 0);
            h.platform = y; // the path monitor's update: no notice reaches anybody
            h.scannerOn = true;
            h.n.noticeAfresh();
            CHECK(h.notified == 1 && h.told == h.identity() && h.told.contains(localNetworkKey(y)));
        }
    }
    // P2-4: координатор выхода на экран.
    CHECK(foregroundIsReturn(true, 0));                       // была заморозка/скрытие
    CHECK(!foregroundIsReturn(false, 3000));                  // Пункт управления: 3 с Inactive
    CHECK(foregroundIsReturn(false, 120000));                 // десктоп: 2 мин в браузере
    const ForegroundPlan fresh = planForeground(-1, -1);
    CHECK(fresh.refreshSubscription && fresh.refreshConfig);
    const ForegroundPlan soon = planForeground(5000, 60000);
    CHECK(!soon.refreshSubscription && !soon.refreshConfig);
    const ForegroundPlan later = planForeground(40000, kFgConfigThrottleMs);
    CHECK(later.refreshSubscription && later.refreshConfig);
    // Волна-4: потеря компонента объясняет только ближайший обрыв.
    CHECK(componentLossFresh(true, now - 1000, now));
    CHECK(!componentLossFresh(true, now - 60000, now));
    CHECK(!componentLossFresh(false, now - 1000, now));
    // Round mac-D3: an Xray session that lost its service reports Disconnected, then Error - one drop, both explained;
    // the next start ends the drop.
    bool mark = true;
    CHECK(componentLossExplains(mark, now - 100, now, /*terminal=*/true, /*starts=*/false)); // Disconnected
    CHECK(componentLossExplains(mark, now - 100, now + 8, true, false));                     // Error 603, 8 ms later
    CHECK(mark);
    CHECK(!componentLossExplains(mark, now - 100, now + 500, false, /*starts=*/true) && !mark); // the reconnect starts
    CHECK(!componentLossExplains(mark, now - 100, now + 5000, true, false)); // a later drop is not this loss
    mark = true; // AmneziaWG: the daemon loss ends with one Disconnected, the reconnect consumes the mark
    CHECK(componentLossExplains(mark, now - 100, now, true, false));
    CHECK(!componentLossExplains(mark, now - 100, now + 900, false, true) && !mark);
    mark = true; // no start after the drop (intent off elsewhere): the mark expires with its bound
    CHECK(componentLossExplains(mark, now - 100, now, true, false));
    CHECK(!componentLossExplains(mark, now - 100, now + 60000, true, false));
}

static void a12Outbox()
{
    const QByteArray ack = "{\"id\":\"8f14e45f-ceea-4e7a-9b1c-2d3e4f5a6b7c\"}";
    CHECK(classifyReportResponse(201, true, ack) == ReportOutcome::Delivered);
    CHECK(classifyReportResponse(400, false, {}) == ReportOutcome::DropTerminal);
    CHECK(classifyReportResponse(404, false, {}) == ReportOutcome::DropTerminal);
    CHECK(classifyReportResponse(413, false, {}) == ReportOutcome::DropTerminal);
    CHECK(classifyReportResponse(408, false, {}) == ReportOutcome::Retry);
    CHECK(classifyReportResponse(429, false, {}) == ReportOutcome::Retry);
    CHECK(classifyReportResponse(401, false, {}) == ReportOutcome::Retry);
    CHECK(classifyReportResponse(503, false, {}) == ReportOutcome::Retry);
    CHECK(classifyReportResponse(0, false, {}) == ReportOutcome::Retry);
    CHECK(classifyReportResponse(200, true, "{}") == ReportOutcome::Retry); // без квитанции
    CHECK(outboxConnectedFlushDue(-1, 1000));
    CHECK(!outboxConnectedFlushDue(1000, 1000 + 599999));
    CHECK(outboxConnectedFlushDue(1000, 1000 + 600000));
}

static void a16ReliabilityRingCollapse()
{
    ReliabilityRing ring;
    appendReliabilityEvent(ring, QStringLiteral("t1 "), QStringLiteral("native_state=5"), 4);
    for (int i = 2; i <= 50; ++i)
        appendReliabilityEvent(ring, QStringLiteral("t%1 ").arg(i), QStringLiteral("status_timeout"), 4);
    CHECK(ring.lines.size() == 2); // 49 повторов — одна строка, кольцо не вымыто
    CHECK(ring.lines.first() == QLatin1String("t1 native_state=5"));
    CHECK(ring.lines.last() == QLatin1String("t2 status_timeout [x49 last=t50 ]"));
    appendReliabilityEvent(ring, QStringLiteral("t51 "), QStringLiteral("path_change"), 4);
    appendReliabilityEvent(ring, QStringLiteral("t52 "), QStringLiteral("status_timeout"), 4);
    CHECK(ring.lines.size() == 4 && ring.lines.last() == QLatin1String("t52 status_timeout"));
    appendReliabilityEvent(ring, QStringLiteral("t53 "), QStringLiteral("x"), 4);
    CHECK(ring.lines.size() == 4 && ring.lines.first() == QLatin1String("t2 status_timeout [x49 last=t50 ]"));
}

// Критик полноты GAP-1 (U1, жалоба 1 «сами перекидываются ноды»): Доктор пробует альтернативы и
// пересаживает только при проблеме самой ноды. Раньше триггер — doctor::hasProblem (любой Warn/Bad).
static void gap1DoctorNodeProblem()
{
    using namespace doctor;
    const StageResult net = networkStage(0, QStringLiteral("wifi"), QString(), 0, 0, 0, QString(), 1);
    const StageResult conOk = connectStage(true, true, 5);
    const StageResult conBad = connectStage(true, false, 200);
    const StageResult srvOk = serverStage(QStringLiteral("Эстония"), QStringLiteral("EE"), 60);
    const StageResult srvFar = serverStage(QStringLiteral("США"), QStringLiteral("US"), 900);
    const StageResult svcOk = servicesStage(4, 4, {}, false, false);
    const StageResult svcBad = servicesStage(2, 4, {QStringLiteral("YouTube")}, false, false);
    const StageResult svcWl = servicesStage(0, 4, {}, true, true);
    const StageResult spdNoVpn = speedStage(2.0, 40, 60, false, 1.5); // «медленно и без VPN»
    const StageResult ruWarn = ruSplitStage({QStringLiteral("Госуслуги"), QStringLiteral("Ozon")},
                                            {false, true});

    // rusplit=Warn (и «без VPN»), connect/services=Ok: на старом триггере — проблема (Доктор
    // пересаживал рабочую EE на US), на новом — нет: альтернативы не пробуются, пин не меняется.
    const QList<StageResult> rusplitOnly{net, conOk, srvOk, svcOk, spdNoVpn, ruWarn};
    CHECK(ruWarn.status == Warn && spdNoVpn.status == Warn);
    CHECK(hasProblem(rusplitOnly));                        // старый триггер: «проблема»
    CHECK(!doctorNodeProblem(rusplitOnly, 40, 150));
    CHECK(!doctorNodeProblem(rusplitOnly, 40, 10));        // даже при более быстрой альтернативе
    CHECK(!doctorDataPlaneProblem(rusplitOnly));

    // data-plane Bad на текущей ноде — проблема, независимо от RTT.
    CHECK(doctorNodeProblem(QList<StageResult>{net, conBad, srvOk, svcOk}, 40, -1));
    CHECK(doctorNodeProblem(QList<StageResult>{net, conOk, srvOk, svcBad}, 40, 150));
    // «белые списки» оператора — не проблема ноды (другая нода их не обойдёт).
    CHECK(svcWl.status == Bad);
    CHECK(!doctorNodeProblem(QList<StageResult>{net, conOk, srvOk, svcWl}, 40, 10));

    // «далеко»: только если альтернатива быстрее не менее чем на 30 %.
    const QList<StageResult> far{net, conOk, srvFar, svcOk};
    CHECK(srvFar.status == Warn);
    CHECK(doctorNodeProblem(far, 900, 630));               // ровно 30 %
    CHECK(!doctorNodeProblem(far, 900, 631));              // хуже порога — нет
    CHECK(!doctorNodeProblem(far, 900, -1));               // альтернатива не измерена — нет
    CHECK(!doctorNodeProblem(far, -1, 100));               // текущая не измерена — нет
    CHECK(doctorAltRttBetterEnough(200, 140) && !doctorAltRttBetterEnough(200, 141));
}

// Критик полноты GAP-4 (U10, жалоба 2 «сам выключается»): отчёты Доктора/краша несут журнал свитчей
// и кольцо reliability (кто гасил: guarded_stop why=...), хвост в пределах байтового капа.
static void gap4ReportReliabilityContext()
{
    ReliabilityRing ring;
    for (int i = 0; i < 100; ++i)
        appendReliabilityEvent(ring, QStringLiteral("t%1 ").arg(i),
                               QStringLiteral("native_state=%1").arg(i % 7), 128);
    appendReliabilityEvent(ring, QStringLiteral("t100 "),
                           QStringLiteral("switch_deadline cause=deadline_down attempts=1"), 128);
    appendReliabilityEvent(ring, QStringLiteral("t101 "),
                           QStringLiteral("guarded_stop why=switch_deadline native=4 intent_on=1 "
                                          "engine=error keep_switch=1"), 128);
    const QStringList switchLog{QStringLiteral("switch 9→9: dead (re-up same node)"),
                                QStringLiteral("switch interrupted (deadline_down): retry 9")};
    QJsonObject extra;
    extra.insert(QStringLiteral("doctor_mode"), QStringLiteral("quick"));
    attachReliabilityContext(extra, switchLog, ring.lines, 4096, 256);
    const QJsonObject report = doctor::buildReport({doctor::connectStage(true, true, 3)}, extra);
    const QJsonObject ex = report.value(QStringLiteral("extra")).toObject();
    const QJsonArray sw = ex.value(QStringLiteral("switch_log")).toArray();
    const QJsonArray rr = ex.value(QStringLiteral("reliability_ring")).toArray();
    CHECK(sw.size() == 2 && sw.last().toString().contains(QLatin1String("deadline_down")));
    CHECK(!rr.isEmpty());
    CHECK(rr.last().toString().contains(QLatin1String("guarded_stop why=switch_deadline")));
    int bytes = 0;
    for (const auto &v : rr)
        bytes += v.toString().toUtf8().size() + 1;
    CHECK(bytes <= 256);                                   // кап по байтам: хвост, а не всё кольцо
    CHECK(rr.size() < ring.lines.size());
    // краш-отчёт: верхний уровень объекта
    QJsonObject crash;
    crash.insert(QStringLiteral("type"), QStringLiteral("crash"));
    attachReliabilityContext(crash, {}, ring.lines);
    CHECK(crash.contains(QStringLiteral("switch_log")) && crash.contains(QStringLiteral("reliability_ring")));
    CHECK(crash.value(QStringLiteral("reliability_ring")).toArray().size() == ring.lines.size());
    CHECK(tailWithinBytes({QStringLiteral("0123456789")}, 5).isEmpty());
}

static void a5HintedCardRow()
{
    // Жалоба владельца 2026-09-23: Connected, VPN работает, карточка «Умный выбор сервера» —
    // адопт с неизвестной identity. Карточка берёт ноду пула по подсказке сессии.
    CHECK(endpointHost(QStringLiteral("38.180.164.134:585")) == QStringLiteral("38.180.164.134"));
    CHECK(endpointHost(QStringLiteral("[2a01:4f9::1]:585")) == QStringLiteral("2a01:4f9::1"));
    CHECK(endpointHost(QStringLiteral("host")) == QStringLiteral("host"));
    QList<NodeDebugRow> pool;
    NodeDebugRow ee; ee.nodeId = QStringLiteral("9"); ee.region = QStringLiteral("Estonia");
    ee.endpoint = QStringLiteral("38.180.164.134:585");
    NodeDebugRow us; us.nodeId = QStringLiteral("10"); us.region = QStringLiteral("USA");
    us.endpoint = QStringLiteral("149.33.7.203:585");
    pool << ee << us;
    // та же нода по id (сменился только порт/протокол)
    CHECK(hintedPoolRow(pool, QStringLiteral("10"), QStringLiteral("149.33.7.203:443")) == 1);
    // нода пересоздана с новым id на том же сервере — по хосту
    CHECK(hintedPoolRow(pool, QStringLiteral("5"), QStringLiteral("38.180.164.134:51820")) == 0);
    // сервера больше нет в пуле — -1 (карточка покажет адрес сессии, а не «Умный выбор»)
    CHECK(hintedPoolRow(pool, QStringLiteral("3"), QStringLiteral("79.110.48.13:585")) == -1);
    // пустая подсказка — ничего не подбираем
    CHECK(hintedPoolRow(pool, QString(), QString()) == -1);
}

// ── AVPN Scanner (lane L6b; CONNECT-INVARIANTS §32; plan scanner-client-plan.md §2.12) ──────────────────
// The engine's half of the three tunnel paths. Every block names the rule it pins; the mutation pass of the
// lane breaks each rule once and this file must fail.

// Review F4: a row tapped with the VPN off must CONNECT (the picker's tap only stores the target).
static void scannerRowTapConnectsWithVpnOff()
{
    const ScannerRowConnect rc = scannerRowConnect(/*tunnelUpOrComingUp=*/false);
    CHECK(rc.userStartBookkeeping); // start()'s bookkeeping first: intent on, fresh attempts, no pause
    CHECK(rc.forceConnect);
    CHECK(rc.userOrigin);
    // Composed with the existing intent rule of pinAndReconnectImpl: down + force = connect, no restart.
    const PinReconnectIntent in = pinReconnectIntent(/*tunnelUp=*/false, rc.forceConnect);
    CHECK(in.wantConnected);
    CHECK(!in.needsRestart);
    // Control: the picker's tap (force false) with the VPN off only stores the target - the F4 defect if
    // the Scanner had used pinAndReconnect().
    const PinReconnectIntent picker = pinReconnectIntent(false, false);
    CHECK(!picker.wantConnected);
    CHECK(!picker.needsRestart);
    // The picker's kill switch never turns a forced connect into "select only".
    CHECK(!pinReconnectSelectOnly(rc.forceConnect, /*instantReconnectOn=*/false));
    CHECK(pinReconnectSelectOnly(false, false));
    CHECK(!pinReconnectSelectOnly(false, true));
}

// VPN on: the row tap is the ordinary move (reconcile restart), without start()'s bookkeeping.
static void scannerRowTapMovesLiveTunnel()
{
    const ScannerRowConnect rc = scannerRowConnect(/*tunnelUpOrComingUp=*/true);
    CHECK(!rc.userStartBookkeeping);
    CHECK(rc.forceConnect);
    CHECK(rc.userOrigin);
    const PinReconnectIntent in = pinReconnectIntent(true, rc.forceConnect);
    CHECK(in.wantConnected);
    CHECK(in.needsRestart);
    // Same as the picker's tap on a live tunnel (unchanged behaviour of 2026-07-10).
    const PinReconnectIntent picker = pinReconnectIntent(true, false);
    CHECK(picker.wantConnected && picker.needsRestart);
    CHECK(decideScanRowConnect(true, QStringLiteral("9:xray")) == ScanRowGate::Connect);
    CHECK(decideScanRowConnect(true, QStringLiteral(" ")) == ScanRowGate::IgnoreNoNode);
    CHECK(decideScanRowConnect(false, QStringLiteral("9")) == ScanRowGate::IgnoreSwitchOff);
}

// Switches absent (the server switch v1_scanner off) = the Scanner does not exist; defaults as published.
static void scannerSwitchesAbsentIsToday()
{
    const auto from = [](const QMap<QString, bool> &m) {
        return scannerSwitchesFrom([&m](const QString &k, bool d) { return m.contains(k) ? m.value(k) : d; }, true);
    };
    const ScannerSwitches none = from({});
    CHECK(!none.scanner);
    CHECK(!none.returnHome);
    CHECK(!none.doctorLegacy);
    CHECK(!none.connectOnOpen); // with the Scanner absent there is nothing to connect for
    CHECK(!none.awgMini);
    CHECK(none.doctorSheet);    // the old Doctor sheet stays reachable as today
    CHECK(none == ScannerSwitches());
    // Other keys without `scanner` change nothing.
    CHECK(from({{QStringLiteral("scanner_return_home"), true}, {QStringLiteral("doctor_legacy"), true},
                {QStringLiteral("scanner_connect_on_open"), true}, {QStringLiteral("scanner_awg_mini"), true}})
          == ScannerSwitches());
    CHECK(from({{QStringLiteral("scanner"), false}}) == ScannerSwitches());
    // scanner on, nothing else: stay in the Scanner, connect on open (compiled default), no AWG mini, the
    // Doctor merged into the Scanner (no old sheet).
    const ScannerSwitches on = from({{QStringLiteral("scanner"), true}});
    CHECK(on.scanner);
    CHECK(!on.returnHome);
    CHECK(!on.doctorLegacy);
    CHECK(on.connectOnOpen);
    CHECK(!on.awgMini);
    CHECK(!on.doctorSheet);
    const ScannerSwitches all = from({{QStringLiteral("scanner"), true}, {QStringLiteral("scanner_return_home"), true},
                                      {QStringLiteral("doctor_legacy"), true}, {QStringLiteral("scanner_connect_on_open"), false},
                                      {QStringLiteral("scanner_awg_mini"), true}});
    CHECK(all.returnHome && all.doctorLegacy && !all.connectOnOpen && all.awgMini && all.doctorSheet);
}

// The Scanner exists only where this build has a probe host (IScanHost.h kScanHostOnThisBuild; android1 D5, owner
// 16.11: Android shows no Scanner until its probe process ships). Without one every switch the server publishes reads
// off - no entry point, the Doctor sheet reachable, as with the server switch off.
static void scannerNeedsProbeHost()
{
    const QMap<QString, bool> all{{QStringLiteral("scanner"), true}, {QStringLiteral("scanner_return_home"), true},
                                  {QStringLiteral("doctor_legacy"), true}, {QStringLiteral("scanner_connect_on_open"), true},
                                  {QStringLiteral("scanner_awg_mini"), true}};
    const auto flag = [&all](const QString &k, bool d) { return all.contains(k) ? all.value(k) : d; };
    const ScannerSwitches noHost = scannerSwitchesFrom(flag, /*hostOnBuild=*/false);
    CHECK(noHost == ScannerSwitches());
    CHECK(!noHost.scanner && noHost.doctorSheet);
    CHECK(scannerSwitchesFrom(flag, true).scanner);
    CHECK(!scannerSwitchOn(true, false) && !scannerSwitchOn(false, true) && scannerSwitchOn(true, true));
#if defined(Q_OS_ANDROID) || defined(MACOS_NE)
    CHECK(!kScanHostOnThisBuild);
#else
    CHECK(kScanHostOnThisBuild); // iOS, macOS service build, Windows, Linux: unchanged
#endif
}

// Path (b): the ordinary start() only from VPN off, only where probes need the tunnel process.
static void scannerConnectOnOpen()
{
    CHECK(decideScanOpenConnect(true, /*hostNeedsVpn=*/true, /*want=*/false, /*up=*/false) == ScanOpenConnect::Start);
    CHECK(decideScanOpenConnect(false, true, false, false) == ScanOpenConnect::IgnoreSwitchOff);
    CHECK(decideScanOpenConnect(true, /*hostNeedsVpn=*/false, false, false) == ScanOpenConnect::IgnoreNoVpnNeeded); // macOS / Windows
    CHECK(decideScanOpenConnect(true, true, /*want=*/true, false) == ScanOpenConnect::IgnoreAlreadyOn);
    CHECK(decideScanOpenConnect(true, true, false, /*up=*/true) == ScanOpenConnect::IgnoreAlreadyOn);
    CHECK(QLatin1String(scanOpenConnectName(ScanOpenConnect::IgnoreAlreadyOn)) == QLatin1String("already_on"));
}

// Path (c): the ordinary stop() of the Scanner's OWN connect, only before «Подключено».
static void scannerCancelPendingConnect()
{
    const quint64 proc = 0x1234;
    const bool loop = true; // the app's event loop runs
    ScanOwnConnect a;
    // Nothing started by this machine: never a stop.
    CHECK(decideScanCancel(a, proc, 1, true, false, loop) == ScanCancel::IgnoreNoAttempt);
    a.id = 7;
    a.processEpoch = proc;
    a.intentSerial = 5;
    // Before «Подключено», the same attempt, the intent still on: the ordinary stop.
    CHECK(decideScanCancel(a, proc, 5, /*want=*/true, /*shownConnected=*/false, loop) == ScanCancel::Stop);
    // A cancel arriving after «Подключено»: ignored ...
    CHECK(decideScanCancel(a, proc, 5, true, /*shownConnected=*/true, loop) == ScanCancel::IgnoreAfterConnected);
    // ... and still ignored when the tunnel went Reconnecting later: «Подключено» once = never turned off.
    ScanOwnConnect latched = a;
    noteScanOwnConnectProgress(latched, /*shownConnectedNow=*/true);
    CHECK(latched.reachedConnected);
    CHECK(decideScanCancel(latched, proc, 5, true, /*shownConnected=*/false, loop) == ScanCancel::IgnoreAfterConnected);
    ScanOwnConnect notLatched = a;
    noteScanOwnConnectProgress(notLatched, false);
    CHECK(!notLatched.reachedConnected);
    // Relaunch: a record of another process (a stale flag) never cancels anything.
    CHECK(decideScanCancel(a, /*processEpoch=*/0x9999, 5, true, false, loop) == ScanCancel::IgnoreOtherProcess);
    // The user (or any other path) touched the intent after the Scanner's start: not the Scanner's any more.
    CHECK(decideScanCancel(a, proc, /*intentSerial=*/6, true, false, loop) == ScanCancel::IgnoreSuperseded);
    // Already stopped: nothing to cancel.
    CHECK(decideScanCancel(a, proc, 5, /*want=*/false, false, loop) == ScanCancel::IgnoreNotPending);
    CHECK(QLatin1String(scanCancelName(ScanCancel::IgnoreAfterConnected)) == QLatin1String("after_connected"));
}

// S1 (owner's iPhone, build 140, 16.11 22:53): AmneziaWG on node 17 reached «Подключено» while the API was
// unreachable - no /v1/ping, no whoami, so dataFlowing (ONLINE) stayed false - and a cancel 18 s later
// stopped it. «Подключено» is what the orb shows: engine Connected on a Connected tunnel.
static void scannerCancelAfterShownConnectedWithoutData()
{
    // The orb's «Подключено» without the data proof counts; paused, a tunnel not Connected or an engine
    // still connecting / verifying does not; the data proof alone counts as before.
    CHECK(scanShownConnected(/*paused=*/false, /*engineConnected=*/true, /*tunnelConnected=*/true, /*data=*/false));
    CHECK(!scanShownConnected(false, /*engineConnected=*/false, true, false));  // Connecting / Verifying
    CHECK(!scanShownConnected(false, true, /*tunnelConnected=*/false, false));  // native not Connected
    CHECK(!scanShownConnected(/*paused=*/true, true, true, false));
    CHECK(scanShownConnected(false, false, false, /*data=*/true));
    // The 22:53 sequence: start 22:53:32, Connected without data 22:53:40, cancel 22:53:58.
    ScanOwnConnect a;
    a.id = 1;
    a.processEpoch = 0x77;
    a.intentSerial = 3;
    noteScanOwnConnectProgress(a, scanShownConnected(false, false, false, false)); // connecting
    CHECK(!a.reachedConnected);
    noteScanOwnConnectProgress(a, scanShownConnected(false, true, true, /*data=*/false)); // «Подключено», no ONLINE
    CHECK(a.reachedConnected);
    CHECK(decideScanCancel(a, 0x77, 3, true, scanShownConnected(false, true, true, false), true)
          == ScanCancel::IgnoreAfterConnected);
    // Before the fix the rule saw only dataFlowing (false here) and answered Stop.
}

// S2 (same evening, 22:53:58): the person swiped the app away with the Scanner open. ~AmneziaApplication
// joined the VPN thread, then deleted the QML engine; the page's Component.onDestruction -> close() ->
// cancel -> stop(): the facade flipped to «disconnected», the queued disconnectFromVpn never ran and the
// tunnel stayed up. With no event loop running the Scanner cancels nothing - whatever the phase.
// The white-list detector's trigger from the attempt owner (it lived in the deleted start watchdog).
// R1 (device round 4): a failed data check is the path's only on the path's own evidence.
// B1 (race measurement 18.11): a stop during the race prelude has no native Disconnected to wait for.
// F2 (round 2): a Scanner row's request is one object with one lifetime.
static void exactRowRequestObject()
{
    using avpn::ExactRowRequest;
    ExactRowRequest none;
    CHECK(!none.active() && !none.exactFor(QStringLiteral("B")));
    const ExactRowRequest a = ExactRowRequest::begin(none, QStringLiteral("B"), QStringLiteral("A"), QStringLiteral("DE"), true);
    CHECK(a.active() && a.exactFor(QStringLiteral("B")) && !a.exactFor(QStringLiteral("A")));
    CHECK(a.restorePin == QLatin1String("A") && a.reconnect);
    // a second row while the first runs: the person's choice before the FIRST tap stays the one to come back to
    const ExactRowRequest c = ExactRowRequest::begin(a, QStringLiteral("C"), QStringLiteral("B"), QStringLiteral("FR"), false);
    CHECK(c.row == QLatin1String("C") && c.restorePin == QLatin1String("A") && c.reconnect);
    CHECK(c.restoreCountry == QLatin1String("DE")); // the country of the choice before the FIRST tap
    // G4: the restore leaves one choice. Applied: pinned again. Refused (server gone): the engine's pin is cleared and
    // the saved choice stays A with its country - never the row the engine would keep.
    {
        const ExactRowRequest::RestorePlan ok = a.restorePlan(true);
        CHECK(!ok.clearEnginePin && ok.savedPin == QLatin1String("A") && ok.savedCountry == QLatin1String("DE"));
        const ExactRowRequest::RestorePlan gone = a.restorePlan(false);
        CHECK(gone.clearEnginePin && gone.savedPin == QLatin1String("A") && gone.savedCountry == QLatin1String("DE"));
        const ExactRowRequest::RestorePlan autoBefore = ExactRowRequest::begin(none, QStringLiteral("B"), QString(), QString(), false)
                                                             .restorePlan(false);
        CHECK(autoBefore.clearEnginePin && autoBefore.savedPin.isEmpty() && autoBefore.savedCountry.isEmpty());
    }
    // G3 + H3 + I1/I2/I7: which attempt serves which intent. The intent is one value (wanted, choice, mode); the epoch
    // moves exactly when the value changes, compared with the value held, never with derived state.
    {
        using avpn::IntentEpoch;
        using avpn::IntentValue;
        auto val = [](bool wanted, const char *choice, const char *mode) {
            IntentValue v;
            v.wanted = wanted;
            v.choice = QLatin1String(choice);
            v.mode = QLatin1String(mode);
            return v;
        };
        // J1: the choice by its stable identity - the same server with another transport id / reordered paths / changed
        // metadata is the same value; another server, another country, exact vs preferred, Auto are different
        {
            using K = avpn::IntentChoiceKind;
            const QString srv = avpn::intentChoiceIdentity(K::Server, QString(), QStringLiteral("DE|fra"), QString());
            CHECK(srv == avpn::intentChoiceIdentity(K::Server, QString(), QStringLiteral("DE|fra"), QStringLiteral("ignored")));
            CHECK(srv != avpn::intentChoiceIdentity(K::Server, QString(), QStringLiteral("DE|ber"), QString()));
            CHECK(srv != avpn::intentChoiceIdentity(K::Country, QString(), QString(), QStringLiteral("DE")));
            CHECK(avpn::intentChoiceIdentity(K::Country, QString(), QString(), QStringLiteral("de"))
                  == avpn::intentChoiceIdentity(K::Country, QString(), QString(), QStringLiteral("DE")));
            CHECK(avpn::intentChoiceIdentity(K::Country, QString(), QString(), QStringLiteral("FR"))
                  != avpn::intentChoiceIdentity(K::Country, QString(), QString(), QStringLiteral("DE")));
            CHECK(avpn::intentChoiceIdentity(K::Exact, QStringLiteral("7"), QString(), QString())
                  != avpn::intentChoiceIdentity(K::Exact, QStringLiteral("8"), QString(), QString()));
            CHECK(avpn::intentChoiceIdentity(K::Exact, QStringLiteral("7"), QStringLiteral("DE|fra"), QString()) != srv);
            CHECK(avpn::intentChoiceIdentity(K::Auto, QString(), QString(), QString()) != srv);
            // a refresh that only renames / reorders transports leaves the epoch where it is
            IntentEpoch refresh;
            IntentValue v1;
            v1.wanted = true;
            v1.choice = srv;
            v1.mode = QStringLiteral("auto");
            refresh.set(v1);
            const quint64 running = refresh.stampForNewAttempt();
            IntentValue v2 = v1; // same identity after the refresh
            CHECK(!refresh.set(v2) && refresh.resultBelongs(running));
        }
        // J2: at launch with a saved Xray the SELECTED mode is the seed; the engine putting Xray in force for an adopted
        // session (or Auto for one it cannot serve) does not change the value, and the adopted attempt is stamped by it
        {
            IntentEpoch l;
            IntentValue saved;
            saved.wanted = false;
            saved.choice = QStringLiteral("auto");
            saved.mode = QStringLiteral("xray"); // the saved setting, whatever is in force while the observation is awaited
            l.set(saved);
            IntentValue adopt = saved;
            adopt.wanted = true; // the facade syncs wanted on, then the engine adopts
            l.set(adopt);
            const quint64 adopted = l.stampForNewAttempt();
            IntentValue after = adopt; // judgeAdoptedSession changes the mode in force only: the selected mode is unchanged
            CHECK(!l.set(after) && l.resultBelongs(adopted));
            // mirror: saved Auto, an adopted tunnel of another transport: the selected mode stays Auto
            IntentEpoch m2;
            IntentValue sa;
            sa.wanted = true;
            sa.choice = QStringLiteral("auto");
            sa.mode = QStringLiteral("auto");
            m2.set(sa);
            const quint64 st = m2.stampForNewAttempt();
            CHECK(!m2.set(sa) && m2.resultBelongs(st));
        }
        // K1 (round 7): "the person's value did not change" does not imply "the running attempt serves it": the attempt
        // began under the mode IN FORCE (Auto while Xray was selected, after an adopted AmneziaWG session); the person
        // taps Xray, the mode in force becomes Xray, the selected mode is Xray -> Xray and the epoch stays. The attempt
        // is still not what would start now - its result is superseded.
        {
            using M = int; // 0 auto, 1 awg, 2 xray (the engine stamps int(TransportMode))
            IntentEpoch k;
            k.set(val(true, "server|DE", "xray")); // selected Xray
            const quint64 stamp = k.stampForNewAttempt();
            const M startedUnder = 0;              // in force at the start: Auto
            CHECK(k.attemptServesIntent(stamp, startedUnder, /*modeNow=*/0));   // nothing changed: current
            CHECK(!k.set(val(true, "server|DE", "xray")));                      // the tap on Xray: the value is the same
            CHECK(!k.attemptServesIntent(stamp, startedUnder, /*modeNow=*/2));  // ... the mode in force moved: superseded
            // siblings: selected Amnezia while Auto was in force; the tap on the segment already in force changes nothing;
            // a server tap that switches the mode to Auto (transport_mode_auto) moves the selected mode itself
            CHECK(!k.attemptServesIntent(stamp, 0, 1));
            CHECK(k.attemptServesIntent(stamp, 2, 2));
            CHECK(k.attemptServesIntent(stamp, -1, 2)); // an attempt of an older stamp-less path: the epoch alone decides
            IntentEpoch sv;
            sv.set(val(true, "server|DE", "xray"));
            const quint64 st2 = sv.stampForNewAttempt();
            CHECK(sv.set(val(true, "server|FR", "auto")) && !sv.attemptServesIntent(st2, 2, 0));
            // J2 stays: an adopted attempt is stamped with the mode in force AFTER the adoption judged it
            CHECK(sv.attemptServesIntent(sv.stampForNewAttempt(), 2, 2));
        }
        // I7: launch - the first value only seeds; the epoch the engine is given is the facade's from the start
        IntentEpoch e;
        CHECK(!e.set(val(false, "auto", "auto")) && e.epoch == 1);
        CHECK(!e.set(val(false, "auto", "auto")));                   // no change: no move
        // G3: a connect to A runs (wanted, choice A); the person taps the row B -> the choice changes
        CHECK(e.set(val(true, "A", "auto")));
        const quint64 attemptA = e.stampForNewAttempt();
        CHECK(e.resultBelongs(attemptA));
        CHECK(e.set(val(true, "B-exact", "auto")));                  // another server / country (I1)
        CHECK(!e.resultBelongs(attemptA) && e.resultBelongs(e.stampForNewAttempt()));
        // I1: from a pinned server to Auto moves it too, wanted unchanged
        const quint64 attemptB = e.stampForNewAttempt();
        CHECK(e.set(val(true, "auto", "auto")) && !e.resultBelongs(attemptB));
        // I2: AmneziaWG -> Auto while connecting (and the mirror): only the mode changed
        IntentEpoch m;
        m.set(val(true, "auto", "awg"));
        const quint64 awgAttempt = m.stampForNewAttempt();
        CHECK(m.set(val(true, "auto", "auto")) && !m.resultBelongs(awgAttempt));
        IntentEpoch x;
        x.set(val(true, "auto", "xray"));
        const quint64 xrayAttempt = x.stampForNewAttempt();
        CHECK(x.set(val(true, "auto", "auto")) && !x.resultBelongs(xrayAttempt));
        // H3: a repeated start() / a refused pick / a no-op leaves the value as it was: the result is current
        IntentEpoch r;
        r.set(val(true, "auto", "auto"));
        const quint64 running = r.stampForNewAttempt();
        CHECK(!r.set(val(true, "auto", "auto")) && r.resultBelongs(running));
        // a Stop (wanted off), then a new start: the old attempt's result is superseded, the new one's is current
        IntentEpoch s2;
        s2.set(val(true, "auto", "auto"));
        const quint64 old = s2.stampForNewAttempt();
        CHECK(s2.set(val(false, "auto", "auto")));
        CHECK(s2.set(val(true, "auto", "auto")));
        const quint64 fresh = s2.stampForNewAttempt();
        CHECK(!s2.resultBelongs(old) && s2.resultBelongs(fresh));
        // the failover attempt after a live loss / an adopted session is stamped with the epoch in force: current
        IntentEpoch f;
        f.set(val(true, "auto", "auto"));
        const quint64 live = f.stampForNewAttempt();
        const quint64 failover = f.stampForNewAttempt();
        CHECK(f.resultBelongs(live) && f.resultBelongs(failover));
        // I7: adoption of a running session after a launch with a saved Auto: wanted flips on, then it is stamped
        IntentEpoch ad;
        ad.set(val(false, "auto", "auto"));
        ad.set(val(true, "auto", "auto"));                           // the facade syncs the value BEFORE the engine adopts
        const quint64 adopted = ad.stampForNewAttempt();
        CHECK(ad.resultBelongs(adopted) && ad.epoch == 2);
    }
    // an ended request holds nothing: no exact choice, no restore, no reconnect (before: the row outlived the flag)
    ExactRowRequest e = c;
    e.clear();
    CHECK(!e.active() && !e.exactFor(QStringLiteral("C")) && e.restorePin.isEmpty() && !e.reconnect);
}

static void stopNothingNative()
{
    CHECK(avpn::stopFindsNothingNative(avpn::ObservedTunnel::Disconnected, /*ownerHoldsNativeLeg=*/false));
    CHECK(!avpn::stopFindsNothingNative(avpn::ObservedTunnel::Disconnected, true));  // a leg is starting
    CHECK(!avpn::stopFindsNothingNative(avpn::ObservedTunnel::Unknown, false));      // not observed yet: maybe up
    CHECK(!avpn::stopFindsNothingNative(avpn::ObservedTunnel::Connected, false));    // an adopted session
    // R1: the stop during the race prelude (Starting, native Disconnected, no leg) must reach guardedStop to settle.
    using avpn::ObservedTunnel;
    CHECK(avpn::stopNeedsGuardedStop(false, false, true, ObservedTunnel::Disconnected, false)); // the prelude
    CHECK(!avpn::stopNeedsGuardedStop(false, false, false, ObservedTunnel::Disconnected, false)); // idle: nothing open
    CHECK(!avpn::stopNeedsGuardedStop(false, false, true, ObservedTunnel::Disconnected, true));  // a leg: owner stops it
    CHECK(!avpn::stopNeedsGuardedStop(false, false, true, ObservedTunnel::Unknown, false));      // maybe up: not ours
    CHECK(avpn::stopNeedsGuardedStop(true, false, true, ObservedTunnel::Connected, true));       // native work: as before
    CHECK(!avpn::stopNeedsGuardedStop(true, true, true, ObservedTunnel::Connected, true));       // a stop already runs
    // Device round air-D 25.11 (N4 pair 2): one native stop at a time - the facade's stop joins the owner's own stop of a
    // leg in flight (its answer confirms both); nothing native - confirmed at once; otherwise the facade's own stop.
    using avpn::FacadeStop;
    CHECK(avpn::facadeStopAction(ObservedTunnel::Disconnected, false, false) == FacadeStop::ConfirmedAtOnce);
    CHECK(avpn::facadeStopAction(ObservedTunnel::Transitional, true, true) == FacadeStop::JoinOwnerStop); // the replay
    CHECK(avpn::facadeStopAction(ObservedTunnel::Error, true, true) == FacadeStop::JoinOwnerStop);
    CHECK(avpn::facadeStopAction(ObservedTunnel::Disconnected, true, true) == FacadeStop::JoinOwnerStop); // answer not seen
    CHECK(avpn::facadeStopAction(ObservedTunnel::Connected, true, true) == FacadeStop::JoinOwnerStop);
    CHECK(avpn::facadeStopAction(ObservedTunnel::Connected, true, false) == FacadeStop::IssueStop);  // restart of a session
    CHECK(avpn::facadeStopAction(ObservedTunnel::Transitional, true, false) == FacadeStop::IssueStop);
    CHECK(avpn::facadeStopAction(ObservedTunnel::Unknown, false, false) == FacadeStop::IssueStop);   // maybe up: stop it
    CHECK(avpn::facadeStopAction(ObservedTunnel::Connected, false, false) == FacadeStop::IssueStop); // an adopted session
    // Device round 19.11: airplane mode while connected - the failover fails with no network under it.
    using avpn::FailedAttemptIntent;
    CHECK(avpn::failedAttemptIntent(true, false, true) == FailedAttemptIntent::Wait);   // the airplane case
    CHECK(avpn::failedAttemptIntent(true, false, false) == FailedAttemptIntent::Wait);  // a tap with no network
    CHECK(avpn::failedAttemptIntent(true, true, true) == FailedAttemptIntent::DropAndResume); // lost session, live net
    CHECK(avpn::failedAttemptIntent(true, true, false) == FailedAttemptIntent::Drop);   // a tap that found nothing
    CHECK(avpn::failedAttemptIntent(false, false, true) == FailedAttemptIntent::Drop);  // exact server, permission...
}

// Review round 20 R1 (Android): a person taps Connect, the physical network really goes away while the app connects
// (out of coverage, Wi-Fi off) and the attempt ends. The decision reads the physical uplink - on Android now the set
// of NOT_VPN networks (UplinkMonitor.cpp), which our own tunnel's teardown cannot empty - so the request is kept
// (Wait: m_waitUplink, «Нет сети — подключимся, когда она появится») and the start comes with the network. With a
// physical network up the same failure is the ordinary one. The defect read a loss "during our own operation" as
// up (a coincidence in time): Drop, the VPN stayed off after the network came back. The wiring - the decision reads
// UplinkMonitor directly, the Android source is the physical set - is check_android_uplink_wiring.sh.
static void r20PhysicalLossDuringConnect()
{
    using avpn::FailedAttemptIntent;
    // judged = the attempt ended NothingProven / NoNetwork (syncAttempt's first argument)
    const auto afterFailure = [](bool judged, bool physicalUp, bool afterLiveLoss) {
        return avpn::failedAttemptIntent(judged, physicalUp, afterLiveLoss);
    };
    // the attempt's budget ran out (nothing proven) with the physical set empty: the request is kept
    CHECK(afterFailure(true, /*physicalUp=*/false, false) == FailedAttemptIntent::Wait);
    // physical network up (our own tunnel went up and down meanwhile - not in the set): the ordinary failure
    CHECK(afterFailure(true, true, false) == FailedAttemptIntent::Drop);
    CHECK(afterFailure(true, true, true) == FailedAttemptIntent::DropAndResume);
    // a failure that judged no server (the exact server, permission) is not about the network either way
    CHECK(afterFailure(false, false, false) == FailedAttemptIntent::Drop);
}

// android2 P5b (21.11): Wi-Fi off during connecting. The medium pick still said Wi-Fi with no subnet ("wifi:-", a usable
// key) and the attempt walked four servers without a network. The observation now carries the authoritative uplink.
static void p5bOfflineObservation()
{
    using namespace avpn::path;
    NetworkObservation wifi;
    wifi.medium = NetMedium::Wifi;
    wifi.gateway = QStringLiteral("gw-a");
    wifi.subnet = QStringLiteral("192.168.1.0/24");
    NetworkObservation wifiNoFingerprint; // what the pick gave on the phone the moment Wi-Fi went off
    wifiNoFingerprint.medium = NetMedium::Wifi;

    // authoritative source, physical set empty: offline (empty key), whatever the medium pick says
    CHECK(localNetworkKey(withPhysicalUplink(wifiNoFingerprint, /*authoritative=*/true, /*up=*/false)).isEmpty());
    CHECK(withPhysicalUplink(wifi, true, false).medium == NetMedium::Offline);
    CHECK(withPhysicalUplink(wifi, true, false).gateway.isEmpty());
    // authoritative and up: the observation as the platform read it
    CHECK(localNetworkKey(withPhysicalUplink(wifi, true, true)) == localNetworkKey(wifi));
    // the fallback (QNetworkInformation: iOS, Windows, the NE build) says down on every own-tunnel teardown (D2):
    // never "offline" from it - the observation is unchanged
    CHECK(localNetworkKey(withPhysicalUplink(wifiNoFingerprint, /*authoritative=*/false, false)) == QLatin1String("wifi:-"));
    CHECK(localNetworkKey(withPhysicalUplink(wifi, false, false)) == localNetworkKey(wifi));

    // through the generation owner: Wi-Fi -> down -> the same Wi-Fi back = two network changes, the middle one unusable
    NetworkTracker t;
    CHECK(t.observe(withPhysicalUplink(wifi, true, true)) && t.current().usable());
    const quint64 g = t.current().generation;
    CHECK(t.observe(withPhysicalUplink(wifiNoFingerprint, true, false)) && !t.current().usable());
    CHECK(!t.observe(withPhysicalUplink(wifiNoFingerprint, true, false))); // a repeated down changes nothing
    CHECK(t.observe(withPhysicalUplink(wifi, true, true)) && t.current().usable() && t.current().generation == g + 2);
}

// android2 "P7 card after UI kill" (21.11): connected through Германия 1 with the choice Эстония 3 pinned; the UI process
// restarted, the adopted session's identity was unknown, and the card named the pin.
static void p7CardNeverNamesThePinForALiveSession()
{
    // live (connected / verifying), identity unknown, a pin: the session's own hint, never the pin
    CHECK(cardNodeSource(/*live=*/true, false, false, /*idKnown=*/false, /*pinned=*/true) == CardNodeSource::Unknown);
    CHECK(cardNodeSource(true, false, false, false, false) == CardNodeSource::Unknown);
    // live and identified: the live node, pin or not (a failover away from the pin shows where the traffic goes)
    CHECK(cardNodeSource(true, false, false, true, true) == CardNodeSource::Live);
    // the attempt walks: the node being tried now; between legs (no node yet) the person's pick at once
    CHECK(cardNodeSource(false, /*walking=*/true, false, true, true) == CardNodeSource::Live);
    CHECK(cardNodeSource(false, true, false, false, true) == CardNodeSource::Pin);
    // nothing live: the pin (the picker tap shows its server while connecting), else the old node of a switch, else none
    CHECK(cardNodeSource(false, false, false, false, true) == CardNodeSource::Pin);
    CHECK(cardNodeSource(false, false, /*switching=*/true, true, false) == CardNodeSource::Live);
    CHECK(cardNodeSource(false, false, false, false, false) == CardNodeSource::None);
}

// Review F1 of the android2 lane (21.11): Connect tapped with no physical network. The observation is offline, the
// attempt ends at once inside the start with NoNetwork; syncAttempt judges that result (failedAttemptIntent: keep the
// request and wait for the uplink, «Нет сети — подключимся, когда она появится») - and guardedStart dropped the intent
// right after it, so the uplink's return started nothing. The start's refusal adds nothing to a result already judged.
static void f1StartRefusalJudgedByItsResult()
{
    // the start ended in a result of THIS attempt that syncAttempt judged: the result decides (intent, text)
    CHECK(startRefusal(/*endedAttempt=*/7, /*judgedAttempt=*/7) == StartRefusal::JudgedByResult);
    // the judged result kept the request: the uplink's return is what starts it
    CHECK(failedAttemptIntent(/*serversWereJudged=*/true, /*uplinkUp=*/false, false) == FailedAttemptIntent::Wait);
    // a refusal no result explains (no tunnel adapter, no subscription and no nodes: connect() never fed the owner)
    CHECK(startRefusal(0, 0) == StartRefusal::DropIntent);
    CHECK(startRefusal(0, 6) == StartRefusal::DropIntent); // an earlier attempt's judgement is not this start's
    // a result syncAttempt did not judge (superseded by a newer intent): the start's own rule
    CHECK(startRefusal(7, 6) == StartRefusal::DropIntent);
}

// Review F2 (21.11): after an offline observation (empty key) the network returned as a kind the app cannot name
// (Bluetooth tethering: authoritative uplink up, medium Unknown). "Unknown is not a network change" kept the EMPTY key
// and every start ended NoNetwork until the app restarted. Unknown keeps the last KNOWN network; with none it is the
// usable placeholder "unknown".
static void f2UnknownAfterOffline()
{
    using namespace avpn::path;
    NetworkObservation wifi;
    wifi.medium = NetMedium::Wifi;
    wifi.gateway = QStringLiteral("gw-a");
    wifi.subnet = QStringLiteral("192.168.1.0/24");
    const NetworkObservation unknown; // medium Unknown
    NetworkTracker t;
    CHECK(t.observe(withPhysicalUplink(wifi, true, true)));
    const QString wifiKey = t.current().local;
    CHECK(t.observe(withPhysicalUplink(wifi, /*authoritative=*/true, /*up=*/false)) && !t.current().usable());
    const quint64 offlineGen = t.current().generation;
    // the uplink is back, its kind unknown: a usable network, a new generation
    CHECK(t.observe(withPhysicalUplink(unknown, true, true)));
    CHECK(t.current().usable() && t.current().local == QLatin1String("unknown") && t.current().generation == offlineGen + 1);
    CHECK(!t.observe(withPhysicalUplink(unknown, true, true))); // a repeated unknown changes nothing
    // the real kind becomes known: its own key, one more change
    CHECK(t.observe(withPhysicalUplink(wifi, true, true)) && t.current().local == wifiKey
          && t.current().generation == offlineGen + 2);
    // Unknown with a known network (iOS under any VPN, the uplink up): the network is kept, no change - as before
    CHECK(!t.observe(withPhysicalUplink(unknown, true, true)) && t.current().local == wifiKey);
    CHECK(!t.observe(withPhysicalUplink(unknown, /*authoritative=*/false, false)) && t.current().local == wifiKey);
}

// android3 runs a, f (21.11): the owner's stop never reached the service and was given up (attempt_stop_unconfirmed); the
// facade's view stayed "Disconnecting" - reconcile waits for a terminal there, so the uplink's return and a tap did
// nothing. The service's next status snapshot resolves the view.
static void android3StatusResolvesAGivenUpStop()
{
    using A = AndroidStatusAction;
    const TeardownLatch none;
    // the block, as it was: a transitional view is not actionable (reconcile waits for its terminal)
    CHECK(!reconcileActionable(ObservedTunnel::Transitional, none));
    // the service runs nothing: our own stop is over (not a loss) - and then a start is possible again
    CHECK(androidStatusAction(false, /*serviceDisconnected=*/true, /*engineConnected=*/false, ObservedTunnel::Transitional,
                              /*attemptRunning=*/false) == A::ConfirmOwnStop);
    CHECK(reconcileActionable(ObservedTunnel::Disconnected, none));
    // the service runs the tunnel (the orphan came up): adopted, as any live tunnel the engine does not hold
    CHECK(androidStatusAction(/*serviceConnected=*/true, false, false, ObservedTunnel::Transitional, false) == A::Adopt);
    // the existing rules stay: a session the service no longer runs; views that agree
    CHECK(androidStatusAction(false, true, /*engineConnected=*/true, ObservedTunnel::Connected, false) == A::Disconnected);
    CHECK(androidStatusAction(false, true, false, ObservedTunnel::Disconnected, false) == A::Nothing);
    CHECK(androidStatusAction(true, false, true, ObservedTunnel::Connected, false) == A::Nothing);
    // an attempt walks (its own legs resolve the view) or the snapshot is in between (its terminal comes as an event)
    CHECK(androidStatusAction(false, true, false, ObservedTunnel::Transitional, /*attemptRunning=*/true) == A::Nothing);
    CHECK(androidStatusAction(false, false, false, ObservedTunnel::Transitional, false) == A::Nothing);
    // a stop that ends late is not a loss: the result's decision on the request stands
    CHECK(classifyLoss(/*weAreOperating=*/true, QStringLiteral("error"), false, false, /*uplinkUp=*/true) == LossClass::Own);
}

// Review R2 (21.11): the person tapped Stop the moment the handshake completed; the CONNECTED already in flight came after
// our stop and the Android adoption set the intent back on (the person's Stop overruled). The person's last will owns
// the outcome: a late Connected after a stop of ours while the person wants the VPN off is stopped, never adopted.
static void r2LateConnectedAfterThePersonsStop()
{
    using A = ObservedTunnelAdoption;
    // the person's OFF, our stop still unconfirmed: the tunnel is stopped (reconcile), the intent stays off
    CHECK(adoptObservedTunnel(/*ourStopPending=*/true, /*wantConnected=*/false) == A::StopIt);
    // our stop was the engine's (no network, failover, a restart for another choice): the request is on - adopted
    CHECK(adoptObservedTunnel(false, true) == A::Adopt);
    CHECK(adoptObservedTunnel(true, true) == A::Adopt);
    // no stop of ours pending (a session started outside the app after OFF - the tile): as before, adopted
    CHECK(adoptObservedTunnel(false, false) == A::Adopt);
}

// Emulator rounds of 26.11 (F2, entry c): a cold start while the service rebuilds a session after a network change -
// the screen showed "off" over a held interface that carried nothing. The STATUS entry takes the session over (our stop,
// then the ordinary connect) by the same person's-will rule an adopted CONNECTED service obeys.
static void f2cStatusTakesOverARebuild()
{
    using A = AndroidStatusAction;
    // one rule for both unfinished states (the facade passes CONNECTING || RECONNECTING, H5): RECONNECTING - the service's
    // rebuild after a network change; CONNECTING - a start whose UI process is gone (round 3, the app swiped away at the
    // notification question during the first connect: the service kept the leg's tunnel with no handshake, the reopened
    // app said "off", nothing loaded). Snapshot unfinished x engine idle x no attempt, nothing of ours pending: taken over
    // (will off or on: the intent of a fresh process is off, as for an adopted CONNECTED service)
    CHECK(androidRebuildStatusDecision(/*serviceUnfinished=*/true, /*engineConnected=*/false, /*attemptRunning=*/false,
                                       /*ourStopPending=*/false, /*wantConnected=*/false) == A::TakeOver);
    CHECK(androidRebuildStatusDecision(true, false, false, false, true) == A::TakeOver);
    // the person's Stop with our stop unconfirmed: stopped, no connect after it
    CHECK(androidRebuildStatusDecision(true, false, false, /*ourStopPending=*/true, /*wantConnected=*/false) == A::StopIt);
    // our stop pending but the will on (the engine's own stop): taken over
    CHECK(androidRebuildStatusDecision(true, false, false, true, true) == A::TakeOver);
    // the engine holds the session: its rebuild bound decides (ServiceEngine::noteLiveRebuild), not this
    CHECK(androidRebuildStatusDecision(true, /*engineConnected=*/true, false, false, true) == A::Nothing);
    // a running attempt owns the tunnel (B7: the tap's attempt beside a redelivered start - its own leg judges it)
    CHECK(androidRebuildStatusDecision(true, false, /*attemptRunning=*/true, false, true) == A::Nothing);
    CHECK(androidRebuildStatusDecision(true, false, true, true, false) == A::Nothing);
    CHECK(androidRebuildStatusDecision(true, false, true, false, false) == A::Nothing);
    // any other snapshot (CONNECTED, DISCONNECTED, DISCONNECTING, UNKNOWN): not this rule, whatever the rest
    for (const bool engine : { false, true })
        for (const bool attempt : { false, true })
            for (const bool pending : { false, true })
                for (const bool want : { false, true })
                    CHECK(androidRebuildStatusDecision(/*serviceUnfinished=*/false, engine, attempt, pending, want)
                          == A::Nothing);
    // the rule is the Adopt rule's will test exactly: with nothing held and no attempt, StopIt here <=> StopIt there
    for (const bool pending : { false, true })
        for (const bool want : { false, true })
            CHECK((androidRebuildStatusDecision(true, false, false, pending, want) == A::StopIt)
                  == (adoptObservedTunnel(pending, want) == ObservedTunnelAdoption::StopIt));
    // the Adopt rule for a CONNECTED service is unchanged
    CHECK(androidStatusDecision(true, false, false, ObservedTunnel::Unknown, false, false, false) == A::Adopt);
    CHECK(androidStatusDecision(true, false, false, ObservedTunnel::Transitional, false, true, false) == A::StopIt);
    // an unfinished snapshot (CONNECTING, RECONNECTING) is still Nothing for the CONNECTED/DISCONNECTED rule
    CHECK(androidStatusDecision(false, false, false, ObservedTunnel::Unknown, false, false, false) == A::Nothing);
    // the take-over's stop holds every start until its Disconnected, and a tap meanwhile is a Stop, never a Start
    TeardownLatch stop;
    stop.awaitingStopConfirm = true;
    CHECK(reconcileGate(stop, ObservedTunnel::Transitional, /*wantConnected=*/true, true) == ReconcileGate::AwaitStatus);
    CHECK(reconcileGate(stop, ObservedTunnel::Transitional, true, false) == ReconcileGate::Wait);
    CHECK(!ownStopInFlight(/*wantConnected=*/true, /*opStopping=*/true, true)); // shown as a transition, not «Disconnecting»
    CHECK(decideOrbTap(/*engineConnected=*/false, /*busy=*/true, /*wantConnected=*/true, /*ownStopping=*/false,
                       /*ownOpInFlight=*/true, false, false) == OrbTap::Stop);
}

// Phone 26.11 (T1) / round 58 review, finding 3: Connect, Stop in the app, then the notification's «Подключиться» - a
// session the service started by itself in a live UI process. The FIX is in VpnConnection (the protocol restored for a
// CONNECTED without one, ensureAndroidProtocol): it is not host-testable and is proven by
// check_android_adopt_protocol_wiring.sh P1-P4 (fails on the old code) and the phone (T1 4/4, phone-3). These rows do NOT
// test the fix (round 59 review: they pass with and without it) - they pin the UNCHANGED Adopt rule the fix routes the fact
// into: after a confirmed Stop nothing of ours is pending, so the OFF intent does not block the new session (A4) - it is
// adopted, never stopped; only a Stop of ours still unconfirmed with the request off stops it.
static void t1NotificationStartIsAdopted()
{
    using A = AndroidStatusAction;
    // the live edge's rule (tryAdoptObservedTunnel on Android = adoptObservedTunnel): confirmed Stop, request off -> adopt
    CHECK(adoptObservedTunnel(/*ourStopPending=*/false, /*wantConnected=*/false) == ObservedTunnelAdoption::Adopt);
    // the person's Stop still unconfirmed (the CONNECTED is that same session's, arriving late): stopped
    CHECK(adoptObservedTunnel(true, false) == ObservedTunnelAdoption::StopIt);
    // the snapshot's rule for the same facts gives the same answer (one decision for edge and snapshot)
    for (const bool pending : { false, true })
        for (const bool want : { false, true }) {
            const A snap = androidStatusDecision(/*serviceConnected=*/true, false, /*engineConnected=*/false,
                                                 ObservedTunnel::Disconnected, /*attemptRunning=*/false, pending, want);
            CHECK((snap == A::StopIt) == (adoptObservedTunnel(pending, want) == ObservedTunnelAdoption::StopIt));
            CHECK(snap == A::StopIt || snap == A::Adopt);
        }
    // the engine holds a session: no adoption from either entry (the views agree)
    CHECK(androidStatusDecision(true, false, /*engineConnected=*/true, ObservedTunnel::Connected, false, false, true) == A::Nothing);
}

// Review R3 (21.11): Connect, Stop during the first bind, the app to the background; on return the service's STATUS said
// "connected" and the STATUS entry adopted it - setting the intent on before the person's-will rule was asked. Both
// entries (native state, STATUS) now decide by the same rule.
static void r3StatusAdoptionObeysThePersonsStop()
{
    using A = AndroidStatusAction;
    // STATUS connected, the person's OFF with our stop unconfirmed: stop it, the intent stays off
    CHECK(androidStatusDecision(/*serviceConnected=*/true, false, /*engineConnected=*/false, ObservedTunnel::Transitional,
                                false, /*ourStopPending=*/true, /*wantConnected=*/false) == A::StopIt);
    // the stop was the engine's (no network: the request is kept on): adopted
    CHECK(androidStatusDecision(true, false, false, ObservedTunnel::Transitional, false, /*ourStopPending=*/false,
                                /*wantConnected=*/true) == A::Adopt);
    CHECK(androidStatusDecision(true, false, false, ObservedTunnel::Transitional, false, true, true) == A::Adopt);
    // found at launch, nothing of ours pending: adopted as before
    CHECK(androidStatusDecision(true, false, false, ObservedTunnel::Unknown, false, false, false) == A::Adopt);
    // the other answers are androidStatusAction's, unchanged
    CHECK(androidStatusDecision(false, true, false, ObservedTunnel::Transitional, false, true, false) == A::ConfirmOwnStop);
    CHECK(androidStatusDecision(false, true, true, ObservedTunnel::Connected, false, false, true) == A::Disconnected);
    // one rule for both entries: the STATUS StopIt is exactly the native entry's StopIt
    for (const bool pending : { false, true })
        for (const bool want : { false, true })
            CHECK((androidStatusDecision(true, false, false, ObservedTunnel::Transitional, false, pending, want) == A::StopIt)
                  == (adoptObservedTunnel(pending, want) == ObservedTunnelAdoption::StopIt));
}

// android4 G4 (21.11): the service ended while the app was in the background (the notification's «Отключиться»). The
// activity now tells the app DISCONNECTED at once on its return (ServiceReach, Kotlin) and for a stop with no service to
// give it to. What that DISCONNECTED means to the facade - the person's belief vs what runs:
static void g4ServiceGoneOnReturn()
{
    // the app believed a live session, nothing of ours in flight: an external end - the intent goes off (not a loss to
    // recover from: the person ended it from the notification), and a start is possible at once
    CHECK(classifyLoss(/*weAreOperating=*/false, QStringLiteral("connected"), false, false, /*uplinkUp=*/true)
          == LossClass::External);
    CHECK(reconcileActionable(ObservedTunnel::Disconnected, TeardownLatch{}));
    // the person's tap was a stop (our operation): it is confirmed - no 10 s wait for a stop that has nothing to stop
    CHECK(classifyLoss(/*weAreOperating=*/true, QStringLiteral("connected"), false, false, true) == LossClass::Own);
    // the same truth as a status snapshot: a session the service no longer runs is the honest Disconnected
    CHECK(androidStatusAction(false, /*serviceDisconnected=*/true, /*engineConnected=*/true, ObservedTunnel::Connected, false)
          == AndroidStatusAction::Disconnected);
}

static void checkBlameRule()
{
    using avpn::CheckBlame;
    CHECK(avpn::checkFailureBlame(true, 4500, 4000, true, 100, true) == CheckBlame::Path);       // no data through the tunnel
    CHECK(avpn::checkFailureBlame(true, 4500, 4000, false, -1, true) == CheckBlame::Path);       // no counter: as before
    CHECK(avpn::checkFailureBlame(false, 4500, 4000, true, 0, true) == CheckBlame::NoNetwork);   // the network went away
    CHECK(avpn::checkFailureBlame(true, 13800, 4000, true, 0, true) == CheckBlame::Suspended);   // 13.8 s after the background
    CHECK(avpn::checkFailureBlame(true, 6400, 4000, true, 90000, true) == CheckBlame::ControlPlane); // the tunnel carries data
    CHECK(avpn::checkFailureBlame(true, 7000, 4000, true, 0, true) == CheckBlame::Path);         // within the stretch grace
    CHECK(avpn::checkFailureBlame(true, 4500, 4000, true, 0, false) == CheckBlame::NetworkChanged); // began on another network
    CHECK(avpn::checkFailureBlame(false, 4500, 4000, true, 0, false) == CheckBlame::NoNetwork);     // no network outranks it
}

static void whitelistTriggerFromOwner()
{
    CHECK(whitelistTriggerFromAttempt(/*legStartFailures=*/1, false));   // a leg never came up
    CHECK(whitelistTriggerFromAttempt(0, /*nothingProven=*/true));       // the attempt ended with nothing proven
    CHECK(!whitelistTriggerFromAttempt(0, false));                       // a leg up without data, a connect: no
}

static void scannerCancelNeverDuringAppQuit()
{
    ScanOwnConnect a;
    a.id = 2;
    a.processEpoch = 0x88;
    a.intentSerial = 9;
    CHECK(decideScanCancel(a, 0x88, 9, /*want=*/true, /*shownConnected=*/false, /*eventLoopRunning=*/false)
          == ScanCancel::IgnoreAppQuit); // «Подключаемся…» too: quitting the app is not the person's cancel
    CHECK(decideScanCancel(a, 0x88, 9, true, false, true) == ScanCancel::Stop); // the same cancel in the app
    CHECK(QLatin1String(scanCancelName(ScanCancel::IgnoreAppQuit)) == QLatin1String("app_quit"));
}

// A row tap's chain as the coordinator sees it: the node the ladder left, the end, «Подключено».
// The chain's own attempt as the engine reports it: the newest attempt began under the row's epoch (D1).
static ScanRowStep observeOwnAttempt(ScanRowAttempt &a, quint64 intentSerial, const QString &engineNode, bool dataFlowing,
                                     bool attemptOver)
{
    return scanRowAttemptObserve(a, intentSerial, engineNode, dataFlowing, /*intentOff=*/false, attemptOver, a.intentEpoch);
}

static void scannerRowChain()
{
    ScanRowAttempt a;
    CHECK(observeOwnAttempt(a, 1, QStringLiteral("9"), true, false).failed.isEmpty()); // inactive: silent
    scanRowAttemptBegin(a, QStringLiteral("9"), 3, /*intentEpoch=*/30);
    ScanRowStep st = observeOwnAttempt(a, 3, QStringLiteral("9"), false, false);
    CHECK(st.failed.isEmpty() && !st.connected && !st.ended);
    st = observeOwnAttempt(a, 3, QStringLiteral("11"), false, false); // the ladder left 9 for 11
    CHECK(st.failed == QStringList{QStringLiteral("9")});
    st = observeOwnAttempt(a, 3, QStringLiteral("11"), false, false);
    CHECK(st.failed.isEmpty()); // reported once
    st = observeOwnAttempt(a, 3, QStringLiteral("11"), /*dataFlowing=*/true, false);
    CHECK(st.connected && st.connectedNode == QLatin1String("11"));
    CHECK(!a.active);
    // The chain gives up: the current node failed, the chain ends.
    scanRowAttemptBegin(a, QStringLiteral("9"), 4, /*intentEpoch=*/40);
    st = observeOwnAttempt(a, 4, QStringLiteral("9"), false, /*gaveUp=*/true);
    CHECK(st.ended && st.failed == QStringList{QStringLiteral("9")});
    // Another action took the tunnel (orb Stop, another tap): no failure is reported (the row did not fail), but the
    // request is over and the Scanner is told so (device round 13, C1: the row stayed «Подключение…» for good).
    scanRowAttemptBegin(a, QStringLiteral("9"), 5, /*intentEpoch=*/50);
    st = observeOwnAttempt(a, /*intentSerial=*/6, QStringLiteral("10"), false, true);
    CHECK(st.failed.isEmpty() && !st.ended && !st.connected && !a.active);
    CHECK(st.superseded && st.supersededNode == QLatin1String("9"));
    st = observeOwnAttempt(a, 6, QStringLiteral("10"), false, true); // told once
    CHECK(!st.superseded);
    // R4 (device round 4): the session before the tap (data on another node, the sibling «Эстония 3») is not a row
    // of this chain: nothing is reported for it, before or after the tapped row fails.
    scanRowAttemptBegin(a, QStringLiteral("9"), 7, /*intentEpoch=*/70);
    st = observeOwnAttempt(a, 7, QStringLiteral("10"), true, false);
    CHECK(!st.connected && st.failed.isEmpty() && a.active);
    st = observeOwnAttempt(a, 7, QStringLiteral("9"), false, false);
    CHECK(st.failed.isEmpty());
    st = observeOwnAttempt(a, 7, QString(), false, /*gaveUp=*/true);
    CHECK(st.ended && st.failed == QStringList{QStringLiteral("9")});
    // the tapped row never came up and the chain gave up: only the tapped row
    scanRowAttemptBegin(a, QStringLiteral("9"), 8, /*intentEpoch=*/80);
    st = observeOwnAttempt(a, 8, QStringLiteral("10"), false, /*gaveUp=*/true);
    CHECK(st.ended && st.failed == QStringList{QStringLiteral("9")});
}


// D1 (release 141, device round air20 R3, 21.11 11:36:12): row A («Германия 4») failed; row B («Германия 3») tapped
// right after. B was marked «Не удалось» 14 ms before its own attempt began (the engine still sat in the Error A's attempt
// left), a failed outcome went for B, and B stayed failed while the VPN was connected through it. An attempt's end
// belongs to the row whose epoch that attempt began under - in either order of the tap and A's result.
static void scannerRowOutcomeBelongsToItsAttempt()
{
    const QString A = QStringLiteral("up:aaaa"), B = QStringLiteral("up:bbbb");
    // (1) A's result lands first, then B is tapped while the engine still shows A's Error.
    {
        ScanRowAttempt row;
        scanRowAttemptBegin(row, A, /*serial=*/1, /*epoch=*/15);
        ScanRowStep st = scanRowAttemptObserve(row, 1, A, false, false, /*attemptOver=*/false, /*attemptEpoch=*/17);
        CHECK(st.failed.isEmpty() && row.seenTapped);
        st = scanRowAttemptObserve(row, 1, QString(), false, false, /*attemptOver=*/true, 17); // A's own attempt failed
        CHECK(st.ended && st.failed == QStringList{A});                                         // the outcome names A
        scanRowAttemptBegin(row, B, /*serial=*/2, /*epoch=*/21);
        // the window between the tap and B's attempt: Error with nothing running, the newest attempt is A's (epoch 17)
        st = scanRowAttemptObserve(row, 2, QString(), false, false, /*attemptOver=*/true, /*attemptEpoch=*/17);
        CHECK(st.failed.isEmpty() && !st.ended && !st.connected && row.active);
        st = scanRowAttemptObserve(row, 2, QString(), false, false, true, 17); // seen again: still nothing for B
        CHECK(st.failed.isEmpty() && !st.ended && row.active);
        // B's attempt begins (epoch 21) and comes up with data: «Подключено» on B, nothing failed
        st = scanRowAttemptObserve(row, 2, B, false, false, false, 21);
        CHECK(st.failed.isEmpty() && row.seenTapped);
        st = scanRowAttemptObserve(row, 2, B, /*dataFlowing=*/true, false, false, 21);
        CHECK(st.connected && st.connectedNode == B && st.failed.isEmpty() && !row.active);
    }
    // (2) B is tapped while A's attempt still runs; A's failure lands after the tap.
    {
        ScanRowAttempt row;
        scanRowAttemptBegin(row, A, 1, 15);
        ScanRowStep st = scanRowAttemptObserve(row, 1, A, false, false, false, 17);
        CHECK(st.failed.isEmpty());
        scanRowAttemptBegin(row, B, 2, 21); // the tap replaces A's request; A's attempt is still the newest
        st = scanRowAttemptObserve(row, 2, A, false, false, false, 17); // A still carried: the session before B
        CHECK(st.failed.isEmpty() && !st.ended);
        st = scanRowAttemptObserve(row, 2, QString(), false, false, /*attemptOver=*/true, 17); // A's result lands
        CHECK(st.failed.isEmpty() && !st.ended && row.active); // neither B nor A is reported by B's chain
        st = scanRowAttemptObserve(row, 2, B, true, false, false, 21);
        CHECK(st.connected && st.connectedNode == B && st.failed.isEmpty());
    }
    // (3) B's own attempt failing still ends B at once (its epoch or a later one), and an intent off ends it too.
    {
        ScanRowAttempt row;
        scanRowAttemptBegin(row, B, 2, 21);
        ScanRowStep st = scanRowAttemptObserve(row, 2, QString(), false, false, true, 17);
        CHECK(st.failed.isEmpty());
        st = scanRowAttemptObserve(row, 2, B, false, false, false, 21);
        st = scanRowAttemptObserve(row, 2, QString(), false, false, /*attemptOver=*/true, /*attemptEpoch=*/22);
        CHECK(st.ended && st.failed == QStringList{B});
        // an intent off after the row's own attempt began is the row's outcome
        scanRowAttemptBegin(row, B, 3, 23);
        st = scanRowAttemptObserve(row, 3, B, false, false, false, 23);
        st = scanRowAttemptObserve(row, 3, QString(), false, /*intentOff=*/true, false, 23);
        CHECK(st.ended && st.failed == QStringList{B});
    }
    // (4) Device round air-D, E2 (journal 00:11:10-00:11:16): A = up:3ab948.. tapped (intent epoch 28, attempt 18 starts),
    // B = up:7a2869.. tapped 0.7 s later (epoch 30, "exact_row_request_dropped row=A"); A's seat request hangs,
    // "upstream_start_failed node=A code=transport", attempt 18 "superseded", then "intent_off why=external_loss" - and
    // B was marked "scan_row_failed" with no attempt_start of its own. B's own attempt never began (the newest attempt is
    // A's, epoch 28 < 30): the request is dropped, no verdict for B.
    {
        ScanRowAttempt row;
        scanRowAttemptBegin(row, B, /*serial=*/7, /*epoch=*/30);
        ScanRowStep st = scanRowAttemptObserve(row, 7, A, false, false, false, /*attemptEpoch=*/28); // A still raised
        CHECK(st.failed.isEmpty() && !st.ended && !st.dropped);
        st = scanRowAttemptObserve(row, 7, QString(), false, /*intentOff=*/true, /*attemptOver=*/false, /*attemptEpoch=*/28);
        CHECK(st.failed.isEmpty() && !st.ended && st.dropped && st.droppedNode == B && !row.active);
        // a person's action (the serial moves) is still "superseded", never "dropped"
        scanRowAttemptBegin(row, B, 8, 31);
        st = scanRowAttemptObserve(row, 9, QString(), false, true, false, 28);
        CHECK(st.superseded && !st.dropped && st.failed.isEmpty());
    }
}

// The live status: the live node and the target of an attempt in progress (never probed with its key).
static void scannerLiveView()
{
    const QString none;
    // S2 (device round 5): connected without the data mark (an adopted session after a relaunch) is not «connecting»
    {
        const ScanLiveView a = scanLiveView(QStringLiteral("connected"), true, QString(), none, none, none, true, false,
                                            /*dataFlowing=*/false, false);
        CHECK(a.live && !a.connecting);
    }
    ScanLiveView v = scanLiveView(QStringLiteral("disconnected"), false, none, none, none, QStringLiteral("9"), false, false, false, /*attemptFailed=*/false);
    CHECK(!v.live && !v.connecting && v.nodeId.isEmpty() && v.attemptNodeId.isEmpty());
    v = scanLiveView(QStringLiteral("connecting"), false, QStringLiteral("9"), none, none, QStringLiteral("9"), true, false, false, /*attemptFailed=*/false);
    CHECK(!v.live && v.connecting && v.attemptNodeId == QLatin1String("9"));
    v = scanLiveView(QStringLiteral("connected"), true, QStringLiteral("9"), none, none, QStringLiteral("9"), true, false, true, /*attemptFailed=*/false);
    CHECK(v.live && !v.connecting && v.nodeId == QLatin1String("9") && v.attemptNodeId.isEmpty());
    // The engine's own switch 9 -> 10, down phase: 9 is still live, 10 is the attempt.
    v = scanLiveView(QStringLiteral("switching"), true, QStringLiteral("9"), QStringLiteral("10"), none, none, true, false, false, /*attemptFailed=*/false);
    CHECK(v.live && v.nodeId == QLatin1String("9") && v.attemptNodeId == QLatin1String("10"));
    // Up phase (current = target, the old runtime gone).
    v = scanLiveView(QStringLiteral("switching"), false, QStringLiteral("10"), none, none, none, true, false, false, /*attemptFailed=*/false);
    CHECK(!v.live && v.attemptNodeId == QLatin1String("10"));
    // A row tap on a live tunnel: the restart's target is the pinned row.
    v = scanLiveView(QStringLiteral("connected"), true, QStringLiteral("9"), none, QStringLiteral("11"), QStringLiteral("11"), true, true, true, /*attemptFailed=*/false);
    CHECK(v.live && v.nodeId == QLatin1String("9") && v.attemptNodeId == QLatin1String("11"));
    // VPN off with the intent on (start preparation / retry): the next connect's node.
    v = scanLiveView(QStringLiteral("error"), false, none, none, none, QStringLiteral("12"), true, false, false, /*attemptFailed=*/true);
    CHECK(v.failed && !v.connecting && v.attemptNodeId == QLatin1String("12"));
}

// ── AVPN Scanner, second pass ────────────────────────────────────────────────────────────────────────────

// Item 7: the network kind under the device's own VPN comes from the physical uplink, not the tunnel's medium.
static void scannerPhysicalNetworkKind()
{
    auto ifc = [](const char *n, int type, bool up, QStringList v4) {
        PhysicalIface i;
        i.name = QLatin1String(n);
        i.type = type;
        i.up = up;
        i.ipv4 = v4;
        return i;
    };
    // This Mac with a VPN up (seen on the integration run): utun4 holds an IPv4, en0 is Wi-Fi.
    const QList<PhysicalIface> vpnOnWifi{ifc("lo0", 0, true, {"127.0.0.1"}), ifc("utun4", 0, true, {"10.8.0.2"}),
                                         ifc("en0", 1, true, {"192.168.1.23"}), ifc("awdl0", 1, true, {}),
                                         ifc("bridge0", 0, true, {}), ifc("en3", 2, true, {})};
    CHECK(physicalUplinkKind(vpnOnWifi) == QLatin1String("wifi"));
    // The monitor's path (other prohibited) names nothing under the VPN; the platform medium is the tunnel's.
    CHECK(scanNetworkKindName(QString(), physicalUplinkKind(vpnOnWifi), QString()) == QLatin1String("wifi"));
    CHECK(scanNetworkKindName(QStringLiteral("ethernet"), QStringLiteral("wifi"), QString()) == QLatin1String("ethernet"));
    CHECK(scanNetworkKindName(QString(), QString(), QStringLiteral("cellular")) == QLatin1String("cellular"));
    // Wired and Wi-Fi both up: the wired service (macOS default order).
    CHECK(physicalUplinkKind({ifc("en0", 1, true, {"192.168.1.23"}), ifc("en5", 2, true, {"10.0.0.7"})}) == QLatin1String("ethernet"));
    // Only a tunnel, a link-local or a down interface: nothing physical known.
    CHECK(physicalUplinkKind({ifc("utun4", 1, true, {"10.8.0.2"}), ifc("en0", 1, true, {"169.254.3.4"}),
                              ifc("en5", 2, false, {"10.0.0.7"})}).isEmpty());
    // One order on both platforms (scanNetworkKindPick), the reporting key from the same kind.
    // macOS under its VPN: the monitor now names the route table's physical uplink; it wins over the list.
    ScanKindPick mac = scanNetworkKindPick(QStringLiteral("wifi"), QStringLiteral("wifi"), QString());
    CHECK(mac.kind == QLatin1String("wifi") && mac.source == QLatin1String("path") && !mac.disagree);
    // An Ethernet link with an address but no default route: the list says ethernet, the monitor wifi -> the
    // monitor's kind, the disagreement flagged for the journal.
    mac = scanNetworkKindPick(QStringLiteral("wifi"), QStringLiteral("ethernet"), QString());
    CHECK(mac.kind == QLatin1String("wifi") && mac.disagree);
    CHECK(upstreamNetworkKey(mac.kind, QString(), QString(), 0) == QLatin1String("wifi"));
    // The monitor without a kind (no route seen yet): the list, then the platform medium.
    mac = scanNetworkKindPick(QString(), QStringLiteral("ethernet"), QStringLiteral("wifi"));
    CHECK(mac.kind == QLatin1String("ethernet") && mac.source == QLatin1String("interfaces") && !mac.disagree);
    CHECK(scanNetworkKindPick(QString(), QString(), QString()).source.isEmpty());
    // iOS (no interface list): the app's own path monitor first - an iPhone on Wi-Fi with a SIM stays Wi-Fi
    // although CoreTelephony makes the platform medium "cellular".
    ScanKindPick ios = scanNetworkKindPick(QStringLiteral("wifi"), QString(), QStringLiteral("cellular"));
    CHECK(ios.kind == QLatin1String("wifi") && ios.source == QLatin1String("path"));
    CHECK(upstreamNetworkKey(ios.kind, QStringLiteral("250-02"), QStringLiteral("lte"), 0) == QLatin1String("wifi"));
    ios = scanNetworkKindPick(QString(), QString(), QStringLiteral("cellular")); // the monitor knows nothing yet
    CHECK(ios.kind == QLatin1String("cellular") && ios.source == QLatin1String("platform"));
    CHECK(upstreamNetworkKey(ios.kind, QStringLiteral("250-02"), QStringLiteral("lte"), 0).startsWith(QLatin1String("cell:250-02:")));
    ios = scanNetworkKindPick(QStringLiteral("cellular"), QString(), QStringLiteral("wifi"));
    CHECK(ios.kind == QLatin1String("cellular"));
    // U1 (device test 142, iPhone Air on Wi-Fi with a SIM, VPN up): Qt's medium Unknown, CoreTelephony "lte".
    // The platform input says "unknown" under our tunnel instead of guessing cellular...
    CHECK(platformNetworkKind(QString(), QStringLiteral("lte"), /*ownTunnelUp=*/true).isEmpty());
    // ...so a path monitor that has not answered yet leaves the kind unknown, never "cellular".
    CHECK(scanNetworkKindPick(QString(), QString(), platformNetworkKind(QString(), QStringLiteral("lte"), true)).kind.isEmpty());
    // The monitor's Wi-Fi wins and the report carries no radio generation for it.
    ios = scanNetworkKindPick(QStringLiteral("wifi"), QString(), platformNetworkKind(QString(), QStringLiteral("lte"), true));
    CHECK(ios.kind == QLatin1String("wifi"));
    CHECK(cellularGenerationForKind(ios.kind, QStringLiteral("lte")).isEmpty());
    // With the tunnel down Unknown + a radio is cellular (iOS reports Unknown on cellular), Qt's known medium wins.
    CHECK(platformNetworkKind(QString(), QStringLiteral("lte"), false) == QLatin1String("cellular"));
    CHECK(platformNetworkKind(QStringLiteral("wifi"), QStringLiteral("lte"), false) == QLatin1String("wifi"));
    CHECK(platformNetworkKind(QStringLiteral("wifi"), QStringLiteral("lte"), true) == QLatin1String("wifi"));
    CHECK(platformNetworkKind(QString(), QString(), false).isEmpty());
    CHECK(cellularGenerationForKind(QStringLiteral("cellular"), QStringLiteral("lte")) == QLatin1String("lte"));
    CHECK(cellularGenerationForKind(QString(), QStringLiteral("lte")).isEmpty());
    // The Doctor's line in the support report: Wi-Fi with a SIM reads "Wi-Fi", not "сотовая LTE".
    {
        const auto st = doctor::networkStage(0, QStringLiteral("wifi"), cellularGenerationForKind(QStringLiteral("wifi"), QStringLiteral("lte")), -1, -1, -1);
        CHECK(st.note == QStringLiteral("Сеть: Wi-Fi"));
        CHECK(!st.data.contains(QStringLiteral("cellular_gen")));
    }
    // The reporting key from the physical kind: never "unknown" for a Mac on Wi-Fi under its VPN.
    CHECK(upstreamNetworkKey(QStringLiteral("wifi"), QString(), QString(), 0) == QLatin1String("wifi"));
    CHECK(upstreamNetworkKey(QString(), QString(), QString(), 0) == QLatin1String("unknown"));
}

// Item 2: the IPs the engine resolved for exactly the probe base's host.
static void scannerKnownHostIps()
{
    const QHash<QString, QStringList> byHost{{QStringLiteral("api.tribevpn.com"), {"201.34.134.103"}},
                                             {QStringLiteral("vpn.wellwon.hk"), {"198.51.100.20", "2a01:4f8::1"}}};
    CHECK(knownIpsForHost(byHost, QStringLiteral("api.tribevpn.com")) == QStringList{"201.34.134.103"});
    CHECK(knownIpsForHost(byHost, QStringLiteral("API.TribeVPN.com.")) == QStringList{"201.34.134.103"});
    CHECK(knownIpsForHost(byHost, QStringLiteral("vpn.wellwon.hk:443")).size() == 2);
    CHECK(knownIpsForHost(byHost, QStringLiteral("tribevpn.com")).isEmpty()); // exactly that host, not a parent
    CHECK(knownIpsForHost(byHost, QString()).isEmpty());
}

// Item 4: why a check could not start or submit, as the machine's shade keys know it.
static void scannerCheckRefusal()
{
    CHECK(scanCheckRefusalReason(QStringLiteral("queue_full")) == QLatin1String("queue_full"));
    CHECK(scanCheckRefusalReason(QStringLiteral("full")) == QLatin1String("queue_full"));
    CHECK(scanCheckRefusalReason(QStringLiteral("busy")) == QLatin1String("busy"));
    CHECK(scanCheckRefusalReason(QStringLiteral("submit_failed")) == QLatin1String("unavailable"));
    CHECK(scanCheckRefusalReason(QStringLiteral("switch_off")) == QLatin1String("unavailable"));
    CHECK(scanCheckRefusalReason(QStringLiteral("not_saved")) == QLatin1String("not_saved"));
    CHECK(scanCheckRefusalReason(QStringLiteral("rejected")) == QLatin1String("rejected"));
}

// The server's kill switch, immediate: 404 (scanner_off) -> one /v1/config refresh -> the refreshed switches turn
// the Scanner off; ten 404s in a minute ask once. The fake keeps ConfigService::refreshIfStale's age gate (no
// fetch while the last one is younger than maxAge): the app fetched its config seconds before the switch went off.
struct FakeConfigService {
    int asks = 0;
    int fetches = 0;
    qint64 lastMaxAge = -1;
    qint64 now = 0;
    qint64 lastFetchMs = 0;
    QMap<QString, bool> features{{QStringLiteral("scanner"), true}};
    void refreshIfStale(qint64 maxAgeMs)
    {
        ++asks;
        lastMaxAge = maxAgeMs;
        if (lastFetchMs > 0 && now - lastFetchMs < maxAgeMs)
            return; // ConfigService::refreshIfStale: the config is "fresh", nothing is fetched
        ++fetches;
        lastFetchMs = now;
        features.remove(QStringLiteral("scanner")); // the refreshed config: v1_scanner off = the switches absent
    }
};
static void scannerKillSwitchImmediate()
{
    FakeConfigService cfg;
    auto switches = [&cfg]() {
        return scannerSwitchesFrom([&cfg](const QString &k, bool d) { return cfg.features.contains(k) ? cfg.features.value(k) : d; },
                                   true);
    };
    CHECK(switches().scanner);
    qint64 last = 0;
    const qint64 t0 = 1'700'000'000'000;
    cfg.lastFetchMs = t0 - 10'000; // the config came 10 s before the switch went off (seen in the real app, pass 4)
    cfg.now = t0;
    CHECK(facadeScannerOffRefresh(cfg, last, t0)); // the first 404
    CHECK(cfg.asks == 1 && cfg.fetches == 1);      // fetched although the config was only 10 s old
    CHECK(!switches().scanner);                    // scannerEnabled false -> the page leaves, the entries go
    for (int i = 1; i < 10; ++i) {                 // nine more 404s within the minute
        cfg.now = t0 + i * 5000;
        CHECK(!facadeScannerOffRefresh(cfg, last, cfg.now));
    }
    CHECK(cfg.asks == 1 && cfg.fetches == 1);
    cfg.features.insert(QStringLiteral("scanner"), true); // the switch came back on meanwhile
    cfg.now = t0 + kScannerOffRefreshMs;
    CHECK(facadeScannerOffRefresh(cfg, last, cfg.now)); // a minute later: once more
    CHECK(cfg.asks == 2 && cfg.fetches == 2);
}

// Item 6: the service step of Connect as a decision; the Scanner's tap runs the same one (upgradeDeclined false).
static void scannerServicePlan()
{
    // Parity with the inline rule guardedStart had before (AvpnEngineQml.cpp, wave 3, 2026-09-28).
    for (int m = 0; m < 16; ++m) {
        const bool installed = m & 1, running = m & 2, outdated = m & 4, declined = m & 8;
        const bool outdatedOnly = installed && running && outdated;
        const bool needInstall = !installed || (outdated && !(outdatedOnly && declined));
        const MacServicePlan p = macServicePlan(installed, running, outdated, declined);
        CHECK(p.outdatedOnly == outdatedOnly);
        CHECK(p.needInstall == needInstall);
        CHECK(p.act == (!running || needInstall));
    }
    // No service: install (confirm dialog + administrator password + bundled tarball).
    CHECK(macServicePlan(false, false, true, false).needInstall);
    CHECK(QLatin1String(macServiceActionName(false, false, true)) == QLatin1String("install"));
    // Installed, current, stopped: only wait for launchd.
    const MacServicePlan stopped = macServicePlan(true, false, false, false);
    CHECK(stopped.act && !stopped.needInstall);
    CHECK(QLatin1String(macServiceActionName(true, false, false)) == QLatin1String("start"));
    // Installed and running but another version (service_old / service_mismatch): the same installer replaces it.
    const MacServicePlan old = macServicePlan(true, true, true, false);
    CHECK(old.act && old.needInstall && old.outdatedOnly);
    CHECK(QLatin1String(macServiceActionName(true, true, true)) == QLatin1String("update"));
    // Connect after a refusal in this session: keeps the old service; the Scanner's tap passes false and asks again.
    CHECK(!macServicePlan(true, true, true, true).act);
    // The Scanner's tap never restarts the service under a live tunnel: install / update only with the VPN off.
    CHECK(!macServiceTapAllowed(old, /*vpnOnOrComing=*/true));
    CHECK(macServiceTapAllowed(old, false));
    CHECK(macServiceTapAllowed(stopped, true)); // starting a stopped service cannot cost a tunnel
    CHECK(!macServiceTapAllowed(macServicePlan(false, false, true, false), true));
    // Running and current: nothing.
    CHECK(!macServicePlan(true, true, false, false).act);
    CHECK(QLatin1String(macServiceActionName(true, true, false)) == QLatin1String("none"));

    // Round mac-E2: an INCOMPATIBLE running service (the replica's SignatureMismatch) - its replacement is required for a
    // connect: asked even after a decline in this session, never "connect through it".
    for (bool declined : {false, true}) {
        const MacServicePlan inc = macServicePlan(true, true, /*outdated=*/true, declined, /*incompatible=*/true);
        CHECK(inc.required && inc.act && inc.needInstall && !inc.outdatedOnly);
        CHECK(macServiceStepAfterConfirm(inc, /*accepted=*/true) == MacServiceStep::Install);   // the install path
        CHECK(macServiceStepAfterConfirm(inc, /*accepted=*/false) == MacServiceStep::StayOff);  // off, one honest line
    }
    CHECK(macServicePlan(true, true, /*outdated=*/false, false, /*incompatible=*/true).required); // the fact, not a version
    // ... a failed install is the existing StayOff of finishSvcInstall; the next Connect asks again: nothing remembered
    CHECK(macServicePlan(true, true, true, /*declined=*/true, true).act);
    // A compatible older service keeps the wave-3 rule: a decline connects through it, a declined session is not asked again.
    const MacServicePlan older = macServicePlan(true, true, true, false, /*incompatible=*/false);
    CHECK(!older.required && older.outdatedOnly);
    CHECK(macServiceStepAfterConfirm(older, false) == MacServiceStep::ConnectWithOld);
    CHECK(!macServicePlan(true, true, true, true, false).act);
    // No service at all: a decline stays off (as before).
    CHECK(macServiceStepAfterConfirm(macServicePlan(false, false, true, false, false), false) == MacServiceStep::StayOff);
    // An incompatible service that is not running is not "running and incompatible": the existing install / start rules.
    CHECK(!macServicePlan(true, false, false, false, true).required);

    // Round mac-E3: the trigger - only an install that cured an INCOMPATIBLE service restarts the app.
    CHECK(restartAfterServiceInstall(/*installOk=*/true, /*wasIncompatible=*/true));
    CHECK(!restartAfterServiceInstall(true, false));  // a compatible older service replaced: no restart
    CHECK(!restartAfterServiceInstall(false, true));  // the install failed: nothing to restart for
    CHECK(!restartAfterServiceInstall(false, false)); // declined: no install ran
    // ... the one-shot record across the restart (a real QSettings file)
    {
        QTemporaryDir dir;
        QSettings st(dir.filePath(QStringLiteral("rc.ini")), QSettings::IniFormat);
        const qint64 t = 1764000000000LL;
        RestartConnectRecord w;
        w.writtenMs = t;
        w.kind = QStringLiteral("connect");
        writeRestartConnect(st, w);
        const RestartConnectRecord first = takeRestartConnect(st);
        CHECK(first.valid() && first.kind == QLatin1String("connect"));
        CHECK(restartConnectStep(first, t + 4000, /*serviceCompatible=*/true) == RestartConnectStep::Honour); // fresh, once
        CHECK(!takeRestartConnect(st).valid()); // taken: a second launch finds nothing - consumed twice impossible
        CHECK(restartConnectStep(first, t + kRestartConnectFreshMs + 1, true) == RestartConnectStep::Drop); // stale
        CHECK(restartConnectStep(first, t - 1, true) == RestartConnectStep::Drop); // the clock went back: not "fresh"
        CHECK(restartConnectStep(first, t + 4000, /*serviceCompatible=*/false) == RestartConnectStep::Drop); // still incompatible
        CHECK(restartConnectStep(RestartConnectRecord(), t, true) == RestartConnectStep::Drop); // nothing written
        RestartConnectRecord row;
        row.writtenMs = t;
        row.kind = QStringLiteral("row");
        row.row = QStringLiteral("up:aaaaaaaaaaaaaaa0");
        writeRestartConnect(st, row);
        const RestartConnectRecord taken = takeRestartConnect(st);
        CHECK(taken.kind == QLatin1String("row") && taken.row == row.row);
        CHECK(restartConnectStep(taken, t + 1000, true) == RestartConnectStep::Honour);
        RestartConnectRecord bad = row;
        bad.row.clear();
        CHECK(!bad.valid() && restartConnectStep(bad, t + 1000, true) == RestartConnectStep::Drop);
        CHECK(kRestartConnectFreshMs == 60000);
    }
}

// Owner's iPhone 16.11 (build 140), D4: a provider start refused before the core ever started (lease transport
// failure) was a synthetic Error right after the observed Disconnected of the old tunnel. On iOS it set
// needStatusBeforeStart; the status reply was the unchanged Disconnected (IosController never re-emits it), and
// every orb tap renewed the status budget - four taps, no start, until a relaunch.
static void preNativeErrorNeedsNoStatus()
{
    // "Before": the old one-argument rule latches.
    TeardownLatch before;
    observeTunnelState(before, ObservedTunnel::Error, false);
    CHECK(before.needStatusBeforeStart && !reconcileActionable(ObservedTunnel::Error, before));
    // Disconnected -> Error with nothing in between: the teardown stays proven, the start goes at once.
    TeardownLatch l;
    observeTunnelState(l, ObservedTunnel::Connected, ObservedTunnel::Disconnected, false);
    observeTunnelState(l, ObservedTunnel::Disconnected, ObservedTunnel::Error, false);
    CHECK(!l.needStatusBeforeStart && !l.awaitingStopConfirm);
    CHECK(reconcileGate(l, ObservedTunnel::Error, true, true) == ReconcileGate::Proceed);
    CHECK(reconcileActionable(ObservedTunnel::Error, l));
    // Error -> Error (the next refused provider): unchanged either way - proven stays proven ...
    observeTunnelState(l, ObservedTunnel::Error, ObservedTunnel::Error, false);
    CHECK(!l.needStatusBeforeStart);
    // ... and a native Error that is unproven stays unproven (the latch is not cleared by a repeat).
    TeardownLatch n;
    observeTunnelState(n, ObservedTunnel::Transitional, ObservedTunnel::Error, false); // Connecting -> Error: native
    CHECK(n.needStatusBeforeStart);
    observeTunnelState(n, ObservedTunnel::Error, ObservedTunnel::Error, false);
    CHECK(n.needStatusBeforeStart);
    // A native attempt in between (connectToVpn always reports Connecting first) keeps today's rule.
    TeardownLatch c;
    observeTunnelState(c, ObservedTunnel::Disconnected, ObservedTunnel::Transitional, false);
    observeTunnelState(c, ObservedTunnel::Transitional, ObservedTunnel::Error, false);
    CHECK(c.needStatusBeforeStart);
    // Connected -> Error (a live session failed): unchanged rule.
    TeardownLatch d;
    observeTunnelState(d, ObservedTunnel::Connected, ObservedTunnel::Error, false);
    CHECK(d.needStatusBeforeStart);
    // Our stop in flight is not confirmed by such an Error either (only Disconnected confirms it).
    TeardownLatch s;
    s.awaitingStopConfirm = true;
    observeTunnelState(s, ObservedTunnel::Error, ObservedTunnel::Error, false);
    CHECK(s.awaitingStopConfirm);
    // Platforms where Error proves the teardown: unchanged (the latch clears).
    TeardownLatch w;
    w.needStatusBeforeStart = true;
    observeTunnelState(w, ObservedTunnel::Disconnected, ObservedTunnel::Error, true);
    CHECK(!w.needStatusBeforeStart);
}

// D4: seat first - the live tunnel stays until the provider's seat and profile are in hand.
static void upstreamSeatFirstRule()
{
    CHECK(upstreamSeatFirst(true, true, false));
    CHECK(!upstreamSeatFirst(false, true, false)); // the tunnel is down: the ordinary start (nothing to keep)
    CHECK(!upstreamSeatFirst(true, false, false)); // an own node: the ordinary pin restart
    CHECK(!upstreamSeatFirst(true, true, true));   // a provider session is live: one owner, one seat - old order
    const QString a = QStringLiteral("up:aaaaaaaaaaaaaaa0");
    UpstreamSeatFirst p{true, a, QStringLiteral("12:xray"), true, 7, /*prepareId=*/42};
    CHECK(decideSeatFirstReply(p, a, 42, 7, true) == SeatFirstStep::Switch);
    CHECK(decideSeatFirstReply(p, a, 42, 7, false) == SeatFirstStep::Stay);
    CHECK(decideSeatFirstReply(p, a, 42, 8, true) == SeatFirstStep::Drop);
    CHECK(decideSeatFirstReply(p, a, 42, 8, false) == SeatFirstStep::Drop);
    CHECK(decideSeatFirstReply(p, QStringLiteral("up:bbbbbbbbbbbbbbb0"), 42, 7, true) == SeatFirstStep::Ignore);
    CHECK(decideSeatFirstReply(UpstreamSeatFirst(), a, 0, 0, true) == SeatFirstStep::Ignore);
    // Review F5 of 17.11: the queued success of an EARLIER prepare of the same node, matched after a second tap
    // started a new prepare (same node, the intent serial of the new tap): never taken for the pending one.
    CHECK(decideSeatFirstReply(p, a, 41, 7, true) == SeatFirstStep::Ignore);
    CHECK(decideSeatFirstReply(p, a, 41, 7, false) == SeatFirstStep::Ignore);
    UpstreamSeatFirst noId = p;
    noId.prepareId = 0;
    CHECK(decideSeatFirstReply(noId, a, 0, 7, true) == SeatFirstStep::Ignore);
    // While the seat is being taken the Scanner sees the provider node as the attempt (never probed with its key).
    const ScanLiveView v = scanLiveView(QStringLiteral("connected"), true, QStringLiteral("12:xray"), QString(),
                                        QStringLiteral("up:aaaaaaaaaaaaaaa0"), QString(), true, /*restartPending=*/true, true, /*attemptFailed=*/false);
    CHECK(v.live && v.nodeId == QLatin1String("12:xray") && v.attemptNodeId == QLatin1String("up:aaaaaaaaaaaaaaa0"));
}

// U7 (device test of 142): the Connect card and the server list row show a node's signal by one rule.
static void nodeFigureOneRule()
{
    // A connected provider node: the live probe answered 47 ms, the Scanner has no figure on this network ->
    // nothing (the card showed 47 ms and green bars while its row showed "—").
    NodeFigure f = nodeFigure(/*upstream=*/true, /*currentLive=*/true, true, false, 47, 5, -1);
    CHECK(f.ms == -1 && f.bars == -1 && !f.failed);
    // ...with a Scanner figure: that figure, on the card as in the row.
    f = nodeFigure(true, true, true, false, 47, 5, 92);
    CHECK(f.ms == 92 && f.bars == barsForNode(92));
    const NodeFigure row = nodeFigure(true, false, true, false, 47, 5, 92);
    CHECK(row.ms == f.ms && row.bars == f.bars);
    // Our own node carrying the tunnel: the live probe once it has a figure; before it answers - its list figure,
    // never bars next to a dash.
    f = nodeFigure(false, true, true, false, 41, 4, 60);
    CHECK(f.ms == 41 && f.bars == 4);
    f = nodeFigure(false, true, false, false, -1, 0, 60);
    CHECK(f.ms == 60 && f.bars == barsForNode(60));
    f = nodeFigure(false, true, false, false, -1, 0, -1);
    CHECK(f.ms == -1 && f.bars == -1);
    // A dead probe on the node carrying the tunnel: red, whatever the kind.
    CHECK(nodeFigure(false, true, true, true, 41, 4, 60).failed);
    CHECK(nodeFigure(true, true, true, true, 41, 4, 92).failed);
    // Rows not carrying the tunnel: their figure, else the idle track.
    f = nodeFigure(false, false, true, false, 41, 4, 60);
    CHECK(f.ms == 60 && f.bars == barsForNode(60) && !f.failed);
    f = nodeFigure(false, false, true, true, 41, 4, -1);
    CHECK(f.ms == -1 && f.bars == -1 && !f.failed);
}

// Review R50 2: the tunnel worked, then stopped passing data (amber «трафик не проходит»); the person toggles the network
// and the transport stays Connected. A move of the uplink fact (AvpnEngineQml::noteUplinkFact) sets the live claim back to
// "not known yet": neither the stale failure (liveDead) nor the stale proof (a live pass, the connect's "works") shows
// ONLINE - only a live probe that passes again does. The live fields as the facade keeps them.
static void r50UplinkMoveVoidsTheLiveClaim()
{
    for (const QString &connectVerdict : {QString(), QStringLiteral("works")}) { // own AWG node / provider session
        bool dead = false;
        LiveProof proof = LiveProof::None;
        const auto online = [&] { return dataFlowingNow(true, dead, connectVerdict, proof); };
        CHECK(online() == (connectVerdict == QLatin1String("works"))); // a new session: the connect's "works" may go first
        proof = liveProofAfterProbe(proof, true);                       // a live probe passes
        CHECK(proof == LiveProof::Proven && online());
        proof = liveProofAfterProbe(proof, false);                      // ...then the data stops: the dead streak
        dead = true;
        CHECK(proof == LiveProof::Proven && !online());                 // «Подключено, трафик не проходит»
        // the network goes and comes back, the tunnel stays Connected: both moves void the live claim
        for (int move = 0; move < 2; ++move) {
            dead = false;
            proof = liveProofAfterUplinkMove(proof);
            CHECK(proof == LiveProof::Voided);
            CHECK(!online()); // was ONLINE + «Защита активна» here while no data passed
        }
        proof = liveProofAfterProbe(proof, false); // the first probe after the return fails: still not known
        CHECK(proof == LiveProof::Voided && !online());
        proof = liveProofAfterProbe(proof, true);  // a fresh pass: ONLINE again
        CHECK(proof == LiveProof::Proven && online());
        // a move before anything was measured voids the connect's "works" as well
        CHECK(!dataFlowingNow(true, false, connectVerdict, liveProofAfterUplinkMove(LiveProof::None)));
        // the connect's own verdicts still forbid after a fresh pass
        CHECK(!dataFlowingNow(true, false, QStringLiteral("no_data"), liveProofAfterProbe(LiveProof::Voided, true)));
    }
}

// S1 (owner road 26.11, journal J2): the server the person tapped wins over the transport mode - a location without the
// mode's transport, and a Scanner row whose own path kind the mode excludes; an attempt that never started ends the row's
// request without a verdict.
static void s1ExactRowWinsOverTheMode()
{
    // a location the mode cannot serve (setPinnedNode no_transport): switch, whatever the row
    CHECK(serverTapSwitchesModeToAuto(false, QStringLiteral("no_transport: location x has no 'awg' transport"), false, false, false));
    CHECK(serverTapSwitchesModeToAuto(false, QStringLiteral("no_transport: location x has no 'awg' transport"), true, false, true));
    // another refusal of the pin: no switch (the pin's own error)
    CHECK(!serverTapSwitchesModeToAuto(false, QStringLiteral("node not in subscription: 12:xray"), true, false, false));
    CHECK(!serverTapSwitchesModeToAuto(false, QStringLiteral("unsupported_proto: node 9 proto 'x'"), true, false, true));
    // the pin passed by location (Germany 1 has an AmneziaWG listener): a Scanner Xray row in AmneziaWG mode that Auto
    // would dial switches; a server of the list does not (a preference: its allowed transports); a row ranked now does not
    CHECK(serverTapSwitchesModeToAuto(true, QString(), true, false, true));
    CHECK(!serverTapSwitchesModeToAuto(true, QString(), false, false, true));
    CHECK(!serverTapSwitchesModeToAuto(true, QString(), true, true, true));
    // review C4: a row Auto would not dial either (no health, a platform without its proto): no mode change
    CHECK(!serverTapSwitchesModeToAuto(true, QString(), true, false, false));
    // second read: also when the exact row's pin was refused for transport (a provider row in AmneziaWG mode) -
    // switch only if Auto would dial it; a tap from the server list keeps decision 9 (location level)
    CHECK(!serverTapSwitchesModeToAuto(false, QStringLiteral("no_transport: location x has no 'awg' transport"), true, false, false));
    CHECK(serverTapSwitchesModeToAuto(false, QStringLiteral("no_transport: location x has no 'awg' transport"), false, false, false));
    // rule 2: only the result of the attempt that ended inside connect() ends the row without a verdict
    CHECK(scanRowEndOf(3, 3) == ScanRowEnd::NoVerdict);
    CHECK(scanRowEndOf(4, 3) == ScanRowEnd::Failed);  // a later attempt that dialled
    CHECK(scanRowEndOf(3, 0) == ScanRowEnd::Failed);  // nothing ended at once
    CHECK(scanRowEndOf(0, 0) == ScanRowEnd::Failed);
}

// T1 (owner road 26.11, journal J1; review C5): one judgement per real return - the first status asked after it; a check
// only on a live AmneziaWG session with the intent on, nothing else running, outside the network-change grace, at or
// past the threshold; any other first answer disarms it.
static void t1ThawStallCheck()
{
    ThawStallCheckInput in;
    in.armedForThawMs = 1'000'000;
    in.stallAtMs = 1'001'200;
    in.stallSec = 600; // J1: ten minutes of demand without data
    in.awgConnected = true;
    in.intentOn = true;
    in.idle = true;
    in.thresholdSec = 45;
    CHECK(judgeThawStall(in) == ThawStallJudgement::Check);
    ThawStallCheckInput x = in;
    x.stallSec = 45;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Check);   // at the threshold
    x.stallSec = 44;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // below: judged, disarmed
    x = in; x.stallSec = 0;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // tribe.22: 0 = data flows or nobody sends
    x = in; x.stallSec = -1;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // unknown or stale (freshDataStallSec)
    x = in; x.stallAtMs = 999'000;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Wait);    // a status asked before the return: not this judgement
    x = in; x.armedForThawMs = 0;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Wait);    // not armed: an Inactive -> Active flicker, or judged already
    x = in; x.networkGrace = true;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // a network change is being healed
    x = in; x.idle = false;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // an own start / stop / teardown latch / attempt / check / pause
    x = in; x.intentOn = false;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);
    x = in; x.awgConnected = false;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // Xray, a provider, not connected
    x = in; x.thresholdSec = 0;
    CHECK(judgeThawStall(x) == ThawStallJudgement::Disarm);  // awg_probe_dead_stall_s off
}

int main()
{
    f2cStatusTakesOverARebuild();
    t1NotificationStartIsAdopted();
    s1ExactRowWinsOverTheMode();
    t1ThawStallCheck();
    r50UplinkMoveVoidsTheLiveClaim();
    r20PhysicalLossDuringConnect();
    p5bOfflineObservation();
    p7CardNeverNamesThePinForALiveSession();
    f1StartRefusalJudgedByItsResult();
    f2UnknownAfterOffline();
    android3StatusResolvesAGivenUpStop();
    r2LateConnectedAfterThePersonsStop();
    r3StatusAdoptionObeysThePersonsStop();
    g4ServiceGoneOnReturn();
    a1ErrorDoesNotLatchAdoption();
    a4AdoptNewSessionAfterOff();
    rev1UnconfirmedStopIsDriven();
    rev3GenerationKinds();
    a2EmptyIssuanceKeepsPoolAndLkg();
    a6a7PinPersistence();
    pinOnTransportModeChange();
    tunnelAsTheTransportModeGateSeesIt();
    lateDeadlineTick();
    a8a9a15InternalSwitch();
    a10a11Selection();
    parityConnectDoesNotWaitForNetwork();
    parityBackgroundPollingOnlyWhenActive();
    wave3StartAndLossPolicy();
    wave4UpstreamBehaviour();
    a12Outbox();
    a16ReliabilityRingCollapse();
    gap1DoctorNodeProblem();
    gap4ReportReliabilityContext();
    a5HintedCardRow();
    scannerRowTapConnectsWithVpnOff();
    scannerRowTapMovesLiveTunnel();
    scannerSwitchesAbsentIsToday();
    scannerNeedsProbeHost();
    scannerConnectOnOpen();
    scannerCancelPendingConnect();
    scannerCancelAfterShownConnectedWithoutData();
    scannerCancelNeverDuringAppQuit();
    whitelistTriggerFromOwner();
    checkBlameRule();
    stopNothingNative();
    exactRowRequestObject();
    scannerRowChain();
    scannerRowOutcomeBelongsToItsAttempt();
    scannerLiveView();
    scannerPhysicalNetworkKind();
    scannerKnownHostIps();
    scannerCheckRefusal();
    scannerKillSwitchImmediate();
    scannerServicePlan();
    preNativeErrorNeedsNoStatus();
    upstreamSeatFirstRule();
    nodeFigureOneRule();
    if (g_fail) {
        std::printf("facade_policy_check: %d FAILED\n", g_fail);
        return 1;
    }
    std::printf("facade_policy_check: OK\n");
    return 0;
}

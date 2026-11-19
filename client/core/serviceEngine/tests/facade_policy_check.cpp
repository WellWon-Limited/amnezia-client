// AVPN (фикс-волна 2026-09-22, зона CL-A): чистые решения фасада AvpnEngineQml
// (DebugSnapshot.h / ReportDelivery.h). Каждый блок — сценарий из ревью реализации; на коде до
// фикса он либо не собирается (решения не было — фасад делал дефектное действие инлайн), либо
// падает на утверждении (canAdoptObservedTunnel «manual OFF»).
#include "../DebugSnapshot.h"
#include "../DoctorReport.h"
#include "../NodeRanking.h" // nodeFigure (U7)
#include "../ReportDelivery.h"
#include "../UplinkMonitor.h"
#include "../UpstreamEngine.h" // upstreamNetworkKey (Scanner item 7)

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
    // Owner test 06.11: clearConnectionCache() strands requests in flight. Our clear - only on a real
    // transition; abort whenever someone cleared: we, or upstream on EVERY Connected (adoption too).
    {
        const auto act = [](ObservedTunnel p, ObservedTunnel n) {
            const TransitionNetAction a = transitionNetAction(p, n);
            return QByteArray(a.clearCache ? "C" : "-") + (a.abortInFlight ? "A" : "-");
        };
        CHECK(act(ObservedTunnel::Transitional, ObservedTunnel::Connected) == "CA");  // tunnel up
        CHECK(act(ObservedTunnel::Disconnected, ObservedTunnel::Connected) == "CA");
        CHECK(act(ObservedTunnel::Connected, ObservedTunnel::Disconnected) == "CA");  // tunnel down
        CHECK(act(ObservedTunnel::Transitional, ObservedTunnel::Disconnected) == "CA");
        CHECK(act(ObservedTunnel::Unknown, ObservedTunnel::Disconnected) == "--");    // cold start, tunnel off
        CHECK(act(ObservedTunnel::Unknown, ObservedTunnel::Connected) == "-A");       // adoption: upstream cleared
        CHECK(act(ObservedTunnel::Connected, ObservedTunnel::Connected) == "-A");     // repeat: upstream cleared
        CHECK(act(ObservedTunnel::Connected, ObservedTunnel::Transitional) == "--");
        CHECK(act(ObservedTunnel::Disconnected, ObservedTunnel::Disconnected) == "--");
    }
    CHECK(reissueAfterOwnAbort(true, false));   // our abort on a transition -> re-issue once
    CHECK(!reissueAfterOwnAbort(true, true));   // our 15 s timeout -> no
    CHECK(!reissueAfterOwnAbort(false, false)); // answered / failed by the network -> no
    // 5.1.108: ONLINE without node_scan - the live in-tunnel probe proves data; whoami only
    // accelerates (works) or forbids (no_data / bypass); a confirmed dead probe always forbids.
    CHECK(!dataFlowingNow(true, false, QString(), false));                      // nothing proven yet
    CHECK(dataFlowingNow(true, false, QString(), true));                        // flag off, live probe ok
    CHECK(dataFlowingNow(true, false, QStringLiteral("works"), false));         // whoami first
    CHECK(dataFlowingNow(true, false, QStringLiteral("limited"), true));        // limited + live probe
    CHECK(!dataFlowingNow(true, false, QStringLiteral("limited"), false));
    CHECK(!dataFlowingNow(true, false, QStringLiteral("no_data"), true));       // whoami forbids
    CHECK(!dataFlowingNow(true, false, QStringLiteral("bypass"), true));
    CHECK(!dataFlowingNow(true, true, QStringLiteral("works"), true));          // dead live probe
    CHECK(!dataFlowingNow(false, false, QStringLiteral("works"), true));        // tunnel not up
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
    // Scanner notices (coordinator 18.11 (c) + device round air9 19.11 10:08): a new generation, or the Scanner's
    // network key completing with the same generation; nothing new - no notice.
    {
        const QString wifiBare = QStringLiteral("wifi|wifi|"), wifiFull = QStringLiteral("wifi|wifi:asn:64500|a1b2c3d4e5f60718");
        CHECK(scanNetworkNoticeDue(3, 4, wifiBare, wifiBare));        // the engine's generation moved
        CHECK(scanNetworkNoticeDue(4, 4, wifiBare, wifiFull));        // the key completed, the same generation (air9)
        CHECK(!scanNetworkNoticeDue(4, 4, wifiFull, wifiFull));       // nothing moved: our own tunnel settling, a row tap
        CHECK(scanNetworkNoticeDue(4, 4, QString(), wifiFull));       // the Scanner never got a notice
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
        return scannerSwitchesFrom([&m](const QString &k, bool d) { return m.contains(k) ? m.value(k) : d; });
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
    const ExactRowRequest a = ExactRowRequest::begin(none, QStringLiteral("B"), QStringLiteral("A"), true);
    CHECK(a.active() && a.exactFor(QStringLiteral("B")) && !a.exactFor(QStringLiteral("A")));
    CHECK(a.restorePin == QLatin1String("A") && a.reconnect);
    // a second row while the first runs: the person's choice before the FIRST tap stays the one to come back to
    const ExactRowRequest c = ExactRowRequest::begin(a, QStringLiteral("C"), QStringLiteral("B"), false);
    CHECK(c.row == QLatin1String("C") && c.restorePin == QLatin1String("A") && c.reconnect);
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
    // Device round 19.11: airplane mode while connected - the failover fails with no network under it.
    using avpn::FailedAttemptIntent;
    CHECK(avpn::failedAttemptIntent(true, false, true) == FailedAttemptIntent::Wait);   // the airplane case
    CHECK(avpn::failedAttemptIntent(true, false, false) == FailedAttemptIntent::Wait);  // a tap with no network
    CHECK(avpn::failedAttemptIntent(true, true, true) == FailedAttemptIntent::DropAndResume); // lost session, live net
    CHECK(avpn::failedAttemptIntent(true, true, false) == FailedAttemptIntent::Drop);   // a tap that found nothing
    CHECK(avpn::failedAttemptIntent(false, false, true) == FailedAttemptIntent::Drop);  // exact server, permission...
}

static void checkBlameRule()
{
    using avpn::CheckBlame;
    CHECK(avpn::checkFailureBlame(true, 4500, 4000, true, 100) == CheckBlame::Path);       // no data through the tunnel
    CHECK(avpn::checkFailureBlame(true, 4500, 4000, false, -1) == CheckBlame::Path);       // no counter: as before
    CHECK(avpn::checkFailureBlame(false, 4500, 4000, true, 0) == CheckBlame::NoNetwork);   // the network went away
    CHECK(avpn::checkFailureBlame(true, 13800, 4000, true, 0) == CheckBlame::Suspended);   // 13.8 s after the background
    CHECK(avpn::checkFailureBlame(true, 6400, 4000, true, 90000) == CheckBlame::ControlPlane); // the tunnel carries data
    CHECK(avpn::checkFailureBlame(true, 7000, 4000, true, 0) == CheckBlame::Path);         // within the stretch grace
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
static void scannerRowChain()
{
    ScanRowAttempt a;
    CHECK(scanRowAttemptObserve(a, 1, QStringLiteral("9"), true, false).failed.isEmpty()); // inactive: silent
    scanRowAttemptBegin(a, QStringLiteral("9"), 3);
    ScanRowStep st = scanRowAttemptObserve(a, 3, QStringLiteral("9"), false, false);
    CHECK(st.failed.isEmpty() && !st.connected && !st.ended);
    st = scanRowAttemptObserve(a, 3, QStringLiteral("11"), false, false); // the ladder left 9 for 11
    CHECK(st.failed == QStringList{QStringLiteral("9")});
    st = scanRowAttemptObserve(a, 3, QStringLiteral("11"), false, false);
    CHECK(st.failed.isEmpty()); // reported once
    st = scanRowAttemptObserve(a, 3, QStringLiteral("11"), /*dataFlowing=*/true, false);
    CHECK(st.connected && st.connectedNode == QLatin1String("11"));
    CHECK(!a.active);
    // The chain gives up: the current node failed, the chain ends.
    scanRowAttemptBegin(a, QStringLiteral("9"), 4);
    st = scanRowAttemptObserve(a, 4, QStringLiteral("9"), false, /*gaveUp=*/true);
    CHECK(st.ended && st.failed == QStringList{QStringLiteral("9")});
    // Another action took the tunnel (orb, another tap): silent, no failure reported.
    scanRowAttemptBegin(a, QStringLiteral("9"), 5);
    st = scanRowAttemptObserve(a, /*intentSerial=*/6, QStringLiteral("10"), false, true);
    CHECK(st.failed.isEmpty() && !st.ended && !st.connected && !a.active);
    // R4 (device round 4): the session before the tap (data on another node, the sibling «Эстония 3») is not a row
    // of this chain: nothing is reported for it, before or after the tapped row fails.
    scanRowAttemptBegin(a, QStringLiteral("9"), 7);
    st = scanRowAttemptObserve(a, 7, QStringLiteral("10"), true, false);
    CHECK(!st.connected && st.failed.isEmpty() && a.active);
    st = scanRowAttemptObserve(a, 7, QStringLiteral("9"), false, false);
    CHECK(st.failed.isEmpty());
    st = scanRowAttemptObserve(a, 7, QString(), false, /*gaveUp=*/true);
    CHECK(st.ended && st.failed == QStringList{QStringLiteral("9")});
    // the tapped row never came up and the chain gave up: only the tapped row
    scanRowAttemptBegin(a, QStringLiteral("9"), 8);
    st = scanRowAttemptObserve(a, 8, QStringLiteral("10"), false, /*gaveUp=*/true);
    CHECK(st.ended && st.failed == QStringList{QStringLiteral("9")});
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
        return scannerSwitchesFrom([&cfg](const QString &k, bool d) { return cfg.features.contains(k) ? cfg.features.value(k) : d; });
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

int main()
{
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
    scannerConnectOnOpen();
    scannerCancelPendingConnect();
    scannerCancelAfterShownConnectedWithoutData();
    scannerCancelNeverDuringAppQuit();
    whitelistTriggerFromOwner();
    checkBlameRule();
    stopNothingNative();
    exactRowRequestObject();
    scannerRowChain();
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

// AVPN (фикс-волна 2026-09-22, зона CL-A): чистые решения фасада AvpnEngineQml
// (DebugSnapshot.h / ReportDelivery.h). Каждый блок — сценарий из ревью реализации; на коде до
// фикса он либо не собирается (решения не было — фасад делал дефектное действие инлайн), либо
// падает на утверждении (canAdoptObservedTunnel «manual OFF»).
#include "../DebugSnapshot.h"
#include "../DoctorReport.h"
#include "../ReportDelivery.h"

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

static void a8a9a15InternalSwitch()
{
    // A8: дедлайн свитча — повтор старта, намерение снимается только при исчерпании попыток.
    CHECK(decideSwitchDeadline(1) == SwitchDeadlineAction::RetryStart);
    CHECK(decideSwitchDeadline(2) == SwitchDeadlineAction::RetryStart);
    CHECK(decideSwitchDeadline(3) == SwitchDeadlineAction::GiveUp);

    // A9: до фикса решение принималось по состоянию движка ПОСЛЕ onTunnelError (всегда "error") →
    // Error посреди внутреннего failover снимал намерение без тоста. Теперь — по состоянию ДО.
    CHECK(!tunnelLossIsExternal(false, QStringLiteral("switching"), false));
    CHECK(!tunnelLossIsExternal(false, QStringLiteral("error"), /*interrupted=*/true));
    CHECK(tunnelLossIsExternal(false, QStringLiteral("connected"), false)); // внешний обрыв — §13
    CHECK(tunnelLossIsExternal(false, QStringLiteral("error"), false));
    CHECK(!tunnelLossIsExternal(true, QStringLiteral("connected"), false)); // наша операция

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
    CHECK(decideSelectionBudget(true, 5999) == SelectionBudget::KeepWaiting);
    CHECK(decideSelectionBudget(true, 6000) == SelectionBudget::Finish);

    // A11: без pin ICMP-раунд сразу (параллельно refresh), а не по таймеру 4 с.
    CHECK(startRttRoundImmediately(false, true));
    CHECK(!startRttRoundImmediately(true, true));
    CHECK(!startRttRoundImmediately(false, false));
    // Прошлый RTT не очищается в начале раунда и не затирается «нет ответа».
    QHash<QString, int> cache{{QStringLiteral("9:awg"), 40}};
    mergeRttSample(cache, QStringLiteral("9:awg"), -1);
    CHECK(cache.value(QStringLiteral("9:awg")) == 40);
    mergeRttSample(cache, QStringLiteral("9:awg"), 35);
    CHECK(cache.value(QStringLiteral("9:awg")) == 35);
    mergeRttSample(cache, QStringLiteral("10:awg"), -1);
    CHECK(cache.value(QStringLiteral("10:awg")) == -1);
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

int main()
{
    a1ErrorDoesNotLatchAdoption();
    a4AdoptNewSessionAfterOff();
    rev1UnconfirmedStopIsDriven();
    rev3GenerationKinds();
    a2EmptyIssuanceKeepsPoolAndLkg();
    a6a7PinPersistence();
    a8a9a15InternalSwitch();
    a10a11Selection();
    a12Outbox();
    a16ReliabilityRingCollapse();
    gap1DoctorNodeProblem();
    gap4ReportReliabilityContext();
    a5HintedCardRow();
    if (g_fail) {
        std::printf("facade_policy_check: %d FAILED\n", g_fail);
        return 1;
    }
    std::printf("facade_policy_check: OK\n");
    return 0;
}

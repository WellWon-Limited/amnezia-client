// AVPN serviceEngine — снимок состояния для диагностической панели (5 тапов по логотипу). [СКАФФОЛД]
#pragma once

#include <functional> // build 142: NoHandshakeOps

#include "dto/Subscription.h"
#include "ConfigCachePolicy.h" // kConfigRefreshThrottleMs - the one throttle of the config refresh
#include "TransportModeGate.h"  // ModeTunnel - what the transport-mode gate is told about the tunnel
#include "WhoamiVerdict.h" // timerFiredLate - the one "late timer = frozen process" rule (§29 п.5)
#include <QHash>
#include <QPair>
#include <QRegularExpression>
#include <QString>
#include <QStringList>
#include <QList>
#include <QVariantMap>

namespace avpn {

// ── AVPN (фикс-волна 2026-09-22, CL-A) — чистые решения фасада (AvpnEngineQml), покрыты
// tests/facade_policy_check.cpp. Фасад держит состояние, здесь только «что делать».

// A1/A4: адопт наблюдённого живого туннеля (iOS/MACOS_NE; на остальных платформах фасад
// адоптирует по базе — только при operationIdle).
//  Reject              — пауза / наша операция в полёте / МЫ просили стоп этой же сессии и
//                        Disconnected ещё не видели (stop в пути).
//  AdoptExistingIntent — намерение уже «вкл» (или неизвестно — холодный старт).
//  AdoptNewIntent      — намерение «выкл», но туннель поднят НОВОЙ сессией: стоп уже подтверждён
//                        Disconnected-ом (awaitingStopConfirm снят) либо runtime-поколение
//                        отличается от гашенного. Это ОС/Настройки/Shortcuts — не авто-коннект
//                        приложения (§13 цел): фасад ставит намерение «вкл» и пишет "resume".
enum class TunnelAdoption { Reject, AdoptExistingIntent, AdoptNewIntent };

// A4 (ревью CL-A r2): sessionMetadata()["generation"] бывает двух видов. Runtime-поколение NE
// (после первого status-ответа; в метаданных есть ключ configuration_generation) и поколение
// КОНФИГУРАЦИИ профиля (restoreSessionMetadata из prefs; ключа configuration_generation нет).
// Сравнивать можно только однородное: иначе первый runtime-ответ ТОЙ ЖЕ сессии выглядел «новой
// сессией», и адопт отменял выключение пользователя («VPN сам подключается»).
struct SessionGeneration {
    QString runtime;       // runtime-поколение NE; пусто — известно только поколение конфигурации
    QString configuration; // поколение конфигурации профиля (prefs)
    bool known() const { return !runtime.isEmpty() || !configuration.isEmpty(); }
};
inline SessionGeneration sessionGenerationFrom(const QVariantMap &metadata)
{
    const QString generation = metadata.value(QStringLiteral("generation")).toString();
    if (metadata.contains(QStringLiteral("configuration_generation")))
        return { generation, metadata.value(QStringLiteral("configuration_generation")).toString() };
    return { QString(), generation };
}
// Доказанно ДРУГАЯ сессия: оба runtime-поколения известны и различаются, либо различаются
// поколения конфигурации (профиль пересохранён — это не гашенная нами сессия). Новый запуск NE
// того же профиля при известном только поколении конфигурации неотличим от гашенной сессии —
// его признак наблюдённый Disconnected (awaitingStopConfirm снят).
inline bool isDifferentSession(const SessionGeneration &stopped, const SessionGeneration &observed)
{
    if (!stopped.runtime.isEmpty() && !observed.runtime.isEmpty())
        return stopped.runtime != observed.runtime;
    return !stopped.configuration.isEmpty() && !observed.configuration.isEmpty()
        && stopped.configuration != observed.configuration;
}
inline TunnelAdoption decideTunnelAdoption(bool connected, bool intentKnown, bool wantConnected,
                                           bool paused, bool awaitingStopConfirm, bool operationIdle,
                                           const SessionGeneration &stopped,
                                           const SessionGeneration &observed)
{
    if (!connected || paused || !operationIdle)
        return TunnelAdoption::Reject;
    if (awaitingStopConfirm && !isDifferentSession(stopped, observed))
        return TunnelAdoption::Reject;
    if (!intentKnown || wantConnected)
        return TunnelAdoption::AdoptExistingIntent;
    return TunnelAdoption::AdoptNewIntent;
}
// Строковая форма: обе строки — runtime-поколения NE (совместимость с прежними проверками).
inline TunnelAdoption decideTunnelAdoption(bool connected, bool intentKnown, bool wantConnected,
                                           bool paused, bool awaitingStopConfirm, bool operationIdle,
                                           const QString &stopGeneration = {},
                                           const QString &observedGeneration = {})
{
    return decideTunnelAdoption(connected, intentKnown, wantConnected, paused, awaitingStopConfirm,
                                operationIdle, SessionGeneration{ stopGeneration, QString() },
                                SessionGeneration{ observedGeneration, QString() });
}

// Native observations never override a pause, our own in-flight operation or a stop of the same
// session that has not been confirmed yet. An OFF intent does NOT block a new session (A4).
inline bool canAdoptObservedTunnel(bool connected, bool intentKnown, bool wantConnected,
                                  bool paused, bool awaitingDown, bool operationIdle)
{
    return decideTunnelAdoption(connected, intentKnown, wantConnected, paused, awaitingDown,
                                operationIdle) != TunnelAdoption::Reject;
}

// A1: латч «подтверждения» разделён на два смысла.
//  awaitingStopConfirm   — МЫ попросили стоп: не адоптить эту сессию, не стартовать и не гнать
//                          health до Disconnected.
//  needStatusBeforeStart — был Error (iOS/MACOS_NE: Error не доказывает teardown): перед НОВЫМ
//                          стартом нужен наблюдённый терминал. Адопт и health он НЕ блокирует.
// errorProvesTeardown=true на Android/macOS-демоне/Windows (база 3c8cc74e: Error — терминал).
enum class ObservedTunnel { Unknown, Connected, Disconnected, Error, Transitional };
struct TeardownLatch {
    bool awaitingStopConfirm = false;
    bool needStatusBeforeStart = false;
};
inline void observeTunnelState(TeardownLatch &latch, ObservedTunnel s, bool errorProvesTeardown)
{
    switch (s) {
    case ObservedTunnel::Disconnected:
        latch = TeardownLatch{};
        break;
    case ObservedTunnel::Error:
        if (errorProvesTeardown)
            latch = TeardownLatch{};
        else
            latch.needStatusBeforeStart = true;
        break;
    case ObservedTunnel::Connected:
        // Живой туннель без нашего стопа = наблюдённый терминал: Error был ложным.
        // Не-iOS (ревью CL-A r2): Connected после нашего стопа — терминал, как в базе 3c8cc74e:
        // латч снят, reconcile при want=false и connected сам повторит guardedStop (без вечного Wait).
        if (errorProvesTeardown)
            latch = TeardownLatch{};
        else if (!latch.awaitingStopConfirm)
            latch.needStatusBeforeStart = false;
        break;
    default:
        break;
    }
}
// The same, with the state observed before this one. An Error that follows a terminal state (Disconnected, or an
// Error) with nothing in between is a start that failed BEFORE the platform tunnel was asked for anything -
// VpnConnection::connectToVpn always reports Connecting first: a provider node whose seat or profile was refused
// (§31 п. 1), the bridge refusing an armed start. No session was started since the last terminal, so it changes
// nothing the latch knows: after a Disconnected the teardown stays proven and a start may go at once. Before
// (owner's iPhone 16.11, build 140) such an Error set needStatusBeforeStart on iOS; the status reply was the
// unchanged Disconnected, which IosController never re-emits, so every orb tap (which renews the status budget)
// waited again - four taps did nothing until the app was relaunched.
inline void observeTunnelState(TeardownLatch &latch, ObservedTunnel previous, ObservedTunnel s, bool errorProvesTeardown)
{
    if (s == ObservedTunnel::Error && !errorProvesTeardown
        && (previous == ObservedTunnel::Disconnected || previous == ObservedTunnel::Error))
        return;
    observeTunnelState(latch, s, errorProvesTeardown);
}

// Seat first (owner's iPhone 16.11, D4): a pick of a provider node while a working tunnel of another node is up
// does not tear it down first. The seat is acquired through the live tunnel and the profile checked
// (VpnConnectionTunnelControl::prepareUpstream); only with both in hand does the usual pin restart run
// (stop -> Disconnected -> start, which brings the held seat up). restartOfLiveTunnel = pinReconnectIntent's
// needsRestart; providerSessionLive = the lease owner holds a session (a provider tunnel is live: one owner holds
// one seat - that switch keeps the old order).
inline bool upstreamSeatFirst(bool restartOfLiveTunnel, bool targetIsUpstream, bool providerSessionLive)
{
    return restartOfLiveTunnel && targetIsUpstream && !providerSessionLive;
}
struct UpstreamSeatFirst {
    bool pending = false;
    QString nodeId;
    QString prevPin;       // the pin before the pick ("" = automatic choice): back on a refusal
    bool persistPin = false;
    quint64 intentSerial = 0;
    quint64 prepareId = 0; // VpnConnectionTunnelControl::prepareUpstream: only its own answer counts (review F5)
};
enum class SeatFirstStep {
    Ignore, // not the pending pick (a cancelled one: its seat was already given back)
    Drop,   // the user did something else since: give the seat back, touch nothing
    Switch, // seat and profile in hand: the pin restart runs now
    Stay,   // refused: the live tunnel stays, the node is excluded for the attempt, the old pin comes back
};
// replyPrepareId = the prepare the answer belongs to: an answer of an earlier prepare - even of the same node, queued
// before a second tap started a new one - is never taken for the pending one (review F5 of 17.11).
inline SeatFirstStep decideSeatFirstReply(const UpstreamSeatFirst &p, const QString &replyNode, quint64 replyPrepareId,
                                          quint64 intentSerialNow, bool ok)
{
    if (!p.pending || p.nodeId != replyNode || p.prepareId == 0 || p.prepareId != replyPrepareId)
        return SeatFirstStep::Ignore;
    if (p.intentSerial != intentSerialNow)
        return SeatFirstStep::Drop;
    return ok ? SeatFirstStep::Switch : SeatFirstStep::Stay;
}

// Гейт onTick: глушит health только наш стоп в пути или пауза (Error — нет).
inline bool healthTickAllowed(const TeardownLatch &latch, bool connected, bool paused)
{
    return connected && !latch.awaitingStopConfirm && !paused;
}
// Гейт reconcile. AwaitStatus — запросить статус (с backoff, ограниченно) и ждать; Wait — ждать
// без запроса (бюджет запросов исчерпан, стоп ведёт сторож стопа); Proceed — обычная логика.
// Для needStatusBeforeStart исчерпанный бюджет = Proceed: натив сам проверяет владение профилем
// перед connect (K3), а вечного «серого» состояния быть не должно.
enum class ReconcileGate { Proceed, AwaitStatus, Wait };
inline ReconcileGate reconcileGate(const TeardownLatch &latch, ObservedTunnel s, bool wantConnected,
                                   bool statusBudgetLeft)
{
    if (latch.awaitingStopConfirm && s != ObservedTunnel::Disconnected)
        return statusBudgetLeft ? ReconcileGate::AwaitStatus : ReconcileGate::Wait;
    if (latch.needStatusBeforeStart && wantConnected && s != ObservedTunnel::Disconnected
        && s != ObservedTunnel::Connected)
        return statusBudgetLeft ? ReconcileGate::AwaitStatus : ReconcileGate::Proceed;
    return ReconcileGate::Proceed;
}
// Можно ли действовать (стартовать) из этого состояния. Error — только когда он не требует
// подтверждения (не-iOS, либо бюджет запросов статуса исчерпан и латч снят).
inline bool reconcileActionable(ObservedTunnel s, const TeardownLatch &latch)
{
    return s == ObservedTunnel::Disconnected || s == ObservedTunnel::Unknown
        || (s == ObservedTunnel::Error && !latch.needStatusBeforeStart);
}
// Backoff запросов статуса (1/2/4 с, 3 попытки) и повторов стопа после дедлайна (2/4 с, 2 повтора).
inline int statusRequestDelayMs(int attemptsDone)
{
    return attemptsDone == 0 ? 1000 : attemptsDone == 1 ? 2000 : attemptsDone == 2 ? 4000 : -1;
}
inline int stopRetryDelayMs(int retriesDone)
{
    return retriesDone == 0 ? 2000 : retriesDone == 1 ? 4000 : -1;
}
// A1a (ревью CL-A r2): наш стоп не подтверждён, и его никто не ведёт — терминал Connected (или Error
// на iOS) снял m_op и сторож стопа раньше Disconnected, таймер повтора не взведён. Раньше reconcile
// после ~7 с запросов статуса навсегда уходил в Wait (туннель поднят, кнопка мёртвая — жалоба 2).
//  None      — стоп подтверждён, либо его ведёт наша операция / сторож / взведённый повтор;
//  RetryStop — повторить стоп через stopRetryDelayMs(retriesDone);
//  Resolve   — повторы исчерпаны: честное состояние (resolveUnconfirmedStop).
enum class UnconfirmedStopStep { None, RetryStop, Resolve };
inline UnconfirmedStopStep decideUnconfirmedStop(const TeardownLatch &latch, ObservedTunnel s,
                                                 bool stopDriverIdle, bool retryArmed, int retriesDone)
{
    if (!latch.awaitingStopConfirm || s == ObservedTunnel::Disconnected || !stopDriverIdle || retryArmed)
        return UnconfirmedStopStep::None;
    return stopRetryDelayMs(retriesDone) >= 0 ? UnconfirmedStopStep::RetryStop
                                              : UnconfirmedStopStep::Resolve;
}

// A8: истёк дедлайн внутреннего свитча — повтор старта (обычный guardedStart), пока не исчерпан
// анти-зацикливающий счётчик; намерение снимается только при исчерпании (с честной ошибкой).
enum class SwitchDeadlineAction { RetryStart, GiveUp };
inline SwitchDeadlineAction decideSwitchDeadline(int startAttemptsAfterThisFailure, int maxAttempts = 3)
{
    return startAttemptsAfterThisFailure < maxAttempts ? SwitchDeadlineAction::RetryStart
                                                       : SwitchDeadlineAction::GiveUp;
}

// A9: Disconnected/Error — внешний обрыв (снять намерение, §13) только если ни мы (m_op), ни движок
// (свой свитч/failover ДО этого колбэка или прерванный свитч) не вели операцию.
inline bool engineOwnTransitionState(const QString &engineStateBeforeCallback)
{
    return engineStateBeforeCallback == QLatin1String("switching")
        || engineStateBeforeCallback == QLatin1String("connecting")
        || engineStateBeforeCallback == QLatin1String("selecting");
}
inline bool tunnelLossIsExternal(bool weAreOperating, const QString &engineStateBeforeCallback,
                                 bool engineInterruptedSwitch)
{
    return !weAreOperating && !engineOwnTransitionState(engineStateBeforeCallback)
        && !engineInterruptedSwitch;
}

// Критик полноты (U8, жалоба 3): смена сети в фасаде — ТОЛЬКО noteNetworkChange движка. Раньше
// фасад перед ней безусловно звал resetHealthSampling(): это обходило кап серии 2×grace и
// «остывание» HealthLoop (REV-5), и при флаппинге чаще раза в ~12 с мёртвый туннель не доходил до
// DEAD никогда. Выборку HealthLoop сбрасывает сам, когда открывает/продлевает окно.
template <typename Engine>
inline void facadeNoteNetworkChange(Engine &engine, qint64 nowEpoch = -1)
{
    engine.noteNetworkChange(nowEpoch);
}

// Критик полноты (жалобы 1/2): стоп фасада. keepEngineSwitch=true — туннель опускаем ради ПОВТОРА
// прерванного внутреннего свитча (дедлайн фазы, A8): requestStop() не зовём, иначе он стирал цель
// повтора (interruptedSwitchTarget, в том числе переподъём EE), бюджет лечения ноды и стрик
// провалов data-plane (кап карусели), и connect() выбирал по пину/весам. Выборку health чистим.
template <typename Engine>
inline void facadeEngineStop(Engine &engine, bool keepEngineSwitch)
{
    if (keepEngineSwitch && engine.hasInterruptedSwitch())
        engine.resetHealthSampling();
    else
        engine.requestStop();
}

// Критик полноты (U1, жалоба 1 «сами перекидываются ноды»): Доктор пробует альтернативы и
// пересаживает ТОЛЬКО при проблеме самой ноды. Раньше триггер был doctor::hasProblem — любой
// Warn/Bad, включая «сайты РФ», «сеть медленная и без VPN», 3G и IPv6-заметку: пользователь с
// рабочей EE после Доктора оказывался на US.
//  data-plane: стадия connect = Bad (не поднялась / данные не идут) или services = Bad не из-за
//              «белых списков» оператора (другая нода их не обойдёт);
//  «далеко»:   стадия servers = Warn, и последний известный RTT лучшей альтернативы лучше текущего
//              не менее чем на 30 % (иначе пересадка ничего не даст).
// Stages — список doctor::StageResult (поля id/status/data), status: Ok=0, Warn=1, Bad=2.
inline bool doctorAltRttBetterEnough(int curRttMs, int altRttMs)
{
    return curRttMs > 0 && altRttMs >= 0 && qint64(altRttMs) * 10 <= qint64(curRttMs) * 7;
}
template <typename Stages>
inline bool doctorDataPlaneProblem(const Stages &stages)
{
    for (const auto &s : stages) {
        if (s.status != 2)
            continue;
        if (s.id == QLatin1String("connect"))
            return true;
        if (s.id == QLatin1String("services")
            && !s.data.value(QStringLiteral("whitelist_active")).toBool())
            return true;
    }
    return false;
}
template <typename Stages>
inline bool doctorServerFar(const Stages &stages)
{
    for (const auto &s : stages)
        if (s.id == QLatin1String("servers") && s.status == 1)
            return true;
    return false;
}
template <typename Stages>
inline bool doctorNodeProblem(const Stages &stages, int curRttMs, int bestAltRttMs)
{
    if (doctorDataPlaneProblem(stages))
        return true;
    return doctorServerFar(stages) && doctorAltRttBetterEnough(curRttMs, bestAltRttMs);
}

// A15: intentional disconnectReason не отменяет СВОЙ свитч движка, если это наш же стоп.
inline bool intentionalStopCancelsSwitch(const QString &reason, bool engineSwitching)
{
    return !(engineSwitching && reason == QLatin1String("expected_app_stop"));
}

// A2: тело подписки. Пустые nodes при уже имеющемся пуле обновляют только traffic/expiry/status
// (loadSubscription по K5 сохраняет пул) — без probe/restorePin; нет пула или нет ревизии — полная
// загрузка; иначе reseed по ревизии.
enum class SubscriptionBodyRoute { KeepPoolUpdateMeta, LoadFull, Reseed };
inline SubscriptionBodyRoute routeSubscriptionBody(bool bodyHasNodes, bool haveSubscription,
                                                   qint64 bodyPoolRevision)
{
    if (!bodyHasNodes)
        return haveSubscription ? SubscriptionBodyRoute::KeepPoolUpdateMeta
                                : SubscriptionBodyRoute::LoadFull;
    if (!haveSubscription || bodyPoolRevision <= 0)
        return SubscriptionBodyRoute::LoadFull;
    return SubscriptionBodyRoute::Reseed;
}
// LKG: тело с пустыми nodes не перезаписывает дисковый LKG, в котором ноды есть.
inline bool shouldPersistLkgBody(bool bodyHasNodes, bool lkgHasNodes)
{
    return bodyHasNodes || !lkgHasNodes;
}

// A6: постоянным (QSettings avpn/pinnedNode) делается только явный выбор сервера пользователем
// в списке. «Заменить сервер», Доктор, свип бенча — pin только в памяти (как в базе 3c8cc74e).
enum class PinOrigin { UserChoice, Rotate, Doctor, Sweep };
inline bool pinOriginPersists(PinOrigin origin) { return origin == PinOrigin::UserChoice; }

// A7: сверка pin после loadSubscription/reseed. saved — персистентный явный выбор, before/after —
// pin движка до и после применения тела.
//  Nothing         — всё согласовано, либо в памяти неявный pin (не персистим).
//  PersistMigrated — явный pin движок перенёс на соседа той же локации: сохранить НОВЫЙ id.
//  ApplySaved      — pin в памяти пуст: попробовать сохранённый (неудача сохранённое не стирает).
enum class PinRestoreAction { Nothing, PersistMigrated, ApplySaved };
inline PinRestoreAction decidePinRestore(const QString &saved, const QString &pinBefore,
                                         const QString &pinAfter)
{
    if (saved.isEmpty())
        return PinRestoreAction::Nothing;
    if (pinAfter.isEmpty())
        return PinRestoreAction::ApplySaved;
    if (pinAfter == saved)
        return PinRestoreAction::Nothing;
    return pinBefore == saved ? PinRestoreAction::PersistMigrated : PinRestoreAction::Nothing;
}

// One format for a pin cleared because the mode cannot serve it (a tap or an admission).
inline QString pinClearedByModeJournal(const QString &mode, const QString &nodeId)
{
    return QStringLiteral("pin_cleared why=transport_mode mode=%1 node=%2").arg(mode, nodeId);
}

// 5.1.109 (review R3): the facade's decision on a transport mode change (AvpnEngineQml::setTransportMode,
// after the new mode is applied). mode - the effective mode name ("auto" | "awg" | "xray");
// pinnedNodeId - the engine's pin; pinLacksTransport - ServiceEngine::pinLacksTransport(effective mode);
// tunnelUp / currentProto - the tunnel now (proto of the identified node, empty = unknown).
//  clearPin      - a pin the mode cannot serve: clearPin() + persistPin(), journal line below. Auto never
//                  clears (every connectable location serves Auto).
//  restartTunnel - a tunnel up on a transport the mode excludes is restarted through reconcile +
//                  m_needsRestart (stop -> Disconnected -> start, §2/§4), never a direct up(); the start
//                  then picks without the cleared pin. Unknown proto (adopted, not identified) - no restart.
struct PinModeDecision {
    bool clearPin = false;
    bool restartTunnel = false;
    QString journal; // empty = nothing to journal
};
inline PinModeDecision decidePinOnTransportMode(const QString &mode, const QString &pinnedNodeId,
                                                bool pinLacksTransport, bool tunnelUp,
                                                const QString &currentProto)
{
    PinModeDecision d;
    const bool autoMode = mode == QLatin1String("auto");
    if (!autoMode && !pinnedNodeId.isEmpty() && pinLacksTransport) {
        d.clearPin = true;
        d.journal = pinClearedByModeJournal(mode, pinnedNodeId);
    }
    const bool curXray = currentProto == QLatin1String("xray");
    const bool mismatch = (mode == QLatin1String("awg") && curXray)
                          || (mode == QLatin1String("xray") && !currentProto.isEmpty() && !curXray);
    d.restartTunnel = tunnelUp && mismatch;
    return d;
}

// 5.1.109 (S4.1): how the tunnel looks to the transport-mode gate (TransportModeGate.h: when the
// stored choice may come into force). The gate admits only when the tunnel is OBSERVED down:
//  Unknown - no status seen in this run yet. Not "down": a session of an earlier process may be alive
//            (review of 3dbe0361f: Unknown was treated as idle, so a config that arrived before the
//            first status put the choice in force - and cleared the pin - under a live session);
//  Disconnected - down, unless our own stop is still unconfirmed (then, whatever the state reads, moving);
//  Error - down only when a start may act from it (reconcileActionable), otherwise still moving.
inline ModeTunnel modeTunnelOf(ObservedTunnel tunnel, const TeardownLatch &latch)
{
    switch (tunnel) {
    case ObservedTunnel::Connected:
        return ModeTunnel::Up;
    case ObservedTunnel::Unknown:
        return latch.awaitingStopConfirm ? ModeTunnel::Moving : ModeTunnel::NotObserved;
    case ObservedTunnel::Disconnected:
    case ObservedTunnel::Error:
        return (latch.awaitingStopConfirm || !reconcileActionable(tunnel, latch)) ? ModeTunnel::Moving
                                                                                  : ModeTunnel::Down;
    case ObservedTunnel::Transitional:
        break;
    }
    return ModeTunnel::Moving;
}

// 5.1.109 (R7, device 35 build 138, 10-11.11.2026): a deadline timer that fires late means the process
// was frozen (iOS suspended the app in the background, a laptop slept): the time of the freeze is no
// evidence about the tunnel (§29 п.5 "заморозка — не довод"; same rule as timerFiredLate). Such a tick
// does not judge the deadline: the facade shifts the running switch-phase clock by frozenMs
// (ServiceEngine::shiftSwitchClock) and asks for a fresh status; the normal path then decides (a
// confirmed Connected ends the switch, a dead session meets the unchanged deadline after thaw).
// sinceLastTickMs < 0 (wall clock went backwards) - judge normally: ServiceEngine::expireSwitch clamps a
// phase start that is now in the future (R7c). The engine shifts at most once per phase (R7a): with
// timers the OS only slows (App Nap, EcoQoS) every tick is late, later ones are judged normally.
// Was: 11.6 h overdue 1 s tick -> expireSwitch -> guardedStop of a session the extension had healed.
struct DeadlineTick {
    bool evaluate = true;
    qint64 frozenMs = 0;
};
inline DeadlineTick decideDeadlineTick(qint64 sinceLastTickMs, qint64 periodMs)
{
    if (sinceLastTickMs < 0)
        return {true, 0};
    if (!timerFiredLate(sinceLastTickMs, periodMs))
        return {true, 0};
    return {false, sinceLastTickMs - periodMs};
}
// The start watchdog (one-shot) fired late: re-arm it once for the same operation without spending a
// deferral or an attempt, and ask for status (device 269, builds 128/138: a working session was
// stopped by an overdue start watchdog). A second late firing of the same operation is judged.
inline bool rearmStartWatchdogAfterFreeze(const DeadlineTick &tick, bool rearmedThisOperation)
{
    return !tick.evaluate && !rearmedThisOperation;
}

// A10: бюджет подготовки старта. С пулом — мягкий бюджет завершает подготовку; без пула
// (свежая установка: enroll+fetch) намерение НЕ снимается до общего потолка (~20 с).
// Волна «как апстрим» (2026-09-28): мягкий бюджет 6 с → 2 с. С пулом подготовка ждёт только
// ICMP-раунд (таймаут 1,5 с), а не ответ refresh: после гашения туннеля тот висел до 15 с, и
// каждый Connect на Mac владельца упирался в 6 с (журнал 26–28.09, 11 из 11).
constexpr qint64 kStartPrepSoftBudgetMs = 2000;
constexpr qint64 kStartPrepCeilingMs = 20000;
enum class SelectionBudget { KeepWaiting, Finish, GiveUp };
inline SelectionBudget decideSelectionBudget(bool haveSubscription, qint64 elapsedMs,
                                             qint64 softBudgetMs = kStartPrepSoftBudgetMs,
                                             qint64 ceilingMs = kStartPrepCeilingMs)
{
    if (haveSubscription)
        return elapsedMs >= softBudgetMs ? SelectionBudget::Finish : SelectionBudget::KeepWaiting;
    return elapsedMs >= ceilingMs ? SelectionBudget::GiveUp : SelectionBudget::KeepWaiting;
}
// A11: ICMP-раунд стартует сразу, параллельно refresh, если нет пригодного pin и есть пул.
inline bool startRttRoundImmediately(bool hasConnectablePin, bool haveSubscription)
{
    return !hasConnectablePin && haveSubscription;
}
// Волна «как апстрим» (2026-09-28, CONNECT-INVARIANTS §1 «кнопка Connect в сеть не ходит»):
// что делать на входе в подготовку старта. Пул уже есть (LKG/последний refresh), и цель известна —
// закреплённая локация или свежий (≤ TTL) замер RTT — подключаемся сразу; пул обновляют фоновые
// refresh (выход на экран, таймер), не кнопка. Без цели — только ICMP-раунд; без пула — bootstrap.
enum class StartPrep { ConnectNow, MeasureRtt, AwaitPool };
inline StartPrep decideStartPreparation(bool haveSubscription, bool hasConnectablePin, bool haveFreshRtt)
{
    if (!haveSubscription)
        return StartPrep::AwaitPool;
    if (hasConnectablePin || haveFreshRtt)
        return StartPrep::ConnectNow;
    return StartPrep::MeasureRtt;
}
// Волна «как апстрим» (2026-09-28): фоновые сетевые опросы — пока окно приложения активно. У апстрима
// периодических сетевых таймеров нет вовсе; у нас HEAD /v1/ping шёл каждые 4 с и /v1/subscription
// каждые 20 с при окне в фоне (Mac владельца: 13,3 тыс. пингов за 2,3 сут). Палочки RTT видны
// только на экране; бейдж трафика в фоне освежаем не чаще ~5 мин (лимиты/срок режет сервер).
constexpr int kBackgroundTrafficSyncTicks = 75; // × health-tick 4 с ≈ 5 мин
// Волна-2 (ревью 5.1.95): в фоне проба не выключается, а разрежается до каждого 15-го тика
// (~60 с). Удачная проба через туннель — единственный сброс счётчика провалов data-plane
// (ServiceEngine::feedProbeResult); без неё 4 failover за долгую сессию давали «сдаёмся» и
// снятие намерения, а мёртвый xray в фоне не обнаруживался.
constexpr int kBackgroundProbeEveryTicks = 15;
inline bool liveProbeDue(bool flagOn, bool connected, bool uiActive, int bgTick)
{
    if (!flagOn || !connected)
        return false;
    return uiActive || (bgTick > 0 && bgTick % kBackgroundProbeEveryTicks == 0);
}
// Волна-2: «подключаемся сразу по кэшу RTT» — только если замер сделан ПОСЛЕ последней смены
// сети и покрывает все авто-ноды пула. Частичный замер (EE потерял пакет, US измерен) или замер
// из прошлой сети (Wi-Fi → LTE) уводил бы на дальнюю ноду без раунда.
inline bool rttCoverageFresh(int eligible, int measuredEligible, qint64 rttAgeMs, qint64 sinceNetChangeMs)
{
    if (eligible <= 0 || measuredEligible < eligible || rttAgeMs < 0)
        return false;
    return sinceNetChangeMs < 0 || rttAgeMs < sinceNetChangeMs;
}
inline int trafficSyncTicks(int configuredTicks, bool uiActive)
{
    return uiActive ? configuredTicks : qMax(configuredTicks, kBackgroundTrafficSyncTicks);
}
// ---- Волна-3 (2026-09-28): намерение пользователя переживает отсутствие сети и падение компонента ----
// Апстрим Amnezia не снимает «хочу VPN» никогда; мы снимали его по счётчику 3×15 с и по любому
// Disconnected при m_op==None. Разбор Mac 26–28.09: 9/9 «сам выключился» и 3×15 с в сеть без
// default route. Правила: (1) попытка старта без физического аплинка не считается — ждём сеть;
// (2) исчерпание попыток при живой сети = пауза с ростом 30/60/120 с, не OFF (пользователь
// всегда может выключить сам); (3) обрыв классифицируется, намерение снимает ТОЛЬКО внешний
// (§13: пользователь/другой VPN/ОС), а «нет сети» и «упал компонент» его держат.
enum class StartFailure { CountAndRetry, WaitUplink };
inline StartFailure judgeStartFailure(bool uplinkUp)
{
    return uplinkUp ? StartFailure::CountAndRetry : StartFailure::WaitUplink;
}
inline int startRetryBackoffMs(int exhaustedRounds)
{
    static const int steps[] = { 30000, 60000, 120000 };
    const int i = exhaustedRounds < 0 ? 0 : (exhaustedRounds > 2 ? 2 : exhaustedRounds);
    return steps[i];
}
enum class LossClass { Own, External, NoNetwork, Component };
inline LossClass classifyLoss(bool weAreOperating, const QString &engineStateBeforeCallback,
                              bool engineInterruptedSwitch, bool componentLost, bool uplinkUp)
{
    if (weAreOperating || engineOwnTransitionState(engineStateBeforeCallback) || engineInterruptedSwitch)
        return LossClass::Own;
    if (componentLost)
        return LossClass::Component;
    if (!uplinkUp)
        return LossClass::NoNetwork;
    return LossClass::External;
}
inline bool lossDropsIntent(LossClass c) { return c == LossClass::External; }
// §16-сторож десктопа: 20 с в Reconnecting → спросить демона (status). Ответил (эхо статистики)
// → жив, остаёмся в Reconnecting (перевзвод ≤ 3 раз ≈ ещё 60 с); молчит 3 с → мёртв.
enum class ReconnectWatchdog { Rearm, ForceDisconnectedAlive, ForceDisconnectedDead };
inline ReconnectWatchdog decideReconnectWatchdog(bool daemonAnswered, int rearmsDone, int maxRearms = 3)
{
    if (!daemonAnswered)
        return ReconnectWatchdog::ForceDisconnectedDead;
    return rearmsDone < maxRearms ? ReconnectWatchdog::Rearm : ReconnectWatchdog::ForceDisconnectedAlive;
}
// Смена сети во время подготовки: refresh нужен, только если пула ещё нет (свежая установка).
// Раньше смена сети (в том числе от гашения собственного туннеля при смене ноды) заново взводила
// ожидание refresh — и подготовка упиралась в бюджет.
inline bool prepRefreshOnNetworkChange(bool haveSubscription)
{
    return !haveSubscription;
}
// A11: результат замера не затирает прошлый RTT ноды «нет ответа» (заменяем по приходу нового).
// ── Волна-4 «как апстрим» (2026-09-29, аудит iOS против апстрима + журнал 24–28.09) ────────

// P1-4 (revised 2026-11-04, connect audit): the orb tap does what the orb shows, as in upstream
// Amnezia (ConnectionUiController::toggleConnection: Connected or in progress -> closeConnection,
// otherwise connect). The former 2.5 s grace after adoption (kAdoptTapGraceMs) is removed: with a
// dead data path the orb showed "Connected", the user tapped it to turn the VPN off and the tap was
// dropped ("tap does not disconnect, it connects again").
//  - our own stop in flight (ownStopInFlight, orb "Disconnecting…") -> StopAgain: the idempotent
//    stop path is re-issued, as upstream re-calls closeConnection() on Disconnecting, so a stuck
//    stop has a way out; it never restarts. The former "tap while stopping = start" rule restarted
//    the tunnel 0.2-1.0 s after a user stop (device journals 2026-10-21..11-04: 91 of 218 user
//    stops followed by a reconnect within 60 s, the start being pinned_location_ready right after
//    Disconnected with no adoption in between);
//  - off and idle -> Start. "Busy with intent off" that is NOT our stop (a tunnel brought up from
//    iOS/macOS Settings or by the system while our intent is off, redeem/transfer flows) is not
//    "Disconnecting…": the orb reads "Connect" and the tap starts;
//  - cancelling our own start (preparation, op in flight) -> Stop;
//  - a shown "Connected" (engine connected, not busy) -> Stop;
//  - "Checking…" (busy && liveSessionPending: the orb has not shown "Connected" yet, the tap repeats
//    "turn on") -> Ignore;
//  - any other busy state ("Connecting…") -> Stop.
// ownStopInFlight: we asked for a stop and it is not confirmed yet (op Stopping or the latch awaits
// the Disconnected), with intent off. Drives both decideOrbTap and the "Disconnecting…" label.
inline bool ownStopInFlight(bool wantConnected, bool opStopping, bool awaitingStopConfirm)
{
    return !wantConnected && (opStopping || awaitingStopConfirm);
}
enum class OrbTap { Start, Stop, StopAgain, Ignore };
inline OrbTap decideOrbTap(bool engineConnected, bool busy, bool wantConnected, bool ownStopping,
                           bool ownOpInFlight, bool preparingStart, bool liveSessionPending)
{
    if (ownStopping)
        return OrbTap::StopAgain;
    if (preparingStart || ownOpInFlight)
        return OrbTap::Stop;
    // Not connected and either idle or busy with intent off (a foreign transition): orb "Connect".
    if (!engineConnected && (!busy || !wantConnected))
        return OrbTap::Start;
    if (engineConnected && !busy)
        return OrbTap::Stop;
    if (busy && liveSessionPending)
        return OrbTap::Ignore;
    return OrbTap::Stop;
}
inline const char *orbTapName(OrbTap d)
{
    switch (d) {
    case OrbTap::Start: return "start";
    case OrbTap::Stop: return "stop";
    case OrbTap::StopAgain: return "stop_again";
    case OrbTap::Ignore: return "ignored";
    }
    return "?";
}

// P1-5: сторож старта на iOS/NE. 15-секундный сторож фасада гасил живую NE-сессию посреди
// медленного рукопожатия на сотовой (12 watchdog_start за 9 у-сут). Пока натив сообщает, что
// сессия есть (Connecting/Reconnecting), сторож перевзводится, но не дольше бюджета рукопожатия
// натива (3×12 с): для СВОЕГО старта натив Error не отдаёт (m_connectPending снят до
// startVPNTunnel, после 36 с — только Reconnecting), поэтому потолок держит фасад: 3×15 с.
enum class StartWatchdog { Stop, Defer };
inline StartWatchdog decideStartWatchdog(bool nativeSessionAlive, int deferrals, int maxDeferrals = 2)
{
    return (nativeSessionAlive && deferrals < maxDeferrals) ? StartWatchdog::Defer : StartWatchdog::Stop;
}

// P2-2: отказ API идёт в edge-walk/детектор белых списков, только если он честный: не наш abort
// при гашении туннеля (OperationCanceled без таймаута), не запрос, начатый до заморозки iOS
// (t0 < момент выхода на экран), не отказ в окне 5 с после своего перехода туннеля (keep-alive
// через погашенный utun). Регресс 126: abort всех запросов на Disconnected давал 2–3 «отказа»
// разом → смена API-эджа почти на каждой смене ноды.
enum class ApiOutcome { Success, Failure, Ignore };
constexpr qint64 kApiTransitionWindowMs = 5000;
inline ApiOutcome classifyApiOutcome(int httpCode, bool canceled, bool timedOut, qint64 startedMs,
                                     qint64 lastResumeMs, qint64 lastTunnelTransitionMs, qint64 nowMs)
{
    if (httpCode > 0 && httpCode < 500)
        return ApiOutcome::Success;        // любой прикладной ответ доказывает, что вход жив
    if (canceled && !timedOut)
        return ApiOutcome::Ignore;         // оборвали сами (смена ноды/стоп) — не отказ входа
    if (startedMs > 0 && lastResumeMs > 0 && startedMs < lastResumeMs)
        return ApiOutcome::Ignore;         // запрос пережил заморозку — таймаут не про сеть
    if (lastTunnelTransitionMs > 0 && nowMs - lastTunnelTransitionMs < kApiTransitionWindowMs)
        return ApiOutcome::Ignore;         // рядом со своим переходом туннеля
    return ApiOutcome::Failure;
}

// QNetworkAccessManager::clearConnectionCache() strands every request in flight: Qt destroys its
// HTTP thread and the reply never finishes - only our 15 s armTimeout ends it (measured on Qt 6.11.1;
// owner's journal 06.11 10:31:21, build 134: /v1/config, /v1/edges, /v1/bypass-lists, support and
// announcements started at launch all timed out at 15 s after the adoption of a live tunnel, so the
// process stayed on the cached config with Xray frozen). Two parties clear the shared QNAM:
//  - we, on a real tunnel transition to Connected/Disconnected (keep-alive connections of the old
//    path are dead); not on the first status a process observes (Unknown -> X: no tunnel of ours
//    carried them), not on a repeat of the same state;
//  - upstream ConnectionUiController, on EVERY Connected (adoption and repeats included).
// Whoever cleared, the requests in flight at that moment are aborted right away (their owners
// re-issue them over the new path) instead of hanging for 15 s. Decision 2026-11-05 + owner test 06.11.
struct TransitionNetAction {
    bool clearCache = false;
    bool abortInFlight = false;
};
inline TransitionNetAction transitionNetAction(ObservedTunnel previous, ObservedTunnel now)
{
    TransitionNetAction a;
    a.clearCache = previous != ObservedTunnel::Unknown && previous != now
                   && (now == ObservedTunnel::Connected || now == ObservedTunnel::Disconnected);
    a.abortInFlight = a.clearCache || now == ObservedTunnel::Connected;
    return a;
}

// A request we aborted ourselves (OperationCanceled without our timeout mark) is re-issued once by
// its owner over the new path; a timeout or a server answer is not.
inline bool reissueAfterOwnAbort(bool canceled, bool timedOut)
{
    return canceled && !timedOut;
}

// ONLINE badge (5.1.108): "data flows" no longer depends on the server flag node_scan. Before, the
// badge needed the whoami verdict "works", and whoami runs only with node_scan on (off since
// 06.11.2026) - so no build ever showed ONLINE. Now the live in-tunnel probe (QualityProbe:
// /v1/ping, then generate_204, every tick while connected) proves it as well; whoami only
// accelerates (works) or forbids (no_data / bypass). A confirmed dead live probe (liveDead) always
// forbids. liveProven = at least one live probe succeeded in this Connected session.
inline bool dataFlowingNow(bool tunnelConnected, bool liveDead, const QString &pathCheck, bool liveProven)
{
    if (!tunnelConnected || liveDead)
        return false;
    if (pathCheck == QLatin1String("no_data") || pathCheck == QLatin1String("bypass"))
        return false;
    return pathCheck == QLatin1String("works") || liveProven;
}

// Decision 2026-11-05: an edge can pass small answers and still never deliver /v1/subscription (the
// owner's cellular path to vpn.wellwon.hk: 0 of 23 in 3 days while /v1/account passed; nginx answered
// each with 200, ~6.7 KB). The edge walk cannot see that - every small success resets its streak - so
// /v1/subscription has its own streak per edge (EdgeWalk.h::SubscriptionEdgeStreak):
//  Delivered - the reply ended without a transport error (any HTTP status): resets the streak;
//  Failure   - transport error (our timeout, connection cut mid-body), not our abort, not across an
//              iOS freeze, not in our own tunnel-transition window: counts;
//  Ignore    - our own abort, a freeze, our transition window.
// networkError = QNetworkReply::NetworkError: 1..99 network layer, 100..199 proxy, 300..399 protocol
// (transport failures); 200..299 content and 400..499 server errors are HTTP answers (delivered).
enum class SubscriptionEdgeOutcome { Delivered, Failure, Ignore };
inline SubscriptionEdgeOutcome classifySubscriptionEdgeOutcome(int networkError, bool timedOut, qint64 startedMs,
                                                              qint64 lastResumeMs, qint64 lastTunnelTransitionMs,
                                                              qint64 nowMs)
{
    const bool httpAnswer = networkError == 0 || (networkError >= 200 && networkError < 300)
                            || (networkError >= 400 && networkError < 500);
    if (httpAnswer)
        return SubscriptionEdgeOutcome::Delivered;
    if (networkError == 5 /* OperationCanceledError */ && !timedOut)
        return SubscriptionEdgeOutcome::Ignore;
    if (startedMs > 0 && lastResumeMs > 0 && startedMs < lastResumeMs)
        return SubscriptionEdgeOutcome::Ignore;
    if (lastTunnelTransitionMs > 0 && nowMs - lastTunnelTransitionMs < kApiTransitionWindowMs)
        return SubscriptionEdgeOutcome::Ignore;
    return SubscriptionEdgeOutcome::Failure;
}

// P2-3: эффекты «Подключено» (сброс чипов, пробы сервисов 2×128 КБ) — только для НОВОЙ сессии
// (другая нода или прошло ≥ 30 мин) и только на экране; повторный Connected той же сессии
// (Reconnecting→Connected при смене сети, подхват) их не запускает. Не на экране — откладываем до
// выхода на экран.
enum class ConnectEffects { RunNow, Defer, Skip };
constexpr qint64 kConnectEffectsRepeatMs = 30 * 60 * 1000;
inline ConnectEffects decideConnectEffects(bool sameNodeAsLastProbe, qint64 sinceLastProbeMs, bool uiOnScreen)
{
    const bool newSession = !sameNodeAsLastProbe || sinceLastProbeMs < 0 || sinceLastProbeMs >= kConnectEffectsRepeatMs;
    if (!newSession)
        return ConnectEffects::Skip;
    return uiOnScreen ? ConnectEffects::RunNow : ConnectEffects::Defer;
}

// P1-6: липкий m_needsRestart. Флаг взводят действия пользователя и исполняют немедленно; флаг,
// доживший до reconcile старше kRestartRequestTtlMs (уход в фон посреди перехода, ранний выход
// reconcile), исполнялся при первом Connected после разморозки — рестарт живого туннеля через
// 1–7 с после открытия. Просроченный запрос сбрасываем.
constexpr qint64 kRestartRequestTtlMs = 120000;
inline bool restartRequestStale(qint64 requestedMs, qint64 nowMs)
{
    return requestedMs > 0 && nowMs - requestedMs > kRestartRequestTtlMs;
}

// P1-5: исчерпан дедлайн внутреннего свитча. Раньше: intent_off + гашение туннеля навсегда. Теперь:
// намерение держим; поднятый/переходный туннель гасим через сторожевой guardedStop (down() свитча
// уже мог уйти — адоптировать его нельзя), опущенный — сразу в паузу с ростом (start_retry_backoff).
inline bool switchGiveUpNeedsStop(bool tunnelDownOrUnknown, bool ownOpInFlight)
{
    return !tunnelDownOrUnknown && !ownOpInFlight;
}

// P2-6: собственные up/down utun приходят как reachability/transportMedium changed и инвалидировали
// замер RTT (257 инвалидаций за 4,5 сут у одного устройства) → следующий Connect ждал ICMP-раунд.
// «Своё» событие — в окне своей операции (guardedStart/guardedStop, свой свитч) или 5 с после
// неё; наблюдённые переходы туннеля от чужих причин (роуминг NE) окно НЕ открывают. Подавляется
// только сброс кэша RTT — grace-окно HealthLoop и отмена пробы остаются (иначе ложный DEAD).
inline bool networkChangeIsOwnTunnel(bool ownOpInFlight, qint64 lastOwnOpMs, qint64 nowMs)
{
    return ownOpInFlight || (lastOwnOpMs > 0 && nowMs - lastOwnOpMs < kApiTransitionWindowMs);
}

// P2-4: один координатор выхода на экран. Реагируем на возврат после реальной заморозки/скрытия
// (Suspended/Hidden) или после долгого Inactive (десктоп: фокус в браузере после оплаты), не на
// Inactive→Active-мигание (Пункт управления, системный алерт); подписка — с троттлом, конфиг —
// раз в 15 мин (ENG-03: iOS обновлял конфиг только перезапуском процесса).
constexpr qint64 kFgMinInactiveMs = 10000;
constexpr qint64 kFgSubscriptionThrottleMs = 30000;
constexpr qint64 kFgConfigThrottleMs = kConfigRefreshThrottleMs; // 15 min, ConfigCachePolicy.h (one constant)
inline bool foregroundIsReturn(bool hiddenSeen, qint64 inactiveForMs)
{
    return hiddenSeen || inactiveForMs >= kFgMinInactiveMs;
}
struct ForegroundPlan { bool refreshSubscription = false; bool refreshConfig = false; };
inline ForegroundPlan planForeground(qint64 sinceLastSubRefreshMs, qint64 sinceLastConfigFetchMs)
{
    ForegroundPlan p;
    p.refreshSubscription = sinceLastSubRefreshMs < 0 || sinceLastSubRefreshMs >= kFgSubscriptionThrottleMs;
    p.refreshConfig = sinceLastConfigFetchMs < 0 || sinceLastConfigFetchMs >= kFgConfigThrottleMs;
    return p;
}

// Волна-4: потеря компонента (сокет демона/§16-сторож) годится как объяснение только для
// ближайшего Disconnected; флаг, зависший на часы, не должен переклассифицировать поздний
// внешний обрыв (§13: чужой VPN погасил — не переподключаемся).
constexpr qint64 kComponentLossTtlMs = 30000;
inline bool componentLossFresh(bool flagged, qint64 lostMs, qint64 nowMs)
{
    return flagged && lostMs > 0 && nowMs - lostMs < kComponentLossTtlMs;
}

inline void mergeRttSample(QHash<QString, int> &cache, const QString &nodeId, int rttMs)
{
    if (rttMs >= 0 || !cache.contains(nodeId))
        cache.insert(nodeId, rttMs);
}

// A16: кольцо reliability-лога — подряд идущие одинаковые события схлопываются в одну строку
// со счётчиком повторов (status_timeout/path_change не вымывают кольцо).
struct ReliabilityRing {
    QStringList lines;
    QString lastEvent;
    QString lastBase;   // строка первого вхождения серии (штамп + событие)
    int repeat = 0;
};
inline void appendReliabilityEvent(ReliabilityRing &ring, const QString &stamp, const QString &event,
                                   int cap = 128)
{
    if (!ring.lines.isEmpty() && ring.repeat > 0 && event == ring.lastEvent) {
        ++ring.repeat;
        ring.lines.last() = ring.lastBase + QStringLiteral(" [x%1 last=%2]").arg(ring.repeat).arg(stamp);
        return;
    }
    ring.lastEvent = event;
    ring.lastBase = stamp + event;
    ring.repeat = 1;
    ring.lines.append(ring.lastBase);
    while (ring.lines.size() > cap)
        ring.lines.removeFirst();
}


// ── AVPN Scanner (CONNECT-INVARIANTS §32; plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md
// v2.2 §2.12, §3, §4.4) — the engine's half of the ONLY three ways the Scanner reaches the tunnel, the
// client switches, the live status the coordinator reads. Pure; tests/facade_policy_check.cpp
// (scanner*), tests/facade_engine_check.cpp (row connect against the real ServiceEngine).
//
// Before the picker's tap and the Scanner's row tap share it: what pinAndReconnectImpl does with the intent.
// selectOnly — features.picker_instant_reconnect off and no explicit connect: the old switchToNode (target only).
inline bool pinReconnectSelectOnly(bool forceConnect, bool instantReconnectOn)
{
    return !forceConnect && !instantReconnectOn;
}
// Up (or coming up): intent on, restart through reconcile (stop -> Disconnected -> start, §4 update 2026-07-10).
// Down: only an explicit connect (forceConnect: the Doctor's restore, the Scanner's row) turns the intent on;
// the picker's tap stores the target (cold connect by the orb). Review F4: the Scanner's row must connect.
struct PinReconnectIntent {
    bool wantConnected = false;
    bool needsRestart = false;
};
inline PinReconnectIntent pinReconnectIntent(bool tunnelUp, bool forceConnect)
{
    if (tunnelUp || forceConnect)
        return {true, tunnelUp};
    return {false, false};
}

// Client switches (REMOTE-TUNING §1; the server publishes them only while its switch v1_scanner is on and
// ABSENT otherwise). Absent `scanner` = the Scanner does not exist: no entry point acts, every other
// switch reads off and the old Doctor sheet stays where it is today.
inline constexpr char kScannerSwitchKey[] = "scanner";
inline constexpr char kScannerReturnHomeKey[] = "scanner_return_home";
inline constexpr char kScannerDoctorLegacyKey[] = "doctor_legacy";
inline constexpr char kScannerConnectOnOpenKey[] = "scanner_connect_on_open";
inline constexpr char kScannerAwgMiniKey[] = "scanner_awg_mini";
struct ScannerSwitches {
    bool scanner = false;
    bool returnHome = false;     // after «Подключено» from a row: home (false = stay in the Scanner, owner 15.11)
    bool doctorLegacy = false;   // the old Doctor sheet for one more release
    bool connectOnOpen = false;  // REQ S3 (b): iPhone/Android open with the VPN off connects (compiled default on)
    bool awgMini = false;        // own AmneziaWG mini-probe
    bool doctorSheet = true;     // the old Doctor sheet is reachable (today: always)
    bool operator==(const ScannerSwitches &o) const
    {
        return scanner == o.scanner && returnHome == o.returnHome && doctorLegacy == o.doctorLegacy
            && connectOnOpen == o.connectOnOpen && awgMini == o.awgMini && doctorSheet == o.doctorSheet;
    }
    bool operator!=(const ScannerSwitches &o) const { return !(*this == o); }
};
// flag(key, compiledDefault) -> bool: TuningStore::flag in the app, a map in the tests.
template <typename Flag>
inline ScannerSwitches scannerSwitchesFrom(Flag flag)
{
    ScannerSwitches s;
    s.scanner = flag(QLatin1String(kScannerSwitchKey), false);
    if (!s.scanner)
        return s;
    s.returnHome = flag(QLatin1String(kScannerReturnHomeKey), false);
    s.doctorLegacy = flag(QLatin1String(kScannerDoctorLegacyKey), false);
    s.connectOnOpen = flag(QLatin1String(kScannerConnectOnOpenKey), true);
    s.awgMini = flag(QLatin1String(kScannerAwgMiniKey), false);
    s.doctorSheet = s.doctorLegacy;
    return s;
}

// Path (a) ConnectRow: the ordinary user connect, forced (review F4) — when the tunnel is down, first the
// user-start bookkeeping of start(); then pinAndReconnectImpl(force, StartOrigin::User). Up: the ordinary
// move through reconcile (pinReconnectIntent -> needsRestart).
struct ScannerRowConnect {
    bool userStartBookkeeping = false;
    bool forceConnect = true;
    bool userOrigin = true;
};
inline ScannerRowConnect scannerRowConnect(bool tunnelUpOrComingUp)
{
    ScannerRowConnect r;
    r.userStartBookkeeping = !tunnelUpOrComingUp;
    return r;
}
// The engine part of a row tap that the facade and tests/facade_engine_check.cpp share: the one-attempt order
// hint (head = the tapped row) for ServiceEngine::nextCandidate / connect() / onDead step 3.
template <typename Engine>
inline void facadeScanRowHint(Engine &engine, const QStringList &order, qint64 ttlMs)
{
    engine.setAttemptOrder(order, ttlMs);
}
enum class ScanRowGate { Connect, IgnoreSwitchOff, IgnoreNoNode };
inline ScanRowGate decideScanRowConnect(bool scannerOn, const QString &nodeId)
{
    if (!scannerOn)
        return ScanRowGate::IgnoreSwitchOff;
    if (nodeId.trimmed().isEmpty())
        return ScanRowGate::IgnoreNoNode;
    return ScanRowGate::Connect;
}

// Path (b) UserConnectForScan: the ordinary start() (StartOrigin::User), only from VPN off. A start the
// user already made (intent on, a tunnel up or coming up) is not doubled and is not the Scanner's to cancel.
// hostNeedsVpn = the platform's probe host lives in the tunnel process (iPhone, Android); a host that probes
// with the VPN off (macOS, Windows) never connects for a scan.
enum class ScanOpenConnect { Start, IgnoreSwitchOff, IgnoreNoVpnNeeded, IgnoreAlreadyOn };
inline const char *scanOpenConnectName(ScanOpenConnect d)
{
    switch (d) {
    case ScanOpenConnect::Start: return "start";
    case ScanOpenConnect::IgnoreSwitchOff: return "switch_off";
    case ScanOpenConnect::IgnoreNoVpnNeeded: return "no_vpn_needed";
    case ScanOpenConnect::IgnoreAlreadyOn: return "already_on";
    }
    return "unknown";
}
inline ScanOpenConnect decideScanOpenConnect(bool scannerOn, bool hostNeedsVpn, bool wantConnected, bool tunnelUpOrComingUp)
{
    if (!scannerOn)
        return ScanOpenConnect::IgnoreSwitchOff;
    if (!hostNeedsVpn)
        return ScanOpenConnect::IgnoreNoVpnNeeded;
    if (wantConnected || tunnelUpOrComingUp)
        return ScanOpenConnect::IgnoreAlreadyOn;
    return ScanOpenConnect::Start;
}

// The connect the Scanner itself started (path b), as the engine keeps it — in memory only, keyed by
// the attempt: its id, the process that made it and the intent serial right after its start(). Any other
// action on the intent (orb, stop, picker, row tap, Doctor) moves the serial: the attempt is no longer
// the Scanner's.
struct ScanOwnConnect {
    quint64 id = 0;               // 0 = none
    quint64 processEpoch = 0;     // random per process
    quint64 intentSerial = 0;
    bool reachedConnected = false; // «Подключено» (scanShownConnected) seen once: latched, never undone
    bool active() const { return id != 0; }
};
// «Подключено» for the Scanner's own connect is what the person sees on the orb: the engine reached
// Connected on a Connected tunnel (the first input of dataFlowingNow), with or without the data proof.
// Build 140 (owner's iPhone, 16.11 22:53): the latch was dataFlowing only; AmneziaWG came up on node 17
// while the API was unreachable (no /v1/ping, no whoami), so the ONLINE proof never came, and a later
// cancel stopped a tunnel that had shown «Подключено» for 18 s.
inline bool scanShownConnected(bool paused, bool engineConnected, bool tunnelConnected, bool dataFlowingNow)
{
    return (!paused && engineConnected && tunnelConnected) || dataFlowingNow;
}
inline void noteScanOwnConnectProgress(ScanOwnConnect &a, bool shownConnectedNow)
{
    if (a.active() && shownConnectedNow)
        a.reachedConnected = true;
}
// Path (c) CancelPendingConnect: the ordinary stop() ONLY for that connect and only before «Подключено».
// After an app relaunch the record belongs to another process (or does not exist): nothing to cancel.
// eventLoopRunning = the app's event loop still runs (QThread::loopLevel() > 0 on the GUI thread). It does
// not while the app is being terminated: ~AmneziaApplication joins the VPN thread, THEN deletes the QML
// engine, whose Scanner page calls close() from Component.onDestruction. A stop() there reaches only the
// facade (state and intent flip to off) - its disconnectFromVpn is queued to the joined thread and never
// runs - so app and tunnel diverged (S2, 16.11 22:53:58), and quitting the app is not the person's cancel
// anyway: the GUI's exit never acts on the tunnel (§19, BUG-6; upstream iOS does not stop on exit either).
enum class ScanCancel { Stop, IgnoreNoAttempt, IgnoreAppQuit, IgnoreOtherProcess, IgnoreAfterConnected,
                        IgnoreSuperseded, IgnoreNotPending };
inline const char *scanCancelName(ScanCancel d)
{
    switch (d) {
    case ScanCancel::Stop: return "stop";
    case ScanCancel::IgnoreNoAttempt: return "no_attempt";
    case ScanCancel::IgnoreAppQuit: return "app_quit";
    case ScanCancel::IgnoreOtherProcess: return "other_process";
    case ScanCancel::IgnoreAfterConnected: return "after_connected";
    case ScanCancel::IgnoreSuperseded: return "superseded";
    case ScanCancel::IgnoreNotPending: return "not_pending";
    }
    return "unknown";
}
inline ScanCancel decideScanCancel(const ScanOwnConnect &a, quint64 processEpoch, quint64 intentSerial,
                                   bool wantConnected, bool shownConnectedNow, bool eventLoopRunning)
{
    if (!a.active())
        return ScanCancel::IgnoreNoAttempt;
    if (!eventLoopRunning)
        return ScanCancel::IgnoreAppQuit;
    if (a.processEpoch != processEpoch)
        return ScanCancel::IgnoreOtherProcess;
    if (a.reachedConnected || shownConnectedNow)
        return ScanCancel::IgnoreAfterConnected;
    if (a.intentSerial != intentSerial)
        return ScanCancel::IgnoreSuperseded;
    if (!wantConnected)
        return ScanCancel::IgnoreNotPending;
    return ScanCancel::Stop;
}

// Build 142 - ONE rule for a session that never handshakes (owner's iPhone, build 140, 16.11; S3 and S5,
// three review rounds). The native tells every handshake timeout of a session whose extension answered "no
// handshake, no data" (IosController::handshakeNeverCompleted) with the send time of that status request.
// Invariant: an AmneziaWG session without a handshake within its budget is never kept as «Подключено»; what
// follows is the app's ORDINARY start path, whose end is proven (a handshake - and the data check where the app
// has one - or the counted failed start, the next pick and the backoff; it never shows Connected without a
// handshake). There is no special check of its own that could be left waiting (review rounds 1-3: the adopted
// session's re-check through the data check leaked three times around freezes and native state changes).
//  * stale: the request was sent before the app's last freeze (nativeFactFresh) - nothing; the next timeout
//    tells again (every 12 s while the native awaits the handshake);
//  * our own start in flight: its own budget goes on (start watchdog, failed start); only S5 acts - in Auto
//    mode, not for an exactly chosen node (a Scanner row tap), when an Xray pick exists and AmneziaWG is not
//    banned yet: AmneziaWG is banned for the attempt and the start ends as a failed start (next pick: Xray);
//  * a session the app holds as up (adopted at a relaunch - S3 of 23:20:26 -, or its own after a reassert),
//    no operation in flight: it is not kept - the same AmneziaWG ban when allowed, then the ordinary restart
//    (our guarded stop, reconcile starts the next pick of this attempt). Whatever states the native went
//    through meanwhile (Reconnecting -> Connecting -> Reconnecting around a thaw) and whatever was decided for
//    an earlier fact: the next fresh fact decides again, nothing is "already checked".
struct NoHandshakeInputs {
    bool fresh = false;            // the fact's status request was sent after the app's last freeze
    bool ownStartInFlight = false; // our start is in flight and the person still wants the VPN on
    bool tunnelHeldUp = false;     // the engine holds the session as up (Connected / Verifying), nothing in flight,
                                   // the person wants the VPN on
    bool nodeIsAwg = false;        // the session's node is an own AmneziaWG node
    bool autoMode = false;         // the effective transport mode is Auto
    bool explicitNode = false;     // the person chose exactly this node (a Scanner row tap)
    bool alreadyLeft = false;      // AmneziaWG is already banned in this attempt
    bool xrayPick = false;         // with every AmneziaWG node out this start could take an Xray node
};
enum class NoHandshake { LeaveAwg, Restart, IgnoreStale, IgnoreNotOurs, IgnoreOwnStartGoesOn };
inline NoHandshake decideNoHandshake(const NoHandshakeInputs &in)
{
    if (!in.fresh)
        return NoHandshake::IgnoreStale;
    if (!in.ownStartInFlight && !in.tunnelHeldUp)
        return NoHandshake::IgnoreNotOurs;
    const bool leave = in.nodeIsAwg && in.autoMode && !in.explicitNode && !in.alreadyLeft && in.xrayPick;
    if (in.ownStartInFlight)
        return leave ? NoHandshake::LeaveAwg : NoHandshake::IgnoreOwnStartGoesOn;
    return leave ? NoHandshake::LeaveAwg : NoHandshake::Restart;
}
inline const char *noHandshakeName(NoHandshake d)
{
    switch (d) {
    case NoHandshake::LeaveAwg: return "leave_awg";
    case NoHandshake::Restart: return "restart";
    case NoHandshake::IgnoreStale: return "stale";
    case NoHandshake::IgnoreNotOurs: return "not_ours";
    case NoHandshake::IgnoreOwnStartGoesOn: return "own_start_goes_on";
    }
    return "unknown";
}
// The facade's only path for the fact - its effects handed in, so the whole sequence runs in a test.
//  facts()          - the inputs as the facade sees them now (fresh = the request's send time vs. the freeze);
//  banAwg()         - ServiceEngine::banAwgForAttempt (records the failed rise, bans AmneziaWG for the attempt);
//  endSession(own)  - our start in flight: the failed-start bookkeeping; a held session: the network memory
//                     forgets its node; then our guarded stop with the intent kept - reconcile starts again.
struct NoHandshakeOps {
    std::function<NoHandshakeInputs()> facts;
    std::function<void(const QString &)> journal;
    std::function<void()> banAwg;
    std::function<void(bool ownStart)> endSession;
};
inline NoHandshake handleNoHandshakeFact(int timeouts, const QString &nodeId, const NoHandshakeOps &ops)
{
    const NoHandshakeInputs in = ops.facts();
    const NoHandshake d = decideNoHandshake(in);
    // Told every 12 s: silent unless something is done or a start of ours is being judged for the first time.
    if (d == NoHandshake::IgnoreNotOurs || (d == NoHandshake::IgnoreOwnStartGoesOn && (in.alreadyLeft || timeouts > 1)))
        return d;
    ops.journal(QStringLiteral("no_handshake node=%1 timeouts=%2 own_start=%3 held=%4 -> %5")
                    .arg(nodeId.isEmpty() ? QStringLiteral("-") : nodeId)
                    .arg(timeouts)
                    .arg(int(in.ownStartInFlight))
                    .arg(int(in.tunnelHeldUp))
                    .arg(QLatin1String(noHandshakeName(d))));
    if (d == NoHandshake::LeaveAwg)
        ops.banAwg();
    if (d == NoHandshake::LeaveAwg || d == NoHandshake::Restart)
        ops.endSession(in.ownStartInFlight);
    return d;
}

// Build 142 (review round 2, N4): a state or a fact from before the app's last freeze is never evidence.
// iOS suspends the app with requests and timers pending; the extension lives on and may restore the path
// meanwhile. freezeBoundaryMs = the later of the last hide and the last return to the screen (the P2-2 rule of
// classifyApiOutcome); <= 0 = never frozen.
// A native fact (an answered status reply) counts only if its request was sent after the boundary.
inline bool nativeFactFresh(qint64 requestSentMs, qint64 freezeBoundaryMs)
{
    return freezeBoundaryMs <= 0 || requestSentMs >= freezeBoundaryMs;
}

// A row tap's connect chain as the coordinator needs it: the node the ladder left (connectFailed), the end
// of the chain without data (attemptEnded), «Подключено» (dataFlowing on a node). Observed from engine
// state on every change; no timer.
struct ScanRowAttempt {
    bool active = false;
    QString tapped;
    QString lastNode;
    quint64 intentSerial = 0;
    QStringList reported;
};
struct ScanRowStep {
    QStringList failed;
    bool connected = false;
    QString connectedNode;
    bool ended = false;
};
inline void scanRowAttemptBegin(ScanRowAttempt &a, const QString &nodeId, quint64 intentSerial)
{
    a = ScanRowAttempt();
    a.active = true;
    a.tapped = nodeId;
    a.lastNode = nodeId;
    a.intentSerial = intentSerial;
}
// engineNode = the node the engine raises or carries now ("" = none); gaveUp = the chain cannot go on by
// itself (intent off, the start backoff began, data-plane cap reached).
inline ScanRowStep scanRowAttemptObserve(ScanRowAttempt &a, quint64 intentSerial, const QString &engineNode,
                                         bool dataFlowing, bool gaveUp)
{
    ScanRowStep st;
    if (!a.active)
        return st;
    if (intentSerial != a.intentSerial) { // another action took the tunnel: not this chain any more
        a.active = false;
        return st;
    }
    auto fail = [&a, &st](const QString &n) {
        if (!n.isEmpty() && !a.reported.contains(n)) {
            a.reported << n;
            st.failed << n;
        }
    };
    if (dataFlowing && !engineNode.isEmpty()) {
        if (engineNode != a.lastNode)
            fail(a.lastNode);
        a.active = false;
        st.connected = true;
        st.connectedNode = engineNode;
        return st;
    }
    if (!engineNode.isEmpty() && engineNode != a.lastNode) {
        fail(a.lastNode);
        a.lastNode = engineNode;
    }
    if (gaveUp) {
        fail(a.lastNode);
        a.active = false;
        st.ended = true;
    }
    return st;
}

// The live status the coordinator reads (ScanCurrent): which node the live tunnel is on and which node an
// attempt in progress raises (never probed with its key, §32 п. 3). state = DebugSnapshot::state;
// nativeUp = the platform reports the old runtime still up (Connected / Reconnecting / Disconnecting);
// next = ServiceEngine::nextCandidate() (what the next connect() raises).
struct ScanLiveView {
    bool live = false;
    bool connecting = false;
    bool failed = false;
    QString nodeId;
    QString attemptNodeId;
};
inline ScanLiveView scanLiveView(const QString &state, bool nativeUp, const QString &current, const QString &pendingSwitch,
                                 const QString &pinned, const QString &next, bool wantConnected, bool restartPending,
                                 bool dataFlowing)
{
    ScanLiveView v;
    const bool up = state == QLatin1String("connected") || state == QLatin1String("verifying");
    const bool switching = state == QLatin1String("switching");
    v.live = up || (switching && nativeUp && !pendingSwitch.isEmpty());
    v.nodeId = v.live ? current : QString();
    v.failed = state == QLatin1String("error");
    v.connecting = wantConnected && !dataFlowing && !v.failed;
    if (!wantConnected)
        return v;
    QString target;
    if (switching)
        target = pendingSwitch.isEmpty() ? current : pendingSwitch;
    else if (state == QLatin1String("connecting") || state == QLatin1String("selecting"))
        target = current.isEmpty() ? next : current;
    else if (restartPending)
        target = pinned.isEmpty() ? next : pinned;
    else if (!up)
        target = next;
    v.attemptNodeId = target == v.nodeId ? QString() : target;
    return v;
}

// ── AVPN Scanner, second pass (lane L6b) ───────────────────────────────────────────────────────────────────

// An endpoint "a.b.c.d:port" or "[v6]:port" whose host is an IP literal (an awg_mini session dials it without DNS).
inline bool endpointIsIpLiteral(const QString &endpoint)
{
    const QString e = endpoint.trimmed();
    static const QRegularExpression v4(QStringLiteral("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}):([0-9]{1,5})$"));
    static const QRegularExpression v6(QStringLiteral("^\\[([0-9A-Fa-f:.]{2,45})\\]:([0-9]{1,5})$"));
    QRegularExpressionMatch m = v4.match(e);
    if (m.hasMatch()) {
        for (int i = 1; i <= 4; ++i)
            if (m.captured(i).toInt() > 255)
                return false;
        const int port = m.captured(5).toInt();
        return port >= 1 && port <= 65535;
    }
    m = v6.match(e);
    if (m.hasMatch()) {
        const int port = m.captured(2).toInt();
        return m.captured(1).contains(QLatin1Char(':')) && port >= 1 && port <= 65535;
    }
    return false;
}

// awg_mini (awg-probe-plan.md §3; TribeScanner.h ScanAwgNodeInput): the device's OWN AmneziaWG input for one own
// node, exactly as the live tunnel gets it - AwgConfigBuilder (address = the subscription's, mtu = the node's or the
// platform default, the node's peer key / PSK / endpoint) and the daemon's UAPI order of the obfuscation lines
// (platforms/macos/daemon/wireguardutilsmacos.cpp: jc jmin jmax s1 s2 [s3] [s4] h1..h4, i1..i5, the AWG 3.0 keys,
// header_protection_key as hex, random_trailers / disable_cookies as 1|0). false = no config for that node (not an
// own AWG node, no private key, no tunnel address). An endpoint that is not an IP literal is left empty (the
// coordinator then refuses awg_no_endpoint). SECRET in, SECRET out: never logged, never stored here.
template <typename Out>
inline bool awgProbeInputFrom(const Subscription &sub, const SubscriptionNode &node, const QString &privateKey,
                              int defaultMtu, Out &out)
{
    if (node.upstream.has_value() || node.xray.has_value() || node.proto.compare(QLatin1String("awg"), Qt::CaseInsensitive) != 0)
        return false;
    if (privateKey.trimmed().isEmpty() || node.serverPubkey.trimmed().isEmpty())
        return false;
    QString address;
    for (const QString &a : sub.address) // the probe needs one address: the IPv4 one first, else the first
        if (!a.contains(QLatin1Char(':'))) {
            address = a.trimmed();
            break;
        }
    if (address.isEmpty() && !sub.address.isEmpty())
        address = sub.address.first().trimmed();
    if (address.isEmpty())
        return false;
    out.privateKey = privateKey.trimmed();
    out.address = address;
    out.mtu = node.mtu > 0 ? node.mtu : defaultMtu;
    out.peerPublicKey = node.serverPubkey.trimmed();
    out.presharedKey = node.presharedKey.trimmed();
    out.endpoint = endpointIsIpLiteral(node.endpoint) ? node.endpoint.trimmed() : QString();
    const AwgParams &a = node.awg;
    QList<QPair<QString, QString>> ob;
    auto num = [&ob](const char *k, int v) { ob.append({QLatin1String(k), QString::number(v)}); };
    auto str = [&ob](const char *k, const QString &v) {
        if (!v.trimmed().isEmpty())
            ob.append({QLatin1String(k), v.trimmed()});
    };
    num("jc", a.Jc);
    num("jmin", a.Jmin);
    num("jmax", a.Jmax);
    num("s1", a.S1);
    num("s2", a.S2);
    if (a.S3)
        num("s3", *a.S3);
    if (a.S4)
        num("s4", *a.S4);
    num("h1", a.H1);
    num("h2", a.H2);
    num("h3", a.H3);
    num("h4", a.H4);
    str("i1", a.I1);
    str("i2", a.I2);
    str("i3", a.I3);
    str("i4", a.I4);
    str("i5", a.I5);
    if (!a.headerProtectionKey.trimmed().isEmpty())
        ob.append({QStringLiteral("header_protection_key"),
                   QString::fromLatin1(QByteArray::fromBase64(a.headerProtectionKey.trimmed().toLatin1()).toHex())});
    str("content_padding_addition", a.contentPaddingAddition);
    str("rekey_after_time", a.rekeyAfterTime);
    str("rekey_timeout", a.rekeyTimeout);
    str("reject_after_time", a.rejectAfterTime);
    str("keepalive_timeout", a.keepaliveTimeout);
    str("max_handshake_attempts", a.maxHandshakeAttempts);
    if (a.randomTrailers.has_value())
        ob.append({QStringLiteral("random_trailers"), *a.randomTrailers ? QStringLiteral("1") : QStringLiteral("0")});
    if (a.disableCookies.has_value())
        ob.append({QStringLiteral("disable_cookies"), *a.disableCookies ? QStringLiteral("1") : QStringLiteral("0")});
    out.obfuscation = ob;
    out.boundIf = -1;
    return true;
}

// knownHostIps: the IP literals the engine resolved for EXACTLY this host (case-insensitive; a "host:port" or a
// URL host as given), in resolution order, without duplicates. {} = none known.
inline QStringList knownIpsForHost(const QHash<QString, QStringList> &byHost, const QString &host)
{
    QString h = host.trimmed().toLower();
    if (h.startsWith(QLatin1Char('[')) && h.contains(QLatin1Char(']')))
        h = h.mid(1, h.indexOf(QLatin1Char(']')) - 1);
    else if (h.count(QLatin1Char(':')) == 1)
        h = h.section(QLatin1Char(':'), 0, 0);
    if (h.endsWith(QLatin1Char('.')))
        h.chop(1);
    return byHost.value(h);
}

// The PHYSICAL uplink under the tunnel (item 7): the device's own VPN holds the default route on utun, so the
// platform's "transport medium" reads unknown (macOS) while the Wi-Fi / Ethernet interface still carries the
// tunnel. type: 1 Wi-Fi, 2 Ethernet, 3 cellular, 0 anything else; only an interface that is up, not virtual by
// name and has a routable IPv4 address counts. Wi-Fi and Ethernet both present -> "ethernet" (the order macOS
// gives the wired service by default); nothing -> "".
struct PhysicalIface {
    QString name;
    int type = 0;
    bool up = false;
    QStringList ipv4;
};
inline bool physicalIfaceNameVirtual(const QString &name)
{
    static const QStringList virt{QStringLiteral("utun"), QStringLiteral("ipsec"), QStringLiteral("ppp"), QStringLiteral("gif"),
                                  QStringLiteral("stf"), QStringLiteral("bridge"), QStringLiteral("awdl"), QStringLiteral("llw"),
                                  QStringLiteral("anpi"), QStringLiteral("ap"), QStringLiteral("lo"), QStringLiteral("vmenet"),
                                  QStringLiteral("tun"), QStringLiteral("tap"), QStringLiteral("wg"), QStringLiteral("feth")};
    for (const QString &v : virt)
        if (name.startsWith(v))
            return true;
    return false;
}
inline QString physicalUplinkKind(const QList<PhysicalIface> &ifaces)
{
    bool wifi = false, wired = false, cell = false;
    for (const PhysicalIface &i : ifaces) {
        if (!i.up || physicalIfaceNameVirtual(i.name))
            continue;
        bool routable = false;
        for (const QString &a : i.ipv4)
            routable = routable || (!a.startsWith(QLatin1String("169.254.")) && !a.startsWith(QLatin1String("127.")) && !a.isEmpty());
        if (!routable)
            continue;
        wifi = wifi || i.type == 1;
        wired = wired || i.type == 2;
        cell = cell || i.type == 3;
    }
    if (wired)
        return QStringLiteral("ethernet");
    if (wifi)
        return QStringLiteral("wifi");
    if (cell)
        return QStringLiteral("cellular");
    return QString();
}
// The network kind the Scanner uses, one order on every platform: the path monitor's physical kind first
// (macOS UplinkMonitor::pathKind - the route table's physical default route under the VPN; iOS
// IosScanHost::appPathKind), then the interface list (desktop only; iOS passes ""), then the platform's medium
// (doctorNetType) - which under the device's own VPN is the tunnel's and so last. The monitor and the interface
// list can differ (an Ethernet link with an address but no default route): the monitor wins and `disagree` asks
// the caller to journal it once. The reporting key is built from `kind` (upstreamNetworkKey).
struct ScanKindPick {
    QString kind;
    QString source; // "path" | "interfaces" | "platform" | "" (nothing known)
    bool disagree = false;
};
inline ScanKindPick scanNetworkKindPick(const QString &pathKind, const QString &interfacesKind, const QString &platformMedium)
{
    ScanKindPick p;
    if (!pathKind.isEmpty()) {
        p.kind = pathKind;
        p.source = QStringLiteral("path");
        p.disagree = !interfacesKind.isEmpty() && interfacesKind != pathKind;
        return p;
    }
    if (!interfacesKind.isEmpty()) {
        p.kind = interfacesKind;
        p.source = QStringLiteral("interfaces");
        return p;
    }
    if (!platformMedium.isEmpty()) {
        p.kind = platformMedium;
        p.source = QStringLiteral("platform");
    }
    return p;
}
inline QString scanNetworkKindName(const QString &pathKind, const QString &interfacesKind, const QString &platformMedium)
{
    return scanNetworkKindPick(pathKind, interfacesKind, platformMedium).kind;
}

// Item 4 (TribeScanner::reportCheckRefused): why a full check could not start or submit, as the machine's shade
// keys know it - "queue_full" (report_queue_full: the queue's 20 reports / 32 MiB wait for the network), "busy"
// (report_check_busy: another diagnostic runs), "unavailable" (report_check_unavailable: no queue, the switch off,
// the queue refused the report for another reason - support_diag off, too large twice, unsupported log type).
// Review F1: every light fact goes back WITH the ask it answers - TribeScanner::lightFactFor(askId, fact), which
// drops a fact of any ask but the latest - so a late fact of a previous scan never fills the next scan's card.
// The engine also drops it itself once a newer ask started (its epoch moved). bound = asked through
// startLightChecksFor; an old-style ask (startLightChecks) answers through lightFact.
struct ScanLightAsk {
    quint64 askId = 0;
    bool bound = false;
    quint64 epoch = 0; // the engine's light epoch when the ask came
};
template <typename Scanner, typename Fact>
inline bool scanDeliverLightFact(Scanner &scanner, const ScanLightAsk &ask, quint64 epochNow, const Fact &f)
{
    if (ask.epoch != epochNow)
        return false;
    if (ask.bound)
        scanner.lightFactFor(ask.askId, f);
    else
        scanner.lightFact(f);
    return true;
}

// The server's kill switch, immediate: a 404 of the scan endpoints (TribeScanner::serverSwitchedOff) asks for a
// fresh /v1/config at once through the existing refresh (ConfigService::refreshIfStale, the foreground path; no
// new timer), at most once per kScannerOffRefreshMs - ten 404s in a minute are one request. The refreshed
// switches then turn scannerEnabled off and the page leaves; the reverse waits for the periodic fetch.
// The throttle is the ask's own (lastAskMs): the refresh itself runs whatever the config's age (maxAge 0). With
// maxAge = kScannerOffRefreshMs a config fetched less than a minute before the 404 was "fresh", nothing was asked,
// and scanner_off stops every later scan request - the entry points stayed until the periodic fetch (~15 min).
inline constexpr qint64 kScannerOffRefreshMs = 60000;
template <typename Config>
inline bool facadeScannerOffRefresh(Config &config, qint64 &lastAskMs, qint64 nowMs)
{
    if (lastAskMs > 0 && nowMs - lastAskMs < kScannerOffRefreshMs)
        return false;
    lastAskMs = nowMs;
    config.refreshIfStale(0);
    return true;
}

// Queue lane F3/F4: "not_saved" (report_check_not_saved: not written to disk, not confirmed) and "rejected"
// (report_check_rejected: the server refused it; kept and retried after an app update) pass through.
inline QString scanCheckRefusalReason(const QString &why)
{
    if (why == QLatin1String("queue_full") || why == QLatin1String("full"))
        return QStringLiteral("queue_full");
    if (why == QLatin1String("busy") || why == QLatin1String("not_saved") || why == QLatin1String("rejected"))
        return why;
    return QStringLiteral("unavailable");
}

// Item 6: the existing service step of guardedStart (macOS desktop) as a decision, shared with the Scanner's
// explicit «Запустить службу». installed / running / outdated = macServiceInstalled / macServiceRunning /
// macServiceOutdated (MacServiceInstaller.h); upgradeDeclined = the user said no to the update in this session
// (Connect only: the Scanner's explicit tap asks again).
//  act          - anything to do at all (not running, or an install / update is due)
//  needInstall  - run the bundled installer (confirm dialog, administrator password, tarball, bootstrap)
//  outdatedOnly - installed and running, only older than this app (a refusal keeps the old service working)
struct MacServicePlan {
    bool act = false;
    bool needInstall = false;
    bool outdatedOnly = false;
};
inline MacServicePlan macServicePlan(bool installed, bool running, bool outdated, bool upgradeDeclined)
{
    MacServicePlan p;
    p.outdatedOnly = installed && running && outdated;
    p.needInstall = !installed || (outdated && !(p.outdatedOnly && upgradeDeclined));
    p.act = !running || p.needInstall;
    return p;
}
// The Scanner's tap must never cost the user the tunnel (§32): the installer replaces and restarts the root
// service (tribe-svc-install.sh bootstraps it again), which ends a live tunnel - so an install / update runs from the
// Scanner only while the VPN is off and not coming up; Connect does its own update with the tunnel down anyway.
// Starting a stopped service is always allowed (no tunnel can run without it).
inline bool macServiceTapAllowed(const MacServicePlan &p, bool vpnOnOrComing)
{
    return !(p.needInstall && vpnOnOrComing);
}
// What the Scanner's button would do now (QML text): "install" (no service), "update" (installed, other than
// this app's: older or newer - the app installs its own bundled one), "start" (installed, current, not running:
// launchd is given up to ~5 s), "none" (running and current).
inline const char *macServiceActionName(bool installed, bool running, bool outdated)
{
    if (!installed)
        return "install";
    if (outdated)
        return "update";
    if (!running)
        return "start";
    return "none";
}

struct AppliedIntentState {
    bool paused;
    bool resumeAfterPause;
    bool wantConnected;
};
inline AppliedIntentState appliedIntentState(bool pause, bool wasActive)
{
    // Resume is an explicit Enable; the state before the command may have been OFF.
    return {pause, pause && wasActive, !pause};
}

struct NodeDebugRow {
    QString nodeId;
    QString region;
    QString name;            // AVPN: имя сервера (опц.)
    QString countryCode;     // AVPN: ISO-3166 alpha-2 → флаг-эмодзи в UI; пусто = нет флага
    QString endpoint;        // AVPN: "host:port" — для показа реального сервера в UI (карточка/Серверы)
    double  scoreMs = 0.0;
    bool    healthy = true;
    // AVPN (live-node picker): обогащённый пул для шторки выбора сервера. Источник правды — backend
    // (weight оператора + health-агрегат из /v1/subscription), TCP-RTT не показываем (AWG = UDP-only).
    double  weight = 1.0;    // AVPN: вес оператора (ёмкость/нагрузка) — сортировка/фолбэк-выбор
    double  healthAgg = 1.0; // AVPN: агрегат backend-health 0..1 (пусто = 1.0 = живой) → 0..4 бара в UI
    bool    alive = true;    // AVPN: жив ли узел по backend-данным (healthAgg > 0)
    bool    current = false; // AVPN: == текущая выбранная нода (для акцента/галки в UI)
    QString reason;          // почему так ранжирована / последний вердикт пробы
    // AVPN (diag-report, Task 4 bff-3): протокол ноды из подписки ("awg") — для диагностики.
    QString proto;
    // AVPN AWG 3.0: мажор версии протокола обфускации ("1"/"2"/"3") — метка «Amnezia vN» в пикере.
    QString protoVersion;
    // AVPN (Доктор): manual_only/RU — только ручной pin; авто-потребители снапшота (очередь
    // запасных нод) обязаны такие скипать, иначе Доктор пересадит пользователя на RU-ноду.
    bool    manualOnly = false;
    // AVPN awg31-xray-v1 (§2.3, пикер «локации × транспорты»): host_id ноды (0 = не пришёл),
    // ключ локации (NodeRotation.h::locationKeyOf — по нему группируются строки пикера),
    // транспорты, доступные в локации среди живых нод (порядок = transport_rank), серверный
    // ранг транспорта ноды, поддерживается ли её proto ЭТИМ клиентом (xray под kill-switch и
    // платформенным гейтом — иначе строка серая «недоступно в этой версии»), и активный
    // транспорт локации (proto текущей ноды, если текущая — из этой локации; иначе пусто).
    int         hostId = 0;
    QString     location;
    QStringList transports;
    int         transportRank = 0;
    bool        transportSupported = true;
    QString     activeProto;
    // Upstream nodes (plan provider-pool v2, point 16): a provider profile row (no endpoint, no ICMP target,
    // neutral RTT) and its policy tier (own nodes 0). Model roles `upstream` / `upstreamTier` for the UI.
    bool        upstream = false;
    int         upstreamTier = 0;
    bool        packSourced = false; // synthesized from the standby pack (no stub in the subscription)
    // Display name parts (UpstreamNode.h::upstreamDisplayName); `name` carries the label only when custom.
    int         upstreamOrdinal = 0;
    bool        upstreamLabelCustom = false;
    // How the profile is shown (dto/Subscription.h::upstreamRowKind, contract 1.10.0): Country / Whitelist rows of
    // the manual list, Auto - the provider's balancer, kept in the pool for Auto and the Connect card, never a row.
    UpstreamKind upstreamKind = UpstreamKind::Unspecified;
};

// AVPN (A5, жалоба владельца 2026-09-23 «Connected, VPN работает, а карточка пишет «Умный выбор
// сервера»»): хост endpoint'а без порта — "host:port" → host, "[v6]:port" → v6.
inline QString endpointHost(const QString &endpoint)
{
    if (endpoint.startsWith(QLatin1Char('['))) {
        const int close = endpoint.indexOf(QLatin1Char(']'));
        return close > 0 ? endpoint.mid(1, close - 1) : endpoint;
    }
    const int colon = endpoint.lastIndexOf(QLatin1Char(':'));
    return colon > 0 ? endpoint.left(colon) : endpoint;
}

// Строка пула для карточки адоптированной сессии с НЕИЗВЕСТНОЙ identity (движок её не опознал:
// нода удалена/пересоздана или сменился порт/протокол): нода с id подсказки, иначе первая нода
// того же хоста (тот же сервер — та же страна). -1 — такого сервера в пуле нет, карточка
// показывает адрес сессии. Только показ: identity движка (health/failover) это НЕ меняет.
inline int hintedPoolRow(const QList<NodeDebugRow> &pool, const QString &hintNodeId,
                         const QString &hintEndpoint)
{
    if (!hintNodeId.isEmpty())
        for (int i = 0; i < pool.size(); ++i)
            if (pool.at(i).nodeId == hintNodeId)
                return i;
    const QString host = endpointHost(hintEndpoint);
    if (!host.isEmpty())
        for (int i = 0; i < pool.size(); ++i)
            if (endpointHost(pool.at(i).endpoint) == host)
                return i;
    return -1;
}

struct DebugSnapshot {
    QString state;                       // фаза машины состояний
    QString currentNodeId;
    qint64  latestHandshakeAgeSec = -1;
    qint64  rxBytes = 0, txBytes = 0;
    QString subStatus;                   // active/degraded
    bool    lkgStale = false;
    qint64  trafficUsed = 0, trafficLimit = 0;
    QString expiresAt;                   // AVPN: ISO-8601 из Subscription; "" = бессрочно (для daysLeft)
    // AVPN (diag-report, Task 4 bff-3): новые поля с дефолтами — существующих потребителей не ломают.
    QString graceUntil;                  // AVPN: expires_at + 24ч из Subscription; "" = нет
    int     bypassListVersion = 0;       // AVPN: версия применённых серверных bypass-списков (0 = вкомпиленные);
                                         // сеет фасад из BypassListService::lkgVersion() (движок его не знает)
    // AVPN awg31-xray-v1: proto текущей ноды ("awg"/"xray", пусто = не подключены), ручной режим
    // транспорта ("auto"/"awg"/"xray"), verifying = xray-туннель поднят, ждём первую удачную пробу
    // через него (фаза «Проверяем трафик…», «Подключено» ещё НЕ показываем — инвариант волны §4.3),
    // ревизия пула подписки (pool_revision, 0 = не пришла) и есть ли отложенный reseed.
    QString activeProto;
    QString transportMode = QStringLiteral("auto");
    bool    verifying = false;
    qint64  poolRevision = 0;
    bool    reseedPending = false;
    QList<NodeDebugRow> pool;
    QStringList switchLog;               // «switch A→B: причина»
    // Секреты (токен/приватный ключ) сюда НЕ кладём — маскировка на уровне UI (план §7).
};

// AVPN awg31-xray-v1 (независимое ревью волны, MINOR-7): единый предикат «туннель поднят или
// поднимается» по имени фазы из DebugSnapshot::state. Раньше этот список копировался в четыре
// места фасада (reprobe / switchToNode / setTransportMode / pauseForShopping), и в четвёртом
// забыли verifying — пауза для покупок считала xray-сессию «не поднятой» (m_wasConnected=false)
// и после паузы туннель не возвращался. Один список — одна правда.
inline bool isTunnelUpStateName(const QString &state)
{
    return state == QLatin1String("connected") || state == QLatin1String("connecting")
        || state == QLatin1String("switching") || state == QLatin1String("selecting")
        || state == QLatin1String("verifying");
}

} // namespace avpn

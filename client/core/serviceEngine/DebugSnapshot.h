// AVPN serviceEngine — снимок состояния для диагностической панели (5 тапов по логотипу). [СКАФФОЛД]
#pragma once

#include "dto/Subscription.h"
#include <QHash>
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

// P1-4: тап по орбу во время подхвата живой сессии (liveSessionFound → ждём статус, m_busy) или в
// первые секунды после адопта — это второй тап пользователя, который хотел ВКЛЮЧИТЬ (орб ещё
// показывал «выкл»/«Проверяем…»), а не выключить. 8 из 33 быстрых стопов по журналу — ровно эта
// последовательность (journal_on → adopt_connected → guarded_stop why=user за 0,6–1,5 с). Отмена
// СВОЕГО старта (подготовка, Op в полёте) остаётся законной.
constexpr qint64 kAdoptTapGraceMs = 2500;
inline bool stopTapIgnored(bool busy, bool ownOpInFlight, bool preparingStart, bool liveSessionPending,
                           qint64 sinceAdoptMs)
{
    if (preparingStart || ownOpInFlight)
        return false;
    if (busy && liveSessionPending)
        return true;
    return sinceAdoptMs >= 0 && sinceAdoptMs < kAdoptTapGraceMs;
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
constexpr qint64 kFgConfigThrottleMs = 15 * 60 * 1000;
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

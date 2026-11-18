// AVPN serviceEngine — оркестратор сервисной модели поверх движка Amnezia. [СКАФФОЛД C-1]
// Overlay: НЕ часть апстрима. Интеграция в UI/туннель — через тонкие адаптеры, см. README.md.
// TODO: сделать QObject в фоновом QThread (как VpnConnection), когда подключим к приложению.
#pragma once
#include <utility> // std::exchange

#include "DebugSnapshot.h"
#include "Enrollment.h"
#include "HealthLoop.h"
#include "ITunnelControl.h"
#include "Identity.h"
#include "NodePool.h"
#include "NodeRotation.h"
#include "TransportModeGate.h"
#include "TunnelWatchPlan.h"
#include "path/AttemptOwner.h"

#include <QJsonArray>
#include "path/PathProber.h"
#include "path/PathRace.h"
#include "dto/Subscription.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QHash>
#include <QSet>
#include <QString>

#include <functional>
#include <optional>

namespace avpn {

// AVPN awg31-xray-v1: Verifying — xray-туннель поднят платформой, но «Подключено» ещё НЕ показываем:
// ждём первую удачную пробу (DNS+HTTPS) ЧЕРЕЗ туннель (инвариант волны §4.3). Фасад ведёт пробу
// (async, бюджет xray_verify_timeout_ms) и зовёт verifySucceeded()/verifyFailed().
enum class EngineState { Disconnected, Selecting, Connecting, Verifying, Connected, Switching, Error };

// AVPN awg31-xray-v1: исход reseedPool (см. ниже).
// AVPN (фикс-волна 2026-09-22, K5): Unchanged — тело по содержимому совпало с текущим пулом
// (состав, identity и метаданные нод, адрес): обновлены только traffic/expiry/status, switchLog не
// трогаем (равная ревизия каждые ~20 с вымывала его), фасаду — ни changed(), ни persistPin, ни проб.
enum class ReseedResult { Applied, Deferred, Rejected, Unchanged };

class ServiceEngine {
public:
    ServiceEngine() : m_owner(path::AttemptTimings{})
    {
        m_net.observe(path::NetworkObservation{}); // "unknown" until the platform tells the network (observeNetwork)
    }

    // Платформенный туннель-адаптер (владение — у вызывающего).
    void setTunnel(ITunnelControl *tunnel) { m_tunnel = tunnel; }

    // AVPN (фикс-волна 2026-09-22): инъекция часов (epoch ms) для тестов — TTL кэша RTT и часы
    // фаз свитча. Пусто = QDateTime::currentMSecsSinceEpoch().
    void setNowMsForTest(std::function<qint64()> nowMs) { m_nowMsFn = std::move(nowMs); }

    // AVPN (выбор по скорости): кэш измеренного RTT по nodeId (off-tunnel ICMP, из AvpnEngineQml::probeNodeRtt).
    // connect() предпочитает ноду с минимальным RTT отсюда (pickByMeasuredRtt); пусто → фолбэк на weight.
    // AVPN (фикс-волна 2026-09-22, B9): у каждой ноды свой возраст замера (TTL kRttTtlMs).
    //  setMeasuredRtt(map) — заменить свежий кэш: ноды вне map забываются; значение <0 («нет ответа в
    //    этом раунде») НЕ затирает прошлый замер этой ноды, если он моложе TTL (один потерянный пакет не
    //    исключает ноду из ранжирования);
    //  mergeMeasuredRtt(map) — то же, но ноды вне map сохраняются (раунд дополняет кэш);
    //  measuredRtt() — только значения >=0 моложе TTL;
    //  lastKnownRtt() — последний известный замер каждой ноды БЕЗ TTL (failover при запрете замеров в
    //    connected: лучше старый RTT с пометкой возраста в switchLog, чем монета по весам).
    static constexpr qint64 kRttTtlMs = 120000;
    void setMeasuredRtt(const QHash<QString, int> &rtt);
    void mergeMeasuredRtt(const QHash<QString, int> &rtt);
    qint64 measuredRttAgeMs() const;
    QHash<QString, int> measuredRtt() const;
    QHash<QString, int> lastKnownRtt() const;
    // Decision 2026-11-05: what ranks and what an Xray listener's exit measures (TransportPick.h).
    // rankingRtt(raw) - for every "fastest" choice (auto location, failover, Doctor alternatives);
    // exitRtt(raw) - the honest exit RTT only (unknown = absent), for comparisons that need a real value.
    QHash<QString, int> rankingRtt(const QHash<QString, int> &raw) const;
    QHash<QString, int> exitRtt(const QHash<QString, int> &raw) const;
    qint64 lastKnownRttAgeMs(const QString &nodeId) const; // -1 = замера не было

    // Первый вход: genkey (Identity, reuse форка) → POST /v1/trial → сохранить токен. [IN-FORK]
    // store/nam отдаёт приложение (SecureAppSettingsRepository, amnApp->networkManager()).
    bool enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                SecureAppSettingsRepository *store, QString &error);
    QString subscriptionToken() const { return m_token; }

    // Загрузить подписку (тело GET /v1/subscription). Заполняет NodePool. false + error при провале.
    // AVPN (фикс-волна 2026-09-22, K5/B1): false — ТОЛЬКО битое тело (парс). Серверная pool_revision
    // не глобальный монотонный счётчик — по ней не отвергаем (порядок ответов гарантирует фасад по
    // m_subscriptionSequence). Пустые nodes при непустом пуле ТОГО ЖЕ аккаунта (address совпал):
    // обновляются только traffic/expiry/status/grace, пул и pending-reseed сохраняются (degraded/окно
    // readiness не затирает рабочий пул). Пустые nodes с ДРУГИМ address (redeem/transfer → новый
    // аккаунт в окне readiness) — обычный путь применения/отложения: чужой пул и /32 не сохраняем.
    bool loadSubscription(const QByteArray &json, QString &error);

    // AVPN (фикс-волна 2026-09-22, K5/B1, ревью CL-B): правило перезаписи дискового LKG телом ответа
    // (то же, что shouldPersistLkgBody фасада): тело с нодами — пишем; пустое — только если в текущем
    // дисковом LKG нод нет или LKG принадлежит другому аккаунту (другой address).
    static bool lkgWriteAllowed(const Subscription &body, const QByteArray &diskLkg);

    // AVPN (LKG, C-7): загрузить подписку из ДИСКОВОГО кэша (последний удачный ответ) — мгновенный
    // бейдж/пул при старте до сетевого bootstrap. Помечает снапшот lkgStale=true; свежий сетевой
    // loadSubscription (ensureSubscription) перезаписывает данные и снимает флаг.
    bool loadSubscriptionFromLkg(const QByteArray &json, QString &error);

    // Список не-фатальных проблем текущей подписки (см. SubscriptionParser::validate).
    QStringList subscriptionIssues() const;

    // AVPN (#35 живой трафик): освежить счётчики подписки из GET /v1/account (used/limit/expires),
    // не перезагружая ноды. Зовётся периодически из onTick, пока подключены → бейдж ГБ/дней «живой».
    void updateSubscriptionTraffic(qint64 used, qint64 limit, const QString &expiresAt)
    {
        m_pool.updateTraffic(used, limit, expiresAt);
    }

    // AVPN awg31-xray-v1 (спека §2.3, инвариант §4.4): reseed пула на ЖИВОМ приложении по смене
    // pool_revision (refreshSubscription фасада; kill-switch features.subscription_reseed_pool —
    // проверяет фасад). Правила: применяем СРАЗУ только в терминале (Disconnected/Error) ИЛИ если
    // текущая нода (и цель незавершённого свитча) в новом пуле НЕ изменилась (endpoint +
    // server_pubkey / xray uuid); иначе Deferred — тело откладывается и применяется при переходе в
    // терминал (applyPendingReseed, фасад зовёт через QTimer::singleShot(0) — никогда из-под
    // Selector::pick). Rejected: пустой пул / нет ревизии — пул НЕ затирается.
    // AVPN (фикс-волна 2026-09-22, K5/B2): меньшая ревизия допустима (ревизия не монотонна — удаление
    // ноды опускает max); Unchanged — содержимое совпало с текущим пулом (см. enum).
    // При применении: ревалидация pin по локации (узел исчез → сосед той же локации, иначе снять;
    // актуальный pin — pinnedNodeId(), фасад персистит его, а не старый id), сброс RTT-кэша и
    // сессионных провалов для исчезнувших узлов, запись в switchLog (только при смене состава/identity
    // или ревизии). Адоптированный туннель без identity: после применения — попытка опознать текущую
    // ноду по endpoint сессии (подсказка из adoptTunnelConnected).
    ReseedResult reseedPool(const Subscription &sub);
    bool hasPendingReseed() const { return m_pendingReseed.has_value(); }
    bool applyPendingReseed();
    // GAP-1: отложенное тело reseed движок применяет сам МЕЖДУ рантаймами своего свитча (DEAD →
    // переподъём/другая нода; туннель гасится или уже погашен) — иначе переподъём «той же ноды» шёл
    // по старому конфигу (порт/awg_params/pubkey) и поднимался мёртвым. Чистая операция в памяти (без
    // I/O). Фасад, у которого после этого hasPendingReseed()==false, забирает флаг и делает свою
    // пост-обработку applyPendingReseed (m_nodeRtt, persist актуального pin, changed()). true = было.
    bool takeReseedAppliedInSwitch()
    {
        const bool was = m_reseedAppliedInSwitch;
        m_reseedAppliedInSwitch = false;
        return was;
    }
    qint64 poolRevision() const { return m_pool.subscription().poolRevision; }

    // Подключиться: выбрать ноду и поднять туннель. [СКАФФОЛД: выбор=первый, реальный скоринг в C-4]
    bool connect(QString &error);

    EngineState state() const { return m_state; }
    // AVPN: подписка уже загружена (есть ноды) → connect() можно звать ЛОКАЛЬНО, без сетевого startFlow
    // (enroll/GET subscription). Нужно, чтобы реконнект не ходил в сеть на главном потоке (вложенный
    // QEventLoop → Hang UIKit + abort на 2-м коннекте). Как Amnezia: коннект-кнопка только поднимает туннель.
    bool hasSubscription() const { return !m_pool.nodes().isEmpty(); }
    DebugSnapshot debugSnapshot() const;

    // C-5 health-loop:
    //  tick() — периодический (QTimer 3–5с в in-fork обвязке): читает stats, кормит HealthLoop,
    //           при DEAD → onDead() (свитч на лучшего кандидата, исключая мёртвую ноду).
    //  notifyConnectionLost() — реактивный: дёргать из onConnectionStateChanged при неожиданном
    //           Error/Disconnected, пока state==Connected → немедленный свитч.
    //  Возвращают true, если произошёл свитч/обработка DEAD.
    // AVPN (фикс-волна 2026-09-22, K5/B3): tick работает и для адоптированного туннеля без identity
    // (нода сессии не найдена в пуле) — DEAD → лечение/failover на авто-выбор, лог «dead (unknown identity)».
    bool tick(qint64 nowEpoch);
    bool notifyConnectionLost();
    // AVPN (macOS wake-реконнект, спека 2026-07-17 §2.2): сброс prev-сэмпла HealthLoop на
    // пробуждении — ночные дельты rx/tx против свежего замера дали бы ложный onDead (up() в ещё
    // не готовую сеть). Аналог общий с iOS P1 (foreground-ресинк). Только сэмплинг, фазу не трогает.
    void resetHealthSampling() { m_health.reset(); }
    // AVPN (фикс-волна 2026-09-22, K5/B8, роуминг): смена сети (reachability/интерфейс/путь) —
    // сброс выборки HealthLoop и запрет DEAD-вердикта в окне grace (health_network_grace_s, деф. 20 с):
    // NE лечит путь сам (bump/rebind ≤ ~15 с), ложный DEAD в этом окне уводил EE→US.
    // nowEpoch <0 → текущее время (сек).
    void noteNetworkChange(qint64 nowEpoch = -1);

    // AVPN (фикс-волна 2026-09-22, K4/B7): итог rebind в NE (IosController::rebindFinished →
    // фасад). performed=false (NE отказал по бюджету / адаптер не запущен / нет ответа за 3 с) =
    // провал шага лечения: следующий DEAD-цикл сразу идёт на шаг 2/3 (переподъём / другая нода).
    // Ответ без ожидающего rebind (поздний/чужой) игнорируется. true = учтено.
    // GAP-2: reason — причина отказа из ответа NE ({"rebind":"denied","reason":…}). "offline" = у NE
    // путь unsatisfied (телефон без сети, нода ни при чём): это НЕ провал шага — попытка rebind не
    // тратится, m_rebindDenied не ставится, открывается окно grace смены сети (как noteNetworkChange);
    // следующий DEAD снова делает rebind. Кап kRebindOfflineDeferMax таких отсрочек на сессию лечения
    // (страховка от вечной петли при ложном "offline"). "budget"/"not_started"/пусто — провал (как было).
    bool onRebindResult(bool performed, const QString &reason = QString());
    static constexpr int kRebindOfflineDeferMax = 10;
    bool rebindAwaitingResult() const { return m_rebindAwaiting; }
    QString currentNodeId() const { return m_currentNodeId; }

    // ---- Upstream nodes (plan provider-pool v2, lane L1; CONNECT-INVARIANTS proposal §31) ----
    // The start of a provider node was refused BEFORE its tunnel came up (no seat, refused, bad or no answer):
    // the tunnel adapter calls it right before it reports the tunnel Error. It is an outcome of the leg for the
    // attempt owner (no seat / refused - recorded in the ledger as a short cooldown, never the network ladder).
    void noteStartRefused(const QString &nodeId, const QString &code);
    // The lease owner said the running upstream session must leave its node: the live session is lost (refused /
    // no seat recorded) and the failover attempt walks on without it. false = not connected on an upstream node.
    bool leaveUpstreamNode(const QString &code, const QString &detail = QString());
    bool currentNodeIsUpstream() const;
    // upstream_revision of the subscription in force (0 = none).
    qint64 upstreamRevision() const { return m_pool.subscription().upstreamRevision; }
    // The node by id (the tunnel adapter builds an upstream bring-up from it). nullptr = not in the pool.
    const SubscriptionNode *nodeById(const QString &nodeId) const { return findNode(nodeId); }
    // Standby-pack candidates (UpstreamEngine.h::standbyPackCandidates, computed by the facade): merged
    // after the subscription's nodes into the candidates of every choice and the debug rows. Empty = none.
    void setStandbyCandidates(const QList<SubscriptionNode> &nodes);
    // Contract 1.14.0: provider stubs of a Scanner batch beyond the delivered ones, parsed by the subscription's own
    // parser (the upstream revision in force). Kept up to kMaxScanOffered (newest win, deduplicated by node id),
    // dropped when the upstream revision changes; merged into the pool with the standby candidates (the facade's
    // syncStandbyCandidates). Returns how many are kept now.
    static constexpr int kMaxScanOffered = 48;
    int offerScanNodes(const QJsonArray &nodes);
    QList<SubscriptionNode> scanOfferedNodes();
    QList<path::PathCandidate> pathPoolForTest() const { return pathPool(); }
    const QList<SubscriptionNode> &subscriptionNodes() const { return m_pool.nodes(); }
    const QList<SubscriptionNode> &candidateNodes() const { return m_merged; }

    // ---- Path engine, stage 1 (design 2026-11-17; path/*.h) ----------------------------------------------
    // ONE owner of every connect attempt (path::AttemptOwner) and ONE evidence store (path::PathLedger, per
    // local network). connect() begins an attempt for the user's choice; the owner brings candidates up one at a
    // time through this engine (up/down of the tunnel adapter), judges each by its start deadline and by one
    // in-tunnel data check (Verifying), records attributable outcomes and ends with one result. The facade
    // feeds: the network (observeNetwork), a tick (attemptTick), the tunnel callbacks (onTunnel*), the data
    // check (verify*), and reads the result (takeAttemptResult) and the journal lines (takeAttemptJournal).
    // The choice: Auto / preferred country / exact server (path::UserChoice); the transport mode is stronger.
    void setUserChoice(const path::UserChoice &c) { m_choice = c; }
    const path::UserChoice &userChoice() const { return m_choice; }
    // Every observation of the platform's network (tunnel down medium, fingerprint). A new local key = a new
    // generation: an attempt in flight restarts on the new network, late answers of the old one change nothing.
    void observeNetwork(const path::NetworkObservation &o);
    const path::NetworkKey &network() const { return m_net.current(); }
    void attemptTick();
    // Stage 2: a race that runs before the owner's first leg is part of the attempt (the orb is busy, reconcile waits).
    bool attemptRunning() const { return m_owner.running() || m_raceFirst; }

    // ---- Stage 2: the probe race in front of the owner (path/PathRace.h) ----
    // The platform's probe host (nullptr = none: stage-1 behaviour exactly). Server switch features.path_race
    // (compiled default off) gates it on top of the host's own availability.
    void setProber(path::IPathProber *prober)
    {
        m_prober = prober;
        if (m_prober && m_net.current().usable())
            m_prober->prepare(m_net.current());
    }
    // The one byte ledger the Scanner uses: bytes the race may still spend now (-1 = no cap) and the charge of what
    // a probe spent. Unset = no cap, nothing charged.
    void setProbeBudget(std::function<qint64()> bytesLeft, std::function<void(qint64)> charge)
    {
        m_probeBytesLeft = std::move(bytesLeft);
        m_chargeProbeBytes = std::move(charge);
    }
    void setProbeCosts(const path::PathRace::Costs &c) { m_probeCosts = c; }
    void onProbeResult(const path::ProbeStamp &stamp, path::PathOutcome outcome, qint64 bytesSpent);
    // A probe proof that came from elsewhere (the Scanner's finished scan on the current network): recorded at
    // "probe ok" strength, like a race result. false = not recorded (unknown node, no usable network).
    bool recordProbeProof(const QString &nodeId, const QString &source);
    // R1 (device round 4): the ledger outcome of a provider start failure code (Inconclusive = not the path's).
    static path::PathOutcome startFailureOutcome(const QString &code);
    bool raceRunning() const { return m_race.running(); }
    void setRaceTimingsForTest(const path::RaceTimings &t) { m_raceTimingsForTest = t; }
    // "checked N of M" of the running attempt (0/0 = no walk).
    int attemptChecked() const { return m_owner.running() ? m_owner.progressDone() : 0; }
    int attemptTotal() const { return m_owner.running() ? m_owner.progressTotal() : 0; }
    // The data check deadline of a leg (the facade's checks finish inside it).
    int dataCheckMs() const { return m_owner.timings().dataCheckMs; }
    std::optional<path::AttemptResult> takeAttemptResult() { return std::exchange(m_lastResult, std::nullopt); }
    QStringList takeAttemptJournal() { return std::exchange(m_attemptJournal, QStringList()); }
    // Legs whose tunnel never came up (no handshake / no connect within the start deadline) since the last call -
    // the white-list detector's "the connect did not come up" input (DebugSnapshot.h::whitelistTriggerFromAttempt).
    int takeLegStartFailures() { return std::exchange(m_legStartFailures, 0); }
    // The owner asked to run the data check again on the same tunnel (RunDataCheck recheck): the facade drops the
    // running check and starts a new one.
    bool takeCheckRerun() { return std::exchange(m_checkRerun, false); }
    // Review E2 of 18.11: a native event delivered while the native stream is at `nativeLeg`
    // (ITunnelControl::nativeLegSeen) belongs to that leg; one of an older leg than the leg the owner is starting,
    // checking or stopping is obsolete (a duplicate error, a late answer) and is dropped before any state change.
    bool nativeEventStale(quint64 nativeLeg) const;
    quint64 attemptLeg() const { return m_owner.currentLeg().leg; }
    // The ledger (persisted by the facade: QSettings avpn/pathLedger).
    void loadPathLedger(const QByteArray &json) { m_ledger = path::PathLedger::fromJson(json); m_ledgerDirty = false; }
    QByteArray pathLedgerJson() const { return m_ledger.toJson(); }
    bool pathLedgerDirty() const { return m_ledgerDirty; }
    void clearPathLedgerDirty() { m_ledgerDirty = false; }
    // The state of a node on the current network ("working" / "unknown" / "suspect" / "dead").
    QString pathStateHere(const QString &nodeId) const;
    // Nodes that failed on the current network (suspect / dead) and the newest working one ("" = none) -
    // the Scanner's plan reads them instead of its own caches.
    QSet<QString> pathsFailedHere() const;
    QString bestWorkingPathHere() const;
    // Test hook: attempt numbers without TuningStore.
    void setAttemptTimingsForTest(const path::AttemptTimings &t) { m_timingsForTest = t; }

    // The subscription in force (account fields + the device's tunnel address; nodes via candidateNodes()).
    const Subscription &subscription() const { return m_pool.subscription(); }
    // AVPN awg31-xray-v1: транспорт текущей ноды ("awg"/"xray"; пусто = нет текущей) и её локация.
    QString currentNodeProto() const;
    bool currentNodeIsXray() const { return isXrayProto(currentNodeProto()); }
    QString currentLocation() const;

    // AVPN awg31-xray-v1 (§2.3 «Connected по xray только после probe»):
    //  isVerifying()      — фаза Verifying (xray поднят, ждём пробу через туннель);
    //  verifySucceeded()  — проба прошла → Connected (история: успех + время до трафика);
    //  verifyFailed()     — бюджет исчерпан → провал data-plane: другой транспорт той же локации,
    //                       потом соседняя (onDead, tunnelStillUp=true — down()→Disconnected→up()).
    //  feedProbeResult()  — живая проба через туннель в Connected (QualityProbe фасада): для xray
    //                       N провалов подряд (xray_probe_fail_cycles) = DEAD → failover; awg — no-op
    //                       (у него handshake-критерий HealthLoop). true = произошёл свитч.
    // Все — без I/O; переходы туннеля, как всегда, приходят колбэками onTunnel*().
    bool isVerifying() const { return m_state == EngineState::Verifying; }
    bool verifySucceeded(int ttfbMs = -1);
    // reason: failover reason for onDead; any non-health-DEAD reason goes straight to step 3 of
    // the ladder (other transport of the same location, then another location).
    bool verifyFailed(const QString &reason = QStringLiteral("verify failed (failover)"));
    // Plan v3 step 5 (review): the data-path check could not decide (whoami 429/404, or no answer
    // and generate_204 passed). Connected exactly as without the check, but nothing is proven: the
    // give-up streak (data_plane_fail_max_tries) and the dead flag stay as they are - a reset here
    // made the failover carousel endless on a dead network.
    bool verifyInconclusive();
    // AVPN (iOS data watch, build 141): the extension reported no_data / unconfirmed for this session -
    // back from Connected to Verifying, so the facade re-checks the path with the existing data check
    // (verifySucceeded / verifyFailed / verifyInconclusive as after a start). Only from Connected with a
    // known node; heal budget, streak and failed list are untouched; a success of the re-check is recorded
    // in the transport history at most once per rise and without a time to traffic. Compiled for every
    // platform, called only from the facade's Q_OS_IOS block (PLATFORM-SCOPING §2).
    bool reenterVerifying();
    bool feedProbeResult(bool ok);

    // AVPN awg31-xray-v1: ручной режим транспорта (Авто / Amnezia / Xray). Локальная настройка —
    // персистит фасад (QSettings avpn/transportMode). В ручном режиме — hard-filter по proto на
    // всех путях выбора (connect/failover/ротация/pin); нет кандидатов → честная ошибка no_transport.
    // Review E8 of 18.11: an unavailable Xray (kill switch features.xray_client or the platform) no longer
    // reads as Auto - the mode stays as chosen and the attempt reports that it has no path (TransportModeGate.h
    // rule 2); every reader uses transportMode().
    //
    // 5.1.109 (S4.1; defect of 12.11.2026 on 138): the user's CHOICE is kept apart from the mode IN
    // FORCE, and the whole rule of how the mode in force follows the choice is one plain class -
    // TransportModeGate.h (read its header: a tap, a loss of Xray, admission at load / after the
    // startup observation / while nothing is running, sessions this process did not start). The
    // engine owns the gate, gives it what it cannot know (is Xray usable now, the engine phase, the
    // pin) and feeds the session events itself; the facade forwards its own events through the
    // calls below and applies the returned ModeChange (tests: transport_mode_gate_check for the
    // rule, transport_pick_check §17 for this side of it).
    void setTransportMode(TransportMode m) { m_modeGate.set(m, xrayClientSupported()); } // choice + in force
    // Review E8 of 18.11: the mode in force as the person chose it - availability never broadens it.
    TransportMode transportMode() const { return m_modeGate.inForce(); }
    TransportMode chosenTransportMode() const { return m_modeGate.choice(); }
    bool transportModeChoicePending() const { return m_modeGate.choicePending(xrayClientSupported()); }

    // What an event did. pinUnapplied - a pin the admitted mode cannot serve was dropped from the
    // engine; the saved pin stays (as "mode first, then restorePin" gave before 139) - no event of
    // the gate erases it. storeChoice - write avpn/transportMode (a legacy "xray" was dropped).
    // idleEntered - nothing is running any more.
    struct ModeChange {
        bool changed = false;
        TransportMode from = TransportMode::Auto;
        TransportMode to = TransportMode::Auto;
        QString pinUnapplied;
        bool storeChoice = false;
        TransportMode storedMode = TransportMode::Auto;
        bool idleEntered = false;
    };
    // The stored choice at load. The facade restores the pin AFTER this call.
    ModeChange loadTransportModeChoice(const QString &stored, bool byChoiceBuild);
    // Every transition of the facade (it forwards changed()), a config applied, the runtime gate.
    ModeChange noteModeActivity(const ModeActivity &a, const QString &why);
    // The startup observation is done and the tunnel reports no state while down (macOS service:
    // the end of the daemon probe). iOS / macOS NE need no call: their first status is it.
    ModeChange noteStartupObserved(const ModeActivity &a);
    // A tap on the selector: refused (Xray is not usable), a no-op, or the choice and the mode in force.
    TransportModeGate::Tap tapTransportMode(TransportMode m) { return m_modeGate.tap(m, xrayClientSupported()); }
    // macOS service: the next value of the tun2socks gate (loss at once; gain at once unless "Xray"
    // is the choice - then only while nothing is running).
    bool nextXrayRuntimeGate(bool readyNow, bool present, const ModeActivity &a) const;
    // Journal lines of the gate (and of the pin rule) since the last call - the facade writes them.
    QStringList takeModeJournal() { return m_modeGate.takeJournal(); }

    // AVPN (live-node picker): ручной выбор/ротация поверх авто-логики.
    //  setPinnedNode(nodeId) — «Выбрать»: только закрепляет узел (m_pinnedNodeId=nodeId), НЕ коннектит.
    //    Модель «выбор = задать цель, коннект — кнопкой»: следующий connect() (orb «Connect») поднимет
    //    закреплённую ноду. Тиар-даун текущего туннеля (если был онлайн другой узел) делает мост
    //    (AvpnEngineQml::switchToNode), чтобы избежать back-to-back up() без down() (iOS-storm).
    //    AVPN awg31-xray-v1: PIN — ПО ЛОКАЦИИ (host_id), не по узлу: закрепить можно любой узел
    //    локации (даже xray-строку при выключенном xray_client — если в локации есть awg); фактический
    //    транспорт выбирает connect() (transport_rank + история + ручной режим). Ошибки (технические
    //    строки, человеческий текст — AvpnEngineQml::humanPinError): unsupported_proto — в локации нет
    //    ни одного поднимаемого узла; no_transport — есть, но ручной режим их отфильтровал.
    //  rotateNext() — round-robin по живым ЛОКАЦИЯМ (NodeRotation.h::nextLiveNodeId), круговой индекс
    //    от текущей → следующая (заворот). Кнопка «Сменить сервер».
    //  pinnedNodeId() — закреплённая пользователем нода (пусто = авто); pinnedLocation() — её локация.
    // Возвращают true при успешном свитче/старте; false + error — нет такой/живой ноды или провал.
    bool setPinnedNode(const QString &nodeId, QString &error); // AVPN (был switchToNode: коннектил сам)
    bool rotateNext(QString &error);                          // AVPN
    // AVPN: следующая живая локация после текущей (та же логика, что rotateNext, но БЕЗ side-effects —
    // фасад использует для «Обновить подключение» через единый reconcile). Пусто = некуда ротировать.
    QString nextLiveNodeId() const;
    QString pinnedNodeId() const { return m_pinnedNodeId; }   // AVPN
    bool hasConnectablePin() const;
    // 5.1.109: the pinned location has connectable nodes but none of them serves transport mode
    // `mode` (as chosen - review E8 of 18.11) - the no_transport refusal of setPinnedNode (which
    // normalizes the stored mode first), without its side effects (setPinnedNode also drops the
    // interrupted-switch replay). False without a pin, for a pin no longer in the pool and in Auto.
    // The facade clears such a pin on a mode change (DebugSnapshot.h::decidePinOnTransportMode).
    bool pinLacksTransport(TransportMode mode) const;
    // 5.1.109 (review R1): the pin the last pool refresh dropped because its location no longer has a
    // node the effective transport mode allows (the pinned listener was removed). One-shot: the facade
    // persists the cleared pin and journals pin_cleared why=reseed. Empty = nothing dropped that way.
    QString takePinDroppedForTransport() { return std::exchange(m_pinDroppedForTransport, QString()); }
    // 5.1.108: the node the next connect() would raise - the same order (pin -> network memory ->
    // pickTransport; the legacy measured-RTT/weight chain when transport_auto_pick is off) without
    // any side effect (no switch log, no state change, no I/O). For the Connect card's protocol badge
    // before connecting. Not covered: the one-shot retry of an interrupted switch (no user choice).
    // Inside an equal-weight tier without measurements the pick is random - callers that must not
    // flicker show it only when the choice is deterministic (pin or a manual transport mode).
    // 5.1.109: the pick helpers read the mode in force (transportMode()), as connect() does.
    const SubscriptionNode *nextCandidate() const; // the owner's first choice now (PathSelect), no side effect
    QString pinnedLocation() const;                           // AVPN awg31-xray-v1
    // AVPN (RU-нода): закреплена ли сейчас РФ-нода (countryCode==RU). RU достижима ТОЛЬКО через ручной pin
    // (авто-выбор её исключает) → по этому флагу RU-direct-сплит отключается (full-tunnel через РФ).
    bool pinnedNodeIsRu() const;
    // AVPN: снять закрепление (вернуться в авто). «Авто (быстрейший)» (reprobe) и ручная ротация
    // (rotateNext) снимают pin — иначе connect() всегда отдаёт приоритет закреплённой ноде, и
    // возврат-в-авто / offline-ротация молча ломаются (reselect закреплённой).
    void clearPin() { m_pinnedNodeId.clear(); m_choice = path::UserChoice::automatic(); } // AVPN: back to Auto

    // AVPN: правдивый статус. up() ставит туннель в очередь (async), поэтому connect() остаётся в
    // Connecting; реальные переходы прилетают из VpnConnection::connectionStateChanged через
    // AvpnEngineQml. Вызывать ТОЛЬКО из onConnectionStateChanged (enum-free, без зависимости на Vpn::).
    //  onTunnelConnected()    — туннель реально поднялся (Connecting/Switching → Connected; для xray →
    //                           Verifying, см. выше).
    //  onTunnelError()        — туннель упал с ошибкой (любая фаза → Error).
    //  onTunnelDisconnected() — туннель отключился (Connected/Verifying/… → Disconnected, без свитча).
    // Возвращают true, если фаза изменилась (вызывающий шлёт changed()).
    bool onTunnelConnected();
    bool onTunnelError(bool tunnelGone = false); // tunnelGone: the Error proves the tunnel is down (desktop)
    bool onTunnelDisconnected();

    // AVPN (Android-адопт): туннель ФАКТИЧЕСКИ жив (AndroidController::initConnectionState после
    // ре-байнда мессенджера/холодного старта), а движок — в терминале после фейкового Disconnected
    // (обрыв байндинга при уходе в фон). Единственный легальный «воскреситель» Connected извне фаз
    // подъёма; обычный onTunnelConnected терминалы намеренно НЕ воскрешает.
    // AVPN (фикс-волна 2026-09-22, A5/B3): нода сессии не найдена в пуле (или её endpoint/proto уже
    // другие) → адопт с НЕИЗВЕСТНОЙ identity (true), подсказка {nodeId, proto, endpoint} запоминается:
    // после reseed движок пытается опознать текущую ноду по ней (tryIdentifyCurrentNode). В фазе
    // Connected — только обновление identity/подсказки (false, как раньше).
    bool adoptTunnelConnected(const QString &nodeId = {}, const QString &proto = {},
                              const QString &endpoint = {});
    bool currentIdentityKnown() const { return !m_currentNodeId.isEmpty(); }
    bool tryIdentifyCurrentNode();
    // AVPN (A5): подсказка сессии {node_id, proto, endpoint} неопознанного адопта — только для
    // показа на карточке (DebugSnapshot.h::hintedPoolRow); пусто, когда identity известна.
    struct SessionHint { QString nodeId, proto, endpoint; };
    SessionHint sessionHint() const
    {
        return {m_sessionHintNodeId, m_sessionHintProto, m_sessionHintEndpoint};
    }

    // AVPN: пользователь нажал «стоп». Помечаем НАМЕРЕННОЕ отключение (state→Disconnected,
    // сбрасываем текущую ноду) ДО m_tunnel.down(), иначе прилетевший Disconnected уйдёт в
    // notifyConnectionLost()→onDead()→switchTo() и туннель переподнимется сразу после стопа.
    void requestStop();

    // Полный flow «одной кнопки» (in-fork): enroll (если нет токена) → GET /v1/subscription → load → connect.
    // store/nam — из приложения; baseUrl — control plane. nowEpoch — для health/snapshot.
    bool startFlow(QNetworkAccessManager *nam, const QString &baseUrl,
                   SecureAppSettingsRepository *store, QString &error);

    // AVPN: «тихий» bootstrap при старте приложения (Task 11) — наполнить подписку ДО первого Connect,
    // чтобы бейдж ГБ/дней/subActive был живой сразу. Шаги: токен из хранилища (иначе enroll) →
    // GET /v1/subscription → loadSubscription. БЕЗ connect() (туннель не поднимаем). Состояние движка
    // НЕ трогаем (остаётся Disconnected). Возвращает true, если подписка наполнена; false + error —
    // при оффлайне/отсутствии токена (вызывающий трактует мягко, это не фатальная ошибка).
    bool bootstrap(QNetworkAccessManager *nam, const QString &baseUrl,
                   SecureAppSettingsRepository *store, QString &error);

    QStringList switchLog() const { return m_switchLog; }
    // AVPN (BUG-4 auto-heal): счётчики ребайнд-попыток — текущей ноды-сессии и суммарно с запуска
    // (телеметрия benchExtra: паттерн «оператор×нода×heal помог/нет» ищется по отчётам).
    int rebindHealTries() const { return m_rebindHealTries; }

    int rebindHealTotal() const { return m_rebindHealTotal; }
    TunnelStats currentStats() const { return m_tunnel ? m_tunnel->readStats() : TunnelStats{}; }

    // Ключи клиента (zero-knowledge) — фасад прокидывает их в туннель-адаптер до connect.
    bool identityEnsureKeys(SecureAppSettingsRepository *store, QString &error)
    {
        return m_identity.ensureKeys(store, error);
    }
    ClientKeys clientKeys() const { return m_identity.keys(); }
    // AVPN: доступ к Identity для in-fork сетевых вызовов фасада (redeem по коду — Enrollment::redeemCode).
    Identity &identity() { return m_identity; }

private:
    // AVPN (auth self-heal): общий путь startFlow/bootstrap — токен (из стора / enroll) → GET
    // /v1/subscription → loadSubscription. На 401 от токена ИЗ СТОРА: clearToken + один ре-энролл +
    // ретрай (стейл-токен после ротации secret на бэкенде; корень бага «unauthorized (token)»).
    // Решения вынесены в Enrollment::classifyFetch/decideAuthRecovery (покрыты auth_heal_check).
    bool ensureSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                            SecureAppSettingsRepository *store, QString &error);

    // The live session stopped carrying data (health DEAD, a failed live probe or re-check) or went away
    // (tunnelStillUp=false). Step 1 (B6) - rebind the socket on the same node (AmneziaWG, rebind_heal_max_tries,
    // a refusal of the NE skips it) - stays here. Otherwise the failover is a new attempt of the owner
    // (loseLiveSession): the first health DEAD of a node within its re-up budget (dead_reup_max_tries) does not
    // blame it, so the attempt raises it again first (step 2); a proven dead data plane is recorded and the
    // attempt walks on without it (step 3). reason - for the switch log.
    bool onDead(bool tunnelStillUp, const QString &reason = QString());

    // The pool of the attempt owner: supported, alive nodes as paths (path::pathCandidateFromNode).
    QList<path::PathCandidate> pathPool() const;
    path::SelectionContext ownerContext() const;
    void feedOwner(const path::AttemptEvent &ev);
    void applyOwnerEffects(const QList<path::AttemptEffect> &effects);
    void attemptJournal(const QString &line);
    path::AttemptTimings attemptTimings() const;
    // A live session is gone or no longer carries data (health DEAD after the heal steps, the data check of a
    // live session failed, the lease asked to leave): the failover attempt through the owner.
    void loseLiveSession(path::PathOutcome outcome, bool tunnelGone, bool restart, const QString &why);
    const SubscriptionNode *findNode(const QString &nodeId) const;
    bool anySupportedNode() const;
    // 5.1.109: can location `loc` be raised at all / under transport mode `mode` (the rule of
    // setPinnedNode and pinLacksTransport). anySupported - a connectable node of any proto.
    struct LocationTransports { bool anySupported = false; bool anyAllowed = false; };
    LocationTransports locationTransportsFor(const QString &loc, TransportMode mode) const;
    // 5.1.109 (S4.1): the engine's side of the mode gate - the pin rule of an admission, the engine
    // phase for "nothing is running", and sessions this process did not start.
    ModeChange applyGateOutcome(const TransportModeGate::Outcome &o);
    ModeActivity withEnginePhase(ModeActivity a) const;
    void judgeAdoptedSession(const QString &sessionProto, bool adoptedNow);
    // AVPN awg31-xray-v1 (reseed): применимо ли тело сейчас (терминал ИЛИ текущая/целевая нода без изменений).
    bool reseedApplicableNow(const Subscription &sub) const;
    static bool sameNodeIdentity(const SubscriptionNode &a, const SubscriptionNode &b);
    // AVPN (фикс-волна 2026-09-22, B2): полное совпадение содержимого (identity + метаданные выбора/
    // отображения) и совпадение состава пула/адреса — основа ReseedResult::Unchanged.
    static bool sameNodeContent(const SubscriptionNode &a, const SubscriptionNode &b);
    bool samePoolContent(const Subscription &sub) const;
    // Обновить только «аккаунтные» поля (traffic/expiry/status/grace/ревизию), пул не трогая.
    void updateAccountFields(const Subscription &sub, bool includeRevision);
    void applyReseedNow(const Subscription &sub);
    // GAP-1: применить m_pendingReseed (с нодами) между рантаймами свитча; true = применено.
    bool applyPendingReseedBetweenRuntimes();
    void markUpStarted();
    void appendSwitchLog(const QString &line);
    qint64 nowMs() const;
    // Сессия лечения (rebind/переподъём) принадлежит ноде: сбрасывается при смене ноды, стопе,
    // connect() и адопте — переподъём той же ноды бюджет НЕ возвращает (иначе вечная лестница).
    // Ревью CL-B (REV-1): бюджет возвращается и сам — после heal_budget_restore_s здорового туннеля
    // на той же ноде (rx растёт или свежий handshake, ни одного плохого цикла), см. noteHealthyTick.
    void resetHealSession(const QString &nodeId);
    void noteHealStep();
    void noteHealthyTick(const TunnelStats &stats, qint64 nowEpoch);
    bool applyLoadedSubscription(const Subscription &sub);

    Identity      m_identity;
    NodePool      m_pool;
    bool          m_lkgActive = false; // AVPN (LKG): пул наполнен из дискового кэша, свежего фетча ещё не было
    HealthLoop    m_health;
    ITunnelControl *m_tunnel = nullptr;
    EngineState   m_state = EngineState::Disconnected;
    QString       m_currentNodeId;
    QString       m_pinnedNodeId; // AVPN: закреплённая пользователем нода (switchToNode); пусто = авто
    // AVPN (выбор по скорости): off-tunnel ICMP RTT по nodeId. B9: у каждого замера свой момент (epoch ms).
    struct RttSample { int ms = -1; qint64 atMs = 0; };
    QHash<QString, RttSample> m_rttFresh;     // свежий кэш (читается с TTL kRttTtlMs)
    QHash<QString, RttSample> m_rttLastKnown; // последний известный замер без TTL (failover)
    qint64        m_rttSetAtMs = -1;          // момент последнего set/merge (measuredRttAgeMs)
    std::function<qint64()> m_nowMsFn;        // тестовые часы (пусто = системные)
    // A5/B3: подсказка identity адоптированной сессии (sessionMetadata), когда нода не опознана.
    QString       m_sessionHintNodeId, m_sessionHintProto, m_sessionHintEndpoint;
    QString       m_pinDroppedForTransport; // 5.1.109 (review R1), takePinDroppedForTransport
    QString       m_token;
    QString       m_accountId;
    QStringList   m_switchLog;
    int           m_rebindHealTries = 0; // AVPN BUG-4: попытки heal на текущей ноде-сессии (кап tunable)
    int           m_rebindHealTotal = 0; // AVPN BUG-4: суммарно с запуска (в benchExtra отчётов)
    QString       m_healNodeId;          // B6: нода, которой принадлежит текущая сессия лечения
    int           m_sameNodeReupTries = 0; // B6: переподъёмы той же ноды в этой сессии лечения
    bool          m_rebindAwaiting = false; // B7: rebind отправлен, ждём итог NE
    bool          m_rebindDenied = false;   // B7: NE отказал — шаг rebind в этой сессии лечения пропускаем
    int           m_rebindOfflineDefers = 0; // GAP-2: отказы NE "offline" в этой сессии лечения (кап)
    bool          m_reseedAppliedInSwitch = false; // GAP-1: pending-reseed применён движком в свитче
    // REV-1: восстановление бюджета лечения по времени здорового туннеля (epoch сек, 0 = нет).
    qint64        m_lastTickEpoch = 0;      // момент последнего tick (шаги лечения зовутся из него)
    qint64        m_healStepEpoch = 0;      // последний шаг лечения (rebind/переподъём) этой сессии
    qint64        m_healthySinceEpoch = 0;  // начало непрерывного здорового отрезка после шага
    qint64        m_tickPrevRx = -1;        // rx прошлого tick (рост rx = доказательство живого туннеля)
    // AVPN awg31-xray-v1:
    TransportModeGate m_modeGate; // 5.1.109: the stored choice and the mode in force (TransportModeGate.h)
    // Path engine (design 2026-11-17): the one owner of attempts, the evidence, the network, the user's choice.
    path::AttemptOwner m_owner;
    QList<SubscriptionNode> m_scanOffered;   // contract 1.14.0
    qint64 m_scanOfferedRevision = 0;
    // stage 2
    path::PathRace m_race;
    path::IPathProber *m_prober = nullptr;
    std::function<qint64()> m_probeBytesLeft;
    std::function<void(qint64)> m_chargeProbeBytes;
    path::PathRace::Costs m_probeCosts;
    std::optional<path::RaceTimings> m_raceTimingsForTest;
    bool m_ownerQueueRaceStop = false; // the owner finished inside an effect batch: stop the race after it
    bool m_raceStartedOwner = false; // this tap's owner was started by the race (never a second UserStart)
    bool m_raceFirst = false; // the race runs and the owner waits for its first proven path (or its end)
    bool raceAllowed() const;
    void beginRaceForTap();
    void applyRaceEffects(const QList<path::RaceEffect> &effects);
    void startOwnerAfterRace(const char *why);
    path::PathLedger m_ledger;
    bool m_ledgerDirty = false;
    path::NetworkTracker m_net;
    path::UserChoice m_choice;
    std::optional<path::AttemptResult> m_lastResult;
    QStringList m_attemptJournal;
    QList<path::AttemptEvent> m_ownerQueue;
    bool m_inOwner = false;
    int m_legStartFailures = 0;
    bool m_checkRerun = false;
    bool m_facadeStop = false;                 // the facade itself takes the tunnel down (user stop / restart)
    std::optional<path::AttemptTimings> m_timingsForTest;
    QList<SubscriptionNode> m_packCandidates;  // upstream: synthesized from the standby pack
    QList<SubscriptionNode> m_merged;          // subscription nodes + pack candidates (the pick pool)
    void rebuildCandidates();
    int           m_probeFailStreak = 0; // xray: провалы живой пробы подряд (feedProbeResult)
    qint64        m_upStartedMs = 0;     // момент последнего up()
    std::optional<Subscription> m_pendingReseed; // отложенное тело reseed (применить в терминале)
};

} // namespace avpn

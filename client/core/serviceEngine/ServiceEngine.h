// AVPN serviceEngine — оркестратор сервисной модели поверх движка Amnezia. [СКАФФОЛД C-1]
// Overlay: НЕ часть апстрима. Интеграция в UI/туннель — через тонкие адаптеры, см. README.md.
// TODO: сделать QObject в фоновом QThread (как VpnConnection), когда подключим к приложению.
#pragma once

#include "DebugSnapshot.h"
#include "Enrollment.h"
#include "HealthLoop.h"
#include "ITunnelControl.h"
#include "Identity.h"
#include "NodePool.h"
#include "NodeRotation.h"
#include "Selector.h"
#include "Switcher.h"
#include "TransportPick.h"
#include "dto/Subscription.h"

#include <QByteArray>
#include <QHash>
#include <QSet>
#include <QString>

#include <optional>

namespace avpn {

// AVPN awg31-xray-v1: Verifying — xray-туннель поднят платформой, но «Подключено» ещё НЕ показываем:
// ждём первую удачную пробу (DNS+HTTPS) ЧЕРЕЗ туннель (инвариант волны §4.3). Фасад ведёт пробу
// (async, бюджет xray_verify_timeout_ms) и зовёт verifySucceeded()/verifyFailed().
enum class EngineState { Disconnected, Selecting, Connecting, Verifying, Connected, Switching, Error };

// AVPN awg31-xray-v1: исход reseedPool (см. ниже).
enum class ReseedResult { Applied, Deferred, Rejected };

class ServiceEngine {
public:
    ServiceEngine() : m_switcher(nullptr) {}

    // Платформенный туннель-адаптер (владение — у вызывающего).
    void setTunnel(ITunnelControl *tunnel) { m_tunnel = tunnel; m_switcher = Switcher(tunnel); }

    // AVPN (выбор по скорости): кэш измеренного RTT по nodeId (off-tunnel ICMP, из AvpnEngineQml::probeNodeRtt).
    // connect() предпочитает ноду с минимальным RTT отсюда (pickByMeasuredRtt); пусто → фолбэк на weight.
    void setMeasuredRtt(const QHash<QString, int> &rtt) { m_measuredRtt = rtt; }
    QHash<QString, int> measuredRtt() const { return m_measuredRtt; } // AVPN awg31-xray-v1: после reseed (обрезан)

    // Первый вход: genkey (Identity, reuse форка) → POST /v1/trial → сохранить токен. [IN-FORK]
    // store/nam отдаёт приложение (SecureAppSettingsRepository, amnApp->networkManager()).
    bool enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                SecureAppSettingsRepository *store, QString &error);
    QString subscriptionToken() const { return m_token; }

    // Загрузить подписку (тело GET /v1/subscription). Заполняет NodePool. false + error при провале.
    bool loadSubscription(const QByteArray &json, QString &error);

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
    // Selector::pick). Rejected: пустой пул / нет ревизии / та же ревизия — пул НЕ затирается.
    // При применении: ревалидация pin по локации (узел исчез → сосед той же локации, иначе снять),
    // сброс RTT-кэша и сессионных провалов для исчезнувших узлов, запись в switchLog.
    ReseedResult reseedPool(const Subscription &sub);
    bool hasPendingReseed() const { return m_pendingReseed.has_value(); }
    bool applyPendingReseed();
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
    bool tick(qint64 nowEpoch);
    bool notifyConnectionLost();
    // AVPN (macOS wake-реконнект, спека 2026-07-17 §2.2): сброс prev-сэмпла HealthLoop на
    // пробуждении — ночные дельты rx/tx против свежего замера дали бы ложный onDead (up() в ещё
    // не готовую сеть). Аналог общий с iOS P1 (foreground-ресинк). Только сэмплинг, фазу не трогает.
    void resetHealthSampling() { m_health.reset(); }
    QString currentNodeId() const { return m_currentNodeId; }

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
    bool verifySucceeded();
    bool verifyFailed();
    bool feedProbeResult(bool ok);

    // AVPN awg31-xray-v1: ручной режим транспорта (Авто / Amnezia / Xray). Локальная настройка —
    // персистит фасад (QSettings avpn/transportMode). В ручном режиме — hard-filter по proto на
    // всех путях выбора (connect/failover/ротация/pin); нет кандидатов → честная ошибка no_transport.
    // AVPN (независимое ревью волны, MAJOR-2): недоступный Xray (kill-switch features.xray_client
    // или платформа) всегда читается как Auto — и при загрузке сохранённой настройки, и в UI, и на
    // всех путях выбора (normalizeTransportMode зовётся в начале connect()/onDead()).
    void setTransportMode(TransportMode m) { m_transportMode = effectiveTransportMode(m); }
    TransportMode transportMode() const { return effectiveTransportMode(m_transportMode); }
    void normalizeTransportMode() { m_transportMode = effectiveTransportMode(m_transportMode); }

    // AVPN awg31-xray-v1: локальная история транспортов (EWMA успеха/времени до трафика по паре
    // локация×proto, TransportPick.h). Персистит фасад (QSettings avpn/transportHistory):
    // load на старте, serialize — когда transportHistoryDirty().
    //  recordTransportOutcome(ok) — исход подъёма ТЕКУЩЕЙ ноды: ok=true на реальном Connected
    //    (awg — фасад на Vpn::Connected; xray — сам движок в verifySucceeded), ok=false на провале
    //    (Error при старте — фасад; DEAD/verify/probe — сам движок). Один успех и один провал на
    //    сессию подъёма (повторы игнорируются). true = записано.
    const TransportHistory &transportHistory() const { return m_transportHistory; }
    TransportHistory &transportHistory() { return m_transportHistory; }
    void loadTransportHistory(const QByteArray &bytes)
    {
        m_transportHistory = TransportHistory::deserialize(bytes);
        m_historyDirty = false;
    }
    QByteArray transportHistoryJson() const { return m_transportHistory.serialize(); }
    bool transportHistoryDirty() const { return m_historyDirty; }
    void clearTransportHistoryDirty() { m_historyDirty = false; }
    bool recordTransportOutcome(bool ok);

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
    QString pinnedLocation() const;                           // AVPN awg31-xray-v1
    // AVPN (RU-нода): закреплена ли сейчас РФ-нода (countryCode==RU). RU достижима ТОЛЬКО через ручной pin
    // (авто-выбор её исключает) → по этому флагу RU-direct-сплит отключается (full-tunnel через РФ).
    bool pinnedNodeIsRu() const;
    // AVPN: снять закрепление (вернуться в авто). «Авто (быстрейший)» (reprobe) и ручная ротация
    // (rotateNext) снимают pin — иначе connect() всегда отдаёт приоритет закреплённой ноде, и
    // возврат-в-авто / offline-ротация молча ломаются (reselect закреплённой).
    void clearPin() { m_pinnedNodeId.clear(); }               // AVPN

    // AVPN: правдивый статус. up() ставит туннель в очередь (async), поэтому connect() остаётся в
    // Connecting; реальные переходы прилетают из VpnConnection::connectionStateChanged через
    // AvpnEngineQml. Вызывать ТОЛЬКО из onConnectionStateChanged (enum-free, без зависимости на Vpn::).
    //  onTunnelConnected()    — туннель реально поднялся (Connecting/Switching → Connected; для xray →
    //                           Verifying, см. выше).
    //  onTunnelError()        — туннель упал с ошибкой (любая фаза → Error).
    //  onTunnelDisconnected() — туннель отключился (Connected/Verifying/… → Disconnected, без свитча).
    // Возвращают true, если фаза изменилась (вызывающий шлёт changed()).
    bool onTunnelConnected();
    bool onTunnelError();
    bool onTunnelDisconnected();

    // AVPN (Android-адопт): туннель ФАКТИЧЕСКИ жив (AndroidController::initConnectionState после
    // ре-байнда мессенджера/холодного старта), а движок — в терминале после фейкового Disconnected
    // (обрыв байндинга при уходе в фон). Единственный легальный «воскреситель» Connected извне фаз
    // подъёма; обычный onTunnelConnected терминалы намеренно НЕ воскрешает.
    bool adoptTunnelConnected();

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

    // AVPN (независимое ревью волны, MAJOR-1): подряд идущие провалы data-plane за сессию
    // (health-DEAD / провал verify / провал живой пробы) и признак «кап исчерпан» — движок ушёл в
    // Error вместо очередного круга failover. Сбрасываются успешной пробой через туннель
    // (verifySucceeded / feedProbeResult(true)) и явным действием пользователя (connect/stop/адопт).
    int dataPlaneFailStreak() const { return m_dataPlaneFailStreak; }
    bool dataPlaneExhausted() const { return m_dataPlaneExhausted; }
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

    // tunnelStillUp=true (health-DEAD из tick — туннель ещё «поднят») → down()→ждём Disconnected→up();
    // false (failover из реального Disconnected/Error — туннель уже опущен) → up() сразу.
    // reason — для switchLog (dead / verify failed / probe failed).
    bool onDead(bool tunnelStillUp, const QString &reason = QString()); // выбрать кандидата (исключая текущую) и переключиться

    // AVPN (live-node picker): backend-фолбэк выбор по max weight среди ЖИВЫХ нод, исключая exclA/exclB
    // (мёртвая/текущая). Живой = health-агрегат > 0; пустой health = живой (бэкенд провижинит живыми).
    // Не делает I/O (в отличие от Selector::pick) — чистый выбор по данным подписки. nullptr = нет.
    // Легаси-цепочка (kill-switch transport_auto_pick=false).
    const SubscriptionNode *pickByWeight(const QString &exclA, const QString &exclB) const; // AVPN

    // AVPN (выбор по скорости): среди ЖИВЫХ нод (health-агрегат > 0, исключая exclA/exclB) выбрать с
    // МИНИМАЛЬНЫМ измеренным RTT (m_measuredRtt, off-tunnel ICMP). nullptr = ни одна не измерена → caller
    // откатывается на Selector::pick/pickByWeight. Без I/O (использует уже накопленный кэш — CONNECT-INVARIANTS §1).
    // Легаси-цепочка (kill-switch transport_auto_pick=false).
    const SubscriptionNode *pickByMeasuredRtt(const QString &exclA, const QString &exclB) const; // AVPN

    // AVPN awg31-xray-v1: выбор транспорта по локациям (TransportPick.h) — pin-локация / та же
    // локация при failover / соседние; учитывает ручной режим, сессионные провалы, историю.
    // withExclusions=false — повторная попытка без сессионных провалов (иначе «нет нод» после
    // круга failover'ов). nullptr = кандидатов нет.
    const SubscriptionNode *pickTransport(const QString &preferLocation, const QString &preferNodeId,
                                          const QString &exclA, bool withExclusions) const;
    const SubscriptionNode *findNode(const QString &nodeId) const;
    bool anySupportedNode() const;
    // Провал data-plane текущей ноды: история + сессионный список провалов.
    void noteDataPlaneFailure();
    // AVPN awg31-xray-v1 (reseed): применимо ли тело сейчас (терминал ИЛИ текущая/целевая нода без изменений).
    bool reseedApplicableNow(const Subscription &sub) const;
    static bool sameNodeIdentity(const SubscriptionNode &a, const SubscriptionNode &b);
    void applyReseedNow(const Subscription &sub);
    void markUpStarted();
    void appendSwitchLog(const QString &line);

    // AVPN (фикс iOS-шторма свитча): двухфазный секвенс-свитч. requestSwitch ставит m_state=Switching
    // (→ transient Disconnected/Error от down() НЕ запускает failover) и: при tunnelUp — down(), ждём
    // реальный Disconnected (onTunnelDisconnected→continuePendingSwitch→up); при !tunnelUp — up() сразу.
    // НЕЛЬЗЯ up() сразу после down() на iOS (NEVPNManager «Operation Cancelled»). reason — для switchLog.
    bool requestSwitch(const QString &targetNodeId, bool tunnelUp, const QString &reason); // AVPN
    bool continuePendingSwitch(); // AVPN: поднять up() на отложенную целевую ноду (туннель уже опущен)

    Identity      m_identity;
    NodePool      m_pool;
    Selector      m_selector;
    bool          m_lkgActive = false; // AVPN (LKG): пул наполнен из дискового кэша, свежего фетча ещё не было
    Switcher      m_switcher;
    HealthLoop    m_health;
    ITunnelControl *m_tunnel = nullptr;
    EngineState   m_state = EngineState::Disconnected;
    QString       m_currentNodeId;
    QString       m_pinnedNodeId; // AVPN: закреплённая пользователем нода (switchToNode); пусто = авто
    QHash<QString, int> m_measuredRtt; // AVPN (выбор по скорости): off-tunnel ICMP RTT по nodeId (кэш)
    QString       m_pendingSwitchNodeId; // AVPN: целевая нода во время двухфазного свитча (пусто = нет)
    QString       m_pendingSwitchReason; // AVPN: причина для switchLog (pinned/rotate/dead)
    QString       m_token;
    QString       m_accountId;
    QStringList   m_switchLog;
    int           m_rebindHealTries = 0; // AVPN BUG-4: попытки heal на текущей ноде-сессии (кап tunable)
    int           m_rebindHealTotal = 0; // AVPN BUG-4: суммарно с запуска (в benchExtra отчётов)
    // AVPN awg31-xray-v1:
    TransportMode m_transportMode = TransportMode::Auto;
    TransportHistory m_transportHistory;
    bool          m_historyDirty = false;
    QSet<QString> m_failedThisSession;   // узлы, провалившие data-plane с последнего стопа (failover не ходит по кругу)
    int           m_probeFailStreak = 0; // xray: провалы живой пробы подряд (feedProbeResult)
    int           m_dataPlaneFailStreak = 0; // провалы data-plane подряд за сессию (кап — ConnectTunables.h)
    bool          m_dataPlaneExhausted = false; // кап исчерпан: Error вместо очередного failover
    qint64        m_upStartedMs = 0;     // момент последнего up() — время до «реального трафика» для истории
    bool          m_okRecorded = false;  // один успех / один провал на сессию подъёма
    bool          m_failRecorded = false;
    std::optional<Subscription> m_pendingReseed; // отложенное тело reseed (применить в терминале)
};

} // namespace avpn

#ifndef IOS_CONTROLLER_H
#define IOS_CONTROLLER_H

#include "core/protocols/vpnProtocol.h"
#include <functional>
#include <QVariant>
#include <QVariantMap>
#include <QStringList>
#include <QList>
#include <QElapsedTimer>
#include <atomic>
#include <mutex>    // AVPN (upstream nodes)
#include <optional> // AVPN (upstream nodes)
#include "IosStatusRequest.h"
#include "IosNativePolicy.h"

#ifdef __OBJC__
    #import <Foundation/Foundation.h>
@class NETunnelProviderManager;
#endif

using namespace amnezia;

struct Action
{
    static const char *start;
    static const char *restart;
    static const char *stop;
    static const char *getTunnelId;
    static const char *getStatus;
    static const char *rebind; // AVPN BUG-4 auto-heal: wgSetConfig listen_port=0 в живом NE
};

struct MessageKey
{
    static const char *action;
    static const char *tunnelId;
    static const char *config;
    static const char *errorCode;
    static const char *host;
    static const char *port;
    static const char *isOnDemand;
    static const char *SplitTunnelType;
    static const char *SplitTunnelSites;
};

class IosController : public QObject
{
    Q_OBJECT

public:
    static IosController *Instance();

    virtual ~IosController() override = default;

    bool initialize();
    bool connectVpn(amnezia::Proto proto, const QJsonObject &configuration);
    void disconnectVpn();

    void vpnStatusDidChange(void *pNotification);
    
    void vpnConfigurationDidChange(void *pNotification);

    void getBackendLogs(std::function<void(const QString &)> &&callback);
    void checkStatus();
    // AVPN (iOS data watch, build 141; the facade calls these only under Q_OS_IOS and the flags).
    // requestStatusSnapshot: one consistent snapshot through the status path - replies of requests sent
    // before this call are no longer applied (IosStatusRequest::invalidate), then checkStatus(). The
    // first reply applied after it arrives as tunnelWatchSnapshot, once; without a request the signal
    // is never emitted. writeTunnelWatchPlanFile: TribeWatchPlan.json in the App
    // Group, atomic, protected until the first unlock (contract C1); false = not written.
    // noteAppBackground: the On-Demand arming after leaving the screen (§5.5 step 1,
    // features.ios_on_demand_bg_arm; decision IosBackgroundArm.h) - events arrive as onDemandBackgroundEvent.
    void requestStatusSnapshot();
    bool writeTunnelWatchPlanFile(const QByteArray &json);
    void noteAppBackground(bool bgArmFlag, int maxHoldMs);
    // The macOS harness has no UIKit: it says here whether the app is on the screen.
    void setAppActiveProbe(std::function<bool()> probe) { m_appActiveProbe = std::move(probe); }
    // AVPN (review of 136): the facade provides the physical uplink state (UplinkMonitor).
    void setUplinkProbe(std::function<bool()> probe) { m_uplinkProbe = std::move(probe); }
#ifdef AVPN_IOS_HARNESS
    void setRawConfigForTest(const QJsonObject &config) { m_rawConfig = config; }
#endif
    void requestReconcileStatus();
    QVariantMap sessionMetadata() const;


    // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета ЖИВОГО NE-туннеля — provider message
    // {"action":"rebind"} (extension зовёт wgSetConfig listen_port=0 → BindUpdate → новый
    // локальный порт = новый 5-tuple flow, лечит сессионный блок ТСПУ).
    // true = сообщение отправляется живому туннелю; итог (K4) — сигнал rebindFinished(bool).
    // false = отправлять некому (нет менеджера / туннель не Connected), сигнала не будет.
    bool rebindTunnel();

    // AVPN (upstream nodes, contract client-envelope-contract.md; the engine lane calls these).
    // setUpstreamStart: arms the NEXT connectVpn of an upstream node - right before the connect,
    // from any thread. connectVpn takes it only when start.nodeId equals the configuration's
    // tribeSessionMetadata.node_id and the protocol is Xray; any other connect drops it. The start
    // envelope then carries tribeSessionMetadata {node_id, proto:"xray", upstream:1, profile_id,
    // config_sha256} and, when start.hasLease, upstream_lease (section 1). An invalid struct is
    // refused (logged by field name) and returns false.
    bool setUpstreamStart(const avpn_ios::UpstreamStartEnvelope &start);
    void clearUpstreamStart();
    // Provisional start hand-over (section 2): app message upstream_lease_set to the live extension.
    // true = sent; the reply arrives as upstreamLeaseEvent. false = invalid lease or no live tunnel.
    bool sendUpstreamLeaseSet(const avpn_ios::UpstreamLeaseEnvelope &lease);

    // AVPN (Scanner, plan scanner-client-plan.md §2.3, lane L4; caller: serviceEngine/IosScanHost.mm). One
    // tribe-scan-v1 message to the live extension (PacketTunnelProvider+Scan.swift), the bytes as they are and the
    // reply bytes as they come. `done` exactly once, on this controller's thread, never from inside the call:
    // Reply + bytes | NeedsVpn - no running extension (no profile, not Connected/Reasserting) | NoReply - no
    // answer (send error, nil reply) | Timeout - nothing within timeoutMs (200..10000). Never touches the tunnel.
    enum class ScanSendResult { Reply, NeedsVpn, NoReply, Timeout };
    void sendScanMessage(const QByteArray &message, int timeoutMs,
                         std::function<void(ScanSendResult, const QByteArray &)> done);
    bool scanHostRunning(); // the extension runs (Connected/Reasserting): the scan host can answer
    // AVPN (path engine, device round 19.11): the tunnel this process started last - 0 none (no start of this process:
    // only the extension can tell the live peer), 1 not AmneziaWG, 2 AmneziaWG with `peer` (the awg_live_peer object,
    // IosAppScanHost.h::iosAwgLivePeerJson). Any thread.
    int ownStartLivePeer(QJsonObject *peer) const;

    bool shareText(const QStringList &filesToSend);
    QString openFile();

    // Store-specific purchase failure reasons; values match StoreKit2Helper error codes
    enum class StorePurchaseFailure {
        Other,
        Cancelled,
        Pending
    };

    void purchaseProduct(const QString &productId,
                         std::function<void(bool success,
                                            const QString &transactionId,
                                            const QString &purchasedProductId,
                                            const QString &originalTransactionId,
                                            const QString &storeEnvironment,
                                            const QString &errorString,
                                            StorePurchaseFailure failureReason)> &&callback);

    // Finish a StoreKit transaction after the gateway has validated the purchase
    void finishStoreTransaction(const QString &transactionId);

    // Start listening to StoreKit transaction updates; each verified transaction is
    // reported once per session via the storeTransactionUpdated signal
    void startStoreTransactionObserver();

    void restorePurchases(std::function<void(bool success,
                                             const QList<QVariantMap> &transactions,
                                             const QString &errorString)> &&callback);

    void fetchLocalEntitlements(std::function<void(bool success,
                                                    const QList<QVariantMap> &transactions,
                                                    const QString &errorString)> &&callback);

    // Fetch product info for given product identifiers and return basic fields for logging
    void fetchProducts(const QStringList &productIds,
                       std::function<void(const QList<QVariantMap> &products,
                                          const QStringList &invalidIds,
                                          const QString &errorString)> &&callback);

    void requestInetAccess();
    bool isTestFlight();

signals:
    void sessionMetadataChanged(const QVariantMap &metadata);
    // AVPN (iOS data watch, build 141, contract C2): every applied status reply, after its session
    // metadata was taken: {"session": <session_metadata of the reply>, "watch": <the extension's `watch`
    // object, only when the reply has one>}. A build 139 extension has no `watch` key.
    void tunnelWatchSnapshot(const QVariantMap &snapshot);
    // AVPN (iOS data watch, build 141, stage 2): the status reply said `engine_down` - a failed in-place
    // switch left the tunnel without an engine (the extension keeps retrying). Emitted for every such
    // reply; the facade restarts the tunnel by its ordinary restart, once.
    void tunnelEngineDown();
    // AVPN (iOS data watch, build 141): journal lines of the On-Demand arming in the background
    // (on_demand_state ..., on_demand_bg_arm result=...); the facade writes them to the tester journal.
    void onDemandBackgroundEvent(const QString &line);
    void disconnectReason(const QString &reason, bool intentional);
    void connectionStateChanged(Vpn::ConnectionState state);
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    // AVPN: возраст WG-хендшейка (unix sec, 0 = нет/неизвестно) — для DEAD-детекта serviceEngine
    // (HealthLoop). Значение уже парсится в checkStatus из UAPI last_handshake_time_sec; здесь лишь
    // отдаём его наружу (раньше использовалось только для подтверждения коннекта). См. VpnConnectionTunnelControl.
    void handshakeChanged(qint64 lastHandshakeEpochSec);
    // AVPN (awg-apple tribe.16, device round 24.11 B1): the extension's `data_quiet_s` - seconds since inbound DATA
    // last proved the path (no handshake bytes, no echo of a repair step); -1 = the reply has none (an extension
    // before tribe.16, an Xray session, a stale watchdog). Feeds the AmneziaWG probe failover (HealthLoop).
    void dataQuietChanged(qint64 seconds);
    // AVPN (floor 19.11): the awaited AmneziaWG handshake was seen - awaitedMs from the NE's Connected to this
    // status reply (the stage between "extension Connected" and the app's Connected; journal ios_handshake_seen).
    void handshakeConfirmed(qint64 awaitedMs);
    // AVPN (девайс-разбор 2026-09-02): текст причины, по которой ядро Xray не поднялось в NE.
    // Слушает VpnConnectionTunnelControl → лог + диагностика; без него отказ был безымянным.
    void xrayStartFailed(const QString &reason);
    void importConfigFromOutside(const QString);
    void importBackupFromOutside(const QString);
    void storeTransactionUpdated(const QVariantMap &transaction);
    // AVPN (контракт K3, фикс-волна 2026-09-22): connectVpn застал СВОЙ живой профиль
    // (Connected/Connecting/Reasserting, поднятый Настройками/Shortcuts/Intent или прошлым
    // запуском). Натив НЕ эмитит Error и не стартует поверх: снимает m_connectPending,
    // восстанавливает sessionMetadata и эмитит этот сигнал ПЕРЕД пересылкой реального статуса.
    // Фасад отменяет свой Op::Starting и адоптирует следующий Connected (identity — sessionMetadata()).
    // Профиль в Disconnecting живым НЕ считается (ревью REV-2): сигнала нет, натив молча ждёт
    // реальный Disconnected (в пределах дедлайна коннекта) и продолжает обычный старт; фасад всё
    // это время остаётся в своём Op::Starting. Если за ожидание профиль снова поднялся (Настройки),
    // это уже живая сессия — liveSessionFound.
    void liveSessionFound();
    // AVPN (контракт K4): итог provider message {"action":"rebind"}. performed=true — NE ответил
    // {"rebind":"performed"}; false — {"rebind":"denied",...}, нет живого туннеля, ошибка отправки
    // или ответ не пришёл за 3 с. Эмитится ровно один раз на каждый вызов rebindTunnel(), вернувший
    // true (при false-возврате сигнала нет: вызывающий уже знает, что rebind не отправлен).
    // Ревью REV-5: итог вызова, который перекрыт более новым rebindTunnel(), не эмитится —
    // запоздалый false прошлого шага не закрывает ожидание нового.
    void rebindFinished(bool performed);
    // AVPN (C4): true — натив создаёт НОВЫЙ профиль и ждёт completion saveToPreferences (на первом
    // запуске iOS показывает системный диалог «Разрешить VPN»); дедлайн коннекта в это время не
    // тикает (потолок NativeTimings::permissionPromptCapMs). false — ожидание закончилось
    // (сохранили/ошибка/отмена). ОБЯЗАТЕЛЕН для фасада (ревью REV-1): пока true, его сторож старта
    // не должен звать down() — disconnectVpn сменит поколение операции, и поздний save отбросится.
    void permissionPromptPending(bool pending);

    void finished();

    // AVPN (upstream nodes, contract section 5): the extension's `upstream` status object, normalized
    // (IosNativePolicy.h::normalizeUpstreamStatus), keys exactly as the contract: state, code, seq,
    // renewed_ms_ago, expires_in_ms, revision, config_changed, applied_bytes, shadow_bytes, meter_scope.
    // Emitted when state/code/seq/revision/config_changed/meter_scope change (status polls) and on
    // every upstream_lease_set reply. The engine lane connects it (terminal -> leave the node through
    // the dead-session path; newer revision -> refresh /v1/subscription).
    void upstreamLeaseEvent(const QVariantMap &upstream);

protected slots:

private:
    explicit IosController();

    bool setupOpenVPN();
    bool setupWireGuard();
    bool setupAwg();
    bool setupXray();
    bool setupSSXray();

    bool startOpenVPN(const QString &config);
    bool startWireGuard(const QString &jsonConfig);
    bool startXray(const QString &jsonConfig);

    void startTunnel();
    bool configureSelectedTunnel();
    bool operationCurrent(uint64_t generation) const;

    void emitConnectionStateIfChanged(Vpn::ConnectionState state);
    // AVPN (C1): терминал напрямую, минуя дедуп m_lastEmittedState — движок, стоящий в
    // Disconnecting после disconnectVpn, обязан получить ответ, даже если прошлый эмит был тем же.
    void emitConnectionStateForced(Vpn::ConnectionState state);
    // AVPN (C1): реконсил с ограниченными повторами вместо синтетического Error.
    void scheduleReconcileLoad(int attempt);
    void retryReconcileLater(uint64_t request, int attempt);
    // AVPN (C1): поиск профиля для стопа, когда менеджер ещё не известен (с повторами).
    void discoverTunnelToStop(uint64_t operation, int attempt);
    // AVPN (C2/K2): единственная точка эмиссии disconnectReason (не более раза на переход).
    void emitDisconnectReason(const QString &reason, bool intentional);
    void reportDisconnected();
    void noteAppStopForCurrentSession();
    void noteSessionRuntimeEnded();
    // AVPN (ревью REV-3): флаг стопа приложения привязан к сессии; снимаем при доказательстве новой.
    void markLocalStopRequested();
    void clearLocalStopIfNewSession(bool observedConnecting);
    // On-Demand (2026-09-30): правило взводится для сессии с подтверждённым рукопожатием и
    // снимается перед любым стопом приложения (см. IosNativePolicy.h).
    void armOnDemandForConfirmedSession();
    void stopTunnelHonoringOnDemand(avpn_ios::OnDemandStop mode);
    // AVPN (ревью REV-2): connectVpn застал свой профиль в Disconnecting — ждём терминал.
    enum class TeardownStep { NotAwaiting, Waiting, StartContinued, LiveFound };
    void beginAwaitTeardown(uint64_t operation);
    void recheckTeardown(uint64_t operation);
    TeardownStep continueConnectAfterTeardown();
    // AVPN (C4): дедлайн фазы коннекта; повторный вызов перевзводит (старый таймер гаснет).
    void armConnectDeadline(uint64_t operation, int ms);
    void setPermissionPromptPending(bool pending);

private:
    void *m_iosControllerWrapper {};
#ifdef __OBJC__
    // AVPN (краш-фикс UAF): файл MRC (без ARC) — менеджером ВЛАДЕЕМ через setCurrentTunnel
    // (retain/release), напрямую m_currentTunnel не присваивать. Менеджеры из loadAllFromPreferences
    // autoreleased; без retain указатель повисал после долгого фона → SIGSEGV в checkStatus.
    NETunnelProviderManager *m_currentTunnel {};
    void setCurrentTunnel(NETunnelProviderManager *tunnel);
    // AVPN (ревью 2026-07-11, гонка MRC): checkStatus работает с менеджером на ФОНОВОЙ очереди,
    // а setCurrentTunnel(nil) при быстром реконнекте может параллельно сделать release на главном
    // треде → UAF (класс краша AmneziaVPN-2026-07-06). Фоновые читатели берут менеджер ТОЛЬКО через
    // retainedCurrentTunnel() (retain под локом; caller обязан release), ivar напрямую не читать.
    NETunnelProviderManager *retainedCurrentTunnel();
    NETunnelProviderManager *selectOurManager(NSArray<NETunnelProviderManager *> *managers);
    void restoreSessionMetadata(NETunnelProviderManager *manager);
    NSDictionary *providerMetadata();

    NSString *m_serverAddress {};
    bool isOurManager(NETunnelProviderManager *manager);
    void sendVpnExtensionMessage(NETunnelProviderManager *tunnel, NSDictionary *message,
                                 std::function<void(NSDictionary *)> callback = nullptr);
#else
    // AVPN (crash 5.1.110, SIGSEGV in setUplinkProbe): the same storage in C++ translation units.
    // Without it every member below sat 16 bytes earlier in a .cpp than in ios_controller.mm, so an
    // inline member access compiled in a .cpp (setUplinkProbe from AvpnEngineQml.cpp) wrote into
    // other members and destroyed garbage as the "old" std::function. Order and size must match the
    // two Objective-C pointers above (MRC: plain pointers); check: tests/run_ios_reliability_checks.sh.
    void *m_currentTunnelStorage {};
    void *m_serverAddressStorage {};
#endif

    // AVPN (path engine): ownStartLivePeer, written by connectVpn. Plain C++ members live OUTSIDE the __OBJC__ block
    // above, so the class has one layout in every translation unit (the harness checks sizeof from a C++ unit).
    mutable std::mutex m_ownPeerLock;
    int m_ownPeerKind = 0;
    QJsonObject m_ownPeer;

    amnezia::Proto m_proto = amnezia::Proto::Awg;   // AVPN: дефолт до connectVpn (AWG-only продукт; иначе uninit enum)
    QJsonObject m_rawConfig;
    QString m_tunnelId;
    uint64_t m_txBytes = 0;
    uint64_t m_rxBytes = 0;
    bool m_handshakeAwaiting = false;
    bool m_handshakeConfirmed = false;
    // AVPN (owner test 06.11): the cold-start rule (showEstablishedAsConnected) showed this session
    // Connected before any handshake check - it is adopted, not our start of this process.
    bool m_shownConnectedBeforeHandshake = false;
    // AVPN (review of 136): "a physical network path exists" - set by the facade (UplinkMonitor);
    // unset = unknown = no stop of a dead adopted session.
    std::function<bool()> m_uplinkProbe;
    QElapsedTimer m_handshakeTimer;
    int m_handshakeTimeouts = 0;
    Vpn::ConnectionState m_lastEmittedState = Vpn::ConnectionState::Unknown;
    IosStatusRequest m_statusRequests;
    std::atomic<uint64_t> m_operationGeneration { 0 };
    uint64_t m_reconcileGeneration = 0;
    bool m_connectPending = false;
    bool m_reconcileScheduled = false;
    bool m_localStopRequested = false;
    avpn_ios::LocalStopInfo m_localStopInfo;        // AVPN (REV-3): чью сессию гасили
    uint64_t m_connectAwaitingTeardown = 0;         // AVPN (REV-2): операция ждёт Disconnected
    bool m_onDemandArmed = false;                   // On-Demand: этот процесс взвёл правило
    bool m_onDemandChangePending = false;           // On-Demand: идёт load/save взвода
    uint64_t m_onDemandArmToken = 0;                // On-Demand: поколение попытки взвода (дедлайн)
    int m_onDemandDisarmsInFlight = 0;              // On-Demand: снятий правила в полёте
    avpn_ios::DisconnectReasonGate m_disconnectGate; // AVPN (K2)
    uint64_t m_connectDeadlineToken = 0;            // AVPN (C4)
    bool m_creatingProfile = false;                 // AVPN (C4): ждём save нового профиля
    bool m_permissionPromptPending = false;         // AVPN (C4)
    QString m_operationIntentGeneration;
    QVariantMap m_sessionMetadata;
    // AVPN (ревью CL-C REV-4): runtime-метаданные в m_sessionMetadata принадлежат сессии, которая
    // уже закончилась (наблюдали её Disconnected). restoreSessionMetadata их не переносит на новый
    // запуск того же профиля; снимается первым принятым status-ответом новой сессии.
    bool m_sessionRuntimeEnded = false;
    uint64_t m_rebindSeq = 0; // AVPN (REV-5): итог только последнего rebindTunnel()
    // AVPN (iOS data watch, build 141): the On-Demand arming in the background (IosBackgroundArm.h) - the
    // hold of background time (reason OnDemandArm), when it began and its bound; judged on the status poll.
    std::atomic<bool> m_watchSnapshotWanted { false }; // set by requestStatusSnapshot, cleared by the reply that answers it
    bool m_bgArmHeld = false;
    long long m_bgArmSinceMs = 0;
    int m_bgArmMaxMs = 0;
    uint64_t m_bgArmToken = 0;
    void tickBackgroundArmHold();
    void endBackgroundArmHold(const char *result, const char *why);
    bool appIsActive() const;
    std::function<bool()> m_appActiveProbe;

    QString m_lastRoamSummary; // AVPN seamless roaming: последняя строка счётчиков NE (лог при изменении)
    QString m_lastAdoptedDeadCheck; // AVPN 5.1.109 (IOS-UP35): last journaled §25 decision inputs (log on change)
    // AVPN (девайс-разбор 2026-09-02): последняя доставленная причина отказа ядра Xray и хвост его
    // лога — чтобы одну и ту же строку не эмитить/не писать в лог на каждом опросе статуса.
    QString m_lastXrayStartFailure;
    QString m_lastXrayCoreLogTail;
    QString m_lastXrayDataPlaneDiag;
    // AVPN (ревью 2026-07-11): поколение сессии — стейл-ответ checkStatus СТАРОЙ сессии,
    // долетевший после реконнекта, не должен трогать счётчики/статусы новой (underflow-дельта).
    std::atomic<uint64_t> m_statusGeneration { 0 };
    // AVPN (upstream nodes): armed by setUpstreamStart (any thread), taken by connectVpn.
    std::mutex m_upstreamStartLock;
    std::optional<avpn_ios::UpstreamStartEnvelope> m_upstreamStartArmed;
    std::optional<avpn_ios::UpstreamStartEnvelope> m_upstreamStart; // the current connect's
    avpn_ios::UpstreamStatusFields m_lastUpstreamStatus;
    void emitUpstreamStatus(const avpn_ios::UpstreamStatusFields &fields, bool always);
};

#endif // IOS_CONTROLLER_H

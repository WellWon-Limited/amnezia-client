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
    void requestReconcileStatus();
    QVariantMap sessionMetadata() const;


    // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета ЖИВОГО NE-туннеля — provider message
    // {"action":"rebind"} (extension зовёт wgSetConfig listen_port=0 → BindUpdate → новый
    // локальный порт = новый 5-tuple flow, лечит сессионный блок ТСПУ).
    // true = сообщение отправляется живому туннелю; итог (K4) — сигнал rebindFinished(bool).
    // false = отправлять некому (нет менеджера / туннель не Connected), сигнала не будет.
    bool rebindTunnel();

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
    void disconnectReason(const QString &reason, bool intentional);
    void connectionStateChanged(Vpn::ConnectionState state);
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    // AVPN: возраст WG-хендшейка (unix sec, 0 = нет/неизвестно) — для DEAD-детекта serviceEngine
    // (HealthLoop). Значение уже парсится в checkStatus из UAPI last_handshake_time_sec; здесь лишь
    // отдаём его наружу (раньше использовалось только для подтверждения коннекта). См. VpnConnectionTunnelControl.
    void handshakeChanged(qint64 lastHandshakeEpochSec);
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
#endif

    amnezia::Proto m_proto = amnezia::Proto::Awg;   // AVPN: дефолт до connectVpn (AWG-only продукт; иначе uninit enum)
    QJsonObject m_rawConfig;
    QString m_tunnelId;
    uint64_t m_txBytes = 0;
    uint64_t m_rxBytes = 0;
    bool m_handshakeAwaiting = false;
    bool m_handshakeConfirmed = false;
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

    QString m_lastRoamSummary; // AVPN seamless roaming: последняя строка счётчиков NE (лог при изменении)
    // AVPN (девайс-разбор 2026-09-02): последняя доставленная причина отказа ядра Xray и хвост его
    // лога — чтобы одну и ту же строку не эмитить/не писать в лог на каждом опросе статуса.
    QString m_lastXrayStartFailure;
    QString m_lastXrayCoreLogTail;
    QString m_lastXrayDataPlaneDiag;
    // AVPN (ревью 2026-07-11): поколение сессии — стейл-ответ checkStatus СТАРОЙ сессии,
    // долетевший после реконнекта, не должен трогать счётчики/статусы новой (underflow-дельта).
    std::atomic<uint64_t> m_statusGeneration { 0 };
};

#endif // IOS_CONTROLLER_H

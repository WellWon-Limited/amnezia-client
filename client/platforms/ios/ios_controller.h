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

    // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета ЖИВОГО NE-туннеля — provider message
    // {"action":"rebind"} (extension зовёт wgSetConfig listen_port=0 → BindUpdate → новый
    // локальный порт = новый 5-tuple flow, лечит сессионный блок ТСПУ). Fire-and-forget:
    // true = сообщение отправлено живому туннелю, итог меряет HealthLoop по rx/handshake.
    bool rebindTunnel();

    bool shareText(const QStringList &filesToSend);
    QString openFile();

    void purchaseProduct(const QString &productId,
                         std::function<void(bool success,
                                            const QString &transactionId,
                                            const QString &purchasedProductId,
                                            const QString &originalTransactionId,
                                            const QString &errorString)> &&callback);
    void restorePurchases(std::function<void(bool success,
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
    void connectionStateChanged(Vpn::ConnectionState state);
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    // AVPN: возраст WG-хендшейка (unix sec, 0 = нет/неизвестно) — для DEAD-детекта serviceEngine
    // (HealthLoop). Значение уже парсится в checkStatus из UAPI last_handshake_time_sec; здесь лишь
    // отдаём его наружу (раньше использовалось только для подтверждения коннекта). См. VpnConnectionTunnelControl.
    void handshakeChanged(qint64 lastHandshakeEpochSec);
    void importConfigFromOutside(const QString);
    void importBackupFromOutside(const QString);

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
    void emitConnectionStateIfChanged(Vpn::ConnectionState state);

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
    std::atomic_bool m_statusRequestInFlight { false };
    // AVPN (ревью 2026-07-11): поколение сессии — стейл-ответ checkStatus СТАРОЙ сессии,
    // долетевший после реконнекта, не должен трогать счётчики/статусы новой (underflow-дельта).
    std::atomic<uint64_t> m_statusGeneration { 0 };
};

#endif // IOS_CONTROLLER_H

#ifndef ANDROID_CONTROLLER_H
#define ANDROID_CONTROLLER_H

#include <QJniObject>
#include <QPixmap>

#include <QVariantMap> // AVPN (android2 P7)
#include <atomic> // AVPN (android2 V2)

#include "core/protocols/vpnProtocol.h"
#include "core/serviceEngine/UpstreamStatusWire.h" // AVPN (upstream nodes, release C): status of the Xray service

using namespace amnezia;

class AndroidController : public QObject
{
    Q_OBJECT

public:
    // AVPN (android2 V2): the Kotlin half reports its builds (onTunnelBuild registered by initialize()).
    static bool reportsTunnelBuild() { return s_reportsTunnelBuild.load(); }
    explicit AndroidController();
    static AndroidController *instance();

    bool initialize();

    // keep synchronized with org.amnezia.vpn.protocol.ProtocolState
    enum class ConnectionState
    {
        DISCONNECTED,
        CONNECTED,
        CONNECTING,
        DISCONNECTING,
        RECONNECTING,
        UNKNOWN
    };

    ErrorCode start(const QJsonObject &vpnConfig);
    void stop();
    void resetLastServer(int serverIndex);
    void saveFile(const QString &fileName, const QString &data);
    QString openFile(const QString &filter);
    int getFd(const QString &fileName);
    void closeFd();
    QString getFileName(const QString &uri);
    bool isCameraPresent();
    bool isOnTv();
    bool isEdgeToEdgeEnabled();
    int getStatusBarHeight();
    int getNavigationBarHeight();
    void startQrReaderActivity();
    void setSaveLogs(bool enabled);
    void exportLogsFile(const QString &fileName);
    void clearLogs();
    void setScreenshotsEnabled(bool enabled);
    void setNavigationBarColor(unsigned int color);
    void minimizeApp();
    QJsonArray getAppList();
    QPixmap getAppIcon(const QString &package, QSize *size, const QSize &requestedSize);
    bool isNotificationPermissionGranted();
    void requestNotificationPermission();
    bool requestAuthentication();
    void sendTouch(float x, float y);
    bool isPlay();
    QJsonObject getSubscriptionPlans();
    QJsonObject purchaseSubscription(const QString &offerToken);
    QJsonObject upgradeSubscription(const QString &offerToken, const QString &oldPurchaseToken);
    QJsonObject acknowledgePurchase(const QString &purchaseToken);
    QJsonObject queryPurchases();
    // AVPN (upstream nodes, release C): the late lease hand-over to the Xray service process, which owns the
    // lease from then on (android-ipc-contract.md §2). message = {"action":"upstream_lease_set",
    // "upstream_lease":{...}} - secret, never logged. true = the activity handed it to the bound service;
    // false = no activity, no bound service, or the Kotlin half is missing (the seat lapses at TTL).
    bool sendUpstreamLeaseSet(const QByteArray &message);
    // AVPN (Scanner, lane A3): one tribe-scan-v1 message to the Xray service's probe host (activity
    // scanMessage(id, request) -> Action.SCAN_MESSAGE). The reply comes as scanReplyReceived with the same id.
    // request = secret (scan token, configs), never logged. true = handed to the bound service.
    bool sendScanMessage(qint64 id, const QByteArray &request);

    static bool initLogging();
    static void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message);

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void status(ConnectionState state);
    void serviceDisconnected();
    void serviceError();
    void vpnPermissionRejected();
    // AVPN (Android permission prompt): the system's "allow VPN configuration" dialog. 0 = on screen (pending),
    // 1 = closed, granted, 2 = closed, denied or cancelled. The engine pauses its clock while 0 (the same rule as
    // IosController::permissionPromptPending) and ends the attempt on 2. Optional native: see initialize().
    void vpnPermissionPrompt(int state);
    // AVPN (local build, emulator round 20.11): the VPN service builds the tunnel interface of a start (state 0, from
    // the start command) or has built it (state 1: VpnService.Builder.establish() returned and the backend runs), or
    // the start ended without a tunnel (state 2, android2 V2). `seq` numbers the service's starts: a "built" belongs to
    // the "building" with the same number; `leg` is the engine leg the start config named (tribeStartLeg, 0 = none). The
    // engine's leg is local until its own "built" (AttemptOwner.h "Local build"). Optional native.
    void tunnelBuild(int state, int seq, quint64 leg);
    // AVPN (android2 P7): the tribeSessionMetadata {node_id, proto, endpoint, ...} of the session the service runs
    // (empty: none), emitted before the status() / vpnStateChanged() it came with. Optional native.
    void sessionMetadata(const QVariantMap &metadata);
    void notificationStateChanged();
    void vpnStateChanged(ConnectionState state);
    void statisticsUpdated(quint64 rxBytes, quint64 txBytes);
    // AVPN: возраст WG-хендшейка (unix sec, 0 = нет/неизвестно) — для DEAD-детекта serviceEngine.
    void handshakeUpdated(qint64 lastHandshakeEpochSec);
    void fileOpened(QString uri);
    void configImported(QString config);
    void importConfigFromOutside(QString config);
    void initConnectionState(Vpn::ConnectionState state);
    void authenticationResult(bool result);
    void imeInsetsChanged(int heightDp);
    void systemBarsInsetsChanged(int navBarHeightDp, int statusBarHeightDp);
    void activityPaused();
    void activityResumed();
    // AVPN (upstream nodes, release C): the Xray service's lease status (contract §5, android-ipc-contract.md
    // §3), normalized, emitted only when something the engine acts on changed - the same map as
    // IosController::upstreamLeaseEvent (AvpnEngineQml::applyUpstreamTunnelStatus).
    void upstreamLeaseEvent(const QVariantMap &upstream);
    // AVPN: the raw JNI event (Android thread) -> decoded on the controller's thread.
    void upstreamStatusReceived(const QByteArray &json);
    // AVPN (Scanner, lane A3): emitted on the activity's thread (connect queued): the probe host's reply to request
    // `id`, and its state {"open":bool,"gen":{...}} (ServiceEvent.SCAN_REPLY / SCAN_HOST_STATE).
    void scanReplyReceived(qint64 id, const QByteArray &reply);
    void scanHostStateReceived(const QByteArray &json);

private:
    bool isWaitingStatus = true;
    avpn::UpstreamTunnelStatus m_lastUpstreamStatus; // AVPN (release C): the controller's thread only
    void applyUpstreamStatusEvent(const QByteArray &json); // AVPN (release C)
    void resetUpstreamStatus(); // AVPN (release C): a new session starts from "nothing seen"
    static inline std::atomic<bool> s_reportsTunnelBuild{false}; // AVPN (android2 V2): reportsTunnelBuild()

    static jclass log;
    static jmethodID logDebug;
    static jmethodID logInfo;
    static jmethodID logWarning;
    static jmethodID logError;
    static jmethodID logFatal;

    void qtAndroidControllerInitialized();

    static Vpn::ConnectionState convertState(ConnectionState state);
    static QString textConnectionState(ConnectionState state);

    // JNI functions called by Android
    static void onStatus(JNIEnv *env, jobject thiz, jint stateCode);
    static void onServiceDisconnected(JNIEnv *env, jobject thiz);
    static void onServiceError(JNIEnv *env, jobject thiz);
    static void onVpnPermissionRejected(JNIEnv *env, jobject thiz);
    static void onVpnPermissionPrompt(JNIEnv *env, jobject thiz, jint state); // AVPN, optional native
    static void onTunnelBuild(JNIEnv *env, jobject thiz, jint state, jint seq, jlong leg); // AVPN, optional native
    static void onSessionMetadata(JNIEnv *env, jobject thiz, jstring json); // AVPN (android2 P7), optional native
    static void onNotificationStateChanged(JNIEnv *env, jobject thiz);
    static void onVpnStateChanged(JNIEnv *env, jobject thiz, jint stateCode);
    static void onStatisticsUpdate(JNIEnv *env, jobject thiz, jlong rxBytes, jlong txBytes,
                                   jlong lastHandshakeSec); // AVPN: + handshake (JNI (JJJ)V)
    static void onConfigImported(JNIEnv *env, jobject thiz, jstring data);
    static void onFileOpened(JNIEnv *env, jobject thiz, jstring uri);
    static void onAuthResult(JNIEnv *env, jobject thiz, jboolean result);
    static bool decodeQrCode(JNIEnv *env, jobject thiz, jstring data);
    static void onImeInsetsChanged(JNIEnv *env, jobject thiz, jint heightDp);
    static void onSystemBarsInsetsChanged(JNIEnv *env, jobject thiz, jint navBarHeightDp, jint statusBarHeightDp);
    static void onActivityPaused(JNIEnv *env, jobject thiz);
    static void onActivityResumed(JNIEnv *env, jobject thiz);
    static void onUpstreamStatus(JNIEnv *env, jobject thiz, jstring json); // AVPN (release C), optional native
    static void onScanReply(JNIEnv *env, jobject thiz, jlong id, jstring reply); // AVPN (Scanner A3), optional
    static void onScanHostState(JNIEnv *env, jobject thiz, jstring json);        // AVPN (Scanner A3), optional

    template <typename Ret, typename ...Args>
    static auto callActivityMethod(const char *methodName, const char *signature, Args &&...args);
    template <typename ...Args>
    static void callActivityMethod(const char *methodName, const char *signature, Args &&...args);
};

#endif // ANDROID_CONTROLLER_H

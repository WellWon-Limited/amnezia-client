#ifndef ANDROID_CONTROLLER_H
#define ANDROID_CONTROLLER_H

#include <QJniObject>
#include <QJsonObject>
#include <QPixmap>

#include "core/protocols/vpnProtocol.h"

using namespace amnezia;

class AndroidController : public QObject
{
    Q_OBJECT

public:
    explicit AndroidController();
    static AndroidController *instance();

    bool initialize();
    // AVPN: validated schema-v1 facts for both embedded engines. Empty means
    // capability selection must fail closed.
    QJsonObject engineManifest() const { return m_engineManifest; }
    QJsonObject runtimeStatus() const { return m_runtimeStatus; }
    QString runtimeSessionId() const { return m_runtimeSessionId; }
    bool nativeGuardRecoveryPending() const { return m_guardRecoveryPending; }
    QJsonObject nativeGuardRecoveryEvent() const { return m_guardRecoveryEvent; }

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
    bool renewRuntimeAuthority(const QJsonObject &vpnConfig, const QString &operation,
                               const QString &session, const QString &outerSessionId,
                               const QString &expectedRuntimeSessionId,
                               const QString &renewalId,
                               const QString &authorityCommitmentHex);
    bool requestSessionGuardArm(const QJsonObject &vpnConfig, const QString &operation,
                                const QString &session, const QString &policyHashHex,
                                const QString &expectedRuntimeSessionId);
    bool activateNativeSession(const QJsonObject &vpnConfig, const QString &operation,
                               const QString &session, const QString &outerSessionId,
                               const QString &expectedRuntimeSessionId);
    bool stopNativeSession(const QString &outerSessionId,
                           const QString &expectedRuntimeSessionId);
    bool requestSessionGuardRelease(const QString &operation, const QString &session,
                                    const QString &outerSessionId);
    bool requestSessionGuardReconcileArm(
        const QString &operation, const QString &session, const QString &policyHashHex,
        const QString &expectedRuntimeSessionId);
    bool requestSessionGuardReconcileRelease(
        const QString &operation, const QString &session, const QString &policyHashHex,
        const QString &outerSessionId, const QString &expectedRuntimeSessionId);
    bool requestSessionGuardRecoveryResolution(const QJsonObject &exactRecoveryEvent,
                                               const QString &action,
                                               const QJsonObject &validatedConfiguration);
    void requestSessionGuardRecoveryStatus();
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

    void showUpdateCover();
    void hideUpdateCover();
    void showUpdatePrompt(const QString &title, const QString &message, const QString &updateTitle,
                          const QString &skipTitle, const QString &storeUrl);

    static bool initLogging();
    static void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message);

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void status(ConnectionState state);
    void serviceDisconnected();
    void serviceError();
    void vpnPermissionRejected();
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
    void engineManifestChanged(QJsonObject manifest);
    void runtimeStatusChanged(QJsonObject status);
    void sessionGuardEvent(QJsonObject event);
    void sessionGuardRecoveryRequired(QJsonObject event);
    void sessionGuardRecoveryResolved(QJsonObject receipt);
    void runtimeAuthorityRenewalReceipt(QJsonObject receipt);

private:
    bool isWaitingStatus = true;
    QJsonObject m_engineManifest;
    QJsonObject m_runtimeStatus;
    QString m_runtimeSessionId;
    QString m_runtimeServiceEpoch;
    quint64 m_runtimeSessionGeneration = 0;
    QString m_runtimeCounterEpoch;
    quint64 m_runtimeRawRx = 0;
    quint64 m_runtimeRawTx = 0;
    quint64 m_runtimeNormalizedRx = 0;
    quint64 m_runtimeNormalizedTx = 0;
    bool m_runtimeHasRawCounters = false;
    bool m_runtimeStopping = false;
    bool m_runtimeTerminal = false;
    // Catalog-v2 identity is allocated by the C++ reducer before PREPARE. Runtime status must
    // byte-match it; unlike the legacy epoch:generation token it is never learned from a callback.
    QString m_expectedCatalogRuntimeSessionId;
    QJsonObject m_pendingGuardRequest;
    QJsonObject m_armedGuardReceipt;
    QJsonObject m_pendingGuardReleaseRequest;
    QJsonObject m_pendingAuthorityRenewalRequest;
    bool m_guardRecoveryPending = false;
    bool m_guardRecoveryResolutionPending = false;
    QJsonObject m_guardRecoveryEvent;
    QString m_guardRecoveryAction;

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
    static void onNotificationStateChanged(JNIEnv *env, jobject thiz);
    static void onVpnStateChanged(JNIEnv *env, jobject thiz, jint stateCode);
    static void onStatisticsUpdate(JNIEnv *env, jobject thiz, jlong rxBytes, jlong txBytes,
                                   jlong lastHandshakeSec); // AVPN: + handshake (JNI (JJJ)V)
    static void onRuntimeStatus(JNIEnv *env, jobject thiz, jstring json); // AVPN: typed status v1.
    static void onEngineManifest(JNIEnv *env, jobject thiz, jstring json); // AVPN
    static void onSessionGuardEvent(JNIEnv *env, jobject thiz, jstring json);
    static void onSessionGuardRecoveryReceipt(JNIEnv *env, jobject thiz, jstring json);
    static void onRuntimeAuthorityRenewalReceipt(JNIEnv *env, jobject thiz, jstring json);
    static void onConfigImported(JNIEnv *env, jobject thiz, jstring data);
    static void onFileOpened(JNIEnv *env, jobject thiz, jstring uri);
    static void onAuthResult(JNIEnv *env, jobject thiz, jboolean result);
    static bool decodeQrCode(JNIEnv *env, jobject thiz, jstring data);
    static void onImeInsetsChanged(JNIEnv *env, jobject thiz, jint heightDp);
    static void onSystemBarsInsetsChanged(JNIEnv *env, jobject thiz, jint navBarHeightDp, jint statusBarHeightDp);
    static void onActivityPaused(JNIEnv *env, jobject thiz);
    static void onActivityResumed(JNIEnv *env, jobject thiz);

    void publishGuardChannelLoss();

    template <typename Ret, typename ...Args>
    static auto callActivityMethod(const char *methodName, const char *signature, Args &&...args);
    template <typename ...Args>
    static void callActivityMethod(const char *methodName, const char *signature, Args &&...args);
};

#endif // ANDROID_CONTROLLER_H

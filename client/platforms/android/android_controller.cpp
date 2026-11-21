#include <QJniEnvironment>
#include <QJsonDocument>
#include <QQmlFile>
#include <QEventLoop>
#include <QImage>

#include <android/bitmap.h>

#include "android_controller.h"
#include "android_utils.h"
#include "avpn_fcm_bridge.h" // AVPN (Task 9): FCM natives + запрос токена
#include "avpn_selfupdate_android.h" // AVPN (2026-11-16): site APK self-update natives
#include "ui/controllers/importUiController.h"

namespace
{
    AndroidController *s_instance = nullptr;

    constexpr auto QT_ANDROID_CONTROLLER_CLASS = "org/amnezia/vpn/qt/QtAndroidController";
    constexpr auto ANDROID_LOG_CLASS = "org/amnezia/vpn/util/Log";
    constexpr auto TAG = "AmneziaQt";
} // namespace

AndroidController::AndroidController() : QObject()
{
    connect(this, &AndroidController::status, this,
            [this](AndroidController::ConnectionState state) {
                qDebug() << "Android event: status =" << textConnectionState(state);
                if (isWaitingStatus) {
                    qDebug() << "Initialization by service status";
                    isWaitingStatus = false;
                    emit initConnectionState(convertState(state));
                }
            },
            Qt::QueuedConnection);

    connect(
        this, &AndroidController::serviceDisconnected, this,
        [this]() {
            qDebug() << "Android event: service disconnected";
            isWaitingStatus = true;
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::serviceError, this,
        [this]() {
            qDebug() << "Android event: service error";
            // todo: add error message
            emit connectionStateChanged(Vpn::ConnectionState::Error);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::vpnPermissionRejected, this,
        [this]() {
            qWarning() << "Android event: VPN permission rejected";
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::vpnStateChanged, this,
        [this](AndroidController::ConnectionState state) {
            qDebug() << "Android event: VPN state changed:" << textConnectionState(state);
            emit connectionStateChanged(convertState(state));
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::configImported, this,
        [this](const QString& config) {
            qDebug() << "Android event: config import";
            emit importConfigFromOutside(config);
        },
        Qt::QueuedConnection);

    // AVPN (upstream nodes, release C): the Xray service's lease status hops from the Android thread here.
    connect(this, &AndroidController::upstreamStatusReceived, this,
            [this](const QByteArray &json) { applyUpstreamStatusEvent(json); }, Qt::QueuedConnection);
}

AndroidController *AndroidController::instance()
{
    if (!s_instance) {
        s_instance = new AndroidController();
    }

    return s_instance;
}

bool AndroidController::initialize()
{
    qDebug() << "Initialize AndroidController";

    const JNINativeMethod methods[] = {
        {"onStatus", "(I)V", reinterpret_cast<void *>(onStatus)},
        {"onServiceDisconnected", "()V", reinterpret_cast<void *>(onServiceDisconnected)},
        {"onServiceError", "()V", reinterpret_cast<void *>(onServiceError)},
        {"onVpnPermissionRejected", "()V", reinterpret_cast<void *>(onVpnPermissionRejected)},
        {"onNotificationStateChanged", "()V", reinterpret_cast<void *>(onNotificationStateChanged)},
        {"onVpnStateChanged", "(I)V", reinterpret_cast<void *>(onVpnStateChanged)},
        {"onStatisticsUpdate", "(JJJ)V", reinterpret_cast<void *>(onStatisticsUpdate)}, // AVPN: +handshake long
        {"onFileOpened", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onFileOpened)},
        {"onConfigImported", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onConfigImported)},
        {"onAuthResult", "(Z)V", reinterpret_cast<void *>(onAuthResult)},
        {"decodeQrCode", "(Ljava/lang/String;)Z", reinterpret_cast<bool *>(decodeQrCode)},
        {"onImeInsetsChanged", "(I)V", reinterpret_cast<void *>(onImeInsetsChanged)},
        {"onSystemBarsInsetsChanged", "(II)V", reinterpret_cast<void *>(onSystemBarsInsetsChanged)},
        {"onActivityPaused", "()V", reinterpret_cast<void *>(onActivityPaused)},
        {"onActivityResumed", "()V", reinterpret_cast<void *>(onActivityResumed)}
    };

    QJniEnvironment env;
    bool registered = env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, methods,
                                                sizeof(methods) / sizeof(JNINativeMethod));
    if (!registered) {
        qCritical() << "Failed native method registration";
        return false;
    }
    // AVPN (upstream nodes, release C): registered on its own and optional - an APK whose Kotlin half does
    // not declare QtAndroidController.onUpstreamStatus yet must keep every other native (one failing entry
    // fails a whole RegisterNatives batch). Without it the app gets no lease status: upstream nodes stay off
    // there anyway (features.xray_client_android).
    {
        const JNINativeMethod upstreamMethods[] = {
            {"onUpstreamStatus", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onUpstreamStatus)},
        };
        if (!env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, upstreamMethods, 1)) {
            env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent);
            qWarning() << "AndroidController: no onUpstreamStatus in the Kotlin half - upstream lease status off";
        }
    }
    // AVPN (Android permission prompt): the permission dialog's state, optional the same way (the Kotlin side
    // guards the call; without it the engine simply does not pause for the dialog).
    {
        const JNINativeMethod promptMethods[] = {
            {"onVpnPermissionPrompt", "(I)V", reinterpret_cast<void *>(onVpnPermissionPrompt)},
        };
        if (!env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, promptMethods, 1)) {
            env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent);
            qWarning() << "AndroidController: no onVpnPermissionPrompt in the Kotlin half - no pause for the VPN dialog";
        }
    }
    // AVPN (local build): the service's own build of the tunnel interface, optional the same way (without it the
    // engine's leg clock runs through the build, as before).
    {
        const JNINativeMethod buildMethods[] = {
            {"onTunnelBuild", "(IIJ)V", reinterpret_cast<void *>(onTunnelBuild)},
        };
        if (!env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, buildMethods, 1)) {
            env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent);
            qWarning() << "AndroidController: no onTunnelBuild in the Kotlin half - the leg clock runs through the build";
        } else {
            s_reportsTunnelBuild.store(true); // android2 V2: the engine's legs are local until their own "built"
        }
    }
    // AVPN (Scanner, lane A3): the probe host's reply and state, optional the same way (without them the Scanner's
    // host stays NeedsVpn on Android: every scan ends «Не проверено» / NoScan host_no_vpn).
    {
        const JNINativeMethod scanMethods[] = {
            {"onScanReply", "(JLjava/lang/String;)V", reinterpret_cast<void *>(onScanReply)},
            {"onScanHostState", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onScanHostState)},
        };
        if (!env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, scanMethods, 2)) {
            env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent);
            qWarning() << "AndroidController: no scan natives in the Kotlin half - the Scanner's host is off";
        }
    }

    // AVPN (Task 9, FCM): natives пуш-сервиса + старт Kotlin-половины (см. avpn_fcm_bridge.cpp).
    // Неуспех НЕ валит контроллер: без Play Services пуши деградируют до поллинга чата.
    avpn::registerFcmNatives();
    avpn::registerSelfUpdateNatives(); // AVPN (2026-11-16): TribeSelfUpdate installer status
    qtAndroidControllerInitialized();
    return true;
}

// static
template <typename Ret, typename ...Args>
auto AndroidController::callActivityMethod(const char *methodName, const char *signature, Args &&...args)
{
    qDebug() << "Call activity method:" << methodName;
    QJniObject activity = AndroidUtils::getActivity();
    Q_ASSERT(activity.isValid());
    return activity.callMethod<Ret>(methodName, signature, std::forward<Args>(args)...);
}

// static
template <typename ...Args>
void AndroidController::callActivityMethod(const char *methodName, const char *signature, Args &&...args)
{
    callActivityMethod<void>(methodName, signature, std::forward<Args>(args)...);
}

ErrorCode AndroidController::start(const QJsonObject &vpnConfig)
{
    isWaitingStatus = false;
    resetUpstreamStatus(); // AVPN (release C): the status of the previous session is not this one's
    auto config = QJsonDocument(vpnConfig).toJson();
    callActivityMethod("start", "(Ljava/lang/String;)V",
                       QJniObject::fromString(config).object<jstring>());

    return ErrorCode::NoError;
}

void AndroidController::stop()
{
    callActivityMethod("stop", "()V");
}

// AVPN (upstream nodes, release C): android-ipc-contract.md §2. The message carries the renew token: only the
// method name is logged. A missing Kotlin method (NoSuchMethodError) is cleared and reads as "not sent".
bool AndroidController::sendUpstreamLeaseSet(const QByteArray &message)
{
    if (message.isEmpty())
        return false;
    QJniObject activity = AndroidUtils::getActivity();
    if (!activity.isValid())
        return false;
    const jboolean sent = activity.callMethod<jboolean>(
        "upstreamLeaseSet", "(Ljava/lang/String;)Z",
        QJniObject::fromString(QString::fromUtf8(message)).object<jstring>());
    QJniEnvironment env;
    if (env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent)) {
        qWarning() << "AndroidController::sendUpstreamLeaseSet : the activity has no upstreamLeaseSet";
        return false;
    }
    return sent;
}

// AVPN (Scanner, lane A3): the request carries the scan token and candidate configs - only the id is logged by the
// caller. A missing Kotlin method is cleared and reads as "not sent".
bool AndroidController::sendScanMessage(qint64 id, const QByteArray &request)
{
    if (request.isEmpty())
        return false;
    QJniObject activity = AndroidUtils::getActivity();
    if (!activity.isValid())
        return false;
    const jboolean sent = activity.callMethod<jboolean>(
        "scanMessage", "(JLjava/lang/String;)Z", jlong(id),
        QJniObject::fromString(QString::fromUtf8(request)).object<jstring>());
    QJniEnvironment env;
    if (env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent)) {
        qWarning() << "AndroidController::sendScanMessage : the activity has no scanMessage";
        return false;
    }
    return sent;
}

// AVPN (upstream nodes, release C): the controller's thread. The iOS bridge's rules (UpstreamStatusWire.h):
// normalized, emitted only when state, code, seq, revision, config_changed or the scope changed.
void AndroidController::applyUpstreamStatusEvent(const QByteArray &json)
{
    const avpn::UpstreamTunnelStatus next = avpn::decodeUpstreamStatusEvent(json);
    if (!next.present) {
        qWarning() << "AndroidController : upstream status event without an upstream object - ignored";
        return;
    }
    if (!avpn::upstreamTunnelStatusChanged(m_lastUpstreamStatus, next))
        return;
    if (next.state != m_lastUpstreamStatus.state || next.code != m_lastUpstreamStatus.code)
        qInfo() << "AndroidController : upstream lease" << next.state << next.code << "seq" << next.seq;
    m_lastUpstreamStatus = next;
    emit upstreamLeaseEvent(avpn::upstreamTunnelStatusMap(next));
}

void AndroidController::resetUpstreamStatus()
{
    // start() runs on the VpnConnection thread: the reset is queued to the controller's thread, ahead of any
    // status of the session being started (the service reports it only after it got the start).
    QMetaObject::invokeMethod(this, [this]() { m_lastUpstreamStatus = avpn::UpstreamTunnelStatus(); },
                              Qt::QueuedConnection);
}

void AndroidController::resetLastServer(int serverIndex)
{
    callActivityMethod("resetLastServer", "(I)V", serverIndex);
}

void AndroidController::saveFile(const QString &fileName, const QString &data)
{
    callActivityMethod("saveFile", "(Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(fileName).object<jstring>(),
                       QJniObject::fromString(data).object<jstring>());
}

QString AndroidController::openFile(const QString &filter)
{
    QEventLoop wait;
    QString fileName;
    connect(this, &AndroidController::fileOpened, this,
            [&fileName, &wait](const QString &uri) {
                fileName = uri;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("openFile", "(Ljava/lang/String;)V",
                       QJniObject::fromString(filter).object<jstring>());
    wait.exec();
    return fileName;
}

int AndroidController::getFd(const QString &fileName)
{
    return callActivityMethod<jint>("getFd", "(Ljava/lang/String;)I",
                                    QJniObject::fromString(fileName).object<jstring>());
}

void AndroidController::closeFd()
{
    callActivityMethod("closeFd", "()V");
}

QString AndroidController::getFileName(const QString &uri)
{
    auto fileName = callActivityMethod<jstring, jstring>("getFileName", "(Ljava/lang/String;)Ljava/lang/String;",
                                                         QJniObject::fromString(uri).object<jstring>());
    QJniEnvironment env;
    return AndroidUtils::convertJString(env.jniEnv(), fileName.object<jstring>());
}

bool AndroidController::isCameraPresent()
{
    return callActivityMethod<jboolean>("isCameraPresent", "()Z");
}

bool AndroidController::isOnTv()
{
    return callActivityMethod<jboolean>("isOnTv", "()Z");
}

bool AndroidController::isEdgeToEdgeEnabled()
{
    return callActivityMethod<jboolean>("isEdgeToEdgeEnabled", "()Z");
}

int AndroidController::getStatusBarHeight()
{
    return callActivityMethod<jint>("getStatusBarHeight", "()I");
}

int AndroidController::getNavigationBarHeight()
{
    return callActivityMethod<jint>("getNavigationBarHeight", "()I");
}

void AndroidController::startQrReaderActivity()
{
    callActivityMethod("startQrCodeReader", "()V");
}

void AndroidController::setSaveLogs(bool enabled)
{
    callActivityMethod("setSaveLogs", "(Z)V", enabled);
}

void AndroidController::exportLogsFile(const QString &fileName)
{
    callActivityMethod("exportLogsFile", "(Ljava/lang/String;)V",
                       QJniObject::fromString(fileName).object<jstring>());
}

void AndroidController::clearLogs()
{
    callActivityMethod("clearLogs", "()V");
}

void AndroidController::setScreenshotsEnabled(bool enabled)
{
    callActivityMethod("setScreenshotsEnabled", "(Z)V", enabled);
}

void AndroidController::setNavigationBarColor(unsigned int color)
{
    callActivityMethod("setNavigationBarColor", "(I)V", color);
}

void AndroidController::minimizeApp()
{
    callActivityMethod("minimizeApp", "()V");
}

QJsonArray AndroidController::getAppList()
{
    QJniObject appList = callActivityMethod<jstring>("getAppList", "()Ljava/lang/String;");
    QJsonArray jsonAppList = QJsonDocument::fromJson(appList.toString().toUtf8()).array();
    return jsonAppList;
}

QPixmap AndroidController::getAppIcon(const QString &package, QSize *size, const QSize &requestedSize)
{
    QJniObject bitmap = callActivityMethod<jobject>("getAppIcon", "(Ljava/lang/String;II)Landroid/graphics/Bitmap;",
                                                    QJniObject::fromString(package).object<jstring>(),
                                                    requestedSize.width(), requestedSize.height());

    QJniEnvironment env;
    AndroidBitmapInfo info;
    if (AndroidBitmap_getInfo(env.jniEnv(), bitmap.object(), &info) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    void *pixels;
    if (AndroidBitmap_lockPixels(env.jniEnv(), bitmap.object(), &pixels) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    int width = info.width;
    int height = info.height;

    size->setWidth(width);
    size->setHeight(height);

    QImage image(width, height, QImage::Format_RGBA8888);
    if (info.stride == uint32_t(image.bytesPerLine())) {
        memcpy((void *) image.constBits(), pixels, info.stride * height);
    } else {
        auto *bmpPtr = static_cast<uchar *>(pixels);
        for (int i = 0; i < height; i++, bmpPtr += info.stride)
            memcpy((void *) image.constScanLine(i), bmpPtr, width);
    }

    if (AndroidBitmap_unlockPixels(env.jniEnv(), bitmap.object()) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    return QPixmap::fromImage(image);
}

bool AndroidController::isNotificationPermissionGranted()
{
    return callActivityMethod<jboolean>("isNotificationPermissionGranted", "()Z");
}

void AndroidController::requestNotificationPermission()
{
    callActivityMethod("requestNotificationPermission", "()V");
}

bool AndroidController::requestAuthentication()
{
    QEventLoop wait;
    bool result;
    connect(this, &AndroidController::authenticationResult, this,
            [&result, &wait](const bool &authResult){
                qDebug() << "Android authentication result:" << authResult;
                result = authResult;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("requestAuthentication", "()V");
    wait.exec();
    return result;
}

void AndroidController::sendTouch(float x, float y)
{
    callActivityMethod("sendTouch", "(FF)V", x, y);
}


bool AndroidController::isPlay()
{
    return callActivityMethod<jboolean>("isPlay", "()Z");
}

QJsonObject AndroidController::getSubscriptionPlans()
{
    QJniObject subscriptionPlans = callActivityMethod<jstring>("getSubscriptionPlans", "()Ljava/lang/String;");
    QJsonObject json = QJsonDocument::fromJson(subscriptionPlans.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::purchaseSubscription(const QString &offerToken)
{
    QJniObject result = callActivityMethod<jstring, jstring>("purchaseSubscription", "(Ljava/lang/String;)Ljava/lang/String;",
                                                    QJniObject::fromString(offerToken).object<jstring>());
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::upgradeSubscription(const QString &offerToken, const QString &oldPurchaseToken)
{
    QJniObject result = callActivityMethod<jstring, jstring, jstring>("upgradeSubscription",
                                                                      "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                                                                      QJniObject::fromString(offerToken).object<jstring>(),
                                                                      QJniObject::fromString(oldPurchaseToken).object<jstring>());
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::acknowledgePurchase(const QString &purchaseToken)
{
    QJniObject result = callActivityMethod<jstring, jstring>("acknowledgePurchase", "(Ljava/lang/String;)Ljava/lang/String;",
                                                             QJniObject::fromString(purchaseToken).object<jstring>());
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::queryPurchases()
{
    QJniObject result = callActivityMethod<jstring>("queryPurchases", "()Ljava/lang/String;");
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

// Moving log processing to the Android side
jclass AndroidController::log;
jmethodID AndroidController::logDebug;
jmethodID AndroidController::logInfo;
jmethodID AndroidController::logWarning;
jmethodID AndroidController::logError;
jmethodID AndroidController::logFatal;

// static
bool AndroidController::initLogging()
{
    QJniEnvironment env;

    log = env.findClass(ANDROID_LOG_CLASS);
    if (log == nullptr) {
        qCritical() << "Android log class" << ANDROID_LOG_CLASS << "not found";
        return false;
    }

    auto logMethodSignature = "(Ljava/lang/String;Ljava/lang/String;)V";

    logDebug = env.findStaticMethod(log, "d", logMethodSignature);
    if (logDebug == nullptr) {
        qCritical() << "Android debug log method not found";
        return false;
    }

    logInfo = env.findStaticMethod(log, "i", logMethodSignature);
    if (logInfo == nullptr) {
        qCritical() << "Android info log method not found";
        return false;
    }

    logWarning = env.findStaticMethod(log, "w", logMethodSignature);
    if (logWarning == nullptr) {
        qCritical() << "Android warning log method not found";
        return false;
    }

    logError = env.findStaticMethod(log, "e", logMethodSignature);
    if (logError == nullptr) {
        qCritical() << "Android error log method not found";
        return false;
    }

    logFatal = env.findStaticMethod(log, "f", logMethodSignature);
    if (logFatal == nullptr) {
        qCritical() << "Android fatal log method not found";
        return false;
    }

    qInstallMessageHandler(messageHandler);
    return true;
}

// static
void AndroidController::messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    jmethodID logMethod = logDebug;
    switch (type) {
        case QtDebugMsg:
            logMethod = logDebug;
            break;
        case QtInfoMsg:
            logMethod = logInfo;
            break;
        case QtWarningMsg:
            logMethod = logWarning;
            break;
        case QtCriticalMsg:
            logMethod = logError;
            break;
        case QtFatalMsg:
            logMethod = logFatal;
            break;
    }
    QString formattedMessage = qFormatLogMessage(type, context, message);
    QJniObject::callStaticMethod<void>(log, logMethod,
                                       QJniObject::fromString(TAG).object<jstring>(),
                                       QJniObject::fromString(formattedMessage).object<jstring>());
}

void AndroidController::qtAndroidControllerInitialized()
{
    callActivityMethod("qtAndroidControllerInitialized", "()V");
}

// static
Vpn::ConnectionState AndroidController::convertState(AndroidController::ConnectionState state)
{
    switch (state) {
        case AndroidController::ConnectionState::CONNECTED: return Vpn::ConnectionState::Connected;
        case AndroidController::ConnectionState::CONNECTING: return Vpn::ConnectionState::Connecting;
        case AndroidController::ConnectionState::DISCONNECTED: return Vpn::ConnectionState::Disconnected;
        case AndroidController::ConnectionState::DISCONNECTING: return Vpn::ConnectionState::Disconnecting;
        case AndroidController::ConnectionState::RECONNECTING: return Vpn::ConnectionState::Reconnecting;
        case AndroidController::ConnectionState::UNKNOWN: return Vpn::ConnectionState::Unknown;
    }
}

// static
QString AndroidController::textConnectionState(AndroidController::ConnectionState state)
{
    switch (state) {
        case AndroidController::ConnectionState::CONNECTED: return "CONNECTED";
        case AndroidController::ConnectionState::CONNECTING: return "CONNECTING";
        case AndroidController::ConnectionState::DISCONNECTED: return "DISCONNECTED";
        case AndroidController::ConnectionState::DISCONNECTING: return "DISCONNECTING";
        case AndroidController::ConnectionState::RECONNECTING: return "RECONNECTING";
        case AndroidController::ConnectionState::UNKNOWN: return "UNKNOWN";
    }
}

// JNI functions called by Android
// static
void AndroidController::onStatus(JNIEnv *env, jobject thiz, jint stateCode)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    auto state = ConnectionState(stateCode);

    emit AndroidController::instance()->status(state);
}

// static
void AndroidController::onServiceDisconnected(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->serviceDisconnected();
}

// static
void AndroidController::onServiceError(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->serviceError();
}

// static
void AndroidController::onVpnPermissionRejected(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->vpnPermissionRejected();
}

// static
void AndroidController::onVpnPermissionPrompt(JNIEnv *env, jobject thiz, jint state)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->vpnPermissionPrompt(int(state));
}

// static
void AndroidController::onTunnelBuild(JNIEnv *env, jobject thiz, jint state, jint seq, jlong leg)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->tunnelBuild(int(state), int(seq), quint64(leg));
}

// static
void AndroidController::onNotificationStateChanged(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->notificationStateChanged();
}

// static
void AndroidController::onVpnStateChanged(JNIEnv *env, jobject thiz, jint stateCode)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    auto state = ConnectionState(stateCode);

    emit AndroidController::instance()->vpnStateChanged(state);
}

// static
void AndroidController::onStatisticsUpdate(JNIEnv *env, jobject thiz, jlong rxBytes, jlong txBytes,
                                           jlong lastHandshakeSec)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->statisticsUpdated((quint64) rxBytes, (quint64) txBytes);
    // AVPN: возраст хендшейка наружу (<=0 → 0 «неизвестно») — serviceEngine HealthLoop DEAD-детект.
    emit AndroidController::instance()->handshakeUpdated(lastHandshakeSec > 0 ? (qint64) lastHandshakeSec : 0);
}

// static
void AndroidController::onFileOpened(JNIEnv *env, jobject thiz, jstring uri)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->fileOpened(AndroidUtils::convertJString(env, uri));
}

// static
void AndroidController::onConfigImported(JNIEnv *env, jobject thiz, jstring data)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->configImported(AndroidUtils::convertJString(env, data));
}

// static
void AndroidController::onAuthResult(JNIEnv *env, jobject thiz, jboolean result)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->authenticationResult(result);
}

// static
bool AndroidController::decodeQrCode(JNIEnv *env, jobject thiz, jstring data)
{
    Q_UNUSED(thiz);

    return ImportUiController::decodeQrCode(AndroidUtils::convertJString(env, data));
}
// static
void AndroidController::onImeInsetsChanged(JNIEnv *env, jobject thiz, jint heightDp)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    qDebug() << "Android IME insets changed: height =" << heightDp << "dp";
    emit AndroidController::instance()->imeInsetsChanged(heightDp);
}

// static
void AndroidController::onSystemBarsInsetsChanged(JNIEnv *env, jobject thiz, jint navBarHeightDp, jint statusBarHeightDp)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    qDebug() << "Android system bars insets changed: nav bar =" << navBarHeightDp << "dp, status bar =" << statusBarHeightDp << "dp";
    emit AndroidController::instance()->systemBarsInsetsChanged(navBarHeightDp, statusBarHeightDp);
}

// static
void AndroidController::onActivityPaused(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->activityPaused();
}

// static
void AndroidController::onActivityResumed(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->activityResumed();
}

// AVPN (Scanner, lane A3): ServiceEvent.SCAN_REPLY / SCAN_HOST_STATE forwarded by the activity, unchanged.
// static
void AndroidController::onScanReply(JNIEnv *env, jobject thiz, jlong id, jstring reply)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->scanReplyReceived(qint64(id), AndroidUtils::convertJString(env, reply).toUtf8());
}

// static
void AndroidController::onScanHostState(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->scanHostStateReceived(AndroidUtils::convertJString(env, json).toUtf8());
}

// AVPN (upstream nodes, release C): ServiceEvent.UPSTREAM_STATUS forwarded by the activity
// (android-ipc-contract.md §3). Decoded on the controller's thread.
// static
void AndroidController::onUpstreamStatus(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->upstreamStatusReceived(AndroidUtils::convertJString(env, json).toUtf8());
}

// AVPN (owner decision 2026-11-16): Android in-app update of the site APK. See the header and
// core/serviceEngine/ApkUpdatePolicy.h for the invariants.
#include "avpn_selfupdate_android.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QJniEnvironment>
#include <QJniObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QStandardPaths>
#include <QTimer>

#include <iterator>

#include "core/serviceEngine/ApkUpdatePolicy.h"

namespace
{
    constexpr auto SELF_UPDATE_CLASS = "org/amnezia/vpn/TribeSelfUpdate";

    QJniObject androidContext()
    {
        return QJniObject(QNativeInterface::QAndroidApplication::context());
    }

    void onInstallStatusNative(JNIEnv *, jclass, jint status, jstring jmessage)
    {
        const int s = static_cast<int>(status);
        const QString message = QJniObject(jmessage).toString();
        auto *self = avpn::AndroidSelfUpdate::instance();
        QMetaObject::invokeMethod(self, [self, s, message] { self->onInstallStatus(s, message); },
                                  Qt::QueuedConnection);
    }
} // namespace

namespace avpn {

AndroidSelfUpdate *AndroidSelfUpdate::instance()
{
    static AndroidSelfUpdate *s = new AndroidSelfUpdate(QCoreApplication::instance());
    return s;
}

AndroidSelfUpdate::AndroidSelfUpdate(QObject *parent) : QObject(parent) {}

bool AndroidSelfUpdate::isSupported()
{
    static const bool supported =
        QJniObject::callStaticMethod<jboolean>(SELF_UPDATE_CLASS, "isSupported", "()Z") == JNI_TRUE;
    return supported;
}

QString AndroidSelfUpdate::workDir() const
{
    // Same directory TribeSelfUpdate.onPackageReplaced() clears: <cacheDir>/tribe-update.
    const QJniObject ctx = androidContext();
    const QJniObject cacheDir = ctx.callObjectMethod("getCacheDir", "()Ljava/io/File;");
    const QString base = cacheDir.isValid()
        ? cacheDir.callObjectMethod("getAbsolutePath", "()Ljava/lang/String;").toString()
        : QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    return base + QStringLiteral("/tribe-update");
}

void AndroidSelfUpdate::fail(const QString &reason)
{
    if (m_reply) {
        m_reply->disconnect(this);
        m_reply->abort();
        m_reply->deleteLater();
    }
    if (m_file) {
        m_file->remove();
        delete m_file;
        m_file = nullptr;
    }
    m_running = false;
    qWarning() << "[selfupdate-android] failed:" << reason;
    emit failed(reason);
}

void AndroidSelfUpdate::start(const QString &url, const QString &expectedVersion)
{
    if (m_running)
        return;
    const QUrl u(url);
    if (!ApkUpdate::urlAllowed(u)) {
        qWarning() << "[selfupdate-android] update link rejected:" << url;
        emit failed(ApkUpdate::installStatusText(ApkUpdate::kStatusFailure));
        return;
    }
    if (!isSupported()) {
        emit failed(QCoreApplication::translate("AvpnApkUpdate", "Обновление внутри приложения тут недоступно"));
        return;
    }
    const QJniObject ctx = androidContext();
    if (!ctx.isValid()) {
        emit failed(ApkUpdate::installStatusText(ApkUpdate::kStatusFailure));
        return;
    }
    // «Install unknown apps» for Tribe VPN: one switch in Android settings, asked before downloading.
    const bool canInstall = QJniObject::callStaticMethod<jboolean>(
        SELF_UPDATE_CLASS, "canInstall", "(Landroid/content/Context;)Z", ctx.object()) == JNI_TRUE;
    if (!canInstall) {
        QJniObject::callStaticMethod<void>(SELF_UPDATE_CLASS, "openInstallPermission",
                                           "(Landroid/content/Context;)V", ctx.object());
        emit failed(QCoreApplication::translate(
            "AvpnApkUpdate",
            "Разрешите Tribe VPN устанавливать приложения — включите переключатель в открывшихся "
            "настройках, вернитесь и нажмите «Обновить» ещё раз."));
        return;
    }

    m_running = true;
    m_attempt = 0;
    m_url = u;
    m_expectedVersion = expectedVersion;
    emit progress(QCoreApplication::translate("AvpnApkUpdate", "Скачиваем обновление…"));
    qInfo() << "[selfupdate-android] downloading" << u.toString() << "expected" << expectedVersion;
    beginDownload();
}

void AndroidSelfUpdate::beginDownload()
{
    const QString dir = workDir();
    QDir().mkpath(dir);
    m_file = new QFile(dir + QStringLiteral("/TribeVPN-update.apk.part"));
    if (!m_file->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        delete m_file;
        m_file = nullptr;
        fail(ApkUpdate::installStatusText(ApkUpdate::kStatusStorage));
        return;
    }
    if (!m_nam)
        m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req(m_url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    req.setTransferTimeout(60'000); // inactivity, not total time
    m_reply = m_nam->get(req);

    connect(m_reply, &QNetworkReply::readyRead, this, [this] {
        if (!m_reply || !m_file)
            return;
        m_file->write(m_reply->readAll());
        if (!ApkUpdate::sizeAllowed(m_file->size()))
            fail(ApkUpdate::verdictText(ApkUpdate::Verdict::Unreadable));
    });
    connect(m_reply, &QNetworkReply::downloadProgress, this, [this](qint64 got, qint64 total) {
        if (total > 0 && !ApkUpdate::sizeAllowed(total)) {
            fail(ApkUpdate::verdictText(ApkUpdate::Verdict::Unreadable));
            return;
        }
        if (total > 0)
            emit downloadProgress(int(got * 100 / total));
    });
    connect(m_reply, &QNetworkReply::finished, this, &AndroidSelfUpdate::onDownloadFinished);
}

void AndroidSelfUpdate::onDownloadFinished()
{
    if (!m_reply || !m_file)
        return;
    QNetworkReply *reply = m_reply;
    m_reply = nullptr;
    reply->deleteLater();
    const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->error() != QNetworkReply::NoError || http != 200) {
        qWarning() << "[selfupdate-android] download error" << reply->error() << http << reply->errorString();
        // A network-level failure (handshake, reset, timeout — no HTTP answer at all) is retried
        // quietly, three attempts in all, 2 s and 5 s apart. Emulator check 2026-11-16: the TLS
        // handshake to tribevpn.com failed in bursts of a few seconds and then went through.
        static constexpr int kRetryDelayMs[] = {2000, 5000};
        if (http == 0 && m_attempt < int(std::size(kRetryDelayMs))) {
            const int delay = kRetryDelayMs[m_attempt++];
            m_file->remove();
            delete m_file;
            m_file = nullptr;
            QTimer::singleShot(delay, this, [this] {
                if (m_running && !m_reply)
                    beginDownload();
            });
            return;
        }
        fail(QCoreApplication::translate("AvpnApkUpdate",
                                         "Не удалось скачать обновление. Проверьте интернет и попробуйте ещё раз."));
        return;
    }
    // Redirects stay on our host (NoLessSafe keeps https; the host is checked here).
    if (!ApkUpdate::urlAllowed(reply->url())) {
        qWarning() << "[selfupdate-android] redirected off our host:" << reply->url().toString();
        fail(ApkUpdate::verdictText(ApkUpdate::Verdict::WrongSigner));
        return;
    }
    m_file->write(reply->readAll());
    m_file->close();
    const QString part = m_file->fileName();
    QString path = part;
    path.chop(5); // ".part"
    QFile::remove(path);
    const bool renamed = m_file->rename(path);
    delete m_file;
    m_file = nullptr;
    if (!renamed) {
        QFile::remove(part);
        fail(ApkUpdate::installStatusText(ApkUpdate::kStatusStorage));
        return;
    }
    verifyAndInstall(path);
}

void AndroidSelfUpdate::verifyAndInstall(const QString &path)
{
    emit progress(QCoreApplication::translate("AvpnApkUpdate", "Проверяем подпись…"));
    const QJniObject ctx = androidContext();
    const QString line = QJniObject::callStaticObjectMethod(
        SELF_UPDATE_CLASS, "inspect", "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
        ctx.object(), QJniObject::fromString(path).object<jstring>()).toString();
    const qint64 installed = QJniObject::callStaticMethod<jlong>(
        SELF_UPDATE_CLASS, "installedVersionCode", "(Landroid/content/Context;)J", ctx.object());
    const QString ownPackage = ctx.callObjectMethod("getPackageName", "()Ljava/lang/String;").toString();

    const ApkUpdate::ApkInfo info = ApkUpdate::parseInspect(line);
    const ApkUpdate::Verdict v = ApkUpdate::verdict(info, ownPackage, installed, m_expectedVersion);
    qInfo() << "[selfupdate-android] inspect" << line << "installed" << installed << "verdict" << int(v);
    if (v != ApkUpdate::Verdict::Ok) {
        QFile::remove(path);
        fail(ApkUpdate::verdictText(v));
        return;
    }
    const bool started = QJniObject::callStaticMethod<jboolean>(
        SELF_UPDATE_CLASS, "install", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Z",
        ctx.object(), QJniObject::fromString(path).object<jstring>(),
        QJniObject::fromString(info.versionName).object<jstring>()) == JNI_TRUE;
    if (!started) {
        fail(ApkUpdate::installStatusText(ApkUpdate::kStatusFailure));
        return;
    }
    emit progress(QCoreApplication::translate("AvpnApkUpdate", "Устанавливаем…"));
}

void AndroidSelfUpdate::onInstallStatus(int status, const QString &message)
{
    qInfo() << "[selfupdate-android] installer status" << status << message;
    if (!m_running)
        return;
    if (status == ApkUpdate::kStatusPendingUserAction) {
        emit awaitingConfirmation();
        return;
    }
    if (status == ApkUpdate::kStatusSuccess) {
        m_running = false;
        emit installed();
        return;
    }
    fail(ApkUpdate::installStatusText(status));
}

bool registerSelfUpdateNatives()
{
    const JNINativeMethod methods[] = {
        {"nativeOnInstallStatus", "(ILjava/lang/String;)V", reinterpret_cast<void *>(onInstallStatusNative)},
    };
    QJniEnvironment env;
    if (!env.registerNativeMethods(SELF_UPDATE_CLASS, methods, sizeof(methods) / sizeof(JNINativeMethod))) {
        qWarning() << "[selfupdate-android] native method registration failed";
        return false;
    }
    return true;
}

} // namespace avpn

// AVPN (owner decision 2026-11-16): Android in-app update of the site APK.
// Download from /dl/ (QNetworkAccessManager) → TribeSelfUpdate.inspect() (Kotlin) → decision by
// avpn::ApkUpdate (core/serviceEngine/ApkUpdatePolicy.h) → TribeSelfUpdate.install() → Android's
// own confirmation. Driven by AvpnEngineQml under Q_OS_ANDROID only.
#pragma once

#include <QObject>
#include <QPointer>
#include <QString>
#include <QUrl>

QT_BEGIN_NAMESPACE
class QFile;
class QNetworkAccessManager;
class QNetworkReply;
QT_END_NAMESPACE

namespace avpn {

class AndroidSelfUpdate : public QObject
{
    Q_OBJECT
public:
    static AndroidSelfUpdate *instance();

    // oss (site) build only; the Play build updates through the store.
    static bool isSupported();

    bool running() const { return m_running; }

    // url — urls.store_android; expectedVersion — recommended_version.android (empty = not pinned).
    void start(const QString &url, const QString &expectedVersion);

    // Kotlin → C++ (any thread; marshalled to this object's thread).
    void onInstallStatus(int status, const QString &message);

signals:
    void progress(const QString &text);
    void downloadProgress(int percent);
    void awaitingConfirmation();   // Android's dialog «Update this app?» is on screen
    void failed(const QString &reason);
    void installed();              // Android reported success (the process is usually gone by then)

private:
    explicit AndroidSelfUpdate(QObject *parent = nullptr);
    void fail(const QString &reason);
    void onDownloadFinished();
    void verifyAndInstall(const QString &path);
    void beginDownload();
    QString workDir() const;

    QNetworkAccessManager *m_nam = nullptr;
    QPointer<QNetworkReply> m_reply;
    QFile *m_file = nullptr;
    QString m_expectedVersion;
    QUrl m_url;
    int m_attempt = 0;                   // network-level failures are retried (see onDownloadFinished)
    bool m_running = false;
};

// Registers TribeSelfUpdate.nativeOnInstallStatus. Called once from AndroidController::initialize().
bool registerSelfUpdateNatives();

} // namespace avpn

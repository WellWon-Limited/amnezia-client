#include <QDebug>
#include <QTimer>
#include <libssh/libssh.h>
#include <openssl/ssl.h>

#include "amneziaApplication.h"
#include "core/utils/osSignalHandler.h"
#include "core/utils/migrations.h"
#include "core/utils/appUiConfig.h"
#ifdef AVPN_ENGINE_ENABLED
#include "core/serviceEngine/LaunchGuard.h" // AVPN (self-update v2): crash-loop после обновления → откат
#endif
#include "version.h"


// use openssl symbols to prevent linker throwing-off the OpenSSL dependency
void anchorOpenSSL() {
    SSL_CTX_free(SSL_CTX_new(TLS_method()));
}

#ifdef Q_OS_WIN
    #include "Windows.h"
#endif

#if defined(Q_OS_IOS)
    #include "platforms/ios/QtAppDelegate-C-Interface.h"
#endif

#if defined(Q_OS_ANDROID)
    #include <QSettings>
    #include <unistd.h> // AVPN (emulator round 26.11.2026): _exit at the end of the Android UI process, see main()
#endif

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
bool isAnotherInstanceRunning()
{
    QLocalSocket socket;
    // AVPN: derive instance socket from APPLICATION_NAME (→"AVPNInstance"), was hardcoded
    // "AmneziaVPNInstance" — shared name cross-linked our fork with official Amnezia
    // (clicking either icon raised whichever instance already held the socket).
    socket.connectToServer(APP_INSTANCE_NAME);
    if (socket.waitForConnected(500)) {
#ifdef AVPN_ENGINE_ENABLED
        // AVPN (перенос по QR): Windows/Linux URL-протокол запускает ВТОРОЙ инстанс с диплинком
        // tribe:// в argv — пробрасываем его работающему инстансу через этот же instance-сокет
        // (читает startLocalServer → AvpnDeepLink_handleUrl). macOS идёт через QFileOpenEvent.
        const QStringList args = QCoreApplication::arguments();
        for (const QString &a : args) {
            if (a.startsWith(QStringLiteral("tribe://")) || a.contains(QStringLiteral("tribevpn.com/transfer"))) {
                socket.write(a.toUtf8());
                socket.flush();
                socket.waitForBytesWritten(500);
                break;
            }
        }
#endif
        qWarning() << APPLICATION_NAME << "is already running";
        return true;
    }
    return false;
}
#endif

int main(int argc, char *argv[])
{
#if defined(Q_OS_ANDROID)
    // AVPN (emulator round 26.11.2026): the Android UI process ends with _exit once main's work is done - the ending the
    // iOS build already uses (AvpnEngineQml.cpp, its aboutToQuit guard). After main() returns, Qt's Android plugin unloads
    // this library and calls exit(), so the C++ static destructors run while system threads of the process are still
    // alive - by all signs the render pool of Android's view layer (libhwui), waiting on a mutex those destructors
    // destroy. A swipe from recents ended in SIGABRT «FORTIFY: pthread_mutex_lock called on a destroyed mutex» in two such
    // threads, 10 ms after «main() returned 0». Nothing of ours needs that pass: every settings object writes itself when
    // destroyed (~AmneziaApplication's SecureQSettings, each local QSettings) and the settings are synced once more here,
    // as on iOS; the log file is flushed per message; our files are committed QSaveFiles; the tunnel runs in its own
    // service process (:amneziaAwgService and the others), which the end of this process does not touch.
    // Declared first, so it runs after every other local of main, ~AmneziaApplication included.
    struct AndroidUiProcessEnd {
        int code = 0;
        ~AndroidUiProcessEnd()
        {
            { QSettings settings; settings.sync(); }
            qInfo().noquote() << QStringLiteral("UI process ends with _exit(%1) after main").arg(code);
            ::_exit(code);
        }
    } androidUiProcessEnd;
#endif
    Migrations migrationsManager;
    migrationsManager.doMigrations();

#ifdef Q_OS_WIN
    AllowSetForegroundWindow(ASFW_ANY);
#endif

#ifdef Q_OS_ANDROID
    // QTBUG-95974 QTBUG-95764 QTBUG-102168
    qputenv("QT_ANDROID_DISABLE_ACCESSIBILITY", "1");
    qputenv("ANDROID_OPENSSL_SUFFIX", "_3");
#endif

    AmneziaApplication app(argc, argv);
    // One exact version on every platform; server-side cohorts must not see
    // Qt's platform-specific default (for example a bare Apple build number).
    QCoreApplication::setApplicationVersion(QStringLiteral(APP_VERSION));
    OsSignalHandler::setup();

    anchorOpenSSL();

    ssh_init();
    QObject::connect(&app, &QCoreApplication::aboutToQuit, []() {
        ssh_finalize();
    });

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (isAnotherInstanceRunning()) {
        QTimer::singleShot(1000, &app, [&]() { app.quit(); });
        return app.exec();
    }
    app.startLocalServer();
#endif

// Allow to raise app window if secondary instance launched
#ifdef Q_OS_WIN
    AllowSetForegroundWindow(0);
#endif

    app.registerTypes();

    app.setApplicationName(APPLICATION_NAME);
    app.setOrganizationName(ORGANIZATION_NAME);
    app.setApplicationDisplayName(APPLICATION_DISPLAY_NAME); // AVPN: продуктовое имя пользователю, не внутренний ключ

    app.loadFonts();

    bool doExec = app.parseCommands();

    if (doExec) {
#if defined(AVPN_ENGINE_ENABLED) && defined(Q_OS_MACOS) && !defined(MACOS_NE)
        // AVPN (self-update v2): третий старт подряд без подтверждения «жива» после обновления =
        // crash-loop (инцидент 112: падение в QML до любого нашего кода). Откат на сохранённую
        // копию ДО загрузки QML, отдельным процессом; сами выходим, он ждёт наш PID.
        {
            const QString stateDir = avpn::LaunchGuard::defaultStateDir();
            const QString appPath = avpn::LaunchGuard::installedAppPath();
            if (avpn::LaunchGuard::startNeedsRollback(stateDir, QStringLiteral(APP_VERSION), appPath)
                && avpn::LaunchGuard::spawnRollback(stateDir, appPath, QStringLiteral("crash_loop"),
                                                    QCoreApplication::applicationPid())) {
                qWarning().noquote() << "LaunchGuard: crash-loop after update, rolling back and exiting";
                return 0;
            }
        }
#endif
        app.init();

        qInfo().noquote() << QString("Started %1 version %2 %3").arg(APPLICATION_NAME, APP_VERSION, GIT_COMMIT_HASH);
        qInfo().noquote() << QString("%1 (%2)").arg(QSysInfo::prettyProductName(), QSysInfo::currentCpuArchitecture());

#if defined(Q_OS_ANDROID)
        return androidUiProcessEnd.code = app.exec(); // AVPN: the code the UI process ends with (androidUiProcessEnd)
#else
        return app.exec();
#endif
    }
    return 0;
}

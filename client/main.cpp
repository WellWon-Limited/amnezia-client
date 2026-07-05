#include <QDebug>
#include <QTimer>
#include <libssh/libssh.h>

#include "amneziaApplication.h"
#include "core/utils/osSignalHandler.h"
#include "core/utils/migrations.h"
#include "version.h"

#ifdef Q_OS_WIN
    #include "Windows.h"
#endif

#if defined(Q_OS_IOS)
    #include "platforms/ios/QtAppDelegate-C-Interface.h"
#endif

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
bool isAnotherInstanceRunning()
{
    QLocalSocket socket;
    // AVPN: derive instance socket from APPLICATION_NAME (→"AVPNInstance"), was hardcoded
    // "AmneziaVPNInstance" — shared name cross-linked our fork with official Amnezia
    // (clicking either icon raised whichever instance already held the socket).
    socket.connectToServer(QStringLiteral(APPLICATION_NAME "Instance"));
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
        qWarning() << "AmneziaVPN is already running";
        return true;
    }
    return false;
}
#endif

int main(int argc, char *argv[])
{
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
    OsSignalHandler::setup();

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
        app.init();

        qInfo().noquote() << QString("Started %1 version %2 %3").arg(APPLICATION_NAME, APP_VERSION, GIT_COMMIT_HASH);
        qInfo().noquote() << QString("%1 (%2)").arg(QSysInfo::prettyProductName(), QSysInfo::currentCpuArchitecture());

        return app.exec();
    }
    return 0;
}

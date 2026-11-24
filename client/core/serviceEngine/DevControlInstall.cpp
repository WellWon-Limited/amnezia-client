// AVPN (desktop test rig): the app's test command channel over its QML engine (DevControlApp.h install). App only:
// the host test (tests/dev_control_check.cpp) builds App + Server against fakes instead.
#include "AvpnEngineQml.h"
#include "DevControlApp.h"
#include "TribeJournal.h"

#include <QCoreApplication>
#include <QDebug>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QStandardPaths>

namespace avpn::devctl {

Server *install(QQmlEngine *qml, QObject *parent)
{
    AppEnv env;
    const QPointer<QQmlEngine> q(qml);
    env.object = [q](const QString &name) -> QObject * {
        return q ? q->rootContext()->contextProperty(name).value<QObject *>() : nullptr;
    };
    env.root = [q]() -> QObject * {
        auto *app = qobject_cast<QQmlApplicationEngine *>(q.data());
        return (app && !app->rootObjects().isEmpty()) ? app->rootObjects().constFirst() : nullptr;
    };
    // the directory of the app's log and journal (~/Library/Application Support/AVPN.ORG/AVPN on macOS)
    env.dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
#ifdef APP_VERSION
    env.version = QStringLiteral(APP_VERSION);
#endif
#ifdef GIT_COMMIT_HASH
    env.commit = QStringLiteral(GIT_COMMIT_HASH);
#endif
    env.journal = [](const QString &ev, const QJsonObject &fields) { TribeJournal::append(ev, fields); };
    env.journalActive = [] { return TribeJournal::active(); };
    env.log = [](const QString &line) { qInfo().noquote() << line; };
    env.quit = [] { QCoreApplication::quit(); }; // the tray's «Quit» (systemTrayNotificationHandler.cpp)
    // the system-sleep gate's proof of a person (SystemAwake.h): the engine's one entry, never a faked input event
    env.personPresent = [q] {
        QObject *o = q ? q->rootContext()->contextProperty(QStringLiteral("TribeEngine")).value<QObject *>() : nullptr;
        if (auto *engine = qobject_cast<avpn::AvpnEngineQml *>(o))
            engine->notePersonPresent();
    };

    auto *app = new App(env, parent);
    auto *server = new Server(env.dataDir, app, app);
    QString why;
    if (!server->start(&why)) {
        qWarning().noquote() << "[avpn devctl] test command channel not started:" << why;
        delete app;
        return nullptr;
    }
    app->setServer(server);
    qWarning().noquote() << "[avpn devctl] test command channel (development build) at" << server->path();
    return server;
}

} // namespace avpn::devctl

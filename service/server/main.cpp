#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "version.h"
#include "localserver.h"
#include "killswitch.h"
#include "logger.h"
#include "systemservice.h"
#include "core/utils/utilities.h"

#include <cstring>

#ifdef Q_OS_MACOS
#include "openvpndnssecurity.h"
#include <cstdio>

namespace {

constexpr char kEngineManifestArgument[] = "--tribe-engine-manifest-v1";

#ifdef TRIBE_ENGINE_MANIFEST_ENABLED
int writeEngineManifestV1()
{
    QJsonObject app;
    app.insert(QStringLiteral("version"), QStringLiteral(APP_VERSION));
    app.insert(QStringLiteral("build"), APP_BUILD);

    QJsonObject awg;
    awg.insert(QStringLiteral("protocol"), QStringLiteral("awg"));
    awg.insert(QStringLiteral("adapter"), QStringLiteral("awg-go"));
    awg.insert(QStringLiteral("adapterVersion"),
               QStringLiteral(TRIBE_AWG_ENGINE_VERSION));
    awg.insert(QStringLiteral("declaredCoreVersion"),
               QStringLiteral(TRIBE_AWG_CORE_VERSION));
    awg.insert(QStringLiteral("sourceCommit"),
               QStringLiteral(TRIBE_AWG_ENGINE_COMMIT));
    awg.insert(QStringLiteral("abi"), QStringLiteral(TRIBE_AWG_UAPI_ABI));
    awg.insert(QStringLiteral("runtimeCoreVersion"), QJsonValue::Null);
    awg.insert(QStringLiteral("runtimeVersionProbed"), false);
    awg.insert(QStringLiteral("versionEvidence"),
               QStringLiteral("compile_time_lock_plus_artifact_probe"));
    awg.insert(QStringLiteral("capabilities"), QJsonArray{
        QStringLiteral("awg.random_trailers"),
        QStringLiteral("awg.disable_cookies"),
        QStringLiteral("uapi.readback"),
        QStringLiteral("tribe.guarded_settings_owner"),
    });

    QJsonObject xray;
    xray.insert(QStringLiteral("protocol"), QStringLiteral("xray"));
    xray.insert(QStringLiteral("adapter"),
                QStringLiteral("amnezia-xray-bindings"));
    xray.insert(QStringLiteral("adapterVersion"),
                QStringLiteral(TRIBE_XRAY_BINDINGS_VERSION));
    xray.insert(QStringLiteral("declaredCoreVersion"),
                QStringLiteral(TRIBE_XRAY_CORE_VERSION));
    xray.insert(QStringLiteral("sourceCommit"),
                QStringLiteral(TRIBE_XRAY_BINDINGS_COMMIT));
    xray.insert(QStringLiteral("abi"), QStringLiteral(TRIBE_XRAY_BINDINGS_ABI));
    xray.insert(QStringLiteral("runtimeCoreVersion"), QJsonValue::Null);
    xray.insert(QStringLiteral("runtimeVersionProbed"), false);
    xray.insert(QStringLiteral("versionEvidence"),
                QStringLiteral("compile_time_lock_plus_linked_symbol_probe"));
    xray.insert(QStringLiteral("capabilities"), QJsonArray{
        QStringLiteral("xray.vless.reality.vision.tcp"),
        QStringLiteral("xray.socket_callback"),
        QStringLiteral("tribe.guarded_settings_owner"),
    });

    QJsonObject manifest;
    manifest.insert(QStringLiteral("type"), QStringLiteral("engine_manifest_v1"));
    manifest.insert(QStringLiteral("schema"), 1);
    manifest.insert(QStringLiteral("app"), app);
    manifest.insert(QStringLiteral("engines"), QJsonArray{awg, xray});

    QByteArray output = QJsonDocument(manifest).toJson(QJsonDocument::Compact);
    output.append('\n');
    const auto written = std::fwrite(output.constData(), 1,
                                     static_cast<std::size_t>(output.size()), stdout);
    return written == static_cast<std::size_t>(output.size())
                    && std::fflush(stdout) == 0 ? 0 : 74;
}
#endif

} // namespace
#endif

#ifdef Q_OS_WIN
#include "platforms/windows/daemon/windowsdaemontunnel.h"

namespace {
int s_argc = 0;
char** s_argv = nullptr;
}  // namespace

#endif

int runApplication(int argc, char** argv)
{
    QCoreApplication app(argc,argv);

#ifdef Q_OS_MACOS
    QString startupRecoveryError;
    if (!amnezia::openvpndnssecurity::recover(&startupRecoveryError)) {
        KillSwitch::instance()->disableAllTraffic();
        std::fprintf(stderr, "Tribe DNS startup recovery failed: %s\n",
                     qPrintable(startupRecoveryError));
        return 1;
    }
#endif

#ifdef Q_OS_WIN
    if(argc > 2){
        s_argc = argc;
        s_argv = argv;
        QStringList tokens;
        for (int i = 1; i < argc; ++i) {
            tokens.append(QString(argv[i]));
        }

        if (!tokens.empty() && tokens[0] == "tunneldaemon") {
            WindowsDaemonTunnel *daemon = new WindowsDaemonTunnel();
            daemon->run(tokens);
        }
    }
#endif

    int result = 0;
    {
        LocalServer localServer;
        result = localServer.isReady() ? app.exec() : 1;
    }
    return result;

}


int main(int argc, char **argv)
{
#ifdef Q_OS_MACOS
    // This artifact identity ABI is deliberately the first executable path.
    // It must remain safe to call from an unprivileged release gate: no
    // QCoreApplication, path/log initialization, DNS/PF recovery, IPC or
    // network activity may happen before it returns.
    if (argc >= 2 && std::strcmp(argv[1], kEngineManifestArgument) == 0) {
        if (argc != 2) {
            return 64;
        }
#ifdef TRIBE_ENGINE_MANIFEST_ENABLED
        return writeEngineManifestV1();
#else
        return 78;
#endif
    }
    if (argc >= 2 && QString::fromUtf8(argv[1])
            == QLatin1String(amnezia::openvpndnssecurity::kHookArgument)) {
        QStringList arguments;
        arguments.reserve(argc);
        for (int index = 0; index < argc; ++index) {
            arguments.append(QString::fromUtf8(argv[index]));
        }
        QString hookError;
        const int result = amnezia::openvpndnssecurity::runHookFromEnvironment(
                arguments, &hookError);
        if (result != 0) {
            std::fprintf(stderr, "Tribe OpenVPN DNS hook rejected: %s\n",
                         qPrintable(hookError));
        }
        return result;
    }
    if (argc >= 2 && QString::fromUtf8(argv[1])
            == QLatin1String(amnezia::openvpndnssecurity::kRecoveryArgument)) {
        if (argc != 2) {
            return 64;
        }
        QString recoveryError;
        if (!amnezia::openvpndnssecurity::recover(&recoveryError)) {
            std::fprintf(stderr, "Tribe OpenVPN DNS recovery failed: %s\n",
                         qPrintable(recoveryError));
            return 1;
        }
        return 0;
    }

#endif
    Utils::initializePath(Logger::systemLogDir());

    if (argc >= 2) {
        qInfo() << "Started as console application";
        return runApplication(argc, argv);
    }
    else {
        qInfo() << "Started as system service";
#ifdef Q_OS_WIN
        SystemService systemService(argc, argv);
        return systemService.exec();
#else
    return runApplication(argc, argv);
#endif

    }
}

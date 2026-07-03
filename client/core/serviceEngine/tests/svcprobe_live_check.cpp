// AVPN: ЖИВАЯ проверка goodput-проб ServiceProbe (сеть! не для CI) — youtube/instagram резолв+замер
// с текущей машины. Цель: убедиться, что резолв НЕ падает в Unknown на здоровой сети (фикс 2026-07-03:
// InnerTube на www.youtube.com; инкрементальный Instagram-резолв). Запуск: build_svcprobe_live.sh.
#include "../ServiceProbe.h"

#include <QCoreApplication>
#include <QNetworkAccessManager>
#include <QTimer>
#include <cstdio>

using namespace avpn;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QNetworkAccessManager nam;

    QList<ServiceProbeConfig> cfgs;
    cfgs.append({QStringLiteral("youtube"), ServiceProbeConfig::Goodput,
                 QStringLiteral("redirector.googlevideo.com")});
    cfgs.append({QStringLiteral("instagram"), ServiceProbeConfig::Goodput,
                 QStringLiteral("static.cdninstagram.com")});

    ServiceProbe probe(&nam);
    probe.setServices(cfgs);

    int unknowns = 0;
    QObject::connect(&probe, &ServiceProbe::result,
                     [&unknowns](const QString &key, int state, int rttMs) {
                         static const char *st[] = {"BLOCKED", "SLOW", "WORKS"};
                         std::printf("%-10s -> %s (metric=%d kbit/s)\n", key.toUtf8().constData(),
                                     (state >= 0 && state <= 2) ? st[state] : "UNKNOWN(-1)", rttMs);
                         if (state == -1)
                             ++unknowns;
                     });
    QObject::connect(&probe, &ServiceProbe::allDone, [&app, &unknowns]() {
        std::printf(unknowns ? ">>> svcprobe_live: %d UNKNOWN (резолв не отработал)\n"
                             : ">>> svcprobe_live: все сервисы ИЗМЕРЕНЫ (без Unknown)\n",
                    unknowns);
        app.exit(unknowns ? 1 : 0);
    });

    QTimer::singleShot(0, [&probe]() { probe.probeAll(); });
    QTimer::singleShot(40000, [&app]() { std::printf(">>> svcprobe_live: TIMEOUT\n"); app.exit(2); });
    return app.exec();
}

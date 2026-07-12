// AVPN: ЖИВАЯ проверка проб ServiceProbe v2 (сеть! не для CI) — вкомпиленные дефолт-цели
// (telegram MTProto + youtube/instagram кворум+качество) с текущей машины. Цель: на здоровой сети
// ни один сервис не UNKNOWN и не BLOCKED (кворум официальных лёгких эндпоинтов обязан отвечать).
// Запуск: build_svcprobe_live.sh.
#include "../ServiceProbe.h"
#include "../ServiceProbeTargets.h"

#include <QCoreApplication>
#include <QNetworkAccessManager>
#include <QTimer>
#include <cstdio>

using namespace avpn;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QNetworkAccessManager nam;

    ServiceProbe probe(&nam);
    probe.setServices(defaultServiceProbeConfigs());

    int bad = 0;
    QObject::connect(&probe, &ServiceProbe::result,
                     [&bad](const QString &key, int state, int rttMs) {
                         static const char *st[] = {"BLOCKED", "SLOW", "WORKS"};
                         std::printf("%-10s -> %s (metric=%d)\n", key.toUtf8().constData(),
                                     (state >= 0 && state <= 2) ? st[state] : "UNKNOWN(-1)", rttMs);
                         if (state <= 0) // на здоровой сети UNKNOWN/BLOCKED = регресс кворума
                             ++bad;
                     });
    QObject::connect(&probe, &ServiceProbe::allDone, [&app, &bad]() {
        std::printf(bad ? ">>> svcprobe_live: %d сервис(ов) UNKNOWN/BLOCKED на здоровой сети\n"
                        : ">>> svcprobe_live: все сервисы живы (кворум v2 отработал)\n",
                    bad);
        app.exit(bad ? 1 : 0);
    });

    QTimer::singleShot(0, [&probe]() { probe.probeAll(); });
    QTimer::singleShot(40000, [&app]() { std::printf(">>> svcprobe_live: TIMEOUT\n"); app.exit(2); });
    return app.exec();
}

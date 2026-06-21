// AVPN serviceEngine — интеграционный тест нативного ICMP-пробера (Darwin/Linux unprivileged ICMP).
// Darwin == iOS по ICMP API ⇒ зелёный тут = рабочий iOS-producer. Проверяем: живой адрес даёт RTT>=0,
// не-отвечающий TEST-NET (RFC5737 192.0.2.1) → -1 по таймауту, и onDone зовётся ровно один раз.
#include "../RttProbeIcmp.h"

#include <QCoreApplication>
#include <QHash>
#include <QTimer>
#include <cstdio>

using namespace avpn;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    RttProbeIcmp probe;
    QHash<QString, int> got;
    int doneCount = 0;

    QList<RttTarget> targets;
    targets.append({ QStringLiteral("local"), QStringLiteral("127.0.0.1"), 0 });
    targets.append({ QStringLiteral("dead"), QStringLiteral("192.0.2.1"), 0 }); // TEST-NET-1, не отвечает

    QTimer guard; // страховка: тест не должен висеть
    guard.setSingleShot(true);
    QObject::connect(&guard, &QTimer::timeout, &app, [&]() { app.exit(2); });
    guard.start(5000);

    probe.probeAll(
        targets, 1500,
        [&](const QString &nodeId, int rttMs) { got.insert(nodeId, rttMs); },
        [&]() {
            ++doneCount;
            app.quit();
        });

    const int rc = app.exec();
    if (rc == 2) { std::printf("FAIL: timed out (onDone never fired)\n"); return 1; }

    int failures = 0;
#define CHECK(cond, msg)                                                                            \
    do {                                                                                            \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; }                                \
        else { std::printf("ok:   %s\n", msg); }                                                    \
    } while (0)

    CHECK(doneCount == 1, "onDone fired exactly once");
    CHECK(got.contains("local"), "local sampled");
    CHECK(got.contains("dead"), "dead sampled");
    std::printf("     local rtt=%d, dead rtt=%d\n", got.value("local", -99), got.value("dead", -99));
    CHECK(got.value("local", -99) >= 0, "localhost reachable (rtt>=0)");
    CHECK(got.value("local", -99) < 1500, "localhost rtt under budget");
    CHECK(got.value("dead", -99) == -1, "TEST-NET non-responder -> -1");

    if (failures) { std::printf("\n%d FAILURES\n", failures); return 1; }
    std::printf("\nALL PASS\n");
    return 0;
}

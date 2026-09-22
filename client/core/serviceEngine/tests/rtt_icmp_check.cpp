// AVPN serviceEngine — интеграционный тест нативного ICMP-пробера (Darwin/Linux unprivileged ICMP).
// Darwin == iOS по ICMP API ⇒ зелёный тут = рабочий iOS-producer. Проверяем: живой адрес даёт RTT>=0,
// не-отвечающий TEST-NET (RFC5737 192.0.2.1) → -1 по таймауту, и onDone зовётся ровно один раз.
#include "../RttProbeIcmp.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHash>
#include <QTimer>
#include <cstdio>

using namespace avpn;

// AVPN (фикс-волна 2026-09-22, B9): чистая агрегация эх (без сокетов) — один потерянный пакет из
// трёх не делает цель «недостижимой», RTT = минимум, досрочное «оседание» без ожидания таймаута.
static int aggregateChecks()
{
    int failures = 0;
    auto check = [&](bool cond, const char *msg) {
        if (!cond) { std::printf("FAIL: %s\n", msg); ++failures; }
        else { std::printf("ok:   %s\n", msg); }
    };
    {
        RttEchoAggregate a; // эха в 0/120/240 мс; ответ на №0 потерян, №1 — 55 мс, №2 — 40 мс
        a.markSent(0, 0); a.markSent(1, 120); a.markSent(2, 240);
        check(!a.settled(250), "agg: nothing answered yet -> not settled");
        check(a.markReply(1, 175), "agg: reply #1 accepted");
        check(!a.markReply(1, 180), "agg: duplicate reply ignored");
        check(a.markReply(2, 280), "agg: reply #2 accepted");
        check(a.best == 40, "agg: rtt = min over answered echoes (40)");
        check(!a.complete(), "agg: one echo lost -> not complete");
        check(!a.settled(300), "agg: waits settle grace after last send");
        check(a.settled(240 + RttEchoAggregate::settleGraceMs(40)), "agg: settles with lost echo, before round timeout");
    }
    {
        RttEchoAggregate a;
        a.markSent(0, 0); a.markSent(1, 120); a.markSent(2, 240);
        a.markReply(0, 30); a.markReply(1, 150); a.markReply(2, 272);
        check(a.complete() && a.settled(272), "agg: all answered -> complete immediately");
        check(a.best == 30, "agg: best of three = 30");
    }
    {
        RttEchoAggregate a; // ни одного ответа — только общий таймаут, RTT -1
        a.markSent(0, 0); a.markSent(1, 120); a.markSent(2, 240);
        check(!a.settled(1400) && a.best < 0, "agg: no replies -> never settles early, rtt -1");
    }
    {
        RttEchoAggregate a; // отправка не удалась совсем
        a.markSendFailed(0); a.markSendFailed(1); a.markSendFailed(2);
        check(a.allAccounted() && a.lastSentAt < 0 && a.best < 0, "agg: all sends failed -> unreachable");
        check(!a.markReply(0, 10), "agg: reply to unsent echo ignored");
    }
    return failures;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const int aggFailures = aggregateChecks();

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

    // AVPN B9: живая цель «оседает» досрочно (все 3 эха ответили) — раунд без мёртвых целей
    // укладывается задолго до общего таймаута (Connect без pin ≤ ~2.5 с при живой сети).
    {
        RttProbeIcmp fast;
        int fastRtt = -99;
        QElapsedTimer t;
        t.start();
        qint64 doneAt = -1;
        QTimer guard2;
        guard2.setSingleShot(true);
        QObject::connect(&guard2, &QTimer::timeout, &app, [&]() { app.exit(2); });
        guard2.start(5000);
        fast.probeAll({ { QStringLiteral("local"), QStringLiteral("127.0.0.1"), 0 } }, 1500,
            [&](const QString &, int rttMs) { fastRtt = rttMs; },
            [&]() { doneAt = t.elapsed(); app.quit(); });
        const int rc2 = app.exec();
        std::printf("     local-only round done in %lld ms, rtt=%d\n", (long long) doneAt, fastRtt);
        CHECK(rc2 != 2, "local-only round finished");
        CHECK(fastRtt >= 0, "local-only rtt>=0");
        CHECK(doneAt >= 0 && doneAt < 1000, "local-only round settles well before 1500 ms timeout");
    }
    failures += aggFailures;

    if (failures) { std::printf("\n%d FAILURES\n", failures); return 1; }
    std::printf("\nALL PASS\n");
    return 0;
}

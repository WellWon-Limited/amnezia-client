// AVPN (фикс-волна 2026-09-22, зона CL-A, пробелы критика полноты): последовательности вызовов
// ФАСАДА (AvpnEngineQml) против настоящего ServiceEngine/HealthLoop. Фасад зовёт движок через
// DebugSnapshot.h::facadeNoteNetworkChange / facadeEngineStop — здесь те же функции.
//  GAP-2 (жалоба 3): смена сети каждые 6 с 5 минут при мёртвом data-plane — DEAD наступает
//        (раньше фасад перед noteNetworkChange звал resetHealthSampling() и DEAD не наступал никогда);
//  GAP-3 (жалобы 1/2): повтор после дедлайна фазы down переподъёма EE — connect() идёт на EE и
//        бюджет лечения/стрик data-plane не сбрасываются (раньше guardedStop → requestStop() стирал
//        цель: выбор по пину/весам, карусель лечения заново).
// Каждый блок содержит и «контроль старого поведения»: прежняя последовательность фасада на том же
// движке воспроизводит дефект (иначе тест ничего бы не доказывал).
#include "../DebugSnapshot.h"
#include "../HealthLoop.h"
#include "../ServiceEngine.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

struct FakeTunnel : ITunnelControl {
    QString lastUpNodeId;
    int upCalls = 0;
    int downCalls = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ++upCalls;
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &node) override
    {
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return st; }
    bool rebindSocket() override { return false; }
    void down() override { ++downCalls; }
};

static TunnelStats mkStats(qint64 hs, qint64 rx, qint64 tx)
{
    TunnelStats s; s.latestHandshakeEpoch = hs; s.rxBytes = rx; s.txBytes = tx; s.valid = true; return s;
}

static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, const char *endpoint)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": 1.0, "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

static QByteArray subJson(int rev)
{
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 },
        "pool_revision": )") + QByteArray::number(rev) + R"(,
        "nodes": [)" + awgNodeJson("9", 9, "EE", "38.180.164.134:585") + ","
        + awgNodeJson("10", 10, "US", "149.33.7.203:585") + "] }";
}

// Три тика: посев prev + 2 плохих цикла (tx растёт, rx стоит, handshake неизвестен) → DEAD.
static bool feedDead(ServiceEngine &eng, FakeTunnel &tun, qint64 now, qint64 txBase)
{
    tun.st = mkStats(0, 100, txBase + 100);
    eng.tick(now);
    tun.st = mkStats(0, 100, txBase + 200);
    eng.tick(now + 4);
    tun.st = mkStats(0, 100, txBase + 300);
    return eng.tick(now + 8);
}

// Мёртвый data-plane (tx растёт, rx стоит, handshake >180 с) + смена сети каждые 6 с 5 минут,
// тик health каждые 4 с. legacyReset — прежняя последовательность фасада (resetHealthSampling()
// перед noteNetworkChange). Возвращает секунды от первой смены до DEAD/свитча, -1 — не наступил.
static qint64 flappingDeadAfter(bool legacyReset)
{
    ServiceEngine eng;
    FakeTunnel tun;
    eng.setTunnel(&tun);
    QString err;
    CHECK(eng.loadSubscription(subJson(7), err));
    CHECK(eng.connect(err));
    CHECK(eng.onTunnelConnected());
    const qint64 start = 100000;
    const qint64 staleHs = start - 600; // handshake старше 180 с
    qint64 tx = 0;
    qint64 nextChange = start;
    for (qint64 t = start; t < start + 300; t += 4) {
        while (nextChange <= t) {
            if (legacyReset)
                eng.resetHealthSampling();
            facadeNoteNetworkChange(eng, nextChange);
            nextChange += 6;
        }
        tx += 100;
        tun.st = mkStats(staleHs, 100, tx);
        if (eng.tick(t) || eng.state() != EngineState::Connected)
            return t - start;
    }
    return -1;
}

// AVPN Scanner (lane L6b): three locations, EE close, FI medium, US far.
static QByteArray subJson3(int rev)
{
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 },
        "pool_revision": )") + QByteArray::number(rev) + R"(,
        "nodes": [)" + awgNodeJson("9", 9, "EE", "38.180.164.134:585") + ","
        + awgNodeJson("10", 10, "US", "149.33.7.203:585") + ","
        + awgNodeJson("11", 11, "FI", "203.0.113.11:585") + "] }";
}

// The facade's row tap on the engine (AvpnEngineQml::connectToNode): the user-start bookkeeping when the
// tunnel is down, the hint (head = the tapped row), the pin; then reconcile raises it when the intent is on.
// Returns whether connect() ran (the intent rule pinReconnectIntent of the facade).
static bool rowTap(ServiceEngine &eng, const QString &node, const QStringList &after, bool tunnelUp, bool force,
                   qint64 ttlMs = 120000)
{
    const ScannerRowConnect rc = scannerRowConnect(tunnelUp);
    if (rc.userStartBookkeeping)
        eng.beginUserAttempt();
    QStringList hint{node};
    hint << after;
    facadeScanRowHint(eng, hint, ttlMs);
    QString err;
    CHECK(eng.setPinnedNode(node, err));
    const PinReconnectIntent in = pinReconnectIntent(tunnelUp, force);
    if (!in.wantConnected)
        return false;
    if (in.needsRestart) { // reconcile: stop -> Disconnected -> start (guardedStop -> facadeEngineStop)
        facadeEngineStop(eng, false);
        eng.onTunnelDisconnected();
    }
    return eng.connect(err);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --- AVPN Scanner, review F4: VPN off -> row tap -> connect() on the tapped node ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}, {QStringLiteral("11"), 60}});
        // The Scanner's row: forced, so the VPN-off tap really connects - on the far node it named.
        CHECK(rowTap(eng, QStringLiteral("10"), {QStringLiteral("11")}, /*tunnelUp=*/false, scannerRowConnect(false).forceConnect));
        CHECK(tun.upCalls == 1);
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        CHECK(eng.currentNodeId() == QLatin1String("10"));
        // Control: the picker's tap with the VPN off only stores the target (F4: no connect at all).
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson3(7), err));
        CHECK(!rowTap(eng2, QStringLiteral("10"), {}, false, /*force=*/false));
        CHECK(tun2.upCalls == 0);
    }

    // --- AVPN Scanner: VPN on -> row tap -> the ordinary move (stop -> Disconnected -> start), hint kept ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}, {QStringLiteral("11"), 60}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(eng.onTunnelConnected());
        const int downsBefore = tun.downCalls;
        // The tunnel-up tap: requestStop of the restart must not take the hint with it.
        const ScannerRowConnect rc = scannerRowConnect(true);
        CHECK(!rc.userStartBookkeeping);
        facadeScanRowHint(eng, {QStringLiteral("11"), QStringLiteral("10")}, 120000);
        CHECK(eng.setPinnedNode(QStringLiteral("11"), err));
        facadeEngineStop(eng, false);
        tun.down();
        eng.onTunnelDisconnected();
        CHECK(eng.attemptOrder() == (QStringList{QStringLiteral("11"), QStringLiteral("10")}));
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("11"));
        CHECK(tun.downCalls == downsBefore + 1);
        // AWG without a verify phase: Connected = data path over, the hint is gone.
        CHECK(eng.onTunnelConnected());
        CHECK(eng.attemptOrder().isEmpty());
    }

    // --- AVPN Scanner: the ladder takes the next HINTED row, not its own RTT pick ---
    for (const bool withHint : {true, false}) {
        TuningStore::set({}, {}, {}, {});
        qint64 clk = 5'000'000;
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        eng.setNowMsForTest([&clk]() { return clk; });
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}, {QStringLiteral("11"), 60}});
        eng.setVerifyEveryTransport(true); // features.node_scan: every transport passes a data check (§29)
        // Tapped US (10); the visible order after it: FI (11), then EE (9). Without a hint the ladder's own
        // pick after US is EE (best RTT).
        CHECK(rowTap(eng, QStringLiteral("10"), withHint ? QStringList{QStringLiteral("11"), QStringLiteral("9")} : QStringList{},
                     false, true));
        if (!withHint)
            eng.clearAttemptOrder();
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        CHECK(eng.onTunnelConnected());
        // The data check of US failed (verifyFailed -> onDead step 3), the two-phase switch runs.
        CHECK(eng.verifyFailed(QStringLiteral("whoami no data (failover)")));
        eng.onTunnelDisconnected(); // the old runtime is down -> up() on the target
        CHECK(tun.lastUpNodeId == (withHint ? QLatin1String("11") : QLatin1String("9")));
        if (withHint) {
            // FI fails too: the next hinted row (EE), never back to the failed US.
            CHECK(eng.onTunnelConnected());
            CHECK(eng.verifyFailed(QStringLiteral("whoami no data (failover)")));
            eng.onTunnelDisconnected();
            CHECK(tun.lastUpNodeId == QLatin1String("9"));
        }
    }

    // --- AVPN Scanner: the hint lives for one attempt only (TTL, a new user attempt) ---
    {
        TuningStore::set({}, {}, {}, {});
        qint64 clk = 7'000'000;
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        eng.setNowMsForTest([&clk]() { return clk; });
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}, {QStringLiteral("11"), 60}});
        facadeScanRowHint(eng, {QStringLiteral("10"), QStringLiteral("11")}, 120000);
        CHECK(eng.nextCandidate() && eng.nextCandidate()->nodeId == QLatin1String("10"));
        {
            // connect() raises the hint's head (the tapped row) before the pin's location pick: the pin is a
            // location, its best transport may be another row than the one the scan verified.
            ServiceEngine e2;
            FakeTunnel t2;
            e2.setTunnel(&t2);
            CHECK(e2.loadSubscription(subJson3(7), err));
            CHECK(e2.setPinnedNode(QStringLiteral("9"), err));
            facadeScanRowHint(e2, {QStringLiteral("11")}, 120000);
            CHECK(e2.connect(err));
            CHECK(t2.lastUpNodeId == QLatin1String("11"));
            e2.clearAttemptOrder();
            facadeEngineStop(e2, false);
            e2.onTunnelDisconnected();
            CHECK(e2.connect(err));
            CHECK(t2.lastUpNodeId == QLatin1String("9")); // no hint: the pin as before
        }
        clk += 121'000; // past scan_attempt_hint_ttl_s
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}, {QStringLiteral("11"), 60}}); // a fresh round
        CHECK(eng.attemptOrder().isEmpty());
        CHECK(eng.nextCandidate() && eng.nextCandidate()->nodeId == QLatin1String("9")); // the ordinary pick again
        facadeScanRowHint(eng, {QStringLiteral("10")}, 120000);
        CHECK(!eng.attemptOrder().isEmpty());
        eng.beginUserAttempt(); // the orb, a stop, another tap
        CHECK(eng.attemptOrder().isEmpty());
        // A zero TTL or an empty order is no hint.
        facadeScanRowHint(eng, {QStringLiteral("10")}, 0);
        CHECK(eng.attemptOrder().isEmpty());
        facadeScanRowHint(eng, {QString(), QStringLiteral(" ")}, 120000);
        CHECK(eng.attemptOrder().isEmpty());
        // Data passed (verifySucceeded): the attempt is over.
        facadeScanRowHint(eng, {QStringLiteral("10")}, 120000);
        eng.setVerifyEveryTransport(true);
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.isVerifying());
        CHECK(!eng.attemptOrder().isEmpty());
        CHECK(eng.verifySucceeded());
        CHECK(eng.attemptOrder().isEmpty());
    }

    // --- GAP-2: флаппинг сети не глушит DEAD мёртвого туннеля ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        const int grace = healthNetworkGraceSTuned();
        const int cycles = HealthThresholds::fromTuning().cyclesToDead;
        const qint64 deadAfter = flappingDeadAfter(/*legacyReset=*/false);
        CHECK(deadAfter >= 0);
        CHECK(deadAfter <= 2 * grace + (cycles + 1) * 4); // ≤ 2×grace + cyclesToDead тиков
        fprintf(stderr, "GAP-2: dead after %lld s (grace %d, cycles %d)\n",
                (long long) deadAfter, grace, cycles);
        // контроль: прежняя последовательность фасада — DEAD не наступает за 5 минут никогда
        CHECK(flappingDeadAfter(/*legacyReset=*/true) == -1);
    }

    // --- GAP-3: повтор после дедлайна фазы down переподъёма EE сохраняет цель и бюджет лечения ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        for (const bool keep : { true, false }) {
            int ee = 0, targetLost = 0, secondDeadMovedOn = 0, streakKept = 0;
            for (int i = 0; i < 20; ++i) {
                qint64 clk = 1'000'000;
                ServiceEngine eng;
                FakeTunnel tun;
                eng.setTunnel(&tun);
                eng.setNowMsForTest([&clk]() { return clk; });
                QString err;
                eng.loadSubscription(subJson(7), err);
                eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
                eng.connect(err);
                eng.onTunnelConnected();
                clk += 300'000;                          // 5 мин connected: свежий RTT-кэш истёк
                feedDead(eng, tun, 1000, 0);             // шаг 2: переподъём EE, down() отправлен
                clk += 16'000;
                if (!eng.expireSwitch(15000))            // натив молчит: дедлайн фазы down
                    continue;
                const int streakBefore = eng.dataPlaneFailStreak();
                // фасад onSwitchDeadline → guardedStop("switch_deadline", keep) → натив Connected →
                // ... → подтверждённый Disconnected → reconcile → guardedStart → connect()
                facadeEngineStop(eng, keep);
                tun.down();
                eng.onTunnelDisconnected();
                if (!eng.hasInterruptedSwitch())
                    ++targetLost;
                eng.connect(err);
                const QString retryNode = tun.lastUpNodeId;
                if (retryNode == QLatin1String("9"))
                    ++ee;
                if (eng.dataPlaneFailStreak() == streakBefore)
                    ++streakKept;
                // переподъём EE истрачен: следующий DEAD — к другой ноде, а не снова переподъём EE
                eng.onTunnelConnected();
                const int upsBefore = tun.upCalls;
                if (feedDead(eng, tun, 5000, 1000)) {
                    eng.onTunnelDisconnected();
                    if (tun.upCalls > upsBefore && tun.lastUpNodeId != retryNode)
                        ++secondDeadMovedOn;
                }
            }
            fprintf(stderr, "GAP-3 keep=%d: ee=%d target_lost=%d streak_kept=%d second_dead_moved_on=%d\n",
                    int(keep), ee, targetLost, streakKept, secondDeadMovedOn);
            if (keep) {
                CHECK(targetLost == 0);
                CHECK(ee == 20);                         // повтор на цель прерванного свитча — EE
                CHECK(streakKept == 20);
                CHECK(secondDeadMovedOn == 20);             // бюджет лечения не вернулся — нет карусели
            } else {
                // контроль: прежний путь (requestStop) теряет цель и возвращает бюджет лечения
                CHECK(targetLost == 20);
                CHECK(secondDeadMovedOn == 0);                // снова переподъём той же ноды
            }
        }
    }

    if (g_failed) {
        fprintf(stderr, "facade_engine_check: %d/%d FAILED\n", g_failed, g_total);
        return 1;
    }
    printf("facade_engine_check: OK (%d checks)\n", g_total);
    return 0;
}

// --- линк-стабы (как engine_reliability_check / failover_check): сеть и хранилище не нужны ---
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &,
                        SecureAppSettingsRepository *, TrialResponse &, QString &error,
                        FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &,
                                   QByteArray &, QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

void Enrollment::saveLkgSubscription(const QByteArray &) { }

QByteArray Enrollment::loadLkgSubscription()
{
    return {};
}

QString Enrollment::loadToken()
{
    return {};
}

void Enrollment::clearToken() { }

bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &)
{
    return true;
}

} // namespace avpn

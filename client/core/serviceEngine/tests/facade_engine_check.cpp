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

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

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

// AVPN (фикс-волна 2026-09-22, зона CL-A, пробелы критика полноты): последовательности вызовов
// ФАСАДА (AvpnEngineQml) против настоящего ServiceEngine/HealthLoop. Фасад зовёт движок через
// DebugSnapshot.h::facadeNoteNetworkChange — здесь та же функция.
//  GAP-2 (жалоба 3): смена сети каждые 6 с 5 минут при мёртвом data-plane — DEAD наступает
//        (раньше фасад перед noteNetworkChange звал resetHealthSampling() и DEAD не наступал никогда);
//  Scanner rows (path engine): a row is one exact path - raised as it is, never a fallback to another row.
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
    CHECK(eng.onTunnelConnected() && eng.verifySucceeded()); // path engine: Connected after the data check
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

// The facade's row tap on the engine (AvpnEngineQml::connectToNode): the pin of the row and its one exact path (a
// Scanner row never falls back - path engine, design 2026-11-17 §3); then reconcile raises it when the intent is on
// (a live tunnel: the facade's stop, confirmed, then the start). Returns whether connect() ran.
static bool rowTap(ServiceEngine &eng, const QString &node, bool tunnelUp, bool force)
{
    QString err;
    CHECK(eng.setPinnedNode(node, err));
    eng.setUserChoice(path::UserChoice::exactPath(node));
    const PinReconnectIntent in = pinReconnectIntent(tunnelUp, force);
    if (!in.wantConnected)
        return false;
    if (in.needsRestart) { // reconcile: guardedStop -> requestStop -> Disconnected -> start
        eng.requestStop();
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
        // The Scanner's row: forced, so the VPN-off tap really connects - on the far node it named.
        CHECK(rowTap(eng, QStringLiteral("10"), /*tunnelUp=*/false, scannerRowConnect(false).forceConnect));
        CHECK(tun.upCalls == 1);
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        CHECK(eng.currentNodeId() == QLatin1String("10"));
        // Control: the picker's tap with the VPN off only stores the target (F4: no connect at all).
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson3(7), err));
        CHECK(!rowTap(eng2, QStringLiteral("10"), false, /*force=*/false));
        CHECK(tun2.upCalls == 0);
    }

    // --- AVPN Scanner: VPN on -> row tap -> the ordinary move (stop -> Disconnected -> start) on the row ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected() && eng.verifySucceeded());
        const QString first = tun.lastUpNodeId;
        CHECK(!scannerRowConnect(true).userStartBookkeeping);
        const QString row = first == QLatin1String("11") ? QStringLiteral("9") : QStringLiteral("11");
        CHECK(rowTap(eng, row, /*tunnelUp=*/true, true));
        CHECK(tun.lastUpNodeId == row && tun.upCalls == 2);
    }

    // --- AVPN Scanner: a row is one exact path - its failure ends the attempt, no other row is raised ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        qint64 now = 1'800'000'000'000LL;
        eng.setNowMsForTest([&now] { return now; });
        eng.setAttemptTimingsForTest(path::AttemptTimings{});
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        CHECK(rowTap(eng, QStringLiteral("10"), false, true));
        for (int i = 0; i < 12; ++i) { // the start deadline passes: no handshake
            now += 500;
            eng.attemptTick();
        }
        CHECK(eng.onTunnelDisconnected()); // the stop of the row's leg confirmed
        const std::optional<path::AttemptResult> r = eng.takeAttemptResult();
        CHECK(r && r->reason == path::FailReason::ExactNodeFailed && tun.upCalls == 1);
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

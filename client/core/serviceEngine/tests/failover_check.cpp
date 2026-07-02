// AVPN serviceEngine — автономная проверка failover-выбора onDead (фикс «гонка вложенного цикла»).
// Сборка/запуск: core/serviceEngine/tests/build_failover.sh
//
// Требование (CONNECT-INVARIANTS §1): onDead НЕ должен делать I/O — он зовётся из health-tick /
// notifyConnectionLost на GUI-потоке БЕЗ гарда m_inSyncNetCall. Старый Selector::pick крутил
// вложенный QEventLoop TCP-пинга до 3с — окно, в которое queued Disconnected → singleShot(0)
// reconcile входил ПОВЕРХ стека onDead → back-to-back up→down (запрещено §2). При AWG (UDP-only)
// TCP-пинг всё равно почти всегда пуст. Новый порядок = как в connect(): измеренный RTT → weight.
//
// Проверяем: (1) кандидат = нода с минимальным ИЗМЕРЕННЫМ RTT (не weight-фолбэк после TCP-провала);
// (2) выбор мгновенный (< 1.5с; старый код на недостижимых endpoint'ах блокировал ≥3с);
// (3) RU-нода в failover не берётся, пока есть живая не-RU (§14.3), но берётся, когда осталась одна.

#include "../ServiceEngine.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHash>
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

// Туннель-стаб: фиксирует up/down, всегда успешен, статов не отдаёт.
struct FakeTunnel : ITunnelControl {
    QString lastUpNodeId;
    int upCalls = 0;
    int downCalls = 0;
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
    TunnelStats readStats() override { return {}; }
    void down() override { ++downCalls; }
};

// Пул: cur (текущая, «умрёт»), fastA (RTT измерен, weight МЕНЬШЕ), heavyB (weight max, RTT нет),
// ruC (RU, самый быстрый RTT — приманка для проверки RU-фильтра §14.3). Endpoint'ы — блэкхол
// (RFC1918 unroutable): старый TCP-pick висел бы на них до таймаута.
static QByteArray subscriptionJson()
{
    return R"({
      "version": 1,
      "address": ["10.7.0.5/32"],
      "status": "active",
      "expires_at": "2026-09-01T00:00:00Z",
      "traffic": { "used": 0, "limit": 0 },
      "nodes": [
        { "node_id": "cur",    "endpoint": "10.255.255.1:51820", "server_pubkey": "K=", "proto": "awg",
          "weight": 5.0, "country_code": "FI", "allowed_ips": ["0.0.0.0/0", "::/0"] },
        { "node_id": "fastA",  "endpoint": "10.255.255.2:51820", "server_pubkey": "K=", "proto": "awg",
          "weight": 1.0, "country_code": "DE", "allowed_ips": ["0.0.0.0/0", "::/0"] },
        { "node_id": "heavyB", "endpoint": "10.255.255.3:51820", "server_pubkey": "K=", "proto": "awg",
          "weight": 9.0, "country_code": "PL", "allowed_ips": ["0.0.0.0/0", "::/0"] },
        { "node_id": "ruC",    "endpoint": "10.255.255.4:51820", "server_pubkey": "K=", "proto": "awg",
          "weight": 9.0, "country_code": "RU", "allowed_ips": ["0.0.0.0/0", "::/0"] }
      ]
    })";
}

// Поднять движок в Connected на ноде cur (pin → connect → подтверждение туннеля).
static bool bringUpOnCur(ServiceEngine &eng, FakeTunnel &tun, QString &err)
{
    if (!eng.loadSubscription(subscriptionJson(), err))
        return false;
    if (!eng.setPinnedNode(QStringLiteral("cur"), err))
        return false;
    if (!eng.connect(err))
        return false;
    eng.onTunnelConnected();
    return eng.state() == EngineState::Connected && tun.lastUpNodeId == QLatin1String("cur");
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --- 1) failover предпочитает измеренный RTT (не weight) и не делает I/O ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(bringUpOnCur(eng, tun, err));

        QHash<QString, int> rtt;
        rtt.insert(QStringLiteral("fastA"), 50);
        rtt.insert(QStringLiteral("ruC"), 10); // приманка: RU быстрее всех — брать НЕЛЬЗЯ (§14.3)
        eng.setMeasuredRtt(rtt);

        QElapsedTimer timer;
        timer.start();
        CHECK(eng.notifyConnectionLost()); // Connected → onDead(tunnelStillUp=false) → up(кандидат)
        const qint64 elapsedMs = timer.elapsed();

        printf("failover: candidate=%s elapsed=%lldms upCalls=%d\n",
               tun.lastUpNodeId.toUtf8().constData(), (long long) elapsedMs, tun.upCalls);
        CHECK(elapsedMs < 1500);                                  // без вложенного TCP-пинга (старый: ≥3000мс)
        CHECK(tun.lastUpNodeId == QLatin1String("fastA"));        // RTT-приоритет, не weight (heavyB)
        CHECK(eng.currentNodeId() == QLatin1String("fastA"));
        CHECK(tun.downCalls == 0);                                // tunnelStillUp=false → up() сразу, без down()
    }

    // --- 2) кэш RTT пуст → weight-фолбэк (heavyB), RU по-прежнему не берётся ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(bringUpOnCur(eng, tun, err));

        QElapsedTimer timer;
        timer.start();
        CHECK(eng.notifyConnectionLost());
        CHECK(timer.elapsed() < 1500);
        CHECK(tun.lastUpNodeId == QLatin1String("heavyB"));       // max weight среди не-RU
    }

    // --- 3) живых не-RU нет → мягкий RU-fallback обязателен (не «no nodes») ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        // пул из текущей и единственной живой RU
        const QByteArray json = R"({
          "version": 1, "address": ["10.7.0.5/32"], "status": "active",
          "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 0, "limit": 0 },
          "nodes": [
            { "node_id": "cur", "endpoint": "10.255.255.1:51820", "server_pubkey": "K=", "proto": "awg",
              "weight": 5.0, "country_code": "FI", "allowed_ips": ["0.0.0.0/0", "::/0"] },
            { "node_id": "ruC", "endpoint": "10.255.255.4:51820", "server_pubkey": "K=", "proto": "awg",
              "weight": 1.0, "country_code": "RU", "allowed_ips": ["0.0.0.0/0", "::/0"] }
          ]
        })";
        CHECK(eng.loadSubscription(json, err));
        CHECK(eng.setPinnedNode(QStringLiteral("cur"), err));
        CHECK(eng.connect(err));
        eng.onTunnelConnected();

        CHECK(eng.notifyConnectionLost());
        CHECK(tun.lastUpNodeId == QLatin1String("ruC"));          // fallback на RU вместо смерти failover
    }

    if (g_failed) {
        fprintf(stderr, "failover_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("failover_check: OK (%d checks — RTT-приоритет, мгновенно/без I/O, RU-фильтр+fallback)\n", g_total);
    return 0;
}

// --- линк-стабы: сетевые части движка (enroll/fetch) тестом не вызываются, но нужны линкеру,
// т.к. Enrollment.cpp/Identity.cpp сюда не линкуем (тянут secureQSettings/keychain/version.h). ---
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &,
                        SecureAppSettingsRepository *, TrialResponse &, QString &error)
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

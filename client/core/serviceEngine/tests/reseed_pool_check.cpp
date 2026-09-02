// AVPN serviceEngine — автономная проверка reseed пула на живом приложении (волна awg31-xray-v1,
// спека 2026-09-01 §2.3, инвариант §4.4): ServiceEngine::reseedPool применяется ТОЛЬКО в терминале
// (Disconnected/Error) или когда текущая нода (endpoint + server_pubkey / xray uuid) в новом пуле не
// изменилась; иначе откладывается (pending) и применяется при переходе в терминал. Пин ревалидируется
// по локации, RTT-кэш исчезнувших узлов сбрасывается, пустое тело/та же ревизия/нет ревизии — пул
// не затирают. Сборка/запуск: core/serviceEngine/tests/build_reseed_pool.sh.
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"
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

static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, const char *endpoint,
                              const char *pubkey = "K1nDpUbLiCkEyExAmPlE0000000000000000000000=")
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": ")" + pubkey + R"(",
        "proto": "awg", "weight": 1.0, "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

static QByteArray xrayNodeJson(const char *id, int hostId, const char *cc, const char *uuid)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": "203.0.113.10:443", "proto": "xray", "weight": 1.0, "country_code": ")" + cc + R"(",
        "xray_params": { "uuid": ")" + uuid + R"(",
                         "public_key": "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE",
                         "short_id": "a1b2c3d4", "server_name": "vision.example.com",
                         "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                         "network": "tcp", "security": "reality" } })";
}

static QByteArray subJson(const QList<QByteArray> &nodes, int rev)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i) {
        if (i) joined += ",";
        joined += nodes[i];
    }
    QByteArray revPart = rev >= 0 ? (QByteArray(R"("pool_revision": )") + QByteArray::number(rev) + ",") : QByteArray();
    return R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 },
        )" + revPart + R"(
        "nodes": [)" + joined + "] }";
}

static Subscription parse(const QByteArray &json)
{
    Subscription sub;
    QString err;
    if (!SubscriptionParser::parse(json, sub, err))
        fprintf(stderr, "parse error: %s\n", err.toUtf8().constData());
    return sub;
}

static QStringList poolIds(const ServiceEngine &eng)
{
    QStringList ids;
    for (const NodeDebugRow &r : eng.debugSnapshot().pool)
        ids << r.nodeId;
    ids.sort();
    return ids;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    TuningStore::set({}, {{QStringLiteral("xray_client"), true}}, {}, {});

    const QByteArray A = awgNodeJson("A", 1, "FI", "10.0.0.1:585");
    const QByteArray B = awgNodeJson("B", 2, "PL", "10.0.0.2:585");
    const QByteArray C = awgNodeJson("C", 3, "US", "10.0.0.3:585");

    // --- 1) терминал: reseed применяется, ревизия растёт, RTT исчезнувших сбрасывается ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ A, B }, 1), err));
        CHECK(eng.poolRevision() == 1);
        eng.setMeasuredRtt({{QStringLiteral("A"), 10}, {QStringLiteral("B"), 20}});
        CHECK(eng.reseedPool(parse(subJson({ A, C }, 2))) == ReseedResult::Applied);
        CHECK(eng.poolRevision() == 2);
        CHECK(poolIds(eng) == QStringList({QStringLiteral("A"), QStringLiteral("C")}));
        CHECK(eng.measuredRtt().contains(QStringLiteral("A")));
        CHECK(!eng.measuredRtt().contains(QStringLiteral("B")));
        CHECK(!eng.hasPendingReseed());
        CHECK(eng.debugSnapshot().trafficUsed == 5); // счётчики из нового тела
        // та же ревизия / нет ревизии / пустой пул — пул не затирают
        CHECK(eng.reseedPool(parse(subJson({ B }, 2))) == ReseedResult::Rejected);
        CHECK(eng.reseedPool(parse(subJson({ B }, -1))) == ReseedResult::Rejected);
        CHECK(eng.reseedPool(parse(subJson({}, 3))) == ReseedResult::Rejected);
        CHECK(poolIds(eng) == QStringList({QStringLiteral("A"), QStringLiteral("C")}));
        CHECK(eng.poolRevision() == 2);
        // switchLog фиксирует reseed
        bool logged = false;
        for (const QString &l : eng.switchLog())
            if (l.contains(QLatin1String("reseed")))
                logged = true;
        CHECK(logged);
    }

    // --- 2) подключены: текущая нода не изменилась → применяем сразу; изменилась → откладываем ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ A, B }, 1), err));
        CHECK(eng.setPinnedNode(QStringLiteral("A"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected() && eng.state() == EngineState::Connected);
        CHECK(eng.currentNodeId() == QLatin1String("A"));
        // A не изменилась (endpoint + pubkey те же), B ушла, C пришла → Applied на живом туннеле
        CHECK(eng.reseedPool(parse(subJson({ A, C }, 2))) == ReseedResult::Applied);
        CHECK(eng.state() == EngineState::Connected);
        CHECK(eng.currentNodeId() == QLatin1String("A"));
        CHECK(poolIds(eng) == QStringList({QStringLiteral("A"), QStringLiteral("C")}));
        // A сменила endpoint → Deferred: пул прежний, pending взведён
        const QByteArray A2 = awgNodeJson("A", 1, "FI", "10.0.0.99:585");
        CHECK(eng.reseedPool(parse(subJson({ A2, C }, 3))) == ReseedResult::Deferred);
        CHECK(eng.hasPendingReseed());
        CHECK(eng.debugSnapshot().reseedPending);
        CHECK(eng.poolRevision() == 2);
        CHECK(!eng.applyPendingReseed()); // всё ещё подключены к изменившейся ноде
        // терминал → применяется
        eng.requestStop();
        CHECK(eng.applyPendingReseed());
        CHECK(eng.poolRevision() == 3);
        CHECK(!eng.hasPendingReseed());
        CHECK(!eng.applyPendingReseed()); // повторно нечего
        // A сменила pubkey → тоже «изменилась»
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        const QByteArray A3 = awgNodeJson("A", 1, "FI", "10.0.0.99:585", "NEWPUBKEY00000000000000000000000000000000000=");
        CHECK(eng.reseedPool(parse(subJson({ A3, C }, 4))) == ReseedResult::Deferred);
        // Disconnected-терминал → pending остаётся до явного applyPendingReseed (зовёт фасад через singleShot)
        CHECK(eng.onTunnelDisconnected());
        CHECK(eng.hasPendingReseed());
        CHECK(eng.applyPendingReseed());
        CHECK(eng.poolRevision() == 4);
        // текущая нода ИСЧЕЗЛА из нового пула → Deferred (не рвём живой туннель)
        CHECK(eng.setPinnedNode(QStringLiteral("A"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.reseedPool(parse(subJson({ C }, 5))) == ReseedResult::Deferred);
        CHECK(eng.onTunnelError());
        CHECK(eng.applyPendingReseed());
        CHECK(poolIds(eng) == QStringList{QStringLiteral("C")});
        // pin на исчезнувшую локацию снят
        CHECK(eng.pinnedNodeId().isEmpty());
        // более новая ревизия перекрывает pending; loadSubscription (bootstrap) сбрасывает pending
        CHECK(eng.setPinnedNode(QStringLiteral("C"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        const QByteArray C2 = awgNodeJson("C", 3, "US", "10.0.0.33:585");
        CHECK(eng.reseedPool(parse(subJson({ C2 }, 6))) == ReseedResult::Deferred);
        CHECK(eng.reseedPool(parse(subJson({ C2, A }, 7))) == ReseedResult::Deferred);
        CHECK(eng.loadSubscription(subJson({ C, A }, 8), err));
        CHECK(!eng.hasPendingReseed());
        CHECK(eng.poolRevision() == 8);
    }

    // --- 3) ревалидация pin по локации ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ A, B }, 1), err));
        CHECK(eng.setPinnedNode(QStringLiteral("B"), err));
        // B (host 2) ушла, пришла B2 того же хоста → pin переезжает на B2
        const QByteArray B2 = awgNodeJson("B2", 2, "PL", "10.0.0.22:585");
        CHECK(eng.reseedPool(parse(subJson({ A, B2 }, 2))) == ReseedResult::Applied);
        CHECK(eng.pinnedNodeId() == QLatin1String("B2"));
        CHECK(eng.pinnedLocation() == QLatin1String("h:2"));
        // локация исчезла целиком → pin снят
        CHECK(eng.reseedPool(parse(subJson({ A }, 3))) == ReseedResult::Applied);
        CHECK(eng.pinnedNodeId().isEmpty());
    }

    // --- 4) xray: текущая нода сравнивается по uuid ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        const QByteArray X = xrayNodeJson("X", 9, "EE", "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f");
        CHECK(eng.loadSubscription(subJson({ X, A }, 1), err));
        CHECK(eng.setPinnedNode(QStringLiteral("X"), err));
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("X"));
        CHECK(eng.onTunnelConnected() && eng.state() == EngineState::Verifying);
        CHECK(eng.verifySucceeded() && eng.state() == EngineState::Connected);
        // тот же uuid → Applied
        CHECK(eng.reseedPool(parse(subJson({ X, B }, 2))) == ReseedResult::Applied);
        CHECK(eng.currentNodeId() == QLatin1String("X"));
        // новый uuid (перевыпуск binding) → Deferred
        const QByteArray X2 = xrayNodeJson("X", 9, "EE", "11111111-2222-4333-8444-555555555555");
        CHECK(eng.reseedPool(parse(subJson({ X2, B }, 3))) == ReseedResult::Deferred);
        // в Verifying тоже не применяем (не терминал)
        eng.requestStop();
        CHECK(eng.applyPendingReseed());
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected() && eng.state() == EngineState::Verifying);
        const QByteArray X3 = xrayNodeJson("X", 9, "EE", "22222222-2222-4333-8444-555555555555");
        CHECK(eng.reseedPool(parse(subJson({ X3, B }, 4))) == ReseedResult::Deferred);
        CHECK(!eng.applyPendingReseed());
    }

    if (g_failed) {
        fprintf(stderr, "reseed_pool_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("reseed_pool_check: OK (%d checks — терминал/подключены/pending, ревизии, pin по локации, RTT-кэш, xray uuid)\n",
           g_total);
    return 0;
}

// --- линк-стабы (как failover_check) ---
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

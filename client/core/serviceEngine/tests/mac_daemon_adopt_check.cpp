// AVPN (round mac-C, 25.11.2026, defect 2): a session the macOS GUI adopts from the root daemon after a restart is a
// session like one it started (DaemonAdoptHint.h). The device round: quit on AmneziaWG, relaunch ("[adopt] daemon holds a
// live tunnel"), mode -> Xray: nothing happened for 20 s (the same amneziawg-go, the exit country unchanged) until the
// user pressed stop and connect. Cause: the adoption gave the engine no hint, so the session had no node and no
// transport; decidePinOnTransportMode read the unknown transport as "no mismatch".
//   1. the daemon's status reply -> the hint (AmneziaWG, the peer's endpoint), an older daemon's (no endpoint);
//   2. on the real ServiceEngine: the hint names the node by its endpoint (the facade's call order: adopt with the
//      hint, then tryIdentifyCurrentNode), the node's transport is AmneziaWG, and the mode decision restarts the
//      session for Xray - as for a session the GUI started;
//   3. the adoption without a hint (what the facade did before, and still does with an older daemon): no node - the
//      decision on the engine's transport alone keeps the session (the defect), the daemon's transport restarts it;
//   4. an Xray session the GUI started is never taken for AmneziaWG (the fallback reads only daemon-adopted sessions).
// Wiring of the facade and the daemon: tests/check_mac_daemon_adopt_wiring.sh. Run by build_mac_daemon_adopt.sh.
#include "../DaemonAdoptHint.h"
#include "../DebugSnapshot.h"
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;
#define CHECK(expr)                                                                                                    \
    do {                                                                                                               \
        ++g_total;                                                                                                     \
        if (!(expr)) {                                                                                                 \
            ++g_failed;                                                                                                \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                                          \
        }                                                                                                              \
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

static QByteArray awgNode(const char *id, int hostId, const char *cc, const char *endpoint)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": 1.0, "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"], "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57, "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

static QByteArray xrayNode(const char *id, int hostId, const char *cc, const char *endpoint)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "proto": "xray", "weight": 1.0, "country_code": ")" + cc + R"(",
        "xray_params": { "uuid": "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f",
                         "public_key": "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE",
                         "short_id": "a1b2c3d4", "server_name": "vision.example.com",
                         "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                         "network": "tcp", "security": "reality" } })";
}

static QByteArray subJson(const QList<QByteArray> &nodes, int rev)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i)
        joined += (i ? "," : "") + nodes[i];
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-12-31T00:00:00Z", "traffic": { "used": 5, "limit": 0 }, "pool_revision": )")
        + QByteArray::number(rev) + R"(, "nodes": [)" + joined + "] }";
}

static const QByteArray FI = awgNode("11", 11, "FI", "203.0.113.11:585");
static const QByteArray FIX = xrayNode("11:xray", 11, "FI", "203.0.113.11:443");
static const QByteArray DE = awgNode("12", 12, "DE", "203.0.113.12:585");
static const QByteArray DEX = xrayNode("12:xray", 12, "DE", "203.0.113.12:443");

static QJsonObject json(const char *s) { return QJsonDocument::fromJson(QByteArray(s)).object(); }

// The facade's decision on a mode tap (AvpnEngineQml::setTransportMode) for a live session.
static PinModeDecision modeTap(const QString &mode, ServiceEngine &eng, const QString &liveProto)
{
    return decidePinOnTransportMode(mode, eng.pinnedNodeId(), false, true, liveProto);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true}}, {}, {});

    // --- 1. the daemon's status reply -> the hint ---
    {
        const DaemonAdoptHint up = daemonAdoptHintFromStatus(
            json(R"({"type":"status","connected":true,"date":"x","endpoint":"203.0.113.11:585","txBytes":1,"rxBytes":2})"));
        CHECK(up.proto == QLatin1String("awg") && up.endpoint == QLatin1String("203.0.113.11:585"));
        const DaemonAdoptHint older = daemonAdoptHintFromStatus(json(R"({"type":"status","connected":true,"date":"x"})"));
        CHECK(older.proto == QLatin1String("awg") && older.endpoint.isEmpty()); // an older daemon: the transport only
        CHECK(daemonAdoptHintFromStatus(json(R"({"type":"status","connected":false})")).proto.isEmpty());
        CHECK(daemonAdoptHintFromStatus(json(R"({"type":"status","connected":true,"endpoint":"nonsense"})")).endpoint.isEmpty());
        CHECK(daemonAdoptHintFromStatus(json(R"({"type":"status","connected":true,"endpoint":":585"})")).endpoint.isEmpty());
        CHECK(liveSessionTransport(QStringLiteral("xray"), true) == QLatin1String("xray")); // the engine's node wins
        CHECK(liveSessionTransport(QString(), true) == QLatin1String("awg"));
        CHECK(liveSessionTransport(QString(), false).isEmpty());
    }

    // --- 2. the hint names the node; a mode tap to Xray restarts the session like one the GUI started ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({FI, FIX, DE, DEX}, 7), err));
        const DaemonAdoptHint hint = daemonAdoptHintFromStatus(
            json(R"({"type":"status","connected":true,"date":"x","endpoint":"203.0.113.11:585"})"));
        // the facade's order (AvpnEngineQml::tryAdoptObservedTunnel, macOS): adopt with the hint, then name the node
        CHECK(eng.adoptTunnelConnected(QString(), hint.proto, hint.endpoint));
        if (!eng.currentIdentityKnown())
            eng.tryIdentifyCurrentNode();
        CHECK(eng.currentNodeId() == QLatin1String("11")); // by the endpoint: the AmneziaWG node, not 11:xray
        CHECK(eng.currentNodeProto() == QLatin1String("awg"));
        CHECK(eng.isVerifying() && eng.verifySucceeded() && eng.state() == EngineState::Connected);
        CHECK(tun.upCalls == 0 && tun.downCalls == 0); // the adoption itself touches nothing
        const PinModeDecision d = modeTap(QStringLiteral("xray"), eng, liveSessionTransport(eng.currentNodeProto(), true));
        CHECK(d.restartTunnel); // mode -> Xray over a live AmneziaWG session: stop -> Disconnected -> start
        CHECK(!modeTap(QStringLiteral("awg"), eng, liveSessionTransport(eng.currentNodeProto(), true)).restartTunnel);
        CHECK(!modeTap(QStringLiteral("auto"), eng, liveSessionTransport(eng.currentNodeProto(), true)).restartTunnel);
    }

    // --- 3. no hint (before; an older daemon): no node - the engine's transport alone keeps the session (the defect) ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({FI, FIX, DE, DEX}, 7), err));
        CHECK(eng.adoptTunnelConnected());
        CHECK(eng.verifySucceeded() && eng.state() == EngineState::Connected);
        CHECK(!eng.currentIdentityKnown() && eng.currentNodeProto().isEmpty());
        CHECK(!modeTap(QStringLiteral("xray"), eng, eng.currentNodeProto()).restartTunnel); // bce1b3105's input: ignored
        CHECK(modeTap(QStringLiteral("xray"), eng, liveSessionTransport(eng.currentNodeProto(), true)).restartTunnel);
        // the endpoint of a node no longer in the pool: adopted, not named - the transport still holds
        ServiceEngine eng2;
        eng2.setTunnel(&tun);
        CHECK(eng2.loadSubscription(subJson({DE, DEX}, 8), err));
        CHECK(eng2.adoptTunnelConnected(QString(), QStringLiteral("awg"), QStringLiteral("203.0.113.11:585")));
        eng2.tryIdentifyCurrentNode();
        CHECK(!eng2.currentIdentityKnown());
        CHECK(modeTap(QStringLiteral("xray"), eng2, liveSessionTransport(eng2.currentNodeProto(), true)).restartTunnel);
    }

    // --- 4. an Xray session the GUI started: its own transport, never the daemon's ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({FIX}, 7), err)); // the location's Xray path only: the start takes it
        CHECK(eng.setPinnedNode(QStringLiteral("11:xray"), err));
        CHECK(eng.connect(err));
        const bool up = eng.onTunnelConnected();
        CHECK(eng.isVerifying() ? eng.verifySucceeded() : up);
        CHECK(eng.currentNodeProto() == QLatin1String("xray"));
        CHECK(liveSessionTransport(eng.currentNodeProto(), false) == QLatin1String("xray"));
        CHECK(modeTap(QStringLiteral("awg"), eng, liveSessionTransport(eng.currentNodeProto(), false)).restartTunnel);
        CHECK(!modeTap(QStringLiteral("xray"), eng, liveSessionTransport(eng.currentNodeProto(), false)).restartTunnel);
    }

    if (g_failed) {
        fprintf(stderr, "mac_daemon_adopt_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("mac_daemon_adopt_check: OK (%d checks: the daemon's hint names the adopted node, a mode tap restarts it)\n",
           g_total);
    return 0;
}

// --- link stubs (as engine_reliability_check) ---
namespace avpn {
bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &, SecureAppSettingsRepository *, TrialResponse &,
                        QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}
bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &, QByteArray &, QString &error,
                                   FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}
void Enrollment::saveLkgSubscription(const QByteArray &) {}
QByteArray Enrollment::loadLkgSubscription() { return {}; }
QString Enrollment::loadToken() { return {}; }
void Enrollment::clearToken() {}
bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &) { return true; }
} // namespace avpn

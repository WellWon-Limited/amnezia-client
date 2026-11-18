// AVPN path engine, stage 1 integration (design 2026-11-17): the real ServiceEngine with the attempt owner, driven
// the way the facade drives it - connect(), the tunnel callbacks (onTunnelConnected / onTunnelDisconnected /
// onTunnelError), the one data check (verifySucceeded / verifyFailed), the attempt tick, the network, the user's
// stop - against a fake tunnel. It proves what replaced the old mechanisms: the walk over candidates with deadlines
// and one data check, the ledger read by the next start, the failover of a live session as a new attempt (re-up of
// the same node first, then without it), refused provider seats, the user's stop, an exact server, a network change,
// an adopted session judged by its data check, a stop that is never confirmed, and that a user action clears no
// evidence. Build/run: build_path_integration.sh. QtCore/QtNetwork, no event loop needed.
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <cstdio>

using namespace avpn;

static int g_failed = 0, g_total = 0;
#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

struct FakeTunnel : ITunnelControl {
    QStringList ups;
    int downs = 0;
    bool rebindCapable = false;
    int rebindCalls = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ups << node.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &) override { return TunnelResult::success(); }
    TunnelStats readStats() override { return st; }
    bool rebindSocket() override { ++rebindCalls; return rebindCapable; }
    void down() override { ++downs; }
};

static QByteArray awg(const char *id, int host, const char *cc, const char *endpoint, double weight = 1.0,
                      bool manual = false)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(host)
         + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": )" + QByteArray::number(weight) + R"(, "country_code": ")" + cc + R"(",
        "manual_only": )" + (manual ? "true" : "false") + R"(, "allowed_ips": ["0.0.0.0/0", "::/0"],
        "dns": ["1.1.1.1"], "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57, "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}
static QByteArray xray(const char *id, int host, const char *cc, const char *endpoint)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(host)
         + R"(, "endpoint": ")" + endpoint + R"(", "proto": "xray", "weight": 1.0, "country_code": ")" + cc + R"(",
        "xray_params": { "uuid": "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f",
                         "public_key": "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE", "short_id": "a1b2c3d4",
                         "server_name": "vision.example.com", "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                         "network": "tcp", "security": "reality" } })";
}
static QByteArray sub(const QList<QByteArray> &nodes, int rev = 1)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i)
        joined += (i ? "," : "") + nodes[i];
    return R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active", "expires_at": "2027-09-01T00:00:00Z",
        "traffic": { "used": 0, "limit": 0 }, "pool_revision": )" + QByteArray::number(rev) + R"(, "nodes": [)" + joined + "] }";
}

// The engine, its fake tunnel and a test clock; the attempt numbers of the defaults.
struct Rig {
    ServiceEngine eng;
    FakeTunnel tun;
    qint64 now = 1'800'000'000'000LL;
    QStringList journal;
    Rig(const QByteArray &json)
    {
        eng.setTunnel(&tun);
        eng.setNowMsForTest([this] { return now; });
        eng.setAttemptTimingsForTest(path::AttemptTimings{});
        QString err;
        if (!eng.loadSubscription(json, err))
            fprintf(stderr, "subscription: %s\n", err.toUtf8().constData());
        path::NetworkObservation home;
        home.medium = path::NetMedium::Wifi;
        home.gateway = QStringLiteral("192.168.1.1");
        home.subnet = QStringLiteral("192.168.1.0/24");
        eng.observeNetwork(home);
    }
    // Let time pass with the facade's 500 ms tick.
    void pass(qint64 ms)
    {
        for (qint64 t = 0; t < ms; t += 500) {
            now += 500;
            eng.attemptTick();
        }
        journal << eng.takeAttemptJournal();
    }
    // What the platform does for a stop the engine asked for (its own down()): Disconnected a bit later.
    void confirmStop()
    {
        now += 300;
        eng.onTunnelDisconnected();
        journal << eng.takeAttemptJournal();
    }
    void up() { now += 1000; eng.onTunnelConnected(); }
    QString last() const { return tun.ups.isEmpty() ? QString() : tun.ups.last(); }
    path::AttemptResult result()
    {
        journal << eng.takeAttemptJournal();
        return eng.takeAttemptResult().value_or(path::AttemptResult{});
    }
    // A leg that never handshakes: its deadline passes, the engine stops it, the stop is confirmed.
    void noHandshake()
    {
        const int downs = tun.downs;
        pass(eng.attemptRunning() ? 5000 : 0);
        if (tun.downs > downs)
            confirmStop();
    }
};

static TunnelStats stats(qint64 hs, qint64 rx, qint64 tx)
{
    TunnelStats s;
    s.latestHandshakeEpoch = hs;
    s.rxBytes = rx;
    s.txBytes = tx;
    s.valid = true;
    return s;
}

static bool journalHas(const QStringList &j, const char *needle)
{
    for (const QString &l : j)
        if (l.contains(QLatin1String(needle)))
            return true;
    return false;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true}}, {}, {});
    const QByteArray pool = sub({ awg("17", 17, "EE", "1.1.1.17:585", 3.0), awg("16", 16, "NL", "1.1.1.16:585", 2.0),
                                  awg("11", 11, "FI", "1.1.1.11:585", 1.0, /*manual=*/true) });

    // 1. The walk: 17 and 16 never handshake, 11 (manual_only, last wave) carries data; the next start is straight.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.eng.attemptRunning() && r.last() == QLatin1String("17"));
        CHECK(r.eng.state() == EngineState::Connecting && r.eng.attemptTotal() == 3 && r.eng.attemptChecked() == 1);
        r.noHandshake();
        CHECK(r.last() == QLatin1String("16") && r.eng.attemptChecked() == 2);
        r.noHandshake();
        CHECK(r.last() == QLatin1String("11"));
        r.up();
        CHECK(r.eng.state() == EngineState::Verifying && r.eng.isVerifying());
        CHECK(r.eng.verifySucceeded(220) && r.eng.state() == EngineState::Connected);
        const path::AttemptResult res = r.result();
        CHECK(res.connected && res.path.id.id == QLatin1String("11") && res.paths == 3 && !r.eng.attemptRunning());
        CHECK(r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("suspect"));
        CHECK(r.eng.pathStateHere(QStringLiteral("11")) == QLatin1String("working"));
        CHECK(r.eng.pathsFailedHere() == (QSet<QString>{ QStringLiteral("17"), QStringLiteral("16") }));
        CHECK(r.eng.bestWorkingPathHere() == QLatin1String("11") && r.eng.pathLedgerDirty());
        CHECK(journalHas(r.journal, "attempt_leg attempt=1") && journalHas(r.journal, "path_outcome")
              && journalHas(r.journal, "outcome=no_handshake") && journalHas(r.journal, "attempt_result attempt=1 net_gen=")
              && journalHas(r.journal, "result=connected"));
        // the user stops: nothing recorded, nothing forgotten
        r.eng.requestStop();
        r.confirmStop();
        CHECK(r.eng.state() == EngineState::Disconnected && r.eng.pathStateHere(QStringLiteral("11")) == QLatin1String("working"));
        // «Авто» / a new start: straight to the proven path (the remembered node of this network)
        r.eng.setUserChoice(path::UserChoice::automatic());
        CHECK(r.eng.nextCandidate() && r.eng.nextCandidate()->nodeId == QLatin1String("11"));
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("11"));
        r.up();
        CHECK(r.eng.verifySucceeded() && r.result().paths == 1);
        // the ledger survives a restart of the app (persisted JSON)
        ServiceEngine again;
        again.loadPathLedger(r.eng.pathLedgerJson());
        QString e2;
        again.loadSubscription(pool, e2);
        path::NetworkObservation home;
        home.medium = path::NetMedium::Wifi;
        home.gateway = QStringLiteral("192.168.1.1");
        home.subnet = QStringLiteral("192.168.1.0/24");
        again.observeNetwork(home);
        CHECK(again.pathStateHere(QStringLiteral("11")) == QLatin1String("working"));
    }

    // 2. A data check that fails: recorded, the leg goes down, the next path comes up; the data check of the live
    //    session (the extension's re-check) failing is a lost live session - a failover attempt without that node.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
        r.up();
        CHECK(r.eng.verifyFailed(QStringLiteral("whoami no data")) && r.tun.downs == 1 && r.eng.state() == EngineState::Switching);
        r.confirmStop();
        CHECK(r.last() == QLatin1String("16") && r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("suspect"));
        r.up();
        CHECK(r.eng.verifySucceeded() && r.eng.state() == EngineState::Connected);
        r.result();
        CHECK(r.eng.reenterVerifying() && r.eng.isVerifying());
        CHECK(r.eng.verifyFailed(QStringLiteral("extension no data")) && r.eng.attemptRunning());
        r.confirmStop();
        CHECK(r.last() == QLatin1String("11")); // not 16 again (proven dead here), 17 failed earlier: the last wave
        CHECK(r.eng.pathStateHere(QStringLiteral("16")) == QLatin1String("suspect"));
    }

    // 3. Health DEAD of the live session: the first does not blame the node (re-up of the same node first); once
    //    its re-up budget is spent the node is recorded and the failover attempt walks on without it.
    {
        TuningStore::set({{QStringLiteral("dead_reup_max_tries"), 1}},
                         {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true}});
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err));
        r.up();
        r.eng.verifySucceeded();
        r.result();
        const auto dead = [&r](qint64 tx) {
            r.tun.st = stats(0, 100, tx + 100);
            r.eng.tick(r.now / 1000);
            r.tun.st = stats(0, 100, tx + 200);
            r.eng.tick(r.now / 1000 + 4);
            r.tun.st = stats(0, 100, tx + 300);
            return r.eng.tick(r.now / 1000 + 8);
        };
        CHECK(dead(0) && r.eng.attemptRunning() && r.tun.downs == 1);
        r.confirmStop();
        CHECK(r.last() == QLatin1String("17")); // re-up of the same node (still proven here)
        r.up();
        r.eng.verifySucceeded();
        r.result();
        r.now += 30000;
        CHECK(dead(1000));
        r.confirmStop();
        CHECK(r.last() == QLatin1String("16") && r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("suspect"));
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true}}, {}, {});
    }

    // 4. A provider seat refused before the tunnel came up: an outcome of the leg (no seat), the walk goes on.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
        r.eng.noteStartRefused(QStringLiteral("17"), QStringLiteral("no_seat"));
        CHECK(r.tun.downs == 1);
        r.eng.onTunnelError(/*tunnelGone=*/false); // the adapter's Error after the refusal: changes nothing more
        r.confirmStop();
        CHECK(r.last() == QLatin1String("16"));
        CHECK(r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("dead")); // a short cooldown, not the ladder
    }

    // 5. The user stops in the middle of a start: one terminal result, nothing recorded.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err));
        r.pass(1000);
        r.eng.requestStop();
        CHECK(r.tun.downs == 0); // the facade takes the tunnel down itself (its stop protocol)
        r.confirmStop();
        const path::AttemptResult res = r.result();
        CHECK(!res.connected && res.reason == path::FailReason::StoppedByUser && !r.eng.pathLedgerDirty());
        CHECK(r.eng.state() == EngineState::Disconnected && r.tun.ups.size() == 1);
    }

    // 6. An exact server never falls back; a server the mode cannot serve is refused by the pin (the facade then
    //    switches the mode to Auto - decision 9 of 18.11).
    {
        Rig r(sub({ awg("17", 17, "EE", "1.1.1.17:585"), awg("16", 16, "NL", "1.1.1.16:585"),
                    xray("16x", 16, "NL", "2.2.2.16:443") }));
        r.eng.setUserChoice(path::UserChoice::exactPaths({ QStringLiteral("16"), QStringLiteral("16x") }));
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("16"));
        r.noHandshake();
        CHECK(r.last() == QLatin1String("16x"));
        r.noHandshake();
        const path::AttemptResult res = r.result();
        CHECK(res.reason == path::FailReason::ExactNodeFailed && r.tun.ups.size() == 2 && r.eng.state() == EngineState::Error);
        r.eng.setTransportMode(TransportMode::Awg);
        r.eng.setUserChoice(path::UserChoice::exactPath(QStringLiteral("16x")));
        CHECK(!r.eng.connect(err) && err == QLatin1String("exact_unavailable")); // the mode is stronger: not started
        CHECK(r.tun.ups.size() == 2);
        r.eng.setTransportMode(TransportMode::Auto);
    }

    // 7. A network change in the middle of a start: the leg goes down unrecorded, the attempt starts over on the
    //    new network (its own evidence), late answers of the old leg change nothing.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
        r.pass(1000);
        path::NetworkObservation lte;
        lte.medium = path::NetMedium::Cellular;
        lte.carrier = QStringLiteral("250-01");
        lte.radio = QStringLiteral("lte");
        const quint64 genBefore = r.eng.network().generation;
        r.eng.observeNetwork(lte);
        CHECK(r.eng.network().generation == genBefore + 1 && r.tun.downs == 1);
        r.confirmStop();
        CHECK(r.last() == QLatin1String("17") && r.tun.ups.size() == 2); // 17 again: nothing is known on cellular
        r.up();
        r.eng.verifySucceeded();
        CHECK(r.result().connected && r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("working"));
        CHECK(!r.eng.pathLedgerJson().contains("wifi:")); // the Wi-Fi leg was cut, not recorded
    }

    // 8. A live tunnel found at launch: adopted as a leg, one data check decides; no data -> the attempt walks on.
    {
        Rig r(pool);
        CHECK(r.eng.adoptTunnelConnected(QStringLiteral("16"), QStringLiteral("awg"), QStringLiteral("1.1.1.16:585")));
        CHECK(r.eng.isVerifying() && r.eng.attemptRunning() && r.tun.ups.isEmpty());
        CHECK(r.eng.verifySucceeded() && r.eng.state() == EngineState::Connected && r.result().connected);
        Rig q(pool);
        q.eng.adoptTunnelConnected(QStringLiteral("16"), QStringLiteral("awg"), QStringLiteral("1.1.1.16:585"));
        CHECK(q.eng.verifyFailed(QStringLiteral("no data")) && q.tun.downs == 1);
        q.confirmStop();
        CHECK(q.last() == QLatin1String("17") && q.eng.pathStateHere(QStringLiteral("16")) == QLatin1String("suspect"));
    }

    // 9. A stop that is never confirmed does not block the walk; nothing is recorded for it.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err));
        r.pass(5000);   // 17's deadline: stopped
        CHECK(r.tun.downs == 1 && r.tun.ups.size() == 1);
        r.pass(10500);  // no Disconnected ever came: the stop deadline passed
        CHECK(r.tun.ups.size() == 2 && r.last() == QLatin1String("16") && journalHas(r.journal, "attempt_stop_unconfirmed"));
    }

    // 10. A pool body deferred while connected is applied between two legs (GAP-1): the next leg reads it.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
        Subscription next;
        QString perr;
        SubscriptionParser::parse(sub({ awg("17", 17, "EE", "1.1.1.17:586", 3.0), awg("16", 16, "NL", "1.1.1.16:585", 2.0) }, 2),
                                  next, perr);
        CHECK(r.eng.reseedPool(next) == ReseedResult::Deferred);
        r.pass(5000);
        r.confirmStop();
        CHECK(!r.eng.hasPendingReseed() && r.eng.nodeById(QStringLiteral("17"))->endpoint == QLatin1String("1.1.1.17:586"));
        CHECK(r.last() == QLatin1String("16"));
    }

    // 11. Nothing to raise: an honest error at once (no candidate for the mode).
    {
        Rig r(sub({ xray("16x", 16, "NL", "2.2.2.16:443") }));
        r.eng.setTransportMode(TransportMode::Awg);
        QString err;
        CHECK(!r.eng.connect(err) && err.startsWith(QLatin1String("no_transport")) && r.tun.ups.isEmpty());
        CHECK(r.eng.state() == EngineState::Error && !r.eng.attemptRunning());
        r.eng.setTransportMode(TransportMode::Auto);
    }

    std::printf("path_integration_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed ? 1 : 0;
}

// --- link stubs (no network in this test) ---
namespace avpn {
bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &, SecureAppSettingsRepository *,
                        TrialResponse &, QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}
bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &, QByteArray &,
                                   QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}
void Enrollment::saveLkgSubscription(const QByteArray &) { }
QByteArray Enrollment::loadLkgSubscription() { return {}; }
QString Enrollment::loadToken() { return {}; }
void Enrollment::clearToken() { }
bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &) { return true; }
} // namespace avpn

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
    TunnelStats readStats() override { return st; }
    bool rebindSocket() override { ++rebindCalls; return rebindCapable; }
    void down() override { ++downs; }
};

// Stage 2: a probe host double - records what the race asked; the test answers through onProbeResult.
struct FakeProber : path::IPathProber {
    bool on = true;
    bool ready = true;      // the session of the host is in hand
    bool preparing = false; // it is being fetched
    int prepares = 0;       // prepare() calls (the manifest fetch of the real host starts there)
    void prepare(const path::NetworkKey &) override { ++prepares; }
    QList<std::pair<path::ProbeStamp, QString>> started;
    int cancels = 0;
    std::function<void(quint64, qint64)> sink; // the engine's byte sink (setSpendSink): the test spends through it
    QList<quint64> endedRaces;        // raceEnded(race) calls
    void setSpendSink(std::function<void(quint64, qint64)> f) override { sink = std::move(f); }
    void raceEnded(quint64 race) override { endedRaces << race; }
    path::ProberCaps caps() const override
    {
        path::ProberCaps c;
        c.available = on;
        c.ready = ready;
        c.preparing = preparing;
        return c;
    }
    void start(const path::ProbeStamp &s, const path::PathCandidate &p, int) override { started.append({ s, p.id.id }); }
    void cancel(const path::ProbeStamp &) override { ++cancels; }
    path::ProbeStamp stampOf(const char *node) const
    {
        for (const auto &e : started)
            if (e.second == QLatin1String(node))
                return e.first;
        return {};
    }
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
        CHECK(!r.eng.reenterVerifying()); // only from Connected (rev-E1): a phase in flight is never thrown back
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

    // 6b. A server of the list is a preference (owner decision of 17.11, coordinator 18.11): its transports first,
    //     then the best available path with the fallback notice; the preference is kept for the next start. A Scanner
    //     row (exact) on the same dead server ends with an honest error instead.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.setPinnedNode(QStringLiteral("16"), err));
        CHECK(r.eng.userChoice().kind == path::UserChoice::Kind::PreferCountry
              && r.eng.userChoice().pathIds == QStringList{ QStringLiteral("16") });
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("16"));
        r.noHandshake();
        CHECK(r.last() == QLatin1String("17")); // the best available after the preferred server
        r.up();
        CHECK(r.eng.verifySucceeded());
        const path::AttemptResult res = r.result();
        CHECK(res.connected && res.fallbackNotice && res.path.id.id == QLatin1String("17"));
        CHECK(r.eng.pinnedNodeId() == QLatin1String("16")); // the preference is kept
        Rig q(pool);
        q.eng.setUserChoice(path::UserChoice::exactPath(QStringLiteral("16")));
        CHECK(q.eng.connect(err) && q.last() == QLatin1String("16"));
        q.noHandshake();
        const path::AttemptResult exact = q.result();
        CHECK(exact.reason == path::FailReason::ExactNodeFailed && q.tun.ups.size() == 1);
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

    // Review of 18.11, E2: a native event of an older leg is obsolete - the facade drops it before any state change
    // (ServiceEngine::nativeEventStale on the native stream marker, ITunnelControl::nativeLegSeen).
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
        const quint64 legA = r.eng.attemptLeg();
        CHECK(r.tun.nativeLegSeen() == legA && !r.eng.nativeEventStale(r.tun.nativeLegSeen()));
        r.now += 200;
        r.eng.onTunnelError(/*tunnelGone=*/true); // A's first error: the walk goes on to B at once
        CHECK(r.last() == QLatin1String("16") && r.eng.attemptLeg() != legA);
        // the duplicate of A's error arrives while the native stream is still at A (the marker of B not back yet)
        CHECK(r.eng.nativeEventStale(legA));
        r.tun.beginNativeOp(legA); // a late marker of A never moves the stream back
        CHECK(r.tun.nativeLegSeen() == r.eng.attemptLeg() && !r.eng.nativeEventStale(r.tun.nativeLegSeen()));
        r.up();
        CHECK(r.eng.verifySucceeded() && r.result().connected && r.eng.currentNodeId() == QLatin1String("16"));
        CHECK(!r.eng.nativeEventStale(legA)); // a live session: every event is its own
    }

    // Review of 18.11, E3: the owner asks for the data check again on the same tunnel (an inconclusive check) - the
    // facade restarts it; nothing recorded, no new start.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err));
        r.up();
        CHECK(r.eng.verifyInconclusive() && r.eng.takeCheckRerun() && r.eng.isVerifying());
        CHECK(r.tun.ups.size() == 1 && r.tun.downs == 0 && r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("unknown"));
        CHECK(r.eng.verifySucceeded() && r.result().connected);
    }

    // Review of 18.11, E7: a live session found while the owner is busy (the native refused our start over its live
    // profile) supersedes the attempt and goes into the owner's Checking - never Connected without its data check.
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.eng.attemptRunning());
        r.eng.requestStop(); // liveSessionFound: the facade cancels its start
        CHECK(r.eng.adoptTunnelConnected(QStringLiteral("16"), QStringLiteral("awg"), QStringLiteral("1.1.1.16:585")));
        CHECK(r.eng.isVerifying() && r.eng.state() != EngineState::Connected && r.eng.attemptRunning());
        CHECK(r.eng.verifySucceeded() && r.eng.state() == EngineState::Connected);
        r.journal << r.eng.takeAttemptJournal();
        CHECK(journalHas(r.journal, "attempt_superseded_by_live_session"));
    }

    // Stage 2 in the engine: no host or the server switch off - stage 1 exactly; with both, the race runs first and
    // the owner starts with the first proven path; the spent bytes go to the one byte ledger.
    {
        Rig r(pool);
        FakeProber prober;
        r.eng.setProber(&prober);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17") && prober.started.isEmpty()); // switch off
    }
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true},
                              {avpn::ServiceEngine::raceFlagKey(), true}}, {}, {});
        Rig r(pool);
        FakeProber prober;
        qint64 charged = 0;
        r.eng.setProber(&prober);
        path::RaceTimings slowHedge;
        slowHedge.hedgeMs = 5000; // this block proves the winner path; the hedge has its own block below
        r.eng.setRaceTimingsForTest(slowHedge);
        r.eng.setProbeBudget([] { return qint64(-1); }, [&charged](qint64 b) { charged += b; });
        QString err;
        CHECK(r.eng.connect(err) && r.eng.attemptRunning() && r.tun.ups.isEmpty() && r.eng.raceRunning());
        r.pass(1000); // the stagger: more probes start
        CHECK(prober.started.size() >= 2);
        prober.sink(prober.started.first().first.race, 70000); // the prober's one byte stream: the hour ledger gets it once (and the race's cap, PathRace)
        CHECK(charged == 70000);
        r.eng.onProbeResult(prober.stampOf("16"), path::PathOutcome::ProbeOk, 70000); // the figure is the journal's only
        CHECK(r.last() == QLatin1String("16") && charged == 70000); // the proven path is the owner's first leg; the result charged nothing
        r.journal << r.eng.takeAttemptJournal();
        CHECK(journalHas(r.journal, "race_winner node=16") && journalHas(r.journal, "source=race"));
        r.up();
        CHECK(r.eng.verifySucceeded() && r.result().connected && !r.eng.raceRunning()); // the race ends with the result
        CHECK(prober.endedRaces.size() == 1); // the prober is told once that the race is over (it ends its host scan)
        // Seventh review, finding 3: the hour ledger gets every byte, the race's cap only its own race's - a stopped race's late
        // spend (its scan still being polled, a seat release in flight) must not use up the next race's cap.
        {
            Rig q(pool);
            FakeProber qp;
            qint64 hour = 0;
            q.eng.setProber(&qp);
            q.eng.setProbeBudget([] { return qint64(-1); }, [&hour](qint64 b) { hour += b; });
            path::RaceTimings slow;
            slow.hedgeMs = 5000;
            q.eng.setRaceTimingsForTest(slow);
            QString e2;
            CHECK(q.eng.connect(e2) && q.eng.raceRunning() && !qp.started.isEmpty());
            const quint64 raceA = qp.started.first().first.race;
            qp.sink(raceA, 1000);
            CHECK(hour == 1000 && q.eng.raceSpentBytes() == 1000);
            CHECK(q.eng.connect(e2));  // a new tap: race A ends, race B begins
            const quint64 raceB = qp.started.last().first.race;
            CHECK(raceB != raceA && q.eng.raceRunning());
            qp.sink(raceA, 7000);      // A's late spend (a closing /netinfo, a seat release)
            CHECK(hour == 8000 && q.eng.raceSpentBytes() == 0); // the hour ledger has it, B's cap does not
            qp.sink(raceB, 500);
            CHECK(hour == 8500 && q.eng.raceSpentBytes() == 500);
            qp.sink(0, 300);           // outside any race (a warm-up fetch): the hour ledger only
            CHECK(hour == 8800 && q.eng.raceSpentBytes() == 500);
        }
        // a stale result of that race changes nothing
        r.eng.onProbeResult(prober.stampOf("17"), path::PathOutcome::ProbeOk, 1000);
        CHECK(r.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("unknown"));
        CHECK(journalHas(r.journal, "race_owner_start why=winner lead=16"));
        CHECK(journalHas(r.journal, "node=16 kind=awg timeout_ms=4500 checked=1/") && journalHas(r.journal, "pick=proof"));
        // No evidence and nothing proven within the race's wait (PathRace.h hedgeAfterMs, 2750 ms by default): the owner
        // starts its first choice blind, the race runs on beside it.
        Rig h(pool);
        FakeProber hp;
        h.eng.setProber(&hp);
        CHECK(h.eng.connect(err) && h.tun.ups.isEmpty() && h.eng.raceRunning() && h.eng.attemptRunning());
        h.pass(2500);
        CHECK(h.tun.ups.isEmpty()); // still waiting for a first proof
        h.pass(500);
        CHECK(h.last() == QLatin1String("17") && h.eng.raceRunning());
        CHECK(journalHas(h.journal, "wait_ms=2750") && journalHas(h.journal, "race_owner_start why=hedge lead=-")
              && journalHas(h.journal, "pick=order"));
        // race_hedge_ms = 0 (the server's switch back to the old hedge): the first choice starts at once, never probed
        Rig h0(pool);
        FakeProber h0p;
        h0.eng.setProber(&h0p);
        path::RaceTimings atOnce;
        atOnce.hedgeMs = 0;
        h0.eng.setRaceTimingsForTest(atOnce);
        CHECK(h0.eng.connect(err) && h0.last() == QLatin1String("17") && h0.eng.raceRunning() && !h0p.stampOf("17").probe);
        // B1: a stop during the race prelude ends the attempt at once (nothing native runs)
        Rig b(pool);
        FakeProber bp;
        b.eng.setProber(&bp);
        b.eng.setRaceTimingsForTest(slowHedge); // a prelude: the owner waits for a proof
        CHECK(b.eng.connect(err) && b.eng.attemptRunning() && b.tun.ups.isEmpty());
        b.eng.requestStop();
        CHECK(!b.eng.attemptRunning() && !b.eng.raceRunning() && !b.eng.ownerHoldsNativeLeg() && b.tun.ups.isEmpty());
        // T1 (device round 6): the leg in its data check has no first byte and the race proved another path - the
        // leg is left at once (nothing recorded) and the proven one comes up; a leg receiving bytes is kept
        Rig t(pool);
        FakeProber tp;
        t.eng.setProber(&tp);
        t.eng.setRaceTimingsForTest(atOnce);
        CHECK(t.eng.connect(err) && t.last() == QLatin1String("17"));
        t.up(); // 17 is up, in its check
        t.eng.noteCheckStarved(false); // receiving: nothing happens even with a proof
        t.pass(500);
        t.eng.onProbeResult(tp.stampOf("16"), path::PathOutcome::ProbeOk, 1000);
        CHECK(t.tun.downs == 0 && t.eng.isVerifying());
        t.eng.noteCheckStarved(true); // no first byte past its share
        CHECK(t.tun.downs == 1);
        t.confirmStop();
        CHECK(t.last() == QLatin1String("16") && t.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("unknown"));
        t.journal << t.eng.takeAttemptJournal();
        CHECK(journalHas(t.journal, "leg_preempted_for_proof node=17 to=16") && journalHas(t.journal, "pick=proof"));
        // A leg raised blind after the race's wait (its own probe proved nothing) yields to a later proof: nothing
        // recorded, the proven path comes up; a leg already up keeps its check.
        Rig y(pool);
        FakeProber yp;
        y.eng.setProber(&yp);
        CHECK(y.eng.connect(err) && y.tun.ups.isEmpty());
        CHECK(yp.stampOf("17").probe != 0); // the first choice is probed while nothing runs
        y.pass(3000);
        CHECK(y.last() == QLatin1String("17") && yp.cancels >= 1); // raised blind: its probe in flight is cancelled
        y.eng.onProbeResult(yp.stampOf("16"), path::PathOutcome::ProbeOk, 1000);
        CHECK(y.tun.downs == 1);
        y.confirmStop();
        CHECK(y.last() == QLatin1String("16") && y.eng.pathStateHere(QStringLiteral("17")) == QLatin1String("unknown"));
        y.journal << y.eng.takeAttemptJournal();
        CHECK(journalHas(y.journal, "leg_preempted_for_proof node=17 to=16"));
        Rig u(pool);
        FakeProber up;
        u.eng.setProber(&up);
        u.eng.setRaceTimingsForTest(atOnce);
        CHECK(u.eng.connect(err) && u.last() == QLatin1String("17"));
        u.up(); // the leg shook hands before the proof
        u.pass(500);
        u.eng.onProbeResult(up.stampOf("16"), path::PathOutcome::ProbeOk, 1000);
        CHECK(u.tun.downs == 0 && u.eng.isVerifying());
        // A leg that is the race's proof (the lead) is not ended by a later proof while it starts.
        Rig l(pool);
        FakeProber lp;
        l.eng.setProber(&lp);
        CHECK(l.eng.connect(err) && l.tun.ups.isEmpty());
        l.pass(500);
        l.eng.onProbeResult(lp.stampOf("16"), path::PathOutcome::ProbeOk, 1000);
        CHECK(l.last() == QLatin1String("16"));
        l.eng.onProbeResult(lp.stampOf("17"), path::PathOutcome::ProbeOk, 1000);
        CHECK(l.tun.downs == 0 && l.tun.ups.size() == 1);
        // no host: stage 1
        Rig q(pool);
        FakeProber off;
        off.on = false;
        q.eng.setProber(&off);
        CHECK(q.eng.connect(err) && q.last() == QLatin1String("17") && off.started.isEmpty());
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true}}, {}, {});
    }

    // Lane C (C1, C3) in the engine: with the direct control plane unreachable, a provider profile without a standby-pack
    // entry is not walked (one journal line per attempt: count and reason; never a path outcome); on a cellular network
    // without proof the white-list provider with a pack entry leads; on Wi-Fi the usual order stays.
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true},
                              {QStringLiteral("upstream_nodes"), true}}, {}, {});
        avpn::upstreamPlatformRuntimeReady().store(true);
        const auto stub = [](const char *id, UpstreamKind kind, bool pack, int prio) {
            SubscriptionNode n;
            n.nodeId = QString::fromLatin1(id);
            n.region = QStringLiteral("upstream");
            n.proto = QStringLiteral("xray");
            UpstreamStub u;
            u.profileId = n.nodeId.mid(3);
            u.kind = kind;
            u.packSourced = pack;
            u.priority = prio;
            n.upstream = u;
            return n;
        };
        const QList<SubscriptionNode> prov = { stub("up:n1", UpstreamKind::Auto, false, 0),
                                               stub("up:w1", UpstreamKind::Whitelist, true, 5) };
        QString err;
        {   // Wi-Fi, control plane unreachable: the non-pack provider is skipped (counted), the usual order leads
            Rig r(pool);
            r.eng.setStandbyCandidates(prov);
            r.eng.setControlPlaneSource([] { return avpn::ApiReach::Unreachable; });
            CHECK(r.eng.connect(err));
            r.journal << r.eng.takeAttemptJournal();
            CHECK(journalHas(r.journal, "paths_skipped reason=no_control count=1"));
            CHECK(r.last() == QLatin1String("17")); // own servers first on an ordinary network
        }
        {   // UNKNOWN: nothing skipped, no line
            Rig r(pool);
            r.eng.setStandbyCandidates(prov);
            CHECK(r.eng.connect(err));
            r.journal << r.eng.takeAttemptJournal();
            CHECK(!journalHas(r.journal, "paths_skipped"));
        }
        {   // cellular, no proof, unreachable: the white-list pack provider leads
            Rig r(pool);
            r.eng.setStandbyCandidates(prov);
            r.eng.setControlPlaneSource([] { return avpn::ApiReach::Unreachable; });
            path::NetworkObservation lte;
            lte.medium = path::NetMedium::Cellular;
            lte.carrier = QStringLiteral("250-01");
            lte.radio = QStringLiteral("lte");
            r.eng.observeNetwork(lte);
            CHECK(r.eng.connect(err));
            r.journal << r.eng.takeAttemptJournal();
            CHECK(r.last() == QLatin1String("up:w1"));
        }
        avpn::upstreamPlatformRuntimeReady().store(false);
    }

    // Device round 19.11 (LTE, first tap after launch): the prober's session was not in hand. The race must not
    // pretend to probe: no probe started, nothing reserved or charged; the session arriving within the race's own wait
    // starts the probes; no session (failed, or not arriving in time) ends the race `no_session` and the owner starts.
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true},
                              {avpn::ServiceEngine::raceFlagKey(), true}}, {}, {});
        QString err;
        {   // not ready, nothing coming: the owner starts at once
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            qint64 charged = 0;
            r.eng.setProber(&p);
            r.eng.setProbeBudget([] { return qint64(-1); }, [&charged](qint64 b) { charged += b; });
            CHECK(r.eng.connect(err) && r.last() == QLatin1String("17") && !r.eng.raceRunning());
            r.journal << r.eng.takeAttemptJournal();
            CHECK(p.started.isEmpty() && charged == 0 && journalHas(r.journal, "race_done reason=no_session proven=0")
                  && !journalHas(r.journal, "race_begin") && !journalHas(r.journal, "race_probe "));
        }
        {   // the session arrives inside the wait: the probes start then, not before
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            p.preparing = true;
            r.eng.setProber(&p);
            CHECK(r.eng.connect(err) && r.eng.attemptRunning() && r.tun.ups.isEmpty() && !r.eng.raceRunning());
            r.pass(1000);
            CHECK(p.started.isEmpty() && r.tun.ups.isEmpty() && !r.eng.raceRunning());
            p.ready = true;
            p.preparing = false;
            r.pass(500);
            CHECK(r.eng.raceRunning() && !p.started.isEmpty() && r.tun.ups.isEmpty());
            r.journal << r.eng.takeAttemptJournal();
            CHECK(journalHas(r.journal, "race_wait_session") && journalHas(r.journal, "race_begin known=-"));
            // the owner's wait for a first proof counts from the tap: it is shortened by the 1.5 s spent waiting
            r.pass(1000);
            CHECK(r.tun.ups.isEmpty());
            r.pass(500);
            CHECK(!r.tun.ups.isEmpty()); // 2750 - 1500 = 1250 ms after the race began, not 2750
        }
        {   // the session does not arrive within the bound: `no_session`, the owner starts, nothing was started
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            p.preparing = true;
            qint64 charged = 0;
            r.eng.setProber(&p);
            r.eng.setProbeBudget([] { return qint64(-1); }, [&charged](qint64 b) { charged += b; });
            CHECK(r.eng.connect(err) && r.tun.ups.isEmpty());
            r.pass(2000);
            CHECK(r.tun.ups.isEmpty());
            r.pass(1500);
            CHECK(r.last() == QLatin1String("17") && !r.eng.raceRunning() && p.started.isEmpty() && charged == 0);
            r.journal << r.eng.takeAttemptJournal();
            CHECK(journalHas(r.journal, "race_done reason=no_session proven=0") && journalHas(r.journal, "race_owner_start why=no_session"));
            p.ready = true; // a late session does not start a race of a tap that moved on
            r.pass(1000);
            CHECK(p.started.isEmpty());
        }
        {   // the fetch failed while waiting: the owner starts at the next tick, not at the bound
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            p.preparing = true;
            r.eng.setProber(&p);
            CHECK(r.eng.connect(err) && r.tun.ups.isEmpty());
            r.pass(500);
            p.preparing = false;
            r.pass(500);
            CHECK(r.last() == QLatin1String("17") && p.started.isEmpty());
        }
        {   // I3: known A starts, the race waits for its session, A fails, B starts: when the session arrives
            // neither B (its tunnel is coming up) nor A is probed - a raised path is never probed, whatever the race state
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            p.preparing = true;
            r.eng.setProber(&p);
            CHECK(r.eng.recordProbeProof(QStringLiteral("17"), QStringLiteral("test")));
            CHECK(r.eng.connect(err) && r.last() == QLatin1String("17") && !r.eng.raceRunning());
            r.up();
            CHECK(r.eng.verifyFailed(QStringLiteral("no data")));
            r.confirmStop();
            CHECK(r.last() == QLatin1String("16") && !r.eng.raceRunning());
            p.ready = true;
            p.preparing = false;
            r.pass(1500);
            CHECK(p.stampOf("16").probe == 0 && p.stampOf("17").probe == 0);
        }
        {   // the session arrives BEFORE A fails: B's probe in flight is cancelled when B starts (the existing rule)
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            p.preparing = true;
            r.eng.setProber(&p);
            CHECK(r.eng.recordProbeProof(QStringLiteral("17"), QStringLiteral("test")));
            CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
            p.ready = true;
            p.preparing = false;
            r.pass(500);
            CHECK(r.eng.raceRunning() && p.stampOf("17").probe == 0);
            const bool bProbed = p.stampOf("16").probe != 0;
            r.up();
            CHECK(r.eng.verifyFailed(QStringLiteral("no data")));
            r.confirmStop();
            CHECK(r.last() == QLatin1String("16") && bProbed && p.cancels >= 1);
        }
        {   // the person stops while the race waits: nothing starts afterwards
            Rig r(pool);
            FakeProber p;
            p.ready = false;
            p.preparing = true;
            r.eng.setProber(&p);
            CHECK(r.eng.connect(err));
            r.eng.requestStop();
            p.ready = true;
            r.pass(3000);
            CHECK(p.started.isEmpty() && r.tun.ups.isEmpty());
        }
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true}}, {}, {});
    }

    // R1 (device round 4): only the server's own answer about a profile is the path's outcome.
    CHECK(ServiceEngine::startFailureOutcome(QStringLiteral("no_seat")) == path::PathOutcome::NoSeat);
    CHECK(ServiceEngine::startFailureOutcome(QStringLiteral("disabled")) == path::PathOutcome::Refused);
    for (const char *ours : { "transport", "rate_limited", "upstream_unavailable", "invalid_request", "envelope",
                              "bridge_refused", "invoke", "signature", "http_502", "standby_unconfirmed", "unknown" })
        CHECK(ServiceEngine::startFailureOutcome(QString::fromLatin1(ours)) == path::PathOutcome::Inconclusive);
    // S6 (device round 5): a tunnel no-data outranks a later probe ok for the Scanner's screen too
    {
        Rig r(pool);
        QString err;
        CHECK(r.eng.connect(err) && r.last() == QLatin1String("17"));
        r.up();
        CHECK(r.eng.verifyFailed(QStringLiteral("no data")));
        CHECK(r.eng.failedInTunnelHere(QStringLiteral("17")));
        CHECK(r.eng.recordProbeProof(QStringLiteral("17"), QStringLiteral("scanner")));
        CHECK(r.eng.failedInTunnelHere(QStringLiteral("17"))); // the probe does not lift it
        CHECK(!r.eng.failedInTunnelHere(QStringLiteral("16")));
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

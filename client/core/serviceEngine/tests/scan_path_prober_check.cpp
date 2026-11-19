// AVPN path engine stage 2: checks of the race's probe host adapter (ScanPathProber.h) against a fake tribe-scan-v1
// host, a fake server side (session, probe seats) and a fake engine. QtCore only; no network, no device.
// Built and run by build_scan_path_prober.sh.
#include "ScanPathProber.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace avpn;

static int g_checks = 0;
static int g_failures = 0;
static const char *g_case = "";

static void check(bool ok, const char *what)
{
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::fprintf(stderr, "FAIL [%s]: %s\n", g_case, what);
    }
}

static void spin(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
}

// --- fakes ------------------------------------------------------------------------------------------------------

struct FakeHost : IScanHost {
    ScanHostAvailability av = ScanHostAvailability::Available;
    QList<QJsonObject> requests;
    QJsonObject caps{{"type", "scan_caps"}, {"version", "tribe-scan-v1"}, {"max_full_concurrent", 4}, {"max_leg_concurrent", 6},
                     {"max_awg_concurrent", 2}, {"can_verify_composite", true}, {"dns_plan", true}, {"reach_stage", true},
                     {"needs_vpn", false}, {"kinds", QJsonArray{"xray_full", "xray_leg", "awg_mini"}}, {"platform", "ios-app"}};
    QHash<QString, bool> scanOpen;
    QHash<QString, QJsonArray> pendingItems; // scan id -> data items to hand out at the next poll
    QHash<QString, bool> doneNext;
    QHash<QString, bool> unknownScan;
    bool refuseAdds = false;
    qint64 seq = 0;

    ScanHostCaps knownCaps() const override { return ScanHostCaps(); }
    ScanHostAvailability availability() const override { return av; }
    QString unavailableReason() const override { return QString(); }
    bool generation(ScanNetSource &) const override { return false; }
    void stopAll() override {}

    QList<QJsonObject> of(const QString &action) const
    {
        QList<QJsonObject> out;
        for (const QJsonObject &r : requests)
            if (r.value("action").toString() == action)
                out << r;
        return out;
    }

    void sendMessage(const QByteArray &request, ReplyFn reply) override
    {
        const QJsonObject o = QJsonDocument::fromJson(request).object();
        requests << o;
        const QString a = o.value("action").toString();
        const QString id = o.value("scan_id").toString();
        QJsonObject r;
        if (a == "scan_caps") {
            r = caps;
        } else if (a == "scan_start") {
            scanOpen.insert(id, true);
            r = QJsonObject{{"type", "scan_ack"}, {"scan_id", id}, {"accepted", o.value("candidates").toArray().size()}, {"mem_mb", 40}};
        } else if (a == "scan_add") {
            const bool ok = scanOpen.value(id) && !refuseAdds;
            r = QJsonObject{{"type", "scan_ack"}, {"scan_id", id}, {"accepted", ok ? o.value("candidates").toArray().size() : 0}, {"mem_mb", 40}};
        } else if (a == "scan_poll") {
            if (unknownScan.value(id)) {
                r = QJsonObject{{"error", "unknown_scan"}, {"scan_id", id}};
            } else {
                const bool done = doneNext.take(id);
                r = QJsonObject{{"type", "scan_progress"}, {"scan_id", id}, {"seq", double(++seq)}, {"phase", done ? "done" : "data"},
                                {"items", pendingItems.take(id)}, {"bytes_spent", 0}, {"bytes_reserved", 0}, {"mem_mb", 41},
                                {"done", done}, {"reason", done ? "complete" : ""}, {"access", QJsonValue::Null},
                                {"access_close", QJsonValue::Null}, {"gen", QJsonValue::Null}};
                if (done) {
                    r.insert("final", true);
                    scanOpen.insert(id, false);
                }
            }
        } else if (a == "scan_cancel") {
            scanOpen.insert(id, false);
            r = QJsonObject{{"type", "scan_ack"}, {"scan_id", id}, {"accepted", 0}, {"mem_mb", 40}};
        } else {
            r = QJsonObject{{"error", "unknown_action"}};
        }
        const QByteArray bytes = QJsonDocument(r).toJson(QJsonDocument::Compact);
        QTimer::singleShot(0, [reply, bytes]() { reply(bytes); });
    }

    // A data item for the candidate whose host id ends with "-<probe>".
    QString hostIdOf(quint64 probe) const
    {
        for (const QJsonObject &rq : requests)
            for (const QJsonValue &v : rq.value("candidates").toArray())
                if (v.toObject().value("id").toString().endsWith(QStringLiteral("-%1").arg(probe)))
                    return v.toObject().value("id").toString();
        return QString();
    }
    QJsonObject candidateOf(quint64 probe) const
    {
        for (const QJsonObject &rq : requests)
            for (const QJsonValue &v : rq.value("candidates").toArray())
                if (v.toObject().value("id").toString().endsWith(QStringLiteral("-%1").arg(probe)))
                    return v.toObject();
        return {};
    }
    QString scanOf(quint64 probe) const // the scan that last took the candidate
    {
        for (int i = requests.size() - 1; i >= 0; --i)
            for (const QJsonValue &v : requests.at(i).value("candidates").toArray())
                if (v.toObject().value("id").toString().endsWith(QStringLiteral("-%1").arg(probe)))
                    return requests.at(i).value("scan_id").toString();
        return QString();
    }
    QStringList partIdsOf(quint64 probe) const
    {
        QStringList out;
        for (const QJsonObject &rq : requests)
            for (const QJsonValue &v : rq.value("candidates").toArray()) {
                const QString id = v.toObject().value("id").toString();
                if ((id.endsWith(QStringLiteral("-%1").arg(probe)) || id.contains(QStringLiteral("-%1.").arg(probe))) && !out.contains(id))
                    out << id;
            }
        return out;
    }
    void itemFor(const QString &id, const QString &scan, bool ok, qint64 spent)
    {
        QJsonObject it{{"id", id}, {"stage", "data"}, {"seq", double(++seq)}, {"error", ok ? "" : "dial"},
                       {"http_status", ok ? 200 : 0}, {"sha_ok", ok}, {"bytes", ok ? 4096 : 0}, {"bytes_requested", 4096},
                       {"duration_ms", 600}, {"ttfb1_ms", 300}, {"rtt_ms", 40}, {"t64_ms", 100}, {"spent_bytes", double(spent)},
                       {"retries", 0}, {"start_ms", 10}, {"end_ms", 610}, {"egress_class", QJsonValue::Null},
                       {"egress_node", QJsonValue::Null}, {"egress_asn", QJsonValue::Null}, {"net_token", QJsonValue::Null}};
        QJsonArray a = pendingItems.value(scan);
        a << it;
        pendingItems.insert(scan, a);
    }
    void item(quint64 probe, bool ok, qint64 spent = 85000)
    {
        QJsonObject it{{"id", hostIdOf(probe)}, {"stage", "data"}, {"seq", double(++seq)}, {"error", ok ? "" : "dial"},
                       {"http_status", ok ? 200 : 0}, {"sha_ok", ok}, {"bytes", ok ? 65536 : 0}, {"bytes_requested", 65536},
                       {"duration_ms", 600}, {"ttfb1_ms", 300}, {"rtt_ms", 40}, {"t64_ms", 100}, {"spent_bytes", double(spent)},
                       {"retries", 0}, {"start_ms", 10}, {"end_ms", 610}, {"egress_class", QJsonValue::Null},
                       {"egress_node", QJsonValue::Null}, {"egress_asn", QJsonValue::Null}, {"net_token", QJsonValue::Null}};
        QJsonArray a = pendingItems.value(scanOf(probe));
        a << it;
        pendingItems.insert(scanOf(probe), a);
    }
};

struct FakeApi : IRaceScanApi {
    bool isConfigured = true;
    bool sessionOk = true;
    int sessions = 0;
    QStringList seatsAsked;
    QList<qint64> seatCosts;
    QStringList released; // a seat whose owner went (production: released by its operation id, also unseen seats)
    bool seatOk = true;
    QString seatCode = QStringLiteral("no_seat"); // the refusal when !seatOk
    QByteArray providerConfig;
    bool holdSeat = false;
    std::function<void(const Seat &)> heldSeat;
    struct FakeSeat : IRaceSeat {
        FakeApi *api = nullptr;
        QString lease;
        ~FakeSeat() override { api->released << lease; }
    };

    bool configured() const override { return isConfigured; }
    void session(const QString &key, std::function<void(const RaceScanSession &)> done) override
    {
        ++sessions;
        RaceScanSession s;
        s.ok = sessionOk;
        s.reason = sessionOk ? QString() : QStringLiteral("manifest_unavailable");
        s.networkKey = key;
        s.token = QStringLiteral("SCANTOKEN");
        s.probeBase = QStringLiteral("https://probe.example");
        s.baseIps = {QStringLiteral("192.0.2.10")};
        s.awgNodes.insert(QStringLiteral("16"), QStringLiteral("10.8.1.1"));
        s.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
        s.bytes = 3000;
        QTimer::singleShot(0, [done, s]() { done(s); });
    }
    std::shared_ptr<IRaceSeat> probeSeat(const QString &profileId, qint64 costBytes, std::function<void(const Seat &)> done,
                                         std::function<void(qint64)>) override
    {
        seatsAsked << profileId;
        seatCosts << costBytes;
        Seat s;
        s.ok = seatOk;
        s.leaseId = seatOk ? QStringLiteral("LEASE-%1").arg(profileId) : QString();
        s.config = QString::fromUtf8(providerConfig);
        s.configSha256 = QString::fromLatin1(QCryptographicHash::hash(providerConfig, QCryptographicHash::Sha256).toHex());
        s.code = seatOk ? QString() : seatCode;
        s.bytes = 2000;
        auto seat = std::make_shared<FakeSeat>();
        seat->api = this;
        seat->lease = QStringLiteral("LEASE-%1").arg(profileId);
        if (holdSeat)
            heldSeat = [done, s](const Seat &) { done(s); };
        else
            QTimer::singleShot(0, [done, s]() { done(s); });
        return seat;
    }
};

struct FakeEngine : IScanEngine {
    QString key = QStringLiteral("wifi:test");
    ScanCurrent current() const override { return ScanCurrent(); }
    ScanNetFacts network() const override
    {
        ScanNetFacts f;
        f.reportingKey = key;
        return f;
    }
    void fillManifestInput(ScanManifestInput &) const override {}
    QString ownProbeConfig(const ScanCandidate &c) const override
    {
        return c.id == QLatin1String("11:xray") ? QStringLiteral(R"({"outbound":{"protocol":"vless","tag":"proxy"},"dns":[]})") : QString();
    }
    QString liveProbeBase(const ScanCurrent &) const override { return QString(); }
    bool reportQueueFull() const override { return false; }
    QString uiLanguage() const override { return QStringLiteral("ru"); }
    bool awgProbeInput(const QString &nodeId, ScanAwgNodeInput &out) const override
    {
        if (nodeId != QLatin1String("16") && nodeId != QLatin1String("17"))
            return false;
        out.privateKey = QString(64, QLatin1Char('1'));
        out.address = QStringLiteral("10.8.1.5/32");
        out.peerPublicKey = QString(64, QLatin1Char('2'));
        out.endpoint = QStringLiteral("198.51.100.16:585");
        return true;
    }
    void userConnectForScan() override {}
    void cancelPendingConnect() override {}
    void connectRow(const QString &, const QStringList &, qint64, bool, bool) override {}
    void startReportCheck(const QString &, const QJsonObject &, bool) override {}
};

static QByteArray providerProfile()
{
    return R"({"inbounds":[{"listen":"127.0.0.1","port":"__TRIBE_SOCKS_PORT__","protocol":"socks",)"
           R"("settings":{"accounts":[{"pass":"__TRIBE_SOCKS_PASS__","user":"__TRIBE_SOCKS_USER__"}],"auth":"password","udp":true},)"
           R"("tag":"tribe-in"}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.31","port":443,)"
           R"("users":[{"encryption":"none","id":"11111111-2222-4333-8444-555555555555"}]}]},"tag":"proxy"},)"
           R"({"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}],)"
           R"("routing":{"rules":[{"ip":["geoip:private"],"outboundTag":"direct"},{"network":"tcp,udp","outboundTag":"proxy"}]}})";
}

struct World {
    FakeHost host;
    FakeApi api;
    FakeEngine engine;
    ScanPathProber prober{&host, &engine, &api};
    struct Result {
        path::ProbeStamp stamp;
        path::PathOutcome outcome;
        qint64 bytes;
    };
    QList<Result> results;
    bool inStart = false;
    bool resultInsideStart = false;
    World()
    {
        api.providerConfig = providerProfile();
        prober.pollIntervalMs = 5;
        prober.xrayBurst = 1; // the single-connection cases; caseBurst checks the burst
        prober.onResult = [this](const path::ProbeStamp &s, path::PathOutcome o, qint64 b) {
            resultInsideStart = resultInsideStart || inStart;
            results << Result{s, o, b};
        };
    }
    void ready()
    {
        prober.warmUp();
        spin(30);
    }
    path::ProbeStamp start(quint64 race, quint64 probe, const QString &id, path::PathKind kind)
    {
        path::PathCandidate c;
        c.id.id = id;
        c.kind = kind;
        const path::ProbeStamp s{race, 1, probe};
        inStart = true;
        prober.start(s, c, 4000);
        inStart = false;
        return s;
    }
    const Result *resultOf(quint64 probe) const
    {
        for (const Result &r : results)
            if (r.stamp.probe == probe)
                return &r;
        return nullptr;
    }
};

static void caseCaps()
{
    g_case = "caps";
    World w;
    check(!w.prober.caps().available, "unavailable before the host's caps are known");
    w.ready();
    const path::ProberCaps c = w.prober.caps();
    check(c.available && c.inFlight == 6 && c.providerAtOnce == 4 && c.awgAtOnce == 2, "the host's pools (in-app: 4 full profiles)");
    check(w.prober.sessionReady() && w.api.sessions == 1, "warm-up fetched the session of the network");
    w.prober.hostBusy = []() { return true; };
    check(!w.prober.caps().available, "the Scanner's own scan owns the host: no race");
    w.prober.hostBusy = nullptr;
    w.host.av = ScanHostAvailability::NeedsVpn;
    check(!w.prober.caps().available, "a host that needs the tunnel (the extension before a tunnel): no race");
    w.host.av = ScanHostAvailability::Available;
    w.api.isConfigured = false;
    check(!w.prober.caps().available, "no session source: no race");
    ScanHostCaps ext;
    ext.maxFullConcurrent = 1;
    ext.maxLegConcurrent = 6;
    ext.maxAwgConcurrent = 2;
    const path::ProberCaps e = scanPathProberCaps(ext, true);
    check(e.inFlight == 6 && e.providerAtOnce == 1, "the extension's pools: one provider profile at a time");
}

static void caseOwnXrayAndJoin()
{
    g_case = "own_xray_join";
    World w;
    w.ready();
    w.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    check(w.results.isEmpty() && !w.resultInsideStart, "nothing comes from inside start()");
    spin(30);
    const QList<QJsonObject> starts = w.host.of("scan_start");
    check(starts.size() == 1, "the first probe opens a host scan");
    const QJsonObject c = w.host.candidateOf(1);
    check(c.value("kind").toString() == "xray_leg" && c.value("config").toString().contains("vless")
              && c.value("reach_at_ms").toInt() == -1 && starts.value(0).value("probe").toObject().value("base").toString() == "https://probe.example",
          "own Xray: a leg with the node's outbound, no reach stage, the session's probe base");
    w.start(1, 2, QStringLiteral("16"), path::PathKind::OwnAwg);
    spin(30);
    check(w.host.of("scan_add").size() == 1 && w.host.of("scan_start").size() == 1, "the next probe of the race joins (scan_add)");
    const QJsonObject a = w.host.candidateOf(2);
    check(a.value("kind").toString() == "awg_mini" && a.value("config").toString().contains("198.51.100.16"), "own AmneziaWG: awg_mini");
    w.host.item(1, true, 85000);
    w.host.item(2, false, 4000);
    spin(40);
    const World::Result *r1 = w.resultOf(1);
    const World::Result *r2 = w.resultOf(2);
    check(r1 && r1->outcome == path::PathOutcome::ProbeOk && r1->bytes == 85000, "a verified digest = probe ok, with its bytes");
    check(r2 && r2->outcome == path::PathOutcome::Inconclusive && r2->bytes == 4000, "a failed probe = not proven, bytes kept");
    check(w.prober.liveProbes() == 0, "nothing left");
}

static void caseRefusedLocally()
{
    g_case = "refused_locally";
    World w;
    w.ready();
    w.start(1, 1, QStringLiteral("17"), path::PathKind::OwnAwg); // not marked awg_probe in the manifest
    w.start(1, 2, QStringLiteral("99:xray"), path::PathKind::OwnXray); // no config
    check(w.results.isEmpty() && !w.resultInsideStart, "never from inside start()");
    spin(30);
    check(w.resultOf(1) && w.resultOf(1)->outcome == path::PathOutcome::Inconclusive, "AmneziaWG without the manifest's mark: not proven");
    check(w.resultOf(2) && w.resultOf(2)->outcome == path::PathOutcome::Inconclusive, "own Xray without a config: not proven");
    check(w.host.of("scan_start").isEmpty(), "nothing reached the host");
}

static void caseProvider()
{
    g_case = "provider";
    World w;
    w.ready();
    w.start(1, 1, QStringLiteral("up:abcdef0123456789"), path::PathKind::Provider);
    spin(30);
    check(w.api.seatsAsked == QStringList{QStringLiteral("abcdef0123456789")}, "one probe seat for the profile");
    const ScanTunables dt;
    check(w.api.seatCosts == QList<qint64>{qint64(dt.costBatchBytes) + dt.costConfigBytes},
          "the seat's request is cut at the price the race paid for it (the batch with its config)");
    check(w.api.released.isEmpty(), "the seat is held while the probe runs");
    const QJsonObject c = w.host.candidateOf(1);
    check(c.value("kind").toString() == "xray_full" && c.value("profile_id").toString() == "abcdef0123456789"
              && c.value("config").toString().contains("192.0.2.31"),
          "provider: a full-profile probe with the seat's config");
    w.host.item(1, true);
    spin(30);
    check(w.resultOf(1) && w.resultOf(1)->outcome == path::PathOutcome::ProbeOk, "proven");
    check(w.api.released == QStringList{QStringLiteral("LEASE-abcdef0123456789")}, "the seat is released with the result");

    World x;
    x.api.seatOk = false;
    x.ready();
    x.start(1, 1, QStringLiteral("up:abcdef0123456789"), path::PathKind::Provider);
    spin(30);
    check(x.resultOf(1) && x.resultOf(1)->outcome == path::PathOutcome::Inconclusive && x.host.of("scan_start").isEmpty(),
          "no seat: not proven, nothing sent");

    // Contract 1.15.0: a resent operation whose seat already ended answers lease_gone - the candidate has no seat:
    // skipped (not proven, never probed), not an error of the batch.
    World g;
    g.api.seatOk = false;
    g.api.seatCode = QStringLiteral("lease_gone");
    g.ready();
    g.start(1, 1, QStringLiteral("up:abcdef0123456789"), path::PathKind::Provider);
    g.start(1, 2, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    check(g.resultOf(1) && g.resultOf(1)->outcome == path::PathOutcome::Inconclusive && g.host.candidateOf(1).isEmpty(),
          "lease_gone: the provider candidate is skipped, nothing probed");
    check(!g.host.candidateOf(2).isEmpty() && !g.resultOf(2), "the race's other probes go on");

    World y;
    y.api.providerConfig = R"({"api":{"tag":"api"},"outbounds":[]})";
    y.ready();
    y.start(1, 1, QStringLiteral("up:abcdef0123456789"), path::PathKind::Provider);
    spin(30);
    check(y.resultOf(1) && y.resultOf(1)->outcome == path::PathOutcome::Inconclusive && y.host.of("scan_start").isEmpty()
              && y.api.released.size() == 1,
          "a profile the connect would refuse is never probed; its seat goes back");
}

static void caseCancel()
{
    g_case = "cancel";
    World w;
    w.ready();
    const path::ProbeStamp s1 = w.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    w.prober.cancel(s1);
    spin(20);
    check(w.host.of("scan_cancel").size() == 1, "nothing of the scan wanted any more: the host scan is cancelled");
    w.host.item(1, true);
    spin(30);
    check(w.results.isEmpty(), "a cancelled probe's result is dropped");

    // Two probes share one host scan; cancelling one must stop exactly that one AT THE HOST (the host has only a
    // per-scan stop: the scan is cancelled and the other probe is re-opened in a new scan), the other still reports.
    World t;
    t.ready();
    t.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(40);
    const path::ProbeStamp a1 = t.start(1, 2, QStringLiteral("16"), path::PathKind::OwnAwg);
    spin(40);
    const QString firstScan = t.host.scanOf(2);
    t.prober.cancel(a1);
    spin(40);
    check(t.host.of("scan_cancel").size() == 1 && t.host.of("scan_cancel").first().value("scan_id").toString() == firstScan,
          "cancel (an AmneziaWG probe) with a neighbour in the scan: the host scan that held it is stopped");
    const QString secondScan = t.host.scanOf(1);
    check(!secondScan.isEmpty() && secondScan != firstScan && t.host.scanOf(2) == firstScan,
          "the still-wanted probe is re-opened in a new scan, the cancelled one is never re-sent");
    t.host.item(1, true);
    spin(40);
    check(t.resultOf(1) && t.resultOf(1)->outcome == path::PathOutcome::ProbeOk && !t.resultOf(2),
          "the neighbour still reports, the cancelled probe does not");

    World x;
    x.api.holdSeat = true;
    x.ready();
    const path::ProbeStamp s = x.start(1, 1, QStringLiteral("up:abcdef0123456789"), path::PathKind::Provider);
    spin(20);
    x.prober.cancel(s);
    x.api.heldSeat(IRaceScanApi::Seat());
    spin(20);
    check(x.api.released == QStringList{QStringLiteral("LEASE-abcdef0123456789")} && x.results.isEmpty() && x.host.of("scan_start").isEmpty(),
          "a seat still asked when the probe is cancelled is released by its owner at once (its operation id), nothing probed");

    FakeApi api; // the prober goes while its provider probe holds a seat: the seat goes with it
    {
        FakeHost host;
        FakeEngine engine;
        api.providerConfig = providerProfile();
        ScanPathProber p(&host, &engine, &api);
        p.pollIntervalMs = 5;
        p.warmUp();
        spin(30);
        path::PathCandidate c;
        c.id.id = QStringLiteral("up:abcdef0123456789");
        c.kind = path::PathKind::Provider;
        p.start(path::ProbeStamp{1, 1, 1}, c, 4000);
        spin(30);
        check(!host.candidateOf(1).isEmpty() && api.released.isEmpty(), "the probe runs with its seat");
    }
    check(api.released == QStringList{QStringLiteral("LEASE-abcdef0123456789")}, "the prober's end releases the seat");
}

static void caseScanReplaced()
{
    g_case = "scan_replaced";
    World w;
    w.ready();
    w.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    w.host.doneNext.insert(w.host.scanOf(1), true); // the engine closes the scan (every candidate final)
    w.host.item(1, true);
    spin(30);
    check(w.resultOf(1) && w.resultOf(1)->outcome == path::PathOutcome::ProbeOk, "the first result");
    w.start(1, 2, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    check(w.host.of("scan_start").size() == 2, "a closed scan: the next probe opens a new one");

    World x;
    x.ready();
    x.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    x.host.refuseAdds = true; // the engine took no candidate (its scan closed meanwhile)
    x.start(1, 2, QStringLiteral("16"), path::PathKind::OwnAwg);
    spin(30);
    check(x.host.of("scan_start").size() == 2 && x.host.scanOf(2) != x.host.scanOf(1), "a refused add goes into a new scan");

    World y;
    y.ready();
    y.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    y.host.unknownScan.insert(y.host.scanOf(1), true); // a Scanner start replaced it
    spin(30);
    check(y.resultOf(1) && y.resultOf(1)->outcome == path::PathOutcome::Inconclusive, "unknown scan: its probes are not proven");

    World z;
    z.ready();
    z.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    z.start(2, 2, QStringLiteral("11:xray"), path::PathKind::OwnXray); // a new race
    spin(30);
    check(z.host.of("scan_start").size() == 2, "a new race opens its own scan");
}

static void caseSession()
{
    g_case = "session";
    World w;
    w.api.sessionOk = false;
    w.ready();
    w.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    check(w.resultOf(1) && w.resultOf(1)->outcome == path::PathOutcome::Inconclusive && w.host.of("scan_start").isEmpty(),
          "no session (scanner off / offline): not proven, the owner walks");

    World x; // no warm-up: the first probe waits for the session
    x.prober.warmUp();
    check(!x.prober.sessionReady(), "fetching");
    x.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(40);
    check(x.host.of("scan_start").size() == 1 && x.api.sessions == 1, "the probe waited for the one fetch");
    x.start(2, 2, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(30);
    check(x.api.sessions == 1, "a fresh session is reused by the next race");
    x.engine.key = QStringLiteral("cell:other");
    check(!x.prober.sessionReady(), "another network: the session is not fresh");
    x.start(3, 3, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(40);
    check(x.api.sessions == 2, "fetched for the new network");

    RaceScanSession s;
    s.ok = true;
    s.networkKey = QStringLiteral("k");
    s.token = QStringLiteral("t");
    s.probeBase = QStringLiteral("https://b");
    s.expiresAtMs = 1000000;
    check(scanPathSessionFresh(s, QStringLiteral("k"), 1000000 - 61000, 0) && !scanPathSessionFresh(s, QStringLiteral("k"), 1000000 - 59000, 0),
          "fresh until 60 s before the token expires");
}


static void caseBurst()
{
    g_case = "xray_burst";
    for (const bool partFails : {false, true}) {
        World w;
        w.prober.xrayBurst = 4;
        w.ready();
        w.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
        spin(40);
        const QStringList parts = w.host.partIdsOf(1);
        check(parts.size() == 4, "own Xray goes out as 4 parallel connections");
        int small = 0;
        for (const QJsonObject &rq : w.host.requests)
            for (const QJsonValue &v : rq.value("candidates").toArray())
                small += v.toObject().value("bytes").toInt() == kScanXrayBurstBytes ? 1 : 0;
        check(small == 3, "the burst's extra connections carry small bodies");
        const QString scan = w.host.scanOf(1);
        for (int i = 0; i < parts.size(); ++i) {
            w.host.itemFor(parts.at(i), scan, !(partFails && i == 2), 10000);
            spin(15);
            if (i < parts.size() - 1)
                check(w.results.isEmpty(), "no verdict before every part answered");
        }
        spin(30);
        const World::Result *r = w.resultOf(1);
        check(r && r->bytes == 40000, "the burst's bytes are summed");
        check(r && r->outcome == (partFails ? path::PathOutcome::Inconclusive : path::PathOutcome::ProbeOk),
              partFails ? "one part without its body: not proven (the tunnel's burst would stall)" : "every part through: proven");
    }
}

// F5 of device round 19.11 (two of three LTE races spent 0.28 MB against the 256 KB cap): the race pays a probe's
// projection before it starts it, so the projection must cover what the prober really sends - every burst part's
// cost on the wire plus the scan's access check; one own Xray probe measured 92 723 B on the iPhone.
static void caseCosts()
{
    g_case = "race_costs";
    World w;
    w.prober.xrayBurst = 4;
    w.ready();
    w.start(1, 1, QStringLiteral("11:xray"), path::PathKind::OwnXray);
    spin(40);
    qint64 parts = 0;
    for (const QJsonObject &rq : w.host.requests)
        for (const QJsonValue &v : rq.value("candidates").toArray())
            parts += qint64(v.toObject().value("cost_bytes").toDouble());
    const path::PathRace::Costs c = w.prober.costs();
    check(parts > 0 && c.xray >= parts, "own Xray: the projection covers every burst part the prober sends");
    check(c.xray >= 92723, "own Xray: at least what one race probe measured on the device");
    const ScanTunables t;
    check(c.awg >= qint64(t.warmBytes) + ScanPathProber::kRaceProbeBytes, "AmneziaWG: the race's body and more");
    check(c.provider >= qint64(t.warmBytes) + ScanPathProber::kRaceProbeBytes + t.costBatchBytes + t.costConfigBytes,
          "provider: the data connection and the seat batch with its config");
    w.prober.xrayBurst = 1;
    check(w.prober.costs().xray < c.xray, "one connection costs less than the burst");

    // Device round 19.11 + prod after gzip (PR #639): a one-profile batch answer with its config is 7.3-12.6 KB on the
    // wire (the HTTP layer counts wire bytes). At 32 KiB per config a provider probe is 107 520 B: one own Xray probe
    // (116 736 B) and one provider probe fit one cellular race (262 144 B) together; at the old 256 KiB price
    // (336 896 B) a provider never took part on cellular.
    const path::PathRace::Costs d = ScanPathProber::raceCosts(ScanTunables(), kScanXrayBurstParts);
    check(d.provider == 107520 && d.xray == 116736, "the compiled prices: provider 107 520 B, own Xray 116 736 B");
    check(d.xray + d.provider <= path::RaceTimings().cellularMaxBytes, "one own Xray and one provider probe fit one cellular race");
    const ScanTunables old = ScanTunables::fromNumbers({{QStringLiteral("scan_cost_config_bytes"), 262144}});
    check(old.costConfigBytes == 262144 && ScanPathProber::raceCosts(old, kScanXrayBurstParts).provider == 336896,
          "a server that still publishes 256 KiB is taken as published (inside the client's range)");
    check(ScanTunables::fromNumbers({{QStringLiteral("scan_cost_config_bytes"), 8192}}).costConfigBytes == 16384,
          "the floor: 16 KiB");
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    caseCaps();
    caseOwnXrayAndJoin();
    caseRefusedLocally();
    caseProvider();
    caseCancel();
    caseScanReplaced();
    caseSession();
    caseBurst();
    caseCosts();
    if (g_failures) {
        std::fprintf(stderr, "scan path prober check: %d of %d checks FAILED\n", g_failures, g_checks);
        return 1;
    }
    std::printf("scan path prober check passed (%d checks)\n", g_checks);
    return 0;
}

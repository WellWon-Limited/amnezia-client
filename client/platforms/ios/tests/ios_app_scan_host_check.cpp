// AVPN (path engine stage 0): host check (macOS, QtCore) of the pure parts of the in-app iOS probe host -
// client/core/serviceEngine/IosAppScanHost.h: the control file, the known caps, the request facts, the routing of a
// scan (before / beside a tunnel, awg_mini beside a tunnel, no path, background), the route table, the host options,
// the caps addition (needs_vpn false, every other byte kept) and the measurement records (no token, no config).
// Built and run by build_ios_scan_host_check.sh; argument 1 = the vectors directory.
#include "core/serviceEngine/IosAppScanHost.h"

#include <QFile>
#include <QJsonArray>

#include <cstdio>

using namespace avpn;

static int g_checks = 0;
static int g_failures = 0;

static void check(bool ok, const char *what)
{
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

static QByteArray vectorReply(const QString &dir, const QString &name)
{
    QFile f(dir + QStringLiteral("/scan_host_vectors.json"));
    if (!f.open(QIODevice::ReadOnly))
        return {};
    const QJsonArray replies = QJsonDocument::fromJson(f.readAll()).object().value(QLatin1String("replies")).toArray();
    for (const QJsonValue &v : replies) {
        const QJsonObject o = v.toObject();
        if (o.value(QLatin1String("name")).toString() == name)
            return QJsonDocument(o.value(QLatin1String("json")).toObject()).toJson(QJsonDocument::Compact);
    }
    return {};
}

static void testControl()
{
    IosAppScanControl c = iosAppScanControlFrom(QByteArray());
    check(c.mode == IosAppScanMode::Always && c.autorunS == 0 && c.closeAfterS == 45, "no file: always, no autorun");
    c = iosAppScanControlFrom(R"({"mode":"before_tunnel","autorun_s":8,"close_after_s":30})");
    check(c.mode == IosAppScanMode::BeforeTunnel && c.autorunS == 8 && c.closeAfterS == 30, "file read");
    c = iosAppScanControlFrom(R"({"mode":"off"})");
    check(c.mode == IosAppScanMode::Off, "off");
    c = iosAppScanControlFrom(R"({"mode":"sometimes","autorun_s":-5,"close_after_s":1})");
    check(c.mode == IosAppScanMode::Always && c.autorunS == 0 && c.closeAfterS == 10, "unknown mode = always; bounds");
    check(QLatin1String(iosAppScanModeName(IosAppScanMode::BeforeTunnel)) == QLatin1String("before_tunnel"), "mode name");
}

static void testCaps()
{
    const ScanHostCaps c = iosAppScanKnownCaps();
    const ScanHostCaps e = iosScanKnownCaps();
    check(!c.needsVpn && e.needsVpn, "in-app needs no tunnel; the extension does");
    check(c.maxFullConcurrent == e.maxFullConcurrent && c.maxLegConcurrent == e.maxLegConcurrent
              && c.maxAwgConcurrent == e.maxAwgConcurrent && c.platform == e.platform,
          "same engine pools as the extension");

    const QByteArray goCaps = R"({"type":"scan_caps","version":"tribe-scan-v1","kinds":["xray_full","xray_leg","awg_mini"],"max_full_concurrent":1,"max_leg_concurrent":6,"max_awg_concurrent":2,"can_verify_composite":false,"dns_plan":true,"reach_stage":true,"needs_vpn":true,"platform":"ios","mem_mb":40})";
    const QByteArray d = iosAppScanDecorateCaps(goCaps);
    QByteArray expect = goCaps;
    expect.replace("\"needs_vpn\":true", "\"needs_vpn\":false");
    check(d == expect, "caps: only needs_vpn changes, every other byte kept");
    const ScanHostReply r = scanDecodeReply(d);
    check(r.kind == ScanHostReplyKind::Caps && !r.caps.needsVpn && r.caps.maxLegConcurrent == 6, "decorated caps decode");
    const QByteArray spaced = R"({"type": "scan_caps", "version": "tribe-scan-v1", "needs_vpn": true, "max_full_concurrent": 1})";
    check(!scanDecodeReply(iosAppScanDecorateCaps(spaced)).caps.needsVpn, "non-compact caps re-encoded with needs_vpn false");
    for (const QByteArray &same : {QByteArray(R"({"error":"no_vpn"})"), QByteArray(R"({"type":"scan_ack","scan_id":"a"})"),
                                   QByteArray(R"({"type":"scan_caps","needs_vpn":false})"), QByteArray("not json")})
        check(iosAppScanDecorateCaps(same) == same, "anything else comes back as it is");
}

static void testRequestFacts()
{
    const QByteArray start = R"({"action":"scan_start","scan_id":"s1","candidates":[{"id":"2","kind":"awg_mini"},{"id":"4:xray","kind":"xray_leg"},{"id":"up:a1","kind":"xray_full"}]})";
    IosAppScanRequestFacts f = iosAppScanRequestFacts(start);
    check(f.action == QLatin1String("scan_start") && f.scanId == QLatin1String("s1") && f.hasAwgMini && f.candidates.size() == 3,
          "start facts");
    check(f.candidates.at(1).first == QLatin1String("4:xray") && f.candidates.at(1).second == QLatin1String("xray_leg"),
          "candidate kinds kept for the journal");
    f = iosAppScanRequestFacts(R"({"action":"scan_add","scan_id":"s1","candidates":[{"id":"4:xray","kind":"xray_leg"}]})");
    check(!f.hasAwgMini && f.action == QLatin1String("scan_add"), "add without awg_mini");
    f = iosAppScanRequestFacts(R"({"action":"scan_poll","scan_id":"s1","since":3})");
    check(f.candidates.isEmpty() && f.scanId == QLatin1String("s1"), "poll facts");
}

static void testRouting()
{
    IosAppScanState s;
    s.bindIndex = 4;
    s.pathSatisfied = true;

    s.mode = IosAppScanMode::Off;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::Extension, "off: always the extension");

    for (IosAppScanMode m : {IosAppScanMode::BeforeTunnel, IosAppScanMode::Always}) {
        s.mode = m;
        s.tunnelDown = true;
        s.extensionRunning = false;
        s.foreground = true;
        check(iosAppScanRouteStart(s, false) == IosAppScanRoute::App, "no tunnel: in the app");
        check(iosAppScanRouteStart(s, true) == IosAppScanRoute::App, "no tunnel: awg_mini in the app too (no live peer)");
        s.bindIndex = 0;
        check(iosAppScanRouteStart(s, false) == IosAppScanRoute::RefuseNoPath, "no physical interface: refused");
        s.bindIndex = 4;
        s.pathSatisfied = false;
        check(iosAppScanRouteStart(s, false) == IosAppScanRoute::RefuseNoPath, "unusable path: refused");
        s.pathSatisfied = true;
    }

    s.mode = IosAppScanMode::BeforeTunnel;
    s.tunnelDown = false;
    s.extensionRunning = true;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::Extension, "before_tunnel beside a tunnel: the extension");
    s.extensionRunning = false;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::Extension,
          "before_tunnel while connecting: the extension (its own no_vpn)");

    s.mode = IosAppScanMode::Always;
    s.extensionRunning = true;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::App, "always beside a tunnel, in front: in the app");
    check(iosAppScanRouteStart(s, true) == IosAppScanRoute::Extension,
          "always beside a tunnel with awg_mini: the extension (it knows the live peer)");
    s.extensionRunning = false; // connecting / stopping
    check(iosAppScanRouteStart(s, true) == IosAppScanRoute::RefuseLivePeerUnknown,
          "awg_mini while the tunnel comes up and the extension does not answer: live peer unknown");
    s.foreground = false;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::RefuseNoPath, "background, no extension: refused");
    s.extensionRunning = true;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::Extension, "background beside a tunnel: the extension");
    s.foreground = true;
    s.bindIndex = 0;
    check(iosAppScanRouteStart(s, false) == IosAppScanRoute::Extension, "no app path beside a tunnel: the extension");

    IosAppScanState down;
    down.tunnelDown = true;
    IosAppScanState up;
    up.tunnelDown = false;
    check(!iosAppScanAddRefusedAwg(down, true) && iosAppScanAddRefusedAwg(up, true) && !iosAppScanAddRefusedAwg(up, false),
          "an in-app add with awg_mini is refused once a tunnel exists");
    check(iosAppScanStopOnTunnelUp(IosAppScanMode::BeforeTunnel) && !iosAppScanStopOnTunnelUp(IosAppScanMode::Always),
          "in-app scans stop on a tunnel only in before_tunnel");
}

static void testRoutes()
{
    IosAppScanRoutes r;
    check(r.of(QStringLiteral("x"), IosAppScanMode::Always) == IosAppScanRoute::App, "unknown scan: the app engine answers");
    check(r.of(QStringLiteral("x"), IosAppScanMode::Off) == IosAppScanRoute::Extension, "off: the extension");
    check(!r.anyApp(), "empty table");
    r.set(QStringLiteral("a"), IosAppScanRoute::Extension);
    r.set(QStringLiteral("b"), IosAppScanRoute::App);
    check(r.of(QStringLiteral("a"), IosAppScanMode::Always) == IosAppScanRoute::Extension
              && r.of(QStringLiteral("b"), IosAppScanMode::Always) == IosAppScanRoute::App && r.anyApp(),
          "each scan keeps its host");
    r.set(QStringLiteral("b"), IosAppScanRoute::Extension);
    check(!r.anyApp(), "a restarted id takes its new route");
    for (int i = 0; i < 9; ++i)
        r.set(QStringLiteral("n%1").arg(i), IosAppScanRoute::Extension);
    check(r.of(QStringLiteral("a"), IosAppScanMode::Always) == IosAppScanRoute::App, "bounded: the oldest forgotten");
    r.set(QString(), IosAppScanRoute::Extension);
    check(r.of(QString(), IosAppScanMode::Always) == IosAppScanRoute::App, "an empty id is never stored");
}

static void testHostOptions()
{
    ScanNetSource g;
    g.source = QStringLiteral("app");
    g.epoch = 0x5eed;
    g.counter = 2;
    const QJsonObject start = QJsonDocument::fromJson(iosAppScanHostOptions(4, true, g, 3)).object();
    check(start.value(QLatin1String("bind_interface_index")).toInt() == 4 && start.value(QLatin1String("host_epoch")).toInt() == 3,
          "start options: bind index + epoch");
    ScanNetSource back;
    check(scanNetSourceFromJson(start.value(QLatin1String("gen")), back) && back == g, "gen in the wire form of the tuple");
    const QJsonObject poll = QJsonDocument::fromJson(iosAppScanHostOptions(0, false, g, 5)).object();
    check(!poll.contains(QLatin1String("bind_interface_index")) && !poll.contains(QLatin1String("gen"))
              && poll.value(QLatin1String("host_epoch")).toInt() == 5,
          "other options: epoch only when no gen is known");
    check(scanDecodeReply(iosAppScanLivePeerUnknownReply()).detail == QLatin1String("awg_live_peer_unknown"),
          "live-peer refusal is the extension's code (the coordinator's retry without AWG)");
    check(scanDecodeReply(iosAppScanNoPathReply()).error == ScanHostError::BadRequest, "no-path refusal = bad_request");
}

static void testRecords(const QString &vectors)
{
    const QByteArray progress = vectorReply(vectors, QStringLiteral("progress_reach_data_awg"));
    check(!progress.isEmpty(), "vector progress_reach_data_awg");
    const QList<QPair<QString, QString>> kinds{{QStringLiteral("2"), QStringLiteral("awg_mini")},
                                               {QStringLiteral("4:xray"), QStringLiteral("xray_leg")}};
    const QList<QJsonObject> recs = iosAppScanProgressRecords(progress, 1200, kinds);
    check(recs.size() == 6, "one record per item + the scan record");
    int proven = 0;
    for (const QJsonObject &o : recs)
        proven += iosAppScanItemProven(o) ? 1 : 0;
    check(proven == 3, "three data items with a verified digest");
    const QJsonObject awg = recs.at(3);
    check(awg.value(QLatin1String("id")).toString() == QLatin1String("2") && awg.value(QLatin1String("kind")).toString() == QLatin1String("awg_mini")
              && awg.value(QLatin1String("hs_ok")).toBool() && awg.value(QLatin1String("hs_ms")).toInt() == 70
              && awg.value(QLatin1String("egress_node")).toString() == QLatin1String("2"),
          "awg_mini record: handshake, egress node");
    const QJsonObject scan = recs.last();
    check(scan.value(QLatin1String("ev")).toString() == QLatin1String("progress") && scan.value(QLatin1String("mem_mb")).toInt() == 34
              && scan.value(QLatin1String("access")).toObject().value(QLatin1String("asn")).toInt() == 64500
              && !scan.contains(QLatin1String("access_close")),
          "scan record: memory, the access ASN (the server's view of the source)");
    QByteArray all;
    for (const QJsonObject &o : recs)
        all += QJsonDocument(o).toJson(QJsonDocument::Compact);
    check(!all.contains("net-access") && !all.contains("net-exit") && !all.contains("net_token"), "no net token in any record");
    check(iosAppScanProgressRecords(R"({"error":"no_vpn"})", 0, kinds).isEmpty()
              && iosAppScanProgressRecords(vectorReply(vectors, QStringLiteral("ack")), 0, kinds).isEmpty(),
          "only progress replies make records");
}

int main(int argc, char **argv)
{
    const QString vectors = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("client/core/serviceEngine/tests/vectors");
    testControl();
    testCaps();
    testRequestFacts();
    testRouting();
    testRoutes();
    testHostOptions();
    testRecords(vectors);
    if (g_failures) {
        std::fprintf(stderr, "iOS in-app scan host check: %d of %d checks FAILED\n", g_failures, g_checks);
        return 1;
    }
    std::printf("iOS in-app scan host check passed (%d checks)\n", g_checks);
    return 0;
}

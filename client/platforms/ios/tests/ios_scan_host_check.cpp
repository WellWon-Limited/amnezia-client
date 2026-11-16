// AVPN (Scanner, lane L4): host check (macOS, QtCore) of the pure parts of the iOS probe host -
// client/core/serviceEngine/IosScanHost.h: the known caps, the per-action bound, the `gen` peek, the host's own
// answers, the "app" generation source, and the agreement of the extension's additions (TribeScanHost.swift)
// with the app's decoder (ScanHostContract.h). Built and run by build_ios_scan_host_check.sh; argument 1 = the
// vectors directory (client/core/serviceEngine/tests/vectors).
#include "core/serviceEngine/IosScanHost.h"
#include "core/serviceEngine/ScanHostContract.h"

#include "../../../core/serviceEngine/tests/scan_scenarios.h"

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

static void testKnownCaps()
{
    const ScanHostCaps c = iosScanKnownCaps();
    const ScanHostCaps fixture = scantest::hostIosFull();
    check(c.maxFullConcurrent == fixture.maxFullConcurrent && c.maxLegConcurrent == fixture.maxLegConcurrent
              && c.dnsPlan == fixture.dnsPlan && c.canVerifyComposite == fixture.canVerifyComposite
              && c.needsVpn && c.platform == QLatin1String("ios"),
          "known caps = the hostIosFull fixture (full 1, legs 4, DNS plan, no composite, needs the VPN)");
    const ScanHostReply refused = scanDecodeReply(QByteArrayLiteral("{\"error\":\"internal\",\"detail\":\"awg_live_peer_unknown\"}"));
    check(refused.error == ScanHostError::Internal && refused.detail == QLatin1String("awg_live_peer_unknown"),
          "the awg_mini refusal without the live peer decodes as internal with its detail");
    check(c.maxAwgConcurrent == fixture.maxAwgConcurrent && c.awgMini(), "known caps: awg_mini as the fixture (2 sessions)");
}

static void testBounds()
{
    check(iosScanReplyTimeoutMs(scanCompact(scanEncodeCaps())) == 2000, "caps: 2 s");
    check(iosScanReplyTimeoutMs(scanCompact(scanEncodePoll(QStringLiteral("s"), 3))) == 2000, "poll: 2 s");
    check(iosScanReplyTimeoutMs(scanCompact(scanEncodeFreeze(QStringLiteral("s")))) == 2000, "freeze: 2 s");
    check(iosScanReplyTimeoutMs(scanCompact(scanEncodeCancel(QStringLiteral("s")))) == 2000, "cancel: 2 s (answered at once; the final total comes by poll)");
    check(iosScanReplyTimeoutMs(scanCompact(scanEncodeAdd(QStringLiteral("s"), {}))) == 3500, "add: 3.5 s (lifecycle gate)");
    ScanStartRequest r;
    r.scanId = QStringLiteral("s");
    check(iosScanReplyTimeoutMs(scanCompact(scanEncodeStart(r))) == 6000, "start: 6 s (replace 3 s + lifecycle gate)");
    check(iosScanReplyTimeoutMs(iosScanStopAllRequest()) == 3000, "stop-all: 3 s");
    check(iosScanReplyTimeoutMs(QByteArrayLiteral("not json")) == 2000, "anything else: 2 s");
}

static void testHostAnswers()
{
    const ScanHostReply noVpn = scanDecodeReply(iosScanNoVpnReply());
    check(noVpn.kind == ScanHostReplyKind::Error && noVpn.error == ScanHostError::NoVpn,
          "the host's own answer while the extension does not run decodes as no_vpn");
    ScanHostRequest req;
    check(scanDecodeRequest(iosScanStopAllRequest(), req) == ScanHostError::UnknownAction,
          "scan_stop_all is not a contract action (host-local: the engine never sees it)");
    const ScanHostReply unknown = scanDecodeReply(QByteArrayLiteral("{\"error\":\"unknown_action\"}"));
    check(unknown.error == ScanHostError::UnknownAction, "the extension's fallback reply decodes as unknown_action");
    const ScanHostReply noPath = scanDecodeReply(QByteArrayLiteral("{\"error\":\"bad_request\",\"detail\":\"host_options.bind_interface\"}"));
    check(noPath.error == ScanHostError::BadRequest && noPath.detail == QLatin1String("host_options.bind_interface"),
          "the no-physical-path refusal decodes as bad_request with its detail");
}

static void testGenPeek(const QString &vectors)
{
    // The wire form TribeScanHost.swift writes (key order source, epoch, counter).
    const QByteArray swiftElement = QByteArrayLiteral("{\"source\":\"ne\",\"epoch\":\"5eed0000000000ab\",\"counter\":3}");
    ScanNetSource s;
    check(scanNetSourceFromJson(QJsonDocument::fromJson(swiftElement).object(), s) && s.source == QLatin1String("ne")
              && s.epoch == 0x5eed0000000000abULL && s.counter == 3,
          "the extension's element decodes with the contract's reader");

    const QByteArray caps = QByteArrayLiteral("{\"type\":\"scan_caps\",\"version\":\"tribe-scan-v1\",\"max_full_concurrent\":1,"
                                              "\"max_leg_concurrent\":4,\"max_awg_concurrent\":0,\"can_verify_composite\":false,"
                                              "\"dns_plan\":true,\"reach_stage\":true,\"needs_vpn\":true,\"kinds\":[\"xray_full\",\"xray_leg\"],"
                                              "\"mem_mb\":14,\"platform\":\"ios\",\"mem_available_mb\":16,\"gen\":")
                            + swiftElement + "}";
    ScanNetSource g;
    check(iosScanReplyGen(caps, g) && g == s, "gen peeked from a caps reply");
    const ScanHostReply c = scanDecodeReply(caps);
    check(c.kind == ScanHostReplyKind::Caps && c.caps.maxLegConcurrent == 4 && c.caps.needsVpn,
          "a caps reply with the extension's additions still decodes (gen, mem_available_mb ignored)");

    const QByteArray lowered = QByteArrayLiteral("{\"type\":\"scan_caps\",\"version\":\"tribe-scan-v1\",\"max_full_concurrent\":0,"
                                                 "\"max_leg_concurrent\":0,\"max_awg_concurrent\":0,\"can_verify_composite\":false,"
                                                 "\"dns_plan\":false,\"reach_stage\":true,\"needs_vpn\":true,\"kinds\":[],\"mem_mb\":40,"
                                                 "\"platform\":\"ios\",\"mem_available_mb\":10,\"gen\":")
                               + swiftElement + "}";
    const ScanHostReply l = scanDecodeReply(lowered);
    check(l.kind == ScanHostReplyKind::Caps && !l.caps.fullProbe() && !l.caps.legProbe() && !l.caps.awgMini(),
          "caps lowered to no pool decode as a host that probes nothing");

    const QByteArray progress = QByteArrayLiteral("{\"type\":\"scan_progress\",\"scan_id\":\"s1\",\"seq\":1,\"phase\":\"data\",\"items\":[],"
                                                  "\"bytes_spent\":0,\"done\":false,\"reason\":\"\",\"access\":{\"attempted\":true,"
                                                  "\"http_answered\":false,\"asn\":null,\"net_token\":null,\"at_ms\":0,\"gen\":")
                                + swiftElement + "},\"gen\":" + swiftElement + "}";
    check(iosScanReplyGen(progress, g) && g == s, "gen peeked from a progress reply");
    const ScanHostReply p = scanDecodeReply(progress);
    check(p.kind == ScanHostReplyKind::Progress && p.progress.hasGen && p.progress.gen == s
              && p.progress.access.attempted && p.progress.access.hasGen && p.progress.access.gen == s,
          "progress + attempt with the extension's gen decode: progress.gen and access.gen = the ne element");

    const QByteArray vec = vectorReply(vectors, QStringLiteral("progress_reach_data_awg"));
    check(!vec.isEmpty() && iosScanReplyGen(vec, g) && g.source == QLatin1String("ne") && g.counter == 3,
          "gen peeked from the shared vector progress_reach_data_awg");

    check(!iosScanReplyGen(QByteArrayLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"s\",\"accepted\":0,\"gen\":") + swiftElement + "}", g),
          "acks carry no gen");
    check(!iosScanReplyGen(QByteArrayLiteral("{\"error\":\"memory\",\"gen\":") + swiftElement + "}", g), "errors carry no gen");
    check(!iosScanReplyGen(QByteArrayLiteral("{\"type\":\"scan_progress\",\"gen\":null}"), g), "null gen: none");
    check(!iosScanReplyGen(QByteArrayLiteral("{\"type\":\"scan_progress\",\"gen\":{\"source\":\"ne\",\"epoch\":1,\"counter\":0}}"), g),
          "malformed gen: none");
    check(!iosScanReplyGen(QByteArray(), g), "no reply: none");
}

static void testAppGeneration()
{
    IosAppNetGeneration gen(0xabcdefULL);
    check(!gen.seen(), "no path yet");
    const QByteArray a = iosAppPathSignature(true, {QStringLiteral("wifi:en0:4")}, {QStringLiteral("en0/192.0.2.4"), QStringLiteral("en0/fe80::1")});
    const QByteArray a2 = iosAppPathSignature(true, {QStringLiteral("wifi:en0:4")}, {QStringLiteral("en0/fe80::1"), QStringLiteral("en0/192.0.2.4")});
    const QByteArray b = iosAppPathSignature(true, {QStringLiteral("cellular:pdp_ip0:2")}, {QStringLiteral("pdp_ip0/10.1.2.3")});
    const QByteArray off = iosAppPathSignature(false, {QStringLiteral("wifi:en0:4")}, {QStringLiteral("en0/192.0.2.4"), QStringLiteral("en0/fe80::1")});
    check(a == a2, "the signature ignores the order of addresses");
    check(a != off, "an unusable path changes the signature");
    check(!gen.observe(a) && gen.seen() && gen.element().counter == 0, "the first path is the baseline");
    check(!gen.observe(a2) && gen.element().counter == 0, "the same path: no change");
    check(gen.observe(b) && gen.element().counter == 1, "Wi-Fi -> cellular: counter 1");
    check(gen.observe(a) && gen.element().counter == 2, "back to Wi-Fi is a change too (counter never goes back)");
    const ScanNetSource e = gen.element();
    check(e.source == QLatin1String("app") && e.epoch == 0xabcdefULL, "source app, the monitor's epoch");
    ScanNetSource rt;
    check(scanNetSourceFromJson(scanNetSourceToJson(e), rt) && rt == e, "the app element survives the wire form");
    // The strict tuple: the app element and the extension's element side by side; any move changes the stamp.
    ScanNetSource ne;
    ne.source = QStringLiteral("ne");
    ne.epoch = 7;
    ne.counter = 1;
    const QString before = scanNetGeneration({e, ne});
    gen.observe(b);
    check(scanNetGeneration({gen.element(), ne}) != before, "an app path change changes the tuple's stamp");
}

static void testPathKind()
{
    check(iosAppPathKind({QStringLiteral("wifi:en0:4")}) == QLatin1String("wifi"), "Wi-Fi");
    check(iosAppPathKind({QStringLiteral("cellular:pdp_ip0:2")}) == QLatin1String("cellular"), "cellular");
    check(iosAppPathKind({QStringLiteral("wired:en5:9")}) == QLatin1String("ethernet"), "wired = ethernet");
    check(iosAppPathKind({QStringLiteral("cellular:pdp_ip0:2"), QStringLiteral("wifi:en0:4")}) == QLatin1String("wifi"),
          "Wi-Fi beats cellular (an iPhone on Wi-Fi with a SIM)");
    check(iosAppPathKind({QStringLiteral("wifi:en0:4"), QStringLiteral("cellular:pdp_ip0:2"), QStringLiteral("wired:en5:9")})
              == QLatin1String("ethernet"),
          "wired beats Wi-Fi and cellular");
    check(iosAppPathKind({QStringLiteral("wifi"), QStringLiteral("cellular")}) == QLatin1String("wifi"), "bare type names");
    check(iosAppPathKind({}).isEmpty(), "no interface: empty");
    check(iosAppPathKind({QStringLiteral("other:utun4:20"), QStringLiteral("loopback:lo0:1")}).isEmpty(),
          "only virtual / loopback: empty");
    check(iosAppPathKind({QStringLiteral("wifix:en0:4"), QStringLiteral(":wifi:1")}).isEmpty(), "near names are not kinds");
}

int main(int argc, char **argv)
{
    const QString vectors = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("client/core/serviceEngine/tests/vectors");
    testKnownCaps();
    testBounds();
    testHostAnswers();
    testGenPeek(vectors);
    testAppGeneration();
    testPathKind();
    if (g_failures) {
        std::fprintf(stderr, "iOS scan host check: %d of %d checks FAILED\n", g_failures, g_checks);
        return 1;
    }
    std::printf("iOS scan host check passed (%d checks)\n", g_checks);
    return 0;
}

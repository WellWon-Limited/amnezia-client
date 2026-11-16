// AVPN (Scanner, lane A3): host test (macOS Qt, no device) of the pure parts of the Android probe host
// (client/core/serviceEngine/AndroidScanHost.h): the known caps, the per-action reply bounds (the same table as the
// service side, ScanHostCore.kt), the service state payload, the `gen` of replies over the shared vectors, and the
// request table that binds every asynchronous reply to the request that asked for it (a late or foreign reply is
// dropped, each reply delivered once, the bound expires it). Argument 1: the vectors directory.
#include "AndroidScanHost.h"
#include "ScanHostContract.h"

#include <QFile>
#include <QJsonArray>

#include <cstdio>

using namespace avpn;

static int g_checks = 0, g_failures = 0;
#define EXPECT(cond, msg)                                                                                          \
    do {                                                                                                           \
        ++g_checks;                                                                                                \
        if (!(cond)) {                                                                                             \
            ++g_failures;                                                                                          \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                                     \
        }                                                                                                          \
    } while (0)

static void testCapsAndBounds()
{
    const ScanHostCaps c = androidScanKnownCaps();
    EXPECT(c.needsVpn && c.maxAwgConcurrent == 0 && c.maxLegConcurrent == 4 && c.maxFullConcurrent == 1, "android caps");
    EXPECT(!c.canVerifyComposite && c.dnsPlan && c.reachStage && c.platform == QLatin1String("android"), "android caps flags");
    EXPECT(androidScanReplyTimeoutMs("{\"action\":\"scan_start\"}") == 6000, "start bound");
    EXPECT(androidScanReplyTimeoutMs("{\"action\":\"scan_add\"}") == 3500, "add bound");
    EXPECT(androidScanReplyTimeoutMs("{\"action\":\"scan_cancel\"}") == 3000, "cancel bound");
    EXPECT(androidScanReplyTimeoutMs(androidScanStopAllRequest()) == 3000, "stop-all bound");
    EXPECT(androidScanReplyTimeoutMs("{\"action\":\"scan_poll\"}") == 2000, "poll bound");
    EXPECT(androidScanReplyTimeoutMs("{nope") == 2000, "unparsable: the short bound");
    for (const char *r : {"scan_start", "scan_add", "scan_poll", "scan_cancel", "scan_freeze", "scan_caps"}) {
        const QByteArray req = QByteArray("{\"action\":\"") + r + "\"}";
        EXPECT(androidScanReplyTimeoutMs(req) <= 6000, "every bound <= 6 s (IScanHost.h)");
    }
    EXPECT(androidScanNoVpnReply() == "{\"error\":\"no_vpn\"}", "no_vpn reply");
}

static void testState()
{
    bool open = false, hasGen = false;
    ScanNetSource g;
    EXPECT(androidScanStateDecode(R"({"open":true,"gen":{"source":"xray_service","epoch":"5eed5eed5eed5eed","counter":3}})", open, hasGen, g),
           "state decodes");
    EXPECT(open && hasGen && g.source == QLatin1String("xray_service") && g.epoch == 0x5eed5eed5eed5eedULL && g.counter == 3, "state values");
    EXPECT(androidScanStateDecode(R"({"open":false})", open, hasGen, g) && !open && !hasGen, "closed, no gen");
    EXPECT(androidScanStateDecode(R"({"open":true,"gen":{"source":"xray_service","epoch":12,"counter":3}})", open, hasGen, g) && !hasGen,
           "a malformed gen is not taken");
    EXPECT(!androidScanStateDecode(R"({"gen":{}})", open, hasGen, g), "open is required");
    EXPECT(!androidScanStateDecode("nope", open, hasGen, g), "not JSON");
}

static void testVectorsGen(const QString &dir)
{
    QFile f(dir + QStringLiteral("/scan_host_vectors.json"));
    EXPECT(f.open(QIODevice::ReadOnly), "vectors readable");
    const QJsonObject root = QJsonDocument::fromJson(f.readAll()).object();
    const QJsonArray replies = root.value(QLatin1String("replies")).toArray();
    int withGen = 0;
    for (const QJsonValue &v : replies) {
        const QJsonObject o = v.toObject();
        const QJsonValue j = o.value(QLatin1String("json"));
        const QByteArray bytes = j.isString() ? j.toString().toUtf8() : QJsonDocument(j.toObject()).toJson(QJsonDocument::Compact);
        ScanNetSource g;
        const bool got = androidScanReplyGen(bytes, g);
        const QJsonObject r = QJsonDocument::fromJson(bytes).object();
        const QString type = r.value(QLatin1String("type")).toString();
        ScanNetSource expect;
        const bool should = !r.contains(QLatin1String("error"))
                            && (type == QLatin1String("scan_caps") || type == QLatin1String("scan_progress"))
                            && scanNetSourceFromJson(r.value(QLatin1String("gen")), expect);
        EXPECT(got == should, qPrintable(QStringLiteral("reply %1: gen read").arg(o.value(QLatin1String("name")).toString())));
        if (got) {
            ++withGen;
            EXPECT(g == expect, "the same element as the contract decoder reads");
        }
    }
    EXPECT(replies.size() >= 30 && withGen >= 10, "vectors: replies with gen");
}

static void testPending()
{
    AndroidScanPending p;
    QList<QByteArray> got1, got2, got3;
    const qint64 a = p.add([&](const QByteArray &b) { got1 << b; }, 1000);
    const qint64 b = p.add([&](const QByteArray &x) { got2 << x; }, 500);
    const qint64 c = p.add([&](const QByteArray &x) { got3 << x; }, 6000);
    EXPECT(a != b && b != c && a != c, "unique ids");
    EXPECT(p.nextDeadlineMs() == 500, "earliest deadline");
    // A reply goes to ITS request only, once.
    auto fb = p.take(b);
    EXPECT(bool(fb), "b pending");
    fb("reply-b");
    EXPECT(!p.take(b), "b delivered once: a second reply for b is dropped");
    EXPECT(got2 == QList<QByteArray>{"reply-b"} && got1.isEmpty() && got3.isEmpty(), "no cross delivery");
    // The bound: a expires at 1000, c does not.
    const QList<AndroidScanPending::ReplyFn> late = p.expire(1000);
    EXPECT(late.size() == 1, "one expired");
    for (const auto &fn : late)
        fn(QByteArray());
    EXPECT(got1 == QList<QByteArray>{QByteArray()}, "an expired request gets the empty answer once");
    EXPECT(!p.take(a), "the late reply of an expired request finds nothing");
    EXPECT(got1.size() == 1, "still once");
    EXPECT(p.size() == 1 && p.nextDeadlineMs() == 6000, "c still pending");
    EXPECT(!p.take(424242), "an unknown id is dropped");
    auto fc = p.take(c);
    fc("reply-c");
    EXPECT(got3 == QList<QByteArray>{"reply-c"} && p.size() == 0 && p.nextDeadlineMs() == -1, "drained");
    const qint64 d = p.add([](const QByteArray &) {}, 1);
    EXPECT(d > c, "ids grow");
}

int main(int argc, char **argv)
{
    const QString dir = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("vectors");
    testCapsAndBounds();
    testState();
    testVectorsGen(dir);
    testPending();
    std::printf("android_scan_host_check: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

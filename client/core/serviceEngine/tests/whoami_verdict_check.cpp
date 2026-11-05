// AVPN (plan v3 step 5): checks of the whoami verdict (WhoamiVerdict.h) and of the network memory
// helpers (NetworkMemory.h). Build/run: tests/build_whoami_verdict.sh.
//
// The verdict decides whether a freshly raised tunnel gets "Connected" with the "data flows" mark,
// moves to the next path of the same attempt, or stays as it is because the check could not run.
// A false NoData/BypassVpn sends a healthy user through the failover chain, a false Works shows a
// green mark on a dead path - both directions are pinned below.
#include "../NetworkMemory.h"
#include "../WhoamiVerdict.h"

#include <QCryptographicHash>
#include <cstdio>

static int failures = 0;
static int total = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        ++total;                                                                                   \
        if (cond) {                                                                                \
            std::printf("ok   - %s\n", msg);                                                       \
        } else {                                                                                   \
            std::printf("FAIL - %s\n", msg);                                                       \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

using avpn::WhoamiObservation;
using avpn::WhoamiVerdict;

static QByteArray sha(const QByteArray &body)
{
    return QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex();
}

// A healthy 128 KiB answer from node 11 for nonce "abc".
static WhoamiObservation good()
{
    const QByteArray body(128 * 1024, 'x');
    WhoamiObservation o;
    o.httpStatus = 200;
    o.bodyBytes = body.size();
    o.bodySha256Hex = sha(body);
    o.headerSha256 = sha(body);
    o.sentNonce = "abc";
    o.headerNonce = "abc";
    o.nodeHeaderPresent = true;
    o.node = 11;
    return o;
}

int main()
{
    // --- verdict: works ---
    CHECK(avpn::whoamiVerdict(good()) == WhoamiVerdict::Works, "200 + whole body + our node -> works");
    {
        WhoamiObservation o = good();
        o.headerSha256 = o.headerSha256.toUpper();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "sha256 compare is case-insensitive");
        o.headerNonce = " abc ";
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "header whitespace is not a mismatch");
    }
    {
        const QByteArray body(64 * 1024, 'y');
        WhoamiObservation o = good();
        o.bodyBytes = body.size();
        o.bodySha256Hex = sha(body);
        o.headerSha256 = sha(body);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "64 KiB (contract minimum) -> works");
    }

    // --- verdict: no data ---
    {
        WhoamiObservation o = good();
        const QByteArray part(5 * 1024, 'x'); // "freezes after ~5 KB": headers came, body stalled
        o.bodyBytes = part.size();
        o.bodySha256Hex = sha(part);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "200 + 5 KiB stalled body -> no data");
        o.bodyBytes = avpn::kWhoamiMinBodyBytes - 1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "16 KiB - 1 -> no data");
        o.bodyBytes = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "200 + empty body -> no data");
    }
    {
        WhoamiObservation o = good();
        const QByteArray part(100 * 1024, 'x'); // truncated above the 16 KiB floor
        o.bodyBytes = part.size();
        o.bodySha256Hex = sha(part);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "truncated 100 KiB (sha mismatch) -> no data");
    }
    {
        WhoamiObservation o = good();
        o.headerSha256.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData,
              "200 without X-Whoami-Sha256 (captive portal page) -> no data");
    }
    {
        WhoamiObservation o = good();
        o.headerNonce = "zzz";
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "foreign nonce echo (cached answer) -> no data");
        o.headerNonce.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "missing nonce echo -> no data");
        o = good();
        o.sentNonce.clear();
        o.headerNonce.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "no nonce sent -> never works");
    }
    {
        WhoamiObservation o = good();
        o.node = 0;
        o.bodyBytes = 1000;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "short body wins over node 0 (data first)");
    }

    // --- verdict: bypass ---
    {
        WhoamiObservation o = good();
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::BypassVpn, "whole body + node 0 -> past the VPN");
    }

    // --- verdict: check limited (not a failure) ---
    {
        WhoamiObservation o = good();
        for (int code : {429, 404, 401, 400, 500, 502, 204, 301}) {
            o.httpStatus = code;
            CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited,
                  qPrintable(QStringLiteral("HTTP %1 -> check limited").arg(code)));
        }
        WhoamiObservation none;
        CHECK(avpn::whoamiVerdict(none) == WhoamiVerdict::CheckLimited,
              "no HTTP answer (transport error / timeout before headers) -> check limited");
        o = good();
        o.nodeHeaderPresent = false;
        o.node = -1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited, "200 without X-Whoami-Node -> check limited");
        o.nodeHeaderPresent = true;
        o.node = -1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited, "garbage X-Whoami-Node -> check limited");
    }

    // --- helpers ---
    CHECK(avpn::whoamiFailsPath(WhoamiVerdict::NoData) && avpn::whoamiFailsPath(WhoamiVerdict::BypassVpn),
          "no data / bypass move to the next path");
    CHECK(!avpn::whoamiFailsPath(WhoamiVerdict::Works) && !avpn::whoamiFailsPath(WhoamiVerdict::CheckLimited),
          "works / limited keep the path");
    {
        bool present = false;
        CHECK(avpn::parseWhoamiNode("11", &present) == 11 && present, "node header 11");
        CHECK(avpn::parseWhoamiNode(" 0 ", &present) == 0 && present, "node header 0");
        CHECK(avpn::parseWhoamiNode("", &present) == -1 && !present, "node header missing");
        CHECK(avpn::parseWhoamiNode("eleven", &present) == -1 && present, "node header garbage");
        CHECK(avpn::parseWhoamiNode("-3", &present) == -1 && present, "negative node header");
    }
    {
        WhoamiObservation none;
        CHECK(avpn::whoamiShouldRetry(none, 1, 8000), "no answer, 1 attempt, budget left -> retry");
        CHECK(!avpn::whoamiShouldRetry(none, avpn::kWhoamiMaxAttempts, 8000), "attempt cap -> no retry");
        CHECK(!avpn::whoamiShouldRetry(none, 1, avpn::kWhoamiMinAttemptMs - 1), "budget spent -> no retry");
        WhoamiObservation limited = good();
        limited.httpStatus = 429;
        CHECK(!avpn::whoamiShouldRetry(limited, 1, 8000), "429 is never retried (rate limit)");
        WhoamiObservation stalled = good();
        stalled.bodyBytes = 10;
        CHECK(!avpn::whoamiShouldRetry(stalled, 1, 8000), "a stalled 200 is a verdict, not a retry");
    }
    CHECK(avpn::whoamiVerdictName(WhoamiVerdict::Works) == QLatin1String("works")
              && avpn::whoamiVerdictName(WhoamiVerdict::NoData) == QLatin1String("no_data")
              && avpn::whoamiVerdictName(WhoamiVerdict::BypassVpn) == QLatin1String("bypass")
              && avpn::whoamiVerdictName(WhoamiVerdict::CheckLimited) == QLatin1String("limited"),
          "verdict names (QML pathCheck contract)");
    // The failover reason must not be a health-DEAD reason: the ladder goes straight to step 3.
    CHECK(avpn::whoamiFailoverReason(WhoamiVerdict::NoData) != QLatin1String("dead (failover)")
              && avpn::whoamiFailoverReason(WhoamiVerdict::BypassVpn) != QLatin1String("dead (failover)"),
          "failover reason skips rebind/re-up of the same node");

    // --- network memory ---
    CHECK(avpn::networkMemoryKey(QStringLiteral("wifi"), QStringLiteral("250-02")) == QLatin1String("wifi"),
          "wifi key has no operator and no SSID");
    CHECK(avpn::networkMemoryKey(QStringLiteral("ethernet"), QString()) == QLatin1String("wifi"),
          "wired counts as the fixed-network key");
    CHECK(avpn::networkMemoryKey(QStringLiteral("cellular"), QStringLiteral("250-02"))
              == QLatin1String("cellular:250-02"),
          "cellular key carries MCC-MNC");
    CHECK(avpn::networkMemoryKey(QStringLiteral("cellular"), QString()) == QLatin1String("cellular"),
          "cellular without operator code");
    CHECK(avpn::networkMemoryKey(QString(), QStringLiteral("250-02")).isEmpty(), "unknown medium -> no key");
    {
        QByteArray m;
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("wifi")).isEmpty(), "empty memory");
        m = avpn::networkMemoryRemember(m, QStringLiteral("wifi"), QStringLiteral("9:awg"), 100);
        m = avpn::networkMemoryRemember(m, QStringLiteral("cellular:250-02"), QStringLiteral("9:xray"), 200);
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("wifi")) == QLatin1String("9:awg"), "wifi remembered");
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("cellular:250-02")) == QLatin1String("9:xray"),
              "operator remembered separately");
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("cellular:250-01")).isEmpty(),
              "another operator has no memory");
        m = avpn::networkMemoryRemember(m, QStringLiteral("wifi"), QStringLiteral("2:awg"), 300);
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("wifi")) == QLatin1String("2:awg"),
              "newer success replaces the entry");
        // forget only if it still points at the failed node
        QByteArray f = avpn::networkMemoryForget(m, QStringLiteral("wifi"), QStringLiteral("9:awg"));
        CHECK(avpn::networkMemoryLookup(f, QStringLiteral("wifi")) == QLatin1String("2:awg"),
              "failure of an older node keeps the newer entry");
        f = avpn::networkMemoryForget(m, QStringLiteral("wifi"), QStringLiteral("2:awg"));
        CHECK(avpn::networkMemoryLookup(f, QStringLiteral("wifi")).isEmpty(), "failed remembered node is forgotten");
        CHECK(avpn::networkMemoryLookup(f, QStringLiteral("cellular:250-02")) == QLatin1String("9:xray"),
              "other networks untouched");
        CHECK(avpn::networkMemoryRemember(m, QString(), QStringLiteral("x"), 1) == m, "no key -> no write");
        CHECK(avpn::networkMemoryLookup("not json", QStringLiteral("wifi")).isEmpty(), "corrupt blob -> empty");
        QByteArray big;
        for (int i = 0; i < avpn::kNetworkMemoryMax + 5; ++i)
            big = avpn::networkMemoryRemember(big, QStringLiteral("cellular:%1").arg(i), QStringLiteral("n"), i);
        CHECK(QJsonDocument::fromJson(big).array().size() == avpn::kNetworkMemoryMax, "memory is capped");
        CHECK(avpn::networkMemoryLookup(big, QStringLiteral("cellular:%1").arg(avpn::kNetworkMemoryMax + 4))
                  == QLatin1String("n"),
              "cap drops the oldest, keeps the newest");
        CHECK(avpn::networkMemoryLookup(big, QStringLiteral("cellular:0")).isEmpty(), "oldest dropped");
    }

    std::printf("%s: %d/%d checks\n", failures ? "whoami_verdict_check: FAILED" : "whoami_verdict_check: OK",
                total - failures, total);
    return failures ? 1 : 0;
}

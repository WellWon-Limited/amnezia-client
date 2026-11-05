// AVPN (plan v3 step 5): checks of the whoami verdict (WhoamiVerdict.h) and of the network memory
// helpers (NetworkMemory.h). Build/run: tests/build_whoami_verdict.sh.
//
// The verdict decides whether a freshly raised tunnel gets "Connected" with the "data flows" mark,
// moves to the next path of the same attempt, stays as it is, or hands the decision to the existing
// generate_204 check (tiebreak). A false NoData/BypassVpn sends a healthy user through the failover
// chain, a false Works shows a green mark on a dead path - both directions are pinned below.
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
using avpn::WhoamiStep;
using avpn::WhoamiVerdict;

static QByteArray sha(const QByteArray &body)
{
    return QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex();
}

// A healthy, complete 128 KiB answer from node 11 for nonce "abc".
static WhoamiObservation good()
{
    const QByteArray body(128 * 1024, 'x');
    WhoamiObservation o;
    o.httpStatus = 200;
    o.complete = true;
    o.bytesReceived = body.size();
    o.bodySha256Hex = sha(body);
    o.headerSha256 = sha(body);
    o.sentNonce = "abc";
    o.headerNonce = "abc";
    o.nodeHeaderPresent = true;
    o.node = 11;
    return o;
}

// The body was cut by OUR timeout after `bytes` arrived (slow link or a stall).
static WhoamiObservation cutByOurTimeout(qint64 bytes)
{
    WhoamiObservation o = good();
    const QByteArray part(int(bytes), 'x');
    o.complete = false;
    o.timedOut = true;
    o.bytesReceived = bytes;
    o.bodySha256Hex = sha(part);
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
        o.bytesReceived = body.size();
        o.bodySha256Hex = sha(body);
        o.headerSha256 = sha(body);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "64 KiB (contract minimum) -> works");
    }
    // review item 4: slow link - our own timeout cut the body after >= 16 KiB: data flows, slowly
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(40 * 1024)) == WhoamiVerdict::Works,
          "slow link: 40 KiB then our timeout -> works (hash checked only on a complete body)");
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(avpn::kWhoamiMinBodyBytes)) == WhoamiVerdict::Works,
          "slow link: exactly 16 KiB then our timeout -> works");
    {
        WhoamiObservation o = cutByOurTimeout(40 * 1024);
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::BypassVpn, "slow link past the VPN -> bypass");
        o = cutByOurTimeout(40 * 1024);
        o.headerNonce = "zzz";
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "slow link with a foreign nonce -> no data");
    }

    // --- verdict: no data ---
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(5 * 1024)) == WhoamiVerdict::NoData,
          "headers came, body froze after 5 KiB, our timeout -> no data");
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(avpn::kWhoamiMinBodyBytes - 1)) == WhoamiVerdict::NoData,
          "16 KiB - 1 then our timeout -> no data");
    {
        WhoamiObservation o = cutByOurTimeout(100 * 1024);
        o.timedOut = false; // cut by the path (reset), not by our clock
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "body cut by the path (not our timeout) -> no data");
    }
    {
        WhoamiObservation o = good();
        o.bytesReceived = 0;
        o.bodySha256Hex = sha(QByteArray());
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "complete 200 with an empty body -> no data");
    }
    {
        WhoamiObservation o = good();
        const QByteArray other(128 * 1024, 'z');
        o.bodySha256Hex = sha(other);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "complete body, sha mismatch -> no data");
    }
    {
        WhoamiObservation o = good();
        o.headerSha256.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData,
              "complete 200 without X-Whoami-Sha256 (captive portal page) -> no data");
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
        WhoamiObservation o = cutByOurTimeout(1000);
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "short body wins over node 0 (data first)");
    }

    // --- verdict: bypass ---
    {
        WhoamiObservation o = good();
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::BypassVpn, "whole body + node 0 -> past the VPN");
    }

    // --- verdict: check limited only for 429 / 404 (review item 3) ---
    {
        WhoamiObservation o = good();
        o.httpStatus = 429;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited, "429 rate limit -> check limited");
        o.httpStatus = 404;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited, "404 feature off -> check limited");
    }

    // --- verdict: inconclusive -> generate_204 tiebreak ---
    {
        WhoamiObservation none;
        CHECK(avpn::whoamiVerdict(none) == WhoamiVerdict::Inconclusive,
              "no HTTP answer at all -> inconclusive (tiebreak)");
        WhoamiObservation noneTimedOut;
        noneTimedOut.timedOut = true;
        CHECK(avpn::whoamiVerdict(noneTimedOut) == WhoamiVerdict::Inconclusive,
              "our timeout before the headers -> inconclusive (tiebreak)");
        WhoamiObservation o = good();
        for (int code : {400, 401, 500, 502, 204, 301}) {
            o.httpStatus = code;
            CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Inconclusive,
                  qPrintable(QStringLiteral("HTTP %1 -> inconclusive (tiebreak)").arg(code)));
        }
        o = good();
        o.nodeHeaderPresent = false;
        o.node = -1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Inconclusive, "200 without X-Whoami-Node -> inconclusive");
        o.nodeHeaderPresent = true;
        o.node = -1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Inconclusive, "garbage X-Whoami-Node -> inconclusive");
    }
    CHECK(avpn::whoamiTiebreakVerdict(true) == WhoamiVerdict::CheckLimited,
          "tiebreak: generate_204 passed -> check limited (Connected, no green mark)");
    CHECK(avpn::whoamiTiebreakVerdict(false) == WhoamiVerdict::NoData,
          "tiebreak: generate_204 failed too -> no data (next path)");

    // --- next step: retry / tiebreak / finish (review items 3 and 7) ---
    {
        const qint64 plenty = 5000;
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::BypassVpn, 0, 1, plenty) == WhoamiStep::Retry,
              "first bypass answer -> one retry (routes may not have settled)");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::BypassVpn, 200, 2, plenty) == WhoamiStep::Finish,
              "second bypass answer -> bypass is final");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::BypassVpn, 200, 1, avpn::kWhoamiMinAttemptMs - 1)
                  == WhoamiStep::Finish,
              "bypass with no whoami budget left -> final");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::BypassVpn, 200, 1, avpn::kWhoamiMinAttemptMs) == WhoamiStep::Finish,
              "bypass: budget for an attempt but not for the delay + attempt -> final (no doomed retry)");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::BypassVpn, 200, 1,
                                   avpn::kWhoamiRetryDelayMs + avpn::kWhoamiMinAttemptMs) == WhoamiStep::Retry,
              "bypass: exactly delay + attempt left -> retry");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::Inconclusive, 0, 1, plenty) == WhoamiStep::Retry,
              "no answer, budget and cap left -> retry");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::Inconclusive, 0, avpn::kWhoamiMaxAttempts, plenty)
                  == WhoamiStep::Tiebreak,
              "no answer, cap reached -> generate_204 tiebreak");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::Inconclusive, 0, 1, avpn::kWhoamiMinAttemptMs - 1)
                  == WhoamiStep::Tiebreak,
              "no answer, whoami budget spent -> generate_204 tiebreak");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::Inconclusive, 502, 1, plenty) == WhoamiStep::Tiebreak,
              "an HTTP answer that decides nothing (502) -> tiebreak, no retry");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::CheckLimited, 429, 1, plenty) == WhoamiStep::Finish,
              "429 is never retried (rate limit)");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::NoData, 200, 1, plenty) == WhoamiStep::Finish,
              "a stalled 200 is a verdict, not a retry");
        CHECK(avpn::whoamiNextStep(WhoamiVerdict::Works, 200, 1, plenty) == WhoamiStep::Finish, "works is final");
    }
    // whoami gets at most ~60 % of the verify budget, the rest is the tiebreak's (review item 3)
    CHECK(avpn::whoamiBudgetMs(12000) == 7200, "whoami budget = 60 % of 12 s");
    CHECK(avpn::whoamiBudgetMs(3000) == 1800, "whoami budget = 60 % of the 3 s floor");
    CHECK(12000 - avpn::whoamiBudgetMs(12000) >= 4000, "at least 4 s left for generate_204 at the default budget");
    CHECK(avpn::whoamiBudgetMs(3000) - 800 >= avpn::kWhoamiMinAttemptMs,
          "even at the 3 s floor one whoami fits after the 800 ms settle delay");

    // --- helpers ---
    CHECK(avpn::whoamiFailsPath(WhoamiVerdict::NoData) && avpn::whoamiFailsPath(WhoamiVerdict::BypassVpn),
          "no data / bypass move to the next path");
    CHECK(!avpn::whoamiFailsPath(WhoamiVerdict::Works) && !avpn::whoamiFailsPath(WhoamiVerdict::CheckLimited)
              && !avpn::whoamiFailsPath(WhoamiVerdict::Inconclusive),
          "works / limited / inconclusive keep the path");
    {
        bool present = false;
        CHECK(avpn::parseWhoamiNode("11", &present) == 11 && present, "node header 11");
        CHECK(avpn::parseWhoamiNode(" 0 ", &present) == 0 && present, "node header 0");
        CHECK(avpn::parseWhoamiNode("", &present) == -1 && !present, "node header missing");
        CHECK(avpn::parseWhoamiNode("eleven", &present) == -1 && present, "node header garbage");
        CHECK(avpn::parseWhoamiNode("-3", &present) == -1 && present, "negative node header");
    }
    CHECK(avpn::whoamiVerdictName(WhoamiVerdict::Works) == QLatin1String("works")
              && avpn::whoamiVerdictName(WhoamiVerdict::NoData) == QLatin1String("no_data")
              && avpn::whoamiVerdictName(WhoamiVerdict::BypassVpn) == QLatin1String("bypass")
              && avpn::whoamiVerdictName(WhoamiVerdict::CheckLimited) == QLatin1String("limited")
              && avpn::whoamiVerdictName(WhoamiVerdict::Inconclusive) == QLatin1String("inconclusive"),
          "verdict names (QML pathCheck contract)");
    // The failover reason must not be a health-DEAD reason: the ladder goes straight to step 3.
    CHECK(avpn::whoamiFailoverReason(WhoamiVerdict::NoData) != QLatin1String("dead (failover)")
              && avpn::whoamiFailoverReason(WhoamiVerdict::BypassVpn) != QLatin1String("dead (failover)"),
          "failover reason skips rebind/re-up of the same node");

    // --- whoami edge (review item 6): never ask the tunnel's own server address ---
    {
        const QStringList edges{QStringLiteral("https://api.tribevpn.com"), QStringLiteral("https://vpn.wellwon.hk")};
        QHash<QString, QStringList> ips;
        ips.insert(QStringLiteral("api.tribevpn.com"), {QStringLiteral("201.34.134.103")});
        ips.insert(QStringLiteral("vpn.wellwon.hk"), {QStringLiteral("104.21.1.1")});
        const QString active = QStringLiteral("https://api.tribevpn.com");
        CHECK(avpn::whoamiBaseUrl(active, edges, ips, QStringLiteral("79.110.48.13")) == active,
              "tunnel endpoint is not the API address -> the active edge");
        CHECK(avpn::whoamiBaseUrl(active, edges, ips, QStringLiteral("201.34.134.103"))
                  == QLatin1String("https://vpn.wellwon.hk"),
              "API resolves to the xray entry -> the other edge");
        CHECK(avpn::whoamiBaseUrl(active, edges, ips, QString()) == active, "endpoint unknown -> the active edge");
        QHash<QString, QStringList> both = ips;
        both.insert(QStringLiteral("vpn.wellwon.hk"), {QStringLiteral("201.34.134.103")});
        CHECK(avpn::whoamiBaseUrl(active, edges, both, QStringLiteral("201.34.134.103")) == active,
              "every edge is the endpoint -> the active edge (nothing better known)");
        QHash<QString, QStringList> unresolved;
        unresolved.insert(QStringLiteral("api.tribevpn.com"), {QStringLiteral("201.34.134.103")});
        CHECK(avpn::whoamiBaseUrl(active, edges, unresolved, QStringLiteral("201.34.134.103"))
                  == QLatin1String("https://vpn.wellwon.hk"),
              "other edge not resolved yet -> still better than the known-bad one");
        CHECK(avpn::whoamiBaseUrl(QStringLiteral("https://201.34.134.103"), edges, ips,
                                  QStringLiteral("201.34.134.103"))
                  == QLatin1String("https://vpn.wellwon.hk"),
              "literal-IP base equal to the endpoint -> first edge that does not resolve to it");
    }

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
        const qint64 now = 1'800'000'000;
        QByteArray m;
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("wifi"), now).isEmpty(), "empty memory");
        m = avpn::networkMemoryRemember(m, QStringLiteral("wifi"), QStringLiteral("9:awg"), now - 100);
        m = avpn::networkMemoryRemember(m, QStringLiteral("cellular:250-02"), QStringLiteral("9:xray"), now - 50);
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("wifi"), now) == QLatin1String("9:awg"), "wifi remembered");
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("cellular:250-02"), now) == QLatin1String("9:xray"),
              "operator remembered separately");
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("cellular:250-01"), now).isEmpty(),
              "another operator has no memory");
        m = avpn::networkMemoryRemember(m, QStringLiteral("wifi"), QStringLiteral("2:awg"), now - 10);
        CHECK(avpn::networkMemoryLookup(m, QStringLiteral("wifi"), now) == QLatin1String("2:awg"),
              "newer success replaces the entry");
        // review item 5: entries older than 7 days are ignored
        const QByteArray old = avpn::networkMemoryRemember(QByteArray(), QStringLiteral("wifi"), QStringLiteral("9:awg"),
                                                           now - avpn::kNetworkMemoryMaxAgeSec - 1);
        CHECK(avpn::networkMemoryLookup(old, QStringLiteral("wifi"), now).isEmpty(), "older than 7 days -> ignored");
        const QByteArray fresh = avpn::networkMemoryRemember(QByteArray(), QStringLiteral("wifi"), QStringLiteral("9:awg"),
                                                             now - avpn::kNetworkMemoryMaxAgeSec + 60);
        CHECK(avpn::networkMemoryLookup(fresh, QStringLiteral("wifi"), now) == QLatin1String("9:awg"),
              "just under 7 days -> used");
        CHECK(avpn::networkMemoryLookup(R"([{"k":"wifi","n":"9:awg"}])", QStringLiteral("wifi"), now).isEmpty(),
              "entry without a timestamp -> ignored");
        // forget only if it still points at the failed node
        QByteArray f = avpn::networkMemoryForget(m, QStringLiteral("wifi"), QStringLiteral("9:awg"));
        CHECK(avpn::networkMemoryLookup(f, QStringLiteral("wifi"), now) == QLatin1String("2:awg"),
              "failure of an older node keeps the newer entry");
        f = avpn::networkMemoryForget(m, QStringLiteral("wifi"), QStringLiteral("2:awg"));
        CHECK(avpn::networkMemoryLookup(f, QStringLiteral("wifi"), now).isEmpty(), "failed remembered node is forgotten");
        CHECK(avpn::networkMemoryLookup(f, QStringLiteral("cellular:250-02"), now) == QLatin1String("9:xray"),
              "other networks untouched");
        CHECK(avpn::networkMemoryRemember(m, QString(), QStringLiteral("x"), now) == m, "no key -> no write");
        CHECK(avpn::networkMemoryLookup("not json", QStringLiteral("wifi"), now).isEmpty(), "corrupt blob -> empty");
        QByteArray big;
        for (int i = 0; i < avpn::kNetworkMemoryMax + 5; ++i)
            big = avpn::networkMemoryRemember(big, QStringLiteral("cellular:%1").arg(i), QStringLiteral("n"), now - 100 + i);
        CHECK(QJsonDocument::fromJson(big).array().size() == avpn::kNetworkMemoryMax, "memory is capped");
        CHECK(avpn::networkMemoryLookup(big, QStringLiteral("cellular:%1").arg(avpn::kNetworkMemoryMax + 4), now)
                  == QLatin1String("n"),
              "cap drops the oldest, keeps the newest");
        CHECK(avpn::networkMemoryLookup(big, QStringLiteral("cellular:0"), now).isEmpty(), "oldest dropped");
    }

    std::printf("%s: %d/%d checks\n", failures ? "whoami_verdict_check: FAILED" : "whoami_verdict_check: OK",
                total - failures, total);
    return failures ? 1 : 0;
}

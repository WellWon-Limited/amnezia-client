#pragma once
// AVPN (plan v3 step 5, 2026-11-05; review fixes 2026-11-05): honest "Connected". After the tunnel
// comes up the facade makes GET /v1/whoami through it (the same API client as every other /v1 call)
// and these pure functions turn what arrived into a verdict and the next step. No I/O here; test:
// tests/whoami_verdict_check.cpp.
//
// Backend contract (tribe-backend api/openapi.yaml, plan step 4):
//   GET /v1/whoami?nonce=<[A-Za-z0-9._-]{1,64}>, device-token Bearer auth.
//   200: 64-256 KiB of random bytes (128 KiB by default), no compression; headers
//        X-Whoami-Ip (client IP as seen by the API), X-Whoami-Node (integer node id, 0 = not one of
//        our nodes), X-Whoami-Country (ISO2 or empty), X-Whoami-Sha256 (hex sha256 of the body),
//        X-Whoami-Nonce (echo), X-Whoami-Len.
//   400 forged proxy chain, 401 bad token, 404 feature off on the server, 429 rate limited
//        (6/min per device, Retry-After).
//
// Verdicts:
//   NoData       - 200, but data did not pass: fewer than 16 KiB arrived (headers came, the body
//                  froze - the "freezes after ~5 KB" path), a complete body with a wrong sha256, a
//                  body cut by the path (not by our timeout), or a wrong nonce echo (a cached/foreign
//                  answer). Next path of the same attempt.
//   BypassVpn    - data passed, but X-Whoami-Node == 0: the request left past the tunnel. Next path
//                  of the same attempt (after one retry: the early-answer race before routes settle).
//   CheckLimited - 429 or 404 only: the server refused to run the check. Connected, no green mark,
//                  and NOT counted as proven data (the give-up streak is not reset).
//   Inconclusive - nothing decided: no HTTP answer, any other status, or a 200 without a usable node
//                  header. The existing generate_204 check decides with the rest of the verify
//                  budget (whoamiTiebreakVerdict): passes -> CheckLimited, fails -> NoData.
//   Works        - data flows through one of our exits. A body cut by OUR OWN timeout after >= 16 KiB
//                  counts as Works too (slow link); the hash is checked only on a complete body.

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QtGlobal>

namespace avpn {

enum class WhoamiVerdict { Works, NoData, BypassVpn, CheckLimited, Inconclusive };
enum class WhoamiStep { Finish, Retry, Tiebreak };

// The contract's minimum body is 64 KiB; less than 16 KiB is "data does not pass" (plan step 5).
constexpr qint64 kWhoamiMinBodyBytes = 16 * 1024;
// A body above this is not our whoami (contract max is 256 KiB): stop downloading on metered links.
constexpr qint64 kWhoamiMaxBodyBytes = 1024 * 1024;
// At most this many whoami requests per verification (one retry), under the server's 6/min limit.
constexpr int kWhoamiMaxAttempts = 2;
// A whoami request needs at least this much of the whoami budget left to be worth starting.
constexpr int kWhoamiMinAttemptMs = 1000;
// Pause before the one retry (no answer, or the first answer said "past the VPN").
constexpr int kWhoamiRetryDelayMs = 1000;

struct WhoamiObservation {
    int httpStatus = 0;          // 0 = no HTTP answer (transport error / timeout before headers)
    bool complete = false;       // the body finished without error
    bool timedOut = false;       // the request was cut by our own timeout (armTimeout)
    qint64 bytesReceived = 0;    // body bytes that actually arrived, also on a cut transfer
    QByteArray bodySha256Hex;    // hex sha256 of the received bytes
    QByteArray headerSha256;     // X-Whoami-Sha256 (empty = missing)
    QByteArray sentNonce;        // nonce we sent
    QByteArray headerNonce;      // X-Whoami-Nonce (empty = missing)
    bool nodeHeaderPresent = false;
    qint64 node = -1;            // X-Whoami-Node; -1 = present but not an integer
};

inline WhoamiVerdict whoamiVerdict(const WhoamiObservation &o)
{
    if (o.httpStatus == 429 || o.httpStatus == 404)
        return WhoamiVerdict::CheckLimited;
    if (o.httpStatus != 200)
        return WhoamiVerdict::Inconclusive;
    if (o.bytesReceived < kWhoamiMinBodyBytes)
        return WhoamiVerdict::NoData;
    if (o.sentNonce.isEmpty() || o.headerNonce.trimmed() != o.sentNonce)
        return WhoamiVerdict::NoData;
    if (o.complete) {
        if (o.headerSha256.isEmpty() || o.bodySha256Hex.toLower() != o.headerSha256.trimmed().toLower())
            return WhoamiVerdict::NoData;
    } else if (!o.timedOut) {
        return WhoamiVerdict::NoData; // cut by the path (reset/abort), not by our clock
    }
    if (!o.nodeHeaderPresent || o.node < 0)
        return WhoamiVerdict::Inconclusive;
    if (o.node == 0)
        return WhoamiVerdict::BypassVpn;
    return WhoamiVerdict::Works;
}

// What to do after one whoami answer: one retry for "past the VPN" (routes of a fresh tunnel may not
// have settled) and for "no HTTP answer at all", within the attempt cap and the whoami budget; any
// other inconclusive answer goes straight to the generate_204 tiebreak.
inline WhoamiStep whoamiNextStep(WhoamiVerdict v, int httpStatus, int attemptsDone, qint64 whoamiBudgetLeftMs)
{
    // The retry starts after kWhoamiRetryDelayMs and then needs a whole attempt's worth of budget.
    const bool canRetry = attemptsDone < kWhoamiMaxAttempts
                          && whoamiBudgetLeftMs >= kWhoamiRetryDelayMs + kWhoamiMinAttemptMs;
    if (v == WhoamiVerdict::BypassVpn)
        return canRetry ? WhoamiStep::Retry : WhoamiStep::Finish;
    if (v == WhoamiVerdict::Inconclusive)
        return (httpStatus == 0 && canRetry) ? WhoamiStep::Retry : WhoamiStep::Tiebreak;
    return WhoamiStep::Finish;
}

// The tiebreak is the existing generate_204 verification with the rest of the verify budget.
inline WhoamiVerdict whoamiTiebreakVerdict(bool generate204Passed)
{
    return generate204Passed ? WhoamiVerdict::CheckLimited : WhoamiVerdict::NoData;
}

// whoami may use at most ~60 % of the verify budget (xray_verify_timeout_ms); the rest is reserved
// for the tiebreak, so a whoami timeout never leaves the path without a decision.
inline qint64 whoamiBudgetMs(int verifyBudgetMs)
{
    return qint64(verifyBudgetMs) * 6 / 10;
}

// The verdict that moves the attempt to the next path (AWG -> Xray of the same country -> another
// country) via the existing step 3 of the healing ladder (ServiceEngine::verifyFailed).
inline bool whoamiFailsPath(WhoamiVerdict v)
{
    return v == WhoamiVerdict::NoData || v == WhoamiVerdict::BypassVpn;
}

// Parse X-Whoami-Node: present + integer -> value; present + garbage -> -1.
inline qint64 parseWhoamiNode(const QByteArray &header, bool *present)
{
    const QByteArray v = header.trimmed();
    if (present)
        *present = !v.isEmpty();
    if (v.isEmpty())
        return -1;
    bool ok = false;
    const qint64 n = v.toLongLong(&ok);
    return (ok && n >= 0) ? n : -1;
}

// A request to the tunnel's own server address leaves outside the tunnel: the endpoint route is
// excluded on every platform, and macOS xray with the RU split routes it directly
// (client/vpnconnection.cpp, VpnAllExceptSites). api.tribevpn.com resolves to the xray entry
// (201.34.134.103), so whoami there would read "past the VPN" on every such path. If the active API
// base resolves to the current tunnel endpoint, whoami goes to another known edge whose known
// addresses do not include it (an edge not resolved yet still beats the known-bad one); otherwise,
// and when nothing better is known, the active base. Only whoami uses this - other API calls keep
// their base.
inline QString whoamiBaseUrl(const QString &activeBase, const QStringList &edgeBases,
                             const QHash<QString, QStringList> &hostIps, const QString &tunnelEndpointIp)
{
    if (tunnelEndpointIp.isEmpty())
        return activeBase;
    const auto hitsEndpoint = [&](const QString &base) {
        const QString host = QUrl(base).host();
        return host == tunnelEndpointIp || hostIps.value(host).contains(tunnelEndpointIp);
    };
    if (!hitsEndpoint(activeBase))
        return activeBase;
    const QString activeHost = QUrl(activeBase).host();
    for (const QString &e : edgeBases)
        if (QUrl(e).host() != activeHost && !hitsEndpoint(e))
            return e;
    return activeBase;
}

// Name for the journal, the bench report and the QML property pathCheck.
inline QString whoamiVerdictName(WhoamiVerdict v)
{
    switch (v) {
    case WhoamiVerdict::Works:        return QStringLiteral("works");
    case WhoamiVerdict::NoData:       return QStringLiteral("no_data");
    case WhoamiVerdict::BypassVpn:    return QStringLiteral("bypass");
    case WhoamiVerdict::CheckLimited: return QStringLiteral("limited");
    case WhoamiVerdict::Inconclusive: return QStringLiteral("inconclusive");
    }
    return QStringLiteral("inconclusive");
}

// Reason string for ServiceEngine::verifyFailed -> onDead. Not one of the health-DEAD reasons, so
// the ladder skips rebind/re-up of the same node and goes straight to step 3 (other path).
inline QString whoamiFailoverReason(WhoamiVerdict v)
{
    return v == WhoamiVerdict::BypassVpn ? QStringLiteral("whoami bypass (failover)")
                                         : QStringLiteral("whoami no data (failover)");
}

} // namespace avpn

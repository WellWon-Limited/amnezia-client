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
//   CheckLimited - 429 or 404 only: the server refused to run the check. AWG: Connected, no green
//                  mark, NOT counted as proven data (the give-up streak is not reset). Xray: the
//                  generate_204 tiebreak first - Xray is Connected only after a probe (§22.5).
//   Inconclusive - nothing decided: no HTTP answer, any other status, or a 200 without a usable node
//                  header. The existing generate_204 check decides with the rest of the verify
//                  budget (whoamiTiebreakVerdict): passes -> CheckLimited, fails -> NoData.
//   Works        - data flows through one of our exits. A body cut by OUR OWN timeout after >= 16 KiB
//                  counts as Works too (slow link); the hash is checked only on a complete body.

#include "DataCheckRetry.h"

#include <QByteArray>
#include <QString>
#include <QtGlobal>

namespace avpn {

enum class WhoamiVerdict { Works, NoData, BypassVpn, CheckLimited, Inconclusive };
enum class WhoamiStep { Finish, Retry, Tiebreak };
// Before a whoami request: send it, hand over to the tiebreak, or - nothing was sent and the whole
// verify budget is already gone (the app was suspended, timers fired late) - no evidence at all.
enum class WhoamiGate { Send, Tiebreak, NoEvidence };
// What a verdict does to the attempt.
enum class WhoamiAction { Succeed, FailPath, ConnectUnproven, Tiebreak };

// The contract's minimum body is 64 KiB; less than 16 KiB is "data does not pass" (plan step 5).
constexpr qint64 kWhoamiMinBodyBytes = 16 * 1024;
// S3 (device round 5): once bytes flow, a gap longer than this ends the whoami request (progress, not a hard cut).
constexpr qint64 kWhoamiStallMs = 1000;
// T1 (device round 6): after this long with no first byte a data check is "starving" - a proven alternative from the
// race may end it (a working path answers within a second on every network measured).
constexpr qint64 kWhoamiFirstByteShareMs = 1000;
// true = our clock ends the request now: no first byte within firstByteLimitMs, or bytes stopped for kWhoamiStallMs.
// lastByteAtMs < 0 = nothing arrived yet. A request that keeps receiving runs on (up to the check's own backstop).
inline bool whoamiProgressCut(qint64 nowMs, qint64 startMs, qint64 lastByteAtMs, qint64 firstByteLimitMs)
{
    if (lastByteAtMs < 0)
        return nowMs - startMs > firstByteLimitMs;
    return nowMs - lastByteAtMs > kWhoamiStallMs;
}
// A body above this is not our whoami (contract max is 256 KiB): stop downloading on metered links.
constexpr qint64 kWhoamiMaxBodyBytes = 1024 * 1024;
// At most this many ANSWERED whoami requests per verification (one retry after an answer), under the server's
// 6/min limit. A try that got no HTTP answer at all is not counted here: the server did not answer it, and the
// whoami budget bounds such tries (whoamiNext).
constexpr int kWhoamiMaxAttempts = 2;
// A whoami request needs at least this much of the whoami budget left to be worth starting (the same floor as a
// retry of any data check, DataCheckRetry.h).
constexpr int kWhoamiMinAttemptMs = int(kDataCheckRetryMinLeftMs);

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

// "Not yet" (floor 19.11, DataCheckRetry.h): the try got no HTTP answer and no byte - no route yet, DNS not
// answered, connection refused or reset before any byte, or our clock found no first byte. This is what the old
// 800 ms wait before the first try stood for; the check now starts as soon as the tunnel is up and retries this.
inline bool whoamiNotYet(const WhoamiObservation &o)
{
    return o.httpStatus == 0 && o.bytesReceived <= 0;
}

struct WhoamiNext {
    WhoamiStep step = WhoamiStep::Finish;
    qint64 delayMs = 0; // Retry: wait this long, then the next request
};

// What to do after one whoami try. answeredSoFar = tries of this check that got an HTTP answer (the server counted
// them), this one included; retriesSoFar = retries already made in this check (any kind); whoamiBudgetLeftMs = the
// whoami share of the check budget left now. The spacing and the budget floor are the shared data-check rule
// (DataCheckRetry.h: 300, 600, 1200 ms ..., at least kWhoamiMinAttemptMs left after the spacing).
//  - not yet (no answer, no byte): retry on the spacing while the budget allows, then the generate_204 tiebreak;
//  - "past the VPN" (the answer came by the physical path - routes of a fresh tunnel not applied yet): one retry on
//    the same spacing within the answered-request cap, then bypass is final;
//  - any other inconclusive answer: the tiebreak; every other verdict is final.
inline WhoamiNext whoamiNext(WhoamiVerdict v, const WhoamiObservation &o, int answeredSoFar, int retriesSoFar,
                             qint64 whoamiBudgetLeftMs)
{
    WhoamiNext n;
    const DataCheckRetry spacing = decideDataCheckRetry(true, retriesSoFar, whoamiBudgetLeftMs);
    if (whoamiNotYet(o)) {
        n.step = spacing.retry ? WhoamiStep::Retry : WhoamiStep::Tiebreak;
        n.delayMs = spacing.retry ? spacing.delayMs : 0;
        return n;
    }
    if (v == WhoamiVerdict::BypassVpn) {
        if (spacing.retry && answeredSoFar < kWhoamiMaxAttempts) {
            n.step = WhoamiStep::Retry;
            n.delayMs = spacing.delayMs;
        }
        return n;
    }
    if (v == WhoamiVerdict::Inconclusive)
        n.step = WhoamiStep::Tiebreak;
    return n;
}

// The tiebreak is the existing generate_204 verification with the rest of the verify budget.
// requestsSent counts every request of this verification (whoami and generate_204): a failure with
// none sent is a spent budget, not evidence - no verdict, never NoData.
inline WhoamiVerdict whoamiTiebreakVerdict(bool generate204Passed, int requestsSent)
{
    if (generate204Passed || requestsSent == 0)
        return WhoamiVerdict::CheckLimited;
    return WhoamiVerdict::NoData;
}

// A request's timer that fires more than this after it was due means the process was suspended
// (iOS froze the app, timers ran on return) - evidence of suspension, not of a dead path.
constexpr qint64 kWhoamiLateTimerSlackMs = 2000;

inline bool timerFiredLate(qint64 sinceArmMs, qint64 scheduledTimeoutMs)
{
    return sinceArmMs > scheduledTimeoutMs + kWhoamiLateTimerSlackMs;
}

// The whoami request was cut (no HTTP answer, or a 200 whose body stopped) and its timer fired late:
// the would-be NoData/Inconclusive is a suspension artefact - no evidence, the attempt connects
// without the mark (CheckLimited), the request is not counted, memory and streak are untouched.
// Evidence that did arrive stands: >= 16 KiB (Works), a complete answer, a bypass, a 429/404.
inline bool whoamiCutBySuspension(WhoamiVerdict v, const WhoamiObservation &o, qint64 sinceArmMs,
                                  qint64 scheduledTimeoutMs)
{
    const bool cut = o.httpStatus == 0 || (o.httpStatus == 200 && !o.complete);
    const bool failing = v == WhoamiVerdict::NoData || v == WhoamiVerdict::Inconclusive;
    return cut && failing && timerFiredLate(sinceArmMs, scheduledTimeoutMs);
}

// Gate before each whoami request (whoamiLeftMs = whoami share of the budget left, totalLeftMs = the
// whole verify budget left).
inline WhoamiGate whoamiAttemptGate(int requestsSent, qint64 whoamiLeftMs, qint64 totalLeftMs)
{
    if (whoamiLeftMs >= kWhoamiMinAttemptMs)
        return WhoamiGate::Send;
    if (requestsSent == 0 && totalLeftMs <= 0)
        return WhoamiGate::NoEvidence;
    return WhoamiGate::Tiebreak;
}

// What the verdict does. tiebreakDone = the generate_204 tiebreak already produced this verdict
// (it is final then - no second tiebreak).
inline WhoamiAction whoamiAction(WhoamiVerdict v, bool xrayTransport, bool tiebreakDone)
{
    switch (v) {
    case WhoamiVerdict::Works:
        return WhoamiAction::Succeed;
    case WhoamiVerdict::NoData:
    case WhoamiVerdict::BypassVpn:
        return WhoamiAction::FailPath;
    case WhoamiVerdict::CheckLimited:
        // A bare 429/404 of our API is not attributable to the tunnel on any transport (review E7 of 18.11: the
        // API may answer past the tunnel): the probe through the tunnel (generate_204) decides. After it, the
        // probe passed - data through this tunnel.
        Q_UNUSED(xrayTransport)
        return tiebreakDone ? WhoamiAction::ConnectUnproven : WhoamiAction::Tiebreak;
    case WhoamiVerdict::Inconclusive:
        return tiebreakDone ? WhoamiAction::ConnectUnproven : WhoamiAction::Tiebreak;
    }
    return WhoamiAction::ConnectUnproven;
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

// The alternate API edge for whoami on Xray (the second baked edge, AvpnEngineQml kBakedEdges).
constexpr const char kWhoamiXrayEdge[] = "https://vpn.wellwon.hk";

// Where whoami goes. Xray: always the alternate edge. api.tribevpn.com resolves to the Timeweb host
// that is also the Xray entry (201.34.134.103). Routing of an app request to it while Xray is up
// (checked in code for 5.1.109; the earlier note "macOS xray with the RU split routes it directly"
// did not hold):
//  - macOS service (not MACOS_NE): Xray is always full tunnel - VpnConnectionTunnelControl::up sets
//    splitOn=false for an Xray node, so client/vpnconnection.cpp never adds the VpnAllExceptSites host
//    route to the server; XrayProtocol::setupRouting sends 1/8..128/1 into the tun and only xray-core's
//    own sockets are bound to the physical interface (service/server/xray.cpp) - the request enters
//    the tunnel;
//  - iOS / MACOS_NE: the RU split stays on (the NE excludes splitTunnelSites,
//    PacketTunnelProvider+Xray.swift), but the API addresses are carved out of that list
//    (AvpnEngineQml::apiCarveIps / rebuildApiCarveOut) and the compiled ru_prefixes.h has no prefix
//    covering 201.34.134.103 - the request enters the tunnel too;
//  - Android / Windows raise no Xray.
// The choice of the alternate edge itself is unchanged. AWG: the active API address. A dev backend
// (AVPN_API_URL) keeps its own base - its tokens are not valid on the prod edge. Only whoami and the
// live probe (liveProbePingUrl) use this; other API calls keep their base.
inline QString whoamiBaseUrl(const QString &activeBase, bool xrayTransport, bool devBackend)
{
    if (!xrayTransport || devBackend)
        return activeBase;
    return QString::fromLatin1(kWhoamiXrayEdge);
}

// The live probe's first-party ping (QualityProbe: the card's ms, ONLINE, the Xray death detector
// ServiceEngine::feedProbeResult) - on the same edge as whoami (on Xray api.tribevpn.com is the
// entry host of the same path; routing per platform - see whoamiBaseUrl). AWG: the active API
// address, as before.
inline QString liveProbePingUrl(const QString &activeBase, bool xrayTransport, bool devBackend)
{
    return whoamiBaseUrl(activeBase, xrayTransport, devBackend) + QStringLiteral("/v1/ping");
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

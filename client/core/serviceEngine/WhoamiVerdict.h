#pragma once
// AVPN (plan v3 step 5, 2026-11-05): honest "Connected". After the tunnel comes up the facade makes
// ONE GET /v1/whoami through it (the same API client as every other /v1 call) and this pure
// function turns what arrived into a verdict. No I/O here; test: tests/whoami_verdict_check.cpp.
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
//   NoData      - the API answered 200, but the body did not arrive whole: shorter than 16 KiB
//                 (including a transfer that stalled after the headers - the "freezes after ~5 KB"
//                 path), sha256 mismatch, or the nonce echo is wrong (a cached/foreign answer).
//                 The path does not carry data: next path of the same attempt.
//   BypassVpn   - the body is intact, but X-Whoami-Node == 0: the request left through an address
//                 that is not one of our nodes, i.e. past the tunnel. Next path of the same attempt.
//   CheckLimited- the check itself could not run: no HTTP answer at all (transport error, timeout
//                 before the headers - the API may be down while the VPN works), any status other
//                 than 200 (429, 404, 401, 400, 5xx), or a 200 without the node header. Not a
//                 failure: the connection stays as it is, but it never gets the "data flows" mark.
//   Works       - everything above passed: data flows through one of our exits.

#include <QByteArray>
#include <QString>
#include <QtGlobal>

namespace avpn {

enum class WhoamiVerdict { Works, NoData, BypassVpn, CheckLimited };

// The contract's minimum body is 64 KiB; anything under 16 KiB is "data does not pass" even if the
// server was configured below the contract (plan step 5).
constexpr qint64 kWhoamiMinBodyBytes = 16 * 1024;
// A body above this is not our whoami (contract max is 256 KiB): stop downloading on metered links.
constexpr qint64 kWhoamiMaxBodyBytes = 1024 * 1024;
// At most this many requests per verification: one plus one retry when there was no HTTP answer
// at all (routes/DNS of a fresh tunnel not settled yet). Keeps a failover chain under the server's
// 6/min per-device limit.
constexpr int kWhoamiMaxAttempts = 2;
// A request needs at least this much of the verification budget left to be worth starting.
constexpr int kWhoamiMinAttemptMs = 1500;

struct WhoamiObservation {
    int httpStatus = 0;          // 0 = no HTTP answer (transport error / timeout before headers)
    qint64 bodyBytes = 0;        // bytes actually received, also on a stalled/aborted transfer
    QByteArray bodySha256Hex;    // hex sha256 of the received bytes
    QByteArray headerSha256;     // X-Whoami-Sha256 (empty = missing)
    QByteArray sentNonce;        // nonce we sent
    QByteArray headerNonce;      // X-Whoami-Nonce (empty = missing)
    bool nodeHeaderPresent = false;
    qint64 node = -1;            // X-Whoami-Node; -1 = present but not an integer
};

inline WhoamiVerdict whoamiVerdict(const WhoamiObservation &o)
{
    if (o.httpStatus != 200)
        return WhoamiVerdict::CheckLimited;
    if (o.bodyBytes < kWhoamiMinBodyBytes)
        return WhoamiVerdict::NoData;
    if (o.headerSha256.isEmpty() || o.bodySha256Hex.toLower() != o.headerSha256.trimmed().toLower())
        return WhoamiVerdict::NoData;
    if (o.sentNonce.isEmpty() || o.headerNonce.trimmed() != o.sentNonce)
        return WhoamiVerdict::NoData;
    if (!o.nodeHeaderPresent || o.node < 0)
        return WhoamiVerdict::CheckLimited;
    if (o.node == 0)
        return WhoamiVerdict::BypassVpn;
    return WhoamiVerdict::Works;
}

// The verdict that moves the attempt to the next path (AWG -> Xray of the same country -> another
// country) via the existing step 3 of the healing ladder (ServiceEngine::verifyFailed).
inline bool whoamiFailsPath(WhoamiVerdict v)
{
    return v == WhoamiVerdict::NoData || v == WhoamiVerdict::BypassVpn;
}

// Retry only when there was no HTTP answer at all, within the attempt cap and the time budget.
inline bool whoamiShouldRetry(const WhoamiObservation &o, int attemptsDone, qint64 budgetLeftMs)
{
    return o.httpStatus == 0 && attemptsDone < kWhoamiMaxAttempts && budgetLeftMs >= kWhoamiMinAttemptMs;
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

// Name for the journal, the bench report and the QML property pathCheck.
inline QString whoamiVerdictName(WhoamiVerdict v)
{
    switch (v) {
    case WhoamiVerdict::Works:        return QStringLiteral("works");
    case WhoamiVerdict::NoData:       return QStringLiteral("no_data");
    case WhoamiVerdict::BypassVpn:    return QStringLiteral("bypass");
    case WhoamiVerdict::CheckLimited: return QStringLiteral("limited");
    }
    return QStringLiteral("limited");
}

// Reason string for ServiceEngine::verifyFailed -> onDead. Not one of the health-DEAD reasons, so
// the ladder skips rebind/re-up of the same node and goes straight to step 3 (other path).
inline QString whoamiFailoverReason(WhoamiVerdict v)
{
    return v == WhoamiVerdict::BypassVpn ? QStringLiteral("whoami bypass (failover)")
                                         : QStringLiteral("whoami no data (failover)");
}

} // namespace avpn

// client/core/serviceEngine/UpstreamEngine.h
// AVPN serviceEngine - the pure decisions of the upstream-node wiring (lane L1): the policy tier inside the
// automatic pick, the network key of the standby pack, the data check of an upstream session (the
// tribe-probe-v1 digest, the facts -> UpstreamCheckInput, the route of the check), the tunnel owner's
// status object (contract §5), the persisted lease record (macOS adoption after a GUI restart), the
// at-rest form of the standby pack and the Xray tunables of the envelope (contract §3).
// [header-only, QtCore; pure: no I/O, no timers, no globals except TuningStore reads named below]
//
// Plan: ~/avpn-build/plans/provider-pool/client-integration-plan.md (points 4, 5, 7, 8, 9, 14; R1, R9,
// R10, R11); contract: client-envelope-contract.md. Upstream Amnezia has no counterpart.
// Tests: tests/upstream_engine_check.cpp (build_upstream_engine.sh).
#pragma once

#include "UpstreamLeaseMachine.h" // upstreamEarlyRetryDelayMs (lab 14.11 D3)
#include "UpstreamLeaseWire.h"
#include "UpstreamNode.h"
#include "UpstreamStandbyPack.h"
#include "UpstreamNode.h"
#include "UpstreamVerdict.h"
#include "dto/Subscription.h"
#if defined(Q_OS_IOS)
    #include "platforms/ios/IosNativePolicy.h" // kUpstreamProxyMeterSupported (the bridge's constant)
#endif

// Who owns an upstream session's lease (decision B; release C, lane P1). 1 = the app's GUI process renews,
// meters (the service's runtime status), keeps the adoption record and ends the session on a real quit:
// macOS desktop (root daemon) and Windows (Tribe-service.exe) - the desktop service has no device token
// and no TLS backend. 0 = the tunnel process owns it after the hand-over: iOS / macOS NE (the extension)
// and Android (the Xray service process, decision A-1; ~/avpn-build/plans/provider-pool/android-ipc-contract.md).
#if (defined(Q_OS_MACOS) && !defined(MACOS_NE)) || defined(Q_OS_WIN)
    #define AVPN_UPSTREAM_GUI_OWNER 1
#else
    #define AVPN_UPSTREAM_GUI_OWNER 0
#endif

#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QtEndian>

#include <cmath>
#include <functional>
#include <limits>

namespace avpn {

// --- envelope constants (contract §1) ------------------------------------------------------------------

// hostName of an upstream session: a constant, never a provider host. An IP literal from the
// documentation range (RFC 5737) on purpose: the desktop XrayProtocol passes hostName through
// NetworkUtilities::getIPAddress, which would RESOLVE a name synchronously on the VpnConnection thread
// (a hang on a whitelisted network); a literal is returned as is. It is never dialled (the core config
// carries the real outbounds) and only labels the session (iOS serverAddress, the desktop kill-switch
// allow rule, which then allows nothing real).
inline constexpr char kUpstreamDisplayHost[] = "192.0.2.1";

// --- network key of the standby pack request (D10; openapi NetworkKey) --------------------------------

// Radio of the CoreTelephony / Android category ("5g" | "lte" | "3g" | "2g" | "") in the key's grammar.
inline QString upstreamRadioOf(const QString &cellGen)
{
    const QString g = cellGen.trimmed().toLower();
    if (g == QLatin1String("5g")) return QStringLiteral("5g");
    if (g == QLatin1String("lte") || g == QLatin1String("4g")) return QStringLiteral("4g");
    if (g == QLatin1String("3g")) return QStringLiteral("3g");
    if (g == QLatin1String("2g")) return QStringLiteral("2g");
    return QStringLiteral("unknown");
}

// The operator-level class of the current network, nothing finer:
//   cell:<MCC>-<MNC>:<radio> | cell:asn:<ASN>:<radio> | wifi:asn:<ASN> | wifi | unknown.
// netType = AvpnEngineQml::doctorNetType() ("wifi" | "ethernet" | "cellular" | ""), carrierCode =
// TribeNetInfo carrierCode() ("250-02", the anonymous numeric operator code), accessAsn = the ASN the
// server reported for this device's access network on its last direct lease acquire on THIS network
// (0 = unknown). A Wi-Fi BSSID, SSID or address never enters the key.
inline QString upstreamNetworkKey(const QString &netType, const QString &carrierCode, const QString &cellGen,
                                  qint64 accessAsn)
{
    static const QRegularExpression mccMnc(QStringLiteral("^([0-9]{3})-([0-9]{2,3})$"));
    const bool asnOk = accessAsn >= 1 && accessAsn <= 4294967295LL;
    if (netType == QLatin1String("cellular")) {
        const QString radio = upstreamRadioOf(cellGen);
        if (mccMnc.match(carrierCode.trimmed()).hasMatch())
            return QStringLiteral("cell:") + carrierCode.trimmed() + QLatin1Char(':') + radio;
        if (asnOk)
            return QStringLiteral("cell:asn:%1:%2").arg(accessAsn).arg(radio);
        return QStringLiteral("unknown");
    }
    if (netType == QLatin1String("wifi") || netType == QLatin1String("ethernet"))
        return asnOk ? QStringLiteral("wifi:asn:%1").arg(accessAsn) : QStringLiteral("wifi");
    return QStringLiteral("unknown");
}

inline bool upstreamNetworkKeyValid(const QString &k)
{
    static const QRegularExpression re(QStringLiteral(
        "^(cell:[0-9]{3}-[0-9]{2,3}:(2g|3g|4g|5g|unknown)|cell:asn:[0-9]{1,10}:(2g|3g|4g|5g|unknown)"
        "|wifi:asn:[0-9]{1,10}|wifi|unknown)$"));
    return k.size() <= 48 && re.match(k).hasMatch();
}

// --- the data check (point 8, decision D) ----------------------------------------------------------------

// Body scheme tribe-probe-v1 (openapi /v1/probe): block_i = SHA-256(ASCII("tribe-probe-v1") || 0x00 ||
// ASCII(nonce) || 0x00 || uint32_be(i)), body = the first n bytes of block_0 || block_1 || ...
inline QByteArray tribeProbeBody(const QByteArray &nonce, qint64 n)
{
    QByteArray out;
    if (n <= 0)
        return out;
    out.reserve(int(qMin<qint64>(n, 64 * 1024 * 1024)));
    const QByteArray prefix = QByteArrayLiteral("tribe-probe-v1") + '\0' + nonce + '\0';
    for (quint32 i = 0; out.size() < n; ++i) {
        uchar be[4];
        qToBigEndian(i, be);
        QCryptographicHash h(QCryptographicHash::Sha256);
        h.addData(prefix);
        h.addData(QByteArrayView(reinterpret_cast<const char *>(be), 4));
        out += h.result();
    }
    out.truncate(int(n));
    return out;
}

// Lower-case hex SHA-256 of the body the server must send for (nonce, n) - computed locally, the
// answer's X-Tribe-Probe-Sha256 header is never trusted alone.
inline QByteArray tribeProbeExpectedSha256Hex(const QByteArray &nonce, qint64 n)
{
    return QCryptographicHash::hash(tribeProbeBody(nonce, n), QCryptographicHash::Sha256).toHex();
}

// The Authorization header of GET /v1/probe (openapi scanToken scheme, bearerFormat "tsc1.<base64url>"):
// the lease answer's probe.scan_token already IS the whole opaque "tsc1.…" value - it is sent exactly as
// delivered, never with a second prefix.
inline QByteArray upstreamProbeAuthorization(const QString &scanToken)
{
    return QByteArrayLiteral("Bearer ") + scanToken.toUtf8();
}

// What the facade measured for one GET /v1/probe through the tunnel.
struct UpstreamProbeFacts {
    int httpStatus = 0;
    qint64 bytesRequested = 0;
    qint64 bytesReceived = 0;
    QByteArray bodySha256Hex;   // of the bytes that arrived
    QByteArray nonce;
    qint64 elapsedMs = -1, ttfbMs = -1, maxStallMs = -1;
    QString egressClass;        // X-Tribe-Egress-Class
    QString egressAsnHeader;    // X-Tribe-Egress-Asn: a number or "unknown"
    QString egressNetToken;     // X-Tribe-Net-Token
    QString egressNode;         // X-Tribe-Egress-Node (our host node id, only with class tribe-node; Scanner F2)
    qint64 wireBytes = 0;       // response headers + body bytes as read (the Scanner's ledger; never clamped)
    bool cutAtCap = false;      // aborted because ProbeRequest::maxWireBytes would have been passed
};

// Facts + the lease's access facts -> the verdict input. The digest is ours (expected for the nonce and
// the REQUESTED size) against the received bytes; a non-200 answer carries no data at all.
inline UpstreamCheckInput upstreamCheckInputFrom(const UpstreamProbeFacts &f, const UpstreamProbeGrant &access,
                                                 bool strictUnverifiable,
                                                 const UpstreamCheckLimits &limits = UpstreamCheckLimits())
{
    UpstreamCheckInput in;
    in.bytesRequested = f.bytesRequested;
    in.bytesReceived = f.httpStatus == 200 ? f.bytesReceived : 0;
    in.digestOk = f.httpStatus == 200 && f.bytesReceived == f.bytesRequested && !f.nonce.isEmpty()
                  && f.bodySha256Hex.toLower() == tribeProbeExpectedSha256Hex(f.nonce, f.bytesRequested);
    in.elapsedMs = f.elapsedMs;
    in.ttfbMs = f.ttfbMs;
    in.maxStallMs = f.maxStallMs;
    in.limits = limits;
    in.egressClass = f.egressClass;
    bool ok = false;
    const qint64 asn = f.egressAsnHeader.trimmed().toLongLong(&ok);
    in.egressAsn = (ok && asn > 0 && asn <= 4294967295LL) ? asn : 0;
    in.egressNetToken = f.egressNetToken;
    in.accessAsn = access.accessAsn;
    in.accessNetToken = access.accessNetToken;
    in.strictUnverifiable = strictUnverifiable;
    return in;
}

// How the facade verifies an upstream session right now (whoami is NEVER used for one).
enum class UpstreamVerifyRoute {
    Probe,           // the lease carried a probe grant: sized /v1/probe through the tunnel
    WaitForGrant,    // a provisional session whose lease is not confirmed yet: retry shortly in the budget
    Fallback204,     // older server (no probe grant): the generate_204 + rx proof check, then Unverifiable
};

inline UpstreamVerifyRoute decideUpstreamVerifyRoute(bool probeGrantPresent, bool provisionalPending,
                                                     qint64 budgetLeftMs)
{
    if (probeGrantPresent)
        return UpstreamVerifyRoute::Probe;
    if (provisionalPending && budgetLeftMs > 0)
        return UpstreamVerifyRoute::WaitForGrant;
    return UpstreamVerifyRoute::Fallback204;
}

// The result of the fallback check: data went through the tunnel (generate_204 with rx proof) but the
// path cannot be compared -> Unverifiable (passes unless features.upstream_unverifiable_strict); no data
// -> NoData.
inline UpstreamVerdictResult upstreamFallbackVerdict(bool dataProven, bool strictUnverifiable)
{
    UpstreamVerdictResult r;
    if (!dataProven) {
        r.verdict = UpstreamVerdict::NoData;
        r.reason = QStringLiteral("fallback_no_data");
        return r;
    }
    r.verdict = UpstreamVerdict::Unverifiable;
    r.reason = r.pathReason = QStringLiteral("unverifiable_no_probe_grant");
    r.passes = !strictUnverifiable;
    return r;
}

// --- the first seconds of a provider profile (lab 14.11 D3) -------------------------------------------
// A profile may refuse EVERY connection for its first ~1-1.2 s (measured on the leak-guarded ZRO "LTE"
// profiles: the balancer has no observatory result yet and falls back to `block`; on a mobile network that
// window can last several seconds). So neither the data check nor the provisional seat confirmation may
// judge the node on a single early attempt: an attempt that got nothing yet is retried while the EXISTING
// budget allows (no timer of its own), with a short growing spacing; only the last outcome decides.

// The spacing and the budget rule are the one rule of every data check through a fresh tunnel (DataCheckRetry.h:
// the own-server whoami uses it too; the seat confirmation uses the spacing). The check's first try goes as soon as
// the tunnel is up - the 800 ms clock wait before it is gone (floor 19.11): a try that got nothing is this retry.
// A retry is only worth it when at least this much budget is left after the spacing.
inline constexpr qint64 kUpstreamEarlyRetryMinLeftMs = kDataCheckRetryMinLeftMs;

// "Not yet": the attempt got nothing at all - no HTTP answer (connection refused / reset / closed by the
// profile's block fallback) or a 200 without a first byte. Anything else is an answer that is judged at
// once: a complete download with a bad verdict (NotThroughProvider, digest mismatch), a partial or slow
// download (the profile carries data), an HTTP error of our server.
inline bool upstreamProbeNotYet(const UpstreamProbeFacts &f)
{
    return f.bytesReceived <= 0 && (f.httpStatus == 0 || f.httpStatus == 200);
}

using UpstreamEarlyRetry = DataCheckRetry; // retry=false: the outcome of this attempt is the verdict

// notYet = this attempt got nothing yet; retriesSoFar = retries already made in this check; budgetLeftMs =
// what is left of the check's budget now (verify budget for the data check, the confirm budget for the
// seat). Pure: the caller's clock decides budgetLeftMs.
inline UpstreamEarlyRetry decideUpstreamEarlyRetry(bool notYet, int retriesSoFar, qint64 budgetLeftMs)
{
    return decideDataCheckRetry(notYet, retriesSoFar, budgetLeftMs);
}

// --- macOS: the GUI really quits during an upstream session (integration point 15, risk R3) -----------
// Owner decision 15.11: «Отключить, если прям выйти из приложения, а не свернуть в фон». On a REAL quit of
// the macOS GUI (Quit in the app or the tray menu, Cmd+Q / Dock, logout or shutdown, SIGINT/SIGTERM - every
// path that ends in QCoreApplication::quit/exit and so in aboutToQuit) an upstream session is ended through
// the engine's normal user stop: the lease is released with its final report (the existing 1.5 s bound) and
// the tunnel goes down, so the seat is free at once and no unaccounted provider session outlives the GUI that
// owns its lease. Closing or hiding the window, minimising, app nap and sleep never quit the process -
// nothing changes. Own nodes (AWG, own Xray) keep BUG-6 / CONNECT-INVARIANTS §19: the service holds the
// tunnel after the GUI quits. A restart for a self-update or a rollback is not a quit (the new copy adopts
// the session by its lease record). A crash or a force kill cannot run this: the seat is freed at TTL and the
// next start adopts the session by the lease record (point 9) - no watchdog for it.
enum class AppExitKind {
    Quit,    // the user (or the system: logout, shutdown, a signal) ends the GUI process
    Restart, // our own relaunch: self-update installed, rollback to the previous version
    Hide,    // window closed / hidden / minimised: the process stays (never reaches the quit hook)
};

// The whole wait of the quit path: the release's own 1.5 s bound + the stop reaching the service.
inline constexpr int kUpstreamQuitStopBoundMs = 2000;

inline bool upstreamQuitEndsSession(AppExitKind kind, bool upstreamNodesOn, bool upstreamSession)
{
    return kind == AppExitKind::Quit && upstreamNodesOn && upstreamSession;
}

struct UpstreamQuitHooks {
    std::function<void()> userStop;               // the engine's normal user stop (release, then stop)
    std::function<bool()> stopped;                // the stop reached the service (tunnel Disconnected)
    std::function<void(int)> pump;                // run the event loop for up to N ms
    std::function<qint64()> nowMs;                // a monotonic clock
    std::function<void(const QString &)> journal; // the reliability journal
};

// Runs the quit path when it applies (returns true) and waits at most boundMs for the stop - then the exit
// goes on regardless (a quit never hangs, a logout is never held beyond the bound). Not applicable: nothing
// is called at all (the quit is byte-for-byte the one before).
inline bool runUpstreamQuit(AppExitKind kind, bool upstreamNodesOn, bool upstreamSession, const UpstreamQuitHooks &h,
                            int boundMs = kUpstreamQuitStopBoundMs)
{
    if (!upstreamQuitEndsSession(kind, upstreamNodesOn, upstreamSession))
        return false;
    h.journal(QStringLiteral("upstream session ended on app quit"));
    h.userStop();
    const qint64 until = h.nowMs() + qMax(0, boundMs);
    while (!h.stopped()) {
        const qint64 left = until - h.nowMs();
        if (left <= 0)
            break;
        h.pump(int(qMin<qint64>(50, left)));
    }
    return true;
}

// --- what the user is told when the app leaves an upstream node (release A, point 16) ------------------
// One short non-blocking message per kind (AvpnEngineQml::upstreamNoticeText, the notification toast); the
// code itself goes only to the journal - never on screen. Slow and Unverifiable are not errors: no message.
enum class UpstreamNotice {
    None,        // no message (transient start problems, slow, unverifiable, unknown codes)
    SeatsBusy,   // every seat of the provider is taken: the next node is being connected
    NoTraffic,   // the provider path does not carry data / not through the provider / seat unconfirmed
    Unavailable, // the server ended or refused this node for us (disabled, lease gone, entitlement, quota)
};

// code = a lease reason (UpstreamLeaseMachine LeaveNode / TryNextCandidate, the start failure sink, the
// extension status) or an upstream verdict name (upstreamVerdictName); a "code/detail" start failure is
// judged by its code.
inline UpstreamNotice upstreamNoticeFor(const QString &codeIn)
{
    const QString code = codeIn.section(QLatin1Char('/'), 0, 0).trimmed();
    if (code == QLatin1String("no_seat") || code == QLatin1String("no_seat_reacquire")
        || code == QLatin1String("no_seat_standby"))
        return UpstreamNotice::SeatsBusy;
    if (code == QLatin1String("no_data") || code == QLatin1String("not_through_provider")
        || code == QLatin1String("standby_unconfirmed"))
        return UpstreamNotice::NoTraffic;
    if (code == QLatin1String("disabled") || code == QLatin1String("lease_gone") || code == QLatin1String("not_entitled")
        || code == QLatin1String("over_quota") || code == QLatin1String("bridge_refused")
        || code == QLatin1String("renew_rejected"))
        return UpstreamNotice::Unavailable;
    return UpstreamNotice::None;
}

// --- tunnel owner status (contract §5) and its rules ----------------------------------------------------

struct UpstreamStatusDecision {
    bool valid = false;           // an "upstream" object was given
    QString state;                // none | pending | active | terminal
    QString leaveCode;            // non-empty = leave the node through the dead-session path
    qint64 refreshRevision = 0;   // > 0 = refetch /v1/subscription once (newer upstream_revision)
    bool configChanged = false;   // noted, never interrupts
};

// knownRevision = the upstream_revision of the subscription in force (or the newest one a refresh was
// already asked for). Unknown terminal codes leave too (the owner already stopped the core); an unknown
// state is "none".
inline UpstreamStatusDecision decideUpstreamStatus(const QJsonObject &upstream, qint64 knownRevision)
{
    UpstreamStatusDecision d;
    if (upstream.isEmpty())
        return d;
    d.valid = true;
    const QString st = upstream.value(QLatin1String("state")).toString();
    d.state = (st == QLatin1String("pending") || st == QLatin1String("active") || st == QLatin1String("terminal"))
                  ? st : QStringLiteral("none");
    if (d.state == QLatin1String("terminal")) {
        const QString code = upstream.value(QLatin1String("code")).toString();
        static const QRegularExpression codeRe(QStringLiteral("^[a-z_]{1,32}$"));
        d.leaveCode = codeRe.match(code).hasMatch() ? code : QStringLiteral("terminal");
    }
    qint64 rev = 0;
    if (upstreamJsonInt(upstream.value(QLatin1String("revision")), 1, kUpstreamMaxRevision, rev) && rev > knownRevision)
        d.refreshRevision = rev;
    d.configChanged = upstream.value(QLatin1String("config_changed")).toBool();
    return d;
}

// One refetch per newer revision: a revision seen in a lease answer, a renewal, the status or a standby
// pack makes the app refresh the subscription once - never again for the same or an older value.
inline bool upstreamRevisionNeedsRefresh(qint64 seen, qint64 subscriptionRevision, qint64 alreadyAskedFor)
{
    return seen > 0 && seen > subscriptionRevision && seen > alreadyAskedFor;
}

// R11: the parser drops stubs while features.upstream_nodes is off (on a cached config it is on only
// within the bounded trust of its signed value, UpstreamNode.h::upstreamTrustedFromCache); the moment
// the switch turns on the pool must be fetched again, once.
inline bool upstreamFlagFlippedOn(bool wasOn, bool isOn)
{
    return isOn && !wasOn;
}

// --- persisted lease record (macOS GUI owner; adoption after a GUI restart) ----------------------------

// What the GUI keeps so that a restarted GUI that finds the daemon's Xray tunnel alive can re-identify the
// node and confirm the seat through the tunnel (a standby acquire of the same profile: the server returns
// the EXISTING lease - openapi acquire "re-acquiring the same profile returns the existing lease"). The
// renew token is NOT kept at rest: the re-acquire uses the device token and rotates it.
struct UpstreamLeaseRecord {
    QString nodeId;
    QString profileId;
    QString configSha256;
    QString apiBase;        // tunnel_api_base of the lease
    QString leaseId;
    qint64 expiresWallMs = 0; // device wall clock estimate of the lease end
    qint64 savedWallMs = 0;
    qint64 startedWallMs = 0; // wall clock of the bring-up: matched against the daemon's session start
    qint64 revision = 0;
    MeterScope scope = MeterScope::Tunnel;
    QStringList meterTags;    // the lease's meter_tags (proxy scope sums exactly these)

    bool valid() const
    {
        static const QRegularExpression idRe(QStringLiteral("^[A-Za-z0-9_-]{1,64}$"));
        static const QRegularExpression shaRe(QStringLiteral("^[0-9a-f]{64}$"));
        return nodeId == upstreamNodeIdFor(profileId) && idRe.match(profileId).hasMatch()
               && shaRe.match(configSha256).hasMatch() && !upstreamApiBaseNormalized(apiBase).isEmpty()
               && savedWallMs > 0;
    }
    QByteArray toJson() const
    {
        return QJsonDocument(QJsonObject{{QStringLiteral("node_id"), nodeId},
                                         {QStringLiteral("profile_id"), profileId},
                                         {QStringLiteral("config_sha256"), configSha256},
                                         {QStringLiteral("api_base"), apiBase},
                                         {QStringLiteral("lease_id"), leaseId},
                                         {QStringLiteral("expires_wall_ms"), double(expiresWallMs)},
                                         {QStringLiteral("saved_wall_ms"), double(savedWallMs)},
                                         {QStringLiteral("started_wall_ms"), double(startedWallMs)},
                                         {QStringLiteral("revision"), double(revision)},
                                         {QStringLiteral("meter_scope"), meterScopeName(scope)},
                                         {QStringLiteral("meter_tags"), QJsonArray::fromStringList(meterTags)}})
            .toJson(QJsonDocument::Compact);
    }
    static UpstreamLeaseRecord fromJson(const QByteArray &json)
    {
        UpstreamLeaseRecord r;
        const QJsonObject o = QJsonDocument::fromJson(json).object();
        r.nodeId = o.value(QLatin1String("node_id")).toString();
        r.profileId = o.value(QLatin1String("profile_id")).toString();
        r.configSha256 = o.value(QLatin1String("config_sha256")).toString();
        r.apiBase = o.value(QLatin1String("api_base")).toString();
        r.leaseId = o.value(QLatin1String("lease_id")).toString();
        r.expiresWallMs = qint64(o.value(QLatin1String("expires_wall_ms")).toDouble());
        r.savedWallMs = qint64(o.value(QLatin1String("saved_wall_ms")).toDouble());
        r.startedWallMs = qint64(o.value(QLatin1String("started_wall_ms")).toDouble());
        r.revision = qint64(o.value(QLatin1String("revision")).toDouble());
        r.scope = o.value(QLatin1String("meter_scope")).toString() == QLatin1String("proxy") ? MeterScope::Proxy
                                                                                            : MeterScope::Tunnel;
        parseUpstreamMeterTags(o.value(QLatin1String("meter_tags")), r.meterTags);
        if (r.meterTags.isEmpty())
            r.scope = MeterScope::Tunnel;
        return r;
    }
};

// A record older than this is not adopted (the session it describes is long gone).
inline constexpr qint64 kUpstreamRecordMaxAgeMs = 24LL * 3600 * 1000;

inline bool upstreamRecordAdoptable(const UpstreamLeaseRecord &r, qint64 nowWallMs)
{
    return r.valid() && nowWallMs >= r.savedWallMs - 60000 && nowWallMs - r.savedWallMs < kUpstreamRecordMaxAgeMs;
}

// The record describes THE session the daemon runs: the core was started within this window of the
// record's bring-up (the GUI writes the record before connectToVpn; the daemon stamps its start). A
// stale record of an earlier session (a crash before ClearRecord) never claims a later own-Xray session.
inline constexpr qint64 kUpstreamRecordStartWindowMs = 120000;

inline bool upstreamRecordMatchesSession(const UpstreamLeaseRecord &r, qint64 daemonStartedAtWallMs)
{
    if (r.startedWallMs <= 0 || daemonStartedAtWallMs <= 0)
        return false;
    const qint64 d = daemonStartedAtWallMs - r.startedWallMs;
    return d >= -5000 && d <= kUpstreamRecordStartWindowMs;
}

// How long an adopted session may run before its seat is confirmed: what is left of the lease (the
// server still accounts the seat until then), at least 60 s (one retry cycle), at most the max TTL.
inline qint64 upstreamAdoptConfirmBudgetMs(const UpstreamLeaseRecord &r, qint64 nowWallMs)
{
    return qBound<qint64>(60000, r.expiresWallMs - nowWallMs, qint64(kUpstreamLeaseTtlMaxS) * 1000);
}

// --- the standby pack at rest -----------------------------------------------------------------------------

// The exact signed body and its signature, as received (re-verified with parseStandbyPack on every load),
// plus the network key it was asked for and when (debug line only).
struct StandbyStored {
    QByteArray body;
    QByteArray sigB64;
    QString networkKey;
    qint64 fetchedWallMs = 0;
};

inline QByteArray serializeStandbyStored(const StandbyStored &s)
{
    return QJsonDocument(QJsonObject{{QStringLiteral("body_b64"), QString::fromLatin1(s.body.toBase64())},
                                     {QStringLiteral("sig_b64"), QString::fromLatin1(s.sigB64)},
                                     {QStringLiteral("network_key"), s.networkKey},
                                     {QStringLiteral("fetched_wall_ms"), double(s.fetchedWallMs)}})
        .toJson(QJsonDocument::Compact);
}

inline bool parseStandbyStored(const QByteArray &json, StandbyStored &out)
{
    const QJsonDocument d = QJsonDocument::fromJson(json);
    if (!d.isObject())
        return false;
    const QJsonObject o = d.object();
    const QString b = o.value(QLatin1String("body_b64")).toString();
    if (b.isEmpty())
        return false;
    out.body = QByteArray::fromBase64(b.toLatin1());
    out.sigB64 = o.value(QLatin1String("sig_b64")).toString().toLatin1();
    out.networkKey = o.value(QLatin1String("network_key")).toString();
    out.fetchedWallMs = qint64(o.value(QLatin1String("fetched_wall_ms")).toDouble());
    return true;
}

// A pack entry the bring-up may start from (provisional start, contract §2).
struct StandbyCandidate {
    QByteArray config;      // secret, never log
    QString configSha256;
    QString tunnelApiBase;
    qint64 packRevision = 0;
    QStringList meterTags;
};

// The usable entry for a stub, or none: the pack is fresh (standbyPackUsable on the wall clock) and the
// entry is not stale against the subscription (standbyEntryUsable). A pack without tunnel_api_base
// cannot confirm the seat through the tunnel: not usable.
inline bool standbyCandidateFor(const StandbyPack &pack, const SubscriptionNode &stub, qint64 subscriptionRevision,
                                qint64 nowWallMs, int maxAgeCapS, StandbyCandidate &out, QString *why = nullptr)
{
    const auto fail = [why](const QString &w) {
        if (why)
            *why = w;
        return false;
    };
    if (!stub.upstream.has_value())
        return fail(QStringLiteral("not_upstream"));
    const StandbyUse age = standbyPackUsable(pack, nowWallMs, maxAgeCapS);
    if (!age.usable)
        return fail(age.reason);
    if (pack.tunnelApiBase.isEmpty())
        return fail(QStringLiteral("no_tunnel_api_base"));
    const StandbyEntry *e = pack.find(stub.upstream->profileId);
    if (!e)
        return fail(QStringLiteral("no_entry"));
    const StandbyUse use = standbyEntryUsable(*e, &*stub.upstream, subscriptionRevision, pack.upstreamRevision);
    if (!use.usable)
        return fail(use.reason);
    out.config = e->config;
    out.configSha256 = e->configSha256;
    out.tunnelApiBase = pack.tunnelApiBase;
    out.packRevision = pack.upstreamRevision;
    out.meterTags = e->meterTags;
    if (why)
        *why = use.reason;
    return true;
}

// Candidates from the standby pack for profiles the subscription in force has no stub for (cold start in a
// whitelist window: the API unreachable, the cached subscription may predate a profile). Rules:
//  - the pack must be usable now (standbyPackUsable on the wall clock, the tuned cap) and carry a
//    tunnel_api_base (the seat is confirmed through the tunnel);
//  - an entry whose profile HAS a stub in the subscription adds nothing: the stub is the candidate and
//    standbyEntryUsable decides at bring-up whether its pack entry may start it;
//  - an entry without a stub is synthesized only when the pack is NEWER than the subscription's
//    upstream_revision, or there is no subscription pool at all - a fresh subscription that lacks a stub
//    withdrew that profile on purpose.
// The candidate: node_id/profile_id/label/country_code/tier/probe_class/config_sha256 of the entry,
// proto xray, no endpoint, priority after any stub (pack order kept), packSourced = true.
inline QList<SubscriptionNode> standbyPackCandidates(const StandbyPack &pack, const QList<SubscriptionNode> &pool,
                                                     qint64 subscriptionRevision, qint64 nowWallMs, int maxAgeCapS)
{
    QList<SubscriptionNode> out;
    if (pack.tunnelApiBase.isEmpty() || !standbyPackUsable(pack, nowWallMs, maxAgeCapS).usable)
        return out;
    if (!pool.isEmpty() && pack.upstreamRevision <= subscriptionRevision)
        return out;
    for (int i = 0; i < pack.entries.size(); ++i) {
        const StandbyEntry &e = pack.entries.at(i);
        bool known = false;
        for (const SubscriptionNode &n : pool)
            if (n.nodeId == e.nodeId || (n.upstream && n.upstream->profileId == e.profileId))
                known = true;
        if (known)
            continue;
        SubscriptionNode n;
        n.nodeId = e.nodeId;
        n.region = QStringLiteral("upstream");
        n.name = e.label;
        n.countryCode = e.countryCode;
        n.proto = QStringLiteral("xray");
        UpstreamStub s;
        s.profileId = e.profileId;
        s.configSha256 = e.configSha256;
        s.probeClass = e.probeClass;
        s.sizeBytes = int(e.config.size());
        s.tier = e.tier;
        s.priority = kUpstreamMaxPriority / 2 + i;
        s.packSourced = true;
        s.ordinal = e.ordinal;          // the same display name rule as a stub
        s.labelCustom = e.labelCustom;
        s.kind = e.kind;                // and the same row kind (an auto profile stays out of the list)
        n.upstream = s;
        out << n;
    }
    return out;
}

// --- Xray tunables of the envelope (contract §3) --------------------------------------------------------

inline double upstreamTunedOrNaN(const char *key)
{
    return TuningStore::numberOr(QLatin1String(key), std::numeric_limits<double>::quiet_NaN());
}

// Own Xray sessions: only the keys the server sent (absent key = today's behaviour - the default
// /v1/config carries none of them, so with the upstream switches off nothing changes). Upstream sessions:
// memory_limit_mib always (default 30, clamped 20..40 - the iOS extension must not run a provider
// profile without a Go limit), the hev keys when sent. Values clamped in code (§17.2).
inline QJsonObject xrayTunablesFor(bool upstreamSession)
{
    QJsonObject o;
    const double mem = upstreamTunedOrNaN(kXrayMemoryLimitKey);
    if (upstreamSession || std::isfinite(mem))
        o.insert(QStringLiteral("memory_limit_mib"), xrayMemoryLimitMiBFrom(mem));
    struct HevKey { const char *key; const char *field; int def, lo, hi; };
    static const HevKey hev[] = {
        // The backend table and the extension (IosNativePolicy.h hev*From, XrayTunables.swift): one set.
        {"xray_hev_tcp_buffer_size", "hev_tcp_buffer_size", 4096, 4096, 65536},
        {"xray_hev_max_session_count", "hev_max_session_count", 1200, 128, 65535},
        {"xray_hev_task_stack_size", "hev_task_stack_size", 24576, 20480, 131072},
    };
    for (const HevKey &h : hev) {
        const double v = upstreamTunedOrNaN(h.key);
        if (std::isfinite(v))
            o.insert(QLatin1String(h.field), clampTunable(v, h.def, h.lo, h.hi));
    }
    return o;
}

// The scope a session actually reports (contract §4, backend 14.11): "proxy" needs the build's
// per-outbound read AND the lease's meter_tags (exactly those tags are summed); without tags - "tunnel".
inline MeterScope upstreamEffectiveScope(MeterScope buildScope, const QStringList &meterTags)
{
    return (buildScope == MeterScope::Proxy && !meterTags.isEmpty()) ? MeterScope::Proxy : MeterScope::Tunnel;
}

// meter_scope a session of this build requests (contract §4): "proxy" only where the tunnel owner reads
// the core's per-outbound counters. iOS: the extension does (LibXrayTribeOutboundStats; the one source
// of truth is the bridge constant avpn_ios::kUpstreamProxyMeterSupported) - narrowed per lease by its
// meter_tags (upstreamEffectiveScope). macOS: the daemon reports utun counters only (service/server/
// xray.cpp runtimeStatus; no stats export in amnezia-xray-bindings) - "tunnel". Release C: Android
// (TrafficStats of tun0 in the Xray service, decision A-4) and Windows (the service's tun2 counters, no
// stats patch in the bindings) start with "tunnel" too - recorded, charged as shadow.
inline MeterScope upstreamMeterScopeForBuild()
{
#if defined(Q_OS_IOS)
    return avpn_ios::kUpstreamProxyMeterSupported ? MeterScope::Proxy : MeterScope::Tunnel;
#else
    return MeterScope::Tunnel;
#endif
}

} // namespace avpn

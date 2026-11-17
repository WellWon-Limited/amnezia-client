// client/core/serviceEngine/UpstreamLeaseWire.h
// AVPN serviceEngine - wire format of the upstream seat lease (POST /v1/upstream/lease, POST
// /v1/upstream/lease/{id}/renew, DELETE /v1/upstream/lease/{id}): request bodies, answer parsers and
// the classification of an answer into granted / refused / failed. [header-only, QtCore; pure, except
// that classifyAcquireReply verifies the signature through Ed25519Verify.cpp]
//
// Plan provider-pool v2, D6 and D13; contract api/openapi.yaml (UpstreamLease, UpstreamRenewal,
// UpstreamMeter, UpstreamError). An acquire answer is accepted only when, in this order: the signature
// verifies over "tribe-upstream-lease-v1" + "\n" + the exact body bytes with the /v1/config key,
// `type` == "upstream_lease", every field is present and sane, and sha256(config) == config_sha256.
// Renewal answers are not signed (they carry no config). Error answers are bodies {"code": ...};
// only a known code is ever terminal - an unknown body (a proxy page, an empty 403) is a transient
// failure, never a reason to leave a working node.
//
// Tests: tests/upstream_lease_check.cpp (build_upstream_lease.sh).
#pragma once

#include "SignedContext.h"
#include "UpstreamNode.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>
#include <QString>
#include <QUrl>

namespace avpn {

enum class LeaseKind { Session, Probe };

// What the byte deltas of a lease measure (UpstreamMeter.meter_scope): "proxy" = bytes per proxy
// outbound of the profile, "tunnel" = everything that entered the tunnel. Fixed for the life of a lease
// by its first report; the owner chooses it once per session (UpstreamLeaseMachine::start).
enum class MeterScope { Proxy, Tunnel };

inline QString meterScopeName(MeterScope s)
{
    return s == MeterScope::Proxy ? QStringLiteral("proxy") : QStringLiteral("tunnel");
}

inline QString leaseKindName(LeaseKind k)
{
    return k == LeaseKind::Probe ? QStringLiteral("probe") : QStringLiteral("session");
}

enum class UpstreamErrorCode {
    NotEntitled,         // 403, terminal
    OverQuota,           // 410, terminal
    Disabled,            // 410, terminal
    LeaseGone,           // 404, terminal
    NoSeat,              // 409, acquire only: try the next candidate
    RateLimited,         // 429, retry
    UpstreamUnavailable, // 503, retry
    InvalidRequest,      // 422, our server refused the request body: a contract bug, never a network blip
    Unknown,             // no / unknown code: transient, never terminal
};

inline UpstreamErrorCode upstreamErrorCodeFrom(const QString &code)
{
    if (code == QLatin1String("not_entitled")) return UpstreamErrorCode::NotEntitled;
    if (code == QLatin1String("over_quota")) return UpstreamErrorCode::OverQuota;
    if (code == QLatin1String("disabled")) return UpstreamErrorCode::Disabled;
    if (code == QLatin1String("lease_gone")) return UpstreamErrorCode::LeaseGone;
    if (code == QLatin1String("no_seat")) return UpstreamErrorCode::NoSeat;
    if (code == QLatin1String("rate_limited")) return UpstreamErrorCode::RateLimited;
    if (code == QLatin1String("upstream_unavailable")) return UpstreamErrorCode::UpstreamUnavailable;
    if (code == QLatin1String("invalid_request")) return UpstreamErrorCode::InvalidRequest;
    return UpstreamErrorCode::Unknown;
}

// Stable code (journal, reason of a leave action).
inline const char *upstreamErrorCodeName(UpstreamErrorCode c)
{
    switch (c) {
    case UpstreamErrorCode::NotEntitled: return "not_entitled";
    case UpstreamErrorCode::OverQuota: return "over_quota";
    case UpstreamErrorCode::Disabled: return "disabled";
    case UpstreamErrorCode::LeaseGone: return "lease_gone";
    case UpstreamErrorCode::NoSeat: return "no_seat";
    case UpstreamErrorCode::RateLimited: return "rate_limited";
    case UpstreamErrorCode::UpstreamUnavailable: return "upstream_unavailable";
    case UpstreamErrorCode::InvalidRequest: return "invalid_request";
    case UpstreamErrorCode::Unknown: return "unknown";
    }
    return "unknown";
}

// The four answers after which the session leaves the upstream node at once (D6).
inline bool isTerminalUpstreamError(UpstreamErrorCode c)
{
    return c == UpstreamErrorCode::NotEntitled || c == UpstreamErrorCode::OverQuota
           || c == UpstreamErrorCode::Disabled || c == UpstreamErrorCode::LeaseGone;
}

struct UpstreamErrorReply {
    UpstreamErrorCode code = UpstreamErrorCode::Unknown;
    int retryAfterS = -1;        // -1 = not given
    qint64 upstreamRevision = 0; // 0 = not given
    // Optional detail of the server (backend 14.11: a lease_gone because the seat was taken shortly before
    // expiry, or the source over capacity after the seat count was lowered). A stable lower-case code for
    // the switch log only - it never changes a decision. Empty = not given or not a valid code.
    QString reason;
};

// Tags of the outbounds whose per-outbound counters are the provider-carried bytes (meter_scope proxy):
// computed by the server (dialer-only hops, freedom/blackhole/dns/loopback never listed). Empty = the
// owner must report scope "tunnel". At most 64 tags of 1..128 visible characters.
inline bool parseUpstreamMeterTags(const QJsonValue &v, QStringList &out)
{
    out.clear();
    if (v.isUndefined() || v.isNull())
        return true;
    if (!v.isArray() || v.toArray().size() > 64)
        return false;
    static const QRegularExpression tagRe(QStringLiteral("^[\\x21-\\x7e]{1,128}$"));
    QStringList l;
    for (const QJsonValue &t : v.toArray()) {
        if (!t.isString() || !tagRe.match(t.toString()).hasMatch() || l.contains(t.toString()))
            return false;
        l << t.toString();
    }
    out = l;
    return true;
}

// The data-check grant inside a lease answer (`probe`, backend 14.11): a scan token for GET /v1/probe
// through the tunnel and the facts of the network the ACQUIRE came from (the device's own access network
// on a direct acquire; null on a standby acquire, which arrives through the provider). Absent = older
// server: no token, the data check falls back (UpstreamEngine.h::decideUpstreamVerifyRoute).
struct UpstreamProbeGrant {
    bool present = false;
    QString scanToken;      // secret, never log; header X-Tribe-Scan-Token
    int expiresInS = 0;     // from the moment the acquire was sent (the owner anchors it)
    qint64 accessAsn = 0;   // 0 = null
    QString accessNetToken; // empty = null
    QString path = QStringLiteral("/v1/probe");
};

// Validates the optional `probe` object. Absent/null -> true with present=false; present but malformed ->
// false (a broken signed answer is refused as a whole, like every other optional field).
inline bool parseUpstreamProbeGrant(const QJsonValue &v, UpstreamProbeGrant &out)
{
    out = UpstreamProbeGrant();
    if (v.isUndefined() || v.isNull())
        return true;
    if (!v.isObject())
        return false;
    const QJsonObject o = v.toObject();
    static const QRegularExpression tokenRe(QStringLiteral("^[\\x21-\\x7e]{1,128}$"));
    static const QRegularExpression netRe(QStringLiteral("^[\\x21-\\x7e]{1,32}$"));
    static const QRegularExpression pathRe(QStringLiteral("^/[A-Za-z0-9_/.-]{1,63}$"));
    UpstreamProbeGrant p;
    const QJsonValue tok = o.value(QLatin1String("scan_token"));
    if (!tok.isString() || !tokenRe.match(tok.toString()).hasMatch())
        return false;
    p.scanToken = tok.toString();
    qint64 n = 0;
    if (!upstreamJsonInt(o.value(QLatin1String("expires_in_s")), 1, 86400, n))
        return false;
    p.expiresInS = int(n);
    const QJsonValue asn = o.value(QLatin1String("access_asn"));
    if (!asn.isUndefined() && !asn.isNull()) {
        if (!upstreamJsonInt(asn, 1, 4294967295LL, n))
            return false;
        p.accessAsn = n;
    }
    const QJsonValue net = o.value(QLatin1String("access_net_token"));
    if (!net.isUndefined() && !net.isNull()) {
        if (!net.isString() || !netRe.match(net.toString()).hasMatch())
            return false;
        p.accessNetToken = net.toString();
    }
    const QJsonValue path = o.value(QLatin1String("path"));
    if (!path.isUndefined() && !path.isNull()) {
        if (!path.isString() || !pathRe.match(path.toString()).hasMatch() || path.toString().contains(QLatin1String("..")))
            return false;
        p.path = path.toString();
    }
    p.present = true;
    out = p;
    return true;
}

struct UpstreamLeaseGrant {
    QString leaseId;
    QString profileId;
    LeaseKind kind = LeaseKind::Session;
    qint64 expiresAtMs = 0; // server clock; only differences between two server times are used
    int ttlS = 0;
    int renewAfterS = 0;    // 0 for probe leases
    qint64 seq = 0;         // last accepted metering seq (0 for a new lease)
    QByteArray config;      // UTF-8 bytes of `config` - secret, never log
    QString configSha256;   // lower-case hex
    qint64 upstreamRevision = 0;
    qint64 accountingEpoch = 0;
    // Used INSTEAD of the device token for renew/release of this lease (the iOS extension has no device
    // token). Empty = absent (older server): the owner authenticates with the device token.
    QString renewToken;
    // API base for the requests that must go THROUGH the tunnel (renew, release, data check), without a
    // trailing slash. Empty = absent (older server): the owner uses its usual API base.
    QString tunnelApiBase;
    // The server's config differs from the one the device asked about (a standby acquire's
    // config_sha256). Optional; absent = false.
    bool configChanged = false;
    UpstreamProbeGrant probe; // optional (see UpstreamProbeGrant)
    QStringList meterTags;    // optional (parseUpstreamMeterTags); empty = scope "tunnel"
};

struct UpstreamRenewal {
    bool rebaseline = false;
    QString leaseId;
    qint64 expiresAtMs = 0;
    int renewAfterS = 0;
    qint64 seq = 0;
    qint64 upstreamRevision = 0;
    qint64 accountingEpoch = 0;
    bool configChanged = false;
    qint64 appliedBytes = 0;
    qint64 shadowBytes = 0; // absent (older server) = 0; reported, never used for a decision
};

// One metering report (renew body, optional release body). epoch = the traffic accounting epoch the
// device believes is current (the lease answer's traffic_accounting_epoch, replaced by the one of a
// `rebaseline` answer); the server charges a report only when it equals the device's epoch and answers
// `rebaseline` otherwise (an exact fence). The backend requires the field: it is ALWAYS sent, also as 0
// (nothing known - the server's fence then answers `rebaseline` with the real epoch, never a 422).
struct UpstreamMeter {
    qint64 seq = 0;
    qint64 rxDelta = 0;
    qint64 txDelta = 0;
    MeterScope scope = MeterScope::Tunnel;
    qint64 epoch = 0;
};

// Contract cap of one delta (UpstreamMeter.*_bytes_delta maximum, 1 TiB).
inline constexpr qint64 kUpstreamMaxDeltaBytes = 1099511627776LL;
// Lease id goes into a URL path: contract length 32..64, URL-safe characters only.
inline bool upstreamLeaseIdValid(const QString &id)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9_-]{32,64}$"));
    return re.match(id).hasMatch();
}

// A seat release (DELETE) that ended aborted by the app itself - the API reset of a tunnel transition
// (DebugSnapshot.h::transitionNetAction), not its own 1.5 s timeout - is sent ONCE more: by then the transition
// is over and the new request takes the new path. The same rule every other API request follows
// (DebugSnapshot.h::reissueAfterOwnAbort). A timeout or any answer ends it; the server frees the seat at TTL.
inline bool upstreamReleaseResend(int attemptsDone, bool canceled, bool timedOut)
{
    return attemptsDone == 0 && canceled && !timedOut;
}

// standbyConfigSha256 non-empty = a standby acquire: the device already runs that profile from its
// standby pack ("standby": true + the pack entry's config_sha256).
inline QByteArray upstreamAcquireBody(const QString &profileId, LeaseKind kind,
                                      const QString &standbyConfigSha256 = QString())
{
    QJsonObject o{{QStringLiteral("profile_id"), profileId}, {QStringLiteral("kind"), leaseKindName(kind)}};
    if (!standbyConfigSha256.isEmpty()) {
        o.insert(QStringLiteral("standby"), true);
        o.insert(QStringLiteral("config_sha256"), standbyConfigSha256);
    }
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

inline QByteArray upstreamMeterBody(const UpstreamMeter &m)
{
    QJsonObject o{{QStringLiteral("seq"), double(m.seq)},
                  {QStringLiteral("rx_bytes_delta"), double(qBound<qint64>(0, m.rxDelta, kUpstreamMaxDeltaBytes))},
                  {QStringLiteral("tx_bytes_delta"), double(qBound<qint64>(0, m.txDelta, kUpstreamMaxDeltaBytes))},
                  {QStringLiteral("meter_scope"), meterScopeName(m.scope)}};
    o.insert(QStringLiteral("epoch"), double(qBound<qint64>(0, m.epoch, kUpstreamMaxRevision)));
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

// renew_token: an opaque header-safe token (visible ASCII, 1..1024 characters).
inline bool upstreamRenewTokenValid(const QString &t)
{
    static const QRegularExpression re(QStringLiteral("^[\\x21-\\x7e]{1,1024}$"));
    return re.match(t).hasMatch();
}

// tunnel_api_base: an https URL with a host, no user info, query or fragment. Normalized without a
// trailing slash; anything else -> empty.
inline QString upstreamApiBaseNormalized(const QString &s)
{
    const QUrl u(s, QUrl::StrictMode);
    if (!u.isValid() || u.scheme() != QLatin1String("https") || u.host().isEmpty() || !u.userInfo().isEmpty()
        || u.hasQuery() || u.hasFragment())
        return QString();
    QString out = u.toString(QUrl::FullyEncoded);
    while (out.endsWith(QLatin1Char('/')))
        out.chop(1);
    return out;
}

inline bool upstreamParseTime(const QJsonValue &v, qint64 &outMs)
{
    if (!v.isString())
        return false;
    const QDateTime t = QDateTime::fromString(v.toString(), Qt::ISODateWithMs);
    if (!t.isValid())
        return false;
    outMs = t.toMSecsSinceEpoch();
    return true;
}

// Parses a lease answer body that has already passed the signature check. Checks `type`, every field,
// and that config_sha256 is the sha256 of the config bytes. why = the field name only.
inline bool parseUpstreamLeaseGrant(const QByteArray &body, UpstreamLeaseGrant &out, QString &why)
{
    const QJsonDocument doc = QJsonDocument::fromJson(body);
    if (!doc.isObject()) {
        why = QStringLiteral("not_object");
        return false;
    }
    const QJsonObject o = doc.object();
    if (o.value(QLatin1String("type")).toString() != QLatin1String("upstream_lease")) {
        why = QStringLiteral("type");
        return false;
    }
    UpstreamLeaseGrant g;
    qint64 n = 0;
    g.leaseId = o.value(QLatin1String("lease_id")).toString();
    if (!upstreamLeaseIdValid(g.leaseId)) {
        why = QStringLiteral("lease_id");
        return false;
    }
    g.profileId = o.value(QLatin1String("profile_id")).toString();
    if (g.profileId.isEmpty()) {
        why = QStringLiteral("profile_id");
        return false;
    }
    const QString kind = o.value(QLatin1String("kind")).toString();
    if (kind == QLatin1String("session"))
        g.kind = LeaseKind::Session;
    else if (kind == QLatin1String("probe"))
        g.kind = LeaseKind::Probe;
    else {
        why = QStringLiteral("kind");
        return false;
    }
    if (!upstreamParseTime(o.value(QLatin1String("expires_at")), g.expiresAtMs)) {
        why = QStringLiteral("expires_at");
        return false;
    }
    if (!upstreamJsonInt(o.value(QLatin1String("ttl_s")), 1, 86400, n)) {
        why = QStringLiteral("ttl_s");
        return false;
    }
    g.ttlS = int(n);
    if (!upstreamJsonInt(o.value(QLatin1String("renew_after_s")), 0, 86400, n)) {
        why = QStringLiteral("renew_after_s");
        return false;
    }
    g.renewAfterS = int(n);
    if (!upstreamJsonInt(o.value(QLatin1String("seq")), 0, kUpstreamMaxRevision, g.seq)) {
        why = QStringLiteral("seq");
        return false;
    }
    const QJsonValue cfg = o.value(QLatin1String("config"));
    if (!cfg.isString() || cfg.toString().isEmpty()) {
        why = QStringLiteral("config");
        return false;
    }
    g.config = cfg.toString().toUtf8();
    static const QRegularExpression shaRe(QStringLiteral("^[0-9a-fA-F]{64}$"));
    g.configSha256 = o.value(QLatin1String("config_sha256")).toString().toLower();
    if (!shaRe.match(g.configSha256).hasMatch()) {
        why = QStringLiteral("config_sha256");
        return false;
    }
    if (QCryptographicHash::hash(g.config, QCryptographicHash::Sha256).toHex() != g.configSha256.toLatin1()) {
        why = QStringLiteral("config_sha256_mismatch");
        return false;
    }
    if (!upstreamJsonInt(o.value(QLatin1String("upstream_revision")), 0, kUpstreamMaxRevision, g.upstreamRevision)) {
        why = QStringLiteral("upstream_revision");
        return false;
    }
    if (!upstreamJsonInt(o.value(QLatin1String("traffic_accounting_epoch")), 1, kUpstreamMaxRevision,
                         g.accountingEpoch)) {
        why = QStringLiteral("traffic_accounting_epoch");
        return false;
    }
    // Optional (absent on an older server). Present but malformed = a broken signed answer: refused.
    const QJsonValue tok = o.value(QLatin1String("renew_token"));
    if (!tok.isUndefined() && !tok.isNull()) {
        if (!tok.isString() || !upstreamRenewTokenValid(tok.toString())) {
            why = QStringLiteral("renew_token");
            return false;
        }
        g.renewToken = tok.toString();
    }
    const QJsonValue base = o.value(QLatin1String("tunnel_api_base"));
    if (!base.isUndefined() && !base.isNull()) {
        g.tunnelApiBase = base.isString() ? upstreamApiBaseNormalized(base.toString()) : QString();
        if (g.tunnelApiBase.isEmpty()) {
            why = QStringLiteral("tunnel_api_base");
            return false;
        }
    }
    const QJsonValue changed = o.value(QLatin1String("config_changed"));
    if (!changed.isUndefined() && !changed.isNull()) {
        if (!changed.isBool()) {
            why = QStringLiteral("config_changed");
            return false;
        }
        g.configChanged = changed.toBool();
    }
    if (!parseUpstreamProbeGrant(o.value(QLatin1String("probe")), g.probe)) {
        why = QStringLiteral("probe");
        return false;
    }
    if (!parseUpstreamMeterTags(o.value(QLatin1String("meter_tags")), g.meterTags)) {
        why = QStringLiteral("meter_tags");
        return false;
    }
    out = g;
    why.clear();
    return true;
}

inline bool parseUpstreamRenewal(const QByteArray &body, UpstreamRenewal &out, QString &why)
{
    const QJsonDocument doc = QJsonDocument::fromJson(body);
    if (!doc.isObject()) {
        why = QStringLiteral("not_object");
        return false;
    }
    const QJsonObject o = doc.object();
    UpstreamRenewal r;
    qint64 n = 0;
    const QString status = o.value(QLatin1String("status")).toString();
    if (status == QLatin1String("rebaseline"))
        r.rebaseline = true;
    else if (status != QLatin1String("ok")) {
        why = QStringLiteral("status");
        return false;
    }
    r.leaseId = o.value(QLatin1String("lease_id")).toString();
    if (!upstreamLeaseIdValid(r.leaseId)) {
        why = QStringLiteral("lease_id");
        return false;
    }
    if (!upstreamParseTime(o.value(QLatin1String("expires_at")), r.expiresAtMs)) {
        why = QStringLiteral("expires_at");
        return false;
    }
    if (!upstreamJsonInt(o.value(QLatin1String("renew_after_s")), 0, 86400, n)) {
        why = QStringLiteral("renew_after_s");
        return false;
    }
    r.renewAfterS = int(n);
    if (!upstreamJsonInt(o.value(QLatin1String("seq")), 0, kUpstreamMaxRevision, r.seq)) {
        why = QStringLiteral("seq");
        return false;
    }
    if (!upstreamJsonInt(o.value(QLatin1String("upstream_revision")), 0, kUpstreamMaxRevision, r.upstreamRevision)) {
        why = QStringLiteral("upstream_revision");
        return false;
    }
    if (!upstreamJsonInt(o.value(QLatin1String("traffic_accounting_epoch")), 1, kUpstreamMaxRevision,
                         r.accountingEpoch)) {
        why = QStringLiteral("traffic_accounting_epoch");
        return false;
    }
    const QJsonValue cc = o.value(QLatin1String("config_changed"));
    if (!cc.isBool()) {
        why = QStringLiteral("config_changed");
        return false;
    }
    r.configChanged = cc.toBool();
    if (!upstreamJsonInt(o.value(QLatin1String("applied_bytes")), 0, kUpstreamMaxRevision, r.appliedBytes)) {
        why = QStringLiteral("applied_bytes");
        return false;
    }
    const QJsonValue shadow = o.value(QLatin1String("shadow_bytes"));
    if (!shadow.isUndefined() && !shadow.isNull()
        && !upstreamJsonInt(shadow, 0, kUpstreamMaxRevision, r.shadowBytes)) {
        why = QStringLiteral("shadow_bytes");
        return false;
    }
    out = r;
    why.clear();
    return true;
}

// An error body. Only the body's code counts - the HTTP status alone never makes an answer terminal.
inline UpstreamErrorReply parseUpstreamError(const QByteArray &body)
{
    UpstreamErrorReply e;
    const QJsonObject o = QJsonDocument::fromJson(body).object();
    const QJsonValue code = o.value(QLatin1String("code"));
    e.code = code.isString() ? upstreamErrorCodeFrom(code.toString()) : UpstreamErrorCode::Unknown;
    qint64 n = 0;
    if (upstreamJsonInt(o.value(QLatin1String("retry_after_s")), 0, 86400, n))
        e.retryAfterS = int(n);
    if (upstreamJsonInt(o.value(QLatin1String("upstream_revision")), 1, kUpstreamMaxRevision, n))
        e.upstreamRevision = n;
    static const QRegularExpression reasonRe(QStringLiteral("^[a-z][a-z0-9_.-]{0,63}$"));
    const QJsonValue reason = o.value(QLatin1String("reason"));
    if (reason.isString() && reasonRe.match(reason.toString()).hasMatch())
        e.reason = reason.toString();
    return e;
}

// Outcome of one HTTP exchange, as the lease machine consumes it.
enum class LeaseReplyKind {
    Granted, // acquire: signed, typed, sane lease; renew: a renewal (ok or rebaseline)
    Refused, // a non-2xx answer with an UpstreamError body
    Failed,  // transport failure, timeout, bad signature, malformed answer - transient
};

struct AcquireReply {
    LeaseReplyKind kind = LeaseReplyKind::Failed;
    UpstreamLeaseGrant grant;
    UpstreamErrorReply error;
    QString why; // Failed: a short reason for the journal ("transport", "signature", a field name)
    // The HTTP answer carried kUpstreamTribeApiHeader: our server answered (whatever the body says).
    bool fromTribeApi = false;
};

// Response header the backend puts on EVERY answer of the upstream/scan routes (also on rate-limit and
// auth errors): `X-Tribe-Api: 1`. A block page or a foreign proxy never carries it.
inline constexpr char kUpstreamTribeApiHeader[] = "X-Tribe-Api";

inline bool upstreamFromTribeApi(const QByteArray &headerValue)
{
    return headerValue.trimmed() == QByteArrayLiteral("1");
}

struct RenewReply {
    LeaseReplyKind kind = LeaseReplyKind::Failed;
    UpstreamRenewal renewal;
    UpstreamErrorReply error;
    QString why;
};

// httpStatus 0 = no HTTP answer (transport failure / timeout). pubKeyHex = the /v1/config key
// (ConfigService::publicKeyHex()). fromTribeApi = the answer carried `X-Tribe-Api: 1`
// (upstreamFromTribeApi); it changes no classification, only mayStartProvisional.
inline AcquireReply classifyAcquireReply(int httpStatus, const QByteArray &body, const QByteArray &sigB64,
                                         const QString &pubKeyHex, bool fromTribeApi = false)
{
    AcquireReply r;
    r.fromTribeApi = httpStatus > 0 && fromTribeApi;
    if (httpStatus <= 0) {
        r.why = QStringLiteral("transport");
        return r;
    }
    if (httpStatus < 200 || httpStatus >= 300) {
        r.error = parseUpstreamError(body);
        if (r.error.code == UpstreamErrorCode::Unknown) {
            r.why = QStringLiteral("http_%1").arg(httpStatus);
            return r; // Failed
        }
        r.kind = LeaseReplyKind::Refused;
        return r;
    }
    if (!verifyDetachedWithContext(pubKeyHex, QLatin1String(kUpstreamLeaseSigContext), body, sigB64)) {
        r.why = QStringLiteral("signature");
        return r;
    }
    if (!parseUpstreamLeaseGrant(body, r.grant, r.why))
        return r;
    r.kind = LeaseReplyKind::Granted;
    return r;
}

// May the engine bring the tunnel up from a standby pack entry after this DIRECT acquire answer?
// Only when our server did not answer at all: no HTTP answer (transport), an HTTP error without an
// UpstreamError code (a block page, a 5xx of a proxy) or a 200 whose signature does not verify (not our
// server). Never for an answer that carries `X-Tribe-Api: 1` - our server answered, whatever the body
// (a 429 of the shared device-auth limit, an auth error; lab 14.11 D1). Never for a refusal with a code
// (not_entitled, no_seat, disabled, ... - the server spoke), never for a grant, never for a correctly
// signed but malformed answer (our server answered; a bug). A provisional session must still get its
// lease granted through the tunnel (UpstreamLeaseMachine).
inline bool mayStartProvisional(const AcquireReply &direct)
{
    if (direct.kind != LeaseReplyKind::Failed || direct.fromTribeApi)
        return false;
    return direct.why == QLatin1String("transport") || direct.why == QLatin1String("signature")
           || direct.why.startsWith(QLatin1String("http_"));
}

// A renewal our server refused as a malformed request (422 `invalid_request`, or a 422 without a known
// code): a contract bug on the device side, counted by the machine (kUpstreamRenewRejectedLimit).
inline bool upstreamRenewRejected(const RenewReply &r);

inline RenewReply classifyRenewReply(int httpStatus, const QByteArray &body)
{
    RenewReply r;
    if (httpStatus <= 0) {
        r.why = QStringLiteral("transport");
        return r;
    }
    if (httpStatus < 200 || httpStatus >= 300) {
        r.error = parseUpstreamError(body);
        if (r.error.code == UpstreamErrorCode::Unknown) {
            r.why = QStringLiteral("http_%1").arg(httpStatus);
            return r;
        }
        r.kind = LeaseReplyKind::Refused;
        return r;
    }
    if (!parseUpstreamRenewal(body, r.renewal, r.why))
        return r;
    r.kind = LeaseReplyKind::Granted;
    return r;
}

inline bool upstreamRenewRejected(const RenewReply &r)
{
    return (r.kind == LeaseReplyKind::Refused && r.error.code == UpstreamErrorCode::InvalidRequest)
           || (r.kind == LeaseReplyKind::Failed && r.why == QLatin1String("http_422"));
}

} // namespace avpn

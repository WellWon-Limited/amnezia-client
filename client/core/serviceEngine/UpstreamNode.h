// client/core/serviceEngine/UpstreamNode.h
// AVPN serviceEngine - upstream nodes: the kill switch, the clamped server tunables, the stub parser and
// the node identity. [header-only, QtCore]
//
// Plan provider-pool v2 (D2, D3, D6, D13; client §5.1-5.3). An upstream node is a whole third-party
// Xray profile run as "just another node". /v1/subscription carries only a credential-free stub
// (`proto:"xray"`, no `xray_params`, an `upstream{...}` block, node_id "up:<profile_id>"); the config
// itself travels only in the signed answer of POST /v1/upstream/lease (UpstreamLeaseWire.h) and is
// checked once more on the device (XrayProfileSanitizer.h) before the core gets it.
//
// Kill switch features.upstream_nodes, default OFF (absent = off): builds 138/139 drop such a node at
// parse time because parseXrayParams fails; with the switch off this build drops it in exactly the same
// place for exactly the same reason. On a config loaded from the cache the last SIGNED "true" is trusted
// for a bounded time since that copy was received (numbers.upstream_nodes_cache_max_age_h of the same
// signed copy, default 72 h, 1..336 h) - the mechanism build 139 introduced for xray_client
// (ConfigCachePolicy.h::decideXrayClient); past the bound, without a receive time or with a signed "false"
// it reads as off (fail-closed) until a fresh signed /v1/config arrives. Why not frozen like node_scan:
// the main use of upstream nodes is a cold start in a whitelist window, when the API is unreachable and
// only a cached config and the standby pack exist.
//
// Upstream Amnezia has no counterpart: the pool, the subscription and the kill switches exist only in
// this layer. Tests: tests/upstream_nodes_check.cpp (build_upstream_nodes.sh).
#pragma once

#include "TuningStore.h"
#include "dto/Subscription.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QMap>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

#include <cmath>

namespace avpn {

// --- kill switch -------------------------------------------------------------------------------------

inline constexpr char kUpstreamNodesFlag[] = "upstream_nodes";

// The client may run upstream nodes at all (server kill switch, default off). Read at parse time and at
// every choice (NodeRotation.h::isSupportedProtoNode), so an operator "off" removes upstream nodes from
// every pick without waiting for a new subscription.
inline bool upstreamNodesEnabled()
{
    return TuningStore::flag(QLatin1String(kUpstreamNodesFlag), false);
}

// numbers.upstream_nodes_cache_max_age_h: how long a cached signed upstream_nodes=true is trusted.
// Default 72 h, clamped 1..336 h (14 days: an operator typo cannot make it "forever"); non-finite =
// default. Read from the same cached signed config.
inline constexpr char kUpstreamCacheMaxAgeKey[] = "upstream_nodes_cache_max_age_h";
inline constexpr double kUpstreamCacheMaxAgeDefaultH = 72.0;
inline constexpr double kUpstreamCacheMaxAgeMinH = 1.0;
inline constexpr double kUpstreamCacheMaxAgeMaxH = 336.0;

inline qint64 upstreamCacheMaxAgeMs(double hours)
{
    double h = std::isfinite(hours) ? hours : kUpstreamCacheMaxAgeDefaultH;
    if (h < kUpstreamCacheMaxAgeMinH)
        h = kUpstreamCacheMaxAgeMinH;
    if (h > kUpstreamCacheMaxAgeMaxH)
        h = kUpstreamCacheMaxAgeMaxH;
    return qint64(h * 3600.0 * 1000.0);
}

// The cached signed value of the switch, judged (pure). true only for a signed "true" received less than
// maxAgeMs ago by a clock that is not behind the receive time; everything doubtful = off. A cached
// "false" is never upgraded.
inline bool upstreamTrustedFromCache(bool signedValue, qint64 receivedAtMs, qint64 nowMs, qint64 maxAgeMs)
{
    return signedValue && maxAgeMs > 0 && receivedAtMs > 0 && nowMs >= receivedAtMs && nowMs - receivedAtMs < maxAgeMs;
}

// --- clamped server tunables (numbers of /v1/config; REMOTE-TUNING conventions) --------------------
// The default is the value used when the key is absent (the default /v1/config body carries none of
// them); a value outside the range is clamped, a non-finite one falls back to the default. Ranges match
// the server's own clamps (openapi ConfigOut.numbers).

inline int clampTunable(double v, int def, int lo, int hi)
{
    if (!std::isfinite(v))
        return def;
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return int(v);
}

inline constexpr char kUpstreamLeaseTtlKey[] = "upstream_lease_ttl_s";
inline constexpr char kUpstreamRenewIntervalKey[] = "upstream_renew_interval_s";
inline constexpr char kUpstreamProbeTtlKey[] = "upstream_probe_ttl_s";
inline constexpr char kUpstreamVerifyBytesKey[] = "upstream_verify_bytes";
inline constexpr char kXrayMemoryLimitKey[] = "xray_memory_limit_mib";

inline constexpr int kUpstreamLeaseTtlDefaultS = 900, kUpstreamLeaseTtlMinS = 120, kUpstreamLeaseTtlMaxS = 3600;
inline constexpr int kUpstreamRenewDefaultS = 300, kUpstreamRenewMinS = 30;
inline constexpr int kUpstreamProbeTtlDefaultS = 60, kUpstreamProbeTtlMinS = 10, kUpstreamProbeTtlMaxS = 300;
inline constexpr int kUpstreamVerifyBytesDefault = 131072, kUpstreamVerifyBytesMin = 16384,
                     kUpstreamVerifyBytesMax = 1048576;
inline constexpr int kXrayMemoryLimitDefaultMiB = 30, kXrayMemoryLimitMinMiB = 20, kXrayMemoryLimitMaxMiB = 40;

// Session lease TTL the server enforces: default 900 s, 120..3600 s.
inline int upstreamLeaseTtlSFrom(double v)
{
    return clampTunable(v, kUpstreamLeaseTtlDefaultS, kUpstreamLeaseTtlMinS, kUpstreamLeaseTtlMaxS);
}
// Renewal interval: default 300 s, 30 s .. ttl/2 (never later than half the lease).
inline int upstreamRenewIntervalSFrom(double v, int ttlS)
{
    const int hi = qMax(kUpstreamRenewMinS, ttlS / 2);
    return clampTunable(v, qMin(kUpstreamRenewDefaultS, hi), kUpstreamRenewMinS, hi);
}
// Probe lease TTL: default 60 s, 10..300 s.
inline int upstreamProbeTtlSFrom(double v)
{
    return clampTunable(v, kUpstreamProbeTtlDefaultS, kUpstreamProbeTtlMinS, kUpstreamProbeTtlMaxS);
}
// Bytes through the tunnel before an upstream node counts as connected: default 128 KiB, 16 KiB..1 MiB.
inline int upstreamVerifyBytesFrom(double v)
{
    return clampTunable(v, kUpstreamVerifyBytesDefault, kUpstreamVerifyBytesMin, kUpstreamVerifyBytesMax);
}
// Go memory limit of the Xray core in the iOS extension: default 30 MiB, 20..40 MiB.
inline int xrayMemoryLimitMiBFrom(double v)
{
    return clampTunable(v, kXrayMemoryLimitDefaultMiB, kXrayMemoryLimitMinMiB, kXrayMemoryLimitMaxMiB);
}

// Standby pack (UpstreamStandbyPack.h): refetch interval while the API is reachable (default 6 h,
// 15 min..24 h) and the device-side cap of a pack's age (default 72 h, 1 h..14 days).
inline constexpr char kUpstreamStandbyRefreshKey[] = "upstream_standby_refresh_s";
inline constexpr char kUpstreamStandbyMaxAgeKey[] = "upstream_standby_max_age_s";
inline constexpr int kUpstreamStandbyRefreshDefaultS = 21600, kUpstreamStandbyRefreshMinS = 900,
                     kUpstreamStandbyRefreshMaxS = 86400;
inline constexpr int kUpstreamStandbyMaxAgeDefaultS = 259200, kUpstreamStandbyMaxAgeMinS = 3600,
                     kUpstreamStandbyMaxAgeMaxS = 1209600;

inline int upstreamStandbyRefreshSFrom(double v)
{
    return clampTunable(v, kUpstreamStandbyRefreshDefaultS, kUpstreamStandbyRefreshMinS, kUpstreamStandbyRefreshMaxS);
}
inline int upstreamStandbyMaxAgeSFrom(double v)
{
    return clampTunable(v, kUpstreamStandbyMaxAgeDefaultS, kUpstreamStandbyMaxAgeMinS, kUpstreamStandbyMaxAgeMaxS);
}
inline int upstreamStandbyRefreshSTuned()
{
    return upstreamStandbyRefreshSFrom(
        TuningStore::numberOr(QLatin1String(kUpstreamStandbyRefreshKey), kUpstreamStandbyRefreshDefaultS));
}
inline int upstreamStandbyMaxAgeSTuned()
{
    return upstreamStandbyMaxAgeSFrom(
        TuningStore::numberOr(QLatin1String(kUpstreamStandbyMaxAgeKey), kUpstreamStandbyMaxAgeDefaultS));
}

inline int upstreamLeaseTtlSTuned()
{
    return upstreamLeaseTtlSFrom(TuningStore::numberOr(QLatin1String(kUpstreamLeaseTtlKey), kUpstreamLeaseTtlDefaultS));
}
inline int upstreamRenewIntervalSTuned()
{
    return upstreamRenewIntervalSFrom(
        TuningStore::numberOr(QLatin1String(kUpstreamRenewIntervalKey), kUpstreamRenewDefaultS),
        upstreamLeaseTtlSTuned());
}
inline int upstreamProbeTtlSTuned()
{
    return upstreamProbeTtlSFrom(TuningStore::numberOr(QLatin1String(kUpstreamProbeTtlKey), kUpstreamProbeTtlDefaultS));
}
inline int upstreamVerifyBytesTuned()
{
    return upstreamVerifyBytesFrom(
        TuningStore::numberOr(QLatin1String(kUpstreamVerifyBytesKey), kUpstreamVerifyBytesDefault));
}
inline int xrayMemoryLimitMiBTuned()
{
    return xrayMemoryLimitMiBFrom(TuningStore::numberOr(QLatin1String(kXrayMemoryLimitKey), kXrayMemoryLimitDefaultMiB));
}

// --- stub parser ---------------------------------------------------------------------------------------

// Hard cap of one normalized profile (D3) - the same number the sanitizer enforces on the config itself.
inline constexpr int kUpstreamProfileMaxBytes = 256 * 1024;
inline constexpr int kUpstreamMaxTier = 1000;
inline constexpr int kUpstreamMaxOrdinal = 9999;
inline constexpr int kUpstreamMaxPriority = 1000000;
inline constexpr int kUpstreamMaxListEntries = 64;
inline constexpr int kUpstreamMaxListEntryChars = 128;
// Largest integer a JSON number carries exactly (2^53 - 1): revisions, seq, epochs.
inline constexpr qint64 kUpstreamMaxRevision = 9007199254740991LL;

inline QString upstreamNodeIdFor(const QString &profileId)
{
    return QStringLiteral("up:") + profileId;
}

// A JSON integer in [lo, hi] (a number with no fraction part); anything else -> false.
inline bool upstreamJsonInt(const QJsonValue &v, qint64 lo, qint64 hi, qint64 &out)
{
    if (!v.isDouble())
        return false;
    const double d = v.toDouble();
    if (!std::isfinite(d) || std::floor(d) != d || d < double(lo) || d > double(hi))
        return false;
    out = qint64(d);
    return true;
}

inline bool upstreamStringList(const QJsonValue &v, QStringList &out)
{
    if (!v.isArray())
        return false;
    const QJsonArray a = v.toArray();
    if (a.size() > kUpstreamMaxListEntries)
        return false;
    QStringList l;
    for (const QJsonValue &e : a) {
        if (!e.isString() || e.toString().isEmpty() || e.toString().size() > kUpstreamMaxListEntryChars)
            return false;
        l << e.toString();
    }
    out = l;
    return true;
}

// Display name parts of a stub's `upstream` object or a standby entry: `ordinal` (int 1..9999) and
// `label_custom` (bool). Optional and cosmetic: absent or malformed = 0 / false, never a refusal (a node is
// not dropped for its name).
inline void upstreamParseDisplayParts(const QJsonObject &o, int &ordinal, bool &labelCustom)
{
    qint64 n = 0;
    ordinal = upstreamJsonInt(o.value(QLatin1String("ordinal")), 1, kUpstreamMaxOrdinal, n) ? int(n) : 0;
    const QJsonValue c = o.value(QLatin1String("label_custom"));
    labelCustom = c.isBool() && c.toBool();
}

// The wire `kind` of a stub's `upstream` object, a standby entry or a scan manifest entry (contract 1.10.0).
// Optional and cosmetic like the display parts: absent or null = Unspecified (an older server), anything this
// build does not know (another string, another JSON type) = Auto. Never a refusal.
inline UpstreamKind upstreamParseKind(const QJsonObject &o)
{
    const QJsonValue k = o.value(QLatin1String("kind"));
    return upstreamKindFromWire(!(k.isUndefined() || k.isNull()), k.toString());
}

// The name a provider profile is shown under (release A, owner decisions 14.11 and 17.11; the artboard's
// «Нидерланды 1»): the admin's own name when the server marks the label custom; otherwise OUR form - the
// localized country name (a country row), the localized function name (a white-list row: «Белые списки») or
// the localized «Авто» (the provider's balancer: never a list row, the name only reaches the Connect card when
// Auto connected through it), then our stable number. Never «Сервер <n>»; a label that is not custom (a server
// fallback like "NL 1" or "Белые списки 2") is never shown - the words are the app's, in the app's language.
// rowKind = upstreamRowKind(...); countryName = the localized name the list uses for own nodes
// (doctor::countryDisplayName). Pure.
inline QString upstreamDisplayName(const QString &label, bool labelCustom, int ordinal, UpstreamKind rowKind,
                                   const QString &countryName, const QString &whitelistWord, const QString &autoWord)
{
    const QString custom = label.trimmed();
    if (labelCustom && !custom.isEmpty())
        return custom;
    const QString country = countryName.trimmed();
    QString base;
    if (rowKind == UpstreamKind::Whitelist)
        base = whitelistWord;
    else if (rowKind == UpstreamKind::Country && !country.isEmpty())
        base = country;
    else
        base = autoWord;
    return ordinal > 0 ? base + QLatin1Char(' ') + QString::number(ordinal) : base;
}

// Validates nodes[].upstream. true -> out filled; false -> why (field name only, never a value). The
// profile id is the server's opaque id (contract: 16 lower-case hex); the client accepts any short id
// of URL-safe characters so a widened server id does not need a release, but nothing else.
inline bool parseUpstreamStub(const QJsonValue &v, UpstreamStub &out, QString &why)
{
    if (!v.isObject()) {
        why = QStringLiteral("upstream is not an object");
        return false;
    }
    const QJsonObject o = v.toObject();
    UpstreamStub s;
    static const QRegularExpression idRe(QStringLiteral("^[A-Za-z0-9_-]{1,64}$"));
    static const QRegularExpression shaRe(QStringLiteral("^[0-9a-fA-F]{64}$"));
    const QJsonValue pid = o.value(QLatin1String("profile_id"));
    if (!pid.isString() || !idRe.match(pid.toString()).hasMatch()) {
        why = QStringLiteral("upstream.profile_id");
        return false;
    }
    s.profileId = pid.toString();
    const QJsonValue sha = o.value(QLatin1String("config_sha256"));
    if (!sha.isString() || !shaRe.match(sha.toString()).hasMatch()) {
        why = QStringLiteral("upstream.config_sha256");
        return false;
    }
    s.configSha256 = sha.toString().toLower();
    const QString pc = o.value(QLatin1String("probe_class")).toString();
    if (pc == QLatin1String("single"))
        s.probeClass = UpstreamProbeClass::Single;
    else if (pc == QLatin1String("composite"))
        s.probeClass = UpstreamProbeClass::Composite;
    else {
        why = QStringLiteral("upstream.probe_class");
        return false;
    }
    if (!upstreamStringList(o.value(QLatin1String("protocols")), s.protocols)) {
        why = QStringLiteral("upstream.protocols");
        return false;
    }
    if (!upstreamStringList(o.value(QLatin1String("required_geo")), s.requiredGeo)) {
        why = QStringLiteral("upstream.required_geo");
        return false;
    }
    qint64 n = 0;
    // A real normalized profile is never empty; above the cap the sanitizer would refuse it anyway.
    if (!upstreamJsonInt(o.value(QLatin1String("size_bytes")), 1, kUpstreamProfileMaxBytes, n)) {
        why = QStringLiteral("upstream.size_bytes");
        return false;
    }
    s.sizeBytes = int(n);
    if (!upstreamJsonInt(o.value(QLatin1String("tier")), 1, kUpstreamMaxTier, n)) {
        why = QStringLiteral("upstream.tier");
        return false;
    }
    s.tier = int(n);
    if (!upstreamJsonInt(o.value(QLatin1String("priority")), 0, kUpstreamMaxPriority, n)) {
        why = QStringLiteral("upstream.priority");
        return false;
    }
    s.priority = int(n);
    upstreamParseDisplayParts(o, s.ordinal, s.labelCustom);
    s.kind = upstreamParseKind(o);
    out = s;
    why.clear();
    return true;
}

// --- node predicates -----------------------------------------------------------------------------------

inline bool isUpstreamNode(const SubscriptionNode &n)
{
    return n.upstream.has_value();
}

// Identity of an upstream node for the live reseed (ServiceEngine::sameNodeIdentity is the caller to be
// wired): the same row (node id) AND the same profile config. A changed sha = the provider rotated its
// servers: the node stays the same row, but a running session is "changed" and the new config applies
// at the next bring-up.
inline bool sameUpstreamIdentity(const SubscriptionNode &a, const SubscriptionNode &b)
{
    if (!a.upstream.has_value() || !b.upstream.has_value())
        return false;
    return a.nodeId == b.nodeId && a.upstream->profileId == b.upstream->profileId
           && a.upstream->configSha256 == b.upstream->configSha256;
}

// The build carries every geo tag the profile routes by (D5). `available` = the tags of the geo files
// this build ships ("geoip:ru", "geosite:category-ru", ...; empty = none - today's iOS and Tribe macOS
// builds). Comparison is case-insensitive; "@attr" suffixes are not expected (the server strips them).
// The tags of the cut geo pair every Tribe Xray runner ships (recipes/tribe-xray-geo: geosite private,
// category-ru, tiktok, speedtest, youtube; geoip private, ru). Changing the pair changes this list.
inline const QStringList &upstreamBuildGeoTags()
{
    static const QStringList tags{QStringLiteral("geosite:private"), QStringLiteral("geosite:category-ru"),
                                  QStringLiteral("geosite:tiktok"),  QStringLiteral("geosite:speedtest"),
                                  QStringLiteral("geosite:youtube"), QStringLiteral("geoip:private"),
                                  QStringLiteral("geoip:ru")};
    return tags;
}

inline bool upstreamGeoSupported(const UpstreamStub &s, const QStringList &available)
{
    for (const QString &tag : s.requiredGeo)
        if (!available.contains(tag, Qt::CaseInsensitive))
            return false;
    return true;
}

} // namespace avpn

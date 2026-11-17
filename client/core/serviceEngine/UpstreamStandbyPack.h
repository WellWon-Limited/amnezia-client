// client/core/serviceEngine/UpstreamStandbyPack.h
// AVPN serviceEngine - the signed standby pack of upstream profiles: parse, validate, age, lookup and the
// stale-entry rule. [header-only, QtCore; pure except the signature check through Ed25519Verify.cpp]
//
// Why: on a Russian mobile network in a whitelist window the API is unreachable directly and provider
// profiles are often the only thing that works. A device cannot acquire a lease then, so it cannot get
// a config. GET /v1/upstream/standby?network_key= hands out a SIGNED pack (same Ed25519 key as
// /v1/config, context "tribe-upstream-standby-v1") with the configs of the best profiles for the
// network; the app refetches it while the API is reachable (numbers.upstream_standby_refresh_s) and
// stores the exact body + signature. When a direct lease acquire fails by transport, the engine may
// bring the tunnel up from a pack entry and confirm the seat THROUGH the tunnel (provisional start,
// UpstreamLeaseMachine::startProvisional; the decision is mayStartProvisional in UpstreamLeaseWire.h).
//
// Body: {"type":"upstream_standby","version":1,"issued_at":RFC3339,"max_age_s":int,"upstream_revision":int,
//        "tunnel_api_base":"https://...","entries":[{"profile_id","node_id":"up:<id>","label",
//        "country_code"|null,"tier","probe_class","config":"<JSON string>","config_sha256"}]}
// Checks (each a stable refusal code): body size (too_large), signature over context + "\n" + body
// (signature), JSON object (not_object), type (type), version 1 (version), issued_at (issued_at),
// max_age_s >= 1 (max_age), upstream_revision (upstream_revision), tunnel_api_base - absent/null = empty,
// present = https with a host, as for leases (tunnel_api_base), entries array of at most 32 (entries),
// every entry's fields (entry_field), node_id == "up:" + profile_id (entry_node_id), config <= 256 KiB
// (entry_size), sha256 of the exact config bytes (entry_sha), no profile twice (entry_duplicate).
// A pack with one bad entry is refused as a whole: it is a signed answer of our server, a broken one is
// a server bug to see in telemetry, not something to half-use.
//
// Age (standbyPackUsable): wall clock (the pack must survive a reboot; a monotonic clock does not).
// Usable while issued_at - tolerance <= now < issued_at + min(max_age_s, the tuned cap
// numbers.upstream_standby_max_age_s). A device clock BEFORE issued_at by no more than the tolerance
// (default 1 h: ordinary clock error) counts as age 0; earlier than that the clock is not trustworthy
// and the pack is NOT usable (clock_before_issue) - fail closed. Setting the clock back can stretch a
// pack's life; the real bound is elsewhere: a provisional session must get a lease granted through the
// tunnel within its confirm budget or it leaves the node (standby_unconfirmed).
//
// Stale entries (standbyEntryUsable), for one candidate stub of the current subscription:
//  - no stub for that profile, or the stub's config_sha256 equals the entry's: usable;
//  - the shas differ: the entry is usable ONLY when the pack is strictly newer than the subscription
//    (pack upstream_revision > subscription upstream_revision; a subscription without a revision counts
//    as older) - then the stub is the stale side (entry_newer_than_subscription); otherwise the entry is
//    stale (entry_stale) and is not used.
//
// Upstream Amnezia has no counterpart. Tests: tests/upstream_standby_check.cpp (build_upstream_standby.sh).
#pragma once

#include "SignedContext.h"
#include "UpstreamLeaseWire.h"
#include "UpstreamNode.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QRegularExpression>
#include <QSet>
#include <QString>

namespace avpn {

inline constexpr char kUpstreamStandbySigContext[] = "tribe-upstream-standby-v1";
inline constexpr int kStandbyMaxEntries = 32;
inline constexpr qsizetype kStandbyMaxBodyBytes = 10 * 1024 * 1024; // 32 x 256 KiB + JSON escaping
inline constexpr qint64 kStandbyClockBackToleranceMs = 3600LL * 1000;

struct StandbyEntry {
    QString profileId;
    QString nodeId;
    QString label;
    QString countryCode;   // empty = null
    int tier = 1;
    UpstreamProbeClass probeClass = UpstreamProbeClass::Composite;
    QByteArray config;     // exact UTF-8 bytes - secret, never log
    QString configSha256;  // lower-case hex
    QStringList meterTags; // as UpstreamLeaseGrant::meterTags (optional; malformed = entry_field)
    int ordinal = 0;          // display name parts (UpstreamNode.h::upstreamParseDisplayParts), optional
    bool labelCustom = false;
    UpstreamKind kind = UpstreamKind::Unspecified; // wire `kind` (contract 1.10.0, UpstreamNode.h::upstreamParseKind)
};

struct StandbyPack {
    int version = 0;
    qint64 issuedAtMs = 0;
    int maxAgeS = 0;
    qint64 upstreamRevision = 0;
    QString tunnelApiBase; // empty = absent
    QList<StandbyEntry> entries;

    const StandbyEntry *find(const QString &profileId) const
    {
        for (const StandbyEntry &e : entries)
            if (e.profileId == profileId)
                return &e;
        return nullptr;
    }
};

enum class StandbyRefusal {
    None, TooLarge, Signature, NotObject, Type, Version, IssuedAt, MaxAge, Revision, ApiBase, Entries,
    EntryField, EntryNodeId, EntrySize, EntrySha, EntryDuplicate,
};

inline const char *standbyRefusalCode(StandbyRefusal r)
{
    switch (r) {
    case StandbyRefusal::None: return "ok";
    case StandbyRefusal::TooLarge: return "too_large";
    case StandbyRefusal::Signature: return "signature";
    case StandbyRefusal::NotObject: return "not_object";
    case StandbyRefusal::Type: return "type";
    case StandbyRefusal::Version: return "version";
    case StandbyRefusal::IssuedAt: return "issued_at";
    case StandbyRefusal::MaxAge: return "max_age";
    case StandbyRefusal::Revision: return "upstream_revision";
    case StandbyRefusal::ApiBase: return "tunnel_api_base";
    case StandbyRefusal::Entries: return "entries";
    case StandbyRefusal::EntryField: return "entry_field";
    case StandbyRefusal::EntryNodeId: return "entry_node_id";
    case StandbyRefusal::EntrySize: return "entry_size";
    case StandbyRefusal::EntrySha: return "entry_sha";
    case StandbyRefusal::EntryDuplicate: return "entry_duplicate";
    }
    return "unknown";
}

struct StandbyParse {
    StandbyRefusal refusal = StandbyRefusal::None;
    QString detail; // field name / entry index only
    StandbyPack pack;
    bool ok() const { return refusal == StandbyRefusal::None; }
    QString code() const { return QLatin1String(standbyRefusalCode(refusal)); }
};

// body / sigB64 = exactly what was stored from the answer; pubKeyHex = ConfigService::publicKeyHex().
inline StandbyParse parseStandbyPack(const QByteArray &body, const QByteArray &sigB64, const QString &pubKeyHex)
{
    StandbyParse r;
    const auto refuse = [&r](StandbyRefusal why, const QString &detail = QString()) {
        r.refusal = why;
        r.detail = detail;
        r.pack = StandbyPack();
        return r;
    };
    if (body.size() > kStandbyMaxBodyBytes)
        return refuse(StandbyRefusal::TooLarge);
    if (!verifyDetachedWithContext(pubKeyHex, QLatin1String(kUpstreamStandbySigContext), body, sigB64))
        return refuse(StandbyRefusal::Signature);
    const QJsonDocument doc = QJsonDocument::fromJson(body);
    if (!doc.isObject())
        return refuse(StandbyRefusal::NotObject);
    const QJsonObject o = doc.object();
    if (o.value(QLatin1String("type")).toString() != QLatin1String("upstream_standby"))
        return refuse(StandbyRefusal::Type);
    qint64 n = 0;
    if (!upstreamJsonInt(o.value(QLatin1String("version")), 1, 1, n))
        return refuse(StandbyRefusal::Version);
    r.pack.version = int(n);
    if (!upstreamParseTime(o.value(QLatin1String("issued_at")), r.pack.issuedAtMs))
        return refuse(StandbyRefusal::IssuedAt);
    if (!upstreamJsonInt(o.value(QLatin1String("max_age_s")), 1, 365LL * 86400, n))
        return refuse(StandbyRefusal::MaxAge);
    r.pack.maxAgeS = int(n);
    if (!upstreamJsonInt(o.value(QLatin1String("upstream_revision")), 0, kUpstreamMaxRevision, r.pack.upstreamRevision))
        return refuse(StandbyRefusal::Revision);
    const QJsonValue base = o.value(QLatin1String("tunnel_api_base"));
    if (!base.isUndefined() && !base.isNull()) {
        r.pack.tunnelApiBase = base.isString() ? upstreamApiBaseNormalized(base.toString()) : QString();
        if (r.pack.tunnelApiBase.isEmpty())
            return refuse(StandbyRefusal::ApiBase);
    }
    const QJsonValue ev = o.value(QLatin1String("entries"));
    if (!ev.isArray() || ev.toArray().size() > kStandbyMaxEntries)
        return refuse(StandbyRefusal::Entries);
    static const QRegularExpression idRe(QStringLiteral("^[A-Za-z0-9_-]{1,64}$"));
    static const QRegularExpression ccRe(QStringLiteral("^[A-Za-z]{2}$"));
    static const QRegularExpression shaRe(QStringLiteral("^[0-9a-fA-F]{64}$"));
    QSet<QString> seen;
    const QJsonArray entries = ev.toArray();
    for (int i = 0; i < entries.size(); ++i) {
        const QString at = QStringLiteral("entries[%1]").arg(i);
        if (!entries.at(i).isObject())
            return refuse(StandbyRefusal::EntryField, at);
        const QJsonObject eo = entries.at(i).toObject();
        StandbyEntry e;
        const QJsonValue pid = eo.value(QLatin1String("profile_id"));
        if (!pid.isString() || !idRe.match(pid.toString()).hasMatch())
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".profile_id"));
        e.profileId = pid.toString();
        e.nodeId = eo.value(QLatin1String("node_id")).toString();
        if (e.nodeId != upstreamNodeIdFor(e.profileId))
            return refuse(StandbyRefusal::EntryNodeId, at);
        const QJsonValue label = eo.value(QLatin1String("label"));
        if (!label.isString() || label.toString().size() > kUpstreamMaxListEntryChars)
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".label"));
        e.label = label.toString();
        const QJsonValue cc = eo.value(QLatin1String("country_code"));
        if (!cc.isNull() && !cc.isUndefined()) {
            if (!cc.isString() || !ccRe.match(cc.toString()).hasMatch())
                return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".country_code"));
            e.countryCode = cc.toString().toUpper();
        }
        if (!upstreamJsonInt(eo.value(QLatin1String("tier")), 1, kUpstreamMaxTier, n))
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".tier"));
        e.tier = int(n);
        upstreamParseDisplayParts(eo, e.ordinal, e.labelCustom); // cosmetic: never a refusal
        e.kind = upstreamParseKind(eo);                          // cosmetic: never a refusal
        const QString pc = eo.value(QLatin1String("probe_class")).toString();
        if (pc == QLatin1String("single"))
            e.probeClass = UpstreamProbeClass::Single;
        else if (pc == QLatin1String("composite"))
            e.probeClass = UpstreamProbeClass::Composite;
        else
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".probe_class"));
        const QJsonValue cfg = eo.value(QLatin1String("config"));
        if (!cfg.isString() || cfg.toString().isEmpty())
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".config"));
        e.config = cfg.toString().toUtf8();
        if (e.config.size() > kUpstreamProfileMaxBytes)
            return refuse(StandbyRefusal::EntrySize, at);
        const QJsonValue sha = eo.value(QLatin1String("config_sha256"));
        if (!sha.isString() || !shaRe.match(sha.toString()).hasMatch())
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".config_sha256"));
        e.configSha256 = sha.toString().toLower();
        if (QCryptographicHash::hash(e.config, QCryptographicHash::Sha256).toHex() != e.configSha256.toLatin1())
            return refuse(StandbyRefusal::EntrySha, at);
        if (!parseUpstreamMeterTags(eo.value(QLatin1String("meter_tags")), e.meterTags))
            return refuse(StandbyRefusal::EntryField, at + QStringLiteral(".meter_tags"));
        if (seen.contains(e.profileId))
            return refuse(StandbyRefusal::EntryDuplicate, at);
        seen.insert(e.profileId);
        r.pack.entries << e;
    }
    return r;
}

struct StandbyUse {
    bool usable = false;
    QString reason; // stable code
};

// Age of the pack on the device's WALL clock (ms since epoch). maxAgeCapS = upstreamStandbyMaxAgeSTuned().
inline StandbyUse standbyPackUsable(const StandbyPack &p, qint64 nowWallMs, int maxAgeCapS,
                                    qint64 clockBackToleranceMs = kStandbyClockBackToleranceMs)
{
    if (nowWallMs < p.issuedAtMs - clockBackToleranceMs)
        return {false, QStringLiteral("clock_before_issue")};
    const qint64 ageLimitMs = qint64(qMin(p.maxAgeS, maxAgeCapS)) * 1000;
    if (nowWallMs >= p.issuedAtMs + ageLimitMs)
        return {false, QStringLiteral("expired")};
    return {true, QStringLiteral("fresh")};
}

// May this entry stand in for the candidate? stub = the current subscription's stub of the same profile
// (nullptr = none); subscriptionRevision = Subscription::upstreamRevision (0 = none).
inline StandbyUse standbyEntryUsable(const StandbyEntry &e, const UpstreamStub *stub, qint64 subscriptionRevision,
                                     qint64 packRevision)
{
    if (!stub)
        return {true, QStringLiteral("no_stub")};
    if (stub->configSha256 == e.configSha256)
        return {true, QStringLiteral("same_config")};
    if (packRevision > subscriptionRevision)
        return {true, QStringLiteral("entry_newer_than_subscription")};
    return {false, QStringLiteral("entry_stale")};
}

} // namespace avpn

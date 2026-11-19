// client/core/serviceEngine/path/PathId.h
// AVPN path engine (design 2026-11-17, §3 "Path") - what a path is: a stable identity, a revision of the
// parameters that decide whether it is reachable, and the server attributes the choice reads.
// [header-only, QtCore; pure]
//
// A path is something the client can bring up: our server over AmneziaWG, our Xray listener in one variant, a
// provider profile. Evidence about a path (PathLedger.h) is kept per (network, identity) and is valid only for
// the revision it was recorded with: a changed revision means "this is a different path on the wire" and the
// old evidence no longer applies.
//
// Until the server sends an identity and a revision of its own (design §6), both are derived here from what
// the subscription already carries:
//  - identity = the subscription node id, whose form already tells the kind: "<n>" our AmneziaWG node,
//    "<n>:xray" our Xray listener, "up:<profile>" a provider profile;
//  - revision = 16 hex digits of SHA-256 over the parameters that decide reachability on a network:
//      AmneziaWG: endpoint, server key and the whole obfuscation bundle (junk, sizes, headers, I-packets, 3.x
//                 keys) - DPI sees exactly these;
//      Xray:      endpoint, network, security, fingerprint, SNI, Reality key and short id, flow (not the
//                 per-device uuid: it is a credential and says nothing about the path);
//      provider:  the hash of the normalized config the lease hands out (a new hash = the provider rotated
//                 its servers).
//    DNS, MTU, keepalive and allowed IPs are left out: they do not decide whether the path passes a network.
#pragma once

#include "../ApiReach.h" // lane C: the control plane fact (re-exported to the path code below)
#include "../NodeRotation.h" // isManualOnlyNode / protoOf / isXrayProto: today's meaning of the server flags
#include "../dto/Subscription.h"

#include <QCryptographicHash>
#include <QString>
#include <QStringList>

namespace avpn::path {

enum class PathKind { OwnAwg, OwnXray, Provider };

inline const char *pathKindName(PathKind k)
{
    switch (k) {
    case PathKind::OwnAwg: return "awg";
    case PathKind::OwnXray: return "xray";
    case PathKind::Provider: return "provider";
    }
    return "";
}

struct PathId {
    QString id;       // stable identity
    QString revision; // parameters revision; empty = unknown (evidence then never matches a non-empty one)

    bool isValid() const { return !id.isEmpty(); }
    bool operator==(const PathId &o) const { return id == o.id && revision == o.revision; }
    bool operator!=(const PathId &o) const { return !(*this == o); }
};

// One entry of the pool as the choice sees it. Eligibility (server health, drain, platform support, kill
// switches) is decided BEFORE a node becomes a candidate, by the code that builds the pool (today's
// NodeRotation.h::isSupportedProtoNode and healthAggregate); everything in the pool may be brought up.
struct PathCandidate {
    PathId id;
    PathKind kind = PathKind::OwnAwg;
    UpstreamKind providerKind = UpstreamKind::Unspecified; // provider only: country / whitelist / auto
    QString country;      // ISO alpha-2 upper case; empty = none (a whitelist or balancer profile)
    bool manualOnly = false; // server "manual_only" (and RU): Auto reaches it only in the last wave
    int rank = kTransportRankAwg; // server transport_rank, lower first
    double weight = 1.0;  // server weight, higher first
    int tier = 0;         // 0 = our own; provider policy tier >= 1 (main, reserve)
    int priority = 0;     // order inside a provider tier, lower first
    // Lane C (C1): provider only - the profile can start WITHOUT the direct API (a usable standby-pack entry: its
    // config and the seat confirmation's tunnel API base are on the device). A provider without it needs the lease
    // request over the direct route; on a network where that is unreachable it cannot start.
    bool standbyEntry = false;
};

namespace detail {
inline QString revisionOf(const QStringList &parts)
{
    const QByteArray h = QCryptographicHash::hash(parts.join(QChar(0x1f)).toUtf8(), QCryptographicHash::Sha256);
    return QString::fromLatin1(h.toHex().left(16));
}
inline QString optInt(const std::optional<int> &v) { return v ? QString::number(*v) : QString(); }
inline QString optBool(const std::optional<bool> &v) { return v ? (*v ? QStringLiteral("1") : QStringLiteral("0")) : QString(); }
} // namespace detail

inline PathKind pathKindOf(const SubscriptionNode &n)
{
    if (n.upstream.has_value())
        return PathKind::Provider;
    return isXrayProto(protoOf(n)) ? PathKind::OwnXray : PathKind::OwnAwg;
}

inline PathId derivePathId(const SubscriptionNode &n)
{
    PathId p;
    p.id = n.nodeId;
    switch (pathKindOf(n)) {
    case PathKind::Provider:
        p.revision = detail::revisionOf({ QStringLiteral("provider"), n.upstream->configSha256.toLower() });
        break;
    case PathKind::OwnXray: {
        const XrayParams x = n.xray.value_or(XrayParams{});
        p.revision = detail::revisionOf({ QStringLiteral("xray"), n.endpoint, x.network, x.security, x.fingerprint,
                                          x.serverName, x.publicKey, x.shortId, x.flow });
        break;
    }
    case PathKind::OwnAwg: {
        const AwgParams &a = n.awg;
        p.revision = detail::revisionOf(
            { QStringLiteral("awg"), n.endpoint, n.serverPubkey, QString::number(a.Jc), QString::number(a.Jmin),
              QString::number(a.Jmax), QString::number(a.S1), QString::number(a.S2), detail::optInt(a.S3),
              detail::optInt(a.S4), QString::number(a.H1), QString::number(a.H2), QString::number(a.H3),
              QString::number(a.H4), a.I1, a.I2, a.I3, a.I4, a.I5, a.headerProtectionKey, a.contentPaddingAddition,
              a.rekeyAfterTime, a.rekeyTimeout, a.rejectAfterTime, a.keepaliveTimeout, a.maxHandshakeAttempts,
              detail::optBool(a.randomTrailers), detail::optBool(a.disableCookies) });
        break;
    }
    }
    return p;
}

// The pool entry of a subscription node. A provider profile shown as a whitelist or balancer has no country
// (UpstreamNode rules: such a row never carries a flag), so a country preference never matches it.
inline PathCandidate pathCandidateFromNode(const SubscriptionNode &n)
{
    PathCandidate c;
    c.id = derivePathId(n);
    c.kind = pathKindOf(n);
    c.country = n.countryCode.trimmed().toUpper();
    c.manualOnly = isManualOnlyNode(n);
    c.rank = n.transportRank;
    c.weight = n.weight;
    if (c.kind == PathKind::Provider) {
        c.providerKind = upstreamRowKind(n.upstream->kind, n.countryCode);
        if (c.providerKind != UpstreamKind::Country)
            c.country.clear();
        c.tier = qMax(1, n.upstream->tier);
        c.priority = n.upstream->priority;
        c.standbyEntry = n.upstream->packSourced; // a stub with a usable pack entry is marked by the engine (pathPool)
    }
    return c;
}

} // namespace avpn::path

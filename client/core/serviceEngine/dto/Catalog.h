// Tribe serviceEngine v2 — protocol-neutral signed catalog DTO.
// Overlay-only: protocol-specific config remains inside NativeProfile::config and is consumed
// only by a registered, fail-closed transport adapter.
#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

#include <optional>

namespace avpn {

enum class TransportKind {
    Unknown = 0,
    Awg,
    Xray,
};

inline QString transportKindName(TransportKind kind)
{
    switch (kind) {
    case TransportKind::Awg: return QStringLiteral("awg");
    case TransportKind::Xray: return QStringLiteral("xray");
    case TransportKind::Unknown: break;
    }
    return QStringLiteral("unknown");
}

inline TransportKind transportKindFromName(const QString &value)
{
    if (value == QLatin1String("awg"))
        return TransportKind::Awg;
    if (value == QLatin1String("xray"))
        return TransportKind::Xray;
    return TransportKind::Unknown;
}

enum class ConnectionMode {
    Auto = 0,
    ForceAwg,
    ForceXray,
};

struct CatalogResolveSelection {
    ConnectionMode transport = ConnectionMode::Auto;
    QString locationId; // empty = fastest/automatic location

    friend bool operator==(const CatalogResolveSelection &left,
                           const CatalogResolveSelection &right)
    {
        return left.transport == right.transport && left.locationId == right.locationId;
    }
    friend bool operator!=(const CatalogResolveSelection &left,
                           const CatalogResolveSelection &right)
    { return !(left == right); }
};

inline bool modeAllowsTransport(ConnectionMode mode, TransportKind transport)
{
    if (transport == TransportKind::Unknown)
        return false;
    if (mode == ConnectionMode::ForceAwg)
        return transport == TransportKind::Awg;
    if (mode == ConnectionMode::ForceXray)
        return transport == TransportKind::Xray;
    return true;
}

struct VerificationDescriptor {
    QStringList expectedEgressIds;
    QString context;
};

// Stable envelope around protocol-specific declarative data. The generic layer never turns
// config into an Xray/AWG runtime JSON itself; a registered adapter validates and compiles it
// through Amnezia's native ContainerConfig path.
struct NativeProfile {
    QString format;
    QString containerConfigFormat;
    QString containerType;
    QString profileKind;
    quint64 configGeneration = 0;
    quint64 bindingGeneration = 0;
    QDateTime expiresAt;
    QJsonObject config;
};

struct CatalogCandidate {
    QString locationId;
    // AVPN: derived from the signed parent Location by compatibleCandidates(); never parsed from
    // candidate JSON. Runtime policy needs it to preserve RU-direct/full-tunnel semantics.
    QString locationCountry;
    QString profileId;
    TransportKind transport = TransportKind::Unknown;
    QString profileKind;
    QString failureDomain;
    double serverHealth = 0.0;
    QDateTime healthObservedAt;
    double capacityHeadroom = 0.0;
    QStringList requiredCaps;
    VerificationDescriptor verification;
    NativeProfile nativeProfile;
};

struct CatalogLocation {
    QString id;
    QString country;
    QString city;
    QString displayKey;
    QList<CatalogCandidate> candidates;
};

struct CatalogPolicy {
    ConnectionMode modeDefault = ConnectionMode::Auto;
    int maxAttempts = 3;
    int connectTimeoutMs = 12000;
    int verifyTimeoutMs = 6000;
    int profileCooldownS = 300;
    int minimumDwellS = 300;
    int offlineGraceS = 0;
};

enum class CatalogDirectoryAvailability {
    Unsupported = 0,
    TemporarilyUnavailable,
    Selectable,
};

struct CatalogDirectoryTransport {
    TransportKind transport = TransportKind::Unknown;
    CatalogDirectoryAvailability availability =
        CatalogDirectoryAvailability::Unsupported;
    std::optional<double> predictedQuality;
    QDateTime observedAt;
};

struct CatalogDirectoryLocation {
    QString id;
    QString country;
    QString city;
    QString displayKey;
    QList<CatalogDirectoryTransport> transports;
};

struct CatalogLocationDirectory {
    int schemaVersion = 0;
    // Exact signed echo of the resolve scope. An omitted request selection canonically echoes
    // Auto/Fastest so the initial N/N-1-safe discovery remains response-bound.
    CatalogResolveSelection selection;
    QList<CatalogDirectoryLocation> locations;
};

// Bounded signed authority metadata for the post-tunnel receipt quorum. It is parsed only from
// the critical `verification.providers_v1` evolution extension and never enters native config.
struct ReceiptProviderDescriptor {
    QString id;
    QString trustDomain;
    QString baseUrl; // canonical bare HTTPS origin; client appends the fixed receipt path
    QStringList bootstrapIps;
    QString receiptKid;
    quint64 receiptKeyEpoch = 0;
};

struct ReceiptProviderPolicy {
    int schemaVersion = 0;
    int quorum = 0;
    QByteArray verificationToken; // receipt-only scoped token; never the subscription bearer
    QDateTime verificationTokenExpiresAt;
    QList<ReceiptProviderDescriptor> providers;
};

struct Catalog {
    int schemaVersion = 0;
    // Opaque, signed installation/device audience. Never a raw device id or bearer token.
    QString deviceAudience;
    // Exact online resolve challenge echoed under the catalog signature.
    QString requestNonce;
    quint64 catalogRevision = 0;
    quint64 keyEpoch = 0;
    quint64 deviceRevocationEpoch = 0;
    quint64 policyRevision = 0;
    QDateTime entitlementExpiresAt;
    QDateTime issuedAt;
    QDateTime expiresAt;
    QDateTime refreshAfter;
    CatalogPolicy policy;
    QList<CatalogLocation> locations;
    std::optional<ReceiptProviderPolicy> receiptProviderPolicy;
    std::optional<CatalogLocationDirectory> locationDirectory;

    // Exact verified bytes and their digest are retained for atomic LKG/replay checks. They must
    // never be emitted into logs because payload may contain device credentials.
    QByteArray exactPayload;
    QByteArray payloadSha256;
    QString signingKeyId;
};

struct PlatformCapabilities {
    int catalogSchemaMax = 0;
    QSet<QString> nativeProfileFormats;
    QSet<QString> containerConfigFormats;
    QSet<QString> profileKinds;
    QSet<QString> capabilities;
    QSet<TransportKind> transports;
};

} // namespace avpn

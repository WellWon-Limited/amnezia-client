// Tribe serviceEngine v2 — fail-closed client capability firewall.
#pragma once

#include "dto/Catalog.h"

#include "core/utils/containerEnum.h"

#include <QList>
#include <QRegularExpression>
#include <QString>

#include <cmath>

namespace avpn {

enum class CandidateCompatibilityError {
    None = 0,
    ClockInvalid,
    SchemaUnsupported,
    TransportUnsupported,
    NativeProfileFormatUnsupported,
    ContainerConfigFormatUnsupported,
    ProfileKindUnsupported,
    ProfileKindMismatch,
    MissingCapability,
    InvalidRequiredCapabilities,
    ContainerMismatch,
    GenerationInvalid,
    NativeConfigInvalid,
    CandidateValuesInvalid,
    ProfileExpired,
    HealthTimestampInvalid,
};

struct CandidateCompatibility {
    bool compatible = false;
    CandidateCompatibilityError error = CandidateCompatibilityError::None;
    QString detail;
};

inline amnezia::DockerContainer nativeContainerForTransport(TransportKind transport)
{
    switch (transport) {
    case TransportKind::Awg: return amnezia::DockerContainer::Awg;
    case TransportKind::Xray: return amnezia::DockerContainer::Xray;
    case TransportKind::Unknown: break;
    }
    return amnezia::DockerContainer::None;
}

inline QString nativeContainerTypeForTransport(TransportKind transport)
{
    switch (transport) {
    case TransportKind::Awg: return QStringLiteral("amnezia-awg");
    case TransportKind::Xray: return QStringLiteral("amnezia-xray");
    case TransportKind::Unknown: break;
    }
    return QString();
}

inline CandidateCompatibility checkCandidateCompatibility(const CatalogCandidate &candidate,
                                                           int schemaVersion,
                                                           const PlatformCapabilities &caps,
                                                           const QDateTime &nowUtc)
{
    CandidateCompatibility result;
    auto reject = [&](CandidateCompatibilityError code, const QString &detail) {
        result.error = code;
        result.detail = detail;
        return result;
    };

    if (!nowUtc.isValid())
        return reject(CandidateCompatibilityError::ClockInvalid,
                      QStringLiteral("trusted wall clock is unavailable"));

    if (schemaVersion != 2 || schemaVersion > caps.catalogSchemaMax)
        return reject(CandidateCompatibilityError::SchemaUnsupported,
                      QStringLiteral("catalog schema is not supported"));
    if (candidate.transport == TransportKind::Unknown
        || !caps.transports.contains(candidate.transport)) {
        return reject(CandidateCompatibilityError::TransportUnsupported,
                      QStringLiteral("transport is not bundled on this platform"));
    }
    if (candidate.nativeProfile.format != QLatin1String("tribe_native_profile_v1")
        || !caps.nativeProfileFormats.contains(candidate.nativeProfile.format))
        return reject(CandidateCompatibilityError::NativeProfileFormatUnsupported,
                      QStringLiteral("native profile format is not supported"));
    if (candidate.nativeProfile.containerConfigFormat
            != QLatin1String("amnezia_container_config_v1")
        || !caps.containerConfigFormats.contains(candidate.nativeProfile.containerConfigFormat))
        return reject(CandidateCompatibilityError::ContainerConfigFormatUnsupported,
                      QStringLiteral("container config format is not supported"));
    if (!caps.profileKinds.contains(candidate.profileKind))
        return reject(CandidateCompatibilityError::ProfileKindUnsupported,
                      QStringLiteral("profile kind is not supported"));
    if (candidate.nativeProfile.profileKind != candidate.profileKind)
        return reject(CandidateCompatibilityError::ProfileKindMismatch,
                      QStringLiteral("candidate/native profile kind mismatch"));
    QSet<QString> seenCapabilities;
    static const QRegularExpression capability(
        QStringLiteral("^[a-z][a-z0-9_.-]{2,95}$"));
    for (const QString &required : candidate.requiredCaps) {
        if (!capability.match(required).hasMatch()
            || seenCapabilities.contains(required))
            return reject(CandidateCompatibilityError::InvalidRequiredCapabilities,
                          QStringLiteral("invalid or duplicate required capability"));
        seenCapabilities.insert(required);
        if (!caps.capabilities.contains(required))
            return reject(CandidateCompatibilityError::MissingCapability,
                          QStringLiteral("missing required capability: %1").arg(required));
    }
    if (candidate.nativeProfile.containerType
        != nativeContainerTypeForTransport(candidate.transport)) {
        return reject(CandidateCompatibilityError::ContainerMismatch,
                      QStringLiteral("transport/native container mismatch"));
    }
    if (candidate.nativeProfile.configGeneration == 0
        || candidate.nativeProfile.bindingGeneration == 0)
        return reject(CandidateCompatibilityError::GenerationInvalid,
                      QStringLiteral("native profile generation is zero"));
    if (candidate.nativeProfile.config.isEmpty())
        return reject(CandidateCompatibilityError::NativeConfigInvalid,
                      QStringLiteral("native typed config is empty"));
    if (!std::isfinite(candidate.serverHealth) || candidate.serverHealth < 0.0
        || candidate.serverHealth > 1.0 || !std::isfinite(candidate.capacityHeadroom)
        || candidate.capacityHeadroom < 0.0 || candidate.capacityHeadroom > 1.0)
        return reject(CandidateCompatibilityError::CandidateValuesInvalid,
                      QStringLiteral("candidate health/capacity is outside [0,1]"));
    if (!candidate.nativeProfile.expiresAt.isValid()
        || candidate.nativeProfile.expiresAt <= nowUtc.toUTC())
        return reject(CandidateCompatibilityError::ProfileExpired,
                      QStringLiteral("native profile has expired"));
    if (!candidate.healthObservedAt.isValid()
        || candidate.healthObservedAt.toUTC() > nowUtc.toUTC().addSecs(300))
        return reject(CandidateCompatibilityError::HealthTimestampInvalid,
                      QStringLiteral("candidate health timestamp is invalid or in the future"));

    result.compatible = true;
    return result;
}

struct RejectedCandidate {
    QString profileId;
    CandidateCompatibilityError error = CandidateCompatibilityError::None;
    QString detail;
};

struct CompatibleCatalogView {
    QList<CatalogCandidate> candidates;
    QList<RejectedCandidate> rejected;
};

inline CompatibleCatalogView compatibleCandidates(const Catalog &catalog,
                                                   const PlatformCapabilities &caps,
                                                   const QDateTime &nowUtc)
{
    CompatibleCatalogView view;
    for (const CatalogLocation &location : catalog.locations) {
        for (CatalogCandidate candidate : location.candidates) {
            candidate.locationId = location.id; // signed parent is the authority
            candidate.locationCountry = location.country; // signed parent is the authority
            const CandidateCompatibility check =
                checkCandidateCompatibility(candidate, catalog.schemaVersion, caps, nowUtc);
            if (check.compatible) {
                view.candidates.append(candidate);
            } else {
                view.rejected.append({candidate.profileId, check.error, check.detail});
            }
        }
    }
    return view;
}

} // namespace avpn

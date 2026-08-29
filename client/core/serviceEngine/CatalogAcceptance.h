// Tribe serviceEngine v2 — single fail-closed verify → parse → trust → compatibility boundary.
#pragma once

#include "CatalogCompatibility.h"
#include "CatalogParser.h"
#include "CatalogTrust.h"

#include <algorithm>

namespace avpn {

enum class CatalogAcceptanceError {
    None = 0,
    ParseOrSignature,
    ResponseBinding,
    Trust,
    NoCompatibleCandidate,
};

struct CatalogRequestBinding {
    // Exact online resolve nonce. Empty is allowed only when revalidating an encrypted LKG.
    QString expectedRequestNonce;
    std::optional<CatalogResolveSelection> expectedSelection;
    bool requireSelectionEcho = false;
};

struct CatalogAcceptanceResult {
    // `authoritative` means signature + freshness + monotonic trust passed and therefore v1 must
    // close permanently. `connectable` additionally requires at least one compatible candidate.
    // Keeping these separate prevents a valid no-capacity/upgrade/unsupported rollout response
    // from reopening unsigned legacy access.
    bool authoritative = false;
    bool connectable = false;
    CatalogAcceptanceError error = CatalogAcceptanceError::None;
    QString detail;
    Catalog catalog;
    QList<CatalogCandidate> candidates;
    QList<RejectedCandidate> rejectedCandidates;
    CatalogTrustState nextTrustState;
    CatalogParseError parseError;
    CatalogTrustError trustError = CatalogTrustError::None;
    CatalogRuntimeAuthority runtimeAuthority;
};

inline CatalogAcceptanceResult acceptCatalogEnvelope(
    const QByteArray &envelope,
    const CatalogKeyring &keyring,
    const PlatformCapabilities &capabilities,
    const CatalogTrustState &currentTrust,
    CatalogSource source,
    const QDateTime &nowUtc,
    CatalogRequestBinding requestBinding,
    CatalogParserLimits parserLimits = {},
    CatalogTrustLimits trustLimits = {})
{
    CatalogAcceptanceResult result;
    result.nextTrustState = currentTrust;
    if (!CatalogParser::verifyAndParse(envelope, keyring, result.catalog,
                                       result.parseError, parserLimits)) {
        result.error = CatalogAcceptanceError::ParseOrSignature;
        result.detail = result.parseError.detail;
        return result;
    }

    if ((source == CatalogSource::Network
         && (!canonicalCatalogTrustAudience(requestBinding.expectedRequestNonce)
             || result.catalog.requestNonce != requestBinding.expectedRequestNonce))
        || (source == CatalogSource::LastKnownGood
            && !requestBinding.expectedRequestNonce.isEmpty())) {
        result.error = CatalogAcceptanceError::ResponseBinding;
        result.detail = QStringLiteral("catalog response binding mismatch");
        return result;
    }
    if (source == CatalogSource::Network && requestBinding.expectedSelection.has_value()) {
        if ((requestBinding.requireSelectionEcho
             && !result.catalog.locationDirectory.has_value())
            || (result.catalog.locationDirectory.has_value()
                && result.catalog.locationDirectory->selection
                       != *requestBinding.expectedSelection)) {
            result.error = CatalogAcceptanceError::ResponseBinding;
            result.detail = QStringLiteral("catalog signed selection echo mismatch");
            return result;
        }
        // The echo binds not only the public directory but the credential-bearing shortlist.
        // Otherwise a buggy backend could sign `fixed/Xray` while leaving credentials for another
        // country or transport in the LKG, which a later offline intent could accidentally expose.
        for (const CatalogLocation &location : result.catalog.locations) {
            if ((!requestBinding.expectedSelection->locationId.isEmpty()
                 && location.id != requestBinding.expectedSelection->locationId)
                || std::any_of(
                    location.candidates.cbegin(), location.candidates.cend(),
                    [&requestBinding](const CatalogCandidate &candidate) {
                        return !modeAllowsTransport(
                            requestBinding.expectedSelection->transport,
                            candidate.transport);
                    })) {
                result.error = CatalogAcceptanceError::ResponseBinding;
                result.detail = QStringLiteral(
                    "catalog credential shortlist exceeds signed selection");
                return result;
            }
        }
    } else if (source == CatalogSource::Network
               && result.catalog.locationDirectory.has_value()
               && result.catalog.locationDirectory->selection
                      != CatalogResolveSelection{}) {
        // An unscoped N/N-1-compatible discovery has exactly one canonical signed meaning:
        // Auto transport + fastest location. A non-default echo is not attributable to this
        // request even though the directory itself is otherwise well formed and signed.
        result.error = CatalogAcceptanceError::ResponseBinding;
        result.detail = QStringLiteral("unscoped catalog selection echo is not auto/fastest");
        return result;
    }

    const CatalogTrustVerdict trust = evaluateCatalogTrust(
        result.catalog, currentTrust, source, nowUtc, trustLimits);
    if (!trust.accepted) {
        result.error = CatalogAcceptanceError::Trust;
        result.trustError = trust.error;
        result.detail = trust.detail;
        return result;
    }
    result.runtimeAuthority = runtimeAuthorityForAcceptedCatalog(
        result.catalog, source, trust);
    result.authoritative = true;
    result.nextTrustState = trust.nextState;

    const CompatibleCatalogView view =
        compatibleCandidates(result.catalog, capabilities, nowUtc);
    result.candidates = view.candidates;
    result.rejectedCandidates = view.rejected;
    if (result.candidates.isEmpty()) {
        result.error = CatalogAcceptanceError::NoCompatibleCandidate;
        result.detail = QStringLiteral("signed catalog has no compatible candidate");
        return result;
    }

    result.connectable = true;
    return result;
}

} // namespace avpn

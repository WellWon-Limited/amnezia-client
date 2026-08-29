// Tribe serviceEngine v2 — explicit transition policy for the existing /v1 AWG subscription.
#pragma once

#include "CatalogTrust.h"

namespace avpn {

enum class CatalogPath {
    None = 0,
    FreshV2,
    LastKnownGoodV2,
    LegacyV1Awg,
};

struct CatalogPathInputs {
    bool freshV2Accepted = false;
    bool lkgV2Accepted = false;
    bool legacyV1SubscriptionValid = false;
    bool allowLegacyBootstrap = true;
    bool signedUpgradeRequired = false;
    bool signedAccountBlocked = false;
    CatalogTrustState trust;
};

inline CatalogPath chooseCatalogPath(const CatalogPathInputs &inputs)
{
    if (inputs.freshV2Accepted)
        return CatalogPath::FreshV2;
    if (inputs.lkgV2Accepted)
        return CatalogPath::LastKnownGoodV2;

    // v1 is a rollout bootstrap only, not an anti-downgrade escape hatch. Once this install has
    // accepted v2 (and therefore revocation epochs/device-scoped bindings), unsigned/legacy shape
    // can never resurrect access. Signed terminal errors also never fall through to v1.
    if (inputs.allowLegacyBootstrap && inputs.legacyV1SubscriptionValid
        && !inputs.trust.hasAcceptedV2 && !inputs.signedUpgradeRequired
        && !inputs.signedAccountBlocked) {
        return CatalogPath::LegacyV1Awg;
    }
    return CatalogPath::None;
}

} // namespace avpn

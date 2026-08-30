// Tribe catalog v2 — root-anchored, purpose-separated online signing-key rotation.
#pragma once

#include "CatalogParser.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QSet>

namespace avpn {

enum class CatalogSigningPurpose { Catalog = 0, Receipt };

struct CatalogKeysetEntry {
    QString kid;
    CatalogSigningPurpose purpose = CatalogSigningPurpose::Catalog;
    QString publicKeyHex;
    QString authorityId; // required only for receipt keys; immutable provider trust authority
    quint64 keyEpoch = 0;
    QDateTime notBefore;
    QDateTime notAfter;
};

struct CatalogKeysetRevocation {
    CatalogSigningPurpose purpose = CatalogSigningPurpose::Catalog;
    QString kid;
    QString authorityId;
    QDateTime revokedAt;
    QString reasonCode;
};

struct CatalogKeysetManifest {
    quint64 epoch = 0;
    QDateTime issuedAt;
    QDateTime notBefore;
    QDateTime expiresAt;
    QList<CatalogKeysetEntry> keys;
    QList<CatalogKeysetRevocation> revocations;
    QByteArray exactEnvelope;
    QByteArray payloadSha256;
};

struct CatalogKeysetTrustState {
    quint64 highestEpoch = 0;
    QByteArray payloadSha256AtHighestEpoch;
    QByteArray acceptedEnvelope;
    QHash<QString, QByteArray> keyFingerprints; // purpose/kid -> SHA-256(public key)
    QHash<QString, quint64> keyEpochs;          // immutable per purpose/kid
    QHash<QString, QString> keyAuthorities;     // immutable; empty for catalog identities
    QSet<QString> revokedIdentities;            // monotonic purpose/kid tombstones

    friend bool operator==(const CatalogKeysetTrustState &left,
                           const CatalogKeysetTrustState &right)
    {
        return left.highestEpoch == right.highestEpoch
            && left.payloadSha256AtHighestEpoch == right.payloadSha256AtHighestEpoch
            && left.acceptedEnvelope == right.acceptedEnvelope
            && left.keyFingerprints == right.keyFingerprints
            && left.keyEpochs == right.keyEpochs
            && left.keyAuthorities == right.keyAuthorities
            && left.revokedIdentities == right.revokedIdentities;
    }
    friend bool operator!=(const CatalogKeysetTrustState &left,
                           const CatalogKeysetTrustState &right)
    { return !(left == right); }
};

struct CatalogAcceptedKeyrings {
    quint64 manifestEpoch = 0;
    CatalogKeyring catalog;
    QHash<QString, QString> receiptPublicKeysHex;
    QHash<QString, quint64> receiptKeyEpochs;
    QHash<QString, QString> receiptAuthorityIds;
};

struct CatalogKeysetLimits {
    int maximumEnvelopeBytes = 128 * 1024;
    int maximumKeys = 32;
    int maximumRevocations = 64;
    int maximumTrackedKeys = 128;
    // Root-manifest and receipt clocks use a deliberately tighter bound than the legacy catalog
    // envelope. This value is part of the frozen v1 trust contract.
    int allowedClockSkewS = 30;
};

enum class CatalogKeysetError {
    None = 0,
    Signature,
    Parse,
    Time,
    Expired,
    EpochDowngrade,
    EpochCollision,
    EmptyUsableKeyset,
    PersistedState,
};

enum class CatalogKeysetAcceptanceMode {
    Online = 0,
    PersistedRecovery,
};

struct CatalogKeysetAcceptance {
    bool accepted = false;
    // A root-authenticated, structurally and monotonically valid persisted keyset may be kept as
    // rollback authority after its usable time window. It never supplies online/connection keys;
    // this historical catalog ring exists only to authenticate and quarantine the atomic LKG.
    bool recoverableExpired = false;
    CatalogKeysetError error = CatalogKeysetError::None;
    QString detail;
    CatalogKeysetManifest manifest;
    CatalogKeysetTrustState nextState;
    CatalogAcceptedKeyrings keyrings;
    CatalogKeyring persistedCatalogVerificationKeyring;
};

CatalogKeysetAcceptance acceptCatalogKeysetEnvelope(
    const QByteArray &envelope, const QHash<QString, QString> &bundledRootKeysHex,
    const CatalogKeysetTrustState &current, const QDateTime &trustedNowUtc,
    CatalogKeysetLimits limits = {},
    CatalogKeysetAcceptanceMode mode = CatalogKeysetAcceptanceMode::Online);

bool serializeCatalogKeysetTrustState(const CatalogKeysetTrustState &state,
                                      QByteArray &serialized, QString &error);
bool parseCatalogKeysetTrustState(const QByteArray &serialized,
                                  CatalogKeysetTrustState &state, QString &error);

} // namespace avpn

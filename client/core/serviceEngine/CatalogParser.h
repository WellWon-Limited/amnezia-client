// Tribe serviceEngine v2 — strict signed /v2/catalog/resolve envelope and payload parser.
#pragma once

#include "dto/Catalog.h"

#include <QByteArray>
#include <QHash>
#include <QString>

namespace avpn {

// Frozen verification-grant v1 protocol bound (backend parity). The scoped bearer is never
// accepted beyond fifteen minutes from the signed catalog issue time.
inline constexpr qint64 kVerificationGrantMaximumLifetimeSeconds = 900;

enum class CatalogParseErrorCode {
    None = 0,
    EnvelopeTooLarge,
    InvalidEnvelopeJson,
    DuplicateJsonKey,
    UnsupportedAlgorithm,
    MissingKeyId,
    UnknownKeyId,
    InvalidBase64Url,
    InvalidSignature,
    SigningKeyEpochMismatch,
    PayloadTooLarge,
    InvalidUtf8,
    InvalidPayloadJson,
    JsonLimitsExceeded,
    UnsupportedSchema,
    UnsupportedCriticalExtension,
    MissingField,
    InvalidField,
    InvalidPolicy,
    InvalidLocation,
    InvalidCandidate,
    InvalidNativeProfile,
};

struct CatalogParseError {
    CatalogParseErrorCode code = CatalogParseErrorCode::None;
    QString path;
    QString detail;
};

struct CatalogParserLimits {
    int maximumEnvelopeBytes = 768 * 1024;
    int maximumPayloadBytes = 512 * 1024;
    int maximumJsonDepth = 20;
    int maximumJsonNodes = 8192;
    int maximumLocations = 128;
    int maximumCandidatesPerLocation = 32;
    int maximumStringBytes = 4096;
};

struct CatalogKeyring {
    // kid -> lowercase/uppercase hexadecimal raw Ed25519 public key (32 bytes).
    QHash<QString, QString> publicKeysHex;
    // kid -> immutable trusted rotation epoch. The signed payload cannot self-assert a newer epoch
    // for an older key. Bundled entries are bootstrap anchors only; production rotation must add
    // catalog keys through a separately root-signed, monotonic keyset manifest.
    QHash<QString, quint64> keyEpochs;
};

class CatalogParser {
public:
    // Envelope contract:
    //   alg=Ed25519, canonical unpadded RFC4648 base64url payload/signature.
    // Signature input is EXACT ASCII/UTF-8 bytes:
    //   "tribe-catalog-v2\n" + kid + "\n" + payload_base64url_text
    // Signature is verified before payload base64 decode or JSON parsing.
    static bool verifyAndParse(const QByteArray &envelopeBytes,
                               const CatalogKeyring &keyring,
                               Catalog &out,
                               CatalogParseError &error,
                               CatalogParserLimits limits = {});

    // Exposed for deterministic parser fixtures that have already crossed an authenticated
    // verifier boundary. Production callers should use verifyAndParse.
    static bool parseVerifiedPayload(const QByteArray &exactPayload,
                                     const QString &signingKeyId,
                                     Catalog &out,
                                     CatalogParseError &error,
                                     CatalogParserLimits limits = {});

    static QByteArray signatureInput(const QString &kid,
                                     const QByteArray &payloadBase64UrlText);

    // AVPN: adapters re-run the exact typed sanitizer immediately before compilation. This never
    // accepts raw native/core JSON and deliberately shares the parser's strict allowlists.
    static bool validateTypedNativeProfile(const CatalogCandidate &candidate,
                                           CatalogParseError &error);
};

} // namespace avpn

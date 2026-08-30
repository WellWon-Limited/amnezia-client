// Tribe serviceEngine — reusable strict Ed25519 envelope verifier for purpose-separated domains.
#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonDocument>
#include <QString>

namespace avpn {

inline bool canonicalSigningKeyId(const QString &value)
{
    if (value.isEmpty() || value.size() > 64)
        return false;
    for (const QChar ch : value) {
        if (!ch.isLetterOrNumber() || ch.unicode() > 0x7f) {
            if (ch != QLatin1Char('.') && ch != QLatin1Char('+')
                && ch != QLatin1Char('_') && ch != QLatin1Char('-'))
                return false;
        }
    }
    const QChar first = value.front();
    return first.unicode() <= 0x7f && first.isLetterOrNumber();
}

struct VerifiedSignedEnvelope {
    QString keyId;
    QByteArray exactPayload;
};

struct SignedEnvelopeLimits {
    int maximumEnvelopeBytes = 768 * 1024;
    int maximumPayloadBytes = 512 * 1024;
};

// Strict UTF-8 + RFC JSON parse with duplicate-key rejection at every nesting level. Callers
// still own their exact field/type allowlists.
bool parseStrictJsonDocument(const QByteArray &bytes, QJsonDocument &document,
                             QString &error, int maximumBytes);

bool verifyPurposeSignedEnvelope(const QByteArray &envelope,
                                 const QByteArray &asciiDomain,
                                 const QHash<QString, QString> &trustedPublicKeysHex,
                                 VerifiedSignedEnvelope &verified,
                                 QString &error,
                                 SignedEnvelopeLimits limits = {});

} // namespace avpn

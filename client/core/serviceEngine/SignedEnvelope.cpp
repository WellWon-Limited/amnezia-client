#include "SignedEnvelope.h"

#include "Ed25519Verify.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QStringDecoder>

namespace avpn {
namespace {

class DuplicateScanner {
public:
    explicit DuplicateScanner(const QByteArray &json) : m_json(json) {}
    bool valid()
    {
        QString ignored;
        skip();
        return value(ignored) && (skip(), m_pos == m_json.size());
    }
    bool duplicateFound() const { return m_duplicate; }
private:
    void skip() { while (m_pos < m_json.size() && QByteArrayLiteral(" \t\r\n").contains(m_json.at(m_pos))) ++m_pos; }
    bool string(QString *decoded = nullptr)
    {
        if (m_pos >= m_json.size() || m_json.at(m_pos) != '"') return false;
        const int start = m_pos++;
        bool escape = false;
        while (m_pos < m_json.size()) {
            const char c = m_json.at(m_pos++);
            if (escape) { escape = false; continue; }
            if (c == '\\') { escape = true; continue; }
            if (c == '"') {
                if (decoded) {
                    const QJsonDocument doc = QJsonDocument::fromJson(
                        QByteArrayLiteral("[") + m_json.mid(start, m_pos - start) + ']');
                    if (!doc.isArray() || !doc.array().first().isString()) return false;
                    *decoded = doc.array().first().toString();
                }
                return true;
            }
            if (quint8(c) < 0x20) return false;
        }
        return false;
    }
    bool object(QString &duplicate)
    {
        ++m_pos; skip();
        if (m_pos < m_json.size() && m_json.at(m_pos) == '}') { ++m_pos; return true; }
        QSet<QString> keys;
        while (m_pos < m_json.size()) {
            QString key;
            if (!string(&key)) return false;
            if (keys.contains(key)) { duplicate = key; m_duplicate = true; return false; }
            keys.insert(key); skip();
            if (m_pos >= m_json.size() || m_json.at(m_pos++) != ':') return false;
            skip(); if (!value(duplicate)) return false; skip();
            if (m_pos >= m_json.size()) return false;
            const char separator = m_json.at(m_pos++);
            if (separator == '}') return true;
            if (separator != ',') return false;
            skip();
        }
        return false;
    }
    bool array(QString &duplicate)
    {
        ++m_pos; skip();
        if (m_pos < m_json.size() && m_json.at(m_pos) == ']') { ++m_pos; return true; }
        while (m_pos < m_json.size()) {
            if (!value(duplicate)) return false;
            skip(); if (m_pos >= m_json.size()) return false;
            const char separator = m_json.at(m_pos++);
            if (separator == ']') return true;
            if (separator != ',') return false;
            skip();
        }
        return false;
    }
    bool value(QString &duplicate)
    {
        skip(); if (m_pos >= m_json.size()) return false;
        const char c = m_json.at(m_pos);
        if (c == '{') return object(duplicate);
        if (c == '[') return array(duplicate);
        if (c == '"') return string();
        const int start = m_pos;
        while (m_pos < m_json.size() && !QByteArrayLiteral(",]} \t\r\n").contains(m_json.at(m_pos))) ++m_pos;
        return m_pos > start;
    }
    const QByteArray &m_json;
    int m_pos = 0;
    bool m_duplicate = false;
};

bool canonicalToken(const QString &text, QByteArray &raw, int exactSize = -1)
{
    if (text.isEmpty() || text.contains(QLatin1Char('='))) return false;
    const QByteArray encoded = text.toLatin1();
    if (QString::fromLatin1(encoded) != text) return false;
    for (const char c : encoded)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok
        || (exactSize >= 0 && decoded.decoded.size() != exactSize)
        || decoded.decoded.toBase64(QByteArray::Base64UrlEncoding
                                    | QByteArray::OmitTrailingEquals) != encoded) return false;
    raw = decoded.decoded;
    return true;
}

} // namespace

bool parseStrictJsonDocument(const QByteArray &bytes, QJsonDocument &document,
                             QString &error, int maximumBytes)
{
    document = {};
    error.clear();
    if (bytes.isEmpty() || bytes.size() > qBound(1, maximumBytes, 2 * 1024 * 1024)) {
        error = QStringLiteral("JSON bytes outside bounds");
        return false;
    }
    QStringDecoder decoder(QStringDecoder::Utf8);
    decoder(bytes);
    DuplicateScanner scanner(bytes);
    QJsonParseError parseError;
    document = QJsonDocument::fromJson(bytes, &parseError);
    if (decoder.hasError() || parseError.error != QJsonParseError::NoError || !scanner.valid()) {
        error = scanner.duplicateFound() ? QStringLiteral("duplicate JSON key")
                                         : QStringLiteral("strict JSON parse failed");
        document = {};
        return false;
    }
    return true;
}

bool verifyPurposeSignedEnvelope(const QByteArray &envelope, const QByteArray &asciiDomain,
                                 const QHash<QString, QString> &trustedPublicKeysHex,
                                 VerifiedSignedEnvelope &verified, QString &error,
                                 SignedEnvelopeLimits limits)
{
    verified = {}; error.clear();
    if (envelope.isEmpty() || envelope.size() > qBound(1024, limits.maximumEnvelopeBytes, 1024 * 1024)
        || asciiDomain.isEmpty() || !asciiDomain.endsWith('\n')) {
        error = QStringLiteral("signed envelope/domain outside bounds"); return false;
    }
    QJsonDocument document;
    if (!parseStrictJsonDocument(envelope, document, error,
                                 qBound(1024, limits.maximumEnvelopeBytes, 1024 * 1024))
        || !document.isObject()) {
        if (error == QLatin1String("duplicate JSON key"))
            error = QStringLiteral("duplicate JSON key in signed envelope");
        else
            error = QStringLiteral("signed envelope JSON is invalid");
        return false;
    }
    const QJsonObject object = document.object();
    const QSet<QString> keys{QStringLiteral("alg"), QStringLiteral("kid"),
                             QStringLiteral("payload"), QStringLiteral("signature")};
    if (object.size() != keys.size()) { error = QStringLiteral("signed envelope fields mismatch"); return false; }
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!keys.contains(it.key())) { error = QStringLiteral("unknown signed envelope field"); return false; }
    const QString algorithm = object.value(QStringLiteral("alg")).toString();
    const QString kid = object.value(QStringLiteral("kid")).toString();
    const QString payloadText = object.value(QStringLiteral("payload")).toString();
    const QString signatureText = object.value(QStringLiteral("signature")).toString();
    const auto key = trustedPublicKeysHex.constFind(kid);
    QByteArray payload, signature;
    if (algorithm != QLatin1String("Ed25519") || !canonicalSigningKeyId(kid)
        || key == trustedPublicKeysHex.constEnd()
        || !canonicalToken(payloadText, payload)
        || !canonicalToken(signatureText, signature, 64)
        || payload.size() > qBound(1024, limits.maximumPayloadBytes, 1024 * 1024)) {
        error = QStringLiteral("signed envelope cryptographic fields are invalid"); return false;
    }
    const QByteArray input = asciiDomain + kid.toUtf8() + '\n' + payloadText.toLatin1();
    if (!verifyDetached(*key, input, signature.toBase64())) {
        error = QStringLiteral("signed envelope signature mismatch"); return false;
    }
    QJsonDocument payloadDocument;
    if (!parseStrictJsonDocument(payload, payloadDocument, error,
                                 qBound(1024, limits.maximumPayloadBytes, 1024 * 1024))) {
        if (error == QLatin1String("duplicate JSON key"))
            error = QStringLiteral("duplicate JSON key in signed payload");
        else
            error = QStringLiteral("signed payload JSON is invalid");
        return false;
    }
    verified = {kid, payload};
    return true;
}

} // namespace avpn

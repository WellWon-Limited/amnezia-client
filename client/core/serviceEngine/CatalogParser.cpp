#include "CatalogParser.h"

#include "Ed25519Verify.h"
#include "SignedEnvelope.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QHostAddress>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QRegularExpression>
#include <QSet>
#include <QStringDecoder>
#include <QUrl>

#include <algorithm>
#include <cmath>

namespace avpn {
namespace {

constexpr quint64 kMaxSafeJsonInteger = Q_UINT64_C(9007199254740991); // 2^53-1

bool fail(CatalogParseError &error, CatalogParseErrorCode code, const QString &path,
          const QString &detail)
{
    error.code = code;
    error.path = path;
    error.detail = detail;
    return false;
}

bool isCanonicalBase64UrlText(const QByteArray &text, bool allowEmpty = false)
{
    if (text.isEmpty())
        return allowEmpty;
    if ((text.size() % 4) == 1)
        return false;
    for (const char ch : text) {
        const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
        if (!ok)
            return false; // includes '=' padding, '+'/'/' and whitespace
    }
    return true;
}

bool decodeBase64Url(const QByteArray &text, QByteArray &decoded)
{
    if (!isCanonicalBase64UrlText(text))
        return false;
    const auto result = QByteArray::fromBase64Encoding(
        text, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (result.decodingStatus != QByteArray::Base64DecodingStatus::Ok)
        return false;
    decoded = result.decoded;
    return decoded.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) == text;
}

// QJsonDocument follows common "last duplicate key wins" behavior. Signed data must not have
// ambiguous semantics, including escaped duplicates ("id" vs "\u0069d"), so scan the original
// valid JSON and reject duplicates at every object depth before using it.
class DuplicateKeyScanner {
public:
    explicit DuplicateKeyScanner(const QByteArray &json) : m_json(json) {}

    bool scan(QString &duplicate)
    {
        skipWhitespace();
        if (!parseValue(duplicate))
            return false;
        skipWhitespace();
        return m_pos == m_json.size();
    }

private:
    void skipWhitespace()
    {
        while (m_pos < m_json.size()) {
            const char ch = m_json.at(m_pos);
            if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
                break;
            ++m_pos;
        }
    }

    bool parseString(QString *decoded = nullptr)
    {
        if (m_pos >= m_json.size() || m_json.at(m_pos) != '"')
            return false;
        const int start = m_pos++;
        bool escaped = false;
        while (m_pos < m_json.size()) {
            const char ch = m_json.at(m_pos++);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                if (decoded) {
                    const QByteArray quoted = m_json.mid(start, m_pos - start);
                    const QJsonDocument keyDoc = QJsonDocument::fromJson("[" + quoted + "]");
                    if (!keyDoc.isArray() || keyDoc.array().isEmpty()
                        || !keyDoc.array().first().isString())
                        return false;
                    *decoded = keyDoc.array().first().toString();
                }
                return true;
            }
        }
        return false;
    }

    bool parseObject(QString &duplicate)
    {
        ++m_pos; // {
        skipWhitespace();
        if (m_pos < m_json.size() && m_json.at(m_pos) == '}') {
            ++m_pos;
            return true;
        }
        QSet<QString> keys;
        while (m_pos < m_json.size()) {
            QString key;
            if (!parseString(&key))
                return false;
            if (keys.contains(key)) {
                duplicate = key;
                return false;
            }
            keys.insert(key);
            skipWhitespace();
            if (m_pos >= m_json.size() || m_json.at(m_pos++) != ':')
                return false;
            skipWhitespace();
            if (!parseValue(duplicate))
                return false;
            skipWhitespace();
            if (m_pos >= m_json.size())
                return false;
            const char sep = m_json.at(m_pos++);
            if (sep == '}')
                return true;
            if (sep != ',')
                return false;
            skipWhitespace();
        }
        return false;
    }

    bool parseArray(QString &duplicate)
    {
        ++m_pos; // [
        skipWhitespace();
        if (m_pos < m_json.size() && m_json.at(m_pos) == ']') {
            ++m_pos;
            return true;
        }
        while (m_pos < m_json.size()) {
            if (!parseValue(duplicate))
                return false;
            skipWhitespace();
            if (m_pos >= m_json.size())
                return false;
            const char sep = m_json.at(m_pos++);
            if (sep == ']')
                return true;
            if (sep != ',')
                return false;
            skipWhitespace();
        }
        return false;
    }

    bool parseValue(QString &duplicate)
    {
        skipWhitespace();
        if (m_pos >= m_json.size())
            return false;
        const char ch = m_json.at(m_pos);
        if (ch == '{')
            return parseObject(duplicate);
        if (ch == '[')
            return parseArray(duplicate);
        if (ch == '"')
            return parseString();

        // Syntax was already validated by QJsonDocument. Consume number/true/false/null.
        const int start = m_pos;
        while (m_pos < m_json.size()) {
            const char cur = m_json.at(m_pos);
            if (cur == ',' || cur == ']' || cur == '}' || cur == ' ' || cur == '\t'
                || cur == '\r' || cur == '\n')
                break;
            ++m_pos;
        }
        return m_pos > start;
    }

    const QByteArray &m_json;
    int m_pos = 0;
};

bool rejectDuplicateKeys(const QByteArray &json, CatalogParseError &error, const QString &path)
{
    QString duplicate;
    DuplicateKeyScanner scanner(json);
    if (scanner.scan(duplicate))
        return true;
    if (!duplicate.isEmpty())
        return fail(error, CatalogParseErrorCode::DuplicateJsonKey, path,
                    QStringLiteral("duplicate JSON key"));
    return fail(error, CatalogParseErrorCode::InvalidPayloadJson, path,
                QStringLiteral("JSON structure scan failed"));
}

bool withinJsonLimits(const QJsonValue &value, int depth, int &nodes,
                      const CatalogParserLimits &limits, QString &detail)
{
    if (depth > qBound(1, limits.maximumJsonDepth, 64)) {
        detail = QStringLiteral("JSON nesting depth exceeded");
        return false;
    }
    if (++nodes > qBound(1, limits.maximumJsonNodes, 100000)) {
        detail = QStringLiteral("JSON node count exceeded");
        return false;
    }
    if (value.isString()
        && value.toString().toUtf8().size() > qBound(64, limits.maximumStringBytes, 64 * 1024)) {
        detail = QStringLiteral("JSON string length exceeded");
        return false;
    }
    if (value.isArray()) {
        for (const QJsonValue &item : value.toArray())
            if (!withinJsonLimits(item, depth + 1, nodes, limits, detail))
                return false;
    } else if (value.isObject()) {
        const QJsonObject object = value.toObject();
        for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
            if (it.key().toUtf8().size() > qBound(64, limits.maximumStringBytes, 64 * 1024)) {
                detail = QStringLiteral("JSON key length exceeded");
                return false;
            }
            if (!withinJsonLimits(it.value(), depth + 1, nodes, limits, detail))
                return false;
        }
    }
    return true;
}

bool requiredString(const QJsonObject &object, const QString &key, const QString &path,
                    QString &out, CatalogParseError &error, int maximumBytes = 4096)
{
    const QJsonValue value = object.value(key);
    if (!value.isString() || value.toString().isEmpty())
        return fail(error, CatalogParseErrorCode::MissingField, path + QLatin1Char('.') + key,
                    QStringLiteral("required non-empty string"));
    out = value.toString();
    if (out.toUtf8().size() > maximumBytes)
        return fail(error, CatalogParseErrorCode::InvalidField, path + QLatin1Char('.') + key,
                    QStringLiteral("string is too long"));
    return true;
}

bool requiredUInt(const QJsonObject &object, const QString &key, const QString &path,
                  quint64 &out, CatalogParseError &error, bool allowZero = false)
{
    const QJsonValue value = object.value(key);
    if (!value.isDouble())
        return fail(error, CatalogParseErrorCode::MissingField, path + QLatin1Char('.') + key,
                    QStringLiteral("required unsigned integer"));
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 0.0 || number > double(kMaxSafeJsonInteger)
        || std::floor(number) != number || (!allowZero && number == 0.0)) {
        return fail(error, CatalogParseErrorCode::InvalidField, path + QLatin1Char('.') + key,
                    QStringLiteral("invalid unsigned integer"));
    }
    out = static_cast<quint64>(number);
    return true;
}

bool parseUtcDate(const QJsonObject &object, const QString &key, const QString &path,
                  QDateTime &out, CatalogParseError &error)
{
    QString text;
    if (!requiredString(object, key, path, text, error, 64))
        return false;
    out = QDateTime::fromString(text, Qt::ISODateWithMs);
    if (!out.isValid())
        out = QDateTime::fromString(text, Qt::ISODate);
    if (!out.isValid() || (!text.endsWith(QLatin1Char('Z'))
                           && !QRegularExpression(QStringLiteral("[+-]\\d{2}:\\d{2}$"))
                                   .match(text).hasMatch())) {
        return fail(error, CatalogParseErrorCode::InvalidField, path + QLatin1Char('.') + key,
                    QStringLiteral("required ISO-8601 timestamp with timezone"));
    }
    out = out.toUTC();
    return true;
}

bool safeIdentifier(const QString &value, int maximum = 128)
{
    if (value.isEmpty() || value.size() > maximum)
        return false;
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:/-]*$"));
    return re.match(value).hasMatch();
}

bool safeProviderIdentifier(const QString &value)
{
    static const QRegularExpression re(QStringLiteral("^[a-z][a-z0-9.-]{2,63}$"));
    return re.match(value).hasMatch();
}

bool safeVerificationContext(const QString &value)
{
    // The same opaque value is copied into receipt and outcome requests.  Enforce their
    // common closed grammar while accepting the signed catalog, not after tunnel startup.
    static const QRegularExpression re(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$"));
    return re.match(value).hasMatch();
}

bool parseUniqueStrings(const QJsonValue &value, const QString &path, QStringList &out,
                        CatalogParseError &error, bool requireNonEmpty = true, int maximum = 64)
{
    if (!value.isArray())
        return fail(error, CatalogParseErrorCode::MissingField, path,
                    QStringLiteral("required string array"));
    const QJsonArray array = value.toArray();
    if ((requireNonEmpty && array.isEmpty()) || array.size() > maximum)
        return fail(error, CatalogParseErrorCode::InvalidField, path,
                    QStringLiteral("invalid array size"));
    QSet<QString> seen;
    for (int i = 0; i < array.size(); ++i) {
        if (!array.at(i).isString() || array.at(i).toString().isEmpty()
            || array.at(i).toString().toUtf8().size() > 512) {
            return fail(error, CatalogParseErrorCode::InvalidField,
                        QStringLiteral("%1[%2]").arg(path).arg(i),
                        QStringLiteral("required bounded non-empty string"));
        }
        const QString item = array.at(i).toString();
        if (seen.contains(item))
            return fail(error, CatalogParseErrorCode::InvalidField, path,
                        QStringLiteral("duplicate array value"));
        seen.insert(item);
        out.append(item);
    }
    return true;
}

bool rejectUnknownKeys(const QJsonObject &object, const QSet<QString> &allowed,
                       const QString &path, CatalogParseError &error,
                       CatalogParseErrorCode code);

bool validDnsName(const QString &host);

bool parseReceiptProvidersExtension(const QJsonValue &value, const QString &path,
                                    const Catalog &catalog,
                                    ReceiptProviderPolicy &out, CatalogParseError &error)
{
    if (!value.isObject())
        return fail(error, CatalogParseErrorCode::InvalidField, path,
                    QStringLiteral("receipt provider extension value must be an object"));
    const QJsonObject object = value.toObject();
    static const QSet<QString> keys{
        QStringLiteral("schema_version"), QStringLiteral("quorum"),
        QStringLiteral("verification_token"),
        QStringLiteral("verification_token_expires_at"), QStringLiteral("providers")};
    if (!rejectUnknownKeys(object, keys, path, error, CatalogParseErrorCode::InvalidField))
        return false;
    quint64 schema = 0, quorum = 0;
    QString verificationToken;
    QDateTime verificationTokenExpiresAt;
    if (!requiredUInt(object, QStringLiteral("schema_version"), path, schema, error)
        || !requiredUInt(object, QStringLiteral("quorum"), path, quorum, error)
        || schema != 1 || quorum != 2
        || !requiredString(object, QStringLiteral("verification_token"), path,
                           verificationToken, error, 4096)
        || !parseUtcDate(object, QStringLiteral("verification_token_expires_at"), path,
                         verificationTokenExpiresAt, error)
        || !object.value(QStringLiteral("providers")).isArray()
        || object.value(QStringLiteral("providers")).toArray().size() != 2) {
        return fail(error, CatalogParseErrorCode::InvalidField, path,
                    QStringLiteral("receipt provider policy shape/quorum is invalid"));
    }
    const QStringList tokenParts = verificationToken.split(QLatin1Char('.'));
    QByteArray tokenKid, tokenPayload, tokenSignature;
    const auto canonicalPart = [](const QString &part, QByteArray &decoded,
                                  int minimum, int maximum) {
        const QByteArray encoded = part.toLatin1();
        if (QString::fromLatin1(encoded) != part || !isCanonicalBase64UrlText(encoded))
            return false;
        const auto result = QByteArray::fromBase64Encoding(
            encoded, QByteArray::Base64UrlEncoding
                         | QByteArray::AbortOnBase64DecodingErrors);
        if (result.decodingStatus != QByteArray::Base64DecodingStatus::Ok
            || result.decoded.size() < minimum || result.decoded.size() > maximum)
            return false;
        decoded = result.decoded;
        return true;
    };
    const bool scopedTokenValid = tokenParts.size() == 4
        && tokenParts.at(0) == QLatin1String("v1")
        && canonicalPart(tokenParts.at(1), tokenKid, 1, 64)
        && canonicalSigningKeyId(QString::fromLatin1(tokenKid))
        && QString::fromLatin1(tokenKid).toLatin1() == tokenKid
        && canonicalPart(tokenParts.at(2), tokenPayload, 1, 3072)
        && tokenParts.at(3).size() == 86
        && canonicalPart(tokenParts.at(3), tokenSignature, 64, 64);
    tokenKid.fill('\0');
    tokenPayload.fill('\0');
    tokenSignature.fill('\0');
    if (!scopedTokenValid
        || !catalog.issuedAt.isValid() || !catalog.expiresAt.isValid()
        || verificationTokenExpiresAt <= catalog.issuedAt
        || verificationTokenExpiresAt > catalog.expiresAt
        || catalog.issuedAt.secsTo(verificationTokenExpiresAt)
               > kVerificationGrantMaximumLifetimeSeconds) {
        return fail(error, CatalogParseErrorCode::InvalidField,
                    path + QStringLiteral(".verification_token"),
                    QStringLiteral("receipt-only token scope/lifetime is invalid"));
    }
    static const QSet<QString> providerKeys{
        QStringLiteral("id"), QStringLiteral("trust_domain"),
        QStringLiteral("base_url"), QStringLiteral("bootstrap_ips"),
        QStringLiteral("receipt_kid"), QStringLiteral("receipt_key_epoch")};
    QSet<QString> ids, trustDomains, hosts, receiptKids, allIps;
    QString previousId;
    const QJsonArray providers = object.value(QStringLiteral("providers")).toArray();
    QList<ReceiptProviderDescriptor> parsed;
    for (int index = 0; index < providers.size(); ++index) {
        const QString providerPath = QStringLiteral("%1.providers[%2]").arg(path).arg(index);
        if (!providers.at(index).isObject()
            || !rejectUnknownKeys(providers.at(index).toObject(), providerKeys, providerPath,
                                  error, CatalogParseErrorCode::InvalidField))
            return false;
        const QJsonObject provider = providers.at(index).toObject();
        ReceiptProviderDescriptor descriptor;
        quint64 keyEpoch = 0;
        if (!requiredString(provider, QStringLiteral("id"), providerPath,
                            descriptor.id, error, 64)
            || !requiredString(provider, QStringLiteral("trust_domain"), providerPath,
                               descriptor.trustDomain, error, 64)
            || !requiredString(provider, QStringLiteral("base_url"), providerPath,
                               descriptor.baseUrl, error, 512)
            || !requiredString(provider, QStringLiteral("receipt_kid"), providerPath,
                               descriptor.receiptKid, error, 64)
            || !requiredUInt(provider, QStringLiteral("receipt_key_epoch"), providerPath,
                             keyEpoch, error)
            || !safeProviderIdentifier(descriptor.id)
            || !safeProviderIdentifier(descriptor.trustDomain)
            || !canonicalSigningKeyId(descriptor.receiptKid) || ids.contains(descriptor.id)
            || trustDomains.contains(descriptor.trustDomain)
            || receiptKids.contains(descriptor.receiptKid)
            || (!previousId.isEmpty() && descriptor.id <= previousId)) {
            return fail(error, CatalogParseErrorCode::InvalidField, providerPath,
                        QStringLiteral("receipt provider identity/order is invalid"));
        }
        const QUrl base(descriptor.baseUrl, QUrl::StrictMode);
        const QString host = base.host();
        if (!base.isValid() || base.scheme() != QLatin1String("https")
            || host.isEmpty() || host != host.toLower() || !validDnsName(host)
            || hosts.contains(host) || !base.userInfo().isEmpty()
            || !base.path().isEmpty() || !base.query().isEmpty() || !base.fragment().isEmpty()
            || base.port(-1) != -1
            || base.toString(QUrl::FullyEncoded) != descriptor.baseUrl) {
            return fail(error, CatalogParseErrorCode::InvalidField,
                        providerPath + QStringLiteral(".base_url"),
                        QStringLiteral("receipt provider must use a canonical bare HTTPS origin"));
        }
        if (!parseUniqueStrings(provider.value(QStringLiteral("bootstrap_ips")),
                                providerPath + QStringLiteral(".bootstrap_ips"),
                                descriptor.bootstrapIps, error, true, 16))
            return false;
        for (const QString &literal : descriptor.bootstrapIps) {
            QHostAddress address;
            if (!address.setAddress(literal) || !address.scopeId().isEmpty()
                || address.toString() != literal
                || !address.isGlobal() || allIps.contains(literal)) {
                return fail(error, CatalogParseErrorCode::InvalidField,
                            providerPath + QStringLiteral(".bootstrap_ips"),
                            QStringLiteral("bootstrap IPs must be canonical, public and disjoint"));
            }
            allIps.insert(literal);
        }
        descriptor.receiptKeyEpoch = keyEpoch;
        previousId = descriptor.id;
        ids.insert(descriptor.id);
        trustDomains.insert(descriptor.trustDomain);
        hosts.insert(host);
        receiptKids.insert(descriptor.receiptKid);
        parsed.append(std::move(descriptor));
    }
    out.schemaVersion = 1;
    out.quorum = 2;
    out.verificationToken = verificationToken.toLatin1();
    out.verificationTokenExpiresAt = verificationTokenExpiresAt;
    out.providers = std::move(parsed);
    return true;
}

bool boundedExtensionValue(const QJsonValue &value, int maximumBytes, int maximumNodes)
{
    const QByteArray encoded = QJsonDocument(QJsonArray{value}).toJson(QJsonDocument::Compact);
    if (encoded.size() > maximumBytes + 2) return false;
    int nodes = 0;
    const auto walk = [&](const auto &self, const QJsonValue &item, int depth) -> bool {
        if (++nodes > maximumNodes || depth > 8) return false;
        if (item.isString() && item.toString().toUtf8().size() > 4096) return false;
        if (item.isArray()) {
            for (const QJsonValue &child : item.toArray())
                if (!self(self, child, depth + 1)) return false;
        } else if (item.isObject()) {
            const QJsonObject object = item.toObject();
            for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
                if (it.key().isEmpty() || it.key().toUtf8().size() > 64
                    || !self(self, it.value(), depth + 1)) return false;
            }
        }
        return true;
    };
    return walk(walk, value, 0);
}

bool parseDirectorySelection(const QJsonValue &value, const QString &path,
                             CatalogResolveSelection &out, CatalogParseError &error)
{
    if (!value.isObject())
        return fail(error, CatalogParseErrorCode::InvalidField, path,
                    QStringLiteral("directory selection must be an object"));
    const QJsonObject object = value.toObject();
    static const QSet<QString> keys{QStringLiteral("transport"),
                                     QStringLiteral("location_id")};
    if (!rejectUnknownKeys(object, keys, path, error,
                           CatalogParseErrorCode::InvalidField)) return false;
    QString transport;
    if (!requiredString(object, QStringLiteral("transport"), path,
                        transport, error, 8)) return false;
    if (transport == QLatin1String("auto")) out.transport = ConnectionMode::Auto;
    else if (transport == QLatin1String("awg")) out.transport = ConnectionMode::ForceAwg;
    else if (transport == QLatin1String("xray")) out.transport = ConnectionMode::ForceXray;
    else return fail(error, CatalogParseErrorCode::InvalidField,
                     path + QStringLiteral(".transport"),
                     QStringLiteral("directory selection transport is invalid"));
    const QJsonValue location = object.value(QStringLiteral("location_id"));
    static const QRegularExpression locationId(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"));
    if (!location.isUndefined()) {
        if (!location.isString() || !locationId.match(location.toString()).hasMatch())
            return fail(error, CatalogParseErrorCode::InvalidField,
                        path + QStringLiteral(".location_id"),
                        QStringLiteral("directory selection location is invalid"));
        out.locationId = location.toString();
    }
    return true;
}

bool parseLocationDirectoryExtension(const QJsonValue &value, const QString &path,
                                     const Catalog &catalog,
                                     CatalogLocationDirectory &out,
                                     CatalogParseError &error)
{
    if (!value.isObject())
        return fail(error, CatalogParseErrorCode::InvalidField, path,
                    QStringLiteral("location directory must be an object"));
    const QJsonObject object = value.toObject();
    static const QSet<QString> keys{QStringLiteral("schema_version"),
                                     QStringLiteral("selection"),
                                     QStringLiteral("locations")};
    if (!rejectUnknownKeys(object, keys, path, error,
                           CatalogParseErrorCode::InvalidField)) return false;
    quint64 schema = 0;
    if (!requiredUInt(object, QStringLiteral("schema_version"), path, schema, error)
        || schema != 1
        || !parseDirectorySelection(object.value(QStringLiteral("selection")),
                                    path + QStringLiteral(".selection"), out.selection, error)
        || !object.value(QStringLiteral("locations")).isArray()
        || object.value(QStringLiteral("locations")).toArray().isEmpty()
        || object.value(QStringLiteral("locations")).toArray().size() > 128) {
        return error.code == CatalogParseErrorCode::None
            ? fail(error, CatalogParseErrorCode::InvalidField, path,
                   QStringLiteral("location directory header/bounds are invalid"))
            : false;
    }
    static const QSet<QString> locationKeys{
        QStringLiteral("id"), QStringLiteral("country"), QStringLiteral("city"),
        QStringLiteral("display_key"), QStringLiteral("transports")};
    static const QSet<QString> transportKeys{
        QStringLiteral("transport"), QStringLiteral("state"),
        QStringLiteral("predicted_quality"), QStringLiteral("observed_at")};
    static const QRegularExpression locationId(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"));
    static const QRegularExpression country(QStringLiteral("^[A-Z]{2}$"));
    QString previousLocationId;
    const QJsonArray locations = object.value(QStringLiteral("locations")).toArray();
    for (int index = 0; index < locations.size(); ++index) {
        const QString locationPath = QStringLiteral("%1.locations[%2]").arg(path).arg(index);
        if (!locations.at(index).isObject()
            || !rejectUnknownKeys(locations.at(index).toObject(), locationKeys,
                                  locationPath, error,
                                  CatalogParseErrorCode::InvalidField)) return false;
        const QJsonObject item = locations.at(index).toObject();
        CatalogDirectoryLocation location;
        if (!requiredString(item, QStringLiteral("id"), locationPath,
                            location.id, error, 64)
            || !requiredString(item, QStringLiteral("country"), locationPath,
                               location.country, error, 2)
            || !requiredString(item, QStringLiteral("display_key"), locationPath,
                               location.displayKey, error, 128)
            || !locationId.match(location.id).hasMatch()
            || !country.match(location.country).hasMatch()
            || !safeIdentifier(location.displayKey, 128)
            || (!previousLocationId.isEmpty() && location.id <= previousLocationId)) {
            return fail(error, CatalogParseErrorCode::InvalidField, locationPath,
                        QStringLiteral("directory location identity/order is invalid"));
        }
        const QJsonValue city = item.value(QStringLiteral("city"));
        if (!city.isUndefined()) {
            if (!city.isString() || !safeIdentifier(city.toString(), 16))
                return fail(error, CatalogParseErrorCode::InvalidField,
                            locationPath + QStringLiteral(".city"),
                            QStringLiteral("directory city is invalid"));
            location.city = city.toString();
        }
        const QJsonValue transportsValue = item.value(QStringLiteral("transports"));
        if (!transportsValue.isArray() || transportsValue.toArray().size() != 2)
            return fail(error, CatalogParseErrorCode::InvalidField,
                        locationPath + QStringLiteral(".transports"),
                        QStringLiteral("directory requires exact AWG/Xray pair"));
        const QJsonArray transports = transportsValue.toArray();
        for (int transportIndex = 0; transportIndex < 2; ++transportIndex) {
            const QString transportPath = QStringLiteral("%1.transports[%2]")
                                              .arg(locationPath).arg(transportIndex);
            if (!transports.at(transportIndex).isObject()
                || !rejectUnknownKeys(transports.at(transportIndex).toObject(),
                                      transportKeys, transportPath, error,
                                      CatalogParseErrorCode::InvalidField)) return false;
            const QJsonObject summary = transports.at(transportIndex).toObject();
            QString transportName, state;
            if (!requiredString(summary, QStringLiteral("transport"), transportPath,
                                transportName, error, 8)
                || !requiredString(summary, QStringLiteral("state"), transportPath,
                                   state, error, 32)
                || transportName != (transportIndex == 0 ? QLatin1String("awg")
                                                          : QLatin1String("xray"))) {
                return fail(error, CatalogParseErrorCode::InvalidField, transportPath,
                            QStringLiteral("directory transport order/value is invalid"));
            }
            CatalogDirectoryTransport transport;
            transport.transport = transportIndex == 0 ? TransportKind::Awg
                                                       : TransportKind::Xray;
            if (state == QLatin1String("selectable"))
                transport.availability = CatalogDirectoryAvailability::Selectable;
            else if (state == QLatin1String("temporarily_unavailable"))
                transport.availability =
                    CatalogDirectoryAvailability::TemporarilyUnavailable;
            else if (state == QLatin1String("unsupported"))
                transport.availability = CatalogDirectoryAvailability::Unsupported;
            else return fail(error, CatalogParseErrorCode::InvalidField,
                             transportPath + QStringLiteral(".state"),
                             QStringLiteral("directory transport state is invalid"));
            const QJsonValue quality = summary.value(QStringLiteral("predicted_quality"));
            const bool hasQuality = !quality.isUndefined();
            const bool hasObserved = summary.contains(QStringLiteral("observed_at"));
            if (transport.availability == CatalogDirectoryAvailability::Selectable) {
                if (!hasQuality || !quality.isDouble() || !std::isfinite(quality.toDouble())
                    || quality.toDouble() < 0.0 || quality.toDouble() > 1.0
                    || !hasObserved
                    || !parseUtcDate(summary, QStringLiteral("observed_at"), transportPath,
                                     transport.observedAt, error)
                    || transport.observedAt > catalog.issuedAt) {
                    return fail(error, CatalogParseErrorCode::InvalidField, transportPath,
                                QStringLiteral("selectable directory evidence is invalid"));
                }
                transport.predictedQuality = quality.toDouble();
            } else if (hasQuality || hasObserved) {
                return fail(error, CatalogParseErrorCode::InvalidField, transportPath,
                            QStringLiteral("unavailable directory transport has evidence"));
            }
            location.transports.append(std::move(transport));
        }
        previousLocationId = location.id;
        out.locations.append(std::move(location));
    }
    out.schemaVersion = 1;
    return true;
}

bool parseCatalogExtensions(const QJsonValue &value, Catalog &catalog,
                            CatalogParseError &error)
{
    if (value.isUndefined())
        return true; // N-1 payloads omit the evolution zone.
    if (!value.isArray() || value.toArray().size() > 32)
        return fail(error, CatalogParseErrorCode::InvalidField,
                    QStringLiteral("$.extensions"),
                    QStringLiteral("extensions must be a bounded array"));
    static const QSet<QString> knownExtensionIds = {
        QStringLiteral("verification.providers_v1"),
        QStringLiteral("catalog.location_directory_v1"),
    };
    static const QRegularExpression idPattern(
        QStringLiteral("^[a-z][a-z0-9_.-]{2,63}$"));
    static const QRegularExpression capabilityPattern(
        QStringLiteral("^[a-z][a-z0-9_.-]{2,95}$"));
    QSet<QString> ids;
    const QJsonArray extensions = value.toArray();
    for (int index = 0; index < extensions.size(); ++index) {
        const QString path = QStringLiteral("$.extensions[%1]").arg(index);
        if (!extensions.at(index).isObject())
            return fail(error, CatalogParseErrorCode::InvalidField, path,
                        QStringLiteral("extension entry must be an object"));
        const QJsonObject extension = extensions.at(index).toObject();
        static const QSet<QString> keys = {
            QStringLiteral("id"), QStringLiteral("critical"),
            QStringLiteral("required_cap"), QStringLiteral("value"),
        };
        if (!rejectUnknownKeys(extension, keys, path, error,
                               CatalogParseErrorCode::InvalidField))
            return false;
        QString id;
        if (!requiredString(extension, QStringLiteral("id"), path, id, error, 64)
            || !idPattern.match(id).hasMatch() || ids.contains(id)
            || !extension.value(QStringLiteral("critical")).isBool()
            || !extension.contains(QStringLiteral("value"))) {
            return fail(error, CatalogParseErrorCode::InvalidField, path,
                        QStringLiteral("malformed or duplicate extension entry"));
        }
        ids.insert(id);
        const QJsonValue requiredCap = extension.value(QStringLiteral("required_cap"));
        if (!requiredCap.isUndefined()
            && (!requiredCap.isString()
                || !capabilityPattern.match(requiredCap.toString()).hasMatch())) {
            return fail(error, CatalogParseErrorCode::InvalidField,
                        path + QStringLiteral(".required_cap"),
                        QStringLiteral("extension required_cap is malformed"));
        }
        const bool isDirectory = id == QLatin1String("catalog.location_directory_v1");
        if (!boundedExtensionValue(extension.value(QStringLiteral("value")),
                                   isDirectory ? 64 * 1024 : 8192,
                                   isDirectory ? 4096 : 256))
            return fail(error, CatalogParseErrorCode::InvalidField,
                        path + QStringLiteral(".value"),
                        QStringLiteral("extension value exceeds local bounds"));
        if (extension.value(QStringLiteral("critical")).toBool()
            && !knownExtensionIds.contains(id)) {
            return fail(error, CatalogParseErrorCode::UnsupportedCriticalExtension, path,
                        QStringLiteral("unknown critical catalog extension"));
        }
        if (id == QLatin1String("verification.providers_v1")) {
            if (!extension.value(QStringLiteral("critical")).toBool()
                || requiredCap.toString() != QLatin1String("probe.egress_receipt_v1")
                || catalog.receiptProviderPolicy.has_value()) {
                return fail(error, CatalogParseErrorCode::InvalidField, path,
                            QStringLiteral("receipt provider extension capability/criticality invalid"));
            }
            ReceiptProviderPolicy policy;
            if (!parseReceiptProvidersExtension(extension.value(QStringLiteral("value")),
                                                path + QStringLiteral(".value"),
                                                catalog, policy, error))
                return false;
            catalog.receiptProviderPolicy = std::move(policy);
        }
        if (isDirectory) {
            if (!extension.value(QStringLiteral("critical")).toBool()
                || requiredCap.toString()
                       != QLatin1String("catalog.location_directory_v1")
                || catalog.locationDirectory.has_value()) {
                return fail(error, CatalogParseErrorCode::InvalidField, path,
                            QStringLiteral("location directory capability/criticality invalid"));
            }
            CatalogLocationDirectory directory;
            if (!parseLocationDirectoryExtension(extension.value(QStringLiteral("value")),
                                                 path + QStringLiteral(".value"), catalog,
                                                 directory, error)) return false;
            catalog.locationDirectory = std::move(directory);
        }
        // Unknown non-critical values are deliberately discarded here and can never flow into a
        // protocol profile/native compiler. Exact signed bytes remain in Catalog::exactPayload.
    }
    return true;
}

bool validDnsName(const QString &host)
{
    if (host.isEmpty() || host.size() > 253
        || host.compare(QStringLiteral("localhost"), Qt::CaseInsensitive) == 0)
        return false;
    // A single-label name could be resolved through a hostile local search domain. Catalog
    // endpoints/SNI are public authorities and therefore must be explicit FQDNs.
    static const QRegularExpression hostname(
        QStringLiteral("^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+"
                       "[A-Za-z]{2,63}$"));
    return hostname.match(host).hasMatch();
}

bool validEndpointHost(const QString &host)
{
    QHostAddress address;
    if (address.setAddress(host)) {
        // Native policy hashes and platform guards compare this authority byte-for-byte.  Accept
        // only Qt's canonical IP literal, never alternate IPv4 spelling, expanded/uppercase IPv6,
        // or a scoped textual alias for the same address.
        if (!address.scopeId().isEmpty() || address.toString() != host)
            return false;
        if (address.isNull() || address.isLoopback() || address.isLinkLocal()
            || address.isMulticast())
            return false;
        bool mappedV4 = false;
        const quint32 v4 = address.toIPv4Address(&mappedV4);
        if (address.protocol() == QAbstractSocket::IPv4Protocol || mappedV4) {
            const auto inV4 = [v4](quint32 network, int prefix) {
                const quint32 mask = prefix == 0 ? 0u : (~quint32(0) << (32 - prefix));
                return (v4 & mask) == (network & mask);
            };
            // Non-public, shared, documentation, benchmark, multicast and reserved blocks.
            return !inV4(0x00000000u, 8) && !inV4(0x0a000000u, 8)
                   && !inV4(0x64400000u, 10) && !inV4(0x7f000000u, 8)
                   && !inV4(0xa9fe0000u, 16) && !inV4(0xac100000u, 12)
                   && !inV4(0xc0000000u, 24) && !inV4(0xc0000200u, 24)
                   && !inV4(0xc0a80000u, 16) && !inV4(0xc6120000u, 15)
                   && !inV4(0xc6336400u, 24) && !inV4(0xcb007100u, 24)
                   && !inV4(0xe0000000u, 4) && !inV4(0xf0000000u, 4);
        }
        static const QList<QPair<QHostAddress, int>> nonPublicV6 = {
            {QHostAddress(QStringLiteral("::")), 128},
            {QHostAddress(QStringLiteral("::1")), 128},
            {QHostAddress(QStringLiteral("fc00::")), 7},
            {QHostAddress(QStringLiteral("fe80::")), 10},
            {QHostAddress(QStringLiteral("ff00::")), 8},
            {QHostAddress(QStringLiteral("2001:db8::")), 32},
        };
        for (const auto &subnet : nonPublicV6)
            if (address.isInSubnet(subnet))
                return false;
        return address.isGlobal();
    }
    // DNS is case-insensitive on the wire but not in our signed dispatch-policy identity.  The
    // contract therefore uses one canonical lowercase FQDN spelling.
    return host == host.toLower() && validDnsName(host);
}

bool validCidr(const QString &cidr)
{
    const QStringList parts = cidr.split(QLatin1Char('/'));
    if (parts.size() != 2)
        return false;
    QHostAddress address;
    bool prefixOk = false;
    const int prefix = parts.at(1).toInt(&prefixOk);
    if (!prefixOk || !address.setAddress(parts.at(0)))
        return false;
    const int maximum = address.protocol() == QAbstractSocket::IPv4Protocol ? 32
                       : address.protocol() == QAbstractSocket::IPv6Protocol ? 128 : -1;
    return maximum >= 0 && prefix >= 0 && prefix <= maximum;
}

bool validCanonicalCidr(const QString &cidr)
{
    const int slash = cidr.indexOf(QLatin1Char('/'));
    if (slash <= 0 || slash != cidr.lastIndexOf(QLatin1Char('/')))
        return false;
    const QString addressText = cidr.left(slash);
    const QString prefixText = cidr.mid(slash + 1);
    QHostAddress address;
    bool prefixOk = false;
    const int prefix = prefixText.toInt(&prefixOk);
    return prefixOk && prefixText == QString::number(prefix)
           && address.setAddress(addressText) && address.toString() == addressText
           && validCidr(cidr);
}

bool validCanonicalGlobalIpLiteral(const QString &text)
{
    QHostAddress address;
    return address.setAddress(text) && address.toString() == text
           && validEndpointHost(text);
}

bool canonicalBase64Key32(const QString &text)
{
    const QByteArray latin = text.toLatin1();
    if (QString::fromLatin1(latin) != text)
        return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        latin, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.decodingStatus == QByteArray::Base64DecodingStatus::Ok
           && decoded.decoded.size() == 32 && decoded.decoded.toBase64() == latin;
}

bool canonicalBase64UrlKey32(const QString &text)
{
    QByteArray decoded;
    return decodeBase64Url(text.toLatin1(), decoded) && decoded.size() == 32;
}

bool jsonIntegerInRange(const QJsonValue &value, qint64 low, qint64 high, qint64 &out)
{
    if (!value.isDouble() || !std::isfinite(value.toDouble())
        || std::floor(value.toDouble()) != value.toDouble()
        || value.toDouble() < double(low) || value.toDouble() > double(high))
        return false;
    out = static_cast<qint64>(value.toDouble());
    return true;
}

bool rejectUnknownKeys(const QJsonObject &object, const QSet<QString> &allowed,
                       const QString &path, CatalogParseError &error,
                       CatalogParseErrorCode code = CatalogParseErrorCode::InvalidNativeProfile)
{
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (!allowed.contains(it.key()))
            return fail(error, code,
                        path + QStringLiteral(".<unknown>"),
                        QStringLiteral("unknown field in strict catalog schema"));
    }
    return true;
}

bool validCapability(const QString &value)
{
    static const QRegularExpression capability(
        QStringLiteral("^[a-z][a-z0-9_.-]{2,95}$"));
    return capability.match(value).hasMatch();
}

bool parseUnsignedRange(const QJsonValue &value, quint32 minimum, quint32 maximum,
                        quint32 &low, quint32 &high)
{
    if (!value.isString() || value.toString().size() > 64)
        return false;
    const QStringList parts = value.toString().split(QLatin1Char('-'));
    if (parts.isEmpty() || parts.size() > 2 || parts.at(0).isEmpty()
        || (parts.size() == 2 && parts.at(1).isEmpty()))
        return false;
    bool lowOk = false, highOk = false;
    const qulonglong lowValue = parts.at(0).toULongLong(&lowOk, 10);
    const qulonglong highValue = parts.size() == 2
                                     ? parts.at(1).toULongLong(&highOk, 10)
                                     : (highOk = true, lowValue);
    if (!lowOk || !highOk || lowValue < minimum || highValue > maximum
        || lowValue > highValue)
        return false;
    // toULongLong accepts a leading '+'. Canonical signed profiles do not.
    const QString canonical = parts.size() == 2
                                  ? QStringLiteral("%1-%2").arg(lowValue).arg(highValue)
                                  : QString::number(lowValue);
    if (canonical != value.toString())
        return false;
    low = quint32(lowValue);
    high = quint32(highValue);
    return true;
}

// Strict subset equal to the custom-packet grammar documented by amneziawg-go. Besides syntax,
// compute the maximum emitted size so server data cannot force fragmentation or huge allocation.
bool validAwgIPacket(const QString &spec, int mtu)
{
    if (spec.isEmpty() || spec.toUtf8().size() > 4096)
        return false;
    static const QRegularExpression token(
        QStringLiteral("<(?:b 0x([0-9A-Fa-f]+)|(r|rd|rc) ([0-9]+)|(t))>"));
    int offset = 0;
    quint64 maximumBytes = 0;
    while (offset < spec.size()) {
        const QRegularExpressionMatch match = token.match(spec, offset,
                                                           QRegularExpression::NormalMatch,
                                                           QRegularExpression::AnchorAtOffsetMatchOption);
        if (!match.hasMatch())
            return false;
        if (!match.captured(1).isEmpty()) {
            const QString hex = match.captured(1);
            if ((hex.size() % 2) != 0)
                return false;
            maximumBytes += quint64(hex.size() / 2);
        } else if (!match.captured(2).isEmpty()) {
            bool ok = false;
            const qulonglong count = match.captured(3).toULongLong(&ok, 10);
            if (!ok || match.captured(3) != QString::number(count))
                return false;
            maximumBytes += count;
        } else {
            maximumBytes += 4; // <t>
        }
        if (maximumBytes == 0 || maximumBytes >= quint64(mtu))
            return false;
        offset = match.capturedEnd();
    }
    return offset == spec.size() && maximumBytes > 0;
}

bool validateAwgConfig(const CatalogCandidate &candidate, const QJsonObject &config,
                       const QString &path, CatalogParseError &error)
{
    static const QSet<QString> allowed = {
        QStringLiteral("endpoint_host"), QStringLiteral("endpoint_port"),
        QStringLiteral("server_public_key"),
        QStringLiteral("client_public_key"), QStringLiteral("address"),
        QStringLiteral("allowed_ips"), QStringLiteral("dns"), QStringLiteral("mtu"),
        QStringLiteral("persistent_keepalive"), QStringLiteral("awg_params"),
    };
    if (!rejectUnknownKeys(config, allowed, path, error))
        return false;

    QString endpointHost, serverKey, clientKey;
    if (!requiredString(config, QStringLiteral("endpoint_host"), path,
                        endpointHost, error, 253)
        || !validEndpointHost(endpointHost)) {
        if (error.code == CatalogParseErrorCode::None)
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".endpoint_host"),
                        QStringLiteral("invalid endpoint host"));
        return false;
    }
    qint64 endpointPort = 0;
    if (!jsonIntegerInRange(config.value(QStringLiteral("endpoint_port")), 1, 65535, endpointPort))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".endpoint_port"),
                    QStringLiteral("endpoint port outside 1..65535"));
    if (!requiredString(config, QStringLiteral("server_public_key"), path,
                        serverKey, error, 64)
        || !requiredString(config, QStringLiteral("client_public_key"), path,
                           clientKey, error, 64))
        return false;
    if (!canonicalBase64Key32(serverKey) || !canonicalBase64Key32(clientKey))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile, path,
                    QStringLiteral("AWG public keys must be canonical 32-byte base64"));

    const QJsonValue address = config.value(QStringLiteral("address"));
    if (!address.isArray())
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".address"),
                    QStringLiteral("address must be a CIDR array"));
    QStringList addresses;
    if (!parseUniqueStrings(address, path + QStringLiteral(".address"), addresses, error,
                            true, 2))
        return false;
    QSet<QAbstractSocket::NetworkLayerProtocol> addressFamilies;
    for (const QString &cidr : addresses) {
        const int slash = cidr.lastIndexOf(QLatin1Char('/'));
        QHostAddress boundAddress;
        const bool isHostBinding = slash > 0 && boundAddress.setAddress(cidr.left(slash))
                                   && ((boundAddress.protocol() == QAbstractSocket::IPv4Protocol
                                        && cidr.mid(slash + 1) == QLatin1String("32"))
                                       || (boundAddress.protocol() == QAbstractSocket::IPv6Protocol
                                           && cidr.mid(slash + 1) == QLatin1String("128")));
        const bool unspecified = boundAddress == QHostAddress::Any
                                 || boundAddress == QHostAddress::AnyIPv4
                                 || boundAddress == QHostAddress::AnyIPv6;
        if (!validCanonicalCidr(cidr) || !isHostBinding || unspecified
            || boundAddress.isLoopback() || boundAddress.isLinkLocal()
            || boundAddress.isMulticast()
            || addressFamilies.contains(boundAddress.protocol()))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".address"),
                        QStringLiteral("binding requires at most one canonical unicast host per family"));
        addressFamilies.insert(boundAddress.protocol());
    }

    QStringList allowedIps, dns;
    if (!parseUniqueStrings(config.value(QStringLiteral("allowed_ips")),
                            path + QStringLiteral(".allowed_ips"), allowedIps, error, true, 2)
        || !parseUniqueStrings(config.value(QStringLiteral("dns")),
                               path + QStringLiteral(".dns"), dns, error, true, 4))
        return false;
    const QStringList fullTunnelCoverage = {
        QStringLiteral("0.0.0.0/0"), QStringLiteral("::/0"),
    };
    if (allowedIps != fullTunnelCoverage)
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".allowed_ips"),
                    QStringLiteral("AWG profile must preserve canonical dual-stack full-tunnel coverage"));
    for (const QString &ip : dns) {
        if (!validCanonicalGlobalIpLiteral(ip))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".dns"),
                        QStringLiteral("DNS entries must be canonical global-unicast IP literals"));
    }

    qint64 mtu = 0;
    if (!jsonIntegerInRange(config.value(QStringLiteral("mtu")), 576, 1500, mtu))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".mtu"), QStringLiteral("mtu outside local safety bounds"));
    qint64 keepalive = 0;
    if (!jsonIntegerInRange(config.value(QStringLiteral("persistent_keepalive")), 1, 600,
                            keepalive))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".persistent_keepalive"),
                    QStringLiteral("keepalive outside local safety bounds"));
    if (!config.value(QStringLiteral("awg_params")).isObject())
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".awg_params"), QStringLiteral("required AWG parameter object"));
    const QJsonObject awg = config.value(QStringLiteral("awg_params")).toObject();
    static const QSet<QString> allowedAwgParams = {
        QStringLiteral("Jc"), QStringLiteral("Jmin"), QStringLiteral("Jmax"),
        QStringLiteral("S1"), QStringLiteral("S2"), QStringLiteral("S3"),
        QStringLiteral("S4"), QStringLiteral("H1"), QStringLiteral("H2"),
        QStringLiteral("H3"), QStringLiteral("H4"), QStringLiteral("I1"),
        QStringLiteral("I2"), QStringLiteral("I3"), QStringLiteral("I4"),
        QStringLiteral("I5"), QStringLiteral("HeaderProtectionKey"),
        QStringLiteral("ContentPaddingAddition"), QStringLiteral("RekeyAfterTime"),
        QStringLiteral("RekeyTimeout"), QStringLiteral("RejectAfterTime"),
        QStringLiteral("KeepaliveTimeout"), QStringLiteral("MaxHandshakeAttempts"),
        QStringLiteral("RandomTrailers"), QStringLiteral("DisableCookies"),
    };
    if (!rejectUnknownKeys(awg, allowedAwgParams, path + QStringLiteral(".awg_params"), error))
        return false;

    auto requiredAwgInt = [&](const char *name, qint64 low, qint64 high, qint64 &target) {
        const QString key = QString::fromLatin1(name);
        if (!jsonIntegerInRange(awg.value(key), low, high, target))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".awg_params.") + key,
                        QStringLiteral("missing or out-of-range AWG integer"));
        return true;
    };
    qint64 jc = 0, jmin = 0, jmax = 0, s1 = 0, s2 = 0;
    qint64 h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    const qint64 maximumJunk = qMax<qint64>(1, mtu - 1);
    const qint64 maximumS1 = qMax<qint64>(1, mtu - 148);
    const qint64 maximumS2 = qMax<qint64>(1, mtu - 92);
    if (!requiredAwgInt("Jc", 1, 128, jc) || !requiredAwgInt("Jmin", 1, maximumJunk, jmin)
        || !requiredAwgInt("Jmax", 1, maximumJunk, jmax) || jmin >= jmax
        || !requiredAwgInt("S1", 1, maximumS1, s1) || !requiredAwgInt("S2", 1, maximumS2, s2)
        || s1 + 56 == s2
        || !requiredAwgInt("H1", 5, 2147483647, h1)
        || !requiredAwgInt("H2", 5, 2147483647, h2)
        || !requiredAwgInt("H3", 5, 2147483647, h3)
        || !requiredAwgInt("H4", 5, 2147483647, h4))
        return false;
    if (QSet<qint64>{h1, h2, h3, h4}.size() != 4)
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".awg_params"),
                    QStringLiteral("H1..H4 must be distinct scalar values"));

    QHash<QString, qint64> optionalSizes;
    for (const char *optionalSize : {"S3", "S4"}) {
        const QString key = QString::fromLatin1(optionalSize);
        if (!awg.contains(key) || awg.value(key).isNull())
            continue;
        qint64 parsedSize = 0;
        if (!jsonIntegerInRange(awg.value(key), 1, mtu - 1, parsedSize))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".awg_params.") + key,
                        QStringLiteral("invalid optional packet size"));
        optionalSizes.insert(key, parsedSize);
    }
    for (const char *packet : {"I1", "I2", "I3", "I4", "I5"}) {
        const QString key = QString::fromLatin1(packet);
        if (!awg.contains(key) || awg.value(key).isNull())
            continue;
        if (!awg.value(key).isString() || !validAwgIPacket(awg.value(key).toString(), int(mtu)))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".awg_params.") + key,
                        QStringLiteral("invalid or oversized AWG I-packet specification"));
    }
    if (awg.contains(QStringLiteral("HeaderProtectionKey"))
        && !awg.value(QStringLiteral("HeaderProtectionKey")).isNull()
        && (!awg.value(QStringLiteral("HeaderProtectionKey")).isString()
            || !canonicalBase64Key32(
                awg.value(QStringLiteral("HeaderProtectionKey")).toString())))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".awg_params.HeaderProtectionKey"),
                    QStringLiteral("HeaderProtectionKey must be canonical 32-byte base64"));

    for (const char *timing : {"ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                               "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"}) {
        const QString key = QString::fromLatin1(timing);
        if (!awg.contains(key) || awg.value(key).isNull())
            continue;
        quint32 low = 0, high = 0;
        const quint32 minimum = key == QLatin1String("ContentPaddingAddition") ? 0u : 1u;
        if (!parseUnsignedRange(awg.value(key), minimum, 65535, low, high)
            || (key == QLatin1String("ContentPaddingAddition") && high == 0))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".awg_params.") + key,
                        QStringLiteral("invalid or out-of-range AWG scalar/range string"));
    }
    if (awg.contains(QStringLiteral("HeaderProtectionKey"))
        && !awg.value(QStringLiteral("HeaderProtectionKey")).isNull()) {
        if (!optionalSizes.contains(QStringLiteral("S3"))
            || !optionalSizes.contains(QStringLiteral("S4")))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".awg_params"),
                        QStringLiteral("HeaderProtectionKey requires explicit S3 and S4"));
        for (qint64 size : {s1, s2, optionalSizes.value(QStringLiteral("S3")),
                            optionalSizes.value(QStringLiteral("S4"))})
            if (size < 12)
                return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                            path + QStringLiteral(".awg_params"),
                            QStringLiteral("HeaderProtectionKey requires all S values >= 12"));
    }

    if (!awg.value(QStringLiteral("RandomTrailers")).isBool()
        || !awg.value(QStringLiteral("RandomTrailers")).toBool()
        || !awg.value(QStringLiteral("DisableCookies")).isBool()
        || !awg.value(QStringLiteral("DisableCookies")).toBool())
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".awg_params"),
                    QStringLiteral("awg31 requires enabled RandomTrailers and DisableCookies"));
    if (!candidate.requiredCaps.contains(QStringLiteral("awg.random_trailers"))
        || !candidate.requiredCaps.contains(QStringLiteral("awg.disable_cookies")))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path, QStringLiteral("awg31 capability gates are missing"));
    return true;
}

bool validateXrayConfig(const QJsonObject &config, const QString &path, CatalogParseError &error)
{
    // This is a typed compiler input, never raw Xray-core JSON. A concrete registered adapter
    // must additionally build/sanitize the one-loopback-SOCKS + one-VLESS-Reality native config.
    static const QSet<QString> allowed = {
        QStringLiteral("endpoint_host"), QStringLiteral("endpoint_port"),
        QStringLiteral("uuid"), QStringLiteral("network"),
        QStringLiteral("security"), QStringLiteral("flow"),
        QStringLiteral("reality_public_key"), QStringLiteral("short_id"),
        QStringLiteral("server_name"), QStringLiteral("fingerprint"),
    };
    if (!rejectUnknownKeys(config, allowed, path, error))
        return false;

    QString endpointHost, uuid, network, security, flow, publicKey, shortId, serverName, fingerprint;
    if (!requiredString(config, QStringLiteral("endpoint_host"), path,
                        endpointHost, error, 253)
        || !requiredString(config, QStringLiteral("uuid"), path, uuid, error, 64)
        || !requiredString(config, QStringLiteral("network"), path, network, error, 32)
        || !requiredString(config, QStringLiteral("security"), path, security, error, 32)
        || !requiredString(config, QStringLiteral("flow"), path, flow, error, 64)
        || !requiredString(config, QStringLiteral("reality_public_key"), path, publicKey, error, 256)
        || !requiredString(config, QStringLiteral("short_id"), path, shortId, error, 64)
        || !requiredString(config, QStringLiteral("server_name"), path, serverName, error, 255)
        || !requiredString(config, QStringLiteral("fingerprint"), path, fingerprint, error, 64))
        return false;

    static const QRegularExpression uuidRe(
        // Canonical RFC 4122 text: lowercase hex, version 1..5, RFC variant 8/9/a/b.
        QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"));
    // Canonical lowercase hex; mixed-case aliases decode to the same bytes but would produce a
    // different signed/native dispatch identity across language runtimes.
    static const QRegularExpression shortIdRe(QStringLiteral("^(?:[0-9a-f]{2}){1,8}$"));
    static const QSet<QString> fingerprints = {
        QStringLiteral("chrome"), QStringLiteral("firefox"), QStringLiteral("safari"),
        QStringLiteral("ios"), QStringLiteral("android"), QStringLiteral("edge"),
        QStringLiteral("360"), QStringLiteral("qq"), QStringLiteral("random"),
        QStringLiteral("randomized"),
    };
    qint64 endpointPort = 0;
    if (!validEndpointHost(endpointHost)
        || !jsonIntegerInRange(config.value(QStringLiteral("endpoint_port")), 1, 65535,
                               endpointPort)
        || !uuidRe.match(uuid).hasMatch()
        || !shortIdRe.match(shortId).hasMatch() || network != QLatin1String("tcp")
        || security != QLatin1String("reality") || flow != QLatin1String("xtls-rprx-vision")
        || !canonicalBase64UrlKey32(publicKey)
        || serverName != serverName.toLower() || !validDnsName(serverName)
        || !fingerprints.contains(fingerprint)) {
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile, path,
                    QStringLiteral("unsupported or malformed Xray Reality/TCP profile"));
    }
    return true;
}

bool parseNativeProfile(const QJsonObject &object, const CatalogCandidate &candidate,
                        const QString &path, const QDateTime &catalogExpiresAt,
                        const QDateTime &entitlementExpiresAt,
                        NativeProfile &out, CatalogParseError &error)
{
    static const QSet<QString> allowed = {
        QStringLiteral("format"), QStringLiteral("container_config_format"),
        QStringLiteral("container_type"), QStringLiteral("profile_kind"),
        QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
        QStringLiteral("expires_at"), QStringLiteral("config"),
    };
    if (!rejectUnknownKeys(object, allowed, path, error))
        return false;
    if (!requiredString(object, QStringLiteral("format"), path, out.format, error, 64)
        || !requiredString(object, QStringLiteral("container_config_format"), path,
                           out.containerConfigFormat, error, 64)
        || !requiredString(object, QStringLiteral("container_type"), path,
                           out.containerType, error, 64)
        || !requiredString(object, QStringLiteral("profile_kind"), path,
                           out.profileKind, error, 128)
        || !requiredUInt(object, QStringLiteral("config_generation"), path,
                         out.configGeneration, error)
        || !requiredUInt(object, QStringLiteral("binding_generation"), path,
                         out.bindingGeneration, error)
        || !parseUtcDate(object, QStringLiteral("expires_at"), path, out.expiresAt, error))
        return false;

    if (out.profileKind != candidate.profileKind)
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".profile_kind"),
                    QStringLiteral("candidate/native profile kind mismatch"));
    if (out.format != QLatin1String("tribe_native_profile_v1")
        || out.containerConfigFormat != QLatin1String("amnezia_container_config_v1"))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile, path,
                    QStringLiteral("unsupported native profile/container config format"));
    const QString expectedContainer = candidate.transport == TransportKind::Awg
                                          ? QStringLiteral("amnezia-awg")
                                          : QStringLiteral("amnezia-xray");
    if (candidate.transport == TransportKind::Unknown || out.containerType != expectedContainer)
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".container_type"),
                    QStringLiteral("transport/native container mismatch"));
    if (out.expiresAt < catalogExpiresAt || out.expiresAt > entitlementExpiresAt)
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".expires_at"),
                    QStringLiteral("profile credential lifetime does not cover catalog lifetime"));
    if (!object.value(QStringLiteral("config")).isObject()
        || object.value(QStringLiteral("config")).toObject().isEmpty())
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".config"), QStringLiteral("required typed config object"));
    out.config = object.value(QStringLiteral("config")).toObject();

    if (candidate.transport == TransportKind::Awg) {
        if (candidate.profileKind != QLatin1String("awg31"))
            return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                        path + QStringLiteral(".profile_kind"),
                        QStringLiteral("unsupported AWG profile kind"));
        return validateAwgConfig(candidate, out.config, path + QStringLiteral(".config"), error);
    }
    if (candidate.profileKind != QLatin1String("xray_vless_reality_vision_tcp")
        || !candidate.requiredCaps.contains(QStringLiteral("xray.vless.reality.vision.tcp")))
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".profile_kind"),
                    QStringLiteral("unsupported or ungated Xray profile kind"));
    return validateXrayConfig(out.config, path + QStringLiteral(".config"), error);
}

bool parsePolicy(const QJsonObject &object, CatalogPolicy &out, CatalogParseError &error)
{
    const QString path = QStringLiteral("$.policy");
    static const QSet<QString> allowed = {
        QStringLiteral("mode_default"), QStringLiteral("max_attempts"),
        QStringLiteral("connect_timeout_ms"), QStringLiteral("verify_timeout_ms"),
        QStringLiteral("profile_cooldown_s"), QStringLiteral("minimum_dwell_s"),
        QStringLiteral("offline_grace_s"),
    };
    if (!rejectUnknownKeys(object, allowed, path, error, CatalogParseErrorCode::InvalidPolicy))
        return false;
    QString mode;
    if (!requiredString(object, QStringLiteral("mode_default"), path, mode, error, 32))
        return false;
    if (mode == QLatin1String("auto"))
        out.modeDefault = ConnectionMode::Auto;
    else
        return fail(error, CatalogParseErrorCode::InvalidPolicy,
                    path + QStringLiteral(".mode_default"), QStringLiteral("unknown connection mode"));

    auto boundedInt = [&](const char *name, int low, int high, int &target) {
        const QString key = QString::fromLatin1(name);
        const QJsonValue value = object.value(key);
        if (!value.isDouble() || std::floor(value.toDouble()) != value.toDouble()
            || value.toDouble() < low || value.toDouble() > high) {
            return fail(error, CatalogParseErrorCode::InvalidPolicy,
                        path + QLatin1Char('.') + key,
                        QStringLiteral("value outside local safety bounds"));
        }
        target = value.toInt();
        return true;
    };

    return boundedInt("max_attempts", 1, 5, out.maxAttempts)
           && boundedInt("connect_timeout_ms", 3000, 60000, out.connectTimeoutMs)
           && boundedInt("verify_timeout_ms", 2000, 30000, out.verifyTimeoutMs)
           && boundedInt("profile_cooldown_s", 10, 86400, out.profileCooldownS)
           && boundedInt("minimum_dwell_s", 0, 3600, out.minimumDwellS)
           && boundedInt("offline_grace_s", 0, 72 * 60 * 60, out.offlineGraceS);
}

bool parseCandidate(const QJsonObject &object, const QString &locationId, int index,
                    const QDateTime &catalogIssuedAt,
                    const QDateTime &catalogExpiresAt,
                    const QDateTime &entitlementExpiresAt, CatalogCandidate &out,
                    CatalogParseError &error)
{
    const QString path = QStringLiteral("$.locations[%1].candidates[%2]")
                             .arg(locationId).arg(index);
    static const QSet<QString> allowed = {
        QStringLiteral("profile_id"), QStringLiteral("transport"),
        QStringLiteral("profile_kind"), QStringLiteral("failure_domain"),
        QStringLiteral("server_health"), QStringLiteral("health_observed_at"),
        QStringLiteral("capacity_headroom"), QStringLiteral("required_caps"),
        QStringLiteral("verification"), QStringLiteral("native_profile"),
    };
    if (!rejectUnknownKeys(object, allowed, path, error,
                           CatalogParseErrorCode::InvalidCandidate))
        return false;
    QString transport;
    out.locationId = locationId;
    if (!requiredString(object, QStringLiteral("profile_id"), path, out.profileId, error, 96)
        || !requiredString(object, QStringLiteral("transport"), path, transport, error, 16)
        || !requiredString(object, QStringLiteral("profile_kind"), path, out.profileKind, error, 128)
        || !requiredString(object, QStringLiteral("failure_domain"), path,
                           out.failureDomain, error, 192))
        return false;
    static const QRegularExpression profileId(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$"));
    if (!profileId.match(out.profileId).hasMatch() || !safeIdentifier(out.profileKind)
        || !safeIdentifier(out.failureDomain, 192))
        return fail(error, CatalogParseErrorCode::InvalidCandidate, path,
                    QStringLiteral("unsafe profile identifier"));
    out.transport = transportKindFromName(transport);
    if (out.transport == TransportKind::Unknown)
        return fail(error, CatalogParseErrorCode::InvalidCandidate,
                    path + QStringLiteral(".transport"), QStringLiteral("unknown transport"));

    const QJsonValue health = object.value(QStringLiteral("server_health"));
    const QJsonValue capacity = object.value(QStringLiteral("capacity_headroom"));
    if (!health.isDouble() || !capacity.isDouble() || !std::isfinite(health.toDouble())
        || !std::isfinite(capacity.toDouble()) || health.toDouble() < 0.0
        || health.toDouble() > 1.0 || capacity.toDouble() < 0.0
        || capacity.toDouble() > 1.0) {
        return fail(error, CatalogParseErrorCode::InvalidCandidate, path,
                    QStringLiteral("health/capacity must be finite values in [0,1]"));
    }
    out.serverHealth = health.toDouble();
    out.capacityHeadroom = capacity.toDouble();
    if (!parseUtcDate(object, QStringLiteral("health_observed_at"), path,
                      out.healthObservedAt, error)
        || !parseUniqueStrings(object.value(QStringLiteral("required_caps")),
                               path + QStringLiteral(".required_caps"), out.requiredCaps,
                               error, false, 64))
        return false;
    if (out.healthObservedAt > catalogIssuedAt)
        return fail(error, CatalogParseErrorCode::InvalidCandidate,
                    path + QStringLiteral(".health_observed_at"),
                    QStringLiteral("health observation is newer than catalog issuance"));
    for (const QString &capability : out.requiredCaps)
        if (!validCapability(capability))
            return fail(error, CatalogParseErrorCode::InvalidCandidate,
                        path + QStringLiteral(".required_caps"),
                        QStringLiteral("invalid capability identifier"));

    const QJsonValue verification = object.value(QStringLiteral("verification"));
    if (!verification.isObject())
        return fail(error, CatalogParseErrorCode::InvalidCandidate,
                    path + QStringLiteral(".verification"),
                    QStringLiteral("required verification descriptor"));
    const QJsonObject verificationObject = verification.toObject();
    static const QSet<QString> verificationKeys = {
        QStringLiteral("expected_egress_ids"), QStringLiteral("context"),
    };
    if (!rejectUnknownKeys(verificationObject, verificationKeys,
                           path + QStringLiteral(".verification"), error,
                           CatalogParseErrorCode::InvalidCandidate))
        return false;
    if (!parseUniqueStrings(verificationObject.value(QStringLiteral("expected_egress_ids")),
                            path + QStringLiteral(".verification.expected_egress_ids"),
                            out.verification.expectedEgressIds, error, true, 16)
        || !requiredString(verificationObject, QStringLiteral("context"),
                           path + QStringLiteral(".verification"),
                           out.verification.context, error, 128))
        return false;
    if (!safeVerificationContext(out.verification.context))
        return fail(error, CatalogParseErrorCode::InvalidCandidate,
                    path + QStringLiteral(".verification.context"),
                    QStringLiteral("verification context is unsafe or outside 16..128 bytes"));
    for (const QString &egressId : out.verification.expectedEgressIds)
        if (!safeIdentifier(egressId, 96))
            return fail(error, CatalogParseErrorCode::InvalidCandidate,
                        path + QStringLiteral(".verification.expected_egress_ids"),
                        QStringLiteral("egress identifier is unsafe or too long"));

    const QJsonValue native = object.value(QStringLiteral("native_profile"));
    if (!native.isObject())
        return fail(error, CatalogParseErrorCode::InvalidNativeProfile,
                    path + QStringLiteral(".native_profile"),
                    QStringLiteral("required native profile envelope"));
    return parseNativeProfile(native.toObject(), out,
                              path + QStringLiteral(".native_profile"),
                              catalogExpiresAt, entitlementExpiresAt, out.nativeProfile, error);
}

} // namespace

QByteArray CatalogParser::signatureInput(const QString &kid,
                                         const QByteArray &payloadBase64UrlText)
{
    return QByteArrayLiteral("tribe-catalog-v2\n") + kid.toUtf8() + QByteArrayLiteral("\n")
           + payloadBase64UrlText;
}

bool CatalogParser::verifyAndParse(const QByteArray &envelopeBytes,
                                   const CatalogKeyring &keyring,
                                   Catalog &out,
                                   CatalogParseError &error,
                                   CatalogParserLimits limits)
{
    out = Catalog{};
    error = CatalogParseError{};
    if (envelopeBytes.isEmpty()
        || envelopeBytes.size() > qBound(1024, limits.maximumEnvelopeBytes, 2 * 1024 * 1024)) {
        return fail(error, CatalogParseErrorCode::EnvelopeTooLarge, QStringLiteral("$"),
                    QStringLiteral("catalog envelope size outside bounds"));
    }

    QJsonParseError jsonError;
    const QJsonDocument envelopeDoc = QJsonDocument::fromJson(envelopeBytes, &jsonError);
    if (jsonError.error != QJsonParseError::NoError || !envelopeDoc.isObject())
        return fail(error, CatalogParseErrorCode::InvalidEnvelopeJson, QStringLiteral("$"),
                    QStringLiteral("catalog envelope is not a JSON object"));
    if (!rejectDuplicateKeys(envelopeBytes, error, QStringLiteral("$")))
        return false;
    const QJsonObject envelope = envelopeDoc.object();
    static const QSet<QString> envelopeKeys = {
        QStringLiteral("alg"), QStringLiteral("kid"), QStringLiteral("payload"),
        QStringLiteral("signature"),
    };
    if (!rejectUnknownKeys(envelope, envelopeKeys, QStringLiteral("$"), error))
        return false;

    QString alg, kid, payloadText, signatureText;
    if (!requiredString(envelope, QStringLiteral("alg"), QStringLiteral("$"), alg, error, 32)
        || !requiredString(envelope, QStringLiteral("kid"), QStringLiteral("$"), kid, error, 64)
        || !requiredString(envelope, QStringLiteral("payload"), QStringLiteral("$"),
                           payloadText, error, limits.maximumEnvelopeBytes)
        || !requiredString(envelope, QStringLiteral("signature"), QStringLiteral("$"),
                           signatureText, error, 256))
        return false;
    if (alg != QLatin1String("Ed25519"))
        return fail(error, CatalogParseErrorCode::UnsupportedAlgorithm, QStringLiteral("$.alg"),
                    QStringLiteral("only Ed25519 is accepted"));
    if (!canonicalSigningKeyId(kid))
        return fail(error, CatalogParseErrorCode::MissingKeyId, QStringLiteral("$.kid"),
                    QStringLiteral("invalid key id"));
    const auto keyIt = keyring.publicKeysHex.constFind(kid);
    if (keyIt == keyring.publicKeysHex.constEnd())
        return fail(error, CatalogParseErrorCode::UnknownKeyId, QStringLiteral("$.kid"),
                    QStringLiteral("signing key id is not in the bundled keyring"));

    const QByteArray payloadEncoded = payloadText.toLatin1();
    const QByteArray signatureEncoded = signatureText.toLatin1();
    if (QString::fromLatin1(payloadEncoded) != payloadText
        || QString::fromLatin1(signatureEncoded) != signatureText
        || !isCanonicalBase64UrlText(payloadEncoded)
        || !isCanonicalBase64UrlText(signatureEncoded)) {
        return fail(error, CatalogParseErrorCode::InvalidBase64Url, QStringLiteral("$"),
                    QStringLiteral("payload/signature must use canonical unpadded base64url"));
    }

    QByteArray rawSignature;
    if (!decodeBase64Url(signatureEncoded, rawSignature) || rawSignature.size() != 64)
        return fail(error, CatalogParseErrorCode::InvalidBase64Url,
                    QStringLiteral("$.signature"), QStringLiteral("invalid Ed25519 signature"));

    // Convert only the already-canonical signature to the strict standard-base64 primitive.
    // The signed payload remains encoded text at this point: no payload decode/JSON parse occurs
    // before authentication.
    const QByteArray signingBytes = signatureInput(kid, payloadEncoded);
    if (!verifyDetached(*keyIt, signingBytes, rawSignature.toBase64()))
        return fail(error, CatalogParseErrorCode::InvalidSignature,
                    QStringLiteral("$.signature"), QStringLiteral("catalog signature mismatch"));

    QByteArray payload;
    if (!decodeBase64Url(payloadEncoded, payload))
        return fail(error, CatalogParseErrorCode::InvalidBase64Url,
                    QStringLiteral("$.payload"), QStringLiteral("invalid payload base64url"));
    if (payload.size() > qBound(1024, limits.maximumPayloadBytes, 1024 * 1024))
        return fail(error, CatalogParseErrorCode::PayloadTooLarge,
                    QStringLiteral("$.payload"), QStringLiteral("decoded catalog payload too large"));
    if (!parseVerifiedPayload(payload, kid, out, error, limits))
        return false;
    const auto epochIt = keyring.keyEpochs.constFind(kid);
    if (epochIt == keyring.keyEpochs.constEnd() || *epochIt == 0
        || out.keyEpoch != *epochIt) {
        out = Catalog{};
        return fail(error, CatalogParseErrorCode::SigningKeyEpochMismatch,
                    QStringLiteral("$.key_epoch"),
                    QStringLiteral("payload key epoch does not match bundled signing key"));
    }
    return true;
}

bool CatalogParser::parseVerifiedPayload(const QByteArray &exactPayload,
                                         const QString &signingKeyId,
                                         Catalog &out,
                                         CatalogParseError &error,
                                         CatalogParserLimits limits)
{
    out = Catalog{};
    error = CatalogParseError{};
    if (exactPayload.isEmpty()
        || exactPayload.size() > qBound(1024, limits.maximumPayloadBytes, 1024 * 1024))
        return fail(error, CatalogParseErrorCode::PayloadTooLarge, QStringLiteral("$"),
                    QStringLiteral("catalog payload size outside bounds"));

    QStringDecoder decoder(QStringDecoder::Utf8);
    const QString decodedPayload = decoder(exactPayload);
    Q_UNUSED(decodedPayload)
    if (decoder.hasError())
        return fail(error, CatalogParseErrorCode::InvalidUtf8, QStringLiteral("$"),
                    QStringLiteral("catalog payload is not strict UTF-8"));

    QJsonParseError jsonError;
    const QJsonDocument document = QJsonDocument::fromJson(exactPayload, &jsonError);
    if (jsonError.error != QJsonParseError::NoError || !document.isObject())
        return fail(error, CatalogParseErrorCode::InvalidPayloadJson, QStringLiteral("$"),
                    QStringLiteral("catalog payload is not a JSON object"));
    if (!rejectDuplicateKeys(exactPayload, error, QStringLiteral("$")))
        return false;

    int nodes = 0;
    QString limitsDetail;
    if (!withinJsonLimits(document.object(), 0, nodes, limits, limitsDetail))
        return fail(error, CatalogParseErrorCode::JsonLimitsExceeded, QStringLiteral("$"),
                    limitsDetail);

    const QJsonObject root = document.object();
    static const QSet<QString> rootKeys = {
        QStringLiteral("schema_version"), QStringLiteral("catalog_revision"),
        QStringLiteral("device_audience"), QStringLiteral("request_nonce"),
        QStringLiteral("key_epoch"), QStringLiteral("device_revocation_epoch"),
        QStringLiteral("entitlement_expires_at"), QStringLiteral("issued_at"),
        QStringLiteral("expires_at"), QStringLiteral("refresh_after"),
        QStringLiteral("policy_revision"), QStringLiteral("policy"),
        QStringLiteral("locations"), QStringLiteral("extensions"),
    };
    if (!rejectUnknownKeys(root, rootKeys, QStringLiteral("$"), error,
                           CatalogParseErrorCode::InvalidField))
        return false;
    quint64 schema = 0;
    if (!requiredUInt(root, QStringLiteral("schema_version"), QStringLiteral("$"),
                      schema, error))
        return false;
    if (schema != 2)
        return fail(error, CatalogParseErrorCode::UnsupportedSchema,
                    QStringLiteral("$.schema_version"),
                    QStringLiteral("only catalog schema v2 is supported"));
    out.schemaVersion = 2;
    if (!requiredString(root, QStringLiteral("device_audience"), QStringLiteral("$"),
                        out.deviceAudience, error, 43)
        || !requiredString(root, QStringLiteral("request_nonce"), QStringLiteral("$"),
                           out.requestNonce, error, 43))
        return false;
    if (!canonicalBase64UrlKey32(out.deviceAudience)
        || !canonicalBase64UrlKey32(out.requestNonce)) {
        return fail(error, CatalogParseErrorCode::InvalidField, QStringLiteral("$"),
                    QStringLiteral("audience/nonce must be canonical 32-byte base64url"));
    }
    if (!requiredUInt(root, QStringLiteral("catalog_revision"), QStringLiteral("$"),
                      out.catalogRevision, error)
        || !requiredUInt(root, QStringLiteral("key_epoch"), QStringLiteral("$"),
                         out.keyEpoch, error)
        || !requiredUInt(root, QStringLiteral("device_revocation_epoch"), QStringLiteral("$"),
                         out.deviceRevocationEpoch, error, true)
        || !requiredUInt(root, QStringLiteral("policy_revision"), QStringLiteral("$"),
                         out.policyRevision, error)
        || !parseUtcDate(root, QStringLiteral("entitlement_expires_at"), QStringLiteral("$"),
                         out.entitlementExpiresAt, error)
        || !parseUtcDate(root, QStringLiteral("issued_at"), QStringLiteral("$"),
                         out.issuedAt, error)
        || !parseUtcDate(root, QStringLiteral("expires_at"), QStringLiteral("$"),
                         out.expiresAt, error)
        || !parseUtcDate(root, QStringLiteral("refresh_after"), QStringLiteral("$"),
                         out.refreshAfter, error))
        return false;
    if (out.issuedAt > out.expiresAt || out.refreshAfter < out.issuedAt
        || out.refreshAfter > out.expiresAt || out.expiresAt > out.entitlementExpiresAt) {
        return fail(error, CatalogParseErrorCode::InvalidField, QStringLiteral("$"),
                    QStringLiteral("invalid catalog timestamp ordering"));
    }

    if (!parseCatalogExtensions(root.value(QStringLiteral("extensions")), out, error))
        return false;

    if (!root.value(QStringLiteral("policy")).isObject()
        || !parsePolicy(root.value(QStringLiteral("policy")).toObject(), out.policy, error))
        return error.code == CatalogParseErrorCode::None
                   ? fail(error, CatalogParseErrorCode::InvalidPolicy,
                          QStringLiteral("$.policy"), QStringLiteral("required policy object"))
                   : false;

    const QJsonValue locationsValue = root.value(QStringLiteral("locations"));
    if (!locationsValue.isArray() || locationsValue.toArray().isEmpty()
        || locationsValue.toArray().size() > qBound(1, limits.maximumLocations, 1024)) {
        return fail(error, CatalogParseErrorCode::InvalidLocation,
                    QStringLiteral("$.locations"), QStringLiteral("invalid locations array"));
    }
    QSet<QString> locationIds;
    QSet<QString> profileIds;
    const QJsonArray locations = locationsValue.toArray();
    for (int locationIndex = 0; locationIndex < locations.size(); ++locationIndex) {
        if (!locations.at(locationIndex).isObject())
            return fail(error, CatalogParseErrorCode::InvalidLocation,
                        QStringLiteral("$.locations[%1]").arg(locationIndex),
                        QStringLiteral("location must be an object"));
        const QJsonObject object = locations.at(locationIndex).toObject();
        const QString path = QStringLiteral("$.locations[%1]").arg(locationIndex);
        static const QSet<QString> locationKeys = {
            QStringLiteral("id"), QStringLiteral("country"), QStringLiteral("city"),
            QStringLiteral("display_key"), QStringLiteral("candidates"),
        };
        if (!rejectUnknownKeys(object, locationKeys, path, error,
                               CatalogParseErrorCode::InvalidLocation))
            return false;
        CatalogLocation location;
        if (!requiredString(object, QStringLiteral("id"), path, location.id, error, 64)
            || !requiredString(object, QStringLiteral("country"), path,
                               location.country, error, 8)
            || !requiredString(object, QStringLiteral("display_key"), path,
                               location.displayKey, error, 128))
            return false;
        const QJsonValue cityValue = object.value(QStringLiteral("city"));
        if (!cityValue.isUndefined() && !cityValue.isNull() && !cityValue.isString())
            return fail(error, CatalogParseErrorCode::InvalidLocation,
                        path + QStringLiteral(".city"),
                        QStringLiteral("city must be a string or null"));
        if (cityValue.isString()) {
            if ((!cityValue.toString().isEmpty() && !safeIdentifier(cityValue.toString(), 16))
                || cityValue.toString().size() > 16)
                return fail(error, CatalogParseErrorCode::InvalidLocation,
                            path + QStringLiteral(".city"),
                            QStringLiteral("city code is too long"));
            location.city = object.value(QStringLiteral("city")).toString();
        }
        static const QRegularExpression locationId(
            QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"));
        static const QRegularExpression country(QStringLiteral("^[A-Z]{2}$"));
        if (!locationId.match(location.id).hasMatch()
            || !country.match(location.country).hasMatch()
            || !safeIdentifier(location.displayKey, 128)
            || locationIds.contains(location.id)) {
            return fail(error, CatalogParseErrorCode::InvalidLocation, path,
                        QStringLiteral("invalid or duplicate location id/country"));
        }
        locationIds.insert(location.id);

        const QJsonValue candidatesValue = object.value(QStringLiteral("candidates"));
        if (!candidatesValue.isArray() || candidatesValue.toArray().isEmpty()
            || candidatesValue.toArray().size()
                   > qBound(1, limits.maximumCandidatesPerLocation, 256)) {
            return fail(error, CatalogParseErrorCode::InvalidCandidate,
                        path + QStringLiteral(".candidates"),
                        QStringLiteral("invalid candidates array"));
        }
        const QJsonArray candidates = candidatesValue.toArray();
        for (int candidateIndex = 0; candidateIndex < candidates.size(); ++candidateIndex) {
            if (!candidates.at(candidateIndex).isObject())
                return fail(error, CatalogParseErrorCode::InvalidCandidate,
                            path + QStringLiteral(".candidates"),
                            QStringLiteral("candidate must be an object"));
            CatalogCandidate candidate;
            if (!parseCandidate(candidates.at(candidateIndex).toObject(), location.id,
                                candidateIndex, out.issuedAt, out.expiresAt,
                                out.entitlementExpiresAt,
                                candidate, error))
                return false;
            if (profileIds.contains(candidate.profileId))
                return fail(error, CatalogParseErrorCode::InvalidCandidate,
                            path + QStringLiteral(".candidates"),
                            QStringLiteral("duplicate profile_id in catalog"));
            profileIds.insert(candidate.profileId);
            location.candidates.append(candidate);
        }
        out.locations.append(location);
    }

    if (out.locationDirectory.has_value()) {
        for (const CatalogLocation &credentialLocation : out.locations) {
            const auto directoryLocation = std::find_if(
                out.locationDirectory->locations.cbegin(),
                out.locationDirectory->locations.cend(),
                [&credentialLocation](const CatalogDirectoryLocation &location) {
                    return location.id == credentialLocation.id;
                });
            if (directoryLocation == out.locationDirectory->locations.cend()
                || directoryLocation->country != credentialLocation.country
                || directoryLocation->city != credentialLocation.city
                || directoryLocation->displayKey != credentialLocation.displayKey) {
                return fail(error, CatalogParseErrorCode::InvalidLocation,
                            QStringLiteral("$.extensions[catalog.location_directory_v1]"),
                            QStringLiteral("credential location differs from public directory"));
            }
            for (const CatalogCandidate &candidate : credentialLocation.candidates) {
                const bool selectable = std::any_of(
                    directoryLocation->transports.cbegin(),
                    directoryLocation->transports.cend(),
                    [&candidate](const CatalogDirectoryTransport &summary) {
                        return summary.transport == candidate.transport
                            && summary.availability
                                   == CatalogDirectoryAvailability::Selectable;
                    });
                if (!selectable) {
                    return fail(error, CatalogParseErrorCode::InvalidCandidate,
                                QStringLiteral("$.extensions[catalog.location_directory_v1]"),
                                QStringLiteral("credential candidate is not directory-selectable"));
                }
            }
        }
    }

    out.exactPayload = exactPayload;
    out.payloadSha256 = QCryptographicHash::hash(exactPayload, QCryptographicHash::Sha256);
    out.signingKeyId = signingKeyId;
    return true;
}

bool CatalogParser::validateTypedNativeProfile(const CatalogCandidate &candidate,
                                               CatalogParseError &error)
{
    error = CatalogParseError{};
    const NativeProfile &profile = candidate.nativeProfile;
    const QString expectedContainer = candidate.transport == TransportKind::Awg
                                          ? QStringLiteral("amnezia-awg")
                                          : candidate.transport == TransportKind::Xray
                                                ? QStringLiteral("amnezia-xray") : QString();
    if (expectedContainer.isEmpty() || profile.profileKind != candidate.profileKind
        || profile.format != QLatin1String("tribe_native_profile_v1")
        || profile.containerConfigFormat != QLatin1String("amnezia_container_config_v1")
        || profile.containerType != expectedContainer || profile.configGeneration == 0
        || profile.bindingGeneration == 0 || profile.config.isEmpty()) {
        error.code = CatalogParseErrorCode::InvalidNativeProfile;
        error.path = QStringLiteral("$.native_profile");
        error.detail = QStringLiteral("inconsistent typed native profile envelope");
        return false;
    }
    if (candidate.transport == TransportKind::Awg) {
        if (candidate.profileKind != QLatin1String("awg31")) {
            error.code = CatalogParseErrorCode::InvalidNativeProfile;
            error.path = QStringLiteral("$.native_profile.profile_kind");
            error.detail = QStringLiteral("unsupported AWG profile kind");
            return false;
        }
        return validateAwgConfig(candidate, profile.config,
                                 QStringLiteral("$.native_profile.config"), error);
    }
    if (candidate.profileKind != QLatin1String("xray_vless_reality_vision_tcp")
        || !candidate.requiredCaps.contains(
            QStringLiteral("xray.vless.reality.vision.tcp"))) {
        error.code = CatalogParseErrorCode::InvalidNativeProfile;
        error.path = QStringLiteral("$.native_profile.profile_kind");
        error.detail = QStringLiteral("unsupported or ungated Xray profile kind");
        return false;
    }
    return validateXrayConfig(profile.config, QStringLiteral("$.native_profile.config"), error);
}

} // namespace avpn

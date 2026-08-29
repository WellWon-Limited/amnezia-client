#include "AndroidCatalogSecureStorage.h"

#if defined(Q_OS_ANDROID)

#include <QCoreApplication>
#include <QJniEnvironment>
#include <QJniObject>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QSet>
#include <QStringList>

#include <limits>

namespace avpn {
namespace {

constexpr auto kVaultClass = "org/amnezia/vpn/CatalogSecureMetadataVault";
constexpr quint64 kMaxSafeJsonInteger = 9007199254740991ULL;

QString b64url(const QByteArray &value)
{
    return QString::fromLatin1(
        value.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

bool decodeB64(const QJsonValue &value, int expectedBytes, bool emptyAllowed,
               QByteArray &decoded)
{
    decoded.clear();
    if (!value.isString()) return false;
    const QString text = value.toString();
    if (emptyAllowed && text.isEmpty()) return true;
    if (text.contains(QLatin1Char('=')) || QString::fromLatin1(text.toLatin1()) != text)
        return false;
    const auto result = QByteArray::fromBase64Encoding(
        text.toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (result.decodingStatus != QByteArray::Base64DecodingStatus::Ok
        || result.decoded.size() != expectedBytes || b64url(result.decoded) != text)
        return false;
    decoded = result.decoded;
    return true;
}

bool canonicalRevision(const QJsonValue &value, quint64 &revision)
{
    revision = 0;
    if (!value.isString()) return false;
    const QString text = value.toString();
    if (text.isEmpty() || text.size() > 16
        || (text.size() > 1 && text.startsWith(QLatin1Char('0')))) return false;
    bool ok = false;
    revision = text.toULongLong(&ok, 10);
    return ok && revision <= kMaxSafeJsonInteger && QString::number(revision) == text;
}

bool validMetadata(const CatalogSecureMetadata &metadata)
{
    if (metadata.key32.size() != 32 || metadata.storageRevision > kMaxSafeJsonInteger
        || metadata.pendingRevision > kMaxSafeJsonInteger) return false;
    if (metadata.storageRevision == 0) {
        if (!metadata.authenticatedRecordSha256.isEmpty() || !metadata.cleared) return false;
    } else if (metadata.authenticatedRecordSha256.size() != 32) return false;
    if ((metadata.pendingRevision == 0) != metadata.pendingRecordSha256.isEmpty()) return false;
    return metadata.pendingRevision == 0
           || (metadata.pendingRevision == metadata.storageRevision + 1
               && metadata.pendingRecordSha256.size() == 32);
}

QJsonObject encode(const CatalogSecureMetadata &metadata)
{
    return {
        {QStringLiteral("key_b64"), b64url(metadata.key32)},
        {QStringLiteral("storage_revision"), QString::number(metadata.storageRevision)},
        {QStringLiteral("record_sha256_b64"), b64url(metadata.authenticatedRecordSha256)},
        {QStringLiteral("cleared"), metadata.cleared},
        {QStringLiteral("pending_revision"), QString::number(metadata.pendingRevision)},
        {QStringLiteral("pending_sha256_b64"), b64url(metadata.pendingRecordSha256)},
    };
}

bool decode(const QJsonValue &value, CatalogSecureMetadata &metadata)
{
    metadata = {};
    if (!value.isObject()) return false;
    const QJsonObject object = value.toObject();
    static const QSet<QString> keys = {
        QStringLiteral("key_b64"), QStringLiteral("storage_revision"),
        QStringLiteral("record_sha256_b64"), QStringLiteral("cleared"),
        QStringLiteral("pending_revision"), QStringLiteral("pending_sha256_b64"),
    };
    const QStringList objectKeys = object.keys();
    if (QSet<QString>(objectKeys.cbegin(), objectKeys.cend()) != keys
        || !object.value(QStringLiteral("cleared")).isBool()
        || !decodeB64(object.value(QStringLiteral("key_b64")), 32, false, metadata.key32)
        || !decodeB64(object.value(QStringLiteral("record_sha256_b64")), 32, true,
                      metadata.authenticatedRecordSha256)
        || !decodeB64(object.value(QStringLiteral("pending_sha256_b64")), 32, true,
                      metadata.pendingRecordSha256)
        || !canonicalRevision(object.value(QStringLiteral("storage_revision")),
                              metadata.storageRevision)
        || !canonicalRevision(object.value(QStringLiteral("pending_revision")),
                              metadata.pendingRevision)) return false;
    metadata.cleared = object.value(QStringLiteral("cleared")).toBool();
    return validMetadata(metadata);
}

QJsonObject callLoad(bool create)
{
    QJniEnvironment environment;
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid()) return {};
    const QJniObject result = QJniObject::callStaticObjectMethod(
        kVaultClass, "load", "(Landroid/content/Context;Z)Ljava/lang/String;",
        context.object(), jboolean(create));
    if (environment.checkAndClearExceptions() || !result.isValid()) return {};
    const QJsonDocument document = QJsonDocument::fromJson(result.toString().toUtf8());
    return document.isObject() ? document.object() : QJsonObject{};
}

QJsonObject callReplace(const CatalogSecureMetadata &expected,
                        const CatalogSecureMetadata &replacement)
{
    QJniEnvironment environment;
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid()) return {};
    const QString expectedText = QString::fromUtf8(
        QJsonDocument(encode(expected)).toJson(QJsonDocument::Compact));
    const QString replacementText = QString::fromUtf8(
        QJsonDocument(encode(replacement)).toJson(QJsonDocument::Compact));
    const QJniObject result = QJniObject::callStaticObjectMethod(
        kVaultClass, "replace",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        context.object(), QJniObject::fromString(expectedText).object<jstring>(),
        QJniObject::fromString(replacementText).object<jstring>());
    if (environment.checkAndClearExceptions() || !result.isValid()) return {};
    const QJsonDocument document = QJsonDocument::fromJson(result.toString().toUtf8());
    return document.isObject() ? document.object() : QJsonObject{};
}

CatalogSecureKeyStatus parseResult(const QJsonObject &result,
                                   CatalogSecureMetadata &metadata,
                                   QString &error)
{
    metadata = {};
    error.clear();
    const QString status = result.value(QStringLiteral("status")).toString();
    const bool hasMetadata = result.contains(QStringLiteral("metadata"));
    const QSet<QString> expectedKeys = hasMetadata
        ? QSet<QString>{QStringLiteral("type"), QStringLiteral("schema"),
                        QStringLiteral("status"), QStringLiteral("reason"),
                        QStringLiteral("metadata")}
        : QSet<QString>{QStringLiteral("type"), QStringLiteral("schema"),
                        QStringLiteral("status"), QStringLiteral("reason")};
    const QStringList resultKeys = result.keys();
    if (QSet<QString>(resultKeys.cbegin(), resultKeys.cend()) != expectedKeys
        || result.value(QStringLiteral("type"))
               != QLatin1String("catalog_secure_metadata_result_v1")
        || !result.value(QStringLiteral("schema")).isDouble()
        || result.value(QStringLiteral("schema")).toDouble() != 1.0
        || !result.value(QStringLiteral("reason")).isString()) {
        error = QStringLiteral("Android catalog secure metadata response rejected");
        return CatalogSecureKeyStatus::Error;
    }
    if (status == QLatin1String("available")) {
        if (!hasMetadata || !decode(result.value(QStringLiteral("metadata")), metadata)) {
            error = QStringLiteral("Android catalog secure metadata shape rejected");
            return CatalogSecureKeyStatus::Error;
        }
        return CatalogSecureKeyStatus::Available;
    }
    if (hasMetadata) {
        error = QStringLiteral("Android catalog secure metadata status contradiction");
        return CatalogSecureKeyStatus::Error;
    }
    if (status == QLatin1String("missing")) return CatalogSecureKeyStatus::Missing;
    if (status == QLatin1String("unavailable")) {
        error = QStringLiteral("Android Keystore metadata unavailable");
        return CatalogSecureKeyStatus::Unavailable;
    }
    error = QStringLiteral("Android catalog secure metadata operation failed");
    return CatalogSecureKeyStatus::Error;
}

} // namespace

CatalogSecureKeyStatus AndroidCatalogSecureKeyProvider::loadMetadata(
    CatalogSecureMetadata &metadata, QString &error)
{
    QMutexLocker lock(&m_mutex);
    return load(false, metadata, error);
}

CatalogSecureKeyStatus AndroidCatalogSecureKeyProvider::loadOrCreateMetadata(
    CatalogSecureMetadata &metadata, QString &error)
{
    QMutexLocker lock(&m_mutex);
    return load(true, metadata, error);
}

CatalogSecureKeyStatus AndroidCatalogSecureKeyProvider::load(
    bool create, CatalogSecureMetadata &metadata, QString &error)
{
    return parseResult(callLoad(create), metadata, error);
}

bool AndroidCatalogSecureKeyProvider::replaceMetadataWhileLocked(
    const CatalogSecureMetadata &expected, const CatalogSecureMetadata &replacement,
    QString &error)
{
    QMutexLocker lock(&m_mutex);
    if (!validMetadata(expected) || !validMetadata(replacement)) {
        error = QStringLiteral("Android catalog secure metadata replacement rejected");
        return false;
    }
    CatalogSecureMetadata returned;
    const CatalogSecureKeyStatus status = parseResult(
        callReplace(expected, replacement), returned, error);
    if (status != CatalogSecureKeyStatus::Available || !(returned == replacement)) {
        if (error.isEmpty())
            error = QStringLiteral("Android catalog secure metadata receipt mismatch");
        return false;
    }
    return true;
}

} // namespace avpn

#endif // Q_OS_ANDROID

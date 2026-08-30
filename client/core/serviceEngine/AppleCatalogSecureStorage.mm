#include "AppleCatalogSecureStorage.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <TargetConditionals.h>

#include <QMutexLocker>

#include <utility>

namespace avpn {
namespace {

constexpr auto kMetadataAccount = "catalog-secure-metadata-v2";
constexpr int kMetadataBytes = 4 + 1 + 8 + 8 + 32 + 32 + 32;

NSData *data(const QByteArray &bytes)
{
    return [NSData dataWithBytes:bytes.constData() length:NSUInteger(bytes.size())];
}

NSString *string(const QString &value)
{
    return [NSString stringWithUTF8String:value.toUtf8().constData()];
}

NSMutableDictionary *baseQuery(const QString &service)
{
    // Intentionally app-only: no kSecAttrAccessGroup. The Network Extension never reads catalog
    // credentials/LKG; it receives only the already-sanitized active native profile.
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: string(service),
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:kMetadataAccount],
    } mutableCopy];
}

void appendUInt64(QByteArray &bytes, quint64 value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
        bytes.append(char((value >> quint64(shift)) & 0xffU));
}

bool takeUInt64(const QByteArray &bytes, int &offset, quint64 &value)
{
    if (offset + 8 > bytes.size()) return false;
    value = 0;
    for (int index = 0; index < 8; ++index)
        value = (value << 8U) | quint64(quint8(bytes.at(offset++)));
    return true;
}

QByteArray encodeMetadata(const CatalogSecureMetadata &metadata)
{
    QByteArray bytes = QByteArrayLiteral("TCM2");
    bytes.append(metadata.cleared ? char(1) : char(0));
    appendUInt64(bytes, metadata.storageRevision);
    appendUInt64(bytes, metadata.pendingRevision);
    bytes.append(metadata.key32);
    bytes.append(metadata.authenticatedRecordSha256.isEmpty()
                     ? QByteArray(32, '\0') : metadata.authenticatedRecordSha256);
    bytes.append(metadata.pendingRecordSha256.isEmpty()
                     ? QByteArray(32, '\0') : metadata.pendingRecordSha256);
    return bytes;
}

bool decodeMetadata(const QByteArray &bytes, CatalogSecureMetadata &metadata)
{
    metadata = {};
    if (bytes.size() != kMetadataBytes || bytes.left(4) != QByteArrayLiteral("TCM2")
        || (quint8(bytes.at(4)) & ~quint8(1)) != 0) return false;
    int offset = 5;
    metadata.cleared = bytes.at(4) != 0;
    if (!takeUInt64(bytes, offset, metadata.storageRevision)
        || !takeUInt64(bytes, offset, metadata.pendingRevision)) return false;
    metadata.key32 = bytes.mid(offset, 32); offset += 32;
    metadata.authenticatedRecordSha256 = bytes.mid(offset, 32); offset += 32;
    metadata.pendingRecordSha256 = bytes.mid(offset, 32);
    if (metadata.storageRevision == 0
        && metadata.authenticatedRecordSha256 == QByteArray(32, '\0'))
        metadata.authenticatedRecordSha256.clear();
    if (metadata.pendingRevision == 0
        && metadata.pendingRecordSha256 == QByteArray(32, '\0'))
        metadata.pendingRecordSha256.clear();
    return true;
}

CatalogSecureKeyStatus readItem(const QString &service, QByteArray &value, QString &error)
{
    value.clear();
    NSMutableDictionary *query = baseQuery(service);
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = nullptr;
    const OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) return CatalogSecureKeyStatus::Missing;
    if (status == errSecInteractionNotAllowed) {
        error = QStringLiteral("Apple Keychain is locked");
        return CatalogSecureKeyStatus::Unavailable;
    }
    if (status != errSecSuccess || !result || CFGetTypeID(result) != CFDataGetTypeID()) {
        if (result) CFRelease(result);
        error = QStringLiteral("Apple secure metadata read failed (%1)").arg(status);
        return CatalogSecureKeyStatus::Error;
    }
    NSData *item = (__bridge NSData *)result;
    value = QByteArray(static_cast<const char *>(item.bytes), qsizetype(item.length));
    CFRelease(result);
    return CatalogSecureKeyStatus::Available;
}

bool createItem(const QString &service, const QByteArray &value, QString &error)
{
    NSMutableDictionary *query = baseQuery(service);
    query[(__bridge id)kSecValueData] = data(value);
    query[(__bridge id)kSecAttrAccessible] =
        (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    const OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nullptr);
    if (status == errSecSuccess) return true;
    error = QStringLiteral("Apple secure metadata create failed (%1)").arg(status);
    return false;
}

bool updateItem(const QString &service, const QByteArray &value, QString &error)
{
    NSMutableDictionary *query = baseQuery(service);
    NSDictionary *attributes = @{(__bridge id)kSecValueData: data(value)};
    const OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                          (__bridge CFDictionaryRef)attributes);
    if (status == errSecSuccess) return true;
    error = QStringLiteral("Apple secure metadata update failed (%1)").arg(status);
    return false;
}

bool randomKey(QByteArray &key)
{
    key.resize(32);
    if (SecRandomCopyBytes(kSecRandomDefault, size_t(key.size()),
                           reinterpret_cast<uint8_t *>(key.data())) == errSecSuccess)
        return true;
    key.clear();
    return false;
}

} // namespace

AppleCatalogSecureKeyProvider::AppleCatalogSecureKeyProvider(QString serviceName)
    : m_serviceName(std::move(serviceName))
{}

CatalogSecureKeyStatus AppleCatalogSecureKeyProvider::loadMetadata(
    CatalogSecureMetadata &metadata, QString &error)
{
    QMutexLocker locker(&m_mutex);
    metadata = {};
    error.clear();
    QByteArray bytes;
    const CatalogSecureKeyStatus status = readItem(m_serviceName, bytes, error);
    if (status != CatalogSecureKeyStatus::Available) return status;
    if (!decodeMetadata(bytes, metadata)) {
        error = QStringLiteral("Apple catalog secure metadata corrupt");
        return CatalogSecureKeyStatus::Error;
    }
    return CatalogSecureKeyStatus::Available;
}

CatalogSecureKeyStatus AppleCatalogSecureKeyProvider::loadOrCreateMetadata(
    CatalogSecureMetadata &metadata, QString &error)
{
    QMutexLocker locker(&m_mutex);
    metadata = {};
    error.clear();
    QByteArray bytes;
    CatalogSecureKeyStatus status = readItem(m_serviceName, bytes, error);
    if (status == CatalogSecureKeyStatus::Available) {
        if (!decodeMetadata(bytes, metadata)) {
            error = QStringLiteral("Apple catalog secure metadata corrupt");
            return CatalogSecureKeyStatus::Error;
        }
        return CatalogSecureKeyStatus::Available;
    }
    if (status != CatalogSecureKeyStatus::Missing) return status;
    metadata.cleared = true;
    if (!randomKey(metadata.key32)) {
        error = QStringLiteral("Apple secure random unavailable");
        return CatalogSecureKeyStatus::Error;
    }
    if (createItem(m_serviceName, encodeMetadata(metadata), error))
        return CatalogSecureKeyStatus::Available;
    // The file lock serializes cooperating app instances, but tolerate a create race safely.
    error.clear(); bytes.clear();
    status = readItem(m_serviceName, bytes, error);
    if (status == CatalogSecureKeyStatus::Available && decodeMetadata(bytes, metadata))
        return CatalogSecureKeyStatus::Available;
    metadata = {};
    return CatalogSecureKeyStatus::Error;
}

bool AppleCatalogSecureKeyProvider::replaceMetadataWhileLocked(
    const CatalogSecureMetadata &expected, const CatalogSecureMetadata &replacement,
    QString &error)
{
    QMutexLocker locker(&m_mutex);
    error.clear();
    QByteArray bytes;
    CatalogSecureMetadata current;
    if (readItem(m_serviceName, bytes, error) != CatalogSecureKeyStatus::Available
        || !decodeMetadata(bytes, current) || !(current == expected)) {
        if (error.isEmpty()) error = QStringLiteral("Apple catalog metadata CAS mismatch");
        return false;
    }
    return updateItem(m_serviceName, encodeMetadata(replacement), error);
}

bool AppleCatalogFileProtection::protect(const QString &path, QString &error)
{
    error.clear();
    NSURL *url = [NSURL fileURLWithPath:string(path)];
    NSError *nsError = nil;
    if (![url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:&nsError]) {
        error = QStringLiteral("Apple no-backup policy failed");
        return false;
    }
#if TARGET_OS_IPHONE
    if (![[NSFileManager defaultManager] setAttributes:@{
            NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication
        } ofItemAtPath:string(path) error:&nsError]) {
        error = QStringLiteral("Apple file protection policy failed");
        return false;
    }
#endif
    return true;
}

} // namespace avpn

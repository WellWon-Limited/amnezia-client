#include "CatalogSecureStore.h"

#include "CatalogKeyset.h"
#include "CatalogRuntimeState.h"
#include "SignedEnvelope.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSaveFile>

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <utility>

#if defined(Q_OS_UNIX)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace avpn {
namespace {

constexpr quint64 kMaxSafeJsonInteger = 9007199254740991ULL;

QByteArray b64url(const QByteArray &value)
{
    return value.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

bool decodeB64url(const QJsonValue &value, int minimum, int maximum, QByteArray &out)
{
    if (!value.isString() || value.toString().contains(QLatin1Char('=')))
        return false;
    const QByteArray encoded = value.toString().toLatin1();
    if (QString::fromLatin1(encoded) != value.toString())
        return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok
        || decoded.decoded.size() < minimum || decoded.decoded.size() > maximum
        || b64url(decoded.decoded) != encoded)
        return false;
    out = decoded.decoded;
    return true;
}

bool jsonUInt(const QJsonObject &object, const QString &key, quint64 &out, bool zero = true)
{
    const QJsonValue value = object.value(key);
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 0 || number > double(kMaxSafeJsonInteger)
        || std::floor(number) != number || (!zero && number == 0))
        return false;
    out = quint64(number);
    return true;
}

bool exactSchema(const QJsonValue &value, int minimum, int maximum, int &out)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < minimum || number > maximum
        || std::floor(number) != number) return false;
    out = int(number);
    return true;
}

QJsonObject generationMap(const QHash<QString, quint64> &values)
{
    QJsonObject object;
    QStringList keys = values.keys();
    std::sort(keys.begin(), keys.end());
    for (const QString &key : keys)
        object.insert(key, double(values.value(key)));
    return object;
}

bool parseGenerationMap(const QJsonValue &value, QHash<QString, quint64> &out, int maximum)
{
    if (!value.isObject() || value.toObject().size() > maximum)
        return false;
    static const QRegularExpression id(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"));
    const QJsonObject object = value.toObject();
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        quint64 generation = 0;
        const QJsonObject one{{QStringLiteral("v"), it.value()}};
        if (!id.match(it.key()).hasMatch() || !jsonUInt(one, QStringLiteral("v"), generation, false))
            return false;
        out.insert(it.key(), generation);
    }
    return true;
}

QByteArray aadForRevision(quint64 revision)
{
    return QByteArrayLiteral("tribe-catalog-lkg-v1\n") + QByteArray::number(revision) + '\n';
}

bool encryptAesGcm(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                   const QByteArray &plain, QByteArray &cipher, QByteArray &tag)
{
    cipher.resize(plain.size());
    tag.resize(16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int produced = 0, total = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1
              && EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                    reinterpret_cast<const unsigned char *>(key.constData()),
                    reinterpret_cast<const unsigned char *>(nonce.constData())) == 1
              && EVP_EncryptUpdate(ctx, nullptr, &produced,
                    reinterpret_cast<const unsigned char *>(aad.constData()), aad.size()) == 1
              && EVP_EncryptUpdate(ctx,
                    reinterpret_cast<unsigned char *>(cipher.data()), &produced,
                    reinterpret_cast<const unsigned char *>(plain.constData()), plain.size()) == 1;
    total = produced;
    ok = ok && EVP_EncryptFinal_ex(ctx,
                    reinterpret_cast<unsigned char *>(cipher.data()) + total, &produced) == 1;
    total += produced;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { cipher.clear(); tag.clear(); return false; }
    cipher.resize(total);
    return true;
}

bool decryptAesGcm(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                   const QByteArray &cipher, const QByteArray &tag, QByteArray &plain)
{
    plain.resize(cipher.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int produced = 0, total = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1
              && EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                    reinterpret_cast<const unsigned char *>(key.constData()),
                    reinterpret_cast<const unsigned char *>(nonce.constData())) == 1
              && EVP_DecryptUpdate(ctx, nullptr, &produced,
                    reinterpret_cast<const unsigned char *>(aad.constData()), aad.size()) == 1
              && EVP_DecryptUpdate(ctx,
                    reinterpret_cast<unsigned char *>(plain.data()), &produced,
                    reinterpret_cast<const unsigned char *>(cipher.constData()), cipher.size()) == 1;
    total = produced;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                  const_cast<char *>(tag.constData())) == 1
         && EVP_DecryptFinal_ex(ctx,
                    reinterpret_cast<unsigned char *>(plain.data()) + total, &produced) == 1;
    total += produced;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { plain.clear(); return false; }
    plain.resize(total);
    return true;
}

QByteArray randomBytes(int count)
{
    QByteArray bytes(count, Qt::Uninitialized);
    for (int offset = 0; offset < count; offset += int(sizeof(quint32))) {
        const quint32 word = QRandomGenerator::system()->generate();
        const int chunk = qMin(int(sizeof(word)), count - offset);
        memcpy(bytes.data() + offset, &word, size_t(chunk));
    }
    return bytes;
}

void secureClear(QByteArray &bytes)
{
    if (!bytes.isEmpty())
        OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
    bytes.clear();
}

class SecureArrayScope final {
public:
    explicit SecureArrayScope(QByteArray &bytes) : m_bytes(bytes) {}
    ~SecureArrayScope() { secureClear(m_bytes); }
    SecureArrayScope(const SecureArrayScope &) = delete;
    SecureArrayScope &operator=(const SecureArrayScope &) = delete;
private:
    QByteArray &m_bytes;
};

bool safeTrustState(const CatalogTrustState &trust, int maximumProfiles)
{
    return trust.hasAcceptedV2 && canonicalCatalogTrustAudience(trust.deviceAudience)
           && trust.highestCatalogRevision > 0
           && trust.highestCatalogRevision <= kMaxSafeJsonInteger
           && trust.highestDeviceRevocationEpoch <= kMaxSafeJsonInteger
           && trust.highestKeyEpoch <= kMaxSafeJsonInteger
           && trust.highestPolicyRevision <= kMaxSafeJsonInteger
           && trust.payloadSha256AtHighestRevision.size() == 32
           && trust.highestConfigGenerationByProfile.size() <= maximumProfiles
           && trust.highestBindingGenerationByProfile.size() <= maximumProfiles;
}

bool emptyTrustState(const CatalogTrustState &trust)
{
    return !trust.hasAcceptedV2 && trust.deviceAudience.isEmpty()
           && trust.highestCatalogRevision == 0
           && trust.highestDeviceRevocationEpoch == 0 && trust.highestKeyEpoch == 0
           && trust.highestPolicyRevision == 0
           && trust.highestConfigGenerationByProfile.isEmpty()
           && trust.highestBindingGenerationByProfile.isEmpty()
           && trust.payloadSha256AtHighestRevision.isEmpty();
}

bool completeAuthorityArtifacts(const QByteArray &keysetState,
                                const QByteArray &runtimeState)
{
    if (keysetState.isEmpty() || runtimeState.isEmpty()) return false;
    CatalogKeysetTrustState keyset;
    CatalogRuntimeState runtime;
    QString error;
    if (!parseCatalogKeysetTrustState(keysetState, keyset, error)
        || keyset.highestEpoch == 0
        || !parseCatalogRuntimeState(runtimeState, runtime, error))
        return false;
    return runtime.trustedClock.highestSignedIssuedAtUtc.isValid()
        && runtime.trustedClock.highestObservedWallUtc.isValid();
}

bool syncFileAndDirectory(const QString &path)
{
#if defined(Q_OS_UNIX)
    const QByteArray nativePath = QFile::encodeName(path);
    const int fileFd = ::open(nativePath.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fileFd < 0) return false;
    struct stat metadata{};
    const bool fileOk = ::fstat(fileFd, &metadata) == 0 && S_ISREG(metadata.st_mode)
                        && metadata.st_uid == ::geteuid() && metadata.st_nlink == 1
                        && (metadata.st_mode & 0777) == 0600 && ::fsync(fileFd) == 0;
    ::close(fileFd);
    const QByteArray nativeDir = QFile::encodeName(QFileInfo(path).absolutePath());
    const int dirFd = ::open(nativeDir.constData(), O_RDONLY | O_CLOEXEC);
    if (dirFd < 0) return false;
    const bool dirOk = ::fsync(dirFd) == 0;
    ::close(dirFd);
    return fileOk && dirOk;
#else
    Q_UNUSED(path)
    // QSaveFile still provides atomic replace. Platforms that cannot expose fsync must provide
    // an equivalent implementation before enabling durable LKG support.
    return false;
#endif
}

bool syncDirectory(const QString &directory)
{
#if defined(Q_OS_UNIX)
    const QByteArray nativeDir = QFile::encodeName(directory);
    const int dirFd = ::open(nativeDir.constData(), O_RDONLY | O_CLOEXEC);
    if (dirFd < 0) return false;
    const bool ok = ::fsync(dirFd) == 0;
    ::close(dirFd);
    return ok;
#else
    Q_UNUSED(directory)
    return false;
#endif
}

bool validSecureMetadata(const CatalogSecureMetadata &metadata)
{
    if (metadata.key32.size() != 32 || metadata.storageRevision > kMaxSafeJsonInteger
        || metadata.pendingRevision > kMaxSafeJsonInteger) return false;
    if (metadata.storageRevision == 0) {
        if (!metadata.authenticatedRecordSha256.isEmpty() || !metadata.cleared) return false;
    } else if (metadata.authenticatedRecordSha256.size() != 32) {
        return false;
    }
    if ((metadata.pendingRevision == 0) != metadata.pendingRecordSha256.isEmpty()) return false;
    if (metadata.pendingRevision != 0
        && (metadata.pendingRevision != metadata.storageRevision + 1
            || metadata.pendingRecordSha256.size() != 32)) return false;
    return true;
}

QByteArray clearedDigest(quint64 revision)
{
    return QCryptographicHash::hash(
        QByteArrayLiteral("tribe-catalog-cleared-v1\n") + QByteArray::number(revision) + '\n',
        QCryptographicHash::Sha256);
}

bool ensurePrivateDirectory(const QString &filePath, QString &error)
{
    const QFileInfo target(filePath);
    const QString directory = QDir::cleanPath(target.absolutePath());
    if (!target.isAbsolute() || target.fileName().isEmpty()
        || directory == QDir::rootPath() || directory == QDir::homePath()) {
        error = QStringLiteral("catalog store requires a dedicated absolute directory");
        return false;
    }
    QString current = QDir::rootPath();
    const QString relative = QDir(QDir::rootPath()).relativeFilePath(directory);
    const QStringList components = relative.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (const QString &component : components) {
        current = QDir(current).filePath(component);
        QFileInfo info(current);
        if (info.exists()) {
            if (info.isSymLink() || !info.isDir()) {
                error = QStringLiteral("catalog directory symlink/non-directory rejected");
                return false;
            }
        } else if (!QDir().mkdir(current)) {
            error = QStringLiteral("catalog directory creation failed");
            return false;
        }
    }
    if (!QFile::setPermissions(directory, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                              | QFileDevice::ExeOwner)) {
        error = QStringLiteral("catalog directory permissions failed");
        return false;
    }
#if defined(Q_OS_UNIX)
    struct stat directoryMetadata{};
    const QByteArray nativeDirectory = QFile::encodeName(directory);
    if (::lstat(nativeDirectory.constData(), &directoryMetadata) != 0
        || !S_ISDIR(directoryMetadata.st_mode) || S_ISLNK(directoryMetadata.st_mode)
        || directoryMetadata.st_uid != ::geteuid()
        || (directoryMetadata.st_mode & 0777) != 0700) {
        error = QStringLiteral("catalog directory owner/mode rejected");
        return false;
    }
#endif
    return true;
}

bool acquireStoreLock(const QString &filePath, QLockFile &lock, QString &error)
{
    // Age alone never breaks a live writer. Qt may still recognize a dead local PID; explicitly
    // remove only such a stale crash lock and retry once.
    if (QFileInfo(filePath + QStringLiteral(".lock")).isSymLink()) {
        error = QStringLiteral("catalog store symlink lock rejected");
        return false;
    }
    lock.setStaleLockTime(0);
    if (!lock.tryLock(5000) && (!lock.removeStaleLockFile() || !lock.tryLock(5000))) {
        error = QStringLiteral("catalog store cross-process lock unavailable");
        return false;
    }
    return true;
}

bool readRegularOwnerFile(const QString &path, int maximumBytes,
                          QByteArray &bytes, QString &error)
{
    bytes.clear();
#if defined(Q_OS_UNIX)
    const QByteArray nativePath = QFile::encodeName(path);
    const int fd = ::open(nativePath.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { error = QStringLiteral("catalog LKG safe open failed"); return false; }
    struct stat before{};
    bool ok = ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode)
              && before.st_uid == ::geteuid() && before.st_nlink == 1
              && (before.st_mode & 0777) == 0600
              && before.st_size > 0 && before.st_size <= maximumBytes;
    if (ok) {
        bytes.resize(qsizetype(before.st_size));
        qsizetype offset = 0;
        while (offset < bytes.size()) {
            const ssize_t count = ::read(fd, bytes.data() + offset,
                                         size_t(bytes.size() - offset));
            if (count <= 0) { ok = false; break; }
            offset += qsizetype(count);
        }
        char extra = 0;
        if (ok && ::read(fd, &extra, 1) != 0) ok = false;
        struct stat after{};
        if (ok && (::fstat(fd, &after) != 0 || after.st_dev != before.st_dev
                   || after.st_ino != before.st_ino || after.st_size != before.st_size)) ok = false;
    }
    ::close(fd);
    if (!ok) {
        bytes.clear();
        error = QStringLiteral("catalog LKG type/owner/mode/size/read rejected");
    }
    return ok;
#else
    Q_UNUSED(path)
    Q_UNUSED(maximumBytes)
    error = QStringLiteral("catalog safe file reader unavailable on this platform");
    return false;
#endif
}

} // namespace

CatalogSecureStore::CatalogSecureStore(QString filePath, ICatalogSecureKeyProvider *keyProvider,
                                       ICatalogFileProtection *fileProtection,
                                       CatalogSecureStoreLimits limits)
    : m_filePath(std::move(filePath)), m_keyProvider(keyProvider),
      m_fileProtection(fileProtection), m_limits(limits)
{}

bool CatalogSecureStore::serializePlaintext(const CatalogLkgRecord &record, QByteArray &plaintext,
                                            QString &error, CatalogSecureStoreLimits limits)
{
    plaintext.clear(); error.clear();
    const bool fullCatalog = !record.verifiedEnvelope.isEmpty();
    const bool authorityHighWater = record.trustState.hasAcceptedV2;
    const bool authoritative = record.authoritativeV2EndpointSeen
                               || authorityHighWater;
    if (!authoritative
        || record.verifiedEnvelope.size() > qBound(1024, limits.maximumEnvelopeBytes, 1024 * 1024)
        || record.acceptedKeysetState.size()
              > qBound(1024, limits.maximumKeysetStateBytes, 512 * 1024)
        || record.runtimeState.size()
              > qBound(1024, limits.maximumRuntimeStateBytes, 512 * 1024)
        || (authorityHighWater
            ? !safeTrustState(record.trustState,
                              qBound(1, limits.maximumProfilesInTrustState, 8192))
            : !emptyTrustState(record.trustState))
        || (fullCatalog && !authorityHighWater)
        || (authorityHighWater
            && !completeAuthorityArtifacts(record.acceptedKeysetState,
                                           record.runtimeState))) {
        error = QStringLiteral("catalog LKG plaintext is incomplete or outside bounds");
        return false;
    }
    const CatalogTrustState &trust = record.trustState;
    const QJsonObject trustObject{
        {QStringLiteral("has_accepted_v2"), true},
        {QStringLiteral("device_audience"), trust.deviceAudience},
        {QStringLiteral("highest_catalog_revision"), double(trust.highestCatalogRevision)},
        {QStringLiteral("highest_device_revocation_epoch"), double(trust.highestDeviceRevocationEpoch)},
        {QStringLiteral("highest_key_epoch"), double(trust.highestKeyEpoch)},
        {QStringLiteral("highest_policy_revision"), double(trust.highestPolicyRevision)},
        {QStringLiteral("config_generations"), generationMap(trust.highestConfigGenerationByProfile)},
        {QStringLiteral("binding_generations"), generationMap(trust.highestBindingGenerationByProfile)},
        {QStringLiteral("payload_sha256"), QString::fromLatin1(b64url(trust.payloadSha256AtHighestRevision))},
    };
    const QJsonValue trustValue = authorityHighWater ? QJsonValue(trustObject)
                                                      : QJsonValue(QJsonValue::Null);
    const QJsonObject root{
        {QStringLiteral("schema"), 4},
        {QStringLiteral("authoritative_v2_endpoint_seen"), true},
        {QStringLiteral("envelope"), QString::fromLatin1(b64url(record.verifiedEnvelope))},
        {QStringLiteral("trust"), trustValue},
        {QStringLiteral("keyset_state"), QString::fromLatin1(b64url(record.acceptedKeysetState))},
        {QStringLiteral("runtime_state"), QString::fromLatin1(b64url(record.runtimeState))},
    };
    plaintext = QJsonDocument(root).toJson(QJsonDocument::Compact);
    return true;
}

bool CatalogSecureStore::parsePlaintext(const QByteArray &plaintext, CatalogLkgRecord &record,
                                        QString &error, CatalogSecureStoreLimits limits)
{
    record = {}; error.clear();
    QJsonDocument document;
    if (!parseStrictJsonDocument(plaintext, document, error,
                                 qBound(4096, limits.maximumFileBytes, 2 * 1024 * 1024))
        || !document.isObject()) {
        error = QStringLiteral("catalog LKG plaintext JSON is invalid"); return false;
    }
    const QJsonObject root = document.object();
    int schema = 0;
    if (!exactSchema(root.value(QStringLiteral("schema")), 2, 4, schema)) {
        error = QStringLiteral("catalog LKG plaintext schema is invalid");
        return false;
    }
    QSet<QString> rootKeys{QStringLiteral("schema"), QStringLiteral("envelope"),
                           QStringLiteral("trust"), QStringLiteral("keyset_state"),
                           QStringLiteral("runtime_state")};
    if (schema >= 3)
        rootKeys.insert(QStringLiteral("authoritative_v2_endpoint_seen"));
    for (auto it = root.constBegin(); it != root.constEnd(); ++it)
        if (!rootKeys.contains(it.key())) { error = QStringLiteral("unknown LKG plaintext field"); return false; }
    if (root.size() != rootKeys.size() || (schema < 2 || schema > 4)
        || (schema >= 3
            && (!root.value(QStringLiteral("authoritative_v2_endpoint_seen")).isBool()
                || !root.value(QStringLiteral("authoritative_v2_endpoint_seen")).toBool()))
        || !decodeB64url(root.value(QStringLiteral("envelope")), schema == 2 ? 1 : 0,
                         qBound(1024, limits.maximumEnvelopeBytes, 1024 * 1024),
                         record.verifiedEnvelope)
        || !decodeB64url(root.value(QStringLiteral("keyset_state")), 0,
                         qBound(1024, limits.maximumKeysetStateBytes, 512 * 1024),
                         record.acceptedKeysetState)
        || !decodeB64url(root.value(QStringLiteral("runtime_state")), 0,
                         qBound(1024, limits.maximumRuntimeStateBytes, 512 * 1024),
                         record.runtimeState)) {
        error = QStringLiteral("catalog LKG plaintext fields are invalid"); return false;
    }
    record.authoritativeV2EndpointSeen = true;
    if (record.verifiedEnvelope.isEmpty()) {
        const bool endpointOnly = schema >= 3
            && root.value(QStringLiteral("trust")).isNull();
        const bool authorityHighWater = schema == 4
            && root.value(QStringLiteral("trust")).isObject();
        if (!endpointOnly && !authorityHighWater) {
            error = QStringLiteral("catalog v2 endpoint tombstone trust shape invalid");
            return false;
        }
        if (endpointOnly) {
            record.trustState = {};
            return true;
        }
    }
    if (!root.value(QStringLiteral("trust")).isObject()) {
        error = QStringLiteral("catalog LKG trust object missing");
        return false;
    }
    const QJsonObject trust = root.value(QStringLiteral("trust")).toObject();
    const QSet<QString> trustKeys{
        QStringLiteral("has_accepted_v2"), QStringLiteral("device_audience"),
        QStringLiteral("highest_catalog_revision"), QStringLiteral("highest_device_revocation_epoch"),
        QStringLiteral("highest_key_epoch"), QStringLiteral("highest_policy_revision"),
        QStringLiteral("config_generations"), QStringLiteral("binding_generations"),
        QStringLiteral("payload_sha256")};
    for (auto it = trust.constBegin(); it != trust.constEnd(); ++it)
        if (!trustKeys.contains(it.key())) { error = QStringLiteral("unknown LKG trust field"); return false; }
    CatalogTrustState state;
    state.hasAcceptedV2 = trust.value(QStringLiteral("has_accepted_v2")).toBool(false);
    state.deviceAudience = trust.value(QStringLiteral("device_audience")).toString();
    if (trust.size() != trustKeys.size()
        || !trust.value(QStringLiteral("has_accepted_v2")).isBool()
        || !trust.value(QStringLiteral("device_audience")).isString()) {
        error = QStringLiteral("catalog LKG trust shape is invalid"); return false;
    }
    if (!jsonUInt(trust, QStringLiteral("highest_catalog_revision"),
                  state.highestCatalogRevision, false)
        || !jsonUInt(trust, QStringLiteral("highest_device_revocation_epoch"),
                     state.highestDeviceRevocationEpoch)
        || !jsonUInt(trust, QStringLiteral("highest_key_epoch"), state.highestKeyEpoch)
        || !jsonUInt(trust, QStringLiteral("highest_policy_revision"),
                     state.highestPolicyRevision)) {
        error = QStringLiteral("catalog LKG trust counters are invalid"); return false;
    }
    if (!parseGenerationMap(trust.value(QStringLiteral("config_generations")),
                            state.highestConfigGenerationByProfile,
                            qBound(1, limits.maximumProfilesInTrustState, 8192))
        || !parseGenerationMap(trust.value(QStringLiteral("binding_generations")),
                               state.highestBindingGenerationByProfile,
                               qBound(1, limits.maximumProfilesInTrustState, 8192))) {
        error = QStringLiteral("catalog LKG trust generations are invalid"); return false;
    }
    if (!decodeB64url(trust.value(QStringLiteral("payload_sha256")), 32, 32,
                      state.payloadSha256AtHighestRevision)) {
        error = QStringLiteral("catalog LKG trust digest is invalid"); return false;
    }
    if (!safeTrustState(state, qBound(1, limits.maximumProfilesInTrustState, 8192))) {
        error = QStringLiteral("catalog LKG trust invariants are invalid"); return false;
    }
    if (schema == 4
        && !completeAuthorityArtifacts(record.acceptedKeysetState,
                                       record.runtimeState)) {
        error = QStringLiteral("catalog LKG authority artifacts are incomplete");
        return false;
    }
    record.trustState = std::move(state);
    return true;
}

CatalogLkgLoadStatus CatalogSecureStore::load(CatalogLkgRecord &record, QString &error) const
{
    record = {}; error.clear();
    if (!m_keyProvider || m_filePath.isEmpty()) {
        error = QStringLiteral("catalog secure storage dependency unavailable");
        return CatalogLkgLoadStatus::Error;
    }
    if (!ensurePrivateDirectory(m_filePath, error)) return CatalogLkgLoadStatus::Error;
    QLockFile lock(m_filePath + QStringLiteral(".lock"));
    if (!acquireStoreLock(m_filePath, lock, error)) return CatalogLkgLoadStatus::Error;
    CatalogSecureMetadata metadata;
    const CatalogSecureKeyStatus metadataStatus = m_keyProvider->loadMetadata(metadata, error);
    if (metadataStatus == CatalogSecureKeyStatus::Missing) {
        if (QFile::exists(m_filePath)) {
            error = QStringLiteral("catalog file exists without secure metadata");
            return CatalogLkgLoadStatus::Error;
        }
        return CatalogLkgLoadStatus::Empty;
    }
    if (metadataStatus != CatalogSecureKeyStatus::Available || !validSecureMetadata(metadata)) {
        if (error.isEmpty()) error = QStringLiteral("catalog secure metadata unavailable/corrupt");
        return CatalogLkgLoadStatus::Error;
    }
    if (!QFileInfo::exists(m_filePath)) {
        if (metadata.cleared && metadata.pendingRevision == 0)
            return CatalogLkgLoadStatus::Empty;
        if (metadata.storageRevision != 0 || metadata.pendingRevision != 0) {
            error = QStringLiteral("catalog LKG missing below rollback high-water");
            return CatalogLkgLoadStatus::Error;
        }
        return CatalogLkgLoadStatus::Empty;
    }
    QByteArray bytes;
    if (!readRegularOwnerFile(m_filePath,
                             qBound(4096, m_limits.maximumFileBytes, 2 * 1024 * 1024),
                             bytes, error)) return CatalogLkgLoadStatus::Error;
    QJsonDocument document;
    if (!parseStrictJsonDocument(bytes, document, error,
                                 qBound(4096, m_limits.maximumFileBytes, 2 * 1024 * 1024))
        || !document.isObject()) {
        error = QStringLiteral("catalog LKG envelope is corrupt"); return CatalogLkgLoadStatus::Error;
    }
    const QJsonObject outer = document.object();
    const QSet<QString> keys{QStringLiteral("schema"), QStringLiteral("algorithm"),
                             QStringLiteral("revision"), QStringLiteral("nonce"),
                             QStringLiteral("ciphertext"), QStringLiteral("tag")};
    for (auto it = outer.constBegin(); it != outer.constEnd(); ++it)
        if (!keys.contains(it.key())) { error = QStringLiteral("unknown encrypted LKG field"); return CatalogLkgLoadStatus::Error; }
    quint64 revision = 0;
    QByteArray nonce, cipher, tag;
    int outerSchema = 0;
    if (outer.size() != keys.size()
        || !exactSchema(outer.value(QStringLiteral("schema")), 1, 1, outerSchema)
        || outer.value(QStringLiteral("algorithm")).toString() != QLatin1String("AES-256-GCM")
        || !jsonUInt(outer, QStringLiteral("revision"), revision, false)
        || !decodeB64url(outer.value(QStringLiteral("nonce")), 12, 12, nonce)
        || !decodeB64url(outer.value(QStringLiteral("ciphertext")), 1,
                         qBound(4096, m_limits.maximumFileBytes, 2 * 1024 * 1024), cipher)
        || !decodeB64url(outer.value(QStringLiteral("tag")), 16, 16, tag)) {
        error = QStringLiteral("encrypted catalog LKG fields are invalid");
        return CatalogLkgLoadStatus::Error;
    }
    const QByteArray digest = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
    const bool isCurrent = revision == metadata.storageRevision
                           && digest == metadata.authenticatedRecordSha256 && !metadata.cleared;
    const bool isPending = metadata.pendingRevision != 0
                           && revision == metadata.pendingRevision
                           && digest == metadata.pendingRecordSha256;
    if (!isCurrent && !isPending) {
        error = QStringLiteral("catalog LKG rollback/collision detected");
        return CatalogLkgLoadStatus::Error;
    }
    QByteArray plaintext;
    if (!decryptAesGcm(metadata.key32, nonce, aadForRevision(revision), cipher, tag, plaintext)
        || !parsePlaintext(plaintext, record, error, m_limits)) {
        secureClear(plaintext);
        record = {};
        if (error.isEmpty()) error = QStringLiteral("catalog LKG authentication failed");
        return CatalogLkgLoadStatus::Error;
    }
    secureClear(plaintext);
    if (isPending) {
        // A pending digest proves only that QSaveFile commit happened. A crash could have occurred
        // before fsync, NSFileProtection, or no-backup were applied. Repeat every durability and
        // platform-protection step before advancing rollback metadata.
        const bool diskSafe = syncFileAndDirectory(m_filePath)
                              && (!m_fileProtection
                                  || m_fileProtection->protect(m_filePath, error));
        if (!diskSafe) {
            CatalogSecureMetadata tombstone = metadata;
            tombstone.key32 = randomBytes(32);
            tombstone.storageRevision = metadata.pendingRevision;
            tombstone.authenticatedRecordSha256 = clearedDigest(metadata.pendingRevision);
            tombstone.cleared = true;
            tombstone.pendingRevision = 0;
            tombstone.pendingRecordSha256.clear();
            QString tombstoneError;
            const bool tombstoned = tombstone.key32.size() == 32
                                    && m_keyProvider->replaceMetadataWhileLocked(
                                           metadata, tombstone, tombstoneError);
            QFile::remove(m_filePath);
            record = {};
            if (!tombstoned) {
                error = tombstoneError.isEmpty()
                            ? QStringLiteral("catalog pending recovery tombstone failed")
                            : tombstoneError;
            } else if (error.isEmpty()) {
                error = QStringLiteral("catalog pending recovery protection failed");
            }
            secureClear(tombstone.key32);
            return CatalogLkgLoadStatus::Error;
        }
        CatalogSecureMetadata finalized = metadata;
        finalized.storageRevision = metadata.pendingRevision;
        finalized.authenticatedRecordSha256 = metadata.pendingRecordSha256;
        finalized.cleared = false;
        finalized.pendingRevision = 0;
        finalized.pendingRecordSha256.clear();
        if (!m_keyProvider->replaceMetadataWhileLocked(metadata, finalized, error)) {
            record = {};
            if (error.isEmpty()) error = QStringLiteral("catalog pending-write recovery failed");
            return CatalogLkgLoadStatus::Error;
        }
    } else if (metadata.pendingRevision != 0) {
        // Crash before QSaveFile commit: the current authenticated record is intact, so cancel
        // the prepared digest before allowing a subsequent writer.
        CatalogSecureMetadata rollback = metadata;
        rollback.pendingRevision = 0;
        rollback.pendingRecordSha256.clear();
        if (!m_keyProvider->replaceMetadataWhileLocked(metadata, rollback, error)) {
            record = {};
            if (error.isEmpty()) error = QStringLiteral("catalog pending rollback failed");
            return CatalogLkgLoadStatus::Error;
        }
    }
    return CatalogLkgLoadStatus::Loaded;
}

bool CatalogSecureStore::replaceAtomically(const CatalogLkgRecord &record, QString &error)
{
    error.clear();
    if (!m_keyProvider || m_filePath.isEmpty()) {
        error = QStringLiteral("catalog secure storage dependency unavailable"); return false;
    }
    QByteArray plaintext;
    if (!serializePlaintext(record, plaintext, error, m_limits)) return false;
    SecureArrayScope plaintextScope(plaintext);
    if (!ensurePrivateDirectory(m_filePath, error)) return false;
    QLockFile lock(m_filePath + QStringLiteral(".lock"));
    if (!acquireStoreLock(m_filePath, lock, error)) return false;
    CatalogSecureMetadata metadata;
    if (m_keyProvider->loadOrCreateMetadata(metadata, error)
            != CatalogSecureKeyStatus::Available
        || !validSecureMetadata(metadata) || metadata.pendingRevision != 0) {
        if (error.isEmpty()) error = QStringLiteral("platform catalog metadata unavailable/busy");
        return false;
    }
    if (metadata.storageRevision >= kMaxSafeJsonInteger) {
        if (error.isEmpty()) error = QStringLiteral("catalog storage revision unavailable/exhausted");
        return false;
    }
    const quint64 storageRevision = metadata.storageRevision + 1;
    const QByteArray nonce = randomBytes(12);
    QByteArray cipher, tag;
    if (!encryptAesGcm(metadata.key32, nonce, aadForRevision(storageRevision),
                       plaintext, cipher, tag)) {
        secureClear(plaintext);
        error = QStringLiteral("catalog LKG encryption failed"); return false;
    }
    secureClear(plaintext);
    const QJsonObject outer{
        {QStringLiteral("schema"), 1},
        {QStringLiteral("algorithm"), QStringLiteral("AES-256-GCM")},
        {QStringLiteral("revision"), double(storageRevision)},
        {QStringLiteral("nonce"), QString::fromLatin1(b64url(nonce))},
        {QStringLiteral("ciphertext"), QString::fromLatin1(b64url(cipher))},
        {QStringLiteral("tag"), QString::fromLatin1(b64url(tag))},
    };
    const QByteArray bytes = QJsonDocument(outer).toJson(QJsonDocument::Compact);
    if (bytes.size() > qBound(4096, m_limits.maximumFileBytes, 2 * 1024 * 1024)) {
        error = QStringLiteral("encrypted catalog LKG exceeds file bound"); return false;
    }
    const QFileInfo info(m_filePath);
    if (QFileInfo(m_filePath).isSymLink()) {
        error = QStringLiteral("catalog LKG symlink rejected"); return false;
    }
    const QByteArray outerDigest = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
    CatalogSecureMetadata pending = metadata;
    pending.pendingRevision = storageRevision;
    pending.pendingRecordSha256 = outerDigest;
    if (!m_keyProvider->replaceMetadataWhileLocked(metadata, pending, error)) {
        if (error.isEmpty()) error = QStringLiteral("catalog pending metadata CAS failed");
        return false;
    }
    QSaveFile file(m_filePath);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFileDevice::ReadOwner
                                                                 | QFileDevice::WriteOwner)
        || file.write(bytes) != bytes.size() || !file.commit()) {
        CatalogSecureMetadata rollback = metadata;
        QString ignored;
        m_keyProvider->replaceMetadataWhileLocked(pending, rollback, ignored);
        error = QStringLiteral("atomic catalog LKG replace failed"); return false;
    }
    const bool diskSafe = syncFileAndDirectory(m_filePath)
                          && (!m_fileProtection || m_fileProtection->protect(m_filePath, error));
    if (!diskSafe) {
        // Cryptographic logout/tombstone happens before deletion. Even if deletion fails, the
        // committed bytes are no longer decryptable and an old backup cannot match metadata.
        CatalogSecureMetadata tombstone = pending;
        tombstone.key32 = randomBytes(32);
        if (tombstone.key32.size() != 32) {
            if (error.isEmpty()) error = QStringLiteral("catalog tombstone random key unavailable");
            return false;
        }
        tombstone.storageRevision = storageRevision;
        tombstone.authenticatedRecordSha256 = clearedDigest(storageRevision);
        tombstone.cleared = true;
        tombstone.pendingRevision = 0;
        tombstone.pendingRecordSha256.clear();
        QString tombstoneError;
        if (!m_keyProvider->replaceMetadataWhileLocked(pending, tombstone, tombstoneError)) {
            if (error.isEmpty()) error = tombstoneError.isEmpty()
                    ? QStringLiteral("catalog protection failure tombstone failed") : tombstoneError;
            return false;
        }
        QFile::remove(m_filePath);
        if (error.isEmpty()) error = QStringLiteral("catalog LKG disk protection/fsync failed");
        return false;
    }
    CatalogSecureMetadata finalized = pending;
    finalized.storageRevision = storageRevision;
    finalized.authenticatedRecordSha256 = outerDigest;
    finalized.cleared = false;
    finalized.pendingRevision = 0;
    finalized.pendingRecordSha256.clear();
    if (!m_keyProvider->replaceMetadataWhileLocked(pending, finalized, error)) {
        if (error.isEmpty()) error = QStringLiteral("catalog final metadata CAS failed");
        return false; // exact pending digest permits authenticated crash recovery on next load
    }
    return true;
}

bool CatalogSecureStore::clear(QString &error)
{
    error.clear();
    if (!m_keyProvider || m_filePath.isEmpty() || !ensurePrivateDirectory(m_filePath, error))
        return false;
    QLockFile lock(m_filePath + QStringLiteral(".lock"));
    if (!acquireStoreLock(m_filePath, lock, error)) return false;
    CatalogSecureMetadata metadata;
    if (m_keyProvider->loadOrCreateMetadata(metadata, error)
            != CatalogSecureKeyStatus::Available
        || !validSecureMetadata(metadata)) {
        if (error.isEmpty()) error = QStringLiteral("catalog clear metadata unavailable");
        return false;
    }
    const quint64 baseRevision = qMax(metadata.storageRevision, metadata.pendingRevision);
    if (baseRevision >= kMaxSafeJsonInteger) {
        error = QStringLiteral("catalog clear revision exhausted");
        return false;
    }
    CatalogSecureMetadata tombstone;
    tombstone.key32 = randomBytes(32);
    if (tombstone.key32.size() != 32) {
        error = QStringLiteral("catalog clear random key unavailable");
        return false;
    }
    tombstone.storageRevision = baseRevision + 1;
    tombstone.authenticatedRecordSha256 = clearedDigest(tombstone.storageRevision);
    tombstone.cleared = true;
    if (!m_keyProvider->replaceMetadataWhileLocked(metadata, tombstone, error)) {
        if (error.isEmpty()) error = QStringLiteral("catalog cryptographic clear failed");
        return false;
    }
    // Metadata rotation is the security boundary. Report deletion failure, but never roll the
    // tombstone back: residual/backup bytes are encrypted under the destroyed previous key.
    if (QFile::exists(m_filePath) && !QFile::remove(m_filePath)) {
        error = QStringLiteral("catalog ciphertext cleanup failed after cryptographic clear");
        return false;
    }
    if (!syncDirectory(QFileInfo(m_filePath).absolutePath())) {
        error = QStringLiteral("catalog clear directory fsync failed");
        return false;
    }
    return true;
}

} // namespace avpn

// Tribe catalog v2 — atomic encrypted LKG persistence with external platform key custody.
#pragma once

#include "CatalogTrust.h"

#include <QString>

namespace avpn {

enum class CatalogSecureKeyStatus {
    Available = 0,
    Missing,
    Unavailable,
    Error,
};

struct CatalogSecureMetadata {
    QByteArray key32;
    quint64 storageRevision = 0;
    QByteArray authenticatedRecordSha256;
    bool cleared = false;
    quint64 pendingRevision = 0;
    QByteArray pendingRecordSha256;

    friend bool operator==(const CatalogSecureMetadata &left,
                           const CatalogSecureMetadata &right)
    {
        return left.key32 == right.key32
               && left.storageRevision == right.storageRevision
               && left.authenticatedRecordSha256 == right.authenticatedRecordSha256
               && left.cleared == right.cleared
               && left.pendingRevision == right.pendingRevision
               && left.pendingRecordSha256 == right.pendingRecordSha256;
    }
};

// Implementations keep the 256-bit AEAD key and rollback high-water outside the catalog file.
// No implementation may synthesize a plaintext/static fallback when platform storage is locked.
class ICatalogSecureKeyProvider {
public:
    virtual ~ICatalogSecureKeyProvider() = default;
    // One secure item owns key + rollback revision + exact outer-record digest. Splitting these
    // values permits partial-delete resurrection and same-revision collision attacks.
    virtual CatalogSecureKeyStatus loadMetadata(CatalogSecureMetadata &metadata,
                                                QString &error) = 0;
    virtual CatalogSecureKeyStatus loadOrCreateMetadata(CatalogSecureMetadata &metadata,
                                                        QString &error) = 0;
    // Replace while the caller holds the dedicated cross-process catalog lock. Providers compare
    // expected as defense in depth; this method is not claimed as an OS-atomic standalone CAS.
    virtual bool replaceMetadataWhileLocked(const CatalogSecureMetadata &expected,
                                            const CatalogSecureMetadata &replacement,
                                            QString &error) = 0;
};

// Platform hook for NSFileProtection/no-backup or an equivalent OS policy. Failure makes the
// persisted LKG unusable; online in-memory catalog operation remains possible.
class ICatalogFileProtection {
public:
    virtual ~ICatalogFileProtection() = default;
    virtual bool protect(const QString &path, QString &error) = 0;
};

struct CatalogSecureStoreLimits {
    int maximumFileBytes = 1024 * 1024;
    int maximumEnvelopeBytes = 768 * 1024;
    int maximumKeysetStateBytes = 128 * 1024;
    int maximumRuntimeStateBytes = 128 * 1024;
    int maximumProfilesInTrustState = 1024;
};

class CatalogSecureStore final : public ICatalogLkgStore {
public:
    CatalogSecureStore(QString filePath, ICatalogSecureKeyProvider *keyProvider,
                       ICatalogFileProtection *fileProtection = nullptr,
                       CatalogSecureStoreLimits limits = {});

    CatalogLkgLoadStatus load(CatalogLkgRecord &record, QString &error) const override;
    bool replaceAtomically(const CatalogLkgRecord &record, QString &error) override;
    bool clear(QString &error) override;

    static bool serializePlaintext(const CatalogLkgRecord &record, QByteArray &plaintext,
                                   QString &error, CatalogSecureStoreLimits limits = {});
    static bool parsePlaintext(const QByteArray &plaintext, CatalogLkgRecord &record,
                               QString &error, CatalogSecureStoreLimits limits = {});

private:
    QString m_filePath;
    ICatalogSecureKeyProvider *m_keyProvider = nullptr;
    ICatalogFileProtection *m_fileProtection = nullptr;
    CatalogSecureStoreLimits m_limits;
};

} // namespace avpn

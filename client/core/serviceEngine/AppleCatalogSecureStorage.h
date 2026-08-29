// Tribe catalog v2 — Apple Keychain custody and file-protection hooks.
#pragma once

#include "CatalogSecureStore.h"

#include <QMutex>

namespace avpn {

// Available only in Apple targets. AEAD key + rollback revision/digest + pending/tombstone state
// live in one ThisDeviceOnly generic-password item; no value is mirrored into QSettings.
class AppleCatalogSecureKeyProvider final : public ICatalogSecureKeyProvider {
public:
    explicit AppleCatalogSecureKeyProvider(QString serviceName);

    CatalogSecureKeyStatus loadMetadata(CatalogSecureMetadata &metadata,
                                        QString &error) override;
    CatalogSecureKeyStatus loadOrCreateMetadata(CatalogSecureMetadata &metadata,
                                                QString &error) override;
    bool replaceMetadataWhileLocked(const CatalogSecureMetadata &expected,
                                    const CatalogSecureMetadata &replacement,
                                    QString &error) override;

private:
    QString m_serviceName;
    QMutex m_mutex;
};

class AppleCatalogFileProtection final : public ICatalogFileProtection {
public:
    bool protect(const QString &path, QString &error) override;
};

} // namespace avpn

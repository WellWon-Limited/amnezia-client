// Tribe catalog v2 — Android Keystore custody for catalog key + rollback metadata.
#pragma once

#include "CatalogSecureStore.h"

#include <QMutex>

namespace avpn {

class AndroidCatalogSecureKeyProvider final : public ICatalogSecureKeyProvider {
public:
    CatalogSecureKeyStatus loadMetadata(CatalogSecureMetadata &metadata,
                                        QString &error) override;
    CatalogSecureKeyStatus loadOrCreateMetadata(CatalogSecureMetadata &metadata,
                                                QString &error) override;
    bool replaceMetadataWhileLocked(const CatalogSecureMetadata &expected,
                                    const CatalogSecureMetadata &replacement,
                                    QString &error) override;

private:
    CatalogSecureKeyStatus load(bool create, CatalogSecureMetadata &metadata,
                                QString &error);
    QMutex m_mutex;
};

} // namespace avpn

// AVPN serviceEngine — ключи (zero-knowledge) + device_id. ПЕРЕИСПОЛЬЗУЕТ кирпичи форка:
//   ключи      → WireguardConfigurator::genClientKeys() (X25519, base64)
//   хранилище  → SecureAppSettingsRepository (шифрованное)
//   device_id  → SecureAppSettingsRepository::getInstallationUuid() (persisted, idempotent)
// Форк НЕ модифицируем. Приватный ключ на бэкенд не уходит. [IN-FORK build: см. Identity.cpp]
#pragma once

#include "AwgConfigBuilder.h" // ClientKeys
#include <QString>

class SecureAppSettingsRepository; // fwd (форк)

namespace avpn {

class Identity {
public:
    // Гарантирует ключпару: берёт из защ. хранилища, иначе генерит (genClientKeys) и сохраняет приватный.
    bool ensureKeys(SecureAppSettingsRepository *store, QString &error);

    ClientKeys keys() const { return m_keys; }
    QString publicKey() const { return m_keys.publicKey; }

    // Стабильный device_id для anti-abuse/идемпотентности триала = installationUuid форка.
    static QString deviceId(SecureAppSettingsRepository *store);

    static constexpr QLatin1String kPrivKey{"avpn/clientPrivKey"};
    static constexpr QLatin1String kPubKey{"avpn/clientPubKey"};

private:
    ClientKeys m_keys;
};

} // namespace avpn

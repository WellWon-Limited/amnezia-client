#include "Identity.h"

// [IN-FORK BUILD] переиспользуем готовые кирпичи форка:
#include "core/configurators/wireguardConfigurator.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "secureQSettings.h"
#include "version.h"

namespace avpn {

bool Identity::ensureKeys(SecureAppSettingsRepository *store, QString &error)
{
    if (!store) {
        error = QStringLiteral("no settings store");
        return false;
    }
    // Храним ключпару в том же зашифрованном сторе форка (SecureQSettings — публичный API),
    // т.к. SecureAppSettingsRepository::value/setValue приватные. Org/App из version.h →
    // тот же backing store, что и у репозитория. Приватный ключ на бэкенд не уходит.
    SecureQSettings settings(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));

    QString priv = settings.value(kPrivKey).toString();
    QString pub = settings.value(kPubKey).toString();

    if (priv.isEmpty() || pub.isEmpty()) {
        // reuse: генерация ключей форком (не пишем своё крипто)
        const WireguardConfigurator::ConnectionData d = WireguardConfigurator::genClientKeys();
        if (d.clientPrivKey.isEmpty() || d.clientPubKey.isEmpty()) {
            error = QStringLiteral("genClientKeys failed");
            return false;
        }
        priv = d.clientPrivKey;
        pub = d.clientPubKey;
        settings.setValue(kPrivKey, priv);
        settings.setValue(kPubKey, pub);
    }
    m_keys.privateKey = priv;
    m_keys.publicKey = pub;
    return true;
}

QString Identity::deviceId(SecureAppSettingsRepository *store)
{
    return store ? store->getInstallationUuid(true) : QString();
}

} // namespace avpn

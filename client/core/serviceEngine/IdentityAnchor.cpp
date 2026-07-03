// AVPN serviceEngine — Keychain-I/O якоря идентичности (см. IdentityAnchor.h). [IN-FORK]
#include "IdentityAnchor.h"

// ТОЛЬКО iOS: там QSettings (identity) стирается при удалении приложения → нужен Keychain-якорь,
// и iOS читает свой keychain-item молча (без UI). macOS СОЗНАТЕЛЬНО исключён: (1) его настройки в
// ~/Library/Preferences и так переживают удаление .app (якорь избыточен); (2) macOS показывал бы
// диалог пароля связки ключей при несовпадении подписи (dev-пересборка = новая подпись) — недопустимо.
#if defined(Q_OS_IOS)

// [IN-FORK] QtKeychain + зашифрованный стор форка (тот же паттерн, что SecureQSettings::get/setSecTag).
#include "secureQSettings.h"
#include "version.h"

#include <QDebug>
#include <QEventLoop>
#include <QTimer>

using namespace QKeychain;

namespace avpn {

namespace {

    // Тот же сервис, что у SecureQSettings форка («AVPN-Keychain» — изоляция от офиц. Amnezia).
    constexpr const char *kKeychainService = "AVPN-Keychain";
    const QString kAnchorTag = QStringLiteral("avpn/identityAnchor");

    // Ключи identity в QSettings (источники: secureAppSettingsRepository / Identity.h / Enrollment.h).
    const QString kUuidKey = QStringLiteral("Conf/installationUuid");
    const QString kPrivKey = QStringLiteral("avpn/clientPrivKey");
    const QString kPubKey = QStringLiteral("avpn/clientPubKey");
    const QString kTokenKey = QStringLiteral("avpn/subscriptionToken");

    struct StoreIdentity {
        QString uuid, priv, pub, token;
        bool has() const { return !uuid.isEmpty(); }
    };

    StoreIdentity readStore()
    {
        SecureQSettings s(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));
        StoreIdentity st;
        st.uuid = s.value(kUuidKey).toString();
        st.priv = s.value(kPrivKey).toString();
        st.pub = s.value(kPubKey).toString();
        st.token = s.value(kTokenKey).toString();
        return st;
    }

    // Блокирующее чтение якоря (паттерн SecureQSettings::getSecTag). Ошибка/нет записи → пусто.
    QByteArray readAnchor()
    {
        ReadPasswordJob job{QLatin1String(kKeychainService)};
        job.setAutoDelete(false);
        job.setKey(kAnchorTag);
        QEventLoop loop;
        QTimer::singleShot(1500, &loop, &QEventLoop::quit); // сторож: Keychain не должен вешать старт
        QObject::connect(&job, &ReadPasswordJob::finished, &loop, &QEventLoop::quit);
        job.start();
        loop.exec();
        if (job.error() && job.error() != Error::EntryNotFound)
            qWarning() << "AVPN IdentityAnchor: keychain read failed:" << job.errorString();
        return job.binaryData();
    }

    // Блокирующая запись якоря (паттерн SecureQSettings::setSecTag, сторож 1с).
    void writeAnchor(const QByteArray &blob)
    {
        WritePasswordJob job{QLatin1String(kKeychainService)};
        job.setAutoDelete(false);
        job.setKey(kAnchorTag);
        job.setBinaryData(blob);
        QEventLoop loop;
        QTimer::singleShot(1000, &loop, &QEventLoop::quit);
        QObject::connect(&job, &WritePasswordJob::finished, &loop, &QEventLoop::quit);
        job.start();
        loop.exec();
        if (job.error())
            qWarning() << "AVPN IdentityAnchor: keychain write failed:" << job.errorString();
    }

} // namespace

void IdentityAnchor::updateFromStore()
{
    const StoreIdentity st = readStore();
    if (!st.has())
        return; // нечего сохранять (до первого запуска identity)
    const QByteArray blob = packIdentity(st.uuid, st.priv, st.pub, st.token);
    if (blob == readAnchor())
        return; // якорь актуален — не дёргаем Keychain зря
    writeAnchor(blob);
}

void IdentityAnchor::syncAtStartup()
{
    const StoreIdentity st = readStore();
    QString uuid, priv, pub, token, err;
    const bool anchorOk = unpackIdentity(readAnchor(), uuid, priv, pub, token, err);

    switch (decide(st.has(), anchorOk)) {
    case Action::SaveToAnchor:
        updateFromStore(); // освежить (ротация токена/первый запуск после апдейта)
        break;
    case Action::RestoreFromAnchor: {
        // Переустановка: стор пуст, якорь жив → вернуть ПОЛНУЮ identity. Тот же uuid + тот же
        // pubkey ⇒ /v1/trial отдаст идемпотентный replay СТАРОГО аккаунта (дни/оплата целы),
        // гейт key-rotation бэка не задевается.
        SecureQSettings s(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));
        s.setValue(kUuidKey, uuid);
        if (!priv.isEmpty())
            s.setValue(kPrivKey, priv);
        if (!pub.isEmpty())
            s.setValue(kPubKey, pub);
        if (!token.isEmpty())
            s.setValue(kTokenKey, token);
        // флаш — в деструкторе SecureQSettings/QSettings при выходе из scope (как в saveToken)
        qInfo() << "AVPN IdentityAnchor: identity restored from keychain (reinstall detected)";
        break;
    }
    case Action::None:
        break; // свежее устройство — якорь появится после enroll (saveToken → updateFromStore)
    }
}

} // namespace avpn

#else // macOS/Android/win/linux: якорь в Keychain НЕ используем.
      // macOS — plist в ~/Library/Preferences и так переживает удаление .app (+ никаких диалогов связки).
      // Android — отдельный ANDROID_ID-трек (DEVICE-FIRST-SPEC §4.1). win/linux — n/a.

namespace avpn {
void IdentityAnchor::syncAtStartup() {}
void IdentityAnchor::updateFromStore() {}
} // namespace avpn

#endif

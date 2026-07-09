// AVPN serviceEngine — Keychain-I/O якоря идентичности (см. IdentityAnchor.h). [IN-FORK]
#include "IdentityAnchor.h"

// ТОЛЬКО iOS: там QSettings (identity) стирается при удалении приложения → нужен Keychain-якорь,
// и iOS читает свой keychain-item молча (без UI). macOS СОЗНАТЕЛЬНО исключён: (1) его настройки в
// ~/Library/Preferences и так переживают удаление .app (якорь избыточен); (2) macOS показывал бы
// диалог пароля связки ключей при несовпадении подписи (dev-пересборка = новая подпись) — недопустимо.
#if defined(Q_OS_IOS)

// [IN-FORK] зашифрованный стор форка + прямые SecItem-вызовы (Security.framework, чистый C API).
// Раньше здесь был QtKeychain, но он не выставляет kSecAttrAccessible (дефолт WhenUnlocked =
// item мигрирует в зашифрованный бэкап / на новый iPhone). Требование device_fingerprint
// (FINGERPRINT-HANDOFF бэка): якорь с fpSeed — kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
// БЕЗ kSecAttrSynchronizable (iCloud-тираж сида на второе устройство сломал бы reinstall-дедуп
// и дал ложные 403 на rehome-гейте; ThisDeviceOnly = «новый телефон = новое устройство», перенос —
// через QR). Вызовы синхронные и быстрые (~мс) — сторожа-QEventLoop больше не нужны.
#include "secureQSettings.h"
#include "version.h"

#include <QDebug>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

namespace avpn {

namespace {

    // Тот же сервис, что у SecureQSettings форка («AVPN-Keychain» — изоляция от офиц. Amnezia);
    // account совпадает с ключом прежнего QtKeychain-item — старые якоря находятся и апгрейдятся.
    #define AVPN_ANCHOR_SERVICE CFSTR("AVPN-Keychain")
    #define AVPN_ANCHOR_ACCOUNT CFSTR("avpn/identityAnchor")

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

    // База запроса: generic password с нашими service/account.
    CFMutableDictionaryRef anchorQuery()
    {
        CFMutableDictionaryRef q = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(q, kSecAttrService, AVPN_ANCHOR_SERVICE);
        CFDictionarySetValue(q, kSecAttrAccount, AVPN_ANCHOR_ACCOUNT);
        return q;
    }

    // Чтение якоря. Ошибка/нет записи → пусто.
    QByteArray readAnchor()
    {
        CFMutableDictionaryRef q = anchorQuery();
        CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
        CFTypeRef data = nullptr;
        const OSStatus st = SecItemCopyMatching(q, &data);
        CFRelease(q);
        if (st != errSecSuccess || !data) {
            if (st != errSecSuccess && st != errSecItemNotFound)
                qWarning() << "AVPN IdentityAnchor: keychain read failed, OSStatus" << int(st);
            return {};
        }
        const CFDataRef d = static_cast<CFDataRef>(data);
        QByteArray out(reinterpret_cast<const char *>(CFDataGetBytePtr(d)),
                       static_cast<int>(CFDataGetLength(d)));
        CFRelease(data);
        return out;
    }

    // Запись якоря: delete+add, НЕ update — смена класса доступа существующего item надёжна только
    // пересозданием. Так старые якоря (созданные QtKeychain с дефолтным WhenUnlocked) одним махом
    // получают AfterFirstUnlockThisDeviceOnly. kSecAttrSynchronizable НЕ ставим (= false, без iCloud).
    void writeAnchor(const QByteArray &blob)
    {
        CFMutableDictionaryRef del = anchorQuery();
        SecItemDelete(del); // errSecItemNotFound на свежем устройстве — норма
        CFRelease(del);

        CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                      reinterpret_cast<const UInt8 *>(blob.constData()), blob.size());
        CFMutableDictionaryRef add = anchorQuery();
        CFDictionarySetValue(add, kSecValueData, data);
        CFDictionarySetValue(add, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
        const OSStatus st = SecItemAdd(add, nullptr);
        CFRelease(add);
        CFRelease(data);
        if (st != errSecSuccess)
            qWarning() << "AVPN IdentityAnchor: keychain write failed, OSStatus" << int(st);
    }

} // namespace

void IdentityAnchor::updateFromStore()
{
    const StoreIdentity st = readStore();
    if (!st.has())
        return; // нечего сохранять (до первого запуска identity)
    // fpSeed живёт ТОЛЬКО в якоре (стор его не знает) — при перепаковке проносим из текущего блоба.
    const QByteArray current = readAnchor();
    QString u, p1, p2, t, err, seed;
    if (!current.isEmpty())
        unpackIdentity(current, u, p1, p2, t, err, &seed);
    const QByteArray blob = packIdentity(st.uuid, st.priv, st.pub, st.token, seed);
    if (blob == current)
        return; // якорь актуален — не дёргаем Keychain зря
    writeAnchor(blob);
}

QString IdentityAnchor::ensureFingerprintSeed()
{
    QString u, p1, p2, t, err, seed;
    const QByteArray current = readAnchor();
    if (!current.isEmpty() && unpackIdentity(current, u, p1, p2, t, err, &seed) && !seed.isEmpty())
        return seed;

    // Сида нет (свежее устройство / якорь старого билда) — генерим криптостойкий и пишем АТОМАРНО
    // с identity (тот же блоб, одна запись): потерять сид и device_id можно только вместе —
    // устройство тогда честно энроллится как новое, частичных состояний не бывает.
    const StoreIdentity st = readStore();
    if (!st.has())
        return {}; // identity ещё нет — блоб без uuid писать нельзя (unpack его отвергнет)

    QByteArray raw(32, 0);
    if (SecRandomCopyBytes(kSecRandomDefault, raw.size(),
                           reinterpret_cast<uint8_t *>(raw.data())) != errSecSuccess)
        return {};
    writeAnchor(packIdentity(st.uuid, st.priv, st.pub, st.token, QString::fromLatin1(raw.toHex())));

    // read-back: наружу уходит ТОЛЬКО реально легшее в Keychain (иначе после переустановки сид
    // сменился бы → ложный 403 владельцу на rehome-гейте). Не перечиталось → пусто → не слать.
    QString seed2;
    const QByteArray after = readAnchor();
    if (!after.isEmpty() && unpackIdentity(after, u, p1, p2, t, err, &seed2))
        return seed2;
    return {};
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
// device_fingerprint на не-iOS считается от железного якоря (DeviceFingerprint.cpp), не от сида.
QString IdentityAnchor::ensureFingerprintSeed() { return {}; }
} // namespace avpn

#endif

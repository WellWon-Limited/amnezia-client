// AVPN serviceEngine — платформенные якоря device_fingerprint (см. DeviceFingerprint.h). [IN-FORK]
#include "DeviceFingerprint.h"

#include "IdentityAnchor.h" // iOS: fpSeed из keychain-якоря identity

#if defined(Q_OS_ANDROID)
    #include <QCoreApplication>
    #include <QJniObject>
#endif
#if defined(Q_OS_MACOS)
    #include <CoreFoundation/CoreFoundation.h>
    #include <IOKit/IOKitLib.h>
#endif
#if defined(Q_OS_WIN)
    #include <QSettings>
#endif

namespace avpn {

QString DeviceFingerprint::platformAnchor()
{
#if defined(Q_OS_IOS)
    // Секретный fpSeed (та же keychain-запись, что identity; ThisDeviceOnly, read-back внутри).
    return IdentityAnchor::ensureFingerprintSeed();
#elif defined(Q_OS_ANDROID)
    // ANDROID_ID (SSAID): Settings.Secure.getString(resolver, "android_id") — per-app-signing-key,
    // без разрешений; сбрасывается только factory reset. JNI-паттерн — как AvpnShareBridge.
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid())
        return {};
    const QJniObject resolver =
        context.callObjectMethod("getContentResolver", "()Landroid/content/ContentResolver;");
    if (!resolver.isValid())
        return {};
    const QJniObject androidId = QJniObject::callStaticObjectMethod(
        "android/provider/Settings$Secure", "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
        resolver.object(),
        QJniObject::fromString(QStringLiteral("android_id")).object<jstring>());
    return androidId.isValid() ? androidId.toString() : QString();
#elif defined(Q_OS_MACOS)
    // IOPlatformUUID платы (IOPlatformExpertDevice) — IOKit-идиома как в DeviceModel.h.
    const io_service_t expert = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (expert == MACH_PORT_NULL)
        return {};
    QString result;
    CFTypeRef prop = IORegistryEntryCreateCFProperty(expert, CFSTR(kIOPlatformUUIDKey),
                                                     kCFAllocatorDefault, 0);
    if (prop) {
        if (CFGetTypeID(prop) == CFStringGetTypeID()) {
            char tmp[64];
            if (CFStringGetCString(static_cast<CFStringRef>(prop), tmp, sizeof(tmp),
                                   kCFStringEncodingUTF8))
                result = QString::fromUtf8(tmp).trimmed();
        }
        CFRelease(prop);
    }
    IOObjectRelease(expert);
    return result;
#elif defined(Q_OS_WIN)
    // MachineGuid: генерится установкой Windows, переживает переустановку приложения,
    // читается без прав администратора.
    const QSettings reg(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography"),
                        QSettings::NativeFormat);
    return reg.value(QStringLiteral("MachineGuid")).toString();
#else
    return {}; // linux и прочее: якоря нет — поле не шлём (сервер это допускает)
#endif
}

QString DeviceFingerprint::get()
{
    // Кешируем только УСПЕХ: транзиентный провал якоря (например, keychain-запись не удалась)
    // не должен заморозить «пусто» до перезапуска. Якоря детерминированы → значение от ретрая
    // не меняется, инвариант «одинаков во всех трёх запросах» сохраняется.
    static QString s_cached;
    if (!s_cached.isEmpty())
        return s_cached;
    const QString anchor = platformAnchor();
    if (anchor.isEmpty())
        return {};
    s_cached = hashAnchor(anchor);
    return s_cached;
}

} // namespace avpn

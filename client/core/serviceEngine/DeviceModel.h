// AVPN serviceEngine — человекочитаемое имя/ОС ТЕКУЩЕГО устройства для раздела «Устройства».
//
// Apple отдаёт только технический идентификатор; маркетинговое имя добываем нативно:
//   • macOS (вкл. Apple Silicon): дерево устройства IOKit `IODeviceTree:/product` → `product-name`
//     (даёт ровно «MacBook Pro» / «Mac mini» без таблицы — семейство в `Mac14,7` не закодировано).
//   • iOS: `hw.machine` (напр. «iPhone16,1») + КУРИРУЕМАЯ таблица → «iPhone 15 Pro».
//   • фолбэк (незнакомый id / не-Apple): hostname, затем QSysInfo::prettyProductName().
//
// HEADER-ONLY и подключается ТОЛЬКО из AvpnEngineQml.cpp — Enrollment.h остаётся «чистым QtCore»
// (его inline-парсеры тестируются автономно, без Apple-фреймворков). IOKit/CoreFoundation уже
// линкуются в десктоп/iOS-таргете — доп. правок CMake не нужно.
#pragma once

#include <QByteArray>
#include <QString>
#include <QSysInfo>
#include <QtGlobal>

#if defined(Q_OS_MACOS) || defined(Q_OS_IOS)
#include <sys/sysctl.h>
#endif
#if defined(Q_OS_MACOS)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#endif

namespace avpn {

// sysctl-строка по ключу (пусто при недоступности / не-Apple).
inline QString sysctlStr(const char *key)
{
#if defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    size_t len = 0;
    if (::sysctlbyname(key, nullptr, &len, nullptr, 0) != 0 || len == 0)
        return QString();
    QByteArray buf(static_cast<int>(len), '\0');
    if (::sysctlbyname(key, buf.data(), &len, nullptr, 0) != 0)
        return QString();
    return QString::fromLatin1(buf.constData()).trimmed();
#else
    Q_UNUSED(key);
    return QString();
#endif
}

#if defined(Q_OS_MACOS)
// Маркетинговое имя Mac из IOKit (IODeviceTree:/product → product-name). На Apple Silicon
// возвращает «MacBook Pro» / «Mac mini» / «iMac»; на старых Intel-узел может отсутствовать → пусто.
inline QString macProductMarketingName()
{
    io_registry_entry_t entry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/product");
    if (entry == MACH_PORT_NULL)
        return QString();

    QString result;
    CFTypeRef prop = IORegistryEntryCreateCFProperty(entry, CFSTR("product-name"), kCFAllocatorDefault, 0);
    if (prop) {
        if (CFGetTypeID(prop) == CFDataGetTypeID()) {
            // product-name хранится как NUL-terminated UTF-8 в CFData
            CFDataRef data = static_cast<CFDataRef>(prop);
            result = QString::fromUtf8(reinterpret_cast<const char *>(CFDataGetBytePtr(data))).trimmed();
        } else if (CFGetTypeID(prop) == CFStringGetTypeID()) {
            char tmp[256];
            if (CFStringGetCString(static_cast<CFStringRef>(prop), tmp, sizeof(tmp), kCFStringEncodingUTF8))
                result = QString::fromUtf8(tmp).trimmed();
        }
        CFRelease(prop);
    }
    IOObjectRelease(entry);
    return result;
}
#endif

// Курируемая таблица iPhone (hw.machine → маркетинговое имя). Покрывает актуальные линейки;
// при незнакомом id вернётся пусто → общий фолбэк. Обновлять при выходе новых моделей.
inline QString iosMarketingName(const QString &id)
{
    struct Map { const char *id; const char *name; };
    static const Map kPhones[] = {
        {"iPhone13,1", "iPhone 12 mini"},  {"iPhone13,2", "iPhone 12"},
        {"iPhone13,3", "iPhone 12 Pro"},   {"iPhone13,4", "iPhone 12 Pro Max"},
        {"iPhone14,4", "iPhone 13 mini"},  {"iPhone14,5", "iPhone 13"},
        {"iPhone14,2", "iPhone 13 Pro"},   {"iPhone14,3", "iPhone 13 Pro Max"},
        {"iPhone14,6", "iPhone SE (3rd gen)"},
        {"iPhone14,7", "iPhone 14"},       {"iPhone14,8", "iPhone 14 Plus"},
        {"iPhone15,2", "iPhone 14 Pro"},   {"iPhone15,3", "iPhone 14 Pro Max"},
        {"iPhone15,4", "iPhone 15"},       {"iPhone15,5", "iPhone 15 Plus"},
        {"iPhone16,1", "iPhone 15 Pro"},   {"iPhone16,2", "iPhone 15 Pro Max"},
        {"iPhone17,3", "iPhone 16"},       {"iPhone17,4", "iPhone 16 Plus"},
        {"iPhone17,1", "iPhone 16 Pro"},   {"iPhone17,2", "iPhone 16 Pro Max"},
        {"iPhone17,5", "iPhone 16e"},
    };
    for (const auto &m : kPhones) {
        if (id == QLatin1String(m.id))
            return QString::fromLatin1(m.name);
    }
    if (id.startsWith(QLatin1String("iPad")))
        return QStringLiteral("iPad");
    return QString();
}

// Имя текущего устройства: Apple → маркетинговая модель, иначе hostname → prettyProductName.
inline QString deviceMarketingName()
{
#if defined(Q_OS_MACOS)
    const QString mac = macProductMarketingName();
    if (!mac.isEmpty())
        return mac;
#elif defined(Q_OS_IOS)
    const QString ios = iosMarketingName(sysctlStr("hw.machine"));
    if (!ios.isEmpty())
        return ios;
#endif
    const QString host = QSysInfo::machineHostName();
    return host.isEmpty() ? QSysInfo::prettyProductName() : host;
}

// Версия ОС для подзаголовка: «macOS Sequoia (15.5)» / «iOS 17.5» и т.п.
inline QString deviceOsName()
{
    return QSysInfo::prettyProductName();
}

} // namespace avpn

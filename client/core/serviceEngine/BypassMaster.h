#pragma once

// AVPN «Доступ к сайтам РФ» (the RU split switch): the ONE decision of its effective value (owner 26.11.2026, AND-67
// temporary variant: off by default on Android 13+). Every reader - the engine, its tunnel control, the Doctor, the bench,
// QML through TribeEngine.bypassMasterOn - goes through bypassMasterOn(); no reader looks at the stored keys itself.
//
// Why a new key: up to 5.1.113 the QML store of the switch (QtCore Settings in PageConnectTribe) wrote its default true into
// AvpnBypass/masterOn on the first load of the main screen (Qt writes every missing key of a Settings object), so a stored
// true cannot tell "never touched" from "chose on". From now on the person's choice lives in AvpnBypass/masterOnChoice,
// written only by the switch (AvpnEngineQml::setBypassMasterOn); QML no longer stores the switch.
//
// Effective value: the choice if stored; else the legacy key stored as false -> off (only a person's action ever stored
// false - it is moved once into the choice key); else the platform default: off on Android API 33+, on elsewhere (iOS,
// macOS, Windows, Android below 33: unchanged). On Android 13+ a legacy true (the default Qt wrote, or a choice) reads as
// not chosen -> off; the person switches it on by hand, the same path and cost as today.

#include <QSettings>
#include <QString>
#include <QVariant>
#include <optional>

#if defined(Q_OS_ANDROID)
#include <QCoreApplication>
#endif

namespace avpn {

inline const QString kBypassMasterChoiceKey = QStringLiteral("AvpnBypass/masterOnChoice");
inline const QString kBypassMasterLegacyKey = QStringLiteral("AvpnBypass/masterOn");

// THE DEFAULT on Android 13 (API 33) and newer, for a person who never chose: true = off (owner's «ДА» of 26.11 to the
// AND-67 temporary variant: the 963 KB route list breaks the system's binder there), false = on as everywhere else. The
// owner has asked again whether it should stay on - this one constant is the answer; nothing else (tests included) needs
// to change with it. Android below 13 and every other platform are on whatever it says.
inline constexpr bool kBypassMasterOffByDefaultOnAndroid13 = true;

inline bool bypassMasterDefaultOff(bool android, int sdkVersion)
{
    return kBypassMasterOffByDefaultOnAndroid13 && android && sdkVersion >= 33;
}

inline bool bypassMasterEffective(std::optional<bool> choice, std::optional<bool> legacy, bool defaultOff)
{
    if (choice.has_value())
        return *choice;
    if (legacy.has_value() && !*legacy)
        return false;
    return !defaultOff;
}

// The legacy false is the person's choice: moved once into the choice key (the engine's start).
inline bool bypassMasterMigratesLegacy(std::optional<bool> choice, std::optional<bool> legacy)
{
    return !choice.has_value() && legacy.has_value() && !*legacy;
}

inline std::optional<bool> storedBool(const QSettings &s, const QString &key)
{
    if (!s.contains(key))
        return std::nullopt;
    return s.value(key).toBool();
}

inline bool bypassMasterDefaultOffHere()
{
#if defined(Q_OS_ANDROID)
    return bypassMasterDefaultOff(true, QNativeInterface::QAndroidApplication::sdkVersion());
#else
    return false;
#endif
}

inline bool bypassMasterOn(const QSettings &s)
{
    return bypassMasterEffective(storedBool(s, kBypassMasterChoiceKey), storedBool(s, kBypassMasterLegacyKey),
                                 bypassMasterDefaultOffHere());
}

inline bool bypassMasterOn()
{
    const QSettings s;
    return bypassMasterOn(s);
}

} // namespace avpn

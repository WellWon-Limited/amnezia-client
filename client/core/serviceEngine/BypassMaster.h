#pragma once

// AVPN «Доступ к сайтам РФ» (the RU split switch): the ONE decision of its effective value and of where it is available
// (owner 26.11.2026, AND-67). Every reader - the engine, its tunnel control, the Doctor, the bench, QML through
// TribeEngine.bypassMasterOn / bypassMasterAvailable - goes through bypassMasterOn() and bypassMasterUnavailableHere();
// no reader looks at the stored keys itself. Where it is available is the route budget's zero case (RouteBudget.h:
// N = 0 on Android 13+ = unavailable; the compiled N is 0 until the phone measurement).
//
// Why a new key: up to 5.1.113 the QML store of the switch (QtCore Settings in PageConnectTribe) wrote its default true into
// AvpnBypass/masterOn on the first load of the main screen (Qt writes every missing key of a Settings object), so a stored
// true cannot tell "never touched" from "chose on". From now on the person's choice lives in AvpnBypass/masterOnChoice,
// written only by the switch (AvpnEngineQml::setBypassMasterOn); QML no longer stores the switch.
//
// Effective value: off where the route budget is 0 (the mode is unavailable), whatever is stored - the stored keys stay
// untouched there and apply again once it is not. Elsewhere: the choice if stored; else the legacy key stored as false
// -> off (only a person's action ever stored false - it is moved once into the choice key); else the platform default:
// off on Android API 33+ (kBypassMasterOffByDefaultOnAndroid13), on elsewhere (iOS, macOS, Windows, Android below 33:
// unchanged). On Android 13+ a legacy true (the default Qt wrote, or a choice in 141) reads as not chosen -> off.

#include "RouteBudget.h"

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

// THE DEFAULT on Android 13 (API 33) and newer, for a person who never chose: true = off (owner 26.11: kept off until the
// phone measurement of the route budget), false = on as everywhere else. One of the two constants the owner flips after
// the measurement - the other is kAndroidBypassRouteBudget (RouteBudget.h). Android below 13 and every other platform
// are on whatever it says.
inline constexpr bool kBypassMasterOffByDefaultOnAndroid13 = true;

// Unavailable = the platform's route budget is 0 (RouteBudget.h; unlimited off Android and on Android 12 and lower).
inline bool bypassMasterUnavailable(int routeBudget)
{
    return routeBudget == 0;
}

inline bool bypassMasterDefaultOff(bool android, int sdkVersion)
{
    return kBypassMasterOffByDefaultOnAndroid13 && androidRoutesLimited(android, sdkVersion);
}

inline bool bypassMasterEffective(std::optional<bool> choice, std::optional<bool> legacy, bool unavailable,
                                  bool defaultOff)
{
    if (unavailable)
        return false;
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

// This device: the engine and the UI (TribeEngine.bypassMasterAvailable) ask the same predicate.
inline bool bypassMasterUnavailableHere()
{
    return bypassMasterUnavailable(bypassRouteBudgetHere());
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
                                 bypassMasterUnavailableHere(), bypassMasterDefaultOffHere());
}

inline bool bypassMasterOn()
{
    const QSettings s;
    return bypassMasterOn(s);
}

} // namespace avpn

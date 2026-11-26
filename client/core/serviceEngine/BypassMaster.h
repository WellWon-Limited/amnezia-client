#pragma once

// AVPN «Доступ к сайтам РФ» (the RU split switch): the ONE decision of its effective value and of where it is available
// (owner 26.11.2026, AND-67: unavailable on Android 13+ in this release). Every reader - the engine, its tunnel control,
// the Doctor, the bench, QML through TribeEngine.bypassMasterOn / bypassMasterAvailable - goes through bypassMasterOn() and
// bypassMasterUnavailableHere(); no reader looks at the stored keys itself.
//
// Why a new key: up to 5.1.113 the QML store of the switch (QtCore Settings in PageConnectTribe) wrote its default true into
// AvpnBypass/masterOn on the first load of the main screen (Qt writes every missing key of a Settings object), so a stored
// true cannot tell "never touched" from "chose on". From now on the person's choice lives in AvpnBypass/masterOnChoice,
// written only by the switch (AvpnEngineQml::setBypassMasterOn); QML no longer stores the switch.
//
// Effective value: off where the platform cannot apply the split (Android API 33+ in this release), whatever is stored -
// the stored keys stay untouched there and apply again once it can. Elsewhere: the choice if stored; else the legacy key
// stored as false -> off (only a person's action ever stored false - it is moved once into the choice key); else on (iOS,
// macOS, Windows, Android below 33: unchanged).

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

// THE CAPABILITY on Android 13 (API 33) and newer: true = the mode is unavailable there in this release (owner 26.11,
// after the phone and the emulator: with it on, 0 of 3 connects each - the route list overruns the system's binder
// transaction limit, 63-88 FAILED BINDER TRANSACTION per connect, a tunnel build of 38-42 s; the limit is the system's, so
// no Android 13+ device can rely on it until AND-67 moves the split into the tunnel core). It replaces the «off by
// default» of 1d79b2a98: one boundary, one constant. When it turns false the stored choice applies again and a person who
// never chose gets the default of every other platform (on) - a different default then is a new decision. Android below
// 13 and every other platform are available whatever it says.
inline constexpr bool kBypassMasterUnavailableOnAndroid13 = true;

inline bool bypassMasterUnavailable(bool android, int sdkVersion)
{
    return kBypassMasterUnavailableOnAndroid13 && android && sdkVersion >= 33;
}

inline bool bypassMasterEffective(std::optional<bool> choice, std::optional<bool> legacy, bool unavailable)
{
    if (unavailable)
        return false;
    if (choice.has_value())
        return *choice;
    if (legacy.has_value() && !*legacy)
        return false;
    return true;
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
#if defined(Q_OS_ANDROID)
    return bypassMasterUnavailable(true, QNativeInterface::QAndroidApplication::sdkVersion());
#else
    return false;
#endif
}

inline bool bypassMasterOn(const QSettings &s)
{
    return bypassMasterEffective(storedBool(s, kBypassMasterChoiceKey), storedBool(s, kBypassMasterLegacyKey),
                                 bypassMasterUnavailableHere());
}

inline bool bypassMasterOn()
{
    const QSettings s;
    return bypassMasterOn(s);
}

} // namespace avpn

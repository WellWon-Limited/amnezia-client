// AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the platform's route budget of the RU split - how many
// prefixes the system may be handed as split routes. [header-only, QtCore]
//
// Why: the mode hands Android 13+ one excludeRoute per prefix (10,841 with the full RU list); the parcel of that build
// is ~963 KB and the system then delivers the VPN network's LinkProperties to every app with a connectivity callback.
// Measured 26.11 (phone Android 16, emulator Android 15): 0 of 3 connects with it on, 63-88 FAILED BINDER TRANSACTION
// per connect, tunnel builds of 38-42 s, another app crashed. Off: 3 of 3 in 1.6-2.6 s. The failure is a function of
// the route count, so a smaller list (a SUBSET - RouteReduce.h never widens) can work; a left-out RU network simply goes
// through the VPN, as with the mode off.
//
// The budget, ONE function for the engine (the seed), the service's route build (the seed's counts in its log) and the
// UI (TribeEngine.bypassMasterAvailable, BypassMaster.h):
//   - unlimited off Android and on Android 12 and lower (exactly the behaviour before; those versions apply the
//     excluded routes as their complement and were never measured to fail);
//   - N on Android 13+: the compiled kAndroidBypassRouteBudget, overridden by the server-published client number
//     android_bypass_route_budget (/v1/config numbers; absent = the compiled value; clamped to 0..20000, a
//     non-finite value = the compiled one), overridden in a developer build only by a control file (see below).
//   - N = 0 means the mode is unavailable there (BypassMaster.h: the switch is disabled and off, with a caption).
#pragma once

#include <QString>

#include <atomic>
#include <climits>
#include <cmath>
#include <optional>

#if defined(Q_OS_ANDROID)
#include <QCoreApplication>
#endif
#ifdef AVPN_DEV_TOOLS
#include <QFile>
#include <QStandardPaths>
#endif

namespace avpn {

// THE N on Android 13 (API 33) and newer, compiled. 0 = the mode is unavailable there (this release until the phone
// measurement picks a number; the owner's decision, 26.11).
inline constexpr int kAndroidBypassRouteBudget = 0;

inline constexpr int kRouteBudgetUnlimited = -1;
inline constexpr int kRouteBudgetCeiling = 20000;
inline const QString kRouteBudgetNumberKey = QStringLiteral("android_bypass_route_budget");

// The one boundary of the Android limits (the budget here, the switch's default in BypassMaster.h).
inline bool androidRoutesLimited(bool android, int sdkVersion)
{
    return android && sdkVersion >= 33;
}

inline int clampRouteBudget(double v, int fallback)
{
    if (!std::isfinite(v))
        return fallback;
    if (v < 0)
        return 0;
    if (v > kRouteBudgetCeiling)
        return kRouteBudgetCeiling;
    return int(v);
}

// server: the published client number (nullopt = absent); dev: a developer build's control file (nullopt = none).
inline int bypassRouteBudget(bool android, int sdkVersion, std::optional<double> server, std::optional<int> dev)
{
    if (!androidRoutesLimited(android, sdkVersion))
        return kRouteBudgetUnlimited;
    if (dev.has_value())
        return clampRouteBudget(double(*dev), kAndroidBypassRouteBudget);
    if (server.has_value())
        return clampRouteBudget(*server, kAndroidBypassRouteBudget);
    return kAndroidBypassRouteBudget;
}

// The process's inputs of the budget: the engine sets the server number when the remote config is applied and the
// developer override at its start and at every seed; every reader asks bypassRouteBudgetHere(). The seed's counts are
// kept for the session config (the service logs them at each tunnel build).
class RouteBudgetInputs
{
public:
    static void setServer(std::optional<double> v) { server().store(v.has_value() ? *v : NAN); }
    static std::optional<double> serverValue()
    {
        const double v = server().load();
        return std::isnan(v) ? std::nullopt : std::optional<double>(v);
    }
    static void setDev(std::optional<int> v) { dev().store(v.has_value() ? *v : INT_MIN); }
    static std::optional<int> devValue()
    {
        const int v = dev().load();
        return v == INT_MIN ? std::nullopt : std::optional<int>(v);
    }
    static void setLastSeed(int total, int budget)
    {
        lastTotal().store(total);
        lastBudget().store(budget);
    }
    static int lastSeedTotal() { return lastTotal().load(); }
    static int lastSeedBudget() { return lastBudget().load(); }

private:
    static std::atomic<double> &server() { static std::atomic<double> v{NAN}; return v; }
    static std::atomic<int> &dev() { static std::atomic<int> v{INT_MIN}; return v; }
    static std::atomic<int> &lastTotal() { static std::atomic<int> v{-1}; return v; }
    static std::atomic<int> &lastBudget() { static std::atomic<int> v{kRouteBudgetUnlimited}; return v; }
};

#ifdef AVPN_DEV_TOOLS
// Developer build only (a release build compiles none of this): <app files dir>/tribe-dev-route-budget holds one
// integer N that overrides the compiled and the server value - set over adb without a rebuild:
//   adb shell run-as com.tribevpn.client sh -c 'echo 1500 > files/tribe-dev-route-budget'   (rm it = no override)
// (QStandardPaths AppDataLocation on Android = /data/user/0/<pkg>/files, reached through run-as of the debuggable
// developer build.) Read at the engine's start and before every seed (each connect).
inline std::optional<int> readDevRouteBudget()
{
    QFile f(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
            + QStringLiteral("/tribe-dev-route-budget"));
    if (!f.open(QIODevice::ReadOnly))
        return std::nullopt;
    bool ok = false;
    const int n = QString::fromLatin1(f.read(32)).trimmed().toInt(&ok);
    return ok ? std::optional<int>(n) : std::nullopt;
}
#endif

// This device's budget.
inline int bypassRouteBudgetHere()
{
#if defined(Q_OS_ANDROID)
    return bypassRouteBudget(true, QNativeInterface::QAndroidApplication::sdkVersion(), RouteBudgetInputs::serverValue(),
                             RouteBudgetInputs::devValue());
#else
    return bypassRouteBudget(false, 0, RouteBudgetInputs::serverValue(), RouteBudgetInputs::devValue());
#endif
}

} // namespace avpn

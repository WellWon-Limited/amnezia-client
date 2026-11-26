// AVPN «Доступ к сайтам РФ», Android layer 1 (apps, owner 26.11.2026): «Russian services go directly» for apps. On a
// phone the banks, marketplaces and the like are apps; Android excludes an app from the VPN exactly and at no route
// cost (VpnService.Builder.addDisallowedApplication): it uses the network directly, sees no VPN on its own network (no
// "turn off your VPN" refusals) and never sees our exit addresses. The list rides upstream's per-app split plumbing:
// the engine stores it as upstream's "all apps except these" (AppsRouteMode::VpnAllExceptApps), the upstream config
// builder (VpnConnection::appendSplitTunnelingConfig) puts it into the session config as appSplitTunnelType 2 +
// splitTunnelApps, and the service's Protocol.buildVpnInterface excludes the installed ones (one not installed is
// skipped). Layer 2 (sites in a browser) is the route list within the budget (RouteBudget.h, RouteReduce.h).
// [header-only, QtCore; pure] Tests: tests/route_budget_check.cpp.
#pragma once

#include "ru_apps.h"

#include <QSet>
#include <QString>
#include <QStringList>

namespace avpn {

inline const QString kTribeAndroidPackage = QStringLiteral("com.tribevpn.client");

inline QStringList ruAppPackages()
{
    QStringList l;
    for (const char *p : RU_APP_PACKAGES)
        l << QString::fromLatin1(p);
    return l;
}

inline QStringList ruAppNever()
{
    QStringList l;
    for (const char *p : RU_APP_NEVER)
        l << QString::fromLatin1(p);
    return l;
}

// The apps the session config excludes from the tunnel: none while the mode is off (exactly as before); else the listed
// ones without the never-list (browsers: a person must still open blocked sites in them) and without our own package
// (its API and lease traffic must use the tunnel), each once, sorted (a stable config).
inline QStringList bypassAppsForConfig(bool modeOn, const QStringList &listed, const QStringList &never,
                                       const QString &ownPackage)
{
    if (!modeOn)
        return {};
    const QSet<QString> skip(never.cbegin(), never.cend());
    QSet<QString> seen;
    QStringList out;
    for (const QString &p : listed) {
        const QString pkg = p.trimmed();
        if (pkg.isEmpty() || pkg == ownPackage || skip.contains(pkg) || seen.contains(pkg))
            continue;
        seen.insert(pkg);
        out << pkg;
    }
    out.sort();
    return out;
}

} // namespace avpn

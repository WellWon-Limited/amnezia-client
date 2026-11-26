#pragma once

// AVPN «Доступ к сайтам РФ» (the RU split switch): the ONE reading of its value (owner 26.11.2026). Every reader - the
// engine, its tunnel control, the Doctor, the bench, QML through TribeEngine.bypassMasterOn - goes through
// bypassMasterOn(); no reader looks at the stored key itself, and the one writer is AvpnEngineQml::setBypassMasterOn (QML
// no longer stores the switch).
//
// The value: the stored AvpnBypass/masterOn, on when absent - on every platform. On Android the mode is always available:
// its apps layer works on every version (RuApps.h), and the platform's route budget (RouteBudget.h) only decides how many
// site routes go with it (0 on Android 13+ = no routes, the apps still go directly). A person upgrading from 141 keeps the
// stored value: on = the apps layer + the routes of the budget; off = off.
// History: 15210ecdf..e8a24fa0a had an "unavailable" state and an off-by-default on Android 13+ with an explicit-choice key
// (AvpnBypass/masterOnChoice - Qt's store had written the default true, so a stored true could not tell "never touched"
// from "chose on"). With the default on everywhere that key said nothing the stored value does not: removed (a
// masterOnChoice left by a test build is ignored; the switch always mirrored it into masterOn).

#include "RouteBudget.h"

#include <QSettings>
#include <QString>
#include <QVariant>
#include <optional>

namespace avpn {

inline const QString kBypassMasterKey = QStringLiteral("AvpnBypass/masterOn");

inline std::optional<bool> storedBool(const QSettings &s, const QString &key)
{
    if (!s.contains(key))
        return std::nullopt;
    return s.value(key).toBool();
}

// absent = on (the default of every platform)
inline bool bypassMasterValue(std::optional<bool> stored)
{
    return stored.value_or(true);
}

inline bool bypassMasterOn(const QSettings &s)
{
    return bypassMasterValue(storedBool(s, kBypassMasterKey));
}

inline bool bypassMasterOn()
{
    const QSettings s;
    return bypassMasterOn(s);
}

// The mode's SITE routes are on: the switch, and a route budget that is not 0 (RouteBudget.h: 0 only on Android 13+ at
// N = 0, where the apps layer alone works). The one predicate of everything that acts on the site routes (round 59
// review, finding 2): the seed (AvpnEngineQml::applyRuBypassSplit), the tunnel's split and DNS decision
// (VpnConnectionTunnelControl::up), the RU-sites check (RuSplitSentinel) and the Doctor's RU stages. Off Android and on
// Android 12 and lower the budget is unlimited, so this is the switch itself.
inline bool bypassSitesOn(bool modeOn, int routeBudget)
{
    return modeOn && routeBudget != 0;
}

inline bool bypassSitesOn(const QSettings &s)
{
    return bypassSitesOn(bypassMasterOn(s), bypassRouteBudgetHere());
}

inline bool bypassSitesOn()
{
    const QSettings s;
    return bypassSitesOn(s);
}

} // namespace avpn

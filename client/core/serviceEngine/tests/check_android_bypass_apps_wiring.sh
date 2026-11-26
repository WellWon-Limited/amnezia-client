#!/usr/bin/env bash
# AVPN «Доступ к сайтам РФ» on Android (owner 26.11.2026): two layers of one meaning, «Russian services go directly».
# Layer 1 - apps: the compiled list (ru_apps.h) excluded from the tunnel while the mode is on, through upstream's
# per-app split plumbing; layer 2 - sites: the route list cut to the platform's route budget (RouteBudget.h,
# RouteReduce.h). The rules are pure and tested by behaviour (build_route_budget.sh); this checks the wiring:
#   A1  the list in ru_apps.h equals the manifest's <queries> packages (package visibility, API 30+), sorted; never our
#       own package, never a package of the never-list (browsers); no QUERY_ALL_PACKAGES;
#   A2  the engine stores the list as upstream's "all apps except these" only on Android, before the sites' early return
#       (the mode off clears it), from bypassAppsForConfig;
#   A3  the upstream config builder still carries it (appSplitTunnelType + splitTunnelApps) and, on Android, the seed's
#       counts for the service's log;
#   A4  the service excludes the installed ones and skips a missing one (NameNotFoundException), for every protocol
#       that builds the interface (AmneziaWG, WireGuard, Xray, OpenVPN); one log line per build, counts only;
#   A5  the seed cuts the RU part to the budget with an empty priority list, never the fixed groups, and a new budget
#       is a new seed;
#   A6  one ceiling of split routes for the engine's budget and the service's own guard (round 58 review, findings 1+6):
#       the two constants are equal, the budget is clamped to it, and on Android 13+ the service applies none of a
#       config's split routes above it (a saved config of an older build started without the app);
#   A7  an app counts as excluded only if the package manager knows it (the phone counted 286 of 286 with 8 installed).
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }

APPS="$HERE/../ru_apps.h"
MAN="$CLIENT/android/AndroidManifest.xml"
ENG="$HERE/../AvpnEngineQml.cpp"
VC="$CLIENT/vpnConnection.cpp"
PROTO="$CLIENT/android/protocolApi/src/main/kotlin/Protocol.kt"

# ---- A1 ----
listed="$(awk '/RU_APP_PACKAGES\[\] = \{/ { on = 1; next } on && /^\};/ { exit } on' "$APPS" | tr -d ' ",' | sed '/^$/d')"
never="$(awk '/RU_APP_NEVER\[\] = \{/ { on = 1; next } on && /^\};/ { exit } on' "$APPS" | tr -d ' ",' | sed '/^$/d')"
queries="$(awk '/avpn-ru-apps-queries:begin/ { on = 1; next } /avpn-ru-apps-queries:end/ { exit } on' "$MAN" \
    | sed -n 's/.*<package android:name="\([^"]*\)".*/\1/p')"
[ -n "$listed" ] || bad "A1: the compiled app list is empty"
[ "$listed" = "$queries" ] || bad "A1: ru_apps.h and the manifest's <queries> differ (rerun client/android/tools/gen_ru_apps.py)"
[ "$listed" = "$(printf '%s\n' "$listed" | LC_ALL=C sort)" ] || bad "A1: the app list must be sorted"
printf '%s\n' "$listed" | grep -qxF 'com.tribevpn.client' && bad "A1: our own package must never be excluded"
for b in $never; do printf '%s\n' "$listed" | grep -qxF "$b" && bad "A1: $b is on the never-list and in the list"; done
printf '%s\n' "$never" | grep -qxF 'com.android.chrome' || bad "A1: the never-list must keep the browsers"
grep -v '^[[:space:]]*<!--' "$MAN" | grep -q 'android.permission.QUERY_ALL_PACKAGES' \
    && bad "A1: QUERY_ALL_PACKAGES is back (the listed packages are visible through <queries>)"

# ---- A2 ----
ap="$(body "$ENG" 'void AvpnEngineQml::applyRuBypassApps(bool masterOn)')"
has "$ap" '#if defined(Q_OS_ANDROID)' || bad "A2: the app layer must be Android only"
has "$ap" 'avpn::bypassAppsForConfig(masterOn, avpn::ruAppPackages(), avpn::ruAppNever(), own);' \
    || bad "A2: the stored list must come from bypassAppsForConfig over the compiled list"
has "$ap" 'm_store->setVpnApps(AppsRouteMode::VpnAllExceptApps, v);' \
    && has "$ap" 'm_store->setAppsRouteMode(AppsRouteMode::VpnAllExceptApps);' \
    && has "$ap" 'm_store->setAppsSplitTunnelingEnabled(on);' \
    || bad "A2: the list must be stored as upstream's all-apps-except-these split"
split="$(body "$ENG" 'void AvpnEngineQml::applyRuBypassSplit()')"
a=$(printf '%s\n' "$split" | grep -nF 'applyRuBypassApps(masterOn);' | head -1 | cut -d: -f1)
r=$(printf '%s\n' "$split" | grep -nF 'if (!sitesOn && !liAutoOn) {' | head -1 | cut -d: -f1)
if [ -z "$a" ] || [ -z "$r" ] || [ "$a" -ge "$r" ]; then bad "A2: the app layer must be applied before the sites' early return"; fi

# ---- A3 ----
vc="$(code "$VC")"
has "$vc" 'm_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);' \
    && has "$vc" 'm_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);' \
    || bad "A3: the upstream config builder must carry the per-app split"
has "$vc" 'm_vpnConfiguration.insert(QStringLiteral("avpnBypassRoutesTotal"), avpn::RouteBudgetInputs::lastSeedTotal());' \
    && has "$vc" 'm_vpnConfiguration.insert(QStringLiteral("avpnBypassRouteBudget"), avpn::RouteBudgetInputs::lastSeedBudget());' \
    || bad "A3: the session config must carry the seed's counts for the service's log"

# ---- A4 ----
pk="$(code "$PROTO")"
flat="$(printf '%s\n' "$pk" | tr -s ' \n' ' ')"
has "$flat" 'try { vpnBuilder.addDisallowedApplication(app) appsExcluded++ } catch (e: PackageManager.NameNotFoundException) {' \
    || bad "A4: a listed app that is not installed must be skipped, not fail the build"
printf '%s\n' "$pk" | grep -F 'Log.i(TAG, "bypass apps excluded=' > /dev/null || bad "A4: one log line per build"
printf '%s\n' "$pk" | grep -A4 -F 'Log.i(TAG, "bypass apps excluded=' | grep -qE '\$app\b|\$\{app\}|joinToString' \
    && bad "A4: the build's log line must hold counts only"
for f in "$CLIENT/android/awg/src/main/kotlin/Awg.kt" \
         "$CLIENT/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt" \
         "$CLIENT/android/xray/src/main/kotlin/Xray.kt" \
         "$CLIENT/android/openvpn/src/main/kotlin/org/amnezia/vpn/protocol/openvpn/OpenVpn.kt"; do
    code "$f" | grep -q 'configAppSplitTunneling(' || bad "A4: $(basename "$f") must apply the per-app split"
done
code "$CLIENT/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt" \
    | grep -A3 'override fun reconnectVpn' | grep -qF 'start(config, vpnBuilder, protect, true)' \
    || bad "A4: the in-place rebuild must build the interface (and its split) again"

# ---- A5 ----
has "$split" 'const avpn::RouteReduction cut = avpn::reduceRoutes(ruPart, ruBudget, /*priority=*/{});' \
    || bad "A5: the seed must cut the RU part to the budget (priority hook empty)"
has "$split" '(avpn::routeInsideAny(it.key(), fixedCover) ? fixedPart : ruPart) << it.key();' \
    || bad "A5: the fixed groups must never be cut"
has "$split" '+ QStringLiteral("|budget=") + QString::number(routeBudget);' || bad "A5: a new budget must be a new seed"
has "$split" 'if (routeBudget < 0) {' || bad "A5: an unlimited budget must leave the list as before"

# ---- A6 ----
PC="$CLIENT/android/protocolApi/src/main/kotlin/ProtocolConfig.kt"
RB="$HERE/../RouteBudget.h"
cpp=$(code "$RB" | sed -n 's/^inline constexpr int kAndroidSplitRouteCeiling = \([0-9][0-9]*\);.*/\1/p')
kt=$(code "$PC" | sed -n 's/^const val ANDROID_SPLIT_ROUTE_CEILING = \([0-9][0-9]*\).*/\1/p')
[ -n "$cpp" ] && [ -n "$kt" ] && [ "$cpp" = "$kt" ] || bad "A6: the engine's and the service's ceilings differ ($cpp vs $kt)"
rbf="$(code "$RB" | tr -s ' \n' ' ')"
has "$rbf" 'if (!std::isfinite(v) || v < 0) return fallback; if (v > kAndroidSplitRouteCeiling) return kAndroidSplitRouteCeiling;' \
    || bad "A6: a negative or non-finite value must be the compiled one, a larger one the ceiling"
pcf="$(code "$PC" | tr -s ' \n' ' ')"
has "$pcf" '} else if (excludedAddresses.isNotEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && excludedAddresses.size > ANDROID_SPLIT_ROUTE_CEILING) {' \
    && has "$pcf" 'excludedAddresses.clear()' \
    || bad "A6: the service must apply none of a config's split routes above the ceiling on Android 13+"

# ---- A7 ----
has "$flat" 'if (!isInstalled(app)) continue' && has "$flat" 'context.packageManager.getApplicationInfo(packageName, 0)' \
    || bad "A7: only an installed app may count as excluded"

[ "$fail" -eq 0 ] && echo "android bypass apps wiring: OK"
exit "$fail"

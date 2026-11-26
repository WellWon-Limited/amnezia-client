#!/bin/bash
# AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the switch's value has ONE reading (BypassMaster.h: the stored
# AvpnBypass/masterOn, on when absent, on every platform); where the mode's sites go directly is the route budget's
# (RouteBudget.h). The rules are pure and tested by behaviour (build_bypass_master.sh, build_route_budget.sh). What is
# checked here is that nothing goes around them - each line fails if a reader, a store or a second state comes back:
#   B1  no code outside BypassMaster.h names the stored key, and the explicit-choice key is gone everywhere;
#   B2  the key is written only by the switch (setBypassMasterOn) and the A/B bench's exact restore;
#   B3  every C++ reader asks avpn::bypassMasterOn (the engine and its tunnel control);
#   B4  QML no longer stores the switch: no QtCore Settings of the AvpnBypass category anywhere, and the main screen reads
#       TribeEngine.bypassMasterOn and writes only through TribeEngine.setBypassMasterOn; the engine notifies it;
#   B5  no "unavailable" state and no Android-only default are left (the mode is always available; off-by-default gone);
#   B6  the onboarding card that states the switch is on is shown only while the value is on;
#   B7  the main screen's switch is an ordinary one, and its secondary line says what the mode does where the sites do
#       not go directly (TribeEngine.bypassSitesDirect = the route budget is not 0; RU source, EN/ES translated);
#   B8  the switch's write and the A/B bench are never refused; the seed gives the sites only with a budget;
#   B9  (round 59 review, finding 2) ONE predicate for the site routes - bypassSitesOn - in every consumer: the seed,
#       VpnConnectionTunnelControl::up (split and DNS), the RU-sites check and the Doctor's two RU stages.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
count() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }

ENG="$HERE/../AvpnEngineQml.cpp"
HDR="$HERE/../AvpnEngineQml.h"
VTC="$HERE/../VpnConnectionTunnelControl.cpp"
PAGE="$CLIENT/ui/qml/Tribe/Pages/PageConnectTribe.qml"

# ---- B1 ----
hits=$(cd "$CLIENT" && grep -rlE '"AvpnBypass/masterOn(Choice)?"' --include='*.cpp' --include='*.h' --include='*.mm' \
       --include='*.qml' --include='*.kt' --include='*.swift' --include='*.js' . 2>/dev/null \
       | grep -vE '^\./(3rd|core/serviceEngine/tests)/' | grep -vxF './core/serviceEngine/BypassMaster.h' || true)
for f in $hits; do
    code "$CLIENT/$f" | grep -qE '"AvpnBypass/masterOn(Choice)?"' && bad "B1: $f names a stored key of the switch"
done
grep -rlE 'kBypassMasterChoiceKey|kBypassMasterLegacyKey|bypassMasterMigratesLegacy' --include='*.cpp' --include='*.h' \
    "$CLIENT/core" "$CLIENT/platforms" "$CLIENT/ui" 2>/dev/null | grep -v '/tests/' | grep -q . \
    && bad "B1: the explicit-choice key or its migration is back"

# ---- B2 ----
eng="$(code "$ENG")"
n=$(count "$eng" 'setValue(avpn::kBypassMasterKey')
[ "$n" -eq 1 ] || bad "B2: the key is written in $n places, expected 1 (the switch)"
has "$(body "$ENG" 'void AvpnEngineQml::setBypassMasterOn(bool on)')" 's.setValue(avpn::kBypassMasterKey, on);' \
    || bad "B2: the switch must write the key"
rest="$(body "$ENG" 'void AvpnEngineQml::abRestoreBypassMaster()')"
has "$rest" 'put(avpn::kBypassMasterKey, m_abOrigStored);' || bad "B2: the bench must put the key back exactly"
[ "$(count "$eng" 'abRestoreBypassMaster();')" -eq 2 ] || bad "B2: both ends of the bench must restore through abRestoreBypassMaster"

# ---- B3 ----
[ "$(count "$eng" 'avpn::bypassMasterOn(')" -ge 6 ] || bad "B3: the engine's readers must ask avpn::bypassMasterOn"
has "$(code "$VTC")" 'const bool sitesOn = avpn::bypassSitesOn(s);' || bad "B3: the tunnel control must ask avpn::bypassSitesOn"

# ---- B4 ----
stores=$(cd "$CLIENT/ui/qml" && grep -rlE 'category:[[:space:]]*"AvpnBypass"' --include='*.qml' . || true)
[ -z "$stores" ] || bad "B4: a QML Settings store of the switch is back: $stores"
page="$(code "$PAGE")"
has "$page" 'import QtCore' && bad "B4: the main screen imports QtCore (its Settings stored the switch)"
has "$page" 'readonly property bool ruAccessOn: hasEngine ? TribeEngine.bypassMasterOn === true : true' \
    || bad "B4: the main screen must show the engine's value"
has "$page" 'if (root.hasEngine) TribeEngine.setBypassMasterOn(checked)' || bad "B4: the switch must write through the engine"
printf '%s\n' "$page" | grep -qE 'masterOn[[:space:]]*=' && bad "B4: the main screen assigns a masterOn of its own"
has "$(code "$HDR")" 'Q_PROPERTY(bool bypassMasterOn READ bypassMasterOn NOTIFY bypassMasterOnChanged)' \
    || bad "B4: the engine must expose the value with a notify"
has "$(body "$ENG" 'void AvpnEngineQml::setBypassMasterOn(bool on)')" 'emit bypassMasterOnChanged();' \
    || bad "B4: the switch's write must notify QML"

# ---- B5 ---- one value, no second state
bm="$(code "$HERE/../BypassMaster.h")"
bmf="$(printf '%s\n' "$bm" | tr -s ' \n' ' ')"
has "$bmf" 'inline bool bypassMasterValue(std::optional<bool> stored) { return stored.value_or(true); }' \
    || bad "B5: the value must be the stored key, on when absent"
has "$bmf" 'inline bool bypassMasterOn(const QSettings &s) { return bypassMasterValue(storedBool(s, kBypassMasterKey)); }' \
    || bad "B5: the store reading must be that value"
printf '%s\n' "$bm" | grep -qE 'Unavailable|DefaultOff|OffByDefault|sdkVersion|Q_OS_ANDROID' \
    && bad "B5: an Android-only state or default is back in the switch's value"
grep -rqE 'bypassMasterUnavailable|bypassMasterAvailable|bypassMasterDefaultOff' --include='*.cpp' --include='*.h' \
    --include='*.qml' "$CLIENT/core" "$CLIENT/ui" 2>/dev/null && bad "B5: the unavailable state is referenced again"

# ---- B6 ---- the onboarding card that says «Доступ к сайтам РФ включён» shows only while the effective value is on
onb="$(code "$CLIENT/ui/qml/Tribe/Pages/PageOnboardingTribe.qml")"
printf '%s\n' "$onb" | grep -A1 -F '                Rectangle {' \
    | grep -qF 'visible: !root.hasEngine || (TribeEngine.bypassMasterOn === true && TribeEngine.bypassSitesDirect === true)' \
    || bad "B6: the onboarding's «включён» card must follow the switch AND the applied site routes (round 59 review)"

# ---- B7 ---- an ordinary switch; the caption where the sites do not go directly
has "$(code "$HDR")" 'Q_PROPERTY(bool bypassSitesDirect READ bypassSitesDirect NOTIFY bypassMasterOnChanged)' \
    || bad "B7: the engine must expose whether the sites go directly"
has "$(body "$ENG" 'bool AvpnEngineQml::bypassSitesDirect() const')" 'return avpn::bypassRouteBudgetHere() != 0;' \
    || bad "B7: the sites go directly unless the route budget is 0"
has "$page" 'readonly property bool ruSitesDirect: hasEngine ? TribeEngine.bypassSitesDirect === true : true' \
    || bad "B7: the main screen must read it from the engine"
tog="$(printf '%s\n' "$page" | awk '/id: avCardToggle/ { on = 1 } on { print } on && /onToggled/ { exit }')"
printf '%s\n' "$tog" | grep -q 'enabled:' && bad "B7: the switch must be an ordinary one (no disabled state)"
cap='На Android 13+ напрямую идут российские приложения, сайты РФ — через VPN.'
has "$page" 'readonly property bool ruAppsOnlyCaption: ruAccessOn && !ruSitesDirect' \
    && has "$page" "text: root.ruAppsOnlyCaption" && has "$page" "? qsTr(\"$cap\")" \
    || bad "B7: the caption only with the switch on and the site routes not applied (round 59 review)"
TR="$CLIENT/translations/tribe"
for l in en es; do
    grep -A1 -F "<source>$cap</source>" "$TR/tribe_$l.ts" | grep -q '<translation>[^<]' \
        || bad "B7: the caption has no finished $l translation"
done
grep -qF 'пока недоступно' "$PAGE" && bad "B7: the «unavailable» caption is back"

# ---- B8 ---- never refused; the seed gives the sites only with a budget
sw="$(body "$ENG" 'void AvpnEngineQml::setBypassMasterOn(bool on)')"
printf '%s\n' "$sw" | grep -qE 'return;' && bad "B8: the switch's write must not be refused"
ab="$(body "$ENG" 'void AvpnEngineQml::startBypassAb()')"
printf '%s\n' "$ab" | grep -qF 'Android 13' && bad "B8: the A/B bench must not be refused on Android 13+"
seed="$(body "$ENG" 'void AvpnEngineQml::applyRuBypassSplit()')"
has "$seed" 'const bool sitesOn = avpn::bypassSitesOn(masterOn, routeBudget);' && has "$seed" 'if (sitesOn) {' \
    && has "$seed" 'applyRuBypassApps(masterOn);' \
    || bad "B8: the apps follow the switch, the sites the switch and a non-zero budget"

# ---- B9 ----
has "$(code "$HERE/../BypassMaster.h" | tr -s ' \n' ' ')" 'inline bool bypassSitesOn(bool modeOn, int routeBudget) { return modeOn && routeBudget != 0; }' \
    || bad "B9: the site routes' predicate must be the switch and a non-zero budget"
vtc="$(code "$VTC")"
has "$vtc" 'bool splitOn = (sitesOn || liAutoOn) && !ruNode;' && has "$vtc" 'if (!ruNode && sitesOn && dnsMaskOn && !dnsFwdOn) {' \
    || bad "B9: up() must decide the split and the DNS by the site routes' predicate"
has "$eng" '[] { return avpn::bypassSitesOn(); },' || bad "B9: the RU-sites check must follow the site routes"
[ "$(count "$eng" 'masterOn = avpn::bypassSitesOn(st);')" -eq 2 ] || bad "B9: the Doctor's two RU stages must follow the site routes"

[ "$fail" -eq 0 ] && echo "bypass master wiring: OK"
exit "$fail"

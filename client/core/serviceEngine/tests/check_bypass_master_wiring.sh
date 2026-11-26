#!/bin/bash
# AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the switch's effective value has ONE decision (BypassMaster.h:
# off where the platform cannot apply the split - Android 13+ in this release - else the person's choice, a legacy false,
# else on). The rule is pure and tested by behaviour (build_bypass_master.sh). What is checked here is that nothing goes
# around it - each line fails if a reader or a store comes back:
#   B1  no code outside BypassMaster.h names either stored key (AvpnBypass/masterOn, AvpnBypass/masterOnChoice);
#   B2  the choice key is written only by the switch (setBypassMasterOn), the engine start's one-time move of a legacy
#       false, and the A/B bench's exact restore; the engine start runs that move;
#   B3  every C++ reader asks avpn::bypassMasterOn (the engine and its tunnel control);
#   B4  QML no longer stores the switch: no QtCore Settings of the AvpnBypass category anywhere, and the main screen reads
#       TribeEngine.bypassMasterOn and writes only through TribeEngine.setBypassMasterOn; the engine notifies it;
#   B5  the Android 13+ boundary is the one constant kBypassMasterUnavailableOnAndroid13, and where it holds the effective
#       value is off before any stored key is read;
#   B6  the onboarding card that states the switch is on is shown only while the effective value is on;
#   B7  the UI asks the same predicate: the engine exposes bypassMasterAvailable from it, the main screen's switch is
#       disabled there and its secondary line carries the caption (RU source, EN/ES translated);
#   B8  where it is unavailable the switch's write and the A/B bench are refused before anything is stored.
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

# ---- B2 ----
eng="$(code "$ENG")"
n=$(count "$eng" 'setValue(avpn::kBypassMasterChoiceKey')
[ "$n" -eq 2 ] || bad "B2: the choice key is written in $n places, expected 2 (the switch and the start's move)"
has "$(body "$ENG" 'void AvpnEngineQml::setBypassMasterOn(bool on)')" 'setValue(avpn::kBypassMasterChoiceKey, on);' \
    || bad "B2: the switch must write the choice"
ctor="$(body "$ENG" 'AvpnEngineQml::AvpnEngineQml(')"
has "$ctor" 'avpn::bypassMasterMigratesLegacy(' && has "$ctor" 's.setValue(avpn::kBypassMasterChoiceKey, false);' \
    || bad "B2: the engine start must move a legacy false into the choice"
rest="$(body "$ENG" 'void AvpnEngineQml::abRestoreBypassMaster()')"
has "$rest" 'put(avpn::kBypassMasterChoiceKey, m_abOrigChoice);' || bad "B2: the bench must put the choice back exactly"
[ "$(count "$eng" 'abRestoreBypassMaster();')" -eq 2 ] || bad "B2: both ends of the bench must restore through abRestoreBypassMaster"

# ---- B3 ----
[ "$(count "$eng" 'avpn::bypassMasterOn(')" -ge 9 ] || bad "B3: the engine's readers must ask avpn::bypassMasterOn"
has "$(code "$VTC")" 'const bool masterOn = avpn::bypassMasterOn(s);' || bad "B3: the tunnel control must ask avpn::bypassMasterOn"

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

# ---- B5 ---- the Android 13+ boundary is one named constant; unavailable = off before any stored key
bm="$(code "$HERE/../BypassMaster.h")"
bmf="$(printf '%s\n' "$bm" | tr -s ' \n' ' ')"
[ "$(count "$bm" 'inline constexpr bool kBypassMasterUnavailableOnAndroid13 = ')" -eq 1 ] \
    || bad "B5: the Android 13+ boundary must be one constant"
has "$bmf" 'return kBypassMasterUnavailableOnAndroid13 && android && sdkVersion >= 33;' \
    || bad "B5: the platform predicate must read the constant"
has "$bmf" 'std::optional<bool> legacy, bool unavailable) { if (unavailable) return false; if (choice.has_value()) return *choice;' \
    || bad "B5: where the split cannot be applied the value must be off whatever is stored"
has "$bmf" 'storedBool(s, kBypassMasterLegacyKey), bypassMasterUnavailableHere()); }' \
    || bad "B5: the store reading must pass this device's predicate"
printf '%s\n' "$bm" | grep -qE 'OffByDefault|DefaultOff' && bad "B5: a second (default-off) boundary is back"

# ---- B6 ---- the onboarding card that says «Доступ к сайтам РФ включён» shows only while the effective value is on
onb="$(code "$CLIENT/ui/qml/Tribe/Pages/PageOnboardingTribe.qml")"
printf '%s\n' "$onb" | grep -A1 -F '                Rectangle {' | grep -qF 'visible: !root.hasEngine || TribeEngine.bypassMasterOn === true' \
    || bad "B6: the onboarding's «включён» card must follow TribeEngine.bypassMasterOn"

# ---- B7 ---- the UI: one predicate, the switch disabled with its caption
has "$(code "$HDR")" 'Q_PROPERTY(bool bypassMasterAvailable READ bypassMasterAvailable CONSTANT)' \
    || bad "B7: the engine must expose the availability"
has "$(body "$ENG" 'bool AvpnEngineQml::bypassMasterAvailable() const')" 'return !avpn::bypassMasterUnavailableHere();' \
    || bad "B7: the availability must be the value's own predicate"
has "$page" 'readonly property bool ruAccessAvailable: hasEngine ? TribeEngine.bypassMasterAvailable === true : true' \
    || bad "B7: the main screen must read the engine's availability"
tog="$(printf '%s\n' "$page" | awk '/id: avCardToggle/ { on = 1 } on { print } on && /onToggled/ { exit }')"
has "$tog" 'enabled: root.ruAccessAvailable' || bad "B7: the switch must be disabled where the mode is unavailable"
cap='На Android 13 и новее пока недоступно. Вернём в одном из следующих обновлений.'
has "$page" "text: !root.ruAccessAvailable" && has "$page" "? qsTr(\"$cap\")" \
    || bad "B7: the card's secondary line must carry the caption where the mode is unavailable"
TR="$CLIENT/translations/tribe"
for l in en es; do
    grep -A1 -F "<source>$cap</source>" "$TR/tribe_$l.ts" | grep -q '<translation>[^<]' \
        || bad "B7: the caption has no finished $l translation"
done

# ---- B8 ---- unavailable: nothing is stored by the switch or the bench
sw="$(body "$ENG" 'void AvpnEngineQml::setBypassMasterOn(bool on)')"
g=$(printf '%s\n' "$sw" | grep -nF 'if (avpn::bypassMasterUnavailableHere()) {' | head -1 | cut -d: -f1)
w=$(printf '%s\n' "$sw" | grep -nF 'setValue(avpn::kBypassMasterChoiceKey, on);' | head -1 | cut -d: -f1)
if [ -z "$g" ] || [ -z "$w" ] || [ "$g" -ge "$w" ]; then bad "B8: the switch must refuse before it stores a choice"; fi
printf '%s\n' "$sw" | sed -n "${g:-1},${w:-1}p" | grep -qF 'return;' || bad "B8: the refusal must return before the write"
ab="$(body "$ENG" 'void AvpnEngineQml::startBypassAb()')"
ga=$(printf '%s\n' "$ab" | grep -nF 'if (avpn::bypassMasterUnavailableHere()) {' | head -1 | cut -d: -f1)
ea=$(printf '%s\n' "$ab" | grep -nF '++m_abEpoch;' | head -1 | cut -d: -f1)
if [ -z "$ga" ] || [ -z "$ea" ] || [ "$ga" -ge "$ea" ]; then bad "B8: the A/B bench must refuse where the mode is unavailable"; fi

[ "$fail" -eq 0 ] && echo "bypass master wiring: OK"
exit "$fail"

#!/bin/bash
# AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67 temporary variant): the switch's effective value has ONE decision
# (BypassMaster.h: the person's choice, a legacy false, else the platform default - off on Android 13+). The rule is pure
# and tested by behaviour (build_bypass_master.sh). What is checked here is that nothing goes around it - each line fails
# if a reader or a store comes back:
#   B1  no code outside BypassMaster.h names either stored key (AvpnBypass/masterOn, AvpnBypass/masterOnChoice);
#   B2  the choice key is written only by the switch (setBypassMasterOn), the engine start's one-time move of a legacy
#       false, and the A/B bench's exact restore; the engine start runs that move;
#   B3  every C++ reader asks avpn::bypassMasterOn (the engine and its tunnel control);
#   B4  QML no longer stores the switch: no QtCore Settings of the AvpnBypass category anywhere, and the main screen reads
#       TribeEngine.bypassMasterOn and writes only through TribeEngine.setBypassMasterOn; the engine notifies it;
#   B5  the Android 13+ default is the one constant kBypassMasterOffByDefaultOnAndroid13;
#   B6  the onboarding card that states the switch is on is shown only while the effective value is on.
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

# ---- B5 ---- the Android 13+ default is one named constant (owner's open question): the platform rule reads it
bm="$(code "$HERE/../BypassMaster.h")"
[ "$(count "$bm" 'inline constexpr bool kBypassMasterOffByDefaultOnAndroid13 = ')" -eq 1 ] || bad "B5: the Android 13+ default must be one constant"
printf '%s\n' "$bm" | tr -s ' \n' ' ' | grep -qF 'return kBypassMasterOffByDefaultOnAndroid13 && android && sdkVersion >= 33;' \
    || bad "B5: the platform default must read the constant"

# ---- B6 ---- the onboarding card that says «Доступ к сайтам РФ включён» shows only while the effective value is on
onb="$(code "$CLIENT/ui/qml/Tribe/Pages/PageOnboardingTribe.qml")"
printf '%s\n' "$onb" | grep -A1 -F '                Rectangle {' | grep -qF 'visible: !root.hasEngine || TribeEngine.bypassMasterOn === true' \
    || bad "B6: the onboarding's «включён» card must follow TribeEngine.bypassMasterOn"

[ "$fail" -eq 0 ] && echo "bypass master wiring: OK"
exit "$fail"

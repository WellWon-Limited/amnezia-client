#!/bin/bash
# AVPN (desktop test rig): every command of the test command channel makes the call its button makes
# (DevControlApp.h). Reads dev_control_map.tsv:
#   W1  each function of DevControlApp.cpp makes exactly the js()/cpp()/sig() calls its rows name - no other entry
#       point, and no function outside the map calls into the app;
#   W2  each called entry is still declared where the row says (a QML function or signal, a Q_INVOKABLE, a slot);
#   W3  the button's own call site still makes that call (the orb, a row, the bottom bar, a segment, the Scanner's
#       taps), and every `chain` string - the rest of the path down to the engine - is still in its file;
#   W4  every property and getter the channel reads exists under that name (AvpnEngineQml.h, TribeScanner.h, the
#       pages), and the currentNode / debugSnapshot keys of `state` are still written by the engine;
#   W5  the channel reaches the app only by name: no engine or Scanner header, no invokeMethod / setProperty outside
#       the one call helper, nothing written into an app object.
# Run by the check sweep (every check_*.sh of this directory).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
MAP="$HERE/dev_control_map.tsv"
APP="$ROOT/client/core/serviceEngine/DevControlApp.cpp"
ENGINE_H="$ROOT/client/core/serviceEngine/AvpnEngineQml.h"
ENGINE_CPP="$ROOT/client/core/serviceEngine/AvpnEngineQml.cpp"
SCANNER_H="$ROOT/client/core/serviceEngine/TribeScanner.h"
SERVERS_QML="$ROOT/client/ui/qml/Tribe/Pages/PageServersTribe.qml"
START_QML="$ROOT/client/ui/qml/Pages2/PageStart.qml"
NAV_QML="$ROOT/client/ui/qml/Tribe/components/TribeBottomNav.qml"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# The body of a C++ function: from its definition line to the first line that is exactly "}".
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
rawcalls() { grep -oE '\b(js|cpp|sig)\([^,()]*(\([^()]*\))?, "[A-Za-z]+"' | sed -E 's/^(js|cpp|sig)\(.*"([A-Za-z]+)"$/\1:\2/'; }
calls() { rawcalls | sort -u; }
DEF="^[A-Za-z][A-Za-z:<> *]*[ *]App::"

# ---- W1 ------------------------------------------------------------------------------------------------------------
fns="$(code "$APP" | grep -oE "${DEF}[a-zA-Z]+\\(" | sed -E 's/.*App::([a-zA-Z]+)\($/\1/' | sort -u)"
[ -n "$fns" ] || bad "W1: no App:: functions found in $APP"
mapped="$(grep -v '^#' "$MAP" | awk -F'\t' '$1 != "chain" && NF >= 6 { print $1 }' | sort -u)"
for fn in $fns; do
  sig_line="$(code "$APP" | grep -E "${DEF}$fn\\(" | head -1)"
  got="$(body "$APP" "$sig_line" | calls)"
  want="$(grep -v '^#' "$MAP" | awk -F'\t' -v f="$fn" '$1 == f && $2 !~ /^quit:/ { print $2 }' | sort -u)"
  if [ -n "$got" ] && ! printf '%s\n' "$mapped" | grep -qxF "$fn"; then
    bad "W1: App::$fn calls into the app but has no row: $(echo $got)"
  elif [ "$got" != "$want" ]; then
    bad "W1: App::$fn calls [$(echo $got)], the map says [$(echo $want)]"
  fi
done
for fn in $mapped; do
  printf '%s\n' "$fns" | grep -qxF "$fn" || bad "W1: the map names App::$fn, which does not exist"
done
# quit: the env's quit, which the app sets to the tray's QCoreApplication::quit
q="$(body "$APP" 'void App::cmdQuit(const Done &done)')"
printf '%s\n' "$q" | grep -qF 'm_env.quit();' || bad "W1: cmdQuit does not end in the env's quit"
# every call goes through the helpers inside a mapped function: count them
total="$(code "$APP" | rawcalls | wc -l | tr -d ' ')"
inmapped=0
for fn in $mapped; do
  sig_line="$(code "$APP" | grep -E "${DEF}$fn\\(" | head -1)"
  [ -n "$sig_line" ] && inmapped=$(( inmapped + $(body "$APP" "$sig_line" | rawcalls | wc -l | tr -d ' ') ))
done
[ "$total" = "$inmapped" ] || bad "W1: $total calls into the app in the file, only $inmapped inside mapped functions"

# ---- W2, W3 --------------------------------------------------------------------------------------------------------
while IFS=$'\t' read -r fn call dfile decl bfile bcall; do
  case "$fn" in ''|'#'*) continue ;; esac
  if [ "$fn" = chain ]; then
    grep -qF -- "$decl" "$ROOT/$dfile" 2>/dev/null || bad "W3: the path changed: '$decl' is gone from $dfile"
    continue
  fi
  grep -qF -- "$decl" "$ROOT/$dfile" 2>/dev/null || bad "W2: $call ($fn) is not declared as '$decl' in $dfile"
  grep -qF -- "$bcall" "$ROOT/$bfile" 2>/dev/null || bad "W3: the button no longer makes $call: '$bcall' is gone from $bfile"
done < <(grep -v '^#' "$MAP" | awk -F'\t' '$1 == "chain" { print $1 "\t" $2 "\t" $2 "\t" $3; next } { print }')

# ---- W4 ------------------------------------------------------------------------------------------------------------
app="$(code "$APP")"
engprops="$( { printf '%s\n' "$app" | grep -oE 'prop\(e, "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/';
               printf '%s\n' "$app" | grep -oE '\{"[a-z_]+", "[A-Za-z]+"\}' | sed -E 's/.*, "([A-Za-z]+)"\}/\1/';
               printf '%s\n' "$app" | grep -oE 'prop\(eng, "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/'; } | sort -u)"
[ -n "$engprops" ] || bad "W4: no engine property reads found"
for p in $engprops; do
  grep -qE "Q_PROPERTY\([A-Za-z:<>]+ $p READ" "$ENGINE_H" || bad "W4: the engine has no Q_PROPERTY $p (AvpnEngineQml.h)"
done
for g in $(printf '%s\n' "$app" | grep -oE 'read\(e, "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/' | sort -u); do
  grep -qE "Q_INVOKABLE [A-Za-z:<>]+ $g\(\) const" "$ENGINE_H" || bad "W4: the engine has no const Q_INVOKABLE $g()"
done
for p in $(printf '%s\n' "$app" | grep -oE 'prop\((s|sc), "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/' | sort -u); do
  grep -qE "Q_PROPERTY\([A-Za-z:<>]+ $p READ" "$SCANNER_H" || bad "W4: TribeScanner has no Q_PROPERTY $p"
done
for p in $(printf '%s\n' "$app" | grep -oE 'prop\(page, "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/' | sort -u); do
  grep -qE "property [a-z]+ $p[: ]" "$SERVERS_QML" || bad "W4: PageServersTribe has no property $p"
done
for p in $(printf '%s\n' "$app" | grep -oE 'prop\(ps, "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/' | sort -u); do
  grep -qE "property [a-z]+ $p[: ]" "$START_QML" || bad "W4: PageStart has no property $p"
done
for p in $(printf '%s\n' "$app" | grep -oE 'prop\(bar, "[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/' | sort -u); do
  [ "$p" = visible ] && continue
  grep -qE "property [a-z]+ $p[: ]" "$NAV_QML" || bad "W4: TribeBottomNav has no property $p"
done
# the keys `state` reads from currentNode and debugSnapshot are written by the engine
state="$(body "$APP" 'QJsonObject App::cmdState()')"
for k in $(printf '%s\n' "$state" | grep -oE 'n\.(value|contains)\(QStringLiteral\("[A-Za-z]+"\)' | sed -E 's/.*"([A-Za-z]+)".*/\1/' | sort -u); do
  grep -qF "node[\"$k\"]" "$ENGINE_CPP" || bad "W4: currentNode has no key $k (AvpnEngineQml.cpp)"
done
snap="$(printf '%s\n' "$state" | awk '/snapFields\[\] = \{/ { on = 1; next } on { print } on && /\};/ { exit }' | grep -oE '"[A-Za-z]+"' | tr -d '"')"
[ -n "$snap" ] || bad "W4: no snapshot field list found in cmdState"
for k in $snap currentNodeId pool switchLog upstream; do
  grep -qE "m\[\"$k\"\]" "$ENGINE_CPP" || bad "W4: debugSnapshot has no key $k"
done

# ---- W5 ------------------------------------------------------------------------------------------------------------
for f in "$ROOT/client/core/serviceEngine/DevControlApp.cpp" "$ROOT/client/core/serviceEngine/DevControlApp.h" \
         "$ROOT/client/core/serviceEngine/DevControl.cpp" "$ROOT/client/core/serviceEngine/DevControl.h"; do
  grep -qE '#include "(AvpnEngineQml|TribeScanner|ScanMachine|ServiceEngine)\.h"' "$f" && bad "W5: $(basename "$f") includes an engine header"
  grep -qE 'invokeMethod|setProperty\(|->m_|\.m_[a-z]' "$f" && [ "$(basename "$f")" != DevControl.cpp ] \
    && bad "W5: $(basename "$f") reaches into an object (invokeMethod / setProperty / a member)"
done
n="$(code "$APP" | grep -cE '\bmetaCall\(' || true)"
[ "$n" = 5 ] || bad "W5: metaCall is used $n times (its definition + js/cpp/sig/read only)"

# ---- W6 ------------------------------------------------------------------------------------------------------------
# A command that acts for the person tells the engine first, through its one entry (notePersonPresent, SystemAwake.h);
# no input event is ever made up.
h="$(body "$APP" 'void App::handle(const QString &cmd, const QJsonObject &args, QObject *ctx, const Done &done)')"
pp=$(printf '%s\n' "$h" | grep -nF 'm_env.personPresent();' | head -1 | cut -d: -f1)
d1=$(printf '%s\n' "$h" | grep -nF 'return cmdWait(args, ctx, done);' | head -1 | cut -d: -f1)
[ -n "$pp" ] && [ -n "$d1" ] && [ "$pp" -lt "$d1" ] || bad "W6: handle() does not note the person before it dispatches"
pc="$(code "$APP" | awk '/^const QStringList &personCommands\(\)/ { on = 1 } on { print } on && /^}$/ { exit }')"
for c in connect stop nav servers choose auto mode scan.open scan.select scan.start scan.stop scan.connect scan.back window.show quit; do
  printf '%s\n' "$pc" | grep -qF "QStringLiteral(\"$c\")" || bad "W6: $c does not note the person"
done
for c in state shot mark wait help; do
  printf '%s\n' "$pc" | grep -qF "QStringLiteral(\"$c\")" && bad "W6: the read command $c notes a person"
done
grep -qF 'engine->notePersonPresent();' "$ROOT/client/core/serviceEngine/DevControlInstall.cpp" \
  || bad "W6: the app's personPresent is not AvpnEngineQml::notePersonPresent"
grep -qE '^    void notePersonPresent\(\);' "$ENGINE_H" || bad "W6: the engine has no notePersonPresent()"
grep -lE 'sendEvent|postEvent|QMouseEvent|QKeyEvent|QTest|sendSpontaneous|QWindowSystemInterface' \
  "$ROOT"/client/core/serviceEngine/DevControl*.cpp "$ROOT"/client/core/serviceEngine/DevControl*.h 2>/dev/null \
  | while read -r f; do echo "FAIL: W6: $(basename "$f") makes up an input event"; done | grep . && fail=1

[ "$fail" = 0 ] && echo "check_dev_control_wiring: OK ($(printf '%s\n' "$mapped" | wc -l | tr -d ' ') functions, $(grep -c '^chain' "$MAP") chain strings)"
exit "$fail"

#!/bin/bash
# qml_gate.sh — релизный гейт против класса инцидента 5.1.83 (112): апстрим удалил QML-тип
# (ChangelogDrawer), наш main2.qml его инстанцировал, git смержил без конфликта, компиляция и
# статические гейты были зелёными, а приложение падало на старте на ВСЕХ платформах. QML лежит
# в qrc без qmlcachegen — сборка «зелёная» при любой ошибке в QML.
#
#   qml_gate.sh lint [ref]        — qmllint по всем .qml из git (ref, по умолчанию HEAD):
#                                   неизвестный тип/модуль вне allowlist = FAIL.
#   qml_gate.sh run <Tribe VPN.app> [сек]
#                                 — запуск собранного приложения в изоляции (свои HOME/TMPDIR:
#                                   не трогает установленную копию, её настройки, LaunchGuard и
#                                   сокет единственного экземпляра); FAIL, если процесс умер раньше
#                                   срока или в журнале есть ошибка загрузки QML.
#
# Вызывается из ~/avpn-build/mac-release.sh и release.sh ДО нотаризации/выкладки
# (TRIBE-iOS-DEV §14 блок E). Ручной прогон: WW_TEST=1 WW_TEST_ID=qml-gate bash qml_gate.sh lint
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
QT_BIN="${QT_BIN:-$HOME/Qt/6.10.2/macos/bin}"

# Типы и модули, которые регистрирует C++ (qmlRegisterType/контекст), а не QML-файлы:
# qmllint их не видит — это не ошибка. Новый C++-тип добавлять сюда осознанно.
ALLOW_TYPES='^(RegExpFilter|ValueFilter|AnyOf|QRCodeReader|PublicHostInputValidator|InstalledAppsModel|Gamepad|GamepadKeyNavigation)$'
ALLOW_MODULES='^(SortFilterProxyModel|PageEnum|ContainersModelFilters|ContainerProps|UpdateState|TelemtConfig|QtGamepadLegacy|QRCodeReader|ProtocolEnum|MtProxyConfig|InstalledAppsModel|ConnectionState|configuration"\)\))$'

lint() {
  local ref="${1:-HEAD}" work
  work="$(mktemp -d /tmp/tribe-qml-gate.XXXXXX)" || exit 2
  trap 'rm -rf -- "$work"' RETURN
  git -C "$REPO" archive "$ref" client/ui/qml | tar -x -C "$work" || { echo "qml_gate: git archive $ref failed"; return 2; }
  local qml="$work/client/ui/qml" out="$work/lint.txt"
  (cd "$qml" && git -C "$REPO" ls-tree -r --name-only "$ref" -- client/ui/qml | grep '\.qml$' \
     | sed 's#^client/ui/qml/##' | xargs "$QT_BIN/qmllint" -I . -I Modules >"$out" 2>&1)
  local bad
  bad="$( { grep -oE '[A-Za-z0-9_]+ was not found' "$out" | awk '{print $1}' | grep -vE "$ALLOW_TYPES";
            grep -oE 'Failed to import [^ .]+' "$out" | awk '{print $4}' | grep -vE "$ALLOW_MODULES"; } | sort -u)"
  if [ -n "$bad" ]; then
    echo "qml_gate lint: FAIL ($ref) — QML ссылается на несуществующее:"
    echo "$bad" | sed 's/^/  /'
    grep -nE "$(echo "$bad" | paste -sd'|' -)" "$out" | head -20 | sed 's/^/    /'
    return 1
  fi
  echo "qml_gate lint: OK ($ref)"
}

run() {
  local app="${1:?путь к Tribe VPN.app}" secs="${2:-15}" sandbox pid bin log status=0
  bin="$(/usr/bin/find "$app/Contents/MacOS" -maxdepth 1 -type f -perm -u+x -name 'TribeVPN' -print -quit)"
  [ -n "$bin" ] || { echo "qml_gate run: нет $app/Contents/MacOS/TribeVPN"; return 2; }
  sandbox="$(mktemp -d /tmp/tribe-qml-run.XXXXXX)" || return 2
  mkdir -p "$sandbox/home" "$sandbox/tmp"
  log="$sandbox/run.log"
  # Изоляция: свой HOME (QSettings, Application Support/LaunchGuard, Logs) и TMPDIR (сокет
  # единственного экземпляра) — установленная Tribe VPN и её состояние не участвуют.
  # В бандле только cocoa; offscreen берём из установленного Qt той же версии (окно не всплывает).
  local plugins="${QT_BIN%/bin}/plugins/platforms"
  HOME="$sandbox/home" TMPDIR="$sandbox/tmp/" QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" \
    QT_QPA_PLATFORM_PLUGIN_PATH="${QT_QPA_PLATFORM_PLUGIN_PATH:-$plugins}" \
    "$bin" >"$log" 2>&1 &
  pid=$!
  local waited=0
  while [ "$waited" -lt "$secs" ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1; waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null; sleep 1; kill -9 "$pid" 2>/dev/null
  else
    wait "$pid"; echo "qml_gate run: FAIL — процесс завершился через ${waited} с (код $?)"; status=1
  fi
  if grep -nE 'is not a type|was not found|ReferenceError|TypeError|Cannot assign to non-existent|module "[^"]+" is not installed|Failed to load component|QQmlApplicationEngine failed' "$log" \
       | grep -v 'qrc:/.*: QML Connections: ' | head -20 | sed 's/^/    /' | grep .; then
    echo "qml_gate run: FAIL — ошибки загрузки QML в журнале ($log)"; status=1
  fi
  [ "$status" = 0 ] && { echo "qml_gate run: OK — жил ${secs} с без ошибок загрузки QML"; rm -rf -- "$sandbox"; }
  return "$status"
}

case "${1:-lint}" in
  lint) shift; lint "${1:-HEAD}" ;;
  run)  shift; run "$@" ;;
  *) echo "usage: $0 lint [ref] | run <app> [secs]"; exit 2 ;;
esac

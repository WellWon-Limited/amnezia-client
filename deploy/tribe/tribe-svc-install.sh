#!/bin/bash
# tribe-svc-install.sh — ВШИВАЕТСЯ в TribeVPN.app/Contents/Resources/. Запускается приложением
# через osascript «with administrator privileges» (один системный промпт пароля, без терминала).
# Распаковывает payload-tarball (аргумент $1) с закрытым runtime-набором:
# Tribe-service + AWG/OpenVPN/tun2socks helpers + Xray geodata + Frameworks + pf в
# /Library/PrivilegedHelperTools/TribeVPN, пишет LaunchDaemon + bootstrap.
# Payload — tarball-РЕСУРС (а не loose-файлы в бандле): не ломает подпись app, нотаризация внутрь
# tar не лезет. НЕ трогает официальную Amnezia (имена: Tribe-service / tribevpn / анкор tribe).
set -euo pipefail
# AuthorizationExecuteWithPrivileges запускает нас с ПУСТЫМ PATH → bare-команды (tar/mktemp/cp/
# chown/launchctl/dscl в /usr/bin,/usr/sbin,/bin) не находятся. Задаём PATH явно. Лог — для диагностики.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
[ "$(id -u)" -eq 0 ] || { echo "installer must run as root" >&2; exit 1; }
umask 027

# Never let a privileged logger follow an attacker-created /tmp symlink.
LOG_DIR="/var/log/TribeVPN"
[ ! -L "$LOG_DIR" ] || { echo "unsafe installer log directory" >&2; exit 1; }
mkdir -p "$LOG_DIR"
chown root:wheel "$LOG_DIR"
chmod 750 "$LOG_DIR"
LOG_FILE="$LOG_DIR/service-install.log"
[ ! -L "$LOG_FILE" ] || { echo "unsafe installer log file" >&2; exit 1; }
touch "$LOG_FILE"
chown root:wheel "$LOG_FILE"
chmod 640 "$LOG_FILE"
exec >> "$LOG_FILE" 2>&1
echo "=== tribe-svc-install $(date) PATH=$PATH ==="

LABEL="Tribe-service"; GROUP="tribevpn"
DEST="/Library/PrivilegedHelperTools/TribeVPN"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
TEAM_REQUIREMENT='anchor apple generic and certificate leaf[subject.OU] = "Q7DVH5MCWF" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
LOCK_FILE="/var/run/tribevpn-service-install.lock"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
LAUNCHCTL_PARSER="$SCRIPT_DIR/launchctl-job-field.sh"
[ -f "$LAUNCHCTL_PARSER" ] && [ ! -L "$LAUNCHCTL_PARSER" ] \
  && [ -x "$LAUNCHCTL_PARSER" ] \
  && [ "$(stat -f '%l' "$LAUNCHCTL_PARSER")" = 1 ] \
  || { echo "unsafe/missing signed launchctl parser" >&2; exit 1; }

validate_launchd_parent() {
  [ -d /Library/LaunchDaemons ] && [ ! -L /Library/LaunchDaemons ] \
    && [ "$(stat -f '%Su:%Sg:%Lp' /Library/LaunchDaemons)" = "root:wheel:755" ] \
    || { echo "unsafe /Library/LaunchDaemons provenance"; return 1; }
}

validate_launchd_plist_file() {
  plist_path="$1"
  [ -f "$plist_path" ] && [ ! -L "$plist_path" ] \
    && [ "$(stat -f '%Su:%Sg:%Lp:%l' "$plist_path")" = "root:wheel:644:1" ] \
    || { echo "unsafe Tribe launchd plist provenance"; return 1; }
}

validate_tribe_group_unused() {
  group_name="$(dscl . -read "/Groups/$GROUP" RealName 2>/dev/null \
    | sed 's/^RealName:[[:space:]]*//')"
  group_gid="$(dscl . -read "/Groups/$GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}')"
  case "$group_gid" in ''|*[!0-9]*) return 1 ;; esac
  gid_groups="$(dscl . -list /Groups PrimaryGroupID 2>/dev/null \
    | awk -v gid="$group_gid" '$2 == gid { print $1 }')"
  [ "$(printf '%s\n' "$gid_groups" | awk 'NF { n++ } END { print n + 0 }')" -eq 1 ] \
    && [ "$gid_groups" = "$GROUP" ] || return 1
  primary_users="$(dscl . -list /Users PrimaryGroupID 2>/dev/null \
    | awk -v gid="$group_gid" '$2 == gid { print $1 }')"
  group_members="$(dscl . -read "/Groups/$GROUP" GroupMembership 2>/dev/null \
    | sed 's/^GroupMembership:[[:space:]]*//' || true)"
  group_member_uuids="$(dscl . -read "/Groups/$GROUP" GroupMembers 2>/dev/null \
    | sed 's/^GroupMembers:[[:space:]]*//' || true)"
  nested_groups="$(dscl . -read "/Groups/$GROUP" NestedGroups 2>/dev/null \
    | sed 's/^NestedGroups:[[:space:]]*//' || true)"
  [ "$group_name" = "Tribe VPN Service Group" ] \
    && [ -z "$primary_users" ] && [ -z "$group_members" ] \
    && [ -z "$group_member_uuids" ] && [ -z "$nested_groups" ]
}
if ! /usr/bin/shlock -p "$$" -f "$LOCK_FILE"; then
  echo "another Tribe service installation is already running"
  exit 1
fi
# Install an immediate cleanup before any further privileged operation. shlock
# atomically replaces stale PID locks left by crashes or power loss.
trap 'rm -f "$LOCK_FILE"' EXIT
chown root:wheel "$LOCK_FILE"; chmod 600 "$LOCK_FILE"

uninstall_service() {
  echo "removing the exact Tribe VPN privileged service namespace"
  validate_launchd_parent || return 1
  dns_state_dir="/private/var/db/TribeVPN"

  # A substituted launchd plist must never be used to stop or remove another
  # product.  Accept only our root-owned, non-symlink plist and exact label/path.
  if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then
    validate_launchd_plist_file "$PLIST" || return 1
    plist_label="$(plutil -extract Label raw -o - "$PLIST" 2>/dev/null || true)"
    plist_program="$(plutil -extract ProgramArguments.0 raw -o - "$PLIST" 2>/dev/null || true)"
    [ "$plist_label" = "$LABEL" ] && [ "$plist_program" = "$DEST/$LABEL" ] \
      || { echo "Tribe launchd plist identity mismatch"; return 1; }
    launchctl bootout system "$PLIST" 2>/dev/null || true
  fi

  # launchd normally stops the process.  If it did not, signal only PIDs whose
  # command is rooted at the exact Tribe runtime path; a process-name match is
  # insufficient because another product can use the same helper basename.
  for _ in 1 2 3 4 5; do
    service_pids="$(pgrep -x "$LABEL" 2>/dev/null || true)"
    [ -n "$service_pids" ] || break
    sleep 1
  done
  service_pids="$(pgrep -x "$LABEL" 2>/dev/null || true)"
  for pid in $service_pids; do
    command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    case "$command" in
      "$DEST/$LABEL"|"$DEST/$LABEL "*) kill -TERM "$pid" 2>/dev/null || true ;;
      *) echo "refusing to signal foreign $LABEL pid $pid"; return 1 ;;
    esac
  done
  for _ in 1 2 3 4 5; do
    exact_service_pids=""
    for pid in $(pgrep -x "$LABEL" 2>/dev/null || true); do
      command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
      case "$command" in
        "$DEST/$LABEL"|"$DEST/$LABEL "*) exact_service_pids="$exact_service_pids $pid" ;;
      esac
    done
    [ -z "$exact_service_pids" ] && break
    sleep 1
  done
  for pid in $exact_service_pids; do
    command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    case "$command" in
      "$DEST/$LABEL"|"$DEST/$LABEL "*) kill -KILL "$pid" 2>/dev/null || true ;;
    esac
  done
  sleep 1
  for pid in $(pgrep -x "$LABEL" 2>/dev/null || true); do
    command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    case "$command" in
      "$DEST/$LABEL"|"$DEST/$LABEL "*)
        echo "exact Tribe service survived uninstall"; return 1 ;;
    esac
  done
  for helper in amneziawg-go openvpn tun2socks; do
    helper_pids="$(pgrep -f "^$DEST/${helper}([[:space:]]|$)" 2>/dev/null || true)"
    for helper_pid in $helper_pids; do
      case "$helper_pid" in ''|*[!0-9]*) continue ;; esac
      kill -TERM "$helper_pid" 2>/dev/null || true
    done
    for _ in 1 2 3 4 5; do
      helper_pids="$(pgrep -f "^$DEST/${helper}([[:space:]]|$)" 2>/dev/null || true)"
      [ -z "$helper_pids" ] && break
      sleep 1
    done
    helper_pids="$(pgrep -f "^$DEST/${helper}([[:space:]]|$)" 2>/dev/null || true)"
    for helper_pid in $helper_pids; do
      case "$helper_pid" in ''|*[!0-9]*) continue ;; esac
      kill -KILL "$helper_pid" 2>/dev/null || true
    done
    sleep 1
    [ -z "$(pgrep -f "^$DEST/${helper}([[:space:]]|$)" 2>/dev/null || true)" ] \
      || { echo "exact Tribe helper survived uninstall: $helper"; return 1; }
  done

  # The native, signed service owns OpenVPN DNS state. Recover it only after
  # every writer is stopped and before deleting either the executable or its
  # root-only durable state. Old releases did not create this directory.
  if [ -e "$dns_state_dir" ] || [ -L "$dns_state_dir" ]; then
    [ -d "$dns_state_dir" ] && [ ! -L "$dns_state_dir" ] \
      && [ "$(stat -f '%Su:%Lp' "$dns_state_dir")" = "root:700" ] \
      || { echo "unsafe Tribe DNS recovery state"; return 1; }
    [ -d "$DEST" ] && [ ! -L "$DEST" ] \
      && [ "$(stat -f '%Su:%Sg:%Lp' "$DEST")" = "root:wheel:755" ] \
      || { echo "unsafe Tribe runtime for DNS recovery"; return 1; }
    dns_recovery_binary="$DEST/$LABEL"
    [ -f "$dns_recovery_binary" ] && [ ! -L "$dns_recovery_binary" ] \
      && [ "$(stat -f '%Su:%Sg:%Lp:%l' "$dns_recovery_binary")" = "root:wheel:755:1" ] \
      || { echo "unsafe Tribe DNS recovery binary"; return 1; }
    codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" \
      "$dns_recovery_binary" \
      || { echo "invalid Tribe DNS recovery binary signature"; return 1; }
    "$dns_recovery_binary" --tribe-openvpn-dns-recover-v1 \
      || { echo "Tribe DNS recovery failed; preserving runtime and state"; return 1; }
    rm -rf "$dns_state_dir" \
      || { echo "recovered Tribe DNS state could not be removed"; return 1; }
  fi

  # Only anchors in Tribe's closed prefix are flushed.  Never wildcard another
  # VPN's anchors and never infer ownership from an engine basename.
  while IFS= read -r anchor; do
    [ -n "$anchor" ] || continue
    pfctl -a "$anchor" -F all 2>/dev/null || true
  done < <(pfctl -s Anchors 2>/dev/null \
      | awk '$1 == "tribe" || $1 ~ /^tribe[.\/]/ { sub(/\*$/, "", $1); print $1 }')

  if [ -e "$DEST" ] || [ -L "$DEST" ]; then
    [ -d "$DEST" ] && [ ! -L "$DEST" ] \
      || { echo "unsafe Tribe runtime path"; return 1; }
    [ "$(stat -f '%Su' "$DEST")" = root ] \
      || { echo "Tribe runtime is not root-owned"; return 1; }
    rm -rf "$DEST"
  fi
  rm -f "$PLIST"
  rm -rf "/Library/Application Support/TribeVPN" /var/log/TribeVPN
  if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    validate_tribe_group_unused \
      || { echo "refusing to delete unsafe or in-use Tribe service group"; return 1; }
    dscl . -delete "/Groups/$GROUP"
  fi
  echo "Tribe VPN privileged service removed"
}

SRC=""
NEW=""
PLIST_TMP=""
TX_ROOT="/Library/PrivilegedHelperTools/.TribeVPN.install-transaction"
JOURNAL="$TX_ROOT/JOURNAL"
OLD="$TX_ROOT/old-runtime"
PLIST_OLD="$TX_ROOT/old-launchd.plist"
FAILED="$TX_ROOT/failed-runtime"
NEW="$TX_ROOT/new-runtime"
PLIST_TMP="$TX_ROOT/new-launchd.plist"
TRANSACTION_STARTED=0
TRANSACTION_COMMITTED=0
TRANSACTION_DEFERRED=0
TRANSACTION_RECOVERED=0
GROUP_CREATED=0
JOURNAL_PHASE=""
JOURNAL_HAD_DEST=""
JOURNAL_HAD_PLIST=""
JOURNAL_EPOCH=""
JOURNAL_TAR_SHA=""
JOURNAL_RUNTIME_VERSION=""
JOURNAL_GROUP_CREATED=""

validate_privileged_helper_parent() {
  [ -d /Library/PrivilegedHelperTools ] \
    && [ ! -L /Library/PrivilegedHelperTools ] \
    && [ "$(stat -f '%Su:%Sg:%Lp' /Library/PrivilegedHelperTools)" = "root:wheel:755" ] \
    || { echo "unsafe /Library/PrivilegedHelperTools provenance"; return 1; }
}

validate_transaction_root() {
  validate_privileged_helper_parent || return 1
  [ -d "$TX_ROOT" ] && [ ! -L "$TX_ROOT" ] \
    && [ "$(stat -f '%Su:%Sg:%Lp' "$TX_ROOT")" = "root:wheel:700" ] \
    || { echo "unsafe service transaction root"; return 1; }
}

journal_value() {
  key="$1"
  awk -F= -v key="$key" '
    $1 == key { count++; value=substr($0, length(key) + 2) }
    END { if (count != 1) exit 1; print value }
  ' "$JOURNAL"
}

load_journal() {
  validate_transaction_root || return 1
  [ -f "$JOURNAL" ] && [ ! -L "$JOURNAL" ] \
    && [ "$(stat -f '%Su:%Sg:%Lp:%l' "$JOURNAL")" = "root:wheel:600:1" ] \
    && [ "$(wc -l < "$JOURNAL" | tr -d ' ')" = 8 ] \
    || { echo "unsafe/malformed service transaction journal"; return 1; }
  [ "$(journal_value schema)" = 3 ] || return 1
  JOURNAL_PHASE="$(journal_value phase)"
  JOURNAL_HAD_DEST="$(journal_value had_dest)"
  JOURNAL_HAD_PLIST="$(journal_value had_plist)"
  JOURNAL_EPOCH="$(journal_value epoch)"
  JOURNAL_TAR_SHA="$(journal_value tar_sha256)"
  JOURNAL_RUNTIME_VERSION="$(journal_value runtime_version)"
  JOURNAL_GROUP_CREATED="$(journal_value group_created)"
  case "$JOURNAL_PHASE" in prepared|old_stopped|old_saved|new_runtime|new_plist|healthy|committed) ;;
    *) echo "unknown service transaction phase"; return 1 ;;
  esac
  case "$JOURNAL_HAD_DEST:$JOURNAL_HAD_PLIST" in 0:0|0:1|1:0|1:1) ;;
    *) echo "invalid service transaction existence flags"; return 1 ;;
  esac
  case "$JOURNAL_EPOCH" in ''|*[!0-9]*) echo "invalid journal epoch"; return 1 ;; esac
  case "$JOURNAL_TAR_SHA" in ''|*[!0-9a-f]*) echo "invalid journal tar digest"; return 1 ;; esac
  case "$JOURNAL_RUNTIME_VERSION" in ''|*[!0-9a-f]*) echo "invalid journal runtime version"; return 1 ;; esac
  case "$JOURNAL_GROUP_CREATED" in 0|1) ;;
    *) echo "invalid journal group-created flag"; return 1 ;;
  esac
  [ "$JOURNAL_EPOCH" -gt 0 ] && [ "${#JOURNAL_TAR_SHA}" -eq 64 ] \
    && [ "${#JOURNAL_RUNTIME_VERSION}" -eq 64 ] || return 1
}

write_journal() {
  next_phase="$1"
  case "$next_phase" in prepared|old_stopped|old_saved|new_runtime|new_plist|healthy|committed) ;;
    *) echo "refusing invalid transaction phase"; return 1 ;;
  esac
  validate_transaction_root || return 1
  temporary_journal="$TX_ROOT/.JOURNAL.new"
  [ ! -e "$temporary_journal" ] && [ ! -L "$temporary_journal" ] || return 1
  (
    umask 077
    printf 'schema=3\nphase=%s\nhad_dest=%s\nhad_plist=%s\nepoch=%s\ntar_sha256=%s\nruntime_version=%s\ngroup_created=%s\n' \
      "$next_phase" "$JOURNAL_HAD_DEST" "$JOURNAL_HAD_PLIST" \
      "$JOURNAL_EPOCH" "$JOURNAL_TAR_SHA" "$JOURNAL_RUNTIME_VERSION" \
      "$JOURNAL_GROUP_CREATED" \
      > "$temporary_journal"
  )
  chown root:wheel "$temporary_journal"
  chmod 600 "$temporary_journal"
  mv "$temporary_journal" "$JOURNAL"
  # macOS has no shell fsync primitive. sync(2) is the durability barrier for
  # both the atomic phase rename and all preceding same-volume directory moves.
  /bin/sync
  JOURNAL_PHASE="$next_phase"
}

remove_transaction_root() {
  validate_transaction_root || return 1
  rm -rf "$TX_ROOT"
  /bin/sync
}

discard_unstarted_transaction() {
  local unexpected_entry temporary_journal
  # begin_transaction never stages or mutates a live path until the prepared
  # journal rename and sync have succeeded. Therefore an exact 0700 root with
  # no JOURNAL is recoverable only when empty or when it contains the sole
  # interrupted atomic-journal temporary file.
  validate_transaction_root || return 1
  [ ! -e "$JOURNAL" ] && [ ! -L "$JOURNAL" ] || return 1
  unexpected_entry="$(find "$TX_ROOT" -mindepth 1 -maxdepth 1 \
    ! -name .JOURNAL.new -print -quit)"
  [ -z "$unexpected_entry" ] \
    || { echo "journal-less transaction contains staged/live state"; return 1; }
  temporary_journal="$TX_ROOT/.JOURNAL.new"
  if [ -e "$temporary_journal" ] || [ -L "$temporary_journal" ]; then
    [ -f "$temporary_journal" ] && [ ! -L "$temporary_journal" ] \
      && [ "$(stat -f '%Su:%Sg:%Lp:%l' "$temporary_journal")" = "root:wheel:600:1" ] \
      || { echo "unsafe interrupted initial journal"; return 1; }
  fi
  remove_transaction_root
}

validate_service_binary() {
  local binary="$1"
  [ -f "$binary" ] && [ ! -L "$binary" ] \
    && [ "$(stat -f '%Su:%Sg:%Lp:%l' "$binary")" = "root:wheel:755:1" ] \
    && codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" "$binary"
}

launch_program_from_plist() {
  local candidate_plist="$1" candidate_label candidate_program
  validate_launchd_plist_file "$candidate_plist" || return 1
  candidate_label="$(plutil -extract Label raw -o - "$candidate_plist" 2>/dev/null || true)"
  candidate_program="$(plutil -extract ProgramArguments.0 raw -o - "$candidate_plist" 2>/dev/null || true)"
  [ "$candidate_label" = "$LABEL" ] || return 1
  case "$candidate_program" in
    "$DEST/$LABEL"|"/Library/PrivilegedHelperTools/Tribe/$LABEL")
      printf '%s\n' "$candidate_program" ;;
    *) return 1 ;;
  esac
}

verify_launchd_job_stable() {
  local expected_program="$1" stable_pid="" launch_state launch_program
  local launch_job_state launch_pid image_matches
  validate_service_binary "$expected_program" || return 1
  for _ in 1 2 3 4 5; do
    launch_state="$(launchctl print "system/${LABEL}")" || return 1
    launch_program="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" program)" || return 1
    launch_job_state="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" state)" || return 1
    launch_pid="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" pid)" || return 1
    [ "$launch_program" = "$expected_program" ] && [ "$launch_job_state" = running ] \
      || return 1
    case "$launch_pid" in ''|*[!0-9]*) return 1 ;; esac
    image_matches="$(/usr/sbin/lsof -a -p "$launch_pid" -d txt -Fn 2>/dev/null \
      | awk -v expected="n$expected_program" '$0 == expected { n++ } END { print n + 0 }')"
    [ "$image_matches" = 1 ] || return 1
    if [ -z "$stable_pid" ]; then stable_pid="$launch_pid";
    else [ "$stable_pid" = "$launch_pid" ] || return 1; fi
    sleep 1
  done
}

stop_exact_launchd_job() {
  local old_pid="" old_program="" old_state="" launch_state old_image_matches
  if launch_state="$(launchctl print "system/${LABEL}" 2>/dev/null)"; then
    old_program="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" program)" || return 1
    old_state="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" state)" || return 1
    case "$old_program" in
      "$DEST/$LABEL"|"/Library/PrivilegedHelperTools/Tribe/$LABEL") ;;
      *) echo "refusing to stop foreign launchd job"; return 1 ;;
    esac
    if [ "$old_state" = running ]; then
      old_pid="$(printf '%s\n' "$launch_state" | "$LAUNCHCTL_PARSER" pid)" || return 1
      case "$old_pid" in ''|*[!0-9]*) echo "invalid old launchd PID"; return 1 ;; esac
    fi
  fi
  if [ -n "$old_program" ]; then
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
  fi
  for _ in 1 2 3 4 5; do
    launchctl print "system/${LABEL}" >/dev/null 2>&1 || break
    sleep 1
  done
  launchctl print "system/${LABEL}" >/dev/null 2>&1 \
    && { echo "launchd job survived bootout"; return 1; }
  if [ -n "$old_pid" ] && [ -n "$old_program" ]; then
    old_image_matches="$(/usr/sbin/lsof -a -p "$old_pid" -d txt -Fn 2>/dev/null \
      | awk -v expected="n$old_program" '$0 == expected { n++ } END { print n + 0 }')"
    [ "$old_image_matches" = 0 ] \
      || { echo "old launchd PID still executes the service text vnode"; return 1; }
  fi
}

start_launchd_job_and_verify() {
  local candidate_plist="$1" expected_program
  expected_program="$(launch_program_from_plist "$candidate_plist")" || return 1
  launchctl bootstrap system "$candidate_plist" || return 1
  launchctl enable "system/${LABEL}" 2>/dev/null || true
  launchctl kickstart -k "system/${LABEL}" || return 1
  verify_launchd_job_stable "$expected_program"
}

validate_transaction_runtime_markers() {
  local marker
  [ -d "$DEST" ] && [ ! -L "$DEST" ] \
    && [ "$(stat -f '%Su:%Sg:%Lp' "$DEST")" = "root:wheel:755" ] \
    || { echo "unsafe committed Tribe runtime"; return 1; }
  for marker in INSTALL-EPOCH VERSION; do
    [ -f "$DEST/$marker" ] && [ ! -L "$DEST/$marker" ] \
      && [ "$(stat -f '%Su:%Sg:%Lp:%l' "$DEST/$marker")" = "root:wheel:644:1" ] \
      || { echo "unsafe committed runtime marker: $marker"; return 1; }
  done
  [ "$(tr -d '\r\n' < "$DEST/INSTALL-EPOCH")" = "$JOURNAL_EPOCH" ] \
    && [ "$(tr -d '\r\n' < "$DEST/VERSION")" = "$JOURNAL_RUNTIME_VERSION" ] \
    || { echo "committed runtime does not match journal"; return 1; }
}

verify_current_transaction() {
  load_journal || return 1
  case "$JOURNAL_PHASE" in healthy|committed) ;;
    *) echo "transaction has not reached a healthy runtime"; return 1 ;;
  esac
  validate_transaction_runtime_markers || return 1
  [ -e "$PLIST" ] && [ ! -L "$PLIST" ] || return 1
  [ "$(launch_program_from_plist "$PLIST")" = "$DEST/$LABEL" ] || return 1
  verify_launchd_job_stable "$DEST/$LABEL"
}

begin_transaction() {
  validate_privileged_helper_parent || return 1
  [ ! -e "$TX_ROOT" ] && [ ! -L "$TX_ROOT" ] \
    || { echo "pending service transaction already exists"; return 1; }
  mkdir "$TX_ROOT"
  chown root:wheel "$TX_ROOT"
  chmod 700 "$TX_ROOT"
  JOURNAL_HAD_DEST=0
  JOURNAL_HAD_PLIST=0
  case "$JOURNAL_GROUP_CREATED" in 0|1) ;;
    *) JOURNAL_GROUP_CREATED="$GROUP_CREATED" ;;
  esac
  [ ! -e "$DEST" ] && [ ! -L "$DEST" ] || JOURNAL_HAD_DEST=1
  [ ! -e "$PLIST" ] && [ ! -L "$PLIST" ] || JOURNAL_HAD_PLIST=1
  write_journal prepared
  TRANSACTION_STARTED=1
}

# shellcheck disable=SC2329  # invoked by cleanup(), which is installed as EXIT trap
rollback_transaction() {
  local remove_created_group=0
  echo "service update failed; restoring previous service"
  load_journal || return 1
  if [ "$JOURNAL_GROUP_CREATED" = 1 ] \
      && [ "$JOURNAL_HAD_DEST:$JOURNAL_HAD_PLIST" = 0:0 ]; then
    remove_created_group=1
  fi
  stop_exact_launchd_job || return 1
  if [ -e "$OLD" ] || [ -L "$OLD" ]; then
    [ -d "$OLD" ] && [ ! -L "$OLD" ] || return 1
    [ "$JOURNAL_HAD_DEST" = 1 ] || return 1
    if [ -e "$DEST" ] || [ -L "$DEST" ]; then
      [ -d "$DEST" ] && [ ! -L "$DEST" ] || return 1
      [ ! -e "$FAILED" ] && [ ! -L "$FAILED" ] || return 1
      mv "$DEST" "$FAILED"
    fi
    mv "$OLD" "$DEST"
  elif [ "$JOURNAL_HAD_DEST" = 0 ]; then
    if [ -e "$DEST" ] || [ -L "$DEST" ]; then
      [ -d "$DEST" ] && [ ! -L "$DEST" ] || return 1
      [ ! -e "$FAILED" ] && [ ! -L "$FAILED" ] || return 1
      mv "$DEST" "$FAILED"
    fi
  else
    case "$JOURNAL_PHASE" in prepared|old_stopped) ;;
      *) echo "saved previous runtime is missing"; return 1 ;;
    esac
    [ -d "$DEST" ] && [ ! -L "$DEST" ] \
      || { echo "previous runtime disappeared before rollback"; return 1; }
  fi
  if [ -e "$PLIST_OLD" ] || [ -L "$PLIST_OLD" ]; then
    [ -f "$PLIST_OLD" ] && [ ! -L "$PLIST_OLD" ] || return 1
    [ "$JOURNAL_HAD_PLIST" = 1 ] || return 1
    if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then
      validate_launchd_plist_file "$PLIST" || return 1
      rm -f "$PLIST"
    fi
    mv "$PLIST_OLD" "$PLIST"
  elif [ "$JOURNAL_HAD_PLIST" = 0 ]; then
    if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then
      validate_launchd_plist_file "$PLIST" || return 1
      rm -f "$PLIST"
    fi
  else
    case "$JOURNAL_PHASE" in prepared|old_stopped) ;;
      *) echo "saved previous launchd plist is missing"; return 1 ;;
    esac
    validate_launchd_plist_file "$PLIST" || return 1
  fi
  /bin/sync
  if [ "$JOURNAL_HAD_PLIST" = 1 ]; then
    [ -e "$PLIST" ] || { echo "old launchd plist was not restored"; return 1; }
    start_launchd_job_and_verify "$PLIST" \
      || { echo "restored service failed verified launch"; return 1; }
  else
    launchctl print "system/${LABEL}" >/dev/null 2>&1 \
      && { echo "unexpected launchd job after fresh-install rollback"; return 1; }
  fi
  [ ! -e "$FAILED" ] || rm -rf "$FAILED"
  [ ! -e "$NEW" ] || rm -rf "$NEW"
  [ ! -e "$PLIST_TMP" ] || rm -f "$PLIST_TMP"
  TRANSACTION_RECOVERED=1
  remove_transaction_root
  if [ "$remove_created_group" = 1 ] \
      && dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    if ! validate_tribe_group_unused \
        || ! dscl . -delete "/Groups/$GROUP"; then
      echo "restored service; warning: newly-created unused group cleanup failed"
    fi
  fi
}

cleanup_proven_legacy_tribe_runtime() {
  local legacy_dir="/Library/PrivilegedHelperTools/Tribe"
  local legacy_bin="$legacy_dir/$LABEL" legacy_label legacy_program
  [ -f "$PLIST_OLD" ] && [ ! -L "$PLIST_OLD" ] || return 0
  legacy_label="$(plutil -extract Label raw -o - "$PLIST_OLD" 2>/dev/null || true)"
  legacy_program="$(plutil -extract ProgramArguments.0 raw -o - "$PLIST_OLD" 2>/dev/null || true)"
  [ "$legacy_label" = "$LABEL" ] && [ "$legacy_program" = "$legacy_bin" ] \
    || return 0
  [ -d "$legacy_dir" ] && [ ! -L "$legacy_dir" ] \
    && [ "$(stat -f '%Su' "$legacy_dir")" = root ] \
    && [ -f "$legacy_bin" ] && [ ! -L "$legacy_bin" ] \
    && [ "$(stat -f '%Su' "$legacy_bin")" = root ] \
    || { echo "legacy Tribe runtime provenance is incomplete; leaving it untouched"; return 0; }
  codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" "$legacy_bin" \
    || { echo "legacy Tribe runtime signature is foreign; leaving it untouched"; return 0; }
  if ! rm -rf "$legacy_dir"; then
    echo "legacy Tribe runtime cleanup failed after commit; leaving it for a later upgrade"
    return 0
  fi
  echo "removed proven legacy Tribe runtime"
}

cleanup_committed_transaction() {
  verify_current_transaction || return 1
  [ "$JOURNAL_PHASE" = committed ] \
    || { echo "refusing to clean an uncommitted service transaction"; return 1; }
  cleanup_proven_legacy_tribe_runtime \
    || echo "legacy Tribe runtime cleanup failed after service commit"
  remove_transaction_root
}

recover_pending_transaction() {
  local incoming_epoch="$1" incoming_tar_sha="$2"
  [ -e "$TX_ROOT" ] || [ -L "$TX_ROOT" ] || return 0
  if [ ! -e "$JOURNAL" ] && [ ! -L "$JOURNAL" ]; then
    discard_unstarted_transaction
    return
  fi
  load_journal || return 1
  TRANSACTION_STARTED=1
  if [ "$JOURNAL_PHASE" = committed ]; then
    if [ "$incoming_epoch" -lt "$JOURNAL_EPOCH" ]; then
      # A retained OLD tree is a crash/outer-package rollback snapshot, never
      # an authorization to downgrade. In particular, an older still-valid
      # same-Team app must not be able to restore that tree and then pass the
      # ordinary DEST epoch check. Emergency rollback is shipped as the old
      # code in a newly signed package with a strictly higher install epoch.
      echo "refusing signed daemon downgrade against committed journal ($incoming_epoch < $JOURNAL_EPOCH)"
      return 1
    fi
    if [ "$incoming_epoch" -eq "$JOURNAL_EPOCH" ] \
        && [ "$incoming_tar_sha" != "$JOURNAL_TAR_SHA" ]; then
      echo "signed install epoch collision with a different payload"
      return 1
    fi
    if verify_current_transaction; then
      # A matching or newer signed app proves the outer package can no longer
      # roll back this retained transaction. It is now safe to remove the old
      # runtime before beginning another update.
      cleanup_committed_transaction
      TRANSACTION_STARTED=0
      TRANSACTION_COMMITTED=0
      return
    fi
    echo "committed runtime failed proof; restoring the retained old runtime"
  fi
  rollback_transaction
  TRANSACTION_STARTED=0
}

finalize_pending_transaction() {
  local incoming_epoch="$1" incoming_tar_sha="$2" incoming_version="$3"
  load_journal || return 1
  TRANSACTION_STARTED=1
  [ "$JOURNAL_PHASE" = healthy ] \
    && [ "$JOURNAL_EPOCH" = "$incoming_epoch" ] \
    && [ "$JOURNAL_TAR_SHA" = "$incoming_tar_sha" ] \
    && [ "$JOURNAL_RUNTIME_VERSION" = "$incoming_version" ] \
    || { echo "pending service transaction does not match signed package"; return 1; }
  verify_current_transaction || return 1
  write_journal committed
  TRANSACTION_COMMITTED=1
  # Keep OLD until a subsequent matching/newer signed app proves that the
  # enclosing productbuild transaction cannot still roll the app back.
  TRANSACTION_DEFERRED=1
}

# shellcheck disable=SC2329  # invoked by the EXIT trap below
cleanup() {
  rc=$?
  trap - EXIT
  set +e
  if [ "$TRANSACTION_STARTED" -eq 1 ] && [ "$TRANSACTION_COMMITTED" -ne 1 ] \
      && [ "$TRANSACTION_DEFERRED" -ne 1 ]; then
    # A signal can arrive immediately after the durable committed phase rename
    # and before the in-memory flag assignment. Never undo that external commit.
    if load_journal 2>/dev/null && [ "$JOURNAL_PHASE" = committed ]; then
      TRANSACTION_COMMITTED=1
    else
      rollback_transaction || echo "CRITICAL: verified service rollback failed; journal preserved"
    fi
  fi
  [ -z "$SRC" ] || rm -rf "$SRC"
  if [ "$TRANSACTION_STARTED" -eq 0 ] \
      && { [ -e "$TX_ROOT" ] || [ -L "$TX_ROOT" ]; } \
      && [ ! -e "$JOURNAL" ] && [ ! -L "$JOURNAL" ]; then
    discard_unstarted_transaction \
      || echo "CRITICAL: unsafe journal-less service transaction retained"
  fi
  if [ "$TRANSACTION_STARTED" -ne 1 ] || [ "$TRANSACTION_RECOVERED" -eq 1 ] \
      || [ "$TRANSACTION_COMMITTED" -eq 1 ]; then
    [ -z "$NEW" ] || [ ! -e "$NEW" ] || rm -rf "$NEW"
    [ -z "$PLIST_TMP" ] || [ ! -e "$PLIST_TMP" ] || rm -f "$PLIST_TMP"
  fi
  if [ "$GROUP_CREATED" -eq 1 ] && [ "$TRANSACTION_COMMITTED" -ne 1 ] \
      && [ "$TRANSACTION_DEFERRED" -ne 1 ]; then
    if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
      validate_tribe_group_unused \
        && dscl . -delete "/Groups/$GROUP" 2>/dev/null \
        || echo "warning: failed to prove/remove newly-created Tribe group"
    fi
  fi
  rm -f "$LOCK_FILE"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ "${1:-}" = "--is-committed" ]; then
  load_journal && [ "$JOURNAL_PHASE" = committed ]
  exit $?
fi
if [ "${1:-}" = "--rollback-pending" ]; then
  if [ -e "$TX_ROOT" ] || [ -L "$TX_ROOT" ]; then
    if [ ! -e "$JOURNAL" ] && [ ! -L "$JOURNAL" ]; then
      discard_unstarted_transaction
      exit 0
    fi
    load_journal
    [ "$JOURNAL_PHASE" != committed ] \
      || { echo "refusing to roll back a committed service transaction"; exit 1; }
    TRANSACTION_STARTED=1
    rollback_transaction
  fi
  exit 0
fi
if [ "${1:-}" = "--cleanup-committed" ]; then
  cleanup_committed_transaction
  exit 0
fi
if [ "${1:-}" = "--uninstall" ]; then
  if [ -e "$TX_ROOT" ] || [ -L "$TX_ROOT" ]; then
    if [ ! -e "$JOURNAL" ] && [ ! -L "$JOURNAL" ]; then
      discard_unstarted_transaction
    else
    load_journal
    if [ "$JOURNAL_PHASE" = committed ]; then
      cleanup_committed_transaction
    else
      TRANSACTION_STARTED=1
      rollback_transaction
    fi
    fi
  fi
  uninstall_service
  exit 0
fi

TARBALL="${1:?укажи путь к tribe-svc.tar.gz}"
TX_MODE="${2:-install}"
case "$TX_MODE" in install|--defer-finalize|--finalize-pending) ;;
  *) echo "unsupported service transaction mode"; exit 64 ;;
esac
[ -f "$TARBALL" ] || { echo "нет tarball: $TARBALL"; exit 1; }
VERIFIER="$SCRIPT_DIR/macos-service-payload.sh"
EXPECTED_VERSION="$SCRIPT_DIR/tribe-svc.version"
EXPECTED_TARBALL_SHA="$SCRIPT_DIR/tribe-svc.tar.sha256"
EXPECTED_EPOCH="$SCRIPT_DIR/tribe-svc.epoch"
[ -x "$VERIFIER" ] || { echo "нет sealed payload verifier"; exit 1; }
[ -f "$EXPECTED_VERSION" ] || { echo "нет signed app version anchor"; exit 1; }
[ -f "$EXPECTED_TARBALL_SHA" ] || { echo "нет signed tarball digest"; exit 1; }
[ -f "$EXPECTED_EPOCH" ] && [ ! -L "$EXPECTED_EPOCH" ] \
  || { echo "нет signed install epoch"; exit 1; }

# Authenticate every archive byte against a containing-app signed resource
# before privileged listing or extraction.
expected_tar_sha="$(tr -d '\r\n' < "$EXPECTED_TARBALL_SHA")"
case "$expected_tar_sha" in
  ''|*[!0-9a-f]*) echo "invalid signed tarball digest"; exit 1 ;;
esac
[ "${#expected_tar_sha}" -eq 64 ] || { echo "invalid signed tarball digest length"; exit 1; }
actual_tar_sha="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
[ "$actual_tar_sha" = "$expected_tar_sha" ] \
  || { echo "tarball does not match the signed app digest"; exit 1; }

# Reject archive path traversal and any root that is not part of the closed payload contract
# before privileged extraction. The signed app resource remains the trust anchor.
while IFS= read -r entry; do
  case "$entry" in /*|../*|*/../*|*'/..') echo "unsafe tar path: $entry"; exit 1 ;; esac
  case "$entry" in
    Tribe-service|amneziawg-go|openvpn|tun2socks|\
    geoip.dat|geosite.dat|\
    INSTALL-CONTRACT|INSTALL-EPOCH|\
    Frameworks|Frameworks/|Frameworks/*|pf|pf/|pf/*|\
    PAYLOAD-MANIFEST.sha256|PAYLOAD-SYMLINKS|VERSION) ;;
    *) echo "unexpected tar entry: $entry"; exit 1 ;;
  esac
done < <(/usr/bin/bsdtar -tzf "$TARBALL")

SRC="$(mktemp -d)"
chmod 700 "$SRC"
# Preserve the global privileged umask 027, but extract inside a scoped 022
# subshell.  bsdtar --no-same-permissions applies the current umask; with 027
# it would turn the sealed 0755/0644 contract into 0750/0640 and every valid
# payload would be rejected by the exact-mode verifier immediately below.
(
  umask 022
  /usr/bin/bsdtar -xzf "$TARBALL" -C "$SRC" --chroot \
    --no-same-owner --no-same-permissions --no-acls --no-fflags \
    --no-mac-metadata --no-xattrs
) || { echo "распаковка не удалась"; exit 1; }
"$VERIFIER" verify "$SRC" "$EXPECTED_VERSION"

expected_epoch="$(tr -d '\r\n' < "$EXPECTED_EPOCH")"
payload_epoch="$(tr -d '\r\n' < "$SRC/INSTALL-EPOCH")"
payload_version="$(tr -d '\r\n' < "$SRC/VERSION")"
case "$expected_epoch" in ''|*[!0-9]*) echo "invalid signed install epoch"; exit 1 ;; esac
[ "$expected_epoch" -gt 0 ] && [ "$payload_epoch" = "$expected_epoch" ] \
  || { echo "payload install epoch mismatch"; exit 1; }
case "$payload_version" in ''|*[!0-9a-f]*) echo "invalid payload runtime version"; exit 1 ;; esac
[ "${#payload_version}" -eq 64 ] || { echo "invalid payload runtime version length"; exit 1; }

# Product packages split the daemon transaction into a healthy-but-reversible
# phase and a final durable commit. Both calls re-authenticate the same signed
# payload. No normal install evaluates downgrade policy until an interrupted
# transaction has been resolved against its fixed crash journal.
if [ "$TX_MODE" = --finalize-pending ]; then
  finalize_pending_transaction "$expected_epoch" "$expected_tar_sha" "$payload_version"
  echo "Tribe-service transaction committed; rollback snapshot retained."
  exit 0
fi
recover_pending_transaction "$expected_epoch" "$expected_tar_sha"

if [ -e "$DEST/INSTALL-EPOCH" ]; then
  [ -f "$DEST/INSTALL-EPOCH" ] && [ ! -L "$DEST/INSTALL-EPOCH" ] \
    || { echo "unsafe installed epoch marker"; exit 1; }
  installed_epoch="$(tr -d '\r\n' < "$DEST/INSTALL-EPOCH")"
  case "$installed_epoch" in ''|*[!0-9]*) echo "invalid installed epoch marker"; exit 1 ;; esac
  if [ "$expected_epoch" -lt "$installed_epoch" ]; then
    echo "refusing signed daemon downgrade ($expected_epoch < $installed_epoch)"
    exit 1
  fi
  if [ "$expected_epoch" -eq "$installed_epoch" ]; then
    if [ ! -f "$DEST/VERSION" ] || [ -L "$DEST/VERSION" ] \
        || ! cmp -s "$EXPECTED_VERSION" "$DEST/VERSION"; then
      echo "same install epoch is bound to a different payload"
      exit 1
    fi
  fi
fi

for executable in Tribe-service amneziawg-go openvpn tun2socks; do
  codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" "$SRC/$executable" \
    || { echo "invalid Developer ID signature: $executable"; exit 1; }
done
while IFS= read -r -d '' candidate; do
  file -b "$candidate" | grep -q 'Mach-O' || continue
  codesign --verify --strict --verbose=2 -R="$TEAM_REQUIREMENT" "$candidate" \
    || { echo "invalid Framework signature: $candidate"; exit 1; }
done < <(find "$SRC/Frameworks" -type f -print0)

# Decide whether Tribe's own Xray/PF group must be created, but do not mutate
# directory services before the durable prepared journal exists.
GROUP_CREATE_REQUIRED=0
if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
  GROUP_CREATE_REQUIRED=1
else
  validate_tribe_group_unused \
    || { echo "unsafe or in-use tribevpn group"; exit 1; }
fi

# Existing launchd state is part of the rollback transaction.  Authenticate it
# before bootout/move so a substituted plist cannot make the installer stop a
# foreign service.  The historical Tribe path is accepted only for migration.
validate_launchd_parent
validate_privileged_helper_parent
if [ -e "$PLIST" ] || [ -L "$PLIST" ]; then
  validate_launchd_plist_file "$PLIST"
  old_label="$(plutil -extract Label raw -o - "$PLIST" 2>/dev/null || true)"
  old_program="$(plutil -extract ProgramArguments.0 raw -o - "$PLIST" 2>/dev/null || true)"
  [ "$old_label" = "$LABEL" ] \
    || { echo "existing Tribe launchd label mismatch"; exit 1; }
  case "$old_program" in
    "$DEST/$LABEL"|"/Library/PrivilegedHelperTools/Tribe/$LABEL") ;;
    *) echo "existing Tribe launchd program mismatch"; exit 1 ;;
  esac
fi
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  [ -d "$DEST" ] && [ ! -L "$DEST" ] \
    && [ "$(stat -f '%Su:%Sg:%Lp' "$DEST")" = "root:wheel:755" ] \
    || { echo "unsafe existing Tribe runtime"; exit 1; }
fi

# The fixed root-owned journal is created before staging. Every live filesystem
# mutation is followed by a durable phase rename; crash recovery can therefore
# distinguish an untouched old service, saved rollback material and a healthy
# replacement without trusting PID-suffixed temporary paths.
JOURNAL_EPOCH="$expected_epoch"
JOURNAL_TAR_SHA="$expected_tar_sha"
JOURNAL_RUNTIME_VERSION="$payload_version"
JOURNAL_GROUP_CREATED="$GROUP_CREATE_REQUIRED"
begin_transaction

if [ "$GROUP_CREATE_REQUIRED" -eq 1 ]; then
  gid=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' \
    | sort -n | awk '$1>=500{g=$1} END{print (g?g+1:501)}')
  GROUP_CREATED=1
  dscl . -create "/Groups/$GROUP"
  dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
  dscl . -create "/Groups/$GROUP" RealName "Tribe VPN Service Group"
fi
validate_tribe_group_unused \
  || { echo "unsafe or in-use tribevpn group"; exit 1; }

# Build and verify a complete sibling tree before stopping the currently
# running service. NEW is inside the root-only transaction directory but moves
# to DEST on the same filesystem.
mkdir "$NEW"
chmod 700 "$NEW"
for runtime_file in Tribe-service amneziawg-go openvpn tun2socks \
                    geoip.dat geosite.dat INSTALL-CONTRACT INSTALL-EPOCH \
                    PAYLOAD-MANIFEST.sha256 PAYLOAD-SYMLINKS VERSION; do
  cp -f "$SRC/$runtime_file" "$NEW/$runtime_file"
done
cp -aR "$SRC/Frameworks" "$NEW/Frameworks"
cp -aR "$SRC/pf" "$NEW/pf"
chown -R root:wheel "$NEW"
# Reapply the sealed mode contract after the privileged copy. This rejects
# special/writable modes and makes permissions independent of archive metadata.
"$VERIFIER" normalize "$NEW"
xattr -cr "$NEW" 2>/dev/null || true
"$VERIFIER" verify "$NEW" "$EXPECTED_VERSION"

[ ! -e "$PLIST_TMP" ] && [ ! -L "$PLIST_TMP" ] || exit 1
cat > "$PLIST_TMP" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>${DEST}/${LABEL}</string></array>
    <key>KeepAlive</key><true/>
    <key>RunAtLoad</key><true/>
    <key>GroupName</key><string>${GROUP}</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST_TMP"; chmod 644 "$PLIST_TMP"

# Stop only our old daemon, then atomically replace both the runtime tree and plist.
stop_exact_launchd_job
write_journal old_stopped
if [ -e "$DEST" ]; then mv "$DEST" "$OLD"; fi
if [ -e "$PLIST" ]; then mv "$PLIST" "$PLIST_OLD"; fi
write_journal old_saved
mv "$NEW" "$DEST"
write_journal new_runtime
mv "$PLIST_TMP" "$PLIST"
write_journal new_plist

start_launchd_job_and_verify "$PLIST"
write_journal healthy

if [ "$TX_MODE" = --defer-finalize ]; then
  TRANSACTION_DEFERRED=1
  echo "Tribe-service установлен и ожидает внешнего commit."
  exit 0
fi

write_journal committed
TRANSACTION_COMMITTED=1
# From this point the new root service is externally committed. Never return a
# caller-fatal status that could report failure while leaving this daemon.
set +e
trap 'exit 0' HUP INT TERM
cleanup_proven_legacy_tribe_runtime \
  || echo "legacy Tribe runtime cleanup failed after service commit"
remove_transaction_root \
  || echo "committed service transaction cleanup failed; journal retained"
echo "Tribe-service установлен."
exit 0

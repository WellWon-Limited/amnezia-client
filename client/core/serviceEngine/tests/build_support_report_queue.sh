#!/bin/bash
# AVPN - L9 (F12): build + run the support-report queue checks.
#   default   : SupportReportQueue.h checks + TribeSupportChat delivery through the queue against a
#               local fake backend (QtCore + QtNetwork + QtGui; Enrollment and the engine facade stubbed).
#   --mutate  : mutation pass - every rule in MUTATIONS is broken one at a time in a copy of the header
#               and the queue checks must fail for each (exit 0 only when every mutation is caught).
# QT_ROOT=$HOME/Qt/6.11.1/macos (default 6.10.2 like the neighbouring scripts).
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
# Fallback for 3rd submodule headers (qtkeychain) a git worktree may not have checked out.
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
WORK="$(mktemp -d /tmp/tribe-srq.XXXXXX)"
trap 'rm -rf -- "${WORK:?}"' EXIT
ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)

# Queue-only binary (QtCore). $1 = directory searched first for <SupportReportQueue.h>, $2 = output.
build_queue_only() {
  clang++ -std=c++17 -fPIC -w ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} \
    -I"$1" -I"$SE" -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" \
    "$HERE/support_report_queue_check.cpp" \
    -framework QtCore -Wl,-rpath,"$QT/lib" -o "$2"
}

if [ "${1:-}" = "--mutate" ]; then
  build_queue_only "$SE" "$WORK/baseline"
  "$WORK/baseline" >/dev/null 2>&1 || { echo "baseline queue checks fail - fix them before mutating"; exit 1; }
  # name@@from@@to  (literal text of SupportReportQueue.h; "\n" = newline; each "from" must occur once)
  MUTATIONS=(
    "ack-removes-by-position@@            QFile::remove(pathFor(e.id));\n            m_entries.removeAt(idx);@@            QFile::remove(pathFor(e.id));\n            m_entries.removeFirst();"
    "ack-takes-first-pending-not-id@@PartInfo *p = e.part(partId);\n        if (!p)\n            return AckResult::UnknownPart;@@PartInfo *p = nullptr;\n        for (PartInfo &q : e.parts) if (q.state == PartState::Pending) { p = &q; break; }\n        if (!p)\n            return AckResult::UnknownPart;"
    "full-drops-oldest@@            return {EnqueueResult::Full, QString()};@@            { QFile::remove(pathFor(m_entries.first().id)); m_entries.removeFirst(); }"
    "queued-without-write@@        if (!f.commit())\n            return {EnqueueResult::IoError, QString()};@@        f.cancelWriting();"
    "more-than-one-in-flight@@        if (!m_inFlightReport.isEmpty())\n            return std::nullopt;@@"
    "order-by-id-not-sequence@@std::sort(m_entries.begin(), m_entries.end(), [](const Entry &a, const Entry &b) {\n            return a.seq != b.seq ? a.seq < b.seq : a.id < b.id;@@std::sort(m_entries.begin(), m_entries.end(), [](const Entry &a, const Entry &b) {\n            return a.id < b.id;"
    "log-before-text@@[](const PartInput &a, const PartInput &b) { return int(a.kind) < int(b.kind); });@@[](const PartInput &a, const PartInput &b) { return int(a.kind) > int(b.kind); });"
    "network-back-clears-rate-hold@@if (p.state == PartState::Pending && p.hold == Hold::Network) {@@if (p.state == PartState::Pending && p.hold != Hold::None) {"
    "foreground-clears-rate-hold@@(p.hold == Hold::Network || p.hold == Hold::Server)@@p.hold != Hold::None"
    "bench-window-as-support@@return k == PartKind::Bench ? m_limits.benchRateHoldMs : m_limits.supportRateHoldMs;@@return m_limits.supportRateHoldMs;"
    "backoff-uncapped@@return std::min(d, m_limits.backoffMaxMs);@@return d;"
    "backoff-no-growth@@            d *= 2;@@            d *= 1;"
    "terminal-retried-forever@@        case Response::Terminal:\n            p->state = PartState::Rejected;@@        case Response::Terminal:\n            ++p->attempts; p->hold = Hold::Server; p->nextTryAtMs = now + backoffMs(p->attempts); break;\n            p->state = PartState::Rejected;"
    "429-classified-terminal@@    if (httpStatus == 429)\n        return Response::RateLimited;@@"
    "401-classified-terminal@@if (httpStatus == 401 || httpStatus == 403@@if (httpStatus == 403"
    "oversized-part-accepted@@} else if (in.data.size() > maxPartBytes(m_limits, in.kind)) {@@} else if (in.data.size() > maxPartBytes(m_limits, in.kind) + 1) {"
    "text-cap-in-utf16-units@@if (text.toUcs4().size() > m_limits.maxTextCodePoints)@@if (text.size() > m_limits.maxTextCodePoints)"
    "checksum-not-verified@@            if (sha256Hex(decoded.decoded) != p.sha256) {@@            if (false) {"
    "unreadable-file-deleted@@            if (!f.open(QIODevice::ReadOnly)) {\n                ++m_blockedCount;@@            if (!f.open(QIODevice::ReadOnly)) {\n                QFile::remove(path); continue;\n                ++m_blockedCount;"
    "journal-ignored-at-load@@            if (o && o->result == ReportState::Delivered) {@@            if (false) {"
    "reservations-not-counted@@const int liveCount = int(m_entries.size()) + m_blockedCount + otherReservations;@@const int liveCount = int(m_entries.size()) + m_blockedCount;"
    "disk-bound-not-checked@@        if (liveBytes + bytes > m_limits.maxDiskBytes)\n            return false;@@"
    "legacy-id-random@@const QString id = legacyId(data);@@const QString id = QUuid::createUuid().toString(QUuid::WithoutBraces);"
    "clock-back-not-clamped@@        normalizeHolds(now);\n@@"
    "stale-ack-clears-other-flight@@        if (m_inFlightReport == reportId && m_inFlightPart == partId)\n            abandon();@@        abandon();"
    "ack-not-persisted@@        persist(e);\n        if (m_crash && !m_crash(\"ack_after_persist\"))@@        if (m_crash && !m_crash(\"ack_after_persist\"))"
    "rejected-file-deleted@@        m_entries.removeAt(idx);\n        storeRejected(e, pathFor(e.id));@@        m_entries.removeAt(idx);\n        QFile::remove(pathFor(e.id));"
    "rejected-blocks-queue@@        m_entries.removeAt(idx);\n        storeRejected(e, pathFor(e.id));@@        storeRejected(e, pathFor(e.id));"
    "evicts-newest-rejected@@                return a.rejectedAtMs < b.rejectedAtMs;@@                return a.rejectedAtMs > b.rejectedAtMs;"
    "rejected-count-bound-ignored@@(m_rejected.size() > m_limits.maxRejected || bytes > m_limits.maxRejectedBytes)@@(bytes > m_limits.maxRejectedBytes)"
    "rejected-byte-bound-ignored@@(m_rejected.size() > m_limits.maxRejected || bytes > m_limits.maxRejectedBytes)@@(m_rejected.size() > m_limits.maxRejected)"
    "eviction-not-journalled@@            recordOutcome(old.id, ReportState::Rejected, QStringLiteral(\"evicted:\") + rejectReason(old),\n                          partStates(old));@@"
    "retry-not-once@@            if (e.retried)\n                continue;@@"
    "retry-without-context-change@@if ((appChanged || limitsChanged) && requeue(i, /*automatic=*/true))@@if (requeue(i, /*automatic=*/true))"
    "retry-on-unknown-limits@@!m_ctxLimits.isEmpty() && !e.epochLimits.isEmpty() && e.epochLimits != m_ctxLimits@@!m_ctxLimits.isEmpty() && e.epochLimits != m_ctxLimits"
    "retry-resends-acked-parts@@            if (p.state == PartState::Rejected) {\n                p.state = PartState::Pending;@@            if (true) {\n                p.state = PartState::Pending;"
    "retry-ignores-room@@        if (indexOf(e.id) >= 0 || !admits(liveReservations(QString()), e.fileBytes))@@        if (indexOf(e.id) >= 0)"
    "retry-keeps-rejection-journal@@        dropOutcome(e.id);\n        if (m_crash && !m_crash(\"requeue_after_journal\"))@@        if (m_crash && !m_crash(\"requeue_after_journal\"))"
    "requeue-mark-ignored-at-load@@            if (e.requeueMark) { // died inside a retry move: finish it@@            if (false) {"
    "journalled-rejection-deleted-at-load@@            if ((o && o->result == ReportState::Rejected) || (!e.hasPending() && e.hasRejected())) {@@            if (false) {"
    "legacy-dedupe-ignores-journal-and-store@@if (findEntry(id) || m_finalIds.contains(id) || indexOfRejected(id) >= 0)@@if (findEntry(id))"
    "notice-not-created-on-eviction@@            addNotice(old); // written by the same journal save as the eviction below@@"
    "notice-bound-ignored@@        m_notices.append(n);\n        while (m_notices.size() > m_limits.maxNotices)\n            m_notices.removeFirst();@@        m_notices.append(n);"
    "notice-cleared-by-any-ack@@const QStringList delivered = p->kind == PartKind::Text ? e.noticeIds : QStringList();@@const QStringList delivered = e.noticeIds;"
    "notice-kept-after-text-ack@@        dropNotices(delivered, /*save=*/true);\n        return AckResult::Acked;@@        return AckResult::Acked;"
    "notice-kept-after-final-text-ack@@            dropNotices(delivered, /*save=*/false); // saved with the outcome in finalize()@@"
    "notice-attached-twice@@                if (!free.contains(n.reportId))\n                    continue;@@"
    "notice-not-attached@@            if (!noticeIds.isEmpty()) {\n                text = combined;@@            if (false) {\n                text = combined;"
    "notice-over-text-cap@@                if (int(next.toUcs4().size()) > m_limits.maxTextCodePoints)\n                    break;@@"
    "notice-not-reconciled-at-load@@        reconcileNotices();\n@@"
    "notice-free-after-rejected-text@@            if (t && t->state == PartState::Pending)\n                for (const QString &id : e.noticeIds)@@            if (t)\n                for (const QString &id : e.noticeIds)"
    "notice-lost-on-restart@@        for (const QJsonValue &v : root.value(QStringLiteral(\"notice_ids\")).toArray())@@        for (const QJsonValue &v : QJsonArray())"
    "hold-not-persisted@@            break;\n        }\n        persist(e);\n    }@@            break;\n        }\n    }"
  )
  caught=0; missed=0; broken=0
  printf '%-34s %s\n' "mutation" "result"
  for m in "${MUTATIONS[@]}"; do
    name="${m%%@@*}"; rest="${m#*@@}"; from="${rest%%@@*}"; to="${rest#*@@}"
    dir="$WORK/m-$name"; mkdir -p "$dir"
    if ! FROM="$from" TO="$to" python3 -I - "$SE/SupportReportQueue.h" "$dir/SupportReportQueue.h" <<'PY'
import os, sys
src = open(sys.argv[1], encoding="utf-8").read()
frm = os.environ["FROM"].replace("\\n", "\n")
to = os.environ["TO"].replace("\\n", "\n")
n = src.count(frm)
if n != 1:
    sys.stderr.write("pattern occurs %d times\n" % n)
    sys.exit(3)
open(sys.argv[2], "w", encoding="utf-8").write(src.replace(frm, to))
PY
    then
      printf '%-34s %s\n' "$name" "NOT APPLIED"; broken=$((broken + 1)); continue
    fi
    if ! build_queue_only "$dir" "$dir/check" 2>"$dir/build.log"; then
      printf '%-34s %s\n' "$name" "BUILD FAILED"; broken=$((broken + 1)); continue
    fi
    if "$dir/check" >"$dir/run.log" 2>&1; then
      printf '%-34s %s\n' "$name" "MISSED"; missed=$((missed + 1))
    else
      first="$(grep -m1 '^FAIL' "$dir/run.log" | sed 's#^FAIL [^:]*/##' || true)"
      printf '%-34s caught (%s)\n' "$name" "${first:-non-zero exit}"; caught=$((caught + 1))
    fi
  done
  echo ">>> mutations: ${#MUTATIONS[@]}, caught $caught, missed $missed, not applied/build $broken"
  [ "$missed" -eq 0 ] && [ "$broken" -eq 0 ]
  exit $?
fi

# ── default: queue checks + chat delivery ────────────────────────────────────────────────────────
# TribeSupportChat.cpp includes AvpnEngineQml.h (for uiForeground) which pulls containerEnum.h (from
# client/) and secureQSettings.h -> qkeychain_export.h (a generated header: a shim, as in
# build_e2e_support.sh).
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$WORK/qkeychain_export.h"
cat > "$WORK/stubs.cpp" <<'EOF'
// Stubs: a fixed device token instead of SecureQSettings (Keychain); the facade's window state.
#include "Enrollment.h"
namespace avpn {
QString Enrollment::loadToken()
{
    return QStringLiteral("test-token");
}
} // namespace avpn
#include "AvpnEngineQml.h"
bool avpn::AvpnEngineQml::uiForeground()
{
    return true;
}
EOF
"$QT/libexec/moc" -f"TribeSupportChat.h" "$SE/TribeSupportChat.h" -o "$WORK/moc_TribeSupportChat.cpp"
clang++ -std=c++17 -fPIC ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -DSRQ_WITH_CHAT=1 \
  -I"$WORK" -I"$SE" -I"$CLIENT" -I"$MAIN_CLIENT" -I"$QT/include" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtGui.framework/Headers" -F"$QT/lib" \
  "$HERE/support_report_queue_check.cpp" "$SE/TribeSupportChat.cpp" "$WORK/moc_TribeSupportChat.cpp" "$WORK/stubs.cpp" \
  -framework QtCore -framework QtNetwork -framework QtGui -framework Foundation \
  -Wl,-rpath,"$QT/lib" -o "$WORK/support_report_queue_check"
echo ">>> build ok"
QT_PLUGIN_PATH="$QT/plugins" "$WORK/support_report_queue_check"

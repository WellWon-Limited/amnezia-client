#!/bin/bash
# AVPN path engine stage 2: MUTATION TEST of the race's byte accounting. For every invariant a bug it is meant to catch is put
# into a scratch copy of the source (ScanPathProber.cpp for the prober, path/PathRace.h for the race's cap) and the checks must
# FAIL on it: the prober mutants against the model (scan_path_prober_model_check.cpp) and the unit check
# (scan_path_prober_check.cpp), the race mutants against path_engine_check.cpp. A mutant that survives means an invariant
# checks nothing. Exit 0 = every mutation was caught.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
SRC="$SE/ScanPathProber.cpp"
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
WORK="$(mktemp -d /tmp/tribe-prober-mutants.XXXXXX)"
export MODEL_RUNS="${MODEL_RUNS:-1500}"
failed=0

edit() { # source, output, old, new
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
src, out, old, new = sys.argv[1:5]
t = open(src).read()
if t.count(old) != 1:
    sys.exit("mutation anchor not found exactly once: " + old[:70])
open(out, "w").write(t.replace(old, new))
PY
}

mutate() { # name, expected invariant, old, new  (prober mutants: model AND unit check)
  local name="$1" want="$2" old="$3" new="$4"
  edit "$SRC" "$WORK/$name.cpp" "$old" "$new" || { echo "ERROR  $name (anchor)"; failed=1; return; }
  mkdir -p "$WORK/$name.bin" "$WORK/$name.unit"
  local m u
  m="$(PROBER_CPP="$WORK/$name.cpp" OUT_DIR="$WORK/$name.bin" bash "$HERE/build_scan_path_prober_model.sh" 2>&1 | grep -E "^prober model" | tr '\n' ' ')"
  u="$(PROBER_CPP="$WORK/$name.cpp" OUT_DIR="$WORK/$name.unit" bash "$HERE/build_scan_path_prober.sh" 2>&1 | grep -E "FAILED|passed" | tr '\n' ' ')"
  local by=""
  echo "$m" | grep -qE "sequences, [1-9][0-9]* broke" && by="model"
  echo "$u" | grep -q "FAILED" && by="$by unit"
  if [ -n "$by" ]; then echo "caught    $name (expected $want) by: $by"
  elif echo "$m" | grep -q "sequences, 0 broke"; then echo "SURVIVED  $name (expected $want): $m $u"; failed=1
  else echo "ERROR     $name: the mutant did not build or run"; failed=1; fi
}

mutate_race() { # name, expected, old, new  (race mutants: path_engine_check on a mirror of path/ and tests/)
  local name="$1" want="$2" old="$3" new="$4"
  local d="$WORK/race-$name"
  mkdir -p "$d/path" "$d/tests"
  for f in "$SE"/*; do case "$(basename "$f")" in path|tests) ;; *) ln -sf "$f" "$d/" ;; esac; done # the rest of the tree, as it is
  cp "$SE"/path/*.h "$d/path/"; cp "$HERE"/path_engine_check.cpp "$HERE"/path_world.h "$d/tests/"
  edit "$SE/path/PathRace.h" "$d/path/PathRace.h" "$old" "$new" || { echo "ERROR  $name (anchor)"; failed=1; return; }
  if ! clang++ -std=c++17 -fPIC -Wno-everything -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$SE" -F"$QT/lib" \
        "$d/tests/path_engine_check.cpp" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$d/check" 2>"$d/build.log"; then
    echo "ERROR     $name: the mutant did not build"; failed=1; return
  fi
  if ! "$d/check" >/dev/null 2>&1; then echo "caught    $name (expected $want) by: path_engine_check"
  else echo "SURVIVED  $name (expected $want)"; failed=1; fi
}

mutate_engine() { # name, expected, old, new  (engine mutants: ServiceEngine.h, run by path_integration_check on a mirror of the tree)
  local name="$1" want="$2" old="$3" new="$4"
  local d="$WORK/engine-$name" c="$WORK/engine-$name/client"
  mkdir -p "$c/core/serviceEngine/tests"
  for f in "$CLIENT"/*; do [ "$(basename "$f")" = core ] || ln -sf "$f" "$c/"; done
  for f in "$CLIENT"/core/*; do [ "$(basename "$f")" = serviceEngine ] || ln -sf "$f" "$c/core/"; done
  for f in "$SE"/*; do case "$(basename "$f")" in tests|ServiceEngine.h) ;; *) ln -sf "$f" "$c/core/serviceEngine/" ;; esac; done
  cp "$HERE"/* "$c/core/serviceEngine/tests/" 2>/dev/null
  edit "$SE/ServiceEngine.h" "$c/core/serviceEngine/ServiceEngine.h" "$old" "$new" || { echo "ERROR  $name (anchor)"; failed=1; return; }
  if OUT="$d/check" bash "$c/core/serviceEngine/tests/build_path_integration.sh" >"$d/build.log" 2>&1; then
    echo "SURVIVED  $name (expected $want)"; failed=1
  elif [ -x "$d/check" ]; then echo "caught    $name (expected $want) by: path_integration_check"
  else echo "ERROR     $name: the mutant did not build"; failed=1; fi
}

# ---- the prober (model + unit check)
mutate cancelled_result I1 "    m_probes.erase(it); // its seat goes with it (a seat still asked" "    if (onResult) onResult(stamp, path::PathOutcome::Inconclusive, 0);
    m_probes.erase(it); // its seat goes with it (a seat still asked"
mutate result_twice I1 "    if (onResult)
        onResult(p.stamp, outcome, p.bytes);
" "    if (onResult) {
        onResult(p.stamp, outcome, p.bytes);
        onResult(p.stamp, outcome, p.bytes);
    }
"
mutate proven_one_part_short I2 "        if (it->doneParts.size() >= it->parts)" "        if (it->doneParts.size() >= std::max(1, it->parts - 1))"
mutate part_resent_twice I3 "        if (p->partScan.value(c.id) != fromScan)
            continue; // already named in another scan: that scan's own answer decides it
" ""
mutate scan_left_running I4 "    if (m_scan.startSent) {
        const auto book = m_books.find(scanId);" "    if (false) {
        const auto book = m_books.find(scanId);"
mutate drained_scan_closed "I1/I4/I6" "    if (r.progress.done && (r.progress.finalTotals || r.progress.reason != QLatin1String(\"complete\")))
        closeScan(scanId);" "    if (r.progress.done)
        closeScan(scanId);"
mutate delta_charged_twice I6 "    it->seen = total;
    spend(it->race, delta);" "    it->seen = total;
    spend(it->race, delta);
    spend(it->race, delta);"
mutate delta_dropped I6 "    it->seen = total;
    spend(it->race, delta);" "    it->seen = total;"
mutate total_not_delta I6 "    const qint64 delta = total - it->seen;" "    const qint64 delta = total;"
mutate polling_stopped_at_cancel_ack I6 "    book->forgetAtMs = qMax(book->forgetAtMs, mono() + kScanFinalWaitMs);
}" "    m_books.erase(book);
}"
mutate scan_forgotten_before_final I6 "            book->forgetAtMs = mono() + kScanFinalWaitMs;
        const std::weak_ptr<bool> alive" "            book->forgetAtMs = mono() + 1;
        const std::weak_ptr<bool> alive"
mutate final_ack_ignored I6 "    if (r.kind == ScanHostReplyKind::Ack && r.bytesSpent >= 0)
        noteTotal(scanId, r.bytesSpent);" "    if (false)
        noteTotal(scanId, r.bytesSpent);"
mutate size_bound_on_table J6 "    m_books.insert(m_scan.id, book); // its host counter" "    while (m_books.size() >= 16)
        m_books.erase(m_books.begin());
    m_books.insert(m_scan.id, book); // its host counter"
mutate idle_scan_cancelled J4 "    if (onResult)
        onResult(p.stamp, outcome, p.bytes);
}" "    if (onResult)
        onResult(p.stamp, outcome, p.bytes);
    bool bound = false;
    for (const Probe &q : m_probes)
        bound = bound || q.scanId == m_scan.id;
    if (!bound && !m_scan.closed)
        endHostScan();
}"
mutate local_failure_charged J5 "            finish(key, path::PathOutcome::Inconclusive, m_caps.maxAwgConcurrent <= 0 ? \"awg_no_host\"" "            spend(0, 1000);
            finish(key, path::PathOutcome::Inconclusive, m_caps.maxAwgConcurrent <= 0 ? \"awg_no_host\""

# ---- the race's cap (path_engine_check)
mutate_race reservation_kept_at_timeout cap "                m_held.insert(it.key(), costOf(it.value().path)); // it is no longer a candidate, its bytes are not settled yet
                it = m_inFlight.erase(it);" "                it.value().deadline = std::numeric_limits<qint64>::max(); // mutant: the flight stays
                ++it;"
mutate_race reservation_kept_at_result cap "        m_inFlight.erase(it); // its hold on the cap ends with it" "        it.value().deadline = std::numeric_limits<qint64>::max(); // mutant: the flight stays"
mutate_race reservation_kept_when_leg_raised cap "                m_held.insert(it.key(), costOf(it.value().path));
                it = m_inFlight.erase(it);" "                it.value().path.id.id = QStringLiteral(\"-\");
                ++it;"
mutate_race admission_ignores_holds cap "m_spent + reservedInFlight() + costOf(c) <= m_cap" "m_spent + costOf(c) <= m_cap"
mutate_race spent_not_counted cap "            m_spent += bytes;" "            m_spent += 0;"
mutate_race reservation_released_at_timeout cap "                m_held.insert(it.key(), costOf(it.value().path)); // it is no longer a candidate, its bytes are not settled yet
" ""
mutate_race reservation_released_when_leg_raised cap "                m_held.insert(it.key(), costOf(it.value().path));
                it = m_inFlight.erase(it);" "                it = m_inFlight.erase(it);"
mutate_race race_ends_while_hold_waits cap "m_inFlight.isEmpty() && m_held.isEmpty() && m_next" "m_inFlight.isEmpty() && m_next"
mutate_engine late_spend_charged_to_current_race finding3 "        if (race != 0 && race == m_race.raceNumber())" "        if (race != 0)"
mutate_engine hour_ledger_skips_other_race finding3 "        if (m_chargeProbeBytes)
            m_chargeProbeBytes(bytes);
    }" "        if (m_chargeProbeBytes && (race == 0 || race == m_race.raceNumber()))
            m_chargeProbeBytes(bytes);
    }"
mutate settled_at_cancel_not_at_final I8 "    if (followed)
        m_unsettled[it->scanId] << stamp;" "    if (false)
        m_unsettled[it->scanId] << stamp;"
mutate settle_at_cancel_while_api_request_in_flight R1 "    if (seat) { // the seat: the batch request still runs" "    if (false) { // the seat: the batch request still runs"
mutate settle_at_cancel_while_session_fetch_runs R1 "    if (it->waitingSession && m_sessionFetching) {" "    if (false) {"
echo "work dir: $WORK"
exit $failed

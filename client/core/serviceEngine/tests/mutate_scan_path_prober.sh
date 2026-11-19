#!/bin/bash
# AVPN path engine stage 2: MUTATION TEST of the prober's model check. For every invariant of
# scan_path_prober_model_check.cpp a bug it is meant to catch is put into a scratch copy of ScanPathProber.cpp and the model
# must FAIL on it; an invariant no mutation can break is not checking anything. Exit 0 = every mutation was caught.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)/ScanPathProber.cpp"
WORK="$(mktemp -d /tmp/tribe-prober-mutants.XXXXXX)"
export MODEL_RUNS="${MODEL_RUNS:-1500}"
mutate() { # name, expected invariant, python expression: replace(old, new)
  local name="$1" want="$2" old="$3" new="$4"
  python3 - "$SRC" "$WORK/$name.cpp" "$old" "$new" <<'PY'
import sys
src, out, old, new = sys.argv[1:5]
t = open(src).read()
if t.count(old) != 1:
    sys.exit("mutation anchor not found exactly once: " + old[:60])
open(out, "w").write(t.replace(old, new))
PY
  [ $? -eq 0 ] || { echo "ERROR  $name (anchor)"; failed=1; return; }
  local out; mkdir -p "$WORK/$name.bin"
  out="$(PROBER_CPP="$WORK/$name.cpp" OUT_DIR="$WORK/$name.bin" bash "$HERE/build_scan_path_prober_model.sh" 2>&1 | grep -E "^prober model|^  I" | tr '\n' ' ')"
  if echo "$out" | grep -qE "sequences, [1-9][0-9]* broke"; then echo "caught    $name (expected $want): $out"
  elif echo "$out" | grep -q "sequences, 0 broke"; then echo "SURVIVED  $name (expected $want): $out"; failed=1
  else echo "ERROR     $name: the mutant did not build or run"; failed=1; fi
}
failed=0
mkdir -p "$WORK"; for d in "$WORK"/*.bin; do :; done
mutate cancelled_result I1 "    m_probes.erase(it); // its seat goes with it" "    if (onResult) onResult(stamp, path::PathOutcome::Inconclusive, 0);
    m_probes.erase(it); // its seat goes with it"
mutate result_twice I1 "    if (onResult)
        onResult(p.stamp, outcome, bytes);
" "    if (onResult) {
        onResult(p.stamp, outcome, bytes);
        onResult(p.stamp, outcome, bytes);
    }
"
mutate proven_one_part_short I2 "        if (it->doneParts.size() >= it->parts)" "        if (it->doneParts.size() >= std::max(1, it->parts - 1))"
mutate part_resent_twice I3 "        if (p->partScan.value(c.id) != fromScan)
            continue; // already named in another scan: that scan's own answer decides it
" ""
mutate scan_left_running I4 "    if (m_scan.startSent) {
        m_cancelSent.insert(scanId);" "    if (false) {
        m_cancelSent.insert(scanId);"
mutate known_bytes_dropped I5 "    const qint64 bytes = p.reachedHost ? p.bytes : -1;" "    const qint64 bytes = -1;"
mutate result_before_ack_forgotten I5 "        it->reachedHost = true; // a result proves the host took the part, whatever order its ack comes in
" ""
mutate remainder_overcharged I6 "    const qint64 extra = total - it.value();" "    const qint64 extra = total;"
mutate remainder_never_charged I6 "    if (extra > 0 && chargeApiBytes)
        chargeApiBytes(extra);
    say(QStringLiteral(\"race_prober scan_final" "    say(QStringLiteral(\"race_prober scan_final"
mutate drained_scan_closed "I1/I4/I6" "    if (r.progress.done && (r.progress.finalTotals || r.progress.reason != QLatin1String(\"complete\"))) {" "    if (r.progress.done) {"
echo "work dir: $WORK"
exit $failed

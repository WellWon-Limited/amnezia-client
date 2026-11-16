#!/bin/bash
# Standalone build + run of the contract between ScanMachine.h (the Doctor summary it writes) and DoctorReport.h
# (the app's own validator of the schema-5 report): the real machine's summaries of the whole scenario set
# through the real validator, unchanged (lab seam S1, 16.11). Headers only, QtCore. No network, no tunnel.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-scan-summary-contract.XXXXXX)}"
mkdir -p "$OUT_DIR"
FLAGS=(-std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." -F"$QT/lib")
clang++ "${FLAGS[@]}" "$HERE/scan_summary_contract_check.cpp" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/scan_summary_contract_check"
cd "$HERE"
"$OUT_DIR/scan_summary_contract_check"

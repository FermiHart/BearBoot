#!/bin/bash
# test/run.sh — build + run the BBP Josh-Bear adapter harness (hosted).
#   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
#   SPDX-License-Identifier: BSD-3-Clause
#
# Unlike the MINIX port (whose harness is a higher-half Limine ISO booted under
# QEMU), the Josh-Bear adapter runs AFTER vmm/pmm/heap are up, so the shipped
# code is testable hosted: this script compiles the standalone harness with the
# host cc — feeding SYNTHETIC Limine boot data to the SHIPPED port objects
# (../osif.c + ../adapter.c) linked against the frozen BBP core — and greps the
# output for "RESULT: PASS". Proves SPEC §10.1(b) translation on the shipped
# objects without needing the Josh kernel. Writes nothing outside ports/josh/.
#
# Exit 0 iff the harness prints "RESULT: PASS"; non-zero otherwise.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"          # ports/josh/test
PORT="$(dirname "$HERE")"                        # ports/josh
ROOT="$(cd "$PORT/../.." && pwd)"               # BearBoot root

CC="${HOSTCC:-cc}"
BUILD="$HERE/build"
BIN="$BUILD/josh_bbp_test"
LOG="$HERE/run.log"

CFLAGS="-std=c11 -Wall -Wextra -I$ROOT/include"

rm -rf "$BUILD"
mkdir -p "$BUILD"

echo "== compiling harness + shipped port objects + frozen core =="
$CC $CFLAGS \
    "$HERE/harness.c" \
    "$PORT/osif.c" \
    "$PORT/adapter.c" \
    "$ROOT/kernel/bbp_kernel.c" \
    "$ROOT/bootloader/bbp_build.c" \
    -o "$BIN"
echo "   built: $BIN"

echo "== running harness =="
rm -f "$LOG"
set +e
"$BIN" | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e

echo "--------------------------------------------"
if [ "$RC" -eq 0 ] && grep -q "RESULT: PASS" "$LOG"; then
    echo "HARNESS PASS"
    exit 0
else
    echo "HARNESS FAIL (exit $RC, or no 'RESULT: PASS' in output)"
    exit 1
fi

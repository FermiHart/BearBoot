#!/bin/bash
# test/run.sh — build + boot the BBP MINIX adapter harness under QEMU.
#   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
#   SPDX-License-Identifier: BSD-3-Clause
#
# Builds a standalone higher-half Limine kernel that feeds REAL Limine boot
# data to the SHIPPED port code (osif.c + adapter.c) and prints the parser's
# verdict over serial. Proves SPEC §10.1(b) on genuine hardware data.
#
# Reuses the Limine BIOS-CD assets already vendored in the MINIX tree; nothing
# outside ports/minix/ is written. Output: test/serial.log (the deliverable).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"          # ports/minix/test
PORT="$(dirname "$HERE")"                        # ports/minix
ROOT="$(cd "$PORT/../.." && pwd)"                # BearBoot root
LIMINE="/Users/admin/OS/minix/minix/kernel/boot/limine"

CROSS="${CROSS:-x86_64-elf-}"
CC="${CROSS}gcc"
LD="${CROSS}ld"

BUILD="$HERE/build"
ISO_ROOT="$BUILD/iso_root"
ISO="$BUILD/harness.iso"
ELF="$BUILD/harness.elf"
SERIAL="$HERE/serial.log"

rm -rf "$BUILD"
mkdir -p "$BUILD" "$ISO_ROOT/boot/limine" "$ISO_ROOT/EFI/BOOT"

CFLAGS="-ffreestanding -fno-stack-protector -fno-stack-clash-protection \
        -mno-red-zone -mno-sse -mno-mmx -fno-pic -fno-pie -mcmodel=kernel \
        -Wall -Wextra -std=c11 -O2 -g -I$ROOT/include"

echo "== compiling harness + shipped port objects + frozen core =="
$CC $CFLAGS -c "$HERE/boot.S"               -o "$BUILD/boot.o"
$CC $CFLAGS -c "$HERE/harness.c"            -o "$BUILD/harness.o"
$CC $CFLAGS -c "$PORT/osif.c"               -o "$BUILD/osif.o"
$CC $CFLAGS -c "$PORT/adapter.c"            -o "$BUILD/adapter.o"
$CC $CFLAGS -c "$ROOT/kernel/bbp_kernel.c"  -o "$BUILD/bbp_kernel.o"
$CC $CFLAGS -c "$ROOT/bootloader/bbp_build.c" -o "$BUILD/bbp_build.o"

echo "== linking higher-half harness.elf =="
$LD -nostdlib -static -no-pie -z max-page-size=0x1000 \
    -T "$HERE/linker.ld" \
    "$BUILD/boot.o" "$BUILD/harness.o" "$BUILD/osif.o" "$BUILD/adapter.o" \
    "$BUILD/bbp_kernel.o" "$BUILD/bbp_build.o" \
    -o "$ELF"
echo "   $(ls -lh "$ELF" | awk '{print $5}')  $ELF"

echo "== staging Limine BIOS-CD ISO =="
cp "$ELF" "$ISO_ROOT/boot/harness.elf"
cp "$HERE/limine.conf" "$ISO_ROOT/boot/limine/limine.conf"
cp "$LIMINE/limine-bios.sys" "$LIMINE/limine-bios-cd.bin" \
   "$LIMINE/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$LIMINE/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/" 2>/dev/null || true

xorriso -as mkisofs -R -r -J \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ISO_ROOT" -o "$ISO" 2>&1 | tail -2

# BIOS-install Limine onto the ISO so it is bootable on the BIOS path.
limine bios-install "$ISO" 2>&1 | tail -1 || true

echo "== booting under QEMU (BIOS, headless, serial -> log) =="
rm -f "$SERIAL"
set +e
qemu-system-x86_64 \
    -M q35 -m 512M \
    -cdrom "$ISO" \
    -boot d \
    -serial "file:$SERIAL" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -display none -no-reboot \
    -d guest_errors 2>"$BUILD/qemu.stderr"
QCODE=$?
set -e

echo "== QEMU exited with status $QCODE (33 == harness PASS) =="
echo "---------------- serial.log ----------------"
cat "$SERIAL" 2>/dev/null || echo "(no serial output captured)"
echo "--------------------------------------------"

# isa-debug-exit success path: 0x10 -> ((0x10<<1)|1) = 33.
if [ "$QCODE" -eq 33 ]; then
    echo "HARNESS PASS"
    exit 0
else
    echo "HARNESS FAIL (qemu status $QCODE)"
    exit 1
fi

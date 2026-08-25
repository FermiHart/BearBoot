#!/usr/bin/env bash
# Rebuild and execute the Wave 17 x86_64 ELF-to-BBP OVMF machine proof.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TIMEOUT_SECONDS=${BBP_UEFI_TIMEOUT:-30}
CLANG=${CLANG:-clang}
ELF_LD=${ELF_LD:-ld.lld}
EFI_LD=${EFI_LD:-lld-link}
PYTHON=${PYTHON:-python3}
QEMU=${QEMU:-qemu-system-x86_64}
TIMEOUT_BIN=${TIMEOUT_BIN:-timeout}

die()
{
    printf 'UEFI loader machine proof: FAIL: %s\n' "$*" >&2
    exit 1
}

require_tool()
{
    command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

case "$TIMEOUT_SECONDS" in
    ''|*[!0-9]*) die "BBP_UEFI_TIMEOUT must be a positive integer" ;;
    0) die "BBP_UEFI_TIMEOUT must be greater than zero" ;;
esac

require_tool "$CLANG"
require_tool "$ELF_LD"
require_tool "$EFI_LD"
require_tool "$PYTHON"
require_tool "$QEMU"
require_tool "$TIMEOUT_BIN"
require_tool grep
require_tool tr
require_tool cp
require_tool mktemp
require_tool sha256sum

if [[ -n ${OVMF_CODE:-} || -n ${OVMF_VARS:-} ]]; then
    [[ -n ${OVMF_CODE:-} && -n ${OVMF_VARS:-} ]] ||
        die "set both OVMF_CODE and OVMF_VARS, or neither"
else
    for pair in \
        '/usr/share/OVMF/OVMF_CODE_4M.fd|/usr/share/OVMF/OVMF_VARS_4M.fd' \
        '/usr/share/OVMF/OVMF_CODE.fd|/usr/share/OVMF/OVMF_VARS.fd' \
        '/usr/share/edk2/ovmf/OVMF_CODE.fd|/usr/share/edk2/ovmf/OVMF_VARS.fd' \
        '/usr/share/edk2/x64/OVMF_CODE.fd|/usr/share/edk2/x64/OVMF_VARS.fd'
    do
        code=${pair%%|*}
        vars=${pair#*|}
        if [[ -r $code && -r $vars ]]; then
            OVMF_CODE=$code
            OVMF_VARS=$vars
            break
        fi
    done
fi
[[ -n ${OVMF_CODE:-} && -r $OVMF_CODE ]] || die "readable OVMF code image not found"
[[ -n ${OVMF_VARS:-} && -r $OVMF_VARS ]] || die "readable OVMF vars image not found"

# A fresh directory beneath build/ prevents this proof from touching tracked
# evidence or artifacts from another run. It is retained for inspection.
mkdir -p "$ROOT/build"
BUILD_DIR=$(mktemp -d "$ROOT/build/uefi-loader-machine.XXXXXX")
OBJ_DIR=$BUILD_DIR/obj
ESP_DIR=$BUILD_DIR/esp
EFI_DIR=$ESP_DIR/EFI/BOOT
SERIAL_LOG=$BUILD_DIR/serial.raw
SERIAL_TEXT=$BUILD_DIR/serial.txt
TEST_VARS=$BUILD_DIR/OVMF_VARS.fd
KERNEL_ELF=$ESP_DIR/kernel.elf
EFI_APP=$EFI_DIR/BOOTX64.EFI
mkdir -p "$OBJ_DIR" "$EFI_DIR"

printf 'UEFI loader machine proof build: %s\n' "$BUILD_DIR"
printf 'OVMF code: %s\nOVMF vars: %s\n' "$OVMF_CODE" "$OVMF_VARS"

KERNEL_CFLAGS=(
    --target=x86_64-unknown-none-elf
    -ffreestanding -fno-stack-protector -mno-red-zone -mno-sse -mno-mmx
    -fno-pic -mcmodel=kernel -Wall -Wextra -Werror -std=c11 -O2
    -I"$ROOT/include"
)

"$CLANG" "${KERNEL_CFLAGS[@]}" \
    -c "$ROOT/tests/uefi_loader_kernel.c" -o "$OBJ_DIR/kernel.o"
"$CLANG" "${KERNEL_CFLAGS[@]}" \
    -c "$ROOT/kernel/bbp_kernel.c" -o "$OBJ_DIR/kernel_parser.o"
"$ELF_LD" -nostdlib -static -z max-page-size=0x1000 \
    -T "$ROOT/tests/uefi_loader_kernel.ld" \
    "$OBJ_DIR/kernel.o" "$OBJ_DIR/kernel_parser.o" -o "$KERNEL_ELF"
"$PYTHON" "$ROOT/tools/bbp_stamp.py" "$KERNEL_ELF" \
    --requests-symbol bbp_requests
"$PYTHON" "$ROOT/tools/bbp_stamp.py" "$KERNEL_ELF" --check

EFI_CFLAGS=(
    --target=x86_64-pc-win32-coff
    -ffreestanding -fshort-wchar -mno-red-zone -fno-stack-protector
    -mno-stack-arg-probe -Wall -Wextra -Werror -std=c11 -O2
    -I"$ROOT/include"
)

"$CLANG" "${EFI_CFLAGS[@]}" \
    -c "$ROOT/bootloader/efi_main.c" -o "$OBJ_DIR/efi_main.obj"
"$CLANG" "${EFI_CFLAGS[@]}" \
    -c "$ROOT/bootloader/bbp_build.c" -o "$OBJ_DIR/efi_build.obj"
"$CLANG" "${EFI_CFLAGS[@]}" \
    -c "$ROOT/kernel/bbp_kernel.c" -o "$OBJ_DIR/efi_parser.obj"
"$CLANG" "${EFI_CFLAGS[@]}" \
    -c "$ROOT/bootloader/uefi/elf64_loader.c" -o "$OBJ_DIR/elf64_loader.obj"
"$CLANG" "${EFI_CFLAGS[@]}" \
    -c "$ROOT/bootloader/uefi/uefi_exit.c" -o "$OBJ_DIR/uefi_exit.obj"

"$EFI_LD" /subsystem:efi_application /entry:efi_main /nodefaultlib \
    /machine:x64 "/out:$EFI_APP" \
    "$OBJ_DIR/efi_main.obj" "$OBJ_DIR/efi_build.obj" \
    "$OBJ_DIR/efi_parser.obj" "$OBJ_DIR/elf64_loader.obj" \
    "$OBJ_DIR/uefi_exit.obj"

cp "$OVMF_VARS" "$TEST_VARS"
set +e
"$TIMEOUT_BIN" --foreground -k 5 "$TIMEOUT_SECONDS" \
    "$QEMU" \
    -accel tcg -machine q35 -m 128M \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$TEST_VARS" \
    -drive "format=raw,file=fat:rw:$ESP_DIR" \
    -boot order=c,menu=off -display none -monitor none \
    -serial "file:$SERIAL_LOG" -nic none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
qemu_status=$?
set -e

[[ -f $SERIAL_LOG ]] || die "QEMU produced no serial log"
tr -d '\r' < "$SERIAL_LOG" > "$SERIAL_TEXT"
printf '%s\n' '--- OVMF serial ---'
tr -d '\r' < "$SERIAL_LOG"
printf '%s\n' '--- end serial ---'

if [[ $qemu_status -eq 124 || $qemu_status -eq 137 ]]; then
    die "QEMU exceeded the ${TIMEOUT_SECONDS}s hard timeout"
fi
[[ $qemu_status -eq 33 ]] ||
    die "QEMU debug-exit status was $qemu_status, expected 33"
if grep -Fq 'BBP-UEFI-LOADER: FAIL:' "$SERIAL_TEXT"; then
    die "guest serial contains a loader/kernel FAIL marker"
fi
PASS_LINE='BBP-UEFI-LOADER: PASS ELF64 HEADER EBS PAGING HHDM TAGS RDI'
grep -Fxq "$PASS_LINE" "$SERIAL_TEXT" || die "exact serial PASS line missing"

sha256sum "$EFI_APP" "$KERNEL_ELF"
printf 'UEFI loader machine proof: PASS (QEMU status 33)\n'

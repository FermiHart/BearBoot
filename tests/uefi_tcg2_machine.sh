#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD="$ROOT/build/uefi-tcg2"
ESP="$BUILD/esp"
STATE="$BUILD/swtpm-state"
CONTROL="$BUILD/swtpm-control.sock"
PIDFILE="$BUILD/swtpm.pid"
SERIAL="$BUILD/serial.log"
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
VARS="$BUILD/OVMF_VARS.test.fd"
CC=${HOSTCC:-cc}
UEFI_CC=${UEFI_CC:-clang}
UEFI_LD=${UEFI_LD:-lld-link}

cleanup() {
    if [[ -s "$PIDFILE" ]]; then
        timeout --foreground -k 1 5 kill "$(<"$PIDFILE")" 2>/dev/null || true
    fi
}
trap cleanup EXIT

for tool in timeout "$CC" "$UEFI_CC" "$UEFI_LD" qemu-system-x86_64 swtpm python3; do
    command -v "$tool" >/dev/null || {
        printf 'BLOCKED: required tool not found: %s\n' "$tool" >&2
        exit 1
    }
done
for firmware in "$OVMF_CODE" "$OVMF_VARS"; do
    [[ -r "$firmware" ]] || {
        printf 'BLOCKED: required OVMF image is not readable: %s\n' "$firmware" >&2
        exit 1
    }
done

timeout --foreground -k 2 10 rm -rf "$BUILD"
timeout --foreground -k 2 10 mkdir -p "$ESP/EFI/BOOT" "$STATE"
timeout --foreground -k 2 10 cp "$OVMF_VARS" "$VARS"

HOST_FLAGS=(-Wall -Wextra -Werror -std=c11 -O2 -g -I"$ROOT/include")
timeout --foreground -k 2 30 "$CC" "${HOST_FLAGS[@]}" \
    "$ROOT/tests/uefi_tcg2_wire_selftest.c" \
    "$ROOT/experimental/firmware/uefi/tcg2/bbp_uefi_tcg2.c" \
    -o "$BUILD/uefi_tcg2_wire_selftest"
timeout --foreground -k 2 10 "$BUILD/uefi_tcg2_wire_selftest" | \
    tee "$BUILD/wire-selftest.log"

UEFI_FLAGS=(--target=x86_64-pc-win32-coff -ffreestanding -fshort-wchar \
    -mno-red-zone -mno-stack-arg-probe -fno-stack-protector \
    -Wall -Wextra -Werror -std=c11 -O2 -I"$ROOT/include")
timeout --foreground -k 2 30 "$UEFI_CC" "${UEFI_FLAGS[@]}" -c \
    "$ROOT/tests/uefi_tcg2_roundtrip.c" -o "$BUILD/app.obj"
timeout --foreground -k 2 30 "$UEFI_CC" "${UEFI_FLAGS[@]}" -c \
    "$ROOT/experimental/firmware/uefi/tcg2/bbp_uefi_tcg2.c" \
    -o "$BUILD/tcg2.obj"
timeout --foreground -k 2 30 "$UEFI_CC" "${UEFI_FLAGS[@]}" -c \
    "$ROOT/experimental/firmware/uefi/bbp_security_collector.c" \
    -o "$BUILD/collector.obj"
timeout --foreground -k 2 30 "$UEFI_CC" "${UEFI_FLAGS[@]}" -c \
    "$ROOT/bootloader/bbp_build.c" -o "$BUILD/builder.obj"
timeout --foreground -k 2 30 "$UEFI_CC" "${UEFI_FLAGS[@]}" -c \
    "$ROOT/kernel/bbp_kernel.c" -o "$BUILD/parser.obj"
timeout --foreground -k 2 30 "$UEFI_LD" /subsystem:efi_application \
    /entry:efi_main /nodefaultlib /machine:x64 \
    "/out:$ESP/EFI/BOOT/BOOTX64.EFI" \
    "$BUILD/app.obj" "$BUILD/tcg2.obj" "$BUILD/collector.obj" \
    "$BUILD/builder.obj" "$BUILD/parser.obj"

timeout --foreground -k 2 10 swtpm socket --tpm2 \
    --tpmstate "dir=$STATE" \
    --ctrl "type=unixio,path=$CONTROL" \
    --pid "file=$PIDFILE" \
    --log "file=$BUILD/swtpm.log,level=5" --daemon
for _ in {1..50}; do
    [[ -S "$CONTROL" && -s "$PIDFILE" ]] && break
    sleep 0.1
done
[[ -S "$CONTROL" && -s "$PIDFILE" ]] || {
    echo "BLOCKED: swtpm control socket did not become ready" >&2
    exit 1
}

set +e
timeout --foreground -k 5 60 qemu-system-x86_64 \
    -accel tcg -machine q35 -m 256M \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -boot order=c,menu=off -display none -monitor none \
    -serial "file:$SERIAL" -nic none -no-reboot \
    -chardev "socket,id=chrtpm,path=$CONTROL" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
qemu_status=$?
set -e

if [[ -f "$SERIAL" ]]; then
    timeout --foreground -k 2 5 tr -d '\r' < "$SERIAL"
fi
if [[ $qemu_status -eq 124 || $qemu_status -eq 137 ]]; then
    echo "BLOCKED: OVMF/QEMU exceeded the 60 second hard timeout" >&2
    exit 1
fi
if [[ $qemu_status -ne 33 ]]; then
    printf 'FAILED: OVMF guest status %d, expected 33\n' "$qemu_status" >&2
    if [[ -f "$SERIAL" ]] && grep -Fq \
        'BBP-UEFI-TCG2: FAIL: EFI_TCG2_PROTOCOL not found' "$SERIAL"; then
        echo "BLOCKED: installed OVMF does not expose EFI_TCG2_PROTOCOL" >&2
    fi
    exit 1
fi
grep -Fq 'BBP-UEFI-TCG2: PASS' "$SERIAL" || {
    echo "FAILED: serial log lacks EFI machine PASS" >&2
    exit 1
}
if grep -Fq 'BBP-UEFI-TCG2: FAIL:' "$SERIAL"; then
    echo "FAILED: EFI app reported failure" >&2
    exit 1
fi

timeout --foreground -k 2 15 python3 "$ROOT/tests/uefi_tcg2_verify.py" \
    --control "$CONTROL" --serial "$SERIAL" \
    --output "$BUILD/pcr-evidence.json" | tee "$BUILD/host-verification.log"
printf 'Evidence: %s\n' "$SERIAL"
printf 'Evidence: %s\n' "$BUILD/pcr-evidence.json"
printf 'Evidence: %s\n' "$BUILD/swtpm-state"

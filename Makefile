# Bear Boot Protocol (BBP) — build & test
#
#   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
#   SPDX-License-Identifier: BSD-3-Clause
#
# Targets:
#   make test          host-compile + run the ABI/CRC/round-trip self-test
#   make freestanding  cross-compile kernel-side + example as a kernel would
#   make kernel        link the example into a stamped, bootable kernel.elf
#   make fuzz          build + smoke-run the parser fuzzer
#   make qemu          build + boot the bare-metal round-trip proof under TCG
#   make qemu-aarch64  build + boot the AArch64 X0 + DTB proof under TCG
#   make qemu-riscv64  build + boot the RV64 A0 + DTB proof under TCG
#   make qemu-uefi     build + boot the EFI builder/parser proof under OVMF
#   make importers-test verify bounded Limine, Multiboot2, and UEFI translation
#   make bbpctl-test   verify the host-only BBPC capture tool and fixtures
#   make sdk-check     verify C/host packages and the no_std Rust wire crate
#   make sdk-package   build reproducible local SDK archives
#   make release-metadata-test verify support-matrix and SPDX generation
#   make v2-test       verify the experimental offline v2 capsule and bridge
#   make v2-portability cross-compile the v2 Draft core and bridge for three ISAs
#   make abi           just verify the _Static_asserts compile (fastest gate)
#   make check         run host gates plus generated documentation checks
#   make clean

CROSS    ?= x86_64-elf-
CC        := $(CROSS)gcc
LD        := $(CROSS)ld
HOSTCC   ?= cc
PYTHON   ?= python3
HOST_NM       ?= nm
HOST_OBJCOPY  ?= objcopy
HOST_OBJDUMP  ?= objdump
HOST_READELF  ?= readelf

INCLUDE   := -Iinclude

# Freestanding flags for anything linked into a kernel / bootloader.
FREEFLAGS := -ffreestanding -fno-stack-protector -fno-stack-clash-protection \
             -mno-red-zone -mno-sse -mno-mmx -fno-pic \
             -mcmodel=kernel -Wall -Wextra -Werror -std=c11 -O2 -g

# Kernel link flags (static, no PIE, use our linker script).
KLDFLAGS  := -nostdlib -static -no-pie -z max-page-size=0x1000 \
             -T examples/linker.ld

# Host flags for the self-test (runs on the build machine).
HOSTFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g

# Fuzzer: prefer clang libFuzzer; fall back to a deterministic stdin driver.
FUZZCC   ?= clang

BUILD := build
IMPORT_SOURCES := bootloader/bbp_import.c bootloader/bbp_import_limine.c \
	bootloader/bbp_import_multiboot2.c bootloader/bbp_import_uefi.c
IMPORT_OBJECTS := $(patsubst bootloader/%.c,$(BUILD)/%.o,$(IMPORT_SOURCES))
BBP_HEADERS := include/bbp/bbp.h include/bbp/bbp_crc64.h \
	bootloader/bbp_build.h bootloader/bbp_import.h kernel/bbp_kernel.h
V2_HEADERS := include/bbp/bbp_v2.h include/bbp/bbp_v2_profile.h bridge/bbp_bridge.h
AUTH2_BEARSSL_ROOT := third_party/bearssl
AUTH2_BEARSSL_SOURCES := \
	$(AUTH2_BEARSSL_ROOT)/src/codec/ccopy.c \
	$(AUTH2_BEARSSL_ROOT)/src/codec/dec32be.c \
	$(AUTH2_BEARSSL_ROOT)/src/codec/enc32be.c \
	$(AUTH2_BEARSSL_ROOT)/src/ec/ec_p256_m15.c \
	$(AUTH2_BEARSSL_ROOT)/src/ec/ec_secp256r1.c \
	$(AUTH2_BEARSSL_ROOT)/src/ec/ec_secp384r1.c \
	$(AUTH2_BEARSSL_ROOT)/src/ec/ec_secp521r1.c \
	$(AUTH2_BEARSSL_ROOT)/src/ec/ecdsa_i15_bits.c \
	$(AUTH2_BEARSSL_ROOT)/src/ec/ecdsa_i15_vrfy_raw.c \
	$(AUTH2_BEARSSL_ROOT)/src/hash/sha2small.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_add.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_bitlen.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_decode.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_decmod.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_encode.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_fmont.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_iszero.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_modpow.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_montmul.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_muladd.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_ninv15.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_rshift.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_sub.c \
	$(AUTH2_BEARSSL_ROOT)/src/int/i15_tmont.c
AUTH2_BEARSSL_OBJECTS := $(patsubst $(AUTH2_BEARSSL_ROOT)/%.c,\
	$(BUILD)/auth2-bearssl/%.o,$(AUTH2_BEARSSL_SOURCES))
AUTH2_BEARSSL_FLAGS := -ffreestanding -fno-builtin -fno-stack-protector \
	-fno-tree-loop-distribute-patterns \
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
	-Dmemcpy=bbp_auth2_memcpy -Dmemmove=bbp_auth2_memmove \
	-Dmemset=bbp_auth2_memset -I$(AUTH2_BEARSSL_ROOT)/inc \
	-I$(AUTH2_BEARSSL_ROOT)
AUTH2_BEARSSL_HEADERS := $(AUTH2_BEARSSL_ROOT)/inner.h \
	$(AUTH2_BEARSSL_ROOT)/config.h \
	$(wildcard $(AUTH2_BEARSSL_ROOT)/inc/*.h)

.PHONY: all test abi freestanding kernel fuzz check clean qemu qemu-aarch64 \
	qemu-riscv64 \
	uefi qemu-uefi qemu-uefi-loader qemu-uefi-tcg2 \
	importers-test bbpctl-test ports-check readme-art verify-readme verify-site \
	site-preview sdk-c-test sdk-package-test sdk-rust-test sdk-rust-msrv-test \
	sdk-check sdk-package release-metadata-test v2-test

.PHONY: v2-portability v2-profile-test v2-corpus-check v2-vectors-test \
	v2-fuzz v2-auth-test \
	bbp-stamp-test uefi-ebs-test uefi-elf-test uefi-loader-contract-test \
	security-collector-test tpm2-response-test tpm2-measure-test \
	auth-envelope-test auth2-test auth2-freestanding-test auth2-portability \
	auth2-sanitize-test auth2-vendor-check auth2-c-vectors \
	rollback-test evidence-check port-inventory-test ports-hosted-check

.PHONY: release-policy-test

all: test freestanding

# ---- fastest gate: do the ABI static_asserts even hold? -------------------
abi:
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) -fsyntax-only -x c include/bbp/bbp.h
	@echo "ABI static_asserts OK"

# ---- hosted self-test ------------------------------------------------------
# Belt-and-suspenders against a hang regression: the binary arms its own SIGALRM
# watchdog (see abi_selftest.c), AND we wrap it in `timeout` here so even a hang
# that somehow escapes the in-process alarm (e.g. before main, or a blocked
# signal) becomes a hard, visible failure instead of a 100%-CPU zombie. The
# `timeout` is a no-op when absent (portable fallback runs the binary directly).
TEST_TIMEOUT ?= 60
test: $(BUILD)/abi_selftest
	@if command -v timeout >/dev/null 2>&1; then \
	    timeout --foreground -k 5 $(TEST_TIMEOUT) $(BUILD)/abi_selftest; rc=$$?; \
	    if [ $$rc -eq 124 ]; then \
	        echo "FAILED: self-test exceeded $(TEST_TIMEOUT)s (hang regression — see SIGALRM note in abi_selftest.c)"; \
	    fi; \
	    exit $$rc; \
	else \
	    $(BUILD)/abi_selftest; \
	fi

$(BUILD)/abi_selftest: tests/abi_selftest.c bootloader/bbp_build.c \
		kernel/bbp_kernel.c $(BBP_HEADERS)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/abi_selftest.c \
		bootloader/bbp_build.c kernel/bbp_kernel.c -o $@

# ---- cross-compile the kernel-side + example as freestanding objects -------
freestanding: $(BUILD)/bbp_kernel.o $(BUILD)/kernel_header.o $(BUILD)/bbp_build.o \
	$(IMPORT_OBJECTS) $(BUILD)/bbp_v2.o $(BUILD)/bbp_bridge.o
	@echo "freestanding objects built with $(CC)"

$(BUILD)/bbp_kernel.o: kernel/bbp_kernel.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD)/kernel_header.o: examples/kernel_header.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD)/bbp_build.o: bootloader/bbp_build.c bootloader/bbp_build.h \
		include/bbp/bbp.h include/bbp/bbp_crc64.h
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD)/bbp_v2.o: v2/bbp_v2.c $(V2_HEADERS) include/bbp/bbp_crc64.h
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD)/bbp_bridge.o: bridge/bbp_bridge.c $(V2_HEADERS) \
		include/bbp/bbp.h include/bbp/bbp_crc64.h
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(IMPORT_OBJECTS): $(BUILD)/%.o: bootloader/%.c $(BBP_HEADERS)
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

# ---- link + stamp a bootable example kernel --------------------------------
kernel: $(BUILD)/kernel.elf
$(BUILD)/kernel.elf: $(BUILD)/kernel_header.o $(BUILD)/bbp_kernel.o examples/linker.ld
	$(LD) $(KLDFLAGS) $(BUILD)/kernel_header.o $(BUILD)/bbp_kernel.o -o $@
	$(PYTHON) tools/bbp_stamp.py $@ --requests-symbol bbp_requests
	$(PYTHON) tools/bbp_stamp.py $@ --check

# ---- fuzzer ----------------------------------------------------------------
# Bounded so `make fuzz` always TERMINATES and a hang is a visible failure:
#  - libFuzzer build: -max_total_time caps the campaign (no-arg libFuzzer would
#    otherwise fuzz forever).
#  - deterministic build: its own SIGALRM watchdog (in fuzz_parser.c) caps it.
#  - either way, a `timeout` wrapper is the outer belt (exit 124 on overrun).
FUZZ_SECONDS ?= 30
FUZZ_TIMEOUT ?= 90
fuzz: $(BUILD)/bbp_fuzz
	@echo "running fuzz smoke..."
	@if [ -f $(BUILD)/.bbp_fuzz_libfuzzer ]; then \
	    run="$(BUILD)/bbp_fuzz -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1"; \
	else \
	    run="$(BUILD)/bbp_fuzz"; \
	fi; \
	if command -v timeout >/dev/null 2>&1; then \
	    timeout --foreground -k 5 $(FUZZ_TIMEOUT) $$run; rc=$$?; \
	    if [ $$rc -eq 124 ]; then echo "FAILED: fuzz exceeded $(FUZZ_TIMEOUT)s (hang regression)"; fi; \
	    exit $$rc; \
	else $$run; fi

$(BUILD)/bbp_fuzz: tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	@rm -f $(BUILD)/.bbp_fuzz_libfuzzer
	@if $(FUZZCC) -fsanitize=fuzzer,address -std=c11 $(INCLUDE) \
	    -DBBP_LIBFUZZER tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c -o $@ 2>/dev/null; then \
	    echo "[fuzz] built with libFuzzer ($(FUZZCC))"; \
	    touch $(BUILD)/.bbp_fuzz_libfuzzer; \
	else \
	    echo "[fuzz] libFuzzer unavailable; building deterministic driver (+ASan if available)"; \
	    $(HOSTCC) $(HOSTFLAGS) -fsanitize=address $(INCLUDE) tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c -o $@ 2>/dev/null \
	    || $(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c -o $@; \
	fi

# ---- boot-source translation -----------------------------------------------
importers-test: $(BUILD)/importers_selftest
	$(BUILD)/importers_selftest

$(BUILD)/importers_selftest: tests/importers_selftest.c bootloader/bbp_build.c \
		$(IMPORT_SOURCES) \
		kernel/bbp_kernel.c $(BBP_HEADERS)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/importers_selftest.c \
		bootloader/bbp_build.c $(IMPORT_SOURCES) kernel/bbp_kernel.c -o $@

# ---- bare-metal round-trip kernel (Multiboot1, qemu -kernel) ---------------
# 32-bit freestanding; exercises bbp_build + bbp_kernel on real hardware.
QEMU         ?= qemu-system-i386
QEMU_CC      ?= $(HOSTCC)
QEMU_TIMEOUT ?= 30
QEMU_SERIAL  ?= $(BUILD)/qemu-serial.log
QEMU_CFLAGS := -m32 -ffreestanding -fno-stack-protector -fno-pic -fno-pie \
                -mno-sse -mno-mmx -mno-red-zone -Wall -Wextra -std=c11 -O2 -g
qemu: $(BUILD)/roundtrip.elf
	@rm -f "$(QEMU_SERIAL)"
	@set +e; \
	timeout --foreground -k 5 "$(QEMU_TIMEOUT)" "$(QEMU)" \
	    -accel tcg -machine pc -m 64M -kernel "$(BUILD)/roundtrip.elf" \
	    -display none -monitor none -serial "file:$(QEMU_SERIAL)" -no-reboot \
	    -device isa-debug-exit,iobase=0xf4,iosize=0x04; \
	rc=$$?; set -e; \
	if [ -f "$(QEMU_SERIAL)" ]; then cat "$(QEMU_SERIAL)"; fi; \
	if [ $$rc -eq 124 ] || [ $$rc -eq 137 ]; then \
	    echo "FAILED: QEMU exceeded $(QEMU_TIMEOUT)s"; exit 1; \
	fi; \
	if [ $$rc -ne 33 ]; then \
	    echo "FAILED: QEMU guest exit status $$rc (expected 33)"; exit 1; \
	fi; \
	if grep -Fq 'BBP-QEMU: FAIL:' "$(QEMU_SERIAL)"; then \
	    echo "FAILED: guest reported failure"; exit 1; \
	fi; \
	if ! grep -Fq 'BBP-QEMU: PASS' "$(QEMU_SERIAL)"; then \
	    echo "FAILED: missing BBP-QEMU: PASS"; exit 1; \
	fi
$(BUILD)/roundtrip.elf: tests/boot32.S tests/qemu_roundtrip.c \
                        bootloader/bbp_build.c kernel/bbp_kernel.c tests/linker32.ld \
                        Makefile
	@mkdir -p $(BUILD)
	$(QEMU_CC) $(QEMU_CFLAGS) $(INCLUDE) -c tests/boot32.S        -o $(BUILD)/boot32.o
	$(QEMU_CC) $(QEMU_CFLAGS) $(INCLUDE) -c tests/qemu_roundtrip.c -o $(BUILD)/qrt.o
	$(QEMU_CC) $(QEMU_CFLAGS) $(INCLUDE) -c bootloader/bbp_build.c -o $(BUILD)/qrt_build.o
	$(QEMU_CC) $(QEMU_CFLAGS) $(INCLUDE) -c kernel/bbp_kernel.c    -o $(BUILD)/qrt_kernel.o
	$(QEMU_CC) $(QEMU_CFLAGS) -nostdlib -no-pie -Wl,-melf_i386,--build-id=none \
	    -T tests/linker32.ld \
	    $(BUILD)/boot32.o $(BUILD)/qrt.o $(BUILD)/qrt_build.o $(BUILD)/qrt_kernel.o \
	    -o $@

# ---- AArch64 raw Image: QEMU FDT in X0 -> BBP INFO in X0 ------------------
AARCH64_CC       ?= aarch64-linux-gnu-gcc
AARCH64_OBJCOPY  ?= aarch64-linux-gnu-objcopy
AARCH64_NM       ?= aarch64-linux-gnu-nm
QEMU_AARCH64     ?= qemu-system-aarch64
AARCH64_SERIAL   ?= $(BUILD)/qemu-aarch64-serial.log
AARCH64_ELF      := $(BUILD)/roundtrip-aarch64.elf
AARCH64_IMAGE    := $(BUILD)/roundtrip-aarch64.Image
AARCH64_CFLAGS   := -ffreestanding -fno-builtin -fno-stack-protector \
	-fno-stack-clash-protection -fno-pic -fno-pie -fno-unwind-tables \
	-fno-asynchronous-unwind-tables -mgeneral-regs-only \
	-Wall -Wextra -Werror -std=c11 -O2 -g $(INCLUDE)

qemu-aarch64: $(AARCH64_IMAGE)
	@rm -f "$(AARCH64_SERIAL)"
	@set +e; \
	timeout --foreground -k 5 "$(QEMU_TIMEOUT)" "$(QEMU_AARCH64)" \
	    -accel tcg -machine virt,dtb-randomness=off -cpu cortex-a57 \
	    -m 128M -smp 1 -kernel "$(AARCH64_IMAGE)" \
	    -display none -monitor none -serial "file:$(AARCH64_SERIAL)" \
	    -nic none -no-reboot -semihosting-config enable=on,target=native; \
	rc=$$?; set -e; \
	if [ -f "$(AARCH64_SERIAL)" ]; then cat "$(AARCH64_SERIAL)"; fi; \
	if [ $$rc -eq 124 ] || [ $$rc -eq 137 ]; then \
	    echo "FAILED: AArch64 QEMU exceeded $(QEMU_TIMEOUT)s"; exit 1; \
	fi; \
	if [ $$rc -ne 33 ]; then \
	    echo "FAILED: AArch64 QEMU guest exit status $$rc (expected 33)"; exit 1; \
	fi; \
	if grep -Fq 'BBP-AARCH64: FAIL:' "$(AARCH64_SERIAL)"; then \
	    echo "FAILED: AArch64 guest reported failure"; exit 1; \
	fi; \
	if ! grep -Fq 'BBP-AARCH64: PASS' "$(AARCH64_SERIAL)"; then \
	    echo "FAILED: missing BBP-AARCH64: PASS"; exit 1; \
	fi

$(BUILD)/boot_aarch64.o: tests/boot_aarch64.S Makefile
	@mkdir -p $(BUILD)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

$(BUILD)/qrt_aarch64.o: tests/qemu_roundtrip_aarch64.c bootloader/bbp_build.h \
		kernel/bbp_kernel.h include/bbp/bbp.h include/bbp/bbp_crc64.h Makefile
	@mkdir -p $(BUILD)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

$(BUILD)/qrt_aarch64_build.o: bootloader/bbp_build.c bootloader/bbp_build.h \
		include/bbp/bbp.h include/bbp/bbp_crc64.h Makefile
	@mkdir -p $(BUILD)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

$(BUILD)/qrt_aarch64_kernel.o: kernel/bbp_kernel.c kernel/bbp_kernel.h \
		include/bbp/bbp.h include/bbp/bbp_crc64.h Makefile
	@mkdir -p $(BUILD)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

$(AARCH64_ELF): $(BUILD)/boot_aarch64.o $(BUILD)/qrt_aarch64.o \
		$(BUILD)/qrt_aarch64_build.o $(BUILD)/qrt_aarch64_kernel.o \
		tests/linker_aarch64.ld
	$(AARCH64_CC) -nostdlib -static -no-pie -Wl,--build-id=none \
	    -T tests/linker_aarch64.ld $(BUILD)/boot_aarch64.o \
	    $(BUILD)/qrt_aarch64.o $(BUILD)/qrt_aarch64_build.o \
	    $(BUILD)/qrt_aarch64_kernel.o -o $@

$(AARCH64_IMAGE): $(AARCH64_ELF)
	$(AARCH64_OBJCOPY) -O binary $< $@

# ---- RV64 OpenSBI payload: QEMU FDT in A1 -> BBP INFO in A0 ---------------
RISCV64_CC      ?= riscv64-linux-gnu-gcc
RISCV64_OBJCOPY ?= riscv64-linux-gnu-objcopy
RISCV64_NM      ?= riscv64-linux-gnu-nm
QEMU_RISCV64    ?= qemu-system-riscv64
RISCV64_SERIAL  ?= $(BUILD)/qemu-riscv64-serial.log
RISCV64_ELF     := $(BUILD)/roundtrip-riscv64.elf
RISCV64_CFLAGS  := -march=rv64imac_zicsr -mabi=lp64 -mcmodel=medany \
	-mno-relax -msmall-data-limit=0 -ffreestanding -fno-builtin \
	-fno-stack-protector -fno-stack-clash-protection -fno-pic -fno-pie \
	-fno-unwind-tables -fno-asynchronous-unwind-tables \
	-Wall -Wextra -Werror -std=c11 -O2 -g $(INCLUDE)

qemu-riscv64: $(RISCV64_ELF)
	@rm -f "$(RISCV64_SERIAL)"
	@set +e; \
	timeout --foreground -k 5 "$(QEMU_TIMEOUT)" "$(QEMU_RISCV64)" \
	    -accel tcg -machine virt -m 128M -smp 1 -bios default \
	    -kernel "$(RISCV64_ELF)" -display none -monitor none \
	    -serial "file:$(RISCV64_SERIAL)" -nic none -no-reboot; \
	rc=$$?; set -e; \
	if [ -f "$(RISCV64_SERIAL)" ]; then cat "$(RISCV64_SERIAL)"; fi; \
	if [ $$rc -eq 124 ] || [ $$rc -eq 137 ]; then \
	    echo "FAILED: RV64 QEMU exceeded $(QEMU_TIMEOUT)s"; exit 1; \
	fi; \
	if [ $$rc -ne 0 ]; then \
	    echo "FAILED: RV64 QEMU guest exit status $$rc (expected 0)"; exit 1; \
	fi; \
	if grep -Fq 'BBP-RISCV64: FAIL:' "$(RISCV64_SERIAL)"; then \
	    echo "FAILED: RV64 guest reported failure"; exit 1; \
	fi; \
	if ! grep -Fq 'BBP-RISCV64: PASS' "$(RISCV64_SERIAL)"; then \
	    echo "FAILED: missing BBP-RISCV64: PASS"; exit 1; \
	fi

$(BUILD)/boot_riscv64.o: tests/boot_riscv64.S Makefile
	@mkdir -p $(BUILD)
	$(RISCV64_CC) $(RISCV64_CFLAGS) -c $< -o $@

$(BUILD)/qrt_riscv64.o: tests/qemu_roundtrip_riscv64.c \
		bootloader/bbp_build.h kernel/bbp_kernel.h include/bbp/bbp.h \
		include/bbp/bbp_crc64.h Makefile
	@mkdir -p $(BUILD)
	$(RISCV64_CC) $(RISCV64_CFLAGS) -c $< -o $@

$(BUILD)/qrt_riscv64_build.o: bootloader/bbp_build.c bootloader/bbp_build.h \
		include/bbp/bbp.h include/bbp/bbp_crc64.h Makefile
	@mkdir -p $(BUILD)
	$(RISCV64_CC) $(RISCV64_CFLAGS) -c $< -o $@

$(BUILD)/qrt_riscv64_kernel.o: kernel/bbp_kernel.c kernel/bbp_kernel.h \
		include/bbp/bbp.h include/bbp/bbp_crc64.h Makefile
	@mkdir -p $(BUILD)
	$(RISCV64_CC) $(RISCV64_CFLAGS) -c $< -o $@

$(RISCV64_ELF): $(BUILD)/boot_riscv64.o $(BUILD)/qrt_riscv64.o \
		$(BUILD)/qrt_riscv64_build.o $(BUILD)/qrt_riscv64_kernel.o \
		tests/linker_riscv64.ld
	$(RISCV64_CC) -march=rv64imac_zicsr -mabi=lp64 -mcmodel=medany \
	    -mno-relax -nostdlib -static -no-pie \
	    -Wl,--build-id=none,--no-relax,-z,max-page-size=4096 \
	    -T tests/linker_riscv64.ld $(BUILD)/boot_riscv64.o \
	    $(BUILD)/qrt_riscv64.o $(BUILD)/qrt_riscv64_build.o \
	    $(BUILD)/qrt_riscv64_kernel.o -o $@

# ---- OVMF-loaded x86_64 EFI builder/parser proof ---------------------------
UEFI_CC       ?= clang
UEFI_LD       ?= lld-link
UEFI_TARGET   ?= x86_64-pc-win32-coff
UEFI_CFLAGS   := --target=$(UEFI_TARGET) -ffreestanding -fshort-wchar \
	-mno-red-zone -fno-stack-protector \
	-Wall -Wextra -Werror -std=c11 -O2 $(INCLUDE)
UEFI_ESP      ?= $(BUILD)/uefi-esp
UEFI_APP      := $(UEFI_ESP)/EFI/BOOT/BOOTX64.EFI
UEFI_SERIAL   ?= $(BUILD)/uefi-serial.log
OVMF_CODE     ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS     ?= /usr/share/OVMF/OVMF_VARS_4M.fd
OVMF_TEST_VARS := $(BUILD)/OVMF_VARS_4M.test.fd

uefi: $(UEFI_APP)

$(BUILD)/uefi_roundtrip.obj: tests/uefi_roundtrip.c kernel/bbp_kernel.h \
		bootloader/bbp_build.h include/bbp/bbp.h Makefile
	@mkdir -p $(BUILD)
	$(UEFI_CC) $(UEFI_CFLAGS) -c $< -o $@

$(BUILD)/uefi_build.obj: bootloader/bbp_build.c bootloader/bbp_build.h \
		include/bbp/bbp.h Makefile
	@mkdir -p $(BUILD)
	$(UEFI_CC) $(UEFI_CFLAGS) -c $< -o $@

$(BUILD)/uefi_kernel.obj: kernel/bbp_kernel.c kernel/bbp_kernel.h \
		include/bbp/bbp.h Makefile
	@mkdir -p $(BUILD)
	$(UEFI_CC) $(UEFI_CFLAGS) -c $< -o $@

$(UEFI_APP): $(BUILD)/uefi_roundtrip.obj $(BUILD)/uefi_build.obj \
		$(BUILD)/uefi_kernel.obj
	@mkdir -p "$(UEFI_ESP)/EFI/BOOT"
	$(UEFI_LD) /subsystem:efi_application /entry:efi_main /nodefaultlib \
	    /machine:x64 /out:$@ $^

qemu-uefi: $(UEFI_APP)
	@cp "$(OVMF_VARS)" "$(OVMF_TEST_VARS)"
	@rm -f "$(UEFI_SERIAL)"
	@set +e; \
	timeout --foreground -k 5 "$(QEMU_TIMEOUT)" qemu-system-x86_64 \
	    -accel tcg -machine q35 -m 128M \
	    -drive if=pflash,unit=0,format=raw,readonly=on,file="$(OVMF_CODE)" \
	    -drive if=pflash,unit=1,format=raw,file="$(OVMF_TEST_VARS)" \
	    -drive format=raw,file=fat:rw:"$(abspath $(UEFI_ESP))" \
	    -boot order=c,menu=off -display none -monitor none \
	    -serial "file:$(UEFI_SERIAL)" -nic none -no-reboot \
	    -device isa-debug-exit,iobase=0xf4,iosize=0x04; \
	rc=$$?; set -e; \
	if [ -f "$(UEFI_SERIAL)" ]; then cat "$(UEFI_SERIAL)"; fi; \
	if [ $$rc -eq 124 ] || [ $$rc -eq 137 ]; then \
	    echo "FAILED: OVMF exceeded $(QEMU_TIMEOUT)s"; exit 1; \
	fi; \
	if [ $$rc -ne 33 ]; then \
	    echo "FAILED: OVMF guest exit status $$rc (expected 33)"; exit 1; \
	fi; \
	if grep -Fq 'BBP-UEFI: FAIL:' "$(UEFI_SERIAL)"; then \
	    echo "FAILED: EFI guest reported failure"; exit 1; \
	fi; \
	if ! grep -Fq 'BBP-UEFI: PASS' "$(UEFI_SERIAL)"; then \
	    echo "FAILED: missing BBP-UEFI: PASS"; exit 1; \
	fi

# ---- host-only BBP v1 capture tooling -------------------------------------
bbpctl-test:
	$(PYTHON) tests/test_bbpctl.py

# ---- versioned SDK, extracted onboarding, and no_std Rust parity ------------
sdk-c-test:
	$(MAKE) -f sdk/c/Makefile ROOT=. BUILD=$(BUILD)/sdk onboarding

sdk-package-test:
	$(PYTHON) -m unittest tests.test_sdk_package

sdk-rust-test:
	cargo test --manifest-path sdk/rust/bbp-wire/Cargo.toml
	cargo fmt --manifest-path sdk/rust/bbp-wire/Cargo.toml -- --check
	@if cargo clippy --version >/dev/null 2>&1; then \
		cargo clippy --manifest-path sdk/rust/bbp-wire/Cargo.toml --all-targets -- -D warnings; \
	elif cargo +stable clippy --version >/dev/null 2>&1; then \
		cargo +stable clippy --manifest-path sdk/rust/bbp-wire/Cargo.toml --all-targets -- -D warnings; \
	else \
		echo "cargo-clippy unavailable; lint skipped (CI installs and requires it)"; \
	fi

sdk-rust-msrv-test:
	cargo +1.77.0 test --manifest-path sdk/rust/bbp-wire/Cargo.toml
	cargo +1.77.0 package --manifest-path sdk/rust/bbp-wire/Cargo.toml --allow-dirty

sdk-check: sdk-c-test sdk-package-test sdk-rust-test sdk-rust-msrv-test
	@echo "ALL SDK CHECKS PASSED"

sdk-package:
	$(PYTHON) tools/package_sdk.py

release-metadata-test:
	$(PYTHON) -m unittest tests.test_release_metadata

release-policy-test:
	$(PYTHON) -m unittest tests.test_release_policy

# ---- experimental BBP v2 contiguous capsule and explicit v1.1 bridge ------
v2-test: $(BUILD)/v2_selftest
	$(BUILD)/v2_selftest

$(BUILD)/v2_selftest: tests/v2_selftest.c v2/bbp_v2.c bridge/bbp_bridge.c \
		bootloader/bbp_build.c kernel/bbp_kernel.c $(BBP_HEADERS) $(V2_HEADERS)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/v2_selftest.c v2/bbp_v2.c \
		bridge/bbp_bridge.c bootloader/bbp_build.c kernel/bbp_kernel.c -o $@

# The v2 Draft is byte-oriented and must not inherit x86-only kernel flags.
V2_PORTABLE_FLAGS := -ffreestanding -fno-builtin -fno-stack-protector \
	-Wall -Wextra -Werror -std=c11 -O2 $(INCLUDE)
V2_X86_64_CC ?= x86_64-linux-gnu-gcc
v2-portability:
	@mkdir -p $(BUILD)/v2-portability
	$(V2_X86_64_CC) $(V2_PORTABLE_FLAGS) -c v2/bbp_v2.c \
	    -o $(BUILD)/v2-portability/bbp_v2-x86_64.o
	$(V2_X86_64_CC) $(V2_PORTABLE_FLAGS) -c v2/bbp_v2_profile.c \
	    -o $(BUILD)/v2-portability/profile-x86_64.o
	$(V2_X86_64_CC) $(V2_PORTABLE_FLAGS) -c bridge/bbp_bridge.c \
	    -o $(BUILD)/v2-portability/bridge-x86_64.o
	$(AARCH64_CC) $(V2_PORTABLE_FLAGS) -mgeneral-regs-only -c v2/bbp_v2.c \
	    -o $(BUILD)/v2-portability/bbp_v2-aarch64.o
	$(RISCV64_CC) $(V2_PORTABLE_FLAGS) -march=rv64imac_zicsr -mabi=lp64 \
	    -c v2/bbp_v2.c -o $(BUILD)/v2-portability/bbp_v2-riscv64.o
	$(AARCH64_CC) $(V2_PORTABLE_FLAGS) -mgeneral-regs-only -c v2/bbp_v2_profile.c -o $(BUILD)/v2-portability/profile-aarch64.o
	$(RISCV64_CC) $(V2_PORTABLE_FLAGS) -march=rv64imac_zicsr -mabi=lp64 -c v2/bbp_v2_profile.c -o $(BUILD)/v2-portability/profile-riscv64.o
	$(AARCH64_CC) $(V2_PORTABLE_FLAGS) -mgeneral-regs-only -c bridge/bbp_bridge.c -o $(BUILD)/v2-portability/bridge-aarch64.o
	$(RISCV64_CC) $(V2_PORTABLE_FLAGS) -march=rv64imac_zicsr -mabi=lp64 -c bridge/bbp_bridge.c -o $(BUILD)/v2-portability/bridge-riscv64.o
	@echo "BBP v2 portability: PASS (x86_64, AArch64, RV64)"

v2-profile-test: $(BUILD)/v2_profile_selftest
	$(BUILD)/v2_profile_selftest
$(BUILD)/v2_profile_selftest: tests/v2_profile_selftest.c v2/bbp_v2.c v2/bbp_v2_profile.c $(V2_HEADERS)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/v2_profile_selftest.c v2/bbp_v2.c v2/bbp_v2_profile.c -o $@

v2-corpus-check:
	$(PYTHON) tools/generate_v2_corpus.py --check

v2-vectors-test: v2-corpus-check $(BUILD)/libbbp_v2_vectors.so
	$(PYTHON) tests/test_v2_vectors.py $(BUILD)/libbbp_v2_vectors.so
$(BUILD)/libbbp_v2_vectors.so: v2/bbp_v2.c v2/bbp_v2_profile.c $(V2_HEADERS)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) -fPIC -shared $(INCLUDE) v2/bbp_v2.c v2/bbp_v2_profile.c -o $@

v2-fuzz: $(BUILD)/v2_fuzz
	@if [ -f $(BUILD)/.v2_fuzz_libfuzzer ]; then \
	    run="$(BUILD)/v2_fuzz -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1"; \
	else \
	    run="$(BUILD)/v2_fuzz"; \
	fi; \
	timeout --foreground -k 5 $(FUZZ_TIMEOUT) $$run

$(BUILD)/v2_fuzz: tests/fuzz_v2.c v2/bbp_v2.c v2/bbp_v2_profile.c $(V2_HEADERS)
	@mkdir -p $(BUILD)
	@rm -f $(BUILD)/.v2_fuzz_libfuzzer
	@if $(FUZZCC) -fsanitize=fuzzer,address -DBBP_V2_LIBFUZZER \
	    -std=c11 $(INCLUDE) tests/fuzz_v2.c v2/bbp_v2.c v2/bbp_v2_profile.c \
	    -o $@ 2>/dev/null; then \
	    echo "[v2-fuzz] built with libFuzzer"; touch $(BUILD)/.v2_fuzz_libfuzzer; \
	else \
	    $(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/fuzz_v2.c v2/bbp_v2.c \
	        v2/bbp_v2_profile.c -o $@; \
	fi

bbp-stamp-test:
	$(PYTHON) -m unittest tests.test_bbp_stamp

uefi-ebs-test: $(BUILD)/uefi_ebs_selftest
	$(BUILD)/uefi_ebs_selftest

$(BUILD)/uefi_ebs_selftest: tests/uefi_ebs_selftest.c \
		bootloader/uefi/uefi_exit.c bootloader/uefi/uefi_exit.h
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) tests/uefi_ebs_selftest.c \
		bootloader/uefi/uefi_exit.c -o $@

uefi-elf-test: $(BUILD)/uefi_elf_selftest
	$(BUILD)/uefi_elf_selftest

$(BUILD)/uefi_elf_selftest: tests/uefi_elf_selftest.c \
		bootloader/uefi/elf64_loader.c bootloader/uefi/elf64_loader.h
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) tests/uefi_elf_selftest.c \
		bootloader/uefi/elf64_loader.c -o $@

uefi-loader-contract-test: bbp-stamp-test uefi-ebs-test uefi-elf-test
	@echo "UEFI LOADER CONTRACT GATES PASSED"

security-collector-test: $(BUILD)/security_collector_selftest
	$(BUILD)/security_collector_selftest

$(BUILD)/security_collector_selftest: tests/security_collector_selftest.c \
		experimental/firmware/uefi/bbp_security_collector.c \
		experimental/firmware/uefi/bbp_security_collector.h \
		bootloader/bbp_build.c kernel/bbp_kernel.c $(BBP_HEADERS)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/security_collector_selftest.c \
		experimental/firmware/uefi/bbp_security_collector.c \
		bootloader/bbp_build.c kernel/bbp_kernel.c -o $@

tpm2-response-test:
	$(PYTHON) -m unittest tests.test_tpm2_measure

tpm2-measure-test: tpm2-response-test
	$(PYTHON) tools/tpm2_measure.py

v2-auth-test: $(BUILD)/v2_auth_selftest
	$(BUILD)/v2_auth_selftest tests/vectors/bbp-v2-profile0-auth-v1.json
	$(PYTHON) -m unittest tests.test_v2_envelope tests.test_v2_interop

$(BUILD)/v2_auth_selftest: tests/v2_auth_selftest.c v2/bbp_v2_auth.c \
		v2/bbp_v2.c v2/bbp_v2_profile.c include/bbp/bbp_v2_auth.h \
		include/bbp/bbp_v2.h include/bbp/bbp_v2_profile.h
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/v2_auth_selftest.c \
		v2/bbp_v2_auth.c v2/bbp_v2.c v2/bbp_v2_profile.c -o $@

auth-envelope-test: v2-auth-test

auth2-test:
	$(PYTHON) -m unittest tests.test_auth2

auth2-vendor-check:
	sha256sum -c $(AUTH2_BEARSSL_ROOT)/SHA256SUMS

auth2-freestanding-test: auth2-c-vectors $(BUILD)/auth2_freestanding_selftest
	$(BUILD)/auth2_freestanding_selftest

auth2-c-vectors: $(BUILD)/auth2-vectors/.stamp

$(BUILD)/auth2-vectors/.stamp: tests/generate_auth2_c_vectors.py \
		tests/vectors/auth2/manifest.auth2 \
		tests/vectors/auth2/root.test-only.private.pem \
		tests/vectors/auth2/release.public.pem experimental/auth2/auth2.py
	@mkdir -p $(BUILD)/auth2-vectors
	$(PYTHON) tests/generate_auth2_c_vectors.py $(BUILD)/auth2-vectors
	@touch $@

$(BUILD)/auth2_freestanding_selftest: tests/auth2_freestanding_selftest.c \
		v2/bbp_auth2.c v2/bbp_auth2_crypto.c v2/bbp_auth2_crypto.h \
		include/bbp/bbp_auth2.h $(AUTH2_BEARSSL_OBJECTS)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) -I$(AUTH2_BEARSSL_ROOT)/inc \
		-DBBP_AUTH2_TEST_VECTOR_DIR='"$(BUILD)/auth2-vectors"' \
		tests/auth2_freestanding_selftest.c v2/bbp_auth2.c \
		v2/bbp_auth2_crypto.c $(AUTH2_BEARSSL_OBJECTS) -o $@

$(BUILD)/auth2-bearssl/%.o: $(AUTH2_BEARSSL_ROOT)/%.c \
		$(AUTH2_BEARSSL_HEADERS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HOSTFLAGS) $(AUTH2_BEARSSL_FLAGS) -c $< -o $@

AUTH2_PORTABLE_FLAGS := $(V2_PORTABLE_FLAGS) $(AUTH2_BEARSSL_FLAGS) \
	-r -nostdlib -Wl,--defsym,memcpy=bbp_auth2_memcpy \
	-Wl,--defsym,memmove=bbp_auth2_memmove \
	-Wl,--defsym,memset=bbp_auth2_memset -Wframe-larger-than=2048
AUTH2_PUBLIC_SYMBOL_FLAGS := \
	-G bbp_auth2_verify_manifest -G bbp_auth2_verify_envelope \
	-G bbp_auth2_status_string

auth2-portability:
	@mkdir -p $(BUILD)/auth2-portability
	$(V2_X86_64_CC) $(AUTH2_PORTABLE_FLAGS) -mno-sse -mno-mmx v2/bbp_auth2.c \
		v2/bbp_auth2_crypto.c $(AUTH2_BEARSSL_SOURCES) \
		-o $(BUILD)/auth2-portability/auth2-x86_64.o
	$(HOST_OBJCOPY) $(AUTH2_PUBLIC_SYMBOL_FLAGS) \
		$(BUILD)/auth2-portability/auth2-x86_64.o
	$(AARCH64_CC) $(AUTH2_PORTABLE_FLAGS) -mgeneral-regs-only \
		v2/bbp_auth2.c v2/bbp_auth2_crypto.c $(AUTH2_BEARSSL_SOURCES) \
		-o $(BUILD)/auth2-portability/auth2-aarch64.o
	$(AARCH64_OBJCOPY) $(AUTH2_PUBLIC_SYMBOL_FLAGS) \
		$(BUILD)/auth2-portability/auth2-aarch64.o
	$(RISCV64_CC) $(AUTH2_PORTABLE_FLAGS) -march=rv64imac_zicsr -mabi=lp64 \
		v2/bbp_auth2.c v2/bbp_auth2_crypto.c $(AUTH2_BEARSSL_SOURCES) \
		-o $(BUILD)/auth2-portability/auth2-riscv64.o
	$(RISCV64_OBJCOPY) $(AUTH2_PUBLIC_SYMBOL_FLAGS) \
		$(BUILD)/auth2-portability/auth2-riscv64.o
	@for pair in "$(HOST_NM) $(BUILD)/auth2-portability/auth2-x86_64.o" \
		"$(AARCH64_NM) $(BUILD)/auth2-portability/auth2-aarch64.o" \
		"$(RISCV64_NM) $(BUILD)/auth2-portability/auth2-riscv64.o"; do \
		set -- $$pair; tool=$$1; object=$$2; \
		undefined="$$("$$tool" -u "$$object")" || exit 1; \
		test -z "$$undefined" || { printf '%s\n' "$$undefined"; exit 1; }; \
		exports="$$("$$tool" -g --defined-only -j "$$object")" || exit 1; \
		manifest_export=0; envelope_export=0; status_export=0; \
		for symbol in $$exports; do case $$symbol in bbp_auth2_verify_manifest) manifest_export=1;; bbp_auth2_verify_envelope) envelope_export=1;; bbp_auth2_status_string) status_export=1;; *) printf 'unexpected export %s in %s\n' "$$symbol" "$$object"; exit 1;; esac; done; \
		test $$manifest_export -eq 1 && test $$envelope_export -eq 1 && test $$status_export -eq 1 || { printf 'missing required auth2 export in %s\n' "$$object"; exit 1; }; \
	done
	$(HOST_READELF) -h $(BUILD)/auth2-portability/auth2-x86_64.o > $(BUILD)/auth2-portability/x86_64.elf-header
	$(HOST_READELF) -h $(BUILD)/auth2-portability/auth2-aarch64.o > $(BUILD)/auth2-portability/aarch64.elf-header
	$(HOST_READELF) -h $(BUILD)/auth2-portability/auth2-riscv64.o > $(BUILD)/auth2-portability/riscv64.elf-header
	grep -Eq 'Machine:.*X86-64' $(BUILD)/auth2-portability/x86_64.elf-header
	grep -Eq 'Machine:.*AArch64' $(BUILD)/auth2-portability/aarch64.elf-header
	grep -Eq 'Machine:.*RISC-V' $(BUILD)/auth2-portability/riscv64.elf-header
	$(HOST_OBJDUMP) -d $(BUILD)/auth2-portability/auth2-x86_64.o > $(BUILD)/auth2-portability/x86_64.disassembly
	@if grep -Eiq '\b([xyz]mm[0-9]+|mm[0-7]|vzeroupper|vzeroall)\b' $(BUILD)/auth2-portability/x86_64.disassembly; then printf '%s\n' "unexpected x86 SIMD instruction in auth2 verifier"; exit 1; fi
	@echo "BBP auth2 portability: PASS (x86_64, AArch64, RV64; closed symbols, no x86 SIMD)"

auth2-sanitize-test: auth2-c-vectors
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) -O1 -fno-omit-frame-pointer \
		-fsanitize=address,undefined $(INCLUDE) $(AUTH2_BEARSSL_FLAGS) \
		-DBBP_AUTH2_TEST_VECTOR_DIR='"$(BUILD)/auth2-vectors"' \
		tests/auth2_freestanding_selftest.c v2/bbp_auth2.c \
		v2/bbp_auth2_crypto.c $(AUTH2_BEARSSL_SOURCES) \
		-o $(BUILD)/auth2_freestanding_selftest.san
	ASAN_OPTIONS=detect_leaks=1 $(BUILD)/auth2_freestanding_selftest.san

rollback-test: $(BUILD)/rollback_model_selftest
	$(BUILD)/rollback_model_selftest
	$(PYTHON) -m unittest tests.test_rollback_state

$(BUILD)/rollback_model_selftest: tests/rollback_model_selftest.c \
		experimental/rollback/bbp_boot_state.c \
		experimental/rollback/bbp_boot_state.h
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) tests/rollback_model_selftest.c \
		experimental/rollback/bbp_boot_state.c -o $@

evidence-check:
	$(PYTHON) -m unittest tests.test_execution_evidence

port-inventory-test:
	$(PYTHON) -m unittest tests.test_port_inventory

# ---- deterministic project identity + local Pages prototype ----------------
readme-art:
	$(PYTHON) tools/generate_readme_art.py

verify-readme:
	$(PYTHON) tools/generate_readme_art.py --check

verify-site: verify-readme
	$(PYTHON) scripts/verify_site.py

site-preview: verify-site
	@echo "BearBoot preview: http://127.0.0.1:8042/website/"
	$(PYTHON) -m http.server 8042 --bind 127.0.0.1

# ---- everything that runs without a cross toolchain ------------------------
check: abi test v2-test v2-profile-test v2-vectors-test auth-envelope-test \
	uefi-loader-contract-test security-collector-test tpm2-response-test \
	auth2-test auth2-vendor-check auth2-freestanding-test rollback-test evidence-check \
	port-inventory-test fuzz importers-test bbpctl-test sdk-check \
	release-metadata-test release-policy-test verify-site
	@echo "ALL HOST CHECKS PASSED"

# ---- compile-check every OS port against the frozen core -------------------
ports-check:
	@for p in ports/*/; do \
	    if [ -f "$$p/Makefile" ]; then \
	        echo "== $$p =="; $(MAKE) -C "$$p" scaffold-check CROSS=$(CROSS) || exit 1; \
	    fi; \
	done
	@echo "ALL PORTS COMPILE AGAINST THE FROZEN CORE"

ports-hosted-check: port-inventory-test
	@for p in ports/*/; do \
	    if [ -f "$$p/Makefile" ]; then \
	        echo "== $$p =="; $(MAKE) -C "$$p" test-hosted || exit 1; \
	    fi; \
	done
	@echo "ALL PORT HOSTED ADAPTER TESTS PASSED"

# ---- complete OVMF loader and TCG2 machine proofs -------------------------
qemu-uefi-loader:
	tests/uefi_loader_machine.sh

qemu-uefi-tcg2:
	tests/uefi_tcg2_machine.sh

clean:
	rm -rf $(BUILD) sdk/rust/bbp-wire/target

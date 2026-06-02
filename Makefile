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
#   make abi           just verify the _Static_asserts compile (fastest gate)
#   make check         run everything that does not need a cross toolchain
#   make clean

CROSS    ?= x86_64-elf-
CC        := $(CROSS)gcc
LD        := $(CROSS)ld
HOSTCC   ?= cc
PYTHON   ?= python3

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

.PHONY: all test abi freestanding kernel fuzz check clean qemu ports-check

all: test freestanding

# ---- fastest gate: do the ABI static_asserts even hold? -------------------
abi:
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) -fsyntax-only -x c include/bbp/bbp.h
	@echo "ABI static_asserts OK"

# ---- hosted self-test ------------------------------------------------------
test: $(BUILD)/abi_selftest
	$(BUILD)/abi_selftest

$(BUILD)/abi_selftest: tests/abi_selftest.c bootloader/bbp_build.c kernel/bbp_kernel.c
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $(INCLUDE) $^ -o $@

# ---- cross-compile the kernel-side + example as freestanding objects -------
freestanding: $(BUILD)/bbp_kernel.o $(BUILD)/kernel_header.o $(BUILD)/bbp_build.o
	@echo "freestanding objects built with $(CC)"

$(BUILD)/bbp_kernel.o: kernel/bbp_kernel.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD)/kernel_header.o: examples/kernel_header.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD)/bbp_build.o: bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -c $< -o $@

# ---- link + stamp a bootable example kernel --------------------------------
kernel: $(BUILD)/kernel.elf
$(BUILD)/kernel.elf: $(BUILD)/kernel_header.o $(BUILD)/bbp_kernel.o examples/linker.ld
	$(LD) $(KLDFLAGS) $(BUILD)/kernel_header.o $(BUILD)/bbp_kernel.o -o $@
	$(PYTHON) tools/bbp_stamp.py $@ --requests-symbol bbp_requests
	$(PYTHON) tools/bbp_stamp.py $@ --check

# ---- fuzzer ----------------------------------------------------------------
fuzz: $(BUILD)/bbp_fuzz
	@echo "running fuzz smoke (deterministic corpus)..."
	$(BUILD)/bbp_fuzz

$(BUILD)/bbp_fuzz: tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	@if $(FUZZCC) -fsanitize=fuzzer,address -std=c11 $(INCLUDE) \
	    -DBBP_LIBFUZZER tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c -o $@ 2>/dev/null; then \
	    echo "[fuzz] built with libFuzzer ($(FUZZCC))"; \
	else \
	    echo "[fuzz] libFuzzer unavailable; building deterministic driver (+ASan if available)"; \
	    $(HOSTCC) $(HOSTFLAGS) -fsanitize=address $(INCLUDE) tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c -o $@ 2>/dev/null \
	    || $(HOSTCC) $(HOSTFLAGS) $(INCLUDE) tests/fuzz_parser.c kernel/bbp_kernel.c bootloader/bbp_build.c -o $@; \
	fi

# ---- bare-metal round-trip kernel (Multiboot1, qemu -kernel) ---------------
# 32-bit freestanding; exercises bbp_build + bbp_kernel on real hardware.
QEMU_CFLAGS := -m32 -ffreestanding -fno-stack-protector -fno-pic -fno-pie \
               -mno-sse -mno-mmx -mno-red-zone -Wall -Wextra -std=c11 -O2 -g
qemu: $(BUILD)/roundtrip.elf
$(BUILD)/roundtrip.elf: tests/boot32.S tests/qemu_roundtrip.c \
                        bootloader/bbp_build.c kernel/bbp_kernel.c tests/linker32.ld
	@mkdir -p $(BUILD)
	$(CC) $(QEMU_CFLAGS) $(INCLUDE) -c tests/boot32.S        -o $(BUILD)/boot32.o
	$(CC) $(QEMU_CFLAGS) $(INCLUDE) -c tests/qemu_roundtrip.c -o $(BUILD)/qrt.o
	$(CC) $(QEMU_CFLAGS) $(INCLUDE) -c bootloader/bbp_build.c -o $(BUILD)/qrt_build.o
	$(CC) $(QEMU_CFLAGS) $(INCLUDE) -c kernel/bbp_kernel.c    -o $(BUILD)/qrt_kernel.o
	$(CC) $(QEMU_CFLAGS) -nostdlib -no-pie -Wl,-melf_i386 -T tests/linker32.ld \
	    $(BUILD)/boot32.o $(BUILD)/qrt.o $(BUILD)/qrt_build.o $(BUILD)/qrt_kernel.o \
	    -o $@

# ---- everything that runs without a cross toolchain ------------------------
check: abi test fuzz
	@echo "ALL HOST CHECKS PASSED"

# ---- compile-check every OS port against the frozen core -------------------
ports-check:
	@for p in ports/*/; do \
	    if [ -f "$$p/Makefile" ]; then \
	        echo "== $$p =="; $(MAKE) -C "$$p" scaffold-check CROSS=$(CROSS) || exit 1; \
	    fi; \
	done
	@echo "ALL PORTS COMPILE AGAINST THE FROZEN CORE"

clean:
	rm -rf $(BUILD)

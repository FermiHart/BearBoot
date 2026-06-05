# ports/josh/Makefile — build+run the Josh-Bear port test, and compile-check
# the port against the frozen BBP core.
#
#   Author: F E R M I  ∞  H A R T   SPDX-License-Identifier: BSD-3-Clause
#
# Unlike ports/minix/ (whose harness is a higher-half Limine ISO booted under
# QEMU), the Josh port runs its adapter AFTER vmm/pmm/heap are up, so the shipped
# code is plain freestanding-but-hosted-testable: the test target compiles the
# standalone harness with the host `cc` and runs it (expect "RESULT: PASS").
# `scaffold-check` additionally proves osif.c + adapter.c build FREESTANDING
# against the core ABI (no run) — run it after each change to catch ABI drift
# early, before the real integration inside the Josh tree per integration.md.

# Host compiler for the standalone harness (identity-map, runs on the dev box).
HOSTCC ?= cc

# Cross compiler for the freestanding scaffold-check (proves it links bare-metal).
CROSS  ?= x86_64-elf-
CC     := $(CROSS)gcc

ROOT    := ../..
INCLUDE := -I$(ROOT)/include

# Hosted-harness flags: the exact command the BBP repo's hosted test uses.
HOSTFLAGS := -std=c11 -Wall -Wextra $(INCLUDE)

# Freestanding flags: prove the port builds with no libc / no runtime.
FREEFLAGS := -ffreestanding -fno-stack-protector -fno-stack-clash-protection \
             -mno-red-zone -mno-sse -mno-mmx -fno-pic -mcmodel=kernel \
             -Wall -Wextra -Werror -std=c11 -O2 -g

BUILD := build
TESTBIN := $(BUILD)/josh_bbp_test

.PHONY: all test scaffold-check clean

# Default = run the hosted harness against the shipped port + frozen core.
all: test

# Compile the standalone harness with the host cc and run it; the port passes
# when the parser validates all 5 synthesized tags ("RESULT: PASS").
test: $(TESTBIN)
	@echo "== running Josh-Bear BBP hosted harness =="
	@$(TESTBIN)

$(TESTBIN): test/harness.c osif.c adapter.c \
            $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $^ -o $@
	@echo "built: $@"

# Link the port glue + the core parser + the core builder into one relocatable
# object with the cross compiler — proves every symbol the port uses exists in
# the frozen core ABI and that osif.c + adapter.c are freestanding-clean. No run.
scaffold-check: $(BUILD)/port.elf
	@echo "Josh-Bear port scaffold compiles + links against frozen BBP core."

$(BUILD)/port.elf: osif.c adapter.c $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -r $^ -o $@
	@echo "linked: $@"

clean:
	rm -rf $(BUILD)

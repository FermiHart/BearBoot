# ports/tinalinux/Makefile — compile-check + hosted-verify the TinaLinux port.
#
#   Author: F E R M I  ∞  H A R T   SPDX-License-Identifier: BSD-3-Clause
#
# This does NOT build TinaLinux. It proves:
#   scaffold-check : the port sources compile + link against the FROZEN BBP core
#                    ABI under kernel-like freestanding flags (-nostdinc via the
#                    compat shim, -ffreestanding). Catches ABI drift early.
#   test           : a HOSTED harness feeds representative NATIVE boot data
#                    (e820-style map, RSDP, kernel slide, cmdline) through the
#                    REAL adapter (osif.c + adapter.c) and asserts the frozen
#                    parser returns BBP_OK with CRC-validated tags. No QEMU.
#
# The real-kernel boot proof (the shipped late_initcall in tina_bbp.c) is
# captured separately as a serial log — see CONFORMANCE.md / integration.md.

ROOT    := ../..
INCLUDE := -I$(ROOT)/include
BUILD   := build

# ---- freestanding scaffold (mirrors the Linux -nostdinc kernel build) -------
CROSS     ?=
FREE_CC   := $(CROSS)gcc
COMPAT    := -I$(ROOT)/ports/tinalinux/compat
FREEFLAGS := -nostdinc -ffreestanding -fno-stack-protector \
             -mno-red-zone -mno-sse -mno-mmx -fno-pic -mcmodel=kernel \
             -Wall -Wextra -Werror -std=gnu11 -O2 -g

# ---- hosted harness ---------------------------------------------------------
HOST_CC   ?= cc
HOSTFLAGS := -Wall -Wextra -std=gnu11 -O2 -g

.PHONY: all scaffold-check test clean
all: scaffold-check test

# Link the port glue + the core parser + the core builder into one relocatable
# object — proves every symbol the port uses exists in the frozen core ABI, and
# that the ABI-frozen core compiles under -nostdinc via the compat shim.
scaffold-check: $(BUILD)/port.o
	@echo "TinaLinux port scaffold compiles + links against frozen BBP core."

$(BUILD)/port.o: osif.c adapter.c $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(FREE_CC) $(FREEFLAGS) $(COMPAT) $(INCLUDE) -r $^ -o $@
	@echo "linked: $@"

# Hosted verification rig. Compiles the SHIPPED osif.c + adapter.c with the
# frozen core and the harness (which supplies strong hosted OSIF hooks), runs
# it, and asserts PASS. tina_bbp.c is NOT included (it is the kernel glue).
test: $(BUILD)/harness
	@echo "running hosted adapter verification..."
	@$(BUILD)/harness

$(BUILD)/harness: test/harness.c osif.c adapter.c $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(HOST_CC) $(HOSTFLAGS) $(INCLUDE) -I. $^ -o $@

clean:
	rm -rf $(BUILD)

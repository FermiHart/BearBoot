# ports/linux01/Makefile — compile-check + hosted-verify the linux-0.01 port.
#
#   Author: F E R M I ∞ H A R T   SPDX-License-Identifier: BSD-3-Clause
#
# This does NOT build linux-0.01. It proves:
#   scaffold-check : the port sources compile + link against the FROZEN BBP core
#                    ABI under kernel-like freestanding flags (-nostdinc via the
#                    compat shim, -ffreestanding, -m32 to mirror the i386 kernel).
#                    Catches ABI drift early.
#   test           : a HOSTED harness feeds the linux-0.01 fixed RAM model
#                    through the REAL adapter (osif.c + adapter.c) and asserts
#                    the frozen parser returns BBP_OK with CRC-validated tags.
#                    No QEMU.
#
# The real-kernel boot proof (printk "[bbp] linux-0.01 adapter: ok" from the
# bbp_linux01_init() call site) is captured separately as a serial log — see
# CONFORMANCE.md / integration.md.

ROOT    := ../..
INCLUDE := -I$(ROOT)/include
BUILD   := build

# ---- freestanding scaffold (mirrors the linux-0.01 -nostdinc -m32 build) ----
# scaffold-check is INHERENTLY a cross-toolchain target: it must emit
# elf32-i386 and link relocatably with GNU ld (-melf_i386). A host compiler on
# a non-Linux box (e.g. Apple clang on macOS) cannot produce that target, so we
# default CROSS to the project's canonical bare-metal prefix. Override on a
# native x86 Linux box with a multilib gcc:  make scaffold-check CROSS=
CROSS     ?= x86_64-elf-
FREE_CC   := $(CROSS)gcc
COMPAT    := -I$(ROOT)/ports/linux01/compat
# linux-0.01 is 32-bit i386. -m32 makes uintptr_t 32-bit, exactly as in the
# real kernel, so the uint64_t->uintptr_t narrowing in phys_to_virt is checked
# under the production ABI. -mno-sse/-mno-mmx mirror a kernel without FPU setup.
#
# NOTE on -std: the linux-0.01 kernel proper compiles with -std=gnu89 (K&R-era
# source). The BBP core, however, REQUIRES C99+ (it declares loop variables in
# `for` initializers). These are reconciled the same way the tinalinux port
# does it: the BBP translation units carry their OWN -std=gnu11, independent of
# the kernel's gnu89 build. A port never forces the frozen core down to gnu89;
# it gives the BBP objects a C11 dialect via their own CFLAGS (see Kbuild stanza
# in integration.md). So this scaffold uses gnu11, matching how the BBP TUs are
# actually compiled inside the kernel.
FREEFLAGS := -m32 -march=i386 -nostdinc -ffreestanding -fno-stack-protector \
             -fno-pic -fno-pie -mno-sse -mno-mmx \
             -Wall -Wextra -Werror -std=gnu11 -O2 -g

# ---- hosted harness ---------------------------------------------------------
HOST_CC   ?= cc
HOSTFLAGS := -Wall -Wextra -std=gnu11 -O2 -g

.PHONY: all scaffold-check test clean
all: scaffold-check test

# Link the port glue + the core parser + the core builder into one relocatable
# object — proves every symbol the port uses exists in the frozen core ABI, and
# that the ABI-frozen core compiles under -nostdinc -m32 via the compat shim.
scaffold-check: $(BUILD)/port.o
	@echo "linux-0.01 port scaffold compiles + links against frozen BBP core."

$(BUILD)/port.o: osif.c adapter.c $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(FREE_CC) $(FREEFLAGS) $(COMPAT) $(INCLUDE) -Wl,-melf_i386 -r $^ -o $@
	@echo "linked: $@"

# Hosted verification rig. Compiles the SHIPPED osif.c + adapter.c with the
# frozen core and the harness (which supplies strong hosted OSIF hooks), runs
# it, and asserts PASS. linux01_bbp.c is NOT included (it is the kernel glue).
test: $(BUILD)/harness
	@echo "running hosted adapter verification..."
	@$(BUILD)/harness

$(BUILD)/harness: test/harness.c osif.c adapter.c $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(HOST_CC) $(HOSTFLAGS) $(INCLUDE) -I. $^ -o $@

clean:
	rm -rf $(BUILD)

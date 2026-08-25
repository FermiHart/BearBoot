# ports/minix/Makefile — compile-check the MINIX port against the frozen core.
#
#   Author: F E R M I  ∞  H A R T   SPDX-License-Identifier: BSD-3-Clause
#
# This does NOT build MINIX. It proves the port sources compile and link
# against the BBP core ABI (the scaffold uses compile-only stubs). The MINIX
# agent runs `make scaffold-check` after each change to catch ABI drift early,
# then does the real integration inside the MINIX tree per integration.md.

CROSS ?= x86_64-elf-
CC    := $(CROSS)gcc
HOSTCC ?= cc
ROOT  := ../..
INCLUDE := -I$(ROOT)/include

FREEFLAGS := -ffreestanding -fno-stack-protector -fno-stack-clash-protection \
              -mno-red-zone -mno-sse -mno-mmx -fno-pic -mcmodel=kernel \
              -Wall -Wextra -Werror -std=c11 -O2 -g
HOSTFLAGS := -std=c11 -Wall -Wextra -O2 -g $(INCLUDE)

BUILD := build
HOSTED_TEST := $(BUILD)/minix_hosted_test

.PHONY: all scaffold-check test-hosted clean
all: scaffold-check test-hosted

scaffold-check: $(BUILD)/port.elf
	@echo "MINIX port scaffold compiles + links against frozen BBP core."

# Link the port glue + the core parser + the core builder into one relocatable
# object — proves every symbol the port uses exists in the core ABI.
$(BUILD)/port.elf: osif.c adapter.c minix_glue.c $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(CC) $(FREEFLAGS) $(INCLUDE) -r $^ -o $@
	@echo "linked: $@"

test-hosted: $(HOSTED_TEST)
	@echo "== running MINIX BBP hosted synthetic snapshot =="
	@$(HOSTED_TEST)

$(HOSTED_TEST): test/hosted_harness.c osif.c adapter.c \
                $(ROOT)/kernel/bbp_kernel.c $(ROOT)/bootloader/bbp_build.c
	@mkdir -p $(BUILD)
	$(HOSTCC) $(HOSTFLAGS) $^ -o $@
	@echo "built: $@"

clean:
	rm -rf $(BUILD)

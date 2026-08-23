# Standalone BearBoot C SDK onboarding and conformance build.
# In the source tree use: make -f sdk/c/Makefile ROOT=. BUILD=build/sdk onboarding

ROOT ?= .
BUILD ?= build
CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -std=c11 -O2 -g
SDK_INCLUDE := $(if $(wildcard $(ROOT)/sdk/c/include/bbp/bbp_sdk.h),$(ROOT)/sdk/c/include,$(ROOT)/include)
CPPFLAGS := -I$(ROOT)/include -I$(SDK_INCLUDE)

CORE_SOURCES := $(ROOT)/bootloader/bbp_build.c $(ROOT)/kernel/bbp_kernel.c
IMPORT_SOURCES := $(ROOT)/bootloader/bbp_import.c \
	$(ROOT)/bootloader/bbp_import_limine.c \
	$(ROOT)/bootloader/bbp_import_multiboot2.c \
	$(ROOT)/bootloader/bbp_import_uefi.c
IMPORT_OBJECTS := $(patsubst $(ROOT)/bootloader/%.c,$(BUILD)/%.o,$(IMPORT_SOURCES))
CONFORMANCE := $(BUILD)/bbp_sdk_conformance
REPORT := $(BUILD)/conformance.json

.PHONY: all onboarding compile-sdk conformance report clean

all: compile-sdk

onboarding: compile-sdk report
	@$(CONFORMANCE) --human
	@echo "BBP SDK onboarding: PASS"
	@echo "Deterministic report: $(REPORT)"

compile-sdk: $(CONFORMANCE) $(IMPORT_OBJECTS)

conformance: $(CONFORMANCE)
	@$(CONFORMANCE) --json

report: $(CONFORMANCE)
	@mkdir -p $(BUILD)
	@$(CONFORMANCE) --json > $(REPORT)

$(CONFORMANCE): $(ROOT)/examples/sdk_roundtrip.c $(CORE_SOURCES) \
		$(ROOT)/include/bbp/bbp.h $(ROOT)/include/bbp/bbp_crc64.h \
		$(ROOT)/bootloader/bbp_build.h $(ROOT)/kernel/bbp_kernel.h \
		$(SDK_INCLUDE)/bbp/bbp_sdk.h
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(ROOT)/examples/sdk_roundtrip.c \
		$(CORE_SOURCES) -o $@

$(IMPORT_OBJECTS): $(BUILD)/%.o: $(ROOT)/bootloader/%.c \
		$(ROOT)/bootloader/bbp_import.h $(ROOT)/bootloader/bbp_build.h \
		$(ROOT)/include/bbp/bbp.h $(ROOT)/include/bbp/bbp_crc64.h
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)

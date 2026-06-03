# BBP MINIX adapter — verification harness (test/)

This directory is the VERIFICATION RIG for the Limine->BBP adapter. It is not
part of the shipped port objects (`../osif.c` + `../adapter.c`); it exists only
to PROVE those objects work on real higher-half Limine boot data, per the port
README rule "no green claims without a serial log" and SPEC §10.1.

## What it does

`harness.c` is a tiny standalone kernel booted by the SAME Limine the MINIX
port targets (limine protocol, 64-bit, paging on, higher-half, HHDM provided).
It:

1. Publishes the same Limine requests MINIX does (memmap, hhdm,
   kernel-address, rsdp, framebuffer) and receives REAL hardware data.
2. Performs the EXACT field copy the MINIX integration does
   (Limine response -> `struct bbp_minix_bootinfo`).
3. Calls the REAL shipped `bbp_minix_adapter()` (compiled from `../adapter.c`
   and linked with `../osif.c` + the frozen BBP core).
4. Prints the parser verdict, walks every validated tag, and runs
   `bbp_verify_blob()` on the out-of-line cmdline (ADR-0006).
5. Exits via QEMU `isa-debug-exit`: code 33 == PASS, anything else == FAIL.

If `bbp_init_ex` returns `BBP_OK` here, the adapter is proven against genuine
higher-half Limine boot data — the MINIX integration is then just the wiring
in `../integration.md` (identical field copy + call).

## Files

    boot.S        Limine entry stub: sets a 16B-aligned stack, calls harness_main
    harness.c     the rig (Limine requests, field copy, adapter call, tag dump)
    linker.ld     higher-half link (-2GiB), KEEP(.limine_requests*)
    limine.conf   Limine boot entry for harness.elf
    run.sh        build everything + make a Limine BIOS-CD ISO + boot QEMU
    serial.log    CAPTURED serial output (the deliverable) — created by run.sh

## Run it

    cd /Users/admin/OS/BearBoot/ports/minix/test
    ./run.sh

Reuses the Limine BIOS-CD assets already vendored at
`/Users/admin/OS/minix/minix/kernel/boot/limine/`; writes nothing outside
`ports/minix/`. Needs `x86_64-elf-gcc/ld`, `xorriso`, `limine`,
`qemu-system-x86_64` on PATH (all present on the dev host).

Success line in `serial.log`:

    bbp: minix adapter ok, N tags, hhdm=0x...
    RESULT: PASS — adapter validated on real Limine data

# ports/ — operating-system ports of the Bear Boot Protocol

The BBP **core** (`include/bbp/`, `kernel/bbp_kernel.*`, `bootloader/bbp_build.*`)
is OS-independent and frozen-ABI (v1.1, commit pinned in each port's
CONFORMANCE.md). Anything OS-specific lives here, behind the OSIF contract in
`include/bbp/bbp_osif.h`. This mirrors the core/ vs osif/ split of a portable
libc: zero per-OS `#ifdef` in the core.

Layout of a port `ports/<os>/`:

    osif.c            implements `struct bbp_osif` for this OS
    osif.h            port-local declarations (the const bbp_osif * accessor)
    adapter.c         OPTIONAL producer adapter (e.g. Limine boot info -> bbp_info)
    integration.md    how to wire it into the OS build (paths, flags, linker)
    CONFORMANCE.md    filled-in conformance report (see template)
    test/             port-specific tests + serial logs proving it boots

A port MUST NOT modify any core file. If the core needs a change, that is a
core PR with a new ADR — not a silent edit from a port.

Current ports:
  - minix/      MINIX x86_64 (limine-boot branch) — Limine->BBP adapter.
  - tinalinux/  TinaLinux x86_64 (Linux 6.12 derivative) — native Linux OSIF.
  - linux01/    linux-0.01 (Linus' 1991 kernel, Limine-booted) — native i386
                OSIF, identity-mapped (HHDM 0, SPEC §10.1(a)); the simplest port.

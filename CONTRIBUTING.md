# Contributing to the Bear Boot Protocol

Thanks for your interest. BBP is a small, deliberately-frozen ABI plus a
defensive parser, a builder, and OS-interface (OSIF) ports. Contributions are
welcome — within the constraints that keep the protocol trustworthy.

## The one hard rule: the core ABI is frozen

`include/bbp/*`, `kernel/bbp_kernel.c`, and `bootloader/bbp_build.c` are
**ABI-frozen** within a major version. Every cross-boundary struct is guarded by
`_Static_assert(sizeof(...) == N)`. A change that alters a struct layout is a
**breaking** change and bumps `BBP_VERSION_MAJOR` — it is not a casual PR.

Within a major version you MAY:
- add a new tag (consumers ignore unknown tags);
- append a field to the END of a variable-length tag's fixed struct, guarded by
  a `tag_version` bump, such that old readers still parse the prefix.

You MAY NOT reorder, resize, or retype an existing field without a major bump.

## Where work usually belongs

- **A new OS integration** → add `ports/<os>/` implementing the OSIF
  (`include/bbp/bbp_osif.h`). Mirror an existing port's structure:
  `osif.{c,h}`, an adapter, a glue/call-site, a `Makefile` with
  `scaffold-check` + a hosted test, and a `CONFORMANCE.md`. See
  `ports/tinalinux/` (native) and `ports/minix/` (Limine adapter).
- **A real producer** (firmware/bootloader side) → build on `bbp_build.c`. The
  UEFI `efi_main.c` is a skeleton to start from.
- **Parser hardening** → `kernel/bbp_kernel.c`, with a matching adversarial case
  in `tests/abi_selftest.c` and, where relevant, the fuzzer corpus.

## Definition of done

Every change must keep these green:

```sh
make check                       # ABI asserts + self-test + fuzzer
cd ports/<os> && make scaffold-check && make test   # if you touched a port
```

A new capability claim must come with a proof: a `make` target or a checked-in
log. Update `STATUS.md` honestly — if something is structure-only, label it
🟡; do not mark it 🟢 without a reproducible proof. **Trust is the product.**

## Style

- Freestanding C (`-ffreestanding`, no libc) for the core and OSIF code; it must
  compile `-nostdinc` inside a kernel. The ports show the compat-shim pattern.
- No new warnings under `-Wall -Wextra`. The core builds `-Werror` clean.
- Record non-trivial design decisions as an ADR in `docs/adr/`.

## Licensing

By contributing you agree your work is licensed under the repository's
BSD-3-Clause + Patent Grant (see `LICENSE`).

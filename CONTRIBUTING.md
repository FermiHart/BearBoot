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
- **A producer** (firmware/bootloader side) → build on `bbp_build.c`. The x86_64
  UEFI `efi_main.c` is machine-proven for its deliberately constrained three-tag,
  four-level-paging contract; expanding it requires new fail-closed tests and a
  machine proof, not an assumption that it is a general-purpose loader.
- **Parser hardening** → `kernel/bbp_kernel.c`, with a matching adversarial case
  in `tests/abi_selftest.c` and, where relevant, the fuzzer corpus.
- **Experimental v2/auth work** → keep it isolated from the frozen v1.1 ABI,
  update the governing RFC, and preserve explicit package allowlists and shared
  vectors. Package availability does not make an experimental format stable.

## Definition of done

Every change must keep these green:

```sh
make check                       # core + fuzz + importers + tools + SDK + docs
cd ports/<os> && make scaffold-check && make test   # if you touched a port
make qemu-uefi-loader qemu-uefi-tcg2  # if loader/TCG2 behavior changed
```

A new capability claim must come with a proof: a `make` target or a checked-in
log. Update `STATUS.md` honestly — if something is structure-only, label it
🟡; do not mark it 🟢 without a reproducible proof. **Trust is the product.**

Execution claims must preserve their provenance. Hosted, emulator, and physical
evidence are distinct scopes under the execution-evidence v1 contract. Never
relabel a fixture, hosted transcript, or QEMU log as physical evidence; physical
claims require identified board metadata and raw serial as documented in
`docs/physical-hardware-runner.md`. The bundle format does not authenticate
these claims, and the physical override is integrity-only, not proof.

Release preparation is not publication. Documentation for a version candidate
must say that the cut is pending until the signed tag and hardened release
workflow have completed; do not claim a tag, registry package, or GitHub release
from an in-tree version bump alone.

## Style

- Freestanding C (`-ffreestanding`, no libc) for the core and OSIF code; it must
  compile `-nostdinc` inside a kernel. The ports show the compat-shim pattern.
- No new warnings under `-Wall -Wextra`. The core builds `-Werror` clean.
- Record non-trivial design decisions as an ADR in `docs/adr/`.

## Licensing

By contributing you agree your work is licensed under the repository's
BSD-3-Clause + Patent Grant (see `LICENSE`).

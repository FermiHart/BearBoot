#!/usr/bin/env python3
"""Generate root-authenticated negative vectors for the C auth2 selftest."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from experimental.auth2 import KeyPolicy, ROLE_RELEASE, build_manifest  # noqa: E402
from experimental.auth2 import auth2 as implementation  # noqa: E402


SOURCE = ROOT / "tests" / "vectors" / "auth2"
SIGNATURE_OFFSET = implementation.MANIFEST_SIGNATURE_OFFSET
ENTRY_OFFSET = implementation.MANIFEST_HEADER_SIZE
ENTRY_SIZE = implementation.MANIFEST_ENTRY_SIZE


def _write_signed_mutation(output: Path, name: str, mutate) -> None:
    raw = bytearray((SOURCE / "manifest.auth2").read_bytes())
    mutate(raw)
    raw[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 64] = bytes(64)
    raw[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 64] = implementation._sign(
        bytes(raw), SOURCE / "root.test-only.private.pem"
    )
    (output / f"manifest-invalid-{name}.auth2").write_bytes(raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)

    mutations = {
        "entry-algorithm": lambda raw: raw.__setitem__(
            slice(ENTRY_OFFSET + 32, ENTRY_OFFSET + 34), b"\xff\xff"
        ),
        "entry-role": lambda raw: raw.__setitem__(
            slice(ENTRY_OFFSET + 34, ENTRY_OFFSET + 36), b"\xff\xff"
        ),
        "entry-flags": lambda raw: raw.__setitem__(ENTRY_OFFSET + 36, 2),
        "entry-window": lambda raw: raw.__setitem__(
            slice(ENTRY_OFFSET + 40, ENTRY_OFFSET + 48), bytes(8)
        ),
        "entry-reserved": lambda raw: raw.__setitem__(ENTRY_OFFSET + 121, 1),
        "entry-key-id": lambda raw: raw.__setitem__(
            ENTRY_OFFSET, raw[ENTRY_OFFSET] ^ 1
        ),
        "entry-point": lambda raw: raw.__setitem__(ENTRY_OFFSET + 56, 3),
        "duplicate-entry": lambda raw: raw.__setitem__(
            slice(ENTRY_OFFSET + ENTRY_SIZE, ENTRY_OFFSET + 2 * ENTRY_SIZE),
            raw[ENTRY_OFFSET:ENTRY_OFFSET + ENTRY_SIZE],
        ),
    }
    for name, mutate in mutations.items():
        _write_signed_mutation(arguments.output, name, mutate)

    release_public = SOURCE / "release.public.pem"
    root_private = SOURCE / "root.test-only.private.pem"
    lifecycle = {
        "revoked": KeyPolicy(release_public, ROLE_RELEASE, 1, 20, True),
        "not-active": KeyPolicy(release_public, ROLE_RELEASE, 8, 20, False),
        "retired": KeyPolicy(release_public, ROLE_RELEASE, 1, 6, False),
    }
    for name, policy in lifecycle.items():
        manifest = build_manifest(root_private, 7, [policy])
        (arguments.output / f"manifest-{name}.auth2").write_bytes(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

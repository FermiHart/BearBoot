#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Verify that the local BearBoot site presents the canonical ABI honestly."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ABI = (ROOT / "include/bbp/bbp.h").read_text(encoding="utf-8")
SDK_VERSION = (ROOT / "sdk/VERSION").read_text(encoding="ascii").strip()
SITE = ROOT / "website/index.html"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(SITE.exists(), "website/index.html is missing")
    page = SITE.read_text(encoding="utf-8")
    major = re.search(r"#define BBP_VERSION_MAJOR\s+(\d+)", ABI).group(1)
    minor = re.search(r"#define BBP_VERSION_MINOR\s+(\d+)", ABI).group(1)
    tags = re.findall(r"#define\s+BBP_TAG_\w+\s+BBP_TAG_ID\(", ABI)
    sizes = dict(re.findall(
        r"_Static_assert\(sizeof\(struct\s+(\w+)\)\s*==\s*(\d+)", ABI
    ))

    for token in (
        '<meta name="viewport"',
        f'data-abi="{major}.{minor}"',
        f'data-tags="{len(tags)}"',
        f'data-header-bytes="{sizes["bbp_header"]}"',
        f'data-info-bytes="{sizes["bbp_info"]}"',
        f'data-tag-bytes="{sizes["bbp_tag_header"]}"',
        f"SDK {SDK_VERSION} / ABI {major}.{minor}",
        "CRC-64/XZ",
        "bbp_init_bounded()",
        "requires serial PASS",
        "hero-proof-geometry.svg",
    ):
        require(token in page, f"site contract missing: {token}")
    for token in ("integrity is not authenticity", "not a bootloader"):
        require(token in page.lower(), f"site contract missing: {token}")

    require("http://" not in page, "site contains an insecure external URL")
    require("<script src=" not in page, "site must not depend on remote scripts")
    require(page.count('class="tag-node"') == len(tags), "site tag constellation drifted from ABI")
    require(page.count('class="port-card"') == 4, "site integration inventory must list four ports")
    require("does not yet launch QEMU" not in page, "site carries stale QEMU claim")
    require((ROOT / "readme/hero-proof-geometry.svg").exists(), "desktop geometry missing")
    require((ROOT / "readme/hero-proof-geometry-mobile.svg").exists(), "mobile geometry missing")
    print(f"BearBoot site: PASS (ABI {major}.{minor}, {len(tags)} tags, 4 integration records)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AttributeError, RuntimeError) as error:
        print(f"BearBoot site: FAIL: {error}", file=sys.stderr)
        sys.exit(1)

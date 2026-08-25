#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Verify that the local BearBoot site presents the canonical ABI honestly."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ABI = (ROOT / "include/bbp/bbp.h").read_text(encoding="utf-8")
SDK_VERSION = (ROOT / "sdk/VERSION").read_text(encoding="ascii").strip()
SDK_SERIES = SDK_VERSION.rsplit(".", 1)[0]
SITE = ROOT / "website/index.html"
STATE_PAGE = ROOT / "website/estado.html"
PAGES_ENTRY = ROOT / "index.html"
NOJEKYLL = ROOT / ".nojekyll"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(SITE.exists(), "website/index.html is missing")
    require(STATE_PAGE.exists(), "website/estado.html is missing")
    require(PAGES_ENTRY.exists(), "GitHub Pages root entry is missing")
    require(NOJEKYLL.exists(), "GitHub Pages must preserve static repository paths")
    page = SITE.read_text(encoding="utf-8")
    state_page = STATE_PAGE.read_text(encoding="utf-8")
    pages_entry = PAGES_ENTRY.read_text(encoding="utf-8")
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
        "make qemu-aarch64",
        "make qemu-riscv64",
        "make importers-test",
        "make bbpctl-test",
        "make sdk-check release-metadata-test",
        "make qemu-uefi-loader",
        "make qemu-uefi-tcg2",
        "make auth2-test rollback-test",
        "make ports-hosted-check evidence-check",
        "injected monotonic floor",
        "exact serial PASS",
        "RELEASE / PUBLISHED",
        "exact 15 verified assets",
        "no physical PASS proof",
        "hero-proof-geometry.svg",
    ):
        require(token in page, f"site contract missing: {token}")
    for token in ("integrity is not authenticity", "not a bootloader"):
        require(token in page.lower(), f"site contract missing: {token}")

    require("http://" not in page, "site contains an insecure external URL")
    require("<script src=" not in page, "site must not depend on remote scripts")
    require('href="estado.html"' in page, "site does not link the current-state page")
    for token in (
        f"SDK {SDK_VERSION} / wire {major}.{minor}",
        "BBP v2 Draft / offline",
        "AArch64 boot proof",
        "Release checkpoint",
        f"WAVE 16 / SDK {SDK_SERIES}",
        f"WAVE 25 / SDK {SDK_SERIES}",
        "TCG2 + SECURITY",
        "Release checkpoint / concluído",
        "nenhum PASS físico",
        "INTEGRAÇÕES OSIF",
        "Linux 0.01 tem harness host",
        "integridade com confiança",
    ):
        require(token in state_page, f"current-state page missing: {token}")
    require("http://" not in state_page, "current-state page contains an insecure URL")
    require("<script src=" not in state_page, "current-state page must be standalone")
    for token in (
        'content="0; url=website/"',
        'href="website/"',
        'href="https://fermihart.github.io/BearBoot/"',
    ):
        require(token in pages_entry, f"GitHub Pages root entry missing: {token}")
    require(page.count('class="tag-node"') == len(tags), "site tag constellation drifted from ABI")
    require(page.count('class="port-card"') == 4, "site integration inventory must list four ports")
    require(page.count('class="product-row"') == 4, "site must list four distributable/host surfaces")
    require(page.count('class="machine"') == 4, "site must list four machine contexts")
    require(page.count('class="proof-card"') == 10, "site proof ledger is incomplete")
    require(page.count('class="ingest-node') == 6, "site ingestion rail is incomplete")
    require("does not yet launch QEMU" not in page, "site carries stale QEMU claim")
    require("MULTI-ISA LIVE / UNRELEASED" not in page,
            "site carries stale architecture release claim")
    require(re.search(r"\bRC\b", page + state_page) is None,
            "site carries a stale release-candidate label")
    require("+ WORKTREE" not in state_page,
            "current-state page carries stale worktree claim")
    require("PROVAS DE SO" not in state_page,
            "current-state page conflates OSIF integrations with boot proofs")
    presented_versions = set(re.findall(
        r"SDK (\d+\.\d+\.\d+)", page + state_page
    ))
    require(presented_versions == {SDK_VERSION},
            f"site SDK versions drifted from {SDK_VERSION}: {presented_versions}")
    release_path = f"releases/tag/sdk-v{SDK_VERSION}"
    require(release_path in page, f"site does not link published SDK {SDK_VERSION}")
    require(release_path in state_page,
            f"current-state page does not link published SDK {SDK_VERSION}")
    for document, name in ((page, "site"), (state_page, "current-state page")):
        ids = set(re.findall(r'\bid="([^"]+)"', document))
        fragments = set(re.findall(r'href="#([^"]+)"', document))
        require(fragments <= ids, f"{name} links missing fragments: {sorted(fragments - ids)}")
    for stale in (
        "LIVE CONTRACT MODEL",
        "never forged data",
        "IN-KERNEL QEMU RECORD",
        "INFO / RDI",
        "release candidate",
        "cut pending workflow",
    ):
        require(stale not in page, f"site carries stale or overstated claim: {stale}")
    require((ROOT / "readme/hero-proof-geometry.svg").exists(), "desktop geometry missing")
    require((ROOT / "readme/hero-proof-geometry-mobile.svg").exists(), "mobile geometry missing")
    print(f"BearBoot site: PASS (SDK {SDK_VERSION} published, ABI {major}.{minor}, "
          f"{len(tags)} tags, 4 integration records)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AttributeError, RuntimeError) as error:
        print(f"BearBoot site: FAIL: {error}", file=sys.stderr)
        sys.exit(1)

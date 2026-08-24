#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate BearBoot's deterministic, ABI-bound proof geometry."""

import argparse
import hashlib
import html
import math
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ABI = ROOT / "include/bbp/bbp.h"
OUT = ROOT / "readme"
CORE_FILES = [
    "include/bbp/bbp.h",
    "include/bbp/bbp_crc64.h",
    "include/bbp/bbp_osif.h",
    "kernel/bbp_kernel.c",
    "kernel/bbp_kernel.h",
    "bootloader/bbp_build.c",
    "bootloader/bbp_build.h",
    "tests/abi_selftest.c",
]
PALETTE = ["#65fbd2", "#ffcc66", "#ff6b8a", "#8ea1ff", "#d58cff"]
BANNED_SVG = {"script", "foreignObject", "animate", "animateMotion", "animateTransform", "set"}


def abi_facts():
    source = ABI.read_text(encoding="utf-8")
    major = re.search(r"#define BBP_VERSION_MAJOR\s+(\d+)", source)
    minor = re.search(r"#define BBP_VERSION_MINOR\s+(\d+)", source)
    if not major or not minor:
        raise RuntimeError("cannot parse BBP protocol version")

    sizes = dict(re.findall(
        r"_Static_assert\(sizeof\(struct\s+(\w+)\)\s*==\s*(\d+)", source
    ))
    required = {"bbp_header", "bbp_info", "bbp_tag_header", "bbp_tag_request"}
    if not required.issubset(sizes):
        raise RuntimeError("canonical ABI sizes are missing")

    tag_pattern = re.compile(
        r"#define\s+BBP_TAG_(\w+)\s+BBP_TAG_ID\(BBP_CAT_(\w+),\s*(0x[0-9A-Fa-f]+)\)"
    )
    tags = tag_pattern.findall(source)
    if len(tags) != 15:
        raise RuntimeError(f"expected 15 canonical tags, found {len(tags)}")
    return f"{major.group(1)}.{minor.group(1)}", sizes, tags


def fingerprint():
    digest = hashlib.sha256(b"FERMI-HART-BEARBOOT-PROOF-GEOMETRY-V1\0")
    for relative in CORE_FILES:
        data = (ROOT / relative).read_bytes()
        digest.update(relative.encode("ascii") + b"\0")
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def text(x, y, value, size, fill="#edf3ff", weight=500, anchor="start", spacing=0):
    value = html.escape(str(value))
    family = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    return (f'<text x="{x}" y="{y}" fill="{fill}" font-family="{family}" '
            f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
            f'letter-spacing="{spacing}">{value}</text>\n')


def start_svg(title, description, width, height):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
<title id="title">{html.escape(title)}</title>
<desc id="desc">{html.escape(description)}</desc>
<defs>
  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#070a12"/><stop offset=".52" stop-color="#111426"/><stop offset="1" stop-color="#071715"/></linearGradient>
  <radialGradient id="seal"><stop stop-color="#fff2c2"/><stop offset=".38" stop-color="#ffcc66"/><stop offset="1" stop-color="#b56722"/></radialGradient>
  <radialGradient id="jade"><stop stop-color="#c8fff0"/><stop offset=".38" stop-color="#65fbd2"/><stop offset="1" stop-color="#158a78"/></radialGradient>
  <filter id="glow" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="8"/></filter>
  <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#8ea1ff" stroke-opacity=".07"/></pattern>
</defs>
<rect width="{width}" height="{height}" rx="24" fill="url(#bg)"/>
<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="23" fill="none" stroke="#8ea1ff" stroke-opacity=".28"/>
<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="23" fill="url(#grid)"/>
'''


def metatron(cx, cy, scale, digest, tags, label=True):
    raw = bytes.fromhex(digest)
    out = []
    points = [(cx, cy)]
    for radius in (scale * .37, scale * .75):
        for index in range(6):
            angle = math.radians(-90 + index * 60)
            points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))

    out.append(f'<circle cx="{cx}" cy="{cy}" r="{scale * .9:.1f}" fill="#07100f" fill-opacity=".58" stroke="#65fbd2" stroke-opacity=".18"/>\n')
    out.append(f'<circle cx="{cx}" cy="{cy}" r="{scale * .75:.1f}" fill="none" stroke="#ffcc66" stroke-opacity=".34" stroke-dasharray="3 10"/>\n')
    out.append(f'<circle cx="{cx}" cy="{cy}" r="{scale * .37:.1f}" fill="none" stroke="#d58cff" stroke-opacity=".28"/>\n')

    for left in range(len(points)):
        for right in range(left + 1, len(points)):
            byte = raw[(left * 13 + right) % len(raw)]
            if (byte >> ((left + right) % 8)) & 1:
                x1, y1 = points[left]
                x2, y2 = points[right]
                color = PALETTE[(left + right + byte) % len(PALETTE)]
                out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-opacity=".23"/>\n')

    for index, (x, y) in enumerate(points):
        radius = scale * (.105 if index == 0 else .035)
        fill = "url(#seal)" if index == 0 else "url(#jade)"
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius + 5:.1f}" fill="none" stroke="#65fbd2" stroke-opacity=".17"/>\n')
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="{fill}" stroke="#f5f1df" stroke-opacity=".65"/>\n')

    tag_radius = scale * .92
    for index, (name, category, _) in enumerate(tags):
        angle = math.radians(-90 + index * (360 / len(tags)))
        x = cx + tag_radius * math.cos(angle)
        y = cy + tag_radius * math.sin(angle)
        color = PALETTE[index % len(PALETTE)]
        radius = 3 + raw[index] % 4
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{color}"/>\n')
        if label and index in (0, 3, 6, 8, 9, 14):
            anchor = "middle" if abs(x - cx) < scale * .2 else ("start" if x > cx else "end")
            dx = 12 if anchor == "start" else (-12 if anchor == "end" else 0)
            dy = -10 if y < cy else 17
            out.append(text(f"{x + dx:.1f}", f"{y + dy:.1f}", category, 10, color, 700, anchor, 1))

    out.append(text(cx, cy - 3, "CRC-64", max(9, int(scale * .042)), "#171006", 800, "middle", .3))
    out.append(text(cx, cy + scale * .045, "XZ", max(8, int(scale * .034)), "#171006", 800, "middle", 1))
    return "".join(out)


def desktop(version, sizes, tags, digest):
    out = [start_svg(
        "BearBoot ABI proof geometry",
        "Fermi Hart proof geometry derived from the frozen BearBoot ABI, parser, builder, and adversarial tests.",
        1200, 640,
    )]
    out.append('<circle cx="929" cy="294" r="242" fill="#65fbd2" fill-opacity=".035" filter="url(#glow)"/>\n')
    out.append(metatron(930, 292, 248, digest, tags))
    out.append(text(70, 75, "FERMI HART / PROOF GEOMETRY 02", 17, "#65fbd2", 700, spacing=3))
    out.append(text(70, 180, "BearBoot", 76, "#f4f0dd", 800))
    out.append(text(72, 226, "SEALED BOOT HANDOFF", 24, "#ffcc66", 700, spacing=2))
    out.append(text(72, 281, "UNTRUSTED INPUT. BOUNDED PARSER.", 17, "#aebbd1", 500, spacing=1))
    out.append(text(72, 321, "HEADER", 13, "#91ad91", 700, spacing=2))
    out.append(text(196, 321, f"{sizes['bbp_header']} B", 26, "#65fbd2", 800))
    out.append(text(72, 361, "INFO", 13, "#91ad91", 700, spacing=2))
    out.append(text(196, 361, f"{sizes['bbp_info']} B", 26, "#ffcc66", 800))
    out.append(text(72, 401, "TAG FRAME", 13, "#91ad91", 700, spacing=2))
    out.append(text(196, 401, f"{sizes['bbp_tag_header']} B", 26, "#ff6b8a", 800))
    out.append(text(72, 456, f"ABI {version} / {len(tags)} TAG UUIDs / 7 NAMESPACES", 15, "#d7deeb", 600, spacing=1))
    out.append(text(72, 505, "INTEGRITY IS NOT AUTHENTICITY", 14, "#ffcc66", 700, spacing=2))
    out.append(text(72, 532, "CRC detects corruption. Trust remains upstream.", 13, "#91ad91"))
    out.append(f'<line x1="70" y1="574" x2="1130" y2="574" stroke="#8ea1ff" stroke-opacity=".2"/>\n')
    out.append(text(70, 606, f"CORE SHA-256  {digest[:16]}:{digest[16:32]}:{digest[32:48]}:{digest[48:]}", 12, "#77869e", 500, spacing=.4))
    out.append('</svg>\n')
    return "".join(out)


def mobile(version, sizes, tags, digest):
    out = [start_svg(
        "BearBoot mobile ABI proof geometry",
        "Responsive Fermi Hart seal derived from the frozen BearBoot core.",
        720, 1040,
    )]
    out.append(text(360, 68, "FERMI HART / PROOF GEOMETRY 02", 15, "#65fbd2", 700, "middle", 2))
    out.append(text(360, 158, "BearBoot", 68, "#f4f0dd", 800, "middle"))
    out.append(text(360, 203, "SEALED BOOT HANDOFF", 20, "#ffcc66", 700, "middle", 2))
    out.append(metatron(360, 492, 255, digest, tags, label=False))
    stats = [
        ("HEADER", sizes["bbp_header"], "#65fbd2"),
        ("INFO", sizes["bbp_info"], "#ffcc66"),
        ("TAG FRAME", sizes["bbp_tag_header"], "#ff6b8a"),
    ]
    for index, (name, size, color) in enumerate(stats):
        x = 122 + index * 238
        out.append(text(x, 793, name, 11, "#91ad91", 700, "middle", 1))
        out.append(text(x, 831, f"{size} B", 25, color, 800, "middle"))
    out.append(text(360, 892, f"ABI {version} / {len(tags)} TAG UUIDs / 7 NAMESPACES", 14, "#d7deeb", 600, "middle", 1))
    out.append(text(360, 936, "INTEGRITY IS NOT AUTHENTICITY", 13, "#ffcc66", 700, "middle", 2))
    out.append(text(360, 977, f"CORE SHA-256  {digest[:16]}...{digest[-16:]}", 11, "#77869e", 500, "middle"))
    out.append('</svg>\n')
    return "".join(out)


def validate_svg(data):
    root = ET.fromstring(data)
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] in BANNED_SVG:
            raise RuntimeError(f"unsafe SVG element: {element.tag}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    version, sizes, tags = abi_facts()
    digest = fingerprint()
    generated = {
        OUT / "hero-proof-geometry.svg": desktop(version, sizes, tags, digest),
        OUT / "hero-proof-geometry-mobile.svg": mobile(version, sizes, tags, digest),
    }
    for data in generated.values():
        validate_svg(data)

    stale = []
    for path, data in generated.items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != data:
                stale.append(path.relative_to(ROOT))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data, encoding="utf-8")
    if stale:
        print("stale proof geometry: " + ", ".join(map(str, stale)), file=sys.stderr)
        return 1
    print(f"BearBoot proof geometry: ABI {version}, {len(tags)} tags, core {digest[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

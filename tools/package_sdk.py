#!/usr/bin/env python3
"""Build reproducible, allowlisted BearBoot SDK development archives."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "sdk" / "VERSION").read_text(encoding="ascii").strip()
WIRE_VERSION = "1.1"
MAX_SOURCE_DATE_EPOCH = (1 << 32) - 1
MAX_VERSION_LENGTH = 32
VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)

C_SDK_FILES = {
    "LICENSE": "LICENSE",
    "README.md": "sdk/c/README.md",
    "SECURITY.md": "SECURITY.md",
    "SPEC.md": "SPEC.md",
    "VERSION": "sdk/VERSION",
    "docs/bbp-conformance-report-v1.schema.json": "docs/schemas/bbp-conformance-report-v1.schema.json",
    "Makefile": "sdk/c/Makefile",
    "include/bbp/bbp.h": "include/bbp/bbp.h",
    "include/bbp/bbp_crc64.h": "include/bbp/bbp_crc64.h",
    "include/bbp/bbp_osif.h": "include/bbp/bbp_osif.h",
    "include/bbp/bbp_sdk.h": "sdk/c/include/bbp/bbp_sdk.h",
    "kernel/bbp_kernel.c": "kernel/bbp_kernel.c",
    "kernel/bbp_kernel.h": "kernel/bbp_kernel.h",
    "bootloader/bbp_build.c": "bootloader/bbp_build.c",
    "bootloader/bbp_build.h": "bootloader/bbp_build.h",
    "bootloader/bbp_import.c": "bootloader/bbp_import.c",
    "bootloader/bbp_import.h": "bootloader/bbp_import.h",
    "bootloader/bbp_import_limine.c": "bootloader/bbp_import_limine.c",
    "bootloader/bbp_import_multiboot2.c": "bootloader/bbp_import_multiboot2.c",
    "bootloader/bbp_import_uefi.c": "bootloader/bbp_import_uefi.c",
    "examples/sdk_roundtrip.c": "examples/sdk_roundtrip.c",
}

HOST_FILES = {
    "LICENSE": "LICENSE",
    "README.md": "sdk/host/README.md",
    "VERSION": "sdk/VERSION",
    "bin/bbpctl.py": "tools/bbpctl.py",
    "docs/bbpc-v1.md": "docs/bbpc-v1.md",
}


def git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


class PackageError(Exception):
    """Invalid package input that must fail before archive creation."""


def validate_version(version: str) -> bool:
    if len(version) > MAX_VERSION_LENGTH:
        return False
    match = VERSION_PATTERN.fullmatch(version)
    if match is None:
        return False
    prerelease = match.group(1)
    if prerelease:
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier[0] == "0":
                return False
    return True


def release_error(dirty: bool, version: str) -> str | None:
    if dirty:
        return "--release requires a clean Git tree"
    prerelease = version.partition("-")[2].split(".")
    if "dev" in prerelease:
        return "--release requires a non-development VERSION"
    return None


def source_bytes(source: str) -> bytes:
    relative = Path(source)
    if relative.is_absolute() or ".." in relative.parts:
        raise PackageError(f"unsafe source path: {source}")

    candidate = ROOT / relative
    current = candidate
    while current != ROOT:
        if current.is_symlink():
            raise PackageError(f"allowlisted source must not be a symlink: {source}")
        current = current.parent
    if not candidate.is_file():
        raise PackageError(f"allowlisted source is not a regular file: {source}")
    try:
        candidate.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except ValueError as error:
        raise PackageError(f"allowlisted source escapes repository: {source}") from error
    return candidate.read_bytes()


def snapshot(files: dict[str, str]) -> dict[str, bytes]:
    payloads = {}
    for destination, source in files.items():
        path = PurePosixPath(destination)
        if path.is_absolute() or ".." in path.parts or str(path) != destination:
            raise PackageError(f"unsafe archive path: {destination}")
        payloads[destination] = source_bytes(source)
    return payloads


def manifest(payloads: dict[str, bytes], package: str, source_revision: str,
             tree_state: str) -> bytes:
    entries = []
    for destination, data in sorted(payloads.items()):
        entries.append({
            "path": destination,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    document = {
        "format": "bearboot-sdk-manifest-v1",
        "package": package,
        "sdk_version": VERSION,
        "wire_version": WIRE_VERSION,
        "source_revision": source_revision,
        "tree_state": tree_state,
        "files": entries,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def add_file(archive: tarfile.TarFile, name: str, data: bytes, epoch: int,
             executable: bool = False) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755 if executable else 0o644
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    archive.addfile(info, io.BytesIO(data))


def build_archive(output: Path, root_name: str, package: str,
                  payloads: dict[str, bytes], epoch: int, source_revision: str,
                  tree_state: str) -> None:
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for destination, data in sorted(payloads.items()):
            add_file(archive, f"{root_name}/{destination}",
                     data, epoch,
                     executable=destination == "bin/bbpctl.py")
        add_file(archive, f"{root_name}/MANIFEST.json",
                 manifest(payloads, package, source_revision, tree_state), epoch)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                           compresslevel=9, mtime=epoch) as compressed:
            compressed.write(tar_bytes.getvalue())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build" / "dist")
    parser.add_argument(
        "--release", action="store_true",
        help="require a clean tree and a non-development SDK version",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not validate_version(VERSION):
        print("package_sdk: VERSION must be a path-safe SemVer without build metadata",
              file=sys.stderr)
        return 1
    dirty = bool(git(["status", "--porcelain"]))
    source_revision = git(["rev-parse", "HEAD"])
    tree_state = "dirty" if dirty else "clean"
    if args.release and (error := release_error(dirty, VERSION)):
        print(f"package_sdk: {error}", file=sys.stderr)
        return 1

    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"), 10)
        if epoch < 0 or epoch > MAX_SOURCE_DATE_EPOCH:
            raise ValueError
    except ValueError:
        print("package_sdk: SOURCE_DATE_EPOCH must be an integer from 0 to 4294967295",
              file=sys.stderr)
        return 1

    packages = (
        (f"bearboot-c-sdk-{VERSION}", "bearboot-c-sdk", C_SDK_FILES),
        (f"bearboot-host-tools-{VERSION}", "bearboot-host-tools", HOST_FILES),
    )
    try:
        prepared = [
            (root_name, package, snapshot(files))
            for root_name, package, files in packages
        ]
        for root_name, package, payloads in prepared:
            archive = args.output_dir / f"{root_name}.tar.gz"
            build_archive(archive, root_name, package, payloads, epoch,
                          source_revision, tree_state)
            print(archive)
    except (OSError, PackageError, tarfile.TarError, ValueError) as error:
        print(f"package_sdk: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

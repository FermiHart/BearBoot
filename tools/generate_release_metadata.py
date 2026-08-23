#!/usr/bin/env python3
"""Generate deterministic BearBoot release support and SPDX metadata."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
WIRE_VERSION = "1.1"
MAX_SOURCE_DATE_EPOCH = (1 << 32) - 1
REVISION_PATTERN = re.compile(r"[0-9a-fA-F]{7,64}")
ARTIFACT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


class MetadataError(Exception):
    """Release metadata input is invalid or unsafe."""


def json_bytes(document: dict) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")


def timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_date_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(value, 10)
    except ValueError as error:
        raise MetadataError("SOURCE_DATE_EPOCH must be an integer from 0 to 4294967295") from error
    if epoch < 0 or epoch > MAX_SOURCE_DATE_EPOCH:
        raise MetadataError("SOURCE_DATE_EPOCH must be an integer from 0 to 4294967295")
    return epoch


def source_revision(value: str | None) -> str:
    if value is None:
        try:
            value = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                capture_output=True, text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise MetadataError("cannot determine source revision; use --source-revision") from error
    if REVISION_PATTERN.fullmatch(value) is None:
        raise MetadataError("source revision must be a 7 to 64 character hexadecimal commit ID")
    return value.lower()


def has_symlink_component(path: Path) -> bool:
    current = Path(os.path.abspath(path))
    while True:
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except FileNotFoundError:
            pass
        if current.parent == current:
            return False
        current = current.parent


def canonical_path(path: Path) -> Path:
    return path.resolve(strict=False)


def artifact_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_spec(value: str) -> tuple[str, str]:
    if "=" in value:
        return tuple(value.split("=", 1))
    path = Path(value)
    return path.name, value


def parse_artifacts(values: list[str]) -> list[dict[str, str]]:
    artifacts = []
    names = set()
    sources = set()
    for value in values:
        name, local_name = artifact_spec(value)
        posix_name = PurePosixPath(name)
        if (not ARTIFACT_NAME_PATTERN.fullmatch(name)
                or posix_name.name != name or name in (".", "..")):
            raise MetadataError(f"unsafe artifact release name: {name!r}")
        if name in names:
            raise MetadataError(f"duplicate artifact release name: {name}")
        if not local_name:
            raise MetadataError(f"artifact path is empty: {name}")

        local_path = Path(local_name)
        if has_symlink_component(local_path):
            raise MetadataError(f"artifact must not be a symlink: {name}")
        try:
            mode = local_path.lstat().st_mode
        except FileNotFoundError as error:
            raise MetadataError(f"artifact does not exist: {name}") from error
        if not stat.S_ISREG(mode):
            raise MetadataError(f"artifact is not a regular file: {name}")

        source = canonical_path(local_path)
        if source in sources:
            raise MetadataError(f"artifact file listed more than once: {name}")
        try:
            sha256 = artifact_digest(local_path)
        except OSError as error:
            raise MetadataError(f"cannot read artifact {name}: {error}") from error
        artifacts.append({"name": name, "sha256": sha256})
        names.add(name)
        sources.add(source)
    return sorted(artifacts, key=lambda artifact: artifact["name"])


def validate_output(path: Path, label: str) -> None:
    if has_symlink_component(path):
        raise MetadataError(f"{label} output must not use a symlink")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise MetadataError(f"{label} output exists and is not a regular file")


def validate_outputs(support_output: Path, sbom_output: Path,
                     artifact_values: list[str]) -> None:
    validate_output(support_output, "support matrix")
    validate_output(sbom_output, "SBOM")
    support_path = canonical_path(support_output)
    sbom_path = canonical_path(sbom_output)
    if support_path == sbom_path:
        raise MetadataError("support matrix and SBOM outputs overlap")
    for value in artifact_values:
        name, local_name = artifact_spec(value)
        artifact_path = canonical_path(Path(local_name))
        if artifact_path in (support_path, sbom_path):
            raise MetadataError(f"output overlaps release artifact: {name}")


def support_matrix(package_version: str, revision: str, created: str) -> dict:
    return {
        "architectures": [
            {
                "architecture": "x86_64",
                "note": "Current reproducible end-to-end boot proofs target x86 hardware.",
                "proof_commands": ["make abi", "make test", "make qemu", "make qemu-uefi"],
                "status": "live",
                "support_scope": "end-to-end",
            },
            {
                "architecture": "aarch64",
                "note": "The little-endian ABI and X0 handoff are defined; no AArch64 boot is exercised.",
                "proof_commands": [],
                "status": "abi-only",
                "support_scope": "wire-abi",
            },
            {
                "architecture": "riscv64",
                "note": "The little-endian ABI and A0 handoff are defined; no RISC-V boot is exercised.",
                "proof_commands": [],
                "status": "abi-only",
                "support_scope": "wire-abi",
            },
            {
                "architecture": "loongarch",
                "lifecycle": "suspended",
                "note": "Only the architecture enum is reserved.",
                "proof_commands": [],
                "status": "roadmap",
                "support_scope": "none",
            },
        ],
        "format": "bearboot-support-matrix-v1",
        "generated_at": created,
        "package_version": package_version,
        "ports": [
            {
                "evidence": "ports/tinalinux/test/serial.log",
                "note": "Hosted adapter proof is reproducible; a real Linux boot record is checked in.",
                "port": "tinalinux",
                "proof_commands": [
                    "make -C ports/tinalinux scaffold-check",
                    "make -C ports/tinalinux test",
                ],
                "status": "live",
            },
            {
                "evidence": "ports/minix/test/serial.log",
                "note": "The real MINIX boot is recorded but is not reproduced by the root CI.",
                "port": "minix",
                "proof_commands": ["make -C ports/minix scaffold-check"],
                "status": "recorded",
            },
            {
                "evidence": "ports/linux01/test/serial.log",
                "note": "Hosted adapter proof is reproducible; the recorded OS boot is not reproduced by root CI.",
                "port": "linux01",
                "proof_commands": [
                    "make -C ports/linux01 scaffold-check",
                    "make -C ports/linux01 test",
                ],
                "status": "recorded",
            },
            {
                "evidence": "ports/josh/test/serial.log",
                "note": "Hosted adapter proof is reproducible; the recorded OS boot is not reproduced by root CI.",
                "port": "josh",
                "proof_commands": [
                    "make -C ports/josh scaffold-check",
                    "make -C ports/josh test",
                ],
                "status": "recorded",
            },
        ],
        "source_revision": revision,
        "status_source": "STATUS.md",
        "title": f"BearBoot SDK {package_version} (BBP wire {WIRE_VERSION})",
        "wire_version": WIRE_VERSION,
    }


def spdx_sbom(artifacts: list[dict[str, str]], package_version: str,
              revision: str, created: str, epoch: int) -> dict:
    identity = json.dumps({
        "artifacts": artifacts,
        "epoch": epoch,
        "package_version": package_version,
        "revision": revision,
        "wire_version": WIRE_VERSION,
    }, sort_keys=True, separators=(",", ":"))
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, identity)
    packages = []
    describes = []
    for index, artifact in enumerate(artifacts, start=1):
        spdx_id = f"SPDXRef-Artifact-{index}"
        describes.append(spdx_id)
        packages.append({
            "SPDXID": spdx_id,
            "builtDate": created,
            "checksums": [{
                "algorithm": "SHA256",
                "checksumValue": artifact["sha256"],
            }],
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceLocator": revision,
                    "referenceType": "bearboot-source-revision",
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceLocator": WIRE_VERSION,
                    "referenceType": "bearboot-wire-version",
                },
            ],
            "filesAnalyzed": False,
            "name": artifact["name"],
            "packageFileName": artifact["name"],
            "primaryPackagePurpose": "FILE",
            "sourceInfo": f"Built from BearBoot source revision {revision} for BBP wire version {WIRE_VERSION}.",
            "versionInfo": package_version,
        })
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "comment": "This SBOM inventories only the explicitly supplied release artifacts; archive contents and dependencies were not inventoried.",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: BearBoot-generate-release-metadata"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": describes,
        "documentNamespace": f"urn:uuid:{namespace}",
        "name": f"BearBoot release artifacts {package_version}",
        "packages": packages,
        "spdxVersion": "SPDX-2.3",
    }


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
            temporary_name = output.name
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def check_output(path: Path, expected: bytes, label: str) -> bool:
    try:
        actual = path.read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        print(f"generate_release_metadata: {label} is missing: {path}", file=sys.stderr)
        return False
    if actual != expected:
        print(f"generate_release_metadata: {label} is out of date: {path}", file=sys.stderr)
        return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact", action="append", required=True, metavar="[NAME=]LOCAL_FILE",
        help="local regular file and optional release name (repeatable)",
    )
    parser.add_argument(
        "--output-dir", type=Path, metavar="DIR",
        help="write the release-named support matrix and SBOM under DIR",
    )
    parser.add_argument("--support-matrix", type=Path, metavar="FILE")
    parser.add_argument("--sbom", type=Path, metavar="FILE")
    parser.add_argument(
        "--source-revision", metavar="HEX_COMMIT",
        help="source commit ID (defaults to git rev-parse HEAD)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="verify existing outputs without modifying them",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        epoch = source_date_epoch()
        revision = source_revision(args.source_revision)
        package_version = (ROOT / "sdk" / "VERSION").read_text(encoding="ascii").strip()
        if not package_version:
            raise MetadataError("sdk/VERSION is empty")
        if args.output_dir is not None:
            if args.support_matrix is not None or args.sbom is not None:
                raise MetadataError("--output-dir cannot be combined with explicit output files")
            support_output = args.output_dir / "SUPPORT-MATRIX.json"
            sbom_output = args.output_dir / f"bearboot-sdk-{package_version}.spdx.json"
        else:
            if args.support_matrix is None or args.sbom is None:
                raise MetadataError("use --output-dir or both --support-matrix and --sbom")
            support_output = args.support_matrix
            sbom_output = args.sbom
        artifacts = parse_artifacts(args.artifact)
        validate_outputs(support_output, sbom_output, args.artifact)
        created = timestamp(epoch)
        support_data = json_bytes(support_matrix(package_version, revision, created))
        sbom_data = json_bytes(
            spdx_sbom(artifacts, package_version, revision, created, epoch)
        )
        if args.check:
            valid = check_output(support_output, support_data, "support matrix")
            valid = check_output(sbom_output, sbom_data, "SBOM") and valid
            return 0 if valid else 1
        write_atomic(support_output, support_data)
        write_atomic(sbom_output, sbom_data)
    except (MetadataError, OSError, UnicodeError, ValueError) as error:
        print(f"generate_release_metadata: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

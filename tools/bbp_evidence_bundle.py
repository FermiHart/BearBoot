#!/usr/bin/env python3
"""Create and verify strict BearBoot execution-evidence bundles."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile


SCHEMA_NAME = "bbp-execution-evidence-v1"
SCOPES = ("hosted", "emulator", "physical")
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MEDIA_TYPE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*"
)
ROOT_KEYS = {"schema", "provenance", "scope", "identity", "execution", "artifacts"}
EXECUTION_KEYS = {"command", "exit_code", "timed_out", "pass_marker", "verdict"}
ARTIFACT_KEYS = {"path", "role", "media_type", "size", "sha256"}
IDENTITY_KEYS = {
    "hosted": ("host", ("architecture", "operating_system")),
    "emulator": ("emulator", ("architecture", "name", "version", "machine")),
    "physical": (
        "board",
        ("architecture", "manufacturer", "model", "revision", "serial_number"),
    ),
}


class EvidenceError(Exception):
    """Evidence input is invalid or does not prove a passing execution."""


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unexpected_keys(value: dict, expected: set[str], label: str,
                    errors: list[str]) -> None:
    extra = sorted(set(value) - expected)
    if extra:
        errors.append(f"{label} has unexpected members: {', '.join(extra)}")


def required_keys(value: dict, required: set[str], label: str,
                  errors: list[str]) -> None:
    missing = sorted(required - set(value))
    if missing:
        errors.append(f"{label} is missing required members: {', '.join(missing)}")


def nonempty_string(value, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str) or not value:
        errors.append(f"{label} must be a non-empty string")
        return False
    return True


def validate_identity(scope, identity, errors: list[str]) -> None:
    if scope not in IDENTITY_KEYS:
        return
    kind, fields = IDENTITY_KEYS[scope]
    if not isinstance(identity, dict):
        errors.append(f"{scope} identity must be an object containing {kind}")
        return
    if set(identity) != {kind}:
        errors.append(f"{scope} identity must contain only {kind}")
    details = identity.get(kind)
    if not isinstance(details, dict):
        errors.append(f"{scope} {kind} identity must be an object")
        return
    missing = [field for field in fields if field not in details]
    if missing:
        errors.append(
            f"{scope} {kind} identity is missing: {', '.join(missing)}"
        )
    extra = sorted(set(details) - set(fields))
    if extra:
        errors.append(
            f"{scope} {kind} identity has unexpected members: {', '.join(extra)}"
        )
    for field in fields:
        if field in details:
            nonempty_string(details[field], f"{scope} {kind}.{field}", errors)


def validate_execution(execution, errors: list[str]) -> None:
    if not isinstance(execution, dict):
        errors.append("execution must be an object")
        return
    required_keys(execution, EXECUTION_KEYS, "execution", errors)
    unexpected_keys(execution, EXECUTION_KEYS, "execution", errors)
    command = execution.get("command")
    if (not isinstance(command, list) or not command
            or any(not isinstance(part, str) or not part for part in command)):
        errors.append("execution command must be a non-empty array of non-empty strings")
    timed_out = execution.get("timed_out")
    if not isinstance(timed_out, bool):
        errors.append("execution timed_out must be a boolean")
    exit_code = execution.get("exit_code")
    if timed_out is True:
        if exit_code is not None:
            errors.append("a timed-out execution must have a null exit_code")
    elif timed_out is False:
        if (isinstance(exit_code, bool) or not isinstance(exit_code, int)
                or not 0 <= exit_code <= 255):
            errors.append("a completed execution must have an exit_code from 0 to 255")
    marker = execution.get("pass_marker")
    if nonempty_string(marker, "execution pass_marker", errors):
        if len(marker) > 256 or "\r" in marker or "\n" in marker:
            errors.append("execution pass_marker must be one line of at most 256 characters")
        try:
            marker.encode("ascii")
        except UnicodeEncodeError:
            errors.append("execution pass_marker must be ASCII")
    if execution.get("verdict") != "PASS":
        errors.append("execution verdict must be PASS")


def validate_artifacts(artifacts, errors: list[str]) -> list[dict]:
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifacts must be a non-empty array")
        return []
    valid = []
    paths = set()
    raw_count = 0
    for index, artifact in enumerate(artifacts):
        label = f"artifact {index}"
        if not isinstance(artifact, dict):
            errors.append(f"{label} must be an object")
            continue
        required_keys(artifact, ARTIFACT_KEYS, label, errors)
        unexpected_keys(artifact, ARTIFACT_KEYS, label, errors)
        path = artifact.get("path")
        if (not isinstance(path, str) or not path.startswith("artifacts/")
                or ARTIFACT_NAME.fullmatch(path.removeprefix("artifacts/")) is None):
            errors.append(f"{label} path must be a safe flat path below artifacts/")
        elif path in paths:
            errors.append(f"duplicate artifact path: {path}")
        else:
            paths.add(path)
        role = artifact.get("role")
        if role not in ("raw-serial", "runner-log", "artifact"):
            errors.append(f"{label} has an invalid role")
        if role == "raw-serial":
            raw_count += 1
        media_type = artifact.get("media_type")
        if (not isinstance(media_type, str) or len(media_type) > 128
                or MEDIA_TYPE.fullmatch(media_type) is None):
            errors.append(f"{label} has an invalid media_type")
        size = artifact.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            errors.append(f"{label} size must be a non-negative integer")
        elif size > MAX_ARTIFACT_BYTES:
            errors.append(
                f"{label} size exceeds {MAX_ARTIFACT_BYTES} byte limit"
            )
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            errors.append(f"{label} sha256 must be exactly 64 lowercase hexadecimal digits")
        valid.append(artifact)
    if raw_count != 1:
        errors.append("bundle must contain exactly one raw-serial artifact")
    return valid


def validate_manifest(manifest) -> list[str]:
    errors = []
    if not isinstance(manifest, dict):
        return ["manifest root must be an object"]
    required_keys(manifest, ROOT_KEYS, "manifest", errors)
    unexpected_keys(manifest, ROOT_KEYS, "manifest", errors)
    if manifest.get("schema") != SCHEMA_NAME:
        errors.append(f"schema must be {SCHEMA_NAME}")
    if manifest.get("provenance") not in ("execution", "fixture"):
        errors.append("provenance must be execution or fixture")
    scope = manifest.get("scope")
    if scope not in SCOPES:
        errors.append("scope must be hosted, emulator, or physical")
    validate_identity(scope, manifest.get("identity"), errors)
    validate_execution(manifest.get("execution"), errors)
    validate_artifacts(manifest.get("artifacts"), errors)
    return errors


def verdict_errors(execution: dict, serial: bytes) -> list[str]:
    errors = []
    if execution.get("timed_out") is True:
        errors.append("execution timed out")
    if execution.get("exit_code") != 0:
        errors.append(f"execution exit code is {execution.get('exit_code')!r}, not 0")
    marker = execution.get("pass_marker")
    marker_bytes = None
    if isinstance(marker, str):
        try:
            marker_bytes = marker.encode("ascii")
        except UnicodeEncodeError:
            pass
    if marker_bytes is None or marker_bytes not in serial.splitlines():
        errors.append("raw serial does not contain the exact PASS marker line")
    if b"FAIL" in serial:
        errors.append("raw serial contains a forbidden FAIL sequence")
    if errors:
        errors.append("recomputed verdict is FAIL")
    return errors


def load_manifest(bundle: Path) -> dict:
    manifest_path = bundle / "manifest.json"
    try:
        metadata = manifest_path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError("manifest.json must not be a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("manifest.json is not a regular file")
        if metadata.st_size > MAX_MANIFEST_BYTES:
            raise EvidenceError(
                f"manifest.json exceeds {MAX_MANIFEST_BYTES} byte limit"
            )
        with manifest_path.open("rb") as stream:
            data = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(data) > MAX_MANIFEST_BYTES:
            raise EvidenceError(
                f"manifest.json exceeds {MAX_MANIFEST_BYTES} byte limit"
            )
    except FileNotFoundError as error:
        raise EvidenceError("manifest.json is missing") from error
    except IsADirectoryError as error:
        raise EvidenceError("manifest.json is not a regular file") from error
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=json_object)
    except UnicodeDecodeError as error:
        raise EvidenceError("manifest.json must be UTF-8 JSON") from error
    except json.JSONDecodeError as error:
        raise EvidenceError(f"manifest.json is invalid JSON: {error}") from error


def artifact_files(bundle: Path) -> set[str]:
    directory = bundle / "artifacts"
    try:
        mode = directory.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise EvidenceError("artifacts must be a real directory, not a file or symlink")
        entries = list(directory.iterdir())
    except FileNotFoundError:
        return set()
    result = set()
    for entry in entries:
        result.add(f"artifacts/{entry.name}")
    return result


def verify_bundle(bundle: Path, allow_fixture: bool = False,
                  allow_unauthenticated_physical: bool = False) -> list[str]:
    errors = []
    try:
        mode = bundle.lstat().st_mode
    except FileNotFoundError:
        return [f"bundle is missing: {bundle}"]
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        return ["bundle must be a real directory, not a file or symlink"]
    try:
        root_entries = {entry.name for entry in bundle.iterdir()}
    except OSError as error:
        return [f"cannot inventory bundle root: {error}"]
    for name in sorted(root_entries - {"manifest.json", "artifacts"}):
        errors.append(f"unlisted bundle entry: {name}")
    try:
        manifest = load_manifest(bundle)
    except (EvidenceError, OSError) as error:
        return [str(error)]
    errors.extend(validate_manifest(manifest))
    if manifest.get("provenance") == "fixture" and not allow_fixture:
        errors.append("fixture manifests are not execution proof")
    if (manifest.get("provenance") == "execution"
            and manifest.get("scope") == "physical"
            and not allow_unauthenticated_physical):
        errors.append(
            "unauthenticated physical claim is not execution proof; "
            "use --allow-unauthenticated-physical only for integrity checking"
        )

    artifacts = manifest.get("artifacts")
    expected_paths = set()
    serial = None
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            relative = artifact.get("path")
            if (not isinstance(relative, str) or not relative.startswith("artifacts/")
                    or ARTIFACT_NAME.fullmatch(relative.removeprefix("artifacts/")) is None):
                continue
            expected_paths.add(relative)
            path = bundle / relative
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                errors.append(f"artifact is missing: {relative}")
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                errors.append(f"artifact is not a regular file: {relative}")
                continue
            if metadata.st_size > MAX_ARTIFACT_BYTES:
                errors.append(
                    f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit: {relative}"
                )
                continue
            try:
                with path.open("rb") as stream:
                    data = stream.read(MAX_ARTIFACT_BYTES + 1)
            except OSError as error:
                errors.append(f"cannot read artifact {relative}: {error}")
                continue
            if len(data) > MAX_ARTIFACT_BYTES:
                errors.append(
                    f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit: {relative}"
                )
                continue
            if artifact.get("size") != len(data):
                errors.append(f"artifact size mismatch: {relative}")
            if artifact.get("sha256") != sha256_bytes(data):
                errors.append(f"artifact SHA-256 mismatch: {relative}")
            if artifact.get("role") == "raw-serial":
                serial = data
    try:
        actual_paths = artifact_files(bundle)
    except EvidenceError as error:
        errors.append(str(error))
        actual_paths = set()
    for relative in sorted(actual_paths - expected_paths):
        errors.append(f"unlisted artifact: {relative}")

    execution = manifest.get("execution")
    if serial is not None and isinstance(execution, dict):
        recomputed_errors = verdict_errors(execution, serial)
        errors.extend(recomputed_errors)
        if not recomputed_errors and execution.get("verdict") != "PASS":
            errors.append("stored verdict disagrees with recomputed PASS verdict")
    return errors


def source_data(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise EvidenceError(f"{label} artifact is missing: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{label} artifact must be a regular non-symlink file: {path}")
    if metadata.st_size > MAX_ARTIFACT_BYTES:
        raise EvidenceError(
            f"{label} artifact exceeds {MAX_ARTIFACT_BYTES} byte limit: {path}"
        )
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_ARTIFACT_BYTES + 1)
    except OSError as error:
        raise EvidenceError(f"cannot read {label} artifact: {path}: {error}") from error
    if len(data) > MAX_ARTIFACT_BYTES:
        raise EvidenceError(
            f"{label} artifact exceeds {MAX_ARTIFACT_BYTES} byte limit: {path}"
        )
    return data


def artifact_spec(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise EvidenceError("--artifact must use NAME=FILE")
    name, local = value.split("=", 1)
    if ARTIFACT_NAME.fullmatch(name) is None or name == "serial.raw":
        raise EvidenceError(f"unsafe or reserved artifact name: {name!r}")
    if not local:
        raise EvidenceError(f"artifact path is empty: {name}")
    return name, Path(local)


def create_identity(args: argparse.Namespace) -> dict:
    if args.scope == "hosted":
        return {"host": {
            "architecture": args.architecture,
            "operating_system": args.host_os,
        }}
    if args.scope == "emulator":
        return {"emulator": {
            "architecture": args.architecture,
            "name": args.emulator,
            "version": args.emulator_version,
            "machine": args.machine,
        }}
    return {"board": {
        "architecture": args.architecture,
        "manufacturer": args.board_manufacturer,
        "model": args.board_model,
        "revision": args.board_revision,
        "serial_number": args.board_serial,
    }}


def manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii")


def create_bundle(args: argparse.Namespace) -> None:
    if args.output.exists() or args.output.is_symlink():
        raise EvidenceError(f"output already exists: {args.output}")
    if not args.command:
        raise EvidenceError("the recorded command is required after --")
    if args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command or any(not part for part in args.command):
        raise EvidenceError("the recorded command must contain non-empty arguments")
    if args.fixture and args.scope == "physical":
        raise EvidenceError("a physical PASS fixture must not be created")
    if args.scope == "physical" and not args.allow_unauthenticated_physical:
        raise EvidenceError(
            "unauthenticated physical claim is not execution proof; "
            "use --allow-unauthenticated-physical only to record the claim"
        )
    if not args.timed_out and args.exit_code is None:
        raise EvidenceError("--exit-code is required unless --timed-out is used")
    if args.exit_code is not None and not 0 <= args.exit_code <= 255:
        raise EvidenceError("--exit-code must be from 0 to 255")
    if not args.pass_marker or "\r" in args.pass_marker or "\n" in args.pass_marker:
        raise EvidenceError("--pass-marker must be one non-empty line")
    try:
        args.pass_marker.encode("ascii")
    except UnicodeEncodeError as error:
        raise EvidenceError("--pass-marker must be ASCII") from error

    serial = source_data(args.serial, "raw serial")
    execution = {
        "command": args.command,
        "exit_code": None if args.timed_out else args.exit_code,
        "timed_out": args.timed_out,
        "pass_marker": args.pass_marker,
        "verdict": "PASS",
    }
    failures = verdict_errors(execution, serial)
    if failures:
        raise EvidenceError("; ".join(failures))

    payloads = [("serial.raw", "raw-serial", serial)]
    names = {"serial.raw"}
    for value in args.artifact:
        name, path = artifact_spec(value)
        if name in names:
            raise EvidenceError(f"duplicate artifact name: {name}")
        payloads.append((name, "artifact", source_data(path, name)))
        names.add(name)
    artifacts = [
        {
            "path": f"artifacts/{name}",
            "role": role,
            "media_type": "application/octet-stream",
            "size": len(data),
            "sha256": sha256_bytes(data),
        }
        for name, role, data in payloads
    ]
    manifest = {
        "schema": SCHEMA_NAME,
        "provenance": "fixture" if args.fixture else "execution",
        "scope": args.scope,
        "identity": create_identity(args),
        "execution": execution,
        "artifacts": artifacts,
    }
    validation = validate_manifest(manifest)
    if validation:
        raise EvidenceError("; ".join(validation))

    parent = args.output.parent
    if not parent.is_dir():
        raise EvidenceError(f"output parent is not a directory: {parent}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{args.output.name}.", dir=parent))
    try:
        (temporary / "artifacts").mkdir()
        for name, _role, data in payloads:
            (temporary / "artifacts" / name).write_bytes(data)
        (temporary / "manifest.json").write_bytes(manifest_bytes(manifest))
        os.replace(temporary, args.output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)

    create = commands.add_parser("create", help="create a bundle from captured artifacts")
    create.add_argument("--output", type=Path, required=True, metavar="DIR")
    create.add_argument("--scope", choices=SCOPES, required=True)
    create.add_argument("--architecture", required=True)
    create.add_argument("--host-os")
    create.add_argument("--emulator")
    create.add_argument("--emulator-version")
    create.add_argument("--machine")
    create.add_argument("--board-manufacturer")
    create.add_argument("--board-model")
    create.add_argument("--board-revision")
    create.add_argument("--board-serial")
    create.add_argument("--serial", type=Path, required=True, metavar="RAW_FILE")
    create.add_argument("--exit-code", type=int)
    create.add_argument("--timed-out", action="store_true")
    create.add_argument("--pass-marker", required=True)
    create.add_argument("--artifact", action="append", default=[], metavar="NAME=FILE")
    create.add_argument(
        "--allow-unauthenticated-physical", action="store_true",
        help="record a physical claim without treating it as authenticated proof",
    )
    create.add_argument("--fixture", action="store_true", help=argparse.SUPPRESS)
    create.add_argument("command", nargs=argparse.REMAINDER)

    verify = commands.add_parser("verify", help="verify hashes and recompute PASS")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--allow-fixture", action="store_true",
                        help="validate a fixture without accepting it as execution proof")
    verify.add_argument(
        "--allow-unauthenticated-physical", action="store_true",
        help="integrity-check a physical claim without accepting its authenticity",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.operation == "create":
            create_bundle(args)
            if args.scope == "physical":
                print("bbp_evidence_bundle: PASS: created unauthenticated "
                      f"physical claim {args.output}")
            else:
                print(f"bbp_evidence_bundle: PASS: created {args.output}")
            return 0
        errors = verify_bundle(
            args.bundle,
            args.allow_fixture,
            args.allow_unauthenticated_physical,
        )
        if errors:
            raise EvidenceError("; ".join(errors))
        manifest = load_manifest(args.bundle)
        if (manifest.get("provenance") == "execution"
                and manifest.get("scope") == "physical"):
            print("bbp_evidence_bundle: PASS: integrity-checked unauthenticated "
                  f"physical claim {args.bundle}")
        else:
            print(f"bbp_evidence_bundle: PASS: verified {args.bundle}")
        return 0
    except (EvidenceError, OSError, ValueError) as error:
        print(f"bbp_evidence_bundle: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

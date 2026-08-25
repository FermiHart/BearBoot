#!/usr/bin/env python3
"""SDK packaging and package-consumption regression tests."""

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.4.0"
ARCHIVES = (
    f"bearboot-c-sdk-{VERSION}.tar.gz",
    f"bearboot-host-tools-{VERSION}.tar.gz",
)
VECTOR = "tests/vectors/bbp-v2-profile0-auth-v1.json"
C_PACKAGE_FILES = {
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "SPEC.md",
    "VERSION",
    "bootloader/bbp_build.c",
    "bootloader/bbp_build.h",
    "bootloader/bbp_import.c",
    "bootloader/bbp_import.h",
    "bootloader/bbp_import_limine.c",
    "bootloader/bbp_import_multiboot2.c",
    "bootloader/bbp_import_uefi.c",
    "docs/adr/0019-experimental-v2-sdk-surfaces.md",
    "docs/bbp-conformance-report-v1.schema.json",
    "docs/rfc/0001-bbp-v2-capsule.md",
    "docs/rfc/0002-bbp-v2-profile-0.md",
    "docs/rfc/0003-bbp-v2-auth-envelope.md",
    "examples/sdk_roundtrip.c",
    "examples/v2_profile_roundtrip.c",
    "include/bbp/bbp.h",
    "include/bbp/bbp_crc64.h",
    "include/bbp/bbp_osif.h",
    "include/bbp/bbp_sdk.h",
    "include/bbp/bbp_v2.h",
    "include/bbp/bbp_v2_auth.h",
    "include/bbp/bbp_v2_profile.h",
    "kernel/bbp_kernel.c",
    "kernel/bbp_kernel.h",
    VECTOR,
    "v2/bbp_v2.c",
    "v2/bbp_v2_auth.c",
    "v2/bbp_v2_profile.c",
}
HOST_PACKAGE_FILES = {
    "LICENSE",
    "README.md",
    "VERSION",
    "bin/bbpctl.py",
    "docs/adr/0019-experimental-v2-sdk-surfaces.md",
    "docs/bbpc-v1.md",
    "docs/rfc/0001-bbp-v2-capsule.md",
    "docs/rfc/0002-bbp-v2-profile-0.md",
    "docs/rfc/0003-bbp-v2-auth-envelope.md",
    "examples/host_v2_roundtrip.py",
    "lib/bbp_v2_envelope.py",
    VECTOR,
}
CARGO_PACKAGE_FILES = {
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE",
    "README.md",
    "examples/auth_envelope.rs",
    "examples/v2_profile.rs",
    "src/auth.rs",
    "src/crc.rs",
    "src/lib.rs",
    "src/refs.rs",
    "src/v2.rs",
    "src/wire.rs",
    "tests/conformance.rs",
    "tests/v2_conformance.rs",
    "tests/vectors/bbp-v2-profile0-auth-v1.json",
}


class SdkPackageTests(unittest.TestCase):
    def package(self, output: Path) -> None:
        env = dict(os.environ, SOURCE_DATE_EPOCH="0")
        subprocess.run(
            ["python3", "tools/package_sdk.py", "--output-dir", str(output)],
            cwd=ROOT, env=env, check=True, capture_output=True,
        )

    def test_packages_are_reproducible_safe_and_onboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first, second = base / "first", base / "second"
            first.mkdir(); second.mkdir()
            self.package(first); self.package(second)

            for name in ARCHIVES:
                one, two = first / name, second / name
                self.assertEqual(one.read_bytes(), two.read_bytes(), name)
                with tarfile.open(one, "r:gz") as archive:
                    members = archive.getmembers()
                    self.assertTrue(members)
                    for member in members:
                        self.assertFalse(member.name.startswith("/"))
                        self.assertNotIn("..", Path(member.name).parts)
                        self.assertFalse(member.issym() or member.islnk())
                        self.assertEqual(member.uid, 0)
                        self.assertEqual(member.gid, 0)
                        self.assertEqual(member.mtime, 0)

                    manifest_member = next(
                        member for member in members
                        if member.name.endswith("/MANIFEST.json")
                    )
                    manifest = json.load(io.TextIOWrapper(
                        archive.extractfile(manifest_member), encoding="utf-8"
                    ))
                    self.assertEqual(manifest["sdk_version"], VERSION)
                    self.assertEqual(manifest["wire_version"], "1.1")
                    expected = (C_PACKAGE_FILES if name == ARCHIVES[0]
                                else HOST_PACKAGE_FILES)
                    self.assertEqual(
                        {entry["path"] for entry in manifest["files"]}, expected
                    )
                    archive_root = manifest_member.name.rsplit("/", 1)[0]
                    self.assertEqual(
                        {member.name.removeprefix(archive_root + "/")
                         for member in members},
                        expected | {"MANIFEST.json"},
                    )
                    for entry in manifest["files"]:
                        member = archive.getmember(
                            manifest_member.name.rsplit("/", 1)[0] + "/" + entry["path"]
                        )
                        data = archive.extractfile(member).read()
                        self.assertEqual(len(data), entry["size"])
                        self.assertEqual(hashlib.sha256(data).hexdigest(),
                                         entry["sha256"])

            extracted = base / "extracted"
            with tarfile.open(first / ARCHIVES[0], "r:gz") as archive:
                archive.extractall(extracted, filter="data")
            sdk_root = extracted / f"bearboot-c-sdk-{VERSION}"
            result = subprocess.run(
                ["make", "-s", "onboarding"], cwd=sdk_root,
                check=True, capture_output=True, text=True,
            )
            self.assertIn("BBP SDK onboarding: PASS", result.stdout)

            report_one = subprocess.run(
                ["make", "-s", "conformance"], cwd=sdk_root,
                check=True, capture_output=True, text=True,
            ).stdout
            report_two = subprocess.run(
                ["make", "-s", "conformance"], cwd=sdk_root,
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertEqual(report_one, report_two)
            report = json.loads(report_one)
            self.assertTrue(report["conformant"])
            self.assertEqual(report["profile"], "bbp-c-sdk-host-roundtrip-v1")
            self.assertEqual([check["status"] for check in report["checks"]],
                             ["pass"] * len(report["checks"]))
            schema = json.loads((
                ROOT / "docs/schemas/bbp-conformance-report-v1.schema.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"],
                             "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(len(schema["allOf"]), 2)

            v2_example = subprocess.run(
                ["make", "-s", "v2-profile-roundtrip"], cwd=sdk_root,
                check=True, capture_output=True, text=True,
            )
            self.assertIn("BBP v2 Profile 0 roundtrip: PASS", v2_example.stdout)

            host_extracted = base / "host"
            with tarfile.open(first / ARCHIVES[1], "r:gz") as archive:
                archive.extractall(host_extracted, filter="data")
            host_root = host_extracted / f"bearboot-host-tools-{VERSION}"
            subprocess.run(
                ["python3", "bin/bbpctl.py", "--help"], cwd=host_root,
                check=True, capture_output=True,
            )
            host_example = subprocess.run(
                ["python3", "examples/host_v2_roundtrip.py"], cwd=host_root,
                check=True, capture_output=True, text=True,
            )
            self.assertIn("BBP host v2 envelope roundtrip: PASS",
                          host_example.stdout)

            canonical = (ROOT / VECTOR).read_bytes()
            self.assertEqual((sdk_root / VECTOR).read_bytes(), canonical)
            self.assertEqual((host_root / VECTOR).read_bytes(), canonical)
            self.assertEqual((
                ROOT / "sdk/rust/bbp-wire/tests/vectors/"
                "bbp-v2-profile0-auth-v1.json"
            ).read_bytes(), canonical)

    def test_release_mode_rejects_dirty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory(
            prefix=".sdk-package-dirty-", dir=ROOT
        ) as dirty:
            marker = Path(dirty) / "marker"
            marker.write_text("dirty\n", encoding="ascii")
            marker_status = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=all", "--",
                 str(marker.relative_to(ROOT))],
                cwd=ROOT, check=True, capture_output=True, text=True,
            ).stdout
            self.assertIn(str(marker.relative_to(ROOT)), marker_status)
            result = subprocess.run(
                ["python3", "tools/package_sdk.py", "--release",
                 "--output-dir", temporary],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("clean Git tree", result.stderr)

    def test_c_and_rust_sdk_versions_match(self) -> None:
        c_header = (ROOT / "sdk/c/include/bbp/bbp_sdk.h").read_text(
            encoding="ascii"
        )
        cargo = (ROOT / "sdk/rust/bbp-wire/Cargo.toml").read_text(
            encoding="ascii"
        )
        self.assertIn(f'#define BBP_SDK_VERSION "{VERSION}"', c_header)
        self.assertIn(f'version = "{VERSION}"', cargo)

    def test_rust_crate_has_an_exact_non_publishable_package(self) -> None:
        crate = ROOT / "sdk/rust/bbp-wire"
        cargo = (crate / "Cargo.toml").read_text(encoding="ascii")
        self.assertIn("publish = false", cargo)
        self.assertEqual((crate / "LICENSE").read_bytes(),
                         (ROOT / "LICENSE").read_bytes())
        result = subprocess.run(
            ["cargo", "package", "--list", "--allow-dirty"], cwd=crate,
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(set(result.stdout.splitlines()), CARGO_PACKAGE_FILES)

    def test_packager_rejects_unsafe_inputs_and_models_release_policy(self) -> None:
        tool = runpy.run_path(str(ROOT / "tools/package_sdk.py"))
        validate_version = tool["validate_version"]
        release_error = tool["release_error"]
        package_error = tool["PackageError"]

        self.assertTrue(validate_version("1.2.0-dev"))
        for invalid in (
            "1.2", "01.2.3", "1.2.3-01", "1.2.3/../../escape",
            "1.2.3+local", "1.2.3-" + "a" * 33,
        ):
            self.assertFalse(validate_version(invalid), invalid)
        self.assertIsNone(release_error(False, "1.2.0"))
        self.assertIn("non-development", release_error(False, "1.2.0-dev"))
        self.assertIn("clean Git tree", release_error(True, "1.2.0"))

        with self.assertRaises(package_error):
            tool["snapshot"]({"../escape": "LICENSE"})
        with tempfile.TemporaryDirectory(prefix=".sdk-symlink-", dir=ROOT) as temporary:
            link = Path(temporary) / "external"
            link.symlink_to("/etc/hosts")
            relative = link.relative_to(ROOT).as_posix()
            with self.assertRaises(package_error):
                tool["source_bytes"](relative)

        with tempfile.TemporaryDirectory() as output:
            env = dict(os.environ, SOURCE_DATE_EPOCH=str(1 << 32))
            result = subprocess.run(
                ["python3", "tools/package_sdk.py", "--output-dir", output],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("0 to 4294967295", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

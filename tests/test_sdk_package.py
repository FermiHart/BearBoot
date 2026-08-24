#!/usr/bin/env python3
"""Wave 8 SDK packaging and onboarding regression tests."""

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
VERSION = "1.3.0"
ARCHIVES = (
    f"bearboot-c-sdk-{VERSION}.tar.gz",
    f"bearboot-host-tools-{VERSION}.tar.gz",
)


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

            host_extracted = base / "host"
            with tarfile.open(first / ARCHIVES[1], "r:gz") as archive:
                archive.extractall(host_extracted, filter="data")
            host_root = host_extracted / f"bearboot-host-tools-{VERSION}"
            subprocess.run(
                ["python3", "bin/bbpctl.py", "--help"], cwd=host_root,
                check=True, capture_output=True,
            )

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

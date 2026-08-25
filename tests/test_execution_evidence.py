#!/usr/bin/env python3
"""Wave 22 execution-evidence contract regression tests."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "bbp_evidence_bundle.py"
SCHEMA = ROOT / "docs" / "schemas" / "bbp-execution-evidence-v1.schema.json"
FIXTURES = ROOT / "tests" / "fixtures" / "evidence"


class ExecutionEvidenceTests(unittest.TestCase):
    def invoke(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["python3", str(TOOL), *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def fixture_copy(self, temporary: str, name: str) -> Path:
        destination = Path(temporary) / name
        shutil.copytree(FIXTURES / name, destination)
        return destination

    def rewrite_manifest(self, bundle: Path, update) -> dict:
        path = bundle / "manifest.json"
        manifest = json.loads(path.read_text(encoding="ascii"))
        update(manifest)
        path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        return manifest

    def test_schema_separates_hosted_emulator_and_physical_identity(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="ascii"))
        self.assertEqual(schema["$schema"],
                         "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["scope"]["enum"],
                         ["hosted", "emulator", "physical"])
        conditionals = schema["allOf"]
        self.assertEqual(
            {item["if"]["properties"]["scope"]["const"] for item in conditionals},
            {"hosted", "emulator", "physical"},
        )
        physical = next(
            item for item in conditionals
            if item["if"]["properties"]["scope"]["const"] == "physical"
        )
        board = physical["then"]["properties"]["identity"]["properties"]["board"]
        self.assertEqual(
            set(board["required"]),
            {"architecture", "manufacturer", "model", "revision", "serial_number"},
        )

    def test_hosted_and_emulator_fixtures_verify_only_as_fixtures(self) -> None:
        for name in ("hosted-pass", "emulator-pass"):
            with self.subTest(name=name):
                result = self.invoke("verify", str(FIXTURES / name), "--allow-fixture")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("PASS", result.stdout)

    def test_scope_identity_cannot_be_relabelled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.fixture_copy(temporary, "hosted-pass")
            self.rewrite_manifest(bundle, lambda manifest: manifest.update(scope="emulator"))
            result = self.invoke("verify", str(bundle), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("emulator identity", result.stderr)

    def test_unauthenticated_physical_claim_is_not_accepted_as_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.fixture_copy(temporary, "hosted-pass")

            def relabel_as_physical(manifest):
                manifest["provenance"] = "execution"
                manifest["scope"] = "physical"
                manifest["identity"] = {"board": {
                    "architecture": "x86_64",
                    "manufacturer": "Invented",
                    "model": "Not-A-Board",
                    "revision": "none",
                    "serial_number": "fabricated",
                }}

            self.rewrite_manifest(bundle, relabel_as_physical)
            result = self.invoke("verify", str(bundle))
            self.assertEqual(result.returncode, 1)
            self.assertIn("unauthenticated physical claim", result.stderr)

            result = self.invoke(
                "verify", str(bundle), "--allow-unauthenticated-physical"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("integrity-checked unauthenticated physical claim",
                          result.stdout)

    def test_physical_scope_requires_complete_board_identity(self) -> None:
        result = self.invoke(
            "verify", str(FIXTURES / "physical-invalid"), "--allow-fixture"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("board identity", result.stderr)
        self.assertIn("serial_number", result.stderr)

    def test_physical_scope_requires_raw_serial_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.fixture_copy(temporary, "physical-invalid")

            def remove_raw_serial(manifest):
                manifest["identity"]["board"]["serial_number"] = "BBP-CI-0001"
                manifest["artifacts"][0]["role"] = "runner-log"

            self.rewrite_manifest(bundle, remove_raw_serial)
            result = self.invoke("verify", str(bundle), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("exactly one raw-serial artifact", result.stderr)

    def test_exact_artifact_hash_and_size_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.fixture_copy(temporary, "hosted-pass")
            serial = bundle / "artifacts" / "serial.raw"
            serial.write_bytes(serial.read_bytes() + b"tamper\n")
            result = self.invoke("verify", str(bundle), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("size mismatch", result.stderr)
            self.assertIn("SHA-256 mismatch", result.stderr)

    def test_pass_line_is_required_and_fail_token_is_forbidden(self) -> None:
        cases = (
            (b"boot completed without verdict\n", "exact PASS marker"),
            (b"BBP-HOSTED: PASS\ncleanup: FAILED\n", "FAIL sequence"),
        )
        for serial_data, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                bundle = self.fixture_copy(temporary, "hosted-pass")
                serial = bundle / "artifacts" / "serial.raw"
                serial.write_bytes(serial_data)

                def update_hash(manifest):
                    artifact = manifest["artifacts"][0]
                    artifact["size"] = len(serial_data)
                    artifact["sha256"] = hashlib.sha256(serial_data).hexdigest()

                self.rewrite_manifest(bundle, update_hash)
                result = self.invoke("verify", str(bundle), "--allow-fixture")
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)

    def test_timeout_can_never_be_relabelled_as_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.fixture_copy(temporary, "hosted-pass")
            self.rewrite_manifest(
                bundle,
                lambda manifest: manifest["execution"].update(timed_out=True,
                                                                exit_code=None),
            )
            result = self.invoke("verify", str(bundle), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("timed out", result.stderr)
            self.assertIn("recomputed verdict is FAIL", result.stderr)

    def test_missing_and_unlisted_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = self.fixture_copy(temporary, "hosted-pass")
            (missing / "artifacts" / "serial.raw").unlink()
            result = self.invoke("verify", str(missing), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("artifact is missing", result.stderr)

            unlisted = self.fixture_copy(temporary, "emulator-pass")
            (unlisted / "artifacts" / "not-in-manifest.bin").write_bytes(b"extra")
            result = self.invoke("verify", str(unlisted), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("unlisted artifact", result.stderr)

            root_extra = Path(temporary) / "root-extra"
            shutil.copytree(FIXTURES / "hosted-pass", root_extra)
            (root_extra / "unlisted.txt").write_text("extra", encoding="ascii")
            result = self.invoke("verify", str(root_extra), "--allow-fixture")
            self.assertEqual(result.returncode, 1)
            self.assertIn("unlisted bundle entry", result.stderr)

    def test_oversized_manifest_and_artifact_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_bundle = self.fixture_copy(temporary, "hosted-pass")
            manifest = manifest_bundle / "manifest.json"
            with manifest.open("ab") as stream:
                stream.write(b" " * (64 * 1024))
            result = self.invoke(
                "verify", str(manifest_bundle), "--allow-fixture"
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("manifest.json exceeds", result.stderr)

            artifact_bundle = self.fixture_copy(temporary, "emulator-pass")
            serial = artifact_bundle / "artifacts" / "serial.raw"
            with serial.open("r+b") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)
            result = self.invoke(
                "verify", str(artifact_bundle), "--allow-fixture"
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("artifact exceeds", result.stderr)

    def test_fixture_manifest_is_forbidden_as_proof(self) -> None:
        result = self.invoke("verify", str(FIXTURES / "hosted-pass"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("fixture manifests are not execution proof", result.stderr)

    def test_create_preserves_raw_serial_and_computes_verdict(self) -> None:
        raw = b"\xffuart preamble\r\nBBP-HOSTED: PASS\r\n"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            serial = base / "capture.bin"
            serial.write_bytes(raw)
            bundle = base / "bundle"
            result = self.invoke(
                "create", "--output", str(bundle),
                "--scope", "hosted", "--architecture", "x86_64",
                "--host-os", "linux", "--serial", str(serial),
                "--exit-code", "0", "--pass-marker", "BBP-HOSTED: PASS",
                "--", "make", "test-hosted",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((bundle / "artifacts" / "serial.raw").read_bytes(), raw)
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertEqual(manifest["execution"]["verdict"], "PASS")
            self.assertEqual(manifest["execution"]["command"],
                             ["make", "test-hosted"])
            self.assertEqual(self.invoke("verify", str(bundle)).returncode, 0)

    def test_create_requires_explicit_unauthenticated_physical_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            serial = base / "serial.raw"
            serial.write_bytes(b"BBP-PHYSICAL: PASS\n")
            arguments = (
                "create", "--output", str(base / "bundle"),
                "--scope", "physical", "--architecture", "x86_64",
                "--board-manufacturer", "ExampleCorp",
                "--board-model", "Atlas-X1", "--board-revision", "rev-c",
                "--board-serial", "ACX1-000017", "--serial", str(serial),
                "--exit-code", "0", "--pass-marker", "BBP-PHYSICAL: PASS",
                "--", "lab-runner", "boot", "--board", "ACX1-000017",
            )
            result = self.invoke(*arguments)
            self.assertEqual(result.returncode, 1)
            self.assertIn("unauthenticated physical claim", result.stderr)

            arguments = (arguments[0], "--allow-unauthenticated-physical",
                         *arguments[1:])
            result = self.invoke(*arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("created unauthenticated physical claim", result.stdout)

    def test_create_rejects_fail_timeout_and_missing_artifact(self) -> None:
        cases = (
            (b"BBP-HOSTED: FAILED\n", (), "FAIL sequence"),
            (b"BBP-HOSTED: PASS\n", ("--timed-out",), "timed out"),
        )
        for serial_data, extra, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                serial = base / "serial.raw"
                serial.write_bytes(serial_data)
                result = self.invoke(
                    "create", "--output", str(base / "bundle"),
                    "--scope", "hosted", "--architecture", "x86_64",
                    "--host-os", "linux", "--serial", str(serial),
                    "--exit-code", "0", "--pass-marker", "BBP-HOSTED: PASS",
                    *extra, "--", "runner",
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            serial = base / "serial.raw"
            serial.write_bytes(b"BBP-HOSTED: PASS\n")
            result = self.invoke(
                "create", "--output", str(base / "bundle"),
                "--scope", "hosted", "--architecture", "x86_64",
                "--host-os", "linux", "--serial", str(serial),
                "--exit-code", "0", "--pass-marker", "BBP-HOSTED: PASS",
                "--artifact", f"missing.bin={base / 'missing.bin'}",
                "--", "runner",
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("artifact is missing", result.stderr)

    def test_no_physical_pass_fixture_is_shipped(self) -> None:
        for manifest_path in FIXTURES.glob("*/manifest.json"):
            manifest = json.loads(manifest_path.read_text(encoding="ascii"))
            self.assertFalse(
                manifest["scope"] == "physical"
                and manifest["execution"]["verdict"] == "PASS",
                manifest_path,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

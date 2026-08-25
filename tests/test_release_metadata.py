#!/usr/bin/env python3
"""Deterministic release metadata and evidence-honesty regression tests."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "generate_release_metadata.py"
REVISION = "0123456789abcdef0123456789abcdef01234567"


class ReleaseMetadataTests(unittest.TestCase):
    def string_values(self, value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from self.string_values(item)
        elif isinstance(value, list):
            for item in value:
                yield from self.string_values(item)

    def invoke(self, directory: Path, artifacts: list[tuple[str, Path]],
               *extra: str, epoch: str = "123456789") -> subprocess.CompletedProcess:
        command = [
            "python3", str(TOOL),
            "--source-revision", REVISION,
            "--support-matrix", str(directory / "support.json"),
            "--sbom", str(directory / "sbom.spdx.json"),
        ]
        for name, path in artifacts:
            command.extend(("--artifact", f"{name}={path}"))
        command.extend(extra)
        env = dict(os.environ, SOURCE_DATE_EPOCH=epoch)
        return subprocess.run(
            command, cwd=ROOT, env=env, capture_output=True, text=True
        )

    def make_artifacts(self, directory: Path) -> list[tuple[str, Path]]:
        first = directory / "local-one.bin"
        second = directory / "local-two.tar.gz"
        first.write_bytes(b"bearboot-kernel\x00\x01")
        second.write_bytes(b"deterministic-sdk-archive\n")
        return [("bearboot-kernel.elf", first), ("bearboot-sdk.tar.gz", second)]

    def test_outputs_are_byte_deterministic_and_contain_no_host_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = base / "first"
            second = base / "second"
            first.mkdir()
            second.mkdir()
            first_artifacts = self.make_artifacts(first)
            second_artifacts = self.make_artifacts(second)

            one = self.invoke(first, list(reversed(first_artifacts)))
            two = self.invoke(second, second_artifacts)
            self.assertEqual(one.returncode, 0, one.stderr)
            self.assertEqual(two.returncode, 0, two.stderr)
            self.assertEqual(
                (first / "support.json").read_bytes(),
                (second / "support.json").read_bytes(),
            )
            self.assertEqual(
                (first / "sbom.spdx.json").read_bytes(),
                (second / "sbom.spdx.json").read_bytes(),
            )
            for output in (first / "support.json", first / "sbom.spdx.json"):
                text = output.read_text(encoding="ascii")
                self.assertNotIn(str(base), text)
                self.assertNotIn(str(ROOT), text)
                document = json.loads(text)
                self.assertFalse(any(
                    value.startswith("/") for value in self.string_values(document)
                ))

    def test_support_matrix_and_spdx_critical_fields_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifacts = self.make_artifacts(directory)
            result = self.invoke(directory, artifacts)
            self.assertEqual(result.returncode, 0, result.stderr)

            support = json.loads((directory / "support.json").read_text())
            self.assertEqual(support["format"], "bearboot-support-matrix-v1")
            self.assertEqual(support["package_version"], "1.4.0")
            self.assertEqual(support["wire_version"], "1.1")
            self.assertEqual(support["source_revision"], REVISION)
            self.assertEqual(support["generated_at"], "1973-11-29T21:33:09Z")
            architectures = {
                item["architecture"]: item for item in support["architectures"]
            }
            self.assertEqual(architectures["x86_64"]["status"], "live")
            self.assertTrue(architectures["x86_64"]["proof_commands"])
            self.assertEqual(architectures["aarch64"]["status"], "live")
            self.assertEqual(
                architectures["aarch64"]["proof_commands"],
                ["make qemu-aarch64"],
            )
            self.assertEqual(architectures["riscv64"]["status"], "live")
            self.assertEqual(
                architectures["riscv64"]["proof_commands"],
                ["make qemu-riscv64"],
            )
            self.assertEqual(architectures["loongarch"]["status"], "roadmap")
            self.assertEqual(architectures["loongarch"]["lifecycle"], "suspended")
            ports = {item["port"]: item for item in support["ports"]}
            self.assertEqual(set(ports), {"tinalinux", "minix", "linux01", "josh"})
            self.assertEqual(ports["tinalinux"]["status"], "host-tested")
            self.assertEqual(ports["minix"]["status"], "host-tested")
            self.assertEqual(ports["linux01"]["status"], "host-tested")
            self.assertEqual(ports["josh"]["status"], "host-tested")
            self.assertTrue(all(port["proof_commands"] for port in ports.values()))
            self.assertIn("Historical port records", support["source_revision_scope"])

            proofs = {
                port: {proof.get("path", proof.get("proof_command")): proof
                       for proof in item["proofs"]}
                for port, item in ports.items()
            }
            for item in ports.values():
                for proof in item["proofs"]:
                    self.assertIn("core_revision", proof)
                    self.assertIn("proof_scope", proof)
                    self.assertIn("substrate", proof)
                    self.assertIn("replay", proof)
                    if "path" in proof:
                        self.assertTrue((ROOT / proof["path"]).is_file(), proof["path"])

            minix = proofs["minix"]
            self.assertEqual(
                minix["ports/minix/test/serial.log"]["proof_scope"],
                "adapter-machine-harness",
            )
            self.assertEqual(
                minix["ports/minix/test/serial-all6-consumers.log"]["proof_scope"],
                "full-os-boot",
            )
            linux_os = next(
                proof for proof in ports["linux01"]["proofs"]
                if proof["proof_scope"] == "reported-full-os-boot"
            )
            self.assertNotIn("path", linux_os)
            self.assertEqual(linux_os["replay"], "unarchived-not-replayable")
            self.assertEqual(
                proofs["josh"]["ports/josh/test/run.log"]["proof_scope"],
                "hosted-adapter",
            )
            self.assertEqual(
                proofs["josh"]["ports/josh/test/serial.log"]["proof_scope"],
                "full-os-boot",
            )
            self.assertEqual(
                proofs["tinalinux"]["ports/tinalinux/test/serial.log"]["substrate"],
                "qemu-kvm-emulator",
            )
            self.assertNotIn(
                "physical",
                proofs["tinalinux"]["ports/tinalinux/test/serial.log"]["substrate"],
            )

            sbom = json.loads((directory / "sbom.spdx.json").read_text())
            self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
            self.assertEqual(sbom["SPDXID"], "SPDXRef-DOCUMENT")
            self.assertEqual(sbom["dataLicense"], "CC0-1.0")
            self.assertTrue(sbom["documentNamespace"].startswith("urn:uuid:"))
            self.assertEqual(sbom["creationInfo"]["created"], "1973-11-29T21:33:09Z")
            self.assertEqual(sbom["documentDescribes"], [
                "SPDXRef-Artifact-1", "SPDXRef-Artifact-2"
            ])
            packages = {package["name"]: package for package in sbom["packages"]}
            self.assertEqual(set(packages), {name for name, _ in artifacts})
            for name, path in artifacts:
                package = packages[name]
                self.assertEqual(package["versionInfo"], "1.4.0")
                self.assertEqual(package["packageFileName"], name)
                self.assertFalse(package["filesAnalyzed"])
                self.assertEqual(package["builtDate"], "1973-11-29T21:33:09Z")
                self.assertEqual(package["checksums"], [{
                    "algorithm": "SHA256",
                    "checksumValue": hashlib.sha256(path.read_bytes()).hexdigest(),
                }])
                references = {
                    reference["referenceType"]: reference["referenceLocator"]
                    for reference in package["externalRefs"]
                }
                self.assertEqual(references["bearboot-source-revision"], REVISION)
                self.assertEqual(references["bearboot-wire-version"], "1.1")

    def test_checked_evidence_is_classified_honestly_in_docs(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        minix = (ROOT / "ports/minix/CONFORMANCE.md").read_text(encoding="utf-8")
        linux01 = (ROOT / "ports/linux01/CONFORMANCE.md").read_text(encoding="utf-8")
        josh = (ROOT / "ports/josh/CONFORMANCE.md").read_text(encoding="utf-8")
        tina = (ROOT / "ports/tinalinux/CONFORMANCE.md").read_text(encoding="utf-8")

        self.assertIn("`serial.log` is a 7-tag adapter machine harness", readme)
        self.assertIn("`test/serial.log` | adapter machine harness", minix)
        self.assertIn("`test/serial-all6-consumers.log` | full MINIX OS boot", minix)
        self.assertIn("In-kernel QEMU boot is reported but unarchived", linux01)
        self.assertIn("no raw in-kernel serial artifact is checked in", status)
        self.assertIn("`test/run.log` | archived hosted adapter output (6 tags)", josh)
        self.assertIn("`test/serial.log` | full Josh OS boot (5 tags)", josh)
        self.assertIn("QEMU emulator with KVM acceleration", tina)
        self.assertIn("No physical TinaLinux boot is claimed", tina)

    def test_check_detects_drift_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifacts = self.make_artifacts(directory)
            generated = self.invoke(directory, artifacts)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            checked = self.invoke(directory, artifacts, "--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

            sbom_path = directory / "sbom.spdx.json"
            sbom_path.write_bytes(sbom_path.read_bytes() + b" ")
            before = sbom_path.read_bytes()
            stale = self.invoke(directory, artifacts, "--check")
            self.assertEqual(stale.returncode, 1)
            self.assertIn("SBOM is out of date", stale.stderr)
            self.assertEqual(sbom_path.read_bytes(), before)

    def test_output_directory_interface_accepts_raw_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifact = directory / "bearboot-release.tar.gz"
            artifact.write_bytes(b"release bytes")
            output = directory / "release"
            result = subprocess.run(
                ["python3", str(TOOL), "--source-revision", REVISION,
                 "--output-dir", str(output), "--artifact", str(artifact)],
                cwd=ROOT,
                env=dict(os.environ, SOURCE_DATE_EPOCH="123456789"),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            support = json.loads((output / "SUPPORT-MATRIX.json").read_text())
            self.assertEqual(
                support["title"], "BearBoot SDK 1.4.0 (BBP wire 1.1)"
            )
            sbom = json.loads(
                (output / "bearboot-sdk-1.4.0.spdx.json").read_text()
            )
            self.assertEqual(sbom["packages"][0]["name"], artifact.name)

    def test_rejects_missing_non_regular_and_symlink_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            missing = directory / "missing.bin"
            result = self.invoke(directory, [("missing.bin", missing)])
            self.assertEqual(result.returncode, 1)
            self.assertIn("does not exist", result.stderr)

            result = self.invoke(directory, [("directory.bin", directory)])
            self.assertEqual(result.returncode, 1)
            self.assertIn("not a regular file", result.stderr)

            target = directory / "target.bin"
            link = directory / "link.bin"
            target.write_bytes(b"target")
            link.symlink_to(target)
            result = self.invoke(directory, [("link.bin", link)])
            self.assertEqual(result.returncode, 1)
            self.assertIn("must not be a symlink", result.stderr)

    def test_rejects_unsafe_names_overlap_revision_and_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifacts = self.make_artifacts(directory)
            artifact_path = artifacts[0][1]
            common = ["python3", str(TOOL), "--source-revision", REVISION]
            env = dict(os.environ, SOURCE_DATE_EPOCH="0")

            for value in (f"../escape={artifact_path}", "artifact-without-path="):
                result = subprocess.run(
                    common + ["--artifact", value, "--support-matrix",
                              str(directory / "support.json"), "--sbom",
                              str(directory / "sbom.json")],
                    cwd=ROOT, env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 1, value)

            result = subprocess.run(
                common + ["--artifact", f"artifact.bin={artifact_path}",
                          "--support-matrix", str(artifact_path),
                          "--sbom", str(directory / "sbom.json")],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("overlaps release artifact", result.stderr)

            result = subprocess.run(
                common + ["--artifact", f"artifact.bin={artifact_path}",
                          "--support-matrix", str(directory / "same.json"),
                          "--sbom", str(directory / "same.json")],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("outputs overlap", result.stderr)

            bad_epoch = self.invoke(directory, artifacts, epoch="not-an-epoch")
            self.assertEqual(bad_epoch.returncode, 1)
            self.assertIn("SOURCE_DATE_EPOCH", bad_epoch.stderr)

            result = subprocess.run(
                ["python3", str(TOOL), "--source-revision", "not-a-commit",
                 "--artifact", f"artifact.bin={artifact_path}",
                 "--support-matrix", str(directory / "support.json"),
                 "--sbom", str(directory / "sbom.json")],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("source revision", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

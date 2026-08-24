#!/usr/bin/env python3
"""Regression tests for tools/bbpctl.py. Run with: python3 tests/test_bbpctl.py"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
sys.path.insert(0, str(TOOLS))
import bbpctl  # noqa: E402


CLI = [sys.executable, str(TOOLS / "bbpctl.py")]
FIXTURE_SHA256 = "d160d7991928e9cf9139a86e1c3fc01d993a768d9b106ccde1d3bb4896082752"
EVIDENCE_DIGESTS = {
    "sha256": "988032f1e5edde6c0c1d3563b6e0c74d48caa77190df4479cb829a892082ede0",
    "sha384": "76d6b1d0ce0ee2d153c711e5de6ceb22fb79f7e8f1c200a94ca942c37d4fa0280809895b95622e8bffdafe5986f790f2",
    "sha512": "c454339d30715aca0cef72fec97c070844102b2feed78f548d2c25a819d6d398c68354e42e1441498278b486d3388370b7d48f5127c0a3025e1beb8d14c4713e",
    "blake2b": "b0f408286588a08f83548fef690f877cc839b51795757dd9f194908c8b70f383875164f7c892ef25ddf233d574197f2594a1653996db258a7aea034c38f4942c",
}


class BbpctlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.capture = self.directory / "fixture.bbpc"
        result = self.run_cli("fixture", "create", self.capture)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    @staticmethod
    def run_cli(*arguments):
        return subprocess.run(
            CLI + [os.fspath(argument) for argument in arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    @staticmethod
    def refresh_container_crc(raw):
        struct.pack_into("<Q", raw, bbpctl.CONTAINER_CHECKSUM_OFFSET, 0)
        struct.pack_into(
            "<Q", raw, bbpctl.CONTAINER_CHECKSUM_OFFSET, bbpctl.crc64_xz(bytes(raw))
        )

    def write_mutation(self, name, mutate):
        raw = bytearray(self.capture.read_bytes())
        mutate(raw)
        self.refresh_container_crc(raw)
        path = self.directory / name
        path.write_bytes(raw)
        return path

    def test_crc_vector_and_fixture_byte_identity(self):
        self.assertEqual(bbpctl.crc64_xz(b"123456789"), 0x995DC9BBDF1939FA)
        raw = self.capture.read_bytes()
        self.assertEqual(len(raw), 384)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FIXTURE_SHA256)
        second = self.directory / "second.bbpc"
        result = self.run_cli("fixture", "create", second)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(raw, second.read_bytes())

    def test_verify_inspect_and_evidence_json(self):
        verify = self.run_cli("verify", self.capture, "--json")
        self.assertEqual(verify.returncode, 0, verify.stderr.decode())
        self.assertEqual(json.loads(verify.stdout), {
            "errors": [], "tags_walked": 2, "valid": True,
        })

        inspect = self.run_cli("inspect", self.capture, "--json")
        self.assertEqual(inspect.returncode, 0, inspect.stderr.decode())
        report = json.loads(inspect.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["info"]["bootloader_name"], "bbpctl-fixture")
        self.assertEqual(report["info"]["architecture"], "x86_64")
        self.assertEqual([tag["name"] for tag in report["chain"]], ["HHDM", "ACPI"])
        self.assertEqual(
            [tag["source_phys"] for tag in report["chain"]], ["0x200000", "0x301000"]
        )

        for algorithm, expected in EVIDENCE_DIGESTS.items():
            with self.subTest(algorithm=algorithm):
                result = self.run_cli(
                    "evidence", self.capture, "--algorithm", algorithm, "--json"
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                evidence = json.loads(result.stdout)
                self.assertEqual(evidence["digest"], expected)
                self.assertEqual(evidence["evidence_bytes"], 256)
                self.assertEqual(evidence["tags_included"], 2)
                self.assertEqual(evidence["tags_skipped_crc"], 0)

        raw = bytearray(self.capture.read_bytes())
        struct.pack_into("<I", raw, bbpctl.INFO_OFFSET + 20, 4096)
        bbpctl._pack_region_checksum(
            raw, bbpctl.INFO_OFFSET, bbpctl.INFO_SIZE,
            bbpctl.INFO_CHECKSUM_OFFSET,
        )
        self.refresh_container_crc(raw)
        noncontiguous = self.directory / "informational-info-size.bbpc"
        noncontiguous.write_bytes(raw)
        result = self.run_cli("verify", noncontiguous, "--json")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_evidence_stream_is_canonical_and_has_no_container_metadata(self):
        raw = self.capture.read_bytes()
        expected = (
            bbpctl.EVIDENCE_MAGIC
            + raw[bbpctl.INFO_OFFSET:bbpctl.INFO_OFFSET + bbpctl.INFO_SIZE]
            + raw[288:328]
            + raw[328:384]
        )
        stream = self.directory / "evidence.bin"
        result = self.run_cli("evidence", self.capture, "--stream", stream, "--json")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(stream.read_bytes(), expected)
        self.assertNotIn(b"BBP-CAPTURE-V1", expected)
        self.assertNotIn(struct.pack("<Q", 0x100000), expected[:16])

        stdout_stream = self.run_cli("evidence", self.capture, "--stream", "-")
        self.assertEqual(stdout_stream.returncode, 0)
        self.assertEqual(stdout_stream.stdout, expected)
        self.assertIn(EVIDENCE_DIGESTS["sha256"].encode(), stdout_stream.stderr)

    def test_all_corruption_cases_and_evidence_policy(self):
        cases = (
            "container-crc", "info-body", "info-magic-padding", "tag-body",
            "tag-size-small", "first-misaligned", "next-dangling", "next-cycle",
        )
        for case in cases:
            with self.subTest(case=case):
                corrupted = self.directory / f"{case}.bbpc"
                create = self.run_cli(
                    "fixture", "corrupt", self.capture, corrupted, "--case", case
                )
                self.assertEqual(create.returncode, 0, create.stderr.decode())
                verify = self.run_cli("verify", corrupted, "--json")
                self.assertEqual(verify.returncode, 1, verify.stderr.decode())
                self.assertFalse(json.loads(verify.stdout)["valid"])
                inspect = self.run_cli("inspect", corrupted, "--json")
                self.assertEqual(inspect.returncode, 0, inspect.stderr.decode())
                self.assertTrue(json.loads(inspect.stdout)["errors"])
                evidence = self.run_cli("evidence", corrupted, "--json")
                expected_exit = 0 if case == "tag-body" else 1
                self.assertEqual(evidence.returncode, expected_exit, evidence.stderr.decode())
                if case == "tag-body":
                    report = json.loads(evidence.stdout)
                    self.assertEqual(report["tags_included"], 1)
                    self.assertEqual(report["tags_skipped_crc"], 1)

    def test_crc_bad_tag_is_excluded_but_its_next_link_is_followed(self):
        corrupted = self.directory / "tag-body.bbpc"
        result = self.run_cli(
            "fixture", "corrupt", self.capture, corrupted,
            "--case", "tag-body", "--tag-index", "0",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        stream = self.directory / "crc-exclusion.bin"
        result = self.run_cli("evidence", corrupted, "--stream", stream, "--json")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads(result.stdout)
        raw = corrupted.read_bytes()
        expected = (
            bbpctl.EVIDENCE_MAGIC
            + raw[bbpctl.INFO_OFFSET:bbpctl.INFO_OFFSET + bbpctl.INFO_SIZE]
            + raw[328:384]
        )
        self.assertEqual(stream.read_bytes(), expected)
        self.assertEqual(report["tags_included"], 1)
        self.assertEqual(report["tags_skipped_crc"], 1)

    def test_truncation_bounds_overlap_duplicates_padding_and_trailing_data(self):
        mutations = {}

        truncated = self.directory / "truncated.bbpc"
        truncated.write_bytes(self.capture.read_bytes()[:-1])
        mutations["truncated"] = truncated

        def bad_size(raw):
            struct.pack_into("<I", raw, bbpctl.DIRECTORY_OFFSET + 16, bbpctl.MAX_TAG_SIZE + 1)
        mutations["bounds"] = self.write_mutation("bounds.bbpc", bad_size)

        def overlap(raw):
            struct.pack_into(
                "<Q", raw, bbpctl.DIRECTORY_OFFSET + bbpctl.DIRECTORY_ENTRY_SIZE + 8, 320
            )
        mutations["file-overlap"] = self.write_mutation("file-overlap.bbpc", overlap)

        def duplicate(raw):
            struct.pack_into(
                "<Q", raw, bbpctl.DIRECTORY_OFFSET + bbpctl.DIRECTORY_ENTRY_SIZE, 0x200000
            )
        mutations["duplicate"] = self.write_mutation("duplicate.bbpc", duplicate)

        def physical_overlap(raw):
            struct.pack_into(
                "<Q", raw, bbpctl.DIRECTORY_OFFSET + bbpctl.DIRECTORY_ENTRY_SIZE, 0x200020
            )
        mutations["physical-overlap"] = self.write_mutation(
            "physical-overlap.bbpc", physical_overlap
        )

        raw = bytearray(self.capture.read_bytes())
        raw[288:288] = b"\x01" + b"\0" * 7
        struct.pack_into("<Q", raw, bbpctl.DIRECTORY_OFFSET + 8, 296)
        struct.pack_into(
            "<Q", raw, bbpctl.DIRECTORY_OFFSET + bbpctl.DIRECTORY_ENTRY_SIZE + 8, 336
        )
        struct.pack_into("<Q", raw, 72, len(raw))
        self.refresh_container_crc(raw)
        padding = self.directory / "padding.bbpc"
        padding.write_bytes(raw)
        mutations["nonzero-padding"] = padding

        raw = bytearray(self.capture.read_bytes()) + b"x"
        struct.pack_into("<Q", raw, 72, len(raw))
        self.refresh_container_crc(raw)
        trailing = self.directory / "trailing.bbpc"
        trailing.write_bytes(raw)
        mutations["trailing"] = trailing

        for name, path in mutations.items():
            with self.subTest(name=name):
                result = self.run_cli("verify", path, "--json")
                self.assertEqual(result.returncode, 1, result.stderr.decode())
                self.assertTrue(json.loads(result.stdout)["errors"])
                evidence = self.run_cli("evidence", path, "--json")
                self.assertEqual(evidence.returncode, 1, evidence.stderr.decode())

        tiny = self.directory / "tiny.bbpc"
        tiny.write_bytes(b"BBP")
        self.assertEqual(self.run_cli("verify", tiny).returncode, 2)
        wrong_magic = self.directory / "wrong-magic.bbpc"
        wrong_magic.write_bytes(b"x" * bbpctl.HEADER_SIZE)
        self.assertEqual(self.run_cli("inspect", wrong_magic).returncode, 2)

    def test_overwrite_same_path_and_usage_protections(self):
        original = self.capture.read_bytes()
        result = self.run_cli("fixture", "create", self.capture)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.capture.read_bytes(), original)
        result = self.run_cli("fixture", "create", self.capture, "--force")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

        result = self.run_cli(
            "fixture", "corrupt", self.capture, self.capture,
            "--case", "container-crc", "--force",
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.capture.read_bytes(), original)

        evidence = self.directory / "existing.bin"
        evidence.write_bytes(b"keep")
        result = self.run_cli("evidence", self.capture, "--stream", evidence)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(evidence.read_bytes(), b"keep")
        self.assertEqual(
            self.run_cli("evidence", self.capture, "--stream", "-", "--json").returncode, 2
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

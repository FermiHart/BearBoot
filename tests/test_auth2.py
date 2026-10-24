import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experimental.auth2 import (
    ALG_ECDSA_P256_SHA256,
    ENVELOPE_SIGNATURE_OFFSET,
    MANIFEST_SIGNATURE_OFFSET,
    P256_ORDER,
    ROLE_RECOVERY,
    ROLE_RELEASE,
    Auth2Error,
    KeyPolicy,
    build_manifest,
    ecdsa_raw_to_der,
    envelope_signing_bytes,
    key_id_from_public_key,
    manifest_signing_bytes,
    sign_envelope,
    verify_envelope,
    verify_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "auth2"


class Auth2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = (VECTORS / "payload.dat").read_bytes()
        cls.manifest = (VECTORS / "manifest.auth2").read_bytes()
        cls.envelope = (VECTORS / "release.auth2").read_bytes()
        cls.recovery_envelope = (VECTORS / "recovery.auth2").read_bytes()
        cls.root_private = VECTORS / "root.test-only.private.pem"
        cls.root_public = VECTORS / "root.public.pem"
        cls.wrong_root_public = VECTORS / "wrong-root.public.pem"
        cls.release_private = VECTORS / "release.test-only.private.pem"
        cls.release_public = VECTORS / "release.public.pem"
        cls.recovery_private = VECTORS / "recovery.test-only.private.pem"
        cls.recovery_public = VECTORS / "recovery.public.pem"
        cls.intruder_private = VECTORS / "intruder.test-only.private.pem"
        cls.intruder_public = VECTORS / "intruder.public.pem"

    def policy(self, public_key, role, activation=1, retirement=20,
               revoked=False):
        return KeyPolicy(public_key, role, activation, retirement, revoked)

    def fresh_manifest(self, *policies, generation=7):
        return build_manifest(self.root_private, generation, policies)

    def test_checked_in_public_vector_verifies(self):
        parsed = verify_manifest(self.manifest, self.root_public,
                                 minimum_generation=7)
        verified = verify_envelope(self.envelope, self.manifest,
                                   self.root_public, minimum_generation=7)
        self.assertEqual(verified.payload, self.payload)
        self.assertEqual(verified.security_generation, 7)
        self.assertEqual(verified.role, ROLE_RELEASE)
        self.assertEqual(len(parsed.keys), 2)
        self.assertEqual(verified.signer_key_id[:2],
                         struct.pack("<H", ALG_ECDSA_P256_SHA256))

    def test_payload_and_signed_header_tamper_are_rejected(self):
        for offset in (20, len(self.envelope) - 1):
            damaged = bytearray(self.envelope)
            damaged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(Auth2Error):
                verify_envelope(bytes(damaged), self.manifest,
                                self.root_public)

    def test_wrong_root_and_wrong_signer_are_rejected(self):
        with self.assertRaises(Auth2Error):
            verify_manifest(self.manifest, self.wrong_root_public)

        intruder = sign_envelope(self.payload, self.intruder_private, 7,
                                 ROLE_RELEASE)
        with self.assertRaisesRegex(Auth2Error, "unknown signer"):
            verify_envelope(intruder, self.manifest, self.root_public)

    def test_high_s_envelope_and_manifest_signatures_are_rejected(self):
        damaged_envelope = bytearray(self.envelope)
        signature = damaged_envelope[
            ENVELOPE_SIGNATURE_OFFSET:ENVELOPE_SIGNATURE_OFFSET + 64]
        s = int.from_bytes(signature[32:], "big")
        signature[32:] = (P256_ORDER - s).to_bytes(32, "big")
        damaged_envelope[
            ENVELOPE_SIGNATURE_OFFSET:ENVELOPE_SIGNATURE_OFFSET + 64] = signature
        with self.assertRaisesRegex(Auth2Error, "high-S"):
            verify_envelope(bytes(damaged_envelope), self.manifest,
                            self.root_public)

        damaged_manifest = bytearray(self.manifest)
        signature = damaged_manifest[
            MANIFEST_SIGNATURE_OFFSET:MANIFEST_SIGNATURE_OFFSET + 64]
        s = int.from_bytes(signature[32:], "big")
        signature[32:] = (P256_ORDER - s).to_bytes(32, "big")
        damaged_manifest[
            MANIFEST_SIGNATURE_OFFSET:MANIFEST_SIGNATURE_OFFSET + 64] = signature
        with self.assertRaisesRegex(Auth2Error, "high-S"):
            verify_manifest(bytes(damaged_manifest), self.root_public)

    def test_unknown_algorithms_are_rejected_before_authentication(self):
        damaged = bytearray(self.envelope)
        struct.pack_into("<H", damaged, 12, 0xFFFF)
        with self.assertRaisesRegex(Auth2Error, "unknown envelope algorithm"):
            verify_envelope(bytes(damaged), self.manifest, self.root_public)

        damaged = bytearray(self.manifest)
        struct.pack_into("<H", damaged, 12, 0xFFFF)
        with self.assertRaisesRegex(Auth2Error, "unknown manifest algorithm"):
            verify_manifest(bytes(damaged), self.root_public)

    def test_activation_retirement_revocation_and_generation_are_enforced(self):
        for policy, message in (
            (self.policy(self.release_public, ROLE_RELEASE, activation=8),
             "not active"),
            (self.policy(self.release_public, ROLE_RELEASE, retirement=6),
             "retired"),
            (self.policy(self.release_public, ROLE_RELEASE, revoked=True),
             "revoked"),
        ):
            manifest = self.fresh_manifest(policy)
            with self.subTest(message=message), self.assertRaisesRegex(
                    Auth2Error, message):
                verify_envelope(self.envelope, manifest, self.root_public)

        with self.assertRaisesRegex(Auth2Error, "security generation"):
            verify_envelope(self.envelope, self.manifest, self.root_public,
                            minimum_generation=8)

    def test_recovery_role_requires_explicit_policy(self):
        manifest = self.fresh_manifest(
            self.policy(self.release_public, ROLE_RELEASE),
            self.policy(self.recovery_public, ROLE_RECOVERY),
        )
        recovery = sign_envelope(self.payload, self.recovery_private, 7,
                                 ROLE_RECOVERY)
        with self.assertRaisesRegex(Auth2Error, "recovery role"):
            verify_envelope(recovery, manifest, self.root_public)
        self.assertEqual(
            verify_envelope(recovery, manifest, self.root_public,
                            allow_recovery=True).payload,
            self.payload,
        )
        with self.assertRaisesRegex(Auth2Error, "recovery role"):
            verify_envelope(self.recovery_envelope, self.manifest,
                            self.root_public)
        self.assertEqual(
            verify_envelope(self.recovery_envelope, self.manifest,
                            self.root_public, allow_recovery=True).payload,
            self.payload,
        )

        mislabeled = sign_envelope(self.payload, self.release_private, 7,
                                   ROLE_RECOVERY)
        with self.assertRaisesRegex(Auth2Error, "signer role"):
            verify_envelope(mislabeled, manifest, self.root_public,
                            allow_recovery=True)

    def test_duplicate_keys_and_malformed_extents_are_rejected(self):
        policy = self.policy(self.release_public, ROLE_RELEASE)
        with self.assertRaisesRegex(Auth2Error, "duplicate key"):
            self.fresh_manifest(policy, policy)

        for damaged in (self.manifest[:-1], self.manifest + b"x"):
            with self.assertRaisesRegex(Auth2Error, "extent"):
                verify_manifest(damaged, self.root_public)
        for damaged in (self.envelope[:-1], self.envelope + b"x"):
            with self.assertRaisesRegex(Auth2Error, "extent"):
                verify_envelope(damaged, self.manifest, self.root_public)

        damaged = bytearray(self.envelope)
        struct.pack_into("<Q", damaged, 32, len(self.payload) + 1)
        with self.assertRaisesRegex(Auth2Error, "extent"):
            verify_envelope(bytes(damaged), self.manifest, self.root_public)

    def test_key_ids_bind_algorithm_and_public_key(self):
        release_id = key_id_from_public_key(self.release_public)
        recovery_id = key_id_from_public_key(self.recovery_public)
        self.assertEqual(release_id[:2], b"\x01\x00")
        self.assertNotEqual(release_id, recovery_id)

    def test_openssl_independently_verifies_both_vector_signatures(self):
        cases = (
            (manifest_signing_bytes(self.manifest),
             self.manifest[MANIFEST_SIGNATURE_OFFSET:
                           MANIFEST_SIGNATURE_OFFSET + 64],
             self.root_public),
            (envelope_signing_bytes(self.envelope),
             self.envelope[ENVELOPE_SIGNATURE_OFFSET:
                           ENVELOPE_SIGNATURE_OFFSET + 64],
             self.release_public),
            (envelope_signing_bytes(self.recovery_envelope),
             self.recovery_envelope[ENVELOPE_SIGNATURE_OFFSET:
                                    ENVELOPE_SIGNATURE_OFFSET + 64],
             self.recovery_public),
        )
        for signed_bytes, raw_signature, public_key in cases:
            with tempfile.TemporaryDirectory() as directory:
                data = Path(directory) / "signed.dat"
                signature = Path(directory) / "signature.der"
                data.write_bytes(signed_bytes)
                signature.write_bytes(ecdsa_raw_to_der(raw_signature))
                result = subprocess.run(
                    ["openssl", "dgst", "-sha256", "-verify",
                     os.fspath(public_key), "-signature", os.fspath(signature),
                     os.fspath(data)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "Verified OK")

    def test_host_cli_signs_and_verifies_without_exposing_private_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            keys = directory / "keys.json"
            manifest = directory / "manifest.auth2"
            envelope = directory / "release.auth2"
            recovered = directory / "payload.dat"
            keys.write_text(json.dumps([
                {
                    "public_key": os.fspath(self.release_public),
                    "role": "release",
                    "activation_generation": 1,
                    "retirement_generation": 20,
                    "revoked": False,
                }
            ]), encoding="ascii")
            commands = (
                ["manifest-sign", "--root-private", os.fspath(self.root_private),
                 "--generation", "7", "--keys", os.fspath(keys),
                 "--output", os.fspath(manifest)],
                ["envelope-sign", "--private", os.fspath(self.release_private),
                 "--generation", "7", "--role", "release", "--payload",
                 os.fspath(VECTORS / "payload.dat"), "--output",
                 os.fspath(envelope)],
                ["verify", "--root-public", os.fspath(self.root_public),
                 "--manifest", os.fspath(manifest), "--envelope",
                 os.fspath(envelope), "--minimum-generation", "7",
                 "--output", os.fspath(recovered)],
            )
            for command in commands:
                result = subprocess.run(
                    [sys.executable, os.fspath(ROOT / "tools" / "bbp_auth2.py"),
                     *command], cwd=ROOT, capture_output=True, text=True,
                    check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(recovered.read_bytes(), self.payload)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.bbp_v2_envelope import HEADER, key_id, seal, verify


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "tests" / "vectors" / "bbp-v2-profile0-auth-v1.json"


class AuthInteropTests(unittest.TestCase):
    def test_c_and_python_consume_canonical_vector(self):
        vector = json.loads(VECTOR.read_text(encoding="ascii"))
        key = bytes.fromhex(vector["key_hex"])
        envelope = bytes.fromhex(vector["envelope_hex"])
        capsule = bytes.fromhex(vector["capsule_hex"])
        self.assertEqual(len(envelope) - len(capsule), HEADER.size)
        self.assertEqual(key_id(key).hex(), vector["key_id_hex"])
        self.assertEqual(seal(capsule, key, vector["rollback_index"]), envelope)
        self.assertEqual(
            verify(envelope, {vector["key_id_hex"]: key}),
            (capsule, vector["rollback_index"], vector["key_id_hex"]),
        )

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "v2_auth_selftest"
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                "-I", str(ROOT / "include"),
                str(ROOT / "tests" / "v2_auth_selftest.c"),
                str(ROOT / "v2" / "bbp_v2_auth.c"),
                str(ROOT / "v2" / "bbp_v2.c"),
                str(ROOT / "v2" / "bbp_v2_profile.c"),
                "-o", str(binary),
            ], check=True, cwd=ROOT)
            completed = subprocess.run([str(binary), str(VECTOR)], check=True,
                                       cwd=ROOT, text=True,
                                       stdout=subprocess.PIPE)
            self.assertIn("BBP v2 authenticated transport: PASSED",
                          completed.stdout)


if __name__ == "__main__":
    unittest.main()

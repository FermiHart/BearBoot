#!/usr/bin/env python3
"""Consume the packaged canonical BBP v2 authenticated Profile 0 vector."""
import json
from pathlib import Path
import sys
import tempfile


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = PACKAGE_ROOT / "lib"
if not MODULE_ROOT.is_dir():
    MODULE_ROOT = PACKAGE_ROOT / "tools"
sys.path.insert(0, str(MODULE_ROOT))

from bbp_v2_envelope import key_id, seal, verify_and_commit  # noqa: E402


def main() -> int:
    vector_path = (Path(sys.argv[1]) if len(sys.argv) == 2 else
                   PACKAGE_ROOT / "tests/vectors/bbp-v2-profile0-auth-v1.json")
    vector = json.loads(vector_path.read_text(encoding="ascii"))
    key = bytes.fromhex(vector["key_hex"])
    capsule = bytes.fromhex(vector["capsule_hex"])
    envelope = bytes.fromhex(vector["envelope_hex"])
    identity = key_id(key).hex()

    if identity != vector["key_id_hex"]:
        raise SystemExit("canonical key identity mismatch")
    if seal(capsule, key, vector["rollback_index"]) != envelope:
        raise SystemExit("canonical envelope mismatch")
    with tempfile.TemporaryDirectory() as directory:
        accepted = verify_and_commit(
            envelope, {identity: key}, str(Path(directory) / "rollback.json")
        )
    if accepted != capsule:
        raise SystemExit("accepted capsule mismatch")

    print("BBP host v2 envelope roundtrip: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

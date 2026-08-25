import json
import os
import struct
import tempfile
import unittest
from unittest import mock

from tests.test_v2_vectors import capsule
from tools.bbp_v2_envelope import (
    ALG_HMAC_SHA256,
    STATE_VERSION,
    EnvelopeError,
    key_id,
    seal,
    verify,
    verify_and_commit,
)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.keys = {key_id(self.key).hex(): self.key}
        self.payload = capsule(64)

    def test_authentication_extent_and_policy(self):
        envelope = seal(self.payload, self.key, 7)
        self.assertEqual(verify(envelope, self.keys, 7)[:2], (self.payload, 7))
        with self.assertRaises(EnvelopeError):
            verify(envelope, self.keys, 8)
        for offset in (0, 20, len(envelope) - 1):
            corrupt = bytearray(envelope)
            corrupt[offset] ^= 1
            with self.assertRaises(EnvelopeError):
                verify(bytes(corrupt), self.keys)
        with self.assertRaises(EnvelopeError):
            verify(envelope[:-1], self.keys)
        with self.assertRaises(EnvelopeError):
            verify(envelope, {key_id(b"wrong").hex(): b"wrong"})

    def test_monotonic_state_rejects_replay_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state.json")
            self.assertEqual(verify_and_commit(seal(self.payload, self.key, 4),
                                               self.keys, state), self.payload)
            with self.assertRaises(EnvelopeError):
                verify_and_commit(seal(self.payload, self.key, 4), self.keys, state)
            with self.assertRaises(EnvelopeError):
                verify_and_commit(seal(self.payload, self.key, 3), self.keys, state)
            verify_and_commit(seal(self.payload, self.key, 5), self.keys, state)
            with open(state, encoding="ascii") as source:
                self.assertEqual(json.load(source), {
                    "accepted_key": key_id(self.key).hex(),
                    "highest_rollback": 5,
                    "version": STATE_VERSION,
                })

    def test_key_rotation_does_not_reset_rollback_floor(self):
        second_key = bytes(reversed(range(32)))
        keys = dict(self.keys)
        keys[key_id(second_key).hex()] = second_key
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state.json")
            verify_and_commit(seal(self.payload, self.key, 100), keys, state)
            with self.assertRaises(EnvelopeError):
                verify_and_commit(seal(self.payload, second_key, 1), keys, state)
            self.assertEqual(verify_and_commit(
                seal(self.payload, second_key, 101), keys, state), self.payload)

    def test_non_capsule_does_not_create_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state.json")
            malformed = seal(b"not a capsule", self.key, 1)
            with self.assertRaisesRegex(EnvelopeError, "BBP v2 capsule"):
                verify(malformed, self.keys)
            with self.assertRaisesRegex(EnvelopeError, "BBP v2 capsule"):
                verify_and_commit(malformed, self.keys, state)
            self.assertFalse(os.path.exists(state))

    def test_policy_rejection_does_not_advance_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state.json")
            verify_and_commit(seal(self.payload, self.key, 4), self.keys, state)
            with open(state, "rb") as source:
                before = source.read()
            calls = []

            def reject(payload, rollback, identity):
                calls.append((payload, rollback, identity))
                return False

            with self.assertRaisesRegex(EnvelopeError, "policy"):
                verify_and_commit(seal(self.payload, self.key, 5), self.keys,
                                  state, policy=reject)
            with open(state, "rb") as source:
                self.assertEqual(source.read(), before)
            self.assertEqual(calls, [(self.payload, 5, key_id(self.key).hex())])

    def test_unknown_flags_and_algorithm_are_rejected(self):
        envelope = bytearray(seal(self.payload, self.key, 7))
        algorithm = bytearray(envelope)
        struct.pack_into("<H", algorithm, 10, ALG_HMAC_SHA256 + 1)
        flags = bytearray(envelope)
        struct.pack_into("<I", flags, 12, 1)
        for malformed in (algorithm, flags):
            with self.assertRaisesRegex(EnvelopeError, "framing"):
                verify(bytes(malformed), self.keys)

    def test_uint64_exhaustion_and_invalid_state_do_not_change_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state.json")
            exhausted = {
                "accepted_key": key_id(self.key).hex(),
                "highest_rollback": 0xFFFFFFFFFFFFFFFF,
                "version": STATE_VERSION,
            }
            with open(state, "w", encoding="ascii") as destination:
                json.dump(exhausted, destination)
            with open(state, "rb") as source:
                before = source.read()
            with self.assertRaisesRegex(EnvelopeError, "exhausted"):
                verify_and_commit(seal(self.payload, self.key,
                                       0xFFFFFFFFFFFFFFFF), self.keys, state)
            with open(state, "rb") as source:
                self.assertEqual(source.read(), before)

            exhausted["highest_rollback"] = -1
            with open(state, "w", encoding="ascii") as destination:
                json.dump(exhausted, destination)
            with self.assertRaisesRegex(EnvelopeError, "state"):
                verify_and_commit(seal(self.payload, self.key, 1), self.keys,
                                  state)

            exhausted["highest_rollback"] = 0
            exhausted["version"] = STATE_VERSION + 1
            with open(state, "w", encoding="ascii") as destination:
                json.dump(exhausted, destination)
            with self.assertRaisesRegex(EnvelopeError, "state"):
                verify_and_commit(seal(self.payload, self.key, 1), self.keys,
                                  state)

    def test_seal_and_verify_validate_ranges(self):
        for rollback in (-1, 0x10000000000000000, True):
            with self.assertRaises(EnvelopeError):
                seal(self.payload, self.key, rollback)
        with self.assertRaises(EnvelopeError):
            verify(seal(self.payload, self.key, 0), self.keys, -1)

    def test_commit_fsyncs_file_and_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state.json")
            real_fsync = os.fsync
            calls = []

            def record_fsync(fd):
                calls.append(fd)
                return real_fsync(fd)

            with mock.patch("tools.bbp_v2_envelope.os.fsync",
                            side_effect=record_fsync):
                verify_and_commit(seal(self.payload, self.key, 1), self.keys,
                                  state)
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()

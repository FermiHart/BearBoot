import json
import os
import tempfile
import unittest
from tools.bbp_v2_envelope import EnvelopeError, key_id, seal, verify, verify_and_commit


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.keys = {key_id(self.key).hex(): self.key}
        self.payload = b"BBP2CAP\0experimental-capsule"

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


if __name__ == "__main__":
    unittest.main()

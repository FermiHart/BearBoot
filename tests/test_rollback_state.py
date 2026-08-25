#!/usr/bin/env python3
"""Wave 20 durable rollback journal regression tests."""

import json
from pathlib import Path
import tempfile
import threading
import unittest

from tools.bbp_rollback_state import (
    CorruptJournalError,
    JournalConflictError,
    MemoryFloorProvider,
    PolicyError,
    RollbackJournal,
)


class RollbackJournalTests(unittest.TestCase):
    def journal(self, directory: str, floor: int = 0):
        provider = MemoryFloorProvider(floor)
        return RollbackJournal(Path(directory) / "boot-state", provider), provider

    def test_deletion_and_rewrite_cannot_lower_injected_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal, provider = self.journal(temporary, 4)
            old = journal.commit(4, "release", "A", "B", expected_sequence=0)
            old_bytes = [path.read_bytes() for path in journal.slot_paths
                         if path.exists()]
            current = journal.commit(
                5, "release", "B", None, expected_sequence=old.sequence
            )
            self.assertEqual(provider.read_floor(), 5)

            for path in journal.slot_paths:
                path.unlink(missing_ok=True)
            self.assertEqual(journal.load().generation, 5)
            with self.assertRaises(PolicyError):
                journal.commit(4, "release", "A", None, expected_sequence=0)
            self.assertEqual(provider.read_floor(), 5)

            for path, data in zip(journal.slot_paths, old_bytes):
                path.write_bytes(data)
            replayed = journal.load()
            self.assertEqual((replayed.generation, replayed.sequence),
                             (5, old.sequence))
            self.assertIsNone(replayed.active_slot)
            self.assertIsNone(replayed.pending_slot)
            with self.assertRaises(PolicyError):
                journal.commit(
                    4, "release", "A", None,
                    expected_sequence=old.sequence,
                )
            self.assertEqual(provider.read_floor(), current.generation)

    def test_two_writers_use_sequence_cas_without_floor_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal, provider = self.journal(temporary)
            barrier = threading.Barrier(3)
            results = []

            def writer(active_slot: str) -> None:
                barrier.wait()
                try:
                    state = journal.commit(
                        1, "release", active_slot, None,
                        expected_sequence=0,
                    )
                    results.append(("ok", state.sequence))
                except JournalConflictError:
                    results.append(("conflict", None))

            threads = [threading.Thread(target=writer, args=(slot,))
                       for slot in ("A", "B")]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join()

            self.assertEqual(sorted(kind for kind, _ in results),
                             ["conflict", "ok"])
            self.assertEqual(provider.read_floor(), 1)
            self.assertEqual(journal.load().generation, 1)

    def test_equal_generation_recovery_repairs_floor_first_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal, provider = self.journal(temporary)
            self.assertTrue(provider.compare_and_advance(0, 1))

            recovered = journal.commit(
                1, "recovery", "A", "B", expected_sequence=0
            )
            self.assertEqual((recovered.generation, recovered.sequence), (1, 1))
            self.assertEqual(journal.load(), recovered)
            with self.assertRaises(PolicyError):
                journal.commit(
                    2, "recovery", "B", None,
                    expected_sequence=recovered.sequence,
                )

    def test_one_corrupt_slot_recovers_and_both_corrupt_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal, _provider = self.journal(temporary)
            first = journal.commit(0, "release", "A", "B", expected_sequence=0)
            second = journal.commit(
                1, "release", "B", None, expected_sequence=first.sequence
            )
            newest_path = journal.slot_paths[second.sequence % 2]
            newest_path.write_bytes(newest_path.read_bytes()[:-1] + b" ")
            recovered = journal.load()
            self.assertEqual(recovered.sequence, first.sequence)
            self.assertEqual(recovered.generation, 1)
            self.assertIsNone(recovered.active_slot)
            self.assertIsNone(recovered.pending_slot)

            for path in journal.slot_paths:
                path.write_bytes(b'{"schema":"corrupt"}\n')
            with self.assertRaises(CorruptJournalError):
                journal.load()

    def test_gaps_exhaustion_bounds_and_integrity_fail_closed(self) -> None:
        maximum = (1 << 64) - 1
        with tempfile.TemporaryDirectory() as temporary:
            journal, provider = self.journal(temporary, 7)
            with self.assertRaises(PolicyError):
                journal.commit(9, "release", "A", None, expected_sequence=0)
            self.assertEqual(provider.read_floor(), 7)

            exhausted, exhausted_provider = self.journal(temporary, maximum)
            retry = exhausted.commit(
                maximum, "release", "A", None, expected_sequence=0
            )
            self.assertEqual(retry.generation, maximum)
            with self.assertRaises((PolicyError, ValueError)):
                exhausted.commit(
                    maximum + 1, "release", "A", None,
                    expected_sequence=retry.sequence,
                )
            self.assertEqual(exhausted_provider.read_floor(), maximum)

            persisted = exhausted.slot_paths[retry.sequence % 2]
            document = json.loads(persisted.read_text(encoding="ascii"))
            document["generation"] = 0
            persisted.write_text(json.dumps(document) + "\n", encoding="ascii")
            with self.assertRaises(CorruptJournalError):
                exhausted.load()

            persisted.write_bytes(b"x" * (RollbackJournal.MAX_RECORD_BYTES + 1))
            with self.assertRaises(CorruptJournalError):
                exhausted.load()


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Wave 20 durable rollback journal regression tests."""

import fcntl
import json
import os
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
    RollbackStateError,
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
        class BlockingProvider(MemoryFloorProvider):
            def __init__(self):
                super().__init__(0)
                self.first_read_entered = threading.Event()
                self.release_first_read = threading.Event()
                self.read_guard = threading.Lock()
                self.read_started = False

            def read_floor(self) -> int:
                with self.read_guard:
                    first = not self.read_started
                    self.read_started = True
                if first:
                    self.first_read_entered.set()
                    if not self.release_first_read.wait(timeout=5):
                        raise AssertionError("first journal writer was not released")
                return super().read_floor()

        with tempfile.TemporaryDirectory() as temporary:
            provider = BlockingProvider()
            journals = [
                RollbackJournal(Path(temporary) / "boot-state", provider)
                for _ in range(2)
            ]
            results = []
            errors = []

            def writer(journal, active_slot: str) -> None:
                try:
                    state = journal.commit(
                        1, "release", active_slot, None,
                        expected_sequence=0,
                    )
                    results.append(("ok", state.sequence))
                except JournalConflictError:
                    results.append(("conflict", None))
                except Exception as error:  # surfaced after both threads join
                    errors.append(error)

            threads = [
                threading.Thread(target=writer, args=(journal, slot))
                for journal, slot in zip(journals, ("A", "B"))
            ]
            threads[0].start()
            first_entered = provider.first_read_entered.wait(timeout=5)

            lock_held = False
            if first_entered:
                fd = os.open(journals[0].lock_path, os.O_RDWR)
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        lock_held = True
                    else:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

            threads[1].start()
            provider.release_first_read.set()
            for thread in threads:
                thread.join(timeout=5)

            self.assertTrue(first_entered)
            self.assertTrue(lock_held)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(sorted(kind for kind, _ in results),
                             ["conflict", "ok"])
            self.assertEqual(provider.read_floor(), 1)
            self.assertEqual(journals[0].load().generation, 1)

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

    def test_provider_cannot_claim_advancement_without_authority(self) -> None:
        class BrokenProvider(MemoryFloorProvider):
            def __init__(self, result):
                super().__init__(0)
                self.result = result

            def compare_and_advance(self, expected: int, new: int) -> bool:
                return self.result

        for result in (0, 1, None, True):
            with self.subTest(result=result):
                with tempfile.TemporaryDirectory() as temporary:
                    provider = BrokenProvider(result)
                    journal = RollbackJournal(
                        Path(temporary) / "boot-state", provider
                    )
                    with self.assertRaises(RollbackStateError):
                        journal.commit(
                            1, "release", "A", None, expected_sequence=0
                        )
                    self.assertEqual(provider.read_floor(), 0)
                    self.assertFalse(
                        any(path.exists() for path in journal.slot_paths)
                    )

    def test_later_concurrent_floor_advance_is_a_conflict_not_provider_lie(
            self) -> None:
        class ConcurrentAdvanceProvider(MemoryFloorProvider):
            def __init__(self):
                super().__init__(0)
                self.advance_before_confirmation = False

            def compare_and_advance(self, expected: int, new: int) -> bool:
                advanced = super().compare_and_advance(expected, new)
                if advanced:
                    self.advance_before_confirmation = True
                return advanced

            def read_floor(self) -> int:
                if self.advance_before_confirmation:
                    self.advance_before_confirmation = False
                    if not super().compare_and_advance(1, 2):
                        raise AssertionError("simulated concurrent CAS failed")
                return super().read_floor()

        with tempfile.TemporaryDirectory() as temporary:
            provider = ConcurrentAdvanceProvider()
            journal = RollbackJournal(
                Path(temporary) / "boot-state", provider
            )
            with self.assertRaises(JournalConflictError):
                journal.commit(
                    1, "release", "A", None, expected_sequence=0
                )
            self.assertEqual(provider.read_floor(), 2)
            self.assertFalse(any(path.exists() for path in journal.slot_paths))

    def test_retry_revalidates_floor_before_journal_publication(self) -> None:
        class AdvanceOnConfirmationProvider(MemoryFloorProvider):
            def __init__(self):
                super().__init__(1)
                self.reads = 0

            def read_floor(self) -> int:
                with self._lock:
                    self.reads += 1
                    if self.reads == 2:
                        self._floor = 2
                    return self._floor

        with tempfile.TemporaryDirectory() as temporary:
            provider = AdvanceOnConfirmationProvider()
            journal = RollbackJournal(
                Path(temporary) / "boot-state", provider
            )
            with self.assertRaises(PolicyError):
                journal.commit(
                    1, "recovery", "A", None, expected_sequence=0
                )
            self.assertEqual(provider.read_floor(), 2)
            self.assertFalse(any(path.exists() for path in journal.slot_paths))

    def test_false_provider_cas_reconciles_unchanged_and_later_floors(
            self) -> None:
        class RefusingProvider(MemoryFloorProvider):
            def compare_and_advance(self, expected: int, new: int) -> bool:
                return False

        class RacedProvider(MemoryFloorProvider):
            def compare_and_advance(self, expected: int, new: int) -> bool:
                with self._lock:
                    self._floor = new + 1
                    return False

        for provider_type, expected_error in (
                (RefusingProvider, JournalConflictError),
                (RacedProvider, PolicyError)):
            with self.subTest(provider=provider_type.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    provider = provider_type(0)
                    journal = RollbackJournal(
                        Path(temporary) / "boot-state", provider
                    )
                    with self.assertRaises(expected_error):
                        journal.commit(
                            1, "release", "A", None, expected_sequence=0
                        )
                    self.assertFalse(
                        any(path.exists() for path in journal.slot_paths)
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)

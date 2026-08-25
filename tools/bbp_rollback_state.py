#!/usr/bin/env python3
"""Durable A/B journal for the experimental BBP boot-generation model."""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from typing import Iterator


SCHEMA = "bbp-durable-boot-state"
VERSION = 1
UINT64_MAX = (1 << 64) - 1
ROLES = ("release", "recovery")
BOOT_SLOTS = ("A", "B")


class RollbackStateError(Exception):
    """Base class for rollback state failures."""


class PolicyError(RollbackStateError):
    """A generation or artifact role violates rollback policy."""


class JournalConflictError(RollbackStateError):
    """The caller's expected journal sequence is stale."""


class CorruptJournalError(RollbackStateError):
    """No authoritative state can be recovered from the journal."""


class FloorProvider(ABC):
    """Abstract monotonic authority; implementations define their trust model."""

    @abstractmethod
    def read_floor(self) -> int:
        """Return the currently established generation floor."""

    @abstractmethod
    def compare_and_advance(self, expected: int, new: int) -> bool:
        """Atomically advance expected to expected + 1, or report a conflict."""


class MemoryFloorProvider(FloorProvider):
    """Thread-safe injected provider for hosted tests, not durable hardware."""

    def __init__(self, floor: int = 0):
        _uint64(floor, "floor")
        self._floor = floor
        self._lock = threading.Lock()

    def read_floor(self) -> int:
        with self._lock:
            return self._floor

    def compare_and_advance(self, expected: int, new: int) -> bool:
        _uint64(expected, "expected floor")
        _uint64(new, "new floor")
        if expected == UINT64_MAX or new != expected + 1:
            return False
        with self._lock:
            if self._floor != expected:
                return False
            self._floor = new
            return True


@dataclass(frozen=True)
class BootState:
    sequence: int
    generation: int
    active_slot: str | None
    pending_slot: str | None
    schema: str = SCHEMA
    version: int = VERSION


def _uint64(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{label} must fit in uint64")
    return value


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorruptJournalError(f"duplicate journal member: {key}")
        result[key] = value
    return result


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _payload(state: BootState) -> dict:
    return {
        "active_slot": state.active_slot,
        "generation": state.generation,
        "pending_slot": state.pending_slot,
        "schema": state.schema,
        "sequence": state.sequence,
        "version": state.version,
    }


def _record_bytes(state: BootState) -> bytes:
    payload = _payload(state)
    record = dict(payload)
    record["sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return _canonical(record)


def _validate_slots(active_slot: object, pending_slot: object,
                    allow_unset: bool = False) -> None:
    if allow_unset and active_slot is None and pending_slot is None:
        return
    if active_slot not in BOOT_SLOTS:
        raise ValueError("active_slot must be A or B")
    if pending_slot is not None and pending_slot not in BOOT_SLOTS:
        raise ValueError("pending_slot must be A, B, or null")
    if pending_slot == active_slot:
        raise ValueError("active_slot and pending_slot must differ")


def _policy(floor: int, generation: int, role: str) -> str:
    if role not in ROLES:
        raise PolicyError("artifact role must be release or recovery")
    if floor == UINT64_MAX and generation != floor:
        raise PolicyError("generation floor is exhausted")
    if generation < floor:
        raise PolicyError("generation is below the monotonic floor")
    if generation == floor:
        return "retry"
    if generation - floor != 1:
        raise PolicyError("generation gap is not permitted")
    if role == "recovery":
        raise PolicyError("recovery artifacts cannot advance the floor")
    return "update"


class RollbackJournal:
    """Two-record journal whose authority is bounded by an injected floor."""

    MAX_RECORD_BYTES = 1024

    def __init__(self, path: str | os.PathLike[str],
                 floor_provider: FloorProvider):
        self.path = Path(path)
        self.floor_provider = floor_provider
        self.slot_paths = (Path(f"{self.path}.a"), Path(f"{self.path}.b"))
        self.lock_path = Path(f"{self.path}.lock")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_slot(self, path: Path) -> BootState | None:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise CorruptJournalError(f"journal slot is not regular: {path}")
            if metadata.st_size <= 0 or metadata.st_size > self.MAX_RECORD_BYTES:
                raise CorruptJournalError(f"journal slot has invalid extent: {path}")
            chunks = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if remaining or os.read(fd, 1):
                raise CorruptJournalError(f"journal slot extent changed: {path}")
        finally:
            os.close(fd)

        try:
            record = json.loads(data.decode("ascii"), object_pairs_hook=_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CorruptJournalError(f"invalid journal JSON: {path}") from error
        expected_keys = {
            "active_slot", "generation", "pending_slot", "schema", "sequence",
            "sha256", "version",
        }
        if not isinstance(record, dict) or set(record) != expected_keys:
            raise CorruptJournalError(f"invalid journal schema members: {path}")
        if record.get("schema") != SCHEMA or record.get("version") != VERSION:
            raise CorruptJournalError(f"unsupported journal schema: {path}")
        try:
            sequence = _uint64(record.get("sequence"), "sequence")
            generation = _uint64(record.get("generation"), "generation")
            _validate_slots(record.get("active_slot"), record.get("pending_slot"))
        except ValueError as error:
            raise CorruptJournalError(f"invalid journal value: {path}") from error
        if sequence == 0:
            raise CorruptJournalError(f"persisted journal sequence must be positive: {path}")
        state = BootState(
            sequence=sequence,
            generation=generation,
            active_slot=record["active_slot"],
            pending_slot=record["pending_slot"],
        )
        digest = record.get("sha256")
        expected_digest = hashlib.sha256(_canonical(_payload(state))).hexdigest()
        if not isinstance(digest, str) or digest != expected_digest:
            raise CorruptJournalError(f"journal integrity failure: {path}")
        if data != _record_bytes(state):
            raise CorruptJournalError(f"journal encoding or extent is not canonical: {path}")
        return state

    def _load_unlocked(self, floor: int) -> BootState:
        valid = []
        present = 0
        for path in self.slot_paths:
            try:
                state = self._read_slot(path)
            except (CorruptJournalError, OSError):
                present += 1
                continue
            if state is not None:
                present += 1
                valid.append(state)
        if not valid:
            if present:
                raise CorruptJournalError("both rollback journal slots are unusable")
            return BootState(0, floor, None, None)

        highest_sequence = max(state.sequence for state in valid)
        newest = [state for state in valid if state.sequence == highest_sequence]
        if len(newest) > 1 and newest[0] != newest[1]:
            raise CorruptJournalError("journal slots conflict at the same sequence")
        state = newest[0]
        if state.generation > floor:
            raise CorruptJournalError("journal generation exceeds monotonic authority")
        if state.generation < floor:
            state = replace(
                state, generation=floor, active_slot=None, pending_slot=None
            )
        return state

    def load(self) -> BootState:
        with self._locked():
            floor = _uint64(self.floor_provider.read_floor(), "provider floor")
            return self._load_unlocked(floor)

    def _write_slot(self, path: Path, state: BootState) -> None:
        data = _record_bytes(state)
        if len(data) > self.MAX_RECORD_BYTES:
            raise RollbackStateError("journal record exceeds exact file bound")
        directory = path.parent
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=directory
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as destination:
                destination.write(data)
                destination.flush()
                os.fsync(destination.fileno())
            fd = -1
            os.replace(temporary, path)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(directory, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def commit(self, generation: int, role: str, active_slot: str,
               pending_slot: str | None, *, expected_sequence: int) -> BootState:
        generation = _uint64(generation, "generation")
        expected_sequence = _uint64(expected_sequence, "expected sequence")
        _validate_slots(active_slot, pending_slot)

        with self._locked():
            while True:
                floor = _uint64(self.floor_provider.read_floor(), "provider floor")
                current = self._load_unlocked(floor)
                if current.sequence != expected_sequence:
                    raise JournalConflictError(
                        f"expected sequence {expected_sequence}, found {current.sequence}"
                    )
                if current.sequence == UINT64_MAX:
                    raise PolicyError("journal sequence is exhausted")
                action = _policy(floor, generation, role)
                if action == "retry":
                    break
                if self.floor_provider.compare_and_advance(floor, generation):
                    break
                if self.floor_provider.read_floor() == floor:
                    raise JournalConflictError("floor provider refused compare-and-advance")

            state = BootState(
                sequence=current.sequence + 1,
                generation=generation,
                active_slot=active_slot,
                pending_slot=pending_slot,
            )
            self._write_slot(self.slot_paths[state.sequence % 2], state)
            return state

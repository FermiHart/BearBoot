#!/usr/bin/env python3
"""Experimental authenticated envelope for offline BBP v2 capsules."""
import hashlib
import hmac
import json
import os
import struct
import tempfile
import fcntl

MAGIC = b"BBP2AUTH"
HEADER = struct.Struct("<8sHHIQQ16s32s")
VERSION = 1
ALG_HMAC_SHA256 = 1
STATE_VERSION = 1
MAX_CAPSULE_SIZE = 64 * 1024 * 1024
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
V2_HEADER = struct.Struct("<8sHHHHIIQQQQQ")
V2_DIRENT = struct.Struct("<QIHHQQQII")
V2_MAGIC = b"BBP2CAP\0"


def _crc64_table():
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 if crc & 1 else 0)
        table.append(crc)
    return tuple(table)


CRC64_TABLE = _crc64_table()


class EnvelopeError(ValueError):
    pass


def key_id(key):
    return hashlib.sha256(key).digest()[:16]


def seal(payload, key, rollback_index):
    if not isinstance(payload, bytes) or len(payload) > MAX_CAPSULE_SIZE:
        raise EnvelopeError("invalid capsule extent")
    if not isinstance(key, bytes) or not key or not _uint64(rollback_index):
        raise EnvelopeError("invalid key or rollback index")
    prefix = HEADER.pack(MAGIC, VERSION, ALG_HMAC_SHA256, 0, rollback_index,
                         len(payload), key_id(key), bytes(32))
    tag = hmac.new(key, prefix + payload, hashlib.sha256).digest()
    return prefix[:-32] + tag + payload


def verify(envelope, keys, minimum_rollback=0):
    if not isinstance(envelope, bytes) or len(envelope) < HEADER.size:
        raise EnvelopeError("truncated envelope")
    if len(envelope) - HEADER.size > MAX_CAPSULE_SIZE:
        raise EnvelopeError("capsule extent exceeds limit")
    if not _uint64(minimum_rollback):
        raise EnvelopeError("invalid rollback policy range")
    magic, version, algorithm, flags, rollback, size, identity, tag = \
        HEADER.unpack_from(envelope)
    if magic != MAGIC or version != VERSION or algorithm != ALG_HMAC_SHA256 or flags:
        raise EnvelopeError("unsupported envelope framing")
    if size != len(envelope) - HEADER.size:
        raise EnvelopeError("payload extent mismatch")
    if rollback < minimum_rollback:
        raise EnvelopeError("rollback policy rejected envelope")
    if not hasattr(keys, "get"):
        raise EnvelopeError("invalid key store")
    key = keys.get(identity.hex())
    if (not isinstance(key, bytes) or not key
            or not hmac.compare_digest(identity, key_id(key))):
        raise EnvelopeError("unknown key identity")
    unsigned = envelope[:HEADER.size - 32] + bytes(32) + envelope[HEADER.size:]
    expected = hmac.new(key, unsigned, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise EnvelopeError("authentication failed")
    payload = envelope[HEADER.size:]
    _validate_v2_capsule(payload)
    return payload, rollback, identity.hex()


def _uint64(value):
    return isinstance(value, int) and not isinstance(value, bool) \
        and 0 <= value <= UINT64_MAX


def _crc64(data):
    crc = UINT64_MAX
    for byte in data:
        crc = CRC64_TABLE[(crc ^ byte) & 0xff] ^ (crc >> 8)
    return crc ^ UINT64_MAX


def _validate_v2_capsule(capsule):
    if len(capsule) < V2_HEADER.size or len(capsule) > MAX_CAPSULE_SIZE:
        raise EnvelopeError("invalid BBP v2 capsule extent")
    fields = V2_HEADER.unpack_from(capsule)
    (magic, major, minor, header_size, entry_size, flags, count, total_size,
     directory_offset, checksum, reserved0, reserved1) = fields
    if magic != V2_MAGIC or major != 2 or minor != 0:
        raise EnvelopeError("invalid BBP v2 capsule framing")
    if (header_size != V2_HEADER.size or entry_size != V2_DIRENT.size
            or flags or reserved0 or reserved1 or count > 1024):
        raise EnvelopeError("invalid BBP v2 capsule framing")
    if total_size != len(capsule):
        raise EnvelopeError("invalid BBP v2 capsule extent")
    if directory_offset & 7:
        raise EnvelopeError("invalid BBP v2 capsule alignment")
    if count == 0 and (directory_offset != V2_HEADER.size
                       or total_size != V2_HEADER.size):
        raise EnvelopeError("invalid BBP v2 capsule framing")
    directory_size = count * V2_DIRENT.size
    if (directory_offset < V2_HEADER.size or directory_offset > total_size
            or directory_size > total_size - directory_offset):
        raise EnvelopeError("invalid BBP v2 capsule directory")

    spans = [(0, V2_HEADER.size)]
    if count:
        spans.append((directory_offset, directory_size))
    payload_work = total_size
    payload_checksums = []
    for index in range(count):
        offset = directory_offset + index * V2_DIRENT.size
        (_, _, _, entry_reserved, payload_offset, payload_size,
         payload_checksum, alignment, tail_reserved) = \
            V2_DIRENT.unpack_from(capsule, offset)
        if entry_reserved or tail_reserved or payload_size == 0:
            raise EnvelopeError("invalid BBP v2 capsule entry")
        if (alignment == 0 or alignment > 4096
                or alignment & (alignment - 1)
                or payload_offset & (alignment - 1)):
            raise EnvelopeError("invalid BBP v2 capsule alignment")
        if (payload_offset > total_size
                or payload_size > total_size - payload_offset):
            raise EnvelopeError("invalid BBP v2 capsule extent")
        if payload_work + payload_size > 96 * 1024 * 1024:
            raise EnvelopeError("BBP v2 capsule work limit exceeded")
        for prior_offset, prior_size in spans:
            if (payload_offset < prior_offset + prior_size
                    and prior_offset < payload_offset + payload_size):
                raise EnvelopeError("overlapping BBP v2 capsule spans")
        spans.append((payload_offset, payload_size))
        payload_checksums.append((payload_offset, payload_size,
                                  payload_checksum))
        payload_work += payload_size

    cursor = 0
    for offset, size in sorted(spans):
        if offset > cursor and any(capsule[cursor:offset]):
            raise EnvelopeError("nonzero BBP v2 capsule padding")
        cursor = offset + size
    if cursor < total_size and any(capsule[cursor:]):
        raise EnvelopeError("nonzero BBP v2 capsule padding")
    unsigned = capsule[:40] + bytes(8) + capsule[48:]
    if _crc64(unsigned) != checksum:
        raise EnvelopeError("invalid BBP v2 capsule checksum")
    for offset, size, expected in payload_checksums:
        if _crc64(capsule[offset:offset + size]) != expected:
            raise EnvelopeError("invalid BBP v2 payload checksum")


def _load_state(state_path):
    if not os.path.exists(state_path):
        return None
    try:
        with open(state_path, encoding="ascii") as source:
            state = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EnvelopeError("invalid rollback state") from error
    if (not isinstance(state, dict)
            or type(state.get("version")) is not int
            or state["version"] != STATE_VERSION
            or not _uint64(state.get("highest_rollback"))
            or not isinstance(state.get("accepted_key"), str)
            or len(state["accepted_key"]) != 32
            or any(character not in "0123456789abcdef"
                   for character in state["accepted_key"])):
        raise EnvelopeError("invalid rollback state")
    return state


def verify_and_commit(envelope, keys, state_path, policy=None):
    directory = os.path.dirname(os.path.abspath(state_path))
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(f"{state_path}.lock", lock_flags, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = _load_state(state_path)
        if state is None:
            minimum_rollback = 0
        else:
            if state["highest_rollback"] == UINT64_MAX:
                raise EnvelopeError("rollback index exhausted")
            minimum_rollback = state["highest_rollback"] + 1
        payload, rollback, identity = verify(envelope, keys, minimum_rollback)
        if policy is not None and not policy(payload, rollback, identity):
            raise EnvelopeError("policy rejected envelope")
        state = {"version": STATE_VERSION, "highest_rollback": rollback,
                 "accepted_key": identity}
        fd, temporary = tempfile.mkstemp(prefix=".bbp-v2-state-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as destination:
                json.dump(state, destination, sort_keys=True)
                destination.write("\n")
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, state_path)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(directory, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    finally:
        os.close(lock_fd)
    return payload

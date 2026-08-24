#!/usr/bin/env python3
"""Experimental authenticated envelope for offline BBP v2 capsules."""
import hashlib
import hmac
import json
import os
import struct
import tempfile

MAGIC = b"BBP2AUTH"
HEADER = struct.Struct("<8sHHIQQ16s32s")
VERSION = 1
ALG_HMAC_SHA256 = 1


class EnvelopeError(ValueError):
    pass


def key_id(key):
    return hashlib.sha256(key).digest()[:16]


def seal(payload, key, rollback_index):
    if not key or rollback_index < 0 or rollback_index > 0xFFFFFFFFFFFFFFFF:
        raise EnvelopeError("invalid key or rollback index")
    prefix = HEADER.pack(MAGIC, VERSION, ALG_HMAC_SHA256, 0, rollback_index,
                         len(payload), key_id(key), bytes(32))
    tag = hmac.new(key, prefix + payload, hashlib.sha256).digest()
    return prefix[:-32] + tag + payload


def verify(envelope, keys, minimum_rollback=0):
    if len(envelope) < HEADER.size:
        raise EnvelopeError("truncated envelope")
    magic, version, algorithm, flags, rollback, size, identity, tag = \
        HEADER.unpack_from(envelope)
    if magic != MAGIC or version != VERSION or algorithm != ALG_HMAC_SHA256 or flags:
        raise EnvelopeError("unsupported envelope framing")
    if size != len(envelope) - HEADER.size:
        raise EnvelopeError("payload extent mismatch")
    if rollback < minimum_rollback:
        raise EnvelopeError("rollback policy rejected envelope")
    key = keys.get(identity.hex())
    if key is None or not hmac.compare_digest(identity, key_id(key)):
        raise EnvelopeError("unknown key identity")
    unsigned = envelope[:HEADER.size - 32] + bytes(32) + envelope[HEADER.size:]
    expected = hmac.new(key, unsigned, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise EnvelopeError("authentication failed")
    return envelope[HEADER.size:], rollback, identity.hex()


def verify_and_commit(envelope, keys, state_path):
    state = {}
    if os.path.exists(state_path):
        with open(state_path, encoding="ascii") as source:
            state = json.load(source)
    payload, rollback, identity = verify(
        envelope, keys, int(state.get("highest_rollback", -1)) + 1)
    state = {"highest_rollback": rollback, "accepted_key": identity}
    directory = os.path.dirname(os.path.abspath(state_path))
    fd, temporary = tempfile.mkstemp(prefix=".bbp-v2-state-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as destination:
            json.dump(state, destination, sort_keys=True)
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, state_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return payload

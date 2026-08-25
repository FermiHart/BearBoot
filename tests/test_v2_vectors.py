#!/usr/bin/env python3
"""Shared BBP v2 corpus consumed independently by Python and C."""
import ctypes
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.bbp_v2_envelope import EnvelopeError, _validate_v2_capsule

MAGIC = b"BBP2CAP\0"
HEADER = struct.Struct("<8sHHHHIIQQQQQ")
DIRENT = struct.Struct("<QIHHQQQII")
CORPUS = ROOT / "tests/vectors/bbp-v2-corpus-v1.txt"
GENERIC_C_STATUS = {
    "generic_negative_count_cap": 7,
    "generic_negative_directory_alignment": 8,
    "generic_negative_directory_bounds": 6,
    "generic_negative_entry_reserved": 4,
    "generic_negative_header_framing": 4,
    "generic_negative_header_reserved": 4,
    "generic_negative_invalid_alignment": 8,
    "generic_negative_magic": 2,
    "generic_negative_nonzero_padding": 10,
    "generic_negative_payload_crc": 11,
    "generic_negative_payload_out_of_bounds": 6,
    "generic_negative_payload_overlap": 9,
    "generic_negative_version": 3,
    "generic_negative_whole_capsule_crc": 11,
    "generic_negative_zero_payload": 4,
}
TYPES = [0x4242503200000001, 0x4242503200000002,
         0x4242503200000003, 0x4242503200000004]
PAYLOADS = [
    struct.pack("<HHIII", 2, 0, 1, 0, 0),
    struct.pack("<IIQQIIII", 1, 32, 0x100000, 0x200000, 1, 0, 0, 0),
    struct.pack("<QQ", 0x40080000, 0xFFFFFFFF80000000),
    struct.pack("<II", 0, 4) + b"\xd0\x0d\xfe\xed",
]


def crc64(data):
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFFFFFFFFFF


def capsule(directory_offset, reverse_layout=False):
    directory_size = 48 * len(PAYLOADS)
    cursor = (directory_offset + directory_size + 7) & ~7
    offsets = []
    order = reversed(PAYLOADS) if reverse_layout else PAYLOADS
    regions = []
    for payload in order:
        offsets.append((payload, cursor))
        cursor = (cursor + len(payload) + 7) & ~7
    location = {payload: offset for payload, offset in offsets}
    raw = bytearray(cursor)
    struct.pack_into("<8sHHHHIIQQQQQ", raw, 0, MAGIC, 2, 0, 64, 48, 0,
                     len(PAYLOADS), len(raw), directory_offset, 0, 0, 0)
    for index, (type_id, payload) in enumerate(zip(TYPES, PAYLOADS)):
        struct.pack_into("<QIHHQQQII", raw, directory_offset + index * 48,
                         type_id, 0, 1, 0, location[payload], len(payload),
                         crc64(payload), 8, 0)
        raw[location[payload]:location[payload] + len(payload)] = payload
    sealed = raw[:]
    sealed[40:48] = b"\0" * 8
    struct.pack_into("<Q", raw, 40, crc64(sealed))
    return bytes(raw)


class View(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("total_size", ctypes.c_size_t),
                ("directory_offset", ctypes.c_size_t), ("flags", ctypes.c_uint32),
                ("entry_count", ctypes.c_uint32)]


class Profile(ctypes.Structure):
    _fields_ = [("architecture", ctypes.c_uint16), ("cpu_count", ctypes.c_uint32),
                ("memory_entry_count", ctypes.c_uint32),
                ("kernel_physical_base", ctypes.c_uint64),
                ("kernel_virtual_base", ctypes.c_uint64), ("dtb", ctypes.c_void_p),
                ("dtb_size", ctypes.c_uint32)]

DigestCallback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t)


def load_corpus():
    version = None
    cases = {}
    for line_number, raw_line in enumerate(CORPUS.read_text(encoding="ascii").splitlines(), 1):
        if not raw_line or raw_line.startswith("#"):
            continue
        if version is None:
            assert raw_line == "bbp-v2-corpus-v1", (line_number, raw_line)
            version = raw_line
            continue
        fields = raw_line.split("\t")
        assert len(fields) == 11, (line_number, len(fields))
        name = fields[0]
        assert name not in cases
        cases[name] = fields[1:]
    assert version is not None and cases
    return cases


def entries(raw):
    (_, major, minor, _, _, flags, count, _, directory_offset, _, _, _) = \
        HEADER.unpack_from(raw)
    result = []
    for index in range(count):
        frame = DIRENT.unpack_from(raw, directory_offset + index * DIRENT.size)
        entry_type, entry_flags, version = frame[:3]
        offset, size = frame[4:6]
        result.append((entry_type, entry_flags, version, raw[offset:offset + size]))
    return major, minor, flags, result


def entry_offset(raw, target_type):
    count = struct.unpack_from("<I", raw, 20)[0]
    directory_offset = struct.unpack_from("<Q", raw, 32)[0]
    for index in range(count):
        frame = DIRENT.unpack_from(raw, directory_offset + index * DIRENT.size)
        if frame[0] == target_type:
            return frame[4]
    raise AssertionError(f"missing entry type {target_type:#x}")


def semantic_digest(raw):
    major, minor, flags, parsed = entries(raw)
    digest = hashlib.sha256()
    digest.update(b"BBP-V2-DIGEST\0\0\x01")
    digest.update(struct.pack("<HHIII", major, minor, flags, len(parsed), 0))
    for entry_type, entry_flags, version, payload in parsed:
        digest.update(struct.pack("<QIHHQQ", entry_type, entry_flags, version,
                                  0, len(payload), 0))
        digest.update(payload)
    return digest.hexdigest()


def profile0(raw):
    _, _, _, parsed = entries(raw)
    recognized = {type_id: 1 << index for index, type_id in enumerate(TYPES)}
    seen = 0
    architecture = cpu_count = memory_count = 0
    kernel_physical = kernel_virtual = 0
    dtb = b""
    for entry_type, flags, version, payload in parsed:
        bit = recognized.get(entry_type, 0)
        if not bit:
            continue
        if seen & bit or flags or version != 1:
            raise ValueError("recognized entry framing")
        seen |= bit
        if bit == 1:
            if len(payload) != 16:
                raise ValueError("identity size")
            architecture, reserved0, cpu_count, identity_flags, reserved1 = \
                struct.unpack("<HHIII", payload)
            if not 1 <= architecture <= 4 or reserved0 or cpu_count == 0 \
                    or identity_flags or reserved1:
                raise ValueError("identity values")
        elif bit == 2:
            if len(payload) < 8:
                raise ValueError("memory header")
            memory_count, stride = struct.unpack_from("<II", payload)
            if memory_count == 0 or memory_count > 4096 or stride != 32 \
                    or len(payload) != 8 + memory_count * stride:
                raise ValueError("memory framing")
            for offset in range(8, len(payload), stride):
                base, length, memory_type, _, _, reserved = \
                    struct.unpack_from("<QQIIII", payload, offset)
                if length == 0 or base + length > 0xffffffffffffffff \
                        or memory_type == 0 or reserved:
                    raise ValueError("memory record")
        elif bit == 4:
            if len(payload) != 16:
                raise ValueError("kernel size")
            kernel_physical, kernel_virtual = struct.unpack("<QQ", payload)
            if kernel_physical == 0:
                raise ValueError("kernel physical base")
        else:
            if len(payload) <= 8:
                raise ValueError("Device Tree empty")
            dtb_flags, dtb_size = struct.unpack_from("<II", payload)
            if dtb_flags or dtb_size != len(payload) - 8:
                raise ValueError("Device Tree framing")
            dtb = payload[8:]
    if seen != 15:
        raise ValueError("missing recognized entry")
    return (architecture, cpu_count, memory_count, kernel_physical,
            kernel_virtual, dtb)


def c_digest(lib, view):
    digest = hashlib.sha256()
    callback = DigestCallback(
        lambda _state, data, size: digest.update(ctypes.string_at(data, size)))
    assert lib.bbp_v2_digest(ctypes.byref(view), callback, None) == 0
    return digest.hexdigest()


def check_case(lib, name, fields):
    (generic_expect, profile_expect, expected_digest, architecture, cpu_count,
     memory_count, kernel_physical, kernel_virtual, dtb_hex,
     capsule_hex) = fields
    raw = bytes.fromhex(capsule_hex)
    backing = ctypes.create_string_buffer(raw)
    view = View()
    ctypes.memset(ctypes.byref(view), 0xa5, ctypes.sizeof(view))
    view_before = bytes(view)
    status = lib.bbp_v2_parse(backing, len(raw), ctypes.byref(view))

    try:
        _validate_v2_capsule(raw)
        python_generic = "ok"
    except EnvelopeError:
        python_generic = "reject"
    assert python_generic == generic_expect, name
    assert (status == 0) == (generic_expect == "ok"), (name, status)
    if generic_expect == "reject":
        if name in GENERIC_C_STATUS:
            assert status == GENERIC_C_STATUS[name], (name, status)
        assert bytes(view) == view_before, name
        assert profile_expect == "skip"
        return

    assert view.data == ctypes.addressof(backing), name
    assert semantic_digest(raw) == expected_digest, name
    assert c_digest(lib, view) == expected_digest, name
    profile = Profile()
    ctypes.memset(ctypes.byref(profile), 0xa5, ctypes.sizeof(profile))
    profile_before = bytes(profile)
    status = lib.bbp_v2_p0_validate(ctypes.byref(view), ctypes.byref(profile))
    try:
        python_profile = profile0(raw)
        python_profile_status = "ok"
    except ValueError:
        python_profile = None
        python_profile_status = "reject"
    assert python_profile_status == profile_expect, name
    assert (status == 0) == (profile_expect == "ok"), (name, status)
    if profile_expect == "reject":
        assert bytes(profile) == profile_before, name
        return

    expected = (int(architecture), int(cpu_count), int(memory_count),
                int(kernel_physical, 16), int(kernel_virtual, 16),
                bytes.fromhex(dtb_hex))
    actual = (profile.architecture, profile.cpu_count,
              profile.memory_entry_count, profile.kernel_physical_base,
              profile.kernel_virtual_base,
              ctypes.string_at(profile.dtb, profile.dtb_size))
    dtb_offset = entry_offset(raw, TYPES[3])
    assert profile.dtb == ctypes.addressof(backing) + dtb_offset + 8, name
    assert python_profile == expected, name
    assert actual == expected, name


def main():
    lib = ctypes.CDLL(sys.argv[1])
    lib.bbp_v2_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(View)]
    lib.bbp_v2_p0_validate.argtypes = [ctypes.POINTER(View), ctypes.POINTER(Profile)]
    lib.bbp_v2_digest.argtypes = [ctypes.POINTER(View), DigestCallback,
                                   ctypes.c_void_p]
    cases = load_corpus()
    assert bytes.fromhex(cases["positive_auth_padded_canonical"][-1]) == capsule(64)
    assert bytes.fromhex(cases["positive_relocated_reversed_layout"][-1]) == \
        capsule(96, True)
    for name, fields in cases.items():
        check_case(lib, name, fields)
    print(f"BBP v2 shared Python/C corpus: PASS ({len(cases)} cases)")


if __name__ == "__main__":
    main()

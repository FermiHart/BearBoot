#!/usr/bin/env python3
"""Independent Python encoder vectors consumed by the C v2 parser."""
import ctypes
import hashlib
import struct
import sys

MAGIC = b"BBP2CAP\0"
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


def check(lib, raw):
    backing = ctypes.create_string_buffer(raw)
    view, profile = View(), Profile()
    assert lib.bbp_v2_parse(backing, len(raw), ctypes.byref(view)) == 0
    assert lib.bbp_v2_p0_validate(ctypes.byref(view), ctypes.byref(profile)) == 0
    assert (profile.architecture, profile.cpu_count, profile.memory_entry_count) == (2, 1, 1)
    assert profile.kernel_physical_base == 0x40080000 and profile.dtb_size == 4
    digest = hashlib.sha256()
    callback = DigestCallback(
        lambda _state, data, size: digest.update(ctypes.string_at(data, size)))
    assert lib.bbp_v2_digest(ctypes.byref(view), callback, None) == 0
    assert digest.hexdigest() == "11ab3341860b1a81de19319922a0697ba0c422534902c3ae8aaf5b6950334b28"


def main():
    lib = ctypes.CDLL(sys.argv[1])
    lib.bbp_v2_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(View)]
    lib.bbp_v2_p0_validate.argtypes = [ctypes.POINTER(View), ctypes.POINTER(Profile)]
    lib.bbp_v2_digest.argtypes = [ctypes.POINTER(View), DigestCallback,
                                  ctypes.c_void_p]
    canonical = capsule(64)
    relocated = capsule(96, True)
    check(lib, canonical)
    check(lib, relocated)
    broken = bytearray(canonical)
    broken[-1] ^= 1
    view = View()
    backing = ctypes.create_string_buffer(bytes(broken))
    assert lib.bbp_v2_parse(backing, len(broken), ctypes.byref(view)) != 0
    print("BBP v2 independent Python/C vectors: PASS")


if __name__ == "__main__":
    main()

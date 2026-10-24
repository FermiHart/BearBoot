#!/usr/bin/env python3
"""Generate the deterministic BBP v2.0 shared conformance corpus."""

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


MAGIC = b"BBP2CAP\0"
HEADER = struct.Struct("<8sHHHHIIQQQQQ")
DIRENT = struct.Struct("<QIHHQQQII")
HEADER_SIZE = 64
DIRENT_SIZE = 48
MAX_ENTRIES = 1024
MAX_ALIGNMENT = 4096
MAX_EXTENT = 64 * 1024 * 1024
MAX_CRC_WORK = 96 * 1024 * 1024
UINT64_MAX = (1 << 64) - 1

P0_IDENTITY = 0x4242503200000001
P0_MEMORY = 0x4242503200000002
P0_KERNEL = 0x4242503200000003
P0_DTB = 0x4242503200000004
P0_VERSION = 1

DOMAIN = b"BBP-V2-DIGEST\0\0\x01"
NAME_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
HEX_RE = re.compile(r"(?:[0-9a-f]{2})*\Z")

ROOT = Path(__file__).resolve().parents[1]
ROOT_CORPUS = ROOT / "tests/vectors/bbp-v2-corpus-v1.txt"
AUTH_VECTOR = ROOT / "tests/vectors/bbp-v2-profile0-auth-v1.json"


class InvalidCapsule(ValueError):
    """Raised by the generator's independent validators."""


@dataclass(frozen=True)
class Entry:
    entry_type: int
    payload: bytes
    flags: int = 0
    version: int = P0_VERSION
    alignment: int = 8


@dataclass(frozen=True)
class ParsedEntry:
    entry_type: int
    flags: int
    version: int
    offset: int
    payload: bytes


@dataclass(frozen=True)
class Case:
    name: str
    generic: str
    profile0: str
    digest: str
    architecture: str
    cpu_count: str
    memory_entry_count: str
    kernel_physical: str
    kernel_virtual: str
    dtb_hex: str
    capsule_hex: str


def crc64_xz(data):
    """CRC-64/XZ, reflected polynomial, all-one init and final XOR."""
    crc = UINT64_MAX
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 if crc & 1 else 0)
    return crc ^ UINT64_MAX


def reseal_capsule(capsule):
    sealed = bytearray(capsule)
    sealed[40:48] = bytes(8)
    struct.pack_into("<Q", sealed, 40, crc64_xz(sealed))
    return bytes(sealed)


def build_capsule(entries, *, directory_offset=HEADER_SIZE, payload_offsets=None,
                  final_padding=0, allow_oversized_count=False):
    """Encode a capsule without using any project parser or encoder."""
    count = len(entries)
    if count > MAX_ENTRIES and not allow_oversized_count:
        raise ValueError("too many source entries")
    directory_end = directory_offset + count * DIRENT_SIZE
    if payload_offsets is None:
        cursor = directory_end
        offsets = []
        for entry in entries:
            cursor = (cursor + entry.alignment - 1) & -entry.alignment
            offsets.append(cursor)
            cursor += len(entry.payload)
    else:
        offsets = list(payload_offsets)
        if len(offsets) != count:
            raise ValueError("payload offset count mismatch")
        cursor = max([directory_end, HEADER_SIZE] + [
            offset + len(entry.payload) for entry, offset in zip(entries, offsets)
        ])

    total_size = cursor + final_padding
    if count == 0:
        if directory_offset != HEADER_SIZE or final_padding:
            raise ValueError("invalid empty capsule layout")
        total_size = HEADER_SIZE
    capsule = bytearray(total_size)
    HEADER.pack_into(capsule, 0, MAGIC, 2, 0, HEADER_SIZE, DIRENT_SIZE, 0,
                     count, total_size, directory_offset, 0, 0, 0)

    spans = [(0, HEADER_SIZE)]
    if count:
        spans.append((directory_offset, count * DIRENT_SIZE))
    for index, (entry, offset) in enumerate(zip(entries, offsets)):
        if not entry.payload:
            raise ValueError("source payload must be nonempty")
        if (entry.alignment == 0 or entry.alignment > MAX_ALIGNMENT
                or entry.alignment & (entry.alignment - 1)
                or offset & (entry.alignment - 1)):
            raise ValueError("invalid source alignment")
        span = (offset, len(entry.payload))
        if any(offset < start + size and start < offset + len(entry.payload)
               for start, size in spans):
            raise ValueError("overlapping source layout")
        spans.append(span)
        capsule[offset:offset + len(entry.payload)] = entry.payload
        DIRENT.pack_into(capsule, directory_offset + index * DIRENT_SIZE,
                         entry.entry_type, entry.flags, entry.version, 0,
                         offset, len(entry.payload), crc64_xz(entry.payload),
                         entry.alignment, 0)
    return reseal_capsule(capsule)


def generic_validate(capsule):
    """Independently enforce the RFC 0001 parser rules used by this corpus."""
    if len(capsule) < HEADER_SIZE or len(capsule) > MAX_EXTENT:
        raise InvalidCapsule("extent")
    fields = HEADER.unpack_from(capsule)
    (magic, major, minor, header_size, entry_size, flags, count, total_size,
     directory_offset, checksum, reserved0, reserved1) = fields
    if magic != MAGIC:
        raise InvalidCapsule("magic")
    if (major, minor) != (2, 0):
        raise InvalidCapsule("version")
    if (header_size != HEADER_SIZE or entry_size != DIRENT_SIZE or flags
            or reserved0 or reserved1):
        raise InvalidCapsule("header framing")
    if total_size != len(capsule):
        raise InvalidCapsule("total extent")
    if count > MAX_ENTRIES:
        raise InvalidCapsule("count")
    if directory_offset & 7:
        raise InvalidCapsule("directory alignment")
    if count == 0 and (directory_offset != HEADER_SIZE
                       or total_size != HEADER_SIZE):
        raise InvalidCapsule("empty framing")
    directory_size = count * DIRENT_SIZE
    if (directory_offset < HEADER_SIZE or directory_offset > total_size
            or directory_size > total_size - directory_offset):
        raise InvalidCapsule("directory bounds")

    spans = [(0, HEADER_SIZE)]
    if count:
        spans.append((directory_offset, directory_size))
    parsed = []
    work = total_size
    for index in range(count):
        frame_offset = directory_offset + index * DIRENT_SIZE
        (entry_type, entry_flags, version, entry_reserved, offset, size,
         payload_checksum, alignment, tail_reserved) = DIRENT.unpack_from(
             capsule, frame_offset)
        if entry_reserved or tail_reserved or size == 0:
            raise InvalidCapsule("entry framing")
        if (alignment == 0 or alignment > MAX_ALIGNMENT
                or alignment & (alignment - 1) or offset & (alignment - 1)):
            raise InvalidCapsule("payload alignment")
        if offset > total_size or size > total_size - offset:
            raise InvalidCapsule("payload bounds")
        if any(offset < start + span_size and start < offset + size
               for start, span_size in spans):
            raise InvalidCapsule("span overlap")
        work += size
        if work > MAX_CRC_WORK:
            raise InvalidCapsule("work")
        spans.append((offset, size))
        parsed.append(ParsedEntry(entry_type, entry_flags, version, offset,
                                  capsule[offset:offset + size]))

    cursor = 0
    for offset, size in sorted(spans):
        if any(capsule[cursor:offset]):
            raise InvalidCapsule("padding")
        cursor = offset + size
    if any(capsule[cursor:]):
        raise InvalidCapsule("padding")
    unsigned = capsule[:40] + bytes(8) + capsule[48:]
    if crc64_xz(unsigned) != checksum:
        raise InvalidCapsule("capsule checksum")
    for index, entry in enumerate(parsed):
        frame_offset = directory_offset + index * DIRENT_SIZE
        expected = struct.unpack_from("<Q", capsule, frame_offset + 32)[0]
        if crc64_xz(entry.payload) != expected:
            raise InvalidCapsule("payload checksum")
    return flags, parsed


def semantic_digest(capsule):
    flags, entries = generic_validate(capsule)
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    digest.update(struct.pack("<HHIII", 2, 0, flags, len(entries), 0))
    for entry in entries:
        digest.update(struct.pack("<QIHHQQ", entry.entry_type, entry.flags,
                                  entry.version, 0, len(entry.payload), 0))
        digest.update(entry.payload)
    return digest.hexdigest()


def profile0_validate(capsule):
    _, entries = generic_validate(capsule)
    recognized = {
        P0_IDENTITY: 1,
        P0_MEMORY: 2,
        P0_KERNEL: 4,
        P0_DTB: 8,
    }
    seen = 0
    architecture = cpu_count = memory_count = 0
    kernel_physical = kernel_virtual = 0
    dtb = b""
    for entry in entries:
        bit = recognized.get(entry.entry_type, 0)
        if not bit:
            continue
        if seen & bit or entry.flags or entry.version != P0_VERSION:
            raise InvalidCapsule("recognized entry framing")
        seen |= bit
        data = entry.payload
        if bit == 1:
            if (len(data) != 16 or struct.unpack_from("<H", data, 2)[0]
                    or struct.unpack_from("<I", data, 8)[0]
                    or struct.unpack_from("<I", data, 12)[0]):
                raise InvalidCapsule("identity framing")
            architecture = struct.unpack_from("<H", data)[0]
            cpu_count = struct.unpack_from("<I", data, 4)[0]
            if not 1 <= architecture <= 4 or cpu_count == 0:
                raise InvalidCapsule("identity values")
        elif bit == 2:
            if len(data) < 8:
                raise InvalidCapsule("memory header")
            memory_count, stride = struct.unpack_from("<II", data)
            if (memory_count == 0 or memory_count > 4096 or stride != 32
                    or memory_count * 32 != len(data) - 8):
                raise InvalidCapsule("memory framing")
            for offset in range(8, len(data), 32):
                base, length, memory_type, _, _, reserved = struct.unpack_from(
                    "<QQIIII", data, offset)
                if (length == 0 or base > UINT64_MAX - length
                        or memory_type == 0 or reserved):
                    raise InvalidCapsule("memory record")
        elif bit == 4:
            if len(data) != 16:
                raise InvalidCapsule("kernel size")
            kernel_physical, kernel_virtual = struct.unpack("<QQ", data)
            if kernel_physical == 0:
                raise InvalidCapsule("kernel physical base")
        else:
            if len(data) <= 8:
                raise InvalidCapsule("Device Tree empty")
            dtb_flags, dtb_size = struct.unpack_from("<II", data)
            if dtb_flags or dtb_size != len(data) - 8:
                raise InvalidCapsule("Device Tree framing")
            dtb = data[8:]
    if seen != 15:
        raise InvalidCapsule("missing recognized entry")
    return (architecture, cpu_count, memory_count, kernel_physical,
            kernel_virtual, dtb)


def identity(architecture=2, cpu_count=1, reserved0=0, flags=0,
             reserved1=0):
    return struct.pack("<HHIII", architecture, reserved0, cpu_count, flags,
                       reserved1)


def memory_record(base=0x100000, length=0x200000, memory_type=1, attributes=0,
                  numa_node=0, reserved=0):
    return struct.pack("<QQIIII", base, length, memory_type, attributes,
                       numa_node, reserved)


def memory_payload(records=None, count=None, stride=32):
    if records is None:
        records = [memory_record()]
    if count is None:
        count = len(records)
    return struct.pack("<II", count, stride) + b"".join(records)


def kernel(physical=0x40080000, virtual=0xFFFFFFFF80000000):
    return struct.pack("<QQ", physical, virtual)


def device_tree(data=b"\xd0\x0d\xfe\xed", flags=0, declared_size=None):
    if declared_size is None:
        declared_size = len(data)
    return struct.pack("<II", flags, declared_size) + data


def profile_entries(*, identity_payload=None, memory_map=None,
                    kernel_payload=None, dtb_payload=None):
    return [
        Entry(P0_IDENTITY, identity() if identity_payload is None
              else identity_payload),
        Entry(P0_MEMORY, memory_payload() if memory_map is None else memory_map),
        Entry(P0_KERNEL, kernel() if kernel_payload is None else kernel_payload),
        Entry(P0_DTB, device_tree() if dtb_payload is None else dtb_payload),
    ]


def patch(capsule, offset, value, *, reseal=True):
    result = bytearray(capsule)
    result[offset:offset + len(value)] = value
    return reseal_capsule(result) if reseal else bytes(result)


def generic_ok_case(name, capsule, profile_expected):
    digest = semantic_digest(capsule)
    if profile_expected == "ok":
        values = profile0_validate(capsule)
        architecture, cpus, memories, physical, virtual, dtb = values
        fields = (str(architecture), str(cpus), str(memories),
                  f"0x{physical:016x}", f"0x{virtual:016x}", dtb.hex())
    elif profile_expected == "reject":
        try:
            profile0_validate(capsule)
        except InvalidCapsule:
            pass
        else:
            raise AssertionError(f"{name}: Profile 0 unexpectedly accepted")
        fields = ("-",) * 6
    else:
        raise AssertionError(f"{name}: invalid Profile 0 expectation")
    return Case(name, "ok", profile_expected, digest, *fields, capsule.hex())


def generic_reject_case(name, capsule):
    try:
        generic_validate(capsule)
    except (InvalidCapsule, struct.error):
        pass
    else:
        raise AssertionError(f"{name}: generic parser unexpectedly accepted")
    return Case(name, "reject", "skip", "-", *("-",) * 6, capsule.hex())


def make_cases():
    cases = []
    canonical_entries = profile_entries()
    canonical = build_capsule(canonical_entries, final_padding=4)
    with AUTH_VECTOR.open(encoding="ascii") as source:
        auth_capsule = bytes.fromhex(json.load(source)["capsule_hex"])
    if canonical != auth_capsule:
        mismatches = [index for index, pair in enumerate(zip(canonical, auth_capsule))
                      if pair[0] != pair[1]]
        raise AssertionError(
            "independent canonical encoding differs from auth JSON "
            f"(sizes {len(canonical)}/{len(auth_capsule)}, bytes {mismatches[:24]}, "
            f"checksums {canonical[40:48].hex()}/{auth_capsule[40:48].hex()})")

    compact = build_capsule(canonical_entries)
    relocated = build_capsule(canonical_entries, directory_offset=96,
                              payload_offsets=[360, 320, 304, 288])
    unknown = Entry(0xF00DFACE12345678, b"\x00unknown\xff", flags=0xA5A5,
                    version=0x1234, alignment=1)
    with_unknown = build_capsule(canonical_entries + [unknown])
    permissive_records = [
        memory_record(3, 16, 0xDEADBEEF, 0xFFFFFFFF, 0xABCDEF01),
        memory_record(5, 2, 0x80000000, 0x13579BDF, 0xFFFFFFFF),
    ]
    permissive = build_capsule(profile_entries(
        identity_payload=identity(4, 0xFFFFFFFF),
        memory_map=memory_payload(permissive_records),
        kernel_payload=kernel(1, 0x0123456789ABCDEF),
        dtb_payload=device_tree(b"definitely-not-an-fdt")))
    memory_limit = build_capsule(profile_entries(
        memory_map=memory_payload([memory_record()] * 4096)))
    empty = build_capsule([])

    cases.extend([
        generic_ok_case("positive_auth_padded_canonical", canonical, "ok"),
        generic_ok_case("positive_compact_no_final_padding", compact, "ok"),
        generic_ok_case("positive_generic_empty", empty, "reject"),
        generic_ok_case("positive_profile_memory_count_limit", memory_limit,
                        "ok"),
        generic_ok_case("positive_profile_permissive_values", permissive, "ok"),
        generic_ok_case("positive_profile_unknown_entry", with_unknown, "ok"),
        generic_ok_case("positive_relocated_reversed_layout", relocated, "ok"),
    ])
    canonical_digest = semantic_digest(canonical)
    if semantic_digest(compact) != canonical_digest \
            or semantic_digest(relocated) != canonical_digest:
        raise AssertionError("semantic digest changed across physical layouts")

    one = build_capsule([Entry(0x99, b"x", alignment=1)])
    two = build_capsule([Entry(0x99, b"x", alignment=1),
                         Entry(0x98, b"x", alignment=1)])
    padded = build_capsule([Entry(0x99, b"x", alignment=32)])
    excessive_count = build_capsule(
        [Entry(0x99, b"x", alignment=1)] * (MAX_ENTRIES + 1),
        allow_oversized_count=True)
    misaligned_directory = build_capsule(
        [Entry(0x99, b"x", alignment=1)], directory_offset=65)
    overlapping = bytearray(two)
    second_frame = HEADER_SIZE + DIRENT_SIZE
    second_payload = struct.unpack_from("<Q", overlapping,
                                        second_frame + 16)[0]
    first_payload = struct.unpack_from("<Q", overlapping,
                                       HEADER_SIZE + 16)[0]
    struct.pack_into("<Q", overlapping, second_frame + 16, first_payload)
    overlapping[second_payload] = 0
    overlapping = reseal_capsule(overlapping)
    generic_negatives = {
        "generic_negative_count_cap": excessive_count,
        "generic_negative_directory_alignment": misaligned_directory,
        "generic_negative_directory_bounds": patch(
            one, 32, struct.pack("<Q", 112)),
        "generic_negative_entry_reserved": patch(
            one, HEADER_SIZE + 14, struct.pack("<H", 1)),
        "generic_negative_header_framing": patch(
            one, 12, struct.pack("<H", HEADER_SIZE - 1)),
        "generic_negative_header_reserved": patch(
            one, 48, struct.pack("<Q", 1)),
        "generic_negative_invalid_alignment": patch(
            one, HEADER_SIZE + 40, struct.pack("<I", 3)),
        "generic_negative_magic": patch(one, 0, b"X"),
        "generic_negative_nonzero_padding": patch(padded, 112, b"\x01"),
        "generic_negative_payload_out_of_bounds": patch(
            one, HEADER_SIZE + 16, struct.pack("<Q", len(one))),
        "generic_negative_payload_overlap": overlapping,
        "generic_negative_version": patch(one, 8, struct.pack("<H", 3)),
        "generic_negative_zero_payload": patch(
            one, HEADER_SIZE + 24, struct.pack("<Q", 0)),
    }
    bad_whole_crc = bytearray(one)
    bad_whole_crc[40] ^= 1
    generic_negatives["generic_negative_whole_capsule_crc"] = bytes(bad_whole_crc)
    payload_offset = struct.unpack_from("<Q", one, HEADER_SIZE + 16)[0]
    bad_payload_crc = bytearray(one)
    bad_payload_crc[payload_offset] ^= 1
    generic_negatives["generic_negative_payload_crc"] = reseal_capsule(
        bad_payload_crc)
    cases.extend(generic_reject_case(name, capsule)
                 for name, capsule in generic_negatives.items())

    profile_negative_entries = {
        "profile_negative_device_tree_empty": profile_entries(
            dtb_payload=device_tree(b"")),
        "profile_negative_device_tree_flags": profile_entries(
            dtb_payload=device_tree(b"x", flags=1)),
        "profile_negative_device_tree_size_mismatch": profile_entries(
            dtb_payload=device_tree(b"x", declared_size=2)),
        "profile_negative_identity_architecture": profile_entries(
            identity_payload=identity(5)),
        "profile_negative_identity_architecture_zero": profile_entries(
            identity_payload=identity(0)),
        "profile_negative_identity_cpu_zero": profile_entries(
            identity_payload=identity(cpu_count=0)),
        "profile_negative_identity_flags": profile_entries(
            identity_payload=identity(flags=1)),
        "profile_negative_identity_reserved": profile_entries(
            identity_payload=identity(reserved0=1)),
        "profile_negative_identity_size": profile_entries(
            identity_payload=identity()[:-1]),
        "profile_negative_kernel_size": profile_entries(
            kernel_payload=kernel()[:-1]),
        "profile_negative_kernel_zero_physical_base": profile_entries(
            kernel_payload=kernel(0)),
        "profile_negative_memory_count": profile_entries(
            memory_map=memory_payload([], count=0)),
        "profile_negative_memory_count_above_limit": profile_entries(
            memory_map=memory_payload([memory_record()] * 4097)),
        "profile_negative_memory_exact_length": profile_entries(
            memory_map=memory_payload([memory_record()], count=2)),
        "profile_negative_memory_header": profile_entries(memory_map=b"\0" * 7),
        "profile_negative_memory_reserved": profile_entries(
            memory_map=memory_payload([memory_record(reserved=1)])),
        "profile_negative_memory_stride": profile_entries(
            memory_map=memory_payload(stride=31)),
        "profile_negative_memory_wrap": profile_entries(
            memory_map=memory_payload([memory_record(UINT64_MAX, 1)])),
        "profile_negative_memory_zero_length": profile_entries(
            memory_map=memory_payload([memory_record(length=0)])),
        "profile_negative_memory_zero_type": profile_entries(
            memory_map=memory_payload([memory_record(memory_type=0)])),
    }
    profile_negative_entries["profile_negative_duplicate"] = (
        canonical_entries + [canonical_entries[0]])
    profile_negative_entries["profile_negative_missing"] = canonical_entries[:-1]
    flagged = list(canonical_entries)
    flagged[0] = Entry(P0_IDENTITY, identity(), flags=1)
    profile_negative_entries["profile_negative_recognized_flags"] = flagged
    versioned = list(canonical_entries)
    versioned[0] = Entry(P0_IDENTITY, identity(), version=2)
    profile_negative_entries["profile_negative_recognized_version"] = versioned
    cases.extend(generic_ok_case(name, build_capsule(entries), "reject")
                 for name, entries in profile_negative_entries.items())

    cases.sort(key=lambda case: case.name)
    validate_cases(cases)
    return cases


def validate_cases(cases):
    names = [case.name for case in cases]
    if names != sorted(names) or len(names) != len(set(names)):
        raise AssertionError("case names must be unique and sorted")
    for case in cases:
        if not NAME_RE.fullmatch(case.name):
            raise AssertionError(f"invalid case name: {case.name!r}")
        if case.generic not in ("ok", "reject"):
            raise AssertionError(f"{case.name}: invalid generic expectation")
        if case.profile0 not in ("ok", "reject", "skip"):
            raise AssertionError(f"{case.name}: invalid Profile 0 expectation")
        if not HEX_RE.fullmatch(case.capsule_hex):
            raise AssertionError(f"{case.name}: invalid capsule hex")
        if case.digest != "-" and not re.fullmatch(r"[0-9a-f]{64}", case.digest):
            raise AssertionError(f"{case.name}: invalid digest hex")
        if case.dtb_hex != "-" and not HEX_RE.fullmatch(case.dtb_hex):
            raise AssertionError(f"{case.name}: invalid Device Tree hex")
        scalar_fields = (case.architecture, case.cpu_count,
                         case.memory_entry_count)
        if any(value != "-" and not value.isdecimal() for value in scalar_fields):
            raise AssertionError(f"{case.name}: invalid decimal expectation")
        address_fields = (case.kernel_physical, case.kernel_virtual)
        if any(value != "-" and not re.fullmatch(r"0x[0-9a-f]{16}", value)
               for value in address_fields):
            raise AssertionError(f"{case.name}: invalid address hex")
        profile_fields = scalar_fields + address_fields + (case.dtb_hex,)
        if case.profile0 == "ok" and any(value == "-" for value in profile_fields):
            raise AssertionError(f"{case.name}: missing Profile 0 expectation")
        if case.profile0 != "ok" and any(value != "-" for value in profile_fields):
            raise AssertionError(f"{case.name}: unexpected Profile 0 values")
        if case.generic == "ok" and case.digest == "-":
            raise AssertionError(f"{case.name}: missing semantic digest")
        if case.generic == "reject" and (case.digest != "-" or case.profile0 != "skip"):
            raise AssertionError(f"{case.name}: invalid generic reject fields")


def render(cases):
    comments = [
        "# BBP v2.0 deterministic shared corpus. Generated; do not edit.",
        "# First non-comment line is the corpus format version marker.",
        "# Case columns (11, ASCII TSV): name, generic_expect, profile0_expect,",
        "# semantic_sha256, architecture_dec, cpu_count_dec, memory_entry_count_dec,",
        "# kernel_physical_hex, kernel_virtual_hex, dtb_hex, capsule_hex.",
        "# semantic_sha256 is RFC 0001's canonical digest stream hashed with SHA-256.",
        "# Profile fields are '-' unless profile0_expect is ok; generic rejects use skip.",
        "bbp-v2-corpus-v1",
    ]
    lines = comments + ["\t".join((
        case.name, case.generic, case.profile0, case.digest, case.architecture,
        case.cpu_count, case.memory_entry_count, case.kernel_physical,
        case.kernel_virtual, case.dtb_hex, case.capsule_hex,
    )) for case in cases]
    for line in lines[8:]:
        if len(line.split("\t")) != 11:
            raise AssertionError("corpus row does not have 11 columns")
    return ("\n".join(lines) + "\n").encode("ascii")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the generated corpus is stale; never write")
    args = parser.parse_args(argv)
    cases = make_cases()
    corpus = render(cases)
    if args.check:
        try:
            current = ROOT_CORPUS.read_bytes()
        except OSError:
            current = None
        if current != corpus:
            print(f"stale or missing: {ROOT_CORPUS.relative_to(ROOT)}",
                  file=sys.stderr)
            return 1
        print(f"BBP v2 corpus is current ({len(cases)} cases)")
        return 0

    ROOT_CORPUS.write_bytes(corpus)
    print(f"wrote {len(cases)} cases to {ROOT_CORPUS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

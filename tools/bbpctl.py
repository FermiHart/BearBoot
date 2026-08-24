#!/usr/bin/env python3
"""Inspect, verify, and create evidence from host-only BBPC v1 files."""

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


CAPTURE_MAGIC = b"BBP-CAPTURE-V1\0\0"
INFO_MAGIC = b"BEAR_INFO" + b"\0" * 7
EVIDENCE_MAGIC = b"BBP-EVIDENCE\0\x01\0\0"

HEADER_SIZE = 96
INFO_OFFSET = 96
INFO_SIZE = 144
DIRECTORY_OFFSET = 240
DIRECTORY_ENTRY_SIZE = 24
INFO_CHECKSUM_OFFSET = 136
TAG_HEADER_SIZE = 32
TAG_CHECKSUM_OFFSET = 24
CONTAINER_CHECKSUM_OFFSET = 80

MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_INFO_SIZE = 64 * 1024 * 1024
MAX_TAG_SIZE = 16 * 1024 * 1024
MAX_TAGS = 1024
UINT64_MAX = (1 << 64) - 1

BBP_TAG_HHDM = (0x0002 << 48) | 0x0002
BBP_TAG_ACPI = (0x0005 << 48) | 0x0001

HEADER_STRUCT = struct.Struct("<16sHHIIHHIIIIQQQQQQ")
DIRECTORY_STRUCT = struct.Struct("<QQII")

HEADER_NAMES = (
    "magic", "format_major", "format_minor", "header_size", "flags",
    "bbp_major", "bbp_minor", "info_bytes", "count", "dir_entry_size",
    "reserved0", "info_phys", "dir_offset", "data_offset", "file_size",
    "container_crc64", "reserved1",
)

ARCH_NAMES = {1: "x86_64", 2: "aarch64", 3: "riscv64", 4: "loongarch"}
TAG_NAMES = {BBP_TAG_HHDM: "HHDM", BBP_TAG_ACPI: "ACPI"}


def _make_crc64_table() -> Tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 if crc & 1 else 0)
        table.append(crc)
    return tuple(table)


CRC64_TABLE = _make_crc64_table()


class FormatError(Exception):
    """The input is not a recognizable, safely readable BBPC v1 file."""


class CommandError(Exception):
    """A command could not be completed because of usage or I/O."""


class VerificationError(Exception):
    """A recognizable capture is unsafe to use as evidence."""


@dataclass
class DirectoryEntry:
    index: int
    source_phys: int
    payload_offset: int
    data_size: int
    flags: int
    payload: bytes


@dataclass
class ChainTag:
    index: int
    source_phys: int
    tag_id: int
    tag_size: int
    tag_version: int
    flags: int
    next_tag: int
    checksum: int
    checksum_valid: bool
    payload: bytes


@dataclass
class Capture:
    raw: bytes
    header: Dict[str, int]
    info: bytes
    info_fields: Dict[str, object]
    entries: List[DirectoryEntry]
    container_errors: List[str]
    info_errors: List[str]


def align8(value: int) -> int:
    return (value + 7) & ~7


def crc64_xz(data: bytes) -> int:
    """CRC-64/XZ (ECMA-182), reflected, init/xorout all ones."""
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = CRC64_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


def checksum_with_zero(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("checksum field is outside data")
    mutable = bytearray(data)
    mutable[offset:offset + 8] = b"\0" * 8
    return crc64_xz(bytes(mutable))


def _read_capture_file(path: str) -> bytes:
    try:
        size = os.stat(path).st_size
        if size > MAX_FILE_SIZE:
            raise FormatError("file exceeds the 64 MiB limit")
        with open(path, "rb") as stream:
            raw = stream.read(MAX_FILE_SIZE + 1)
    except OSError as exc:
        raise CommandError(str(exc)) from exc
    if len(raw) > MAX_FILE_SIZE:
        raise FormatError("file exceeds the 64 MiB limit")
    return raw


def _decode_c_string(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def _parse_info(info: bytes) -> Tuple[Dict[str, object], List[str]]:
    errors: List[str] = []
    fields: Dict[str, object] = {}
    if len(info) != INFO_SIZE:
        return fields, [f"INFO is truncated: {len(info)} bytes, expected {INFO_SIZE}"]

    fields.update({
        "magic": info[:16],
        "version_major": struct.unpack_from("<H", info, 16)[0],
        "version_minor": struct.unpack_from("<H", info, 18)[0],
        "info_size": struct.unpack_from("<I", info, 20)[0],
        "bootloader_name": _decode_c_string(info[24:56]),
        "bootloader_version": _decode_c_string(info[56:72]),
        "architecture": struct.unpack_from("<H", info, 112)[0],
        "cpu_count": struct.unpack_from("<H", info, 114)[0],
        "tag_count": struct.unpack_from("<I", info, 116)[0],
        "first_tag": struct.unpack_from("<Q", info, 120)[0],
        "next_context": struct.unpack_from("<Q", info, 128)[0],
        "checksum": struct.unpack_from("<Q", info, INFO_CHECKSUM_OFFSET)[0],
    })
    fields["checksum_expected"] = checksum_with_zero(info, INFO_CHECKSUM_OFFSET)
    fields["checksum_valid"] = fields["checksum"] == fields["checksum_expected"]

    if fields["magic"] != INFO_MAGIC:
        errors.append("INFO magic is not the full 16-byte BEAR_INFO magic")
    if fields["version_major"] != 1:
        errors.append(f"INFO version_major is {fields['version_major']}, expected 1")
    if not INFO_SIZE <= fields["info_size"] <= MAX_INFO_SIZE:
        errors.append(f"INFO info_size {fields['info_size']} is outside 144..67108864")
    if fields["tag_count"] > MAX_TAGS:
        errors.append(f"INFO tag_count {fields['tag_count']} exceeds {MAX_TAGS}")
    for name in ("first_tag", "next_context"):
        value = fields[name]
        if value and value % 8:
            errors.append(f"INFO {name} 0x{value:x} is not 8-byte aligned")
    if not fields["checksum_valid"]:
        errors.append(
            f"INFO checksum mismatch: stored 0x{fields['checksum']:016x}, "
            f"expected 0x{fields['checksum_expected']:016x}"
        )
    return fields, errors


def parse_capture(raw: bytes) -> Capture:
    if len(raw) < HEADER_SIZE:
        raise FormatError(f"truncated BBPC header: {len(raw)} bytes, expected 96")
    if raw[:16] != CAPTURE_MAGIC:
        raise FormatError("not a BBPC v1 file (bad 16-byte capture magic)")

    values = HEADER_STRUCT.unpack_from(raw)
    header = dict(zip(HEADER_NAMES, values))
    errors: List[str] = []

    exact_fields = (
        ("format_major", 1), ("format_minor", 0), ("header_size", HEADER_SIZE),
        ("flags", 0), ("bbp_major", 1), ("info_bytes", INFO_SIZE),
        ("dir_entry_size", DIRECTORY_ENTRY_SIZE), ("reserved0", 0),
        ("dir_offset", DIRECTORY_OFFSET), ("reserved1", 0),
    )
    for name, expected in exact_fields:
        if header[name] != expected:
            errors.append(f"header {name} is {header[name]}, expected {expected}")
    if header["count"] > MAX_TAGS:
        errors.append(f"header count {header['count']} exceeds {MAX_TAGS}")
    expected_data_offset = align8(DIRECTORY_OFFSET + min(header["count"], MAX_TAGS) * DIRECTORY_ENTRY_SIZE)
    if header["count"] <= MAX_TAGS and header["data_offset"] != expected_data_offset:
        errors.append(
            f"header data_offset is {header['data_offset']}, expected {expected_data_offset}"
        )
    if not header["info_phys"] or header["info_phys"] % 8:
        errors.append("header info_phys must be nonzero and 8-byte aligned")
    if header["info_phys"] + INFO_SIZE > UINT64_MAX:
        errors.append("INFO physical source range wraps")
    if header["file_size"] != len(raw):
        errors.append(f"header file_size is {header['file_size']}, actual size is {len(raw)}")
    if len(raw) > MAX_FILE_SIZE or header["file_size"] > MAX_FILE_SIZE:
        errors.append("container file_size exceeds the 64 MiB limit")

    expected_container_crc = checksum_with_zero(raw, CONTAINER_CHECKSUM_OFFSET)
    if header["container_crc64"] != expected_container_crc:
        errors.append(
            f"container checksum mismatch: stored 0x{header['container_crc64']:016x}, "
            f"expected 0x{expected_container_crc:016x}"
        )

    info = raw[INFO_OFFSET:INFO_OFFSET + INFO_SIZE]
    info_fields, info_errors = _parse_info(info)
    if info_fields:
        if (info_fields["version_major"], info_fields["version_minor"]) != (
            header["bbp_major"], header["bbp_minor"]
        ):
            info_errors.append("INFO version does not match the BBP version in the container header")

    entries: List[DirectoryEntry] = []
    count = header["count"] if header["count"] <= MAX_TAGS else 0
    directory_end = DIRECTORY_OFFSET + count * DIRECTORY_ENTRY_SIZE
    if directory_end > len(raw):
        errors.append("directory extends beyond the file")
    else:
        for index in range(count):
            offset = DIRECTORY_OFFSET + index * DIRECTORY_ENTRY_SIZE
            source_phys, payload_offset, data_size, flags = DIRECTORY_STRUCT.unpack_from(raw, offset)
            end = payload_offset + data_size
            payload = raw[payload_offset:end] if end >= payload_offset and end <= len(raw) else b""
            entries.append(DirectoryEntry(index, source_phys, payload_offset, data_size, flags, payload))

    expected_data = align8(directory_end)
    if directory_end <= len(raw) and expected_data <= len(raw):
        if any(raw[directory_end:expected_data]):
            errors.append("nonzero padding between directory and payload area")

    source_seen: Dict[int, int] = {}
    payload_seen: Dict[int, int] = {}
    file_ranges: List[Tuple[int, int, int]] = []
    source_ranges: List[Tuple[int, int, str]] = [
        (header["info_phys"], header["info_phys"] + INFO_SIZE, "INFO")
    ]
    for entry in entries:
        label = f"directory entry {entry.index}"
        if not entry.source_phys or entry.source_phys % 8:
            errors.append(f"{label} source_phys must be nonzero and 8-byte aligned")
        if entry.source_phys in source_seen:
            errors.append(
                f"{label} duplicates source_phys from entry {source_seen[entry.source_phys]}"
            )
        else:
            source_seen[entry.source_phys] = entry.index
        if entry.payload_offset % 8:
            errors.append(f"{label} payload_offset is not 8-byte aligned")
        if entry.payload_offset in payload_seen:
            errors.append(
                f"{label} duplicates payload_offset from entry {payload_seen[entry.payload_offset]}"
            )
        else:
            payload_seen[entry.payload_offset] = entry.index
        if not TAG_HEADER_SIZE <= entry.data_size <= MAX_TAG_SIZE:
            errors.append(f"{label} data_size {entry.data_size} is outside 32..16777216")
        if entry.flags != 0:
            errors.append(f"{label} flags is {entry.flags}, expected 0")
        end = entry.payload_offset + entry.data_size
        if end > UINT64_MAX:
            errors.append(f"{label} payload range wraps")
        elif entry.payload_offset < expected_data:
            errors.append(f"{label} payload begins before data_offset")
        elif end > len(raw):
            errors.append(f"{label} payload extends beyond the file")
        else:
            file_ranges.append((entry.payload_offset, end, entry.index))
        if entry.source_phys and TAG_HEADER_SIZE <= entry.data_size <= MAX_TAG_SIZE:
            source_end = entry.source_phys + entry.data_size
            if source_end > UINT64_MAX:
                errors.append(f"{label} source range wraps")
            else:
                source_ranges.append((entry.source_phys, source_end, f"entry {entry.index}"))

    file_ranges.sort()
    cursor = expected_data
    previous: Optional[Tuple[int, int, int]] = None
    for start, end, index in file_ranges:
        if previous is not None and start < previous[1]:
            errors.append(f"payload ranges for entries {previous[2]} and {index} overlap")
        elif start > cursor and any(raw[cursor:start]):
            errors.append(f"nonzero payload padding before entry {index}")
        cursor = max(cursor, end)
        previous = (start, end, index)
    if cursor < len(raw):
        errors.append(f"trailing data after final payload: {len(raw) - cursor} bytes")

    source_ranges.sort()
    for previous_range, current_range in zip(source_ranges, source_ranges[1:]):
        if current_range[0] < previous_range[1]:
            errors.append(f"physical source ranges for {previous_range[2]} and {current_range[2]} overlap")

    return Capture(raw, header, info, info_fields, entries, errors, info_errors)


def load_capture(path: str) -> Capture:
    return parse_capture(_read_capture_file(path))


def walk_chain(capture: Capture) -> Tuple[List[ChainTag], List[str]]:
    errors: List[str] = []
    tags: List[ChainTag] = []
    if not capture.info_fields:
        return tags, ["cannot walk tags without a complete INFO"]

    by_source: Dict[int, DirectoryEntry] = {}
    for entry in capture.entries:
        if entry.source_phys not in by_source:
            by_source[entry.source_phys] = entry

    pointer = int(capture.info_fields["first_tag"])
    visited = set()
    while pointer:
        if len(tags) >= MAX_TAGS:
            errors.append(f"tag walk exceeds {MAX_TAGS} steps")
            break
        if pointer % 8:
            errors.append(f"tag link 0x{pointer:x} is not 8-byte aligned")
            break
        if pointer in visited:
            errors.append(f"tag chain cycle at source_phys 0x{pointer:x}")
            break
        visited.add(pointer)
        entry = by_source.get(pointer)
        if entry is None:
            errors.append(f"tag link 0x{pointer:x} has no directory entry")
            break
        payload = entry.payload
        if len(payload) < TAG_HEADER_SIZE:
            errors.append(f"tag at 0x{pointer:x} has no complete 32-byte header")
            break
        tag_id, tag_size, tag_version, flags, next_tag, checksum = struct.unpack_from(
            "<QIHHQQ", payload
        )
        if not TAG_HEADER_SIZE <= tag_size <= MAX_TAG_SIZE:
            errors.append(f"tag at 0x{pointer:x} size {tag_size} is outside 32..16777216")
            break
        if tag_size != entry.data_size or tag_size != len(payload):
            errors.append(
                f"tag at 0x{pointer:x} size {tag_size} does not match directory size {entry.data_size}"
            )
            break
        checksum_expected = checksum_with_zero(payload, TAG_CHECKSUM_OFFSET)
        tags.append(ChainTag(
            len(tags), pointer, tag_id, tag_size, tag_version, flags, next_tag,
            checksum, checksum == checksum_expected, payload,
        ))
        pointer = next_tag
    return tags, errors


def validation(capture: Capture) -> Tuple[List[str], List[ChainTag], List[str]]:
    tags, chain_errors = walk_chain(capture)
    errors = list(capture.container_errors) + list(capture.info_errors) + list(chain_errors)
    tag_crc_errors = [
        f"tag {tag.index} at 0x{tag.source_phys:x} checksum mismatch"
        for tag in tags if not tag.checksum_valid
    ]
    errors.extend(tag_crc_errors)

    if capture.info_fields:
        declared = int(capture.info_fields["tag_count"])
        if not chain_errors and declared != len(tags):
            errors.append(f"INFO tag_count is {declared}, reachable tag count is {len(tags)}")
        if not chain_errors:
            reachable = {tag.source_phys for tag in tags}
            directory_sources = {entry.source_phys for entry in capture.entries}
            if reachable != directory_sources:
                errors.append("directory contains tags that are not exactly the reachable chain")
    return errors, tags, chain_errors


def _hex(value: int) -> str:
    return f"0x{value:x}"


def inspect_result(capture: Capture) -> Dict[str, object]:
    errors, tags, chain_errors = validation(capture)
    info = capture.info_fields
    return {
        "format": "BBPC",
        "format_version": f"{capture.header['format_major']}.{capture.header['format_minor']}",
        "bbp_version": f"{capture.header['bbp_major']}.{capture.header['bbp_minor']}",
        "file_size": len(capture.raw),
        "info_phys": _hex(capture.header["info_phys"]),
        "info": {
            "version": f"{info.get('version_major', '?')}.{info.get('version_minor', '?')}",
            "info_size": info.get("info_size"),
            "bootloader_name": info.get("bootloader_name"),
            "bootloader_version": info.get("bootloader_version"),
            "architecture": ARCH_NAMES.get(info.get("architecture"), info.get("architecture")),
            "cpu_count": info.get("cpu_count"),
            "tag_count": info.get("tag_count"),
            "first_tag": _hex(int(info["first_tag"])) if "first_tag" in info else None,
            "checksum_valid": info.get("checksum_valid"),
        },
        "directory": [
            {
                "index": entry.index,
                "source_phys": _hex(entry.source_phys),
                "payload_offset": entry.payload_offset,
                "data_size": entry.data_size,
                "flags": entry.flags,
            }
            for entry in capture.entries
        ],
        "chain": [
            {
                "index": tag.index,
                "source_phys": _hex(tag.source_phys),
                "tag_id": f"0x{tag.tag_id:016x}",
                "name": TAG_NAMES.get(tag.tag_id, "unknown"),
                "tag_size": tag.tag_size,
                "tag_version": tag.tag_version,
                "flags": tag.flags,
                "next_tag": _hex(tag.next_tag),
                "checksum_valid": tag.checksum_valid,
            }
            for tag in tags
        ],
        "chain_errors": chain_errors,
        "errors": errors,
        "valid": not errors,
    }


def evidence_bytes(capture: Capture) -> Tuple[bytes, List[ChainTag], List[ChainTag]]:
    errors, tags, chain_errors = validation(capture)
    tag_crc_messages = {
        f"tag {tag.index} at 0x{tag.source_phys:x} checksum mismatch"
        for tag in tags if not tag.checksum_valid
    }
    fatal = [error for error in errors if error not in tag_crc_messages]
    if chain_errors or fatal:
        raise VerificationError("evidence refused: " + "; ".join(fatal or chain_errors))
    included = [tag for tag in tags if tag.checksum_valid]
    skipped = [tag for tag in tags if not tag.checksum_valid]
    evidence = EVIDENCE_MAGIC + capture.info + b"".join(tag.payload for tag in included)
    return evidence, included, skipped


def _pack_checksum(mutable: bytearray, offset: int) -> None:
    struct.pack_into("<Q", mutable, offset, 0)
    struct.pack_into("<Q", mutable, offset, crc64_xz(bytes(mutable)))


def _pack_region_checksum(mutable: bytearray, start: int, size: int, checksum_offset: int) -> None:
    region = bytearray(mutable[start:start + size])
    _pack_checksum(region, checksum_offset)
    mutable[start:start + size] = region


def build_fixture() -> bytes:
    hhdm = bytearray(40)
    struct.pack_into("<QIHHQQQ", hhdm, 0, BBP_TAG_HHDM, 40, 1, 0, 0x301000, 0, 0)
    _pack_checksum(hhdm, TAG_CHECKSUM_OFFSET)

    acpi = bytearray(56)
    struct.pack_into(
        "<QIHHQQQQIHH", acpi, 0, BBP_TAG_ACPI, 56, 1, 0, 0, 0,
        0xE0000, 0, 0, 0x0604, 0,
    )
    _pack_checksum(acpi, TAG_CHECKSUM_OFFSET)

    info = bytearray(INFO_SIZE)
    info[:16] = INFO_MAGIC
    struct.pack_into("<HHI", info, 16, 1, 1, 240)
    info[24:24 + len(b"bbpctl-fixture")] = b"bbpctl-fixture"
    struct.pack_into("<HHIQ", info, 112, 1, 1, 2, 0x200000)
    struct.pack_into("<Q", info, 128, 0)
    _pack_checksum(info, INFO_CHECKSUM_OFFSET)

    data_offset = align8(DIRECTORY_OFFSET + 2 * DIRECTORY_ENTRY_SIZE)
    hhdm_offset = data_offset
    acpi_offset = align8(hhdm_offset + len(hhdm))
    file_size = acpi_offset + len(acpi)
    raw = bytearray(file_size)
    raw[INFO_OFFSET:INFO_OFFSET + INFO_SIZE] = info
    DIRECTORY_STRUCT.pack_into(raw, DIRECTORY_OFFSET, 0x200000, hhdm_offset, len(hhdm), 0)
    DIRECTORY_STRUCT.pack_into(
        raw, DIRECTORY_OFFSET + DIRECTORY_ENTRY_SIZE, 0x301000, acpi_offset, len(acpi), 0
    )
    raw[hhdm_offset:hhdm_offset + len(hhdm)] = hhdm
    raw[acpi_offset:acpi_offset + len(acpi)] = acpi
    HEADER_STRUCT.pack_into(
        raw, 0, CAPTURE_MAGIC, 1, 0, HEADER_SIZE, 0, 1, 1, INFO_SIZE, 2,
        DIRECTORY_ENTRY_SIZE, 0, 0x100000, DIRECTORY_OFFSET, data_offset,
        file_size, 0, 0,
    )
    _pack_checksum(raw, CONTAINER_CHECKSUM_OFFSET)
    return bytes(raw)


def _same_path(input_path: str, output_path: str) -> bool:
    input_real = os.path.realpath(os.path.abspath(input_path))
    output_real = os.path.realpath(os.path.abspath(output_path))
    if input_real == output_real:
        return True
    try:
        return os.path.samefile(input_path, output_path)
    except (FileNotFoundError, OSError):
        return False


def atomic_write(path: str, data: bytes, force: bool = False) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        raise CommandError(f"output directory does not exist: {directory}")
    if os.path.exists(path) and not force:
        raise CommandError(f"refusing to overwrite existing file: {path}")
    fd, temporary = tempfile.mkstemp(prefix=".bbpctl-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        if force:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise CommandError(f"refusing to overwrite existing file: {path}") from exc
            os.unlink(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def corrupt_fixture(raw: bytes, case: str, tag_index: int) -> bytes:
    capture = parse_capture(raw)
    errors, tags, _ = validation(capture)
    if errors:
        raise CommandError("input capture must verify before corruption: " + "; ".join(errors))
    if tag_index < 0 or tag_index >= len(tags):
        raise CommandError(f"tag index {tag_index} is outside 0..{len(tags) - 1}")

    mutable = bytearray(raw)
    entry = capture.entries[tag_index]
    tag_offset = entry.payload_offset
    if case == "container-crc":
        mutable[CONTAINER_CHECKSUM_OFFSET] ^= 1
        return bytes(mutable)
    if case == "info-body":
        mutable[INFO_OFFSET + 24] ^= 1
    elif case == "info-magic-padding":
        mutable[INFO_OFFSET + 15] = 1
        _pack_region_checksum(mutable, INFO_OFFSET, INFO_SIZE, INFO_CHECKSUM_OFFSET)
    elif case == "tag-body":
        mutable[tag_offset + TAG_HEADER_SIZE] ^= 1
    elif case == "tag-size-small":
        struct.pack_into("<I", mutable, tag_offset + 8, TAG_HEADER_SIZE - 1)
    elif case == "first-misaligned":
        struct.pack_into("<Q", mutable, INFO_OFFSET + 120, 0x200001)
        _pack_region_checksum(mutable, INFO_OFFSET, INFO_SIZE, INFO_CHECKSUM_OFFSET)
    elif case == "next-dangling":
        struct.pack_into("<Q", mutable, tag_offset + 16, 0x400000)
        tag = bytearray(mutable[tag_offset:tag_offset + entry.data_size])
        _pack_checksum(tag, TAG_CHECKSUM_OFFSET)
        mutable[tag_offset:tag_offset + entry.data_size] = tag
    elif case == "next-cycle":
        struct.pack_into("<Q", mutable, tag_offset + 16, tags[0].source_phys)
        tag = bytearray(mutable[tag_offset:tag_offset + entry.data_size])
        _pack_checksum(tag, TAG_CHECKSUM_OFFSET)
        mutable[tag_offset:tag_offset + entry.data_size] = tag
    else:
        raise CommandError(f"unknown corruption case: {case}")
    _pack_checksum(mutable, CONTAINER_CHECKSUM_OFFSET)
    return bytes(mutable)


def _print_json(value: object, stream=sys.stdout) -> None:
    json.dump(value, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")


def command_inspect(args: argparse.Namespace) -> int:
    result = inspect_result(load_capture(args.capture))
    if args.json:
        _print_json(result)
    else:
        print(
            f"BBPC {result['format_version']} / BBP {result['bbp_version']}: "
            f"{result['file_size']} bytes"
        )
        info = result["info"]
        print(
            f"INFO {result['info_phys']} {info['bootloader_name'] or '<unnamed>'} "
            f"arch={info['architecture']} tags={info['tag_count']} "
            f"crc={'ok' if info['checksum_valid'] else 'BAD'}"
        )
        for tag in result["chain"]:
            print(
                f"tag[{tag['index']}] {tag['source_phys']} {tag['name']} "
                f"size={tag['tag_size']} next={tag['next_tag']} "
                f"crc={'ok' if tag['checksum_valid'] else 'BAD'}"
            )
        for error in result["errors"]:
            print(f"error: {error}")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    capture = load_capture(args.capture)
    errors, tags, _ = validation(capture)
    result = {"valid": not errors, "errors": errors, "tags_walked": len(tags)}
    if args.json:
        _print_json(result)
    elif errors:
        for error in errors:
            print(f"FAIL: {error}")
    else:
        print(f"OK: valid BBPC v1 capture ({len(tags)} tags)")
    return 0 if not errors else 1


def command_evidence(args: argparse.Namespace) -> int:
    if args.stream == "-" and args.json:
        raise CommandError("--json cannot be combined with --stream -")
    evidence, included, skipped = evidence_bytes(load_capture(args.capture))
    digest = hashlib.new(args.algorithm, evidence).hexdigest()
    result = {
        "algorithm": args.algorithm,
        "digest": digest,
        "evidence_bytes": len(evidence),
        "tags_included": len(included),
        "tags_skipped_crc": len(skipped),
    }
    if args.stream == "-":
        sys.stdout.buffer.write(evidence)
        sys.stdout.buffer.flush()
        print(f"{args.algorithm}:{digest}", file=sys.stderr)
    else:
        if args.stream:
            atomic_write(args.stream, evidence)
        if args.json:
            _print_json(result)
        else:
            print(f"{args.algorithm}:{digest}")
            if skipped:
                print(f"skipped {len(skipped)} tag(s) with invalid CRC", file=sys.stderr)
    return 0


def command_fixture_create(args: argparse.Namespace) -> int:
    atomic_write(args.output, build_fixture(), args.force)
    print(f"created deterministic BBPC fixture: {args.output}")
    return 0


def command_fixture_corrupt(args: argparse.Namespace) -> int:
    if _same_path(args.input, args.output):
        raise CommandError("input and output paths must differ")
    raw = _read_capture_file(args.input)
    corrupted = corrupt_fixture(raw, args.case, args.tag_index)
    atomic_write(args.output, corrupted, args.force)
    print(f"created {args.case} corruption fixture: {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bbpctl", description="Host-only BBP capture container (BBPC v1) tool"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect_parser = commands.add_parser("inspect", help="bounded best-effort inspection")
    inspect_parser.add_argument("capture")
    inspect_parser.add_argument("--json", action="store_true")
    inspect_parser.set_defaults(handler=command_inspect)

    verify_parser = commands.add_parser("verify", help="strictly verify a capture")
    verify_parser.add_argument("capture")
    verify_parser.add_argument("--json", action="store_true")
    verify_parser.set_defaults(handler=command_verify)

    evidence_parser = commands.add_parser("evidence", help="hash canonical BBP evidence")
    evidence_parser.add_argument("capture")
    evidence_parser.add_argument(
        "--algorithm", choices=("sha256", "sha384", "sha512", "blake2b"), default="sha256"
    )
    evidence_parser.add_argument("--stream", metavar="PATH", help="write evidence bytes to PATH or -")
    evidence_parser.add_argument("--json", action="store_true")
    evidence_parser.set_defaults(handler=command_evidence)

    fixture_parser = commands.add_parser("fixture", help="create deterministic test captures")
    fixture_commands = fixture_parser.add_subparsers(dest="fixture_command", required=True)
    create_parser = fixture_commands.add_parser("create")
    create_parser.add_argument("output")
    create_parser.add_argument("--force", action="store_true")
    create_parser.set_defaults(handler=command_fixture_create)

    corrupt_parser = fixture_commands.add_parser("corrupt")
    corrupt_parser.add_argument("input")
    corrupt_parser.add_argument("output")
    corrupt_parser.add_argument(
        "--case", required=True,
        choices=(
            "container-crc", "info-body", "info-magic-padding", "tag-body",
            "tag-size-small", "first-misaligned", "next-dangling", "next-cycle",
        ),
    )
    corrupt_parser.add_argument("--tag-index", type=int, default=0)
    corrupt_parser.add_argument("--force", action="store_true")
    corrupt_parser.set_defaults(handler=command_fixture_corrupt)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except FormatError as exc:
        print(f"bbpctl: format error: {exc}", file=sys.stderr)
        return 2
    except VerificationError as exc:
        print(f"bbpctl: verification failure: {exc}", file=sys.stderr)
        return 1
    except (CommandError, OSError, ValueError, struct.error) as exc:
        print(f"bbpctl: error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 2


if __name__ == "__main__":
    sys.exit(main())

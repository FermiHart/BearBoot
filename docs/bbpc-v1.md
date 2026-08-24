# BBPC v1 Host Capture Container

BBPC v1 is a host-side file format for preserving one fixed BBP INFO and the
raw tags reachable from it. It is an analysis and evidence container. It is
not the BBP wire ABI, is not passed to a kernel, and makes no commitment about
a future BBP or BBPC v2.

All integers are little-endian. All offsets below are absolute file offsets.
CRC fields use CRC-64/XZ as specified by ADR-0002.

## File Layout

| Region | Offset | Size |
|--------|--------|------|
| BBPC header | 0 | 96 bytes |
| Raw `struct bbp_info` | 96 | exactly 144 bytes |
| Tag directory | 240 | `count * 24` bytes |
| Zero alignment padding | directory end | to next 8-byte boundary |
| Raw tag payloads | `data_offset` | individually 8-byte aligned |

The INFO and tag payload bytes are preserved exactly, including their original
BBP checksums and physical links. A reader reconstructs links by looking up
`first_tag` and `next_tag` in a dictionary keyed by directory `source_phys`.
It must never infer a link by adding an address or assuming physical adjacency.

## Header

The 96-byte header has this packed layout:

| Offset | Type | Name | Required value |
|--------|------|------|----------------|
| 0 | `u8[16]` | magic | `BBP-CAPTURE-V1\0\0` |
| 16 | `u16` | format_major | 1 |
| 18 | `u16` | format_minor | 0 |
| 20 | `u32` | header_size | 96 |
| 24 | `u32` | flags | 0 |
| 28 | `u16` | bbp_major | 1 |
| 30 | `u16` | bbp_minor | captured BBP minor version |
| 32 | `u32` | info_bytes | 144 |
| 36 | `u32` | count | directory entries, at most 1024 |
| 40 | `u32` | dir_entry_size | 24 |
| 44 | `u32` | reserved0 | 0 |
| 48 | `u64` | info_phys | original aligned INFO physical address |
| 56 | `u64` | dir_offset | 240 |
| 64 | `u64` | data_offset | `align8(240 + count * 24)` |
| 72 | `u64` | file_size | exact file length |
| 80 | `u64` | container_crc64 | CRC-64/XZ of the whole file with bytes 80..87 zero |
| 88 | `u64` | reserved1 | 0 |

The complete 16-byte magic is compared. Prefix comparisons are invalid.

## Directory

Each packed 24-byte directory entry is:

| Offset | Type | Name | Meaning |
|--------|------|------|---------|
| 0 | `u64` | source_phys | original physical address of this tag |
| 8 | `u64` | payload_offset | absolute offset of the raw tag bytes |
| 16 | `u32` | data_size | payload length, from 32 bytes through 16 MiB |
| 20 | `u32` | flags | 0 |

Source addresses and payload offsets are 8-byte aligned. Source physical
ranges and file payload ranges cannot overlap, and source addresses and payload
offsets cannot be duplicated. Gaps used for alignment contain only zero bytes.
No bytes follow the final payload.

## Verification

A strict verifier applies these bounds before following untrusted fields:

* The actual and declared file sizes are at most 64 MiB and are equal.
* INFO is exactly 144 captured bytes, has the full 16-byte `BEAR_INFO` magic,
  declares BBP major 1, and has `info_size` in 144 bytes through 64 MiB.
* INFO checksum validation covers exactly 144 bytes with bytes 136..143 zero.
* There are at most 1024 directory entries and at most 1024 walk steps.
* Every tag is 32 bytes through 16 MiB. Its embedded `tag_size` equals its
  directory payload size. Tag checksum validation zeros bytes 24..31.
* `info_phys`, every `source_phys`, and every nonzero INFO/tag link is 8-byte
  aligned. Every nonzero tag link resolves through the source dictionary.
* Duplicate ranges, overlapping ranges, nonzero padding, and trailing data are
  rejected. The directory must describe exactly the reachable chain.
* The reachable count equals INFO `tag_count`. `info_size` is range-checked but
  remains informational; it is never treated as a contiguity or file bound.

CRC failure does not make a tag header unsafe after its framing is bounded. A
walk therefore reads the bounded `next_tag` and continues, but never exposes a
CRC-failed tag as valid content. Invalid framing, an unresolved link, a cycle,
or the walk ceiling stops traversal.

## Canonical Evidence

The evidence byte stream is:

```text
"BBP-EVIDENCE\0\x01\0\0"
+ raw INFO[144]
+ each structurally valid, CRC-valid reachable tag once in chain order
```

CRC-failed tags are omitted while traversal follows their bounded `next_tag`.
Evidence generation refuses an invalid container, invalid INFO, or any
structural chain error. The stream deliberately excludes the BBPC header,
directory, offsets, padding, and all other container metadata. `bbpctl evidence`
hashes this stream with SHA-256 by default; SHA-384, SHA-512, and BLAKE2b are
also available.

## `bbpctl`

```text
bbpctl inspect CAPTURE [--json]
bbpctl verify CAPTURE [--json]
bbpctl evidence CAPTURE [--algorithm sha256|sha384|sha512|blake2b]
                         [--stream PATH|-] [--json]
bbpctl fixture create OUTPUT [--force]
bbpctl fixture corrupt INPUT OUTPUT --case CASE [--tag-index N] [--force]
```

`inspect` is bounded and best-effort for a recognizable BBPC file. `verify`
reports deterministic errors. `--stream -` writes only evidence bytes to
stdout and reports the digest on stderr; it cannot be combined with `--json`.
File writes are atomic. Existing outputs are refused unless the fixture command
has `--force`; evidence streams never overwrite. Corruption input and output
must be different paths.

Exit status is 0 for success, 1 for verification or evidence-policy failure,
and 2 for usage, I/O, or an unrecognizable/unsafe outer format.

## Deterministic Fixture

The fixture has INFO at physical `0x100000`, BBP version 1.1, `info_size=240`,
bootloader name `bbpctl-fixture`, architecture x86_64, one CPU, two tags, and
`first_tag=0x200000`. Unspecified fixed fields are zero.

The first tag is a 40-byte HHDM tag at `0x200000`, with offset zero and
`next_tag=0x301000`. The second is a 56-byte ACPI tag at `0x301000`, with
`next_tag=0`, RSDP `0xe0000`, and ACPI version `0x0604`. The noncontiguous
physical addresses are intentional and exercise dictionary-based link
reconstruction.

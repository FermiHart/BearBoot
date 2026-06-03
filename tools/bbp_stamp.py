#!/usr/bin/env python3
# bbp_stamp — post-link header stamper for the Bear Boot Protocol (ADR-0007).
#
#   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
#   SPDX-License-Identifier: BSD-3-Clause
#
# Patches a linked ELF kernel's ".bbp_hdr" section in place:
#   - entry_point  <- ELF e_entry (unless already non-zero or --entry given)
#   - requests     <- physical/virtual addr of the request array (--requests / symbol)
#   - checksum     <- CRC-64/XZ over the 160-byte header with checksum=0
#
# Dependency-free: parses ELF64 section/symbol tables directly. Mirrors the
# CRC in include/bbp/bbp_crc64.h exactly (verified against the canonical
# check vector at startup).
#
# Usage:
#   bbp_stamp.py kernel.elf
#   bbp_stamp.py kernel.elf --requests-symbol bbp_requests
#   bbp_stamp.py kernel.elf --requests 0x12000 --entry 0xffffffff80001000
#   bbp_stamp.py kernel.elf --check        # validate without writing

import sys, struct, argparse

# ---- CRC-64/XZ (ECMA-182), identical params to bbp_crc64.h -----------------
_POLY_REFLECTED = 0xC96C5795D7870F42
def crc64_xz(data: bytes) -> int:
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (_POLY_REFLECTED if (crc & 1) else 0)
    return crc ^ 0xFFFFFFFFFFFFFFFF

# ---- BBP header layout (must match struct bbp_header in bbp.h) -------------
HDR_SIZE          = 160
MAGIC             = b"BEAR_BOOT"          # 16-byte field, NUL-padded
OFF_MAGIC         = 0      # [16]
OFF_VERSION_MAJOR = 16     # u16
OFF_VERSION_MINOR = 18     # u16
OFF_HEADER_SIZE   = 20     # u32
OFF_ENTRY_POINT   = 32     # u64  (after flags@24)
OFF_REQUESTS      = 64     # u64
OFF_CHECKSUM      = 152    # u64

VERSION_MAJOR = 1

class ElfError(Exception): pass

class Elf64:
    """Minimal ELF64 reader/writer: sections + symbols, little-endian."""
    def __init__(self, raw: bytearray):
        self.raw = raw
        if raw[:4] != b"\x7fELF": raise ElfError("not an ELF")
        if raw[4] != 2:           raise ElfError("not ELF64")
        if raw[5] != 1:           raise ElfError("not little-endian")
        (self.e_entry,) = struct.unpack_from("<Q", raw, 24)
        self.e_shoff,  = struct.unpack_from("<Q", raw, 40)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = \
            struct.unpack_from("<HHH", raw, 58)
        self._read_sections()

    def _read_sections(self):
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            name, stype, flags, addr, offset, size, link, info, align, entsz = \
                struct.unpack_from("<IIQQQQIIQQ", self.raw, off)
            self.sections.append(dict(name_off=name, type=stype, addr=addr,
                                      offset=offset, size=size, link=link,
                                      info=info, entsize=entsz))
        shstr = self.sections[self.e_shstrndx]
        self._shstr = self.raw[shstr["offset"]:shstr["offset"]+shstr["size"]]
        for s in self.sections:
            s["name"] = self._cstr(self._shstr, s["name_off"])

    @staticmethod
    def _cstr(buf, off):
        end = buf.find(b"\0", off)
        return buf[off:end].decode("utf-8", "replace")

    def section(self, name):
        for s in self.sections:
            if s["name"] == name: return s
        return None

    def symbol_addr(self, want):
        symtab = self.section(".symtab")
        if not symtab: raise ElfError("no .symtab (stripped?) — pass --requests")
        strtab = self.sections[symtab["link"]]
        sbuf = self.raw[strtab["offset"]:strtab["offset"]+strtab["size"]]
        n = symtab["size"] // 24
        for i in range(n):
            off = symtab["offset"] + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", self.raw, off)
            if self._cstr(sbuf, st_name) == want:
                return st_value
        return None

def stamp(path, *, requests=None, requests_symbol=None, entry=None,
          check_only=False, verbose=True):
    # Self-test the CRC before touching anything.
    if crc64_xz(b"123456789") != 0x995DC9BBDF1939FA:
        raise ElfError("CRC-64/XZ self-test failed (internal)")

    with open(path, "rb") as f:
        raw = bytearray(f.read())
    elf = Elf64(raw)

    sec = elf.section(".bbp_hdr")
    if sec is None:
        # Fallback: scan for the magic anywhere in the file.
        idx = raw.find(MAGIC)
        if idx < 0:
            raise ElfError(".bbp_hdr not found and magic not present "
                           "(did you KEEP(*(.bbp_hdr)) in the linker script?)")
        base = idx
        if verbose: print(f"[bbp_stamp] .bbp_hdr section absent; magic at file offset 0x{base:x}")
    else:
        base = sec["offset"]
        if sec["size"] < HDR_SIZE:
            raise ElfError(f".bbp_hdr too small: {sec['size']} < {HDR_SIZE}")

    # Validate the header we are about to stamp.
    if raw[base:base+len(MAGIC)] != MAGIC:
        raise ElfError("bad magic in .bbp_hdr")
    vmaj, = struct.unpack_from("<H", raw, base + OFF_VERSION_MAJOR)
    if vmaj != VERSION_MAJOR:
        raise ElfError(f"header version_major {vmaj} != {VERSION_MAJOR}")
    hsz, = struct.unpack_from("<I", raw, base + OFF_HEADER_SIZE)
    if hsz != HDR_SIZE:
        raise ElfError(f"header_size {hsz} != {HDR_SIZE}")

    # Resolve entry_point.
    cur_entry, = struct.unpack_from("<Q", raw, base + OFF_ENTRY_POINT)
    if entry is not None:
        new_entry = entry
    elif cur_entry != 0:
        new_entry = cur_entry            # respect a value the kernel set itself
    else:
        new_entry = elf.e_entry

    # Resolve requests pointer.
    cur_req, = struct.unpack_from("<Q", raw, base + OFF_REQUESTS)
    if requests is not None:
        new_req = requests
    elif requests_symbol:
        a = elf.symbol_addr(requests_symbol)
        if a is None: raise ElfError(f"symbol '{requests_symbol}' not found")
        new_req = a
    else:
        new_req = cur_req                # leave as-is (may legitimately be 0)

    if check_only:
        chk, = struct.unpack_from("<Q", raw, base + OFF_CHECKSUM)
        hdr = bytearray(raw[base:base+HDR_SIZE])
        struct.pack_into("<Q", hdr, OFF_CHECKSUM, 0)
        want = crc64_xz(bytes(hdr))
        ok = (chk == want)
        print(f"[bbp_stamp] entry=0x{cur_entry:x} requests=0x{cur_req:x} "
              f"checksum=0x{chk:016x} expected=0x{want:016x} "
              f"{'OK' if ok else 'MISMATCH'}")
        return 0 if ok else 1

    # Write entry + requests, zero checksum, compute, write checksum.
    struct.pack_into("<Q", raw, base + OFF_ENTRY_POINT, new_entry)
    struct.pack_into("<Q", raw, base + OFF_REQUESTS,    new_req)
    struct.pack_into("<Q", raw, base + OFF_CHECKSUM,    0)
    hdr = bytes(raw[base:base+HDR_SIZE])
    crc = crc64_xz(hdr)
    struct.pack_into("<Q", raw, base + OFF_CHECKSUM, crc)

    with open(path, "r+b") as f:
        f.seek(0); f.write(raw)

    if verbose:
        print(f"[bbp_stamp] {path}: entry=0x{new_entry:x} "
              f"requests=0x{new_req:x} checksum=0x{crc:016x}  stamped.")
    return 0

def main(argv):
    ap = argparse.ArgumentParser(description="Stamp a BBP kernel header post-link.")
    ap.add_argument("elf")
    ap.add_argument("--entry", type=lambda x: int(x, 0), default=None,
                    help="override entry_point (default: ELF e_entry)")
    ap.add_argument("--requests", type=lambda x: int(x, 0), default=None,
                    help="physical/virtual addr of the request array")
    ap.add_argument("--requests-symbol", default=None,
                    help="resolve the request array addr from a symbol name")
    ap.add_argument("--check", action="store_true",
                    help="validate the existing checksum, do not write")
    a = ap.parse_args(argv)
    try:
        return stamp(a.elf, requests=a.requests, requests_symbol=a.requests_symbol,
                     entry=a.entry, check_only=a.check)
    except (ElfError, OSError) as e:
        print(f"bbp_stamp: error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Wave 16 regression tests for tools/bbp_stamp.py."""

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
sys.path.insert(0, str(TOOLS))
import bbp_stamp  # noqa: E402


CLI = [sys.executable, str(TOOLS / "bbp_stamp.py")]
LOAD_VADDR = 0xFFFFFFFF80000000
LOAD_PADDR = 0x00200000
SYMBOL_OFFSET = 0x120
SYMBOL_NAME = "bbp_requests"


def build_elf64(path: Path, symbol_vma: int) -> None:
    """Write a minimal sectioned ELF64 image with one PT_LOAD and one symbol."""
    phoff = 0x40
    load_offset = 0x200
    bbp_offset = load_offset
    requests_offset = load_offset + SYMBOL_OFFSET
    strtab_offset = 0x420
    symtab_offset = 0x440
    shstrtab_offset = 0x480
    shoff = 0x500
    shnum = 6

    raw = bytearray(shoff + shnum * 64)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    raw[:16] = ident
    struct.pack_into(
        "<HHIQQQIHHHHHH", raw, 16,
        2, 62, 1, LOAD_VADDR + 0x40, phoff, shoff, 0,
        64, 56, 1, 64, shnum, 5,
    )
    struct.pack_into(
        "<IIQQQQQQ", raw, phoff,
        1, 6, load_offset, LOAD_VADDR, LOAD_PADDR, 0x200, 0x300, 0x1000,
    )

    header = bytearray(bbp_stamp.HDR_SIZE)
    header[:len(bbp_stamp.MAGIC)] = bbp_stamp.MAGIC
    struct.pack_into("<H", header, bbp_stamp.OFF_VERSION_MAJOR, 1)
    struct.pack_into("<I", header, bbp_stamp.OFF_HEADER_SIZE, bbp_stamp.HDR_SIZE)
    raw[bbp_offset:bbp_offset + len(header)] = header

    strtab = b"\0" + SYMBOL_NAME.encode("ascii") + b"\0"
    raw[strtab_offset:strtab_offset + len(strtab)] = strtab
    struct.pack_into(
        "<IBBHQQ", raw, symtab_offset + 24,
        1, 0x11, 0, 2, symbol_vma, 8,
    )

    shstrtab = b"\0.bbp_hdr\0.requests\0.symtab\0.strtab\0.shstrtab\0"
    raw[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab
    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (shstrtab.index(b".bbp_hdr"), 1, 2, LOAD_VADDR, bbp_offset,
         bbp_stamp.HDR_SIZE, 0, 0, 8, 0),
        (shstrtab.index(b".requests"), 1, 3, symbol_vma, requests_offset,
         8, 0, 0, 8, 0),
        (shstrtab.index(b".symtab"), 2, 0, 0, symtab_offset,
         48, 4, 1, 8, 24),
        (shstrtab.index(b".strtab"), 3, 0, 0, strtab_offset,
         len(strtab), 0, 0, 1, 0),
        (shstrtab.index(b".shstrtab"), 3, 0, 0, shstrtab_offset,
         len(shstrtab), 0, 0, 1, 0),
    )
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", raw, shoff + index * 64, *section)

    path.write_bytes(raw)


class BbpStampTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.elf = Path(self.temporary.name) / "kernel.elf"

    def run_cli(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            CLI + [str(self.elf), "--requests-symbol", SYMBOL_NAME],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def requests_field(self) -> int:
        raw = self.elf.read_bytes()
        return struct.unpack_from(
            "<Q", raw, 0x200 + bbp_stamp.OFF_REQUESTS
        )[0]

    def test_requests_symbol_translates_higher_half_vma_through_pt_load(self) -> None:
        build_elf64(self.elf, LOAD_VADDR + SYMBOL_OFFSET)

        result = self.run_cli()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.requests_field(), LOAD_PADDR + SYMBOL_OFFSET)

    def test_requests_symbol_outside_loadable_segment_is_rejected(self) -> None:
        build_elf64(self.elf, LOAD_VADDR + 0x400)
        before = self.elf.read_bytes()

        result = self.run_cli()

        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("outside PT_LOAD segments", result.stderr)
        self.assertEqual(self.elf.read_bytes(), before)

    def test_requests_symbol_never_stamps_higher_half_vma_as_physical(self) -> None:
        symbol_vma = LOAD_VADDR + SYMBOL_OFFSET
        build_elf64(self.elf, symbol_vma)

        result = self.run_cli()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.requests_field(), symbol_vma)
        self.assertEqual(self.requests_field(), LOAD_PADDR + SYMBOL_OFFSET)

    def test_nonzero_magic_padding_is_rejected_without_modification(self) -> None:
        build_elf64(self.elf, LOAD_VADDR + SYMBOL_OFFSET)
        malformed = bytearray(self.elf.read_bytes())
        malformed[0x200 + 15] = 1
        self.elf.write_bytes(malformed)

        result = self.run_cli()

        self.assertEqual(result.returncode, 2)
        self.assertIn("bad magic", result.stderr)
        self.assertEqual(self.elf.read_bytes(), malformed)

    def test_truncated_elf_is_reported_without_traceback(self) -> None:
        self.elf.write_bytes(b"\x7fELF")

        result = self.run_cli()

        self.assertEqual(result.returncode, 2)
        self.assertIn("truncated ELF header", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_requests_help_describes_a_physical_address(self) -> None:
        result = subprocess.run(
            CLI + ["--help"], cwd=ROOT, capture_output=True, text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("physical address of the request array", result.stdout)
        self.assertNotIn("physical/virtual", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)

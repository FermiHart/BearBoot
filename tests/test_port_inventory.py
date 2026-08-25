#!/usr/bin/env python3
"""Wave 21 port Makefile interface inventory tests."""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PORTS = ("tinalinux", "linux01", "josh", "minix")
TARGETS = ("scaffold-check", "test-hosted")


class PortInventoryTests(unittest.TestCase):
    def test_all_ports_expose_consistent_validation_targets(self) -> None:
        for port in PORTS:
            makefile = ROOT / "ports" / port / "Makefile"
            self.assertTrue(makefile.is_file(), f"missing port Makefile: {port}")
            for target in TARGETS:
                with self.subTest(port=port, target=target):
                    result = subprocess.run(
                        ["make", "-C", str(makefile.parent), "-n", target],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        result.stdout + result.stderr,
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Boundary tests for tools/tpm2_measure.py."""

import socket
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
sys.path.insert(0, str(TOOLS))
import tpm2_measure  # noqa: E402


def response_header(tag=tpm2_measure.TPM_ST_NO_SESSIONS, size=10, result=0):
    return struct.pack(">HII", tag, size, result)


def pcr_read_payload(digest=b"\x5a" * 32):
    selection = struct.pack(">IHB3s", 1, tpm2_measure.TPM_ALG_SHA256, 3,
                            (1 << tpm2_measure.PCR).to_bytes(3, "little"))
    return struct.pack(">I", 7) + selection + struct.pack(">IH", 1, len(digest)) + digest


class TpmResponseParsingTests(unittest.TestCase):
    def test_short_response_header_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "truncated TPM response header"):
            tpm2_measure.parse_response_header(b"\x80\x01")

    def test_oversized_declared_response_is_rejected(self):
        header = response_header(size=tpm2_measure.MAX_TPM_RESPONSE_SIZE + 1)
        with self.assertRaisesRegex(RuntimeError, "TPM response size"):
            tpm2_measure.parse_response_header(header)

    def test_wrong_response_tag_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "TPM response tag"):
            tpm2_measure.parse_response_header(
                response_header(tag=tpm2_measure.TPM_ST_SESSIONS),
                expected_tag=tpm2_measure.TPM_ST_NO_SESSIONS,
            )

    def test_nonzero_response_code_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "TPM command failed: 0x00000101"):
            tpm2_measure.parse_response_header(response_header(result=0x101))

    def test_truncated_pcr_selection_is_rejected(self):
        payload = struct.pack(">IIHB", 7, 1, tpm2_measure.TPM_ALG_SHA256, 3) + b"\x00\x00"
        with self.assertRaisesRegex(RuntimeError, "truncated PCR selection"):
            tpm2_measure.parse_pcr_read_payload(payload)

    def test_truncated_pcr_digest_is_rejected(self):
        payload = pcr_read_payload()[:-1]
        with self.assertRaisesRegex(RuntimeError, "truncated PCR digest"):
            tpm2_measure.parse_pcr_read_payload(payload)

    def test_wrong_pcr_digest_count_is_rejected(self):
        payload = pcr_read_payload()[:14] + struct.pack(">I", 2)
        with self.assertRaisesRegex(RuntimeError, "unexpected PCR digest count"):
            tpm2_measure.parse_pcr_read_payload(payload)

    def test_wrong_pcr_digest_size_is_rejected(self):
        payload = pcr_read_payload(b"\x5a" * 31)
        with self.assertRaisesRegex(RuntimeError, "unexpected PCR digest size"):
            tpm2_measure.parse_pcr_read_payload(payload)

    def test_wrong_pcr_bank_is_rejected(self):
        payload = bytearray(pcr_read_payload())
        struct.pack_into(">H", payload, 8, 0x000C)
        with self.assertRaisesRegex(RuntimeError, "unexpected PCR bank"):
            tpm2_measure.parse_pcr_read_payload(payload)

    def test_wrong_pcr_selection_is_rejected(self):
        payload = bytearray(pcr_read_payload())
        payload[11:14] = (1 << 15).to_bytes(3, "little")
        with self.assertRaisesRegex(RuntimeError, "unexpected PCR selection"):
            tpm2_measure.parse_pcr_read_payload(payload)

    def test_trailing_pcr_data_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "trailing PCR response data"):
            tpm2_measure.parse_pcr_read_payload(pcr_read_payload() + b"x")


class TpmSocketTests(unittest.TestCase):
    @mock.patch.object(tpm2_measure.socket, "socket")
    def test_connected_socket_has_finite_timeout(self, socket_factory):
        sock = socket_factory.return_value

        result = tpm2_measure.connect_tpm_socket("/tmp/test-tpm.sock")

        socket_factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout.assert_called_once_with(tpm2_measure.TPM_SOCKET_TIMEOUT_SECONDS)
        sock.connect.assert_called_once_with("/tmp/test-tpm.sock")
        self.assertGreater(tpm2_measure.TPM_SOCKET_TIMEOUT_SECONDS, 0)
        self.assertIs(result, sock)


if __name__ == "__main__":
    unittest.main(verbosity=2)

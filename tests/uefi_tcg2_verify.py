#!/usr/bin/env python3
"""Independently query persistent swtpm PCR16 and verify EFI serial evidence."""

import argparse
import array
import hashlib
import json
import re
import socket
import struct
from pathlib import Path


PCR_INDEX = 16
SHA256_ALG = 0x000B
CMD_SET_DATAFD = 0x10
EVIDENCE = b"BearBoot Wave 18 real OVMF TCG2 PCR16 machine proof v1"
HEX_LINE = re.compile(
    r"^BBP-UEFI-TCG2: (PCR16_BEFORE|EVIDENCE_SHA256|PCR16_AFTER) "
    r"([0-9a-f]{64})$",
    re.MULTILINE,
)


def recv_exact(channel: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = channel.recv(count - len(result))
        if not chunk:
            raise RuntimeError("swtpm closed a truncated response")
        result.extend(chunk)
    return bytes(result)


def parse_pcr_read(response: bytes) -> tuple[int, bytes]:
    if len(response) < 10:
        raise RuntimeError("TPM response header is truncated")
    tag, declared, response_code = struct.unpack_from(">HII", response)
    if declared != len(response) or declared > 1024:
        raise RuntimeError("TPM response has an invalid bounded length")
    if tag != 0x8001 or response_code != 0:
        raise RuntimeError(
            f"TPM response tag/code rejected: 0x{tag:04x}/0x{response_code:08x}"
        )

    offset = 10
    if len(response) - offset < 8:
        raise RuntimeError("TPM PCR_Read selection header is truncated")
    update_counter, selection_count = struct.unpack_from(">II", response, offset)
    offset += 8
    if selection_count != 1 or len(response) - offset < 6:
        raise RuntimeError("TPM PCR_Read returned an invalid selection count")
    algorithm = struct.unpack_from(">H", response, offset)[0]
    select_size = response[offset + 2]
    selection = response[offset + 3 : offset + 6]
    offset += 6
    if algorithm != SHA256_ALG or select_size != 3 or selection != b"\0\0\1":
        raise RuntimeError("TPM PCR_Read did not return only SHA-256 PCR16")
    if len(response) - offset < 6:
        raise RuntimeError("TPM PCR_Read digest header is truncated")
    digest_count = struct.unpack_from(">I", response, offset)[0]
    digest_size = struct.unpack_from(">H", response, offset + 4)[0]
    offset += 6
    if digest_count != 1 or digest_size != 32:
        raise RuntimeError("TPM PCR_Read returned an invalid digest list")
    if len(response) - offset != 32:
        raise RuntimeError("TPM PCR_Read digest is truncated or has trailing bytes")
    return update_counter, response[offset:]


def query_swtpm(control_path: Path) -> tuple[int, bytes]:
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.settimeout(5.0)
    command_channel, passed_channel = socket.socketpair()
    command_channel.settimeout(5.0)
    try:
        control.connect(str(control_path))
        descriptors = array.array("i", [passed_channel.fileno()])
        control.sendmsg(
            [struct.pack(">I", CMD_SET_DATAFD)],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
        )
        passed_channel.close()
        result = recv_exact(control, 4)
        if result != b"\0\0\0\0":
            raise RuntimeError(f"swtpm CMD_SET_DATAFD failed: {result.hex()}")

        selection = b"\0\0\1"
        command = (
            struct.pack(">HII", 0x8001, 20, 0x0000017E)
            + struct.pack(">IH", 1, SHA256_ALG)
            + bytes([len(selection)])
            + selection
        )
        command_channel.sendall(command)
        header = recv_exact(command_channel, 10)
        declared = struct.unpack_from(">I", header, 2)[0]
        if declared < 10 or declared > 1024:
            raise RuntimeError("swtpm declared an invalid TPM response length")
        response = header + recv_exact(command_channel, declared - 10)
        return parse_pcr_read(response)
    finally:
        passed_channel.close()
        command_channel.close()
        control.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--serial", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    serial = args.serial.read_bytes().decode("ascii", errors="strict").replace("\r", "")
    found = HEX_LINE.findall(serial)
    matches = dict(found)
    required = {"PCR16_BEFORE", "EVIDENCE_SHA256", "PCR16_AFTER"}
    if len(found) != 3 or set(matches) != required:
        raise RuntimeError("serial log lacks one exact, unique digest evidence line")
    if "BBP-UEFI-TCG2: PASS\n" not in serial:
        raise RuntimeError("serial log lacks EFI PASS")
    if "BBP-UEFI-TCG2: FAIL:" in serial:
        raise RuntimeError("serial log contains EFI failure")

    before = bytes.fromhex(matches["PCR16_BEFORE"])
    serial_evidence_digest = bytes.fromhex(matches["EVIDENCE_SHA256"])
    serial_after = bytes.fromhex(matches["PCR16_AFTER"])
    independent_evidence_digest = hashlib.sha256(EVIDENCE).digest()
    expected_after = hashlib.sha256(before + independent_evidence_digest).digest()
    if serial_evidence_digest != independent_evidence_digest:
        raise RuntimeError("EFI evidence digest disagrees with host SHA-256")
    if serial_after != expected_after:
        raise RuntimeError("EFI PCR16_AFTER disagrees with host extend calculation")

    update_counter, socket_pcr = query_swtpm(args.control)
    if socket_pcr != expected_after:
        raise RuntimeError("independent swtpm PCR16 disagrees with expected extend")

    result = {
        "proof": "real-ovmf-efi-tcg2-swtpm-pcr16",
        "pcr": PCR_INDEX,
        "algorithm": "sha256",
        "evidence_ascii": EVIDENCE.decode("ascii"),
        "pcr16_before": before.hex(),
        "evidence_sha256": independent_evidence_digest.hex(),
        "expected_pcr16_after": expected_after.hex(),
        "efi_pcr16_after": serial_after.hex(),
        "independent_swtpm_pcr16": socket_pcr.hex(),
        "tpm_update_counter": update_counter,
        "efi_exit_status": 33,
        "bbp_security_bounded_validation": True,
        "secure_boot_or_identity_claims": False,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("HOST-TPM: raw persistent swtpm PCR_Read PASS")
    print(f"HOST-TPM: PCR16 {socket_pcr.hex()}")
    print("WAVE18-UEFI-TCG2: MACHINE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

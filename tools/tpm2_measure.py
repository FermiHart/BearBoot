#!/usr/bin/env python3
"""Reproducible BBP v2 measurement proof against a real swtpm process."""
import hashlib
import json
import os
import socket
import struct
import subprocess
import tempfile
import time

TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS = 0x8002
TPM_CC_PCR_READ = 0x0000017E
TPM_CC_PCR_EXTEND = 0x00000182
TPM_RS_PW = 0x40000009
TPM_ALG_SHA256 = 0x000B
PCR = 16
TPM_HEADER_SIZE = 10
MAX_TPM_RESPONSE_SIZE = 4096
TPM_SOCKET_TIMEOUT_SECONDS = 5.0


def command(code, body=b"", sessions=False):
    tag = TPM_ST_SESSIONS if sessions else TPM_ST_NO_SESSIONS
    return struct.pack(">HII", tag, TPM_HEADER_SIZE + len(body), code) + body


def parse_response_header(header, expected_tag=TPM_ST_NO_SESSIONS):
    """Validate a complete TPM response header and return its declared size."""
    if len(header) != TPM_HEADER_SIZE:
        raise RuntimeError("truncated TPM response header")
    tag, size, result = struct.unpack(">HII", header)
    if tag not in (TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS):
        raise RuntimeError("invalid TPM response tag")
    if size < TPM_HEADER_SIZE or size > MAX_TPM_RESPONSE_SIZE:
        raise RuntimeError("invalid TPM response size")
    if result != 0:
        raise RuntimeError(f"TPM command failed: 0x{result:08x}")
    if tag != expected_tag:
        raise RuntimeError("invalid TPM response tag")
    return size


def exchange(sock, request):
    sock.sendall(request)
    header = receive_exact(sock, TPM_HEADER_SIZE)
    expected_tag = struct.unpack_from(">H", request)[0]
    size = parse_response_header(header, expected_tag)
    return receive_exact(sock, size - TPM_HEADER_SIZE)


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise RuntimeError("truncated TPM response")
        data.extend(block)
    return bytes(data)


def parse_pcr_read_payload(payload):
    """Extract one SHA-256 digest from a bounded TPM2_PCR_Read payload."""
    if len(payload) > MAX_TPM_RESPONSE_SIZE - TPM_HEADER_SIZE:
        raise RuntimeError("invalid TPM response size")
    if len(payload) < 8:
        raise RuntimeError("truncated PCR selection")

    offset = 4  # Skip pcrUpdateCounter.
    selection_count = struct.unpack_from(">I", payload, offset)[0]
    offset += 4
    if selection_count != 1:
        raise RuntimeError("unexpected PCR selection count")
    if selection_count > (len(payload) - offset) // 3:
        raise RuntimeError("truncated PCR selection")
    for _ in range(selection_count):
        if len(payload) - offset < 3:
            raise RuntimeError("truncated PCR selection")
        algorithm, selection_size = struct.unpack_from(">HB", payload, offset)
        offset += 3
        if len(payload) - offset < selection_size:
            raise RuntimeError("truncated PCR selection")
        selection = payload[offset:offset + selection_size]
        offset += selection_size
        if algorithm != TPM_ALG_SHA256:
            raise RuntimeError("unexpected PCR bank")
        expected_selection = (1 << PCR).to_bytes(3, "little")
        if selection != expected_selection:
            raise RuntimeError("unexpected PCR selection")

    if len(payload) - offset < 4:
        raise RuntimeError("truncated PCR digest section")
    digest_count = struct.unpack_from(">I", payload, offset)[0]
    offset += 4
    if digest_count != 1:
        raise RuntimeError("unexpected PCR digest count")
    if len(payload) - offset < 2:
        raise RuntimeError("truncated PCR digest")
    digest_size = struct.unpack_from(">H", payload, offset)[0]
    offset += 2
    if digest_size != hashlib.sha256().digest_size:
        raise RuntimeError("unexpected PCR digest size")
    if len(payload) - offset < digest_size:
        raise RuntimeError("truncated PCR digest")
    digest = payload[offset:offset + digest_size]
    offset += digest_size
    if offset != len(payload):
        raise RuntimeError("trailing PCR response data")
    return digest


def pcr_read(sock):
    selection = struct.pack(">IH B3s", 1, TPM_ALG_SHA256, 3,
                            (1 << PCR).to_bytes(3, "little"))
    payload = exchange(sock, command(TPM_CC_PCR_READ, selection))
    return parse_pcr_read_payload(payload)


def pcr_extend(sock, digest):
    authorization = struct.pack(">IHBH", TPM_RS_PW, 0, 0, 0)
    body = struct.pack(">II", PCR, len(authorization)) + authorization
    body += struct.pack(">IH", 1, TPM_ALG_SHA256) + digest
    exchange(sock, command(TPM_CC_PCR_EXTEND, body, sessions=True))


def canonical_measurement():
    domain = b"BBP-V2-DIGEST\0\0\1"
    payloads = [
        (0x4242503200000001, struct.pack("<HHIII", 2, 0, 1, 0, 0)),
        (0x4242503200000002,
         struct.pack("<IIQQIIII", 1, 32, 0x100000, 0x200000, 1, 0, 0, 0)),
        (0x4242503200000003,
         struct.pack("<QQ", 0x40080000, 0xFFFFFFFF80000000)),
        (0x4242503200000004, struct.pack("<II", 0, 4) + b"\xd0\x0d\xfe\xed"),
    ]
    stream = bytearray(domain + struct.pack("<HHIII", 2, 0, 0, len(payloads), 0))
    for type_id, payload in payloads:
        stream += struct.pack("<QIHHQII", type_id, 0, 1, 0, len(payload), 0, 0)
        stream += payload
    return hashlib.sha256(stream).digest()


def connect_tpm_socket(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(TPM_SOCKET_TIMEOUT_SECONDS)
    try:
        sock.connect(path)
    except Exception:
        sock.close()
        raise
    return sock


def main():
    with tempfile.TemporaryDirectory(prefix="bbp-swtpm-") as directory:
        data_socket = os.path.join(directory, "tpm.sock")
        control_socket = os.path.join(directory, "ctrl.sock")
        process = subprocess.Popen([
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={directory}",
            "--server", f"type=unixio,path={data_socket}",
            "--ctrl", f"type=unixio,path={control_socket}",
            "--flags", "not-need-init,startup-clear",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if os.path.exists(data_socket):
                    break
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                time.sleep(0.01)
            with connect_tpm_socket(data_socket) as sock:
                before = pcr_read(sock)
                measurement = canonical_measurement()
                pcr_extend(sock, measurement)
                after = pcr_read(sock)
            expected = hashlib.sha256(before + measurement).digest()
            if after != expected:
                raise RuntimeError("PCR value does not match TPM extend formula")
            print(json.dumps({"hash_algorithm": "sha256", "pcr": PCR,
                              "measurement": measurement.hex(),
                              "pcr_before": before.hex(),
                              "pcr_after": after.hex()}, sort_keys=True))
            print("BBP v2 swtpm measurement: PASS")
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()

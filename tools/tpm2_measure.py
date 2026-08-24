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


def command(code, body=b"", sessions=False):
    tag = TPM_ST_SESSIONS if sessions else TPM_ST_NO_SESSIONS
    return struct.pack(">HII", tag, 10 + len(body), code) + body


def exchange(sock, request):
    sock.sendall(request)
    header = receive_exact(sock, 10)
    _, size, result = struct.unpack(">HII", header)
    if size < 10:
        raise RuntimeError("invalid TPM response size")
    payload = receive_exact(sock, size - 10)
    if result != 0:
        raise RuntimeError(f"TPM command failed: 0x{result:08x}")
    return payload


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise RuntimeError("truncated TPM response")
        data.extend(block)
    return bytes(data)


def pcr_read(sock):
    selection = struct.pack(">IH B3s", 1, TPM_ALG_SHA256, 3,
                            (1 << PCR).to_bytes(3, "little"))
    payload = exchange(sock, command(TPM_CC_PCR_READ, selection))
    offset = 4
    count = struct.unpack_from(">I", payload, offset)[0]
    offset += 4
    for _ in range(count):
        size = payload[offset + 2]
        offset += 3 + size
    digest_count = struct.unpack_from(">I", payload, offset)[0]
    offset += 4
    if digest_count != 1:
        raise RuntimeError("unexpected PCR digest count")
    size = struct.unpack_from(">H", payload, offset)[0]
    return payload[offset + 2:offset + 2 + size]


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
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.connect(data_socket)
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

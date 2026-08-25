"""Bounded BBP auth2 manifest and signed-envelope host proof.

Cryptographic operations are delegated to the installed OpenSSL command-line
provider. This module only implements framing, policy, and strict ECDSA
signature encoding.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ALG_ECDSA_P256_SHA256 = 1
ROLE_RELEASE = 1
ROLE_RECOVERY = 2

P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
MAX_U64 = (1 << 64) - 1
MAX_KEYS = 32
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024

MANIFEST_MAGIC = b"BBP2KEY\0"
MANIFEST_VERSION = 1
MANIFEST_HEADER = struct.Struct("<8sHHHHIIQQ32s64s")
MANIFEST_ENTRY = struct.Struct("<32sHHIQQ65s7s")
MANIFEST_HEADER_SIZE = MANIFEST_HEADER.size
MANIFEST_ENTRY_SIZE = MANIFEST_ENTRY.size
MANIFEST_SIGNATURE_OFFSET = 72

ENVELOPE_MAGIC = b"BBP2SIG\0"
ENVELOPE_VERSION = 1
ENVELOPE_HEADER = struct.Struct("<8sHHHHIIQQ32s64s")
ENVELOPE_HEADER_SIZE = ENVELOPE_HEADER.size
ENVELOPE_SIGNATURE_OFFSET = 72

KEY_FLAG_REVOKED = 1
_SPKI_P256_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)


class Auth2Error(ValueError):
    """The object is malformed, unauthentic, or rejected by policy."""


@dataclass(frozen=True)
class KeyPolicy:
    public_key: os.PathLike[str] | str
    role: int
    activation_generation: int
    retirement_generation: int
    revoked: bool = False


@dataclass(frozen=True)
class ManifestKey:
    key_id: bytes
    algorithm: int
    role: int
    activation_generation: int
    retirement_generation: int
    revoked: bool
    public_point: bytes


@dataclass(frozen=True)
class Manifest:
    security_generation: int
    root_key_id: bytes
    keys: tuple[ManifestKey, ...]


@dataclass(frozen=True)
class VerifiedEnvelope:
    payload: bytes
    security_generation: int
    signer_key_id: bytes
    role: int


def _openssl_path() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise Auth2Error("OpenSSL provider is unavailable")
    return executable


def _run_openssl(arguments: list[str], data: bytes = b"") -> bytes:
    try:
        result = subprocess.run(
            [_openssl_path(), *arguments],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise Auth2Error("OpenSSL provider failed to start") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise Auth2Error(f"OpenSSL provider rejected operation: {detail}")
    return result.stdout


def _public_spki(public_key: os.PathLike[str] | str) -> bytes:
    path = os.fspath(public_key)
    try:
        der = _run_openssl(["pkey", "-pubin", "-in", path,
                            "-pubout", "-outform", "DER"])
    except Auth2Error:
        der = _run_openssl(["pkey", "-in", path, "-pubout",
                            "-outform", "DER"])
    if len(der) != len(_SPKI_P256_PREFIX) + 65 or not der.startswith(
            _SPKI_P256_PREFIX):
        raise Auth2Error("key is not an ECDSA P-256 public key")
    point = der[len(_SPKI_P256_PREFIX):]
    if point[0] != 4:
        raise Auth2Error("P-256 public key is not uncompressed SEC1")
    return der


def _spki_from_point(point: bytes) -> bytes:
    if len(point) != 65 or point[0] != 4:
        raise Auth2Error("malformed P-256 public point")
    return _SPKI_P256_PREFIX + point


def _validate_public_point(point: bytes) -> bytes:
    spki = _spki_from_point(point)
    _run_openssl(["pkey", "-pubin", "-pubcheck", "-noout"],
                 _pem_public_key(point))
    return spki


def _pem_public_key(point: bytes) -> bytes:
    encoded = base64.b64encode(_spki_from_point(point)).decode("ascii")
    lines = [encoded[index:index + 64]
             for index in range(0, len(encoded), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) +
            "\n-----END PUBLIC KEY-----\n").encode("ascii")


def _key_id(spki: bytes, algorithm: int = ALG_ECDSA_P256_SHA256) -> bytes:
    if algorithm < 0 or algorithm > 0xFFFF:
        raise Auth2Error("invalid key algorithm")
    return struct.pack("<H", algorithm) + hashlib.sha256(spki).digest()[:30]


def key_id_from_public_key(public_key: os.PathLike[str] | str) -> bytes:
    """Return the algorithm tag followed by a 240-bit SPKI digest."""
    return _key_id(_public_spki(public_key))


def _encode_der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if encoded[0] & 0x80:
        encoded = b"\0" + encoded
    return b"\x02" + bytes((len(encoded),)) + encoded


def ecdsa_raw_to_der(signature: bytes) -> bytes:
    """Convert fixed-width r||s into strict ASN.1 DER for OpenSSL."""
    if len(signature) != 64:
        raise Auth2Error("ECDSA signature must be 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise Auth2Error("ECDSA signature scalar is out of range")
    body = _encode_der_integer(r) + _encode_der_integer(s)
    return b"\x30" + bytes((len(body),)) + body


def _decode_der_integer(der: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(der) or der[offset] != 2:
        raise Auth2Error("malformed OpenSSL ECDSA signature")
    size = der[offset + 1]
    start = offset + 2
    end = start + size
    if size == 0 or end > len(der):
        raise Auth2Error("malformed OpenSSL ECDSA signature")
    encoded = der[start:end]
    if encoded[0] & 0x80:
        raise Auth2Error("negative ECDSA signature scalar")
    if len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80:
        raise Auth2Error("non-canonical ECDSA signature scalar")
    return int.from_bytes(encoded, "big"), end


def _ecdsa_der_to_raw(signature: bytes) -> bytes:
    if len(signature) < 6 or signature[0] != 0x30:
        raise Auth2Error("malformed OpenSSL ECDSA signature")
    if signature[1] & 0x80 or signature[1] != len(signature) - 2:
        raise Auth2Error("malformed OpenSSL ECDSA signature")
    r, offset = _decode_der_integer(signature, 2)
    s, offset = _decode_der_integer(signature, offset)
    if offset != len(signature) or not (0 < r < P256_ORDER and
                                        0 < s < P256_ORDER):
        raise Auth2Error("OpenSSL ECDSA signature scalar is out of range")
    s = min(s, P256_ORDER - s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _check_low_s(signature: bytes) -> None:
    if len(signature) != 64:
        raise Auth2Error("ECDSA signature must be 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise Auth2Error("ECDSA signature scalar is out of range")
    if s > P256_ORDER // 2:
        raise Auth2Error("high-S ECDSA signature rejected")


def _sign(data: bytes, private_key: os.PathLike[str] | str) -> bytes:
    _public_spki(private_key)
    der = _run_openssl(["dgst", "-sha256", "-sign",
                        os.fspath(private_key)], data)
    return _ecdsa_der_to_raw(der)


def _verify_signature(data: bytes, signature: bytes, point: bytes) -> None:
    _check_low_s(signature)
    with tempfile.TemporaryDirectory(prefix="bbp-auth2-") as directory:
        public_path = Path(directory) / "public.pem"
        signature_path = Path(directory) / "signature.der"
        public_path.write_bytes(_pem_public_key(point))
        signature_path.write_bytes(ecdsa_raw_to_der(signature))
        result = subprocess.run(
            [_openssl_path(), "dgst", "-sha256", "-verify",
             os.fspath(public_path), "-signature", os.fspath(signature_path)],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise Auth2Error("ECDSA authentication failed")


def _validate_generation(generation: int, label: str) -> None:
    if not isinstance(generation, int) or isinstance(generation, bool) or not (
            0 < generation <= MAX_U64):
        raise Auth2Error(f"invalid {label} security generation")


def manifest_signing_bytes(manifest: bytes) -> bytes:
    """Return the exact root-signed manifest bytes with signature zeroed."""
    if len(manifest) < MANIFEST_HEADER_SIZE:
        raise Auth2Error("manifest extent is truncated")
    signed = bytearray(manifest)
    signed[MANIFEST_SIGNATURE_OFFSET:MANIFEST_SIGNATURE_OFFSET + 64] = bytes(64)
    return bytes(signed)


def build_manifest(root_private_key: os.PathLike[str] | str,
                   security_generation: int,
                   policies: Iterable[KeyPolicy]) -> bytes:
    """Build and root-sign a canonical fixed-entry key manifest."""
    _validate_generation(security_generation, "manifest")
    root_spki = _public_spki(root_private_key)
    records = []
    seen = set()
    for policy in policies:
        if policy.role not in (ROLE_RELEASE, ROLE_RECOVERY):
            raise Auth2Error("unknown signer role")
        _validate_generation(policy.activation_generation, "activation")
        _validate_generation(policy.retirement_generation, "retirement")
        if policy.activation_generation > policy.retirement_generation:
            raise Auth2Error("activation follows retirement")
        spki = _public_spki(policy.public_key)
        identity = _key_id(spki)
        if identity in seen:
            raise Auth2Error("duplicate key in manifest")
        seen.add(identity)
        records.append((identity, policy, spki[len(_SPKI_P256_PREFIX):]))
    if not records or len(records) > MAX_KEYS:
        raise Auth2Error("manifest key count is out of bounds")
    records.sort(key=lambda record: record[0])
    total_size = MANIFEST_HEADER_SIZE + len(records) * MANIFEST_ENTRY_SIZE
    raw = bytearray(MANIFEST_HEADER.pack(
        MANIFEST_MAGIC,
        MANIFEST_VERSION,
        MANIFEST_HEADER_SIZE,
        ALG_ECDSA_P256_SHA256,
        MANIFEST_ENTRY_SIZE,
        0,
        len(records),
        security_generation,
        total_size,
        _key_id(root_spki),
        bytes(64),
    ))
    for identity, policy, point in records:
        raw.extend(MANIFEST_ENTRY.pack(
            identity,
            ALG_ECDSA_P256_SHA256,
            policy.role,
            KEY_FLAG_REVOKED if policy.revoked else 0,
            policy.activation_generation,
            policy.retirement_generation,
            point,
            bytes(7),
        ))
    signature = _sign(bytes(raw), root_private_key)
    raw[MANIFEST_SIGNATURE_OFFSET:MANIFEST_SIGNATURE_OFFSET + 64] = signature
    return bytes(raw)


def verify_manifest(manifest: bytes,
                    root_public_key: os.PathLike[str] | str,
                    minimum_generation: int = 0) -> Manifest:
    """Authenticate and parse a manifest against an out-of-band root key."""
    if len(manifest) < MANIFEST_HEADER_SIZE:
        raise Auth2Error("manifest extent is truncated")
    (magic, version, header_size, algorithm, entry_size, flags, key_count,
     generation, total_size, root_id, signature) = MANIFEST_HEADER.unpack_from(
         manifest)
    if magic != MANIFEST_MAGIC or version != MANIFEST_VERSION:
        raise Auth2Error("unsupported manifest framing")
    if algorithm != ALG_ECDSA_P256_SHA256:
        raise Auth2Error("unknown manifest algorithm")
    if header_size != MANIFEST_HEADER_SIZE or entry_size != MANIFEST_ENTRY_SIZE:
        raise Auth2Error("unsupported manifest fixed widths")
    if flags != 0:
        raise Auth2Error("unsupported manifest flags")
    if key_count == 0 or key_count > MAX_KEYS:
        raise Auth2Error("manifest key count is out of bounds")
    expected_size = MANIFEST_HEADER_SIZE + key_count * MANIFEST_ENTRY_SIZE
    if total_size != expected_size or len(manifest) != expected_size:
        raise Auth2Error("manifest extent mismatch")
    _validate_generation(generation, "manifest")
    if minimum_generation < 0 or minimum_generation > MAX_U64:
        raise Auth2Error("invalid minimum security generation")
    if generation < minimum_generation:
        raise Auth2Error("manifest security generation is below policy floor")

    root_spki = _public_spki(root_public_key)
    if root_id != _key_id(root_spki):
        raise Auth2Error("wrong root key identity")
    _verify_signature(manifest_signing_bytes(manifest), signature,
                      root_spki[len(_SPKI_P256_PREFIX):])

    keys = []
    seen = set()
    offset = MANIFEST_HEADER_SIZE
    for _ in range(key_count):
        (identity, key_algorithm, role, key_flags, activation, retirement,
         point, reserved) = MANIFEST_ENTRY.unpack_from(manifest, offset)
        offset += MANIFEST_ENTRY_SIZE
        if key_algorithm != ALG_ECDSA_P256_SHA256:
            raise Auth2Error("unknown manifest key algorithm")
        if role not in (ROLE_RELEASE, ROLE_RECOVERY):
            raise Auth2Error("unknown manifest signer role")
        if key_flags & ~KEY_FLAG_REVOKED:
            raise Auth2Error("unsupported manifest key flags")
        if reserved != bytes(7):
            raise Auth2Error("nonzero manifest reserved bytes")
        _validate_generation(activation, "activation")
        _validate_generation(retirement, "retirement")
        if activation > retirement:
            raise Auth2Error("manifest activation follows retirement")
        spki = _validate_public_point(point)
        if identity != _key_id(spki, key_algorithm):
            raise Auth2Error("manifest key identity mismatch")
        if identity in seen:
            raise Auth2Error("duplicate key in manifest")
        seen.add(identity)
        keys.append(ManifestKey(identity, key_algorithm, role, activation,
                                retirement, bool(key_flags & KEY_FLAG_REVOKED),
                                point))
    return Manifest(generation, root_id, tuple(keys))


def envelope_signing_bytes(envelope: bytes) -> bytes:
    """Return the exact signer-authenticated bytes with signature zeroed."""
    if len(envelope) < ENVELOPE_HEADER_SIZE:
        raise Auth2Error("envelope extent is truncated")
    signed = bytearray(envelope)
    signed[ENVELOPE_SIGNATURE_OFFSET:ENVELOPE_SIGNATURE_OFFSET + 64] = bytes(64)
    return bytes(signed)


def sign_envelope(payload: bytes,
                  private_key: os.PathLike[str] | str,
                  security_generation: int,
                  role: int = ROLE_RELEASE) -> bytes:
    """Sign an exact bounded payload extent with a release or recovery key."""
    _validate_generation(security_generation, "envelope")
    if role not in (ROLE_RELEASE, ROLE_RECOVERY):
        raise Auth2Error("unknown envelope signer role")
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise Auth2Error("payload extent exceeds auth2 bound")
    signer_spki = _public_spki(private_key)
    raw = bytearray(ENVELOPE_HEADER.pack(
        ENVELOPE_MAGIC,
        ENVELOPE_VERSION,
        ENVELOPE_HEADER_SIZE,
        ALG_ECDSA_P256_SHA256,
        role,
        0,
        0,
        security_generation,
        len(payload),
        _key_id(signer_spki),
        bytes(64),
    ))
    raw.extend(payload)
    signature = _sign(bytes(raw), private_key)
    raw[ENVELOPE_SIGNATURE_OFFSET:ENVELOPE_SIGNATURE_OFFSET + 64] = signature
    return bytes(raw)


def verify_envelope(envelope: bytes,
                    manifest_bytes: bytes,
                    root_public_key: os.PathLike[str] | str,
                    minimum_generation: int = 0,
                    allow_recovery: bool = False) -> VerifiedEnvelope:
    """Verify exact framing, root policy, signer role, and payload signature."""
    if len(envelope) < ENVELOPE_HEADER_SIZE:
        raise Auth2Error("envelope extent is truncated")
    (magic, version, header_size, algorithm, role, flags, reserved, generation,
     payload_size, signer_id, signature) = ENVELOPE_HEADER.unpack_from(envelope)
    if magic != ENVELOPE_MAGIC or version != ENVELOPE_VERSION:
        raise Auth2Error("unsupported envelope framing")
    if algorithm != ALG_ECDSA_P256_SHA256:
        raise Auth2Error("unknown envelope algorithm")
    if header_size != ENVELOPE_HEADER_SIZE:
        raise Auth2Error("unsupported envelope fixed width")
    if role not in (ROLE_RELEASE, ROLE_RECOVERY):
        raise Auth2Error("unknown envelope signer role")
    if flags != 0 or reserved != 0:
        raise Auth2Error("unsupported envelope flags or reserved bytes")
    if payload_size > MAX_PAYLOAD_SIZE or len(envelope) != (
            ENVELOPE_HEADER_SIZE + payload_size):
        raise Auth2Error("envelope payload extent mismatch")
    _validate_generation(generation, "envelope")
    _check_low_s(signature)

    manifest = verify_manifest(manifest_bytes, root_public_key,
                               minimum_generation)
    if generation != manifest.security_generation:
        raise Auth2Error("envelope and manifest security generation mismatch")
    signer = next((key for key in manifest.keys
                   if key.key_id == signer_id), None)
    if signer is None:
        raise Auth2Error("unknown signer key identity")
    if signer.role != role:
        raise Auth2Error("signer role does not match manifest")
    if role == ROLE_RECOVERY and not allow_recovery:
        raise Auth2Error("recovery role requires explicit policy")
    if signer.revoked:
        raise Auth2Error("signer key is revoked")
    if generation < signer.activation_generation:
        raise Auth2Error("signer key is not active")
    if generation > signer.retirement_generation:
        raise Auth2Error("signer key is retired")
    _verify_signature(envelope_signing_bytes(envelope), signature,
                      signer.public_point)
    return VerifiedEnvelope(envelope[ENVELOPE_HEADER_SIZE:], generation,
                            signer_id, role)

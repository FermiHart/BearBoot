#!/usr/bin/env python3
"""Strict TPM2 NV counter provider for the experimental rollback model."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import math
import os
from pathlib import Path
import socket
import stat
import struct
import time

from tools.bbp_rollback_state import FloorProvider, RollbackStateError, UINT64_MAX


TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS = 0x8002
TPM_CC_NV_INCREMENT = 0x00000134
TPM_CC_NV_READ = 0x0000014E
TPM_CC_NV_READ_PUBLIC = 0x00000169
TPM_RH_OWNER = 0x40000001
TPM_RS_PW = 0x40000009
TPM_ALG_SHA256 = 0x000B
TPM_HT_NV_INDEX = 0x01
TPMA_SESSION_CONTINUESESSION = 0x01
TPMA_NV_AUTHWRITE = 0x00000004
TPMA_NV_COUNTER = 0x00000010
TPMA_NV_AUTHREAD = 0x00040000
TPMA_NV_NO_DA = 0x02000000
TPMA_NV_WRITTEN = 0x20000000
NV_EXPECTED_ATTRIBUTES = (
    TPMA_NV_AUTHWRITE | TPMA_NV_COUNTER | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA
)
DEFAULT_NV_INDEX = 0x01804242
TPM_HEADER_SIZE = 10
MAX_TPM_AUTH_SIZE = 32
MAX_TPM_RESPONSE_SIZE = 1024
TPM_SOCKET_TIMEOUT_SECONDS = 5.0


class TpmNvError(RollbackStateError):
    """Base class for TPM NV counter failures."""


class TpmTransportError(TpmNvError):
    """The TPM exchange did not complete with a bounded response."""


class TpmLockError(TpmNvError):
    """The cooperating-writer lock is unavailable or untrusted."""


class TpmNvMetadataError(TpmNvError):
    """The provisioned NV public area does not match the pinned contract."""


class TpmNvRollbackError(TpmNvError):
    """The backend returned a floor below one already observed."""


class TpmNvAmbiguousError(TpmNvError):
    """An increment result could not be reconciled with authoritative state."""


class TpmResponseError(TpmNvError):
    def __init__(self, response_code):
        self.response_code = response_code
        super().__init__(f"TPM command failed: 0x{response_code:08x}")


@dataclass(frozen=True)
class NvPublic:
    index: int
    attributes: int
    name: bytes
    written: bool


def _uint32(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not (
            0 <= value <= 0xFFFFFFFF):
        raise ValueError(f"{label} must fit in uint32")
    return value


def _uint64(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not (
            0 <= value <= UINT64_MAX):
        raise ValueError(f"{label} must fit in uint64")
    return value


def _nv_index(value, label="NV index"):
    value = _uint32(value, label)
    if value >> 24 != TPM_HT_NV_INDEX:
        raise ValueError(f"{label} must be an NV index handle")
    return value


def _auth_value(value, label="NV index authorization"):
    if (not isinstance(value, bytes) or
            not (1 <= len(value) <= MAX_TPM_AUTH_SIZE) or value[-1] == 0):
        raise ValueError(
            f"{label} must be 1..{MAX_TPM_AUTH_SIZE} canonical bytes"
        )
    return value


def _header(tag, size, command_code):
    return struct.pack(">HII", tag, size, command_code)


def _password_authorization(auth_value):
    auth_value = _auth_value(auth_value)
    return struct.pack(">IHBH", TPM_RS_PW, 0, 0, len(auth_value)) + auth_value


def _session_command(command_code, handles, auth_value, parameters=b""):
    authorization = _password_authorization(auth_value)
    size = TPM_HEADER_SIZE + len(handles) + 4 + len(authorization) + len(parameters)
    return (_header(TPM_ST_SESSIONS, size, command_code) + handles +
            struct.pack(">I", len(authorization)) + authorization + parameters)


def build_nv_read_public(index):
    index = _nv_index(index)
    return _header(TPM_ST_NO_SESSIONS, 14, TPM_CC_NV_READ_PUBLIC) + struct.pack(
        ">I", index
    )


def build_nv_read(index, index_auth):
    index = _nv_index(index)
    handles = struct.pack(">II", index, index)
    return _session_command(
        TPM_CC_NV_READ, handles, index_auth, struct.pack(">HH", 8, 0)
    )


def build_nv_increment(index, index_auth):
    index = _nv_index(index)
    return _session_command(
        TPM_CC_NV_INCREMENT, struct.pack(">II", index, index), index_auth
    )


def _response_payload(response, expected_tag):
    if not isinstance(response, bytes) or len(response) < TPM_HEADER_SIZE:
        raise TpmNvError("truncated TPM response header")
    tag, declared_size, response_code = struct.unpack_from(">HII", response)
    if declared_size < TPM_HEADER_SIZE or declared_size > MAX_TPM_RESPONSE_SIZE:
        raise TpmNvError("invalid TPM response size")
    if declared_size != len(response):
        raise TpmNvError("TPM response extent does not match declared size")
    if response_code != 0:
        if tag != TPM_ST_NO_SESSIONS or declared_size != TPM_HEADER_SIZE:
            raise TpmNvError("malformed TPM error response")
        raise TpmResponseError(response_code)
    if tag != expected_tag:
        raise TpmNvError("unexpected TPM response tag")
    return response[TPM_HEADER_SIZE:]


def parse_nv_read_public(response, expected_index,
                         expected_attributes=NV_EXPECTED_ATTRIBUTES):
    expected_index = _nv_index(expected_index, "expected NV index")
    expected_attributes = _uint32(expected_attributes, "expected attributes")
    payload = _response_payload(response, TPM_ST_NO_SESSIONS)
    if len(payload) < 2:
        raise TpmNvError("truncated NV public area")
    public_size = struct.unpack_from(">H", payload)[0]
    if public_size != 14 or len(payload) < 2 + public_size + 2:
        raise TpmNvError("invalid NV public area size")
    public = payload[2:2 + public_size]
    index, name_algorithm, attributes, policy_size = struct.unpack_from(
        ">IHIH", public
    )
    data_size = struct.unpack_from(">H", public, 12)[0]
    if index != expected_index:
        raise TpmNvMetadataError("unexpected NV index")
    if name_algorithm != TPM_ALG_SHA256:
        raise TpmNvMetadataError("unexpected NV name algorithm")
    if policy_size != 0 or data_size != 8:
        raise TpmNvMetadataError("unexpected NV policy or data size")
    if attributes not in (expected_attributes,
                           expected_attributes | TPMA_NV_WRITTEN):
        raise TpmNvMetadataError("unexpected NV attributes")

    offset = 2 + public_size
    name_size = struct.unpack_from(">H", payload, offset)[0]
    offset += 2
    if name_size != 34 or len(payload) - offset != name_size:
        raise TpmNvError("invalid NV Name extent")
    name = payload[offset:]
    expected_name = struct.pack(">H", TPM_ALG_SHA256) + hashlib.sha256(
        public
    ).digest()
    if name != expected_name:
        raise TpmNvMetadataError("NV Name does not authenticate public area")
    return NvPublic(index, attributes, name,
                    bool(attributes & TPMA_NV_WRITTEN))


def _parse_password_response(payload):
    expected = struct.pack(
        ">HBH", 0, TPMA_SESSION_CONTINUESESSION, 0
    )
    if payload != expected:
        raise TpmNvError("malformed TPM password-session response")


def parse_nv_read(response):
    payload = _response_payload(response, TPM_ST_SESSIONS)
    if len(payload) < 4:
        raise TpmNvError("truncated NV read response")
    parameter_size = struct.unpack_from(">I", payload)[0]
    if parameter_size != 10 or len(payload) != 4 + parameter_size + 5:
        raise TpmNvError("invalid NV read parameter extent")
    data_size = struct.unpack_from(">H", payload, 4)[0]
    if data_size != 8:
        raise TpmNvError("unexpected NV counter size")
    value = int.from_bytes(payload[6:14], "big")
    _parse_password_response(payload[14:])
    return value


def parse_nv_increment(response):
    payload = _response_payload(response, TPM_ST_SESSIONS)
    if len(payload) != 9 or struct.unpack_from(">I", payload)[0] != 0:
        raise TpmNvError("invalid NV increment parameter extent")
    _parse_password_response(payload[4:])


class SocketTransport:
    """One bounded TPM command to a UID-pinned private UNIX endpoint."""

    def __init__(self, socket_path, *, expected_uid,
                 timeout_seconds=TPM_SOCKET_TIMEOUT_SECONDS):
        self.socket_path = Path(socket_path)
        if not self.socket_path.is_absolute():
            raise ValueError("TPM socket path must be absolute")
        self.expected_uid = _uint32(expected_uid, "expected TPM peer UID")
        if (isinstance(timeout_seconds, bool) or
                not isinstance(timeout_seconds, (int, float)) or
                not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise ValueError("TPM socket timeout must be finite and positive")
        self.timeout_seconds = float(timeout_seconds)

    def _validate_endpoint(self):
        try:
            directory = os.stat(
                self.socket_path.parent, follow_symlinks=False
            )
            endpoint = os.stat(self.socket_path, follow_symlinks=False)
        except OSError as error:
            raise TpmTransportError("could not inspect TPM socket") from error
        if not stat.S_ISDIR(directory.st_mode):
            raise TpmTransportError("TPM socket parent is not a directory")
        if directory.st_uid not in (0, self.expected_uid):
            raise TpmTransportError("TPM socket parent has an unexpected owner")
        if stat.S_IMODE(directory.st_mode) & 0o022:
            raise TpmTransportError("TPM socket parent is writable by others")
        if not stat.S_ISSOCK(endpoint.st_mode):
            raise TpmTransportError("TPM endpoint is not a UNIX socket")
        if endpoint.st_uid != self.expected_uid:
            raise TpmTransportError("TPM socket has an unexpected owner")
        if stat.S_IMODE(endpoint.st_mode) & 0o022:
            raise TpmTransportError("TPM socket accepts untrusted writers")

    def _validate_peer(self, sock):
        if not hasattr(socket, "SO_PEERCRED"):
            raise TpmTransportError("UNIX peer credentials are unavailable")
        credential_format = "=iII"
        credential_size = struct.calcsize(credential_format)
        credentials = sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, credential_size
        )
        if len(credentials) != credential_size:
            raise TpmTransportError("invalid TPM peer credentials")
        _pid, uid, _gid = struct.unpack(credential_format, credentials)
        if uid != self.expected_uid:
            raise TpmTransportError("TPM peer UID does not match pinned owner")

    @staticmethod
    def _remaining_timeout(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TpmTransportError("TPM socket exchange deadline exceeded")
        return remaining

    @classmethod
    def _receive_exact(cls, sock, size, *, deadline):
        data = bytearray()
        while len(data) < size:
            sock.settimeout(cls._remaining_timeout(deadline))
            block = sock.recv(size - len(data))
            if not block:
                raise TpmTransportError("truncated TPM socket response")
            data.extend(block)
        return bytes(data)

    def exchange(self, request):
        deadline = time.monotonic() + self.timeout_seconds
        self._validate_endpoint()
        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self._remaining_timeout(deadline))
            sock.connect(os.fspath(self.socket_path))
            self._validate_peer(sock)
            sock.settimeout(self._remaining_timeout(deadline))
            sock.sendall(request)
            header = self._receive_exact(
                sock, TPM_HEADER_SIZE, deadline=deadline
            )
            _tag, size, _response_code = struct.unpack(">HII", header)
            if size < TPM_HEADER_SIZE or size > MAX_TPM_RESPONSE_SIZE:
                raise TpmTransportError("invalid TPM socket response size")
            return header + self._receive_exact(
                sock, size - TPM_HEADER_SIZE, deadline=deadline
            )
        except TpmTransportError:
            raise
        except (OSError, socket.timeout) as error:
            raise TpmTransportError("TPM socket exchange failed") from error
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


class Tpm2NvFloorProvider(FloorProvider):
    """Index-authorized NV counter for one cooperating writer set."""

    def __init__(self, transport, index=DEFAULT_NV_INDEX, *, index_auth,
                 lock_path, lock_timeout_seconds=5.0):
        if not callable(getattr(transport, "exchange", None)):
            raise TypeError("transport must provide exchange(request)")
        self.transport = transport
        self.index = _nv_index(index)
        self.index_auth = _auth_value(index_auth)
        self.lock_path = Path(lock_path)
        if not self.lock_path.is_absolute():
            raise ValueError("lock path must be absolute")
        if (isinstance(lock_timeout_seconds, bool) or
                not isinstance(lock_timeout_seconds, (int, float)) or
                not math.isfinite(lock_timeout_seconds) or
                lock_timeout_seconds < 0):
            raise ValueError("lock timeout must be a finite non-negative number")
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        self._last_floor = None

    def _validate_lock_directory(self):
        try:
            metadata = os.stat(
                self.lock_path.parent, follow_symlinks=False
            )
        except OSError as error:
            raise TpmLockError("could not inspect NV lock directory") from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise TpmLockError("NV lock parent is not a directory")
        if metadata.st_uid not in (0, os.geteuid()):
            raise TpmLockError("NV lock directory has an unexpected owner")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TpmLockError("NV lock directory is writable by others")

    @staticmethod
    def _validate_lock_file(metadata):
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise TpmLockError("NV lock is not a private regular file")
        if metadata.st_uid != os.geteuid():
            raise TpmLockError("NV lock has an unexpected owner")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise TpmLockError("NV lock permissions must be 0600")

    def _acquire_lock(self, fd):
        deadline = time.monotonic() + self.lock_timeout_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TpmLockError("timed out acquiring NV lock") from error
                time.sleep(min(0.01, remaining))

    @staticmethod
    def _release_lock(fd):
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @contextmanager
    def _locked(self):
        self._validate_lock_directory()
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError as error:
            raise TpmLockError("could not open NV lock") from error
        acquired = False
        try:
            metadata = os.fstat(fd)
            self._validate_lock_file(metadata)
            self._acquire_lock(fd)
            acquired = True
            path_metadata = os.stat(self.lock_path, follow_symlinks=False)
            self._validate_lock_file(path_metadata)
            if ((metadata.st_dev, metadata.st_ino) !=
                    (path_metadata.st_dev, path_metadata.st_ino)):
                raise TpmLockError("NV lock path changed during acquisition")
        except TpmLockError:
            if acquired:
                try:
                    self._release_lock(fd)
                except OSError:
                    pass
            else:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        except OSError as error:
            if acquired:
                try:
                    self._release_lock(fd)
                except OSError:
                    pass
            else:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise TpmLockError("could not validate NV lock") from error
        try:
            yield
        except BaseException:
            try:
                self._release_lock(fd)
            except OSError:
                pass
            raise
        else:
            try:
                self._release_lock(fd)
            except OSError as error:
                raise TpmLockError("could not release NV lock") from error

    def _read_floor_unlocked(self):
        public_response = self.transport.exchange(build_nv_read_public(self.index))
        public = parse_nv_read_public(public_response, self.index)
        if not public.written:
            raise TpmNvMetadataError("NV counter has not been initialized")
        observed = parse_nv_read(self.transport.exchange(
            build_nv_read(self.index, self.index_auth)
        ))
        if self._last_floor is not None and observed < self._last_floor:
            raise TpmNvRollbackError(
                "NV floor regressed below a previously observed value"
            )
        self._last_floor = observed
        return observed

    def read_floor(self):
        with self._locked():
            return self._read_floor_unlocked()

    def compare_and_advance(self, expected, new):
        expected = _uint64(expected, "expected floor")
        new = _uint64(new, "new floor")
        if expected == UINT64_MAX or new != expected + 1:
            return False
        with self._locked():
            if self._read_floor_unlocked() != expected:
                return False
            try:
                increment_response = self.transport.exchange(
                    build_nv_increment(self.index, self.index_auth)
                )
                parse_nv_increment(increment_response)
            except TpmResponseError:
                raise
            except TpmNvError as error:
                try:
                    observed = self._read_floor_unlocked()
                except TpmNvRollbackError:
                    raise
                except TpmNvError as reconcile_error:
                    raise TpmNvAmbiguousError(
                        "could not reconcile NV increment outcome"
                    ) from reconcile_error
                if observed == new:
                    return True
                if observed == expected:
                    raise TpmNvAmbiguousError(
                        "NV increment outcome remains uncertain"
                    ) from error
                return False
            try:
                observed = self._read_floor_unlocked()
            except TpmNvRollbackError:
                raise
            except TpmNvError as verify_error:
                raise TpmNvAmbiguousError(
                    "could not verify acknowledged NV increment"
                ) from verify_error
            if observed == new:
                return True
            if observed == expected:
                raise TpmNvError("TPM acknowledged increment without advancement")
            return False

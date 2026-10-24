#!/usr/bin/env python3
"""TPM2 NV monotonic-floor codec and provider tests."""

import fcntl
import hashlib
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

from tools import tpm2_nv
from tools.bbp_rollback_state import (
    PolicyError,
    RollbackJournal,
    RollbackStateError,
)


INDEX_AUTH = b"bearboot-test-index-auth"


def response(tag, payload=b"", result=0):
    return struct.pack(">HII", tag, 10 + len(payload), result) + payload


def public_response(index=tpm2_nv.DEFAULT_NV_INDEX,
                    attributes=tpm2_nv.NV_EXPECTED_ATTRIBUTES):
    public = struct.pack(">IHIH", index, tpm2_nv.TPM_ALG_SHA256,
                         attributes, 0) + struct.pack(">H", 8)
    name = struct.pack(">H", tpm2_nv.TPM_ALG_SHA256) + hashlib.sha256(
        public
    ).digest()
    payload = struct.pack(">H", len(public)) + public
    payload += struct.pack(">H", len(name)) + name
    return response(tpm2_nv.TPM_ST_NO_SESSIONS, payload)


def read_response(value):
    parameters = struct.pack(">H", 8) + value.to_bytes(8, "big")
    auth = struct.pack(">HBH", 0, tpm2_nv.TPMA_SESSION_CONTINUESESSION, 0)
    return response(tpm2_nv.TPM_ST_SESSIONS,
                    struct.pack(">I", len(parameters)) + parameters + auth)


def increment_response():
    auth = struct.pack(">HBH", 0, tpm2_nv.TPMA_SESSION_CONTINUESESSION, 0)
    return response(tpm2_nv.TPM_ST_SESSIONS, struct.pack(">I", 0) + auth)


class FakeTransport:
    def __init__(self, floor=0):
        self.floor = floor
        self.requests = []
        self.fail_after_increment = False
        self.fail_before_increment = False
        self.malformed_after_increment = False
        self.fail_verification_read = False
        self.increment_seen = False
        self.ack_without_increment = False
        self.advance_by_two = False
        self.increment_error_code = None
        self.regress_after_increment = False
        self.written = True
        self.wrong_public = False

    def exchange(self, request):
        self.requests.append(request)
        code = struct.unpack_from(">I", request, 6)[0]
        if self.increment_seen and self.fail_verification_read:
            self.fail_verification_read = False
            raise tpm2_nv.TpmTransportError("verification read failed")
        if code == tpm2_nv.TPM_CC_NV_READ_PUBLIC:
            attributes = tpm2_nv.NV_EXPECTED_ATTRIBUTES
            if self.written:
                attributes |= tpm2_nv.TPMA_NV_WRITTEN
            if self.wrong_public:
                attributes ^= tpm2_nv.TPMA_NV_AUTHREAD
            return public_response(attributes=attributes)
        if code == tpm2_nv.TPM_CC_NV_READ:
            return read_response(self.floor)
        if code == tpm2_nv.TPM_CC_NV_INCREMENT:
            if self.fail_before_increment:
                self.fail_before_increment = False
                raise tpm2_nv.TpmTransportError("increment was not delivered")
            if self.increment_error_code is not None:
                error_code = self.increment_error_code
                self.increment_error_code = None
                return response(
                    tpm2_nv.TPM_ST_NO_SESSIONS, result=error_code
                )
            if not self.ack_without_increment:
                self.floor += 2 if self.advance_by_two else 1
            if self.regress_after_increment:
                self.floor -= 2
            self.increment_seen = True
            if self.fail_after_increment:
                self.fail_after_increment = False
                raise tpm2_nv.TpmTransportError("connection lost after send")
            if self.malformed_after_increment:
                self.malformed_after_increment = False
                return response(tpm2_nv.TPM_ST_NO_SESSIONS)
            return increment_response()
        raise AssertionError(f"unexpected TPM command 0x{code:08x}")


class Tpm2NvCodecTests(unittest.TestCase):
    def test_commands_have_exact_handles_sessions_and_bounds(self):
        read_public = tpm2_nv.build_nv_read_public(tpm2_nv.DEFAULT_NV_INDEX)
        self.assertEqual(
            read_public,
            struct.pack(">HIII", tpm2_nv.TPM_ST_NO_SESSIONS, 14,
                        tpm2_nv.TPM_CC_NV_READ_PUBLIC,
                        tpm2_nv.DEFAULT_NV_INDEX),
        )

        authorization = struct.pack(">IHBH", tpm2_nv.TPM_RS_PW, 0, 0,
                                    len(INDEX_AUTH)) + INDEX_AUTH
        read = tpm2_nv.build_nv_read(tpm2_nv.DEFAULT_NV_INDEX, INDEX_AUTH)
        expected_read = (
            struct.pack(">HII", tpm2_nv.TPM_ST_SESSIONS, 35 + len(INDEX_AUTH),
                        tpm2_nv.TPM_CC_NV_READ)
            + struct.pack(">II", tpm2_nv.DEFAULT_NV_INDEX,
                          tpm2_nv.DEFAULT_NV_INDEX)
            + struct.pack(">I", len(authorization)) + authorization
            + struct.pack(">HH", 8, 0)
        )
        self.assertEqual(read, expected_read)

        increment = tpm2_nv.build_nv_increment(
            tpm2_nv.DEFAULT_NV_INDEX, INDEX_AUTH
        )
        expected_increment = (
            struct.pack(">HII", tpm2_nv.TPM_ST_SESSIONS, 31 + len(INDEX_AUTH),
                        tpm2_nv.TPM_CC_NV_INCREMENT)
            + struct.pack(">II", tpm2_nv.DEFAULT_NV_INDEX,
                          tpm2_nv.DEFAULT_NV_INDEX)
            + struct.pack(">I", len(authorization)) + authorization
        )
        self.assertEqual(increment, expected_increment)

        for invalid in (-1, 0, tpm2_nv.TPM_RH_OWNER, 0x02000000,
                        1 << 32, True):
            with self.subTest(index=invalid), self.assertRaises(ValueError):
                tpm2_nv.build_nv_read_public(invalid)
            if isinstance(invalid, int) and not isinstance(invalid, bool) and (
                    0 <= invalid <= 0xFFFFFFFF):
                with self.subTest(expected_index=invalid), self.assertRaises(
                        ValueError):
                    tpm2_nv.parse_nv_read_public(public_response(), invalid)

        for invalid in (b"", b"\0", b"secret\0", b"x" * 33,
                        bytearray(b"secret"), "secret"):
            with self.subTest(auth=invalid), self.assertRaises(ValueError):
                tpm2_nv.build_nv_increment(
                    tpm2_nv.DEFAULT_NV_INDEX, invalid
                )

    def test_public_metadata_name_and_exact_extent_are_validated(self):
        parsed = tpm2_nv.parse_nv_read_public(
            public_response(), tpm2_nv.DEFAULT_NV_INDEX
        )
        self.assertEqual(parsed.attributes, tpm2_nv.NV_EXPECTED_ATTRIBUTES)
        self.assertFalse(parsed.written)

        written = tpm2_nv.parse_nv_read_public(
            public_response(attributes=tpm2_nv.NV_EXPECTED_ATTRIBUTES |
                            tpm2_nv.TPMA_NV_WRITTEN),
            tpm2_nv.DEFAULT_NV_INDEX,
        )
        self.assertTrue(written.written)

        cases = []
        cases.append(public_response(index=tpm2_nv.DEFAULT_NV_INDEX + 1))
        cases.append(public_response(attributes=tpm2_nv.NV_EXPECTED_ATTRIBUTES ^
                                     tpm2_nv.TPMA_NV_AUTHREAD))
        bad_name = bytearray(public_response())
        bad_name[-1] ^= 1
        cases.append(bytes(bad_name))
        cases.append(public_response() + b"x")
        for damaged in cases:
            with self.subTest(size=len(damaged)), self.assertRaises(
                    tpm2_nv.TpmNvError):
                tpm2_nv.parse_nv_read_public(
                    damaged, tpm2_nv.DEFAULT_NV_INDEX
                )

        valid = public_response()
        for size in range(len(valid)):
            with self.subTest(prefix=size), self.assertRaises(tpm2_nv.TpmNvError):
                tpm2_nv.parse_nv_read_public(valid[:size],
                                             tpm2_nv.DEFAULT_NV_INDEX)

    def test_session_responses_reject_malformed_auth_and_trailing_data(self):
        self.assertEqual(tpm2_nv.parse_nv_read(read_response(7)), 7)
        tpm2_nv.parse_nv_increment(increment_response())

        malformed = [
            read_response(7)[:-1],
            read_response(7) + b"x",
            response(tpm2_nv.TPM_ST_NO_SESSIONS,
                     read_response(7)[10:]),
            response(tpm2_nv.TPM_ST_SESSIONS, struct.pack(">I", 9) +
                     read_response(7)[14:]),
        ]
        wrong_session_attributes = bytearray(read_response(7))
        wrong_session_attributes[26] = 0
        malformed.append(bytes(wrong_session_attributes))
        for damaged in malformed:
            with self.subTest(size=len(damaged)), self.assertRaises(
                    tpm2_nv.TpmNvError):
                tpm2_nv.parse_nv_read(damaged)

        with self.assertRaises(tpm2_nv.TpmNvError):
            tpm2_nv.parse_nv_increment(increment_response() + b"x")

    def test_tpm_errors_require_the_canonical_error_header(self):
        error_code = 0x000009A2
        with self.assertRaises(tpm2_nv.TpmResponseError) as caught:
            tpm2_nv.parse_nv_read(response(
                tpm2_nv.TPM_ST_NO_SESSIONS, result=error_code
            ))
        self.assertEqual(caught.exception.response_code, error_code)

        malformed = [
            response(tpm2_nv.TPM_ST_SESSIONS, result=error_code),
            response(tpm2_nv.TPM_ST_NO_SESSIONS, b"x", result=error_code),
        ]
        for damaged in malformed:
            with self.subTest(response=damaged), self.assertRaises(
                    tpm2_nv.TpmNvError) as malformed_error:
                tpm2_nv.parse_nv_read(damaged)
            self.assertNotIsInstance(
                malformed_error.exception, tpm2_nv.TpmResponseError
            )


class SocketTransportTests(unittest.TestCase):
    def test_private_socket_peer_is_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "tpm.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o700)
            server.listen(1)
            request = tpm2_nv.build_nv_read_public(tpm2_nv.DEFAULT_NV_INDEX)
            expected_response = response(tpm2_nv.TPM_ST_NO_SESSIONS)
            received = []
            transport = tpm2_nv.SocketTransport(
                socket_path, expected_uid=os.geteuid()
            )
            transport._validate_endpoint()

            def serve():
                connection, _address = server.accept()
                with connection:
                    received.append(connection.recv(1024))
                    connection.sendall(expected_response)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                self.assertEqual(transport.exchange(request), expected_response)
            finally:
                thread.join(timeout=5)
                server.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(received, [request])

    def test_socket_path_and_owner_must_match_the_pinned_endpoint(self):
        with self.assertRaises(ValueError):
            tpm2_nv.SocketTransport("relative.sock", expected_uid=os.geteuid())
        with self.assertRaises(ValueError):
            tpm2_nv.SocketTransport("/tmp/tpm.sock", expected_uid=True)
        for invalid_timeout in (0, -1, True, float("inf")):
            with self.subTest(timeout=invalid_timeout), self.assertRaises(
                    ValueError):
                tpm2_nv.SocketTransport(
                    "/tmp/tpm.sock", expected_uid=os.geteuid(),
                    timeout_seconds=invalid_timeout,
                )

        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "tpm.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(os.fspath(socket_path))
            server.listen(1)
            try:
                transport = tpm2_nv.SocketTransport(
                    socket_path, expected_uid=os.geteuid() + 1
                )
                with self.assertRaises(tpm2_nv.TpmTransportError):
                    transport.exchange(b"request")
            finally:
                server.close()

        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "tpm.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(os.fspath(socket_path))
            transport = tpm2_nv.SocketTransport(
                socket_path, expected_uid=os.geteuid()
            )
            try:
                os.chmod(socket_path, 0o777)
                with self.assertRaises(tpm2_nv.TpmTransportError):
                    transport._validate_endpoint()
                os.chmod(socket_path, 0o700)
                os.chmod(directory, 0o777)
                with self.assertRaises(tpm2_nv.TpmTransportError):
                    transport._validate_endpoint()
            finally:
                os.chmod(directory, 0o700)
                server.close()

    def test_socket_setup_failure_is_wrapped_and_closes_descriptor(self):
        class FailingSocket:
            def __init__(self):
                self.closed = False

            def settimeout(self, _timeout):
                raise OSError("settimeout failed")

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "tpm.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o700)
            failing = FailingSocket()
            try:
                transport = tpm2_nv.SocketTransport(
                    socket_path, expected_uid=os.geteuid()
                )
                with mock.patch("tools.tpm2_nv.socket.socket",
                                return_value=failing):
                    with self.assertRaises(tpm2_nv.TpmTransportError):
                        transport.exchange(b"request")
            finally:
                server.close()
            self.assertTrue(failing.closed)

    def test_live_peer_uid_must_match_even_when_path_metadata_is_trusted(self):
        class WrongPeer:
            def getsockopt(self, level, option, size):
                self.request = (level, option, size)
                return struct.pack("=iII", 123, os.geteuid() + 1, os.getegid())

        transport = tpm2_nv.SocketTransport(
            "/trusted/tpm.sock", expected_uid=os.geteuid()
        )
        peer = WrongPeer()
        with self.assertRaises(tpm2_nv.TpmTransportError):
            transport._validate_peer(peer)
        self.assertEqual(
            peer.request[:2], (socket.SOL_SOCKET, socket.SO_PEERCRED)
        )

    def test_receive_deadline_is_total_not_renewed_per_byte(self):
        class DripSocket:
            def __init__(self):
                self.blocks = [b"a", b"b"]
                self.timeouts = []

            def settimeout(self, timeout):
                self.timeouts.append(timeout)

            def recv(self, _size):
                return self.blocks.pop(0)

        transport = tpm2_nv.SocketTransport(
            "/trusted/tpm.sock", expected_uid=os.geteuid(),
            timeout_seconds=1.0,
        )
        sock = DripSocket()
        with mock.patch("tools.tpm2_nv.time.monotonic",
                        side_effect=[0.5, 1.1]):
            with self.assertRaises(tpm2_nv.TpmTransportError):
                transport._receive_exact(sock, 2, deadline=1.0)
        self.assertEqual(sock.blocks, [b"b"])
        self.assertEqual(sock.timeouts, [0.5])


class Tpm2NvProviderTests(unittest.TestCase):
    def provider(self, directory, transport, **options):
        return tpm2_nv.Tpm2NvFloorProvider(
            transport, tpm2_nv.DEFAULT_NV_INDEX, index_auth=INDEX_AUTH,
            lock_path=Path(directory) / "tpm-nv.lock",
            **options,
        )

    def test_provider_requires_explicit_private_authority_configuration(self):
        self.assertTrue(issubclass(tpm2_nv.TpmNvError, RollbackStateError))
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "tpm-nv.lock"
            invalid_transport = type("InvalidTransport", (), {"exchange": 1})()
            with self.assertRaises(TypeError):
                tpm2_nv.Tpm2NvFloorProvider(
                    invalid_transport, index_auth=INDEX_AUTH,
                    lock_path=lock_path,
                )
            with self.assertRaises(ValueError):
                tpm2_nv.Tpm2NvFloorProvider(
                    FakeTransport(1), index_auth=b"", lock_path=lock_path
                )
            with self.assertRaises(ValueError):
                tpm2_nv.Tpm2NvFloorProvider(
                    FakeTransport(1), index_auth=INDEX_AUTH,
                    lock_path="relative.lock",
                )
            with self.assertRaises(ValueError):
                tpm2_nv.Tpm2NvFloorProvider(
                    FakeTransport(1), tpm2_nv.TPM_RH_OWNER,
                    index_auth=INDEX_AUTH, lock_path=lock_path,
                )
            for invalid_timeout in (-1, True, float("inf"), "five"):
                with self.subTest(timeout=invalid_timeout), self.assertRaises(
                        ValueError):
                    tpm2_nv.Tpm2NvFloorProvider(
                        FakeTransport(1), index_auth=INDEX_AUTH,
                        lock_path=lock_path,
                        lock_timeout_seconds=invalid_timeout,
                    )

    def test_compare_and_advance_is_serialized_and_reconciles_disconnect(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            self.assertEqual(provider.read_floor(), 4)

            commands_before = len(transport.requests)
            self.assertFalse(provider.compare_and_advance(3, 4))
            attempted = transport.requests[commands_before:]
            self.assertNotIn(tpm2_nv.TPM_CC_NV_INCREMENT,
                             [struct.unpack_from(">I", item, 6)[0]
                              for item in attempted])

            transport.fail_after_increment = True
            self.assertTrue(provider.compare_and_advance(4, 5))
            self.assertEqual(provider.read_floor(), 5)

    def test_malformed_increment_success_is_reconciled(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.malformed_after_increment = True
            self.assertTrue(provider.compare_and_advance(4, 5))
            self.assertEqual(provider.read_floor(), 5)

    def test_failed_post_increment_read_is_explicitly_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.fail_verification_read = True
            with self.assertRaises(tpm2_nv.TpmNvAmbiguousError):
                provider.compare_and_advance(4, 5)
            self.assertEqual(transport.floor, 5)

    def test_uncertain_increment_without_observed_advance_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.fail_before_increment = True
            with self.assertRaises(tpm2_nv.TpmNvAmbiguousError):
                provider.compare_and_advance(4, 5)
            self.assertEqual(transport.floor, 4)

    def test_failed_increment_reconciliation_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.fail_after_increment = True
            transport.fail_verification_read = True
            with self.assertRaises(tpm2_nv.TpmNvAmbiguousError):
                provider.compare_and_advance(4, 5)
            self.assertEqual(transport.floor, 5)

    def test_acknowledged_increment_without_advancement_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.ack_without_increment = True
            with self.assertRaises(tpm2_nv.TpmNvError) as caught:
                provider.compare_and_advance(4, 5)
            self.assertNotIsInstance(
                caught.exception, tpm2_nv.TpmNvAmbiguousError
            )
            self.assertEqual(transport.floor, 4)

    def test_later_floor_after_increment_is_reported_as_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.advance_by_two = True
            self.assertFalse(provider.compare_and_advance(4, 5))
            self.assertEqual(transport.floor, 6)

    def test_canonical_tpm_increment_error_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.increment_error_code = 0x000009A2
            with self.assertRaises(tpm2_nv.TpmResponseError) as caught:
                provider.compare_and_advance(4, 5)
            self.assertEqual(caught.exception.response_code, 0x000009A2)
            self.assertEqual(transport.floor, 4)

    def test_invalid_metadata_and_generation_fail_without_increment(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(2)
            provider = self.provider(directory, transport)
            transport.wrong_public = True
            with self.assertRaises(tpm2_nv.TpmNvMetadataError):
                provider.read_floor()
            self.assertFalse(any(
                struct.unpack_from(">I", request, 6)[0] ==
                tpm2_nv.TPM_CC_NV_INCREMENT
                for request in transport.requests
            ))

            transport.wrong_public = False
            for expected, new in ((2, 4), (3, 2), ((1 << 64) - 1, 0)):
                with self.subTest(expected=expected, new=new):
                    self.assertFalse(provider.compare_and_advance(expected, new))
            self.assertEqual(transport.floor, 2)

    def test_unwritten_counter_fails_before_nv_read(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport()
            transport.written = False
            provider = self.provider(directory, transport)
            with self.assertRaises(tpm2_nv.TpmNvMetadataError):
                provider.read_floor()
            commands = [struct.unpack_from(">I", item, 6)[0]
                        for item in transport.requests]
            self.assertEqual(commands, [tpm2_nv.TPM_CC_NV_READ_PUBLIC])

    def test_observed_floor_regression_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            self.assertEqual(provider.read_floor(), 4)
            transport.floor = 3
            with self.assertRaises(tpm2_nv.TpmNvRollbackError):
                provider.read_floor()

    def test_post_increment_regression_is_not_downgraded_to_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            transport.regress_after_increment = True
            with self.assertRaises(tpm2_nv.TpmNvRollbackError):
                provider.compare_and_advance(4, 5)

    def test_two_providers_serialize_one_authoritative_increment(self):
        class BlockingTransport(FakeTransport):
            def __init__(self, floor):
                super().__init__(floor)
                self.first_reader_entered = threading.Event()
                self.release_first_reader = threading.Event()
                self.overlap_observed = threading.Event()
                self.reader_guard = threading.Lock()
                self.reader_count = 0

            def exchange(self, request):
                code = struct.unpack_from(">I", request, 6)[0]
                if code == tpm2_nv.TPM_CC_NV_READ_PUBLIC:
                    with self.reader_guard:
                        self.reader_count += 1
                        reader = self.reader_count
                    if reader == 1:
                        self.first_reader_entered.set()
                        if not self.release_first_reader.wait(timeout=5):
                            raise AssertionError("first provider was not released")
                    elif not self.release_first_reader.is_set():
                        self.overlap_observed.set()
                return super().exchange(request)

        with tempfile.TemporaryDirectory() as directory:
            transport = BlockingTransport(4)
            providers = [self.provider(directory, transport) for _ in range(2)]
            results = []
            errors = []
            probe_complete = threading.Event()
            contention_observed = threading.Event()
            lock_was_unexpectedly_free = threading.Event()
            original_second_acquire = providers[1]._acquire_lock

            def probe_then_acquire(fd):
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    contention_observed.set()
                else:
                    lock_was_unexpectedly_free.set()
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    probe_complete.set()
                original_second_acquire(fd)

            providers[1]._acquire_lock = probe_then_acquire

            def advance(provider):
                try:
                    results.append(provider.compare_and_advance(4, 5))
                except Exception as error:  # surfaced after both threads join
                    errors.append(error)

            threads = [
                threading.Thread(target=advance, args=(provider,))
                for provider in providers
            ]
            threads[0].start()
            first_entered = transport.first_reader_entered.wait(timeout=5)
            threads[1].start()
            probe_finished = probe_complete.wait(timeout=5)
            contention = contention_observed.is_set()
            unexpectedly_free = lock_was_unexpectedly_free.is_set()
            overlap = transport.overlap_observed.is_set()
            transport.release_first_reader.set()
            for thread in threads:
                thread.join(timeout=5)

            self.assertTrue(first_entered)
            self.assertTrue(probe_finished)
            self.assertTrue(contention)
            self.assertFalse(unexpectedly_free)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertFalse(overlap)
            self.assertEqual(errors, [])
            self.assertEqual(sorted(results), [False, True])
            self.assertEqual(transport.floor, 5)
            increments = [
                request for request in transport.requests
                if struct.unpack_from(">I", request, 6)[0] ==
                tpm2_nv.TPM_CC_NV_INCREMENT
            ]
            self.assertEqual(len(increments), 1)

    def test_journal_recovers_after_ambiguous_floor_first_advance(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            journal = RollbackJournal(
                Path(directory) / "boot-state", provider
            )
            transport.fail_verification_read = True
            with self.assertRaises(tpm2_nv.TpmNvAmbiguousError):
                journal.commit(
                    5, "release", "A", "B", expected_sequence=0
                )
            self.assertEqual(transport.floor, 5)
            self.assertFalse(any(path.exists() for path in journal.slot_paths))

            recovered = journal.commit(
                5, "recovery", "A", "B", expected_sequence=0
            )
            self.assertEqual((recovered.generation, recovered.sequence), (5, 1))
            with self.assertRaises(PolicyError):
                journal.commit(
                    6, "recovery", "B", None,
                    expected_sequence=recovered.sequence,
                )
            self.assertEqual(transport.floor, 5)

    def test_journal_recovers_when_publication_fails_after_tpm_advance(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(4)
            provider = self.provider(directory, transport)
            journal = RollbackJournal(
                Path(directory) / "boot-state", provider
            )
            first = journal.commit(
                5, "release", "A", "B", expected_sequence=0
            )
            self.assertEqual((first.generation, first.sequence), (5, 1))
            self.assertEqual(transport.floor, 5)

            original_write = journal._write_slot

            def fail_publication(_path, _state):
                raise OSError("simulated journal publication failure")

            journal._write_slot = fail_publication
            with self.assertRaises(OSError):
                journal.commit(
                    6, "release", "B", None,
                    expected_sequence=first.sequence,
                )
            self.assertEqual(transport.floor, 6)

            journal._write_slot = original_write
            recovered = journal.commit(
                6, "recovery", "B", None,
                expected_sequence=first.sequence,
            )
            self.assertEqual((recovered.generation, recovered.sequence), (6, 2))
            self.assertEqual(journal.load(), recovered)
            self.assertTrue(all(path.exists() for path in journal.slot_paths))

    def test_lock_rejects_permissive_files_and_untrusted_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "tpm-nv.lock"
            lock_path.touch(mode=0o600)
            os.chmod(lock_path, 0o644)
            provider = self.provider(directory, FakeTransport(1))
            with self.assertRaises(tpm2_nv.TpmLockError):
                provider.read_floor()

            os.chmod(lock_path, 0o600)
            os.chmod(directory, 0o777)
            try:
                with self.assertRaises(tpm2_nv.TpmLockError):
                    provider.read_floor()
            finally:
                os.chmod(directory, 0o700)

    def test_lock_contention_has_a_finite_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(
                directory, FakeTransport(1), lock_timeout_seconds=0
            )
            fd = os.open(provider.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(tpm2_nv.TpmLockError):
                    provider.read_floor()
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def test_lock_path_replacement_is_detected_after_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, FakeTransport(1))
            original_acquire = provider._acquire_lock

            def acquire_then_replace(fd):
                original_acquire(fd)
                provider.lock_path.unlink()
                provider.lock_path.touch(mode=0o600)

            provider._acquire_lock = acquire_then_replace
            with self.assertRaises(tpm2_nv.TpmLockError):
                provider.read_floor()

    def test_lock_release_error_is_typed_without_masking_operation_error(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(1)
            provider = self.provider(directory, transport)
            original_release = provider._release_lock

            def release_then_fail(fd):
                original_release(fd)
                raise OSError("simulated unlock reporting failure")

            provider._release_lock = release_then_fail
            with self.assertRaises(tpm2_nv.TpmLockError):
                provider.read_floor()

            transport.wrong_public = True
            with self.assertRaises(tpm2_nv.TpmNvMetadataError):
                provider.read_floor()


if __name__ == "__main__":
    unittest.main(verbosity=2)

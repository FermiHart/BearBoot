#!/usr/bin/env python3
"""Host CLI for the experimental BBP auth2 public-key proof."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from experimental.auth2 import (  # noqa: E402
    ROLE_RECOVERY,
    ROLE_RELEASE,
    Auth2Error,
    KeyPolicy,
    build_manifest,
    sign_envelope,
    verify_envelope,
    verify_manifest,
)


ROLES = {"release": ROLE_RELEASE, "recovery": ROLE_RECOVERY}


def _write(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)


def _load_policies(path: str) -> list[KeyPolicy]:
    policy_path = Path(path)
    document = json.loads(policy_path.read_text(encoding="ascii"))
    if not isinstance(document, list):
        raise Auth2Error("key policy JSON must be a list")
    policies = []
    allowed = {"public_key", "role", "activation_generation",
               "retirement_generation", "revoked"}
    for record in document:
        if not isinstance(record, dict) or set(record) - allowed:
            raise Auth2Error("malformed key policy record")
        try:
            public_key = Path(record["public_key"])
            if not public_key.is_absolute():
                public_key = policy_path.parent / public_key
            policies.append(KeyPolicy(
                public_key,
                ROLES[record["role"]],
                record["activation_generation"],
                record["retirement_generation"],
                record.get("revoked", False),
            ))
        except (KeyError, TypeError) as error:
            raise Auth2Error("malformed key policy record") from error
    return policies


def _manifest_sign(arguments: argparse.Namespace) -> dict[str, object]:
    manifest = build_manifest(arguments.root_private, arguments.generation,
                              _load_policies(arguments.keys))
    _write(arguments.output, manifest)
    parsed = verify_manifest(manifest, arguments.root_private)
    return {"generation": parsed.security_generation,
            "key_count": len(parsed.keys), "output": arguments.output}


def _manifest_verify(arguments: argparse.Namespace) -> dict[str, object]:
    manifest = verify_manifest(Path(arguments.manifest).read_bytes(),
                               arguments.root_public,
                               arguments.minimum_generation)
    return {
        "generation": manifest.security_generation,
        "key_count": len(manifest.keys),
        "root_key_id": manifest.root_key_id.hex(),
    }


def _envelope_sign(arguments: argparse.Namespace) -> dict[str, object]:
    payload = Path(arguments.payload).read_bytes()
    envelope = sign_envelope(payload, arguments.private,
                             arguments.generation, ROLES[arguments.role])
    _write(arguments.output, envelope)
    return {"generation": arguments.generation, "payload_size": len(payload),
            "role": arguments.role, "output": arguments.output}


def _verify(arguments: argparse.Namespace) -> dict[str, object]:
    verified = verify_envelope(
        Path(arguments.envelope).read_bytes(),
        Path(arguments.manifest).read_bytes(),
        arguments.root_public,
        arguments.minimum_generation,
        arguments.allow_recovery,
    )
    if arguments.output:
        _write(arguments.output, verified.payload)
    return {
        "generation": verified.security_generation,
        "payload_size": len(verified.payload),
        "role": "release" if verified.role == ROLE_RELEASE else "recovery",
        "signer_key_id": verified.signer_key_id.hex(),
        "output": arguments.output,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Experimental BBP v2 ECDSA P-256 host authenticity proof")
    commands = parser.add_subparsers(dest="command", required=True)

    manifest_sign = commands.add_parser(
        "manifest-sign", help="build a root-signed fixed-width key manifest")
    manifest_sign.add_argument("--root-private", required=True)
    manifest_sign.add_argument("--generation", required=True, type=int)
    manifest_sign.add_argument("--keys", required=True,
                               help="JSON key-policy list")
    manifest_sign.add_argument("--output", required=True)
    manifest_sign.set_defaults(handler=_manifest_sign)

    manifest_verify = commands.add_parser(
        "manifest-verify", help="verify and describe a key manifest")
    manifest_verify.add_argument("--root-public", required=True)
    manifest_verify.add_argument("--manifest", required=True)
    manifest_verify.add_argument("--minimum-generation", type=int, default=0)
    manifest_verify.set_defaults(handler=_manifest_verify)

    envelope_sign = commands.add_parser(
        "envelope-sign", help="sign an exact bounded payload extent")
    envelope_sign.add_argument("--private", required=True)
    envelope_sign.add_argument("--generation", required=True, type=int)
    envelope_sign.add_argument("--role", choices=ROLES, default="release")
    envelope_sign.add_argument("--payload", required=True)
    envelope_sign.add_argument("--output", required=True)
    envelope_sign.set_defaults(handler=_envelope_sign)

    verify = commands.add_parser(
        "verify", help="verify manifest policy and an exact signed envelope")
    verify.add_argument("--root-public", required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--envelope", required=True)
    verify.add_argument("--minimum-generation", type=int, default=0)
    verify.add_argument("--allow-recovery", action="store_true")
    verify.add_argument("--output",
                        help="write payload only after successful verification")
    verify.set_defaults(handler=_verify)
    return parser


def main() -> int:
    parser = _parser()
    arguments = parser.parse_args()
    try:
        result = arguments.handler(arguments)
    except (Auth2Error, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"bbp-auth2: error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# BearBoot Host Tools

This package ships `bin/bbpctl.py`, a dependency-free inspector for host-only
BBPC v1 captures. BBPC is an archival and test container, not the BBP boot wire
ABI and not a preview of BBP v2.

```sh
python3 bin/bbpctl.py --help
python3 bin/bbpctl.py verify capture.bbpc
python3 bin/bbpctl.py inspect --json capture.bbpc
```

The tool treats captures as untrusted input and does not dereference physical
addresses recorded in them. See `docs/bbpc-v1.md` for the container format.

The package also includes the dependency-free experimental BBP v2 HMAC envelope
module at `lib/bbp_v2_envelope.py`. Its example seals and verifies the shared
Profile 0 vector, including rollback-state validation:

```sh
python3 examples/host_v2_roundtrip.py
```

This is offline host tooling for the draft RFCs under `docs/rfc/`; it is not a
firmware verifier, key-provisioning design, or stable v2 release surface.

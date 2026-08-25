# BBP auth2 test vectors

All private keys in this directory use tiny fixed P-256 scalars and are
**TEST ONLY**. They are intentionally public fixture material and must never be
used for production signing. Public keys, manifests, envelopes, and payloads
are deterministic checked-in interoperability fixtures.

The vector policy has security generation 7. The release and recovery keys are
active for generations 1 through 20 inclusive. `manifest.auth2` is signed by
the root key and `release.auth2` signs the exact bytes of `payload.dat`.

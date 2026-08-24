# RFC 0003: Experimental BBP v2 authenticated envelope

- Status: **Draft**
- Deployment: **Host only**

The 80-byte little-endian header contains magic `BBP2AUTH`, envelope version,
algorithm, flags, rollback index, exact payload size, 16-byte key identity, and
a 32-byte HMAC-SHA256 tag. Authentication covers the header with a zeroed tag
field followed by the exact capsule bytes.

`tools/bbp_v2_envelope.py` implements deterministic sealing, verification, and
single-writer global monotonic acceptance across all trusted keys. The draft deliberately does not specify
public-key signatures, firmware provisioning, recovery, or multi-writer state.

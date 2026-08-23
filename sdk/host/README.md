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

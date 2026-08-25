# Physical hardware execution evidence

The BBP execution-evidence v1 contract records hosted, emulator, and physical
claims as separate scopes. A physical claim must identify the actual board and
include the raw serial capture from that run. The format cannot authenticate
those operator-supplied claims or prevent deliberate relabeling.

## Required runner behavior

1. Record the board architecture, manufacturer, model, hardware revision, and
   unique serial number before boot. Do not use a shared lab name as the serial
   number.
2. Start the serial capture before reset or power-on. Capture bytes directly to
   a file without terminal rendering, newline conversion, timestamp prefixes,
   filtering, or ANSI cleanup.
3. Run the reset, boot, and bounded wait. Preserve the runner exit status. A
   timeout is a failure even if the serial file contains an earlier PASS line.
4. Stop and flush capture only after the runner has completed. Keep any firmware
   image, runner log, or configuration needed to identify the run as additional
   artifacts.
5. Create the bundle with the exact expected PASS line. Creation fails unless
   the command completed with exit status zero, raw serial contains that whole
   line, and raw serial contains no `FAIL` byte sequence.
6. Run `verify` on the completed bundle before publishing it. Verification
   re-reads every artifact, checks its exact byte size and SHA-256 digest, and
   derives the verdict again from raw serial and execution status.

Example after a successful x86_64 board run:

```sh
python3 tools/bbp_evidence_bundle.py create \
  --output build/evidence/lab-board-17 \
  --allow-unauthenticated-physical \
  --scope physical \
  --architecture x86_64 \
  --board-manufacturer ExampleCorp \
  --board-model Atlas-X1 \
  --board-revision rev-c \
  --board-serial ACX1-000017 \
  --serial build/lab-board-17.serial.raw \
  --exit-code 0 \
  --pass-marker 'BBP-PHYSICAL: PASS' \
  --artifact firmware.bin=build/bearboot.bin \
  -- lab-runner boot --board ACX1-000017

python3 tools/bbp_evidence_bundle.py verify \
  --allow-unauthenticated-physical \
  build/evidence/lab-board-17
```

For a timeout, retain the raw diagnostics outside a proof bundle. Passing
`--timed-out` to `create` deliberately fails; timeout output cannot become PASS
evidence. Likewise, a nonzero `--exit-code`, a missing PASS marker, any `FAIL`
sequence, a missing artifact, a changed hash, or an incomplete board identity
is rejected.

## Bundle layout

Each bundle is a directory containing `manifest.json` and a flat `artifacts/`
directory. `artifacts/serial.raw` has role `raw-serial` and is copied byte for
byte. Every artifact is a regular, non-symlink file listed exactly once in the
manifest. Unlisted files are rejected. The manifest is bounded to 64 KiB and
each artifact to 64 MiB.

The schema is `docs/schemas/bbp-execution-evidence-v1.schema.json`. The Python
tool uses only the standard library and enforces the same closed contract
without requiring a JSON Schema package.

## Fixture boundary

Test fixtures set `provenance` to `fixture`. Normal verification always rejects
them with "fixture manifests are not execution proof". `verify --allow-fixture`
exists only to regression-test parser and verifier behavior. A physical PASS
fixture must never be created or checked in; physical PASS evidence must come
from an identified board run.

This format provides integrity and distinct claim fields, not authenticity. By
default, the tool rejects physical claims as execution proof. The explicitly
named `--allow-unauthenticated-physical` option permits recording or checking
their internal integrity only; it does not upgrade them to proof. Authenticate
the runner and bind its output to the bundle before relying on a physical claim.

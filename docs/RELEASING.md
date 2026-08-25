# Releasing the BearBoot SDK

Releases are cut only from signed `sdk-vMAJOR.MINOR.PATCH` tags. The SDK and
wire versions are deliberately separate. The current release is named exactly:

> BearBoot SDK 1.4.0 (BBP wire 1.1)

`.github/workflows/release.yml` checks out the exact tag and runs the gates
present in that immutable revision. The `sdk-v1.2.0` tag predates the AArch64
and RISC-V gates; those proofs first ship in 1.3.0 and are never attributed
retroactively to 1.2.0. For a new tag, the workflow verifies that
GitHub accepts its signature and that its commit is on the default branch, runs
every host, Rust, port, multi-architecture QEMU, and OVMF gate, and builds every
package twice. A separate OIDC-only job signs the validated bytes. Only after
the publish job rechecks the checksums and every Sigstore bundle does its
isolated `contents: write` permission create a draft, upload and reconcile the
assets, and publish it. Tagged repository code never runs with either signing
or release permission.

## Prepare a release

1. Replace development versions with the release version in `sdk/VERSION`,
   `sdk/c/include/bbp/bbp_sdk.h`, `sdk/rust/bbp-wire/Cargo.toml`,
   `sdk/rust/bbp-wire/Cargo.lock`, `sdk/rust/bbp-wire/README.md`,
   `tests/test_sdk_package.py`, and the expected version/title/output names in
   `tests/test_release_metadata.py`. Update the README/site development labels.
2. Move the relevant changelog entries out of `Unreleased` and commit all release
   preparation. The release commit must be reachable from the default branch.
3. Confirm the complete local gate is green:

   ```sh
    make check
    make v2-portability v2-fuzz
    make tpm2-measure-test
    make freestanding CROSS=
    make qemu
    make qemu-aarch64
     make qemu-riscv64
     make qemu-uefi
     make qemu-uefi-loader
     make qemu-uefi-tcg2
     make ports-check CROSS=
     make ports-hosted-check
     make release-policy-test
   ```

4. Confirm the tree is clean. Release packaging intentionally fails otherwise:

   ```sh
   test -z "$(git status --porcelain=v1 --untracked-files=all)"
   ```

## Dry-run packaging

Use the release commit timestamp for every reproducible output. This checks the
same clean-release policy used by CI without publishing anything:

```sh
version="$(tr -d '\r\n' < sdk/VERSION)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
rm -rf /tmp/bearboot-release-a /tmp/bearboot-release-b
mkdir -p /tmp/bearboot-release-a/sdk /tmp/bearboot-release-b/sdk

python3 tools/package_sdk.py --release --output-dir /tmp/bearboot-release-a/sdk
python3 tools/package_sdk.py --release --output-dir /tmp/bearboot-release-b/sdk
cmp /tmp/bearboot-release-a/sdk/bearboot-c-sdk-$version.tar.gz \
    /tmp/bearboot-release-b/sdk/bearboot-c-sdk-$version.tar.gz
cmp /tmp/bearboot-release-a/sdk/bearboot-host-tools-$version.tar.gz \
    /tmp/bearboot-release-b/sdk/bearboot-host-tools-$version.tar.gz

CARGO_TARGET_DIR=/tmp/bearboot-release-a/cargo \
  cargo +stable package --frozen --manifest-path sdk/rust/bbp-wire/Cargo.toml
CARGO_TARGET_DIR=/tmp/bearboot-release-b/cargo \
  cargo +stable package --frozen --manifest-path sdk/rust/bbp-wire/Cargo.toml
cmp /tmp/bearboot-release-a/cargo/package/bbp-wire-$version.crate \
    /tmp/bearboot-release-b/cargo/package/bbp-wire-$version.crate
```

The release workflow then invokes the metadata generator as follows:

```sh
python3 tools/generate_release_metadata.py \
  --source-revision "$(git rev-parse HEAD)" \
  --output-dir "$release_dir" \
  --artifact "$release_dir/bearboot-c-sdk-$version.tar.gz" \
  --artifact "$release_dir/bearboot-host-tools-$version.tar.gz" \
  --artifact "$release_dir/bbp-wire-$version.crate"
```

This is the release interface for `tools/generate_release_metadata.py`:
`--artifact [NAME=]LOCAL_FILE` is repeatable, `SOURCE_DATE_EPOCH` supplies the
timestamp, and `--output-dir` writes deterministic `SUPPORT-MATRIX.json` and
`bearboot-sdk-$version.spdx.json` outputs.

## Sign and push the tag

Use an SSH signing key registered as a **signing key** on GitHub. The tag message
and release title keep both versions visible:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/fermihart_signing.pub
git tag -s sdk-v1.4.0 -m 'BearBoot SDK 1.4.0 (BBP wire 1.1)'
git push origin sdk-v1.4.0
```

The workflow requires an annotated tag that GitHub reports as verified. A
lightweight, unsigned, malformed, off-default-branch, or version-mismatched tag
fails before any package is built.

## Publication and recovery

Publication is a draft-first transaction. After all validation and signing
gates pass, the workflow creates a draft whose notes begin with a hidden
ownership marker containing the release tag, tagged commit SHA, and GitHub run
ID. It records the draft's numeric release ID and uses that ID for subsequent
ownership and asset checks. The marker is operational provenance, not a
substitute for the tag signature or Sigstore verification.

The publication allowlist is exactly these 15 assets for version `$version`:

```text
bearboot-c-sdk-$version.tar.gz
bearboot-host-tools-$version.tar.gz
bbp-wire-$version.crate
SUPPORT-MATRIX.json
bearboot-sdk-$version.spdx.json
SHA256SUMS
bearboot-c-sdk-$version.tar.gz.sigstore.json
bearboot-host-tools-$version.tar.gz.sigstore.json
bbp-wire-$version.crate.sigstore.json
SUPPORT-MATRIX.json.sigstore.json
bearboot-sdk-$version.spdx.json.sigstore.json
SHA256SUMS.sigstore.json
bearboot-c-sdk-$version.tar.gz.sbom.sigstore.json
bearboot-host-tools-$version.tar.gz.sbom.sigstore.json
bbp-wire-$version.crate.sbom.sigstore.json
```

Before upload, an owned draft may contain no asset outside that allowlist. The
workflow uploads every allowlisted file with `--clobber`, which makes a rerun
repair an interrupted or partial upload without creating another release. It
then requires the remote asset names, byte sizes, and GitHub SHA-256 digests to
match the local signed bundle exactly before changing the draft to published.

GitHub keeps the run ID stable when a failed workflow run is rerun, so that same
run can safely resume its matching draft. The workflow refuses to claim a draft
from another run or commit, refuses an unexpected asset, and refuses an already
published release. It never deletes or replaces the release object. For
publication recovery, rerun the failed workflow run rather than starting a new
workflow or manually uploading files. If ownership checks reject the draft,
inspect its tag, target SHA, marker, and assets before taking any manual action.

To verify an SSH-signed tag independently, obtain the release public key through
a trusted channel and bind its tagger email principal in an allowed-signers file:

```sh
printf '%s %s\n' 'release@example.com' "$(cat release-key.pub)" \
  > /tmp/bearboot-allowed-signers
git -c gpg.format=ssh \
  -c gpg.ssh.allowedSignersFile=/tmp/bearboot-allowed-signers \
  verify-tag sdk-v1.4.0
```

Replace `release@example.com` with the tagger identity and compare the public-key
fingerprint with the trusted value before accepting the result.

## Verify downloaded assets

Download all assets into one directory, then verify the checksums first:

```sh
sha256sum --check SHA256SUMS
```

Each payload has a `<payload>.sigstore.json` keyless signature bundle. The three
distributable packages also have `<payload>.sbom.sigstore.json` SPDX attestation
bundles. For `sdk-v1.4.0`, verify them against the exact workflow identity:

```sh
identity='https://github.com/FermiHart/BearBoot/.github/workflows/release.yml@refs/tags/sdk-v1.4.0'
issuer='https://token.actions.githubusercontent.com'
file='bearboot-c-sdk-1.4.0.tar.gz'

cosign verify-blob \
  --bundle "$file.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$file"
cosign verify-blob-attestation --type spdxjson \
  --bundle "$file.sbom.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$file"
```

Repeat the signature check for every entry in `SHA256SUMS` and the attestation
check for the C SDK, host tools, and Rust crate.

## crates.io

Automation does not publish to crates.io: the repository has no registry
credential, the release job receives none, and the crate manifest deliberately
sets `publish = false`. The `.crate` attached to GitHub Releases is therefore a
verified source package, not a registry candidate. Enabling registry publication
requires a separately reviewed manifest revision and owner-controlled process;
it is not part of this release's success criteria.

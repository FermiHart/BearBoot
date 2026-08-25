#!/usr/bin/env python3
"""Wave 25 release-publication policy regression tests."""

from pathlib import Path
import re
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"

EXPECTED_ASSETS = (
    "bearboot-c-sdk-$VERSION.tar.gz",
    "bearboot-host-tools-$VERSION.tar.gz",
    "bbp-wire-$VERSION.crate",
    "SUPPORT-MATRIX.json",
    "bearboot-sdk-$VERSION.spdx.json",
    "SHA256SUMS",
    "bearboot-c-sdk-$VERSION.tar.gz.sigstore.json",
    "bearboot-host-tools-$VERSION.tar.gz.sigstore.json",
    "bbp-wire-$VERSION.crate.sigstore.json",
    "SUPPORT-MATRIX.json.sigstore.json",
    "bearboot-sdk-$VERSION.spdx.json.sigstore.json",
    "SHA256SUMS.sigstore.json",
    "bearboot-c-sdk-$VERSION.tar.gz.sbom.sigstore.json",
    "bearboot-host-tools-$VERSION.tar.gz.sbom.sigstore.json",
    "bbp-wire-$VERSION.crate.sbom.sigstore.json",
)


class ReleasePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)
        cls.jobs = cls.workflow["jobs"]

    def step(self, job: str, name: str) -> dict:
        matches = [
            step for step in self.jobs[job]["steps"] if step.get("name") == name
        ]
        self.assertEqual(len(matches), 1, f"missing or duplicate step: {job}/{name}")
        return matches[0]

    def script(self, job: str, name: str) -> str:
        return self.step(job, name)["run"]

    def asset_array(self, script: str) -> tuple[str, ...]:
        match = re.search(r"^\s*assets=\(\n(?P<body>.*?)^\s*\)", script,
                          flags=re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, "script must declare an explicit assets array")
        return tuple(re.findall(r'^\s*"release/([^"]+)"\s*$',
                                match.group("body"), flags=re.MULTILINE))

    def test_workflow_has_an_exact_publication_asset_allowlist(self) -> None:
        validate = self.script("publish", "Validate signed release bundle")
        upload = self.script("publish", "Upload exact assets to owned draft")
        remote = self.script(
            "publish", "Verify remote assets and publish owned draft"
        )
        self.assertEqual(self.asset_array(validate), EXPECTED_ASSETS)
        self.assertEqual(self.asset_array(upload), EXPECTED_ASSETS)
        self.assertEqual(self.asset_array(remote), EXPECTED_ASSETS)
        self.assertIn("uploads.github.com", upload)
        self.assertIn("releases/$RELEASE_ID/assets", upload)
        self.assertNotIn("gh release upload", upload)
        self.assertNotIn("release/*", upload)
        self.assertNotIn("release/*", remote)

    def test_draft_is_created_or_only_matching_provenance_is_resumed(self) -> None:
        validate = self.script("validate", "Verify tag identity and provenance")
        self.assertIn("gpg.ssh.allowedSignersFile=.github/release-signers", validate)
        self.assertIn('verify-tag "refs/tags/$RELEASE_TAG"', validate)
        self.assertIn('git rev-parse "refs/tags/$RELEASE_TAG^{commit}"', validate)
        self.assertIn('test "$event_commit" = "$tag_commit"', validate)

        stage = self.script("publish", "Create or resume owned draft")
        self.assertIn("--draft", stage)
        self.assertIn("GITHUB_SHA", stage)
        self.assertIn("GITHUB_RUN_ID", stage)
        self.assertIn("RELEASE_TAG", stage)
        self.assertRegex(stage, r"marker=.*RELEASE_TAG.*GITHUB_SHA.*GITHUB_RUN_ID")
        self.assertRegex(stage, r"\.draft")
        self.assertIn(".published_at", stage)
        self.assertNotIn(".target_commitish", stage)
        self.assertIn(".body", stage)
        self.assertIn(".draft == true", stage)
        self.assertIn(".published_at == null", stage)
        self.assertIn(".tag_name == $tag", stage)
        self.assertIn("startswith($marker", stage)
        self.assertRegex(stage, r"refus|reject")

        names = [step.get("name") for step in self.jobs["publish"]["steps"]]
        self.assertLess(names.index("Reverify Sigstore bundles"),
                        names.index("Create or resume owned draft"))

        workflow_scripts = "\n".join(
            step.get("run", "")
            for job in self.jobs.values()
            for step in job["steps"]
        )
        self.assertNotIn("gh release delete", workflow_scripts)
        self.assertEqual(workflow_scripts.count("gh release create"), 1)

    def test_upload_rechecks_draft_ownership_and_remote_asset_integrity(self) -> None:
        upload = self.script("publish", "Upload exact assets to owned draft")
        for policy in (
            "RELEASE_ID", ".id", ".draft", ".published_at",
            ".tag_name", ".body",
        ):
            self.assertIn(policy, upload)
        self.assertIn("--method DELETE", upload)
        self.assertIn("--method POST", upload)

        verify = self.script(
            "publish", "Verify remote assets and publish owned draft"
        )
        self.assertIn("RELEASE_ID", verify)
        self.assertIn("sha256sum", verify)
        self.assertIn("stat", verify)
        self.assertIn(".name", verify)
        self.assertIn(".size", verify)
        self.assertIn(".digest", verify)
        self.assertRegex(verify, r"sha256:")
        self.assertGreaterEqual(verify.count("assert_remote_assets"), 4)
        self.assertGreaterEqual(verify.count("assert_remote_tag"), 4)
        self.assertIn("RELEASE_ID", verify)
        self.assertIn("--method PATCH", verify)
        self.assertIn("draft=false", verify)

    def test_publish_job_rechecks_sha256_and_sigstore_bundles(self) -> None:
        validate = self.script("publish", "Validate signed release bundle")
        self.assertIn("sha256sum --check SHA256SUMS", validate)
        install = self.step("publish", "Install Cosign for publication checks")
        self.assertRegex(install["uses"],
                         r"^sigstore/cosign-installer@[0-9a-f]{40}$")
        verify = self.script("publish", "Reverify Sigstore bundles")
        self.assertIn("cosign verify-blob", verify)
        self.assertIn("cosign verify-blob-attestation", verify)
        self.assertIn("--certificate-identity", verify)
        self.assertIn("--certificate-oidc-issuer", verify)

    def test_every_gh_step_has_explicit_repository_context(self) -> None:
        for job_name, job in self.jobs.items():
            for step in job["steps"]:
                if re.search(r"\bgh\s", step.get("run", "")):
                    self.assertIn(
                        "GH_REPO", step.get("env", {}),
                        f"{job_name}/{step.get('name')} lacks GH_REPO",
                    )

    def test_registry_publication_and_credentials_are_absent(self) -> None:
        self.assertNotRegex(self.text, r"cargo\s+(?:\+\S+\s+)?publish\b")
        for forbidden in (
            "CARGO_REGISTRY_TOKEN", "CRATES_IO_TOKEN", "NPM_TOKEN",
            "DOCKER_PASSWORD", "REGISTRY_PASSWORD",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_job_permissions_remain_isolated(self) -> None:
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(self.jobs["validate"]["permissions"], {"contents": "read"})
        self.assertEqual(
            self.jobs["sign"]["permissions"],
            {"actions": "read", "id-token": "write"},
        )
        self.assertEqual(
            self.jobs["publish"]["permissions"],
            {"actions": "read", "contents": "write"},
        )
        self.assertEqual(self.jobs["publish"]["needs"], ["validate", "sign"])

    def test_all_workflow_shell_steps_parse(self) -> None:
        for job_name, job in self.jobs.items():
            for step in job["steps"]:
                script = step.get("run")
                if not script:
                    continue
                result = subprocess.run(
                    ["bash", "-n"], input=script, text=True,
                    capture_output=True, cwd=ROOT,
                )
                self.assertEqual(
                    result.returncode, 0,
                    f"{job_name}/{step.get('name')}: {result.stderr}",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

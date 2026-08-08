#!/usr/bin/env python3
"""Regression tests for the private-to-public GitHub release boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github/workflows/ci.yml"
PRIVATE_RELEASE = ROOT / ".github/workflows/release.yml"
RELEASE_CHECK = ROOT / ".github/workflows/release-check.yml"
PUBLIC_PROMOTION = ROOT / ".github/workflows/promote-public-release.yml"
FIRST_NPM_PUBLICATION = ROOT / ".github/workflows/npm-first-publication.yml"
TRUSTED_NPM_PUBLICATION = ROOT / ".github/workflows/npm-publish.yml"
ATTEST_ACTION = "actions/attest-build-provenance@"


class GitHubReleasePolicyTests(unittest.TestCase):
    """Keep unsupported private attestations out of the candidate workflow."""

    def test_tag_release_gates_attach_the_exact_commit_to_main(self) -> None:
        command = 'git switch --force-create main "$GITHUB_SHA"'
        for path in (PRIVATE_RELEASE, RELEASE_CHECK):
            workflow = path.read_text(encoding="utf-8")
            self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', workflow)
            self.assertIn(command, workflow)

    def test_private_candidate_does_not_request_github_attestations(self) -> None:
        workflow = PRIVATE_RELEASE.read_text(encoding="utf-8")
        self.assertNotIn(ATTEST_ACTION, workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+attestations:\s+")
        self.assertIn("cosign sign --yes", workflow)
        self.assertIn("verify-native-release", workflow)
        self.assertIn("private-release-clone-back", workflow)
        self.assertNotIn("--previous-version 2.0.0", workflow)

    def test_public_promotion_attests_before_publishing_the_draft(self) -> None:
        workflow = PUBLIC_PROMOTION.read_text(encoding="utf-8")
        attestation = workflow.index(ATTEST_ACTION)
        verification = workflow.index("gh attestation verify")
        containers = workflow.index("visibility=$(gh api")
        publication = workflow.index("--draft=false")
        promotion_evidence = workflow.index("name: Upload promotion evidence")
        dispatch = workflow.index("gh workflow run npm-publish.yml")
        self.assertLess(attestation, verification)
        self.assertLess(verification, publication)
        self.assertLess(containers, publication)
        self.assertLess(publication, dispatch)
        self.assertLess(promotion_evidence, dispatch)
        self.assertIn('"$visibility" != public', workflow)
        self.assertIn("NPM_TRUSTED_PUBLISHING_READY", workflow)
        self.assertIn('--ref "$TAG"', workflow[dispatch:])
        self.assertRegex(workflow, r"(?m)^  actions: write$")
        self.assertIn("docker manifest inspect", workflow)
        self.assertIn("cosign verify", workflow)
        self.assertRegex(workflow, r"(?m)^\s+attestations:\s+write$")
        self.assertRegex(workflow, r"(?m)^\s+id-token:\s+write$")
        action_revisions = re.findall(
            r"actions/attest-build-provenance@([0-9a-f]+)", workflow
        )
        self.assertEqual(len(action_revisions), 1)
        self.assertEqual(len(action_revisions[0]), 40)

    def test_first_npm_publication_is_explicit_and_token_is_not_retained(self) -> None:
        first = FIRST_NPM_PUBLICATION.read_text(encoding="utf-8")
        trusted = TRUSTED_NPM_PUBLICATION.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", first)
        self.assertIn("NPM_FIRST_PUBLICATION_TOKEN", first)
        self.assertIn("--provenance", first)
        self.assertIn("-bootstrap.0", first)
        self.assertIn("--tag bootstrap", first)
        self.assertIn("create-first-publication-candidates.mjs", first)
        self.assertNotIn("npm publish ./packages/getaip-cli", first)
        self.assertNotIn("npm publish ./packages/getaip", first)
        self.assertIn("NPM_FIRST_PUBLICATION_COMPLETE", first)
        self.assertNotIn("NPM_FIRST_PUBLICATION_TOKEN", trusted)
        self.assertIn("NPM_TRUSTED_PUBLISHING_READY", trusted)
        self.assertNotIn("--tag bootstrap", trusted)
        self.assertIn("workflow_dispatch:", trusted)
        self.assertIn("dist.attestations", first)
        self.assertIn("dist.attestations", trusted)
        self.assertNotIn("dist.integrity --json", first)
        self.assertEqual(
            first.count('npm view "@getaip/cli@${BOOTSTRAP_VERSION}" --json'), 1
        )
        self.assertEqual(
            first.count('npm view "getaip@${BOOTSTRAP_VERSION}" --json'), 1
        )
        self.assertEqual(trusted.count('npm view "@getaip/cli@${version}" --json'), 2)
        self.assertEqual(trusted.count('npm view "getaip@${version}" --json'), 2)
        production_marker = trusted[
            trusted.index("name: attest-final-production-marker") :
        ]
        self.assertIn('["dist.integrity"] // .dist.integrity', production_marker)
        self.assertIn('["dist.attestations"] // .dist.attestations', production_marker)

    def test_heavy_ci_jobs_wait_for_the_release_preflight(self) -> None:
        workflow = CI.read_text(encoding="utf-8")

        def job_block(name: str) -> str:
            match = re.search(
                rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                workflow,
            )
            self.assertIsNotNone(match, name)
            assert match is not None
            return match.group(1)

        preflight = job_block("release-preflight")
        self.assertIn("ruff format --check", preflight)
        self.assertIn("ruff check", preflight)
        self.assertIn("unittest discover -s tools/release", preflight)
        for job in [
            "rust-core",
            "connector-catalog",
            "msrv",
            "macos-core",
            "nats",
            "postgres",
            "migration-images",
            "connector-fleet-runtime",
        ]:
            self.assertIn("needs: release-preflight", job_block(job), job)


if __name__ == "__main__":
    unittest.main()

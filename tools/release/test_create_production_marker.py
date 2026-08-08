#!/usr/bin/env python3
"""Contract tests for the final GetAIP production-marker generator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("create-production-marker.py")
SPEC = importlib.util.spec_from_file_location("create_production_marker", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load production-marker generator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProductionMarkerTest(unittest.TestCase):
    def test_flat_npm_projection_is_accepted_and_conflicts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "scoped.json"
            flat = {
                "name": "@getaip/cli",
                "version": "2.1.0",
                "dist.integrity": "sha512-scoped",
                "dist.tarball": "https://registry.npmjs.org/@getaip/cli/-/cli-2.1.0.tgz",
                "dist.attestations": {
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/@getaip%2fcli@2.1.0",
                    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
                },
            }
            write_json(evidence, flat)
            record = MODULE.npm_record(evidence, "@getaip/cli", "2.1.0")
            self.assertEqual(record["integrity"], "sha512-scoped")

            flat["dist"] = {"integrity": "sha512-conflicting"}
            write_json(evidence, flat)
            with self.assertRaisesRegex(SystemExit, "conflicting dist.integrity"):
                MODULE.npm_record(evidence, "@getaip/cli", "2.1.0")

    def test_exact_evidence_creates_one_bound_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gitea_commit = "a" * 40
            gitea_tree = "b" * 40
            github_commit = "c" * 40
            github_tree = "d" * 40
            snapshot = root / "SOURCE_SNAPSHOT.json"
            publication = root / "PUBLICATION_MANIFEST.json"
            write_json(
                snapshot,
                {
                    "schema_version": 2,
                    "mode": "code-only-single-root",
                    "release": {"version": "2.1.0", "aip_protocol_version": "1.0"},
                    "source": {"revision": gitea_commit, "tree": gitea_tree},
                },
            )
            write_json(
                publication, {"source": {"revision": gitea_commit, "tree": gitea_tree}}
            )

            native = root / "native"
            native.mkdir()
            manifest = native / "getaip-distribution-manifest.v1.json"
            signature = native / "getaip-distribution-manifest.v1.json.sig"
            write_json(
                manifest,
                {
                    "release": {
                        "version": "2.1.0",
                        "aip_protocol_version": "1.0",
                        "source": {
                            "gitea_commit": gitea_commit,
                            "gitea_tree": gitea_tree,
                            "github_commit": github_commit,
                            "github_tree": github_tree,
                        },
                    }
                },
            )
            signature.write_text("signed\n", encoding="utf-8")
            assets = [manifest, signature]
            checksums = native / "SHA256SUMS"
            checksums.write_text(
                "".join(f"{digest(path)}  {path.name}\n" for path in sorted(assets)),
                encoding="utf-8",
            )

            image_evidence = root / "images"
            for image in sorted(MODULE.EXPECTED_IMAGES):
                name = image.removeprefix("ghcr.io/getaip/")
                path = image_evidence / name / f"{name}.digest"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{image}@sha256:{'e' * 64}\n", encoding="utf-8")

            native_qualification = root / "native-qualification"
            public_install = root / "public-install"
            for asset in sorted(MODULE.EXPECTED_ASSETS):
                write_json(
                    native_qualification / asset / "qualification.json",
                    {
                        "schema": "org.getaip.qualification.native-install.v1",
                        "asset": asset,
                        "clean_install": "pass",
                        "repeated_setup": "pass",
                        "diagnostics": "pass",
                        "foreground_server": "pass",
                        "isolated_service_lifecycle": "pass",
                        "installer_security": "pass",
                        "upgrade_rollback": "pass",
                        "upgrade_rollback_evidence": "native_installer_contract_tests",
                        "previous_native_release": None,
                        "uninstall": "pass",
                    },
                )
                write_json(
                    public_install / asset / "setup.json",
                    {"asset": asset, "status": "pass"},
                )

            scoped = root / "scoped.json"
            launcher = root / "launcher.json"
            write_json(
                scoped,
                {
                    "name": "@getaip/cli",
                    "version": "2.1.0",
                    "dist": {
                        "integrity": "sha512-scoped",
                        "tarball": "https://registry.npmjs.org/@getaip/cli/-/cli-2.1.0.tgz",
                        "attestations": {
                            "url": "https://registry.npmjs.org/-/npm/v1/attestations/@getaip%2fcli@2.1.0",
                            "provenance": {
                                "predicateType": "https://slsa.dev/provenance/v1"
                            },
                        },
                    },
                },
            )
            write_json(
                launcher,
                {
                    "name": "getaip",
                    "version": "2.1.0",
                    "dependencies": {"@getaip/cli": "2.1.0"},
                    "dist": {
                        "integrity": "sha512-launcher",
                        "tarball": "https://registry.npmjs.org/getaip/-/getaip-2.1.0.tgz",
                        "attestations": {
                            "url": "https://registry.npmjs.org/-/npm/v1/attestations/getaip@2.1.0",
                            "provenance": {
                                "predicateType": "https://slsa.dev/provenance/v1"
                            },
                        },
                    },
                },
            )
            output = root / "getaip-production-marker.v1.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--source-snapshot",
                    str(snapshot),
                    "--publication-manifest",
                    str(publication),
                    "--native-release",
                    str(native),
                    "--image-evidence",
                    str(image_evidence),
                    "--native-qualification",
                    str(native_qualification),
                    "--public-install-evidence",
                    str(public_install),
                    "--scoped-npm-evidence",
                    str(scoped),
                    "--launcher-npm-evidence",
                    str(launcher),
                    "--tag",
                    "v2.1.0",
                    "--github-commit",
                    github_commit,
                    "--github-tree",
                    github_tree,
                    "--immutable-run-id",
                    "101",
                    "--npm-run-id",
                    "202",
                    "--marked-at",
                    "2026-08-04T12:00:00Z",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            marker = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                marker["schema"], "org.getaip.release.production-marker.v1"
            )
            self.assertEqual(marker["source"]["gitea_commit"], gitea_commit)
            self.assertEqual(marker["source"]["github_commit"], github_commit)
            self.assertEqual(len(marker["containers"]), len(MODULE.EXPECTED_IMAGES))
            self.assertEqual(len(marker["qualification"]["native"]), 4)


if __name__ == "__main__":
    unittest.main()

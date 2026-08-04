#!/usr/bin/env python3
"""Create the exact final GetAIP production marker from retained evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

EXPECTED_ASSETS = {"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"}
EXPECTED_IMAGES = {
    "ghcr.io/getaip/aip-connector-control-plane",
    "ghcr.io/getaip/aip-crewai-sidecar",
    "ghcr.io/getaip/aip-host-cal-diy",
    "ghcr.io/getaip/aip-host-chatwoot",
    "ghcr.io/getaip/aip-host-crewai",
    "ghcr.io/getaip/aip-host-dify",
    "ghcr.io/getaip/aip-host-enterprise-sandbox",
    "ghcr.io/getaip/aip-host-hermes-agent",
    "ghcr.io/getaip/aip-host-support-sandbox",
    "ghcr.io/getaip/aip-host-twenty",
    "ghcr.io/getaip/aip-host-wa-archive",
    "ghcr.io/getaip/cli",
    "ghcr.io/getaip/server",
    "ghcr.io/getaip/server-migration-bundle",
}
OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^(ghcr\.io/getaip/[a-z0-9-]+)@(sha256:[0-9a-f]{64})$")


def fail(message: str) -> None:
    raise SystemExit(message)


def read_bytes(path: Path, *, maximum: int = 64 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"expected a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        fail(f"file has an invalid size: {path}")
    return path.read_bytes()


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(read_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON in {path}: {error}")
    if not isinstance(value, dict):
        fail(f"expected a JSON object in {path}")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"expected a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size <= 0 or size > 2 * 1024 * 1024 * 1024:
        fail(f"file has an invalid size: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_object_id(value: object, label: str) -> str:
    if not isinstance(value, str) or OBJECT_ID.fullmatch(value) is None:
        fail(f"{label} is not a full Git object id")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def parse_checksums(path: Path, release_directory: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    text = read_bytes(path).decode("utf-8")
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None:
            fail(f"invalid SHA256SUMS entry: {line!r}")
        digest, name = match.groups()
        if name in seen:
            fail(f"duplicate SHA256SUMS entry: {name}")
        seen.add(name)
        actual = sha256_file(release_directory / name)
        if actual != digest:
            fail(f"release asset digest mismatch for {name}")
        records.append({"name": name, "sha256": digest})
    if not records or records != sorted(records, key=lambda record: record["name"]):
        fail("SHA256SUMS must be non-empty and sorted by asset name")
    return records


def npm_record(path: Path, expected_name: str, version: str) -> dict[str, object]:
    value = read_json(path)
    if value.get("name") != expected_name or value.get("version") != version:
        fail(f"npm evidence identity mismatch for {expected_name}")
    distribution = value.get("dist")
    if not isinstance(distribution, dict):
        fail(f"npm evidence omits dist for {expected_name}")
    integrity = distribution.get("integrity")
    tarball = distribution.get("tarball")
    attestations = distribution.get("attestations")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        fail(f"npm integrity is invalid for {expected_name}")
    if not isinstance(tarball, str) or not tarball.startswith(
        "https://registry.npmjs.org/"
    ):
        fail(f"npm tarball URL is invalid for {expected_name}")
    if not isinstance(attestations, dict):
        fail(f"npm provenance is missing for {expected_name}")
    attestation_url = attestations.get("url")
    provenance = attestations.get("provenance")
    if (
        not isinstance(attestation_url, str)
        or not attestation_url.startswith(
            "https://registry.npmjs.org/-/npm/v1/attestations/"
        )
        or not isinstance(provenance, dict)
        or provenance.get("predicateType") != "https://slsa.dev/provenance/v1"
    ):
        fail(f"npm provenance identity is invalid for {expected_name}")
    if expected_name == "getaip":
        dependencies = value.get("dependencies")
        if (
            not isinstance(dependencies, dict)
            or dependencies.get("@getaip/cli") != version
        ):
            fail("short npm launcher does not depend on the exact scoped version")
    return {
        "name": expected_name,
        "version": version,
        "integrity": integrity,
        "tarball": tarball,
        "provenance": {
            "url": attestation_url,
            "predicate_type": provenance["predicateType"],
        },
    }


def image_records(directory: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in sorted(directory.rglob("*.digest")):
        value = read_bytes(path, maximum=4096).decode("utf-8").strip()
        match = IMAGE_DIGEST.fullmatch(value)
        if match is None:
            fail(f"invalid container digest evidence: {path}")
        image, digest = match.groups()
        if image in seen:
            fail(f"duplicate container digest evidence: {image}")
        seen.add(image)
        records.append({"image": image, "digest": digest})
    if seen != EXPECTED_IMAGES:
        fail(f"container evidence differs from the release matrix: {sorted(seen)}")
    return sorted(records, key=lambda record: record["image"])


def native_qualification(directory: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in sorted(directory.rglob("qualification.json")):
        value = read_json(path)
        asset = value.get("asset")
        if (
            value.get("schema") != "org.getaip.qualification.native-install.v1"
            or not isinstance(asset, str)
            or asset in seen
        ):
            fail(f"invalid native qualification evidence: {path}")
        for check in [
            "clean_install",
            "repeated_setup",
            "diagnostics",
            "foreground_server",
            "isolated_service_lifecycle",
            "installer_security",
            "upgrade_rollback",
            "uninstall",
        ]:
            if value.get(check) != "pass":
                fail(f"native qualification {asset} did not pass {check}")
        if (
            value.get("upgrade_rollback_evidence")
            != "native_installer_contract_tests"
            or value.get("previous_native_release") is not None
        ):
            fail(
                f"native qualification {asset} misstates the first-release lifecycle boundary"
            )
        seen.add(asset)
        records.append({"asset": asset, "sha256": sha256_file(path)})
    if seen != EXPECTED_ASSETS:
        fail(f"native qualification differs from the release matrix: {sorted(seen)}")
    return sorted(records, key=lambda record: record["asset"])


def public_install_evidence(directory: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for asset in sorted(EXPECTED_ASSETS):
        matching = [
            path
            for path in directory.rglob("*")
            if path.is_file() and asset in str(path)
        ]
        if not matching:
            fail(f"public npm install evidence is missing for {asset}")
        seen.add(asset)
        records.append(
            {
                "asset": asset,
                "files": [
                    {
                        "name": path.name,
                        "sha256": sha256_file(path),
                    }
                    for path in sorted(matching)
                ],
            }
        )
    if seen != EXPECTED_ASSETS:
        fail("public npm install evidence differs from the release matrix")
    return records


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-snapshot", type=Path, required=True)
    parser.add_argument("--publication-manifest", type=Path, required=True)
    parser.add_argument("--native-release", type=Path, required=True)
    parser.add_argument("--image-evidence", type=Path, required=True)
    parser.add_argument("--native-qualification", type=Path, required=True)
    parser.add_argument("--public-install-evidence", type=Path, required=True)
    parser.add_argument("--scoped-npm-evidence", type=Path, required=True)
    parser.add_argument("--launcher-npm-evidence", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--github-commit", required=True)
    parser.add_argument("--github-tree", required=True)
    parser.add_argument("--immutable-run-id", type=int, required=True)
    parser.add_argument("--npm-run-id", type=int, required=True)
    parser.add_argument("--marked-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = arguments()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag):
        fail("production tag is invalid")
    version = args.tag.removeprefix("v")
    github_commit = require_object_id(args.github_commit, "GitHub commit")
    github_tree = require_object_id(args.github_tree, "GitHub tree")
    if args.immutable_run_id <= 0 or args.npm_run_id <= 0:
        fail("workflow run ids must be positive")
    try:
        marked_at = datetime.fromisoformat(args.marked_at.replace("Z", "+00:00"))
    except ValueError as error:
        fail(f"invalid production timestamp: {error}")
    if marked_at.tzinfo is None:
        fail("production timestamp must include a timezone")

    snapshot = read_json(args.source_snapshot)
    publication = read_json(args.publication_manifest)
    if (
        snapshot.get("schema_version") != 2
        or snapshot.get("mode") != "code-only-single-root"
    ):
        fail("SOURCE_SNAPSHOT is not the final code-only schema")
    release = snapshot.get("release")
    source = snapshot.get("source")
    if not isinstance(release, dict) or not isinstance(source, dict):
        fail("SOURCE_SNAPSHOT omits release or source identity")
    if (
        release.get("version") != version
        or release.get("aip_protocol_version") != "1.0"
    ):
        fail("SOURCE_SNAPSHOT release identity differs from the production tag")
    gitea_commit = require_object_id(source.get("revision"), "Gitea commit")
    gitea_tree = require_object_id(source.get("tree"), "Gitea tree")
    publication_source = publication.get("source")
    if not isinstance(publication_source, dict) or publication_source != {
        "revision": gitea_commit,
        "tree": gitea_tree,
    }:
        fail("publication manifest source differs from SOURCE_SNAPSHOT")

    release_directory = args.native_release
    native_manifest_path = release_directory / "getaip-distribution-manifest.v1.json"
    native_signature_path = (
        release_directory / "getaip-distribution-manifest.v1.json.sig"
    )
    checksums_path = release_directory / "SHA256SUMS"
    native_manifest = read_json(native_manifest_path)
    native_identity = native_manifest.get("release")
    if not isinstance(native_identity, dict):
        fail("native manifest omits release identity")
    native_source = native_identity.get("source")
    if (
        native_identity.get("version") != version
        or native_identity.get("aip_protocol_version") != "1.0"
        or native_source
        != {
            "gitea_commit": gitea_commit,
            "gitea_tree": gitea_tree,
            "github_commit": github_commit,
            "github_tree": github_tree,
        }
    ):
        fail("native manifest source or version differs from the release")

    marker = {
        "schema": "org.getaip.release.production-marker.v1",
        "status": "production",
        "marked_at": args.marked_at,
        "release": {
            "version": version,
            "aip_protocol_version": "1.0",
            "tag": args.tag,
        },
        "source": {
            "gitea_commit": gitea_commit,
            "gitea_tree": gitea_tree,
            "github_commit": github_commit,
            "github_tree": github_tree,
        },
        "workflows": {
            "immutable_release_run_id": args.immutable_run_id,
            "npm_publication_run_id": args.npm_run_id,
        },
        "native": {
            "manifest_sha256": sha256_file(native_manifest_path),
            "manifest_signature_sha256": sha256_file(native_signature_path),
            "checksums_sha256": sha256_file(checksums_path),
            "assets": parse_checksums(checksums_path, release_directory),
        },
        "npm": [
            npm_record(args.scoped_npm_evidence, "@getaip/cli", version),
            npm_record(args.launcher_npm_evidence, "getaip", version),
        ],
        "containers": image_records(args.image_evidence),
        "qualification": {
            "native": native_qualification(args.native_qualification),
            "public_npm_install": public_install_evidence(args.public_install_evidence),
        },
    }
    if args.output.exists() or args.output.is_symlink():
        fail(f"refusing to replace production marker: {args.output}")
    args.output.write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()

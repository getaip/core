#!/usr/bin/env python3
"""Verify the complete GetAIP code-only GitHub snapshot boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path
from typing import NoReturn

SOURCE_SNAPSHOT = "SOURCE_SNAPSHOT.json"
PUBLICATION_MANIFEST = "PUBLICATION_MANIFEST.json"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"code-only verification: {message}")


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--expected-source-tree")
    parser.add_argument("--expected-source-branch", default="develop")
    return parser.parse_args()


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"failed to parse `{path.name}`: {error}")
    if not isinstance(value, dict):
        fail(f"`{path.name}` must contain a JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_digest(files: list[object]) -> str:
    encoded = json.dumps(
        files, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def require_object_id(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        fail(f"{label} is not a full lowercase Git object id")
    return value


def verify(arguments: argparse.Namespace) -> None:
    repository = arguments.repository.resolve(strict=True)
    if (
        Path(git(repository, "rev-parse", "--show-toplevel").strip()).resolve()
        != repository
    ):
        fail("--repository must be the Git root")
    if git(repository, "status", "--porcelain=v1", "--untracked-files=all").strip():
        fail("publication worktree is not clean")
    if git(repository, "rev-list", "--count", "HEAD").strip() != "1":
        fail("publication history must contain exactly one commit")
    root_line = git(repository, "rev-list", "--parents", "HEAD").strip().split()
    if len(root_line) != 1:
        fail("publication commit must be a root commit")
    if git(repository, "branch", "--show-current").strip() != "main":
        fail("publication branch must be `main`")

    tracked = sorted(path for path in git(repository, "ls-files").splitlines() if path)
    if PUBLICATION_MANIFEST not in tracked or SOURCE_SNAPSHOT not in tracked:
        fail("publication metadata files are not tracked")
    for path in tracked:
        if path.lower().endswith(".md") or path == "CHANGELOG":
            fail(f"forbidden documentation file is tracked: `{path}`")
        if path.startswith((".gitea/", "artifacts/")):
            fail(f"internal source-only path is tracked: `{path}`")

    snapshot = read_json(repository / SOURCE_SNAPSHOT)
    manifest = read_json(repository / PUBLICATION_MANIFEST)
    if (
        snapshot.get("schema_version") != 2
        or snapshot.get("mode") != "code-only-single-root"
    ):
        fail("SOURCE_SNAPSHOT schema or mode is invalid")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("self_excluded_from_inventory") is not True
    ):
        fail("PUBLICATION_MANIFEST schema or self-boundary is invalid")
    snapshot_source = snapshot.get("source")
    manifest_source = manifest.get("source")
    if not isinstance(snapshot_source, dict) or not isinstance(manifest_source, dict):
        fail("source identity is missing")
    source_commit = require_object_id(snapshot_source.get("revision"), "source commit")
    source_tree = require_object_id(snapshot_source.get("tree"), "source tree")
    if snapshot_source.get("branch") != arguments.expected_source_branch:
        fail("source branch differs from the expected canonical branch")
    if manifest_source != {"revision": source_commit, "tree": source_tree}:
        fail("publication manifest source differs from SOURCE_SNAPSHOT")
    if (
        arguments.expected_source_commit is not None
        and source_commit != arguments.expected_source_commit
    ):
        fail("source commit differs from the expected canonical commit")
    if (
        arguments.expected_source_tree is not None
        and source_tree != arguments.expected_source_tree
    ):
        fail("source tree differs from the expected canonical tree")

    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("file_count") != len(files):
        fail("publication file inventory count is invalid")
    if manifest.get("inventory_sha256") != inventory_digest(files):
        fail("publication inventory digest is invalid")
    inventory_paths: list[str] = []
    for record in files:
        if not isinstance(record, dict) or set(record) != {
            "mode",
            "path",
            "sha256",
            "size",
        }:
            fail("publication inventory record has unexpected fields")
        path_value = record["path"]
        if not isinstance(path_value, str) or path_value == PUBLICATION_MANIFEST:
            fail("publication inventory contains an invalid path")
        path = repository / path_value
        try:
            metadata = path.lstat()
        except OSError as error:
            fail(f"publication inventory file `{path_value}` is missing: {error}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"publication file `{path_value}` is not regular")
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if record["mode"] != mode or mode not in {"0644", "0755"}:
            fail(f"publication file `{path_value}` mode differs from its inventory")
        if record["size"] != metadata.st_size or record["sha256"] != sha256_file(path):
            fail(f"publication file `{path_value}` bytes differ from its inventory")
        inventory_paths.append(path_value)
    expected_inventory_paths = sorted(
        path for path in tracked if path != PUBLICATION_MANIFEST
    )
    if inventory_paths != expected_inventory_paths or len(set(inventory_paths)) != len(
        inventory_paths
    ):
        fail("publication inventory paths differ from the tracked tree")

    print(
        json.dumps(
            {
                "publication_commit": git(repository, "rev-parse", "HEAD").strip(),
                "publication_tree": git(repository, "rev-parse", "HEAD^{tree}").strip(),
                "source_commit": source_commit,
                "source_tree": source_tree,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    verify(parse_arguments())

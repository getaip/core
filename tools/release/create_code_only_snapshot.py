#!/usr/bin/env python3
"""Create a deterministic, single-root GetAIP GitHub publication snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn

SOURCE_SNAPSHOT = "SOURCE_SNAPSHOT.json"
PUBLICATION_MANIFEST = "PUBLICATION_MANIFEST.json"
ROOT_README = "README.md"
CANONICAL_REMOTE = "http://localhost:3000/admin/core.git"
PUBLIC_REPOSITORY = "https://github.com/getaip/core"
VERSION = "2.1.0"
EXCLUDED_PREFIXES = (".gitea/", "artifacts/")


@dataclass(frozen=True)
class SourceFile:
    path: str
    mode: int


def fail(message: str) -> NoReturn:
    raise SystemExit(f"code-only snapshot: {message}")


def git(repository: Path, *arguments: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=text,
    )
    if result.returncode != 0:
        error = (
            result.stderr.strip()
            if text
            else result.stderr.decode(errors="replace").strip()
        )
        fail(f"git {' '.join(arguments)} failed: {error}")
    return result.stdout


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepared-at", required=True)
    parser.add_argument("--source-branch", default="develop")
    return parser.parse_args()


def validate_inputs(arguments: argparse.Namespace) -> tuple[Path, Path]:
    source = arguments.source.resolve(strict=True)
    output = arguments.output.resolve(strict=False)
    if not source.is_dir():
        fail("source must be a directory")
    top = Path(str(git(source, "rev-parse", "--show-toplevel")).strip()).resolve()
    if top != source:
        fail("--source must be the Git repository root")
    if output == source or source in output.parents or output in source.parents:
        fail("output must be outside the source repository")
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            fail("output must not exist or must be an empty real directory")
    else:
        output.mkdir(mode=0o755, parents=False)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", arguments.prepared_at):
        fail("--prepared-at must be an exact UTC RFC 3339 timestamp")
    if git(source, "status", "--porcelain=v1", "--untracked-files=all").strip():
        fail("canonical source worktree must be clean")
    branch = str(git(source, "branch", "--show-current")).strip()
    if branch != arguments.source_branch:
        fail(f"source branch is `{branch}`, expected `{arguments.source_branch}`")
    remote = str(git(source, "remote", "get-url", "gitea")).strip()
    if remote != CANONICAL_REMOTE:
        fail(f"canonical Gitea remote differs from `{CANONICAL_REMOTE}`")
    head = str(git(source, "rev-parse", "HEAD")).strip()
    remote_line = str(
        git(
            source,
            "ls-remote",
            "--exit-code",
            "gitea",
            f"refs/heads/{arguments.source_branch}",
        )
    ).strip()
    remote_fields = remote_line.split()
    if (
        len(remote_fields) != 2
        or remote_fields[1] != f"refs/heads/{arguments.source_branch}"
    ):
        fail("canonical Gitea branch lookup returned an unexpected record")
    if remote_fields[0] != head:
        fail("local source HEAD differs from the canonical Gitea branch")
    with (source / "Cargo.toml").open("rb") as file:
        version = tomllib.load(file)["workspace"]["package"]["version"]
    if version != VERSION:
        fail(f"workspace version is `{version}`, expected `{VERSION}`")
    return source, output


def validate_path(path: str) -> None:
    parsed = PurePosixPath(path)
    if (
        not path
        or parsed.is_absolute()
        or "\\" in path
        or "//" in path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or any(ord(character) < 32 for character in path)
    ):
        fail(f"unsafe tracked path `{path}`")


def tracked_files(source: Path) -> list[SourceFile]:
    raw = git(source, "ls-files", "--stage", "-z", text=False)
    assert isinstance(raw, bytes)
    records: list[SourceFile] = []
    seen: set[str] = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, separator, raw_path = item.partition(b"\t")
        if not separator:
            fail("git index record omitted its path")
        fields = metadata.decode("ascii").split()
        if len(fields) != 3 or fields[2] != "0":
            fail("git index contains an unmerged record")
        mode = int(fields[0], 8)
        if mode not in {0o100644, 0o100755}:
            fail(f"unsupported tracked mode {fields[0]}")
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            fail("tracked paths must be UTF-8")
        validate_path(path)
        if path in seen:
            fail(f"duplicate tracked path `{path}`")
        seen.add(path)
        records.append(SourceFile(path=path, mode=mode & 0o777))
    return sorted(records, key=lambda item: item.path)


def exclusion_reason(path: str) -> str | None:
    if path in {"CHANGELOG", SOURCE_SNAPSHOT, PUBLICATION_MANIFEST}:
        return path
    if path.lower().endswith(".md") and path != ROOT_README:
        return "markdown"
    for prefix in EXCLUDED_PREFIXES:
        if path.startswith(prefix):
            return prefix
    return None


def copy_source_file(source: Path, output: Path, record: SourceFile) -> None:
    source_path = source / record.path
    source_metadata = source_path.lstat()
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISREG(
        source_metadata.st_mode
    ):
        fail(f"tracked input `{record.path}` is not a regular non-symlink file")
    destination = output / record.path
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with source_path.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    destination.chmod(record.mode)


def write_json(path: Path, value: object) -> None:
    encoded = (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True).encode() + b"\n"
    )
    with path.open("xb") as file:
        file.write(encoded)
        file.flush()
        os.fsync(file.fileno())
    path.chmod(0o644)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def publication_inventory(output: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(
        output.rglob("*"), key=lambda entry: entry.relative_to(output).as_posix()
    ):
        if path.is_dir():
            continue
        relative = path.relative_to(output).as_posix()
        if relative == PUBLICATION_MANIFEST or relative.startswith(".git/"):
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"publication entry `{relative}` is not a regular file")
        mode = stat.S_IMODE(metadata.st_mode)
        if mode not in {0o644, 0o755}:
            fail(f"publication entry `{relative}` has unsupported mode {mode:04o}")
        files.append(
            {
                "mode": f"{mode:04o}",
                "path": relative,
                "sha256": sha256_file(path),
                "size": metadata.st_size,
            }
        )
    return files


def inventory_digest(files: list[dict[str, object]]) -> str:
    encoded = json.dumps(
        files, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def create_snapshot(arguments: argparse.Namespace) -> dict[str, str]:
    source, output = validate_inputs(arguments)
    commit = str(git(source, "rev-parse", "HEAD")).strip()
    tree = str(git(source, "rev-parse", "HEAD^{tree}")).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(
        r"[0-9a-f]{40}", tree
    ):
        fail("source commit or tree is not a full SHA-1 object id")

    records = tracked_files(source)
    tracked_markdown = [
        record.path for record in records if record.path.lower().endswith(".md")
    ]
    if tracked_markdown != [ROOT_README]:
        fail("canonical source must track README.md as its only Markdown file")
    excluded: dict[str, int] = {}
    exported = 0
    for record in records:
        reason = exclusion_reason(record.path)
        if reason is not None:
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        copy_source_file(source, output, record)
        exported += 1

    source_snapshot = {
        "history": {
            "expected_initial_commit_count": 1,
            "imported_commits": 0,
            "imported_tags": [],
            "initial_branch": "main",
            "strategy": "single-root-snapshot",
        },
        "licensing": {
            "licensor": "WAI LLC",
            "spdx_identifier": "BUSL-1.1",
        },
        "mode": "code-only-single-root",
        "prepared_at": arguments.prepared_at,
        "publication": {
            "branch": "main",
            "repository": PUBLIC_REPOSITORY,
            "tag": f"v{VERSION}",
            "visibility_at_preparation": "public",
        },
        "publication_boundary": {
            "excluded_changelog": True,
            "excluded_markdown": True,
            "included_markdown": [ROOT_README],
            "excluded_paths": list(EXCLUDED_PREFIXES),
            "publication_manifest": PUBLICATION_MANIFEST,
        },
        "release": {
            "aip_protocol_version": "1.0",
            "name": "GetAIP Core",
            "version": VERSION,
        },
        "schema_version": 2,
        "source": {
            "branch": arguments.source_branch,
            "export_method": "reviewed-filtered-index",
            "exported_source_files": exported,
            "repository": CANONICAL_REMOTE,
            "revision": commit,
            "tracked_files": len(records),
            "tree": tree,
        },
    }
    write_json(output / SOURCE_SNAPSHOT, source_snapshot)
    files = publication_inventory(output)
    publication_manifest = {
        "excluded_counts": dict(sorted(excluded.items())),
        "file_count": len(files),
        "files": files,
        "inventory_sha256": inventory_digest(files),
        "release": {
            "aip_protocol_version": "1.0",
            "version": VERSION,
        },
        "schema_version": 1,
        "self_excluded_from_inventory": True,
        "source": {
            "revision": commit,
            "tree": tree,
        },
    }
    write_json(output / PUBLICATION_MANIFEST, publication_manifest)

    git(output, "init", "--initial-branch=main")
    # The canonical index is authoritative. Some reviewed fixture files are
    # intentionally ignored for day-to-day source work but remain tracked, so
    # the publication index must not silently drop them after export.
    git(output, "add", "--force", "--all")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": arguments.prepared_at,
            "GIT_AUTHOR_EMAIL": "hi@getaip.org",
            "GIT_AUTHOR_NAME": "WAI LLC",
            "GIT_COMMITTER_DATE": arguments.prepared_at,
            "GIT_COMMITTER_EMAIL": "hi@getaip.org",
            "GIT_COMMITTER_NAME": "WAI LLC",
        }
    )
    commit_result = subprocess.run(
        [
            "git",
            "-C",
            str(output),
            "commit",
            "--no-gpg-sign",
            "-m",
            f"Release GetAIP {VERSION} code-only snapshot",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if commit_result.returncode != 0:
        fail(f"snapshot root commit failed: {commit_result.stderr.strip()}")

    verifier = source / "tools/release/verify_code_only_snapshot.py"
    verification = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--repository",
            str(output),
            "--expected-source-commit",
            commit,
            "--expected-source-tree",
            tree,
            "--expected-source-branch",
            arguments.source_branch,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if verification.returncode != 0:
        fail(f"generated snapshot verification failed: {verification.stderr.strip()}")
    return {
        "publication_commit": str(git(output, "rev-parse", "HEAD")).strip(),
        "publication_tree": str(git(output, "rev-parse", "HEAD^{tree}")).strip(),
        "source_commit": commit,
        "source_tree": tree,
    }


def main() -> None:
    evidence = create_snapshot(parse_arguments())
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()

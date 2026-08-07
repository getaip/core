#!/usr/bin/env python3
"""Inventory Part 1 and enforce the current GetAIP naming/release contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "tools/naming/getaip-rename-ledger.json"

CLI_OLD = "aip" + "ctl"
SERVER_OLD = "aip" + "d"
TOKEN_FORMS = (
    CLI_OLD,
    SERVER_OLD,
    CLI_OLD.capitalize(),
    SERVER_OLD.capitalize(),
    CLI_OLD.upper(),
    SERVER_OLD.upper(),
)
TOKEN_RE = re.compile("|".join(re.escape(value) for value in TOKEN_FORMS))
VERSION_RE = re.compile(r"v?1\.0\.0")
ENV_RE = re.compile(
    rf"(?:{re.escape(CLI_OLD.upper())}|{re.escape(SERVER_OLD.upper())})_[A-Z0-9_]+"
)
FOREIGN_DOMAIN = "aip" + ".dev"
LEGACY_SCHEMA_ID_PREFIX = f"https://{FOREIGN_DOMAIN}/schemas/aip/"
OWNED_SCHEMA_ID_PREFIX = "https://getaip.org/schemas/aip/"

BASELINE_REVISION = "6eff581e75bfa9c0c1869d1f4dc8aec9a020adf9"
BASELINE_TREE = "507c5369d020c025806b167735a18fe8721c6887"
PROTOCOL_OWNED_BASELINE_FILES = 65
PROTOCOL_OWNED_BASELINE_SHA256 = (
    "68b63fd8babf5d2d9388fefdc45cb07ac278f0b2ecff2a0875802cb8095d59ca"
)
PROTOCOL_OWNED_PATHS = ("schemas/aip", "crates/aip-core", "crates/aip-schema")
FINAL_SOFTWARE_VERSION = "2.1.0"
FINAL_WORKSPACE_PACKAGES = 61
FINAL_ROOT_PATH_DEPENDENCIES = 55

LEDGER_RELATIVE = "tools/naming/getaip-rename-ledger.json"
VALIDATOR_RELATIVE = "tools/ci/check-getaip-naming.py"
BASELINE_SCAN_EXCLUSIONS = {LEDGER_RELATIVE, VALIDATOR_RELATIVE}
FINAL_SCAN_EXCLUSIONS = {LEDGER_RELATIVE}

PATH_MOVES = (
    (f"crates/{CLI_OLD}/", "crates/getaip-cli/"),
    (f"crates/{SERVER_OLD}/", "crates/getaip-server/"),
    (f"crates/{SERVER_OLD}-legacy-bundled/", "crates/getaip-server-legacy-bundled/"),
    (f"examples/{SERVER_OLD}-docker/", "examples/getaip-server-docker/"),
    (f"examples/mcp-server-{SERVER_OLD}/", "examples/getaip-server-mcp/"),
)

EXACT_PATH_MOVES = {
    f"crates/aip-connector-hermes-agent/src/bin/{SERVER_OLD}-hermes-chat-smoke.rs": "crates/aip-connector-hermes-agent/src/bin/getaip-server-hermes-chat-smoke.rs",
    f"crates/aip-connector-hermes-agent/src/bin/{SERVER_OLD}-hermes-mcp-smoke.rs": "crates/aip-connector-hermes-agent/src/bin/getaip-server-hermes-mcp-smoke.rs",
    f"crates/aip-connector-hermes-agent/src/bin/{SERVER_OLD}-hermes-operator-smoke.rs": "crates/aip-connector-hermes-agent/src/bin/getaip-server-hermes-operator-smoke.rs",
    f"crates/aip-connector-support-sandbox/src/bin/{SERVER_OLD}-support-sandbox-smoke.rs": "crates/aip-connector-support-sandbox/src/bin/getaip-server-support-sandbox-smoke.rs",
    f"examples/cal-diy-qualification/build-{SERVER_OLD}-offline.sh": "examples/cal-diy-qualification/build-getaip-server-offline.sh",
    f"tools/{SERVER_OLD}-mcp-stdio.sh": "tools/getaip-server-mcp-stdio.sh",
}

FINAL_PATHS = tuple(final for _, final in PATH_MOVES) + tuple(EXACT_PATH_MOVES.values())

CAL_SUFFIXES = {
    "ACCOUNT_ID",
    "BASE_URL",
    "BEARER_TOKEN_FILE",
    "CREDENTIAL_FILES",
    "MAX_RESPONSE_BYTES",
    "OAUTH_CLIENT_ID",
    "OAUTH_CLIENT_SECRET_FILE",
    "TENANT_ACCOUNTS",
    "WEBHOOK_REPLAY_FILE",
    "WEBHOOK_SECRET_FILES",
    "WEBHOOK_SUBSCRIBER_PREFIXES",
}

HERMES_SUFFIXES = {
    "API_KEY",
    "ENDPOINTS",
    "OPERATOR_APPROVAL_EXEMPT_CAPABILITY_PREFIXES",
    "OPERATOR_CANCEL_GRACE_MS",
    "OPERATOR_CAPABILITY_PREFIXES",
    "OPERATOR_CLAIM_TTL_MS",
    "OPERATOR_DELEGATION_ENABLED",
    "OPERATOR_INSTRUCTIONS",
    "OPERATOR_INSTRUCTIONS_FILE",
    "OPERATOR_MAX_DELEGATION_DEPTH",
    "OPERATOR_MAX_EVENTS",
    "OPERATOR_MAX_INPUT_BYTES",
    "OPERATOR_MODEL",
    "OPERATOR_POLL_MS",
    "OPERATOR_SCOPE_PREFIXES",
    "OPERATOR_TIMEOUT_MS",
}

SPECIAL_ENV_MAPPINGS = {
    f"{SERVER_OLD.upper()}_ENTERPRISE_SANDBOX_DATABASE_URL": (
        "AIP_ENTERPRISE_SANDBOX_DATABASE_URL",
        "connector-enterprise-sandbox",
    ),
    f"{SERVER_OLD.upper()}_SUPPORT_SANDBOX_DATABASE_URL": (
        "AIP_SUPPORT_SANDBOX_DATABASE_URL",
        "connector-support-sandbox",
    ),
    f"{SERVER_OLD.upper()}_SUPPORT_POSTGRES_PASSWORD": (
        "AIP_SUPPORT_SANDBOX_POSTGRES_PASSWORD",
        "support-sandbox-compose",
    ),
}

SEMANTIC_MAPPINGS = (
    (f"agent:{CLI_OLD}", "agent:getaip:cli", "cli-agent-principal"),
    (f"agent:{CLI_OLD}:<suffix>", "agent:getaip:cli:<suffix>", "cli-agent-principal"),
    (
        f"service:{CLI_OLD}:<suffix>",
        "service:getaip:cli:<suffix>",
        "cli-service-principal",
    ),
    (
        f"agent:{SERVER_OLD}:<suffix>",
        "agent:getaip:server:<suffix>",
        "server-agent-principal",
    ),
    (
        f"service:{SERVER_OLD}:<suffix>",
        "service:getaip:server:<suffix>",
        "server-service-principal",
    ),
    (f"cap:{SERVER_OLD}:<suffix>", "cap:aip:server:<suffix>", "server-capability"),
    (SERVER_OLD, "getaip-server", "nats-service-and-server-product"),
    (
        f"{SERVER_OLD}:<service-id>:<uuid>",
        "getaip-server:<service-id>:<uuid>",
        "worker-lease-id",
    ),
    (f"{SERVER_OLD}:native-http", "getaip-server:native-http", "native-http-issuer"),
    (
        f"{SERVER_OLD}:local-development",
        "getaip-server:local-development",
        "development-issuer",
    ),
    (
        f"{SERVER_OLD}:static-development-token",
        "getaip-server:static-development-token",
        "static-token-issuer",
    ),
    (f"{SERVER_OLD}_health", "getaip_server_health", "mcp-health-tool"),
    (f"enforced_by_{SERVER_OLD}", "enforced_by_getaip_server", "policy-json-metadata"),
    (f"{SERVER_OLD}_url", "server_url", "smoke-json-field"),
    (f"--{SERVER_OLD}-url", "--server-url", "smoke-cli-field"),
    (f"{SERVER_OLD.upper()}_PATH_OK", "GETAIP_SERVER_PATH_OK", "hermes-smoke-sentinel"),
    (f"check-{SERVER_OLD}-boundary", "check-getaip-server-boundary", "xtask-command"),
    (f"check_{SERVER_OLD}_boundary", "check_getaip_server_boundary", "xtask-symbol"),
    (
        f"Check{SERVER_OLD.capitalize()}Boundary",
        "CheckGetaipServerBoundary",
        "xtask-variant",
    ),
    (f"mcp-server-{SERVER_OLD}", "getaip-server-mcp", "cargo-example"),
    (f"{SERVER_OLD}-core", "getaip-server-core", "capability-owner"),
    (f"{SERVER_OLD}-<suffix>", "getaip-server-<suffix>", "server-kebab-prefix"),
    (f"{SERVER_OLD}_<suffix>", "getaip_server_<suffix>", "server-snake-prefix"),
    (f"{SERVER_OLD}-runtime", "getaip-server-runtime", "postgres-role"),
    (f"{SERVER_OLD}_runtime", "getaip_server_runtime", "postgres-database"),
    (f"{SERVER_OLD}-runtime.url", "getaip-server-runtime.url", "runtime-url-file"),
    (f"/etc/{SERVER_OLD}", "/etc/getaip-server", "server-config-directory"),
    (
        f"/run/secrets/{SERVER_OLD}-<suffix>",
        "/run/secrets/getaip-server-<suffix>",
        "server-secret-prefix",
    ),
    (f"{SERVER_OLD}-state", "getaip-server-state", "compose-state-volume"),
    (
        f"service:test-central-{SERVER_OLD}",
        "service:test-central-getaip-server",
        "embedded-test-principal",
    ),
    (
        f"service:test-fleet-{SERVER_OLD}",
        "service:test-fleet-getaip-server",
        "embedded-test-principal",
    ),
    (f"service:{SERVER_OLD}", "service:getaip-server", "compose-network-mode"),
    (f"{SERVER_OLD}:<tag>", "getaip/server:<tag>", "local-server-image"),
    (f"{SERVER_OLD}.<code>", "aip.server.<code>", "server-error-code"),
    (f"{CLI_OLD}.<code>", "aip.cli.<code>", "cli-error-code"),
    (f"getaip/{CLI_OLD}", "getaip/cli", "cli-image"),
    (f"getaip/{SERVER_OLD}-core", "getaip/server", "server-image"),
    (
        f"getaip/{SERVER_OLD}-migration-bundle",
        "getaip/server-migration-bundle",
        "migration-image",
    ),
)

TARGET_MAPPINGS = (
    {
        "entity": "package",
        "old_package": CLI_OLD,
        "old": CLI_OLD,
        "new_package": "getaip-cli",
        "new": "getaip-cli",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": CLI_OLD,
        "old": CLI_OLD,
        "new_package": "getaip-cli",
        "new": "getaip",
    },
    {
        "entity": "package",
        "old_package": SERVER_OLD,
        "old": SERVER_OLD,
        "new_package": "getaip-server",
        "new": "getaip-server",
    },
    {
        "entity": "target",
        "kind": "lib",
        "old_package": SERVER_OLD,
        "old": SERVER_OLD,
        "new_package": "getaip-server",
        "new": "getaip_server",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": SERVER_OLD,
        "old": SERVER_OLD,
        "new_package": "getaip-server",
        "new": "getaip-server",
    },
    {
        "entity": "package",
        "old_package": f"{SERVER_OLD}-legacy-bundled",
        "old": f"{SERVER_OLD}-legacy-bundled",
        "new_package": "getaip-server-legacy-bundled",
        "new": "getaip-server-legacy-bundled",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": f"{SERVER_OLD}-legacy-bundled",
        "old": f"{SERVER_OLD}-legacy-bundled",
        "new_package": "getaip-server-legacy-bundled",
        "new": "getaip-server-legacy-bundled",
    },
    {
        "entity": "target",
        "kind": "example",
        "old_package": "aip",
        "old": f"mcp-server-{SERVER_OLD}",
        "new_package": "aip",
        "new": "getaip-server-mcp",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": "aip-connector-hermes-agent",
        "old": f"{SERVER_OLD}-hermes-chat-smoke",
        "new_package": "aip-connector-hermes-agent",
        "new": "getaip-server-hermes-chat-smoke",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": "aip-connector-hermes-agent",
        "old": f"{SERVER_OLD}-hermes-mcp-smoke",
        "new_package": "aip-connector-hermes-agent",
        "new": "getaip-server-hermes-mcp-smoke",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": "aip-connector-hermes-agent",
        "old": f"{SERVER_OLD}-hermes-operator-smoke",
        "new_package": "aip-connector-hermes-agent",
        "new": "getaip-server-hermes-operator-smoke",
    },
    {
        "entity": "target",
        "kind": "bin",
        "old_package": "aip-connector-support-sandbox",
        "old": f"{SERVER_OLD}-support-sandbox-smoke",
        "new_package": "aip-connector-support-sandbox",
        "new": "getaip-server-support-sandbox-smoke",
    },
)

RELEASE_VERSION_PATHS = {
    "crates/aip-connector-control-plane/Dockerfile",
    f"crates/{CLI_OLD}/Dockerfile",
    f"crates/{SERVER_OLD}/Dockerfile",
    f"crates/{SERVER_OLD}-legacy-bundled/Dockerfile",
    "deploy/connector-fleet/Dockerfile.edge",
    "deploy/connector-fleet/Dockerfile.fixture",
    "deploy/connector-fleet/Dockerfile.host",
    "deploy/connector-fleet/Dockerfile.product-fixture",
    "deploy/connector-fleet/compose.yml",
    f"examples/cal-diy-qualification/build-{SERVER_OLD}-offline.sh",
    "private-sdk-release.json",
}

HISTORICAL_VERSION_PATHS = {
    "CHANGELOG",
    "LICENSE",
    "NOTICE",
    "SOURCE_SNAPSHOT.json",
    "tools/ci/check-publication-hygiene.sh",
}

LEGACY_RETENTION_PATHS = {
    ".gitignore",
    ".dockerignore",
    "tools/ci/check-publication-hygiene.sh",
}


def run(*args: str) -> str:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def protocol_owned_index_identity() -> tuple[int, str]:
    raw = subprocess.check_output(
        ["git", "ls-files", "--stage", "-z", "--", *PROTOCOL_OWNED_PATHS],
        cwd=ROOT,
    )
    records: list[tuple[str, str, str]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, separator, raw_path = item.partition(b"\t")
        if not separator:
            raise ValueError("protocol-owned index record omitted its path")
        mode, object_id, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise ValueError("protocol-owned index contains an unmerged record")
        path = raw_path.decode("utf-8")
        records.append((path, mode, object_id))
    canonical = "".join(
        f"{mode} {object_id}\t{path}\n" for path, mode, object_id in sorted(records)
    ).encode()
    return len(records), hashlib.sha256(canonical).hexdigest()


def tracked_paths(exclusions: set[str] = BASELINE_SCAN_EXCLUSIONS) -> list[str]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return sorted(
        value.decode("utf-8")
        for value in output.split(b"\0")
        if value and value.decode("utf-8") not in exclusions
    )


def text_lines(path: str) -> list[str] | None:
    try:
        return (ROOT / path).read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def occurrence_class(path: str, line: str, match: str, offset: int) -> str:
    if ENV_RE.fullmatch(extract_environment_name(line, offset) or ""):
        return "configuration-environment"
    lowered = line.lower()
    if path.endswith((".md", ".mdx")) or path in {"README.md", "CHANGELOG"}:
        return "documentation"
    if path.endswith("Cargo.toml") or "cargo" in lowered or "binary" in lowered:
        return "cargo-package-or-target"
    if any(
        value in lowered
        for value in ("service:", "agent:", "cap:", "issuer", "audience", "principal")
    ):
        return "implementation-identity"
    if any(
        value in lowered
        for value in ("error", "metric", "tracing", "component", "realm")
    ):
        return "error-or-observability"
    if any(value in path.lower() for value in ("test", "fixture", "example")):
        return "test-fixture-or-example"
    if path in LEGACY_RETENTION_PATHS and f".{SERVER_OLD}-" in line:
        return "legacy-retention-control"
    return "active-implementation"


def namespace(match: str) -> str:
    return "cli" if CLI_OLD in match.lower() else "server"


def extract_environment_name(line: str, offset: int) -> str | None:
    for found in ENV_RE.finditer(line):
        if found.start() <= offset < found.end():
            return found.group(0)
    return None


def content_occurrences(paths: Iterable[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in paths:
        lines = text_lines(path)
        if lines is None:
            continue
        for line_number, line in enumerate(lines, start=1):
            for found in TOKEN_RE.finditer(line):
                match = found.group(0)
                entries.append(
                    {
                        "path": path,
                        "line": line_number,
                        "column": found.start() + 1,
                        "match": match,
                        "namespace": namespace(match),
                        "class": occurrence_class(path, line, match, found.start()),
                        "line_text": line,
                    }
                )
    return entries


def map_environment(old: str) -> tuple[str, str]:
    cli_prefix = f"{CLI_OLD.upper()}_"
    server_prefix = f"{SERVER_OLD.upper()}_"
    if old.startswith(cli_prefix):
        return f"GETAIP_{old.removeprefix(cli_prefix)}", "getaip-cli"
    if old in SPECIAL_ENV_MAPPINGS:
        return SPECIAL_ENV_MAPPINGS[old]
    suffix = old.removeprefix(server_prefix)
    if suffix.startswith("CAL_DIY_"):
        connector_suffix = suffix.removeprefix("CAL_DIY_")
        if connector_suffix not in CAL_SUFFIXES:
            raise ValueError(f"unapproved Cal.com environment suffix: {old}")
        return f"AIP_CAL_DIY_{connector_suffix}", "connector-cal-diy"
    if suffix.startswith("HERMES_"):
        connector_suffix = suffix.removeprefix("HERMES_")
        if connector_suffix not in HERMES_SUFFIXES:
            raise ValueError(f"unapproved Hermes environment suffix: {old}")
        return f"AIP_HERMES_{connector_suffix}", "connector-hermes-agent"
    return f"GETAIP_SERVER_{suffix}", "getaip-server"


def environment_ledger(paths: Iterable[str]) -> list[dict[str, Any]]:
    locations: dict[str, list[dict[str, Any]]] = {}
    sentinel = f"{SERVER_OLD.upper()}_PATH_OK"
    for path in paths:
        lines = text_lines(path)
        if lines is None:
            continue
        for line_number, line in enumerate(lines, start=1):
            for found in ENV_RE.finditer(line):
                old = found.group(0)
                if old == sentinel:
                    continue
                locations.setdefault(old, []).append(
                    {"path": path, "line": line_number, "column": found.start() + 1}
                )
    entries = []
    for old in sorted(locations):
        final, owner = map_environment(old)
        entries.append(
            {
                "old": old,
                "final": final,
                "owner": owner,
                "consuming_process": owner,
                "locations": locations[old],
            }
        )
    return entries


def mapped_path(path: str) -> str | None:
    if path in EXACT_PATH_MOVES:
        return EXACT_PATH_MOVES[path]
    for old_prefix, final_prefix in PATH_MOVES:
        if path.startswith(old_prefix):
            return final_prefix + path.removeprefix(old_prefix)
    return None


def path_ledger(paths: Iterable[str]) -> list[dict[str, str]]:
    entries = []
    for path in paths:
        if not TOKEN_RE.search(path):
            continue
        final = mapped_path(path)
        if final is None:
            raise ValueError(f"tracked old-name path has no frozen mapping: {path}")
        entries.append({"old": path, "final": final})
    return entries


def cargo_metadata() -> dict[str, Any]:
    return json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps"))


def workspace_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    members = set(metadata["workspace_members"])
    return [package for package in metadata["packages"] if package["id"] in members]


def cargo_old_entities(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for package in workspace_packages(metadata):
        package_name = package["name"]
        if TOKEN_RE.search(package_name):
            entries.append(
                {
                    "entity": "package",
                    "old_package": package_name,
                    "old": package_name,
                    "manifest": str(Path(package["manifest_path"]).relative_to(ROOT)),
                }
            )
        for target in package["targets"]:
            if not TOKEN_RE.search(target["name"]):
                continue
            for kind in target["kind"]:
                entries.append(
                    {
                        "entity": "target",
                        "kind": kind,
                        "old_package": package_name,
                        "old": target["name"],
                        "source": str(Path(target["src_path"]).relative_to(ROOT)),
                    }
                )
    return sorted(entries, key=lambda item: json.dumps(item, sort_keys=True))


def lock_package_by_line(lines: list[str]) -> dict[int, str | None]:
    result: dict[int, str | None] = {}
    package: str | None = None
    in_package = False
    for number, line in enumerate(lines, start=1):
        if line == "[[package]]":
            package = None
            in_package = True
        elif line.startswith("[["):
            in_package = False
            package = None
        elif in_package and package is None:
            found = re.fullmatch(r'name = "([^"]+)"', line)
            if found:
                package = found.group(1)
        result[number] = package
    return result


def version_class(
    path: str,
    line_number: int,
    line: str,
    lock_package: str | None,
    workspace_names: set[str],
) -> tuple[str, str]:
    if path == "Cargo.toml":
        return (
            "release-owned",
            "workspace package version or root path dependency requirement",
        )
    if path.endswith("Cargo.lock"):
        if lock_package in workspace_names:
            return (
                "release-owned",
                f"generated lock entry for workspace package {lock_package}",
            )
        return (
            "protocol-or-independent",
            f"independent lock entry for {lock_package or 'unknown package'}",
        )
    if path in RELEASE_VERSION_PATHS:
        return "release-owned", "current workspace image or release metadata"
    if path == "README.md" and line_number < 100:
        return "release-owned", "current workspace release guidance"
    if path == "README.md":
        return "historical", "license conversion statement for the original release"
    if path in HISTORICAL_VERSION_PATHS:
        return "historical", "original release, license, or publication provenance"
    return (
        "protocol-or-independent",
        "protocol fixture, peer, sidecar, plugin, or semver test value",
    )


def version_ledger(
    paths: Iterable[str], metadata: dict[str, Any]
) -> list[dict[str, Any]]:
    workspace_names = {package["name"] for package in workspace_packages(metadata)}
    entries: list[dict[str, Any]] = []
    for path in paths:
        lines = text_lines(path)
        if lines is None:
            continue
        package_lines = (
            lock_package_by_line(lines) if path.endswith("Cargo.lock") else {}
        )
        for line_number, line in enumerate(lines, start=1):
            for found in VERSION_RE.finditer(line):
                item_class, reason = version_class(
                    path,
                    line_number,
                    line,
                    package_lines.get(line_number),
                    workspace_names,
                )
                entries.append(
                    {
                        "path": path,
                        "line": line_number,
                        "column": found.start() + 1,
                        "value": found.group(0),
                        "class": item_class,
                        "reason": reason,
                        "line_text": line,
                    }
                )
    return entries


def inventory_summary(
    paths: list[str],
    occurrences: list[dict[str, Any]],
    environments: list[dict[str, Any]],
    moved_paths: list[dict[str, str]],
    versions: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, int]:
    text_by_path = {
        path: "\n".join(lines)
        for path in paths
        if (lines := text_lines(path)) is not None
    }
    word_re = re.compile(rf"\b(?:{re.escape(CLI_OLD)}|{re.escape(SERVER_OLD)})\b")
    raw_lower_re = re.compile(rf"{re.escape(CLI_OLD)}|{re.escape(SERVER_OLD)}")
    content_paths = {entry["path"] for entry in occurrences}
    path_matches = {entry["old"] for entry in moved_paths}
    return {
        "tracked_content_files_word_boundary_lowercase": sum(
            bool(word_re.search(text)) for text in text_by_path.values()
        ),
        "tracked_content_files_raw_lowercase": sum(
            bool(raw_lower_re.search(text)) for text in text_by_path.values()
        ),
        "tracked_content_files_any_explicit_form": len(content_paths),
        "tracked_files_content_or_path": len(content_paths | path_matches),
        "lowercase_cli_occurrences": sum(
            text.count(CLI_OLD) for text in text_by_path.values()
        ),
        "lowercase_server_occurrences": sum(
            text.count(SERVER_OLD) for text in text_by_path.values()
        ),
        "uppercase_cli_occurrences": sum(
            text.count(CLI_OLD.upper()) for text in text_by_path.values()
        ),
        "uppercase_server_occurrences": sum(
            text.count(SERVER_OLD.upper()) for text in text_by_path.values()
        ),
        "unique_cli_environment_names": sum(
            entry["old"].startswith(CLI_OLD.upper() + "_") for entry in environments
        ),
        "unique_server_environment_names": sum(
            entry["old"].startswith(SERVER_OLD.upper() + "_") for entry in environments
        ),
        "non_environment_uppercase_sentinels": sum(
            text.count(f"{SERVER_OLD.upper()}_PATH_OK")
            for text in text_by_path.values()
        ),
        "tracked_old_name_paths": len(moved_paths),
        "version_occurrences": len(versions),
        "workspace_packages": len(workspace_packages(metadata)),
        "root_path_dependency_requirements": sum(
            1
            for line in text_by_path["Cargo.toml"].splitlines()
            if 'path = "crates/' in line and 'version = "1.0.0"' in line
        ),
    }


def build_ledger() -> dict[str, Any]:
    paths = tracked_paths()
    metadata = cargo_metadata()
    occurrences = content_occurrences(paths)
    environments = environment_ledger(paths)
    moved_paths = path_ledger(paths)
    versions = version_ledger(paths, metadata)
    return {
        "schema_version": 1,
        "scope": "GetAIP Part 1 simple naming migration; no protocol change",
        "baseline": {"revision": BASELINE_REVISION, "tree": BASELINE_TREE},
        "explicit_token_forms": list(TOKEN_FORMS),
        "summary": inventory_summary(
            paths, occurrences, environments, moved_paths, versions, metadata
        ),
        "environment_mappings": environments,
        "semantic_mappings": [
            {"old": old, "final": final, "class": item_class}
            for old, final, item_class in SEMANTIC_MAPPINGS
        ],
        "target_mappings": list(TARGET_MAPPINGS),
        "baseline_cargo_entities": cargo_old_entities(metadata),
        "tracked_path_mappings": moved_paths,
        "content_occurrences": occurrences,
        "software_version_occurrences": versions,
        "allowed_final_occurrences": [],
        "legacy_retention_policy": {
            "paths": sorted(LEGACY_RETENTION_PATHS),
            "literal_prefix": f".{SERVER_OLD}-",
            "owner": "release-engineering",
            "removal_condition": "remove only after all pre-v2 local evidence is retired",
        },
    }


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate_environment_ledger(
    entries: list[dict[str, Any]], errors: list[str]
) -> None:
    old_names = [entry.get("old") for entry in entries]
    final_names = [entry.get("final") for entry in entries]
    owners = [entry.get("owner") for entry in entries]
    require(
        len(entries) == 131,
        f"environment ledger has {len(entries)} entries, expected 131",
        errors,
    )
    require(
        len(old_names) == len(set(old_names)),
        "environment ledger has duplicate old names",
        errors,
    )
    require(
        len(final_names) == len(set(final_names)),
        "environment ledger has duplicate final names",
        errors,
    )
    require(
        all(owners), "environment ledger contains an entry without an owner", errors
    )
    require(
        all(entry.get("locations") for entry in entries),
        "environment ledger contains an entry without locations",
        errors,
    )
    counts = Counter(entry["owner"] for entry in entries)
    expected = {
        "getaip-cli": 13,
        "getaip-server": 88,
        "connector-cal-diy": 11,
        "connector-hermes-agent": 16,
        "connector-enterprise-sandbox": 1,
        "connector-support-sandbox": 1,
        "support-sandbox-compose": 1,
    }
    require(
        dict(counts) == expected,
        f"environment ownership partition differs: {dict(counts)}",
        errors,
    )
    for entry in entries:
        try:
            final, owner = map_environment(entry["old"])
        except ValueError as error:
            errors.append(str(error))
            continue
        require(
            (entry["final"], entry["owner"]) == (final, owner),
            f"invalid environment mapping for {entry['old']}",
            errors,
        )


def target_key(entry: dict[str, Any]) -> tuple[str, str | None, str, str]:
    return (
        entry["entity"],
        entry.get("kind"),
        entry["old_package"],
        entry["old"],
    )


def validate_common(ledger: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(ledger.get("schema_version") == 1, "unsupported ledger schema", errors)
    require(
        ledger.get("baseline")
        == {"revision": BASELINE_REVISION, "tree": BASELINE_TREE},
        "baseline identity differs",
        errors,
    )
    require(
        ledger.get("explicit_token_forms") == list(TOKEN_FORMS),
        "explicit token forms differ",
        errors,
    )
    validate_environment_ledger(ledger.get("environment_mappings", []), errors)
    require(
        len(ledger.get("tracked_path_mappings", [])) == 34,
        "tracked path ledger must contain 34 entries",
        errors,
    )
    require(
        len(ledger.get("software_version_occurrences", [])) == 203,
        "software version ledger must contain 203 occurrences",
        errors,
    )
    require(
        Counter(
            entry.get("class")
            for entry in ledger.get("software_version_occurrences", [])
        ).keys()
        == {"release-owned", "protocol-or-independent", "historical"},
        "software version ledger does not contain all three required classes",
        errors,
    )
    mapping_keys = {target_key(entry) for entry in ledger.get("target_mappings", [])}
    for entity in ledger.get("baseline_cargo_entities", []):
        require(
            target_key(entity) in mapping_keys,
            f"Cargo old-name entity lacks a final target: {entity}",
            errors,
        )
    return errors


def compare_inventory(ledger: dict[str, Any]) -> list[str]:
    errors = validate_common(ledger)
    current = build_ledger()
    for key in (
        "summary",
        "environment_mappings",
        "semantic_mappings",
        "target_mappings",
        "baseline_cargo_entities",
        "tracked_path_mappings",
        "content_occurrences",
        "software_version_occurrences",
    ):
        require(current[key] == ledger.get(key), f"inventory drift in {key}", errors)
    expected_summary = {
        "tracked_content_files_word_boundary_lowercase": 69,
        "tracked_content_files_raw_lowercase": 70,
        "tracked_content_files_any_explicit_form": 72,
        "tracked_files_content_or_path": 77,
        "lowercase_cli_occurrences": 126,
        "lowercase_server_occurrences": 749,
        "uppercase_cli_occurrences": 71,
        "uppercase_server_occurrences": 342,
        "unique_cli_environment_names": 13,
        "unique_server_environment_names": 118,
        "non_environment_uppercase_sentinels": 1,
        "tracked_old_name_paths": 34,
        "version_occurrences": 203,
        "workspace_packages": 60,
        "root_path_dependency_requirements": 54,
    }
    require(
        ledger.get("summary") == expected_summary,
        f"baseline summary differs: {ledger.get('summary')}",
        errors,
    )
    for final in FINAL_PATHS:
        require(
            not (ROOT / final.rstrip("/")).exists(),
            f"frozen final path already exists: {final}",
            errors,
        )
    for executable in ("getaip", "getaip-cli", "getaip-server"):
        require(
            shutil.which(executable) is None,
            f"final executable already resolves from PATH: {executable}",
            errors,
        )
    return errors


def final_exception(entry: dict[str, Any], ledger: dict[str, Any]) -> tuple[bool, str]:
    path = entry["path"]
    line_text = entry["line_text"]
    if path in LEGACY_RETENTION_PATHS and f".{SERVER_OLD}-" in line_text:
        return True, "legacy-retention-control"
    for allowed in ledger.get("allowed_final_occurrences", []):
        if (
            allowed.get("path") == path
            and allowed.get("match") == entry["match"]
            and allowed.get("line_text") == line_text
            and allowed.get("reason")
            and allowed.get("owner")
            and allowed.get("removal_condition")
        ):
            return True, "explicit-historical-exception"
    return False, entry["class"]


def validate_final_targets(
    metadata: dict[str, Any], ledger: dict[str, Any], errors: list[str]
) -> None:
    packages = {package["name"]: package for package in workspace_packages(metadata)}
    require(
        len(packages) == FINAL_WORKSPACE_PACKAGES,
        f"final workspace has {len(packages)} packages, expected {FINAL_WORKSPACE_PACKAGES}",
        errors,
    )
    for mapping in ledger["target_mappings"]:
        final_package = mapping["new_package"]
        package = packages.get(final_package)
        require(
            package is not None, f"final package is missing: {final_package}", errors
        )
        if package is None or mapping["entity"] == "package":
            continue
        matching = [
            target
            for target in package["targets"]
            if target["name"] == mapping["new"] and mapping["kind"] in target["kind"]
        ]
        require(
            bool(matching),
            f"final Cargo target is missing: {final_package}/{mapping['kind']}/{mapping['new']}",
            errors,
        )
    require(
        not any(TOKEN_RE.search(package["name"]) for package in packages.values()),
        "final Cargo metadata contains an old package name",
        errors,
    )
    for package in packages.values():
        require(
            package["version"] == FINAL_SOFTWARE_VERSION,
            f"workspace package {package['name']} is not {FINAL_SOFTWARE_VERSION}",
            errors,
        )
        for target in package["targets"]:
            require(
                not TOKEN_RE.search(target["name"]),
                f"final Cargo target contains an old name: {target['name']}",
                errors,
            )


def enforce(ledger: dict[str, Any]) -> list[str]:
    errors = validate_common(ledger)
    paths = tracked_paths(FINAL_SCAN_EXCLUSIONS)
    for path in paths:
        lines = text_lines(path)
        if lines is None:
            continue
        for line_number, line in enumerate(lines, start=1):
            if FOREIGN_DOMAIN in line:
                errors.append(
                    f"foreign public domain: {path}:{line_number} match={FOREIGN_DOMAIN}"
                )
    occurrences = content_occurrences(paths)
    violations: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []
    for entry in occurrences:
        allowed, item_class = final_exception(entry, ledger)
        report = {
            "path": entry["path"],
            "line": entry["line"],
            "match": entry["match"],
            "namespace": entry["namespace"],
            "class": item_class,
        }
        (retained if allowed else violations).append(report)
    old_paths = [path for path in paths if TOKEN_RE.search(path)]
    if old_paths:
        errors.extend(f"old-name tracked path: {path}" for path in old_paths)
    if violations:
        errors.extend(
            f"active old name: {entry['path']}:{entry['line']} match={entry['match']} namespace={entry['namespace']} class={entry['class']}"
            for entry in violations
        )
    metadata = cargo_metadata()
    validate_final_targets(metadata, ledger, errors)
    cargo_toml = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    root_path_versions = sum(
        1
        for line in cargo_toml.splitlines()
        if 'path = "crates/' in line and f'version = "{FINAL_SOFTWARE_VERSION}"' in line
    )
    require(
        root_path_versions == FINAL_ROOT_PATH_DEPENDENCIES,
        f"final root path dependency version count is {root_path_versions}, expected {FINAL_ROOT_PATH_DEPENDENCIES}",
        errors,
    )
    require(
        f'version = "{FINAL_SOFTWARE_VERSION}"' in cargo_toml,
        f"workspace release version {FINAL_SOFTWARE_VERSION} is missing",
        errors,
    )
    protocol_version_hits = run("git", "grep", "-n", "AIP_VERSION.*1\\.0", "--", ".")
    require(
        bool(protocol_version_hits.strip()),
        "AIP_VERSION = 1.0 preservation proof is missing",
        errors,
    )
    protocol_file_count, protocol_digest = protocol_owned_index_identity()
    require(
        protocol_file_count == PROTOCOL_OWNED_BASELINE_FILES,
        "protocol-owned file count differs from the production baseline",
        errors,
    )
    require(
        protocol_digest == PROTOCOL_OWNED_BASELINE_SHA256,
        "protocol-owned index identity differs from the production baseline",
        errors,
    )
    baseline_available = (
        subprocess.run(
            ["git", "cat-file", "-e", f"{BASELINE_REVISION}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )
    if baseline_available:
        protocol_prefixes = (
            "schemas/aip/",
            "crates/aip-core/",
            "crates/aip-schema/",
        )
        baseline_protocol_paths = set(
            run(
                "git",
                "ls-tree",
                "-r",
                "--name-only",
                BASELINE_REVISION,
                "--",
                "schemas/aip",
                "crates/aip-core",
                "crates/aip-schema",
            ).splitlines()
        )
        current_protocol_paths = {
            path for path in paths if path.startswith(protocol_prefixes)
        }
        require(
            current_protocol_paths == baseline_protocol_paths,
            "protocol-owned path set differs from the production baseline",
            errors,
        )
        for path in sorted(current_protocol_paths & baseline_protocol_paths):
            baseline = subprocess.check_output(
                ["git", "show", f"{BASELINE_REVISION}:{path}"],
                cwd=ROOT,
            )
            current = (
                (ROOT / path)
                .read_bytes()
                .replace(
                    OWNED_SCHEMA_ID_PREFIX.encode("utf-8"),
                    LEGACY_SCHEMA_ID_PREFIX.encode("utf-8"),
                )
            )
            if path == "crates/aip-schema/src/lib.rs":
                baseline = re.sub(rb"\s+", b"", baseline)
                current = re.sub(rb"\s+", b"", current)
            require(
                current == baseline,
                f"protocol-owned path differs beyond the owned schema-id namespace: {path}",
                errors,
            )
    evidence = sorted(path.name for path in ROOT.glob(f".{SERVER_OLD}-*"))
    print(
        json.dumps(
            {
                "allowed_old_name_occurrences": retained,
                "retained_untracked_evidence": evidence,
            },
            indent=2,
        )
    )
    return errors


def load_ledger() -> dict[str, Any]:
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))


def write_ledger(ledger: dict[str, Any]) -> None:
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    LEDGER_PATH.write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    inventory_parser = subparsers.add_parser(
        "inventory", help="capture or verify the reviewed baseline inventory"
    )
    inventory_parser.add_argument(
        "--write", action="store_true", help="write the deterministic baseline ledger"
    )
    subparsers.add_parser(
        "enforce", help="reject active old names and validate final identities"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "inventory" and args.write:
        ledger = build_ledger()
        errors = validate_common(ledger)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        write_ledger(ledger)
        print(f"wrote {LEDGER_PATH.relative_to(ROOT)}")
        return 0
    ledger = load_ledger()
    errors = compare_inventory(ledger) if args.mode == "inventory" else enforce(ledger)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"GetAIP naming {args.mode}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

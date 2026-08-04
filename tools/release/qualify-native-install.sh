#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RELEASE_DIRECTORY=${1:?usage: qualify-native-install.sh RELEASE_DIRECTORY EVIDENCE_DIRECTORY}
EVIDENCE_DIRECTORY=${2:?usage: qualify-native-install.sh RELEASE_DIRECTORY EVIDENCE_DIRECTORY}

case "$RELEASE_DIRECTORY" in
  /*) ;;
  *) RELEASE_DIRECTORY="$PWD/$RELEASE_DIRECTORY" ;;
esac
case "$EVIDENCE_DIRECTORY" in
  /*) ;;
  *) EVIDENCE_DIRECTORY="$PWD/$EVIDENCE_DIRECTORY" ;;
esac

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=darwin-arm64 ;;
  Darwin-x86_64) asset=darwin-x64 ;;
  Linux-aarch64 | Linux-arm64) asset=linux-arm64 ;;
  Linux-x86_64 | Linux-amd64) asset=linux-x64 ;;
  *)
    echo "unsupported native qualification platform: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

cli="$RELEASE_DIRECTORY/getaip-$version-$asset"
server="$RELEASE_DIRECTORY/getaip-server-$version-$asset.tar.gz"
archive="$RELEASE_DIRECTORY/getaip-distribution-$version-$asset.tar.gz"
manifest="$RELEASE_DIRECTORY/getaip-distribution-manifest.v1.json"
signature="$RELEASE_DIRECTORY/getaip-distribution-manifest.v1.json.sig"

for path in "$cli" "$server" "$archive" "$manifest" "$signature"; do
  test -f "$path"
  test ! -L "$path"
done
chmod 0755 "$cli"
mkdir -p "$EVIDENCE_DIRECTORY"

(
  cd "$ROOT"
  CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_INCREMENTAL=0 \
    cargo test --locked -p getaip-distribution -p getaip-cli
) > "$EVIDENCE_DIRECTORY/installer-contract-tests.txt" 2>&1

qualification_root=$(mktemp -d)
trap 'rm -rf "$qualification_root"' EXIT HUP INT TERM
install_root="$qualification_root/install"

test "$("$cli" --version)" = "getaip $version"
"$cli" version --output json > "$EVIDENCE_DIRECTORY/version.json"

"$cli" setup \
  --manifest "$manifest" \
  --signature "$signature" \
  --artifact "$archive" \
  --test-root "$install_root" \
  --dry-run --output json > "$EVIDENCE_DIRECTORY/setup-dry-run.json"
test ! -e "$install_root"

"$cli" setup \
  --manifest "$manifest" \
  --signature "$signature" \
  --artifact "$archive" \
  --test-root "$install_root" \
  --output json > "$EVIDENCE_DIRECTORY/setup.json"
"$cli" setup \
  --manifest "$manifest" \
  --signature "$signature" \
  --artifact "$archive" \
  --test-root "$install_root" \
  --output json > "$EVIDENCE_DIRECTORY/setup-idempotent.json"

installed_cli="$install_root/data/versions/$version/bin/getaip"
installed_server="$install_root/data/versions/$version/bin/getaip-server"
test -x "$installed_cli"
test -x "$installed_server"
test "$("$installed_cli" --version)" = "getaip $version"
test "$("$installed_server" --version)" = "getaip-server $version"

"$installed_cli" doctor --test-root "$install_root" --output json \
  > "$EVIDENCE_DIRECTORY/doctor.json"
"$installed_cli" status --test-root "$install_root" --output json \
  > "$EVIDENCE_DIRECTORY/status.json"
"$installed_cli" serve --test-root "$install_root" -- --version \
  > "$EVIDENCE_DIRECTORY/serve-version.txt"
test "$(sed -n '1p' "$EVIDENCE_DIRECTORY/serve-version.txt")" = "getaip-server $version"

service_secret="$qualification_root/service-native-token"
service_environment="$install_root/config/service.env"
printf '%s\n' 'qualification-token-not-retained' > "$service_secret"
chmod 0600 "$service_secret"
printf 'GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE=%s\n' "$service_secret" \
  > "$service_environment"
chmod 0600 "$service_environment"
"$installed_cli" service --test-root "$install_root" install \
  > "$EVIDENCE_DIRECTORY/service-install.txt"
case "$asset" in
  darwin-*)
    service_definition="$install_root/state/services/launchd/org.getaip.server.plist"
    ;;
  linux-*)
    service_definition="$install_root/state/services/systemd/getaip-server.service"
    ;;
esac
test -f "$service_definition"
grep -Fq 'GETAIP_SERVER_NATIVE_BEARER_TOKEN_FILE' "$service_definition"
grep -Fq "$service_secret" "$service_definition"
cp "$service_definition" "$EVIDENCE_DIRECTORY/service-definition.txt"
"$installed_cli" doctor --test-root "$install_root" --output json \
  > "$EVIDENCE_DIRECTORY/doctor-service.json"
"$installed_cli" service --test-root "$install_root" start \
  > "$EVIDENCE_DIRECTORY/service-start.txt"
"$installed_cli" service --test-root "$install_root" status \
  > "$EVIDENCE_DIRECTORY/service-status.txt"
"$installed_cli" service --test-root "$install_root" restart \
  > "$EVIDENCE_DIRECTORY/service-restart.txt"
"$installed_cli" service --test-root "$install_root" stop \
  > "$EVIDENCE_DIRECTORY/service-stop.txt"
"$installed_cli" service --test-root "$install_root" uninstall \
  > "$EVIDENCE_DIRECTORY/service-uninstall.txt"
test ! -e "$service_definition"

"$installed_cli" uninstall --test-root "$install_root" --dry-run --output json \
  > "$EVIDENCE_DIRECTORY/uninstall-dry-run.json"
test -e "$install_root/data/current"
"$installed_cli" uninstall --test-root "$install_root" --output json \
  > "$EVIDENCE_DIRECTORY/uninstall.json"
test ! -e "$install_root/data/current"

python3 - "$EVIDENCE_DIRECTORY" "$version" "$asset" "$manifest" <<'PY'
import hashlib
import json
import pathlib
import sys

evidence = pathlib.Path(sys.argv[1])
version = sys.argv[2]
asset = sys.argv[3]
manifest = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
if manifest["release"]["version"] != version:
    raise SystemExit("qualification manifest version does not match the release")
if manifest.get("previous_version") is not None:
    raise SystemExit("the first native release must not claim a previous native release")
required_diagnostics = {
    "platform.supported",
    "installation.integrity",
    "versions.compatible",
    "configuration.readable",
    "secrets.permissions",
    "service.configuration",
    "server.readiness",
    "database.configuration",
    "connector_registry.configuration",
    "mcp.clients",
    "lifecycle.update",
    "lifecycle.rollback",
}
for name in ["doctor.json", "doctor-service.json"]:
    report = json.loads((evidence / name).read_text(encoding="utf-8"))
    if report.get("schema") != "org.getaip.cli.doctor.v1":
        raise SystemExit(f"{name} has an unexpected schema")
    checks = {item["id"]: item for item in report["checks"]}
    if set(checks) != required_diagnostics:
        raise SystemExit(f"{name} diagnostic ids differ from the reviewed contract")
    failures = [identifier for identifier, item in checks.items() if item["status"] == "fail"]
    if failures:
        raise SystemExit(f"{name} contains failed diagnostics: {failures}")
    if checks["service.configuration"]["status"] != "pass":
        raise SystemExit(f"{name} did not verify service configuration")
status = json.loads((evidence / "status.json").read_text(encoding="utf-8"))
if (
    status.get("schema") != "org.getaip.cli.status.v1"
    or status.get("installation_status") != "verified"
    or status.get("active_version") != version
    or status.get("server_version") != version
):
    raise SystemExit("top-level status does not identify the verified native release")
documents = {}
for path in sorted(evidence.iterdir()):
    if not path.is_file() or path.name == "qualification.json":
        continue
    payload = path.read_bytes()
    documents[path.name] = {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
summary = {
    "schema": "org.getaip.qualification.native-install.v1",
    "version": version,
    "asset": asset,
    "clean_install": "pass",
    "repeated_setup": "pass",
    "diagnostics": "pass",
    "foreground_server": "pass",
    "isolated_service_lifecycle": "pass",
    "service_environment_file": "pass",
    "installer_security": "pass",
    "upgrade_rollback": "pass",
    "upgrade_rollback_evidence": "native_installer_contract_tests",
    "previous_native_release": None,
    "uninstall": "pass",
    "documents": documents,
}
(evidence / "qualification.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

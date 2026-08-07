#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

: "${AIP_HERMES_ENDPOINTS:=hermes-1=http://127.0.0.1:18642,hermes-2=http://127.0.0.1:18643}"
: "${AIP_HERMES_API_KEY:=hermes-aip-smoke-key-0000000000000000}"
: "${AIP_SUPPORT_SANDBOX_DATABASE_URL:=postgres://aip_support:aip_support_sandbox_password@127.0.0.1:15432/aip_support_sandbox}"

export AIP_HERMES_ENDPOINTS
export AIP_HERMES_API_KEY
export AIP_SUPPORT_SANDBOX_DATABASE_URL

exec cargo run -q -p getaip-server -- \
  --mcp-stdio \
  --service-id agent:getaip:server:codex-mcp \
  --trust-domain local.codex \
  --storage-dir .getaip-mcp-state

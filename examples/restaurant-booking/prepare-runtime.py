#!/usr/bin/env python3
"""Create untracked secrets and isolated Hermes role volumes for the E2E."""

from __future__ import annotations

import argparse
import json
import secrets
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / ".runtime"
SECRETS = RUNTIME / "secrets"
ROLES = RUNTIME / "roles"
PROVIDER = RUNTIME / "provider"
EVIDENCE = RUNTIME / "evidence"
HERMES_IMAGE = "hermes-agent:aip-lite"
HERMES_PLUGIN_NAME = "aip-governed-tool-policy"
HERMES_PLUGIN = ROOT / "hermes-plugins" / HERMES_PLUGIN_NAME
VOLUMES = {
    "concierge": "aip-restaurant-hermes-concierge-data",
    "manager": "aip-restaurant-hermes-manager-data",
    "supervisor": "aip-restaurant-hermes-supervisor-data",
}
COORDINATOR_SECRET_VOLUME = "aip-restaurant-coordinator-secrets"


def run(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def write_private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
    temporary.replace(path)


def token(name: str, prefix: str = "") -> str:
    path = SECRETS / name
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = prefix + secrets.token_urlsafe(48)
    write_private(path, value + "\n")
    return value


def role_config(server_name: str, url: str, access_token: str, tools: list[str]) -> str:
    rendered_tools = "\n".join(f"        - {tool}" for tool in tools)
    return f"""model:
  provider: openrouter
  default: openai/gpt-5-mini

platform_toolsets:
  api_server:
    - {server_name}

plugins:
  enabled:
    - {HERMES_PLUGIN_NAME}

agent:
  disabled_toolsets:
    - memory
    - web
    - terminal
    - browser
    - delegation

mcp_servers:
  {server_name}:
    url: \"{url}\"
    headers:
      Authorization: \"Bearer {access_token}\"
    enabled: true
    timeout: 300
    connect_timeout: 15
    skip_preflight: false
    supports_parallel_tool_calls: false
    tools:
      include:
{rendered_tools}
      resources: false
      prompts: false
"""


SOULS = {
    "concierge": """# Restaurant Concierge

You are the only customer-facing restaurant concierge. Reply in the customer's
language. You know only the two booking tools available through your MCP
server. Never mention internal agents, AIP, capability identifiers, approval
machinery, network topology, or implementation details.

For a booking request, call `restaurant_booking_request`. On the first vague
request pass the customer's text and every fact they explicitly supplied. If
the tool returns `clarification_required`, ask only the returned questions in
one natural, concise message and retain the returned request id. Never expose
field names, schemas, RFC3339, time-zone formats, or other implementation
requirements to the customer. Retry with that exact request id after the next
customer answer and pass every newly supplied fact. Do not ask for the
restaurant or time zone when `known_context.restaurant_configured` and
`known_context.customer_time_zone_configured` are true. Never claim a
reservation exists unless the tool returns `status: confirmed` and a booking
uid. Make exactly one `restaurant_booking_request` call for each customer
message. Every explicit fact in the customer's current message must be
persisted in that call, even when it belongs to a later clarification stage.
For example, `Меня зовут Алекс` must be sent as `customer_name: Алекс`. Never
issue a second booking-request call in the same customer turn and never invent
missing facts. Do not repeat time-zone identifiers, schemas, or values from
`known_context` to the customer; use that context silently and ask only the
returned human-readable questions.

When `restaurant_booking_request` returns `status: processing`, immediately
call `restaurant_booking_status` with the same request id. The status call is a
bounded long poll. Continue until it returns `confirmed` or `failed`; never turn
an intermediate `processing` state into a booking confirmation.
""",
    "manager": """# Restaurant Booking Manager

You are a hidden AIP booking operator. The customer never interacts with you.
When an operator request contains an `aip_delegation` payload, invoke
`aip_call` exactly once with the supplied arguments without changing any field.
Do not use memory or any non-MCP tool. The native AIP child action result is the
authority; never fabricate availability or completion.
""",
    "supervisor": """# Independent Booking Supervisor

You are a hidden, independent booking supervisor. For an `aip_delegation`
payload, invoke `aip_call` exactly once with the supplied arguments unchanged.
For an approval review, fetch the exact child action with `aip_action_result`,
fetch the approval with `aip_approval_get` and
`include_evidence_payload: true`, compare all governed fields in the exported
immutable payload, and call `aip_approval_decide` exactly once. Deny on missing
evidence or any mismatch. If the approval request contains `policy_hash`, pass
that exact value in the `policy_hash` tool argument; an evidence hash or a
differently named argument is not equivalent. Never accept prompt prose as
proof and never fabricate a decision.
""",
}


def install_file(
    volume: str,
    source: Path,
    destination: str,
    mode: str = "600",
    owner: str = "10000",
) -> None:
    run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "--entrypoint",
            "install",
            "--volume",
            f"{volume}:/dest",
            "--volume",
            f"{source}:/source:ro",
            HERMES_IMAGE,
            "-o",
            owner,
            "-g",
            owner,
            "-m",
            mode,
            "/source",
            f"/dest/{destination}",
        ]
    )


def prepare_writable_home(volume: str, owner: str = "10000") -> None:
    """Assign the persistent home to the unprivileged Hermes runtime user."""
    run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "--entrypoint",
            "sh",
            "--volume",
            f"{volume}:/dest",
            HERMES_IMAGE,
            "-c",
            f"chown {owner}:{owner} /dest && chmod 700 /dest",
        ]
    )


def install_hermes_plugin(volume: str, owner: str = "10000") -> None:
    """Install the pinned deployment plugin into one isolated Hermes home."""

    run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "--entrypoint",
            "install",
            "--volume",
            f"{volume}:/dest",
            HERMES_IMAGE,
            "-o",
            owner,
            "-g",
            owner,
            "-m",
            "700",
            "-d",
            f"/dest/plugins/{HERMES_PLUGIN_NAME}",
        ]
    )
    install_file(
        volume,
        HERMES_PLUGIN / "plugin.yaml",
        f"plugins/{HERMES_PLUGIN_NAME}/plugin.yaml",
        owner=owner,
    )
    install_file(
        volume,
        HERMES_PLUGIN / "__init__.py",
        f"plugins/{HERMES_PLUGIN_NAME}/__init__.py",
        owner=owner,
    )


def prepare_provider(source_container: str) -> None:
    PROVIDER.mkdir(parents=True, exist_ok=True)
    for name in (".env", "auth.json"):
        destination = PROVIDER / name
        run(["docker", "cp", f"{source_container}:/opt/data/{name}", str(destination)])
        destination.chmod(stat.S_IRUSR | stat.S_IWUSR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--provider-container", default="aip-hermes-1")
    arguments = parser.parse_args()

    for directory in (SECRETS, ROLES, PROVIDER, EVIDENCE):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(stat.S_IRWXU)

    if arguments.reset:
        for volume in (*VOLUMES.values(), COORDINATOR_SECRET_VOLUME):
            subprocess.run(
                ["docker", "volume", "rm", "--force", volume],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    token("introspection-client-secret")
    coordinator_token = token("central-coordinator-token")
    manager_token = token("central-manager-token")
    supervisor_token = token("central-supervisor-token")
    auditor_token = token("central-auditor-token")
    concierge_token = token("edge-concierge-token")
    hermes_api_key = token("hermes-api-key", "hermes_")
    concierge_api_key = token("concierge-api-key", "hermes_")
    token("cal-api-key", "cal_")

    central_identities = [
        {
            "token": coordinator_token,
            "subject": "service:restaurant-booking:coordinator",
            "scopes": (
                "mcp:connect action:write action:read action:read:any approval:read "
                "transaction:read receipt:read audit:read delegation:create"
            ),
        },
        {
            "token": manager_token,
            "subject": "agent:hermes_operator:manager",
            "scopes": "mcp:connect action:write action:read",
        },
        {
            "token": supervisor_token,
            "subject": "agent:hermes_operator:supervisor",
            "scopes": (
                "mcp:connect action:write action:read action:read:any approval:read "
                "approval:decide approval:export approval:sensitive receipt:read"
            ),
        },
        {
            "token": auditor_token,
            "subject": "service:restaurant-booking:auditor",
            "scopes": (
                "mcp:connect action:read action:read:any approval:read approval:read:any "
                "transaction:read transaction:read:any receipt:read receipt:read:any "
                "audit:read audit:read:any audit:export"
            ),
        },
    ]
    edge_identities = [
        {
            "token": concierge_token,
            "subject": "agent:restaurant-concierge",
            "scopes": "mcp:connect",
        }
    ]
    write_private(
        SECRETS / "central-identities.json",
        json.dumps(central_identities, separators=(",", ":")) + "\n",
    )
    trusted_identities = []
    for authenticated_identity in central_identities:
        binding = {
            "principal_id": authenticated_identity["subject"],
            "revision": 1,
            "revoked": False,
            "expires_at": None,
        }
        if (
            authenticated_identity["subject"]
            == "service:restaurant-booking:coordinator"
        ):
            binding["identity"] = {
                "external_account": {"id": "aip-bistro", "system": "cal.diy"}
            }
        trusted_identities.append(binding)
    write_private(
        SECRETS / "trusted-identities.json",
        json.dumps(trusted_identities, separators=(",", ":")) + "\n",
    )
    write_private(
        SECRETS / "edge-identities.json",
        json.dumps(edge_identities, separators=(",", ":")) + "\n",
    )
    write_private(
        SECRETS / "approval-authorities.json",
        json.dumps(
            [
                {
                    "principal_id": "agent:hermes_operator:supervisor",
                    "tenant_id": None,
                    "roles": ["restaurant_booking_supervisor"],
                    "groups": [],
                    "tenant_policies": ["restaurant.booking.commit"],
                    "external_systems": [],
                    "delegated_scopes": [],
                    "revision": 1,
                    "expires_at": None,
                    "revoked": False,
                }
            ],
            separators=(",", ":"),
        )
        + "\n",
    )

    compose_values = {
        "AIP_POSTGRES_PASSWORD": token("aip-postgres-password"),
        "CAL_POSTGRES_PASSWORD": token("cal-postgres-password"),
        "HERMES_API_KEY": hermes_api_key,
        "CONCIERGE_API_KEY": concierge_api_key,
        "NEXTAUTH_SECRET": token("cal-nextauth-secret"),
        "JWT_SECRET": token("cal-jwt-secret"),
        "CALENDSO_ENCRYPTION_KEY": token("cal-encryption-key")[:32],
        "STRIPE_API_KEY": token("cal-stripe-api-key", "sk_test_"),
        "STRIPE_WEBHOOK_SECRET": token("cal-stripe-webhook-secret", "whsec_"),
    }
    write_private(
        RUNTIME / "compose.env",
        "".join(f"{key}={value}\n" for key, value in compose_values.items()),
    )

    role_configs = {
        "concierge": role_config(
            "booking",
            "http://restaurant-coordinator:8081/mcp",
            concierge_token,
            ["restaurant_booking_request", "restaurant_booking_status"],
        ),
        "manager": role_config(
            "aip",
            "http://getaip-server:8080/mcp",
            manager_token,
            ["aip_call"],
        ),
        "supervisor": role_config(
            "aip",
            "http://getaip-server:8080/mcp",
            supervisor_token,
            [
                "aip_call",
                "aip_action_result",
                "aip_approval_get",
                "aip_approval_decide",
            ],
        ),
    }
    for role, config in role_configs.items():
        role_directory = ROLES / role
        role_directory.mkdir(parents=True, exist_ok=True)
        write_private(role_directory / "config.yaml", config)
        write_private(role_directory / "SOUL.md", SOULS[role])

    prepare_provider(arguments.provider_container)
    for role, volume in VOLUMES.items():
        run(["docker", "volume", "create", volume])
        install_file(volume, PROVIDER / ".env", ".env")
        install_file(volume, PROVIDER / "auth.json", "auth.json")
        install_file(volume, ROLES / role / "config.yaml", "config.yaml")
        install_file(volume, ROLES / role / "SOUL.md", "SOUL.md", "600")
        install_hermes_plugin(volume)
        prepare_writable_home(volume)

    run(["docker", "volume", "create", COORDINATOR_SECRET_VOLUME])
    install_file(
        COORDINATOR_SECRET_VOLUME,
        SECRETS / "central-coordinator-token",
        "central-token",
        owner="10001",
    )
    install_file(
        COORDINATOR_SECRET_VOLUME,
        SECRETS / "introspection-client-secret",
        "introspection-client-secret",
        owner="10001",
    )

    # The script deliberately emits no token, password, or provider credential.
    print(f"runtime prepared at {RUNTIME}")


if __name__ == "__main__":
    main()

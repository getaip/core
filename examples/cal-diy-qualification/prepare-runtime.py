#!/usr/bin/env python3
"""Create owner-only secrets for the isolated Cal.diy qualification stack."""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / ".runtime"
SECRETS = RUNTIME / "secrets"
EVIDENCE = RUNTIME / "evidence"
TENANT_ID = "tenant-cal-qualified"
CAL_ACCOUNT_ID = "aip-bistro"
REQUESTER = "service:cal-qualified-client"
APPROVER = "human:cal-qualified-approver"
CREDENTIAL_ID = "credential:cal-qualified"


def private_write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def token(path: str, prefix: str = "") -> str:
    target = SECRETS / path
    if target.exists():
        value = target.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = prefix + secrets.token_urlsafe(36)
    private_write(target, value + "\n")
    return value


def trusted_identity(principal_id: str, role: str) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "principal_id": principal_id,
        "tenant": {
            "tenant": {"id": TENANT_ID, "system": "aip"},
            "membership_id": f"membership:{TENANT_ID}:{role}",
            "roles": [role],
            "groups": [],
            "verified_at": now,
            "expires_at": None,
        },
        "credential": {
            "id": CREDENTIAL_ID,
            "issuer": "cal_diy_deployment",
            "scopes": ["*"],
            "tenant_id": TENANT_ID,
            "expires_at": None,
        },
        "identity": {
            "tenant": {"id": TENANT_ID, "system": "aip"},
            "external_account": {"id": CAL_ACCOUNT_ID, "system": "cal_diy"},
            "external_user": None,
            "human_actor": None,
            "service_account": None,
            "acted_on_behalf_of": None,
            "credential_ref": None,
            "oauth": None,
        },
        "revision": 1,
        "revoked": False,
        "expires_at": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    arguments = parser.parse_args()
    if arguments.reset and RUNTIME.exists():
        shutil.rmtree(RUNTIME)
    for directory in (RUNTIME, SECRETS, EVIDENCE):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(stat.S_IRWXU)

    requester_token = token("requester-token")
    approver_token = token("approver-token")
    token("native-token")
    token("introspection-client-secret")
    token("cal-api-key", "cal_")
    token("cal-webhook-secret", "whsec_")

    identities = [
        {
            "token": requester_token,
            "subject": REQUESTER,
            "scopes": (
                "mcp:connect action:write action:read action:read:any approval:read "
                "transaction:read transaction:read:any receipt:read receipt:read:any "
                "audit:read audit:read:any audit:export events:read:any"
            ),
        },
        {
            "token": approver_token,
            "subject": APPROVER,
            "scopes": (
                "mcp:connect action:read action:read:any approval:read approval:read:any "
                "approval:decide approval:export approval:sensitive transaction:read "
                "transaction:read:any receipt:read receipt:read:any audit:read audit:read:any"
            ),
        },
    ]
    private_write(
        SECRETS / "mcp-identities.json",
        json.dumps(identities, separators=(",", ":")) + "\n",
    )
    private_write(
        SECRETS / "trusted-identities.json",
        json.dumps(
            [
                trusted_identity(REQUESTER, "scheduler"),
                trusted_identity(APPROVER, "scheduling_approver"),
            ],
            separators=(",", ":"),
        )
        + "\n",
    )
    private_write(
        SECRETS / "approval-authorities.json",
        json.dumps(
            [
                {
                    "principal_id": APPROVER,
                    "tenant_id": TENANT_ID,
                    "roles": ["scheduling_approver"],
                    "groups": [],
                    "tenant_policies": ["cal-diy-qualified"],
                    "external_systems": ["cal_diy"],
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
    values = {
        "AIP_POSTGRES_PASSWORD": token("aip-postgres-password"),
        "CAL_POSTGRES_PASSWORD": token("cal-postgres-password"),
        "NEXTAUTH_SECRET": token("cal-nextauth-secret"),
        "JWT_SECRET": token("cal-jwt-secret"),
        "CALENDSO_ENCRYPTION_KEY": token("cal-encryption-key")[:32],
        "STRIPE_API_KEY": token("cal-stripe-api-key", "sk_test_"),
        "STRIPE_WEBHOOK_SECRET": token("cal-stripe-webhook-secret", "whsec_"),
    }
    private_write(
        RUNTIME / "compose.env",
        "".join(f"{key}={value}\n" for key, value in values.items()),
    )
    print(f"Prepared isolated runtime at {RUNTIME}")


if __name__ == "__main__":
    main()

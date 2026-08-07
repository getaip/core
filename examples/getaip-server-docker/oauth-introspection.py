"""Bounded RFC 7662 identity-provider fixture for the local Docker E2E.

This process is not an AIP component. It exists only to exercise getaip-server's
production token-introspection verifier without enabling static bearer or
unauthenticated development modes. The compose profile places it in getaip-server's
network namespace and it listens only on loopback.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import stat
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

MAX_REQUEST_BYTES = 8 * 1024
LISTEN_ADDRESS = ("127.0.0.1", 19090)


def required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\r" in value or "\n" in value:
        raise RuntimeError(f"{name} is missing or invalid")
    return value


CLIENT_ID = required_environment("INTROSPECTION_CLIENT_ID")
CLIENT_SECRET = (
    Path(required_environment("INTROSPECTION_CLIENT_SECRET_FILE"))
    .read_text(encoding="utf-8")
    .strip()
)
ISSUER = required_environment("INTROSPECTION_ISSUER")
AUDIENCE = required_environment("INTROSPECTION_AUDIENCE")

if not CLIENT_SECRET:
    raise RuntimeError("introspection client secret is empty")

EXPECTED_BASIC = "Basic " + base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode("utf-8")
).decode("ascii")


def load_identities() -> tuple[tuple[str, str, str], ...]:
    identities_file = os.environ.get("INTROSPECTION_IDENTITIES_FILE")
    if not identities_file:
        return (
            (
                required_environment("INTROSPECTION_ACCESS_TOKEN"),
                required_environment("INTROSPECTION_SUBJECT"),
                required_environment("INTROSPECTION_SCOPES"),
            ),
        )
    path = Path(identities_file)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
        raise RuntimeError(
            "introspection identities must be a regular file below 1 MiB"
        )
    if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError(
            "introspection identities file must not grant group/world access"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload or len(payload) > 1024:
        raise RuntimeError("introspection identities must be a non-empty bounded array")
    records: list[tuple[str, str, str]] = []
    seen_tokens: set[str] = set()
    seen_subjects: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise RuntimeError("introspection identity entries must be objects")
        token = item.get("token")
        subject = item.get("subject")
        scopes = item.get("scopes")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (token, subject, scopes)
        ):
            raise RuntimeError(
                "introspection identity fields must be non-empty strings"
            )
        if any("\r" in value or "\n" in value for value in (token, subject, scopes)):
            raise RuntimeError(
                "introspection identity fields contain forbidden newlines"
            )
        if token in seen_tokens or subject in seen_subjects:
            raise RuntimeError("introspection tokens and subjects must be unique")
        seen_tokens.add(token)
        seen_subjects.add(subject)
        records.append((token, subject, scopes))
    return tuple(records)


IDENTITIES = load_identities()


class IntrospectionHandler(BaseHTTPRequestHandler):
    server_version = "AipRfc7662Fixture/1.0"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/health":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._json(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/introspect":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not hmac.compare_digest(
            self.headers.get("Authorization", ""), EXPECTED_BASIC
        ):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_client"})
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
        if content_type != "application/x-www-form-urlencoded":
            self._json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "unsupported_media_type"},
            )
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        try:
            form = parse_qs(
                self.rfile.read(content_length).decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
            )
        except (UnicodeDecodeError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        presented = form.get("token", [""])[0]
        identity: tuple[str, str] | None = None
        for token, subject, scopes in IDENTITIES:
            if hmac.compare_digest(presented, token):
                identity = (subject, scopes)
        if identity is None:
            self._json(HTTPStatus.OK, {"active": False})
            return
        subject, scopes = identity
        self._json(
            HTTPStatus.OK,
            {
                "active": True,
                "sub": subject,
                "iss": ISSUER,
                "aud": [AUDIENCE],
                "scope": scopes,
                "exp": int(time.time()) + 3600,
            },
        )

    def log_message(self, format_string: str, *args: object) -> None:
        # Do not emit headers, form bodies, tokens, or client credentials.
        print(f"introspection {self.command} {self.path} {format_string % args}")

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(LISTEN_ADDRESS, IntrospectionHandler)
    server.serve_forever()

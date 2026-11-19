"""Sign an operator-reviewed locale approval provided on stdin."""

import json
import re
import secrets
import sys
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from bootstrap import origin
from tool_registry import LOCALE_FIXTURE_ID, LOCALES


def sign(request, key, *, resource):
    if (
        not isinstance(request, dict) or set(request) != {"subject", "realm", "tool", "action", "target", "locale", "resource"}
        or not isinstance(request["subject"], str) or not re.fullmatch(r"oidc:[0-9a-f]{64}", request["subject"])
        or request["realm"] != "lab" or request["tool"] != "set_user_locale" or request["action"] != "write"
        or request["target"] != LOCALE_FIXTURE_ID or request["locale"] not in LOCALES or request["resource"] != resource
    ):
        raise ValueError("The request must match this installation's exact synthetic locale operation")
    now = int(time.time())
    claims = {field: request[field] for field in ("realm", "tool", "action", "target", "locale")}
    return jwt.encode({
        **claims, "iss": "keycloak-mcp-approval", "aud": resource, "sub": request["subject"],
        "iat": now, "exp": now + 90, "jti": secrets.token_urlsafe(24),
    }, key, algorithm="EdDSA")


if __name__ == "__main__":
    try:
        data = sys.stdin.read(4097)
        if len(data) > 4096:
            raise ValueError("Approval request exceeds 4096 characters")
        request = json.loads(data)
        key = load_pem_private_key(Path("/operator/signer.key").read_bytes(), password=None)
        print(sign(request, key, resource=origin() + "/mcp"))
    except (OSError, ValueError, TypeError) as exc:
        sys.exit("Could not sign the requested approval: " + type(exc).__name__)

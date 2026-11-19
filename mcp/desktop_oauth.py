"""OAuth request and callback validation for the demo's pre-registered client."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Sequence
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

DESKTOP_CLIENT_ID = "https://chatgpt.com/oauth/codex/client.json"
DESKTOP_REDIRECT = "http://127.0.0.1:49446/callback"


@dataclass(frozen=True)
class DesktopAuthorization:
    issuer: str
    resource: str
    state: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    verifier: str = field(default_factory=lambda: secrets.token_urlsafe(48), repr=False)

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/auth"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    def validate_discovery(self, client: httpx.Client) -> None:
        response = client.get(f"{self.issuer}/.well-known/openid-configuration")
        if response.status_code != 200:
            raise ValueError("Keycloak discovery is unavailable")
        metadata = response.json()
        if (
            metadata.get("issuer") != self.issuer
            or metadata.get("authorization_endpoint") != self.authorization_endpoint
            or metadata.get("token_endpoint") != self.token_endpoint
            or "S256" not in metadata.get("code_challenge_methods_supported", [])
            or metadata.get("authorization_response_iss_parameter_supported") is not True
        ):
            raise ValueError("Keycloak discovery does not match the expected issuer and OAuth endpoints")

    def start_url(self, selected_scopes: Sequence[str], *, prompt: str | None = None) -> str:
        digest = hashlib.sha256(self.verifier.encode("ascii")).digest()
        request = {
            "client_id": DESKTOP_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": DESKTOP_REDIRECT,
            "resource": self.resource,
            "scope": " ".join(["openid", *selected_scopes]),
            "state": self.state,
            "code_challenge_method": "S256",
            "code_challenge": base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
        }
        if prompt:
            request["prompt"] = prompt
        return self.authorization_endpoint + "?" + urlencode(request)

    def code_from_callback(self, callback: str) -> str:
        url = urlsplit(callback)
        if url._replace(query="", fragment="").geturl() != DESKTOP_REDIRECT or url.fragment:
            raise ValueError("The OAuth callback URL did not match the registered redirect")
        query = parse_qs(url.query, keep_blank_values=True)
        if query.get("state") != [self.state] or query.get("iss") != [self.issuer]:
            raise ValueError("The OAuth callback did not match the request state and issuer")
        code = query.get("code", [])
        if "error" in query or len(code) != 1 or not code[0]:
            raise ValueError("The provider did not return an authorization code")
        return code[0]

    def token_request(self, code: str) -> dict[str, str]:
        return {
            "grant_type": "authorization_code",
            "client_id": DESKTOP_CLIENT_ID,
            "redirect_uri": DESKTOP_REDIRECT,
            "resource": self.resource,
            "code": code,
            "code_verifier": self.verifier,
        }

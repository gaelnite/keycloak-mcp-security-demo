"""Per-call SPIFFE authentication, constrained exchange and Admin projection."""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import jwt

from auth import JwksCache, KeycloakAuthConfig, KeycloakTokenVerifier, TokenClaims, TokenError
from tool_registry import CLIENTS_READ, LOCALE_FIXTURE_ID, LOCALES, USER_LOCALE, USERS_READ, Capability, ToolSpec

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ADMIN_SCOPE = "kc-admin-api"
MAX_ADMIN_TTL = 60
MAX_ROWS = 50
MAX_RESPONSE_BYTES = 1024 * 1024


class DelegationError(RuntimeError):
    pass


def admin_audience_for(issuer: str, realm: str) -> str:
    suffix = f"/realms/{realm}"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", realm) or not issuer.endswith(suffix):
        raise DelegationError("Delegation requires the configured Keycloak realm issuer URL")
    return issuer.removesuffix(suffix) + f"/admin/realms/{realm}"


def spiffe_subject(trust_domain: str, capability: Capability) -> str:
    return f"spiffe://{trust_domain}/workload/mcp-exchange/{capability.scope}"


@dataclass(frozen=True)
class DelegationConfig:
    auth: KeycloakAuthConfig
    private_origin: str
    ca_file: str
    trust_domain: str
    socket: str
    executable: str

    @classmethod
    def from_env(cls, auth: KeycloakAuthConfig, env: Mapping[str, str]) -> DelegationConfig | None:
        private_origin = env.get("KC_MCP_DELEGATED_ADMIN_URL", "").strip()
        if not private_origin:
            return None
        if not auth.interactive_client_ids or not auth.protected_resource:
            raise DelegationError("Delegation requires configured interactive clients and a canonical MCP resource")
        try:
            endpoint = urlsplit(private_origin)
            port = endpoint.port
        except ValueError as exc:
            raise DelegationError("The private Admin port is invalid") from exc
        if (
            not re.fullmatch(r"https://localhost:[1-9][0-9]*", private_origin)
            or port is None
            or endpoint.netloc == urlsplit(auth.issuer).netloc
        ):
            raise DelegationError("KC_MCP_DELEGATED_ADMIN_URL must use a distinct HTTPS localhost port")
        admin_audience_for(auth.issuer, auth.realm)
        if auth.jwks_url != auth.issuer + "/protocol/openid-connect/certs":
            raise DelegationError("Delegation requires the exact realm JWKS endpoint")
        domain = env.get("KC_MCP_SPIFFE_TRUST_DOMAIN", "").strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", domain):
            raise DelegationError("KC_MCP_SPIFFE_TRUST_DOMAIN is required for delegation")
        ca_file = env.get("KC_MCP_DELEGATED_CA_FILE", "").strip()
        socket = env.get("KC_MCP_SPIFFE_WORKLOAD_SOCKET", "").strip()
        executable = env.get("KC_MCP_SPIFFE_EXECUTABLE", "").strip()
        if not all(Path(value).is_absolute() for value in (ca_file, socket, executable)):
            raise DelegationError("Delegation requires explicit CA, Workload API socket and executable paths")
        if not Path(ca_file).is_file() or not Path(executable).is_file():
            raise DelegationError("The delegation CA or Workload API executable is unavailable")
        return cls(auth, private_origin, ca_file, domain, socket, executable)

    @property
    def admin_audience(self) -> str:
        return admin_audience_for(self.auth.issuer, self.auth.realm)

    @property
    def admin_path(self) -> str:
        return urlsplit(self.admin_audience).path

    @property
    def token_endpoint(self) -> str:
        return self.auth.issuer + "/protocol/openid-connect/token"


def fetch_svid(executable: str, socket: str, spiffe_id: str, audience: str) -> str:
    try:
        # S603: argv-list exec (no shell) of a path that DelegationConfig.from_env
        # already validated as absolute and a regular file; every other argument is
        # a constant or a validated trust-domain/capability derived string.
        response = subprocess.run(  # noqa: S603
            [executable, "api", "fetch", "jwt", "-socketPath", socket, "-audience", audience,
             "-spiffeID", spiffe_id, "-output", "json"],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=6,
        )
        if len(response.stdout) > 32768:
            raise ValueError
        records = [record for block in json.loads(response.stdout) for record in block.get("svids", [])]
        if len(records) != 1 or records[0]["spiffe_id"] != spiffe_id:
            raise ValueError
        token = records[0]["svid"]
        claims = jwt.decode(token, options={"verify_signature": False})
        now = time.time()
        if (
            claims["sub"] != spiffe_id or claims["aud"] not in (audience, [audience])
            or not now < claims["exp"] <= now + MAX_ADMIN_TTL
        ):
            raise ValueError
        return token
    except (OSError, subprocess.SubprocessError, jwt.PyJWTError, AttributeError, KeyError, ValueError, TypeError) as exc:
        raise DelegationError("The Workload API did not return the expected short-lived JWT-SVID") from exc


def exchange_form(client_id: str, scope: str, audience: str, subject_token: str, assertion: str) -> dict[str, str]:
    return {
        "grant_type": EXCHANGE_GRANT, "client_id": client_id, "audience": audience, "scope": scope,
        "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE,
        "requested_token_type": ACCESS_TOKEN_TYPE, "client_assertion_type": ASSERTION_TYPE, "client_assertion": assertion,
    }


@dataclass(frozen=True)
class AdminOperation:
    method: str
    path: str
    query: Mapping[str, Any] | None = None
    body: Mapping[str, Any] | None = None


def _uuid(value: str) -> str:
    try:
        if str(UUID(value)) == value:
            return value
    except (ValueError, AttributeError):
        pass
    raise DelegationError("A canonical user UUID is required")


def _query(value: str) -> str:
    if len(value) > 120 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise DelegationError("The query value is invalid")
    return value


def operation_for(spec: ToolSpec, *, user_id: str = "", client_id: str = "", search: str = "", locale: str = "") -> AdminOperation:
    if spec.name == "list_users" and spec.capability == USERS_READ:
        return AdminOperation("GET", "/users", {"max": MAX_ROWS, "briefRepresentation": "true", "search": _query(search)})
    if spec.name == "get_user" and spec.capability == USERS_READ:
        return AdminOperation("GET", f"/users/{_uuid(user_id)}")
    if spec.name == "list_clients" and spec.capability == CLIENTS_READ:
        return AdminOperation("GET", "/clients", {"max": MAX_ROWS, "search": _query(search)})
    if spec.name == "get_client" and spec.capability == CLIENTS_READ:
        if not client_id:
            raise DelegationError("A client identifier is required")
        return AdminOperation("GET", "/clients", {"max": 2, "clientId": _query(client_id)})
    if spec.name == "set_user_locale" and spec.capability == USER_LOCALE:
        if user_id != LOCALE_FIXTURE_ID or locale not in LOCALES:
            raise DelegationError("Only the demo locale fixture and its supported locales can be updated")
        return AdminOperation("PUT", f"/users/{LOCALE_FIXTURE_ID}", body={"attributes": {"locale": [locale]}})
    raise DelegationError("The tool has no delegated Admin operation")


def _collection_query(query: str, capability: Capability) -> bool:
    try:
        fields = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=3)
        if any(len(values) != 1 for values in fields.values()):
            return False
        params = {key: values[0] for key, values in fields.items()}
        maximum = params.pop("max", "")
        if not maximum.isascii() or not maximum.isdecimal() or not 1 <= int(maximum) <= MAX_ROWS:
            return False
        if capability == USERS_READ and params.pop("briefRepresentation", "") != "true":
            return False
        permitted = {"search"} if capability == USERS_READ else {"search", "clientId"}
        return set(params) <= permitted and all(_query(value) == value for value in params.values())
    except (ValueError, DelegationError):
        return False


def gateway_capability(admin_path: str, method: str, path: str, query: str = "") -> Capability | None:
    if method == "GET":
        if path == admin_path + "/clients":
            return CLIENTS_READ if _collection_query(query, CLIENTS_READ) else None
        if path == admin_path + "/users":
            return USERS_READ if _collection_query(query, USERS_READ) else None
        prefix = admin_path + "/users/"
        if path.startswith(prefix):
            try:
                _uuid(path.removeprefix(prefix))
            except DelegationError:
                return None
            return USERS_READ if not query else None
    if method == "PUT" and path == admin_path + f"/users/{LOCALE_FIXTURE_ID}" and not query:
        return USER_LOCALE
    return None


def _project(document: Any, capability: Capability) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("id"), str):
        raise DelegationError("Keycloak returned an unexpected Admin record")
    label_fields = ("username",) if capability == USERS_READ else ("clientId", "protocol")
    result = {field: document[field] for field in ("id", *label_fields) if isinstance(document.get(field), str)}
    if isinstance(document.get("enabled"), bool):
        result["enabled"] = document["enabled"]
    if capability == USERS_READ and document["id"] == LOCALE_FIXTURE_ID:
        attrs = document.get("attributes")
        locale = attrs.get("locale") if isinstance(attrs, dict) else None
        if isinstance(locale, list) and len(locale) == 1 and locale[0] in LOCALES:
            result["locale"] = locale[0]
    return result


class DelegatedAdmin:
    def __init__(self, config: DelegationConfig, *, transport=None, jwks=None) -> None:
        self.config = config
        try:
            trust = ssl.create_default_context(cafile=config.ca_file)
        except OSError as exc:
            raise DelegationError("Could not load the pinned delegation CA") from exc
        self._http = httpx.AsyncClient(verify=trust, trust_env=False, follow_redirects=False, timeout=8, transport=transport)
        key_source = jwks or JwksCache(config.auth.jwks_url, transport=httpx.AsyncHTTPTransport(verify=trust, trust_env=False))
        self.verifier = KeycloakTokenVerifier(config.auth, jwks=key_source)

    async def _json(self, method: str, url: str, *, status: int, **request) -> dict | list | None:
        try:
            async with self._http.stream(method, url, **request) as response:
                if response.status_code != status:
                    raise DelegationError(f"Keycloak refused or could not complete the delegated operation (HTTP {response.status_code})")
                if status == 204:
                    return None
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise DelegationError("The delegated response exceeded the configured size limit")
                return json.loads(body)
        except (httpx.HTTPError, ValueError) as exc:
            raise DelegationError("Keycloak did not return a usable delegated response") from exc

    async def verify_token(self, token: str, capability: Capability, *, caller: TokenClaims | None = None) -> None:
        config = self.config
        try:
            data = await self.verifier.decode_token(token, audience=config.admin_audience, leeway=0)
        except TokenError as exc:
            raise DelegationError("Keycloak issued an invalid delegated token") from exc
        scopes = data.get("scope")
        now = time.time()
        if (
            data["aud"] not in (config.admin_audience, [config.admin_audience])
            or data.get("typ") != "Bearer" or data.get("azp") != capability.requester_audience(config.auth.audience)
            or not data["sub"] or not isinstance(scopes, str) or set(scopes.split()) != {ADMIN_SCOPE, capability.scope}
            or not isinstance(data["exp"], int) or not isinstance(data["iat"], int)
            or not 0 < data["exp"] - data["iat"] <= MAX_ADMIN_TTL
            or (caller is not None and (data["sub"] != caller.subject or caller.expires_at <= now))
        ):
            raise DelegationError("The delegated token does not match the expected subject, audience, capability or lifetime")
        realm_roles = data.get("realm_access") or {}
        resources = data.get("resource_access") or {}
        admin_roles = resources.get("realm-management", {}) if isinstance(resources, dict) else None
        if (
            not isinstance(realm_roles, dict) or any(realm_roles.values())
            or not isinstance(resources, dict) or set(resources).difference({"realm-management"})
            or not isinstance(admin_roles, dict) or not isinstance(admin_roles.get("roles", []), list)
            or any(role != capability.admin_role for role in admin_roles.get("roles", []))
        ):
            raise DelegationError("The delegated token exposes roles outside its ceiling")

    async def exchange(self, capability: Capability, caller: TokenClaims, inbound: str) -> str:
        config = self.config
        if (
            not caller.interactive or caller.issuer != config.auth.issuer or caller.realm != config.auth.realm
            or caller.audience != config.auth.audience or caller.expires_at <= time.time()
            or capability.scope not in caller.scopes or capability.role not in caller.roles
        ):
            raise DelegationError("The current caller is ineligible for this delegation")
        assertion = await asyncio.to_thread(
            fetch_svid, config.executable, config.socket, spiffe_subject(config.trust_domain, capability), config.auth.issuer,
        )
        requester = capability.requester_audience(config.auth.audience)
        result = await self._json("POST", config.token_endpoint, status=200, data=exchange_form(
            requester, capability.scope, config.admin_audience, inbound, assertion,
        ))
        if not isinstance(result, dict) or result.get("issued_token_type") != ACCESS_TOKEN_TYPE or result.get("token_type") != "Bearer":
            raise DelegationError("Keycloak did not issue the expected access-token type")
        token = result.get("access_token")
        if not isinstance(token, str) or token == inbound or result.get("refresh_token") is not None:
            raise DelegationError("Keycloak did not issue a distinct, access-only delegated token")
        await self.verify_token(token, capability, caller=caller)
        return token

    async def dispatch(self, spec: ToolSpec, caller: TokenClaims, inbound: str, **arguments: Any) -> Any:
        capability = spec.capability
        operation = operation_for(spec, **arguments)
        token = await self.exchange(capability, caller, inbound)
        response = await self._json(
            operation.method, self.config.private_origin + self.config.admin_path + operation.path,
            status=204 if operation.method == "PUT" else 200, params=operation.query, json=operation.body,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if operation.method == "PUT":
            return {"updated": True, "user_id": LOCALE_FIXTURE_ID, "locale": arguments["locale"]}
        if spec.name == "get_user":
            return _project(response, capability)
        if not isinstance(response, list):
            raise DelegationError("Keycloak returned an unexpected Admin collection")
        results = [_project(entry, capability) for entry in response[:MAX_ROWS]]
        if spec.name == "get_client":
            exact = [entry for entry in results if entry.get("clientId") == arguments["client_id"]]
            if len(exact) != 1:
                raise DelegationError("No unique client matched the requested identifier")
            return exact[0]
        return results

    async def aclose(self) -> None:
        await self._http.aclose()
        await self.verifier.aclose()

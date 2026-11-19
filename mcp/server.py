#!/usr/bin/env python3
"""Extension-aware Keycloak MCP server with Cedar authorization.

Run:
    python3 mcp/server.py --transport stdio
    python3 mcp/server.py --transport http --port 8766
    python3 mcp/server.py --check

Authentication: Keycloak access token (iss/aud/exp, JWKS cache, azp/CIMD allowlist,
scopes). Authorization: one PEP decision per tool call against a local Cedar PDP
(cedar-wasm). Writes require KC_MCP_ENABLE_WRITES=1 and a signed approval. Delegated
locale writes carry the approval argument through MCP. No secrets or tool arguments are logged.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Sequence
from urllib.parse import quote

import httpx
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken as SdkAccessToken
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.authentication import AuthCredentials
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from approval import (
    ApprovalError,
    ApprovalVerifier,
    SqliteJtiStore,
)
from auth import (
    KeycloakAuthConfig,
    KeycloakTokenVerifier,
    ProtectedResource,
    TokenClaims,
    TokenError,
    bearer_from_header,
)
from delegation import DelegatedAdmin, DelegationConfig, DelegationError, gateway_capability
from pep import CedarPep, PepError, UserPrincipal, pep_from_env
from tool_registry import LOCALE_FIXTURE_ID, LOCALES, TOOLS, ToolSpec

HERE = Path(__file__).resolve().parent
DEFAULT_PORT = 8766
MAX_TOOL_ROWS = 50
HTTP_TIMEOUT = 15.0
ADMIN_CHECK_PATH = "/__delegated_admin_check"


@dataclass
class HttpCaller:
    claims: TokenClaims
    token: str = field(repr=False)
    required_scopes: tuple[str, ...] = ()


_CLAIMS: ContextVar[TokenClaims | None] = ContextVar("kc_mcp_claims", default=None)
_HTTP_CALLER: ContextVar[HttpCaller | None] = ContextVar("kc_mcp_http_caller", default=None)
_STDIO_CLAIMS: TokenClaims | None = None
_STDIO_TOKEN: str | None = None
_RUNTIME: "Runtime | None" = None

log = logging.getLogger("keycloak-mcp")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class ConfigError(Exception):
    pass


class ValidationError(RuntimeError):
    """A caller-supplied value cannot safely become one Admin API path segment."""


# ---------------------------------------------------------------------------
# Admin API path segments (docs/SECURITY.md T17)
# ---------------------------------------------------------------------------
# Caller values are interpolated into /admin/realms/... URLs. An unvalidated
# value with '/', '?', '#' or dot segments adds resources or a query the caller
# was never authorized for (check-then-use divergence); '%' would smuggle
# %2f/%2e escapes past the check. So every interpolated value must be exactly
# one segment: reject structural, percent, dot-segment and control characters,
# then percent-encode. The encoded segment decodes to the exact string Cedar
# and the approval gate saw.
_SEGMENT_MAX = 255
_SEGMENT_REJECTED = frozenset("/?#%\\")


def path_segment(value: Any, *, field: str) -> str:
    """Validate one caller-supplied Admin path segment; fail closed.

    Returns the percent-encoded segment. Raises ValidationError for empty,
    non-string, oversized, dot-segment, structural ('/', '?', '#', '\\',
    '%') or control characters, so a value can never open a second path
    segment, a query, or a fragment in an Admin API URL.
    """
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value) > _SEGMENT_MAX:
        raise ValidationError(f"{field} must be at most {_SEGMENT_MAX} characters")
    if value in (".", ".."):
        raise ValidationError(f"{field} must not be a dot segment")
    if any(ch in _SEGMENT_REJECTED for ch in value):
        raise ValidationError(
            f"{field} must not contain path, query, fragment, or percent characters"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValidationError(f"{field} must not contain control characters")
    return quote(value, safe="")


def _https_base(raw: str) -> str:
    from urllib.parse import urlparse

    value = (raw or "").strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError("KC_URL must be an https:// base URL with a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError("KC_URL must not contain credentials, a query or a fragment")
    return value


@dataclass(frozen=True)
class ServerConfig:
    auth: KeycloakAuthConfig
    base_url: str
    extensions: frozenset[str]
    writes_enabled: bool
    audit_log: str | None
    client_entity_map: Mapping[str, str]
    approval: ApprovalVerifier | None
    tool_allowlist: frozenset[str] | None = None
    delegation: DelegationConfig | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ServerConfig":
        values = dict(os.environ if env is None else env)
        auth = KeycloakAuthConfig.from_env(values)
        base_url = _https_base(values.get("KC_URL") or "")
        extensions = frozenset(
            part.strip()
            for part in (values.get("KC_EXTENSIONS") or "core").replace(",", " ").split()
            if part.strip()
        )
        try:
            entity_map = json.loads(values.get("KC_MCP_CLIENT_ENTITY_MAP") or "{}")
        except json.JSONDecodeError as exc:
            raise ConfigError(f"KC_MCP_CLIENT_ENTITY_MAP is not JSON: {exc}") from exc
        if not isinstance(entity_map, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in entity_map.items()
        ):
            raise ConfigError("KC_MCP_CLIENT_ENTITY_MAP must be a JSON object of string pairs")
        try:
            approval = ApprovalVerifier.from_env(values)
        except ApprovalError as exc:
            raise ConfigError(str(exc)) from exc
        writes_enabled = _truthy(values.get("KC_MCP_ENABLE_WRITES"))
        if writes_enabled and approval is None:
            raise ConfigError(
                "KC_MCP_ENABLE_WRITES=1 requires KC_MCP_APPROVAL_PUBLIC_KEY_FILE; writes "
                "cannot be enabled without independent human approval"
            )
        tool_allowlist = None
        if "KC_MCP_TOOL_ALLOWLIST" in values:
            tool_allowlist = frozenset(values["KC_MCP_TOOL_ALLOWLIST"].replace(",", " ").split())
            if unknown := tool_allowlist.difference(SPECS):
                raise ConfigError("KC_MCP_TOOL_ALLOWLIST contains unknown tools: " + ", ".join(sorted(unknown)))
        if auth.interactive_client_ids.intersection(entity_map):
            raise ConfigError("interactive clients cannot also use static Cedar client mappings")
        delegation = DelegationConfig.from_env(auth, values)
        if delegation is not None and writes_enabled and (
            not isinstance(approval.jti_store, SqliteJtiStore)
            or approval.audience != auth.audience or approval.max_ttl > 120
        ):
            raise ConfigError("Delegated writes require resource-bound approval up to 120 seconds and a durable replay database")
        return cls(
            auth=auth,
            base_url=base_url,
            extensions=extensions,
            writes_enabled=writes_enabled,
            audit_log=(values.get("KC_MCP_AUDIT_LOG") or "").strip() or None,
            client_entity_map=entity_map,
            approval=approval,
            tool_allowlist=tool_allowlist,
            delegation=delegation,
        )

    def redacted(self) -> dict[str, Any]:
        return {
            "issuer": self.auth.issuer,
            "audience": self.auth.audience,
            "resource_url": self.auth.protected_resource.url if self.auth.protected_resource else None,
            "realm": self.auth.realm,
            "jwks_url": self.auth.jwks_url,
            "allowed_client_ids": sorted(self.auth.allowed_client_ids),
            "interactive_client_ids": sorted(self.auth.interactive_client_ids),
            "base_url": self.base_url,
            "extensions": sorted(self.extensions),
            "writes_enabled": self.writes_enabled,
            "delegation_configured": self.delegation is not None,
            "approval_configured": self.approval is not None,
            "audit_log": self.audit_log,
        }


@dataclass
class Runtime:
    config: ServerConfig
    pep: CedarPep
    admin: "KeycloakAdmin"
    delegation: DelegatedAdmin | None = None


# ---------------------------------------------------------------------------
# caller context
# ---------------------------------------------------------------------------
def current_claims() -> TokenClaims:
    caller = _HTTP_CALLER.get()
    if caller is not None:
        return caller.claims
    claims = _CLAIMS.get() or _STDIO_CLAIMS
    if claims is None:
        raise TokenError("No authenticated caller in this request", code="invalid_token")
    if claims.expires_at <= time.time():
        raise TokenError("The stdio access token has expired", code="invalid_token")
    return claims


def current_token() -> str:
    caller = _HTTP_CALLER.get()
    if caller is not None:
        return caller.token
    if not _STDIO_TOKEN:
        raise TokenError("No caller token available for the Admin API call", code="invalid_token")
    return _STDIO_TOKEN


def principal_for(claims: TokenClaims, config: ServerConfig) -> tuple[str, str] | None:
    """Map a Keycloak client to a Cedar Client entity.

    When an entity map is configured, an unmapped client fails closed instead of
    falling back to its raw id (which could match a stale entity in entities.json).
    With no map at all, keep the development fallback to the raw client id.
    """
    mapped = config.client_entity_map.get(claims.client_id)
    if mapped is not None:
        return "Client", mapped
    if not config.client_entity_map:
        return "Client", claims.client_id
    return None


def _entitled(spec: ToolSpec, claims: TokenClaims) -> bool:
    return spec.capability is not None and spec.capability.role in claims.roles


def _user_denial(
    runtime: Runtime, user: UserPrincipal, spec: ToolSpec, reason: str, message: str
) -> dict[str, Any]:
    try:
        runtime.pep.audit_rejection(spec, "User", user.id, user.realm, reason=reason, detail=message)
    except OSError:
        return _error("Authorization audit unavailable", policy_id=spec.policy_id)
    return _error(message, policy_id=spec.policy_id)


def _runtime() -> Runtime:
    if _RUNTIME is None:
        raise ConfigError("server runtime is not initialised")
    return _RUNTIME


# ---------------------------------------------------------------------------
# Keycloak Admin API (caller-token passthrough; no service-account secret)
# ---------------------------------------------------------------------------
class KeycloakAdmin:
    def __init__(self, config: ServerConfig, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.config = config
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=HTTP_TIMEOUT,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._client

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        client = await self._http()
        response = await client.get(
            path,
            params=dict(params or {}),
            headers={"Authorization": f"Bearer {current_token()}", "Accept": "application/json"},
        )
        if response.status_code == 401:
            raise TokenError("Keycloak rejected the caller token for the Admin API", code="invalid_token")
        if response.status_code == 403:
            raise PermissionError(
                "Keycloak denied the Admin API call; the caller needs the matching realm-management role"
            )
        if response.status_code >= 400:
            raise RuntimeError(f"Keycloak Admin API returned HTTP {response.status_code}")
        return response.json()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()


def _capped(items: Any) -> Any:
    return items[:MAX_TOOL_ROWS] if isinstance(items, list) else items


# ---------------------------------------------------------------------------
# tool implementations
# ---------------------------------------------------------------------------
async def list_clients(admin: KeycloakAdmin, realm: str, search: str = "", **_: Any) -> Any:
    params: dict[str, Any] = {"max": MAX_TOOL_ROWS, "first": 0}
    if search:
        params["search"] = search
    return _capped(await admin.get(f"/admin/realms/{path_segment(realm, field='realm')}/clients", params=params))


async def get_client(admin: KeycloakAdmin, realm: str, client_id: str, **_: Any) -> Any:
    matches = await admin.get(
        f"/admin/realms/{path_segment(realm, field='realm')}/clients", params={"clientId": client_id, "max": 1}
    )
    if not matches:
        raise RuntimeError(f"no client with clientId {client_id!r} in realm {realm!r}")
    return await admin.get(
        f"/admin/realms/{path_segment(realm, field='realm')}/clients/"
        f"{path_segment(str(matches[0]['id']), field='client uuid')}"
    )


async def list_users(admin: KeycloakAdmin, realm: str, search: str = "", **_: Any) -> Any:
    params: dict[str, Any] = {"max": MAX_TOOL_ROWS, "first": 0, "briefRepresentation": "true"}
    if search:
        params["search"] = search
    return _capped(await admin.get(f"/admin/realms/{path_segment(realm, field='realm')}/users", params=params))


async def get_user(admin: KeycloakAdmin, realm: str, user_id: str, **_: Any) -> Any:
    return await admin.get(
        f"/admin/realms/{path_segment(realm, field='realm')}/users/{path_segment(user_id, field='user_id')}"
    )


async def get_extension_inventory(config: ServerConfig, **_: Any) -> Any:
    return {
        "installed": sorted(config.extensions),
        "tools": {
            extension: [tool.name for tool in TOOLS if tool.extension == extension]
            for extension in sorted(config.extensions | {"core"})
        },
    }


TOOL_IMPLS: dict[str, Callable[..., Awaitable[Any]]] = {
    "list_clients": list_clients,
    "get_client": get_client,
    "list_users": list_users,
    "get_user": get_user,
    "get_extension_inventory": get_extension_inventory,
}


# ---------------------------------------------------------------------------
# authorization gate (live token scopes, followed by Cedar)
# ---------------------------------------------------------------------------
def _error(message: str, *, policy_id: str, decision: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": message, "policy_id": policy_id}
    if decision is not None:
        payload["decision"] = decision.decision
        payload["reasons"] = list(decision.reasons)
        if decision.failed_closed:
            payload["failed_closed"] = True
    return payload


def _delegated_approval(runtime: Runtime, user: UserPrincipal, spec: ToolSpec, arguments: dict[str, Any]):
    verifier = runtime.config.approval
    if not runtime.config.writes_enabled or verifier is None:
        return _error("Delegated writes are disabled", policy_id=spec.policy_id), None
    target, locale = arguments["user_id"], arguments["locale"]
    if target != LOCALE_FIXTURE_ID or locale not in LOCALES:
        return _user_denial(runtime, user, spec, "target_denied", "Only the demo fixture and supported locales may be changed"), None
    token = arguments.pop("approval", "")
    if not token:
        result = _user_denial(runtime, user, spec, "approval_missing", "An operator approval is required for this locale change")
        result["approval_request"] = {
            "subject": user.id, "realm": user.realm, "tool": spec.name, "action": spec.tier,
            "target": target, "locale": locale, "resource": runtime.config.auth.audience,
        }
        return result, None
    try:
        facts = verifier.verify(token, tool=spec.name, action=spec.tier, target=target, subject=user.id, realm=user.realm, locale=locale)
    except ApprovalError as exc:
        return _user_denial(runtime, user, spec, "approval_rejected", str(exc)), None
    return None, facts.to_pep()


async def _authorized_call(spec: ToolSpec, **kwargs: Any) -> Any:
    runtime = _runtime()
    claims = current_claims()
    user = None
    if claims.interactive:
        user = UserPrincipal(claims.issuer, claims.subject, claims.client_id, claims.realm, claims.scopes, claims.roles)
    mapped = ("User", user.id) if user else principal_for(claims, runtime.config)
    if mapped is None:
        return _error(
            "this client is not mapped to a Cedar entity; add it to KC_MCP_CLIENT_ENTITY_MAP",
            policy_id=spec.policy_id,
        )
    principal_type, principal_id = mapped
    realm = str(kwargs.get("realm") or claims.realm)
    # T17: validate every Admin path argument before the approval verifier or
    # Cedar sees a target, so the authorized value and the value used in the
    # URL are the same single segment (check-then-use parity).
    try:
        path_segment(realm, field="realm")
        if kwargs.get("user_id") is not None:
            path_segment(kwargs["user_id"], field="user_id")
    except ValidationError as exc:
        return _error(str(exc), policy_id=spec.policy_id)

    if user is not None:
        if realm != user.realm:
            return _user_denial(runtime, user, spec, "realm_mismatch", "The requested realm is outside this grant")
        if not _entitled(spec, claims):
            return _user_denial(runtime, user, spec, "entitlement_missing", "This user is not entitled to this tool")
    elif runtime.delegation is not None and spec.name != "get_extension_inventory":
        return _error("This deployment requires an interactive user for Admin tools", policy_id=spec.policy_id)

    # Cedar's configured principal scopes are only the policy view. Check the
    # request's actual grant before evaluating Cedar or consuming an approval.
    missing = [scope for scope in spec.scopes if not claims.allows(scope)]
    if missing:
        caller = _HTTP_CALLER.get()
        if caller is not None:
            caller.required_scopes = spec.scopes
        return _error(
            "the access token lacks the required scope(s): " + ", ".join(missing),
            policy_id=spec.policy_id,
        )
    approval = None
    if spec.write:
        if user is None:
            return _error("Writes require an interactive user", policy_id=spec.policy_id)
        denied, approval = _delegated_approval(runtime, user, spec, kwargs)
        if denied is not None:
            return denied
    decision = runtime.pep.authorize(
        spec,
        principal_type=principal_type,
        principal_id=principal_id,
        realm=realm,
        extensions=runtime.config.extensions,
        writes_enabled=runtime.config.writes_enabled,
        approval=approval,
        **({"user": user} if user is not None else {}),
    )
    if not decision.allowed:
        return _error(
            "Cedar denied this tool call; see policy_id/reasons and the audit log",
            policy_id=spec.policy_id,
            decision=decision,
        )
    if user is not None:
        if runtime.delegation is None:
            return _error(
                "Interactive Admin API dispatch is disabled for this deployment",
                policy_id=spec.policy_id,
                decision=decision,
            )
        kwargs.pop("realm", None)
        try:
            return await runtime.delegation.dispatch(spec, claims, current_token(), **kwargs)
        except DelegationError as exc:
            return _error(str(exc), policy_id=spec.policy_id)
    impl = TOOL_IMPLS[spec.name]
    try:
        return await impl(admin=runtime.admin, config=runtime.config, **kwargs)
    except PermissionError as exc:
        return {"error": str(exc), "policy_id": spec.policy_id}
    except (TokenError, RuntimeError, ConfigError) as exc:
        return {"error": str(exc), "policy_id": spec.policy_id}
    except httpx.HTTPError as exc:
        return {"error": f"Keycloak request failed: {exc.__class__.__name__}", "policy_id": spec.policy_id}


# -- explicit MCP tool signatures (FastMCP builds each input schema from these) --
async def tool_list_clients(realm: str, search: str = "") -> Any:
    return await _authorized_call(SPECS["list_clients"], realm=realm, search=search)


async def tool_get_client(realm: str, client_id: str) -> Any:
    return await _authorized_call(SPECS["get_client"], realm=realm, client_id=client_id)


async def tool_list_users(realm: str, search: str = "") -> Any:
    return await _authorized_call(SPECS["list_users"], realm=realm, search=search)


async def tool_get_user(realm: str, user_id: str) -> Any:
    return await _authorized_call(SPECS["get_user"], realm=realm, user_id=user_id)


async def tool_get_extension_inventory() -> Any:
    return await _authorized_call(SPECS["get_extension_inventory"])


async def tool_set_user_locale(realm: str, user_id: str, locale: str, approval: str = "") -> Any:
    spec = SPECS["set_user_locale"]
    if locale not in LOCALES:
        return _error("locale must be en, de or fr", policy_id=spec.policy_id)
    return await _authorized_call(spec, realm=realm, user_id=user_id, locale=locale, approval=approval)


SPECS = {tool.name: tool for tool in TOOLS}
TOOL_FUNCTIONS: dict[str, Callable[..., Awaitable[Any]]] = {
    "list_clients": tool_list_clients,
    "get_client": tool_get_client,
    "list_users": tool_list_users,
    "get_user": tool_get_user,
    "get_extension_inventory": tool_get_extension_inventory,
    "set_user_locale": tool_set_user_locale,
}


def _register_tools(mcp: FastMCP, config: ServerConfig) -> list[str]:
    registered: list[str] = []
    for spec in TOOLS:
        if spec.write and spec.capability and config.delegation is None:
            continue
        if config.tool_allowlist is not None and spec.name not in config.tool_allowlist:
            continue
        if spec.write and not config.writes_enabled:
            continue
        if spec.extension != "core" and spec.extension not in config.extensions:
            continue
        mcp.tool(name=spec.name, description=spec.description)(TOOL_FUNCTIONS[spec.name])
        registered.append(spec.name)
    return registered


# ---------------------------------------------------------------------------
# HTTP authentication middleware
# ---------------------------------------------------------------------------
class KeycloakMCP(FastMCP):
    async def list_tools(self) -> list[Any]:
        tools = await super().list_tools()
        if not _runtime().config.auth.interactive_client_ids:
            return tools
        request = self.get_context().request_context.request
        claims = request.state.keycloak_caller.claims if request is not None else current_claims()
        return [
            tool for tool in tools
            if all(claims.allows(scope) for scope in SPECS[tool.name].scopes)
            and (not claims.interactive or _entitled(SPECS[tool.name], claims))
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        request = self.get_context().request_context.request
        if request is None:  # stdio
            return await super().call_tool(name, arguments)

        # Stateful MCP workers outlive the HTTP request that created the
        # session. Bind credentials from the SDK's current request metadata.
        caller = request.state.keycloak_caller
        http_caller = _HTTP_CALLER.set(caller)
        try:
            return await super().call_tool(name, arguments)
        finally:
            _HTTP_CALLER.reset(http_caller)


class KeycloakAuthMiddleware:
    def __init__(self, app: ASGIApp, verifier: KeycloakTokenVerifier, *, admin_check: bool = False) -> None:
        self.app = app
        self.verifier = verifier
        self.resource = verifier.config.protected_resource
        self.admin_check = admin_check

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        resource = self.resource
        if scope["type"] != "http" or scope["path"] == "/healthz" or (
            resource is not None
            and scope["path"] == resource.metadata_path
            and scope["method"] in {"GET", "HEAD"}
        ) or (
            self.admin_check and scope["path"] == ADMIN_CHECK_PATH and scope["method"] == "GET"
        ):
            await self.app(scope, receive, send)
            return
        header = None
        for name, value in scope.get("headers") or ():
            if name.lower() == b"authorization":
                header = value.decode("latin-1")
        try:
            token = bearer_from_header(header)
            claims = await self.verifier.verify(token)
        except TokenError as exc:
            error = exc.code
            headers = {}
            if resource is None:
                headers["WWW-Authenticate"] = f'Bearer error="{error}"'
            elif exc.status == 401:
                error = "invalid_token"
                if scope["path"] == resource.path:
                    headers["WWW-Authenticate"] = self._challenge(
                        resource, error=error if header is not None else None
                    )
                else:
                    headers["WWW-Authenticate"] = "Bearer"
            response = JSONResponse(
                {"error": error, "error_description": str(exc)}, status_code=exc.status, headers=headers
            )
            await response(scope, receive, send)
            return
        caller = HttpCaller(claims, token)
        scope.setdefault("state", {})["keycloak_caller"] = caller
        scope["auth"] = AuthCredentials(scopes=sorted(claims.scopes))
        scope["user"] = AuthenticatedUser(
            SdkAccessToken(
                token="",
                client_id=claims.client_id,
                scopes=sorted(claims.scopes),
                expires_at=int(claims.expires_at),
                resource=claims.audience,
                subject=claims.subject,
                claims={"iss": claims.issuer, "realm": claims.realm},
            )
        )
        if resource is None:
            await self.app(scope, receive, send)
            return

        async def send_with_challenge(message: Message) -> None:
            # JSON response mode waits for the tool before sending headers.
            # The SDK reads, limits and validates the request body as usual.
            if (
                caller.required_scopes
                and message["type"] == "http.response.start"
                and message["status"] == 200
            ):
                challenge = self._challenge(resource, error="insufficient_scope", scopes=caller.required_scopes)
                message = {
                    **message,
                    "status": 403,
                    "headers": [*message["headers"], (b"www-authenticate", challenge.encode("ascii"))],
                }
            await send(message)

        await self.app(scope, receive, send_with_challenge)

    @staticmethod
    def _challenge(
        resource: ProtectedResource, *, error: str | None = None, scopes: tuple[str, ...] = ()
    ) -> str:
        params = [f'resource_metadata="{resource.metadata_url}"']
        if error:
            params.append(f'error="{error}"')
        if scopes:
            params.append(f'scope="{" ".join(scopes)}"')
        return "Bearer " + ", ".join(params)


def build_mcp(config: ServerConfig) -> tuple[KeycloakMCP, list[str]]:
    resource = config.auth.protected_resource
    if resource is None:
        mcp = KeycloakMCP("keycloak-mcp")
    else:
        mcp = KeycloakMCP(
            "keycloak-mcp",
            streamable_http_path=resource.path,
            json_response=True,
            transport_security=TransportSecuritySettings(
                allowed_hosts=[resource.authority, "127.0.0.1:*", "localhost:*", "[::1]:*"],
                allowed_origins=[
                    f"https://{resource.authority}",
                    "http://127.0.0.1:*",
                    "http://localhost:*",
                    "http://[::1]:*",
                ],
            ),
        )
    return mcp, _register_tools(mcp, config)


def build_http_app(
    mcp: KeycloakMCP, verifier: KeycloakTokenVerifier, *, delegate: DelegatedAdmin | None = None
) -> ASGIApp:
    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": "keycloak-mcp"})

    resource = verifier.config.protected_resource
    if resource is not None:
        @mcp.custom_route(resource.metadata_path, methods=["GET"])
        async def protected_resource(_request: Request) -> JSONResponse:
            return JSONResponse({
                "resource": resource.url,
                "authorization_servers": [verifier.config.issuer],
                "bearer_methods_supported": ["header"],
            })

    if delegate is not None:
        @mcp.custom_route(ADMIN_CHECK_PATH, methods=["GET"])
        async def check_admin(request: Request) -> Response:
            capability = gateway_capability(
                delegate.config.admin_path, request.headers.get("x-admin-method", ""), request.headers.get("x-admin-path", ""),
                request.headers.get("x-admin-query", ""),
            )
            if capability is None:
                return Response(status_code=403)
            try:
                token = bearer_from_header(request.headers.get("authorization"))
                await delegate.verify_token(token, capability)
            except (TokenError, DelegationError):
                return Response(status_code=403)
            return Response(status_code=204)

    return KeycloakAuthMiddleware(mcp.streamable_http_app(), verifier, admin_check=delegate is not None)


def _stdio_token() -> str:
    direct = (os.environ.get("KC_MCP_ACCESS_TOKEN") or "").strip()
    if direct:
        return direct
    path = (os.environ.get("KC_MCP_ACCESS_TOKEN_FILE") or "").strip()
    if path:
        try:
            return Path(path).read_text().strip()
        except OSError as exc:
            raise ConfigError(f"KC_MCP_ACCESS_TOKEN_FILE cannot be read: {exc}") from exc
    raise ConfigError(
        "stdio mode needs KC_MCP_ACCESS_TOKEN or KC_MCP_ACCESS_TOKEN_FILE with a short-lived "
        "Keycloak access token; there is no anonymous stdio fallback"
    )


def build_runtime(config: ServerConfig) -> Runtime:
    delegate = DelegatedAdmin(config.delegation) if config.delegation else None
    return Runtime(config=config, pep=pep_from_env(), admin=KeycloakAdmin(config), delegation=delegate)


def main(argv: Sequence[str] | None = None) -> int:
    global _RUNTIME, _STDIO_CLAIMS, _STDIO_TOKEN
    parser = argparse.ArgumentParser(prog="keycloak-mcp")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--check", action="store_true", help="validate config/Cedar bundle and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    try:
        config = ServerConfig.from_env()
        if config.delegation is not None and args.transport == "stdio" and not args.check:
            raise ConfigError("The delegation profile requires the private HTTP gateway")
        verifier = KeycloakTokenVerifier(config.auth)
        runtime = build_runtime(config)
        _RUNTIME = runtime
        mcp, registered = build_mcp(config)
    except (ConfigError, DelegationError, TokenError, PepError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(
            json.dumps(
                {
                    "config": config.redacted(),
                    "cedar": {
                        "bundleHash": runtime.pep.meta.get("bundleHash"),
                        "cedarVersion": runtime.pep.meta.get("cedarVersion"),
                        "policies": len(runtime.pep.meta.get("policyIds") or []),
                    },
                    "tools": registered,
                    "unmapped_clients": sorted(
                        client_id
                        for client_id in config.auth.allowed_client_ids
                        if client_id not in config.client_entity_map
                        and client_id not in config.auth.interactive_client_ids
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        runtime.pep.close()
        asyncio.run(runtime.admin.aclose())
        asyncio.run(verifier.aclose())
        if runtime.delegation is not None:
            asyncio.run(runtime.delegation.aclose())
        return 0
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("refusing to bind a non-loopback host", file=sys.stderr)
        runtime.pep.close()
        return 2
    if args.transport == "stdio":
        try:
            token = _stdio_token()
            claims = asyncio.run(verifier.verify(token))
        except (ConfigError, TokenError) as exc:
            print(f"authentication error: {exc}", file=sys.stderr)
            runtime.pep.close()
            return 2
        _STDIO_CLAIMS, _STDIO_TOKEN = claims, token
        print(
            f"keycloak-mcp: stdio, client={claims.client_id}, realm={claims.realm}, "
            f"tools={len(registered)}",
            file=sys.stderr,
        )
        try:
            mcp.run(transport="stdio")
        finally:
            runtime.pep.close()
            asyncio.run(runtime.admin.aclose())
            asyncio.run(verifier.aclose())
        return 0

    import uvicorn

    app = build_http_app(mcp, verifier, delegate=runtime.delegation)
    config_uvicorn = uvicorn.Config(app, host=args.host, port=args.port, log_level="warning")
    print(
        f"keycloak-mcp: http 127.0.0.1:{args.port}, realm={config.auth.realm}, "
        f"tools={len(registered)}",
        file=sys.stderr,
    )
    async def serve_http():
        try:
            await uvicorn.Server(config_uvicorn).serve()
        finally:
            runtime.pep.close()
            await runtime.admin.aclose()
            await verifier.aclose()
            if runtime.delegation is not None:
                await runtime.delegation.aclose()

    asyncio.run(serve_http())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

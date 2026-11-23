"""Keycloak OIDC access-token verification for the MCP server.

Offline construction; network only on the first verification (JWKS). The verifier is
deliberately narrow: HTTPS JWKS, no redirects, no ambient proxy, a bounded streaming
read of the key document, RS256/ES256 only, exact issuer/audience, exp/iat enforced,
`azp`/`client_id` exact allowlist (URL-form entries are validated against the
draft-ietf-oauth-client-id-metadata-document-03 Section 3 grammar and Section 10.1
identifier-equality rules, then accepted unchanged), and scopes parsed from `scope`
or `scp`. Any failure is an instruction-shaped :class:`TokenError`; there is no
anonymous fallback.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlsplit

import httpx
import jwt

from tool_registry import CAPABILITIES

ALLOWED_ALGORITHMS = frozenset({"RS256", "RS384", "ES256", "ES384"})
MAX_TOKEN_BYTES = 16_384
# Single source of truth for the JWKS size bound: a document is a handful of small
# JWK objects (Keycloak 26.8 with two keys is ~1 KiB), so 256 KiB leaves a generous
# rotation window while bounding what a hostile or misconfigured issuer can make
# this process hold. Tests assert this value.
MAX_JWKS_BYTES = 256 * 1024
# Chunk size for the bounded read: the peak overshoot of a stream is one chunk.
JWKS_CHUNK_BYTES = 16 * 1024
DEFAULT_TIMEOUT = 5.0
PROTECTED_RESOURCE_METADATA_PREFIX = "/.well-known/oauth-protected-resource"
_RESOURCE_URL = re.compile(
    r"https://(?P<authority>(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::[0-9]+)?)"
    r"(?P<path>(?:/[A-Za-z0-9._~-]+)*)"
)


class TokenError(Exception):
    def __init__(self, message: str, *, status: int = 401, code: str = "invalid_token") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _https_url(raw: str, field: str) -> str:
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise TokenError(f"{field} must be an https:// URL with a host", code="server_error")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TokenError(
            f"{field} must not contain credentials, a query or a fragment",
            code="server_error",
        )
    return raw.rstrip("/")


def _cimd_entry(entry: str, issuer: str, audience: str) -> str:
    """Validate one KC_ALLOWED_CLIENT_IDS entry against draft-ietf-oauth-
    client-id-metadata-document-03.

    URL-form entries (https://...) must satisfy the Section 3 grammar: the
    Client Identifier URL MUST use https, MUST NOT carry userinfo, a fragment,
    single-dot/double-dot path components, and MUST contain a path component
    other than "/". A query component is SHOULD NOT, rejected here too
    (deny-by-default). Entries equal to this server's own audience or to the
    configured issuer are refused per the Section 10.1 confusion guidance:
    a Client Identifier URL that string-matches an AS/RS identifier turns
    the issuer into an admission oracle. Comparisons are simple string
    comparisons (Section 3: servers MUST NOT normalize). Plain (non-URL)
    client ids are passed through unchanged.
    """
    if "://" not in entry:
        return entry  # native (non-URL) client id, passed through unchanged
    if not entry.startswith("https://"):
        raise TokenError(
            f"client id entry {entry!r}: URL-form client ids MUST use the exact lowercase "
            "https scheme (draft -03 Section 3); http and other schemes are rejected",
            code="server_error",
        )
    parsed = urlparse(entry)
    field = f"client id entry {entry!r}"
    if parsed.scheme != "https" or not parsed.netloc:
        raise TokenError(f"{field}: must be an absolute https URL with a host", code="server_error")
    if parsed.username or parsed.password:
        raise TokenError(f"{field}: userinfo component is prohibited", code="server_error")
    if parsed.fragment:
        raise TokenError(f"{field}: fragment component is prohibited", code="server_error")
    if parsed.query:
        raise TokenError(f"{field}: query component is not accepted", code="server_error")
    if parsed.path in ("", "/"):
        raise TokenError(f"{field}: path component other than '/' is required", code="server_error")
    if any(segment in (".", "..") for segment in parsed.path.split("/")):
        raise TokenError(f"{field}: single-dot/double-dot path components are prohibited", code="server_error")
    if "\\" in entry or any(char in entry for char in " \t\r\n"):
        raise TokenError(f"{field}: whitespace and backslashes are prohibited", code="server_error")
    if entry == audience:
        raise TokenError(
            f"{field}: a Client Identifier URL may not equal this resource server's audience",
            code="server_error",
        )
    if entry == issuer or entry == issuer + "/":
        raise TokenError(
            f"{field}: a Client Identifier URL may not equal the authorization server issuer",
            code="server_error",
        )
    return entry


def _split_list(raw: str | None) -> list[str]:
    """Whitespace-separated; a whitespace token starting https:// is never comma-split."""
    if not raw:
        return []
    values: list[str] = []
    for token in raw.split():
        if token.startswith("https://"):
            values.append(token)
        else:
            values.extend(part for part in token.split(",") if part)
    return values


@dataclass(frozen=True)
class ProtectedResource:
    url: str
    authority: str
    url_path: str

    @classmethod
    def parse(cls, value: str) -> ProtectedResource:
        error = (
            "KC_MCP_RESOURCE_URL must be a canonical HTTPS URL with a lowercase host "
            "and an optional path of unreserved segments"
        )
        match = _RESOURCE_URL.fullmatch(value)
        if match is None:
            raise TokenError(error, code="server_error")
        try:
            port = urlsplit(value).port
        except ValueError as exc:
            raise TokenError(error, code="server_error") from exc
        path = match["path"]
        if (
            port == 0
            or path == "/healthz"
            or path.startswith("/.well-known/")
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            raise TokenError(error, code="server_error")
        return cls(value, match["authority"], path)

    @property
    def path(self) -> str:
        return self.url_path or "/"

    @property
    def metadata_path(self) -> str:
        return PROTECTED_RESOURCE_METADATA_PREFIX + self.url_path

    @property
    def metadata_url(self) -> str:
        return f"https://{self.authority}{self.metadata_path}"


@dataclass(frozen=True)
class KeycloakAuthConfig:
    issuer: str
    audience: str
    jwks_url: str
    allowed_client_ids: frozenset[str]
    realm: str
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    clock_skew: int = 60
    jwks_ttl: float = 300.0
    jwks_min_refresh: float = 30.0
    admin_role: str = "mcp-admin"
    protected_resource: ProtectedResource | None = None
    interactive_client_ids: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> KeycloakAuthConfig:
        values = dict(os.environ if env is None else env)
        issuer = _https_url((values.get("KC_ISSUER") or "").strip(), "KC_ISSUER")
        audience = (values.get("KC_AUDIENCE") or "").strip()
        resource_url = (values.get("KC_MCP_RESOURCE_URL") or "").strip()
        protected_resource = ProtectedResource.parse(resource_url) if resource_url else None
        if protected_resource is not None:
            if audience and audience != protected_resource.url:
                raise TokenError(
                    "KC_AUDIENCE must exactly match KC_MCP_RESOURCE_URL when both are set",
                    code="server_error",
                )
            audience = protected_resource.url
        if not audience:
            raise TokenError("KC_AUDIENCE or KC_MCP_RESOURCE_URL is required", code="server_error")
        jwks_url = _https_url(
            (values.get("KC_JWKS_URL") or f"{issuer}/protocol/openid-connect/certs").strip(),
            "KC_JWKS_URL",
        )
        allowed: list[str] = []
        file_path = (values.get("KC_ALLOWED_CLIENT_IDS_FILE") or "").strip()
        if file_path:
            try:
                with open(file_path, encoding="utf-8") as handle:
                    allowed.extend(
                        line.strip()
                        for line in handle
                        if line.strip() and not line.lstrip().startswith("#")
                    )
            except OSError as exc:
                raise TokenError(
                    f"KC_ALLOWED_CLIENT_IDS_FILE cannot be read: {exc}",
                    code="server_error",
                ) from exc
        allowed.extend(_split_list(values.get("KC_ALLOWED_CLIENT_IDS")))
        if not allowed:
            raise TokenError(
                "KC_ALLOWED_CLIENT_IDS or KC_ALLOWED_CLIENT_IDS_FILE is required; "
                "refusing to accept any client (deny by default)",
                code="server_error",
            )
        allowed = [_cimd_entry(entry, issuer, audience) for entry in allowed]
        interactive_clients = frozenset(_split_list(values.get("KC_MCP_INTERACTIVE_CLIENT_IDS")))
        if interactive_clients and (protected_resource is None or not interactive_clients.issubset(allowed)):
            raise TokenError(
                "interactive clients must be allowlisted and require KC_MCP_RESOURCE_URL",
                code="server_error",
            )
        realm = (values.get("KC_REALM") or "").strip()
        if not realm:
            marker = "/realms/"
            realm = issuer.split(marker, 1)[1].split("/", 1)[0] if marker in issuer else ""
        if not realm:
            raise TokenError(
                "cannot derive the realm from KC_ISSUER; set KC_REALM", code="server_error"
            )
        algorithms = tuple(
            algorithm.upper()
            for algorithm in _split_list(values.get("KC_ALGORITHMS") or "RS256 ES256")
        )
        if not algorithms or any(algorithm not in ALLOWED_ALGORITHMS for algorithm in algorithms):
            raise TokenError(
                "KC_ALGORITHMS must be a subset of RS256 RS384 ES256 ES384",
                code="server_error",
            )
        try:
            skew = int(values.get("KC_CLOCK_SKEW") or "60")
            ttl = float(values.get("KC_JWKS_TTL") or "300")
            min_refresh = float(values.get("KC_JWKS_MIN_REFRESH") or "30")
        except ValueError as exc:
            raise TokenError("KC_CLOCK_SKEW/KC_JWKS_TTL must be numeric", code="server_error") from exc
        if not 0 <= skew <= 300 or not 30 <= ttl <= 3600 or not 1 <= min_refresh <= 300:
            raise TokenError("KC_CLOCK_SKEW/KC_JWKS_TTL/KC_JWKS_MIN_REFRESH out of range", code="server_error")
        return cls(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            allowed_client_ids=frozenset(allowed),
            realm=realm,
            algorithms=algorithms,
            clock_skew=skew,
            jwks_ttl=ttl,
            jwks_min_refresh=min_refresh,
            admin_role=(values.get("KC_ADMIN_ROLE") or "mcp-admin").strip(),
            protected_resource=protected_resource,
            interactive_client_ids=interactive_clients,
        )


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    client_id: str
    scopes: frozenset[str]
    realm: str
    admin: bool
    expires_at: float
    issuer: str
    audience: str
    roles: frozenset[str] = frozenset()
    interactive: bool = False
    # Keycloak's own `realm_access.roles`, kept apart from `roles`: for a human token the
    # entitlements are the issued `mcp_roles` claim, for a machine token they are the
    # client's realm roles. Cedar's `principal.roles` reads whichever one applies.
    realm_roles: frozenset[str] = frozenset()

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


def ssl_trust(ca_file: str | None = None) -> ssl.SSLContext | bool:
    """TLS trust material for an outbound client that runs with `trust_env=False`.

    `trust_env=False` keeps an ambient HTTP(S)_PROXY and any ~/.netrc credential away
    from these requests - but httpx implements SSL_CERT_FILE and SSL_CERT_DIR under that
    same flag, and otherwise falls back to certifi's bundle. A private Keycloak CA
    arrives through SSL_CERT_FILE (the Docker demo mounts it at /trust/edge-ca.pem), so
    those variables are read here explicitly: trust is selected by the deployment,
    routing never is. An explicitly named bundle wins, then the environment, then httpx's
    own default. A bundle that cannot be loaded raises rather than silently trusting a
    different issuer.
    """
    candidates = [("KC_MCP_ADMIN_CA_FILE/ssl_ca_bundle", ca_file, "cafile")]
    candidates.append(("SSL_CERT_FILE", os.environ.get("SSL_CERT_FILE"), "cafile"))
    candidates.append(("SSL_CERT_DIR", os.environ.get("SSL_CERT_DIR"), "capath"))
    for label, value, keyword in candidates:
        if not value:
            continue
        try:
            context = ssl.create_default_context(**{keyword: value})
        except OSError as exc:
            raise TokenError(f"Cannot load the TLS trust material from {label}: {exc}", status=503, code="server_error") from exc
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
    return True


def realm_from_issuer(issuer: str) -> str:
    """The realm path segment of an issuer URL, or "" if it is not a realm issuer.

    Both `iss` and the realm reach us from the token, so the pair is checked here rather
    than assumed: a caller from one realm must not reach another realm's tool.
    """
    parts = urlsplit(issuer)
    marker = "/realms/"
    if not parts.path.startswith(marker) or parts.path != marker + parts.path[len(marker) :].strip("/"):
        return ""
    return parts.path[len(marker) :]




class JwksCache:
    """One HTTPS JWKS URL, cached, streaming-bounded, no redirects, no ambient proxy.

    A failed refresh never replaces the cached key set: `self._keys` is assigned only
    after a document has been read, parsed and validated in full.
    """

    def __init__(
        self,
        url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        ttl: float = 300.0,
        min_refresh: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        max_bytes: int = MAX_JWKS_BYTES,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise TokenError("JWKS URL must be https:// with a host", code="server_error")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be a positive byte count")
        self.url = url
        self.host = parsed.hostname.lower()
        self._transport = transport
        self._timeout = timeout
        self._ttl = ttl
        self._min_refresh = min_refresh
        self._clock = clock
        self._max_bytes = max_bytes
        # Resolved once, at construction: a CA bundle the operator named must either
        # load or stop the server, never be quietly ignored mid-verification.
        self._ssl = ssl_trust()
        self._lock = asyncio.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                transport=self._transport,
                verify=self._ssl,
                follow_redirects=False,
                # The URL is HTTPS-only by construction (`__init__` rejects any other
                # scheme) and redirects are off, so nothing about this request may come
                # from the environment either: with transport=None, httpx would honour
                # HTTP(S)_PROXY/ALL_PROXY - handing an issuer-selecting request to a
                # stray corporate proxy - and could pick up a ~/.netrc credential.
                trust_env=False,
                headers={"Accept": "application/json", "User-Agent": "keycloak-mcp/0.1"},
            )
        return self._client

    async def _read_capped(self, response: httpx.Response) -> bytes:
        """Read a response body incrementally and refuse it as soon as it is too big.

        `client.get()` (and therefore `response.content`) buffers the whole body before
        any size check can run, so `len(body) > max_bytes` only ever protected the
        parse, never the memory: an issuer streaming 500 MB allocated 500 MB first and
        was rejected afterwards. Chunked reads stop within one chunk of the cap, and a
        declared Content-Length over the cap is refused before a byte is read.
        """
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_bytes:
            raise TokenError("The JWKS response was unexpectedly large", status=503)
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes(JWKS_CHUNK_BYTES):
            size += len(chunk)
            if size > self._max_bytes:
                raise TokenError(
                    f"The JWKS response exceeded the {self._max_bytes}-byte limit",
                    status=503,
                )
            chunks.append(chunk)
        return b"".join(chunks)

    async def refresh(self) -> None:
        client = await self._http()
        try:
            # `stream=` keeps the response open until the capped read above has
            # finished, so nothing buffers the whole document.
            async with client.stream("GET", self.url) as response:
                if response.status_code != 200:
                    raise TokenError(
                        f"The Keycloak JWKS endpoint returned HTTP {response.status_code}",
                        status=503,
                        code="temporarily_unavailable",
                    )
                body = await self._read_capped(response)
        except httpx.HTTPError as exc:
            raise TokenError(
                "Could not reach the Keycloak JWKS endpoint; retry, then check KC_JWKS_URL",
                status=503,
                code="temporarily_unavailable",
            ) from exc
        try:
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TokenError("The JWKS endpoint did not return JSON", status=503) from exc
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise TokenError("The JWKS document is not {'keys': [...]}", status=503)
        try:
            key_set = jwt.PyJWKSet.from_dict(document)
        except Exception as exc:  # noqa: BLE001 - malformed key material
            raise TokenError("The JWKS document could not be parsed", status=503) from exc
        keys = {jwk.key_id: jwk for jwk in key_set.keys if jwk.key_id}
        if not keys:
            raise TokenError("The JWKS document contained no key IDs", status=503)
        self._keys = keys
        self._fetched_at = self._clock()

    async def get_key(self, kid: str) -> Any:
        async with self._lock:
            now = self._clock()
            fresh = bool(self._keys) and (now - self._fetched_at) < self._ttl
            if fresh and kid in self._keys:
                return self._keys[kid]
            if not fresh or (kid not in self._keys and now - self._fetched_at >= self._min_refresh):
                await self.refresh()
            key = self._keys.get(kid)
            if key is None:
                raise TokenError("The access token was signed with an unknown key id")
            return key

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _scope_claims(claims: Mapping[str, Any]) -> frozenset[str]:
    raw = claims.get("scope")
    if isinstance(raw, str):
        return frozenset(raw.split())
    scp = claims.get("scp")
    if isinstance(scp, list):
        return frozenset(str(item) for item in scp if isinstance(item, str))
    return frozenset()


def _client_id(claims: Mapping[str, Any]) -> str:
    for name in ("azp", "client_id"):
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    raise TokenError("The access token has no azp/client_id claim")


class KeycloakTokenVerifier:
    def __init__(self, config: KeycloakAuthConfig, *, jwks: Any | None = None) -> None:
        self.config = config
        self._jwks = jwks or JwksCache(
            config.jwks_url,
            ttl=config.jwks_ttl,
            min_refresh=config.jwks_min_refresh,
        )

    async def decode_token(self, token: str, *, audience: str, leeway: int) -> Mapping[str, Any]:
        if not isinstance(token, str) or token.count(".") != 2:
            raise TokenError("The bearer token is not a signed JWT")
        if len(token) > MAX_TOKEN_BYTES:
            raise TokenError("The bearer token is too large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenError("The bearer token has a malformed JWT header") from exc
        algorithm = str(header.get("alg") or "").upper()
        if algorithm not in self.config.algorithms:
            raise TokenError("The token signing algorithm is not accepted")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("The access token has no kid header")
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise TokenError("The bearer token has a malformed JWT payload") from exc
        issuer = unverified.get("iss")
        if not isinstance(issuer, str) or issuer.rstrip("/") != self.config.issuer:
            raise TokenError("The access token was not issued by the configured Keycloak issuer")
        key = await self._jwks.get_key(kid)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                audience=audience,
                issuer=self.config.issuer,
                leeway=leeway,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenError("The access token failed signature/claim validation") from exc
        return claims

    async def verify(self, token: str) -> TokenClaims:
        claims = await self.decode_token(token, audience=self.config.audience, leeway=self.config.clock_skew)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise TokenError("The access token has no subject")
        client_id = _client_id(claims)
        if client_id not in self.config.allowed_client_ids:
            raise TokenError(
                "The access token was issued to a client that is not allowlisted; add its "
                "client id or CIMD URL to KC_ALLOWED_CLIENT_IDS(_FILE)",
                code="invalid_client",
            )
        realm = self.config.realm
        issuer_realm = realm_from_issuer(claims["iss"])
        if issuer_realm != realm:
            raise TokenError("The access token was issued by a different realm than this server serves")
        roles = claims.get("realm_access", {}).get("roles") if isinstance(claims.get("realm_access"), dict) else []
        realm_roles = frozenset(role for role in roles if isinstance(role, str)) if isinstance(roles, list) else frozenset()
        scopes = _scope_claims(claims)
        interactive = client_id in self.config.interactive_client_ids
        entitlements = frozenset()
        if interactive:
            if claims.get("typ") != "Bearer":
                raise TokenError("This client must present a Keycloak access token")
            raw_roles = claims.get("mcp_roles", [])
            if not isinstance(raw_roles, list) or not all(isinstance(role, str) for role in raw_roles):
                raise TokenError("The MCP entitlement claim is malformed")
            entitlements = frozenset(raw_roles)
            expected_audiences = {self.config.audience} | {
                CAPABILITIES[scope].requester_audience(self.config.audience)
                for scope in scopes & CAPABILITIES.keys()
            }
            aud = claims["aud"]
            actual_audiences = {aud} if isinstance(aud, str) else set(aud)
            if actual_audiences != expected_audiences:
                raise TokenError("The token audiences do not match this MCP resource and its issued capabilities")
        return TokenClaims(
            subject=subject,
            client_id=client_id,
            scopes=scopes,
            realm=realm,
            admin=not interactive and isinstance(roles, list) and self.config.admin_role in roles,
            expires_at=float(claims["exp"]),
            issuer=self.config.issuer,
            audience=self.config.audience,
            roles=entitlements,
            interactive=interactive,
            realm_roles=frozenset() if interactive else realm_roles,
        )

    async def aclose(self) -> None:
        close = getattr(self._jwks, "aclose", None)
        if close is not None:
            await close()


def bearer_from_header(header: str | None) -> str:
    if not header or not header.strip():
        raise TokenError("Missing Authorization header; send 'Authorization: Bearer <token>'")
    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise TokenError("Use the Bearer scheme with a Keycloak access token")
    return token.strip()

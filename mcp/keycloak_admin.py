"""Read-only Keycloak Admin client for direct, non-delegated calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import httpx

from auth import TokenError, ssl_trust

HTTP_TIMEOUT = 15.0


class KeycloakAdmin:
    def __init__(
        self,
        base_url: str,
        token_provider: Callable[[], str],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url
        self._token_provider = token_provider
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=HTTP_TIMEOUT,
                follow_redirects=False,
                # Every request here carries a bearer token - the caller's own, or a
                # helpdesk operator's after a delegated exchange. Like the JWKS fetch,
                # this client must not inherit an ambient proxy (which would read and
                # could redirect that token) or ~/.netrc credentials, and it must still
                # trust an explicitly installed CA, which is how the demo reaches
                # Keycloak through its own edge.
                trust_env=False,
                verify=ssl_trust(),
                transport=self._transport,
            )
        return self._client

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        client = await self._http()
        response = await client.get(
            path,
            params=dict(params or {}),
            headers={"Authorization": f"Bearer {self._token_provider()}", "Accept": "application/json"},
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

"""Tool implementations and single-segment validation for direct Admin reads."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

from keycloak_admin import KeycloakAdmin
from tool_registry import TOOLS

MAX_TOOL_ROWS = 50


class ValidationError(RuntimeError):
    """A caller-supplied value cannot safely become one Admin API path segment."""


# ---------------------------------------------------------------------------
# Admin API path segments
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


async def get_extension_inventory(**_: Any) -> Any:
    return {
        "installed": ["core"],
        "tools": {
            "core": [tool.name for tool in TOOLS]
        },
    }


TOOL_IMPLS: dict[str, Callable[..., Awaitable[Any]]] = {
    "list_clients": list_clients,
    "get_client": get_client,
    "list_users": list_users,
    "get_user": get_user,
    "get_extension_inventory": get_extension_inventory,
}

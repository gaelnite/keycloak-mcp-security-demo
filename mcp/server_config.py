"""Configuration for the Keycloak MCP server."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from approval import ApprovalError, ApprovalVerifier, SqliteJtiStore
from auth import KeycloakAuthConfig
from delegation import DelegationConfig
from tool_registry import TOOLS_BY_NAME


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class ConfigError(Exception):
    pass


def _https_base(raw: str) -> str:
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
    approval: ApprovalVerifier | None
    tool_allowlist: frozenset[str] | None = None
    delegation: DelegationConfig | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServerConfig:
        values = dict(os.environ if env is None else env)
        auth = KeycloakAuthConfig.from_env(values)
        base_url = _https_base(values.get("KC_URL") or "")
        extensions = frozenset(
            part.strip()
            for part in (values.get("KC_EXTENSIONS") or "core").replace(",", " ").split()
            if part.strip()
        )
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
            if unknown := tool_allowlist.difference(TOOLS_BY_NAME):
                raise ConfigError("KC_MCP_TOOL_ALLOWLIST contains unknown tools: " + ", ".join(sorted(unknown)))
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

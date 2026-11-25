"""Tool registry for the Keycloak MCP reference server."""

from __future__ import annotations

from dataclasses import dataclass

READ = "read"
WRITE = "write"
TIERS = (READ, WRITE)


@dataclass(frozen=True)
class Capability:
    scope: str
    role: str
    label: str
    admin_role: str
    resource: str

    def requester_audience(self, resource_url: str) -> str:
        return f"{resource_url}/capabilities/{self.scope}"


USERS_READ = Capability("keycloak.users.read", "mcp-users-read", "Read users", "view-users", "user")
CLIENTS_READ = Capability("keycloak.clients.read", "mcp-clients-read", "Read clients", "view-clients", "client")
USER_LOCALE = Capability("keycloak.users.locale.write", "mcp-user-locale", "Change a user's locale", "manage-users", "user")
CAPABILITIES = {capability.scope: capability for capability in (USERS_READ, CLIENTS_READ, USER_LOCALE)}
LOCALE_FIXTURE_ID = "cc5f02c4-3295-5b8a-b698-5e95b0e86082"
LOCALES = ("en", "de", "fr")


@dataclass(frozen=True)
class ToolArgument:
    name: str
    annotation: type[str] = str
    default: str | None = None  # None denotes a required string argument.


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    scopes: tuple[str, ...]
    policy_id: str
    tier: str
    write: bool = False
    capability: Capability | None = None
    arguments: tuple[ToolArgument, ...] = ()

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"{self.name}: unknown tier {self.tier!r}")
        if self.tier == WRITE and not self.write:
            raise ValueError(f"{self.name}: write-tier tools must set write=True")
        if not self.scopes:
            raise ValueError(f"{self.name}: at least one scope is required")
        if not self.policy_id.startswith("kc-"):
            raise ValueError(f"{self.name}: policy_id must start with kc-")
        if self.capability and self.scopes != (self.capability.scope,):
            raise ValueError(f"{self.name}: the tool scope must match its interactive capability")


def _spec(
    name: str,
    description: str,
    scope: str | Capability,
    tier: str,
    *,
    arguments: tuple[ToolArgument, ...] = (),
) -> ToolSpec:
    capability = scope if isinstance(scope, Capability) else None
    return ToolSpec(
        name=name,
        description=description,
        scopes=(capability.scope if capability else scope,),
        policy_id=f"kc-{tier}-{name.replace('_', '-')}",
        tier=tier,
        write=(tier == WRITE),
        capability=capability,
        arguments=arguments,
    )


REALM = ToolArgument("realm")
SEARCH = ToolArgument("search", default="")
USER_ID = ToolArgument("user_id")

TOOLS: tuple[ToolSpec, ...] = (
    _spec("list_clients", "List OIDC/SAML clients in a realm.", CLIENTS_READ, READ, arguments=(REALM, SEARCH)),
    _spec(
        "get_client", "Read one client's configuration.", CLIENTS_READ, READ,
        arguments=(REALM, ToolArgument("client_id")),
    ),
    _spec("list_users", "Search users in a realm.", USERS_READ, READ, arguments=(REALM, SEARCH)),
    _spec("get_user", "Read one user's profile and role mappings.", USERS_READ, READ, arguments=(REALM, USER_ID)),
    _spec(
        "get_extension_inventory",
        "List installed Keycloak extensions and the tools mapped to each.",
        "keycloak.extensions.read",
        READ,
    ),
    _spec(
        "set_user_locale", "Set a user's preferred locale.", USER_LOCALE, WRITE,
        arguments=(REALM, USER_ID, ToolArgument("locale"), ToolArgument("approval", default="")),
    ),
)

TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}
READ_TOOLS = tuple(tool for tool in TOOLS if tool.tier == READ)
WRITE_TOOLS = tuple(tool for tool in TOOLS if tool.write)


def policy_ids() -> tuple[str, ...]:
    return tuple(tool.policy_id for tool in TOOLS)

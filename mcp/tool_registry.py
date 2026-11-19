"""Extension-aware tool registry for the Keycloak MCP reference server.

Pure stdlib so the policy tests can run without the MCP SDK or network. Every tool
declares the Keycloak scope it needs, the Cedar policy that authorizes it (the
``policy_id`` must exist in ``cedar/policies.cedar``) and the extension that owns it.
``extension == "core"`` is always available; any other value must appear in the
server's installed-extension set or the Cedar policy denies the call.
"""

from __future__ import annotations

from dataclasses import dataclass

READ = "read"
WRITE = "write"
ADMIN = "admin"
TIERS = (READ, WRITE, ADMIN)

# Extension names are the inventory keys used by the server and by Cedar entities.
EXTENSIONS = ("core",)


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
    extension: str = "core"
    write: bool = False
    capability: Capability | None = None
    arguments: tuple[ToolArgument, ...] = ()

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"{self.name}: unknown tier {self.tier!r}")
        if self.extension not in EXTENSIONS:
            raise ValueError(f"{self.name}: unknown extension {self.extension!r}")
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
    extension: str = "core",
) -> ToolSpec:
    capability = scope if isinstance(scope, Capability) else None
    return ToolSpec(
        name=name,
        description=description,
        scopes=(capability.scope if capability else scope,),
        policy_id=f"kc-{tier}-{name.replace('_', '-')}",
        tier=tier,
        extension=extension,
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
ADMIN_TOOLS = tuple(tool for tool in TOOLS if tool.tier == ADMIN)


def tools_for_extensions(installed: frozenset[str] | set[str]) -> tuple[ToolSpec, ...]:
    """Tools whose owning extension is installed (core always is)."""
    return tuple(
        tool
        for tool in TOOLS
        if tool.extension == "core" or tool.extension in installed
    )


def policy_ids() -> tuple[str, ...]:
    return tuple(tool.policy_id for tool in TOOLS)

# Implementation map

These files implement the Docker profiles described in the [verification record](acceptance.md).

## Runtime and provisioning

- `deploy/docker/compose.yaml` defines the headless Docker/SPIRE deployment: PostgreSQL, Keycloak,
  SPIRE server/agent, TLS edge, MCP, and an explicit workload check service.
- `deploy/docker/compose.interactive.yaml` adds fixture users and a pre-registered public desktop client.
  `compose.delegated.yaml` adds capability exchange clients, the private Admin bridge, and approval state.
- `deploy/docker/bootstrap.py` creates per-install secrets, certificates, SPIRE configuration and realm
  import data in named volumes. It records the profile and origin used at first install.
- `deploy/docker/Containerfile.keycloak` pins Keycloak 26.8.2 and builds with the SPIFFE provider enabled.
  `deploy/docker/Containerfile` copies the pinned SPIRE tools into the MCP runtime image.

## Authorization and dispatch

- `mcp/auth.py` verifies configured issuer, resource audience, token time claims, admitted client, and
  scopes. It derives the protected-resource metadata URL from `KC_MCP_RESOURCE_URL`.
- `mcp/tool_registry.py` is the scope, role, resource, and tool catalog. The interactive profiles use
  three capabilities for user reads, client reads and the fixture locale write.
- `mcp/server.py` applies the deployment allowlist and authorization to discovery and calls.
  `mcp/server_config.py` validates settings. The registry generates the MCP wrappers, while
  `mcp/tool_handlers.py` and `mcp/keycloak_admin.py` implement direct Admin reads.
  `mcp/pep.py`, `mcp/gen_cedar.py`, `cedar/`, and `mcp/pdp.mjs` implement and validate Cedar decisions.
- `mcp/delegation.py` obtains capability-specific SVIDs, exchanges the verified human token, and validates
  the downstream token. `deploy/docker/private-admin.conf` restricts the private gateway by method and
  route; `mcp/approval.py` checks one-time signed write approvals.

## Profile behavior

| Profile | Effective behavior |
|---|---|
| Headless | `get_extension_inventory` only; tests SPIRE authentication, TLS, Cedar permit, and missing-scope denial |
| Interactive | User/client reads based on role-eligible selected scopes; Cedar evaluates the verified user; Admin calls and writes are disabled |
| Delegated | Adds per-capability Admin reads and one approved locale update on the fixed disabled fixture |

The [protected archive branch](https://github.com/gaelnite/keycloak-mcp-security-demo/blob/archive/legacy-podman-26.8.1/docs/DEPLOYMENT.md) contains the
Keycloak 26.8.1 Podman lab and its deployment automation.

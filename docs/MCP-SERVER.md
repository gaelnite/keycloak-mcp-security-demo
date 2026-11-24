# Keycloak MCP server

The Python server supports stdio and Streamable HTTP. It verifies Keycloak
access tokens, applies scope and Cedar checks, then dispatches only registered
tools. The [Docker demo](DOCKER.md) is the reproducible live profile; see
[interactive OAuth](MCP-INTERACTIVE.md), [delegated Admin](MCP-DELEGATION.md)
and the [authorization model](AUTHZ.md) for those boundaries.

## Local entry points

Install Python and Node dependencies from the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r mcp/requirements.txt
(cd mcp && npm ci --no-audit --no-fund)
```

Configure the required issuer, resource audience and exact client allowlist, then
validate the configuration and Cedar bundle before starting HTTP:

```sh
export KC_URL=https://keycloak.example.test
export KC_ISSUER=https://keycloak.example.test/realms/demo
export KC_MCP_RESOURCE_URL=https://mcp.example.test/mcp
export KC_ALLOWED_CLIENT_IDS_FILE=/secure/path/allowed-clients.txt
.venv/bin/python mcp/server.py --check
.venv/bin/python mcp/server.py --transport http --port 8766
```

HTTP binds only to loopback. Put a TLS proxy in front of it for remote clients.
`/healthz` and configured protected-resource metadata are public; MCP endpoints
require a valid Keycloak bearer. The delegated profile requires HTTP and refuses
stdio. For OAuth discovery and challenges, see [MCP-OAUTH.md](MCP-OAUTH.md).

Stdio requires a short-lived token through `KC_MCP_ACCESS_TOKEN` or
`KC_MCP_ACCESS_TOKEN_FILE`; it has no anonymous mode:

```sh
KC_MCP_ACCESS_TOKEN_FILE=/secure/path/access-token \
  .venv/bin/python mcp/server.py --transport stdio
```

## Configuration and safety defaults

| Setting | Default or requirement | Purpose |
|---|---|---|
| `KC_URL`, `KC_ISSUER` | Required HTTPS URLs | Keycloak base and exact realm issuer. `KC_ISSUER` must be a `/realms/<name>` URL; that realm is the only one whose tokens are accepted, and it is checked against each token's `iss`. |
| `KC_MCP_RESOURCE_URL` or `KC_AUDIENCE` | One required | Canonical HTTPS MCP audience enables OAuth discovery; otherwise use a legacy bearer audience. If both are set, they must match. |
| `KC_ALLOWED_CLIENT_IDS` / `_FILE` | Required; no wildcard | Exact authorized client IDs, one per line in the file. URL-form IDs are validated without normalization. |
| `KC_JWKS_URL` | Issuer cert endpoint | HTTPS JWKS only; no redirects, a 256 KiB streaming bound, and the request never uses an ambient proxy. |
| `KC_MCP_INTERACTIVE_CLIENT_IDS` | Unset | Allowlisted user clients that use verified entitlements and per-subject principals. Requires the canonical resource URL. |
| `KC_EXTENSIONS` | `core` | Inventory labels. The six maintained tools are all core tools. |
| `KC_MCP_TOOL_ALLOWLIST` | Unset | Optional tool-name allowlist; an empty value registers no tools. |
| `KC_MCP_ENABLE_WRITES` | `0` | Write tools stay disabled. Enabling requires an approval public key. |
| `KC_MCP_APPROVAL_PUBLIC_KEY_FILE` | Unset | Ed25519 public key for operation-bound approval. The private signing key belongs outside MCP. |
| `KC_MCP_AUDIT_LOG` | Unset | Optional redacted JSONL decision log, created with mode `0600`. |
| `KC_CEDAR_TIMEOUT_MS` | `500` (range 500–2,000) | PDP deadline; timeout or PDP error denies. |

The [delegated profile](MCP-DELEGATION.md) additionally requires an explicit
private Admin URL, pinned CA, SPIRE Workload API socket and executable. Its
locale write requires a durable replay database and short, resource-bound
approval. Never expose the private Admin gateway through the public edge. The
gateway's authorization check runs in its own container, not in MCP.

## Tool and policy source

[`mcp/tool_registry.py`](../mcp/tool_registry.py) defines six tool records with
scope, tier, extension, Cedar policy ID, and public argument types and defaults. Registration respects the deployment
allowlist and write setting. Interactive entitlement and scope restrict discovery
and are checked again on each call. The normal
headless Docker profile exposes only `get_extension_inventory`.

| Source | Responsibility |
|---|---|
| [`mcp/server.py`](../mcp/server.py) | CLI, stdio/HTTP, token middleware, registration and dispatch gates. |
| [`mcp/admin_gateway.py`](../mcp/admin_gateway.py) | Checks each private Admin request for the gateway, outside the process it constrains. |
| [`mcp/server_config.py`](../mcp/server_config.py) | Configuration parsing and validation. |
| [`mcp/keycloak_admin.py`](../mcp/keycloak_admin.py), [`mcp/tool_handlers.py`](../mcp/tool_handlers.py) | Direct read client, path checks, and tool implementations. |
| [`mcp/gen_tool_wrappers.py`](../mcp/gen_tool_wrappers.py) | Generates typed wrappers that forward all calls to the common authorization gate. |
| [`mcp/auth.py`](../mcp/auth.py) | Issuer, audience, JWKS, time and client allowlist verification. |
| [`mcp/pep.py`](../mcp/pep.py), [`mcp/pdp.mjs`](../mcp/pdp.mjs) | Cedar PEP, fail-closed decisions, Node PDP and optional audit. |
| [`mcp/delegation.py`](../mcp/delegation.py) | Capability-specific exchange, token validation, route mapping and response projection. |
| [`mcp/gen_cedar.py`](../mcp/gen_cedar.py), [`cedar/`](../cedar/) | Generated policies, entities and schema. |

After changing a public tool argument, run `python3 mcp/gen_tool_wrappers.py --write`.
CI checks the generated file against the registry.

For protocol scope, the automated MCP clients negotiate `2025-11-25`. The linked
current MCP authorization specification is `2026-07-28`; the newer revision is
not claimed as tested. Live OAuth integration evidence uses the Keycloak
**26.8.2** Docker profile.

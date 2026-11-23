# Authorization model and demo profiles

This reference server verifies Keycloak access tokens, checks the caller's issued
scope, then asks Cedar whether the registered tool may run for that principal,
realm, extension and approval state. A Cedar permit alone cannot bypass a
missing token scope or entitlement.

## Checked-in deployment profiles

All three Docker profiles use Keycloak **26.8.2**, SPIRE **1.16.0** and the
repository's MCP server. The Keycloak image explicitly enables the Preview
SPIFFE provider.

| Profile | MCP surface and authorization |
|---|---|
| Headless ([DOCKER.md](DOCKER.md)) | The allowlist exposes only `get_extension_inventory`; a pre-registered workload client is allowlisted. No Admin API routes are public. |
| Interactive ([MCP-INTERACTIVE.md](MCP-INTERACTIVE.md)) | A pre-registered desktop client receives role-eligible scopes. Tool discovery follows the token's entitlement and issued scope. Admin dispatch remains disabled. |
| Delegated ([MCP-DELEGATION.md](MCP-DELEGATION.md)) | Separate SPIFFE-bound exchange clients authorize user-read, client-read and fixture-locale capabilities. Admin traffic passes through a private method/path/query gate. Locale writes also need one-time operator approval. |

The default MCP configuration requires an HTTPS Keycloak issuer, an audience
and an explicit client allowlist; it uses the issuer's HTTPS JWKS endpoint by
default. It has no anonymous token or client fallback. The headless profile maps
its workload client to a Cedar client entity;
interactive clients become user principals derived from verified issuer and
subject.

## Request checks

| Check | Source behavior |
|---|---|
| Signature | HTTPS JWKS, no redirects, bounded response; RS256 and ES256 by default. |
| Issuer and audience | Configured issuer and audience; `KC_MCP_RESOURCE_URL`, when used, must exactly match `KC_AUDIENCE`. |
| Time and size | `exp`, `iat` and optional `nbf` checked with configured clock skew; token size is capped. |
| Client | `azp` or `client_id` must exactly match `KC_ALLOWED_CLIENT_IDS` or its file. URL-form IDs are validated and preserved without normalization. |
| Permission | The actual access-token grant and, for interactive users, the Keycloak entitlement role are checked before Cedar. |
| Realm and target | Interactive requests are pinned to the verified realm; path arguments are validated before policy evaluation and dispatch. |

The authorization code flow in the desktop profile uses PKCE S256, exact
loopback redirect matching, `state` and the authorization-response issuer.
Dynamic CIMD admission is disabled in that profile.

## Cedar and failure behavior

`mcp/tool_registry.py` is the source of truth for tool scope, tier, extension and
policy ID. `mcp/gen_cedar.py` generates the checked-in Cedar bundle from that
registry. Policies deny unknown tools, cross-realm principals, missing scopes,
missing extensions and disabled or unapproved writes. Interactive tools are
filtered at discovery and checked again when called.

The PEP validates the Cedar schema, policies and entities at startup. Its PDP
deadline defaults to 500 ms (configurable up to 2,000 ms). Startup, timeout,
crash or malformed response denies the call. One PDP process serves a worker, so
the whole round trip is serialised behind a lock and every response is matched to
its request id; a response that is oversize, unterminated, unparseable or belongs
to another request kills the PDP, and the next request respawns it under a restart
budget. Decisions run on a worker thread so a slow PDP cannot stall the event loop
shared by other sessions. When file auditing is configured, a
write failure also denies; records contain decision facts and policy IDs, not
tokens, arguments or approval artifacts.

## Write and downstream boundaries

Writes default to disabled. The delegated locale write requires an Ed25519
approval public key and durable replay tracking. Each approval binds the user,
realm, tool, fixture, and selected locale. The demo fixes the target and the
set of supported locales. The approval signer is isolated from MCP.

The delegated profile exchanges the human's access token for a short-lived
capability token, then sends it only to a private Admin gateway. MCP validates
the token subject, exact Admin audience, requester, scope set, lifetime and role
ceiling. The gateway checks the HTTP method, normalized route and query before
forwarding. The public edge returns 404 for Admin routes. Keycloak's own role
checks still apply.

Implementation entry points: [`mcp/auth.py`](../mcp/auth.py),
[`mcp/server.py`](../mcp/server.py), [`mcp/pep.py`](../mcp/pep.py),
[`mcp/delegation.py`](../mcp/delegation.py), and
[`deploy/docker/private-admin.conf`](../deploy/docker/private-admin.conf).

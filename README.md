# Keycloak MCP security reference (experimental)

## Purpose

This demo shows how a Keycloak administrator can use a desktop assistant like
Codex to carry out specific tasks in Keycloak. The administrator signs in and
chooses what to allow, then can ask the assistant to look up a user or a
registered application.

The desktop client gets an OAuth access token for the MCP server with scopes
the administrator selects from their available permissions. For each tool
call, the server checks the token and uses Cedar to decide whether the call
is allowed. It then authenticates to Keycloak with its own SPIFFE identity,
issued by SPIRE, and exchanges the user's token for a separate, short-lived
token with limited permissions for the Keycloak Admin REST API. A private
gateway restricts which API requests can reach Keycloak. The demo's only
write, changing the language preference of a disabled test account, also
requires a separate, single-use approval.

[![Delegated user lookup in seven steps. Keycloak issues the user-read grant, MCP checks it with Cedar, SPIRE identifies MCP, and Keycloak exchanges the token. The private gateway forwards the read to the Admin REST API, and MCP returns the permitted user fields.](docs/assets/delegated-user-lookup.svg)](docs/MCP-DELEGATION.md)

[Interactive guide](https://github.com/gaelnite/keycloak-mcp-security-demo/blob/main/docs/mcp-auth-evolution.html) · Open the HTML locally to trace an allowed read, an approved write, and a missing-scope denial.

## Architecture

1. **Desktop grant.** A pre-registered Codex client signs in with authorization
   code and S256 PKCE. OAuth protected-resource metadata identifies the issuer.
   The authorization request identifies the intended MCP resource. Keycloak
   issues scopes from the intersection of the user's entitlement and selection.
   [MCP OAuth](docs/MCP-OAUTH.md) · [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html#section-5.1) · [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html#section-2)
2. **Tool decision.** MCP verifies the current access token and checks the issued
   scope and user entitlement. Cedar evaluates the verified principal, tool,
   and realm. The write also requires a fresh operator-signed approval.
   [Cedar authorization](docs/AUTHZ.md) · [Threat model and tests](docs/THREAT-MODEL.md)
3. **Workload and exchange.** SPIRE supplies a JWT-SVID for the selected
   capability's exchange client. Keycloak exchanges the human grant for a
   distinct, short-lived Admin token. MCP validates the subject, requester,
   audience, scopes, lifetime, and role ceiling before dispatch.
   [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1) · [Keycloak 26.8.2 evidence](docs/evidence/keycloak-26.8.2.md)
4. **Admin operation.** A private gateway constrains the method, path, and query.
   Keycloak enforces backend permissions. MCP projects read results and
   constructs the only allowed write, a locale change for a disabled fixture
   account. [Delegated credential and route boundaries](docs/MCP-DELEGATION.md#credential-and-route-boundaries)

The architecture decisions explain why the demo uses Cedar, SPIRE, one requester
per capability, single-use approvals, and a private Admin gateway.
[Architecture decisions](docs/decisions/README.md) · [Verification coverage](docs/evidence/acceptance.md)

## Limits and roadmap

The demo uses a single trusted Docker host, a synthetic realm, and Keycloak
26.8.2 with its preview SPIFFE provider. The exercised MCP protocol revision
is `2025-11-25`. Deployment recovery, automatic trust rollover, central audit
retention, and multi-host operation remain open.
[Security model](docs/SECURITY.md) · [Operational roadmap](docs/SECURITY.md#operational-roadmap)

## Quickstart

From the repository root, use Docker Compose v2 and a free loopback port.

```sh
KC_MCP_DEMO_PORT=49448 docker compose -p keycloak-mcp-delegated \
  -f deploy/docker/compose.yaml \
  -f deploy/docker/compose.interactive.yaml \
  -f deploy/docker/compose.delegated.yaml \
  up --build -d --wait
```

The installer generates fixture credentials. Export the demo CA, sign in as
helpdesk, and select `keycloak.users.read` to try an allowed read at
`https://localhost:49448/mcp`. Realm administrators can also select client
reads and the fixture locale write. With no selected scopes, desktop discovery
is empty. [Run the delegated demo](docs/MCP-DELEGATION.md) · [Desktop sign-in and scopes](docs/MCP-INTERACTIVE.md)

## Runbooks and reference

| Task | Guide |
| --- | --- |
| Verify workload authentication with an inventory read | [Headless profile](docs/DOCKER.md) |
| Try user grants with Admin dispatch disabled | [Interactive profile](docs/MCP-INTERACTIVE.md) |
| Start, stop, back up, or inspect the fixture | [Operations](docs/OPERATIONS.md) |
| Work on the server or run verification | [Server reference](docs/MCP-SERVER.md) · [Contributing](CONTRIBUTING.md) |
| Review the protocol findings and implementation | [Evidence index](docs/evidence/README.md) |
| Review the historical Podman and dynamic CIMD research | [Protected archive](https://github.com/gaelnite/keycloak-mcp-security-demo/tree/archive/legacy-podman-26.8.1) |
| Report a vulnerability privately | [Security policy](SECURITY.md) |

## Credits and license

The Cedar integration draws on the PEP/PDP pattern in
[openclaw-cedar-policy-demo](https://github.com/windley/openclaw-cedar-policy-demo).
[Third-party notices](NOTICE) · [Apache 2.0 license](LICENSE)

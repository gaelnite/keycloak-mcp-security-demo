# Security model

The showcase runs on one trusted Docker host with a synthetic Keycloak realm.
Its security question is whether a particular user, with a particular desktop
grant, may perform one operation through an authenticated MCP workload.
A Cedar permit authorizes dispatch. Keycloak still decides whether to serve
the resulting Admin request. [Delegated demo](MCP-DELEGATION.md) ·
[Threat model and verification evidence](THREAT-MODEL.md) ·
[Security design decisions](decisions/README.md)

## Which profile demonstrates which property?

| Profile | Caller and workload authentication | Operations |
| --- | --- | --- |
| Delegated Docker, Keycloak 26.8.2 | User signs in with PKCE. The MCP workload uses a SPIRE-issued JWT-SVID for each exchange. | Selected user/client reads and one approved fixture-locale write through the private Admin gateway. |
| Interactive Docker, 26.8.2 | Same user sign-in and role-scoped grants. | Discovery and Cedar decisions for the desktop user. Admin dispatch is disabled. |
| Headless Docker, 26.8.2 | A registered workload obtains a JWT-SVID and authenticates to Keycloak. | Read-only extension inventory. |

## Delegated Docker trust boundaries

| Decision | Enforcement |
| --- | --- |
| Who is the user? | Keycloak authenticates the user. The pre-registered Codex public client uses authorization code, S256 PKCE and an exact loopback callback. MCP validates the access token's signature, issuer, audience, authorized client, lifetime and subject. |
| Which tools can the user call? | Keycloak filters optional scopes by user entitlement. MCP requires the selected scope, the verified role and the configured tool. Cedar evaluates an issuer-and-subject user principal, tool and realm. An empty grant exposes zero interactive tools. |
| Which process can authenticate for exchange? | SPIRE attests the node through X.509 proof of possession. Workload registration checks a Unix UID and the digest of the executable that calls the Workload API. Each capability gets its own SPIFFE ID and Keycloak client. The same MCP workload holds these capabilities. |
| Which token reaches Admin REST? | MCP exchanges the desktop token with a fresh JWT-SVID. It validates the result's signature, human subject, exact Admin audience, requesting client, scopes, role ceiling and maximum 60-second lifetime. It sends only this distinct bearer to the private gateway. |
| Where can that token be used? | The public edge denies Admin routes. A separate loopback listener in the edge/MCP namespace asks MCP to verify the token against the HTTP method, normalized route and query. Keycloak applies backend permissions. MCP limits response fields and constructs the fixture update body. |
| Who approves a write? | A separate operator signs the actor, realm, action, tool, fixture and locale. The signer holds the private key. MCP verifies its Ed25519 signature and consumes the approval ID in SQLite before dispatch. One approval permits one attempt and expires after 90 seconds. |

The shipped Cedar policy defaults to deny. The enforcement point also denies on
evaluation diagnostics, a PDP failure or deadline, and a failed write to a
configured audit log. The delegated profile persists redacted decisions and replay
state in its approval-state volume. The headless profile does not configure a
decision log. [Authorization](AUTHZ.md) · [Policy enforcement code](../mcp/pep.py)

## What the demo trusts

- **Host and operators.** Docker administrators, the identity bridge, Keycloak,
  SPIRE, the edge and the MCP process are trusted. The edge terminates TLS and
  forwards to Keycloak over HTTP on its internal network. The route verifier
  and request-body construction rely on the MCP process. The demo does not
  isolate mutually hostile tenants on a shared host.
- **Bearer lifetime.** Access tokens and JWT-SVIDs can be reused within their
  validity windows by a holder. Local JWT verification allows an issued access
  token to outlive a role change or logout. The demo issues 40-second JWT-SVIDs
  and configures a 120-second realm access-token lifetime. Approval IDs provide
  single-use enforcement specifically for writes.
- **Installation state.** The installer creates local trust anchors, node keys,
  database credentials and fixture passwords. Restrict access to Docker and
  volume backups. Restore the database, keys and replay state together. Wait
  for outstanding approvals to expire after a rollback. Remove exported fixture
  credentials and local CA trust when retiring the demo. [Docker lifecycle](DOCKER.md)
- **Operational coverage.** The example does not exercise high availability,
  continuous CA rollover, centralized audit retention or disaster recovery.
  Scope a separate review for a shared network, a real tenant or different
  Keycloak, SPIRE or MCP versions.

## Historical research

The read-only archive preserves the Keycloak 26.8.1 lab, including script-issued
SVIDs, dynamic CIMD, caller-token passthrough, and the optional extension tools.
[Archived threat assumptions](https://github.com/gaelnite/keycloak-mcp-security-demo/blob/archive/legacy-podman-26.8.1/docs/SECURITY.md)

## Verification

The unit suite exercises JWT validation, scope and role checks, Cedar decisions,
path handling and approval replay. CI also starts each Docker profile and checks
its live contract. The delegated gate changes and restores the synthetic fixture
and checks replay after restarting MCP. [Contribution checks](../CONTRIBUTING.md) ·
[Docker CI](../.github/workflows/docker-demo.yml) · [Reporting](../SECURITY.md)

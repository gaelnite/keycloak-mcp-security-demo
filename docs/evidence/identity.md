# Identity and grant boundaries in the Docker profiles

## Credentials by profile

| Profile | Human or workload identity | Admin access |
|---|---|---|
| Headless | Pre-registered `mcp-workload`; a SPIRE JWT-SVID authenticates the MCP workload | Read-only extension inventory; no delegated Admin REST call |
| Interactive | Public Codex client uses authorization code, PKCE S256, the registered loopback callback, and a user access token | Disabled, including after a Cedar permit |
| Delegated | Same human token plus a fresh JWT-SVID; each capability has a distinct requester client and SPIFFE subject | Short-lived exchanged user token through the private Admin gateway |

The Docker client identifier is pre-registered; dynamic CIMD retrieval is not used by these profiles. The
separate legacy Podman fixture uses a local signing script and is documented in
[archived deployment guide](https://github.com/gaelnite/keycloak-mcp-security-demo/blob/archive/legacy-podman-26.8.1/docs/DEPLOYMENT.md).

## Interactive grants

The demo realm has `demo-helpdesk` and `demo-realm-admin` personas. The helpdesk role is eligible for
`keycloak.users.read`; the realm-admin role is eligible for user reads, client reads, and
`keycloak.users.locale.write`. A user may select any subset of eligible scopes. Keycloak consent and the
MCP verifier enforce the issued grant; discovery and each call use the verified user's roles and scopes.
Empty or ineligible grants expose no corresponding tools.

In the interactive profile, user and client reads are available and Admin dispatch stays disabled. In the
delegated profile, those reads use the same human subject in a capability-specific exchanged token. The
locale write targets one fixed, disabled fixture user, accepts only `en`, `de`, or `fr`, and requires a
one-time operator-signed approval. The [profile guides](../MCP-INTERACTIVE.md) and
[delegation runbook](../MCP-DELEGATION.md) describe the user flow and verification.

## Request path and boundaries

1. The TLS edge publishes the MCP resource and selected Keycloak login routes. Protected-resource metadata
   and the token verifier use the configured resource URL; untrusted forwarded host data does not set it.
2. MCP verifies token signature, issuer, expiry, audience, admitted client, subject, role claims, and scopes.
   Cedar authorizes the verified principal, tool, and realm. Tool visibility and dispatch use the same grant.
3. After a delegated call is authorized, MCP requests a short-lived JWT-SVID from the SPIRE Workload API.
   Keycloak binds each requester client to its unique SPIFFE subject and exchanges the human token for that
   capability. MCP checks the result before forwarding it.
4. The public edge returns no Admin routes. A private gateway checks the exchange token against the
   original HTTP method and constrained route before forwarding to Keycloak. MCP constructs the locale
   update body from the approved fixture ID and locale.

Docker administrators and access to the project's named volumes are inside this single-host demo's trust
boundary. The headless, interactive, and delegated profiles are isolated Compose installations; do not
reuse volumes across profiles or HTTPS origins.

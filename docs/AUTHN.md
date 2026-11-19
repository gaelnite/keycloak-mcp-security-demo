# Keycloak client and workload authentication

This guide covers the Docker authentication flows and links the archived Keycloak
26.8.1 research separately.

| Profile | Keycloak | Workload and client registration | Entry points |
|---|---|---|---|
| Docker demo (current) | 26.8.2; `spiffe` explicitly enabled in the image | SPIRE-issued JWT-SVIDs authenticate pre-registered capability clients. The interactive Codex client is also pre-registered. Dynamic CIMD retrieval is not enabled in the demo. | [`deploy/docker/Containerfile.keycloak`](../deploy/docker/Containerfile.keycloak), [`deploy/docker/bootstrap.py`](../deploy/docker/bootstrap.py), [headless](DOCKER.md), [interactive](MCP-INTERACTIVE.md), [delegated](MCP-DELEGATION.md) |

## Current Docker profile

The normal Compose profile is headless and exposes only the extension inventory
tool. The interactive profile uses a pre-registered public desktop client with
authorization code and PKCE S256. The delegated profile adds separate,
pre-registered exchange clients for user-read, client-read and fixture-locale
capabilities. Each exchange client is bound to a distinct SPIFFE ID. See the
[delegation guide](MCP-DELEGATION.md) for the exact route and approval limits.

Keycloak's SPIFFE provider is a Preview feature. The Docker image explicitly
enables it; this is a reproducible demonstration profile, not a production
recommendation. The public desktop OAuth client and workload exchange clients
have different identities and purposes. The demo does not use dynamic CIMD to
register either one.

## Archived CIMD and SVID experiments

The Keycloak 26.8.1 Podman lab used dynamic CIMD admission with a restricted
HTTPS metadata policy and a script-issued SVID. The preserved branch contains
the original settings, runbook, and tests.
[Podman lab](https://github.com/gaelnite/keycloak-mcp-security-demo/blob/archive/legacy-podman-26.8.1/docs/DEPLOYMENT.md) ·
[26.8.1 authentication results](https://github.com/gaelnite/keycloak-mcp-security-demo/blob/archive/legacy-podman-26.8.1/docs/AUTHN-RESULTS.md)

## Protocol and evidence scope

The Docker profile exercises SPIRE-backed authentication and token exchange
with pre-registered clients. Its [26.8.2 experiment](evidence/keycloak-26.8.2.md)
records version-specific results. Draft-wide interoperability remains outside
the verification scope.

[Keycloak feature flags](https://www.keycloak.org/server/features) ·
[SPIFFE client authentication draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) ·
[CIMD draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)

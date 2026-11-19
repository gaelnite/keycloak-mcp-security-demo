# Keycloak client and workload authentication

This repository has two authentication profiles. Their evidence and settings are
not interchangeable.

| Profile | Keycloak | Workload and client registration | Entry points |
|---|---|---|---|
| Docker demo (current) | 26.8.2; `spiffe` explicitly enabled in the image | SPIRE-issued JWT-SVIDs authenticate pre-registered capability clients. The interactive Codex client is also pre-registered. Dynamic CIMD retrieval is not enabled in the demo. | [`deploy/docker/Containerfile.keycloak`](../deploy/docker/Containerfile.keycloak), [`deploy/docker/bootstrap.py`](../deploy/docker/bootstrap.py), [headless](DOCKER.md), [interactive](MCP-INTERACTIVE.md), [delegated](MCP-DELEGATION.md) |
| Legacy authn lab | 26.8.1; `cimd,spiffe` enabled | CIMD policy can admit HTTPS client metadata; the separate script-minted SVID probe exercises `federated-jwt`. | [`deploy/units/keycloak-mcp-kc.container`](../deploy/units/keycloak-mcp-kc.container), [`terraform/`](../terraform/), [`scripts/authn-demo.sh`](../scripts/authn-demo.sh) |

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

## Legacy CIMD and SVID lab

The older `terraform/` and Podman/Ansible setup targets Keycloak 26.8.1. It
enables experimental CIMD and preview SPIFFE. CIMD requires both the
`client-id-metadata-document` executor profile and a matching `client-id-uri`
client policy; a feature flag alone does not enable document retrieval. The
checked-in profile restricts retrieval to HTTPS `localhost`, same-domain
metadata, requires `client_name`, and caps documents at 5,000 bytes. See
[`realm/cimd-profile.json`](../realm/cimd-profile.json) and
[`realm/cimd-policy.json`](../realm/cimd-policy.json).

That lab's `scripts/authn-demo.sh` and `scripts/mint-svid.py` use a script-minted
test identity. They are not the current Docker demo's SPIRE deployment. Do not
use the lab's CIMD settings or results as evidence for the 26.8.2 profile.

## Protocol and evidence scope

The source and tests reference SPIFFE client-auth draft -03 and CIMD draft -03.
The SPIFFE -03 live characterization is against Keycloak 26.8.1, not the current
26.8.2 Docker profile. The 26.8.2 profile has separate live exchange evidence in
[`docs/delivery/keycloak-26.8.2.md`](delivery/keycloak-26.8.2.md). Neither test
set establishes general compliance with the evolving drafts.

References: [Keycloak feature flags](https://www.keycloak.org/server/features) ·
[SPIFFE client authentication draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) ·
[CIMD draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)

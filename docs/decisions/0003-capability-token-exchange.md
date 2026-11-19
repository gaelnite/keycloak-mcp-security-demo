# Use one exchange client per capability

**Status** Accepted

## Context

The desktop bearer carries the user's grant for MCP. Admin REST needs a
separate credential for the specific downstream operation. Keycloak 26.8.2
applies the requesting client's configuration during exchange, so the
user's grant and the requester's role mapping both matter.

## Decision

Use a distinct Keycloak requester client and SPIFFE subject for user reads,
client reads, and the fixture locale write. Selected scopes place the matching
requester in the desktop token's audience set. The authenticated workload
uses that grant for OAuth token exchange. MCP requires the exchanged token to
preserve the human subject and match the expected requester, Admin audience,
capability scope set, lifespan, and role ceiling. [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693#section-2)

## Alternatives considered

- **Forward the desktop bearer to Admin REST.** The isolated 26.8.2
  experiment sent the public-client credential directly and received HTTP 401.
  Adding Admin authority to it would broaden the credential held by the desktop.
- **Share one requester with broad role mappings.** In the experiment, the
  shared requester could list users after an exchange from a grant that omitted
  the user-read scope. The decoded Admin roles were empty. The live operation
  exposed an authority difference that claim inspection alone missed.

## Evidence and cost

The later per-capability experiment verified allowed reads with actual fixture
rows, denied reads of the other collection, and rejected exchange for empty
grants. Each new capability adds a client, a SPIFFE registration, and tests of
the actual Admin operation. Keycloak's realm-specific Admin audience and
`kc-admin-api` scope are version-specific findings.
[Keycloak 26.8.2 experiment](../evidence/keycloak-26.8.2.md) ·
[Delegated verification](../../scripts/verify-delegation.py)

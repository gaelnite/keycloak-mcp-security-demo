# Keycloak 26.8.2 token exchange and Admin API authority

Isolated experiments recorded on 18 November 2026. They asked whether a
desktop user's selected scope actually limited what a separate exchange
client could do at Admin REST.

## Setup

The first fixture ran Keycloak 26.8.2 in Docker on arm64 with TLS, a per-test
CA, H2, generated users, a public PKCE client, and a confidential exchange
client. A generated client secret isolated the exchange behaviour. A second
fixture enabled the preview SPIFFE provider and used a SPIRE 1.16.0
JWT-SVID as the exchange client's assertion. SPIRE attested the node through
X.509 proof of possession and constrained the Workload API caller by Unix UID
and executable digest. A third fixture used one SPIFFE-bound requester per
capability.

The experiments used the user's bearer as the exchange subject token. The
authorization request's resource identifies MCP, while the exchange targets
the downstream service. [RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2) ·
[RFC 8693 §2.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1)

## Observations

| Configuration or request | Observed result |
| --- | --- |
| Desktop requested two scopes with one entitlement | Keycloak issued only the eligible scope. An `openid`-only grant received zero tool scopes. |
| Desktop bearer sent to Admin REST | HTTP 401. |
| Standard exchange targeted `realm-management` using MCP tool scopes | The token endpoint issued a token. Admin REST returned HTTP 401. |
| Exchange targeted the realm's Admin REST base URL and included `kc-admin-api` | Admin REST accepted the exchanged token. The fixture registered a target client with the exact Admin URL as its identifier. |
| Shared exchange requester had a fixed `view-users` mapping | A grant with only group-read or `openid` still reached the user-list operation after exchange. The decoded token's `realm-management` roles were empty. |
| SPIRE replaced the shared requester's client secret | Keycloak accepted the attested assertion and issued a distinct Admin token with the human subject preserved. The shared requester's role mapping still governed the exchange. |
| Two requester clients tried to use the same SPIFFE subject | The fixture rejected the ambiguous client binding. A distinct subject for each requester succeeded. |

The shared-requester result is the reason to verify actual backend operations,
including the returned data. A query-only role can produce HTTP 200 with an
empty collection. The tested Admin URL audience and `kc-admin-api` scope
describe Keycloak 26.8.2 behaviour and configuration.
[Keycloak upgrade guide](https://www.keycloak.org/docs/26.8.2/upgrading/index.html) ·
[Admin audience check](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/services/resources/admin/AdminRoot.java)

## Per-capability result

Each fixture client had its own SPIFFE subject, optional tool scope, requester
audience and fixed role mapping. Full Scope Allowed was disabled. Successful
reads asserted an actual fixture row. The verifier compared the incoming human
subject with the exchanged subject and checked the exact Admin audience,
requester, and outgoing scope set.

| Selected grant | Allowed | Denied |
| --- | --- | --- |
| Helpdesk requested users-read and clients-read | Users-read issued, exchanged, and read users | Clients exchange and clients collection |
| Realm admin selected clients-read | Clients exchange and client read | Users exchange and users collection |
| Realm admin selected `openid` alone | Session with zero tool scopes | Both tool exchanges |
| Realm admin selected both read scopes | Each requester read its own collection | Both credentials were denied on the other collection |

The shipped profile pairs these exchange boundaries with a private route
check. [Exchange decision](../decisions/0003-capability-token-exchange.md) ·
[Gateway decision](../decisions/0005-private-admin-gateway.md)

## Verify the shipped configuration

1. Start the delegated Docker profile in a disposable Compose project and
   install the verifier dependencies. Use the command and port from the
   [delegated runbook](../MCP-DELEGATION.md).
2. Run `scripts/verify-delegation.py` with the same project and port. The live
   probe tests both allowed collections with actual rows and denied
   cross-capability routes and exchange requests. It also checks wrong SVID
   audience and subject, the public Admin boundary, and the approved fixture
   write and replay denial. [Verifier](../../scripts/verify-delegation.py) ·
   [Admin route probe](../../deploy/docker/delegation_probe.py)
3. Use the hosted [Docker workflow](../../.github/workflows/docker-demo.yml)
   for the same gate on an isolated runner.

The commands check the shipped PostgreSQL, Cedar, SPIRE, and gateway design.
The H2 and shared-requester rows above are observations from the separate
isolated experiments. Dynamic CIMD retrieval was outside the experiment's
scope. The Docker verifier uses a fixture PKCE client and negotiates MCP
`2025-11-25`. [Verification boundaries](acceptance.md)

# Keycloak 26.8.2 protocol checks

An isolated Keycloak 26.8.2 container ran under Docker on arm64 on 18 November. It used production startup, a local H2 database, TLS with a per-test CA/certificate, generated users, a public PKCE desktop client and a separate confidential exchange client. The test client followed Keycloak's normal browser form and verified the authorization response issuer, state and S256 code exchange. This experiment used a generated confidential-client secret to isolate token semantics. A second run used SPIRE, as described below. PostgreSQL, the integrated Cedar path and an actual Codex login have their own gates.

## Observations

| Request | Observed result |
| --- | --- |
| Helpdesk requested users.read and groups.read with only the users.read entitlement | Issued only users.read plus the configured MCP audience. Realm-role restrictions on optional client scopes worked. |
| A second user eligible for both requested only groups.read | Issued only groups.read. A separate login requesting openid alone received zero tool scopes. |
| Either public-client credential used at the Admin API | HTTP 401. |
| Standard exchange with MCP resource URL as requester client ID | Accepted the subject token, returned a distinct token, preserved subject. |
| Exchange targeting realm-management with only MCP tool scopes | Exchange succeeded. Admin REST returned HTTP 401. |
| Exchange targeting the configured realm's Admin REST base URL with the built-in kc-admin-api scope at the backend | Exchange succeeded. The exchanged token had the exact Admin URL audience. Admin REST accepted it. The fixture included a target client registered with that URL. |
| The same backend client had a fixed view-users mapping | Keycloak allowed a user-list operation even when the public user had selected groups.read or openid alone. The upstream token carried zero extra tool grants. The issued backend token's decoded realm-management roles were empty. |

The last observation rules out a shared broadly role-mapped exchange client as proof of end-to-end downscoping. A signature/subject/audience check and token-role inspection alone cannot prove which Admin operations Keycloak will accept.

## Attested exchange

A second fixture removed the exchange client secret, enabled the tagged SPIFFE feature and pinned its pre-registered client to one SPIFFE subject. SPIRE 1.16.0 attested the node with x509pop using a dedicated certificate with digitalSignature key usage. The Workload API required both the numeric UID and executable digest in a shared PID namespace. The Unix attestor needed discover_workload_path enabled.

The workload obtained a 60-second JWT-SVID. The test verified its signature against the live SPIRE bundle; Keycloak fetched the bundle over TLS and accepted the assertion at the token endpoint. Standard exchange of a real human PKCE token returned HTTP 200 with the same subject, a distinct credential and the realm-specific Admin URL audience. Admin REST accepted it. This also confirmed that a stronger workload credential alone leaves the shared requester's broad role scope intact.

## Design conclusions from the experiment

The experiment kept Keycloak's Admin audience check enabled. The realm-specific Admin REST URL was the
downstream audience and `kc-admin-api` the transport scope; neither was granted to the public desktop
client. The Docker delegated profile uses capability-specific exchange clients and validates the
downstream token before dispatch. [Upgrade guide](https://www.keycloak.org/docs/26.8.2/upgrading/index.html) ·
[AdminRoot](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/services/resources/admin/AdminRoot.java)

The built-in downscope executor compared requested scopes with the subject token and restricted token-visible
client scopes during exchange. The shared-client experiment showed that a downstream-only scope cannot be
assumed to combine with the original public scopes unchanged. The profile-specific tests therefore check the
actual Admin operation, not only token claims. [Executor source](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/services/clientpolicy/executor/DownscopeAssertionGrantEnforcerExecutor.java)

The verified design used one exchange client and SPIFFE subject per capability, with fixed role mappings and
requester audiences. The empty grant produced no tool dispatch. Where an Admin role is broader than one MCP
operation, the private gateway also constrains method and route.

## Capability-specific exchange verified

A third fixture registered an exchange client per capability. Each had a unique SPIFFE subject, full-scope-allowed disabled, only its designated optional tool scope, a fixed Keycloak role mapping and the downstream-only kc-admin-api scope. Public optional scopes added the exact requester audience alongside the MCP resource. Keycloak requires an unambiguous subject-to-client binding. Reusing one SPIFFE subject for both registrations failed client authentication.

The helpdesk fixture held view-users. The second fixture held the realm-management realm-admin composite.
Both authenticated with code and S256. The verifier used a real SVID for each exchange, asserted a single
exact Admin URL audience, subject equality, exact requester and outgoing scope set, then called the real
Admin API. Positive list assertions required an actual fixture row.

| Logged-in user and selected scopes | Exchange and downstream result |
| --- | --- |
| Helpdesk requested users.read and clients.read | Keycloak issued users.read only. Its exchange received users 200 and clients 403. The clients exchange itself returned 403. |
| Realm admin selected clients.read only | Clients exchange succeeded and received clients 200 and users 403. Users exchange returned 403. |
| Realm admin selected openid only | Both tool exchanges returned 403. |
| Realm admin selected both reads | Each exchange succeeded only for its own capability. Both credentials were independently unable to read the other collection. |

These read cases exposed the importance of checking the returned resource data: query-only roles can return
200 with an empty list. Broader or overlapping Keycloak roles still need resource and route enforcement.
The delegated profile separately checks its bounded fixture write.

## Desktop registration context

The protocol experiment used a separately configured public PKCE client; it did not establish dynamic CIMD
retrieval by the current Docker profile. That profile pre-registers the Codex client identifier and callback.
Its scope-selection and login behavior are documented in [MCP-INTERACTIVE.md](../MCP-INTERACTIVE.md).

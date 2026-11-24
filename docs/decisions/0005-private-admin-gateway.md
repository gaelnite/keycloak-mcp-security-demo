# Constrain Admin requests at a private gateway

**Status** Accepted

## Context

A Keycloak Admin role can cover more operations than the MCP capability it
supports. The demo must restrict which route a delegated token reaches, even
when Keycloak would accept other operations under the assigned role.

## Decision

Deny Admin routes on the public listener. Route delegated calls through a
private loopback TLS listener. The gateway sends the original method,
normalized path, query, and bearer to the verifier before forwarding.
Keycloak still applies its Admin permissions. MCP constructs the fixture
update body and projects read responses to the documented fields.

The verifier the gateway consults is a separate container
(`mcp/admin_gateway.py`, loopback port 8802), not a route inside MCP. Serving
the check from the constrained process meant a compromised MCP could answer its
own authorization question, and it forced an unauthenticated bypass in MCP's own
middleware. The sidecar receives only the edge CA: it holds no Workload API
socket, executable or trust domain, so it cannot request an SVID and therefore
cannot mint a token the gateway would accept. `mcp/delegation.py`
refuses those credentials for a gateway configuration instead of ignoring them,
and refuses to exchange without them.

## Alternatives considered

- **Call Admin REST directly with the mapped role.** This would remove a
  proxy hop. The route restriction would then rely on the dispatcher's
  URL construction and Keycloak's role granularity.
- **Expose Admin routes on the public listener and rely on the token
  verifier.** This would make routing easier to access and would also make
  the delegated Admin surface reachable from the public listener.
- **Serve the check inside MCP.** One container less, and the exchanged token
  is already parsed there. Rejected: the gateway exists to constrain the MCP
  process, so its decision must not be code that process can rewrite.
- **Validate the locale PUT body at the gateway.** `auth_request` runs a GET
  subrequest and never carries the parent request's body, so a checker that saw
  the bytes would have to proxy the PUT itself and gain a route to Keycloak. The
  deferred position: MCP fixes both the target fixture ID and the body from the
  approved locale, and the gateway still denies the method, path and query, so a
  rewritten body would need a second compromise. Revisit when an operation with
  a client-supplied body crosses this boundary.

These are design comparisons. The 26.8.2 experiment establishes how the
tested backend role mappings affected actual Admin requests.

## Evidence and cost

The delegated probe verifies an allowed read and denies the wrong route,
method, query, and public Admin access. [`tests/test_admin_gateway.py`](../../tests/test_admin_gateway.py)
checks the sidecar's decision matrix, that it answers without calling Keycloak,
and that its configuration and Compose wiring carry no workload identity;
[`scripts/verify-delegation.py`](../../scripts/verify-delegation.py) repeats the
last two live and denies Admin traffic while the sidecar is stopped. The extra
container costs one more start dependency, and its port is a constant shared with
the generated nginx listener rather than a second setting. The boundary
assumes a trusted MCP process and host. The gateway enforces the request
route. Correct construction of the write body remains MCP's responsibility.
[Gateway configuration](../../deploy/docker/private-admin.conf) ·
[Live delegation probe](../../deploy/docker/delegation_probe.py)

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

## Alternatives considered

- **Call Admin REST directly with the mapped role.** This would remove a
  proxy hop. The route restriction would then rely on the dispatcher's
  URL construction and Keycloak's role granularity.
- **Expose Admin routes on the public listener and rely on the token
  verifier.** This would make routing easier to access and would also make
  the delegated Admin surface reachable from the public listener.

These are design comparisons. The 26.8.2 experiment establishes how the
tested backend role mappings affected actual Admin requests.

## Evidence and cost

The delegated probe verifies an allowed read and denies the wrong route,
method, query, and public Admin access. The separate listener and verifier
add configuration and another dependency for dispatch. The boundary
assumes a trusted MCP process and host. The gateway enforces the request
route. Correct construction of the write body remains MCP's responsibility.
[Gateway configuration](../../deploy/docker/private-admin.conf) ·
[Live delegation probe](../../deploy/docker/delegation_probe.py)

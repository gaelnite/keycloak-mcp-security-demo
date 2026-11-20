# Use Cedar for tool decisions

**Status** Accepted

## Context

A token scope says what the issuer granted. An MCP call also has a target
realm, a specific tool, an installed-extension state, and sometimes an
operator approval. The decision needs to use these facts consistently in
both transports and leave an audit record that identifies the policy.

## Decision

Use Cedar as the policy decision point. The server verifies the token and
checks its scope and entitlement before policy evaluation. The tool registry
supplies the facts and policy IDs used to generate the policy bundle. A
bounded local worker evaluates requests. A timeout, invalid result, evaluation
diagnostic, or failure to write a configured audit record denies dispatch.

For example, the registry generates a policy named `kc-read-get-user` for
the `get_user` tool. Its schema defines the types used in the decision.
The local worker validates the policies against that schema at startup.
When auditing is configured, the server records the determining policy IDs
returned by Cedar and the hash of the evaluated bundle.
[Generated policies](../../cedar/policies.cedar) · [Policy worker](../../mcp/pdp.mjs) · [Audit implementation](../../mcp/pep.py)

## Alternatives considered

- **Why not Keycloak Authorization Services?** Keycloak can model tools as
  protected resources and evaluate scope-based permissions with contextual
  claims. That would be a natural choice if realm administrators owned the
  tool policies. In this demo, tool definitions and authorization rules change
  together in Git. Generating policies from the registry lets a reviewer inspect
  both in one change and lets MCP evaluate the call locally before token exchange.
  Keycloak still issues tokens and enforces its own Admin API permissions.
  [Keycloak Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/index.html)
- **Why not Open Policy Agent?** Rego can express the same checks, and a team
  operating OPA could reuse its tooling. Cedar's authorization model maps
  directly to a tool call. For `get_user`, the caller is the principal,
  `Read` is the action, and the tool itself is the resource. The policy
  checks the caller's membership in the target realm supplied in the request
  context. A reviewer can follow that mapping in the generated rule.
  [OPA policy language](https://www.openpolicyagent.org/docs/policy-language)
- **Why not OpenFGA?** OpenFGA is a natural fit when access follows relationships
  such as team membership, ownership, or permissions inherited through an
  organization. It also supports conditions and contextual tuples. This demo
  checks a single realm membership and the permission the user selected for
  this session. MCP already has those facts for each call, so a separate
  relationship model would add little here.
  [OpenFGA concepts](https://openfga.dev/docs/concepts)

- **Check scopes alone.** This would keep request handling simple. It would
  leave realm, tool, and approval constraints to separate checks in each
  handler.
- **Inline all policy in Python.** This would avoid a policy worker. Rules
  would be harder to review separately from transport and dispatch code,
  and the application would have to maintain its own decision attribution.

These comparisons describe design trade-offs. The implementation and test
evidence in this repository cover Cedar.

## Evidence and cost

Real Cedar evaluations allow an in-realm read and deny a cross-realm read.
The tests also cover evaluation errors, timeouts, and audit-write failures.
The worker adds a runtime dependency and a new reason to deny an otherwise
valid call. [Policy tests](../../tests/test_policies.py) · [Enforcement](../AUTHZ.md)

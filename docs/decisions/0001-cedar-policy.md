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

## Alternatives considered

- **Check scopes alone.** This would keep request handling simple. It would
  leave realm, tool, and approval constraints to separate checks in each
  handler.
- **Inline all policy in Python.** This would avoid a policy worker. Rules
  would be harder to review separately from transport and dispatch code,
  and the application would have to maintain its own decision attribution.

These are design comparisons. The verification exercises the selected
implementation.

## Evidence and cost

Real Cedar evaluations allow an in-realm read and deny a cross-realm read.
The tests also cover evaluation errors, timeouts, and audit-write failures.
The worker adds a runtime dependency and a new reason to deny an otherwise
valid call. [Policy tests](../../tests/test_policies.py) · [Enforcement](../AUTHZ.md)

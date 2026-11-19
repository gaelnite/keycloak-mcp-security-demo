# Verification coverage

## CI coverage

| Workflow job | Coverage |
|---|---|
| `unit-tests` | Python unit suite, including Cedar evaluations |
| `cedar-policy` | Real Cedar bundle validation and generated policy/registry consistency |
| Docker headless | Compose validation/build, startup, TLS, SPIRE issuance/expiry, Cedar permit, scope denial |
| Docker interactive | Fixture login cases, role-scoped grants, token refresh, Cedar and disabled Admin dispatch |
| Docker delegated | Capability exchange, SVID and route denials, Admin projections, fixture write, approval replay after restart |

The [Docker workflow](../../.github/workflows/docker-demo.yml) runs the live checks on every pull request to `main`.
The [CI workflow](../../.github/workflows/ci.yml) runs the unit and configuration checks.

## Coverage limits

- The Docker checks use disposable single-host fixtures and generated credentials; they do not establish
  production readiness, HA, or operator-owned PKI.
- The interactive CI job uses the repository's `desktop-check` fixture client. Manual Codex CLI/app-server
  acceptance is recorded in [MCP-INTERACTIVE.md](../MCP-INTERACTIVE.md) and
  [MCP-DELEGATION.md](../MCP-DELEGATION.md); it is not the same as hosted desktop-client CI.
- CI does not rehearse full volume recovery or continuous SPIRE signing-key rollover. The Docker runbook
  records these limits in [DOCKER.md](../DOCKER.md).

The version-specific Keycloak token and Admin REST experiment is recorded in
[keycloak-26.8.2.md](keycloak-26.8.2.md); it is evidence from a separate isolated experiment, not a
substitute for the profile checks above.

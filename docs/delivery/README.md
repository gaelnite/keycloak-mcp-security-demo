# Delivery evidence

The current implementation is a Docker Compose/SPIRE reference for scoped Keycloak administration. This
folder records its design boundaries, source map, acceptance coverage, and version-specific protocol
evidence. It replaces the earlier implementation plan.

## Current profiles

| Profile | Runtime behavior | Source and guide |
|---|---|---|
| Headless | Keycloak 26.8.2, PostgreSQL 17, SPIRE 1.16, Cedar; one read-only inventory tool | `deploy/docker/compose.yaml`, [DOCKER.md](../DOCKER.md) |
| Interactive | PKCE login for a pre-registered Codex public client; role-eligible user/client read scopes; Admin dispatch disabled | `compose.interactive.yaml`, [MCP-INTERACTIVE.md](../MCP-INTERACTIVE.md) |
| Delegated | Per-capability SPIFFE exchange clients, private Admin gateway, and independently approved locale change on a fixed disabled fixture | `compose.delegated.yaml`, [MCP-DELEGATION.md](../MCP-DELEGATION.md) |
| Legacy Linux | Podman/Ansible/Terraform and script-minted SVID without SPIRE attestation | [AUTOMATION.md](../AUTOMATION.md), [DEPLOYMENT.md](../DEPLOYMENT.md) |

The default desktop demonstration is the delegated profile in the root README. The base Compose file is a
separate headless smoke profile. Docker's desktop flow pre-registers the client identifier; it does not
exercise dynamic CIMD retrieval. Keycloak's SPIFFE integration is preview.

## Verification

The hosted workflows run these checks:

- [`ci.yml`](../../.github/workflows/ci.yml): unit tests with Cedar
  evaluations, policy bundle validation and registry generation check, Terraform format/validation, and
  Ansible syntax checks.
- [`docker-demo.yml`](../../.github/workflows/docker-demo.yml): headless
  TLS/SPIRE/expiry/scope check, interactive role-scoped login and refresh checks, and delegated exchange,
  route-boundary, approval-persistence, and fixture checks.

The workflow definitions are in `.github/workflows/ci.yml` and
`.github/workflows/docker-demo.yml`; [acceptance.md](acceptance.md) lists what those gates cover and omit.
The [Keycloak 26.8.2 record](keycloak-26.8.2.md) preserves the isolated protocol experiment that informed
the capability-specific exchange design.

## Limits

These checks exercise disposable, single-host Docker fixtures. They do not establish high availability,
operator PKI, production backup recovery, continuous SPIRE signing-key rollover, or compatibility with
arbitrary Keycloak roles. The SPIRE provider remains a Keycloak preview feature. Treat the legacy
script-SVID results as separate evidence from the current SPIRE profiles.

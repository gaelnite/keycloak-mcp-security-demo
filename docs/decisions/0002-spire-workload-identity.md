# Use SPIRE for workload attestation

**Status** Accepted

## Context

The historical lab used a script-issued assertion and manual renewal. An
expired assertion interrupted verification until it was reissued. The Docker
demo needs to establish which node and process can request the assertion used
to authenticate to Keycloak.

## Decision

Use SPIRE Server and Agent. The Docker fixture uses X.509 proof of possession
for node attestation, then selects the calling workload by Unix UID and the
digest of its Workload API executable. Keycloak validates the JWT-SVID against
the SPIRE trust bundle and binds the SPIFFE subject to a registered client.

## Alternatives considered

- **Schedule the existing minting script.** A timer could reduce manual renewal.
  It would still give a process holding the signing key authority to mint the
  assertion outside an attested workload.
- **Bootstrap with a shared join token.** This would simplify initial node
  enrolment. The chosen fixture requires the node to prove possession of its
  provisioned private key. This is a design comparison.

## Evidence and cost

Headless Docker accepts a fresh assertion, rejects it after expiry, and accepts
a replacement. The delegated probe rejects assertions for the wrong audience
or capability subject. The setup depends on trusted node provisioning, the
Workload API, and the issuer's trust bundle. Expiry and renewal are covered by
the demo. Coordinated signing-key and trust-bundle rollover is separate work.
[Headless verifier](../../deploy/docker/workload.py) ·
[Delegation probe](../../deploy/docker/delegation_probe.py) ·
[Workload registration](../../deploy/docker/register.py)

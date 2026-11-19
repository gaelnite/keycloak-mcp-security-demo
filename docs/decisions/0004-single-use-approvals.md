# Sign and consume approvals once

**Status** Accepted

## Context

The demo permits an entitled user to request a locale change on one disabled
fixture account. An operator needs to approve that exact change. An approval
must survive a restart in the sense that its previous use remains recorded.

## Decision

Keep the Ed25519 signing key with the operator. Verify the signed approval
against the actor, audience, realm, action, tool, fixture, locale, and lifetime.
Atomically consume its unique ID in SQLite before dispatch. An approval grants
one attempt. If a later step fails, the next attempt requires a new approval.

## Alternatives considered

- **Treat the write scope or consent as approval.** Either would authorise a
  category of calls without recording an operator's decision for this target
  and value.
- **Keep used IDs only in memory.** A restart would discard the replay record.
  A signed expiry alone would leave the approval usable again within its
  validity window.

## Evidence and cost

Tests cover mismatched targets and competing consumers of one approval ID.
The live verification changes and restores the fixture, rejects mismatched
requests, and denies replay after MCP restarts. The operator must protect the
signer and coordinate recovery of replay state. Multi-host deployment needs
a shared atomic consumption store.
[Approval tests](../../tests/test_approval.py) ·
[Delegated verification](../../scripts/verify-delegation.py)

# Security design decisions

These records describe the choices implemented in the Docker profiles. They
distinguish observed behaviour from architectural trade-offs.

| Decision | Boundary |
| --- | --- |
| [Use Cedar for tool decisions](0001-cedar-policy.md) | Does this verified principal have authority for this tool and target? |
| [Use SPIRE for workload attestation](0002-spire-workload-identity.md) | Which process may obtain the identity Keycloak accepts? |
| [Use one exchange client per capability](0003-capability-token-exchange.md) | What downstream authority can the human grant request? |
| [Sign and consume approvals once](0004-single-use-approvals.md) | Who can authorise the exact fixture change, and for how many attempts? |
| [Constrain Admin requests at a private gateway](0005-private-admin-gateway.md) | Which REST operation can the workload send with the exchanged token? |

[Threat model and verification](../THREAT-MODEL.md)

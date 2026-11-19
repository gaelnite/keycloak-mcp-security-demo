# Docker Compose and SPIRE deployment

This is the current reference deployment. It uses Keycloak 26.8.2, PostgreSQL 17, SPIRE 1.16, a TLS edge,
and the Cedar-backed MCP server. Use Docker Engine and Compose with service build-context support. CI runs
on Linux; the documented desktop OAuth flow was also exercised on Docker Desktop for arm64.

## Profiles

| Compose files | Use | Enabled tools and checks |
|---|---|---|
| `deploy/docker/compose.yaml` | Headless workload identity smoke demo | Read-only extension inventory; SPIRE SVID, TLS, Cedar, and scope-denial check |
| Add `compose.interactive.yaml` | Role-scoped desktop OAuth | User/client reads; Admin dispatch remains disabled |
| Also add `compose.delegated.yaml` | Delegated Admin demo; this is the README quick start | User/client reads and an approved locale change to a disabled fixture user |

The interactive and delegated guides document desktop sign-in and tool grants:
[MCP-INTERACTIVE.md](MCP-INTERACTIVE.md) and [MCP-DELEGATION.md](MCP-DELEGATION.md).

Start and run the headless check:

```sh
docker compose -p keycloak-mcp -f deploy/docker/compose.yaml up --build -d --wait
docker compose -p keycloak-mcp -f deploy/docker/compose.yaml run --rm --no-deps workload
```

The edge publishes HTTPS on IPv4 loopback, default port 49443. It proxies the MCP resource and required
Keycloak login routes. Admin REST, PostgreSQL, Keycloak management, and SPIRE control/workload services
are not published to the host. Export the generated edge CA from the workload image for a client:

```sh
docker compose -p keycloak-mcp -f deploy/docker/compose.yaml run -T --rm --no-deps workload \
  -c 'print(open("/trust/edge-ca.pem").read(), end="")' > demo-ca.pem
curl --cacert demo-ca.pem https://localhost:49443/.well-known/oauth-protected-resource/mcp
```

For expiry rejection and fresh SVID issuance, run the workload check with `--expiry-check`.

## Trust and lifecycle

- First startup generates per-install TLS, database credentials, Keycloak configuration, and SPIRE state
  in named volumes. Bootstrap records the selected profile and origin and rejects incompatible reuse.
- SPIRE attests its node with X.509 proof of possession. Workload entries bind an executable digest and
  dedicated UID. The agent and workload check share a PID namespace; only the agent gets `SYS_PTRACE`.
  The workload socket is mounted read-only into clients that need it.
- Keycloak fetches the SPIRE bundle over authenticated TLS. Its SPIFFE provider is a preview feature.
  Docker administrators and volume access are inside this single-host demo's trust boundary.
- Use the same Compose project, profile, and port to resume an installation. `stop` preserves volumes;
  a different project name and unused `KC_MCP_DEMO_PORT` create a separate installation. Back up and
  restore the complete set of named volumes together, then run the smoke check before use.
- This fixture exercises JWT-SVID expiry and reissuance. Continuous signing-key rollover and full disaster
  recovery have not been rehearsed. Replace the demo and its locally trusted CA before certificate expiry.

[Keycloak production configuration](https://www.keycloak.org/server/configuration-production) ·
[SPIRE node and workload attestation](https://spiffe.io/docs/latest/deploying/configuring/)

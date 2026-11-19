# Operations: Docker/SPIRE demo

These commands operate the current Docker Compose deployment in [DOCKER.md](DOCKER.md). The default
README profile is delegated; use the exact project and Compose files from the guide that created an
installation. Do not switch a project's profile or HTTPS origin after first startup.

## Inspect and pause

For the delegated profile, use the same project name and file list as the README:

```sh
KC_MCP_DEMO_PORT=49448 docker compose -p keycloak-mcp-delegated \
  -f deploy/docker/compose.yaml \
  -f deploy/docker/compose.interactive.yaml \
  -f deploy/docker/compose.delegated.yaml ps --all
```

Use the same command with `logs --tail 100 keycloak spire-server spire-agent edge mcp` to inspect service
logs. The edge publishes only loopback HTTPS (49448 in the delegated runbook); its health route is `/healthz`, and the
protected-resource metadata is `/.well-known/oauth-protected-resource/mcp`. Keycloak Admin REST,
management, PostgreSQL, and SPIRE endpoints remain private to Docker networks.

Use `stop` to pause and preserve the installation. Re-run the same `up --build -d --wait` command to
resume it. `down` removes containers and networks; keep named volumes by omitting `-v`. Do not reuse a
project's volumes with another profile or origin.

## Backup and restore

Back up the complete set of named volumes for a project together. They contain the realm database,
bootstrap marker, TLS identity, SPIRE server/agent state, and (for delegated mode) operator signing key
and approval replay database. The [Docker guide](DOCKER.md) describes the set and trust boundary.

Restore into an isolated project with the original HTTPS origin, then wait for health checks and repeat
the profile's smoke verification before clients reconnect. A restored signer key and replay database
must remain paired. The hosted workflow does not rehearse full disaster recovery or continuous SPIRE
signing-key rollover.

## Troubleshooting

| Symptom | Check |
|---|---|
| Compose refuses to start | Run `docker compose ... config --quiet`; confirm the project profile and port match the installed volumes |
| A service stays unhealthy | Inspect `ps --all` and that service's logs; bootstrap and dependency health checks run before dependents start |
| Client rejects HTTPS | Export and trust the generated edge CA for this installation; do not disable certificate verification |
| MCP returns a scope denial | Recheck the selected scope and role in the token; the interactive guide describes eligible grants |
| Admin call fails | Confirm the delegated profile is active and repeat the delegated verification; the interactive profile intentionally disables Admin dispatch |

The old systemd/Podman runbook is [AUTOMATION.md](AUTOMATION.md); it uses script-minted SVIDs and is not
the Docker/SPIRE operational path.

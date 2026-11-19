# Legacy Linux deployment notes: Podman and Keycloak 26.8.1

> The current reference deployment is the Docker Compose/SPIRE stack in [DOCKER.md](DOCKER.md). This page
> preserves findings from the earlier Linux Podman fixture; its commands and security properties do not
> describe the current Docker profile. See [AUTOMATION.md](AUTOMATION.md) for its Ansible entry points.

## What the retained fixture does

- `ansible/playbooks/site.yml` builds `deploy/Containerfile.providers`, creates rootless Podman Quadlets,
  starts PostgreSQL and Keycloak, and installs the MCP/Cedar runtime as systemd user services.
- `terraform/main.tf` provisions the lab realm, a CIMD client, default tool scopes, and service-account
  roles. It is broader than the current interactive/delegated model.
- Ansible runs `scripts/mint-svid.py` and serves its bundle beside the CIMD document. This is a local-key
  test fixture, not SPIRE issuance or workload attestation.
- `deploy/Containerfile.providers` targets Keycloak 26.8.1, pins downloaded provider hashes, and enables
  `cimd` and `spiffe` at build time. The current `deploy/docker/Containerfile.keycloak` targets 26.8.2
  and enables SPIFFE only; it does not install those third-party JARs.

## Historical findings kept for reference

- The Podman Keycloak unit used host networking so Keycloak could fetch the CIMD document and trust bundle
  through host-loopback URLs. HTTP and HTTPS were loopback-bound; the management listener remained a lab
  exposure. See `deploy/units/keycloak-mcp-kc.container` before reusing this layout.
- Rootless UID mapping made a host-owned mode-0600 server key unreadable to Keycloak's container UID. The
  lab used mode 0644 to start. Do not copy that workaround into a deployment holding valuable credentials.
- With `--optimized`, database, health, metrics, and feature options must match the build-time settings.
  The legacy image bakes these into `kc.sh build`; changing them only at runtime caused startup failure.
- The prior Terraform smoke run against Keycloak 26.8.1 recorded a successful SVID token request with the
  expected MCP audience and scope. This is historical fixture evidence, not proof of the current Docker
  profile or a live production deployment.

For current service topology, trust, startup, and backup guidance, use [DOCKER.md](DOCKER.md). The old
fixture's provisioning scope and limitations are summarized in [TERRAFORM.md](TERRAFORM.md), and its
provider audit is in [EXTENSIONS.md](EXTENSIONS.md).

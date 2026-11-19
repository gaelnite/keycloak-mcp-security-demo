# Legacy Linux automation: Podman and Ansible

> The current Docker/SPIRE deployment is documented in [DOCKER.md](DOCKER.md) and started from the
> [README](../README.md). This page describes the retained Linux fixture only.

## Scope

`make up` and `make down` run Ansible against rootless Podman and systemd user units. The fixture uses
Keycloak 26.8.1, Terraform-managed realm objects, a CIMD endpoint, and `scripts/mint-svid.py`. Its SVID is
locally signed; it has no SPIRE agent, node attestation, or workload attestation. Do not treat it as the
Docker/SPIRE security path.

It expects Linux, rootless Podman, Ansible, Python, Node/npm, Terraform, and a systemd user manager. The
playbook checks required executables and may enable user lingering with `loginctl`.

## Run and tear down

```sh
make up
```

The playbook creates configuration under `~/.config/keycloak-mcp`, generates passwords and local TLS
certificates on first run, builds `deploy/Containerfile.providers`, installs user Quadlets, and starts
PostgreSQL and Keycloak. It installs MCP/Cedar dependencies, applies `terraform/`, applies the CIMD policy
JSON, mints the local test SVID, starts the CIMD and MCP user services, and runs `scripts/verify.sh`.
Repeated runs retain the database and Terraform-managed objects while restarting the CIMD and MCP services.

```sh
make down
```

Teardown attempts `terraform destroy` while Keycloak is up, then stops services and removes containers,
volumes, generated configuration, and local Terraform state. It keeps the built image by default. Set
`keep_volumes=true` or `keep_config=true` through `ANSIBLE_ARGS` to preserve data or configuration; set
`remove_image=true` to remove the image.

## Configuration and cautions

Defaults are in `ansible/playbooks/group_vars/all.yml`; pass overrides with `ANSIBLE_ARGS`, for example:

```sh
make up ANSIBLE_ARGS='-e kc_http_port=8081 -e kc_https_port=8543 -e mcp_port=8900'
```

Use the same overrides for `make down`. The default ports are Keycloak HTTP 8080, HTTPS 8443, management
9000, CIMD 9444, MCP 8800, and PostgreSQL 5432.

The legacy Keycloak container needs its server key readable through rootless UID mapping, so the fixture
sets that key to mode 0644. This is a lab compromise, not a production secret-handling pattern. The
configuration and teardown behavior are defined by `ansible/playbooks/site.yml` and
`ansible/playbooks/teardown.yml`; [TERRAFORM.md](TERRAFORM.md) records the legacy provisioning model.

# Legacy Terraform provisioning

The Linux Podman playbook uses Terraform to configure Keycloak 26.8.1. Docker
Compose provisions its realm from an installation-specific import.
[Podman lifecycle](AUTOMATION.md) · [Docker profiles](DOCKER.md)

The module manages the lab realm, fourteen protocol and tool scopes, a SPIFFE
identity provider, a confidential CIMD client, its audience mapper and the
`mcp-admin` role. The service account receives read roles from
`realm-management`. Its default scopes model a headless client. The recorded
26.8.1 apply created 30 resources. [Realm configuration](../terraform/main.tf)

## Provision the fixture

Run the following from the repository root against a disposable lab. Set
`TF_VAR_admin_password` in a private shell. Terraform state stays local and
contains deployment data. The module defaults to realm `lab`, Keycloak at
`https://localhost:8443` and CIMD on port 9444.

```sh
make init
make plan
make apply
KEYCLOAK_ADMIN_PASSWORD="$TF_VAR_admin_password" make policies
```

The policy executor requires typed booleans and arrays. The Make target sends
the two JSON documents through the Admin API using the installed lab CA at
`~/.config/keycloak-mcp/certs/ca.crt`. Set `KEYCLOAK_CA` to use a different CA.
The Terraform provider separately defaults to `tls_insecure_skip_verify = true`
in this legacy fixture. [Policy profile](../realm/cimd-profile.json) ·
[Client policy](../realm/cimd-policy.json) · [Module defaults](../terraform/variables.tf)

Terraform 1.6 or later is required. The lockfile records the selected provider
version. CI checks formatting and validates the module. Ansible runs the
end-to-end verifier after a live installation. [Version constraints](../terraform/versions.tf)

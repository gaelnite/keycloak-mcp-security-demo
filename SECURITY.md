# Security policy

This repository is an experimental Keycloak reference for MCP authentication and
authorization. Use an isolated installation with synthetic users and data. Security
fixes target the current `main` branch.

## Report a vulnerability

Use **Security → Report a vulnerability** when the private reporting form is
available. If the button is absent, open an issue titled **Request for a private
security contact** with no technical details. A maintainer can arrange a private
channel. [Repository security page](https://github.com/gaelnite/keycloak-mcp-security-demo/security) · [GitHub reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)

In private, include the affected commit, deployment profile, expected security
decision and observed result. Redact credentials, approval artifacts, personal
data and infrastructure addresses. This volunteer project aims to acknowledge
reports within a few working days.

## Scope

The delegated Docker profile uses real SPIRE workload attestation, a verified
user grant, Cedar authorization and a separate Keycloak Admin credential.
The legacy Podman lab uses script-issued credentials and caller-token passthrough.
The threat model describes what each profile enforces and where it depends on a
trusted operator. [Security model and limitations](docs/SECURITY.md) ·
[Threat model and verification evidence](docs/THREAT-MODEL.md)

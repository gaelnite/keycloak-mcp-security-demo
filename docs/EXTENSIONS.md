# Historical extension audit: Keycloak 26.8.1

> Audit snapshot dated 2026-10-23 for the legacy Podman image in `deploy/Containerfile.providers`. The
> current Docker image is Keycloak 26.8.2 and installs no third-party provider JARs; it enables the
> built-in SPIFFE provider in `deploy/docker/Containerfile.keycloak`.

The audit checked release artifacts and declared Keycloak versions, then pinned included downloads with
SHA-256. The findings below describe that 26.8.1 image, not compatibility with the current image or later
Keycloak releases.

## Findings retained from the snapshot

| Candidate | 26.8.1 audit result | Evidence or reason |
|---|---|---|
| netzbegruenung MFA bundle `v26.8.0-1` | Shipped in legacy image | Five shaded JARs; hashes also matched publisher SHA-512 files |
| p2-inc Magic Link `0.93` | Shipped in legacy image | POM declares Keycloak 26.8.0; no compile-scope dependencies |
| p2-inc Organizations `0.192` | Omitted | Its required SCIM classes are absent from the stock image; the legacy Containerfile warns this would break `/admin/serverinfo`. Keycloak has native Organizations |
| p2-inc Events `0.66` | Commented out | Runtime `kitchen-sink` dependency was required |
| Restrict Client Auth `26.1.1`; Home IdP `26.2.2` | Not shipped | Release artifacts predated 26.8 despite newer compatibility claims on `main` |
| Keycloak metrics SPI | Omitted | Keycloak 26 has built-in metrics; no extra provider was needed |
| `keycloak-config-cli`, `kcwarden` | External tools, not Keycloak providers | Run as separate tooling; they do not load into the Keycloak runtime |

The legacy Containerfile enabled `cimd` and `spiffe` at build time, and built with metrics enabled. CIMD
was experimental and SPIFFE preview in that target. The current Docker image explicitly enables SPIFFE;
dynamic CIMD is not part of its pre-registered desktop flow.

## Compatibility notes

- Provider JARs require `kc.sh build` before an optimized Keycloak start. The legacy image pinned the
  downloaded artifacts and restored the official image's runtime UID after copying them.
- The legacy Organizations failure is the reason that image omitted the third-party provider. Treat the
  recorded result as version-specific; do not add it to another image without rechecking its runtime
  dependencies and `/admin/serverinfo`.
- The shortlists and release dates were checked on the audit date. Recheck publisher artifacts, checksums,
  and Keycloak API compatibility before using any provider with a different target version.

Sources: `deploy/Containerfile.providers`, `deploy/docker/Containerfile.keycloak`, the
[Keycloak extensions index](https://www.keycloak.org/extensions), and the
[legacy Keycloak 26.8.1 release](https://github.com/keycloak/keycloak/releases/tag/26.8.1).

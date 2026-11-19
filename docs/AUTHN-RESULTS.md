# Historical authentication characterization

These are retained results from a separate live Keycloak **26.8.1** lab. They are
not results from the checked-in Docker profile, which uses Keycloak **26.8.2**.
The live tests skip when their lab endpoint and test fixtures are unavailable;
this document does not report a run against the current checkout.

## SPIFFE client-auth draft -03

[`tests/test_spiffe_client_auth.py`](../tests/test_spiffe_client_auth.py)
characterizes a Keycloak 26.8.1 realm with `spiffe` enabled, a pre-registered
`federated-jwt` client and a test-signed JWT-SVID. The test file records draft
-03, published 2 November 2026 and read on 5 November. The test identity is
script-minted; it does not establish live SPIRE interoperability.

| Probe in the 26.8.1 profile | Recorded result |
|---|---|
| Valid assertion | Token issued; authorized-party claim matched the registered client. |
| Missing `aud` or `exp`, expired assertion, wrong or multiple audiences | Rejected at the token endpoint. |
| Unknown or mismatched signing key; wrong or unbound SPIFFE subject | Rejected. |
| Wrong assertion type or a Keycloak access token used as an assertion | Rejected. |
| Same JWT-SVID presented twice before expiry | Accepted twice; this profile does not reject assertion replay. |
| Discovery advertises `spiffe_jwt` | Draft requirement is not met in this characterization (`expectedFailure`). |
| CIMD client request omits `client_id` | Draft requirement is not met in this characterization (`expectedFailure`). |

## CIMD draft -03

[`tests/test_cimd_lifecycle.py`](../tests/test_cimd_lifecycle.py) separately
characterizes dynamic CIMD admission in a Keycloak 26.8.1 realm with a CIMD
executor profile and matching client policy. It exercises HTTPS document fetch,
client creation, redirect handling, cache behavior, size limits and client
assertions. It is not enabled by the current Docker profile.

The live test records three draft gaps as `expectedFailure`: Keycloak returns
`unauthorized_client` instead of `invalid_client` for one rejected public-client
authentication; `cimd-restrict-same-domain` rejects a cross-domain `client_uri`;
and the fetch omits the recommended `Accept: application/json` header. The profile
also deliberately restricts accepted metadata domains and document size.

## Current Docker profile

Keycloak 26.8.2 uses the separate SPIRE-backed, per-capability exchange setup in
[`docs/delivery/keycloak-26.8.2.md`](delivery/keycloak-26.8.2.md). That evidence
covers the documented 26.8.2 fixtures and exchange behavior; it does not resolve
the draft -03 discovery or `client_id` gaps measured against 26.8.1. See
[`AUTHN.md`](AUTHN.md) for profile boundaries and entry points.

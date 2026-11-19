# Run the delegated Admin demo

This profile layers capability-specific Keycloak token exchange and a private
Admin gateway onto the interactive Docker demo. Use a fresh Compose project and
unused loopback port. The first install binds its persistent volumes to that
profile and origin. Run these commands from the repository root.

```sh
delegated_demo() {
  KC_MCP_DEMO_PORT=49448 docker compose -p keycloak-mcp-delegated \
    -f deploy/docker/compose.yaml -f deploy/docker/compose.interactive.yaml \
    -f deploy/docker/compose.delegated.yaml "$@"
}
delegated_demo up --build --wait
python3 -m venv .venv
.venv/bin/python -m pip install -r mcp/requirements.txt
.venv/bin/python scripts/verify-delegation.py --project keycloak-mcp-delegated --port 49448
```

Follow [interactive setup](MCP-INTERACTIVE.md) with port `49448` and the
`delegated_demo` command. The OAuth callback remains `http://127.0.0.1:49446/callback`.
The fixture users and disabled locale target are generated per installation.

| Scope | Delegated operation and response |
|---|---|
| `keycloak.users.read` | List users or get one by UUID in realm `lab`; fields are limited to ID, username, enabled status, and the locale fixture's locale. |
| `keycloak.clients.read` | List clients or get one unique exact client ID in realm `lab`; fields are limited to ID, client ID, protocol and enabled status. |
| `keycloak.users.locale.write` | Change only the disabled locale fixture to `en`, `de` or `fr`, with separate operator approval. The fixed target ID is defined by `LOCALE_FIXTURE_ID` in [`mcp/tool_registry.py`](../mcp/tool_registry.py). |

## Approve a locale change

1. Sign in as `demo-realm-admin` with the locale-write scope. Request
   `set_user_locale` for realm `lab`, the disabled fixture and an allowed locale.
   MCP returns an `approval_request` when no approval is supplied.
2. The operator independently checks the requester, realm, fixture and locale.
   Save the request as `approval-request.json` in the private directory created
   during desktop sign-in. Sign it in the operator container.

   ```sh
   umask 077
   delegated_demo run -T --rm --no-deps approval-signer \
     < "$demo_private/approval-request.json" > "$demo_private/approval.jwt"
   ```

3. Return the artifact through a private channel and pass it as `approval` on a
   second call with the same operation, target and locale. It expires in 90
   seconds and permits one attempt, even if exchange or update fails. Verify the
   locale with a separate read session before requesting a new approval to
   restore it. Keep both files and the approval artifact out of shared transcripts.

The signer has no network and reads its key from a separate volume. MCP mounts
only the public key; PostgreSQL and MCP do not receive the signing key. A private
SQLite database atomically records used approvals and survives MCP restarts.

## Credential and route boundaries

After Cedar permits a call, MCP requests a 40-second JWT-SVID from the SPIRE
Workload API. Each capability has its own SPIFFE subject and pre-registered
Keycloak exchange client. SPIRE binds the MCP workload to a dedicated UID and
the Workload API executable digest. The exchange preserves the human subject and
issues a distinct access token with the exact Admin audience, the selected
capability scope plus `kc-admin-api` and no refresh token. The demo configures a
45-second exchanged-token lifespan; MCP rejects tokens over 60 seconds and
validates the subject, audience, requester, scopes and role ceiling before dispatch.
[RFC 8693 §2.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1) ·
[Keycloak 26.8.2 exchange evidence](evidence/keycloak-26.8.2.md)

The desktop bearer is sent to Keycloak only as the exchange subject token. Admin
REST receives the exchanged token through a private HTTPS gateway. The public
edge returns 404 on Admin routes. The gateway checks the original HTTP method,
normalized route and restricted query before forwarding. MCP builds the locale
update from the approved locale and fixed fixture ID. Keycloak's Admin API role
checks still apply. Docker administrators and the operator-run attestation probe
are within this demo's trust boundary.

## Verification and protocol scope

[`scripts/verify-delegation.py`](../scripts/verify-delegation.py) exercises the
Keycloak **26.8.2** delegated profile with SPIRE **1.16.0**: PKCE logins,
scope-filtered reads, projected responses, wrong SVID audience/subject,
unselected and empty grants, cross-scope and cross-realm denials, public Admin
denials, approved locale change/restore, redacted admin events and replay after
MCP restart. This is profile-specific evidence, not a general Keycloak guarantee.

The automated client negotiates MCP protocol `2025-11-25`. The linked current
MCP specification is `2026-07-28`; that revision is not represented as tested by
this gate. The separately recorded Codex CLI/app-server `0.169.1` exercise is
historical client evidence, not a compatibility claim for later versions.

Use `delegated_demo stop` to preserve the stack. Back up the whole project volume
set together, including signer key and replay database. Restore into an isolated
project at the original origin and wait for outstanding approvals to expire.
See the [Docker lifecycle guide](DOCKER.md).

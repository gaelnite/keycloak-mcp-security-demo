# Select scopes for a desktop session

The interactive Docker profile adds two synthetic users, role-scoped optional
grants and a pre-registered public Codex client to the demo. Use a separate
Compose project: the first import binds persistent volumes to the profile and
HTTPS origin. For delegated Admin calls and an approved fixture write, use the
[delegated profile](MCP-DELEGATION.md).

```sh
interactive_demo() {
  KC_MCP_DEMO_PORT=49447 docker compose -p keycloak-mcp-interactive \
    -f deploy/docker/compose.yaml -f deploy/docker/compose.interactive.yaml "$@"
}
interactive_demo up --build --wait
interactive_demo run -T --rm --no-deps desktop-check
```

The profile pre-registers the [published Codex client identifier](https://chatgpt.com/oauth/codex/client.json)
and exact loopback callback `http://127.0.0.1:49446/callback`. It uses authorization
code with PKCE S256 and validates callback `state` and issuer. The profile uses
operator pre-registration; dynamic CIMD retrieval is disabled.

## Choose and consent

Export the demo CA and fixture passwords to private local files. Each fresh
installation generates new synthetic credentials.

```sh
umask 077
demo_private=$(mktemp -d)
interactive_demo exec -T edge cat /trust/edge-ca.pem > "$demo_private/demo-ca.pem"
interactive_demo run -T --rm --no-deps desktop-check export-fixtures > "$demo_private/passwords.json"
```

Trust the CA in the browser and Codex. The CLI also accepts `SSL_CERT_FILE`.
Add the MCP endpoint and OAuth details to Codex configuration:

```toml
[mcp_servers.keycloak-demo]
url = "https://localhost:49447/mcp"

[mcp_servers.keycloak-demo.oauth]
client_id = "https://chatgpt.com/oauth/codex/client.json"
resource = "https://localhost:49447/mcp"
callback_url = "http://127.0.0.1:49446/callback"
callback_port = 49446
```

Using Python 3.11 or later, install the client dependencies and run the scope chooser with the demo CA.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r mcp/requirements.txt
.venv/bin/python scripts/choose-mcp-scopes.py --port 49447 --ca "$demo_private/demo-ca.pem"
```

It opens Keycloak sign-in with `openid`, verifies the token and entitlement
claim, then prints a `codex mcp login` command for any selected subset. An empty
selection requests no tool scopes. To change the grant, log out and repeat the
chooser and login. Remove the server with `codex mcp remove keycloak-demo`.

| Persona | Eligible tool scopes | Tools exposed when entitled and selected |
|---|---|---|
| `demo-helpdesk` | `keycloak.users.read` | `list_users`, `get_user` |
| `demo-realm-admin` | `keycloak.users.read` | `list_users`, `get_user` |
| `demo-realm-admin` | `keycloak.clients.read` | `list_clients`, `get_client` |
| `demo-realm-admin` | `keycloak.users.locale.write` | Not registered in this profile; delegated profile only. |

MCP filters discovery using verified token roles and scopes, then repeats the
entitlement, realm and issued-scope checks for each call. The non-delegated
interactive profile does not dispatch user or client calls to Admin REST. Use
the delegated profile to exercise those operations. `offline_access` is not
offered by this demo; refresh rotates the token and cannot expand the original
tool grant. Session idle and maximum lifetimes are five and 15 minutes.

## Verification and protocol scope

`desktop-check` exercises the interactive Keycloak **26.8.2** profile over the
TLS edge. It checks PKCE, exact callback, issuer/state validation, token audience
and role/scope claims, discovery filtering, Cedar decisions, disabled Admin
dispatch, refresh rotation and grant-expansion denial. The delegated guide has
separate live Admin operation evidence.

The automated MCP client negotiates `2025-11-25`; the linked current MCP spec is
`2026-07-28`, which this gate does not claim to test. The recorded Codex CLI and
app-server `0.169.1` exercise is historical evidence for that client version,
not a compatibility guarantee for later versions.

Use `interactive_demo stop` to preserve the stack or `interactive_demo down` to
remove its services and network. Delete the local fixture files and remove the
demo CA trust when finished.

[Docker lifecycle](DOCKER.md) · [HTTP OAuth discovery](MCP-OAUTH.md)

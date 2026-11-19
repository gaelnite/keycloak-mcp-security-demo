# HTTP OAuth discovery and scope challenges

Set `KC_MCP_RESOURCE_URL` to the canonical HTTPS URL clients use to reach MCP.
The desktop identifies that resource in its authorization request. Tokens must
include the exact URL in `aud`. If `KC_AUDIENCE` is also set, it must match
the resource URL. Set `KC_ISSUER` to the realm issuer used for token validation
and discovery, and configure an exact client-ID allowlist.
[RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2)

```sh
export KC_URL=https://keycloak.example.test
export KC_ISSUER=https://keycloak.example.test/realms/demo
export KC_MCP_RESOURCE_URL=https://mcp.example.test/mcp
export KC_ALLOWED_CLIENT_IDS_FILE=/secure/path/allowed-clients.txt
.venv/bin/python mcp/server.py --transport http --port 8766
```

`KC_MCP_RESOURCE_URL` accepts a lowercase HTTPS host and optional path made of
unreserved URI segments. Omit a terminal slash, query, fragment, dot-segments
and credentials. An origin-only URL serves MCP at `/`. The backend binds to
loopback; terminate TLS at a reverse proxy and forward `/mcp` and
`/.well-known/oauth-protected-resource/mcp` unchanged. For nested MCP paths,
append that path to the metadata endpoint. The SDK accepts the configured public
authority or loopback hosts; discovery is built from configuration, not forwarded
headers.

```sh
curl -i https://mcp.example.test/.well-known/oauth-protected-resource/mcp
curl -i https://mcp.example.test/mcp
```

The public protected-resource metadata advertises the canonical resource, the
authorization server and bearer-header method. Unauthenticated MCP requests
receive a `401` Bearer challenge linking to the metadata. [RFC 9728 §5.1](https://www.rfc-editor.org/rfc/rfc9728.html#section-5.1)

A valid access token can initialize MCP and list tools with zero tool scopes.
In workload-only mode, discovery returns the registered inventory. With
interactive clients configured, discovery filters by token entitlement and
scope. Calls always check the actual grant.

An authenticated `tools/call` rejected for a missing scope returns HTTP `403`
with `error="insufficient_scope"`, the metadata URL and the required tool scope.
For example, `list_users` requires `keycloak.users.read`. Cedar denials, missing
roles, failed approvals and malformed tool calls remain MCP results. HTTP uses
the SDK's JSON POST response mode so a completed scope check can set the status.

For legacy bearer-only HTTP, leave `KC_MCP_RESOURCE_URL` unset and set
`KC_AUDIENCE` to the existing audience. That mode has no protected-resource
discovery or scope challenge. stdio reads `KC_MCP_ACCESS_TOKEN` or
`KC_MCP_ACCESS_TOKEN_FILE`; anonymous stdio is refused.

## Protocol and verification scope

Transport tests and the Docker client's initialize request negotiate MCP
protocol `2025-11-25`. Transport tests use local JWT, JWKS, Cedar and Admin
fixtures. The interactive Docker OAuth gate uses Keycloak **26.8.2** and the
same MCP protocol revision. The current linked MCP authorization specification
is `2026-07-28`; this checkout does not claim the newer revision was negotiated
by those gates.

[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) ·
[Current MCP HTTP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

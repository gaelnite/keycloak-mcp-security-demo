"""Exercise the interactive demo against real Keycloak and MCP over the TLS edge."""

from __future__ import annotations

import json
import os
import ssl
import sys
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import jwt

from bootstrap import origin
from desktop_oauth import DESKTOP_CLIENT_ID, DESKTOP_REDIRECT, DesktopAuthorization
from tool_registry import CAPABILITIES, CLIENTS_READ, USERS_READ, USER_LOCALE

HELPDESK = "demo-helpdesk"
REALM_ADMIN = "demo-realm-admin"
BASE = origin()
ISSUER = BASE + "/realms/lab"
RESOURCE = BASE + "/mcp"
ACCEPT = "application/json, text/event-stream"
PROTOCOL = "2025-11-25"


class KeycloakForm(HTMLParser):
    def __init__(self, html: str, form_kind: str) -> None:
        super().__init__()
        self.form_kind = form_kind
        self.action = None
        self.fields = {}
        self._in_form = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "form":
            action = fields.get("action") or ""
            self._in_form = urlsplit(action).path == f"/realms/lab/login-actions/{self.form_kind}"
            if self._in_form:
                self.action = action
        elif self._in_form and tag == "input" and fields.get("type") == "hidden" and fields.get("name"):
            self.fields[fields["name"]] = fields.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False

    def submit(self, client: httpx.Client, **data):
        url = urljoin(BASE, self.action or "")
        if not url.startswith(ISSUER + "/login-actions/"):
            raise ValueError(f"Keycloak did not return the expected {self.form_kind} form")
        return client.post(url, data={**self.fields, **data})


def tls_client():
    return httpx.Client(
        verify=ssl.create_default_context(cafile=os.environ.get("DEMO_CA_FILE", "/trust/edge-ca.pem")), trust_env=False, timeout=15,
    )


def login(passwords, user, requested, expected):
    flow = DesktopAuthorization(ISSUER, RESOURCE)
    with tls_client() as client:
        flow.validate_discovery(client)
        sign_in = client.get(flow.start_url(requested, prompt="consent"))
        assert sign_in.status_code == 200, f"Login page returned {sign_in.status_code}"
        response = KeycloakForm(sign_in.text, "authenticate").submit(client, username=user, password=passwords[user])
        if response.is_redirect:
            target = urljoin(BASE, response.headers["location"])
            if target.startswith(ISSUER + "/login-actions/required-action?"):
                response = client.get(target)
        if expected and response.status_code != 200:
            raise ValueError("Keycloak did not show consent for the requested tool grants")
        if response.status_code == 200:
            if set(requested) == expected:
                labels = unescape(response.text)
                for scope, capability in CAPABILITIES.items():
                    assert (capability.label in labels) == (scope in expected), "Consent and the selected grants differ"
            response = KeycloakForm(response.text, "consent").submit(client, accept="Yes")
        assert response.is_redirect, f"Login did not produce a callback: HTTP {response.status_code}"
        code = flow.code_from_callback(response.headers["location"])
        token_reply = client.post(flow.token_endpoint, data=flow.token_request(code))
        assert token_reply.status_code == 200, f"PKCE token request returned {token_reply.status_code}"
        tokens = token_reply.json()
    subject = assert_grant(tokens["access_token"], user, expected)
    print(f"{user}: issued {' '.join(sorted(expected)) or '(no tool scopes)'}")
    return tokens, subject


def assert_grant(access_token, user, expected):
    # Inspect claims for assertions only. The live MCP verifier authenticates each
    # token against Keycloak's JWKS on the normal HTTP entry point below.
    claims = jwt.decode(access_token, options={"verify_signature": False})
    expected_roles = {USERS_READ.role} if user == HELPDESK else {cap.role for cap in CAPABILITIES.values()}
    assert claims["iss"] == ISSUER and claims["azp"] == DESKTOP_CLIENT_ID and claims["typ"] == "Bearer"
    assert 0 < claims["exp"] - claims["iat"] <= 120
    assert set(claims["mcp_roles"]) == expected_roles
    assert set(claims["scope"].split()) == set(expected) | {"openid"}
    expected_audiences = {RESOURCE} | {CAPABILITIES[scope].requester_audience(RESOURCE) for scope in expected}
    audiences = claims["aud"]
    assert ({audiences} if isinstance(audiences, str) else set(audiences)) == expected_audiences
    assert "realm_access" not in claims and "resource_access" not in claims
    return claims["sub"]


def verify_oauth_controls():
    flow = DesktopAuthorization(ISSUER, RESOURCE)
    start_url = httpx.URL(flow.start_url([]))
    with tls_client() as client:
        endpoints = [ISSUER + "/.well-known/openid-configuration", BASE + "/.well-known/oauth-authorization-server/realms/lab"]
        for endpoint in endpoints:
            metadata = client.get(endpoint)
            assert metadata.status_code == 200
            assert "offline_access" not in metadata.json().get("scopes_supported", [])
        wrong_redirect = client.get(start_url.copy_set_param("redirect_uri", DESKTOP_REDIRECT.replace("49446", "49449")))
        assert wrong_redirect.status_code == 400
        missing_pkce = client.get(start_url.copy_remove_param("code_challenge").copy_remove_param("code_challenge_method"))
        callback = urlsplit(missing_pkce.headers.get("location", ""))
        assert missing_pkce.status_code == 400 or (missing_pkce.is_redirect and "error" in parse_qs(callback.query))


def verify_refresh(tokens, subject):
    flow = DesktopAuthorization(ISSUER, RESOURCE)
    parameters = {
        "grant_type": "refresh_token", "client_id": DESKTOP_CLIENT_ID,
        "resource": RESOURCE, "scope": f"openid {CLIENTS_READ.scope}",
    }
    previous = tokens["refresh_token"]
    with tls_client() as client:
        refreshed = client.post(flow.token_endpoint, data={**parameters, "refresh_token": previous})
        assert refreshed.status_code == 200, f"Refresh returned HTTP {refreshed.status_code}"
        fresh = refreshed.json()
        assert fresh["refresh_token"] != previous
        assert assert_grant(fresh["access_token"], REALM_ADMIN, {CLIENTS_READ.scope}) == subject
        expanded = client.post(flow.token_endpoint, data={
            **parameters, "refresh_token": fresh["refresh_token"], "scope": "openid " + " ".join(CAPABILITIES),
        })
        if expanded.status_code == 200:
            assert assert_grant(expanded.json()["access_token"], REALM_ADMIN, {CLIENTS_READ.scope}) == subject
        else:
            assert expanded.status_code == 400 and expanded.json()["error"] == "invalid_scope"
        replay = client.post(flow.token_endpoint, data={**parameters, "refresh_token": previous})
        assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    print("Refresh rotated and preserved the selected grant. Refresh upscoping and reuse denied.")


class McpSession:
    def __init__(self, client, token):
        self.client = client
        self.token = token
        self.headers = {"Accept": ACCEPT}
        self.sequence = 0
        init = self.request("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "desktop-gate", "version": "1"},
        })
        assert init.status_code == 200, f"MCP initialization returned {init.status_code}"
        assert init.json()["result"]["protocolVersion"] == PROTOCOL
        self.headers.update({"Mcp-Session-Id": init.headers["Mcp-Session-Id"], "MCP-Protocol-Version": PROTOCOL})
        assert self.request("notifications/initialized", notify=True).status_code == 202

    def request(self, method, params=None, *, token=None, notify=False):
        self.sequence += 1
        payload = {"jsonrpc": "2.0", "method": method}
        if not notify:
            payload["id"] = self.sequence
        if params is not None:
            payload["params"] = params
        return self.client.post(RESOURCE, json=payload, headers={
            **self.headers, "Authorization": f"Bearer {token or self.token}",
        })

    def visible(self, *names, token=None):
        response = self.request("tools/list", token=token)
        assert response.status_code == 200
        assert {tool["name"] for tool in response.json()["result"]["tools"]} == set(names)

    def call(self, tool, *, realm="lab", token=None, **arguments):
        return self.request("tools/call", {"name": tool, "arguments": {"realm": realm, **arguments}}, token=token)


def tool_content(response):
    result = response.json()["result"]
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def cedar_permitted(response, policy_id):
    assert response.status_code == 200
    result = tool_content(response)
    assert result["decision"] == "allow" and result["reasons"] == [policy_id]
    assert result["error"] == "Interactive Admin API dispatch is disabled for this deployment"


def no_tool(response):
    assert response.status_code == 200 and response.json()["result"]["isError"] is True
    assert "WWW-Authenticate" not in response.headers


def scope_required(response, capability):
    assert response.status_code == 403
    challenge = response.headers["WWW-Authenticate"]
    assert f'scope="{capability.scope}"' in challenge and 'error="insufficient_scope"' in challenge


def verify_matrix(passwords):
    verify_oauth_controls()
    help_tokens, help_subject = login(passwords, HELPDESK, [USERS_READ.scope], {USERS_READ.scope})
    overrequested, overrequested_subject = login(passwords, HELPDESK, list(CAPABILITIES), {USERS_READ.scope})
    admin_tokens, admin_subject = login(passwords, REALM_ADMIN, [CLIENTS_READ.scope], {CLIENTS_READ.scope})
    mixed, mixed_subject = login(passwords, REALM_ADMIN, [USERS_READ.scope, USER_LOCALE.scope], {USERS_READ.scope, USER_LOCALE.scope})
    empty, empty_subject = login(passwords, REALM_ADMIN, [], set())
    assert help_subject != admin_subject and admin_subject == mixed_subject == empty_subject
    assert help_subject == overrequested_subject
    with tls_client() as client:
        helpdesk = McpSession(client, help_tokens["access_token"])
        helpdesk.visible("list_users", "get_user")
        helpdesk.visible("list_users", "get_user", token=overrequested["access_token"])
        cedar_permitted(helpdesk.call("list_users"), "kc-read-list-users")
        ineligible = helpdesk.call("list_clients")
        assert ineligible.status_code == 200 and "WWW-Authenticate" not in ineligible.headers
        assert "not entitled" in tool_content(ineligible)["error"]
        assert "outside this grant" in tool_content(helpdesk.call("list_users", realm="other"))["error"]
        no_tool(helpdesk.call("list_realms"))

        admin = McpSession(client, admin_tokens["access_token"])
        admin.visible("list_clients", "get_client")
        cedar_permitted(admin.call("list_clients"), "kc-read-list-clients")
        scope_required(admin.call("list_users"), USERS_READ)
        assert admin.call("list_clients", token=help_tokens["access_token"]).status_code == 404
        assert admin.call("list_clients", token=admin_tokens["id_token"]).status_code == 401

        admin.visible("list_users", "get_user", token=mixed["access_token"])
        cedar_permitted(admin.call("list_users", token=mixed["access_token"]), "kc-read-list-users")
        no_tool(admin.call("set_user_locale", token=mixed["access_token"], user_id="fixture", locale="fr"))
        admin.visible(token=empty["access_token"])
        scope_required(admin.call("list_clients", token=empty["access_token"]), CLIENTS_READ)

        private_admin = client.get(BASE + "/admin/realms/lab/users", headers={
            "Authorization": f"Bearer {admin_tokens['access_token']}",
        })
        assert private_admin.status_code == 404
    verify_refresh(admin_tokens, admin_subject)
    print("Keycloak consent, exact grants, same-client principal isolation, Cedar decisions and disabled dispatch verified")


if __name__ == "__main__":
    passwords = json.loads(Path("/fixtures/passwords.json").read_text())
    if sys.argv[1:] == ["export-fixtures"]:
        # This operator-only service has Docker logging disabled. Redirect to a
        # private file as documented, with no credentials on the command line.
        print(json.dumps(passwords))
    elif not sys.argv[1:]:
        verify_matrix(passwords)
    else:
        sys.exit("Expected no arguments or export-fixtures")

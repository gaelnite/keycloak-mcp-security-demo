#!/usr/bin/env python3
"""Exercise the delegated profile, including a persisted approval across restart."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "mcp"), str(ROOT / "deploy/docker")]

from delegation import ADMIN_CHECK_PATH, ADMIN_CHECK_PORT
from desktop_oauth import DESKTOP_CLIENT_ID
from tool_registry import CLIENTS_READ, LOCALE_FIXTURE_ID, USER_LOCALE, USERS_READ


def compose(project, port):
    prefix = ["docker", "compose", "-p", project, "-f", "deploy/docker/compose.yaml",
              "-f", "deploy/docker/compose.interactive.yaml", "-f", "deploy/docker/compose.delegated.yaml"]
    environment = {**os.environ, "KC_MCP_DEMO_PORT": str(port)}

    def invoke(*args, input=None):
        process = subprocess.run(prefix + list(args), cwd=ROOT, env=environment, input=input,
                                 text=True, capture_output=True, check=False, timeout=90)
        if process.returncode:
            # Commands never carry secrets in argv. Stdin and stdout can carry
            # an approval artifact or a test token and are never printed here.
            raise RuntimeError(f"Compose {args[0]} failed with exit status {process.returncode}")
        return process.stdout

    return invoke


def exercise(invoke):
    from desktop_check import BASE, HELPDESK, REALM_ADMIN, McpSession, login, scope_required, tls_client, tool_content

    def op(*args, input=None):
        return invoke("run", "-T", "--rm", "--no-deps", *args, input=input)


    def checker_status(port):
        # Ask the loopback listeners from inside the edge network namespace, as nginx does.
        return invoke(
            "exec", "-T", "mcp", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://127.0.0.1:{port}{ADMIN_CHECK_PATH}",
        ).strip()

    def checker_lives_outside_mcp():
        # MCP answers its own port with an authentication challenge: it no longer serves
        # the Admin check at all. The sidecar answers with a denial, because a request
        # without the gateway's method/path snapshot is not an Admin request anyone can
        # reason about, and an unadorned request must never look like a permit.
        assert checker_status(8800) == "401", "MCP is still answering the Admin request check"
        assert checker_status(ADMIN_CHECK_PORT) == "403", "the Admin request checker did not deny a bare request"
        print("The private gateway's check is served outside the MCP process it constrains.")

    def gateway_denies_without_the_checker(session):
        # Fail closed: with no checker listening, the gateway forwards nothing, even for a
        # bearer that was permitted a moment ago.
        invoke("stop", "admin-gateway")
        try:
            denied = tool_content(session.call("list_users"))
            assert isinstance(denied, dict) and "error" in denied, "the private gateway forwarded without a checker"
        finally:
            invoke("up", "-d", "--wait", "--wait-timeout", "120", "admin-gateway")
        assert session.call("list_users").status_code == 200
        print("The gateway denied Admin traffic while the checker container was stopped, and recovered with it.")

    def matching_admin_updates():
        raw = invoke(
            "exec", "-T", "postgres", "sh", "-ec",
            'export PGPASSWORD=$(cat /run/db-secret/application-password); '
            'exec psql -v ON_ERROR_STOP=1 -Atq -h 127.0.0.1 -U keycloak -d keycloak "$@"', "psql",
            "-v", "requester=" + USER_LOCALE.requester_audience(BASE + "/mcp"),
            "-v", "fixture=" + f"users/{LOCALE_FIXTURE_ID}",
            input="""
SELECT count(*)
FROM admin_event_entity a
JOIN client c ON c.id = a.auth_client_id
JOIN user_entity u ON u.id = a.auth_user_id
WHERE c.client_id = :'requester' AND u.username = 'demo-realm-admin'
  AND a.operation_type = 'UPDATE' AND a.resource_path = :'fixture'
  AND a.error IS NULL AND a.representation IS NULL;
""",
        )
        return int(raw.strip())

    passwords = json.loads(op("desktop-check", "export-fixtures"))
    users, helpdesk_id = login(passwords, HELPDESK, [USERS_READ.scope], {USERS_READ.scope})
    clients, admin_id = login(passwords, REALM_ADMIN, [CLIENTS_READ.scope], {CLIENTS_READ.scope})
    write, _ = login(passwords, REALM_ADMIN, [USER_LOCALE.scope], {USER_LOCALE.scope})
    empty, _ = login(passwords, REALM_ADMIN, [], set())
    assert helpdesk_id != admin_id
    tokens = {name: packet["access_token"] for name, packet in {
        "users": users, "clients": clients, "write": write, "empty": empty,
    }.items()}
    probe = op("delegation-probe", input=json.dumps({**tokens, "helpdesk_id": helpdesk_id}))
    print(probe.strip())

    with tls_client() as http:
        user_session = McpSession(http, tokens["users"])
        client_session = McpSession(http, tokens["clients"])
        user_session.visible("list_users", "get_user")
        client_session.visible("list_clients", "get_client")
        listed_users = user_session.call("list_users")
        listed_clients = client_session.call("list_clients")
        assert listed_users.status_code == listed_clients.status_code == 200
        users_content = [json.loads(entry["text"]) for entry in listed_users.json()["result"]["content"]]
        clients_content = [json.loads(entry["text"]) for entry in listed_clients.json()["result"]["content"]]
        assert any(item.get("username") == HELPDESK for item in users_content)
        assert any(item.get("clientId") == DESKTOP_CLIENT_ID for item in clients_content)
        assert all(item.keys() <= {"id", "username", "enabled", "locale"} for item in users_content)
        assert all(item.keys() <= {"id", "clientId", "protocol", "enabled"} for item in clients_content)
        assert tool_content(client_session.call("get_client", client_id=DESKTOP_CLIENT_ID))["clientId"] == DESKTOP_CLIENT_ID
        checker_lives_outside_mcp()
        gateway_denies_without_the_checker(user_session)
        assert "not entitled" in tool_content(user_session.call("list_clients"))["error"]
        scope_required(client_session.call("list_users"), USERS_READ)
        assert "outside this grant" in tool_content(client_session.call("list_clients", realm="master"))["error"]
        McpSession(http, tokens["empty"]).visible()
        print("Both selected reads returned projected data through MCP. Ineligible, cross-scope and cross-realm calls were denied.")

        def locale():
            result = tool_content(user_session.call("get_user", user_id=LOCALE_FIXTURE_ID))
            assert result.get("enabled") is False
            return result["locale"]

        def call(session, value, **changes):
            arguments = {"user_id": LOCALE_FIXTURE_ID, "locale": value, **changes}
            return tool_content(session.call("set_user_locale", **arguments))

        def sign(request):
            return op("approval-signer", input=json.dumps(request)).strip()

        writer = McpSession(http, tokens["write"])
        writer.visible("set_user_locale")
        for legacy_tool, arguments in (
            ("magic_link_create", {"realm": "lab", "user_id": LOCALE_FIXTURE_ID}),
            ("config_cli_apply", {}),
        ):
            response = writer.request("tools/call", {"name": legacy_tool, "arguments": arguments})
            assert response.status_code == 200
            result = response.json()["result"]
            assert result["isError"] is True
            assert f"Unknown tool: {legacy_tool}" in result["content"][0]["text"]
        print("The delegated write session cannot discover or call either legacy write tool.")
        scope_required(writer.call("list_users"), USERS_READ)
        before = locale()
        starting_event_count = matching_admin_updates()
        new_locale = "de" if before != "de" else "fr"
        prompt = call(writer, new_locale)
        assert "approval is required" in prompt["error"] and locale() == before
        approval_request = prompt["approval_request"]
        assert "only the demo fixture" in call(writer, new_locale, user_id=helpdesk_id)["error"].lower()
        mismatched = sign({**approval_request, "subject": "oidc:" + "0" * 64})
        assert "different user" in call(writer, new_locale, approval=mismatched)["error"]
        valid = sign(approval_request)
        assert "different user, realm or locale" in call(writer, before, approval=valid)["error"]
        try:
            outcome = call(writer, new_locale, approval=valid)
            assert outcome.get("updated") is True and locale() == new_locale, "The fixture locale did not change"
            assert "already been used" in call(writer, new_locale, approval=valid)["error"]
            invoke("restart", "-t", "10", "mcp")
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                try:
                    if http.get(BASE + "/healthz", timeout=2).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.3)
            else:
                raise RuntimeError("MCP did not recover after restart")
            user_session = McpSession(http, tokens["users"])
            writer = McpSession(http, tokens["write"])
            assert "already been used" in call(writer, new_locale, approval=valid)["error"]
            assert locale() == new_locale
        finally:
            if locale() != before:
                restore = sign(call(writer, before)["approval_request"])
                assert call(writer, before, approval=restore).get("updated") is True and locale() == before
        assert matching_admin_updates() - starting_event_count == 2
        print("The fixture locale changed and was restored. Missing, mismatched and reused approvals were rejected across restart.")
        print("Keycloak recorded the two changes under the human subject and the locale exchange client, without payloads.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", type=int, default=49448)
    args = parser.parse_args()
    invoke = compose(args.project, args.port)
    with tempfile.TemporaryDirectory(prefix="keycloak-mcp-delegation-") as directory:
        ca = Path(directory) / "demo-ca.pem"
        ca.write_text(invoke("exec", "-T", "edge", "cat", "/trust/edge-ca.pem"))
        os.environ["DEMO_CA_FILE"] = str(ca)
        os.environ["DEMO_PORT"] = str(args.port)
        exercise(invoke)


if __name__ == "__main__":
    main()

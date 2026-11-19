"""Smoke-test Keycloak authentication and MCP authorization with a live JWT-SVID."""

import argparse
import json
import subprocess
import time

import httpx
import jwt

from bootstrap import CLIENT_ID, SCOPE, SPIFFE_ID, origin

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
WORKLOAD_SOCKET = "/run/workload/api.sock"


def fetch_assertion(audience):
    result = subprocess.run(
        ["/opt/demo/bin/spire-agent", "api", "fetch", "jwt", "-socketPath",
         WORKLOAD_SOCKET, "-audience", audience, "-spiffeID", SPIFFE_ID, "-output", "json"],
        capture_output=True, check=True, timeout=15,
    )
    records = [record for block in json.loads(result.stdout) for record in block.get("svids", [])]
    if len(records) != 1 or records[0].get("spiffe_id") != SPIFFE_ID:
        raise ValueError("Expected one JWT-SVID for the workload")
    return records[0]["svid"]


def token_response(http, issuer, assertion, scope=None):
    form = {
        "client_id": CLIENT_ID,
        "grant_type": "client_credentials",
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }
    if scope is not None:
        form["scope"] = scope
    return http.post(issuer + "/protocol/openid-connect/token", data=form)


def access_token(http, issuer, scope=None):
    response = token_response(http, issuer, fetch_assertion(issuer), scope)
    response.raise_for_status()
    result = response.json()
    if scope is not None and scope not in result.get("scope", "").split():
        raise RuntimeError("Keycloak omitted the requested workload scope")
    return result["access_token"]


def rpc(http, url, headers, method, *, params=None, request_id=None):
    message = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    return http.post(url, headers=headers, json=message)


def verify(*, expiry_check=False):
    base = origin()
    issuer = base + "/realms/lab"
    resource = base + "/mcp"
    with httpx.Client(verify="/trust/edge-ca.pem", trust_env=False) as http:
        discovery = http.get(base + "/.well-known/oauth-protected-resource/mcp")
        discovery.raise_for_status()
        assert discovery.json()["resource"] == resource
        assert discovery.json()["authorization_servers"] == [issuer]
        assert http.get(base + "/admin/realms/lab").status_code == 404
        assert http.post(resource).status_code == 401

        granted = access_token(http, issuer, SCOPE)
        headers = {"Authorization": "Bearer " + granted, "Accept": "application/json, text/event-stream"}
        initialized = rpc(http, resource, headers, "initialize", request_id=1, params={
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "keycloak-mcp-demo", "version": "1"},
        })
        initialized.raise_for_status()
        headers["MCP-Session-Id"] = initialized.headers["MCP-Session-Id"]
        headers["MCP-Protocol-Version"] = initialized.json()["result"]["protocolVersion"]
        assert rpc(http, resource, headers, "notifications/initialized").status_code == 202

        discovery_result = rpc(http, resource, headers, "tools/list", request_id=2)
        discovery_result.raise_for_status()
        assert [tool["name"] for tool in discovery_result.json()["result"]["tools"]] == ["get_extension_inventory"]

        params = {"name": "get_extension_inventory", "arguments": {}}
        allowed = rpc(http, resource, headers, "tools/call", params=params, request_id=3)
        allowed.raise_for_status()
        assert "core" in json.dumps(allowed.json()["result"])
        headers["Authorization"] = "Bearer " + access_token(http, issuer)
        denied = rpc(http, resource, headers, "tools/call", params=params, request_id=4)
        assert denied.status_code == 403
        assert f'scope="{SCOPE}"' in denied.headers["WWW-Authenticate"]
        wrong_audience = fetch_assertion(issuer + "/unused")
        assert token_response(http, issuer, wrong_audience).status_code in (400, 401)
        if expiry_check:
            initial = fetch_assertion(issuer)
            claims = jwt.decode(initial, options={"verify_signature": False})
            token_response(http, issuer, initial).raise_for_status()
            time.sleep(max(0, claims["exp"] - time.time() + 2))
            assert token_response(http, issuer, initial).status_code in (400, 401)
            renewed = fetch_assertion(issuer)
            assert renewed != initial
            token_response(http, issuer, renewed).raise_for_status()
            print("Verified expiry of a previously accepted JWT-SVID and recovery with a fresh assertion")
        print("Verified TLS, protected discovery, blocked public admin, SPIRE client authentication, Cedar and scoped denial")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expiry-check", action="store_true")
    verify(expiry_check=parser.parse_args().expiry_check)

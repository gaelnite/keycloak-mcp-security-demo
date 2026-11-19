"""Operator-only live proof of token and private gateway boundaries."""

import json
import sys

from bootstrap import TRUST_DOMAIN
from delegation import admin_audience_for, exchange_form, fetch_svid, spiffe_subject
from desktop_check import BASE, ISSUER, RESOURCE, tls_client
from tool_registry import CLIENTS_READ, LOCALE_FIXTURE_ID, USER_LOCALE, USERS_READ

PRIVATE = "https://localhost:8801/admin/realms/lab"


def assertion(capability, *, audience=ISSUER):
    return fetch_svid("/opt/demo/bin/spire-agent", "/run/workload/api.sock", spiffe_subject(TRUST_DOMAIN, capability), audience)


def exchange(client, capability, inbound, *, signed=None, scope=None):
    return client.post(ISSUER + "/protocol/openid-connect/token", data=exchange_form(
        capability.requester_audience(RESOURCE), scope or capability.scope, admin_audience_for(ISSUER, "lab"),
        inbound, signed or assertion(capability),
    ))


def verify(tokens):
    with tls_client() as client:
        for cap, key, own, wrong in (
            (USERS_READ, "users", "/users", "/clients"),
            (CLIENTS_READ, "clients", "/clients", "/users"),
        ):
            response = exchange(client, cap, tokens[key])
            assert response.status_code == 200, f"Selected {key} exchange returned {response.status_code}"
            token = response.json()["access_token"]
            assert token != tokens[key]
            headers = {"Authorization": f"Bearer {token}"}
            bounds = {"max": 1, "briefRepresentation": "true"} if cap == USERS_READ else {"max": 1}
            allowed = client.get(PRIVATE + own, headers=headers, params=bounds)
            assert allowed.status_code == 200 and len(allowed.json()) == 1
            wrong_bounds = {"max": 1} if cap == USERS_READ else {"max": 1, "briefRepresentation": "true"}
            assert client.get(PRIVATE + wrong, headers=headers, params=wrong_bounds).status_code == 403
            assert client.get(PRIVATE + wrong, headers={**headers, "X-Admin-Path": f"/admin/realms/lab{own}"}, params=wrong_bounds).status_code == 403
            assert client.get(PRIVATE + own, headers=headers, params={**bounds, "max": 51}).status_code == 403
            assert client.get(BASE + "/admin/realms/lab" + own, headers=headers).status_code == 404
        for capability, key in ((USERS_READ, "clients"), (CLIENTS_READ, "users"), (USER_LOCALE, "empty")):
            assert exchange(client, capability, tokens[key]).status_code in (400, 403)
        assert exchange(client, USERS_READ, tokens["users"], scope=CLIENTS_READ.scope).status_code in (400, 403)
        assert exchange(client, USERS_READ, tokens["users"], signed=assertion(USERS_READ, audience=ISSUER + "/unexpected")).status_code in (400, 401)
        assert exchange(client, USERS_READ, tokens["users"], signed=assertion(CLIENTS_READ)).status_code in (400, 401)
        inbound = {"Authorization": f"Bearer {tokens['users']}"}
        assert client.get(PRIVATE + "/users", headers=inbound, params={"max": 1, "briefRepresentation": "true"}).status_code == 403
        write = exchange(client, USER_LOCALE, tokens["write"])
        assert write.status_code == 200
        headers = {"Authorization": f"Bearer {write.json()['access_token']}"}
        # A live scope-valid writer cannot cross into GET or a different write
        # route even though Keycloak's manage-users role can cover more paths.
        item = PRIVATE + "/users/" + LOCALE_FIXTURE_ID
        assert client.get(item, headers=headers).status_code == 403
        assert client.post(item, headers=headers, json={}).status_code == 403
        assert client.put(item, headers=headers, params={"unexpected": "1"}, json={}).status_code == 403
        assert client.put(PRIVATE + "/users/" + tokens["helpdesk_id"], headers=headers, json={}).status_code == 403
        assert client.get(PRIVATE.replace("/lab", "/other") + "/users", headers=headers).status_code == 404
    print("Verified real SPIFFE exchange, rejected unselected scopes and assertions, and checked private gateway method/path constraints")


if __name__ == "__main__":
    verify(json.loads(sys.stdin.read(100_000)))

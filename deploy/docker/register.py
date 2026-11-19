"""Register the actual Workload API client executable with SPIRE."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

from bootstrap import DELEGATE_UID, SPIFFE_ID, SVID_TTL, TRUST_DOMAIN, WORKLOAD_UID
from delegation import spiffe_subject
from tool_registry import CAPABILITIES

SPIRE_SERVER = "/opt/demo/bin/spire-server"
SPIRE_AGENT = "/opt/demo/bin/spire-agent"
CONTROL_SOCKET = "/run/spire-control/api.sock"


def server(*args, input=None):
    result = subprocess.run(
        [SPIRE_SERVER, *args, "-socketPath", CONTROL_SOCKET, "-output", "json"],
        input=input, text=True, capture_output=True, check=True, timeout=15,
    )
    return json.loads(result.stdout)


def register_entry(parent, spiffe_id, entry_id, selectors):
    found = server("entry", "show", "-spiffeID", spiffe_id).get("entries", [])
    if not found:
        server(
            "entry", "create", "-entryID", entry_id, "-parentID", parent, "-spiffeID", spiffe_id,
            "-selector", selectors[0], "-selector", selectors[1], "-jwtSVIDTTL", str(SVID_TTL),
            "-jwtSVIDIncludeJTI", "-disableX509SVIDPrefetch",
        )
        found = server("entry", "show", "-spiffeID", spiffe_id).get("entries", [])
    if len(found) != 1:
        raise RuntimeError("Expected exactly one SPIRE entry for the demo workload")
    entry = found[0]
    current_selectors = {f"{selector['type']}:{selector['value']}" for selector in entry["selectors"]}
    if current_selectors != set(selectors) or entry["id"] != entry_id or entry.get("admin"):
        raise RuntimeError("The demo SPIRE registration differs from the installed workload")
    parent_binding = entry["parent_id"]
    if f"spiffe://{parent_binding['trust_domain']}{parent_binding['path']}" != parent:
        raise RuntimeError("The SPIRE entry is bound to a different node")
    attrs = entry.get("additional_attributes") or {}
    if entry["jwt_svid_ttl"] != SVID_TTL or not attrs.get("jwt_svid_include_jti"):
        raise RuntimeError("The SPIRE entry has an unexpected JWT-SVID lifetime or JTI policy")


def register():
    parent = Path("/trust/node-id").read_text()
    with open(SPIRE_AGENT, "rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    register_entry(parent, SPIFFE_ID, "keycloak-mcp-headless", [f"unix:uid:{WORKLOAD_UID}", f"unix:sha256:{digest}"])
    if os.environ.get("DEMO_PROFILE") == "delegated":
        with open("/delegate/spire-agent", "rb") as pinned:
            if hashlib.file_digest(pinned, "sha256").hexdigest() != digest:
                raise RuntimeError("The delegated Workload API executable differs from the installed version")
        selectors = [f"unix:uid:{DELEGATE_UID}", f"unix:sha256:{digest}"]
        for cap in CAPABILITIES.values():
            register_entry(parent, spiffe_subject(TRUST_DOMAIN, cap), cap.scope, selectors)
    print("SPIRE workload registration verified")


if __name__ == "__main__":
    register()

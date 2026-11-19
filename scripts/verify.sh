#!/usr/bin/env bash
# End-to-end verification for the Keycloak MCP reference.
# Mints the lab SVID; all service probes are read-only. Exits non-zero on failure.
set -uo pipefail
umask 077
KC="${KC:-https://localhost:8443}"
REALM="${REALM:-lab}"
MCP="${MCP:-http://127.0.0.1:8800}"
CIMD_URL="${CIMD_URL:-https://localhost:9444}"
CLIENT_ID="${CLIENT_ID:-$CIMD_URL/client-metadata.json}"
MCP_AUDIENCE="${MCP_AUDIENCE:-https://localhost:8800/mcp}"
MANAGEMENT_URL="${MANAGEMENT_URL:-https://localhost:9000}"
CADIR="${CADIR:-$HOME/.config/keycloak-mcp/certs}"
LAB="${LAB:-$(cd "$(dirname "$0")/.." && pwd)}"
OUTDIR="${OUTDIR:-$HOME/.config/keycloak-mcp/cimd}"
SVID_FILE="${SVID_FILE:-$OUTDIR/svid.jwt}"
TMP_STATE="$(mktemp -d "${TMPDIR:-/tmp}/keycloak-mcp-verify.XXXXXX")" || {
  echo "could not create private temporary directory" >&2
  exit 1
}
trap 'rm -rf "$TMP_STATE"' EXIT
TOKEN_FILE="$TMP_STATE/access-token"
MCP_HEADERS_FILE="$TMP_STATE/mcp-headers"
curl_kc() { curl --proto '=https' -sS --cacert "$CADIR/ca.crt" "$@"; }
pass=0; fail=0
ok(){ echo "PASS  $1"; pass=$((pass+1)); }
no(){ echo "FAIL  $1 ${2:-}"; fail=$((fail+1)); }
mint_svid() {
  python3 "$LAB/scripts/mint-svid.py" --outdir "$OUTDIR" mint "$@" >/dev/null 2>&1
}

# 1. Discovery advertises CIMD
flag=$(curl_kc "$KC/realms/$REALM/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin).get('client_id_metadata_document_supported'))")
[ "$flag" = "True" ] && ok "CIMD advertised in realm discovery" || no "CIMD advertised" "(got $flag)"

# 2. Health + metrics on the management interface
[ "$(curl_kc -o /dev/null -w '%{http_code}' "$MANAGEMENT_URL/health/ready")" = 200 ] && ok "keycloak health" || no "keycloak health"
[ "$(curl_kc -o /dev/null -w '%{http_code}' "$MANAGEMENT_URL/metrics")" = 200 ] && ok "native metrics" || no "native metrics"

# 3. CIMD document and SPIFFE bundle are served with the lab CA
curl_kc -o "$TMP_STATE/cimd.json" -w "%{http_code}" "$CLIENT_ID" | grep -q 200 && ok "CIMD document served" || no "CIMD document"
curl_kc -o "$TMP_STATE/bundle.json" -w "%{http_code}" "$CIMD_URL/bundle.json" | grep -q 200 && ok "SPIFFE bundle served" || no "SPIFFE bundle"

# 4. Positive SVID token, then assert claims
mint_svid --trust-domain spiffe://lab.local --subject spiffe://lab.local/workload/mcp-client --audience "$KC/realms/$REALM" || { no "mint positive SVID"; exit 1; }
request_token() {
  tr -d '\r\n' < "$SVID_FILE" | curl_kc -o "$1" -w '%{http_code}' \
    --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe \
    --data-urlencode 'client_assertion@-' "$KC/realms/$REALM/protocol/openid-connect/token"
}
code=$(request_token "$TMP_STATE/token-positive.json")
if [ "$code" = 200 ] && python3 - "$TMP_STATE/token-positive.json" "$TOKEN_FILE" "$CLIENT_ID" "$MCP_AUDIENCE" <<'PY'
import base64
import json
import sys

try:
    with open(sys.argv[1]) as f:
        response = json.load(f)
    token = response.get("access_token", "")
    if token.count(".") != 2:
        raise ValueError
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
except (OSError, ValueError, json.JSONDecodeError):
    print("  token response or access token was malformed")
    raise SystemExit(1)

need = {"aud": sys.argv[4], "azp": sys.argv[3]}
for key, expected in need.items():
    actual = claims.get(key)
    if isinstance(actual, list) and actual:
        actual = actual[0]
    if actual != expected:
        print(f"  {key} claim mismatch")
        raise SystemExit(1)
if "keycloak.realms.read" not in (claims.get("scope") or "").split():
    print("  required scope missing")
    raise SystemExit(1)
with open(sys.argv[2], "w") as f:
    f.write(token)
PY
then
  ok "SVID -> access token with aud/azp/scope"
else
  no "SVID token"
fi

# 5. Negative: a SVID minted for the wrong audience must be rejected
mint_svid --trust-domain spiffe://lab.local \
  --subject spiffe://lab.local/workload/mcp-client --audience https://wrong.example || { no "mint negative SVID"; exit 1; }
code=$(request_token "$TMP_STATE/token-negative.json")
[ "$code" = 400 ] && ok "wrong-audience SVID rejected (400)" || no "wrong-audience SVID" "(got $code)"
# restore a good SVID
mint_svid --trust-domain spiffe://lab.local \
  --subject spiffe://lab.local/workload/mcp-client --audience "$KC/realms/$REALM" || { no "restore lab SVID"; exit 1; }

# 6. MCP surface
[ "$(curl -s -o /dev/null -w '%{http_code}' "$MCP/healthz")" = 200 ] && ok "MCP healthz" || no "MCP healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MCP/mcp" -H 'Content-Type: application/json' -d '{}')" = 401 ] && ok "MCP rejects unauthenticated" || no "MCP unauthenticated 401"

if [ -s "$TOKEN_FILE" ]; then
  python3 - "$TOKEN_FILE" "$MCP_HEADERS_FILE" <<'PY'
import sys
token = open(sys.argv[1]).read().strip()
with open(sys.argv[2], "w") as f:
    f.write(f"Authorization: Bearer {token}\n")
    f.write("Content-Type: application/json\n")
    f.write("Accept: application/json, text/event-stream\n")
PY
  curl -sS -D "$TMP_STATE/mcp-response.headers" -o /dev/null -H "@$MCP_HEADERS_FILE" -X POST "$MCP/mcp" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}'
  SID=$(grep -i '^mcp-session-id:' "$TMP_STATE/mcp-response.headers" | tr -d '\r' | awk '{print $2}')
  if [ -n "$SID" ]; then
    ok "MCP initialize"
    printf 'Mcp-Session-Id: %s\n' "$SID" > "$TMP_STATE/session-header"
    curl -sS -o "$TMP_STATE/list-realms.json" -H "@$MCP_HEADERS_FILE" -H "@$TMP_STATE/session-header" -X POST "$MCP/mcp" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_realms","arguments":{}}}'
    grep -q 'displayName' "$TMP_STATE/list-realms.json" && ok "tools/call list_realms reached Keycloak" || no "tools/call list_realms" "(payload in MCP audit/log)"
    curl -sS -o "$TMP_STATE/extension-inventory.json" -H "@$MCP_HEADERS_FILE" -H "@$TMP_STATE/session-header" -X POST "$MCP/mcp" \
      -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_extension_inventory","arguments":{}}}'
    grep -q 'magic-link' "$TMP_STATE/extension-inventory.json" && ok "extension inventory reports magic-link" || no "extension inventory" "(payload in MCP audit/log)"
  else
    no "MCP initialize" "(no session id)"
  fi
fi

echo "----------------------------------------"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

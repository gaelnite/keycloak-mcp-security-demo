#!/usr/bin/env bash
# Check client authentication in the legacy Keycloak 26.8.1 Podman lab.
# Set KC, REALM, CLIENT_ID, CADIR, OUTDIR or MCP_AUDIENCE for a custom install.
# Token responses are temporary. The local fixture retains the last minted SVID.

set -uo pipefail
umask 077

KC="${KC:-https://localhost:8443}"
REALM="${REALM:-lab}"
CLIENT_ID="${CLIENT_ID:-https://localhost:9444/client-metadata.json}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://lab.local/workload/mcp-client}"
CIMD_URL="${CIMD_URL:-$CLIENT_ID}"
MCP_AUDIENCE="${MCP_AUDIENCE:-https://localhost:8800/mcp}"
export CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-${CADIR:-$HOME/.config/keycloak-mcp/certs}/ca.crt}"
SCOPE="${SCOPE:-}"
TOKEN_ENDPOINT="${KC}/realms/${REALM}/protocol/openid-connect/token"
DISCOVERY="${KC}/realms/${REALM}/.well-known/openid-configuration"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINT="${HERE}/mint-svid.py"
OUTDIR="${OUTDIR:-$HOME/.config/keycloak-mcp/cimd}"
SVID_FILE="$OUTDIR/svid.jwt"
TMP_STATE="$(mktemp -d "${TMPDIR:-/tmp}/keycloak-mcp-authn.XXXXXX")" || {
  echo "could not create private temporary directory" >&2
  exit 1
}
trap 'rm -rf "$TMP_STATE"' EXIT
FAIL=0

say()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  SKIP  %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 2; }; }
need curl
need python3
mint_svid() {
  "$MINT" --outdir "$OUTDIR" mint --trust-domain spiffe://lab.local "$@" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
say "1. Feature flags visible in realm discovery"
disc_body="$(curl -sS -m 10 "$DISCOVERY" 2>&1)" || disc_body=""
cimd_flag="$(printf '%s' "$disc_body" | python3 -c \
  'import json,sys;
try: print(json.load(sys.stdin).get("client_id_metadata_document_supported"))
except Exception: print("PARSE_ERROR")' 2>/dev/null)"
echo "  client_id_metadata_document_supported = ${cimd_flag}"
case "$cimd_flag" in
  True) ok "CIMD is enabled (feature cimd)" ;;
  None|PARSE_ERROR) bad "flag absent -- is --features=cimd set in this realm?" ;;
  *) bad "unexpected flag value: $cimd_flag" ;;
esac

# ---------------------------------------------------------------------------
say "2. Keycloak can be talked to at all"
code="$(curl -sS -o /dev/null -w '%{http_code}' -m 10 "$DISCOVERY" 2>/dev/null)"
[ "$code" = "200" ] && ok "discovery 200" || bad "discovery returned $code"

# ---------------------------------------------------------------------------
say "3. The CIMD document is served and self-consistent"
doc="$(curl -sS -m 10 "$CIMD_URL" 2>&1)" || doc=""
printf '%s' "$doc" | python3 -c '
import json,sys
url=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception as e:
    print(f"  FAIL  document is not JSON: {e}"); sys.exit(1)
sys.exit(0 if d.get("client_id")==url else 1)
' "$CIMD_URL" && ok "client_id matches the URL exactly" \
                 || bad "client_id does not match the URL (CIMD document)"

# ---------------------------------------------------------------------------
say "4. The SPIFFE bundle endpoint is served"
bundle_url="$(printf '%s' "$doc" | python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("spiffe_bundle_endpoint",""))' 2>/dev/null)"
if [ -n "$bundle_url" ]; then
  bcode="$(curl -sS -o "$TMP_STATE/svid-bundle.json" -w '%{http_code}' -m 10 "$bundle_url" 2>/dev/null)"
  [ "$bcode" = "200" ] && ok "bundle 200 ($bundle_url)" || bad "bundle returned $bcode"
  python3 - "$TMP_STATE/svid-bundle.json" <<'PY'
import json
import sys
d=json.load(open(sys.argv[1]))
keys=[k for k in d.get("keys",[]) if k.get("use")=="jwt-svid"]
sequence=d.get("spiffe_sequence")
print(f"  jwt-svid keys: {len(keys)}  spiffe_sequence={sequence}")
raise SystemExit(0 if keys else 1)
PY
  [ "$?" -eq 0 ] && ok "bundle contains use=jwt-svid keys" || bad "bundle has no jwt-svid keys"
else
  skip "no spiffe_bundle_endpoint in the document"
fi

# ---------------------------------------------------------------------------
say "5. Positive: SVID with correct aud + sub is accepted"
AUD="${KC}/realms/${REALM}"
SVID_READY=0
if mint_svid --subject "$SPIFFE_ID" --audience "$AUD"; then
  SVID_READY=1
  ok "minted SVID for $SPIFFE_ID"
else
  bad "mint-svid.py failed"
fi

post_token() { # $1=SVID file path, $2=assertion type (optional)
  local atype="${2:-urn:ietf:params:oauth:client-assertion-type:jwt-spiffe}"
  local args=(--data-urlencode "grant_type=client_credentials"
              --data-urlencode "client_id=${CLIENT_ID}"
              --data-urlencode "client_assertion_type=${atype}"
              --data-urlencode "client_assertion@-")
  [ -n "$SCOPE" ] && args+=(--data-urlencode "scope=$SCOPE")
  tr -d '\r\n' < "$1" | curl --proto '=https' -sS -o "$TMP_STATE/tok-body.json" -w '%{http_code}' -m 15 -X POST "$TOKEN_ENDPOINT" \
    -H 'Content-Type: application/x-www-form-urlencoded' "${args[@]}" 2>/dev/null
}

if [ "$SVID_READY" -eq 1 ] && [ -s "$SVID_FILE" ]; then code="$(post_token "$SVID_FILE")"; else code=""; fi
if [ "$code" = "200" ]; then
  ok "token endpoint 200"
  python3 - "$TMP_STATE/tok-body.json" "$MCP_AUDIENCE" <<'PY'
import base64, json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("  token response was malformed")
    raise SystemExit(1)
tok = d.get("access_token", "")
def pad(s): return s + "=" * (-len(s) % 4)
try:
    claims = json.loads(base64.urlsafe_b64decode(pad(tok.split(".")[1]))) if tok.count(".") == 2 else {}
except (IndexError, ValueError):
    print("  access token was malformed")
    raise SystemExit(1)
expected_aud = sys.argv[2]
aud = claims.get("aud")
aud_ok = expected_aud in (aud if isinstance(aud, list) else [aud])
print(f"  access token audience check: {'passed' if aud_ok else 'failed'}")
raise SystemExit(0 if aud_ok else 1)
PY
  [ $? -eq 0 ] && ok "access token includes the MCP audience" \
                || bad "access token lacks the MCP audience"
else
  bad "token endpoint returned $code"
fi

# ---------------------------------------------------------------------------
say "6. Negative cases (each MUST be rejected)"
neg() { # $1=label, $2=optional assertion type
  local label="$1" at="${2:-}"
  local c
  if [ -s "$SVID_FILE" ]; then
    if [ -n "$at" ]; then c="$(post_token "$SVID_FILE" "$at")"; else c="$(post_token "$SVID_FILE")"; fi
  else
    c=""
  fi
  case "$c" in
    400|401) ok "$label rejected ($c)" ;;
    *) bad "$label returned HTTP ${c:-unknown}" ;;
  esac
}

if mint_svid --subject "$SPIFFE_ID" --audience https://attacker.example; then
  neg "wrong aud"
else
  bad "wrong aud -> SVID mint failed"
fi

if mint_svid --subject spiffe://lab.local/workload/somebody-else --audience "$AUD"; then
  neg "wrong spiffe_id / sub"
else
  bad "wrong spiffe_id / sub -> SVID mint failed"
fi

if mint_svid --subject "$SPIFFE_ID" --audience "$AUD" --exp-offset -600; then
  neg "expired SVID"
else
  bad "expired SVID -> SVID mint failed"
fi

if mint_svid --subject "$SPIFFE_ID" --audience "$AUD"; then
  neg "wrong client_assertion_type" \
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
else
  bad "wrong client_assertion_type -> SVID mint failed"
fi

# ---------------------------------------------------------------------------
say "7. Optional: CIMD-created client (only if the CIMD policy is active)"
# Record the authorization response separately from token-endpoint verification.
c="$(curl -sS -o "$TMP_STATE/authz-body.txt" -w '%{http_code}' -m 15 \
  "$KC/realms/$REALM/protocol/openid-connect/auth" \
  --get --data-urlencode "client_id=$CIMD_URL" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "redirect_uri=http://localhost:8765/callback" \
  --data-urlencode "state=lab" --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" 2>/dev/null)"
echo "  authorize -> HTTP $c (informational)"

# ---------------------------------------------------------------------------
say "Result"
if [ "$FAIL" -eq 0 ]; then
  echo "  ALL CHECKS PASSED"
  exit 0
fi
echo "  $FAIL CHECK(S) FAILED"
exit 1

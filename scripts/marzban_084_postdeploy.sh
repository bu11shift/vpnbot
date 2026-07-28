#!/usr/bin/env bash
# Post-deploy checklist for Marzban 0.8.4 + XHTTP (run on server after Dokploy deploy).
#
# Required:
#   MARZ_USER MARZ_PASS HOST_ADDRESS
# Optional:
#   MARZ_URL=http://127.0.0.1:8002
#   EXPECTED_USERS=13
#   SKIP_PORT_CHECK=1
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${MARZ_USER:?set MARZ_USER}"
: "${MARZ_PASS:?set MARZ_PASS}"
: "${HOST_ADDRESS:?set HOST_ADDRESS}"

MARZ_URL="${MARZ_URL:-http://127.0.0.1:8002}"
EXPECTED_USERS="${EXPECTED_USERS:-13}"

echo "== 0) find container =="
CID="$(docker ps --format '{{.Names}}' | grep -E 'marzban' | grep -v vpn_bot | head -1 || true)"
echo "CID=${CID:-NONE}"
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' | grep -i marzban || true

echo "== 1) port 443 gate =="
if [[ "${SKIP_PORT_CHECK:-0}" != "1" ]]; then
  if command -v ss >/dev/null 2>&1 && ss -lptn 'sport = :443' 2>/dev/null | grep -q LISTEN; then
    echo "listeners on :443:"
    ss -lptn 'sport = :443' || true
    if ! docker ps --format '{{.Ports}}' | grep -qE '(:|0\.0\.0\.0:|\[::\]:)443->'; then
      echo "ERROR: host :443 is in use but marzban does not publish it. Set VPN_BIND_IP or free Traefik."
      exit 1
    fi
  fi
fi

echo "== 2) API version + user count =="
TOKEN="$(
  curl -sS -X POST "$MARZ_URL/api/admin/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${MARZ_USER}" \
    --data-urlencode "password=${MARZ_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
)"
SYS_FILE="$(mktemp)"
curl -sS -H "Authorization: Bearer $TOKEN" "$MARZ_URL/api/system" > "$SYS_FILE"
python3 - <<PY
import json
d=json.load(open("$SYS_FILE"))
print("version", d.get("version"), "total_user", d.get("total_user"))
assert str(d.get("version","")).startswith("0.8"), d
assert int(d.get("total_user") or 0) == int("$EXPECTED_USERS"), d
print("SYSTEM_OK")
PY
rm -f "$SYS_FILE"

echo "== 3) upsert XHTTP host =="
MARZ_URL="$MARZ_URL" MARZ_USER="$MARZ_USER" MARZ_PASS="$MARZ_PASS" \
  HOST_ADDRESS="$HOST_ADDRESS" \
  "$ROOT/scripts/marzban_084_upsert_xhttp_host.sh"

echo "== 4) enable XHTTP inbounds for existing users =="
MARZ_URL="$MARZ_URL" MARZ_USER="$MARZ_USER" MARZ_PASS="$MARZ_PASS" \
  "$ROOT/scripts/marzban_084_enable_xhttp_inbounds.sh"

echo "== 5) sample user links =="
SAMPLE_FILE="$(mktemp)"
curl -sS -H "Authorization: Bearer $TOKEN" "$MARZ_URL/api/users?limit=1" > "$SAMPLE_FILE"
python3 - <<PY
import json, urllib.request
token="""$TOKEN"""
url="$MARZ_URL"
users=json.load(open("$SAMPLE_FILE")).get("users") or []
assert users, "no users"
u=users[0]["username"]
req=urllib.request.Request(f"{url}/api/user/{u}", headers={"Authorization": f"Bearer {token}"})
out=json.load(urllib.request.urlopen(req))
links=out.get("links") or []
types=set()
for L in links:
    if "type=" in L:
        types.add(L.split("type=")[1].split("&")[0].lower())
print("sample_user", u, "types", sorted(types), "count", len(links))
assert "xhttp" in types, links
assert "tcp" in types or "grpc" in types, links
print("LINKS_OK")
PY
rm -f "$SAMPLE_FILE"

echo "POSTDEPLOY_OK"

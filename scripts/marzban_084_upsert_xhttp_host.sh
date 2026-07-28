#!/usr/bin/env bash
# Upsert Marzban Host row for VLESS XHTTP REALITY (keeps other inbound hosts).
#
# Required:
#   MARZ_URL MARZ_USER MARZ_PASS HOST_ADDRESS
# Optional:
#   HOST_PORT=443 HOST_REMARK=xhttp-reality
set -euo pipefail

: "${MARZ_URL:?set MARZ_URL}"
: "${MARZ_USER:?set MARZ_USER}"
: "${MARZ_PASS:?set MARZ_PASS}"
: "${HOST_ADDRESS:?set HOST_ADDRESS to public IP/DNS for XHTTP}"

HOST_PORT="${HOST_PORT:-443}"
HOST_REMARK="${HOST_REMARK:-xhttp-reality}"
TAG="VLESS XHTTP REALITY"

TOKEN="$(
  curl -sS -X POST "$MARZ_URL/api/admin/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${MARZ_USER}" \
    --data-urlencode "password=${MARZ_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
)"

HOSTS_FILE="$(mktemp)"
curl -sS -H "Authorization: Bearer $TOKEN" "$MARZ_URL/api/hosts" > "$HOSTS_FILE"

python3 - <<PY
import json, urllib.request
token = """$TOKEN"""
url = "$MARZ_URL"
tag = "$TAG"
hosts = json.load(open("$HOSTS_FILE"))
payload = {k: v for k, v in hosts.items()}
payload[tag] = [{
    "remark": "$HOST_REMARK",
    "address": "$HOST_ADDRESS",
    "port": int("$HOST_PORT"),
    "sni": "",
    "host": "",
    "path": "",
    "security": "inbound_default",
    "alpn": "",
    "fingerprint": "",
    "allowinsecure": False,
    "is_disabled": False,
    "mux_enable": False,
    "fragment_setting": "",
    "noise_setting": "",
    "random_user_agent": False,
    "use_sni_as_host": False,
}]
body = json.dumps(payload).encode()
req = urllib.request.Request(
    f"{url}/api/hosts",
    data=body,
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    method="PUT",
)
with urllib.request.urlopen(req) as r:
    out = json.load(r)
print("HOST_OK", tag, out.get(tag))
PY
rm -f "$HOSTS_FILE"

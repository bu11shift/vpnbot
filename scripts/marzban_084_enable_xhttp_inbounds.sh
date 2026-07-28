#!/usr/bin/env bash
# Enable VLESS TCP + gRPC + XHTTP inbounds on all existing Marzban users.
#
# Required env:
#   MARZ_URL   e.g. http://127.0.0.1:8002
#   MARZ_USER
#   MARZ_PASS
set -euo pipefail

: "${MARZ_URL:?set MARZ_URL (e.g. http://127.0.0.1:8002)}"
: "${MARZ_USER:?set MARZ_USER}"
: "${MARZ_PASS:?set MARZ_PASS}"

INBOUNDS_JSON="${INBOUNDS_JSON:-[\"VLESS TCP REALITY\",\"VLESS GRPC REALITY\",\"VLESS XHTTP REALITY\"]}"

TOKEN="$(
  curl -sS -X POST "$MARZ_URL/api/admin/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${MARZ_USER}" \
    --data-urlencode "password=${MARZ_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
)"

OFFSET=0
LIMIT=100
TOTAL=0
FAIL=0

while true; do
  PAGE_FILE="$(mktemp)"
  curl -sS -H "Authorization: Bearer $TOKEN" \
    "$MARZ_URL/api/users?offset=$OFFSET&limit=$LIMIT" > "$PAGE_FILE"
  COUNT="$(python3 -c "import json; d=json.load(open('$PAGE_FILE')); print(len(d.get('users') or []))")"
  if [[ "$COUNT" -eq 0 ]]; then
    rm -f "$PAGE_FILE"
    break
  fi

  FAIL_FILE="$(mktemp)"
  python3 - <<PY
import json, urllib.request
url = "$MARZ_URL"
token = """$TOKEN"""
inbounds = json.loads(r'''$INBOUNDS_JSON''')
data = json.load(open("$PAGE_FILE"))
fail = 0
for u in data.get("users") or []:
    username = u["username"]
    body = json.dumps({"inbounds": {"vless": inbounds}}).encode()
    req = urllib.request.Request(
        f"{url}/api/user/{username}",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req) as r:
            out = json.load(r)
        links = out.get("links") or []
        has_xhttp = any("type=xhttp" in (L or "").lower() for L in links)
        print(f"{username}: links={len(links)} xhttp={has_xhttp}")
        if not has_xhttp:
            fail += 1
    except Exception as e:
        print(f"{username}: ERROR {e}")
        fail += 1
open("$FAIL_FILE", "w").write(str(fail))
PY
  PAGE_FAIL="$(cat "$FAIL_FILE")"
  FAIL=$((FAIL + PAGE_FAIL))
  TOTAL=$((TOTAL + COUNT))
  rm -f "$PAGE_FILE" "$FAIL_FILE"
  OFFSET=$((OFFSET + LIMIT))
done

echo "ENABLE_DONE total_seen=$TOTAL fail=$FAIL"
if [[ "$TOTAL" -lt 1 ]]; then
  echo "ERROR: no users updated"
  exit 1
fi
if [[ "$FAIL" -gt 0 ]]; then
  echo "ERROR: some users missing xhttp links"
  exit 1
fi
echo "ENABLE_OK"

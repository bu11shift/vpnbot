#!/usr/bin/env bash
# One-time DB cutover before/during Marzban 0.8.4 deploy.
# Copies live SQLite from marz-storage (/code/db.sqlite3) into volumes/marzban
# and refuses to continue unless user count matches EXPECTED_USERS (default 13).
#
# Usage (on server, from compose project root):
#   EXPECTED_USERS=13 ./scripts/marzban_084_cutover_db.sh
#   CID=televpn-...-marzban-1 EXPECTED_USERS=13 ./scripts/marzban_084_cutover_db.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

EXPECTED_USERS="${EXPECTED_USERS:-13}"
DEST_DIR="${DEST_DIR:-$ROOT/volumes/marzban}"
DEST_DB="$DEST_DIR/db.sqlite3"
STAMP="$(date +%Y%m%d-%H%M%S)"
SAFETY_BACKUP="${SAFETY_BACKUP:-/root/backups/marzban-cutover-$STAMP}"

if [[ -z "${CID:-}" ]]; then
  CID="$(docker ps --format '{{.Names}}' | grep -E 'marzban' | grep -v vpn_bot | head -1 || true)"
fi
if [[ -z "${CID:-}" ]]; then
  echo "ERROR: marzban container not found. Set CID=..."
  exit 1
fi

echo "CID=$CID"
echo "DEST_DB=$DEST_DB"
echo "EXPECTED_USERS=$EXPECTED_USERS"

mkdir -p "$DEST_DIR" "$SAFETY_BACKUP"

# Prefer live container copy of /code/db.sqlite3 (marz-storage)
TMP_DB="$(mktemp)"
if docker cp "$CID:/code/db.sqlite3" "$TMP_DB" 2>/dev/null; then
  echo "Copied /code/db.sqlite3 from container"
else
  CODE_SRC="$(docker inspect "$CID" --format '{{range .Mounts}}{{if eq .Destination "/code"}}{{.Source}}{{end}}{{end}}')"
  if [[ -n "$CODE_SRC" && -f "$CODE_SRC/db.sqlite3" ]]; then
    cp -a "$CODE_SRC/db.sqlite3" "$TMP_DB"
    echo "Copied db from CODE_SRC=$CODE_SRC"
  else
    echo "ERROR: cannot find live db.sqlite3 in container /code or marz-storage mount"
    exit 1
  fi
fi

COUNT="$(python3 - <<PY
import sqlite3
c = sqlite3.connect("$TMP_DB")
print(c.execute("select count(*) from users").fetchone()[0])
PY
)"
echo "users_in_source=$COUNT"

if [[ "$COUNT" -lt 1 ]]; then
  echo "ERROR: source DB has 0 users — refusing cutover"
  rm -f "$TMP_DB"
  exit 1
fi

if [[ "$COUNT" -ne "$EXPECTED_USERS" ]]; then
  echo "ERROR: expected $EXPECTED_USERS users, found $COUNT"
  echo "Set EXPECTED_USERS=$COUNT if this count is correct, then re-run."
  rm -f "$TMP_DB"
  exit 1
fi

# Safety copies
cp -a "$TMP_DB" "$SAFETY_BACKUP/db.sqlite3"
docker inspect "$CID" --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' > "$SAFETY_BACKUP/mounts.txt" || true
if [[ -f "$DEST_DB" ]]; then
  cp -a "$DEST_DB" "$SAFETY_BACKUP/db.sqlite3.prev-dest"
fi

cp -a "$TMP_DB" "$DEST_DB"
rm -f "$TMP_DB"

VERIFY="$(python3 - <<PY
import sqlite3
c = sqlite3.connect("$DEST_DB")
print(c.execute("select count(*) from users").fetchone()[0])
PY
)"
echo "users_in_dest=$VERIFY"
if [[ "$VERIFY" -ne "$EXPECTED_USERS" ]]; then
  echo "ERROR: destination verify failed"
  exit 1
fi

echo "CUTOVER_OK dest=$DEST_DB users=$VERIFY safety=$SAFETY_BACKUP"
echo "Next: recreate marzban with new compose (SQLALCHEMY -> /var/lib/marzban/db.sqlite3)"

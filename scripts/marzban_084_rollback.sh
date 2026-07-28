#!/usr/bin/env bash
# Rollback Marzban 0.8.4 + XHTTP using a PRODUCTION backup directory.
#
# Required:
#   BACKUP=/root/backups/marzban-users-YYYYMMDD-HHMMSS
# Optional:
#   CID=...  (auto-detected)
#
# Backup dir must contain at least:
#   db.sqlite3  (or db-from-code-volume.sqlite3)
#   xray_config.json.pre084  OR host-var-lib-marzban/xray_config.json
# And preferably docker-compose.yml.pre084 if rolling compose files in-repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${BACKUP:-}" ]]; then
  echo "ERROR: set BACKUP=/root/backups/marzban-users-... (production backup path)"
  echo "Do NOT use local smoke backups under ./backups/"
  exit 1
fi
if [[ ! -d "$BACKUP" ]]; then
  echo "ERROR: BACKUP dir not found: $BACKUP"
  exit 1
fi

DB_SRC=""
for cand in "$BACKUP/db.sqlite3" "$BACKUP/db-from-code-volume.sqlite3"; do
  if [[ -f "$cand" ]]; then DB_SRC="$cand"; break; fi
done
if [[ -z "$DB_SRC" ]]; then
  echo "ERROR: no db.sqlite3 in $BACKUP"
  exit 1
fi

XRAY_SRC=""
for cand in \
  "$BACKUP/xray_config.json.pre084" \
  "$BACKUP/host-var-lib-marzban/xray_config.json" \
  "$BACKUP/var-lib-marzban/xray_config.json"
do
  if [[ -f "$cand" ]]; then XRAY_SRC="$cand"; break; fi
done
if [[ -z "$XRAY_SRC" ]]; then
  echo "ERROR: no pre-XHTTP xray_config in $BACKUP"
  exit 1
fi

USERS="$(python3 - <<PY
import sqlite3
print(sqlite3.connect("$DB_SRC").execute("select count(*) from users").fetchone()[0])
PY
)"
echo "rollback_source_users=$USERS"
if [[ "$USERS" -lt 1 ]]; then
  echo "ERROR: backup DB has 0 users — refusing rollback"
  exit 1
fi

if [[ -z "${CID:-}" ]]; then
  CID="$(docker ps --format '{{.Names}}' | grep -E 'marzban' | grep -v vpn_bot | head -1 || true)"
fi

echo "Stopping marzban (${CID:-none})"
if [[ -n "${CID:-}" ]]; then
  docker stop "$CID" || true
else
  docker compose stop marzban || true
fi

mkdir -p "$ROOT/volumes/marzban"
cp -a "$DB_SRC" "$ROOT/volumes/marzban/db.sqlite3"
cp -a "$XRAY_SRC" "$ROOT/volumes/marzban/xray_config.json"

# Restore pre-0.8.4 compose if present in backup; else keep current and only restore data/config
if [[ -f "$BACKUP/docker-compose.yml.pre084" ]]; then
  cp -f "$BACKUP/docker-compose.yml.pre084" "$ROOT/docker-compose.yml"
  echo "Restored docker-compose.yml.pre084"
fi

# Restore env without SQLAlchemy override pointing at empty path semantics for 0.7+/code default
if [[ -f "$BACKUP/.env.marzban" ]]; then
  cp -f "$BACKUP/.env.marzban" "$ROOT/.env.marzban"
  # Ensure 0.7-style default (db in /code) unless backup already has it commented
  if grep -q '^SQLALCHEMY_DATABASE_URL' "$ROOT/.env.marzban"; then
    sed -i.bak 's/^SQLALCHEMY_DATABASE_URL/# SQLALCHEMY_DATABASE_URL/' "$ROOT/.env.marzban" || true
    rm -f "$ROOT/.env.marzban.bak"
  fi
  echo "Restored .env.marzban (SQLALCHEMY override commented for 0.7 /code db)"
fi

# If rolling back to layout with marz-storage, also put DB back into /code volume when possible
if [[ -n "${CID:-}" ]]; then
  CODE_SRC="$(docker inspect "$CID" --format '{{range .Mounts}}{{if eq .Destination "/code"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
  if [[ -n "${CODE_SRC:-}" && -d "$CODE_SRC" ]]; then
    cp -a "$DB_SRC" "$CODE_SRC/db.sqlite3"
    echo "Also restored DB into marz-storage CODE_SRC=$CODE_SRC"
  fi
fi

docker compose pull marzban || true
docker compose up -d marzban --force-recreate
sleep 3
docker compose logs marzban --tail 40 || true

echo "ROLLBACK_OK backup=$BACKUP users=$USERS"
echo "Verify: docker ps | grep marzban && check panel user count"

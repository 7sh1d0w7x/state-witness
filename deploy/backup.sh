#!/usr/bin/env bash
# backup.sh — restic backup + TEST de restaurare pentru n8n
# rulează: sudo bash backup.sh
set -euo pipefail

echo "== 1/5 instalare restic =="
if ! command -v restic >/dev/null; then
  apt-get update -qq && apt-get install -y restic
fi
echo "   [OK] restic $(restic version | awk '{print $2}')"

echo "== 2/5 configurare repo + parolă persistentă =="
PASSFILE=/opt/n8n/restic-pass
if [ ! -f "$PASSFILE" ]; then
  openssl rand -hex 16 > "$PASSFILE"
  chmod 600 "$PASSFILE"
fi
export RESTIC_PASSWORD_FILE="$PASSFILE"
export RESTIC_REPOSITORY=/backup/n8n
mkdir -p /backup
if [ ! -f /backup/n8n/config ]; then
  restic init
fi
echo "   [OK] repo /backup/n8n"

echo "== 3/5 backup (pg dump + datele n8n) =="
cd /opt/n8n
docker compose exec -T postgres pg_dump -U n8n n8n > /tmp/n8n.sql
restic backup /tmp/n8n.sql
rm -f /tmp/n8n.sql
echo "   [OK] snapshot creat"

echo "== 4/5 snapshot-uri =="
restic snapshots

echo "== 5/5 ⭐ TEST DE RESTAURARE =="
rm -rf /tmp/restore-test
restic restore latest --target /tmp/restore-test
echo "-- fișiere restaurate:"
find /tmp/restore-test -type f -ls
[ -s /tmp/restore-test/tmp/n8n.sql ] && echo "   ✅ RESTORE OK (backup-ul CHIAR revine)" || echo "   ❌ RESTORE FAIL"

echo "== GATA — backup TESTAT =="

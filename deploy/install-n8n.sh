#!/usr/bin/env bash
# install-n8n.sh — n8n self-hosted + Postgres (localhost only)
# rulează: sudo bash install-n8n.sh
set -euo pipefail

DIR=/opt/n8n
echo "== 1/4 folder + secrete =="
mkdir -p "$DIR"
KEY="$(openssl rand -hex 32)"
DBP="$(openssl rand -hex 16)"
cat > "$DIR/.env" <<EOF
N8N_ENCRYPTION_KEY=$KEY
POSTGRES_PASSWORD=$DBP
EOF
chmod 600 "$DIR/.env"
chmod 700 "$DIR"
echo "   [OK] $DIR/.env (0600)"

echo "== 2/4 docker-compose.yml =="
cat > "$DIR/docker-compose.yml" <<'EOF'
services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_USER: n8n
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: n8n
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U n8n"]
      interval: 10s
      retries: 5
  n8n:
    image: docker.n8n.io/n8nio/n8n
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DB_TYPE: postgresdb
      DB_POSTGRESDB_HOST: postgres
      DB_POSTGRESDB_USER: n8n
      DB_POSTGRESDB_PASSWORD: ${POSTGRES_PASSWORD}
      DB_POSTGRESDB_DATABASE: n8n
      N8N_ENCRYPTION_KEY: ${N8N_ENCRYPTION_KEY}
    ports:
      - "127.0.0.1:5678:5678"
    volumes:
      - n8n_data:/home/node/.n8n
volumes:
  pgdata:
  n8n_data:
EOF
echo "   [OK] $DIR/docker-compose.yml"

echo "== 3/4 pornire =="
cd "$DIR"
docker compose up -d
sleep 8
docker compose ps

echo "== 4/4 test =="
curl -s -o /dev/null -w "n8n HTTP: %{http_code}\n" http://127.0.0.1:5678 || echo "   (încă pornește — mai așteaptă 10s)"
echo "-- expunere (trebuie 127.0.0.1:5678, NU 0.0.0.0):"
ss -tulpnH | grep 5678 || echo "   (verifică)"
echo "== GATA =="

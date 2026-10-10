#!/usr/bin/env bash
# caddy.sh v2 — binar static (fără repo) + systemd
set -euo pipefail

echo "== 1/4 instalare caddy (binary static) =="
if [ ! -x /usr/local/bin/caddy ]; then
  curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o /usr/local/bin/caddy
  chmod +x /usr/local/bin/caddy
fi
/usr/local/bin/caddy version

echo "== 2/4 Caddyfile =="
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<'EOF'
192.168.122.50 {
    tls internal
    reverse_proxy 127.0.0.1:5678
}
EOF
/usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
  && echo "   [OK] config valid" || { echo "   [FAIL]"; /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; }

echo "== 3/4 systemd unit =="
cat > /etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy web server
After=network.target

[Service]
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now caddy >/dev/null 2>&1
systemctl restart caddy
sleep 3
echo "   caddy: $(systemctl is-active caddy)"

echo "== 4/4 test =="
curl -sk -o /dev/null -w "https n8n (443): %{http_code}\n" https://192.168.122.50 || echo "   (încă pornește)"
echo "-- expunere:"
ss -tulpnH | grep -E ":80 |:443 |:5678 " || true
echo "== GATA — n8n în spatele Caddy/HTTPS =="

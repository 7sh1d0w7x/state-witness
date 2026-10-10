# Deploy kit — secure self-hosted n8n (Ubuntu)

Reference scripts for turning a fresh Ubuntu Server (24.04+/26.04) into a **hardened, self-hosted n8n** host. These are the exact steps used in my "secure self-hosted" service; `state-witness` is the audit tool used at the end to verify the *effective* state.

> Tested end-to-end on a local Ubuntu VM (n8n + Postgres behind Caddy/HTTPS, tested restore).

## What it does

| Script | Step |
|---|---|
| `harden.sh` | SSH keys-only · ufw · fail2ban · sysctl hardening · auto-updates |
| `install-n8n.sh` | Docker + n8n + Postgres (bound to `127.0.0.1` only) |
| `caddy.sh` | Caddy reverse proxy → HTTPS for n8n (n8n not exposed directly) |
| `backup.sh` | restic backup of n8n DB + **tested restore** |

## Usage

```bash
# on the target server
sudo bash harden.sh          # 1. harden the host FIRST
sudo bash install-n8n.sh     # 2. n8n + Postgres (localhost-only)
sudo bash caddy.sh           # 3. HTTPS in front (edit Caddyfile: domain + remove `tls internal`)
sudo bash backup.sh          # 4. backup + restore test
```

## Verify

```bash
sudo state-witness ssh        # config EFECTIV (sshd -T)
sudo state-witness sysctl     # kernel params
sudo state-witness users      # uid-0, sudoers
sudo state-witness firewall   # active ruleset
```

## Notes / gotchas (learned in testing)

- **sshd "first value wins"** + `/etc/ssh/sshd_config.d/50-cloud-init.conf` sets `PasswordAuthentication yes` → name your hardening drop-in `00-hardening.conf` so it wins.
- **Docker sets `net.ipv4.ip_forward=1`** — expected on a Docker host (state-witness accounts for it).
- Never expose n8n directly: keep it on `127.0.0.1`, put Caddy/HTTPS in front.
- Always **test the SSH key in a new session** before disabling password auth.
- Backups are only real if the **restore was tested**.

## Custom per client

- `caddy.sh`: replace the IP with the client's **domain**, delete the `tls internal` line → Caddy issues a real Let's Encrypt cert automatically.
- Add a CI/off-site `RESTIC_REPOSITORY` (S3/B2) for real 3-2-1 backups.

---
*Part of the "secure self-hosted" service · pairs with the `state-witness` auditor.*

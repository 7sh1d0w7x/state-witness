#!/usr/bin/env bash
# harden.sh — hardening Ubuntu Server (n8n lab) — idempotent
# rulează: sudo bash harden.sh
set -euo pipefail

echo "== 1/4 SSH config =="
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
EOF
if sshd -t; then echo "   [OK] sshd config valid"; else echo "   [FAIL] sshd -t a eșuat"; fi

echo "== 2/4 sysctl =="
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
net.ipv4.conf.all.rp_filter = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.ipv4.tcp_syncookies = 1
EOF
sysctl --system >/dev/null && echo "   [OK] sysctl aplicat"

echo "== 3/4 fail2ban =="
cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = 22
maxretry = 3
bantime = 3600
findtime = 600
EOF
systemctl enable --now fail2ban >/dev/null 2>&1 && echo "   [OK] fail2ban pornit"

echo "== 4/4 auto-updates =="
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 && echo "   [OK] auto-updates"

echo "== VERIFICARE =="
echo "-- sshd efectiv:"
sshd -T | grep -Ei "permitrootlogin|passwordauth|pubkeyauth|kbdinter"
echo "-- yama: $(sysctl -n kernel.yama.ptrace_scope)"
echo "-- ufw:"; ufw status | head -6
echo "-- FAIL2BAN:"; fail2ban-client status sshd 2>/dev/null | head -8 || echo "(inactiv)"
echo "== GATA. NU am dat reload ssh (testează cheia întâi!) =="

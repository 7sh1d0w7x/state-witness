# Checks

What `state-witness` inspects, and the state of each check. Everything here targets **effective runtime state**, not configuration files.

Legend: ✅ implemented · 🚧 in progress · 📋 planned

---

## Implemented

### SSH effective authentication & crypto — ✅
Resolves the effective `sshd` configuration via `sshd -T` (the daemon's own view, after all includes and drop-ins) and reports the values that actually apply — with provenance.

Examples of what it surfaces:

- `PermitRootLogin`
- `PasswordAuthentication`
- `PermitEmptyPasswords`
- `X11Forwarding`
- `MaxAuthTries`
- allowed ciphers / MACs / KEX

> `sshd -T` reads host keys, so this check requires root. Without it, it is skipped with a reason — never reported as a failure.

### Atomic / ostree / bootc deployment — ✅
Reads the deployment as a first-class fact:

- current deployment (image, version)
- whether the deployment is **signed**
- whether the deployment is **pinned**
- **`/etc` drift** via `ostree admin config-diff`

Source: `rpm-ostree status` and `bootc status --json`.

### SYSCTL effective — ✅
Reads the **runtime** value (`sysctl -n`) and compares it against the persisted value, flagging drift. Covers IP forwarding, ASLR, reverse-path filtering, `dmesg_restrict`, `kptr_restrict`, Yama `ptrace_scope`, and TCP syncookies.

Source: `sysctl -n` / `/proc/sys`.

> The effective value is the kernel's live value; a persisted setting that is not applied is reported as drift, not a pass.

### FIREWALL effective — ✅
Detects the active packet filter (nftables / ufw / firewalld) and reports whether it is running.

Source: `nft list ruleset` / `ufw status` / `firewall-cmd --state`.

> Missing tools are reported as `Skip`, never as a failure.

### USERS & SUDO — ✅
Flags extra uid-0 accounts, `NOPASSWD` sudoers entries, and empty password fields in `/etc/shadow`.

Source: `/etc/passwd`, `/etc/sudoers` (+ drop-ins), `/etc/shadow`.

---

## Planned

### v0.2.0 — 6 checks

- **LISTENING SOCKETS** — compare live listeners against an expected set. 📋
- **SUID / SGID** — inventory with allowlist. 📋
- **JSON schema v1** — stabilized, versioned output contract. 📋

### v0.3.0 — 9 checks

- **FILE CAPABILITIES** — anomalies in `getcap` output. 📋
- **SELinux / AppArmor** — enforcement state and domain. 📋
- **systemd hardening** — via `systemd-analyze security`. 📋

### v0.4.0 — 12 checks

- **AUDIT subsystem** — `auditd` presence and rules. 📋
- **KERNEL protections** — `/sys/.../vulnerabilities`, lockdown mode. 📋
- **ATOMIC `/etc` drift** — formalized as a first-class check. 📋

### Later

- **EVIDENCE mode** — compliance-oriented report. 📋
- **SARIF 2.1.0** output. 📋
- Control mapping (NIST SP 800-53, CRA Annex I, BSI). 📋

---

## Design principles for checks

1. **Effective over declared.** Read what the daemon or kernel enforces, not what a file says.
2. **Provenance always.** Every finding points to the file and line that produced the value.
3. **Skip, never false-fail.** A check that cannot run returns `Skip(reason)`.
4. **Read-only by default.** Checks never modify the host. Remediation is a separate, opt-in step.

See [`DESIGN.md`](DESIGN.md) for the architecture behind these checks.

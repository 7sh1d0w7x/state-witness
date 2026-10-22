# Checks

What `state-witness` inspects, and the state of each check. Everything here
targets **effective runtime state**, not configuration files.

Legend: ✅ implemented · 📋 planned

---

## Implemented (v0.1.1 — 25 checks)

### SSH effective configuration — ✅ (8 checks)

Resolves the effective `sshd` configuration via `sshd -T` (the daemon's own view,
after all includes and drop-ins) and reports the values that actually apply.

| ID | Check | What counts as good |
|---|---|---|
| `SSH-001` | `PermitRootLogin` | `no` passes; `prohibit-password` / `without-password` warns; anything else fails |
| `SSH-002` | `PasswordAuthentication` | `no` passes; `yes` fails |
| `SSH-003` | `PermitEmptyPasswords` | `no` passes; anything else fails |
| `SSH-004` | `MaxAuthTries` | `≤ 4` passes; `5–6` warns; `≥ 7` fails (CIS benchmark) |
| `SSH-005` | `X11Forwarding` | `no` passes; `yes` warns |
| `SSH-006` | `AllowUsers` / `AllowGroups` | an allowlist passes; neither set warns (any account may attempt auth) |
| `SSH-007` | `ListenAddress` | loopback-only passes; any non-loopback address warns; unset skips (OpenSSH default binds every interface) |
| `SSH-008` | Weak crypto | warns only on clearly broken primitives (`arcfour*`, `3des-cbc`, `hmac-md5*`, `diffie-hellman-group1-sha1`, `diffie-hellman-group-exchange-sha1`), naming the offending entries |

Source: `sshd -T`.

`SSH-008` is deliberately narrow: `*-cbc` ciphers and `diffie-hellman-group14-sha1`
still appear in stock defaults on several distributions, so flagging them would
report every stock host. The list is the set we are willing to call broken.

> `sshd -T` reads host keys, so these checks usually require root. Without it the
> check returns `Skip` with a reason — never reported as a failure.

### Atomic / ostree / bootc deployment — ✅ (4 checks)

Reads the deployment as a first-class fact.

| ID | Check | Source |
|---|---|---|
| `OSTREE-001` | Current deployment (image, version) | `rpm-ostree status` / `bootc status --json` |
| `OSTREE-002` | Whether the deployment is **signed** | same |
| `OSTREE-003` | Whether the deployment is **pinned** | same |
| `OSTREE-004` | `/etc` drift | `ostree admin config-diff` |

On a mutable host the command returns a single `Skip` — "not an ostree/bootc host"
— rather than pretending to find a deployment.

### SYSCTL effective — ✅ (7 checks)

Reads the **live kernel value** with `sysctl -n` and compares it with the expected
hardened value.

| ID | Key | Expected |
|---|---|---|
| `SYS-001` | `net.ipv4.ip_forward` | `0` (accepted as good when Docker is present) |
| `SYS-002` | `kernel.randomize_va_space` (ASLR) | `2` |
| `SYS-003` | `net.ipv4.conf.all.rp_filter` | `1` |
| `SYS-004` | `kernel.dmesg_restrict` | `1` |
| `SYS-005` | `kernel.kptr_restrict` | `1` or stricter |
| `SYS-006` | `kernel.yama.ptrace_scope` | `1` |
| `SYS-007` | `net.ipv4.tcp_syncookies` | `1` |

Source: `sysctl -n`.

> This compares the runtime value against the **expected** value. It does not
> compare runtime against the persisted `/etc/sysctl.d` value — "the setting is
> not persisted" is not detected yet.

### FIREWALL effective — ✅ (3 checks)

Detects the active packet filter and reports its state. Only the first filter
found is reported.

| ID | Check | Source |
|---|---|---|
| `FW-001` | nftables ruleset (rule count) | `nft list ruleset` |
| `FW-002` | ufw state | `ufw status` |
| `FW-003` | firewalld state | `firewall-cmd --state` |

Missing tools are reported as `Skip`, never as a failure.

### USERS & SUDO — ✅ (3 checks)

| ID | Check | Source |
|---|---|---|
| `USR-001` | Extra uid-0 accounts (only `root` should have uid 0) | `/etc/passwd` |
| `USR-002` | `NOPASSWD` sudoers entries | `/etc/sudoers` |
| `USR-003` | Empty password fields | `/etc/shadow` |

---

## Planned

### v0.2.0

- **LISTENING SOCKETS** — compare live listeners against an expected set. 📋
- **SUID / SGID** — inventory with allowlist. 📋
- **JSON schema v1** — stabilized, versioned output contract. 📋

### v0.3.0

- **FILE CAPABILITIES** — anomalies in `getcap` output. 📋
- **SELinux / AppArmor** — enforcement state and domain. 📋
- **systemd hardening** — via `systemd-analyze security`. 📋
- **More SSH knobs** — `PermitEmptyPasswords`, `X11Forwarding`, `MaxAuthTries`,
  cipher/MAC/KEX lists (already exposed by `sshd -T`). 📋

### Later

- **AUDIT subsystem** — `auditd` presence and rules. 📋
- **KERNEL protections** — `/sys/.../vulnerabilities`, lockdown mode. 📋
- **Remediation** — `--plan` / `--apply` with rollback. 📋
- **EVIDENCE mode** — compliance-oriented report. 📋
- **SARIF 2.1.0** output. 📋
- Control mapping (NIST SP 800-53, CRA Annex I, BSI). 📋

---

## Design principles for checks

1. **Effective over declared.** Read what the daemon or kernel enforces, not what a
   file says.
2. **Provenance always.** Every finding names the command or file that produced the
   value — including `Skip` findings. Line numbers inside a config file are not
   emitted yet (`provenance.line` is currently always `null`).
3. **Skip, never false-fail.** A check that cannot run returns `Skip(reason)`.
4. **Read-only.** Checks never modify the host. Remediation does not exist yet;
   when it does, it will be a separate, opt-in step.

See [`DESIGN.md`](DESIGN.md) for the architecture behind these checks.

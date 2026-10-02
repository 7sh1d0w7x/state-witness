# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.0.x | ✅ |

## Reporting a vulnerability

**Please do NOT open a public issue.**

Report privately via:
- GitHub Security Advisories (preferred): *Security* tab → *Report a vulnerability*
- Or email the maintainer (see repo profile).

Include:
- Description + impact
- Reproduction steps
- Affected version
- Any suggested fix

## What to expect

- Acknowledgment within a few days.
- We'll work on a fix and credit you (unless you prefer otherwise).

## Scope note

`state-witness` is **read-only by default** and inspects system state (`sshd -T`, `sysctl`, `nft`, `/proc`). Privilege requires `sudo` for some checks (e.g. host keys). Report anything that could:
- leak sensitive config,
- cause unintended writes,
- escalate privileges via crafted input.

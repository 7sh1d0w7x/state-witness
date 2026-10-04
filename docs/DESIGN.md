# Design

How `state-witness` is built and why. This is the public design overview; the internal spec (`SPEC.md`) is the full source of truth and stays private.

## Core idea

Most Linux audit tools read **configuration files**. `state-witness` reads the **effective runtime state** — what the kernel and daemons actually enforce right now — and records **which file and line** produced each value.

```
Existing tools read the file. Attackers read the drop-in.
state-witness reads what the host actually enforces — and says from where.
```

## The gap it targets

| | Lynis / OpenSCAP | `state-witness` |
|---|---|---|
| What is audited | static config | effective state (`sshd -T`, `sysctl -n`, live sockets) |
| Provenance | none | file **and line** |
| Atomic/ostree hosts | breaks or misdetects | first-class citizen |
| Effort | shell / Python engine | single static Rust binary |

Immutable/atomic hosts (Fedora Atomic, Bazzite, `bootc` / RHEL Image Mode) have a read-only `/usr`, a 3-way `/usr/etc` → `/etc` merge, and signed, versioned deployments. Tools that probe or remediate via `dnf` either fail here or produce a confident-but-wrong grade.

## Architecture: Fact / Probe / Rule / Finding

```
Fact     = typed value + provenance(path, line) + access(Root | Unprivileged | Cap)
Probe    = a Rust function that collects one Fact (declares the privilege it needs)
Rule     = a declarative predicate over Facts (TOML data — never a script)
Finding  = rule_id, status, severity, evidence, provenance, controls[]
```

**Collect once, assert many.** Probes gather facts; rules are pure predicates over those facts. This is what makes the model fast and testable.

### Why this shape

- **Provenance first-class** — every value knows where it came from.
- **Probes testable in isolation** — a probe can be run against recorded fixtures.
- **Rules testable against synthetic fact sets** — no host required.
- **Graceful degradation** — a probe that cannot run returns `Skip(reason)`, never a false `Fail`.

## Probe registry & privileges

Each probe declares `needs: Root | CapNetAdmin | None`.

Pre-flight checks `geteuid()` and `CapEff` from `/proc/self/status`. The tool **never escalates internally** — no `sudo`, no `setuid`. If a probe needs root and does not have it, it is skipped and the reason is reported:

```
ran 34 probes, skipped 6 (5 require root)
```

## Status model

```
Status::Pass | Warn | Fail | Skip
```

- `Pass` — the effective state meets the rule.
- `Warn` — a weak but not critical state.
- `Fail` — the effective state violates the rule.
- `Skip` — the probe could not run (missing privilege, absent service). **Never** counted as a failure.

Exit codes (CI-friendly): `0` = no `Fail` · `1` = at least one `Fail`.

## Output

- **Text** — human-readable, with provenance lines.
- **JSON** — versioned schema for CI and tooling.
- **SARIF 2.1.0** — planned, for GitHub code scanning / security tab.

## Remediation model (planned)

- Changes are **drop-in only** — never edit files in place:
  `/etc/ssh/sshd_config.d/`, `/etc/sysctl.d/`, `/etc/systemd/system/<unit>.d/`.
- **Validate before applying** (`sshd -t`, `nft -c -f`), then re-read the effective value.
- **Backups + manifest** in `/var/lib/state-witness/`, with `state-witness rollback <id>`.
- **Opt-in:** `scan` is read-only · `fix --plan` shows the diff · `fix --apply` requires an explicit flag.
- SSH is never restarted without an explicit `--allow-lockout`.

## Non-goals

Explicitly out of scope:

- SBOM / CycloneDX generation
- Remote / fleet / agent / dashboard
- Windows / macOS / BSD
- GUI
- Shipping CIS content (licensing)
- Unsupervised auto-apply

See [`CHECKS.md`](CHECKS.md) for what the tool checks, and [`../CONTRIBUTING.md`](../CONTRIBUTING.md) to contribute.

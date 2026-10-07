# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Planned
- More checks (permissions, updates, TLS, logging, network)
- Evidence mode (compliance report)
- Fleet mode (scan 100 hosts)

## [0.1.0] - 2026-10-07

### Added
- `sysctl` check: effective kernel parameters (runtime, via `sysctl -n`) —
  IP forwarding, ASLR, reverse-path filtering, dmesg restrict.
- `firewall` check: detects the active packet filter (nftables / ufw /
  firewalld) and reports whether it is running.
- `users` check: extra uid-0 accounts, `NOPASSWD` sudoers entries, and empty
  password fields in `/etc/shadow`.
- Every finding now carries provenance for all four checks.

### Notes
- 16 unit tests; `cargo fmt` + `cargo clippy -D warnings` clean.

## [0.0.1] - 2026-10-02

### Added
- Initial scaffold (Rust)
- `ssh` check: effective SSH daemon state via `sshd -T`
- `Status::{Pass, Warn, Fail, Skip}` with provenance (which file+line)
- Text + `--json` output
- Demo GIF + banner
- CI workflow
- `ADR.md`, `CONTRIBUTING.md`, `SECURITY.md`
- `atomic` command: immutable/atomic host (ostree, bootc) detection + deployment facts (image, signature, pin) from `rpm-ostree status`, plus `/etc` drift via `ostree admin config-diff`.

# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `atomic` command: immutable/atomic host (ostree, bootc) detection + deployment facts (image, signature, pin) from `rpm-ostree status`, plus `/etc` drift via `ostree admin config-diff`.

### Planned
- More checks (firewall, kernel hardening, users/sudo, permissions, updates, TLS, logging, network)
- Evidence mode (compliance report)
- Fleet mode (scan 100 hosts)

## [0.0.1] - 2026-10-02

### Added
- Initial scaffold (Rust)
- `ssh` check: effective SSH daemon state via `sshd -T`
- `Status::{Pass, Warn, Fail, Skip}` with provenance (which file+line)
- Text + `--json` output
- Demo GIF + banner
- CI workflow
- `ADR.md`, `CONTRIBUTING.md`, `SECURITY.md`

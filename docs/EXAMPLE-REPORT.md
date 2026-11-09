# Example report

A real, unedited run of v0.2.1 on a desktop, published so you can see what the
output looks like **including what it does not prove**.

- **Host:** Bazzite (Fedora Atomic), kernel `7.2.15-ogc1.1.fc45.x86_64`
- **When:** 2026-11-09, 16:09 UTC
- **User:** `7sh1d0w7x` — **not root**
- **Binary:** release build of `v0.2.1`

The run below is one pass of all five commands. Skips are part of the result, not
an error: two checks need root on this host and say so.

## `state-witness ssh`

```console
$ state-witness ssh
– SSH effective config: sshd -T failed (try as root)
  └─ from (effective, sshd -T)
```

`sshd -T` reads host keys, so it normally needs root. The command returns **one
skip for the whole group** — not eight speculative failures. The exit code is `0`:
a skip is "not checked", not "failed".

## `state-witness atomic`

```console
$ state-witness atomic
✓ Deployment: ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable
  └─ from (effective, rpm-ostree status)
✓ Deployment signature: valid
  └─ from (effective, rpm-ostree status)
– Preserved /etc drift: ostree admin config-diff failed (try as root)
  └─ from (effective, ostree admin config-diff)
```

This is the part the other general-purpose auditors do not model: **which
deployment is booted and whether it is signed**. `OSTREE-003` (pinned deployment)
only appears when a deployment is actually pinned; on this host it is not.

`ostree admin config-diff` also needs root, so the `/etc` drift check is a skip
with a reason. Run `sudo state-witness atomic` to turn it into a pass or a count of
modified paths.

## `state-witness sysctl`

```console
$ state-witness sysctl
✗ IP forwarding: net.ipv4.ip_forward = 1 (expected 0)
  └─ from (effective, sysctl -n)
✓ ASLR (randomize_va_space): kernel.randomize_va_space = 2
  └─ from (effective, sysctl -n)
✗ Reverse-path filtering: net.ipv4.conf.all.rp_filter = 0 (expected 1)
  └─ from (effective, sysctl -n)
✓ dmesg restrict: kernel.dmesg_restrict = 1
  └─ from (effective, sysctl -n)
✗ kptr_restrict (hide kernel pointers): kernel.kptr_restrict = 0 (expected 1)
  └─ from (effective, sysctl -n)
✗ Yama ptrace scope (block ptrace): kernel.yama.ptrace_scope = 0 (expected 1)
  └─ from (effective, sysctl -n)
✓ TCP SYN cookies (SYN-flood protection): net.ipv4.tcp_syncookies = 1
  └─ from (effective, sysctl -n)
```

Exit code: **`1`** — the audit ran and at least one finding is `fail`.

Read this as *questions*, not verdicts. `ip_forward = 1` is normal on a desktop
running containers or virtual machines; `rp_filter = 0` and `ptrace_scope = 0` are
common desktop defaults. The tool says which value is in force and what its own
default expectation is — the decision to change it belongs to the host owner.

## `state-witness firewall`

```console
$ state-witness firewall
✓ firewalld: running
  └─ from (effective, firewall-cmd --state)
```

Only the active backend is reported. On a host with `nftables` and no
`firewalld`, this line would instead name the loaded ruleset (or a skip with the
reason no packet filter was detected).

## `state-witness users`

```console
$ state-witness users
✓ uid 0 accounts: only root
  └─ from /etc/passwd
✓ sudoers NOPASSWD: none
  └─ from /etc/sudoers
– empty passwords: /etc/shadow unreadable (try as root)
  └─ from /etc/shadow
```

Exit code `0`. The first two checks read files the user can read; `/etc/shadow`
cannot be read without root, so the third is a skip. That distinction matters:
"cannot check" must never be displayed as "clean".

## Exit codes for this run

| Command | Exit | Why |
|---|---|---|
| `ssh` | `0` | one skip, no failures |
| `atomic` | `0` | two passes, one skip |
| `sysctl` | `1` | four failures |
| `firewall` | `0` | one pass |
| `users` | `0` | two passes, one skip |

A CI job can treat `1` as "findings" and `2` as "the tool could not run" — the two
are deliberately different.

## JSON

`--json` prints a single array on stdout, with diagnostics on stderr:

```console
$ state-witness sysctl --json
[
  {
    "id": "SYS-001",
    "title": "IP forwarding",
    "status": "fail",
    "value": "net.ipv4.ip_forward = 1 (expected 0)",
    "provenance": {
      "path": "(effective, sysctl -n)",
      "line": null
    }
  }
]
```

The real output contains all seven findings; the excerpt above shows the shape. The
schema has no version field yet — pin the tool version if you parse it in CI.

## Footer

On a terminal only (never with `--json`, never when stdout is redirected), the text
output ends with one attribution line:

```console
$ state-witness firewall
✓ firewalld: running
  └─ from (effective, firewall-cmd --state)
state-witness 0.2.1 · by 7sh1d0w7x · 7sh1d0w7x.github.io
```

Use `--quiet` to suppress it.

## Reproduce

```bash
git clone https://github.com/7sh1d0w7x/state-witness
cd state-witness
cargo build --release

./target/release/state-witness ssh
./target/release/state-witness atomic
./target/release/state-witness sysctl
./target/release/state-witness firewall
./target/release/state-witness users

# the same checks with the permissions this run did not have
sudo ./target/release/state-witness ssh
sudo ./target/release/state-witness atomic
sudo ./target/release/state-witness users
```

## What this run does **not** prove

- It is **not a root run**. SSH checks, `/etc/shadow`, and `/etc` drift were not
  evaluated. A report full of skips is not a clean report.
- It is **one moment**, not a trend. Re-run after updates; that is the point of a
  small, scriptable check.
- It is **not a compliance result**. There is no CIS/STIG/PCI-DSS profile here —
  see [`COMPARISON.md`](COMPARISON.md) for the tools that provide one.

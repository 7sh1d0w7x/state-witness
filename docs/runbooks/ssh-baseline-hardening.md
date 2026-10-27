# Runbook: SSH baseline hardening

A runbook is a procedure you can follow while tired. Every step has a command,
what you expect to see, and what to do when you don't see it.

**Change:** after this, the daemon refuses X11 forwarding, allows at most three
authentication attempts per connection, and accepts logins only from the accounts
you name explicitly.

**This does not** disable password authentication, change `PermitRootLogin`,
move the SSH port, or touch the firewall. Those are separate changes with their
own runbooks.

**Path used throughout:**

```sh
DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf
DIR=/etc/ssh/sshd_config.d
```

**Last executed:** 2026-10-27 · Ubuntu 26.04 · OpenSSH_10.2p1 · QEMU/KVM VM.
See `ssh-baseline-hardening.evidence-2026-10-27.txt` for the transcripts.

**Portability:** the unit name and the drop-in directory are distribution facts,
not SSH facts. On Ubuntu/Debian the unit is `ssh.service`; on Fedora/RHEL it is
`sshd.service`. Debian-family systems often ship `50-cloud-init.conf` and
`60-cloudimg-settings.conf` in the same directory — they are read too, and the
`00-` prefix is how this runbook wins against them.

---

## 0. Why three settings and not one

They close different things, and each has its own failure mode:

| Setting | Closes | Fails safe? |
|---|---|---|
| `X11Forwarding no` | an extra channel into the session | yes — nobody notices on a headless server |
| `MaxAuthTries 3` | patience for guessing keys/passwords | yes — three attempts is still enough for a human |
| `AllowUsers` | every account you never meant to expose | **no** — leave your own account out and you are locked out |

`AllowUsers` is the only one of the three that can lock you out. That is why it
is written last in the file and checked from a *new* connection before you close
anything.

---

## 1. Before you touch anything

Stop if any of these is false:

- [ ] you have a **second way in** that does not use sshd: provider console, VNC,
      serial, physical access
- [ ] you are connected with a **key**, not a password
- [ ] you know the exact account name you will put in `AllowUsers`
      (`whoami` — not the hostname, not the display name)
- [ ] you know which other accounts must keep access (deploy user, backup agent).
      Any account not listed after this change is refused, including `root`.

If a service account exists and you are not sure of its name, list the accounts
that have authorized keys before continuing:

```sh
sudo grep -l . /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
```

---

## 2. Capture the state before

```sh
sudo sshd -T | grep -E '^(maxauthtries|x11forwarding|allowusers)'
```

Expected on a fresh Ubuntu cloud image:

```
maxauthtries 6
x11forwarding yes
```

`allowusers` is absent — meaning "no restriction". Record this output; it is half
of the before/after pair.

---

## 3. Write the drop-in

```sh
printf 'MaxAuthTries 3\nAllowUsers %s\nX11Forwarding no\n' "$(whoami)" |
  sudo tee "$DROPIN"
```

Then read back what you actually wrote — and read the **directory**, not just the
file:

```sh
sudo cat "$DROPIN"
sudo ls -l "$DIR"
```

Expected file contents:

```
MaxAuthTries 3
AllowUsers lab
X11Forwarding no
```

> [!warning] A file with a wrong name is still read
> `sshd` includes **every** file in `sshd_config.d/` that ends in `.conf`,
> whatever else the name contains. A typo that produces `00=hardening.conf`
> creates a second, invisible-looking drop-in that is parsed like any other.
> During the run that produced this runbook, two such files existed at once and
> `sshd -T` showed values from the one nobody was looking at.
>
> The check that catches it is `ls -l "$DIR"` — not `cat "$DROPIN"`.

---

## 4. Validate, apply, confirm

```sh
sudo sshd -t && echo OK
```

- `OK` → continue.
- anything else → **stop**. Do not reload. The line number in the message points
  at the drop-in; fix it and re-run.

```sh
sudo systemctl reload ssh     # sshd on Fedora/RHEL
sudo sshd -T | grep -E '^(maxauthtries|x11forwarding|allowusers)'
```

Expected:

```
maxauthtries 3
x11forwarding no
allowusers lab
```

---

## 5. Prove it from a new connection

Configuration output proves intent. Only a connection proves behaviour. Run all
four, from a *new* shell — not the one you already have open.

| Test | Command | Expected |
|---|---|---|
| your account still works | `ssh <user>@<host> whoami` | `<user>` |
| root is refused | `ssh -o PubkeyAuthentication=no root@<host>` | `Permission denied` |
| an unknown account is refused | `ssh ghost@<host>` | `Permission denied` |
| a listed account still works | (repeat row 1 with the deploy account) | its name |

`AllowUsers` also refuses `root`, so row 2 passes for two reasons at once. That is
acceptable here — A4 has its own runbook and its own proof.

---

## 6. Rollback

```sh
sudo rm "$DROPIN"
sudo sshd -t && sudo systemctl reload ssh
sudo sshd -T | grep -E '^(maxauthtries|x11forwarding|allowusers)'
```

Expected: `maxauthtries 6`, `x11forwarding yes`, no `allowusers` line.

Rollback removes **the file the procedure created**. If you created a second file
by accident (§3), remove that one too — otherwise the rollback looks complete
while a renamed drop-in keeps enforcing the change.

---

## 7. Limits

- **Automation and `AllowUsers`.** Any script, cron job, or monitoring agent that
  logs in as an account you did not list stops working. Find them before, not
  after: `grep -rn 'ssh .*@' /etc/cron* /etc/systemd /opt 2>/dev/null`.
- **`MaxAuthTries` and keys in an agent.** The counter is per *connection*, not
  per key. An agent offering twelve keys can burn the budget before reaching the
  right one. `IdentitiesOnly yes` in `~/.ssh/config` avoids that class of failure.
- **`X11Forwarding no` is invisible until someone needs it.** On a workstation
  used for remote GUI work this breaks the workflow. On a server it changes
  nothing anyone can observe — which is why it is safe to do first.
- **`sshd -T` reads the files, not the running daemon.** It will show the new
  value even if the reload silently failed. Pair it with a new connection (§5).
- **`sshd -t` passes on an empty or missing file.** A drop-in that was never
  written validates cleanly and changes nothing. `cat` after every write.

---

## 8. What to keep as evidence

```
   before   sudo sshd -T | grep -E '^(maxauthtries|x11forwarding|allowusers)'
   file     sudo cat "$DROPIN"
   dir      sudo ls -l "$DIR"              ← catches the renamed-file trap
   syntax   sudo sshd -t && echo OK
   after    sudo sshd -T | grep -E '^(maxauthtries|x11forwarding|allowusers)'
   tests    the four connection attempts, with exit codes
```

Four lines of output and four exit codes. That is the whole deliverable.

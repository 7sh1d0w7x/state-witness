# Case study: four doors to root, three left standing

**Date:** 2026-10-27 · **Host:** Ubuntu 26.04, disposable VM (QEMU/KVM)
**Duration:** ~40 minutes, two changes · **Downtime:** none
**Runbooks:** [`ssh-baseline-hardening`](../runbooks/ssh-baseline-hardening.md),
[`sudoers-least-privilege`](../runbooks/sudoers-least-privilege.md)

---

## The situation

A freshly installed cloud image, hardened by hand over a few evenings. SSH keys
in place, password login on the list to be disabled next, firewall not yet built.
Everything looked fine from the outside: no open ports beyond 22, no obvious
misconfiguration.

The brief for the session was narrow — count the paths to root, close the
pointless ones, and keep the evidence. Not "make it secure": that phrase hides
the actual work.

---

## What the count found

Four doors reached root. Two were intended.

| Door | State before | Why it mattered |
|---|---|---|
| `%sudo` group → `lab` | open, password required | intended; the administrator's own path |
| `%admin ALL=(ALL) ALL` | **latent** — group empty | anyone added to `admin` later becomes root, without touching `sudoers` |
| `/etc/sudoers.d/` | no active files | clean, but this had to be verified, not assumed |
| `NOPASSWD` | none | clean |

The second row is the interesting one. Nothing used it. No member, no script, no
warning in any audit output that only lists group membership. It existed because
Debian and Ubuntu ship it, and a rule that grants `ALL` to an empty group is
invisible in `getent group` and invisible in `sudo -l -U <user>`.

It only shows up in one place: reading `/etc/sudoers` as text.

```
$ sudo -l -U lab
User lab may run the following commands on lab:
    (ALL : ALL) ALL          ← says nothing about %admin
```

---

## Change 1 — remove the latent rule

The first two attempts used `visudo` interactively. Both opened the editor and
both exited without saving; `grep` afterwards showed the line still in place.
That is a specific and common failure: `visudo` reports success when the editor
exits cleanly, whether or not the buffer was modified.

The procedure that worked edits a copy and validates the copy before installing
it:

```sh
sudo cp /etc/sudoers /etc/sudoers.new
sudo sed -i '/^%admin ALL=(ALL) ALL/d' /etc/sudoers.new
sudo visudo -c -f /etc/sudoers.new     # parsed OK
sudo install -m 440 -o root -g root /etc/sudoers.new /etc/sudoers
```

Result, and the whole proof of the change:

```
$ sudo diff /etc/sudoers.bak-2026-10-27 /etc/sudoers
50d49
< %admin ALL=(ALL) ALL

$ sudo visudo -c
/etc/sudoers: parsed OK

$ sudo -l -U lab
    (ALL : ALL) ALL            ← unchanged
```

One line removed, syntax valid, own access intact. The group still exists; it
just no longer carries privilege.

---

## Change 2 — SSH baseline, and the file that lied

Three settings were added to a drop-in: `MaxAuthTries 3`, `AllowUsers lab`,
`X11Forwarding no`.

`sshd -T` afterwards showed `maxauthtries 3` and `allowusers lab` — but the
file that was supposed to contain them held only one line:

```
$ sudo cat /etc/ssh/sshd_config.d/00-hardening.conf
X11Forwarding no
```

The other two values came from a second file, created earlier by a typing
mistake:

```
$ sudo ls -l /etc/ssh/sshd_config.d/
-rw-r--r-- 1 root root 17  00-hardening.conf
-rw-r--r-- 1 root root 17  '00=hardening.conf'    ← parsed like any other
```

`sshd` includes every file in that directory ending in `.conf`. The name inside
the quotes — a `=` where a `-` belonged — made it invisible to `cat` on the
expected path and completely visible to the daemon.

Nothing was broken by this. The change was working; it was working from a file
nobody knew about. That is the difference between "the setting is applied" and
"the setting is applied where I think it is".

After removing the stray file and rewriting the intended one:

```
$ sudo sshd -T | grep -E '^(maxauthtries|x11forwarding|allowusers)'
maxauthtries 3
x11forwarding no
allowusers lab

$ ssh lab@… whoami        → lab
$ ssh root@…              → Permission denied (exit 255)
$ ssh ghost@…             → Permission denied (exit 255)
```

---

## The two lessons

**A group with no members is still a door.** Privilege enumeration that stops at
"who is in the sudo group" misses rules attached to groups nobody currently
belongs to. The rule is what grants power; membership only decides who walks
through today.

**A file with a wrong name is still read.** Validation (`sshd -t`, `visudo -c`)
answers "is this valid", not "is this the file in effect". The check that
catches a renamed or duplicated drop-in is a directory listing, not a `cat` of
the file you intended to write.

---

## What a client would receive

```
   before/after   4 lines of sshd -T, 2 lines of sudoers grep
   change         1 diff for sudoers, 1 file listing for the SSH drop-in
   tests          4 connection attempts with exit codes
   notes          the two names that were not where they appeared to be
```

Two changes, both reversible in under a minute, both with evidence that does not
depend on trusting the person who ran them.

---

## Limits of this write-up

- It is a laboratory host, not a production server: no users to coordinate with,
  no maintenance window, no provider console in the loop.
- `AllowUsers` was set to a single account; a real host with service accounts
  needs that list built before the change, not after.
- The `%admin` rule is historically Debian/Ubuntu. RHEL-family hosts have
  `%wheel` and different defaults — same technique, different line.
- Password authentication was still enabled on this host throughout. That change
  has its own runbook and its own failure mode (lockout), and it was deliberately
  left out of this session.

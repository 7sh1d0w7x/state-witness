# Runbook: disable SSH password authentication

A runbook is a procedure you can follow while tired. Every step has a command,
what you expect to see, and what to do when you don't see it.

**Change:** after this, only key-based logins succeed. Passwords stop working.

**This does not** change the port, the firewall, `PermitRootLogin`, or who is
allowed to log in. Those are separate changes with their own runbooks.

**Last executed:** 2026-10-22 · Fedora 42 cloud image · OpenSSH 9.9p1
(executed by hand, one step at a time; full transcript in
`ssh-disable-password-auth.evidence.txt`).

---

## 0. Why both `sshd -T` and a new connection

They are different proofs, and a change is not finished until you have both:

| Evidence | Proves | Does **not** prove |
|---|---|---|
| `sshd -T` output | what the daemon will apply, after includes and drop-ins | that the daemon was reloaded, or that a client is refused |
| a new connection attempt | what actually happens on the wire, now | which directive produced it |

Record them separately. "The config looks right" and "the login is refused" fail
for different reasons, and you need to know which one you have.

---

## 1. Before you touch anything

Stop if any of these is false:

- [ ] you have a **second way in** that does not use sshd: provider console, VNC,
      serial, physical access. If you don't, do not start.
- [ ] your public key is already in `~/.ssh/authorized_keys` on the target account
- [ ] you can reach the host by address, not only by an `~/.ssh/config` alias
      (the alias may be doing the key selection for you)

Record the starting state. Keep the output; it is the "before" half of your
evidence.

```sh
date -u
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|maxauthtries) '
sudo grep -rEi '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication)' \
     /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
sudo ss -tlnp | grep ':22 '
```

Expected: `passwordauthentication yes` — otherwise the change is already done and
you should confirm that before proceeding.

The third command is the one people skip. On stock cloud images the value usually
lives in a **drop-in** (`/etc/ssh/sshd_config.d/*.conf`), not in the main file.
Editing the main file and reloading then changes nothing, and it takes an hour to
notice.

---

## 2. Prove key access works — in a new session, before the change

This is the step that prevents lockouts. Do it now, while you can still fall back.

```sh
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
    -o BatchMode=yes USER@HOST 'echo key-ok'
```

Expected: `key-ok`.

- If it prints `Permission denied (publickey)` → **STOP.** Your key is not in
  place. Fix that first; you are not making any config change until this passes.
- If it asks for a password → your key is not being used; the login is falling
  back to password auth. Stop for the same reason.

Close the session when done. A session opened *before* the change is not evidence
that the change worked.

---

## 3. Make the change

Add a drop-in instead of editing `sshd_config`. It survives package updates, is
easy to remove, and is visible in one `ls`.

**The number in the filename is the whole game.** sshd reads config in order and
the **first** value it sees wins. Drop-ins are read in lexical order, so a
`60-…` file loses to an earlier `50-…` file that says the opposite. Use a prefix
that sorts first, and check what is already there:

```sh
ls -l /etc/ssh/sshd_config.d/
sudo grep -rEi '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication)' /etc/ssh/sshd_config.d/
```

Then write your file, with a number lower than anything it must beat:

```sh
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
  | sudo tee /etc/ssh/sshd_config.d/00-no-password-auth.conf >/dev/null
sudo chmod 644 /etc/ssh/sshd_config.d/00-no-password-auth.conf
```

`KbdInteractiveAuthentication no` matters: PAM can still accept passwords through
keyboard-interactive even when `PasswordAuthentication` is `no`. Both off is the
state you actually mean.

Validate before reloading:

```sh
sudo sshd -t
```

Expected: no output. `sshd -t` checks syntax, not intent — silence means the file
parses, nothing more. It will happily accept a file that loses the ordering race.

```sh
sudo systemctl reload sshd
```

`reload` re-reads the config without dropping existing sessions; `restart` would.
Do not restart sshd from the session you are logged in through unless you have a
console fallback.

> This is not theory. The first execution of this runbook used `60-…` and
> `sshd -T` kept reporting `passwordauthentication yes` — the value from
> `/etc/ssh/sshd_config.d/50-cloud-init.conf` won. Same content, different
> number, different result. The evidence file shows both attempts.

---

## 4. Validate the effective state

```sh
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
sudo systemctl is-active sshd
sudo ss -tlnp | grep ':22 '
```

Expected:

```
passwordauthentication no
kbdinteractiveauthentication no
active
LISTEN ... :22 ...
```

If the values are still `yes` → your drop-in lost the ordering race, or is in a
directory sshd does not read. Check `sudo sshd -T -C user=USER,host=HOST,addr=0.0.0.0`
and look for an earlier-sorted file that sets the opposite value.
---

## 5. Prove the change from a new connection

Two proofs, both in fresh sessions:

**Password must be refused.**

```sh
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    USER@HOST
```

Expected: `Permission denied (publickey).` — the server advertises only the
methods still enabled. If you get a password prompt, the change is not in effect,
regardless of what `sshd -T` said.

**Key must still work.**

```sh
ssh -o PreferredAuthentications=publickey -o BatchMode=yes USER@HOST 'echo key-ok'
```

Expected: `key-ok`.

A change is complete when both hold: refused from one path, admitted from the
other.

---

## 6. Rollback

Config-level rollback, when you still have access:

```sh
sudo rm /etc/ssh/sshd_config.d/60-no-password-auth.conf
sudo sshd -t
sudo systemctl reload sshd
sudo sshd -T | grep ^passwordauthentication    # expect: yes
```

Then repeat step 5: password logins work again, key logins still work.

If you are locked out — no key, password disabled, current session dropped — the
only path back is out-of-band: provider console, VNC, serial, or a rescue boot.
This is why step 1 asks about console access before anything else.

---

## 7. When to stop

Stop, roll back, and write down what happened if any of these is true:

- step 2 does not print `key-ok`
- there is no out-of-band way in
- `sshd -t` prints anything
- after reload, `sshd -T` disagrees with the drop-in
- the password attempt in step 5 still prompts
- you are the only person with access and nobody else can verify a login

Stopping is a successful outcome. A half-applied auth change on a host you cannot
reach is not.

---

## Evidence — execution of 2026-10-22

Environment: Fedora 42 cloud image, OpenSSH 9.9p1, QEMU/KVM VM, user-mode
networking (`ssh -p 2222`). The host is disposable, which is the point: the
runbook was executed before being written down.

**Before** (step 1):

```
$ sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
passwordauthentication yes
kbdinteractiveauthentication no

$ sudo grep -rEi '^\s*(PasswordAuthentication|KbdInteractiveAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
/etc/ssh/sshd_config.d/50-redhat.conf:KbdInteractiveAuthentication no
/etc/ssh/sshd_config.d/50-cloud-init.conf:PasswordAuthentication yes
```

The value was **declared in a drop-in**, not in `/etc/ssh/sshd_config`.

**Key access before the change** (step 2):

```
$ ssh -o PreferredAuthentications=publickey -o BatchMode=yes -p 2222 lab@127.0.0.1 'echo key-ok'
key-ok
```

**After** (steps 4 and 5): full transcript in
`docs/runbooks/ssh-disable-password-auth.evidence.txt`. The short version:

```
$ password-only login (after) — must be refused
lab@127.0.0.1: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).

$ key login in a new session (after) — must succeed
key-ok
```

**Rollback was executed too**, not assumed: removing the drop-in, reloading, and
confirming that password login works again, then re-applying the change for the
final state. A rollback you have never run is a story, not a rollback.

**Three things went wrong, and they stayed in the write-up.** They are the
useful part of this document:

1. **The ordering race.** The first attempt wrote `60-no-password-auth.conf` and
   `sshd -T` still said `passwordauthentication yes` — `50-cloud-init.conf` won.
   Same content, different number, different result. That is now step 3.
2. **The block went to the wrong host.** Step 3 was pasted into the operator's
   workstation instead of the VM. Nothing broke (`sshd` was inactive there), but
   the change "didn't work" for a reason unrelated to sshd. **Check the prompt
   before pasting.**
3. **Multi-line paste interleaved.** `printf … | sudo tee …` plus following lines
   executed out of order: the drop-in was created empty, and `sshd -t` still
   passed, because an empty file is valid config. One line at a time is slower
   and safer. A typo in a `grep` key prints nothing, which looks identical to a
   broken system — silent output is not proof.

### Limits of this evidence

- One execution, one distribution, one OpenSSH version. It shows the procedure
  works, not that it is universal.
- User-mode QEMU networking means connections arrive from `10.0.2.2`; a real
  network adds a firewall and possibly a jump host, neither of which is exercised
  here.
- The VM had a console fallback. On a host without one, the stop conditions in
  step 7 apply before anything is changed.

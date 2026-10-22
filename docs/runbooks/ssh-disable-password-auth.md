# Runbook: disable SSH password authentication

A runbook is a procedure you can follow while tired. Every step has a command,
what you expect to see, and what to do when you don't see it.

**Change:** after this, only key-based logins succeed. Passwords stop working.

**This does not** change the port, the firewall, `PermitRootLogin`, or who is
allowed to log in. Those are separate changes with their own runbooks.

**Path used throughout:**

```sh
DROPIN=/etc/ssh/sshd_config.d/00-no-password-auth.conf
```

Application and rollback use this one variable. A rollback that removes a
different filename than the one you created is a rollback that does nothing.

**Last executed:** 2026-10-22 · Fedora 42 cloud image · OpenSSH 9.9p1 · QEMU/KVM
VM, twice: the original run (`…evidence.txt`) and a second run of the corrected
procedure after the filename mismatch was found (`…evidence-2026-10-22-run2.txt`).

**Portability:** the service name and the drop-in directory are distribution
facts, not SSH facts. This runbook was tested on Fedora 42, where the unit is
`sshd.service` and `/etc/ssh/sshd_config.d/*.conf` is included by the shipped
`sshd_config`. On Debian/Ubuntu the unit is usually `ssh.service`, so
`systemctl reload ssh` is the equivalent; other distributions may not include the
directory at all. Confirm with `sshd -T` — if your drop-in has no effect, check
whether anyone includes it. Details in the "Limits" section.

---

## 0. Why both `sshd -T` and a new connection

They are different proofs, and a change is not finished until you have both:

| Evidence | Proves | Does **not** prove |
|---|---|---|
| `sshd -T` output | what the daemon will apply, after includes and drop-ins | that the daemon was reloaded, or that a client is refused |
| a new connection attempt | what actually happens on the wire, now | which directive produced it |

Record them separately. "The config looks right" and "the login is refused" fail
for different reasons, and you need to know which one you have.

`sshd -T` reports the configuration **after** `Include` and `Match` processing.
`Include` expands its globs and processes the files in lexical order, and for each
keyword **the first obtained value is used** (see `man 5 sshd_config`). That is
why the filename prefix matters, and why a value you grep out of a file is not
necessarily the value in effect.

---

## 1. Before you touch anything

Stop if any of these is false:

- [ ] you have a **second way in** that does not use sshd: provider console, VNC,
      serial, physical access. If you don't, do not start.
- [ ] your public key is already in `~/.ssh/authorized_keys` on the target account
- [ ] you can reach the host by address, not only by an `~/.ssh/config` alias
      (the alias may be doing the key selection for you)

Record the starting state. Keep the output verbatim; it is the "before" half of
your evidence **and** the reference that rollback restores to.

```sh
date -u
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
sudo grep -rEi '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication)' \
     /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
sudo ls -l /etc/ssh/sshd_config.d/
sudo test -e /etc/ssh/sshd_config.d/00-no-password-auth.conf \
     && echo "TARGET EXISTS - read step 3 before continuing"
```

Expected: `passwordauthentication yes` — otherwise the change is already done and
you should confirm that before proceeding.

Write down the two values you observed. Not "the secure value": **the values that
were in effect**, whatever they are. Rollback restores those, and they are not
always `yes`.

The `grep` is the command people skip. On stock cloud images the value usually
lives in a **drop-in** (`/etc/ssh/sshd_config.d/*.conf`), not in the main file.
Editing the main file and reloading then changes nothing, and it takes an hour to
notice.

---

## 2. Prove key access works — in a new session, before the change

This is the step that prevents lockouts. Do it now, while you can still fall back.

```sh
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
    -o BatchMode=yes -o ControlMaster=no -o ControlPath=none \
    USER@HOST 'echo key-ok'
```

Expected: `key-ok`.

- If it prints `Permission denied (publickey)` → **STOP.** Your key is not in
  place. Fix that first; you are not making any config change until this passes.
- If it asks for a password → your key is not being used; the login is falling
  back to password auth. Stop for the same reason.

`ControlMaster=no -o ControlPath=none` disable connection multiplexing for this
invocation. Without them, ssh may silently reuse an already-open master
connection: you think you tested a new login, while the server never saw one. A
multiplexed session is not a new connection and is not evidence.

Close the session when done. A session opened *before* the change is not evidence
that the change worked.

---

## 3. Make the change

Add a drop-in instead of editing `sshd_config`. It survives package updates, is
easy to remove, and is visible in one `ls`.

**First: does the file already exist?** If
`/etc/ssh/sshd_config.d/00-no-password-auth.conf` is already there, it is someone
else's file — yours, a previous automation, a configuration management system.
**Do not overwrite it.** Read it, decide whether it is yours to change, and if
not, pick a name you know is unused. Overwriting and later deleting a file you did
not create leaves the host in a state nobody recorded.

**The number in the filename is the whole game.** sshd reads config in order and
the **first** value it sees wins. Drop-ins are read in lexical order, so a
`60-…` file loses to an earlier `50-…` file that says the opposite. Use a prefix
that sorts first, and check what is already there:

```sh
sudo ls -l /etc/ssh/sshd_config.d/
sudo grep -rEi '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication)' /etc/ssh/sshd_config.d/
```

Then write your file, with a number lower than anything it must beat:

```sh
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
  | sudo tee "$DROPIN" >/dev/null
sudo chmod 644 "$DROPIN"
sudo cat "$DROPIN"
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

**If `sshd -t` prints anything: stop.** Do not reload. Remove the file you just
created and investigate — the daemon is still running on the old configuration,
which is exactly where you want to be while you read the error.

```sh
sudo rm "$DROPIN"        # only the file you created in this step
```

Only when `sshd -t` is silent:

```sh
sudo systemctl reload sshd
```

`reload` re-reads the config without dropping existing sessions; `restart` would.
Do not restart sshd from the session you are logged in through unless you have a
console fallback. (On Debian/Ubuntu the unit is `ssh`, not `sshd`.)

> This is not theory. The first execution of this runbook used `60-…` and
> `sshd -T` kept reporting `passwordauthentication yes` — the value from
> `/etc/ssh/sshd_config.d/50-cloud-init.conf` won. Same content, different
> number, different result. The evidence files show both attempts.

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

If a value is still `yes` → your drop-in lost the ordering race, or the directory
is not included, or a `Match` block applies to the connection you tested.

For the `Match` case, ask sshd what it would apply for a specific connection:

```sh
sudo sshd -T -C user=USER,host=HOST,addr=CLIENT_ADDR
```

All three are **your** values for the connection you are checking:

- `user=` — the account you log in as
- `host=` — the name the client connected to (what `$SSH_CONNECTION`/the client
  used), because `Match Host` compares against the resolved name
- `addr=` — the client's **source** address as the server sees it

Find the real source address from a live session with `echo $SSH_CONNECTION`
(its first field is the client address) or from `who`/`ss`. `addr=0.0.0.0` is not
a universal "any client": inside a `Match Address` block it is a specific value
that can select or skip rules. Use the address you actually connect from.

---

## 5. Prove the change from a new connection

Two proofs, both in fresh sessions. Both commands disable multiplexing, so the
server really sees a new connection.

**Password must be refused.**

```sh
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o ControlMaster=no -o ControlPath=none \
    USER@HOST
```

Expected: `Permission denied (publickey).` — the server advertises only the
methods still enabled. If you get a password prompt, the change is not in effect,
regardless of what `sshd -T` said.

If you do get a prompt, type the **correct** password. A refusal after a correct
password is evidence; a refusal after a wrong one is not.

**Key must still work.**

```sh
ssh -o PreferredAuthentications=publickey -o BatchMode=yes \
    -o ControlMaster=no -o ControlPath=none \
    USER@HOST 'echo key-ok'
```

Expected: `key-ok`.

A change is complete when both hold: refused from one path, admitted from the
other.

---

## 6. Rollback

Remove **the same path** you created in step 3, and nothing else:

```sh
echo "$DROPIN"                    # confirm it is the file you created
sudo rm "$DROPIN"
sudo sshd -t
sudo systemctl reload sshd
```

Then compare against the values you recorded in step 1 — both of them:

```sh
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
```

Expected: the **recorded initial values**. Those may be `passwordauthentication
yes` and `kbdinteractiveauthentication no`, or another combination. Do not assume
`yes` for either: `KbdInteractiveAuthentication` is frequently already `no` on
cloud images, and a rollback that "restores" `yes` there has changed the host
rather than restored it.

If the values do not match what you recorded, stop and investigate. Something
other than your drop-in changed; guessing at it is how a host ends up in a state
nobody can explain.

Then repeat step 5: password logins work again, key logins still work.

If you are locked out — no key, password disabled, current session dropped — the
only path back is out-of-band: provider console, VNC, serial, or a rescue boot.
This is why step 1 asks about console access before anything else.

---

## 7. When to stop

Stop, roll back, and write down what happened if any of these is true:

- step 2 does not print `key-ok`
- the target drop-in already exists and you do not know who owns it
- there is no out-of-band way in
- `sshd -t` prints anything (do not reload)
- after reload, `sshd -T` disagrees with the drop-in
- the password attempt in step 5 still prompts
- rollback does not reproduce the values recorded in step 1
- you are the only person with access and nobody else can verify a login

Stopping is a successful outcome. A half-applied auth change on a host you cannot
reach is not.

---

## Evidence — execution of 2026-10-22

Two transcripts, both kept as they were produced:

| Run | Procedure | Transcript |
|---|---|---|
| 1 | original (wrong filename in rollback) | `…evidence.txt` |
| 2 | corrected, this document | `…evidence-2026-10-22-run2.txt` |

The first transcript is not edited. Renaming a file does not make its results
newer, and a transcript rewritten to match the current procedure stops being
evidence.

Environment: Fedora 42 cloud image, OpenSSH 9.9p1, QEMU/KVM VM, user-mode
networking (`ssh -p 2222`), console available through the serial log. The host is
disposable, which is the point.

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

**After** (steps 4 and 5), from run 1:

```
$ password-only login (after) — must be refused
lab@127.0.0.1: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).

$ key login in a new session (after) — must succeed
key-ok
```

**Rollback was executed**, not assumed: removing the drop-in, reloading, and
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
3. **The rollback named a different file than the apply step.** The procedure
   created `00-…` and removed `60-…`. A reader following it exactly would have
   removed nothing, seen `passwordauthentication no` persist, and concluded the
   rollback had failed. Fixed by the `DROPIN` variable used by both steps.

### Limits of this evidence

- Two runs, one distribution, one OpenSSH version. It shows the procedure works
  on that combination, not that it is universal.
- User-mode QEMU networking means connections arrive from `10.0.2.2`; a real
  network adds a firewall and possibly a jump host, neither of which is exercised
  here. `Match Address` rules in particular are not exercised by this VM.
- The VM had a console fallback. On a host without one, the stop conditions in
  step 7 apply before anything is changed.
- The drop-in directory and the `sshd` unit name are Fedora facts. See the
  portability note at the top.

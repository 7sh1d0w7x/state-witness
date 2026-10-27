# Runbook: sudoers least privilege

A runbook is a procedure you can follow while tired. Every step has a command,
what you expect to see, and what to do when you don't see it.

**Change:** after this, one rule that granted `sudo` to a group is removed. The
group keeps existing; it simply no longer carries privilege.

**This does not** remove `%sudo`, does not touch `NOPASSWD` entries, does not
change group membership, and does not modify anything in `/etc/sudoers.d/`.
Removing a *different* rule than the one you intended is the main risk here, and
this runbook is built around catching that.

**Path used throughout:**

```sh
SUDOERS=/etc/sudoers
BACKUP=/etc/sudoers.bak-$(date +%F)
COPY=/etc/sudoers.new
RULE='%admin ALL=(ALL) ALL'
```

**Last executed:** 2026-10-27 · Ubuntu 26.04 · sudo 1.9.x · QEMU/KVM VM.
See `sudoers-least-privilege.evidence-2026-10-27.txt` for the transcripts.

---

## 0. Why the edit happens on a copy

`visudo` protects the file by validating on save. Two things often defeat that
protection in practice:

1. the editor opens, the save key sequence is wrong or the terminal swallows it,
   and `visudo` exits having written nothing — which looks like success;
2. the operator edits the live file with another tool and validates afterwards,
   when the broken file is already in place.

Editing a **copy**, validating the copy, and installing the copy only on success
removes both. The validation is the protection; the editor is just a way to move
text around.

> [!important] The ordering that matters
> copy → edit copy → `visudo -c -f <copy>` → `install` → verify.
> If the validation fails, the live file was never touched.

---

## 1. Before you touch anything

Stop if any of these is false:

- [ ] a **second root-capable session is open** and stays open until §5 passes
      (a second SSH session, or the provider console)
- [ ] you can name the exact rule you are removing, as it appears in the file
- [ ] you have confirmed the group the rule refers to is not used by anything
      that would lose access silently
- [ ] you know your own privilege does **not** depend on the rule being removed

Check the last two:

```sh
getent group admin
getent group sudo
```

`admin` should have no members. `sudo` must contain your account — that is the
line you are keeping.

---

## 2. Capture the state before

```sh
sudo cp "$SUDOERS" "$BACKUP"
sudo grep -n '^%' "$SUDOERS"
sudo -l -U "$(whoami)" | tail -3
```

Expected shape (the line numbers vary by distribution):

```
50:%admin ALL=(ALL) ALL
53:%sudo  ALL=(ALL:ALL) ALL

User lab may run the following commands on lab:
    (ALL : ALL) ALL
```

The backup is not optional: §5 compares against it, and §6 restores from it.

---

## 3. Edit the copy

```sh
sudo cp "$SUDOERS" "$COPY"
sudo sed -i "/^${RULE//\//\\/}/d" "$COPY"
sudo grep -n '^%' "$COPY"
```

Expected: the `admin` line is gone, `%sudo` is still there. **If the line is
still present, stop** — `sed` matched nothing and the pattern needs adjusting
(whitespace, tabs, a `Defaults` prefix). Continuing here installs an unchanged
file and reports success.

Check that exactly one line differs:

```sh
sudo diff "$SUDOERS" "$COPY"
```

Expected: one `d` chunk and one `<` line — the rule you meant to remove. Anything
else means the pattern matched more than intended.

---

## 4. Validate, then install

```sh
sudo visudo -c -f "$COPY"
```

- `parsed OK` → continue.
- any error → **stop**. Delete the copy, keep the live file, re-read §3.

```sh
sudo install -m 440 -o root -g root "$COPY" "$SUDOERS"
sudo rm "$COPY"
```

`install` rather than `cp` because it sets mode and ownership in the same step.
`cp` over a `440 root:root` file preserves the mode only if you are root and the
destination already exists — `install` does not depend on that.

---

## 5. Prove it

Four checks, in this order. Each answers a different question.

```sh
sudo visudo -c
sudo grep -n '^%' "$SUDOERS"
sudo diff "$BACKUP" "$SUDOERS"
sudo -l -U "$(whoami)" | tail -3
```

| Check | Expected | Proves |
|---|---|---|
| `visudo -c` | `parsed OK` | the live file is syntactically valid |
| `grep -n '^%'` | only `%sudo` | the rule is gone, not merely moved |
| `diff` | one `<` line | nothing else changed |
| `sudo -l` | `(ALL : ALL) ALL` | your own access survived |

The `diff` is the one that catches a wrong-line removal. The `sudo -l` is the one
that catches a lockout before you close the second session.

Also confirm the file mode:

```sh
sudo ls -l "$SUDOERS"      # -r--r----- 1 root root
```

---

## 6. Rollback

```sh
sudo install -m 440 -o root -g root "$BACKUP" "$SUDOERS"
sudo visudo -c
```

Then re-run §5. Rollback restores the whole file, so any change made between the
backup and now is also reverted — that is the point of taking the backup first,
and also the reason not to reuse a backup from another day.

---

## 7. Limits

- **Aliases hide rules.** `User_Alias ADMINS = …` followed by `ADMINS ALL=(ALL) ALL`
  has no `%` at the start and is invisible to `grep '^%'`. Read the file once in
  full when a rule is hard to find.
- **`@includedir` moves rules out of sight.** Anything in `/etc/sudoers.d/` can
  grant the same privilege. A check that stops at `/etc/sudoers` is incomplete.
- **`Match` blocks and `Defaults` can widen or narrow a rule** without changing
  the line you removed.
- **Groups can be defined outside the file** (LDAP, SSSD). `getent group` asks the
  same sources sudo does; `/etc/group` does not.
- **An empty group is still a door.** The rule is removed here because the group
  granted root to anyone added to it later. Removing the rule does not remove the
  group, and that is intentional — deleting the group is a separate, riskier change.
- **File context matters on SELinux systems.** `install` keeps the default
  context of the destination; if you copy across filesystems, check with
  `ls -Z` before validating.

---

## 8. What to keep as evidence

```
   group      getent group admin                 (empty)
   before     sudo grep -n '^%' $SUDOERS
   diff       sudo diff $BACKUP $SUDOERS         ← one line, the intended one
   syntax     sudo visudo -c
   access     sudo -l -U $(whoami) | tail -3     ← unchanged
   mode       sudo ls -l $SUDOERS
```

The `diff` plus `sudo -l` pair is the deliverable: it shows the change was
narrow and that nobody lost access because of it.

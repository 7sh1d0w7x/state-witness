# Runbook: backup and verified restore (restic)

A backup you have never restored is a hope with a schedule. This runbook ends with a
restore that either matches by checksum or the backup is not done.

**Scope:** a directory tree (here `~/opencode/dev`) into a local restic repository.
**Not covered:** off-machine copies, cloud storage, encryption keys of the host, or
application-level consistency (databases). A copy on the same disk protects against
deletion and mistakes, **not** against disk failure.

**Last executed:** 2026-10-25 · restic 0.17.3 · Fedora 42 (Bazzite) · vault ≈ 208 MB
in snapshot, 114 MB on disk.

---

## 1. Before you start

- [ ] `restic version` answers
- [ ] you have a place for the repository with room to grow
- [ ] you accept that **losing the password loses the data** — there is no recovery
- [ ] you know what you are *not* backing up, and why

Know the size you are actually protecting. Build artifacts, caches and existing
archives inflate a backup without adding recoverable value:

```sh
du -sh --exclude=target --exclude=node_modules --exclude=.smart-env .   # ~218 MB
du -sh projects/*/target .smart-env backups                             # excluded
```

---

## 2. Initialise once

The password goes to a file with `600`, never into the repository command line (it ends
up in `ps` and in shell history).

```sh
mkdir -p ~/.config/restic && chmod 700 ~/.config/restic
openssl rand -base64 24 > ~/.config/restic/vault.pass
chmod 600 ~/.config/restic/vault.pass
```

**Now copy that password into a password manager.** A password that exists only on the
disk being backed up is not a password, it is a second copy of the risk.

```sh
export RESTIC_REPOSITORY=/mnt/data/backup/vault-restic
export RESTIC_PASSWORD_FILE=$HOME/.config/restic/vault.pass
restic init
```

---

## 3. Back up

```sh
restic backup "$HOME/opencode/dev" \
  --exclude target --exclude node_modules --exclude .smart-env \
  --exclude 'backups/*' --exclude '*.iso' --exclude '*.tgz' \
  --tag vault
```

The excludes are the whole value of this step: without them this repository would hold
580 MB of Rust build output and 145 MB of archives that already exist elsewhere.

Retention (what keeps it from growing forever):

```sh
restic forget --tag vault --keep-daily 7 --keep-weekly 4 --keep-monthly 3 --prune
```

---

## 4. Verify integrity

```sh
restic check
```

Expected: `no errors were found`. This checks the repository structure and blobs, not
your ability to restore a specific file — that is the next step, and it is the one that
counts.

---

## 5. Restore test (the step people skip)

Restore a small set to a throwaway directory and compare checksums:

```sh
rm -rf /tmp/restore-test && mkdir -p /tmp/restore-test

for f in INDEX.md personal/neuro/interoceptie-tensiune-nesimtita.md \
         projects/state-witness/docs/runbooks/firewall-baseline.md; do
  restic restore latest --target /tmp/restore-test \
    --include "/home/USER/opencode/dev/$f"
  a=$(sha256sum "$HOME/opencode/dev/$f" | cut -d' ' -f1)
  b=$(sha256sum "/tmp/restore-test/home/USER/opencode/dev/$f" | cut -d' ' -f1)
  [ "$a" = "$b" ] && echo "OK  $f" || echo "DIFF $f"
done
```

Expected: `OK` for every file. A restore that produces a file of the right name but the
wrong bytes is worse than no restore, because it looks like success.

Full restore, when you actually need it:

```sh
restic restore latest --target /tmp/full-restore
# then copy back what you need; never restore over the live tree while working in it
```

---

## 6. Schedule it (otherwise it is decoration)

A user timer is enough; no root needed.

```sh
# ~/.config/systemd/user/vault-backup.service
[Service]
Type=oneshot
ExecStart=/home/USER/opencode/dev/scripts/vault-backup.sh

# ~/.config/systemd/user/vault-backup.timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now vault-backup.timer
systemctl --user list-timers vault-backup
```

`Persistent=true` matters on a laptop: a missed run (machine off) executes at the next
boot instead of silently skipping.

The script logs to `~/.local/state/restic/backup-YYYY-MM-DD.log` and exits non-zero on
failure, so `systemctl --user status vault-backup` is a real signal.

---

## 7. Restore from a different snapshot

```sh
restic snapshots                        # pick an id
restic restore <id> --target /tmp/older
```

Snapshots are independent; restoring an older one does not affect the newer ones.

---

## 8. When to stop

- `restic check` reports anything → do not trust the repository; start a new one rather
  than pruning a damaged one
- the restore test shows `DIFF` → the backup is not valid, whatever `check` said
- the password is not in a password manager → fix that before adding data
- the repository is on the same disk and you have no second copy → you have a
  deletion-recovery, not a backup

---

## Evidence (2026-10-25)

```
$ restic snapshots --compact
52ecaa07  2026-10-25 22:04:19  bazzite  vault   208.350 MiB
  1 snapshots
  dimensiune repo: 114 MB

$ restic check
check snapshots, trees and blobs
[0:00] 100.00%  1 / 1 snapshots
no errors were found

$ restic restore latest --target /tmp/restore-test --include ".../INDEX.md"
✅ INDEX.md (sha256 identic)
✅ personal/neuro/interoceptie-tensiune-nesimtita.md (sha256 identic)
✅ projects/state-witness/docs/runbooks/firewall-baseline.md (sha256 identic)
```

Second run through the script (`vault-backup.sh`): 3 seconds, `backup ok`, second
snapshot created, retention and check executed without errors.

### Limits of this evidence

- Same-disk repository. It demonstrates deletion recovery, **not** disk-failure
  recovery. An external copy is a separate, still-missing step.
- One directory tree, one machine, one restic version.
- The restore test covers three files, not the whole tree. A full-restore drill is
  worth doing once before trusting the repository with anything irreplaceable.
- Encryption depends entirely on the password file; there is no key escrow.

---

## Related

`docs/runbooks/ssh-disable-password-auth.md` — the same rule applied elsewhere: an
action is not finished until a *different* kind of evidence confirms it.

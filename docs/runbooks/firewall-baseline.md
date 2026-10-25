# Runbook: firewall baseline (nftables, default-deny inbound)

A runbook is a procedure you can follow while tired. This one has a step whose whole
point is to lock you out — so it is also a test of your out-of-band access.

**Change:** inbound traffic is dropped by default; only SSH, loopback, established
connections and ICMP are allowed. Outbound stays open.

**This does not** configure NAT, forwarding, per-service rules or logging. Those are
separate changes.

**Last executed:** 2026-10-25 · Fedora 42 cloud image · nftables 1.1.1 · QEMU/KVM VM
with a serial console (two runs: the first exposed a rule-ordering mistake, the second
proved lockout and recovery).

**Portability:** nftables is the default on Fedora/RHEL/Debian/Arch. On hosts running
`firewalld` or `ufw`, do not mix them with a raw ruleset — pick one owner for the
firewall. This runbook assumes nothing else manages the ruleset.

---

## 0. The rule that makes this safe

nftables evaluates rules **in order, first match wins**. Every mistake in this area is
an ordering mistake: a `drop` after an `accept` for the same traffic does nothing, and
you will believe you tested the firewall when you tested nothing.

That is not theory. In the first execution of this runbook the lockout rule was
**appended** after `tcp dport 22 accept`. SSH kept working, exit code 0, and the test
"passed" while proving the opposite. See
`firewall-baseline.evidence-2026-10-25-run1.txt`.

---

## 1. Before you touch anything

Stop if any of these is false:

- [ ] you have a **console** that does not go through the network: serial, provider
      VNC, physical. A firewall mistake removes SSH; nothing else removes the console.
- [ ] you know which port carries your session (22 here) and whether it is custom
- [ ] you know the **source address** the server sees for you. Behind NAT that is not
      your laptop address; check `echo $SSH_CONNECTION` in the session.

Record the starting state:

```sh
date -u
sudo nft list ruleset                 # empty output = no ruleset
sudo ss -tlnp | grep LISTEN
echo $SSH_CONNECTION                  # client_addr client_port server_addr server_port
```

If `nft list ruleset` already returns tables, something else owns the firewall. Stop
and find out what, before adding a second owner.

---

## 2. Write the ruleset to a file, not to the command line

A file loads atomically: either the whole ruleset applies or nothing does. Typing rules
one by one leaves you half-configured when the third command is the one that cuts you
off.

```sh
cat > /tmp/baseline.nft <<'EOF'
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
```

Check, then load:

```sh
sudo nft -c -f /tmp/baseline.nft      # parse only, changes nothing
sudo nft -f /tmp/baseline.nft         # atomic apply
```

`nft -c` catches syntax, not intent. Silence means it parses.

---

## 3. Verify that you still have access

From a **new** connection (not the session you already had open):

```sh
ssh -o ControlMaster=no -o ControlPath=none USER@HOST 'echo still-in'
```

Expected: `still-in`.

Your existing session survives even if the ruleset is wrong, because established
connections are accepted. That is exactly why the check must be a new connection — the
old one proves nothing.

---

## 4. Prove the firewall actually blocks (the lockout test)

Do this on a disposable host, or with a console you have already tested. The procedure
is worthless if you never saw it block.

Insert the rule **at the top** of the chain:

```sh
sudo nft insert rule inet filter input ip saddr CLIENT_ADDR tcp dport 22 drop
```

`insert` puts it first; `add` appends it last, which is the mistake described in §0.
Replace `CLIENT_ADDR` with the address from `$SSH_CONNECTION` (in this lab, `10.0.2.2`).

From a new connection:

```sh
ssh -o ControlMaster=no -o ControlPath=none USER@HOST 'echo should-not-arrive'
```

Expected: failure — `Connection timed out`, `Connection refused`, or a hang. Any of
them means the rule matched.

---

## 5. Recover from the console

On the console:

```sh
sudo nft flush ruleset
```

Then, from the workstation:

```sh
ssh -o ControlMaster=no -o ControlPath=none USER@HOST 'echo back-in'
```

Expected: `back-in`. Recovery is one command because the ruleset was never persisted
yet — that is deliberate. Persistence comes only after the lockout test passes.

If this step fails, you are in the "no access, no console" case that step 1 exists to
prevent. Nothing later in this runbook helps.

---

## 6. Persist, only now

```sh
sudo nft list ruleset | sudo tee /etc/nftables.conf >/dev/null
sudo systemctl enable --now nftables.service
sudo systemctl status nftables.service --no-pager | head -5
sudo reboot            # optional: prove it survives a boot
```

After a reboot, repeat §3 with a new connection. A ruleset that does not survive a
reboot is a suggestion.

---

## 7. Rollback

Immediate, without persistence:

```sh
sudo nft flush ruleset
```

With persistence:

```sh
sudo systemctl disable --now nftables.service
sudo rm -f /etc/nftables.conf
sudo nft flush ruleset
```

Then verify from a new connection, not the old one.

---

## 8. When to stop

- no console access → do not start
- `nft list ruleset` shows tables you did not create → find the owner first
- `nft -c -f` reports anything → fix the file, do not load
- the new connection in §3 fails immediately after loading → flush from console
- the lockout test does **not** block → your rule is in the wrong position; fix the
  ordering before going further
- the ruleset does not survive a reboot → persistence step is incomplete

---

## Evidence

| Run | What it shows | Transcript |
|---|---|---|
| 1 | appended `drop` after `accept` had no effect — SSH still worked (exit 0) | `firewall-baseline.evidence-2026-10-25-run1.txt` |
| 2 | `insert` at top blocks (`exit 255`), console `flush` recovers, access restored | `firewall-baseline.evidence-2026-10-25-run2.txt` |

Environment: Fedora 42 cloud image, nftables 1.1.1, QEMU/KVM, user-mode networking,
serial console. The client address is `10.0.2.2` because of user-mode NAT; on a real
network it is the address the server sees, not the one your laptop believes it has.

### Limits of this evidence

- One distribution, one nftables version, IPv4 only for the block test. IPv6 was
  allowed but not exercised.
- User-mode networking means no NAT rules, no forwarding, no upstream firewall —
  none of which this runbook covers.
- The host was disposable and the console was tested before the change. On a host
  where the console is untested, step 1 stops the procedure.

---

## Related

`state-witness firewall` checks whether a ruleset exists at all (`FW-001`). This
runbook is what you do about it; the check is how you know it is still true later.

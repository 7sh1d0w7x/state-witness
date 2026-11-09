# How `state-witness` compares

Three tools, three different questions. This is not a ranking — it is a map of
where each one is the right instrument, and where it is not.

| | `state-witness` | Lynis | OpenSCAP (`oscap` + SCAP Security Guide) |
|---|---|---|---|
| **Primary question** | What does this host enforce *right now*, and which command or file produced each value? | How hardened is this host, broadly, and what should I improve? | Does this host meet profile X, and what is the evidence? |
| **Source of truth** | Effective state: `sshd -T`, `sysctl -n`, the live `nft`/`ufw`/`firewalld` state, `/etc/passwd` and `/etc/shadow` | Mixed: config files plus whichever commands the host happens to provide (opportunistic) | SCAP content (XCCDF + OVAL) evaluated by the `oscap` engine |
| **Scope** | 25 checks across 5 areas | Hundreds of individual tests across the whole system | Hundreds to thousands of rules per profile |
| **Immutable / atomic hosts** | First-class: deployment image, signature, pin state, `/etc` drift (`rpm-ostree status`, `bootc status`, `ostree admin config-diff`) | Works on the host like any other audit; no deployment or drift model | Generic SCAP evaluation; profiles are distribution-specific |
| **Output** | Text for humans, JSON array for machines; every finding carries provenance | Text, `lynis.log`, and `lynis-report.dat` (key/value) | XML/ARF and HTML reports; machine-readable by design |
| **Remediation** | None — read-only | None — suggestions for a human to apply | Yes — `oscap xccdf eval --remediate` can change the host |
| **Compliance profiles** | None | Informal: tests informed by CIS, NIST and vendor guidance | Formal profiles: CIS, DISA STIG, PCI-DSS, USGCB via SCAP Security Guide |
| **Dependencies** | One Rust binary, no runtime engine | Shell and core utilities; installation optional | `oscap` plus a content bundle; larger footprint |
| **License** | MIT OR Apache-2.0 | GPL-3.0 | LGPL-2.1 for the tool; the content is a separate project |

## Where each one wins

**`state-witness`** is narrow on purpose. It wins when the question is *"is this
value actually in force, and can I cite where it came from?"* — after an update, in
a CI diff, or on an atomic host where the interesting fact is which deployment is
booted and what drifted in `/etc`. The output is small enough to read in full, and
every line names its source. It loses on breadth and has no compliance story.

**Lynis** is the broad first look. It runs almost anywhere, needs no installation,
and turns a host into a long list of observations and suggestions. It wins when you
want to learn what is worth looking at, especially on a system you have not audited
before. It is not a formal compliance engine, and its output is designed for a human
reader rather than a strict 0/1 CI gate.

**OpenSCAP** is the formal option. With SCAP Security Guide content it evaluates a
named profile (CIS, STIG, PCI-DSS), produces evidence in a standard format, and can
remediate. It wins when someone else — an auditor, a customer, a regulator — needs
the result in a recognised shape. It is also the heaviest of the three: content must
match the distribution, and remediation is a change to the host, not a report.

## Choosing by situation

| Situation | Start with |
|---|---|
| "Did the SSH baseline survive the last update?" | `state-witness ssh` |
| "What changed on this Bazzite/bootc host after the rebase?" | `state-witness atomic` |
| "Give me a broad hardening review of a server I just inherited" | Lynis |
| "Prove PCI-DSS / STIG compliance to an auditor" | OpenSCAP + SCAP Security Guide |
| "Fail the pipeline if password auth is back on" | `state-witness ssh --json` and the exit code |
| "Show me suggestions, not just findings" | Lynis |
| "Apply the profile, then prove it" | OpenSCAP (remediate), then `state-witness` for the effective values |

They compose. A common sequence is Lynis or OpenSCAP to decide *what* matters,
`state-witness` to confirm what the host actually enforces after the change, then
the same check again in CI so it cannot drift back.

## What `state-witness` does not do

- No compliance control mapping. There is no NIST, CRA or BSI mapping as of v0.2.2.
- No remediation. It never writes to the host.
- 25 checks, not a framework. See [`CHECKS.md`](CHECKS.md) for the exact list.
- No SARIF output yet, and no line numbers inside the file that set a value — the
  `line` field exists in JSON and is currently always `null`.
- Thresholds are defaults, not policy. "ASLR should be 2" is a starting point, not
  a judgement about your host.

## Sources

Checked on 2026-11-09:

- Lynis — <https://cisofy.com/lynis/> · <https://github.com/CISOfy/lynis>
- OpenSCAP — <https://www.open-scap.org/tools/openscap-base/> ·
  <https://github.com/OpenSCAP/openscap>
- SCAP Security Guide — <https://github.com/OpenSCAP/scap-security-guide>
- `state-witness` checks — [`CHECKS.md`](CHECKS.md)

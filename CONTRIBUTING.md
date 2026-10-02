# Contributing

Thanks for your interest in `state-witness`.

## AI usage policy

This project is **human-owned**. AI tools are welcome as *assistants*, but the human contributor stays accountable.

**Required:**
- **Disclose AI use** in your PR description (which tool, for what, e.g. "boilerplate", "tests", "docs").
- **Understand your code.** If a reviewer asks "why this design?", you must be able to explain it.
- **Mark AI-generated code** in commit messages (model + that it was reviewed/verified).
- **Own it.** You are responsible for correctness, security, and maintenance of anything you submit.

**Not accepted:**
- Code you cannot explain.
- Undisclosed, purely AI-generated submissions.
- Bulk AI PRs without engagement (review cost ≫ generation cost).

> Rationale: generating a plausible-but-wrong PR takes seconds; reviewing it takes hours. See the NLnet GenAI policy and the 2025–2026 OSS maintainer consensus.

## Workflow

1. **Open an issue first** for non-trivial changes (so we agree on the approach).
2. **Spec → test → implement → review.** Tests are the verification instrument.
3. **Run before submitting:**
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```
4. **Small, focused PRs.** One change per PR.

## Security

- Do not open public issues for vulnerabilities — see `SECURITY.md`.
- Security-critical code gets extra scrutiny: trust boundaries, `unsafe`, input parsing, privilege handling.

## Licence

By contributing you agree your work is licensed under **MIT OR Apache-2.0** and you accept the project's CLA (see `CLA.md` when present).

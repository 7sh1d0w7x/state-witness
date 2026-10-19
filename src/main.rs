//! state-witness CLI.

use clap::{Parser, Subcommand};

use state_witness::{
    firewall_effective, ostree_effective, ssh_effective, sysctl_effective, users_effective,
    Finding, Status,
};

/// The audit ran and no finding is a `Fail`.
const EXIT_OK: i32 = 0;
/// The audit ran and at least one finding is a `Fail`.
const EXIT_FINDINGS_FAILED: i32 = 1;
/// The audit could not produce a result (usage, I/O, serialization).
const EXIT_ERROR: i32 = 2;

#[derive(Parser)]
#[command(
    name = "state-witness",
    version,
    about = "Effective-state security audit for immutable Linux (ostree, bootc)",
    long_about = "Reports what the host actually enforces (not what the config file says) \
                  and understands ostree/bootc deployments — with provenance."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the effective SSH daemon configuration (sshd -T).
    Ssh {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check immutable/atomic host state (ostree, bootc): deployment + /etc drift.
    Atomic {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check effective kernel parameters (sysctl): runtime hardening knobs.
    Sysctl {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check the effective firewall (nftables / ufw / firewalld).
    Firewall {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check users & sudo (uid-0 accounts, NOPASSWD, empty passwords).
    Users {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show version / status.
    Version,
}

/// The exit policy, shared by every output format.
///
/// `1` if at least one finding is `Fail`; `0` when the report contains only
/// `Pass`, `Warn` and `Skip`. This is the contract documented in the README.
///
/// Execution and serialization errors are **not** audit results, so they never
/// travel through this function: they use [`EXIT_ERROR`] instead. Mixing the two
/// would make "the audit found problems" indistinguishable from "the audit broke".
fn exit_code_for(findings: &[Finding]) -> i32 {
    if findings.iter().any(|f| f.status == Status::Fail) {
        EXIT_FINDINGS_FAILED
    } else {
        EXIT_OK
    }
}

/// Print findings as human-readable text.
///
/// Returns nothing on purpose: the exit code is decided by [`exit_code_for`],
/// so the text and JSON paths cannot drift apart again.
fn print_text(findings: &[Finding]) {
    for f in findings {
        let mark = match f.status {
            Status::Pass => "\u{2713}", // ✓
            Status::Warn => "!",        // !
            Status::Fail => "\u{2717}", // ✗
            Status::Skip => "\u{2013}", // –
        };
        println!("{mark} {}: {}", f.title, f.value.as_deref().unwrap_or("?"));
        if let Some(p) = &f.provenance {
            println!("  \u{2514}\u{2500} from {}", p.path);
        }
    }
}

/// Render the findings and return the process exit code.
///
/// stdout carries the report only; diagnostics go to stderr, so a JSON consumer
/// can pipe stdout straight into a parser.
fn run(findings: &[Finding], json: bool) -> i32 {
    if json {
        match serde_json::to_string_pretty(findings) {
            Ok(rendered) => println!("{rendered}"),
            Err(err) => {
                eprintln!("state-witness: failed to serialize findings: {err}");
                return EXIT_ERROR;
            }
        }
    } else {
        print_text(findings);
    }

    exit_code_for(findings)
}

fn main() {
    let cli = Cli::parse();

    let (findings, json) = match cli.command {
        Command::Ssh { json } => (ssh_effective(), json),
        Command::Atomic { json } => (ostree_effective(), json),
        Command::Sysctl { json } => (sysctl_effective(), json),
        Command::Firewall { json } => (firewall_effective(), json),
        Command::Users { json } => (users_effective(), json),
        Command::Version => {
            println!("state-witness {}", env!("CARGO_PKG_VERSION"));
            return;
        }
    };

    std::process::exit(run(&findings, json));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, status: Status) -> Finding {
        let mut f = Finding::pass(id, "t", "v");
        f.status = status;
        f
    }

    #[test]
    fn exit_code_is_zero_for_pass_warn_skip_only() {
        let findings = vec![
            finding("A", Status::Pass),
            finding("B", Status::Warn),
            finding("C", Status::Skip),
        ];
        assert_eq!(exit_code_for(&findings), EXIT_OK);
    }

    #[test]
    fn exit_code_is_zero_for_an_empty_report() {
        assert_eq!(exit_code_for(&[]), EXIT_OK);
    }

    #[test]
    fn exit_code_is_one_for_a_single_fail() {
        let findings = vec![finding("A", Status::Fail)];
        assert_eq!(exit_code_for(&findings), EXIT_FINDINGS_FAILED);
    }

    #[test]
    fn exit_code_is_one_for_mixed_findings_with_a_fail() {
        // The regression case: one Fail buried among passes must still win.
        let findings = vec![
            finding("A", Status::Pass),
            finding("B", Status::Skip),
            finding("C", Status::Warn),
            finding("D", Status::Fail),
            finding("E", Status::Pass),
        ];
        assert_eq!(exit_code_for(&findings), EXIT_FINDINGS_FAILED);
    }

    #[test]
    fn error_code_is_distinct_from_audit_codes() {
        // A broken run must never look like a clean audit (0) or like findings (1).
        assert_ne!(EXIT_ERROR, EXIT_OK);
        assert_ne!(EXIT_ERROR, EXIT_FINDINGS_FAILED);
    }
}

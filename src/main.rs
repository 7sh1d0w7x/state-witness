//! state-witness CLI.

use clap::{Parser, Subcommand};

use state_witness::{
    firewall_effective, ostree_effective, ssh_effective, sysctl_effective, users_effective,
    Finding, Status,
};

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

/// Print findings as text; return true if any finding failed.
fn print_text(findings: &[Finding]) -> bool {
    let mut failed = false;
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
        if f.status == Status::Fail {
            failed = true;
        }
    }
    failed
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

    if json {
        println!("{}", serde_json::to_string_pretty(&findings).unwrap());
        return;
    }

    if print_text(&findings) {
        std::process::exit(1);
    }
}

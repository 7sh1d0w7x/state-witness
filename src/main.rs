//! state-witness CLI.

use clap::{Parser, Subcommand};

use state_witness::{ssh_effective, Status};

#[derive(Parser)]
#[command(
    name = "state-witness",
    version,
    about = "Effective-state Linux security audit with provenance",
    long_about = "Reports what the kernel and daemons actually enforce right now \
                  (not what the config file says), with provenance."
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
    /// Show version / status.
    Version,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Ssh { json } => {
            let findings = ssh_effective();
            if json {
                println!("{}", serde_json::to_string_pretty(&findings).unwrap());
                return;
            }
            let mut failed = false;
            for f in &findings {
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
            if failed {
                std::process::exit(1);
            }
        }
        Command::Version => {
            println!("state-witness {}", env!("CARGO_PKG_VERSION"));
        }
    }
}

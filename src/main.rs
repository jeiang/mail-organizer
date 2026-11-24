use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Files IMAP mail into folders by rules and learned patterns"
)]
struct Cli {
    /// Path to the TOML config.
    #[arg(long, default_value = "/etc/mail-organizer/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or upgrade the database schema.
    Migrate,
    /// Run the watchers and the web UI.
    Serve,
    /// One sync pass, without routing or applying.
    Sync {
        #[arg(long)]
        account: Option<String>,
    },
    /// Decide eligible inbox messages, without applying.
    Route {
        #[arg(long)]
        account: Option<String>,
    },
    /// Recompute the metadata tokens of every indexed message.
    Reindex,
    /// Leave-one-out accuracy of the routing stages over filed mail.
    Eval {
        #[arg(long)]
        account: Option<String>,
        #[arg(long, default_value_t = 2000)]
        limit: usize,
        #[arg(long)]
        no_similar: bool,
    },
    /// Export or import operator rules as JSON.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Show or set the mode (shadow decides only; live also moves mail).
    Mode { mode: Option<String> },
}

#[derive(Subcommand)]
enum RulesCommand {
    Export,
    /// Replace all rules with the file's (`-` for stdin).
    Import {
        file: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let _ = (cli.config, cli.command);
    anyhow::bail!("not implemented yet")
}

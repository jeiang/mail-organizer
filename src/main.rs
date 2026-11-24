// Removed once every module is wired into a command.
#![allow(dead_code)]

mod config;
mod db;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::db::Db;

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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let db = Db::open(&config.db)?;
    match cli.command {
        Command::Migrate => {
            let n = db.write(db::migrate).await?;
            println!("applied {n} migration(s)");
        }
        Command::Mode { mode } => {
            let mode = match mode.as_deref() {
                None => None,
                Some("shadow") => Some(db::Mode::Shadow),
                Some("live") => Some(db::Mode::Live),
                Some(other) => anyhow::bail!("unknown mode {other:?}, want shadow or live"),
            };
            let current = db
                .write(move |c| {
                    if let Some(m) = mode {
                        db::set_mode(c, m)?;
                    }
                    db::mode(c)
                })
                .await?;
            println!("{}", current.as_str());
        }
        _ => anyhow::bail!("not implemented yet"),
    }
    Ok(())
}

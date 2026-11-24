// Removed once every module is wired into a command.
#![allow(dead_code)]

mod config;
mod db;
mod features;
mod imap;
mod metrics;
mod router;
mod rules;
mod similar;
mod sync;
mod telemetry;
mod utf7;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::db::Db;
use crate::telemetry::Telemetry;

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
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            telemetry::init_tracing(None);
            tracing::error!("{e:#}");
            return ExitCode::FAILURE;
        }
    };
    let telemetry = match &cli.command {
        Command::Serve => match Telemetry::start(&config.telemetry) {
            Ok(t) => t,
            Err(e) => {
                telemetry::init_tracing(None);
                tracing::error!("{e:#}");
                return ExitCode::FAILURE;
            }
        },
        _ => Telemetry::disabled(),
    };
    telemetry::init_tracing(telemetry.tracer());
    let result = run(cli.command, config).await;
    telemetry.shutdown();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command, config: Config) -> Result<()> {
    let db = Db::open(&config.db)?;
    if !matches!(command, Command::Migrate) {
        db.write(db::migrate).await?;
    }
    match command {
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
        Command::Sync { account } => {
            for account in config.select(account.as_deref())? {
                let mut imap = imap::Imap::connect(&account).await?;
                let stats = sync::sync_account(&db, &mut imap, &account).await?;
                imap.logout().await;
                println!(
                    "{}: {} new, {} gone, {} flag changes, {} mailboxes",
                    account.name,
                    stats.new,
                    stats.gone.len(),
                    stats.flag_changes,
                    stats.mailboxes
                );
            }
        }
        Command::Rules {
            command: RulesCommand::Export,
        } => {
            let doc = db.read(rules::export).await?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        Command::Rules {
            command: RulesCommand::Import { file },
        } => {
            let text = if file == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(&file)?
            };
            let doc: serde_json::Value = serde_json::from_str(&text)?;
            let n = db.write(move |c| rules::import(c, &doc)).await?;
            println!("imported {n} rule(s)");
        }
        Command::Route { account } => {
            for account in config.select(account.as_deref())? {
                let routed = router::route_account(&db, &account.name).await?;
                println!(
                    "{}: {} eligible, {:?}",
                    account.name, routed.eligible, routed.by_stage
                );
            }
        }
        _ => anyhow::bail!("not implemented yet"),
    }
    Ok(())
}

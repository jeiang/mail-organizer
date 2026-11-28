mod ai;
mod apply;
mod classify;
mod config;
mod db;
mod eval;
mod features;
mod imap;
mod metrics;
mod router;
mod rules;
mod similar;
mod sync;
mod telemetry;
mod utf7;
mod watch;
mod web;

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
    /// Time-ordered folder agreement using older training examples.
    Eval {
        #[arg(long)]
        account: Option<String>,
        #[arg(long, default_value_t = 2000)]
        limit: usize,
        #[arg(long)]
        no_similar: bool,
        /// Evaluate the language model alone (one request per message).
        #[arg(long)]
        ai: bool,
    },
    /// Export or import operator rules as JSON.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Show or set the mode (shadow decides only; live also moves mail).
    Mode { mode: Option<String> },
    /// Create a folder (a label on Gmail) on the server.
    Folder {
        #[arg(long)]
        account: String,
        name: String,
    },
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
        Command::Folder { account, name } => {
            let account = config.account(&account)?;
            if sync::create_folder(account, &name).await? {
                println!("{}: created {name}", account.name);
            } else {
                println!("{}: {name} already exists", account.name);
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
                let mut routed = router::route_account(&db, &account.name).await?;
                if let Some(llm) = &config.llm
                    && ai::consult(&db, &account.name, llm).await? > 0
                {
                    routed = router::route_account(&db, &account.name).await?;
                }
                println!(
                    "{}: {} eligible, {:?}",
                    account.name, routed.eligible, routed.by_stage
                );
            }
        }
        Command::Serve => serve(db, config).await?,
        Command::Reindex => {
            let n = db
                .write(|c| {
                    let tx = c.transaction()?;
                    tx.execute(
                        "INSERT INTO message_fts (rowid, meta, subject, body) SELECT id, '', subject, '' FROM messages \
                         WHERE gone_at IS NULL AND id NOT IN (SELECT rowid FROM message_fts)",
                        [],
                    )?;
                    let ids: Vec<i64> = tx
                        .prepare("SELECT rowid FROM message_fts")?
                        .query_map([], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?;
                    for id in &ids {
                        sync::reindex_one(&tx, *id)?;
                    }
                    tx.commit()?;
                    Ok(ids.len())
                })
                .await?;
            println!("reindexed {n} message(s)");
        }
        Command::Eval {
            account,
            limit,
            no_similar,
            ai,
        } => {
            for account in config.select(account.as_deref())? {
                if ai {
                    let llm = config
                        .llm
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("--ai needs [llm] in the config"))?;
                    let report = ai::evaluate(&db, &account.name, limit, llm).await?;
                    ai::print(&account.name, &report);
                    continue;
                }
                let name = account.name.clone();
                let report = db
                    .read(move |c| eval::evaluate(c, &name, limit, !no_similar))
                    .await?;
                eval::print(&account.name, !no_similar, &report);
            }
        }
    }
    Ok(())
}

async fn bind(addr: &str, name: &str) -> Result<tokio::net::TcpListener> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("binding the {name} listener {addr}: {e}"))?;
    tracing::info!("{name} listening on {addr}");
    Ok(listener)
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

async fn serve(db: Db, config: Config) -> Result<()> {
    let handle = metrics::install()?;
    let metrics_listener = bind(&config.metrics_listen, "metrics").await?;
    let listener = bind(&config.listen, "web").await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(metrics_listener, metrics::router(handle)).await {
            tracing::error!("metrics listener failed: {e}");
        }
    });
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let watchers: Vec<_> = config
        .accounts
        .iter()
        .cloned()
        .map(|a| {
            tokio::spawn(watch::run(
                db.clone(),
                a,
                config.write_cap,
                config.llm.clone(),
                stopped.clone(),
            ))
        })
        .collect();
    let app = web::router(db.clone(), &config);
    let mut web_stopped = stopped.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = web_stopped.changed().await;
            })
            .await
    });
    shutdown_signal().await;
    tracing::info!("shutting down");
    let _ = stop.send(true);
    let drained = async {
        for w in watchers {
            let _ = w.await;
        }
        let _ = server.await;
    };
    if tokio::time::timeout(std::time::Duration::from_secs(30), drained)
        .await
        .is_err()
    {
        tracing::warn!("shutdown timed out");
    }
    Ok(())
}

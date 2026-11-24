//! One task per account: a pass on start, after each inbox change (IDLE) and
//! every 15 minutes, reconnecting with backoff after errors.

use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{Instrument, error, info, info_span, warn};

use crate::apply;
use crate::config::Account;
use crate::db::{self, Db, Mode};
use crate::imap::Imap;
use crate::router;
use crate::sync::{self, INBOX};

const TIMER: Duration = Duration::from_secs(15 * 60);
const SETTLE: Duration = Duration::from_secs(2);
/// Servers drop long IDLEs silently, and changes during a pass are not seen by
/// IDLE, so IDLE in slices and check for newly readable mail between them.
const SLICE: Duration = Duration::from_secs(2 * 60);
const READABLE: &str = "SEEN UNFLAGGED UNDELETED";
const BACKOFF_START: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
const HEALTHY_RESET: Duration = Duration::from_secs(10 * 60);

pub fn error_key(account: &str) -> String {
    format!("error:{account}")
}

/// Sync, route, queue retention deletions and apply, inside one `mail.pass`
/// trace.
pub async fn pass(
    db: &Db,
    imap: &mut Imap,
    account: &Account,
    cap: usize,
    trigger: &str,
) -> Result<()> {
    let span = info_span!(parent: None, "mail.pass", account = %account.name, trigger);
    let started = std::time::Instant::now();
    let result = async {
        let synced = sync::sync_account(db, imap, account).await?;
        let routed = router::route_account(db, &account.name).await?;
        let mode = db.read(db::mode).await?;
        crate::metrics::live(&account.name, mode == Mode::Live);
        let mut outcome = apply::Outcome::default();
        if mode == Mode::Live {
            apply::deletion_pass(db, account, false).await?;
            outcome = apply::apply_account(db, imap, account, cap).await?;
            if outcome.applied > 0 {
                sync::sync_account(db, imap, account).await?;
            }
        }
        info!(
            account = %account.name,
            new = synced.new,
            gone = synced.gone.len(),
            routed = ?routed.by_stage,
            applied = outcome.applied,
            skipped = outcome.skipped,
            failed = outcome.failed,
            "pass finished"
        );
        Ok(())
    }
    .instrument(span)
    .await;
    crate::metrics::pass_finished(
        &account.name,
        started.elapsed().as_secs_f64(),
        result.is_ok(),
    );
    let (key, message) = (
        error_key(&account.name),
        result.as_ref().err().map(|e| format!("{e:#}")),
    );
    db.write(move |c| {
        match message {
            Some(m) => db::set_state(c, &key, &format!("{}\t{m}", db::now()))?,
            None => {
                c.execute("DELETE FROM state WHERE key = ?1", [&key])?;
            }
        }
        Ok(())
    })
    .await?;
    result
}

async fn session(
    db: &Db,
    account: &Account,
    cap: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut imap = Imap::connect(account).await?;
    let mut trigger = "start";
    loop {
        // Baseline before the pass, so mail read while it runs triggers the next one.
        imap.select(INBOX).await?;
        let mut readable = imap.uid_search(READABLE).await?;
        pass(db, &mut imap, account, cap, trigger).await?;
        imap.select(INBOX).await?;
        let deadline = Instant::now() + TIMER;
        trigger = loop {
            let (next, changed) = tokio::select! {
                r = imap.idle(deadline.min(Instant::now() + SLICE)) => r?,
                _ = shutdown.changed() => return Ok(()),
            };
            imap = next;
            if changed {
                tokio::time::sleep(SETTLE).await;
                break "idle";
            }
            if Instant::now() >= deadline {
                break "timer";
            }
            let now = imap.uid_search(READABLE).await?;
            if now.iter().any(|uid| !readable.contains(uid)) {
                break "flags";
            }
            readable = now;
        };
    }
}

pub async fn run(db: Db, account: Account, cap: usize, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BACKOFF_START;
    while !*shutdown.borrow() {
        let started = Instant::now();
        match session(&db, &account, cap, &mut shutdown).await {
            Ok(()) => break,
            Err(e) => {
                if started.elapsed() >= HEALTHY_RESET {
                    backoff = BACKOFF_START;
                }
                if backoff == BACKOFF_START {
                    warn!(account = %account.name, "watch failed, reconnecting in {backoff:?}: {e:#}");
                } else {
                    error!(account = %account.name, "watch failed, reconnecting in {backoff:?}: {e:#}");
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => break,
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
    info!(account = %account.name, "watcher stopped");
}

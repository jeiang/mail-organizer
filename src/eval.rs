//! Leave-one-out evaluation: decide filed messages as if they were unread in
//! the inbox and compare with the folder they are in.

use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::Connection;

use crate::router;
use crate::rules::{self, MESSAGE_COLUMNS, Message};

#[derive(Debug, Default)]
pub struct Tally {
    pub count: usize,
    pub correct: usize,
}

#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub by_stage: BTreeMap<&'static str, Tally>,
}

pub fn evaluate(c: &Connection, account: &str, limit: usize, use_similar: bool) -> Result<Report> {
    // Age conditions depend on when the message is evaluated, not when it arrived.
    let rules: Vec<_> = rules::load(c, Some(account))?
        .into_iter()
        .filter(|r| !r.has_age())
        .collect();
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM filed_messages m WHERE m.account = ?1 ORDER BY m.date_ts DESC LIMIT ?2"
    );
    let mut stmt = c.prepare(&sql)?;
    let messages: Vec<Message> = stmt
        .query_map(rusqlite::params![account, limit as i64], Message::from_row)?
        .collect::<rusqlite::Result<_>>()?;
    let now = crate::db::now();
    let mut report = Report {
        total: messages.len(),
        ..Report::default()
    };
    for m in &messages {
        let d = router::decide(c, m, &rules, now, use_similar)?;
        let tally = report.by_stage.entry(d.stage).or_default();
        tally.count += 1;
        if d.dest.is_some() && d.dest == m.folder {
            tally.correct += 1;
        }
    }
    Ok(report)
}

pub fn print(account: &str, use_similar: bool, r: &Report) {
    let label = if use_similar {
        ""
    } else {
        " (no similar stage)"
    };
    println!("{account}{label}: {} filed messages", r.total);
    println!(
        "  {:<10} {:>6} {:>8} {:>9} {:>7}",
        "stage", "count", "correct", "accuracy", "share"
    );
    for (stage, t) in &r.by_stage {
        let accuracy = if *stage == "none" || t.count == 0 {
            "-".to_owned()
        } else {
            format!("{:.3}", t.correct as f64 / t.count as f64)
        };
        let share = t.count as f64 / r.total.max(1) as f64;
        println!(
            "  {stage:<10} {:>6} {:>8} {accuracy:>9} {share:>7.3}",
            t.count, t.correct
        );
    }
}

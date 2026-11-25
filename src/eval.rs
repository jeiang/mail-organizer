//! Time-ordered folder agreement using current rules and older training examples.

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

/// Confidence thresholds shown in the sweep.
pub const SWEEP: [f64; 6] = [0.0, 0.5, 0.7, 0.8, 0.9, 0.95];

#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub unfamiliar: usize,
    pub recurring: usize,
    pub by_stage: BTreeMap<&'static str, Tally>,
    /// Stage, confidence, and whether the folder agreed, for every decided
    /// message whose stage carries a confidence.
    pub confident: Vec<(&'static str, f64, bool)>,
}

pub fn evaluate(c: &Connection, account: &str, limit: usize, use_similar: bool) -> Result<Report> {
    let rules: Vec<_> = rules::load(c, Some(account))?
        .into_iter()
        .filter(|r| !r.has_age())
        .collect();
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM main.training_messages m WHERE m.account = ?1 AND m.date_ts > 0 ORDER BY m.date_ts DESC LIMIT ?2"
    );
    let messages: Vec<Message> = c
        .prepare(&sql)?
        .query_map(rusqlite::params![account, limit as i64], Message::from_row)?
        .collect::<rusqlite::Result<_>>()?;
    let mut report = Report {
        total: messages.len(),
        ..Report::default()
    };
    let result = (|| {
        for m in &messages {
            c.execute_batch(&format!(
                "DROP VIEW IF EXISTS temp.training_messages;
                 CREATE TEMP VIEW training_messages AS SELECT * FROM main.training_messages WHERE date_ts < {};",
                m.date_ts
            ))?;
            let d = router::decide(c, m, &rules, crate::db::now(), use_similar)?;
            let correct = d.dest.is_some() && d.dest == m.folder;
            let tally = report.by_stage.entry(d.stage).or_default();
            tally.count += 1;
            if correct {
                tally.correct += 1;
            }
            if let Some(confidence) = d.confidence {
                report.confident.push((d.stage, confidence, correct));
            }
            if d.action == "none" {
                let known: bool = c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM training_messages WHERE account = ?1 AND from_addr = ?2)",
                    [&m.account, &m.from_addr], |r| r.get(0),
                )?;
                if known {
                    report.recurring += 1;
                } else {
                    report.unfamiliar += 1;
                }
            }
        }
        Ok(report)
    })();
    c.execute_batch("DROP VIEW IF EXISTS temp.training_messages")?;
    result
}

pub fn print(account: &str, use_similar: bool, r: &Report) {
    let label = if use_similar {
        ""
    } else {
        " (no similar stage)"
    };
    println!(
        "{account}{label}: {} time-ordered examples, current folders/rules are not independently verified labels",
        r.total
    );
    let sorted: usize = r
        .by_stage
        .iter()
        .filter(|(s, _)| **s != "none")
        .map(|(_, t)| t.count)
        .sum();
    let correct: usize = r.by_stage.values().map(|t| t.correct).sum();
    println!(
        "  automatic coverage: {}/{} ({:.1}%), folder disagreements: {}/{}",
        sorted,
        r.total,
        100.0 * sorted as f64 / r.total.max(1) as f64,
        sorted - correct,
        sorted
    );
    println!(
        "  unresolved: {} recurring, {} unfamiliar",
        r.recurring, r.unfamiliar
    );
    println!(
        "  {:<10} {:>6} {:>8} {:>9} {:>7}",
        "stage", "count", "agree", "agreement", "share"
    );
    for (stage, t) in &r.by_stage {
        let agreement = if *stage == "none" || t.count == 0 {
            "-".to_owned()
        } else {
            format!("{:.3}", t.correct as f64 / t.count as f64)
        };
        println!(
            "  {stage:<10} {:>6} {:>8} {agreement:>9} {:>7.3}",
            t.count,
            t.correct,
            t.count as f64 / r.total.max(1) as f64
        );
    }
    if !r.confident.is_empty() {
        println!(
            "  {:<10} {:>5} {:>8} {:>6} {:>10} {:>9}",
            "stage", "at P", "decided", "agree", "precision", "coverage"
        );
        let mut stages: Vec<&'static str> = r.confident.iter().map(|(s, _, _)| *s).collect();
        stages.sort_unstable();
        stages.dedup();
        for stage in stages {
            for at in SWEEP {
                let (mut decided, mut correct) = (0, 0);
                for (s, confidence, ok) in &r.confident {
                    if *s == stage && *confidence >= at {
                        decided += 1;
                        correct += usize::from(*ok);
                    }
                }
                if decided == 0 {
                    continue;
                }
                println!(
                    "  {stage:<10} {at:>5.2} {decided:>8} {correct:>6} {:>10.3} {:>9.3}",
                    correct as f64 / decided as f64,
                    decided as f64 / r.total.max(1) as f64
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_uses_only_older_deduplicated_examples() {
        let mut c = Connection::open_in_memory().unwrap();
        crate::db::migrate(&mut c).unwrap();
        c.execute_batch("INSERT INTO accounts(name,preset) VALUES ('test','icloud');
            INSERT INTO mailboxes(id,account,name,imap_name,role) VALUES (1,'test','News','News','filed');").unwrap();
        for id in 1..=5 {
            c.execute("INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,from_addr,folder,date_ts,first_seen)
                VALUES (?1,'test',1,1,?1,?2,'news@example.com','News',?1,1)",
                rusqlite::params![id, format!("message-{id}")]).unwrap();
        }
        c.execute_batch("INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,from_addr,folder,date_ts,first_seen)
            VALUES (6,'test',1,1,6,'message-1','news@example.com','News',1,1);").unwrap();
        let report = evaluate(&c, "test", 5, false).unwrap();
        assert_eq!(report.by_stage["none"].count, 3);
        assert_eq!(report.by_stage["learned"].correct, 2);
        assert!(
            report
                .confident
                .iter()
                .any(|(stage, ..)| *stage == "learned")
        );
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM training_messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 5);
    }
}

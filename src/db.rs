use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

const MIGRATIONS: &[&str] = &[
    include_str!("../schema/0001_init.sql"),
    include_str!("../schema/0002_training.sql"),
];

/// One writer connection, shared, and short-lived read connections. Every call
/// runs on the blocking pool.
#[derive(Clone)]
pub struct Db {
    path: PathBuf,
    writer: Arc<Mutex<Connection>>,
    pub mutations: Arc<tokio::sync::Mutex<()>>,
    pub refresh: tokio::sync::watch::Sender<()>,
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        configure(&conn)?;
        // Include all tables because query reads use separate read-only connections.
        conn.execute_batch("PRAGMA optimize = 0x10002")?;
        Ok(Self {
            path: path.to_owned(),
            writer: Arc::new(Mutex::new(conn)),
            mutations: Arc::new(tokio::sync::Mutex::new(())),
            refresh: tokio::sync::watch::channel(()).0,
        })
    }

    /// Runs `f` on the writer connection.
    pub async fn write<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let writer = self.writer.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = writer.lock().map_err(|_| anyhow!("db writer poisoned"))?;
            f(&mut conn)
        })
        .await?
    }

    /// Runs `f` on a fresh read-only connection.
    pub async fn read<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            configure(&conn)?;
            f(&conn)
        })
        .await?
    }
}

pub fn migrate(conn: &mut Connection) -> Result<usize> {
    let current: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let mut applied = 0;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .with_context(|| format!("applying migration {}", i + 1))?;
        tx.pragma_update(None, "user_version", i + 1)?;
        tx.commit()?;
        applied += 1;
    }
    Ok(applied)
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

pub fn get_state(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM state WHERE key = ?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}

pub fn set_state(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO state (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Shadow,
    Live,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Shadow => "shadow",
            Mode::Live => "live",
        }
    }
}

pub fn mode(conn: &Connection) -> Result<Mode> {
    Ok(match get_state(conn, "mode")?.as_deref() {
        Some("live") => Mode::Live,
        _ => Mode::Shadow,
    })
}

pub fn set_mode(conn: &Connection, mode: Mode) -> Result<()> {
    if mode == Mode::Live && self::mode(conn)? != Mode::Live {
        set_state(conn, "live_since", &now().to_string())?;
    }
    set_state(conn, "mode", mode.as_str())
}

pub fn json_list(text: &str) -> Vec<String> {
    serde_json::from_str(text).unwrap_or_default()
}

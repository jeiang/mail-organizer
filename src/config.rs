use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub db: PathBuf,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,
    #[serde(default = "default_write_cap")]
    pub write_cap: usize,
    #[serde(default)]
    pub trace_url_template: String,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default, rename = "account")]
    pub accounts: Vec<Account>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            service_name: default_service_name(),
            sample_ratio: default_sample_ratio(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Icloud,
    Gmail,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Icloud => "icloud",
            Preset::Gmail => "gmail",
        }
    }

    pub fn host(self) -> &'static str {
        match self {
            Preset::Icloud => "imap.mail.me.com",
            Preset::Gmail => "imap.gmail.com",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    pub preset: Preset,
    pub login: String,
    pub password_file: PathBuf,
}

impl Account {
    /// Read at login time only, so commands that never log in need no secrets.
    pub fn password(&self) -> Result<String> {
        let raw = std::fs::read_to_string(&self.password_file)
            .with_context(|| format!("reading the password file of account {}", self.name))?;
        let password = raw.trim_end_matches(['\r', '\n']).to_owned();
        if password.is_empty() {
            bail!("the password file of account {} is empty", self.name);
        }
        Ok(password)
    }
}

fn default_listen() -> String {
    "127.0.0.1:8490".into()
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9490".into()
}
fn default_write_cap() -> usize {
    100
}
fn default_endpoint() -> String {
    "http://127.0.0.1:4318".into()
}
fn default_service_name() -> String {
    "mail-organizer".into()
}
fn default_sample_ratio() -> f64 {
    1.0
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        let mut names = HashSet::new();
        for a in &config.accounts {
            if a.name.is_empty() || !names.insert(a.name.as_str()) {
                bail!("account names must be non-empty and unique: {:?}", a.name);
            }
        }
        if !(0.0..=1.0).contains(&config.telemetry.sample_ratio) {
            bail!("telemetry.sample_ratio must be within 0.0..=1.0");
        }
        if config.write_cap == 0 {
            bail!("write_cap must be at least 1");
        }
        Ok(config)
    }

    pub fn account(&self, name: &str) -> Result<&Account> {
        self.accounts
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("unknown account {name:?}"))
    }

    /// The named account, or all of them.
    pub fn select(&self, name: Option<&str>) -> Result<Vec<Account>> {
        match name {
            Some(n) => Ok(vec![self.account(n)?.clone()]),
            None => Ok(self.accounts.clone()),
        }
    }
}

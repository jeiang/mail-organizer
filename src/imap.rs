//! A thin IMAP client over async-imap: LIST, STATUS, SELECT, SEARCH, FETCH,
//! CREATE, MOVE, Gmail label STORE and IDLE. Every network step has a timeout, so a
//! dead connection fails the pass instead of hanging it.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use async_imap::types::{Fetch, Flag, NameAttribute};
use async_imap::{Client, Session};
use futures::TryStreamExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::config::{Account, Preset};
use crate::utf7;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);
pub const TEXT_CAP_BYTES: usize = 65536;

type Stream = TlsStream<TcpStream>;

pub struct Imap {
    session: Session<Stream>,
    pub preset: Preset,
    caps: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct MailboxInfo {
    /// Decoded name, as stored in the database and shown.
    pub name: String,
    /// The name as the server spells it, for commands.
    pub imap_name: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Status {
    pub uidvalidity: u32,
    pub highestmodseq: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Fetched {
    pub uid: u32,
    pub flags: Vec<String>,
    /// Gmail labels, decoded; `None` when not requested.
    pub labels: Option<Vec<String>>,
    pub header: Vec<u8>,
    pub text: Vec<u8>,
    pub gm_msgid: Option<u64>,
    pub internal_ts: Option<f64>,
}

async fn timed<T, E>(what: &str, f: impl Future<Output = Result<T, E>>) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    match timeout(COMMAND_TIMEOUT, f).await {
        Ok(r) => r.map_err(Into::into).with_context(|| what.to_owned()),
        Err(_) => Err(anyhow!("{what}: timed out")),
    }
}

fn flag_str(flag: &Flag<'_>) -> Option<String> {
    Some(match flag {
        Flag::Seen => "\\Seen".into(),
        Flag::Answered => "\\Answered".into(),
        Flag::Flagged => "\\Flagged".into(),
        Flag::Deleted => "\\Deleted".into(),
        Flag::Draft => "\\Draft".into(),
        // Session state, not message state.
        Flag::Recent | Flag::MayCreate => return None,
        Flag::Custom(s) => s.to_string(),
    })
}

fn attribute_str(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\Noinferiors".into(),
        NameAttribute::NoSelect => "\\Noselect".into(),
        NameAttribute::Marked => "\\Marked".into(),
        NameAttribute::Unmarked => "\\Unmarked".into(),
        NameAttribute::All => "\\All".into(),
        NameAttribute::Archive => "\\Archive".into(),
        NameAttribute::Drafts => "\\Drafts".into(),
        NameAttribute::Flagged => "\\Flagged".into(),
        NameAttribute::Junk => "\\Junk".into(),
        NameAttribute::Sent => "\\Sent".into(),
        NameAttribute::Trash => "\\Trash".into(),
        NameAttribute::Extension(s) => s.to_string(),
        other => format!("{other:?}"),
    }
}

/// `1:3,7` for 1, 2, 3, 7.
pub fn uid_set(uids: &[u32]) -> String {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
        i += 1;
    }
    parts.join(",")
}

/// An IMAP quoted string.
pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A Gmail label for STORE: system labels bare, others quoted and encoded.
fn label_arg(label: &str) -> String {
    if label.starts_with('\\') {
        label.to_owned()
    } else {
        quote(&utf7::encode(label))
    }
}

/// Undoes IMAP quoted-string escapes, which imap-proto leaves in labels.
fn unquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('\\', Some(n @ ('\\' | '"'))) => {
                out.push(n);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

fn convert(f: &Fetch, gmail: bool) -> Option<Fetched> {
    Some(Fetched {
        uid: f.uid?,
        flags: f.flags().filter_map(|x| flag_str(&x)).collect(),
        labels: gmail.then(|| {
            f.gmail_labels()
                .map(|l| l.iter().map(|x| utf7::decode(&unquote(x))).collect())
                .unwrap_or_default()
        }),
        header: f.header().map(<[u8]>::to_vec).unwrap_or_default(),
        text: f.text().map(<[u8]>::to_vec).unwrap_or_default(),
        gm_msgid: f.gmail_msg_id().copied(),
        internal_ts: f.internal_date().map(|d| d.timestamp() as f64),
    })
}

impl Imap {
    pub async fn connect(account: &Account) -> Result<Self> {
        let password = account.password()?;
        let host = account.preset.host();
        let tcp = timed("connecting", TcpStream::connect((host, 993))).await?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
        let stream = timed(
            "TLS handshake",
            TlsConnector::from(Arc::new(tls)).connect(name, tcp),
        )
        .await?;
        let mut client = Client::new(stream);
        timed("reading the greeting", client.read_response())
            .await?
            .context("the server closed the connection before its greeting")?;
        let mut session =
            match timeout(COMMAND_TIMEOUT, client.login(&account.login, password)).await {
                Ok(Ok(s)) => s,
                Ok(Err((e, _))) => return Err(anyhow!(e).context(format!("logging in to {host}"))),
                Err(_) => return Err(anyhow!("logging in to {host}: timed out")),
            };
        let advertised = timed("CAPABILITY", session.capabilities()).await?;
        let caps = ["CONDSTORE", "IDLE", "MOVE"]
            .into_iter()
            .filter(|c| advertised.has_str(c))
            .map(String::from)
            .collect();
        Ok(Self {
            session,
            preset: account.preset,
            caps,
        })
    }

    pub fn has(&self, capability: &str) -> bool {
        self.caps.contains(capability)
    }

    fn gmail(&self) -> bool {
        self.preset == Preset::Gmail
    }

    pub async fn logout(mut self) {
        let _ = timeout(Duration::from_secs(10), self.session.logout()).await;
    }

    pub async fn list(&mut self) -> Result<Vec<MailboxInfo>> {
        let names: Vec<_> = timed("LIST", async {
            self.session
                .list(Some(""), Some("*"))
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        Ok(names
            .iter()
            .map(|n| MailboxInfo {
                name: utf7::decode(n.name()),
                imap_name: n.name().to_owned(),
                flags: n.attributes().iter().map(attribute_str).collect(),
            })
            .collect())
    }

    pub async fn status(&mut self, imap_name: &str) -> Result<Status> {
        let items = if self.has("CONDSTORE") {
            "(UIDVALIDITY HIGHESTMODSEQ)"
        } else {
            "(UIDVALIDITY)"
        };
        let mbox = timed(
            &format!("STATUS {imap_name}"),
            self.session.status(imap_name, items),
        )
        .await?;
        Ok(Status {
            uidvalidity: mbox
                .uid_validity
                .with_context(|| format!("{imap_name}: no UIDVALIDITY"))?,
            highestmodseq: mbox.highest_modseq,
        })
    }

    pub async fn select(&mut self, imap_name: &str) -> Result<u32> {
        let what = format!("SELECT {imap_name}");
        let mbox = if self.has("CONDSTORE") {
            timed(&what, self.session.select_condstore(imap_name)).await?
        } else {
            timed(&what, self.session.select(imap_name)).await?
        };
        self.drain();
        mbox.uid_validity
            .with_context(|| format!("{imap_name}: no UIDVALIDITY"))
    }

    /// Unsolicited responses (EXISTS, EXPUNGE, VANISHED, ...) are not used:
    /// sync compares UID SEARCH results with the database instead.
    fn drain(&mut self) {
        while self.session.unsolicited_responses.try_recv().is_ok() {}
    }

    pub async fn uid_search(&mut self, query: &str) -> Result<Vec<u32>> {
        let found = timed(
            &format!("UID SEARCH {query}"),
            self.session.uid_search(query),
        )
        .await?;
        let mut uids: Vec<u32> = found.into_iter().collect();
        uids.sort_unstable();
        Ok(uids)
    }

    async fn uid_fetch(&mut self, set: &str, query: &str) -> Result<Vec<Fetched>> {
        let gmail = self.gmail();
        let fetches: Vec<Fetch> = timed("UID FETCH", async {
            self.session
                .uid_fetch(set, query)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        self.drain();
        Ok(fetches.iter().filter_map(|f| convert(f, gmail)).collect())
    }

    pub async fn fetch_full(&mut self, uids: &[u32]) -> Result<Vec<Fetched>> {
        let gmail = if self.gmail() {
            " X-GM-LABELS X-GM-MSGID"
        } else {
            ""
        };
        let query = format!(
            "(UID FLAGS INTERNALDATE{gmail} BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.{TEXT_CAP_BYTES}>)"
        );
        self.uid_fetch(&uid_set(uids), &query).await
    }

    fn flags_query(&self) -> &'static str {
        if self.gmail() {
            "(UID FLAGS X-GM-LABELS)"
        } else {
            "(UID FLAGS)"
        }
    }

    pub async fn fetch_flags(&mut self, uids: &[u32]) -> Result<Vec<Fetched>> {
        let query = self.flags_query();
        self.uid_fetch(&uid_set(uids), query).await
    }

    pub async fn fetch_flags_changed_since(&mut self, modseq: u64) -> Result<Vec<Fetched>> {
        let query = format!("{} (CHANGEDSINCE {modseq})", self.flags_query());
        self.uid_fetch("1:*", &query).await
    }

    /// Headers, flags and labels, for checking a message before moving it.
    pub async fn fetch_headers(&mut self, uids: &[u32]) -> Result<Vec<Fetched>> {
        let gmail = if self.gmail() { " X-GM-LABELS" } else { "" };
        let query = format!("(UID FLAGS{gmail} BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])");
        let mut out = self.uid_fetch(&uid_set(uids), &query).await?;
        // HEADER.FIELDS is not the HEADER section async-imap reads; refetch
        // the full header when it came back empty.
        if out.iter().any(|f| f.header.is_empty()) {
            let query = format!("(UID FLAGS{gmail} BODY.PEEK[HEADER])");
            out = self.uid_fetch(&uid_set(uids), &query).await?;
        }
        Ok(out)
    }

    /// Creates a mailbox (a label on Gmail) named by its decoded name.
    pub async fn create(&mut self, name: &str) -> Result<()> {
        timed(
            &format!("CREATE {name}"),
            self.session.create(utf7::encode(name)),
        )
        .await
    }

    pub async fn uid_move(&mut self, uids: &[u32], dest_imap: &str) -> Result<()> {
        timed(
            &format!("UID MOVE to {dest_imap}"),
            self.session.uid_mv(uid_set(uids), dest_imap),
        )
        .await?;
        self.drain();
        Ok(())
    }

    pub async fn store_labels(&mut self, uids: &[u32], add: bool, labels: &[&str]) -> Result<()> {
        let sign = if add { '+' } else { '-' };
        let args: Vec<String> = labels.iter().map(|l| label_arg(l)).collect();
        let query = format!("{sign}X-GM-LABELS.SILENT ({})", args.join(" "));
        timed("UID STORE X-GM-LABELS", async {
            self.session
                .uid_store(uid_set(uids), &query)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        self.drain();
        Ok(())
    }

    /// Waits for a change in the selected mailbox, at most until `deadline`.
    /// Without IDLE, waits a minute and reports a change.
    pub async fn idle(mut self, deadline: Instant) -> Result<(Self, bool)> {
        if !self.has("IDLE") {
            tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_secs(60))).await;
            timed("NOOP", self.session.noop()).await?;
            return Ok((self, true));
        }
        let Imap {
            session,
            preset,
            caps,
        } = self;
        let mut handle = session.idle();
        timed("IDLE", handle.init()).await?;
        let changed = {
            let (wait, _stop) = handle.wait_with_timeout(Duration::from_secs(29 * 60));
            match tokio::time::timeout_at(deadline, wait).await {
                Err(_) => false,
                Ok(Ok(async_imap::extensions::idle::IdleResponse::NewData(_))) => true,
                Ok(Ok(_)) => false,
                Ok(Err(e)) => return Err(anyhow!(e).context("IDLE")),
            }
        };
        let session = timed("DONE", handle.done()).await?;
        let mut imap = Imap {
            session,
            preset,
            caps,
        };
        imap.drain();
        Ok((imap, changed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_sets() {
        assert_eq!(uid_set(&[7, 1, 2, 3, 9, 10]), "1:3,7,9:10");
        assert_eq!(uid_set(&[5]), "5");
    }

    #[test]
    fn unquoting() {
        assert_eq!(unquote("\\\\Important"), "\\Important");
        assert_eq!(unquote("\\Inbox"), "\\Inbox");
        assert_eq!(unquote("a \\\"b\\\""), "a \"b\"");
    }

    #[test]
    fn label_args() {
        assert_eq!(label_arg("\\Inbox"), "\\Inbox");
        assert_eq!(label_arg("Bills \"2026\""), "\"Bills \\\"2026\\\"\"");
        assert_eq!(label_arg("Entwürfe"), "\"Entw&APw-rfe\"");
    }
}

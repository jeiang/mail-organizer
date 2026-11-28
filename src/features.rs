//! Parsed message features with ASCII regex character classes.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use mail_parser::{HeaderForm, HeaderValue, Message, MessageParser, MimeHeaders, PartType};
use regex::Regex;
use sha2::{Digest, Sha256};

pub const BODY_CHARS: usize = 4000;

const MONTH: &str = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?";
const S: &str = r"[\t\n\x0C\r ]";

fn re(pattern: &str) -> Regex {
    Regex::new(&pattern.replace("\\s", S)).expect("static regex")
}

static REPLY_PREFIX: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^\s*(re|fwd?|fw|aw)\s*:\s*"));
static AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?:[$€£]|usd|ttd|tt\$|us\$|cad)\s?[0-9][0-9,]*(?:\.[0-9]+)?|[0-9][0-9,]*(?:\.[0-9]+)?\s?(?:usd|ttd|cad)",
    )
});
static MONTH_DAY: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(?-u:\b){MONTH}\s+[0-9]{{1,2}}(?:st|nd|rd|th)?(?:,?\s+[0-9]{{2,4}})?"
    ))
});
static DAY_MONTH: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(?-u:\b)[0-9]{{1,2}}(?:st|nd|rd|th)?\s+{MONTH}(?:,?\s+[0-9]{{2,4}})?"
    ))
});
static NUMERIC_DATE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?-u:\b)[0-9]{1,4}[/-][0-9]{1,2}[/-][0-9]{1,4}(?-u:\b)"));
static NUMBER_WORD: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?-u:\b)(?-u:\w)*[0-9](?-u:\w)*(?-u:\b)"));
static HASH_NUMBER: LazyLock<Regex> = LazyLock::new(|| re(r"#\s*<n>"));
static SPACE: LazyLock<Regex> = LazyLock::new(|| re(r"\s+"));
static SCRIPT_STYLE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?is)<script.*?</script>|<style.*?</style>"));
static TAG: LazyLock<Regex> = LazyLock::new(|| re(r"<[^>]+>"));
static DIGITS: LazyLock<Regex> = LazyLock::new(|| re(r"[0-9]+"));
static MSGID_STRIP: LazyLock<Regex> = LazyLock::new(|| re(r"[<>\s]"));
static DKIM_DOMAIN: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u:\b)d=([^;\s]+)"));

const ESP_EXACT: &[(&str, &str)] = &[
    ("x-amazon-ses", "ses"),
    ("x-mg-id", "mailgun"),
    ("x-sendgrid-eid", "sendgrid"),
    ("x-mc-user", "mandrill"),
    ("x-pm-message-id", "postmark"),
    ("x-shopid", "shopify"),
    ("x-campaign", "mailchimp"),
    ("x-campaignid", "mailchimp"),
    ("x-mailchimp-id", "mailchimp"),
    ("x-mcid", "mailchimp"),
    ("x-github-reason", "github"),
    ("x-github-sender", "github"),
];

const ESP_PREFIX: &[(&str, &str)] = &[
    ("x-ses", "ses"),
    ("x-mailgun", "mailgun"),
    ("x-sg", "sendgrid"),
    ("x-mandrill", "mandrill"),
    ("x-postmark", "postmark"),
    ("x-sparkpost", "sparkpost"),
    ("x-msys", "sparkpost"),
    ("x-shopify", "shopify"),
];

#[derive(Debug, Default, Clone)]
pub struct Features {
    pub msgid: String,
    pub msgid_domain: String,
    pub date_ts: f64,
    pub from_addr: String,
    pub from_domain: String,
    pub from_name: String,
    pub to_addrs: Vec<String>,
    pub reply_to: String,
    pub rpath_domain: String,
    pub list_id: String,
    pub precedence: String,
    pub subject: String,
    pub subject_tmpl: String,
    pub dkim_d: Vec<String>,
    pub esp: Vec<String>,
    pub att_types: Vec<String>,
    pub att_names: Vec<String>,
    pub body: String,
}

fn sub(re: &Regex, repl: &str, s: &str) -> String {
    re.replace_all(s, repl).into_owned()
}

fn prefix(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

pub fn subject_template(subject: &str) -> String {
    let mut s = subject.trim().to_owned();
    loop {
        let next = sub(&REPLY_PREFIX, "", &s);
        if next == s {
            break;
        }
        s = next;
    }
    let mut s = s.to_lowercase();
    for (re, repl) in [
        (&*AMOUNT, "<amt>"),
        (&*MONTH_DAY, "<date>"),
        (&*DAY_MONTH, "<date>"),
        (&*NUMERIC_DATE, "<date>"),
        (&*NUMBER_WORD, "<n>"),
        (&*HASH_NUMBER, "<n>"),
    ] {
        s = sub(re, repl, &s);
    }
    sub(&SPACE, " ", &s).trim().to_owned()
}

pub const RELAY_DOMAIN: &str = "privaterelay.appleid.com";

/// The original sender's domain behind an Apple Private Relay address, which
/// iCloud writes as `<local>_at_<domain with _ for .>_<10 chars>_<8 hex>@privaterelay.appleid.com`.
pub fn relay_domain(addr: &str) -> Option<String> {
    let local = addr.to_lowercase().strip_suffix(&format!("@{RELAY_DOMAIN}"))?.to_owned();
    let (rest, tag) = local.rsplit_once('_')?;
    let (rest, id) = rest.rsplit_once('_')?;
    if tag.len() != 8 || !tag.bytes().all(|b| b.is_ascii_hexdigit()) || id.len() != 10 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let (_, domain) = rest.split_once("_at_")?;
    let domain = domain.replace('_', ".");
    (domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    .then_some(domain)
}

/// The sender's domain, looking through Apple Private Relay.
pub fn sender_domain(addr: &str) -> String {
    relay_domain(addr).unwrap_or_else(|| domain_of(addr))
}

pub fn domain_of(addr: &str) -> String {
    match addr.rfind('@') {
        Some(i) => addr[i + 1..]
            .to_lowercase()
            .trim_matches(['<', '>'])
            .to_owned(),
        None => String::new(),
    }
}

pub fn strip_markup(text: &str) -> String {
    let text = sub(&SCRIPT_STYLE, " ", text);
    let text = sub(&TAG, " ", &text);
    sub(&SPACE, " ", &unescape(&text)).trim().to_owned()
}

/// The common HTML entities; others stay as written.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest.bytes().take(12).position(|b| b == b';');
        let decoded = end.and_then(|e| {
            let name = &rest[1..e];
            let ch = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" | "#39" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ => name
                    .strip_prefix("#x")
                    .or_else(|| name.strip_prefix("#X"))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| name.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &rest[e + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn normalize_msgid(value: &str) -> String {
    sub(&MSGID_STRIP, "", value)
}

pub fn content_digest(header: &[u8], text: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(header);
    h.update([0]);
    h.update(text);
    hex::encode(h.finalize())
}

fn raw_header<'a>(msg: &'a Message, name: &'a str) -> Option<&'a str> {
    msg.header_raw(name)
        .map(|v| v.trim_matches(|c: char| c.is_ascii_whitespace()))
}

fn addresses(msg: &Message, names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        for value in msg.header_as(*name, HeaderForm::Addresses) {
            if let HeaderValue::Address(a) = value {
                for addr in a.iter() {
                    if let Some(x) = addr.address().filter(|x| !x.is_empty()) {
                        out.push(x.to_lowercase());
                    }
                }
            }
        }
    }
    out
}

fn esp_of(msg: &Message) -> Vec<String> {
    let mut set = BTreeSet::new();
    for (key, value) in msg.headers_raw() {
        let k = key.to_lowercase();
        if let Some((_, esp)) = ESP_EXACT.iter().find(|(name, _)| *name == k) {
            set.insert(*esp);
        } else if let Some((_, esp)) = ESP_PREFIX.iter().find(|(p, _)| k.starts_with(p)) {
            set.insert(*esp);
        } else if prefix(&value.to_lowercase(), 200).contains("amazonses") {
            set.insert("ses");
        }
    }
    set.into_iter().map(String::from).collect()
}

fn body_text(msg: &Message) -> String {
    let plain = msg.text_bodies().find_map(|p| match &p.body {
        PartType::Text(t) => Some(t.as_ref()),
        _ => None,
    });
    if let Some(text) = plain {
        let text = sub(&SPACE, " ", text).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    let html = msg.html_bodies().find_map(|p| match &p.body {
        PartType::Html(t) => Some(t.as_ref()),
        _ => None,
    });
    html.map(strip_markup).unwrap_or_default()
}

/// Features of a message from its raw header and (possibly truncated) text.
pub fn extract(header: &[u8], text: &[u8], fallback_ts: f64) -> Features {
    let mut raw = Vec::with_capacity(header.len() + text.len());
    raw.extend_from_slice(header);
    raw.extend_from_slice(text);
    let Some(msg) = MessageParser::default().parse(&raw) else {
        return Features {
            date_ts: fallback_ts,
            ..Features::default()
        };
    };
    let (from_name, from_addr) = msg
        .from()
        .and_then(|a| a.first())
        .map(|a| {
            (
                a.name().unwrap_or_default().to_owned(),
                a.address().unwrap_or_default().to_lowercase(),
            )
        })
        .unwrap_or_default();
    let date_ts = msg
        .date()
        .map(|d| d.to_timestamp() as f64)
        .filter(|ts| *ts > 0.0)
        .unwrap_or(fallback_ts);
    let subject = msg.subject().unwrap_or_default().to_owned();
    let body = body_text(&msg);
    let mut dkim = BTreeSet::new();
    for value in msg.header_as("DKIM-Signature", HeaderForm::Raw) {
        if let HeaderValue::Text(v) = value
            && let Some(c) = DKIM_DOMAIN.captures(&v)
        {
            dkim.insert(c[1].to_lowercase());
        }
    }
    let mut types = BTreeSet::new();
    let mut names = BTreeSet::new();
    for part in msg.attachments() {
        if let Some(ct) = part.content_type() {
            let t = match ct.subtype() {
                Some(s) => format!("{}/{}", ct.ctype(), s),
                None => ct.ctype().to_owned(),
            };
            types.insert(t.to_lowercase());
        }
        if let Some(name) = part.attachment_name().filter(|n| !n.is_empty()) {
            names.insert(sub(&DIGITS, "#", &name.to_lowercase()));
        }
    }
    let to: BTreeSet<String> = addresses(&msg, &["To", "Delivered-To", "X-Original-To", "Cc"])
        .into_iter()
        .collect();
    let msgid = normalize_msgid(raw_header(&msg, "Message-ID").unwrap_or_default());
    let one_line = |s: &str| s.replace(['\r', '\n'], "").trim().to_lowercase();
    Features {
        msgid_domain: domain_of(&msgid),
        msgid,
        date_ts,
        from_domain: sender_domain(&from_addr),
        from_addr,
        from_name,
        to_addrs: to.into_iter().collect(),
        reply_to: addresses(&msg, &["Reply-To"])
            .into_iter()
            .next()
            .unwrap_or_default(),
        rpath_domain: addresses(&msg, &["Return-Path"])
            .first()
            .map(|a| domain_of(a))
            .unwrap_or_default(),
        list_id: one_line(raw_header(&msg, "List-Id").unwrap_or_default()),
        precedence: one_line(raw_header(&msg, "Precedence").unwrap_or_default()),
        subject_tmpl: subject_template(&subject),
        subject,
        dkim_d: dkim.into_iter().collect(),
        esp: esp_of(&msg),
        att_types: types.into_iter().collect(),
        att_names: names.into_iter().take(3).collect(),
        body: prefix(&body, BODY_CHARS).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_templates() {
        assert_eq!(
            subject_template("Re: Your order #12345 of $40.00"),
            "your order <n> of <amt>"
        );
        assert_eq!(subject_template("Invoice March 3, 2026"), "invoice <date>");
        assert_eq!(
            subject_template("FW: Statement 03/04/2026"),
            "statement <date>"
        );
        assert_eq!(
            subject_template("  Weekly   Newsletter "),
            "weekly newsletter"
        );
        assert_eq!(subject_template("RE: re: fwd: Hi"), "hi");
    }

    #[test]
    fn headers() {
        let header = b"From: \"Shop\" <Orders@Mail.Shop.example>\r\n\
To: me@example.com\r\n\
Cc: Other <Other@Example.com>\r\n\
Subject: Your order 42\r\n\
Message-ID: <abc.123@mta.shop.example>\r\n\
Return-Path: <bounce@bounces.shop.example>\r\n\
List-Id: Shop News <news.shop.example>\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=Shop.example; s=k1; bh=x\r\n\
X-SES-Outgoing: 2026.01.01\r\n\
X-Mailgun-Sid: abc\r\n\
Content-Type: text/plain\r\n\r\n";
        let f = extract(header, b"Thanks for your <b>order</b>.\r\n", 7.0);
        assert_eq!(f.from_addr, "orders@mail.shop.example");
        assert_eq!(f.from_domain, "mail.shop.example");
        assert_eq!(f.from_name, "Shop");
        assert_eq!(f.to_addrs, ["me@example.com", "other@example.com"]);
        assert_eq!(f.msgid, "abc.123@mta.shop.example");
        assert_eq!(f.msgid_domain, "mta.shop.example");
        assert_eq!(f.rpath_domain, "bounces.shop.example");
        assert_eq!(f.list_id, "shop news <news.shop.example>");
        assert_eq!(f.dkim_d, ["shop.example"]);
        assert_eq!(f.esp, ["mailgun", "ses"]);
        assert_eq!(f.subject_tmpl, "your order <n>");
        assert_eq!(f.date_ts, 7.0);
        assert_eq!(f.body, "Thanks for your <b>order</b>.");
    }

    #[test]
    fn private_relay_domains() {
        assert_eq!(
            sender_domain("newsletter_at_service_tiktok_com_zws2fx45wv_30ff5975@privaterelay.appleid.com"),
            "service.tiktok.com"
        );
        assert_eq!(
            sender_domain("Team_at_my-shop_co_uk_ht74v8v5pj_01d4f950@PrivateRelay.AppleID.com"),
            "my-shop.co.uk"
        );
        for odd in [
            "plain@privaterelay.appleid.com",
            "x_at_example_com_short_01d4f950@privaterelay.appleid.com",
            "x_at_example_com_ht74v8v5pj_nothex!!@privaterelay.appleid.com",
            "x_at__ht74v8v5pj_01d4f950@privaterelay.appleid.com",
            "x_at_com_ht74v8v5pj_01d4f950@privaterelay.appleid.com",
        ] {
            assert_eq!(sender_domain(odd), RELAY_DOMAIN, "{odd}");
        }
        assert_eq!(sender_domain("a@b.example"), "b.example");
    }

    #[test]
    fn html_body_is_stripped() {
        let header = b"From: a@b.c\r\nContent-Type: text/html\r\n\r\n";
        let f = extract(
            header,
            b"<style>p{}</style><p>Hello&nbsp;<b>you</b> &amp; me</p>",
            0.0,
        );
        assert_eq!(f.body, "Hello\u{a0} you & me");
        assert_eq!(
            unescape("&ab\u{feff}\u{feff}\u{feff}x"),
            "&ab\u{feff}\u{feff}\u{feff}x"
        );
    }
}

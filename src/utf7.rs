//! IMAP modified UTF-7 (RFC 3501 §5.1.3) and Gmail label collapsing.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

fn b64_value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

/// Decodes a mailbox name; an undecodable shift sequence is kept verbatim.
pub fn decode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('-') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let chunk = &after[..end];
        if chunk.is_empty() {
            out.push('&');
        } else {
            match decode_chunk(chunk) {
                Some(text) => out.push_str(&text),
                None => out.push_str(&rest[start..start + end + 2]),
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn decode_chunk(chunk: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in chunk.bytes() {
        acc = (acc << 6) | b64_value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 || bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        let (mut acc, mut bits) = (0u32, 0u32);
        for b in bytes {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((acc >> bits) & 63) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((acc << (6 - bits)) & 63) as usize] as char);
        }
        out.push('-');
        pending.clear();
    };
    for ch in value.chars() {
        match ch {
            '&' => {
                flush(&mut pending, &mut out);
                out.push_str("&-");
            }
            ' '..='~' => {
                flush(&mut pending, &mut out);
                out.push(ch);
            }
            _ => {
                let mut buf = [0u16; 2];
                pending.extend_from_slice(ch.encode_utf16(&mut buf));
            }
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// User labels without their parents: `A` and `A/B` collapse to `A/B`.
pub fn collapse_labels(labels: &[String]) -> Vec<String> {
    let user: Vec<&String> = labels.iter().filter(|l| !l.starts_with('\\')).collect();
    let mut out: Vec<String> = user
        .iter()
        .filter(|l| {
            !user
                .iter()
                .any(|o| o != *l && o.starts_with(&format!("{l}/")))
        })
        .map(|l| (*l).clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        assert_eq!(encode("Entwürfe"), "Entw&APw-rfe");
        assert_eq!(decode("Entw&APw-rfe"), "Entwürfe");
        assert_eq!(encode("A&B"), "A&-B");
        assert_eq!(decode("A&-B"), "A&B");
        assert_eq!(decode(&encode("日本語 📬")), "日本語 📬");
    }

    #[test]
    fn bad_shift_is_kept() {
        assert_eq!(decode("x&A-y"), "x&A-y");
        assert_eq!(decode("x&abc"), "x&abc");
    }

    #[test]
    fn collapse() {
        let labels = ["\\Inbox", "Work", "Work/Bills", "Home"].map(String::from);
        assert_eq!(collapse_labels(&labels), ["Home", "Work/Bills"]);
    }
}

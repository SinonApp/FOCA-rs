//! Internet messages (RFC 5322 / MIME, `.eml`): sender and recipients, `Reply-To`,
//! `Message-ID` domain, mailer, originating IP, the `Received:` relay chain (hosts, IP
//! addresses, internal addresses flagged) and recursive parsing of MIME attachments
//! (base64 / quoted-printable) through [`crate::Ctx::extract_child`].
//!
//! The header and MIME helpers are shared with the Outlook `.msg` parser.

use std::net::IpAddr;

use foca_core::{Attachment, DocFormat, Metadata, PersonRole};

use crate::util::{clean_str, decode_codepage, find, truncate};
use crate::{Ctx, MetaError};

/// Maximum size of the header block of one message or part.
const MAX_HEADER_BYTES: usize = 1 << 20;
/// Maximum number of headers per message or part.
const MAX_HEADERS: usize = 2000;
/// Maximum MIME nesting.
const MAX_MIME_DEPTH: usize = 32;
/// Maximum collected body text.
const MAX_TEXT: usize = 1 << 20;
/// Maximum number of links collected from bodies.
const MAX_LINKS: usize = 200;
/// Maximum number of stored `Received:` headers.
const MAX_RECEIVED: usize = 64;

// ------------------------------------------------------------------ decoders

/// Decodes base64, ignoring line breaks and any characters outside the alphabet.
pub(crate) fn base64_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes quoted-printable (`=XX`, soft line breaks). With `underscore`, `_` is a space
/// (RFC 2047 "Q" encoding).
pub(crate) fn qp_decode(s: &[u8], underscore: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'=' {
            match (s.get(i + 1).copied(), s.get(i + 2).copied()) {
                (Some(b'\r'), Some(b'\n')) => i += 3,
                (Some(b'\n'), _) => i += 2,
                (Some(h), Some(l)) => match (hex_val(h), hex_val(l)) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 3;
                    }
                    _ => {
                        out.push(c);
                        i += 1;
                    }
                },
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(if underscore && c == b'_' { b' ' } else { c });
            i += 1;
        }
    }
    out
}

const KOI8_LOWER: &str = "юабцдефгхийклмнопярстужвьызшэщчъ";
const KOI8_UPPER: &str = "ЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ";

fn koi8(b: &[u8]) -> String {
    let lower: Vec<char> = KOI8_LOWER.chars().collect();
    let upper: Vec<char> = KOI8_UPPER.chars().collect();
    b.iter()
        .map(|&c| match c {
            0..=0x7F => c as char,
            0xA3 => 'ё',
            0xA4 => 'є',
            0xA6 => 'і',
            0xA7 => 'ї',
            0xAD => 'ґ',
            0xB3 => 'Ё',
            0xB4 => 'Є',
            0xB6 => 'І',
            0xB7 => 'Ї',
            0xBD => 'Ґ',
            0xC0..=0xDF => lower.get(usize::from(c - 0xC0)).copied().unwrap_or('?'),
            0xE0..=0xFF => upper.get(usize::from(c - 0xE0)).copied().unwrap_or('?'),
            _ => '\u{FFFD}',
        })
        .collect()
}

/// Decodes bytes in a MIME charset (UTF-8, Windows-1251/1252, ISO-8859-1, KOI8-R/U, UTF-16).
pub(crate) fn decode_charset(b: &[u8], charset: &str) -> String {
    let cs = charset.trim().trim_matches('"').to_ascii_lowercase();
    match cs.as_str() {
        "windows-1251" | "cp1251" | "x-cp1251" => decode_codepage(b, 1251),
        "koi8-r" | "koi8-u" | "koi8-ru" => koi8(b),
        "iso-8859-1" | "latin1" | "windows-1252" | "cp1252" | "us-ascii" | "ascii" => {
            decode_codepage(b, 1252)
        }
        "utf-16" | "utf-16le" => crate::util::utf16le(b),
        "utf-16be" => crate::util::utf16be(b),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

/// Decodes RFC 2047 encoded words (`=?charset?B|Q?text?=`); whitespace between adjacent
/// encoded words is dropped.
pub(crate) fn decode_words(s: &str) -> String {
    if !s.contains("=?") {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    let mut pending_ws = String::new();
    let mut last_encoded = false;
    while !rest.is_empty() {
        let Some(start) = rest.find("=?") else {
            out.push_str(&pending_ws);
            out.push_str(rest);
            return out;
        };
        let (before, tail) = rest.split_at(start);
        let word = decode_one_word(tail);
        match word {
            Some((text, used)) => {
                if !(last_encoded && before.trim().is_empty()) {
                    out.push_str(&pending_ws);
                    out.push_str(before);
                }
                pending_ws.clear();
                out.push_str(&text);
                last_encoded = true;
                rest = tail.get(used..).unwrap_or("");
                // keep the whitespace following the word until we know what comes next
                let ws_len = rest.len() - rest.trim_start().len();
                pending_ws.push_str(rest.get(..ws_len).unwrap_or(""));
                rest = rest.get(ws_len..).unwrap_or("");
            }
            None => {
                out.push_str(&pending_ws);
                pending_ws.clear();
                out.push_str(before);
                out.push_str("=?");
                rest = tail.get(2..).unwrap_or("");
                last_encoded = false;
            }
        }
    }
    out.push_str(&pending_ws);
    out
}

/// Decodes one encoded word at the start of `s`; returns the text and the consumed length.
fn decode_one_word(s: &str) -> Option<(String, usize)> {
    let body = s.strip_prefix("=?")?;
    let q1 = body.find('?')?;
    let charset = body.get(..q1)?;
    let charset = charset.split('*').next().unwrap_or(charset); // RFC 2231 language suffix
    let enc = body.get(q1 + 1..q1 + 2)?;
    if body.get(q1 + 2..q1 + 3)? != "?" {
        return None;
    }
    let text_start = q1 + 3;
    let end = body.get(text_start..)?.find("?=")? + text_start;
    let text = body.get(text_start..end)?;
    if text.contains(' ') {
        return None;
    }
    let raw = match enc {
        "B" | "b" => base64_decode(text.as_bytes()),
        "Q" | "q" => qp_decode(text.as_bytes(), true),
        _ => return None,
    };
    Some((decode_charset(&raw, charset), 2 + end + 2))
}

// ------------------------------------------------------------------ headers

/// Splits a message into the header block and the body (at the first empty line).
pub(crate) fn split_head(b: &[u8]) -> (&[u8], &[u8]) {
    let crlf = find(b, b"\r\n\r\n", 0).map(|p| (p, p + 4));
    let lf = find(b, b"\n\n", 0).map(|p| (p, p + 2));
    let cut = match (crlf, lf) {
        (Some(a), Some(c)) => Some(if a.0 <= c.0 { a } else { c }),
        (a, c) => a.or(c),
    };
    match cut {
        Some((h, body)) => (&b[..h], b.get(body..).unwrap_or(&[])),
        None => (b, &[]),
    }
}

/// Parses an RFC 5322 header block with unfolding. Names are lower-cased.
pub(crate) fn parse_headers(block: &[u8]) -> Vec<(String, String)> {
    let block = &block[..block.len().min(MAX_HEADER_BYTES)];
    let text = String::from_utf8_lossy(block);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                if v.len() < 64 * 1024 {
                    v.push(' ');
                    v.push_str(line.trim());
                }
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || name.len() > 76
            || !name.bytes().all(|c| c.is_ascii_graphic() && c != b':')
        {
            continue;
        }
        if out.len() >= MAX_HEADERS {
            break;
        }
        out.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    out
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// Splits a header value into the main token and parameters (`type/sub; a=b; c="d"`), with
/// RFC 2231 continuations and charsets for parameters.
pub(crate) fn parse_params(v: &str) -> (String, Vec<(String, String)>) {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in v.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    let main = parts
        .first()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut params: Vec<(String, String)> = Vec::new();
    let mut continued: Vec<(String, u32, String)> = Vec::new();
    for p in parts.iter().skip(1).take(64) {
        let Some((k, val)) = p.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let val = val.trim().trim_matches('"').to_string();
        // name*0*=..., name*1=..., name*=utf-8''...
        if let Some((base, rest)) = k.split_once('*') {
            let idx = rest.trim_end_matches('*').parse::<u32>().unwrap_or(0);
            continued.push((base.to_string(), idx, val));
        } else {
            params.push((k, decode_words(&val)));
        }
    }
    continued.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    let mut i = 0;
    while i < continued.len() {
        let base = continued[i].0.clone();
        let mut joined = String::new();
        while i < continued.len() && continued[i].0 == base {
            joined.push_str(&continued[i].2);
            i += 1;
        }
        let value = match joined.split_once('\'') {
            Some((cs, rest)) => {
                let text = rest.split_once('\'').map_or(rest, |(_, t)| t);
                decode_charset(&pct_decode(text), cs)
            }
            None => joined,
        };
        params.retain(|(k, _)| k != &base);
        params.push((base, value));
    }
    (main, params)
}

fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex_val),
                b.get(i + 2).copied().and_then(hex_val),
            ) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn param<'a>(p: &'a [(String, String)], name: &str) -> Option<&'a str> {
    p.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// Parses an address list into `(display name, address)` pairs.
pub(crate) fn parse_addresses(v: &str) -> Vec<(Option<String>, Option<String>)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut angle, mut paren) = (false, false, 0u32);
    let mut items = Vec::new();
    for c in v.chars() {
        match c {
            '"' if paren == 0 => quoted = !quoted,
            '<' if !quoted && paren == 0 => angle = true,
            '>' if !quoted && paren == 0 => angle = false,
            '(' if !quoted => paren = paren.saturating_add(1),
            ')' if !quoted => paren = paren.saturating_sub(1),
            ',' | ';' if !quoted && !angle && paren == 0 => {
                items.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    items.push(cur);
    for it in items.iter().take(500) {
        let it = decode_words(it.trim());
        if it.is_empty() {
            continue;
        }
        let (name, addr) = match (it.find('<'), it.rfind('>')) {
            (Some(a), Some(b)) if a < b => {
                let name = it[..a].trim().trim_matches('"').trim();
                (name.to_string(), it[a + 1..b].trim().to_string())
            }
            _ => {
                // bare address, maybe with a comment: a@b (Name)
                let (addr, comment) = match (it.find('('), it.rfind(')')) {
                    (Some(a), Some(b)) if a < b => (it[..a].trim(), it[a + 1..b].trim()),
                    _ => (it.as_str(), ""),
                };
                (comment.to_string(), addr.trim_matches('"').to_string())
            }
        };
        let addr = addr.trim_start_matches("mailto:").to_string();
        let addr = (addr.contains('@') && !addr.contains(' ')).then_some(addr);
        let name = clean_str(&name).filter(|n| addr.as_deref() != Some(n.as_str()));
        if name.is_some() || addr.is_some() {
            out.push((name, addr));
        }
    }
    out
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Converts an RFC 5322 date (`Thu, 14 Mar 2024 18:42:00 +0200`) to ISO 8601.
pub(crate) fn rfc2822_date(s: &str) -> Option<String> {
    let s = s.split('(').next().unwrap_or(s);
    let s = s.split_once(',').map_or(s, |(_, r)| r);
    let tok: Vec<&str> = s.split_whitespace().collect();
    let day: u32 = tok.first()?.parse().ok()?;
    let mon = tok.get(1)?.to_ascii_lowercase();
    let mon = MONTHS.iter().position(|m| mon.starts_with(m))? + 1;
    let mut year: u32 = tok.get(2)?.parse().ok()?;
    if year < 100 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let t: Vec<u32> = tok
        .get(3)?
        .split(':')
        .map(|x| x.parse().ok())
        .collect::<Option<Vec<u32>>>()?;
    let (h, m, sec) = (*t.first()?, *t.get(1)?, t.get(2).copied().unwrap_or(0));
    if !(1..=31).contains(&day) || h > 23 || m > 59 || sec > 60 || !(1900..=2200).contains(&year) {
        return None;
    }
    let zone = tok.get(4).copied().unwrap_or("");
    let offset = match zone.to_ascii_uppercase().as_str() {
        "GMT" | "UT" | "UTC" | "Z" => Some("Z".to_string()),
        z if (z.starts_with('+') || z.starts_with('-'))
            && z.len() == 5
            && z[1..].bytes().all(|c| c.is_ascii_digit()) =>
        {
            if &z[1..] == "0000" {
                Some("Z".to_string())
            } else {
                Some(format!("{}{}:{}", &z[..1], &z[1..3], &z[3..5]))
            }
        }
        _ => None,
    };
    Some(format!(
        "{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{sec:02}{}",
        offset.unwrap_or_default()
    ))
}

// ------------------------------------------------------------------ hosts and IPs

/// Returns `true` for private, loopback, link-local and CGNAT addresses.
pub(crate) fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || (s[0] & 0xFE00) == 0xFC00 || (s[0] & 0xFFC0) == 0xFE80
        }
    }
}

const INTERNAL_SUFFIXES: [&str; 12] = [
    ".local",
    ".lan",
    ".corp",
    ".internal",
    ".intra",
    ".intranet",
    ".localdomain",
    ".home",
    ".priv",
    ".private",
    ".ad",
    ".test",
];

/// Returns `true` for host names that look internal (single label or an internal suffix).
pub(crate) fn is_internal_host(h: &str) -> bool {
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    !h.contains('.') || INTERNAL_SUFFIXES.iter().any(|s| h.ends_with(s))
}

fn valid_host(h: &str) -> Option<String> {
    let h = h.trim_matches(|c: char| matches!(c, '[' | ']' | '(' | ')' | ';' | ',' | '<' | '>'));
    let h = h.trim_end_matches('.');
    if h.len() < 2
        || h.len() > 253
        || !h
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
        || h.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        || h.starts_with(['-', '.'])
    {
        return None;
    }
    let lower = h.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "unknown" | "helo" | "ehlo" | "with" | "by" | "from" | "id" | "for" | "via"
    ) {
        return None;
    }
    Some(h.to_string())
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim_matches(|c: char| matches!(c, '[' | ']' | '(' | ')' | ';' | ',' | '<' | '>'));
    let s = s
        .strip_prefix("IPv6:")
        .or_else(|| s.strip_prefix("ipv6:"))
        .unwrap_or(s);
    s.parse().ok()
}

/// Hosts and IP addresses of one `Received:` header.
#[derive(Default)]
pub(crate) struct Hop {
    pub hosts: Vec<String>,
    pub ips: Vec<IpAddr>,
}

pub(crate) fn parse_received(v: &str) -> Hop {
    let mut hop = Hop::default();
    let main = v.rsplit_once(';').map_or(v, |(a, _)| a);
    let toks: Vec<&str> = main.split_whitespace().collect();
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i];
        let lower = t.to_ascii_lowercase();
        if (lower == "from" || lower == "by") && i + 1 < toks.len() {
            if let Some(ip) = parse_ip(toks[i + 1]) {
                push_ip(&mut hop, ip);
            } else if let Some(h) = valid_host(toks[i + 1]) {
                push_host(&mut hop, h);
            }
            i += 2;
            continue;
        }
        if lower == "with" || lower == "id" || lower == "for" {
            // protocol, queue id and recipient are not hosts
            i += 2;
            continue;
        }
        if t.starts_with('(') || t.starts_with('[') {
            // comment: "(host.example.com [192.0.2.1])", "(HELO x)", "([10.0.0.1])"
            if let Some(ip) = parse_ip(t) {
                push_ip(&mut hop, ip);
            } else if t.starts_with('(') && t.contains('.') {
                if let Some(h) = valid_host(t) {
                    push_host(&mut hop, h);
                }
            }
        } else if let Some(ip) = t.find('[').and_then(|a| t.get(a..)).and_then(parse_ip) {
            push_ip(&mut hop, ip);
        }
        i += 1;
    }
    hop
}

/// One `Received:` header as a structured hop: the `from` and `by` names, the first sending
/// IP and the date after the last `;`.
pub(crate) fn mail_hop(v: &str) -> foca_core::MailHop {
    let (main, date) = match v.rsplit_once(';') {
        Some((a, d)) => (a, crate::util::normalize_date(d.trim())),
        None => (v, None),
    };
    let toks: Vec<&str> = main.split_whitespace().collect();
    let mut hop = foca_core::MailHop {
        date: date.map(|d| truncate(&d, 64)),
        ..Default::default()
    };
    let mut i = 0;
    let mut section = "";
    while i < toks.len() {
        let t = toks[i];
        let lower = t.to_ascii_lowercase();
        if (lower == "from" || lower == "by") && i + 1 < toks.len() {
            let name = toks[i + 1].trim_matches(['(', ')', '[', ']', ';']);
            let name = truncate(name, 255);
            if lower == "from" {
                hop.from = Some(name);
            } else {
                hop.by = Some(name);
            }
            section = if lower == "from" { "from" } else { "by" };
            i += 2;
            continue;
        }
        if section == "from" && hop.ip.is_none() {
            if let Some(ip) = t.find('[').and_then(|a| t.get(a..)).and_then(parse_ip) {
                hop.ip = Some(ip.to_string());
            }
        }
        i += 1;
    }
    let ip_internal = hop
        .ip
        .as_deref()
        .and_then(|x| x.parse::<IpAddr>().ok())
        .is_some_and(|ip| is_internal_ip(&ip) && !ip.is_loopback());
    let from_internal = hop.from.as_deref().is_some_and(|f| {
        f.parse::<IpAddr>()
            .map(|ip| is_internal_ip(&ip))
            .unwrap_or_else(|_| is_internal_host(f))
    });
    hop.internal = ip_internal || from_internal;
    hop
}

fn push_host(hop: &mut Hop, h: String) {
    if !hop.hosts.iter().any(|x| x.eq_ignore_ascii_case(&h)) {
        hop.hosts.push(h);
    }
}

fn push_ip(hop: &mut Hop, ip: IpAddr) {
    if !ip.is_unspecified() && !hop.ips.contains(&ip) {
        hop.ips.push(ip);
    }
}

/// Collects `http(s)://` links from text.
pub(crate) fn find_urls(text: &str, out: &mut Vec<String>) {
    let mut rest = text;
    while out.len() < MAX_LINKS {
        let Some(p) = rest.find("http") else { return };
        let tail = &rest[p..];
        let is_url = tail.starts_with("http://") || tail.starts_with("https://");
        if !is_url {
            rest = &rest[p + 4..];
            continue;
        }
        let end = tail
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`' | '{' | '}')
            })
            .unwrap_or(tail.len());
        let url = tail[..end].trim_end_matches(['.', ',', ';', ':', ')', ']', '!', '?']);
        if url.len() > 10 {
            Metadata::add_unique(out, &truncate(url, 2048));
        }
        rest = &tail[end..];
    }
}

// ------------------------------------------------------------------ header mapping

fn add_people(meta: &mut Metadata, v: &str, role: PersonRole, source: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    for (name, addr) in parse_addresses(v) {
        if let Some(a) = &addr {
            Metadata::add_unique(&mut meta.emails, a);
            addrs.push(a.to_ascii_lowercase());
        }
        let who = match (&name, &addr) {
            (Some(n), Some(a)) => format!("{n} <{a}>"),
            (Some(n), None) => n.clone(),
            (None, Some(a)) => a.clone(),
            (None, None) => continue,
        };
        meta.add_person(&truncate(&who, 256), role, source);
    }
    addrs
}

fn domain_of(addr: &str) -> Option<String> {
    let d = addr.rsplit_once('@')?.1.trim_end_matches('>').trim();
    (!d.is_empty()).then(|| d.to_ascii_lowercase())
}

/// Headers whose raw value is kept in `fields` as `<prefix>:<name>`.
const KEPT_HEADERS: [&str; 30] = [
    "message-id",
    "in-reply-to",
    "x-mailer",
    "user-agent",
    "x-originating-ip",
    "x-originating-email",
    "x-sender-ip",
    "x-source-ip",
    "x-client-ip",
    "x-sender",
    "x-envelope-from",
    "x-original-to",
    "delivered-to",
    "return-path",
    "sender",
    "reply-to",
    "organization",
    "thread-index",
    "thread-topic",
    "x-ms-exchange-crosstenant-id",
    "x-ms-exchange-organization-authas",
    "x-ms-exchange-organization-originalclientipaddress",
    "x-ms-exchange-organization-network-message-id",
    "x-ms-has-attach",
    "x-ms-tnef-correlator",
    "x-google-smtp-source",
    "x-virus-scanned",
    "x-spam-checker-version",
    "authentication-results",
    "received-spf",
];

/// Maps message headers onto metadata. `prefix` is the field prefix (`eml` or `msg`).
pub(crate) fn apply_headers(meta: &mut Metadata, h: &[(String, String)], prefix: &str) {
    for (k, v) in h {
        if KEPT_HEADERS.contains(&k.as_str()) {
            let key = format!("{prefix}:{k}");
            meta.fields
                .entry(key)
                .or_insert_with(|| truncate(&decode_words(v), 1024));
        }
    }
    if let Some(s) = header(h, "subject").and_then(|s| clean_str(&decode_words(s))) {
        meta.title.get_or_insert(truncate(&s, 1024));
    }
    if let Some(d) = header(h, "date") {
        if let Some(iso) = rfc2822_date(d) {
            meta.created.get_or_insert(iso);
        }
    }
    let from = header(h, "from")
        .map(|v| add_people(meta, v, PersonRole::Author, &format!("{prefix}:from")))
        .unwrap_or_default();
    if let Some(v) = header(h, "from") {
        if let Some((name, addr)) = parse_addresses(v).into_iter().next() {
            if meta.author.is_none() {
                meta.author = name.or(addr).map(|s| truncate(&s, 256));
            }
        }
    }
    for (name, role) in [
        ("sender", PersonRole::Other),
        ("reply-to", PersonRole::Other),
        ("to", PersonRole::Other),
        ("cc", PersonRole::Other),
        ("bcc", PersonRole::Other),
        ("delivered-to", PersonRole::Other),
        ("x-original-to", PersonRole::Other),
        ("disposition-notification-to", PersonRole::Other),
    ] {
        for (k, v) in h.iter().filter(|(k, _)| k == name) {
            let addrs = add_people(meta, v, role, &format!("{prefix}:{k}"));
            if name == "reply-to" {
                let fd: Vec<String> = from.iter().filter_map(|a| domain_of(a)).collect();
                if addrs
                    .iter()
                    .filter_map(|a| domain_of(a))
                    .any(|d| !fd.is_empty() && !fd.contains(&d))
                {
                    meta.fields
                        .insert(format!("{prefix}:reply_to_differs"), "true".into());
                }
            }
        }
    }
    if let Some(rp) = header(h, "return-path") {
        for (_, a) in parse_addresses(rp) {
            if let Some(a) = a {
                Metadata::add_unique(&mut meta.emails, &a);
            }
        }
    }
    for k in ["x-mailer", "user-agent"] {
        if let Some(m) = header(h, k).and_then(|v| clean_str(&decode_words(v))) {
            let m = truncate(&m, 256);
            meta.application.get_or_insert(m.clone());
            Metadata::add_unique(&mut meta.software, &m);
        }
    }
    if let Some(o) = header(h, "organization").and_then(|v| clean_str(&decode_words(v))) {
        meta.company.get_or_insert(truncate(&o, 256));
    }
    if let Some(id) = header(h, "message-id") {
        let id = id.trim().trim_matches(['<', '>']);
        if let Some(d) = domain_of(id).and_then(|d| valid_host(&d)) {
            meta.fields
                .insert(format!("{prefix}:message_id_domain"), d.clone());
            meta.add_server(&d, &format!("{prefix}:message-id"));
        }
    }
    // originating client addresses
    let mut origin_ips: Vec<IpAddr> = Vec::new();
    for k in [
        "x-originating-ip",
        "x-sender-ip",
        "x-source-ip",
        "x-client-ip",
        "x-ms-exchange-organization-originalclientipaddress",
    ] {
        for (_, v) in h.iter().filter(|(n, _)| n == k) {
            if let Some(ip) = parse_ip(v.trim()) {
                if !origin_ips.contains(&ip) {
                    origin_ips.push(ip);
                }
            }
        }
    }
    if let Some(r) = header(h, "x-forefront-antispam-report") {
        for part in r.split(';') {
            if let Some(ip) = part.trim().strip_prefix("CIP:").and_then(parse_ip) {
                if !origin_ips.contains(&ip) {
                    origin_ips.push(ip);
                }
            }
        }
    }
    if !origin_ips.is_empty() {
        let list: Vec<String> = origin_ips.iter().map(ToString::to_string).collect();
        meta.fields
            .insert(format!("{prefix}:originating_ips"), list.join(", "));
        for ip in &origin_ips {
            meta.add_server(&ip.to_string(), &format!("{prefix}:x-originating-ip"));
        }
    }
    if let Some(d) = header(h, "dkim-signature") {
        for part in d.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                match k.trim() {
                    "d" => {
                        meta.fields
                            .insert(format!("{prefix}:dkim_domain"), truncate(v.trim(), 256));
                    }
                    "s" => {
                        meta.fields
                            .insert(format!("{prefix}:dkim_selector"), truncate(v.trim(), 256));
                    }
                    _ => {}
                }
            }
        }
    }
    // relay chain, top (closest to the recipient) first
    let mut internal_hosts: Vec<String> = Vec::new();
    let mut internal_ips: Vec<String> = Vec::new();
    let mut hops = 0u64;
    for (_, v) in h.iter().filter(|(k, _)| k == "received") {
        hops += 1;
        if hops as usize <= MAX_RECEIVED {
            meta.fields
                .insert(format!("{prefix}:received.{hops:02}"), truncate(v, 512));
        }
        if meta.mail_hops.len() < MAX_RECEIVED {
            meta.mail_hops.push(mail_hop(v));
        }
        let hop = parse_received(v);
        for host in hop.hosts {
            if is_internal_host(&host) {
                Metadata::add_unique(&mut internal_hosts, &host);
            }
            meta.add_server(&host, &format!("{prefix}:received"));
        }
        for ip in hop.ips {
            if is_internal_ip(&ip) {
                if ip.is_loopback() {
                    continue;
                }
                Metadata::add_unique(&mut internal_ips, &ip.to_string());
            }
            meta.add_server(&ip.to_string(), &format!("{prefix}:received"));
        }
    }
    for ip in &origin_ips {
        if is_internal_ip(ip) && !ip.is_loopback() {
            Metadata::add_unique(&mut internal_ips, &ip.to_string());
        }
    }
    if hops > 0 {
        meta.stats.insert("received_hops".into(), hops);
    }
    if !internal_hosts.is_empty() {
        meta.fields.insert(
            format!("{prefix}:internal_hosts"),
            truncate(&internal_hosts.join(", "), 2048),
        );
    }
    if !internal_ips.is_empty() {
        meta.fields.insert(
            format!("{prefix}:internal_ips"),
            truncate(&internal_ips.join(", "), 2048),
        );
    }
}

/// Removes message identifiers (`Message-ID`, `In-Reply-To`) that path post-processing picked up
/// as e-mail addresses.
pub(crate) fn drop_message_ids(meta: &mut Metadata) {
    let ids: Vec<String> = meta
        .fields
        .iter()
        .filter(|(k, _)| k.ends_with(":message-id") || k.ends_with(":in-reply-to"))
        .flat_map(|(_, v)| {
            v.split_whitespace()
                .map(|x| x.trim_matches(['<', '>']).to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    if !ids.is_empty() {
        meta.emails
            .retain(|e| !ids.iter().any(|i| i.eq_ignore_ascii_case(e)));
    }
}

// ------------------------------------------------------------------ MIME

struct Walk<'c, 'a> {
    ctx: &'c Ctx<'a>,
    parts: usize,
    text: String,
    want_text: bool,
}

fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len() / 2);
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn decode_body(body: &[u8], cte: &str) -> Vec<u8> {
    match cte.trim().to_ascii_lowercase().as_str() {
        "base64" => base64_decode(body),
        "quoted-printable" => qp_decode(body, false),
        _ => body.to_vec(),
    }
}

/// Splits a multipart body by its boundary; the preamble and epilogue are dropped.
fn split_multipart<'b>(body: &'b [u8], boundary: &str, max: usize) -> Vec<&'b [u8]> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    let mut starts: Vec<(usize, usize, bool)> = Vec::new(); // (delimiter start, content start, is_close)
    let mut pos = 0;
    while let Some(p) = find(body, d, pos) {
        let at_line_start = p == 0 || body.get(p - 1) == Some(&b'\n');
        let after = p + d.len();
        if at_line_start {
            let close = body.get(after..after + 2) == Some(b"--");
            let content = match find(body, b"\n", after) {
                Some(nl) => nl + 1,
                None => body.len(),
            };
            starts.push((p, content, close));
            if close || starts.len() > max {
                break;
            }
        }
        pos = after;
    }
    let mut parts = Vec::new();
    for w in starts.windows(2) {
        let (_, content, close) = w[0];
        if close {
            break;
        }
        let mut end = w[1].0;
        // the CRLF before the delimiter belongs to the delimiter
        if end > content && body.get(end - 1) == Some(&b'\n') {
            end -= 1;
            if end > content && body.get(end - 1) == Some(&b'\r') {
                end -= 1;
            }
        }
        if let Some(p) = body.get(content..end.max(content)) {
            parts.push(p);
        }
    }
    parts
}

fn walk_part(
    meta: &mut Metadata,
    w: &mut Walk,
    headers: &[(String, String)],
    body: &[u8],
    depth: usize,
) -> Result<(), MetaError> {
    w.parts += 1;
    if w.parts > w.ctx.max_entries() {
        return Err(MetaError::TooManyEntries("MIME: too many parts".into()));
    }
    let (ctype, cparams) = header(headers, "content-type")
        .map(parse_params)
        .unwrap_or_else(|| ("text/plain".to_string(), Vec::new()));
    let (disp, dparams) = header(headers, "content-disposition")
        .map(parse_params)
        .unwrap_or_default();
    if let Some(sub) = ctype.strip_prefix("multipart/") {
        if depth >= MAX_MIME_DEPTH.min(w.ctx.max_xml_depth()) {
            meta.warnings.push("MIME: nesting too deep".into());
            return Ok(());
        }
        let Some(boundary) = param(&cparams, "boundary").filter(|b| !b.is_empty()) else {
            meta.warnings
                .push(format!("MIME: multipart/{sub} without boundary"));
            return Ok(());
        };
        for part in split_multipart(body, boundary, w.ctx.max_entries()) {
            let (ph, pb) = split_head(part);
            let ph = parse_headers(ph);
            walk_part(meta, w, &ph, pb, depth + 1)?;
        }
        return Ok(());
    }
    let cte = header(headers, "content-transfer-encoding").unwrap_or("7bit");
    let filename = param(&dparams, "filename")
        .or_else(|| param(&cparams, "name"))
        .and_then(clean_str)
        .map(|n| truncate(&n, 255));
    let is_text = ctype.starts_with("text/plain") || ctype.starts_with("text/html");
    if is_text && filename.is_none() && disp != "attachment" {
        let data = decode_body(body, cte);
        w.ctx.spend(data.len() as u64)?;
        let charset = param(&cparams, "charset").unwrap_or("utf-8");
        let mut s = decode_charset(&data, charset);
        if ctype.starts_with("text/html") {
            find_urls(&s, &mut meta.links);
            s = strip_html(&s);
        } else {
            find_urls(&s, &mut meta.links);
        }
        if w.want_text && w.text.len() < MAX_TEXT {
            let room = MAX_TEXT - w.text.len();
            let cut = crate::util::floor_char_boundary(&s, room);
            w.text.push_str(&s[..cut]);
            w.text.push('\n');
        }
        return Ok(());
    }
    let data = decode_body(body, cte);
    w.ctx.spend(data.len() as u64)?;
    let name = filename.unwrap_or_else(|| {
        if ctype == "message/rfc822" {
            format!("message-{}.eml", w.parts)
        } else {
            format!("part-{}", w.parts)
        }
    });
    if meta.attachments.len() < 1000 {
        meta.attachments.push(Attachment {
            name: name.clone(),
            size: Some(data.len() as u64),
            mime: Some(truncate(&ctype, 128)),
        });
    }
    w.ctx
        .attach_child(meta, &data, &name, &format!("attachment:{name}"))
}

fn parse(b: &[u8], ctx: &Ctx, want_text: bool) -> Result<(Metadata, String), MetaError> {
    let mut meta = Metadata::new(DocFormat::Eml);
    // an mbox "From " separator line is skipped
    let b = if b.starts_with(b"From ") {
        find(b, b"\n", 0)
            .and_then(|p| b.get(p + 1..))
            .unwrap_or(&[])
    } else {
        b
    };
    let (head, body) = split_head(b);
    let headers = parse_headers(head);
    if headers.is_empty() {
        return Err(MetaError::malformed("eml", "no headers"));
    }
    apply_headers(&mut meta, &headers, "eml");
    let mut w = Walk {
        ctx,
        parts: 0,
        text: String::new(),
        want_text,
    };
    if let Some(s) = &meta.title {
        w.text.push_str(s);
        w.text.push('\n');
    }
    walk_part(&mut meta, &mut w, &headers, body, 0)?;
    if !meta.attachments.is_empty() {
        meta.stats
            .insert("attachments".into(), meta.attachments.len() as u64);
    }
    Ok((meta, w.text))
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    parse(b, ctx, false).map(|(m, _)| m)
}

/// Returns the subject and the decoded text parts (HTML stripped).
pub fn text(b: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    parse(b, ctx, true).map(|(_, t)| t)
}

/// Returns `true` if the text looks like an RFC 5322 message header block.
pub(crate) fn looks_like_mail(head: &str, ext: &str) -> bool {
    let mut known = 0;
    let mut first = true;
    for line in head.lines().take(200) {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        if first && line.starts_with("From ") {
            first = false;
            continue;
        }
        let Some((name, _)) = line.split_once(':') else {
            return false;
        };
        let name = name.to_ascii_lowercase();
        if name.is_empty() || name.contains(' ') {
            return false;
        }
        if first && !(name.starts_with("x-") || MAIL_HEADERS.contains(&name.as_str())) {
            return false;
        }
        first = false;
        if MAIL_HEADERS.contains(&name.as_str()) {
            known += 1;
        }
    }
    known >= 3 || (known >= 1 && matches!(ext, "eml" | "mht" | "mhtml" | "msg"))
}

const MAIL_HEADERS: [&str; 16] = [
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "received",
    "return-path",
    "mime-version",
    "content-type",
    "reply-to",
    "delivered-to",
    "sender",
    "x-mailer",
    "dkim-signature",
    "authentication-results",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoders() {
        assert_eq!(base64_decode(b"SGVs\r\nbG8="), b"Hello");
        assert_eq!(qp_decode(b"a=3Db=\r\nc", false), b"a=bc");
        assert_eq!(
            decode_words("=?UTF-8?B?0IbQstCw0L0=?= =?utf-8?Q?_=D0=9F?= x"),
            "Іван П x"
        );
        assert_eq!(decode_words("=?broken"), "=?broken");
        assert_eq!(decode_charset(&[0xE9, 0xFE, 0xA6], "koi8-u"), "ИЧі");
        assert_eq!(
            rfc2822_date("Thu, 14 Mar 2024 18:42:07 +0200 (EET)").as_deref(),
            Some("2024-03-14T18:42:07+02:00")
        );
        assert_eq!(
            rfc2822_date("14 Mar 24 18:42 GMT").as_deref(),
            Some("2024-03-14T18:42:00Z")
        );
        assert!(rfc2822_date("garbage").is_none());
    }

    #[test]
    fn received_chain() {
        let hop = parse_received(
            "from EXCH01.corp.example.test (10.20.0.15) by mx1.example.com (192.0.2.10) with ESMTPS id 42; Thu, 14 Mar 2024 18:42:00 +0200",
        );
        assert_eq!(
            hop.hosts,
            vec!["EXCH01.corp.example.test", "mx1.example.com"]
        );
        assert_eq!(hop.ips.len(), 2);
        assert!(is_internal_ip(&hop.ips[0]) && !is_internal_ip(&hop.ips[1]));
        let hop = parse_received("from [IPv6:fd00::5] (helo=ws-042) by relay.example.com");
        assert!(is_internal_ip(&hop.ips[0]));
        assert!(is_internal_host("ws-042") && is_internal_host("dc1.corp.local"));
        assert!(!is_internal_host("mail.example.com"));
    }

    #[test]
    fn addresses_and_params() {
        let a = parse_addresses(
            r#""Petrenko, Ivan" <i.petrenko@example.com>, john@example.org (John Doe), undisclosed-recipients:;"#,
        );
        assert_eq!(a[0].0.as_deref(), Some("Petrenko, Ivan"));
        assert_eq!(a[1].1.as_deref(), Some("john@example.org"));
        assert_eq!(a[1].0.as_deref(), Some("John Doe"));
        let (t, p) = parse_params(
            "attachment; filename*0*=utf-8''%D0%97%D0%B2; filename*1*=%D1%96%D1%82.docx",
        );
        assert_eq!(t, "attachment");
        assert_eq!(param(&p, "filename"), Some("Звіт.docx"));
        let parts = split_multipart(
            b"pre\r\n--b\r\nA: 1\r\n\r\nx\r\n--b\r\n\r\ny\r\n--b--\r\n",
            "b",
            10,
        );
        assert_eq!(parts, vec![&b"A: 1\r\n\r\nx"[..], &b"\r\ny"[..]]);
    }
}

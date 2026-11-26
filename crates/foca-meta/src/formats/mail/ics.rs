//! iCalendar (`.ics`, RFC 5545): calendar name and producer, events with organizers and
//! attendees (names and e-mails), locations, UID domains, creation/modification times and
//! online-meeting links (Teams, Zoom, Google Meet, Webex, ...).
//!
//! The content-line parser is shared with the vCard parser.

use foca_core::{DocFormat, Metadata, PersonRole};

use crate::formats::mail::eml::{decode_charset, find_urls, qp_decode};
use crate::util::{clean_str, decode_text, truncate};
use crate::{Ctx, MetaError};

/// Maximum number of content lines.
const MAX_LINES: usize = 200_000;
/// Maximum number of events whose details are stored in `fields`.
const MAX_EVENT_FIELDS: usize = 50;
/// Maximum nesting of `BEGIN`/`END` components.
const MAX_COMPONENT_DEPTH: usize = 16;

/// One content line: upper-cased name without the group prefix, parameters and raw value.
pub(crate) struct Line {
    pub name: String,
    pub params: Vec<(String, String)>,
    pub value: String,
}

impl Line {
    pub fn param(&self, k: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    fn encoding(&self) -> String {
        self.param("ENCODING").unwrap_or("").to_ascii_uppercase()
    }

    /// Raw bytes of a binary value (`ENCODING=b|BASE64`).
    pub fn binary(&self) -> Option<Vec<u8>> {
        let e = self.encoding();
        (e == "B" || e == "BASE64")
            .then(|| crate::formats::mail::eml::base64_decode(self.value.as_bytes()))
    }

    /// Decoded text value: quoted-printable/charset (vCard 2.1) and backslash escapes.
    pub fn text(&self) -> String {
        let raw = if self.encoding() == "QUOTED-PRINTABLE" {
            let b = qp_decode(self.value.as_bytes(), false);
            decode_charset(&b, self.param("CHARSET").unwrap_or("utf-8"))
        } else {
            self.value.clone()
        };
        unescape(&raw)
    }
}

pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(x) => out.push(x),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses content lines with unfolding (and vCard 2.1 quoted-printable soft breaks).
pub(crate) fn parse_lines(b: &[u8]) -> Vec<Line> {
    let text = decode_text(b);
    let mut logical: Vec<String> = Vec::new();
    // whether the current logical line declares quoted-printable encoding
    let mut last_qp = false;
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(cont) = raw.strip_prefix([' ', '\t']) {
            if let Some(last) = logical.last_mut() {
                if last.len() < 1 << 20 {
                    last.push_str(cont);
                }
                continue;
            }
        }
        if let Some(last) = logical.last_mut() {
            // quoted-printable soft line break
            if last_qp && last.ends_with('=') {
                if last.len() < 1 << 20 {
                    last.pop();
                    last.push_str(raw);
                } else {
                    last.pop();
                }
                continue;
            }
        }
        if logical.len() >= MAX_LINES {
            break;
        }
        let head = raw.split(':').next().unwrap_or("");
        last_qp = head.to_ascii_uppercase().contains("QUOTED-PRINTABLE");
        logical.push(raw.to_string());
    }
    logical.iter().filter_map(|l| parse_line(l)).collect()
}

fn parse_line(l: &str) -> Option<Line> {
    // split at the first ':' outside quotes
    let mut quoted = false;
    let mut colon = None;
    for (i, c) in l.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ':' if !quoted => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&l[..colon], &l[colon + 1..]);
    let mut parts = head.split(';');
    let name = parts.next()?.trim();
    let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        return None;
    }
    let params = parts
        .take(32)
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (
                k.trim().to_ascii_uppercase(),
                v.trim().trim_matches('"').to_string(),
            ),
            None => (p.trim().to_ascii_uppercase(), String::new()),
        })
        .collect();
    Some(Line {
        name,
        params,
        value: value.to_string(),
    })
}

/// Converts `20240314T184200Z` / `20240314` to ISO 8601.
pub(crate) fn ical_date(v: &str) -> Option<String> {
    let v = v.trim();
    let d = v.get(..8)?;
    if !d.bytes().all(|c| c.is_ascii_digit()) {
        return crate::util::normalize_date(v);
    }
    let date = format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8]);
    match v.get(8..9) {
        Some("T") => {
            let t = v.get(9..15)?;
            if !t.bytes().all(|c| c.is_ascii_digit()) {
                return Some(date);
            }
            let z = if v.get(15..16) == Some("Z") { "Z" } else { "" };
            Some(format!("{date}T{}:{}:{}{z}", &t[..2], &t[2..4], &t[4..6]))
        }
        _ => Some(date),
    }
}

const MEETING_HOSTS: [&str; 11] = [
    "teams.microsoft.com",
    "teams.live.com",
    "zoom.us",
    "zoomgov.com",
    "meet.google.com",
    "webex.com",
    "gotomeeting.com",
    "meet.jit.si",
    "whereby.com",
    "bluejeans.com",
    "join.skype.com",
];

pub(crate) fn is_meeting_link(u: &str) -> bool {
    let host = u
        .split("://")
        .nth(1)
        .and_then(|r| r.split(['/', '?', '#']).next())
        .unwrap_or("")
        .to_ascii_lowercase();
    MEETING_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// Adds a calendar user address (`ORGANIZER`/`ATTENDEE`) as a person and an e-mail.
fn cal_user(meta: &mut Metadata, l: &Line, role: PersonRole, source: &str) -> Option<String> {
    let addr = l
        .value
        .trim()
        .strip_prefix("mailto:")
        .or_else(|| l.value.trim().strip_prefix("MAILTO:"))
        .map(str::to_string)
        .filter(|a| a.contains('@'));
    if let Some(a) = &addr {
        Metadata::add_unique(&mut meta.emails, a);
    }
    let cn = l.param("CN").and_then(clean_str);
    let who = match (&cn, &addr) {
        (Some(n), Some(a)) => format!("{n} <{a}>"),
        (Some(n), None) => n.clone(),
        (None, Some(a)) => a.clone(),
        (None, None) => return None,
    };
    let who = truncate(&who, 256);
    meta.add_person(&who, role, source);
    Some(who)
}

pub fn extract(b: &[u8], _ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(DocFormat::Ics);
    let lines = parse_lines(b);
    if !lines
        .iter()
        .any(|l| l.name == "BEGIN" && l.value.trim().eq_ignore_ascii_case("VCALENDAR"))
    {
        return Err(MetaError::malformed("ics", "no VCALENDAR"));
    }
    let mut stack: Vec<String> = Vec::new();
    let (mut events, mut todos, mut attendees) = (0u64, 0u64, 0u64);
    let mut created: Vec<String> = Vec::new();
    let mut modified: Vec<String> = Vec::new();
    let mut uid_domains: Vec<String> = Vec::new();
    let mut meeting: Vec<String> = Vec::new();
    let mut organizers: Vec<String> = Vec::new();
    for l in &lines {
        match l.name.as_str() {
            "BEGIN" => {
                if stack.len() >= MAX_COMPONENT_DEPTH {
                    return Err(MetaError::TooDeep("iCalendar components".into()));
                }
                let c = l.value.trim().to_ascii_uppercase();
                match c.as_str() {
                    "VEVENT" => events += 1,
                    "VTODO" => todos += 1,
                    _ => {}
                }
                stack.push(c);
                continue;
            }
            "END" => {
                stack.pop();
                continue;
            }
            _ => {}
        }
        let comp = stack.last().map(String::as_str).unwrap_or("");
        let in_item = matches!(comp, "VEVENT" | "VTODO" | "VJOURNAL");
        let ev = events + todos;
        let ev_key = |k: &str| format!("ics:event.{ev:02}.{k}");
        let store_ev = in_item && (ev as usize) <= MAX_EVENT_FIELDS;
        let v = l.text();
        match (comp, l.name.as_str()) {
            ("VCALENDAR", "PRODID") => {
                if let Some(p) = clean_str(&v) {
                    meta.application.get_or_insert(truncate(&p, 256));
                    Metadata::add_unique(&mut meta.software, &truncate(&p, 256));
                }
            }
            ("VCALENDAR", "X-WR-CALNAME" | "NAME") => {
                if let Some(p) = clean_str(&v) {
                    meta.title.get_or_insert(truncate(&p, 512));
                }
            }
            ("VCALENDAR", "X-WR-CALDESC" | "DESCRIPTION") => {
                meta.description.get_or_insert(truncate(&v, 2048));
            }
            ("VCALENDAR", "X-WR-TIMEZONE" | "X-WR-RELCALID" | "METHOD") => {
                meta.fields.insert(
                    format!("ics:{}", l.name.to_ascii_lowercase()),
                    truncate(&v, 256),
                );
            }
            (_, "ORGANIZER") if in_item => {
                if let Some(w) = cal_user(&mut meta, l, PersonRole::Author, "ics:organizer") {
                    if !organizers.contains(&w) {
                        organizers.push(w.clone());
                    }
                    if store_ev {
                        meta.fields.insert(ev_key("organizer"), w);
                    }
                }
                if let Some(s) = l.param("SENT-BY") {
                    let s = s
                        .trim_start_matches("mailto:")
                        .trim_start_matches("MAILTO:");
                    Metadata::add_unique(&mut meta.emails, s);
                }
            }
            (_, "ATTENDEE") if in_item => {
                attendees += 1;
                cal_user(&mut meta, l, PersonRole::Other, "ics:attendee");
            }
            (_, "SUMMARY") if in_item => {
                if store_ev {
                    meta.fields.insert(ev_key("summary"), truncate(&v, 512));
                }
            }
            (_, "LOCATION") if in_item => {
                find_urls(&v, &mut meta.links);
                if store_ev {
                    meta.fields.insert(ev_key("location"), truncate(&v, 512));
                }
            }
            (_, "DESCRIPTION" | "X-ALT-DESC" | "URL" | "CONFERENCE")
            | (_, "X-MICROSOFT-SKYPETEAMSMEETINGURL" | "X-GOOGLE-CONFERENCE")
                if in_item =>
            {
                if l.name.starts_with('X') || l.name == "URL" || l.name == "CONFERENCE" {
                    if v.starts_with("http") {
                        Metadata::add_unique(&mut meta.links, &truncate(v.trim(), 2048));
                    }
                } else {
                    find_urls(&v, &mut meta.links);
                }
                if store_ev && l.name == "DESCRIPTION" {
                    meta.fields
                        .insert(ev_key("description"), truncate(&v, 1024));
                }
            }
            (_, "DTSTART") if store_ev => {
                if let Some(d) = ical_date(&v) {
                    meta.fields.insert(ev_key("start"), d);
                }
            }
            (_, "CREATED") | (_, "DTSTAMP") if in_item => {
                if let Some(d) = ical_date(&v) {
                    created.push(d);
                }
            }
            (_, "LAST-MODIFIED") if in_item => {
                if let Some(d) = ical_date(&v) {
                    modified.push(d);
                }
            }
            (_, "UID") if in_item => {
                if let Some((_, d)) = v.trim().rsplit_once('@') {
                    let d = d.trim().to_ascii_lowercase();
                    if d.contains('.') && d.len() < 254 && !uid_domains.contains(&d) {
                        uid_domains.push(d);
                    }
                }
            }
            _ => {}
        }
    }
    for u in &meta.links {
        if is_meeting_link(u) && !meeting.contains(u) {
            meeting.push(u.clone());
        }
    }
    created.sort();
    modified.sort();
    meta.created = created.first().cloned();
    meta.modified = modified.last().cloned();
    meta.stats.insert("events".into(), events);
    if todos > 0 {
        meta.stats.insert("todos".into(), todos);
    }
    if attendees > 0 {
        meta.stats.insert("attendees".into(), attendees);
    }
    if let Some(o) = organizers.first() {
        meta.author = Some(o.clone());
    }
    if !uid_domains.is_empty() {
        meta.fields.insert(
            "ics:uid_domains".into(),
            truncate(&uid_domains.join(", "), 1024),
        );
    }
    if !meeting.is_empty() {
        meta.fields.insert(
            "ics:meeting_links".into(),
            truncate(&meeting.join(" "), 4096),
        );
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_and_dates() {
        let l = parse_lines(b"ATTENDEE;CN=\"Doe, John\";ROLE=REQ-PARTICIPANT:mailto:j\r\n ohn@example.com\r\nX:a\\, b\\nc\r\n");
        assert_eq!(l[0].param("CN"), Some("Doe, John"));
        assert_eq!(l[0].value, "mailto:john@example.com");
        assert_eq!(l[1].text(), "a, b\nc");
        assert_eq!(
            ical_date("20240314T184200Z").as_deref(),
            Some("2024-03-14T18:42:00Z")
        );
        assert_eq!(ical_date("20240314").as_deref(), Some("2024-03-14"));
        assert!(is_meeting_link(
            "https://teams.microsoft.com/l/meetup-join/x"
        ));
        assert!(is_meeting_link("https://contoso.zoom.us/j/123"));
        assert!(!is_meeting_link("https://zoom.us.evil.test/j/1"));
    }
}

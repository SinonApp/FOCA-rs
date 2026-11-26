//! Secret masking (`{{s:…}}` and `secrets[]` values) and PII redaction.

use foca_core::api::Snapshot;

use crate::i18n;
use crate::opts::{Lang, SecretMode};

const S0: &str = "{{s:";
const S1: &str = "}}";

/// Returns the secret values from evidence (`{{s:…}}`).
pub fn secrets_in(evidence: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = evidence;
    while let Some(i) = rest.find(S0) {
        let after = &rest[i + S0.len()..];
        match foca_core::api::find_secret_marker_end(after) {
            Some(j) => {
                out.push(foca_core::api::unescape_secret_marker(&after[..j]));
                rest = &after[j + S1.len()..];
            }
            None => break,
        }
    }
    out
}

/// Secret masker for one report or export. Every user string goes through
/// [`Redactor::text`]: `{{s:…}}` markers are replaced according to the mode, and in `hide`
/// and `partial` modes so is any occurrence of a known secret value (passwords, tokens,
/// connection strings).
#[derive(Debug, Clone)]
pub struct Redactor {
    mode: SecretMode,
    hidden: &'static str,
    /// Values for the global sweep (longest first).
    values: Vec<String>,
}

impl Redactor {
    pub fn new(snap: &Snapshot, mode: SecretMode, lang: Lang) -> Self {
        let mut values: Vec<String> = snap
            .secrets
            .iter()
            // Host addresses (`type: host`) stay in the infrastructure tables.
            .filter(|s| s.kind != "host")
            .map(|s| s.value.expose().to_string())
            .chain(
                snap.findings
                    .iter()
                    .filter(|f| f.category != "dns" && f.category != "web")
                    .flat_map(|f| secrets_in(&f.evidence))
                    .filter(|v| !looks_like_host(v)),
            )
            .filter(|v| v.chars().count() >= 4)
            .collect();
        values.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        values.dedup();
        Redactor {
            mode,
            hidden: i18n::strings(lang).hidden,
            values,
        }
    }

    pub fn mode(&self) -> SecretMode {
        self.mode
    }

    /// Renders a secret value in the display mode (like `maskAs` in `ui/screens/reports.js`).
    pub fn mask(&self, v: &str) -> String {
        match self.mode {
            SecretMode::Full => v.to_string(),
            SecretMode::Hide => self.hidden.to_string(),
            SecretMode::Partial => {
                let c: Vec<char> = v.chars().collect();
                if c.len() > 6 {
                    let head: String = c[..2].iter().collect();
                    let tail: String = c[c.len() - 3..].iter().collect();
                    format!("{head}••••••{tail}")
                } else {
                    "••••••".into()
                }
            }
        }
    }

    /// Returns the text with markers and known secret values rendered according to the mode.
    pub fn text(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find(S0) {
            out.push_str(&rest[..i]);
            let after = &rest[i + S0.len()..];
            match foca_core::api::find_secret_marker_end(after) {
                Some(j) => {
                    let raw = foca_core::api::unescape_secret_marker(&after[..j]);
                    out.push_str(&self.mask(&raw));
                    rest = &after[j + S1.len()..];
                }
                None => {
                    // An unterminated marker: treat everything after it as secret.
                    out.push_str(&self.mask(&foca_core::api::unescape_secret_marker(after)));
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        if self.mode == SecretMode::Full {
            return out;
        }
        for v in &self.values {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), &self.mask(v));
            }
        }
        out
    }
}

fn looks_like_host(v: &str) -> bool {
    let v = v.trim();
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        && (v.chars().filter(|c| *c == '.').count() >= 2 || v.parse::<std::net::IpAddr>().is_ok())
}

/// PII redaction (the "redact PII" export option): `Olena Kovalenko → O. K*******`,
/// `o.kovalenko@x.ua → o.k***@x.ua`, logins → `o.k***`.
#[derive(Debug, Clone, Default)]
pub struct Pii {
    /// (original, replacement) pairs, longest first.
    map: Vec<(String, String)>,
}

/// Redacts a full name to initials with asterisks.
pub fn redact_name(name: &str) -> String {
    let parts: Vec<&str> = name.split_whitespace().collect();
    match parts.as_slice() {
        [] => String::new(),
        [one] => {
            let mut c = one.chars();
            let first = c.next().map(String::from).unwrap_or_default();
            format!("{first}{}", "*".repeat(c.count()))
        }
        [first, .., last] => {
            let f = first.chars().next().map(String::from).unwrap_or_default();
            let mut lc = last.chars();
            let l = lc.next().map(String::from).unwrap_or_default();
            format!("{f}. {l}{}", "*".repeat(lc.count()))
        }
    }
}

/// Redacts a login to its first 3 characters + `***` (the first character for short ones).
pub fn redact_login(login: &str) -> String {
    let c: Vec<char> = login.chars().collect();
    let keep = if c.len() > 4 { 3 } else { 1 };
    let head: String = c.iter().take(keep).collect();
    format!("{head}***")
}

/// Redacts an e-mail address: the local part is masked, the domain is kept.
pub fn redact_email(addr: &str) -> String {
    match addr.rsplit_once('@') {
        Some((local, domain)) => format!("{}@{domain}", redact_login(local)),
        None => redact_login(addr),
    }
}

impl Pii {
    pub fn new(snap: &Snapshot) -> Pii {
        let mut map: Vec<(String, String)> = Vec::new();
        let mut add = |from: &str, to: String| {
            let from = from.trim();
            if from.chars().count() >= 3 && !map.iter().any(|(f, _)| f == from) {
                map.push((from.to_string(), to));
            }
        };
        for p in &snap.people {
            for e in &p.emails {
                add(e, redact_email(e));
            }
            add(&p.name, redact_name(&p.name));
            for a in &p.aliases {
                if a.contains(char::is_whitespace) {
                    add(a, redact_name(a));
                } else {
                    add(a, redact_login(a));
                }
            }
            add(&p.login, redact_login(&p.login));
        }
        for e in &snap.emails {
            add(&e.addr, redact_email(&e.addr));
            if let Some(n) = &e.name {
                add(n, redact_name(n));
            }
            if let Some(l) = &e.login {
                add(l, redact_login(l));
            }
        }
        if !snap.scope.phone.is_empty() {
            add(&snap.scope.phone, "+** *** *** ** **".into());
        }
        if !snap.scope.contact.is_empty() {
            add(&snap.scope.contact, redact_name(&snap.scope.contact));
        }
        map.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        Pii { map }
    }

    /// Redacts all known names, logins and addresses in the text at word boundaries.
    pub fn text(&self, s: &str) -> String {
        let mut out = s.to_string();
        for (from, to) in &self.map {
            out = replace_word(&out, from, to);
        }
        out
    }
}

/// Replaces occurrences of `from` not surrounded by letters or digits (so `admin` does not
/// touch `administrator`).
fn replace_word(s: &str, from: &str, to: &str) -> String {
    if from.is_empty() || !s.contains(from) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(pos) = s[i..].find(from) {
        let start = i + pos;
        let end = start + from.len();
        let before_ok = s[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = s[end..].chars().next().is_none_or(|c| !c.is_alphanumeric());
        out.push_str(&s[i..start]);
        if before_ok && after_ok {
            out.push_str(to);
        } else {
            out.push_str(from);
        }
        i = end;
    }
    out.push_str(&s[i..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::{Person, Secret, SecretValue};

    fn snap() -> Snapshot {
        Snapshot {
            secrets: vec![
                Secret {
                    kind: "pass".into(),
                    value: SecretValue::new("Buh2023!"),
                    ..Default::default()
                },
                Secret {
                    kind: "host".into(),
                    value: SecretValue::new("10.10.1.5"),
                    ..Default::default()
                },
            ],
            people: vec![Person {
                login: "o.kovalenko".into(),
                name: "Олена Коваленко".into(),
                emails: vec!["o.kovalenko@contoso.example".into()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn secret_modes() {
        let s = snap();
        let h = Redactor::new(&s, SecretMode::Hide, Lang::Ru);
        assert_eq!(
            h.text("pwd: {{s:Buh2023!}}; again Buh2023!"),
            "pwd: [скрыто]; again [скрыто]"
        );
        assert_eq!(h.text("host 10.10.1.5"), "host 10.10.1.5");
        let p = Redactor::new(&s, SecretMode::Partial, Lang::En);
        assert_eq!(p.text("{{s:Buh2023!}}"), "Bu••••••23!");
        assert_eq!(p.text("{{s:abc}}"), "••••••");
        let f = Redactor::new(&s, SecretMode::Full, Lang::Uk);
        assert_eq!(f.text("x {{s:Buh2023!}}"), "x Buh2023!");
        assert_eq!(h.text("unterminated {{s:Buh2023"), "unterminated [скрыто]");
        assert_eq!(secrets_in("a {{s:1}} b {{s:22}}"), vec!["1", "22"]);

        let esc = foca_core::api::escape_secret_marker("p@ss}}word");
        let marked = format!("tok={{{{s:{esc}}}}} ok");
        assert_eq!(secrets_in(&marked), vec!["p@ss}}word"]);
        assert_eq!(h.text(&marked), "tok=[скрыто] ok");
        assert_eq!(f.text(&marked), "tok=p@ss}}word ok");
    }

    #[test]
    fn pii() {
        assert_eq!(redact_name("Олена Коваленко"), "О. К********");
        assert_eq!(
            redact_email("o.kovalenko@contoso.example"),
            "o.k***@contoso.example"
        );
        let p = Pii::new(&snap());
        let t = p.text(r"Автор: Олена Коваленко, C:\Users\o.kovalenko\Desktop, o.kovalenko@contoso.example, xo.kovalenkox");
        assert!(
            !t.contains("Коваленко")
                && !t.contains(r"\o.kovalenko\")
                && !t.contains("o.kovalenko@"),
            "{t}"
        );
        assert!(t.contains("xo.kovalenkox"));
    }
}

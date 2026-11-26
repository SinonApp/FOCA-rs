//! E-mail addresses: collection, role addresses and the corporate address pattern.
//!
//! The pattern (`{f}.{last}`, `{first}.{last}`, `{first}{l}`, …) is inferred from pairs of
//! a person with a known name and an address found for them; its confidence is the share of
//! confirming addresses. The best pattern (confidence ≥ 60 %) is used to generate addresses
//! for people without one: `found: false`, `src` names the pattern and its confidence.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{Email, Pattern};
use foca_core::Scope;

use crate::people::{ident_key, Cluster, NameCand, Resolved};
use crate::translit::skeleton;

/// Role local parts (`info@`, `hr@`, …).
const ROLE_LOCALS: &[&str] = &[
    "info",
    "admin",
    "administrator",
    "support",
    "help",
    "helpdesk",
    "hr",
    "jobs",
    "career",
    "careers",
    "tender",
    "tenders",
    "office",
    "sales",
    "contact",
    "contacts",
    "noreply",
    "no-reply",
    "donotreply",
    "webmaster",
    "postmaster",
    "hostmaster",
    "dmarc",
    "abuse",
    "security",
    "press",
    "media",
    "pr",
    "marketing",
    "buh",
    "accounting",
    "finance",
    "kadry",
    "reception",
    "secretary",
    "mail",
    "root",
    "billing",
    "service",
    "feedback",
    "hello",
    "team",
    "it",
    "legal",
    "privacy",
    "dpo",
    "zakupki",
    "zakupivli",
    "kancelaria",
    "kanc",
    "post",
    "news",
    "newsletter",
    "orders",
    "order",
    "shop",
    "manager",
    "director",
    "ceo",
    "pressa",
];

/// Public webmail providers, never treated as a corporate domain.
const WEBMAIL: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "ukr.net",
    "i.ua",
    "meta.ua",
    "mail.ru",
    "yandex.ru",
    "yandex.ua",
    "bigmir.net",
    "proton.me",
    "protonmail.com",
    "gmx.net",
    "gmx.de",
    "aol.com",
    "rambler.ru",
];

pub fn is_role(addr: &str) -> bool {
    let local = addr.split('@').next().unwrap_or("").to_lowercase();
    ROLE_LOCALS.contains(&local.as_str())
}

pub fn domain_of(addr: &str) -> &str {
    addr.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

/// Returns `true` if the address looks valid (a rough check: local part, dotted domain with
/// an alphabetic TLD).
pub fn valid_addr(addr: &str) -> bool {
    let Some((l, d)) = addr.rsplit_once('@') else {
        return false;
    };
    !l.is_empty()
        && l.len() <= 64
        && d.contains('.')
        && !d.starts_with('.')
        && !d.ends_with('.')
        && d.rsplit('.')
            .next()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
        && l.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Finds addresses in text by scanning around `@`, without regular expressions.
pub fn find_in_text(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let b = text.as_bytes();
    let is_l = |c: u8| c.is_ascii_alphanumeric() || b"._%+-".contains(&c);
    let is_d = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'-';
    for (i, &c) in b.iter().enumerate() {
        if c != b'@' {
            continue;
        }
        let mut s = i;
        while s > 0 && is_l(b[s - 1]) {
            s -= 1;
        }
        let mut e = i + 1;
        while e < b.len() && is_d(b[e]) {
            e += 1;
        }
        if s == i || e == i + 1 {
            continue;
        }
        let addr = text[s..e]
            .trim_matches(|c: char| c == '.' || c == '-')
            .to_lowercase();
        if valid_addr(&addr) && !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// An occurrence of an address: the address, the document and where it was seen
/// (document metadata or document text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub addr: String,
    pub doc: u64,
    pub src: String,
}

pub const PATTERNS: &[&str] = &[
    "{f}.{last}",
    "{first}.{last}",
    "{f}{last}",
    "{first}{last}",
    "{first}_{last}",
    "{f}_{last}",
    "{first}-{last}",
    "{last}.{first}",
    "{last}.{f}",
    "{last}{f}",
    "{last}{first}",
    "{last}_{first}",
    "{first}.{l}",
    "{first}{l}",
    "{last}",
    "{first}",
];

fn needs_first(p: &str) -> bool {
    p.contains("{first}")
}

/// Renders a name through an address pattern.
pub fn render(p: &str, first: Option<&str>, init: char, last: &str) -> Option<String> {
    if needs_first(p) && first.is_none() {
        return None;
    }
    let f = first.unwrap_or("");
    let l = last.chars().next()?;
    Some(
        p.replace("{first}", f)
            .replace("{last}", last)
            .replace("{f}", &init.to_string())
            .replace("{l}", &l.to_string()),
    )
}

fn local_matches(p: &str, c: &NameCand, local: &str) -> bool {
    let sl = skeleton(local);
    let seps_ok = |r: &str| {
        // Separators must match literally.
        r.chars()
            .filter(|c| !c.is_alphanumeric())
            .collect::<String>()
            == local
                .chars()
                .filter(|c| !c.is_alphanumeric())
                .collect::<String>()
    };
    for &i in &c.inits {
        if let Some(r) = render(p, c.first.as_deref(), i, &c.last) {
            if seps_ok(&r) && (r == local || skeleton(&r) == sl) {
                return true;
            }
        }
    }
    false
}

/// Returns the corporate domains: scope target domains present among the found addresses,
/// otherwise the most frequent non-webmail domain.
fn corporate_domains(addrs: &BTreeSet<String>, scope: &Scope) -> Vec<String> {
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    for a in addrs {
        let d = domain_of(a);
        if !d.is_empty() && !WEBMAIL.contains(&d) {
            *count.entry(d.to_string()).or_default() += 1;
        }
    }
    let in_scope: Vec<String> = count
        .keys()
        .filter(|d| {
            scope.targets.iter().any(|t| t.covers_host(d))
                || scope.excludes.iter().any(|t| t.covers_host(d))
        })
        .cloned()
        .collect();
    if !in_scope.is_empty() {
        return in_scope;
    }
    let mut v: Vec<(String, usize)> = count.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().take(1).map(|(d, _)| d).collect()
}

/// E-mail analysis result.
#[derive(Debug, Clone, Default)]
pub struct EmailResult {
    pub emails: Vec<Email>,
    pub patterns: Vec<Pattern>,
    /// Person index → generated address.
    pub generated: BTreeMap<usize, String>,
}

/// Collects addresses and infers patterns. `keep` holds the indices of persons that made it
/// into the people list.
pub fn build(
    occ: &[Occurrence],
    people: &Resolved,
    keep: &BTreeSet<usize>,
    scope: &Scope,
) -> EmailResult {
    let mut src: BTreeMap<String, String> = BTreeMap::new();
    for o in occ {
        src.entry(o.addr.clone()).or_insert_with(|| o.src.clone());
    }
    let addrs: BTreeSet<String> = src.keys().cloned().collect();
    let corp = corporate_domains(&addrs, scope);
    let cluster_of = |a: &str| -> Option<(usize, &Cluster)> {
        let i = *people.by_key.get(&ident_key(a))?;
        keep.contains(&i).then(|| (i, &people.clusters[i]))
    };

    // Pattern inference: person/address pairs within corporate domains.
    let mut tested: BTreeMap<&str, u32> = BTreeMap::new();
    let mut hits: BTreeMap<&str, (u32, String, String)> = BTreeMap::new();
    for a in &addrs {
        if is_role(a) || !corp.iter().any(|d| d == domain_of(a)) {
            continue;
        }
        let Some((_, c)) = cluster_of(a) else {
            continue;
        };
        if c.service || c.cands.is_empty() {
            continue;
        }
        let local = a.split('@').next().unwrap_or("");
        let has_full = c.cands.iter().any(|x| x.first.is_some());
        for p in PATTERNS {
            if needs_first(p) && !has_full {
                continue;
            }
            *tested.entry(p).or_default() += 1;
            if c.cands.iter().any(|x| local_matches(p, x, local)) {
                let e = hits
                    .entry(p)
                    .or_insert((0, a.clone(), domain_of(a).to_string()));
                e.0 += 1;
            }
        }
    }
    let mut patterns: Vec<Pattern> = hits
        .iter()
        .map(|(p, (n, ex, dom))| {
            let t = tested.get(p).copied().unwrap_or(1).max(1);
            Pattern {
                p: p.to_string(),
                ex: ex.clone(),
                conf: ((*n as f64 / t as f64) * 100.0).round() as u8,
                n: *n,
                domain: dom.clone(),
            }
        })
        .collect();
    // Ties are broken by the order of PATTERNS (more specific patterns first).
    let order = |p: &str| PATTERNS.iter().position(|x| *x == p).unwrap_or(99);
    patterns.sort_by(|a, b| {
        b.conf
            .cmp(&a.conf)
            .then(b.n.cmp(&a.n))
            .then(order(&a.p).cmp(&order(&b.p)))
    });

    let mut emails: Vec<Email> = Vec::new();
    let mut role: Vec<Email> = Vec::new();
    for a in &addrs {
        let r = is_role(a);
        let pc = if r { None } else { cluster_of(a) };
        let e = Email {
            addr: a.clone(),
            login: pc.map(|(_, c)| c.login.clone()),
            name: pc.filter(|(_, c)| !c.service).map(|(_, c)| c.name.clone()),
            found: true,
            src: src.get(a).cloned().unwrap_or_default(),
            role: r,
        };
        if r {
            role.push(e);
        } else {
            emails.push(e);
        }
    }

    // Generate addresses with the best pattern.
    let mut generated = BTreeMap::new();
    if let (Some(best), Some(dom)) = (patterns.first(), corp.first()) {
        if best.conf >= 60 {
            for &i in keep {
                let c = &people.clusters[i];
                // Only real people: no role accounts or departments, a full name that is not all caps, and
                // no address yet. An address on another domain means the person belongs to another
                // organization.
                if c.service
                    || !c.emails.is_empty()
                    || c.email_only
                    || c.best_shape != Some(crate::people::Shape::Full)
                    || crate::people::is_org_name(&c.name)
                    || !c.name.chars().any(char::is_lowercase)
                {
                    continue;
                }
                let Some(nc) = &c.best else { continue };
                let init = match nc.first.as_deref().and_then(|f| f.chars().next()) {
                    Some(ch) => ch,
                    None => match nc.inits.first() {
                        Some(&ch) => ch,
                        None => continue,
                    },
                };
                let Some(local) = render(&best.p, nc.first.as_deref(), init, &nc.last) else {
                    continue;
                };
                let addr = format!("{local}@{dom}");
                if !valid_addr(&addr) || src.contains_key(&addr) {
                    continue;
                }
                generated.insert(i, addr.clone());
                emails.push(Email {
                    addr,
                    login: Some(c.login.clone()),
                    name: Some(c.name.clone()),
                    found: false,
                    src: format!("Шаблон {} ({}%)", best.p, best.conf),
                    role: false,
                });
            }
        }
    }
    emails.sort_by(|a, b| b.found.cmp(&a.found).then(a.addr.cmp(&b.addr)));
    emails.extend(role);
    EmailResult {
        emails,
        patterns,
        generated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::people::{resolve, IdentSource, Identity};

    fn setup(names: &[&str], addrs: &[&str]) -> (Resolved, Vec<Occurrence>) {
        let mut ids: Vec<Identity> = names
            .iter()
            .enumerate()
            .map(|(i, n)| Identity::new(n, i as u64, IdentSource::Meta, "author"))
            .collect();
        let occ: Vec<Occurrence> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| Occurrence {
                addr: a.to_string(),
                doc: 100 + i as u64,
                src: "Текст документа".into(),
            })
            .collect();
        for o in &occ {
            if !is_role(&o.addr) {
                ids.push(Identity::new(&o.addr, o.doc, IdentSource::Text, "email"));
            }
        }
        (resolve(&ids), occ)
    }

    #[test]
    fn pattern_detected_and_generated() {
        let (r, occ) = setup(
            &[
                "Олена Коваленко",
                "Сергій Лисенко",
                "Ігор Петренко",
                "Андрій Бондар",
            ],
            &[
                "o.kovalenko@contoso.example",
                "s.lysenko@contoso.example",
                "info@contoso.example",
            ],
        );
        let keep: BTreeSet<usize> = (0..r.clusters.len()).collect();
        let (scope, _) = Scope::from_lines("contoso.example", "");
        let res = build(&occ, &r, &keep, &scope);
        let p = &res.patterns[0];
        assert_eq!((p.p.as_str(), p.conf, p.n), ("{f}.{last}", 100, 2));
        assert_eq!(p.domain, "contoso.example");
        let gen: Vec<&str> = res
            .emails
            .iter()
            .filter(|e| !e.found)
            .map(|e| e.addr.as_str())
            .collect();
        assert_eq!(
            gen,
            vec!["a.bondar@contoso.example", "i.petrenko@contoso.example"]
        );
        let info = res.emails.last().unwrap();
        assert!(info.role && info.addr.starts_with("info@"));
        let ok = res
            .emails
            .iter()
            .find(|e| e.addr == "o.kovalenko@contoso.example")
            .unwrap();
        assert_eq!(ok.name.as_deref(), Some("Олена Коваленко"));
    }

    #[test]
    fn first_last_pattern() {
        let (r, occ) = setup(
            &["Ivan Petrov", "Olga Sidorova", "Petr Ivanov"],
            &["ivan.petrov@corp.com", "olga.sidorova@corp.com"],
        );
        let keep: BTreeSet<usize> = (0..r.clusters.len()).collect();
        let res = build(&occ, &r, &keep, &Scope::default());
        assert_eq!(res.patterns[0].p, "{first}.{last}");
        assert!(res
            .emails
            .iter()
            .any(|e| e.addr == "petr.ivanov@corp.com" && !e.found));
    }

    /// "Surname, Given name" order, `@DEPT` suffixes, people from other organizations and
    /// departments (strings taken from real documents, domains replaced).
    #[test]
    fn comma_names_and_foreign_people() {
        let (r, occ) = setup(
            &[
                "Ivan Petrov",
                "Olga Sidorova",
                "Moore, Jason",
                "Alfred, Rashawna",
                "Furumo, Paul@ARB",
                "Diane Welch",
                "COMMUNITY PRESERVATION COMMITTEE",
                "Workforce Services",
                "FNSB Employee",
                "WSDOT CEVP",
            ],
            &[
                "ivan.petrov@corp.example",
                "olga.sidorova@corp.example",
                "diane.welch@other.example",
            ],
        );
        let keep: BTreeSet<usize> = (0..r.clusters.len()).collect();
        let (scope, _) = Scope::from_lines("corp.example", "");
        let res = build(&occ, &r, &keep, &scope);
        let mut gen: Vec<&str> = res
            .emails
            .iter()
            .filter(|e| !e.found)
            .map(|e| e.addr.as_str())
            .collect();
        gen.sort();
        assert_eq!(
            gen,
            vec![
                "jason.moore@corp.example",
                "paul.furumo@corp.example",
                "rashawna.alfred@corp.example"
            ]
        );
        assert_eq!(r.login_of("Moore, Jason"), Some("j.moore"));
        assert_eq!(r.login_of("Furumo, Paul@ARB"), Some("p.furumo"));
        for org in [
            "COMMUNITY PRESERVATION COMMITTEE",
            "Workforce Services",
            "FNSB Employee",
        ] {
            let i = r.by_key[&crate::people::ident_key(org)];
            assert!(r.clusters[i].service, "{org} is not a person");
        }
    }

    #[test]
    fn text_extraction() {
        let v = find_in_text("Пишіть: O.Kovalenko@Contoso.example, або info@x.ua. Не a@b");
        assert_eq!(v, vec!["o.kovalenko@contoso.example", "info@x.ua"]);
        assert!(is_role("HR@corp.ua"));
        assert!(!valid_addr("x@localhost"));
    }
}

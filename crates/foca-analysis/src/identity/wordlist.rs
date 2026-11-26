//! Login template generation (`CORP\i.petrov`, `ipetrov`, `petrov_i`, …) and
//! contextual pentest wordlists derived only from non-secret project artifacts.
//!
//! Security invariant: values from [`Snapshot::secrets`] and raw national IDs/payment
//! card numbers are never emitted into generated wordlists.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::Snapshot;
use serde::{Deserialize, Serialize};

use crate::emails::{is_role, render};
use crate::people::is_org_name;
use crate::translit::{is_cyrillic, variants};

/// Standard corporate login patterns generated per employee.
pub const LOGIN_PATTERNS: &[(&str, &str)] = &[
    ("{f}.{last}", "i.petrov"),
    ("{first}.{last}", "ivan.petrov"),
    ("{f}{last}", "ipetrov"),
    ("{first}{last}", "ivanpetrov"),
    ("{first}_{last}", "ivan_petrov"),
    ("{f}_{last}", "i_petrov"),
    ("{last}.{f}", "petrov.i"),
    ("{last}_{f}", "petrov_i"),
    ("{last}{f}", "petrovi"),
    ("{last}", "petrov"),
    ("{first}", "ivan"),
];

const DEFAULT_MAX_ENTRIES: usize = 5000;

/// Options controlling login and contextual wordlist synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WordlistOptions {
    /// Optional explicit Active Directory NetBIOS domain (`CORP`); if `None`, inferred from artifacts.
    pub ad_domain: Option<String>,
    /// Include service accounts (`admin`, `scan`, `support`, …) in login generation.
    pub include_service: bool,
    /// Normalize output tokens to lowercase.
    pub lowercase: bool,
    /// Append recent/observed years and seasonal-year variants to contextual tokens.
    pub include_years: bool,
    /// Hard cap on unique output entries.
    pub max_entries: usize,
}

impl Default for WordlistOptions {
    fn default() -> Self {
        Self {
            ad_domain: None,
            include_service: false,
            lowercase: true,
            include_years: true,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// Summary of one login template observed/synthesized for the project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginPattern {
    pub id: String,
    pub label: String,
    pub count: usize,
    pub examples: Vec<String>,
}

/// Combined login & contextual pentest wordlist result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordlistResult {
    pub ad_domain: Option<String>,
    pub patterns: Vec<LoginPattern>,
    pub logins: Vec<String>,
    pub context: Vec<String>,
}

fn clean_line(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

fn format_case(s: &str, lowercase: bool) -> String {
    if lowercase {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

/// Validates and extracts a NetBIOS AD domain prefix from strings like `CORP\i.petrov`.
fn extract_netbios_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (dom, user) = trimmed.split_once('\\')?;
    let user = user.trim();
    if dom.is_empty()
        || user.is_empty()
        || dom.contains([' ', '/', ':', '.'])
        || user.contains([' ', '\\', '/'])
    {
        return None;
    }
    if !(2..=15).contains(&dom.len())
        || !dom
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    let up = dom.to_ascii_uppercase();
    const IGNORED_DOMAINS: &[&str] = &[
        "NT",
        "BUILTIN",
        "WORKGROUP",
        "LOCAL",
        "USERS",
        "DESKTOP",
        "WINDOWS",
        "C",
        "D",
        "E",
    ];
    if IGNORED_DOMAINS.contains(&up.as_str()) {
        return None;
    }
    Some(up)
}

/// Infers the most frequent Active Directory NetBIOS domain across people, RDP metadata, and paths.
pub fn infer_ad_domain(snap: &Snapshot) -> Option<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut bump = |candidate: &str| {
        if let Some(d) = extract_netbios_domain(candidate) {
            *counts.entry(d).or_default() += 1;
        }
    };
    for p in &snap.people {
        bump(&p.login);
        for a in &p.aliases {
            bump(a);
        }
    }
    for path in &snap.paths {
        if let Some(u) = &path.user {
            bump(u);
        }
    }
    for d in &snap.docs {
        if let Some(rdp) = &d.rdp {
            bump(&rdp.username);
        }
    }
    counts
        .into_iter()
        .max_by(|(da, ca), (db, cb)| ca.cmp(cb).then_with(|| db.cmp(da)))
        .map(|(d, _)| d)
}

fn resolved_ad_domain(snap: &Snapshot, opts: &WordlistOptions) -> Option<String> {
    if let Some(explicit) = opts
        .ad_domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let clean: String = explicit
            .trim_end_matches('\\')
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if !clean.is_empty() {
            return Some(clean.to_ascii_uppercase());
        }
    }
    infer_ad_domain(snap)
}

fn is_patronymic(w: &str) -> bool {
    let lw = w.to_lowercase();
    [
        "ович",
        "евич",
        "йович",
        "євич",
        "івна",
        "ївна",
        "овна",
        "евна",
        "инична",
        "ічна",
        "ovych",
        "evych",
        "ivna",
        "ovna",
        "evna",
    ]
    .iter()
    .any(|suf| lw.ends_with(suf))
}

fn looks_like_surname(w: &str) -> bool {
    let lw = w.to_lowercase();
    [
        "енко",
        "чук",
        "юк",
        "ський",
        "цький",
        "зький",
        "ська",
        "цька",
        "ов",
        "ев",
        "єв",
        "ін",
        "ин",
        "ова",
        "ева",
        "єва",
        "іна",
        "ина",
        "enko",
        "chuk",
        "yuk",
        "skyi",
        "ska",
        "ov",
        "ev",
        "in",
        "ova",
        "eva",
        "ina",
    ]
    .iter()
    .any(|suf| lw.ends_with(suf) && lw.chars().count() > suf.chars().count() + 1)
}

fn clean_name_token(raw: &str) -> String {
    raw.trim_matches(|c: char| !c.is_alphanumeric() && c != '\'' && c != '’' && c != '-')
        .to_string()
}

/// Extracts `(first, last)` transliterated Latin pairs from a display name or login.
fn parse_name_pairs(raw: &str) -> Vec<(String, String)> {
    let stripped = match raw.rfind('\\') {
        Some(i) if !raw.contains(' ') => &raw[i + 1..],
        _ => raw,
    }
    .trim();
    if stripped.is_empty() || stripped.contains('@') || is_org_name(stripped) {
        return Vec::new();
    }

    let has_comma = stripped.contains(',');
    let tokens: Vec<String> = stripped
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(clean_name_token)
        .filter(|w| !w.is_empty())
        .filter(|w| {
            !matches!(
                w.to_lowercase().as_str(),
                "dr" | "mr" | "mrs" | "ms" | "prof" | "jr" | "sr"
            )
        })
        .collect();

    let pair: Option<(String, String)> = match tokens.as_slice() {
        [single] => {
            let sub: Vec<&str> = single.split(['.', '_']).filter(|s| !s.is_empty()).collect();
            match sub.as_slice() {
                [a, b] => Some((a.to_string(), b.to_string())),
                _ => None,
            }
        }
        [a, b] => {
            let swap = has_comma
                || (b.chars().count() == 1 && a.chars().count() > 1)
                || (!(a.chars().count() == 1 && b.chars().count() > 1)
                    && looks_like_surname(a)
                    && !looks_like_surname(b));
            if swap {
                Some((b.clone(), a.clone()))
            } else {
                Some((a.clone(), b.clone()))
            }
        }
        [a, b, c, ..] => {
            if is_patronymic(c) {
                Some((b.clone(), a.clone()))
            } else {
                Some((a.clone(), c.clone()))
            }
        }
        _ => None,
    };

    let Some((first_raw, last_raw)) = pair else {
        return Vec::new();
    };
    let sanitize_lat = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect::<String>()
            .to_lowercase()
    };
    let mut out = Vec::new();
    for f in variants(&first_raw) {
        let fl = sanitize_lat(&f);
        if fl.is_empty() {
            continue;
        }
        for l in variants(&last_raw) {
            let ll = sanitize_lat(&l);
            if !ll.is_empty() && !out.contains(&(fl.clone(), ll.clone())) {
                out.push((fl.clone(), ll));
            }
        }
    }
    out
}

fn secret_blocklist(snap: &Snapshot) -> Vec<String> {
    snap.secrets
        .iter()
        .map(|s| s.value.expose().trim().to_string())
        .filter(|s| s.chars().count() >= 4)
        .collect()
}

fn is_unsafe_token(tok: &str, secrets: &[String]) -> bool {
    if tok.is_empty() {
        return true;
    }
    let tl = tok.to_lowercase();
    if secrets.iter().any(|s| {
        let sl = s.to_lowercase();
        tl == sl || tl.contains(&sl) || sl.contains(&tl) && tl.len() >= 8
    }) {
        return true;
    }
    // Never emit long digit-only strings (РНОКПП / payment cards / accounts).
    let digits = tok.chars().filter(|c| c.is_ascii_digit()).count();
    digits >= 9 && digits == tok.len()
}

/// Generates login candidates across standard corporate templates and optional AD domain prefixes.
pub fn generate_logins(
    snap: &Snapshot,
    opts: &WordlistOptions,
) -> (Option<String>, Vec<LoginPattern>, Vec<String>) {
    let secrets = secret_blocklist(snap);
    let ad_domain = resolved_ad_domain(snap, opts);
    let cap = opts.max_entries.max(1);
    let mut logins: BTreeSet<String> = BTreeSet::new();
    let mut by_pattern: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    let mut ad_examples: BTreeSet<String> = BTreeSet::new();

    let mut push_login = |raw: &str, pat: Option<&'static str>| {
        let cleaned = clean_line(raw);
        if cleaned.is_empty() || is_unsafe_token(&cleaned, &secrets) {
            return;
        }
        let val = format_case(&cleaned, opts.lowercase);
        if logins.len() < cap {
            logins.insert(val.clone());
        }
        if let Some(p) = pat {
            by_pattern.entry(p).or_default().insert(val.clone());
        }
        if let Some(dom) = &ad_domain {
            if !val.contains('\\') && !val.contains('@') {
                let dom_part = if opts.lowercase {
                    dom.to_lowercase()
                } else {
                    dom.clone()
                };
                let prefixed = format!("{dom_part}\\{val}");
                ad_examples.insert(prefixed.clone());
                if logins.len() < cap {
                    logins.insert(prefixed);
                }
            }
        }
    };

    for person in &snap.people {
        if person.service && !opts.include_service {
            continue;
        }
        // Keep observed non-empty logins (stripping AD domain prefix into canonical form too).
        for cand in
            std::iter::once(person.login.as_str()).chain(person.aliases.iter().map(String::as_str))
        {
            let trimmed = cand.trim();
            if trimmed.is_empty() || is_org_name(trimmed) {
                continue;
            }
            let base = trimmed.rsplit_once('\\').map(|(_, u)| u).unwrap_or(trimmed);
            if !base.contains(' ') && base.is_ascii() {
                push_login(base, None);
            }
            if trimmed.contains('\\') && !trimmed.contains(' ') && trimmed.is_ascii() {
                push_login(trimmed, None);
            }
        }
        for addr in &person.emails {
            if !is_role(addr) {
                if let Some(local) = addr.split('@').next() {
                    if !local.is_empty() {
                        push_login(local, None);
                    }
                }
            }
        }

        let mut pairs = parse_name_pairs(&person.name);
        for al in &person.aliases {
            for p in parse_name_pairs(al) {
                if !pairs.contains(&p) {
                    pairs.push(p);
                }
            }
        }
        if pairs.is_empty() {
            for p in parse_name_pairs(&person.login) {
                if !pairs.contains(&p) {
                    pairs.push(p);
                }
            }
        }

        for (first, last) in pairs {
            let Some(init) = first.chars().next() else {
                continue;
            };
            let first_opt = (first.chars().count() > 1).then_some(first.as_str());
            for &(pat, _) in LOGIN_PATTERNS {
                if let Some(rendered) = render(pat, first_opt, init, &last) {
                    if !rendered.is_empty() {
                        push_login(&rendered, Some(pat));
                    }
                }
            }
        }
    }

    for email in &snap.emails {
        if email.role || is_role(&email.addr) {
            continue;
        }
        if let Some(login) = &email.login {
            let base = login.rsplit_once('\\').map(|(_, u)| u).unwrap_or(login);
            if !base.is_empty() && !base.contains(' ') && base.is_ascii() {
                push_login(base, None);
            }
        }
        if let Some(local) = email.addr.split('@').next() {
            if !local.is_empty() && local.is_ascii() {
                push_login(local, None);
            }
        }
    }

    let mut patterns: Vec<LoginPattern> = LOGIN_PATTERNS
        .iter()
        .filter_map(|&(pat, label)| {
            let set = by_pattern.get(pat)?;
            if set.is_empty() {
                return None;
            }
            Some(LoginPattern {
                id: pat.to_string(),
                label: label.to_string(),
                count: set.len(),
                examples: set.iter().take(4).cloned().collect(),
            })
        })
        .collect();

    if let Some(dom) = &ad_domain {
        if !ad_examples.is_empty() {
            patterns.push(LoginPattern {
                id: "{DOMAIN}\\{login}".to_string(),
                label: format!("{dom}\\i.petrov"),
                count: ad_examples.len(),
                examples: ad_examples.iter().take(4).cloned().collect(),
            });
        }
    }

    (ad_domain, patterns, logins.into_iter().collect())
}

fn push_stem(stems: &mut BTreeSet<String>, raw: &str, secrets: &[String]) {
    let legal = [
        "ооо", "тов", "прат", "пат", "кп", "дп", "фоп", "llc", "inc", "ltd", "corp", "gmbh",
        "group",
    ];
    for piece in raw.split(|c: char| !c.is_alphanumeric() && c != '-') {
        let p = piece.trim_matches('-');
        let count = p.chars().count();
        if !(3..=32).contains(&count) {
            continue;
        }
        let low = p.to_lowercase();
        if legal.contains(&low.as_str()) {
            continue;
        }
        if p.chars().any(is_cyrillic) {
            for v in variants(&low) {
                let lat: String = v
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                if lat.len() >= 3 && !is_unsafe_token(&lat, secrets) {
                    stems.insert(lat);
                }
            }
            if !is_unsafe_token(&low, secrets) {
                stems.insert(low);
            }
        } else if low.is_ascii() && !is_unsafe_token(&low, secrets) {
            stems.insert(low);
        }
    }
}

fn extract_years(snap: &Snapshot) -> BTreeSet<String> {
    let mut years = BTreeSet::new();
    let mut scan_date = |s: &str| {
        for tok in s.split(|c: char| !c.is_ascii_digit()) {
            if tok.len() == 4 {
                if let Ok(y) = tok.parse::<u16>() {
                    if (2015..=2035).contains(&y) {
                        years.insert(tok.to_string());
                    }
                }
            }
        }
    };
    scan_date(&snap.project.created_at);
    for sc in &snap.scans {
        scan_date(&sc.started_at);
    }
    for d in &snap.docs {
        if d.deleted {
            continue;
        }
        if let Some(c) = &d.created_at {
            scan_date(c);
        }
        if let Some(m) = &d.modified_at {
            scan_date(m);
        }
    }
    for y in ["2024", "2025", "2026"] {
        years.insert(y.to_string());
    }
    years
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out: String = first.to_uppercase().collect();
    out.push_str(chars.as_str());
    out
}

/// Generates a contextual pentest wordlist tailored to company, domains, hosts, shares, and software.
pub fn generate_context(snap: &Snapshot, opts: &WordlistOptions) -> Vec<String> {
    let secrets = secret_blocklist(snap);
    let cap = opts.max_entries.max(1);
    let mut base_stems = BTreeSet::new();

    for raw in [
        &snap.project.name,
        &snap.project.domain,
        &snap.project.client,
        &snap.scope.client,
    ] {
        push_stem(&mut base_stems, raw, &secrets);
    }
    for d in &snap.docs {
        if d.deleted {
            continue;
        }
        if let Some(comp) = &d.company {
            push_stem(&mut base_stems, comp, &secrets);
        }
        if let Some(folder) = &d.folder {
            push_stem(&mut base_stems, folder, &secrets);
        }
    }
    for p in &snap.people {
        if let Some(dept) = &p.dept {
            push_stem(&mut base_stems, dept, &secrets);
        }
    }
    for h in &snap.hosts {
        let left = h.name.split('.').next().unwrap_or(&h.name);
        push_stem(&mut base_stems, left, &secrets);
    }
    for pc in &snap.pcs {
        let left = pc.name.split('.').next().unwrap_or(&pc.name);
        push_stem(&mut base_stems, left, &secrets);
    }
    for path in &snap.paths {
        for seg in path.path.split(['\\', '/']).take(4) {
            push_stem(&mut base_stems, seg, &secrets);
        }
    }
    for pr in &snap.printers {
        push_stem(&mut base_stems, &pr.name, &secrets);
    }
    for sw in &snap.software {
        push_stem(&mut base_stems, &sw.name, &secrets);
    }

    let years: Vec<String> = if opts.include_years {
        extract_years(snap).into_iter().take(6).collect()
    } else {
        Vec::new()
    };

    let mut out = BTreeSet::new();
    let mut emit = |cand: &str| {
        if out.len() >= cap {
            return;
        }
        let clean = clean_line(cand);
        if clean.chars().count() < 3 || clean.chars().count() > 64 {
            return;
        }
        if is_unsafe_token(&clean, &secrets) {
            return;
        }
        out.insert(format_case(&clean, opts.lowercase));
    };

    // High-signal stems first, capped so combinatorial explosions cannot occur.
    let priority_stems: Vec<String> = base_stems.iter().take(48).cloned().collect();
    for s in &priority_stems {
        emit(s);
        if !opts.lowercase && s.is_ascii() {
            emit(&title_case(s));
        }
        for suf in ["123", "123!", "!", "01", "@123", "_admin", "-vpn"] {
            emit(&format!("{s}{suf}"));
            if !opts.lowercase && s.is_ascii() {
                emit(&format!("{}{suf}", title_case(s)));
            }
        }
        for y in &years {
            emit(&format!("{s}{y}"));
            emit(&format!("{s}{y}!"));
            emit(&format!("{s}@{y}"));
            emit(&format!("{s}_{y}"));
            if !opts.lowercase && s.is_ascii() {
                let tc = title_case(s);
                emit(&format!("{tc}{y}"));
                emit(&format!("{tc}{y}!"));
                emit(&format!("{tc}@{y}"));
            }
        }
    }

    for s in base_stems {
        emit(&s);
    }

    if opts.include_years {
        for season in [
            "winter", "spring", "summer", "autumn", "zima", "vesna", "leto", "osen",
        ] {
            for y in years.iter().take(3) {
                emit(&format!("{season}{y}"));
                emit(&format!("{season}{y}!"));
                if !opts.lowercase {
                    emit(&format!("{}{y}", title_case(season)));
                    emit(&format!("{}{y}!", title_case(season)));
                }
            }
        }
    }

    out.into_iter().collect()
}

/// Builds both login templates and contextual pentest wordlists from one snapshot.
pub fn build(snap: &Snapshot, opts: &WordlistOptions) -> WordlistResult {
    let (ad_domain, patterns, logins) = generate_logins(snap, opts);
    let context = generate_context(snap, opts);
    WordlistResult {
        ad_domain,
        patterns,
        logins,
        context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::{Doc, DocRdp, Host, PathItem, Pc, Person, Secret, SecretValue, Software};
    use foca_core::Severity;

    fn sample_snapshot() -> Snapshot {
        let mut s = Snapshot::default();
        s.project.name = "contoso.example".into();
        s.project.domain = "contoso.example".into();
        s.project.client = "ТОВ «Контосо Енерджі»".into();
        s.scope.client = "Contoso Energy".into();
        s.people = vec![
            Person {
                login: "CORP\\i.petrov".into(),
                name: "Ігор Петров".into(),
                aliases: vec!["Petrov Ihor".into()],
                emails: vec!["i.petrov@contoso.example".into()],
                dept: Some("finance".into()),
                ..Default::default()
            },
            Person {
                login: "petrenko".into(),
                name: "Юлія Гриценко".into(),
                ..Default::default()
            },
            Person {
                login: "administrator".into(),
                name: "Administrator".into(),
                service: true,
                ..Default::default()
            },
        ];
        s.hosts.push(Host {
            name: "vpn.contoso.example".into(),
            ..Default::default()
        });
        s.pcs.push(Pc {
            name: "DC01".into(),
            ..Default::default()
        });
        s.paths.push(PathItem {
            path: "\\\\files01\\buhgalteria\\2025\\otchet.xlsx".into(),
            docs: 1,
            user: Some("CORP\\a.kovalenko".into()),
            host: Some("files01".into()),
        });
        s.docs.push(Doc {
            id: 1,
            created_at: Some("2025-02-14".into()),
            company: Some("Contoso Energy".into()),
            rdp: Some(DocRdp {
                username: "CORP\\rdpuser".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        s.software.push(Software {
            name: "LibreOffice".into(),
            ver: "7.6".into(),
            ..Default::default()
        });
        s.secrets.push(Secret {
            id: 1,
            kind: "pass".into(),
            value: SecretValue::new("MegaSecretPass#9988"),
            doc: 1,
            location: "body".into(),
            sev: Severity::Critical,
            host: None,
            finding: None,
            rule: "pass".into(),
        });
        s
    }

    #[test]
    fn generates_login_templates_translit_and_ad_prefix() {
        let snap = sample_snapshot();
        let res = build(&snap, &WordlistOptions::default());
        assert_eq!(res.ad_domain.as_deref(), Some("CORP"));
        for expected in [
            "i.petrov",
            "ihor.petrov",
            "ipetrov",
            "ihorpetrov",
            "petrov_i",
            "y.hrytsenko",
            "yuliia.hrytsenko",
            "yhrytsenko",
            "corp\\i.petrov",
            "corp\\ipetrov",
            "corp\\yhrytsenko",
        ] {
            assert!(
                res.logins.contains(&expected.to_string()),
                "missing {expected} in {:?}",
                res.logins
            );
        }
        // Service accounts are excluded by default.
        assert!(!res.logins.contains(&"administrator".to_string()));
        assert!(!res.patterns.is_empty());

        // Case-preserving option keeps `CORP\` uppercase prefix.
        let preserved = build(
            &snap,
            &WordlistOptions {
                lowercase: false,
                ..Default::default()
            },
        );
        assert!(preserved.logins.contains(&"CORP\\ipetrov".to_string()));
    }

    #[test]
    fn contextual_wordlist_includes_company_mutations_and_never_leaks_secrets() {
        let snap = sample_snapshot();
        let res = build(&snap, &WordlistOptions::default());
        for expected in [
            "contoso",
            "contoso2025",
            "contoso2025!",
            "energy2025",
            "buhgalteria",
            "finance",
            "dc01",
            "vpn2025",
        ] {
            assert!(
                res.context.contains(&expected.to_string()),
                "missing {expected} in {:?}",
                res.context
            );
        }
        let joined_logins = res.logins.join("\n").to_lowercase();
        let joined_context = res.context.join("\n").to_lowercase();
        assert!(!joined_logins.contains("megasecretpass"));
        assert!(!joined_context.contains("megasecretpass"));
    }
}

//! People: spelling normalization and identity merging.
//!
//! `ipetrov`, `i.petrov`, `Petrov I.`, the same name in Russian or Ukrainian Cyrillic and
//! `i.petrov@corp.ua` are one person. Algorithm:
//!
//! 1. Each spelling is parsed into a shape: full name (given name + surname), partial
//!    (initial + surname: `Petrov I.`, `i.petrov`) or login (`ipetrov`, `Hogwarts`).
//!    Cyrillic is transliterated per the Ukrainian 2010 passport standard or ICAO
//!    (see [`crate::translit`]); names are compared by "skeleton", which evens out
//!    transliteration systems, and by Jaro-Winkler to tolerate typos.
//! 2. Full names are merged with each other (same surname, same or similar given name;
//!    "Surname Given" order is accepted). `Petrov` and `Petrova` are different people.
//! 3. Partial names and logins join a person with a full name only if that candidate is
//!    unique (`i.petrov` stays separate when both Ivan and Igor Petrov exist).
//! 4. Remaining partial names and logins are merged with each other (`ipetrov` = `i.petrov`).
//! 5. Service accounts (`Administrator`, `User`, localized equivalents, `scan`, …) are never
//!    merged and are marked `service`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::translit::{self, initials, skeleton, Script};

/// Where a spelling came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentSource {
    /// A metadata field (author, editor, comment, path, account).
    Meta,
    /// Document text (an e-mail address in the text).
    Text,
}

/// One spelling of an identity with the documents where it occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub raw: String,
    pub docs: BTreeSet<u64>,
    pub source: IdentSource,
    /// Roles/fields (`author`, `last_modified_by`, `path_user`, `email`, …), used to pick the
    /// login.
    pub roles: BTreeSet<String>,
    /// Spellings known to be the same person from metadata rather than similarity, e.g. the
    /// reviewer's AD account address in `word/people.xml` → the reviewer's name.
    pub links: BTreeSet<String>,
}

impl Identity {
    pub fn new(raw: &str, doc: u64, source: IdentSource, role: &str) -> Self {
        Identity {
            raw: raw.trim().to_string(),
            docs: [doc].into_iter().collect(),
            source,
            roles: [role.to_string()].into_iter().collect(),
            links: BTreeSet::new(),
        }
    }

    /// Links this spelling to another one known to be the same person from metadata.
    pub fn with_link(mut self, raw: &str) -> Self {
        self.links.insert(raw.trim().to_string());
        self
    }
}

/// Reviewer roles: author of a comment or a revision (`w:ins`/`w:del`).
const REVIEW_ROLES: &[&str] = &["comment", "revision"];
/// Roles of a person's own document: author, editor, owner, account, user path.
const OWN_ROLES: &[&str] = &[
    "author",
    "last_modified_by",
    "creator",
    "owner",
    "account",
    "path_user",
    "printed_by",
];

/// Returns `true` for a reviewer: only comments or revisions, never an author or editor.
pub fn is_reviewer(roles: &BTreeSet<String>) -> bool {
    roles.iter().any(|r| REVIEW_ROLES.contains(&r.as_str()))
        && !roles.iter().any(|r| OWN_ROLES.contains(&r.as_str()))
}

/// Extracts the e-mail from a Word reviewer account (`w15:presenceInfo w15:userId`). AD and
/// Office 365 write `S::user@domain::<guid>` (sometimes just `user@domain`). Windows Live
/// (hexadecimal id) and `None` (a name) are not addresses and yield `None`.
pub fn presence_email(user_id: &str) -> Option<String> {
    user_id
        .trim()
        .split("::")
        .map(str::trim)
        .find(|p| {
            let Some((l, d)) = p.split_once('@') else {
                return false;
            };
            !l.is_empty()
                && d.contains('.')
                && !d.starts_with('.')
                && !d.ends_with('.')
                && !p.contains(char::is_whitespace)
        })
        .map(str::to_lowercase)
}

/// Returns the spelling key: lowercase, without the Windows domain
/// (`CONTOSO\i.petrenko` → `i.petrenko`) and extra whitespace.
pub fn ident_key(raw: &str) -> String {
    let s = raw.trim();
    let s = match s.rfind('\\') {
        Some(i) if !s.contains(' ') => &s[i + 1..],
        _ => s,
    };
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

const SERVICE: &[&str] = &[
    "administrator",
    "administrador",
    "administrateur",
    "admin",
    "адміністратор",
    "администратор",
    "user",
    "users",
    "user name",
    "username",
    "пользователь",
    "користувач",
    "юзер",
    "owner",
    "author",
    "автор",
    "guest",
    "гость",
    "гість",
    "root",
    "test",
    "тест",
    "default",
    "windows user",
    "microsoft office user",
    "office user",
    "пользователь windows",
    "користувач windows",
    "unknown",
    "неизвестный",
    "невідомий",
    "scan",
    "scanner",
    "сканер",
    "support",
    "helpdesk",
    "system",
    "sysadmin",
    "operator",
    "оператор",
    "home",
    "pc",
    "it",
    "office",
    "secretary",
    "секретарь",
    "секретар",
    "buh",
    "бухгалтер",
    "бухгалтерия",
    "бухгалтерія",
    "accounting",
    "reception",
    "manager",
    "менеджер",
    "anonymous",
    "anonym",
    "anon",
    "аноним",
    "анонім",
    "payroll",
    "planner",
    "staff",
    "personnel",
    "hr",
    "info",
    "noreply",
    "no-reply",
    // Generic words used instead of an author name (seen in real reports).
    "member",
    "members",
    "работа",
    "робота",
    "work",
    "работник",
    "сотрудник",
    "працівник",
    "співробітник",
    "дом",
    "дім",
    "компьютер",
    "комп'ютер",
];

/// Words that mark a name as an organization, department or group rather than a person
/// ("COMMUNITY PRESERVATION COMMITTEE", "Workforce Services", "FNSB Employee").
const ORG_WORDS: &[&str] = &[
    "committee",
    "commission",
    "council",
    "board",
    "department",
    "dept",
    "division",
    "services",
    "service",
    "employee",
    "employees",
    "staff",
    "team",
    "group",
    "agency",
    "authority",
    "administration",
    "office",
    "bureau",
    "center",
    "centre",
    "unit",
    "section",
    "program",
    "programs",
    "project",
    "security",
    "information",
    "ministry",
    "association",
    "foundation",
    "university",
    "college",
    "school",
    "inc",
    "llc",
    "ltd",
    "corp",
    "corporation",
    "company",
    "відділ",
    "відділення",
    "управління",
    "департамент",
    "служба",
    "комітет",
    "міністерство",
    "отдел",
    "управление",
    "комитет",
    "министерство",
    "тов",
    "ооо",
    "пао",
    "прат",
];

/// Returns `true` if the name is an organization or department (contains a word from
/// `ORG_WORDS`) or an all-caps abbreviation (`NIST`, `CBSC`, `WSDOT CEVP`) rather than a
/// personal name.
pub fn is_org_name(raw: &str) -> bool {
    let s = strip_prefixes(raw);
    if s.contains('@') && !s.contains(' ') {
        return false; // address or login
    }
    let words: Vec<&str> = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return false;
    }
    if words
        .iter()
        .any(|w| ORG_WORDS.contains(&w.to_lowercase().as_str()))
    {
        return true;
    }
    // All-caps abbreviations: a single 2-5 letter word (`NIST`, `CBSC`) or several words where
    // one has no vowels (`NSF CBSC`). Personal names in caps ("JOHN SMITH") are left alone.
    let caps = |w: &&str| w.chars().any(char::is_alphabetic) && !w.chars().any(char::is_lowercase);
    if !words.iter().all(caps) || s.contains(',') {
        return false;
    }
    let no_vowel = |w: &str| {
        !w.to_lowercase()
            .chars()
            .any(|c| "aeiouyаеєиіїоуюяыэё".contains(c))
    };
    match words.as_slice() {
        [w] => w.chars().all(char::is_alphabetic) && (2..=5).contains(&w.chars().count()),
        _ => words
            .iter()
            .any(|w| w.chars().all(char::is_alphabetic) && no_vowel(w)),
    }
}

/// Returns `true` for a service account rather than a person: `Administrator`, `User1`,
/// localized equivalents, `DESKTOP-4F2K1`, `scan`, …
pub fn is_service(raw: &str) -> bool {
    let k = ident_key(raw);
    if k.is_empty() {
        return true;
    }
    if SERVICE.contains(&k.as_str()) {
        return true;
    }
    let base = k.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_' || c == '-');
    if base.len() < k.len() && SERVICE.contains(&base) {
        return true;
    }
    for p in ["desktop-", "laptop-", "win-", "pc-"] {
        if let Some(rest) = k.strip_prefix(p) {
            if rest.len() >= 4 && rest.chars().all(|c| c.is_ascii_alphanumeric()) {
                return true;
            }
        }
    }
    !k.chars().any(char::is_alphabetic) || is_org_name(raw)
}

/// A "given name + surname" candidate in lowercase Latin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameCand {
    pub first: Option<String>,
    /// Possible initials of the given name.
    pub inits: Vec<char>,
    pub last: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shape {
    Full,
    Partial,
    Login,
}

/// A parsed spelling.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub shape: Shape,
    pub cands: Vec<NameCand>,
    /// Login skeleton without separators (so that `ipetrov` = `i.petrov`).
    pub compact: Option<String>,
    pub script: Script,
    pub is_email: bool,
    /// (surname, given name) skeletons of the candidates, parallel to `cands`.
    pub sk: Vec<(String, Option<String>)>,
    /// Skeletons of logins the person could have (compared with `ipetrov`-style logins).
    pub compacts: Vec<String>,
}

impl Parsed {
    fn finish(mut self) -> Parsed {
        self.sk = self
            .cands
            .iter()
            .map(|c| (skeleton(&c.last), c.first.as_deref().map(skeleton)))
            .collect();
        let mut v: Vec<String> = self.cands.iter().flat_map(compacts_of).collect();
        v.sort();
        v.dedup();
        self.compacts = v;
        self
    }
}

const SURNAME_SUFFIXES: &[&str] = &[
    "enko", "chuk", "chyk", "uk", "iuk", "yuk", "ak", "iak", "ko", "ov", "ova", "ev", "eva", "in",
    "ina", "skyi", "ska", "sky", "skiy", "ski", "skaya", "ych", "ich", "ets", "yn", "yna", "ii",
    "iy", "ar",
];

fn surname_score(latin: &str) -> u32 {
    SURNAME_SUFFIXES
        .iter()
        .filter(|s| latin.ends_with(*s) && latin.len() > s.len() + 1)
        .map(|s| s.len() as u32)
        .max()
        .unwrap_or(0)
}

fn is_patronymic(latin: &str) -> bool {
    latin.len() > 6
        && [
            "ovych", "ovich", "evych", "evich", "ivna", "ovna", "evna", "yivna", "ich", "ych",
        ]
        .iter()
        .any(|s| latin.ends_with(s))
}

fn is_initial_token(t: &str) -> Option<char> {
    let letters: Vec<char> = t.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() {
        return None;
    }
    let dotted = t.contains('.');
    if letters.len() == 1 || (dotted && t.split('.').all(|p| p.chars().count() <= 1)) {
        return letters.first().copied();
    }
    None
}

fn is_loginish(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && !s.contains(char::is_whitespace)
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn strip_prefixes(s: &str) -> String {
    let mut s = s.trim().to_string();
    let lower = s.to_lowercase();
    for p in [
        "author:",
        "автор:",
        "by:",
        "creator:",
        "created by:",
        "создал:",
        "створив:",
    ] {
        if lower.starts_with(p) {
            s = s[p.len()..].trim().to_string();
            break;
        }
    }
    // Parenthesized remarks, e.g. a department name after the person's name.
    let mut out = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth = (depth - 1i32).max(0),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    strip_dept_tail(out.trim())
}

/// Strips an `@DEPT` suffix: `Furumo, Paul@ARB` → `Furumo, Paul`. A suffix without a dot
/// (not a domain) on a name with a space or comma is an Exchange address book department
/// tag, not part of the name.
fn strip_dept_tail(s: &str) -> String {
    if !s.contains([' ', ',']) {
        return s.to_string();
    }
    s.split_whitespace()
        .map(|w| match w.split_once('@') {
            Some((a, d))
                if !a.is_empty()
                    && !d.is_empty()
                    && !d.contains('.')
                    && d.chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_') =>
            {
                a
            }
            _ => w,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn cand_variants(first: Option<&str>, last: &str) -> Vec<NameCand> {
    let inits = first.map(initials).unwrap_or_default();
    let whole = format!("{} {last}", first.unwrap_or(""));
    let systems: Vec<fn(&str) -> String> = match translit::detect(&whole) {
        Script::Latin => vec![|s: &str| s.to_lowercase()],
        Script::Ukrainian => vec![translit::uk],
        Script::Russian => vec![translit::ru],
        Script::Cyrillic => vec![translit::uk, translit::ru],
    };
    let mut out: Vec<NameCand> = Vec::new();
    for tr in systems {
        let f = first.map(tr);
        let mut inits = inits.clone();
        if let Some(c) = f.as_deref().and_then(|f| f.chars().next()) {
            if !inits.contains(&c) {
                inits.push(c);
            }
        }
        let nc = NameCand {
            first: f,
            inits,
            last: tr(last),
        };
        if !out.contains(&nc) {
            out.push(nc);
        }
    }
    out
}

fn parse_login(local: &str, is_email: bool) -> Parsed {
    let full = local.to_lowercase();
    let l = full.trim_end_matches(|c: char| c.is_ascii_digit());
    // Trailing digits distinguish accounts (user1 ≠ user2), so the skeleton keeps them.
    let digits = &full[l.len()..];
    let parts: Vec<&str> = l.split(['.', '_', '-']).filter(|p| !p.is_empty()).collect();
    let compact_raw: String = parts.concat();
    let compact = if compact_raw.chars().count() >= 3 {
        Some(format!("{}{digits}", skeleton(&compact_raw)))
    } else {
        None
    };
    // With digits it is only a login; do not split it into given name and surname.
    let parts: Vec<&str> = if digits.is_empty() { parts } else { vec![] };
    let mut cands = Vec::new();
    let mut shape = Shape::Login;
    if parts.len() == 2 {
        let (a, b) = (parts[0], parts[1]);
        let ca = a.chars().count();
        let cb = b.chars().count();
        if ca == 1 && cb >= 2 {
            shape = Shape::Partial;
            cands.push(NameCand {
                first: None,
                inits: a.chars().collect(),
                last: b.to_string(),
            });
        } else if cb == 1 && ca >= 2 {
            shape = Shape::Partial;
            cands.push(NameCand {
                first: None,
                inits: b.chars().collect(),
                last: a.to_string(),
            });
        } else if ca >= 2 && cb >= 2 {
            shape = Shape::Full;
            for (f, s) in [(a, b), (b, a)] {
                cands.push(NameCand {
                    first: Some(f.to_string()),
                    inits: f.chars().next().into_iter().collect(),
                    last: s.to_string(),
                });
            }
            if surname_score(a) > surname_score(b) {
                cands.swap(0, 1);
            }
        }
    }
    Parsed {
        shape,
        cands,
        compact,
        script: Script::Latin,
        is_email,
        sk: vec![],
        compacts: vec![],
    }
    .finish()
}

/// Parses a spelling of a name, login or e-mail address.
pub fn parse(raw: &str) -> Parsed {
    let raw = raw.trim();
    if let Some((local, _dom)) = raw.split_once('@') {
        if !local.is_empty() && !local.contains(' ') {
            return parse_login(local, true);
        }
    }
    let key = {
        let s = raw.trim();
        match s.rfind('\\') {
            Some(i) if !s.contains(' ') => s[i + 1..].to_string(),
            _ => s.to_string(),
        }
    };
    let s = strip_prefixes(&key);
    let script = translit::detect(&s);
    if is_loginish(&s) && !s.contains(' ') {
        let mut p = parse_login(&s, false);
        p.script = script;
        return p;
    }
    // "Surname, Given name"
    let (s, comma_last) = match s.split_once(',') {
        Some((a, b)) if !a.trim().is_empty() && !b.trim().is_empty() => {
            (format!("{} {}", b.trim(), a.trim()), true)
        }
        _ => (s.clone(), false),
    };
    let tokens: Vec<String> = s
        .split_whitespace()
        .map(|t| {
            t.trim_matches(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-' || c == '\''))
                .to_string()
        })
        .filter(|t| t.chars().any(char::is_alphabetic))
        .collect();
    let mut init: Option<char> = None;
    let mut words: Vec<String> = Vec::new();
    for t in &tokens {
        if let Some(c) = is_initial_token(t) {
            if init.is_none() {
                init = Some(c);
            }
        } else {
            words.push(t.trim_end_matches('.').to_string());
        }
    }
    if words.len() >= 3 {
        let w2: Vec<String> = words
            .iter()
            .filter(|w| !is_patronymic(&translit::primary(w)))
            .cloned()
            .collect();
        if w2.len() >= 2 {
            words = w2;
        }
    }
    let mut cands = Vec::new();
    let shape;
    match (words.len(), init) {
        (0, _) => {
            shape = Shape::Login;
        }
        (1, Some(c)) => {
            shape = Shape::Partial;
            for mut nc in cand_variants(None, &words[0]) {
                nc.inits = initials(&c.to_string());
                cands.push(nc);
            }
        }
        (1, None) => {
            shape = Shape::Login;
        }
        (n, _) => {
            shape = Shape::Full;
            let (a, b) = if n == 2 {
                (&words[0], &words[1])
            } else {
                (&words[0], &words[n - 1])
            };
            let mut order = vec![(a, b), (b, a)];
            let sa = surname_score(&translit::primary(a));
            let sb = surname_score(&translit::primary(b));
            if !comma_last && sa > sb {
                order.swap(0, 1);
            }
            for (f, l) in order {
                cands.extend(cand_variants(Some(f), l));
            }
        }
    }
    let compact_src: String = words.concat();
    let compact = if shape == Shape::Login && compact_src.chars().count() >= 3 {
        Some(skeleton(&translit::primary(&compact_src)))
    } else {
        None
    };
    Parsed {
        shape,
        cands,
        compact,
        script,
        is_email: false,
        sk: vec![],
        compacts: vec![],
    }
    .finish()
}

/// Returns `true` if two surname skeletons match.
fn last_match(sa: &str, sb: &str) -> bool {
    if sa.len() < 2 || sb.len() < 2 {
        return false;
    }
    if sa == sb {
        return true;
    }
    // Feminine and masculine forms are different people.
    if sa.strip_suffix('a') == Some(sb) || sb.strip_suffix('a') == Some(sa) {
        return false;
    }
    sa.len() >= 6
        && sb.len() >= 6
        && sa.len().abs_diff(sb.len()) <= 1
        && sa.chars().next() == sb.chars().next()
        && strsim::jaro_winkler(sa, sb) >= 0.94
}

fn first_match(sa: &str, sb: &str) -> bool {
    if sa == sb {
        return true;
    }
    sa.len() >= 3
        && sb.len() >= 3
        && sa.chars().next() == sb.chars().next()
        && strsim::jaro_winkler(sa, sb) >= 0.88
}

fn inits_meet(a: &[char], b: &[char]) -> bool {
    a.iter().any(|c| b.contains(c))
}

/// Returns the login skeletons a person with this candidate name could have.
fn compacts_of(c: &NameCand) -> Vec<String> {
    let mut v = Vec::new();
    for i in &c.inits {
        v.push(skeleton(&format!("{i}{}", c.last)));
        v.push(skeleton(&format!("{}{i}", c.last)));
    }
    if let Some(f) = &c.first {
        v.push(skeleton(&format!("{f}{}", c.last)));
        v.push(skeleton(&format!("{}{f}", c.last)));
    }
    if c.last.chars().count() >= 5 {
        v.push(skeleton(&c.last));
    }
    v
}

/// Returns `true` if two parsed spellings can be the same person.
pub fn compatible(a: &Parsed, b: &Parsed) -> bool {
    use Shape::*;
    let pairs = || {
        a.cands
            .iter()
            .zip(&a.sk)
            .flat_map(move |(x, xs)| b.cands.iter().zip(&b.sk).map(move |(y, ys)| (x, xs, y, ys)))
    };
    match (a.shape, b.shape) {
        (Full, Full) => pairs().any(|(_, xs, _, ys)| {
            last_match(&xs.0, &ys.0)
                && match (&xs.1, &ys.1) {
                    (Some(f1), Some(f2)) => first_match(f1, f2),
                    _ => false,
                }
        }),
        (Full, Partial) | (Partial, Full) | (Partial, Partial) => {
            pairs().any(|(x, xs, y, ys)| last_match(&xs.0, &ys.0) && inits_meet(&x.inits, &y.inits))
        }
        (Login, Login) => a.compact.is_some() && a.compact == b.compact,
        (Login, _) => login_vs(a, b),
        (_, Login) => login_vs(b, a),
    }
}

fn login_vs(login: &Parsed, other: &Parsed) -> bool {
    let Some(c) = &login.compact else {
        return false;
    };
    if c.len() < 4 {
        return false;
    }
    other.compacts.binary_search(c).is_ok() || other.compact.as_ref() == Some(c)
}

/// Returns `true` if two strings resolve to the same person (handy for tests and a
/// "same person?" check in the UI).
pub fn same_person(a: &str, b: &str) -> bool {
    if is_service(a) || is_service(b) {
        return ident_key(a) == ident_key(b);
    }
    let (pa, pb) = (parse(a), parse(b));
    ident_key(a) == ident_key(b) || compatible(&pa, &pb)
}

/// A merged person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    pub login: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub service: bool,
    pub docs: BTreeSet<u64>,
    pub from_meta: bool,
    /// All spellings are e-mail addresses (the person is known only by address).
    pub email_only: bool,
    pub emails: Vec<String>,
    /// Best name candidate (Latin), used to generate addresses.
    pub best: Option<NameCand>,
    pub best_shape: Option<Shape>,
    /// All candidates (Latin), used to infer the address pattern.
    pub cands: Vec<NameCand>,
    /// Roles of all spellings (`author`, `comment`, `revision`, …).
    pub roles: BTreeSet<String>,
}

struct Dsu(Vec<usize>);
impl Dsu {
    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while self.0[r] != r {
            r = self.0[r];
        }
        let mut y = x;
        while self.0[y] != r {
            let n = self.0[y];
            self.0[y] = r;
            y = n;
        }
        r
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.0[ra.max(rb)] = ra.min(rb);
        }
    }
}

/// Merge result: persons and a map from spelling key ([`ident_key`]) to person index.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub clusters: Vec<Cluster>,
    pub by_key: HashMap<String, usize>,
}

impl Resolved {
    pub fn login_of(&self, raw: &str) -> Option<&str> {
        self.by_key
            .get(&ident_key(raw))
            .map(|&i| self.clusters[i].login.as_str())
    }
}

fn has_cyr(s: &str) -> bool {
    s.chars().any(translit::is_cyrillic)
}

/// Merges spellings into persons. The result order is deterministic (by document count,
/// then by login).
pub fn resolve(input: &[Identity]) -> Resolved {
    // 1. Merge identical keys.
    let mut merged: BTreeMap<String, Identity> = BTreeMap::new();
    for id in input {
        let k = ident_key(&id.raw);
        if k.is_empty() || k.chars().count() < 2 {
            continue;
        }
        match merged.get_mut(&k) {
            Some(m) => {
                m.docs.extend(id.docs.iter().copied());
                m.roles.extend(id.roles.iter().cloned());
                m.links.extend(id.links.iter().cloned());
                if id.source == IdentSource::Meta {
                    m.source = IdentSource::Meta;
                }
                // Prefer a spelling with capitals or Cyrillic for display.
                if m.raw.chars().all(|c| !c.is_uppercase())
                    && id.raw.chars().any(char::is_uppercase)
                {
                    m.raw = id.raw.clone();
                }
            }
            None => {
                merged.insert(k, id.clone());
            }
        }
    }
    let keys: Vec<String> = merged.keys().cloned().collect();
    let ids: Vec<&Identity> = keys.iter().map(|k| &merged[k]).collect();
    let n = ids.len();
    let service: Vec<bool> = ids.iter().map(|i| is_service(&i.raw)).collect();
    let parsed: Vec<Parsed> = ids.iter().map(|i| parse(&i.raw)).collect();
    let mut dsu = Dsu((0..n).collect());
    // 1b. Links from metadata (reviewer AD address → name), no similarity heuristics.
    for (i, id) in ids.iter().enumerate() {
        for l in &id.links {
            if let Ok(j) = keys.binary_search(&ident_key(l)) {
                dsu.union(i, j);
            }
        }
    }

    // Indices to avoid an all-pairs comparison: surname skeleton → spellings (including
    // "related" surnames to catch typos), login skeleton → spellings.
    let mut by_last: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut by_compact: HashMap<&str, Vec<usize>> = HashMap::new();
    for i in (0..n).filter(|&i| !service[i]) {
        for (sl, _) in &parsed[i].sk {
            let v = by_last.entry(sl.as_str()).or_default();
            if v.last() != Some(&i) {
                v.push(i);
            }
        }
        for c in parsed[i].compacts.iter().chain(parsed[i].compact.iter()) {
            let v = by_compact.entry(c.as_str()).or_default();
            if v.last() != Some(&i) {
                v.push(i);
            }
        }
    }
    let mut lasts: Vec<&str> = by_last.keys().copied().collect();
    lasts.sort_unstable();
    let mut related: HashMap<&str, Vec<&str>> = HashMap::new();
    for (ai, &a) in lasts.iter().enumerate() {
        related.entry(a).or_default().push(a);
        for &b in &lasts[ai + 1..] {
            if a.as_bytes().first() != b.as_bytes().first() {
                break; // sorted, so the next first letter differs
            }
            if last_match(a, b) {
                related.entry(a).or_default().push(b);
                related.entry(b).or_default().push(a);
            }
        }
    }
    let neighbors = |i: usize| -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        for (sl, _) in &parsed[i].sk {
            for r in related.get(sl.as_str()).into_iter().flatten() {
                out.extend(by_last.get(r).into_iter().flatten().copied());
            }
        }
        for c in parsed[i].compacts.iter().chain(parsed[i].compact.iter()) {
            out.extend(by_compact.get(c.as_str()).into_iter().flatten().copied());
        }
        out.remove(&i);
        out
    };
    let nb: Vec<BTreeSet<usize>> = (0..n)
        .map(|i| {
            if service[i] {
                BTreeSet::new()
            } else {
                neighbors(i)
            }
        })
        .collect();

    // 2. Full names with each other.
    let is_full = |i: usize| !service[i] && parsed[i].shape == Shape::Full;
    for a in (0..n).filter(|&i| is_full(i)) {
        for &b in nb[a].iter().filter(|&&b| b > a && is_full(b)) {
            if compatible(&parsed[a], &parsed[b]) {
                dsu.union(a, b);
            }
        }
    }
    // 3. Partial names and logins join the single matching person with a full name.
    let others: Vec<usize> = (0..n)
        .filter(|&i| !service[i] && parsed[i].shape != Shape::Full)
        .collect();
    let mut attached = vec![false; n];
    for &o in &others {
        let mut roots = BTreeSet::new();
        for &f in nb[o].iter().filter(|&&f| is_full(f)) {
            if compatible(&parsed[o], &parsed[f]) {
                roots.insert(dsu.find(f));
            }
        }
        if roots.len() == 1 {
            let r = *roots.iter().next().unwrap_or(&o);
            dsu.union(o, r);
            attached[o] = true;
        }
    }
    // 4. Remaining partial names and logins with each other.
    let in_rest: Vec<bool> = (0..n)
        .map(|i| !service[i] && parsed[i].shape != Shape::Full && !attached[i])
        .collect();
    for a in (0..n).filter(|&i| in_rest[i]) {
        for &b in nb[a].iter().filter(|&&b| b > a && in_rest[b]) {
            if compatible(&parsed[a], &parsed[b]) {
                dsu.union(a, b);
            }
        }
    }

    // 5. Build clusters.
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = dsu.find(i);
        groups.entry(r).or_default().push(i);
    }
    let mut clusters: Vec<(Cluster, Vec<usize>)> = Vec::new();
    for members in groups.values() {
        let mut docs = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        let mut emails = BTreeSet::new();
        let mut from_meta = false;
        let mut roles = BTreeSet::new();
        for &m in members {
            roles.extend(ids[m].roles.iter().cloned());
            docs.extend(ids[m].docs.iter().copied());
            aliases.insert(ids[m].raw.clone());
            if parsed[m].is_email {
                emails.insert(ids[m].raw.to_lowercase());
            }
            if ids[m].source == IdentSource::Meta {
                from_meta = true;
            }
        }
        let is_svc = members.iter().all(|&m| service[m]);
        // Display name: a full name (more documents, Cyrillic preferred), then partial, then login.
        let best_name = members
            .iter()
            .copied()
            .filter(|&m| !parsed[m].is_email)
            .max_by(|&a, &b| {
                let ka = (
                    parsed[a].shape == Shape::Full,
                    parsed[a].shape == Shape::Partial,
                    ids[a].docs.len(),
                    has_cyr(&ids[a].raw),
                    std::cmp::Reverse(ids[a].raw.clone()),
                );
                let kb = (
                    parsed[b].shape == Shape::Full,
                    parsed[b].shape == Shape::Partial,
                    ids[b].docs.len(),
                    has_cyr(&ids[b].raw),
                    std::cmp::Reverse(ids[b].raw.clone()),
                );
                ka.cmp(&kb)
            })
            .or_else(|| members.first().copied());
        let Some(bn) = best_name else { continue };
        let name = if parsed[bn].is_email {
            ids[bn].raw.split('@').next().unwrap_or("").to_string()
        } else {
            strip_prefixes(&ids[bn].raw)
        };
        // Login: a real login (from metadata or the local part of an address).
        let login = members
            .iter()
            .copied()
            .filter(|&m| parsed[m].shape != Shape::Full || parsed[m].is_email)
            .filter_map(|m| {
                let k = ident_key(&ids[m].raw);
                let l = if parsed[m].is_email {
                    k.split('@').next().unwrap_or("").to_string()
                } else {
                    k
                };
                is_loginish(&l).then_some((m, l))
            })
            .max_by(|(a, la), (b, lb)| {
                let ka = (
                    ids[*a].docs.len(),
                    !parsed[*a].is_email,
                    la.contains(['.', '_', '-']),
                    std::cmp::Reverse(la.clone()),
                );
                let kb = (
                    ids[*b].docs.len(),
                    !parsed[*b].is_email,
                    lb.contains(['.', '_', '-']),
                    std::cmp::Reverse(lb.clone()),
                );
                ka.cmp(&kb)
            })
            .map(|(_, l)| l);
        let mut all_cands: Vec<NameCand> = Vec::new();
        let mut best: Option<NameCand> = None;
        let mut best_shape = None;
        for &m in members {
            if parsed[m].shape == Shape::Full || parsed[m].shape == Shape::Partial {
                all_cands.extend(parsed[m].cands.iter().cloned());
            }
        }
        if !parsed[bn].cands.is_empty() && !is_svc {
            best = parsed[bn].cands.first().cloned();
            best_shape = Some(parsed[bn].shape);
        }
        let login = login.unwrap_or_else(|| match &best {
            Some(c) => match (&c.first, c.inits.first()) {
                (Some(f), _) => format!("{}.{}", f.chars().next().unwrap_or('x'), c.last),
                (None, Some(i)) => format!("{i}.{}", c.last),
                _ => c.last.clone(),
            },
            None => ident_key(&name).replace(' ', "."),
        });
        clusters.push((
            Cluster {
                login,
                name,
                aliases: aliases.into_iter().collect(),
                service: is_svc,
                docs,
                from_meta,
                email_only: members.iter().all(|&m| parsed[m].is_email),
                emails: emails.into_iter().collect(),
                best,
                best_shape,
                cands: all_cands,
                roles,
            },
            members.clone(),
        ));
    }
    clusters.sort_by(|(a, _), (b, _)| {
        b.docs
            .len()
            .cmp(&a.docs.len())
            .then(a.service.cmp(&b.service))
            .then(a.login.cmp(&b.login))
    });
    // Make logins unique.
    let mut used: HashMap<String, u32> = HashMap::new();
    for (c, _) in clusters.iter_mut() {
        let n = used.entry(c.login.clone()).or_insert(0);
        *n += 1;
        if *n > 1 {
            c.login = format!("{}-{}", c.login, n);
        }
    }
    let mut by_key = HashMap::new();
    for (ci, (_, members)) in clusters.iter().enumerate() {
        for &m in members {
            by_key.insert(keys[m].clone(), ci);
        }
    }
    Resolved {
        clusters: clusters.into_iter().map(|(c, _)| c).collect(),
        by_key,
    }
}

/// Resolves raw name spellings (metadata, signatures, path users) to merged person logins.
#[derive(Debug, Clone, Default)]
pub struct Logins {
    map: BTreeMap<String, String>,
}

fn norm_name(raw: &str) -> String {
    let s = match raw.find('<') {
        Some(i) if i > 0 => &raw[..i],
        _ => raw,
    };
    s.trim()
        .trim_matches('"')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

impl Logins {
    pub fn new(people: &[foca_core::api::Person]) -> Self {
        let mut map = BTreeMap::new();
        for p in people {
            for n in std::iter::once(&p.login)
                .chain(std::iter::once(&p.name))
                .chain(p.aliases.iter())
                .chain(p.emails.iter())
            {
                let k = norm_name(n);
                if !k.is_empty() {
                    map.entry(k).or_insert_with(|| p.login.clone());
                }
            }
        }
        Logins { map }
    }

    /// Login of a spelling: exact (case-insensitive), then without a `DOMAIN\` prefix, then the
    /// local part of an address.
    pub fn get(&self, raw: &str) -> Option<String> {
        let k = norm_name(raw);
        if k.is_empty() {
            return None;
        }
        if let Some(l) = self.map.get(&k) {
            return Some(l.clone());
        }
        if let Some((_, u)) = k.rsplit_once('\\') {
            if let Some(l) = self.map.get(u) {
                return Some(l.clone());
            }
        }
        if let Some((u, _)) = k.split_once('@') {
            return self.map.get(u).cloned();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_resolve_spellings() {
        let p = foca_core::api::Person {
            login: "i.petrenko".into(),
            name: "Іван Петренко".into(),
            aliases: vec!["Petrenko Ivan".into()],
            emails: vec!["i.petrenko@example.com".into()],
            ..Default::default()
        };
        let l = Logins::new(&[p]);
        assert_eq!(l.get("іван  петренко").as_deref(), Some("i.petrenko"));
        assert_eq!(l.get("CORP\\i.petrenko").as_deref(), Some("i.petrenko"));
        assert_eq!(
            l.get("Іван Петренко <i.petrenko@example.com>").as_deref(),
            Some("i.petrenko")
        );
        assert_eq!(
            l.get("i.petrenko@corp.example.test").as_deref(),
            Some("i.petrenko")
        );
        assert_eq!(l.get("Someone Else"), None);
    }

    fn ids(list: &[&str]) -> Vec<Identity> {
        list.iter()
            .enumerate()
            .map(|(i, s)| Identity::new(s, i as u64 + 1, IdentSource::Meta, "author"))
            .collect()
    }

    #[test]
    fn task_example_merges_into_one() {
        let r = resolve(&ids(&[
            "ipetrov",
            "Petrov I.",
            "Иван Петров",
            "i.petrov@corp.ua",
            "Іван Петров",
            "Петров Иван Сергеевич",
        ]));
        let people: Vec<_> = r.clusters.iter().filter(|c| !c.service).collect();
        assert_eq!(people.len(), 1, "{:#?}", r.clusters);
        let p = people[0];
        assert_eq!(p.docs.len(), 6);
        assert!(p.name.contains("Петров"));
        assert!(p.login == "ipetrov" || p.login == "i.petrov", "{}", p.login);
        assert_eq!(p.emails, vec!["i.petrov@corp.ua"]);
    }

    #[test]
    fn ukrainian_corpus_names() {
        assert!(same_person("Андрій Бондар", "a.bondar"));
        assert!(same_person("Віктор Ткаченко", "Viktor Tkachenko"));
        assert!(same_person("Viktor Tkachenko", "v.tkachenko"));
        assert!(same_person("Тетяна Мельник", "tmelnyk"));
        assert!(same_person("Юлія Гриценко", "y.hrytsenko"));
        assert!(same_person("Ігор Петренко", "Игорь Петренко"));
        assert!(same_person("Marina Shevchuk", "Марина Шевчук"));
        assert!(same_person("Kovalenko Olena", "Олена Коваленко"));
        assert!(same_person("CONTOSO\\i.petrenko", "i.petrenko"));
    }

    #[test]
    fn different_people_stay_apart() {
        assert!(!same_person("Иван Петров", "Ольга Петрова"));
        assert!(!same_person("Иван Петров", "Иван Сидоров"));
        assert!(!same_person("Олена Коваленко", "Андрій Коваленко"));
        assert!(!same_person("Administrator", "a.bondar"));
        // An ambiguous login is merged with neither person.
        let r = resolve(&ids(&["Иван Петров", "Игорь Петров", "i.petrov"]));
        assert_eq!(r.clusters.len(), 3, "{:#?}", r.clusters);
    }

    #[test]
    fn service_accounts_flagged() {
        for s in [
            "Administrator",
            "Администратор",
            "Адміністратор",
            "User",
            "user1",
            "admin",
            "DESKTOP-4F2K1QX",
            "Microsoft Office User",
            "scan",
        ] {
            assert!(is_service(s), "{s}");
        }
        for s in ["Олена Коваленко", "a.bondar", "Phil Harvey", "Hogwarts"] {
            assert!(!is_service(s), "{s}");
        }
        let r = resolve(&ids(&["Administrator", "admin", "Олена Коваленко"]));
        assert_eq!(r.clusters.iter().filter(|c| c.service).count(), 2);
    }

    #[test]
    fn service_and_org_names() {
        for n in [
            "anonymous",
            "payroll",
            "member",
            "Member",
            "работа",
            "Работа",
            "робота",
            "працівник",
            "дом",
            "Planner",
            "NIST",
            "CBSC",
            "Workforce Services",
        ] {
            assert!(is_service(n), "{n}");
        }
        for n in [
            "Jason Moore",
            "JOHN SMITH",
            "Moore, Jason",
            "j.smith",
            "Олена Коваленко",
        ] {
            assert!(!is_service(n), "{n}");
        }
        assert_eq!(
            strip_dept_tail("Richardson, Jeffrey@EDD"),
            "Richardson, Jeffrey"
        );
        assert_eq!(strip_dept_tail("jeff@edd"), "jeff@edd");
    }

    #[test]
    fn login_generated_and_unique() {
        let r = resolve(&ids(&["Віктор Ткаченко"]));
        assert_eq!(r.clusters[0].login, "v.tkachenko");
        assert_eq!(r.login_of("віктор ткаченко"), Some("v.tkachenko"));
        let p = parse("Author: Jeff");
        assert_eq!(p.shape, Shape::Login);
    }
}

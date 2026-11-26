//! Content of artifacts found by `foca-fuzz`: `.git/config`, `.git/logs/HEAD`,
//! `.env`, `.ovpn`, `package.json`, `composer.json`.
//!
//! Pure functions over bytes: no I/O, input clipped to [`MAX_ARTIFACT_BYTES`], every list
//! capped. Secrets (credentials in remote URLs, `.env` values, inline VPN keys) go through the
//! existing secret detector or are wrapped in [`SecretValue`]; display strings are masked.

use foca_core::{api::SecretValue, Severity};
use serde::Serialize;
use serde_json::Value;

use crate::secrets::{self, SecretHit};
use crate::util::{is_internal_fqdn, is_private_ip, parse_ip, url_host};

/// Maximum artifact size parsed, bytes.
pub const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;
/// Maximum entries of each list.
pub const MAX_ITEMS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    GitConfig,
    GitLogs,
    Env,
    Ovpn,
    PackageJson,
    ComposerJson,
}

/// Recognises the artifact by its URL path or file name.
pub fn kind_of(path: &str) -> Option<ArtifactKind> {
    let p = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = p.rsplit('/').next().unwrap_or("");
    if p.ends_with(".git/config") {
        Some(ArtifactKind::GitConfig)
    } else if p.contains(".git/logs/") {
        Some(ArtifactKind::GitLogs)
    } else if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        Some(ArtifactKind::Env)
    } else if name.ends_with(".ovpn") {
        Some(ArtifactKind::Ovpn)
    } else if name == "package.json" {
        Some(ArtifactKind::PackageJson)
    } else if name == "composer.json" {
        Some(ArtifactKind::ComposerJson)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GitRemote {
    pub name: String,
    /// URL with credentials masked.
    pub url: String,
    pub host: Option<String>,
    pub internal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Person {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VpnRemote {
    pub host: String,
    pub port: Option<u16>,
    pub proto: Option<String>,
    pub internal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub dev: bool,
    /// Scoped (`@corp/x`) or vendor (`corp/x`) prefix, a hint at internal packages.
    pub scope: Option<String>,
}

/// Parsed artifact. Fields irrelevant for the kind stay empty.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ArtifactInfo {
    pub kind: ArtifactKind,
    pub remotes: Vec<GitRemote>,
    pub branches: Vec<String>,
    pub people: Vec<Person>,
    /// `.env` variable names (values never stored here).
    pub env_vars: Vec<String>,
    pub secrets: Vec<SecretHit>,
    /// Hosts referenced by the artifact (DB hosts, internal URLs).
    pub hosts: Vec<String>,
    pub vpn: Vec<VpnRemote>,
    /// `.ovpn` with inline `<key>`/`<tls-auth>` material.
    pub inline_key: bool,
    pub package: Option<String>,
    pub deps: Vec<Dependency>,
    /// Non-public package registries / repositories.
    pub registries: Vec<String>,
    /// Proposed finding severity.
    pub sev: Severity,
}

impl ArtifactInfo {
    fn new(kind: ArtifactKind) -> Self {
        ArtifactInfo {
            kind,
            remotes: vec![],
            branches: vec![],
            people: vec![],
            env_vars: vec![],
            secrets: vec![],
            hosts: vec![],
            vpn: vec![],
            inline_key: false,
            package: None,
            deps: vec![],
            registries: vec![],
            sev: Severity::Info,
        }
    }

    fn add_host(&mut self, h: &str) {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if !h.is_empty() && self.hosts.len() < MAX_ITEMS && !self.hosts.contains(&h) {
            self.hosts.push(h);
        }
    }

    fn add_person(&mut self, name: &str, email: &str) {
        let p = Person {
            name: name.trim().to_string(),
            email: email.trim().to_ascii_lowercase(),
        };
        if (p.name.is_empty() && p.email.is_empty())
            || self.people.len() >= MAX_ITEMS
            || self.people.contains(&p)
        {
            return;
        }
        self.people.push(p);
    }

    fn add_branch(&mut self, b: &str) {
        let b = b.trim();
        if !b.is_empty()
            && b.len() <= 200
            && self.branches.len() < MAX_ITEMS
            && !self.branches.iter().any(|x| x == b)
        {
            self.branches.push(b.to_string());
        }
    }

    fn finish(mut self) -> Self {
        let crit = self.secrets.iter().any(|s| s.sev == Severity::Critical) || self.inline_key;
        self.sev = if crit {
            Severity::Critical
        } else if !self.secrets.is_empty() {
            Severity::High
        } else if self.kind == ArtifactKind::Env
            || self.remotes.iter().any(|r| r.internal)
            || !self.vpn.is_empty()
            || !self.registries.is_empty()
        {
            Severity::Medium
        } else if !self.people.is_empty() || !self.deps.is_empty() || !self.remotes.is_empty() {
            Severity::Low
        } else {
            Severity::Info
        };
        self
    }
}

fn text_of(bytes: &[u8]) -> String {
    let b = &bytes[..bytes.len().min(MAX_ARTIFACT_BYTES)];
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    String::from_utf8_lossy(b).into_owned()
}

fn host_internal(h: &str) -> bool {
    match parse_ip(h) {
        Some(ip) => is_private_ip(ip),
        None => is_internal_fqdn(h) || !h.contains('.'),
    }
}

/// Parses an artifact by kind; `None` if the content does not look like that artifact.
pub fn parse(kind: ArtifactKind, bytes: &[u8]) -> Option<ArtifactInfo> {
    match kind {
        ArtifactKind::GitConfig => git_config(bytes),
        ArtifactKind::GitLogs => git_logs(bytes),
        ArtifactKind::Env => env(bytes),
        ArtifactKind::Ovpn => ovpn(bytes),
        ArtifactKind::PackageJson => package_json(bytes),
        ArtifactKind::ComposerJson => composer_json(bytes),
    }
}

/// [`kind_of`] + [`parse`].
pub fn parse_path(path: &str, bytes: &[u8]) -> Option<ArtifactInfo> {
    parse(kind_of(path)?, bytes)
}

/// Masks the password of `scheme://user:pass@host` and returns it as a secret hit.
fn remote_url(url: &str, place: &str, info: &mut ArtifactInfo) -> String {
    let mut shown = url.to_string();
    if let Some(i) = url.find("://") {
        let rest = &url[i + 3..];
        let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
        if let Some((ui, _)) = auth.rsplit_once('@') {
            let secret = ui.split_once(':').map(|(_, p)| p).unwrap_or(ui);
            // `git@host` style user names are not secrets; tokens as user names are.
            let is_secret = ui.contains(':') || secret.len() >= 20;
            if is_secret && !secret.is_empty() {
                shown = url.replacen(secret, &foca_core::api::mask(secret), 1);
                info.secrets.push(SecretHit {
                    rule: "uri-credentials".into(),
                    title: "Учётные данные в URI".into(),
                    kind: "conn".into(),
                    sev: Severity::Critical,
                    value: SecretValue::new(secret),
                    context: format!("url = {{{{s:{secret}}}}}"),
                    location: place.to_string(),
                    host: url_host(url),
                    entropy: secrets::entropy(secret),
                });
            }
        }
    }
    shown
}

/// Host of a Git remote: `https://h/…`, `ssh://git@h:22/…` or scp-like `git@h:group/repo`.
fn git_host(url: &str) -> Option<String> {
    if url.contains("://") {
        return url_host(url);
    }
    let (left, _) = url.split_once(':')?;
    let h = left.rsplit('@').next()?;
    (!h.is_empty() && !h.contains('/')).then(|| h.to_ascii_lowercase())
}

/// `.git/config`: remotes, branches, `[user]`, credentials in URLs.
pub fn git_config(bytes: &[u8]) -> Option<ArtifactInfo> {
    let text = text_of(bytes);
    if !text.contains('[') {
        return None;
    }
    let mut info = ArtifactInfo::new(ArtifactKind::GitConfig);
    let mut section = String::new();
    let mut sub = String::new();
    let (mut uname, mut umail) = (String::new(), String::new());
    let mut sections = 0;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(h) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            sections += 1;
            let (s, n) = match h.split_once(' ') {
                Some((s, n)) => (s, n.trim().trim_matches('"')),
                None => (h, ""),
            };
            section = s.to_ascii_lowercase();
            sub = n.to_string();
            if section == "branch" {
                info.add_branch(&sub);
            }
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().trim_matches('"'));
        match (section.as_str(), k.as_str()) {
            ("remote", "url") | ("remote", "pushurl") | ("submodule", "url") => {
                if info.remotes.len() >= MAX_ITEMS {
                    continue;
                }
                let shown = remote_url(v, ".git/config", &mut info);
                let host = git_host(v);
                let internal = host.as_deref().is_some_and(host_internal);
                if let Some(h) = &host {
                    info.add_host(h);
                }
                info.remotes.push(GitRemote {
                    name: sub.clone(),
                    url: shown,
                    host,
                    internal,
                });
            }
            ("branch", "merge") => {
                info.add_branch(v.trim_start_matches("refs/heads/"));
            }
            ("user", "name") => uname = v.to_string(),
            ("user", "email") => umail = v.to_string(),
            ("http", "extraheader") => {
                for h in secrets::Rules::builtin().scan(l, ".git/config") {
                    info.secrets.push(h);
                }
                if let Some((_, tok)) = v.split_once(':') {
                    let tok = tok
                        .trim()
                        .trim_start_matches("Basic ")
                        .trim_start_matches("Bearer ");
                    if tok.len() >= 8 && !info.secrets.iter().any(|s| s.value.expose() == tok) {
                        info.secrets.push(SecretHit {
                            rule: "git-extraheader".into(),
                            title: "Токен в http.extraheader".into(),
                            kind: "api".into(),
                            sev: Severity::Critical,
                            value: SecretValue::new(tok),
                            context: format!("extraheader = {{{{s:{tok}}}}}"),
                            location: ".git/config".into(),
                            host: None,
                            entropy: secrets::entropy(tok),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if sections == 0 {
        return None;
    }
    info.add_person(&uname, &umail);
    Some(info.finish())
}

/// `.git/logs/HEAD` (reflog): committer names/e-mails, branches, clone URL.
pub fn git_logs(bytes: &[u8]) -> Option<ArtifactInfo> {
    let text = text_of(bytes);
    let mut info = ArtifactInfo::new(ArtifactKind::GitLogs);
    let mut ok = 0;
    for line in text.lines().take(20_000) {
        // <old-sha> <new-sha> Name <email> <unix-ts> <tz>\t<message>
        let (head, msg) = line.split_once('\t').unwrap_or((line, ""));
        let mut it = head.splitn(3, ' ');
        let (Some(a), Some(b), Some(rest)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if a.len() < 40 || b.len() < 40 || !a.bytes().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let (Some(lt), Some(gt)) = (rest.find('<'), rest.find('>')) else {
            continue;
        };
        if gt < lt {
            continue;
        }
        ok += 1;
        info.add_person(&rest[..lt], &rest[lt + 1..gt]);
        if let Some(r) = msg.strip_prefix("checkout: moving from ") {
            if let Some((from, to)) = r.split_once(" to ") {
                for br in [from, to] {
                    if !(br.len() >= 40 && br.bytes().all(|c| c.is_ascii_hexdigit())) {
                        info.add_branch(br);
                    }
                }
            }
        } else if let Some(u) = msg.strip_prefix("clone: from ") {
            let shown = remote_url(u.trim(), ".git/logs/HEAD", &mut info);
            let host = git_host(u.trim());
            if let Some(h) = &host {
                info.add_host(h);
            }
            let internal = host.as_deref().is_some_and(host_internal);
            info.remotes.push(GitRemote {
                name: "clone".into(),
                url: shown,
                host,
                internal,
            });
        } else if let Some(r) = msg.strip_prefix("branch: Created from ") {
            info.add_branch(r);
        }
    }
    (ok > 0).then(|| info.finish())
}

const SECRET_KEY_HINTS: &[&str] = &[
    "PASS",
    "PWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "_KEY",
    "SALT",
    "DSN",
];

fn env_placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    v.len() < 4
        || matches!(
            l.as_str(),
            "null" | "none" | "true" | "false" | "changeme" | "secret" | "password"
        )
        || l.starts_with("${")
        || l.contains("xxx")
        || l.contains("example")
        || l.contains("your")
        || l.starts_with('<')
}

/// `.env`: variable names, secrets (built-in rules plus secret-named keys), hosts.
pub fn env(bytes: &[u8]) -> Option<ArtifactInfo> {
    let text = text_of(bytes);
    let mut info = ArtifactInfo::new(ArtifactKind::Env);
    let mut n = 0;
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.is_empty()
            || !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            continue;
        }
        n += 1;
        if info.env_vars.len() < MAX_ITEMS {
            info.env_vars.push(k.to_string());
        }
        let v = v.trim();
        let v = v
            .split(" #")
            .next()
            .unwrap_or(v)
            .trim()
            .trim_matches(['"', '\'']);
        let place = format!(".env, строка {}", i + 1);
        let ku = k.to_ascii_uppercase();
        if ku.ends_with("HOST") || ku.ends_with("_SERVER") || ku.ends_with("_ADDR") {
            if !v.is_empty() && !v.contains(['$', '{', ' ']) {
                info.add_host(v.split(':').next().unwrap_or(v));
            }
        } else if ku.ends_with("_URL") || ku.ends_with("_URI") || ku.ends_with("_DSN") {
            if let Some(h) = url_host(v) {
                info.add_host(&h);
            }
        }
        let before = info.secrets.len();
        for h in secrets::Rules::builtin().scan(&format!("{k}={v}"), &place) {
            if !info.secrets.iter().any(|s| s.value == h.value) {
                info.secrets.push(h);
            }
        }
        if info.secrets.len() == before
            && SECRET_KEY_HINTS.iter().any(|h| ku.contains(h))
            && !env_placeholder(v)
            && info.secrets.len() < MAX_ITEMS
        {
            info.secrets.push(SecretHit {
                rule: "env-secret".into(),
                title: format!("Секрет в переменной {k}"),
                kind: if ku.contains("PASS") || ku.contains("PWD") {
                    "pass".into()
                } else {
                    "api".into()
                },
                sev: Severity::Critical,
                value: SecretValue::new(v),
                context: format!("{k}={{{{s:{v}}}}}"),
                location: place,
                host: None,
                entropy: secrets::entropy(v),
            });
        }
    }
    (n > 0).then(|| info.finish())
}

/// `.ovpn`: `remote` servers, ports, protocol, inline key material.
pub fn ovpn(bytes: &[u8]) -> Option<ArtifactInfo> {
    let text = text_of(bytes);
    let mut info = ArtifactInfo::new(ArtifactKind::Ovpn);
    let mut proto: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut looks = false;
    let mut raw: Vec<(String, Option<u16>, Option<String>)> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let mut it = l.split_whitespace();
        match it.next() {
            Some("client") | Some("dev") | Some("nobind") | Some("persist-key") => looks = true,
            Some("remote") => {
                looks = true;
                if let Some(h) = it.next() {
                    let p = it.next().and_then(|x| x.parse().ok());
                    let pr = it.next().map(str::to_string);
                    if raw.len() < MAX_ITEMS {
                        raw.push((h.to_ascii_lowercase(), p, pr));
                    }
                }
            }
            Some("proto") => proto = it.next().map(str::to_string),
            Some("port") => port = it.next().and_then(|x| x.parse().ok()),
            Some("<key>") | Some("<tls-auth>") | Some("<tls-crypt>") | Some("<secret>") => {
                info.inline_key = true;
            }
            _ => {}
        }
    }
    if !looks {
        return None;
    }
    for (h, p, pr) in raw {
        info.add_host(&h);
        let internal = host_internal(&h);
        info.vpn.push(VpnRemote {
            host: h,
            port: p.or(port).or(Some(1194)),
            proto: pr.or_else(|| proto.clone()),
            internal,
        });
    }
    if info.inline_key {
        info.secrets.extend(
            secrets::Rules::builtin()
                .scan(&text, ".ovpn")
                .into_iter()
                .filter(|h| h.rule == "private-key"),
        );
    }
    Some(info.finish())
}

/// `Name <email> (url)` (npm author string).
fn npm_person(v: &Value) -> Option<(String, String)> {
    match v {
        Value::String(s) => {
            let name = s.split(['<', '(']).next().unwrap_or("").trim().to_string();
            let email = s
                .split_once('<')
                .and_then(|(_, r)| r.split_once('>'))
                .map(|(e, _)| e.trim().to_string())
                .unwrap_or_default();
            Some((name, email))
        }
        Value::Object(o) => Some((
            o.get("name").and_then(Value::as_str).unwrap_or("").into(),
            o.get("email").and_then(Value::as_str).unwrap_or("").into(),
        )),
        _ => None,
    }
}

fn scope_of(name: &str, npm: bool) -> Option<String> {
    if npm {
        name.strip_prefix('@')
            .and_then(|n| n.split_once('/'))
            .map(|(s, _)| format!("@{s}"))
    } else {
        name.split_once('/').map(|(v, _)| v.to_string())
    }
}

fn add_deps(info: &mut ArtifactInfo, v: Option<&Value>, dev: bool, npm: bool) {
    let Some(Value::Object(m)) = v else { return };
    for (name, ver) in m {
        if info.deps.len() >= MAX_ITEMS {
            return;
        }
        let version = ver.as_str().unwrap_or("").to_string();
        // Dependencies pulled straight from Git/HTTP reveal repository hosts.
        let src = version.trim_start_matches("git+");
        if src.contains("://") || src.starts_with("git@") {
            let shown = remote_url(src, "dependencies", info);
            if let Some(h) = git_host(src) {
                info.add_host(&h);
                if host_internal(&h) && !info.registries.contains(&shown) {
                    info.registries.push(shown);
                }
            }
        }
        if !npm && (name == "php" || name.starts_with("ext-")) {
            continue;
        }
        info.deps.push(Dependency {
            name: name.clone(),
            scope: scope_of(name, npm),
            version,
            dev,
        });
    }
}

fn public_registry(u: &str) -> bool {
    let h = url_host(u).unwrap_or_default();
    matches!(
        h.as_str(),
        "registry.npmjs.org"
            | "registry.yarnpkg.com"
            | "packagist.org"
            | "repo.packagist.org"
            | "npm.pkg.github.com"
    )
}

/// `package.json`: package, authors/contributors, dependencies, private registry, repository.
pub fn package_json(bytes: &[u8]) -> Option<ArtifactInfo> {
    let v: Value = serde_json::from_str(&text_of(bytes)).ok()?;
    let o = v.as_object()?;
    if !(o.contains_key("name")
        || o.contains_key("dependencies")
        || o.contains_key("devDependencies"))
    {
        return None;
    }
    let mut info = ArtifactInfo::new(ArtifactKind::PackageJson);
    info.package = o.get("name").and_then(Value::as_str).map(|n| {
        match o.get("version").and_then(Value::as_str) {
            Some(ver) => format!("{n}@{ver}"),
            None => n.to_string(),
        }
    });
    for key in ["author", "contributors", "maintainers"] {
        let items: Vec<&Value> = match o.get(key) {
            Some(Value::Array(a)) => a.iter().collect(),
            Some(x) => vec![x],
            None => vec![],
        };
        for p in items {
            if let Some((n, e)) = npm_person(p) {
                info.add_person(&n, &e);
            }
        }
    }
    add_deps(&mut info, o.get("dependencies"), false, true);
    add_deps(&mut info, o.get("devDependencies"), true, true);
    add_deps(&mut info, o.get("peerDependencies"), false, true);
    add_deps(&mut info, o.get("optionalDependencies"), false, true);
    if let Some(r) = o
        .get("publishConfig")
        .and_then(|p| p.get("registry"))
        .and_then(Value::as_str)
    {
        if !public_registry(r) {
            let shown = remote_url(r, "publishConfig", &mut info);
            if let Some(h) = url_host(r) {
                info.add_host(&h);
            }
            info.registries.push(shown);
        }
    }
    let repo = match o.get("repository") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(r)) => r.get("url").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    if let Some(u) = repo {
        let u = u.trim_start_matches("git+").to_string();
        let shown = remote_url(&u, "repository", &mut info);
        let host = git_host(&u);
        if let Some(h) = &host {
            info.add_host(h);
        }
        info.remotes.push(GitRemote {
            name: "repository".into(),
            url: shown,
            internal: host.as_deref().is_some_and(host_internal),
            host,
        });
    }
    Some(info.finish())
}

/// `composer.json`: package, authors, `require`/`require-dev`, private repositories.
pub fn composer_json(bytes: &[u8]) -> Option<ArtifactInfo> {
    let v: Value = serde_json::from_str(&text_of(bytes)).ok()?;
    let o = v.as_object()?;
    if !(o.contains_key("name") || o.contains_key("require")) {
        return None;
    }
    let mut info = ArtifactInfo::new(ArtifactKind::ComposerJson);
    info.package = o.get("name").and_then(Value::as_str).map(str::to_string);
    if let Some(Value::Array(a)) = o.get("authors") {
        for p in a.iter().take(MAX_ITEMS) {
            if let Some((n, e)) = npm_person(p) {
                info.add_person(&n, &e);
            }
        }
    }
    add_deps(&mut info, o.get("require"), false, false);
    add_deps(&mut info, o.get("require-dev"), true, false);
    let repos: Vec<&Value> = match o.get("repositories") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Object(m)) => m.values().collect(),
        _ => vec![],
    };
    for r in repos.into_iter().take(MAX_ITEMS) {
        if let Some(u) = r.get("url").and_then(Value::as_str) {
            if public_registry(u) {
                continue;
            }
            let shown = remote_url(u, "repositories", &mut info);
            if let Some(h) = git_host(u) {
                info.add_host(&h);
            }
            if !info.registries.contains(&shown) {
                info.registries.push(shown);
            }
        }
    }
    Some(info.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(
            kind_of("https://h/.git/config"),
            Some(ArtifactKind::GitConfig)
        );
        assert_eq!(kind_of("/app/.git/logs/HEAD"), Some(ArtifactKind::GitLogs));
        assert_eq!(kind_of("/.env.production"), Some(ArtifactKind::Env));
        assert_eq!(kind_of("/vpn/office.ovpn"), Some(ArtifactKind::Ovpn));
        assert_eq!(
            kind_of("/package.json?x=1"),
            Some(ArtifactKind::PackageJson)
        );
        assert_eq!(kind_of("/composer.json"), Some(ArtifactKind::ComposerJson));
        assert_eq!(kind_of("/index.html"), None);
    }

    #[test]
    fn git_config_parsed() {
        let cfg = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://deploy:glpat-AbCdEf0123456789xyz@gitlab.example.corp/web/site.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[remote \"backup\"]\n\turl = git@github.com:example-org/site.git\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n[branch \"release/2.1\"]\n[user]\n\tname = Test Developer\n\temail = dev@example.test\n";
        let i = git_config(cfg).unwrap();
        assert_eq!(i.remotes.len(), 2);
        assert!(i.remotes[0].internal);
        assert_eq!(i.remotes[0].host.as_deref(), Some("gitlab.example.corp"));
        assert!(!i.remotes[0].url.contains("glpat-AbCdEf0123456789xyz"));
        assert_eq!(i.remotes[1].host.as_deref(), Some("github.com"));
        assert_eq!(i.branches, ["main", "release/2.1"]);
        assert_eq!(i.people[0].email, "dev@example.test");
        assert_eq!(i.secrets.len(), 1);
        assert_eq!(i.sev, Severity::Critical);
        assert!(!format!("{i:?}").contains("glpat-AbCdEf0123456789xyz"));
        assert!(git_config(b"not a config").is_none());
    }

    #[test]
    fn git_logs_parsed() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let log = format!(
            "{z} {a} Test Developer <dev@example.test> 1767225600 +0200\tclone: from https://git.example.corp/web/site.git\n\
             {a} {b} Second Dev <second@example.test> 1767229200 +0200\tcheckout: moving from main to feature/payments\n"
        );
        let i = git_logs(log.as_bytes()).unwrap();
        assert_eq!(i.people.len(), 2);
        assert_eq!(i.branches, ["main", "feature/payments"]);
        assert_eq!(i.remotes[0].host.as_deref(), Some("git.example.corp"));
        assert!(git_logs(b"garbage\n").is_none());
    }

    #[test]
    fn env_parsed() {
        let e = b"# app\nAPP_ENV=production\nDB_HOST=10.20.0.5\nDB_PASSWORD=\"Sx9!kq2Lr7\"\nexport STRIPE_SECRET=sk_live_51AbCdEfGhIjKlMnOpQrStUv\nMAIL_PASSWORD=null\nAPI_TOKEN=${TOKEN}\nREDIS_URL=redis://cache.internal:6379\n";
        let i = env(e).unwrap();
        assert_eq!(i.env_vars.len(), 7);
        assert!(i.hosts.contains(&"10.20.0.5".to_string()));
        assert!(i.hosts.contains(&"cache.internal".to_string()));
        let vals: Vec<&str> = i.secrets.iter().map(|s| s.value.expose()).collect();
        assert!(vals.contains(&"Sx9!kq2Lr7"), "{vals:?}");
        assert!(vals.iter().any(|v| v.starts_with("sk_live_")), "{vals:?}");
        assert!(!vals.contains(&"null") && !vals.iter().any(|v| v.contains("${")));
        assert_eq!(i.sev, Severity::Critical);
        assert!(!format!("{i:?}").contains("Sx9!kq2Lr7"));
        assert!(env(b"<html>nope</html>").is_none());
    }

    #[test]
    fn ovpn_parsed() {
        let o = b"client\ndev tun\nproto udp\nremote vpn.example.test 1194\nremote 10.0.0.1 443 tcp\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n<key>\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n</key>\n";
        let i = ovpn(o).unwrap();
        assert_eq!(i.vpn.len(), 2);
        assert_eq!(i.vpn[0].proto.as_deref(), Some("udp"));
        assert_eq!(i.vpn[1].port, Some(443));
        assert!(i.vpn[1].internal);
        assert!(i.inline_key);
        assert_eq!(i.sev, Severity::Critical);
        assert!(ovpn(b"hello").is_none());
    }

    #[test]
    fn package_json_parsed() {
        let p = br#"{"name":"@examplecorp/portal","version":"1.4.0","private":true,
            "author":"Test Developer <dev@example.test> (https://example.test)",
            "contributors":[{"name":"Second Dev","email":"second@example.test"}],
            "dependencies":{"react":"^18.2.0","@examplecorp/ui":"git+ssh://git@gitlab.example.corp/fe/ui.git#v2"},
            "devDependencies":{"jest":"29.7.0"},
            "publishConfig":{"registry":"https://npm.example.corp/repository/npm-private/"},
            "repository":{"type":"git","url":"git+https://gitlab.example.corp/fe/portal.git"}}"#;
        let i = package_json(p).unwrap();
        assert_eq!(i.package.as_deref(), Some("@examplecorp/portal@1.4.0"));
        assert_eq!(i.people.len(), 2);
        assert_eq!(i.people[0].name, "Test Developer");
        assert_eq!(i.deps.len(), 3);
        assert!(i.deps.iter().any(|d| d.dev && d.name == "jest"));
        assert_eq!(
            i.deps
                .iter()
                .find(|d| d.name == "@examplecorp/ui")
                .unwrap()
                .scope
                .as_deref(),
            Some("@examplecorp")
        );
        assert!(i.registries.iter().any(|r| r.contains("npm.example.corp")));
        assert!(i.remotes[0].internal);
        assert_eq!(i.sev, Severity::Medium);
        assert!(package_json(b"[1,2]").is_none());
        assert!(package_json(b"{broken").is_none());
    }

    #[test]
    fn composer_json_parsed() {
        let c = br#"{"name":"examplecorp/billing","authors":[{"name":"Test Developer","email":"dev@example.test"}],
            "require":{"php":">=8.1","ext-json":"*","laravel/framework":"^10.0","examplecorp/core":"dev-main"},
            "require-dev":{"phpunit/phpunit":"^10"},
            "repositories":[{"type":"vcs","url":"https://deploy:S3cretTok3n99@git.example.corp/php/core.git"},{"type":"composer","url":"https://repo.packagist.org"}]}"#;
        let i = composer_json(c).unwrap();
        assert_eq!(i.deps.len(), 3);
        assert_eq!(
            i.deps
                .iter()
                .find(|d| d.name == "examplecorp/core")
                .unwrap()
                .scope
                .as_deref(),
            Some("examplecorp")
        );
        assert_eq!(i.registries.len(), 1);
        assert!(!i.registries[0].contains("S3cretTok3n99"));
        assert_eq!(i.secrets.len(), 1);
        assert_eq!(i.sev, Severity::Critical);
    }

    #[test]
    fn hostile_input() {
        let big = vec![b'['; 3 * MAX_ARTIFACT_BYTES];
        let _ = git_config(&big);
        let _ = env(&[0xff, 0xfe, b'=', b'\n']);
        let nested = "[".repeat(100_000);
        assert!(package_json(nested.as_bytes()).is_none());
        let _ = git_logs(&vec![b'a'; 100_000]);
    }
}

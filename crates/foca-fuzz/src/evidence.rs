//! Short finding evidence with secrets masked: the file is never stored in full, and
//! `KEY=value` / `key: value` / `$var = "..."` values, as well as anything caught by the
//! foca-analysis secret rules, are replaced with a mask.

use std::sync::OnceLock;

use foca_analysis::artifacts::{self, ArtifactKind};
use foca_analysis::secrets::Rules;

use crate::types::ArtifactSummary;
use regex::Regex;

/// Number of evidence lines and characters to keep.
pub const MAX_LINES: usize = 6;
pub const MAX_CHARS: usize = 400;

fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^(\s*(?:export\s+)?[$A-Za-z_][\w.\-\[\]'"]*\s*(?:=>|=|:)\s*)(.+)$"#)
            .expect("re")
    })
}

/// Masks a value as its first 2 characters + `***`.
pub fn mask_value(v: &str) -> String {
    let t = v
        .trim()
        .trim_end_matches(';')
        .trim_matches(|c| c == '"' || c == '\'');
    if t.is_empty() {
        return v.to_string();
    }
    let keep: String = t.chars().take(2).collect();
    format!("{keep}***")
}

/// Returns `true` if the data looks binary.
pub fn is_binary(b: &[u8]) -> bool {
    let n = b.len().min(1024);
    b[..n].contains(&0)
        || std::str::from_utf8(&b[..n]).is_err() && {
            // Tolerate a UTF-8 sequence cut off at the end.
            let valid = match std::str::from_utf8(&b[..n]) {
                Ok(_) => n,
                Err(e) => e.valid_up_to(),
            };
            valid + 4 < n
        }
}

/// Builds evidence from the beginning of the body.
pub fn evidence(body: &[u8], content_type: Option<&str>) -> String {
    if is_binary(body) {
        return format!(
            "двоичные данные ({}{} байт прочитано)",
            content_type.map(|c| format!("{c}, ")).unwrap_or_default(),
            body.len()
        );
    }
    let text = String::from_utf8_lossy(body);
    let mut lines = Vec::new();
    for l in text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
    {
        if lines.len() >= MAX_LINES {
            break;
        }
        lines.push(mask_line(l));
    }
    let mut s = lines.join("\n");
    let rules = Rules::builtin();
    for hit in rules.scan(&s, "evidence") {
        let v = hit.value.expose().to_string();
        if !v.is_empty() {
            s = s.replace(&v, &mask_value(&v));
        }
    }
    truncate_chars(&s, MAX_CHARS)
}

/// Masks the value in a `key = value` line.
pub fn mask_line(l: &str) -> String {
    if l.trim_start().starts_with("<") {
        return l.to_string();
    }
    match kv_re().captures(l) {
        Some(c) => format!("{}{}", &c[1], mask_value(&c[2])),
        None => l.to_string(),
    }
}

pub fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push('…');
        t
    }
}

/// Parses a known artifact (`.git/config`, `.git/logs/HEAD`, `.env`, `.ovpn`, `package.json`,
/// `composer.json`) from the raw body and keeps only the masked summary.
pub fn artifact_summary(path: &str, body: &[u8]) -> Option<ArtifactSummary> {
    let Some(a) = artifacts::parse_path(path, body) else {
        return apidoc_summary(path, body);
    };
    let kind = match a.kind {
        ArtifactKind::GitConfig => "git_config",
        ArtifactKind::GitLogs => "git_logs",
        ArtifactKind::Env => "env",
        ArtifactKind::Ovpn => "ovpn",
        ArtifactKind::PackageJson => "package_json",
        ArtifactKind::ComposerJson => "composer_json",
    };
    let mut s = ArtifactSummary {
        kind: kind.into(),
        sev: a.sev,
        ..Default::default()
    };
    let mut push = |l: String| {
        if s.lines.len() < 20 {
            s.lines.push(truncate(&l, 200));
        }
    };
    for r in a.remotes.iter().take(5) {
        push(format!("Git remote {}: {}", r.name, r.url));
    }
    for b in a.branches.iter().take(5) {
        push(format!("Ветка: {b}"));
    }
    for p in a.people.iter().take(10) {
        push(format!("Разработчик: {} <{}>", p.name, p.email));
    }
    for v in a.vpn.iter().take(5) {
        push(format!(
            "VPN: {}{}{}",
            v.host,
            v.port.map(|p| format!(":{p}")).unwrap_or_default(),
            v.proto
                .as_deref()
                .map(|p| format!("/{p}"))
                .unwrap_or_default()
        ));
    }
    if a.inline_key {
        push("Встроенный закрытый ключ в конфигурации VPN".into());
    }
    if !a.env_vars.is_empty() {
        let names: Vec<&str> = a.env_vars.iter().take(15).map(String::as_str).collect();
        push(format!("Переменные: {}", names.join(", ")));
    }
    for h in a.secrets.iter().take(10) {
        push(format!("Секрет: {} ({})", h.title, h.value.masked()));
    }
    if let Some(p) = &a.package {
        push(format!("Пакет: {p}"));
    }
    if !a.deps.is_empty() {
        push(format!("Зависимостей: {}", a.deps.len()));
    }
    for r in a.registries.iter().take(5) {
        push(format!("Реестр: {r}"));
    }
    s.people = a
        .people
        .iter()
        .take(20)
        .map(|p| format!("{} <{}>", p.name, p.email))
        .collect();
    let mut hosts: Vec<String> = a.hosts.clone();
    hosts.extend(a.remotes.iter().filter_map(|r| r.host.clone()));
    hosts.extend(a.vpn.iter().map(|v| v.host.clone()));
    hosts.sort();
    hosts.dedup();
    hosts.truncate(30);
    s.hosts = hosts;
    s.internal = a.remotes.iter().any(|r| r.internal) || a.vpn.iter().any(|v| v.internal);
    Some(s)
}

/// Parses exposed API documentation and service endpoints (Swagger/OpenAPI, Swagger UI,
/// GraphQL introspection, Spring Boot Actuator, openid-configuration) with
/// `foca_recon::apidocs`. Actuator `env` values are never kept, only property names.
pub fn apidoc_summary(path: &str, body: &[u8]) -> Option<ArtifactSummary> {
    let d = foca_recon::apidocs::summarize(path, path, body)?;
    Some(ArtifactSummary {
        kind: format!("apidoc_{}", d.kind.id()),
        sev: d.sev,
        lines: d
            .summary_lines()
            .into_iter()
            .take(20)
            .map(|l| truncate(&l, 200))
            .collect(),
        hosts: d.hosts.iter().take(30).cloned().collect(),
        ..Default::default()
    })
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_values_masked() {
        let e = evidence(
            b"APP_ENV=production\nDB_PASSWORD=supersecretvalue\nAPP_KEY=base64:QUJDREVGR0hJSktM\n",
            Some("text/plain"),
        );
        assert!(!e.contains("supersecretvalue"), "{e}");
        assert!(!e.contains("QUJDREVGR0hJSktM"), "{e}");
        assert!(e.contains("DB_PASSWORD=su***"), "{e}");
    }

    #[test]
    fn php_values_masked() {
        let e = evidence(
            b"<?php\n$db_password = \"S3cr3tPassw0rd!\";\necho 1;\n",
            None,
        );
        assert!(!e.contains("S3cr3tPassw0rd"), "{e}");
        assert!(e.contains("$db_password = S3***"), "{e}");
    }

    #[test]
    fn binary_and_limits() {
        assert!(evidence(&[0, 1, 2, 3], Some("application/pdf")).starts_with("двоичные"));
        let long = "x".repeat(5000);
        assert!(evidence(long.as_bytes(), None).chars().count() <= MAX_CHARS + 1);
        let many = "a\nb\nc\nd\ne\nf\ng\nh\n";
        assert_eq!(evidence(many.as_bytes(), None).lines().count(), MAX_LINES);
    }
}

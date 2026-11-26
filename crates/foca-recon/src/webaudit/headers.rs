//! Security response headers of already received pages: HSTS, CORS, cookies, CSP, framing,
//! MIME sniffing, Referrer-Policy, Permissions-Policy and software version disclosure.
//!
//! Access class `passive`: everything is computed from headers (and the HTML for
//! `<meta http-equiv="Content-Security-Policy">`) the caller already has; no requests are sent.
//! Cookie values are never stored, only names and attributes.

use serde::{Deserialize, Serialize};

use foca_core::Severity;

use crate::webaudit::csp::{self, Csp, CspDomain};

/// Six months: the commonly recommended minimum HSTS `max-age`.
pub const HSTS_MIN_AGE: u64 = 15_552_000;
/// One year: required for the HSTS preload list.
pub const HSTS_PRELOAD_AGE: u64 = 31_536_000;

/// One problem found by a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    /// Stable id (`hsts_missing`, `cookie_flags:<name>`, `csp_unsafe_inline`, …).
    pub id: String,
    pub sev: Severity,
    pub title: String,
    pub detail: String,
}

impl Issue {
    pub fn new(id: &str, sev: Severity, title: &str, detail: String) -> Issue {
        Issue {
            id: id.into(),
            sev,
            title: title.into(),
            detail,
        }
    }
}

/// A parsed `Strict-Transport-Security` header.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hsts {
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
}

/// A cookie set by the response (value never kept).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub http_only: bool,
    pub secure: bool,
    /// `Strict` | `Lax` | `None` as sent, or empty.
    pub same_site: String,
    /// The name looks like a session or authentication cookie.
    pub session: bool,
}

/// Static CORS headers of the response (no `Origin` was sent by us).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsHeaders {
    pub allow_origin: Option<String>,
    pub allow_credentials: bool,
}

/// A response header revealing software or its version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    pub header: String,
    pub value: String,
    /// The value contains a version number.
    pub versioned: bool,
}

/// Assessment of one response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HeaderAudit {
    pub url: String,
    pub https: bool,
    pub hsts: Option<Hsts>,
    pub csp: Option<Csp>,
    /// Where the CSP came from: `header`, `report-only`, `meta`, or empty.
    pub csp_source: String,
    pub csp_domains: Vec<CspDomain>,
    pub cors: CorsHeaders,
    pub cookies: Vec<CookieInfo>,
    pub disclosure: Vec<Disclosure>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub issues: Vec<Issue>,
}

fn values<'a>(h: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    h.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect()
}

fn first(h: &[(String, String)], name: &str) -> Option<String> {
    values(h, name).first().map(|s| s.to_string())
}

/// Parses `Strict-Transport-Security`.
pub fn parse_hsts(v: &str) -> Hsts {
    let mut h = Hsts::default();
    for p in v.split(';') {
        let p = p.trim();
        let (k, val) = p.split_once('=').unwrap_or((p, ""));
        match k.trim().to_ascii_lowercase().as_str() {
            "max-age" => h.max_age = val.trim().trim_matches('"').parse().ok(),
            "includesubdomains" => h.include_subdomains = true,
            "preload" => h.preload = true,
            _ => {}
        }
    }
    h
}

/// Returns `true` for cookie names that usually carry a session or authentication token.
pub fn is_session_cookie(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const EXACT: &[&str] = &[
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspsessionid",
        "connect.sid",
        "cfid",
        "cftoken",
        "sid",
        "ssid",
    ];
    const PARTS: &[&str] = &[
        "sess", "auth", "token", "jwt", "login", "remember", "identity", "logged",
    ];
    EXACT.contains(&n.as_str())
        || n.starts_with("aspsessionid")
        || n.starts_with("wordpress_logged_in")
        || PARTS.iter().any(|p| n.contains(p))
}

/// Parses one `Set-Cookie` value into its attributes (the value is discarded).
pub fn parse_cookie(v: &str) -> Option<CookieInfo> {
    let mut parts = v.split(';');
    let name = parts.next()?.split_once('=')?.0.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut c = CookieInfo {
        session: is_session_cookie(&name),
        name,
        ..Default::default()
    };
    for a in parts {
        let a = a.trim();
        let (k, val) = a.split_once('=').unwrap_or((a, ""));
        match k.trim().to_ascii_lowercase().as_str() {
            "httponly" => c.http_only = true,
            "secure" => c.secure = true,
            "samesite" => c.same_site = val.trim().to_string(),
            _ => {}
        }
    }
    Some(c)
}

fn has_version(v: &str) -> bool {
    let b = v.as_bytes();
    b.windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit())
        || b.windows(2).any(|w| w[0] == b'/' && w[1].is_ascii_digit())
}

/// Extracts `<meta http-equiv="Content-Security-Policy" content="...">` from HTML.
pub fn meta_csp(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find("<meta") {
        let start = from + i;
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        let tag = &lower[start..end];
        from = end;
        if !tag.contains("content-security-policy") || !tag.contains("http-equiv") {
            continue;
        }
        let Some(ci) = tag.find("content=").map(|i| i + "content=".len()) else {
            continue;
        };
        let Some(q) = tag[ci..].chars().next() else {
            continue;
        };
        if q != '"' && q != '\'' {
            continue;
        }
        let vs = start + ci + 1;
        let ve = html[vs..end].find(q).map_or(end, |e| vs + e);
        return Some(html[vs..ve].replace("&#39;", "'").replace("&apos;", "'"));
    }
    None
}

fn clip(s: &str, n: usize) -> String {
    let mut t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        t.push('…');
    }
    t
}

/// Assesses the security headers of a response. `html` (may be empty) is used for a `<meta>`
/// CSP and to decide whether page-only headers (framing, CSP) apply.
pub fn analyze(url: &str, headers: &[(String, String)], html: &str) -> HeaderAudit {
    let https = url.to_ascii_lowercase().starts_with("https://");
    let ctype = first(headers, "content-type").unwrap_or_default();
    let is_page =
        ctype.is_empty() && !html.is_empty() || ctype.to_ascii_lowercase().contains("html");
    let mut a = HeaderAudit {
        url: url.into(),
        https,
        ..Default::default()
    };
    let mut issue = |id: &str, sev: Severity, title: &str, detail: String| {
        a.issues.push(Issue::new(id, sev, title, detail));
    };

    // HSTS: only meaningful over HTTPS (browsers ignore it on plain HTTP).
    if https {
        match first(headers, "strict-transport-security") {
            None => issue(
                "hsts_missing",
                Severity::Medium,
                "Нет заголовка HSTS",
                "ответ по HTTPS без Strict-Transport-Security, возможен SSL stripping".into(),
            ),
            Some(v) => {
                let h = parse_hsts(&v);
                match h.max_age {
                    Some(0) => issue(
                        "hsts_disabled",
                        Severity::Medium,
                        "HSTS отключён (max-age=0)",
                        format!("Strict-Transport-Security: {}", clip(&v, 120)),
                    ),
                    Some(n) if n < HSTS_MIN_AGE => issue(
                        "hsts_short",
                        Severity::Low,
                        "Короткий срок HSTS",
                        format!("max-age={n} (< {HSTS_MIN_AGE}, 180 дней)"),
                    ),
                    None => issue(
                        "hsts_invalid",
                        Severity::Low,
                        "Некорректный заголовок HSTS",
                        format!("нет max-age: {}", clip(&v, 120)),
                    ),
                    _ => {}
                }
                if h.preload && (!h.include_subdomains || h.max_age.unwrap_or(0) < HSTS_PRELOAD_AGE)
                {
                    issue(
                        "hsts_preload_invalid",
                        Severity::Info,
                        "HSTS preload без выполнения требований",
                        "для списка preload нужны includeSubDomains и max-age ≥ 31536000".into(),
                    );
                }
                a.hsts = Some(h);
            }
        }
    }

    // CORS from a plain request (no Origin sent).
    let acao = first(headers, "access-control-allow-origin");
    let acac = first(headers, "access-control-allow-credentials")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    match acao.as_deref() {
        Some("*") if acac => issue(
            "cors_wildcard_credentials",
            Severity::Medium,
            "CORS: * вместе с Allow-Credentials",
            "Access-Control-Allow-Origin: * и Access-Control-Allow-Credentials: true, ошибка конфигурации (браузер блокирует, но политика собрана неверно)".into(),
        ),
        Some("*") => issue(
            "cors_wildcard",
            Severity::Info,
            "CORS открыт для любого источника",
            "Access-Control-Allow-Origin: *, данные ответа читаются с любого сайта (без кук)".into(),
        ),
        Some(o) if o.eq_ignore_ascii_case("null") => issue(
            "cors_null_origin",
            Severity::Medium,
            "CORS разрешает Origin: null",
            format!("Access-Control-Allow-Origin: null{}", if acac { ", с Allow-Credentials" } else { "" }),
        ),
        _ => {}
    }
    a.cors = CorsHeaders {
        allow_origin: acao,
        allow_credentials: acac,
    };

    // Cookies.
    for v in values(headers, "set-cookie") {
        let Some(c) = parse_cookie(v) else { continue };
        if c.session {
            let mut miss = Vec::new();
            if !c.http_only {
                miss.push("HttpOnly");
            }
            if https && !c.secure {
                miss.push("Secure");
            }
            if c.same_site.is_empty() {
                miss.push("SameSite");
            }
            let none_insecure = c.same_site.eq_ignore_ascii_case("none") && !c.secure;
            if none_insecure {
                miss.push("Secure (обязателен при SameSite=None)");
            }
            if !miss.is_empty() {
                let sev = if !c.http_only || (https && !c.secure) || none_insecure {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                issue(
                    &format!("cookie_flags:{}", c.name),
                    sev,
                    "Сессионная кука без защитных флагов",
                    format!("{}: нет {}", c.name, miss.join(", ")),
                );
            }
        }
        a.cookies.push(c);
    }

    // Software disclosure.
    for h in [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-runtime",
    ] {
        for v in values(headers, h) {
            if v.is_empty() {
                continue;
            }
            let versioned = has_version(v);
            if h == "server" && !versioned {
                continue; // "nginx", "cloudflare" alone are not a disclosure
            }
            if h == "x-drupal-cache" || h == "x-runtime" {
                continue; // informative for tech detection only
            }
            a.disclosure.push(Disclosure {
                header: h.into(),
                value: clip(v, 120),
                versioned,
            });
        }
    }
    if !a.disclosure.is_empty() {
        let ev: Vec<String> = a
            .disclosure
            .iter()
            .map(|d| format!("{}: {}", d.header, d.value))
            .collect();
        let versioned = a.disclosure.iter().any(|d| d.versioned);
        issue(
            "version_disclosure",
            Severity::Low,
            if versioned {
                "Заголовки раскрывают версию ПО"
            } else {
                "Заголовки раскрывают используемое ПО"
            },
            ev.join("; "),
        );
    }

    // CSP: enforced header, then report-only, then <meta>.
    let (policy, source) = match first(headers, "content-security-policy") {
        Some(_) => (
            Some(csp::parse(
                &values(headers, "content-security-policy").join(","),
                false,
            )),
            "header",
        ),
        None => match first(headers, "content-security-policy-report-only") {
            Some(v) => (Some(csp::parse(&v, true)), "report-only"),
            None => match meta_csp(html) {
                Some(v) => (Some(csp::parse(&v, false)), "meta"),
                None => (None, ""),
            },
        },
    };
    a.csp_source = source.into();
    let frame_ancestors = policy
        .as_ref()
        .filter(|p| !p.report_only && source != "meta") // ignored in <meta> and report-only
        .and_then(|p| p.get("frame-ancestors").map(|v| v.to_vec()));
    match &policy {
        Some(p) => {
            for i in p.issues() {
                issue(
                    &format!("csp_{}", i.id),
                    i.sev,
                    "Слабая политика CSP",
                    i.detail,
                );
            }
            a.csp_domains = p.domains();
        }
        None if is_page => issue(
            "csp_missing",
            Severity::Low,
            "Нет политики CSP",
            "страница без Content-Security-Policy, нет защиты от XSS на уровне браузера".into(),
        ),
        None => {}
    }
    a.csp = policy;

    // Framing.
    a.x_frame_options = first(headers, "x-frame-options");
    if is_page && frame_ancestors.is_none() {
        match a.x_frame_options.as_deref().map(str::to_ascii_lowercase) {
            None => issue(
                "clickjacking",
                Severity::Low,
                "Нет защиты от clickjacking",
                "нет X-Frame-Options и CSP frame-ancestors: страницу можно встроить во фрейм"
                    .into(),
            ),
            Some(v) if v.starts_with("allow-from") => issue(
                "xfo_allow_from",
                Severity::Low,
                "Устаревший X-Frame-Options: ALLOW-FROM",
                "ALLOW-FROM не поддерживается современными браузерами: используйте frame-ancestors"
                    .into(),
            ),
            Some(v) if v != "deny" && v != "sameorigin" => issue(
                "xfo_invalid",
                Severity::Low,
                "Некорректный X-Frame-Options",
                format!("X-Frame-Options: {v}"),
            ),
            _ => {}
        }
    }

    a.x_content_type_options = first(headers, "x-content-type-options");
    if !a
        .x_content_type_options
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("nosniff"))
    {
        issue(
            "nosniff_missing",
            Severity::Low,
            "Нет X-Content-Type-Options: nosniff",
            "браузер может «угадывать» MIME-тип ответа".into(),
        );
    }
    a.referrer_policy = first(headers, "referrer-policy");
    match a.referrer_policy.as_deref().map(str::to_ascii_lowercase) {
        None if is_page => issue(
            "referrer_policy_missing",
            Severity::Info,
            "Нет Referrer-Policy",
            "используется политика браузера по умолчанию".into(),
        ),
        Some(v) if v.contains("unsafe-url") => issue(
            "referrer_policy_unsafe",
            Severity::Low,
            "Referrer-Policy раскрывает полный URL",
            format!("Referrer-Policy: {v}, путь и параметры уходят сторонним сайтам"),
        ),
        _ => {}
    }
    a.permissions_policy =
        first(headers, "permissions-policy").or_else(|| first(headers, "feature-policy"));
    if is_page && a.permissions_policy.is_none() {
        issue(
            "permissions_policy_missing",
            Severity::Info,
            "Нет Permissions-Policy",
            "не ограничен доступ встроенного контента к камере, геолокации и т. п.".into(),
        );
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn ids(a: &HeaderAudit) -> Vec<&str> {
        a.issues.iter().map(|i| i.id.as_str()).collect()
    }

    #[test]
    fn weak_site() {
        let a = analyze(
            "https://contoso.ua/",
            &h(&[
                ("Content-Type", "text/html"),
                ("Strict-Transport-Security", "max-age=3600; preload"),
                ("Server", "Apache/2.4.41 (Ubuntu)"),
                ("X-Powered-By", "PHP/7.4.3"),
                ("Set-Cookie", "PHPSESSID=abcdef123; path=/"),
                ("Set-Cookie", "lang=uk; path=/"),
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
                ("X-Frame-Options", "ALLOW-FROM https://a.example"),
            ]),
            "<html></html>",
        );
        let i = ids(&a);
        for want in [
            "hsts_short",
            "hsts_preload_invalid",
            "cors_wildcard_credentials",
            "cookie_flags:PHPSESSID",
            "version_disclosure",
            "csp_missing",
            "xfo_allow_from",
            "nosniff_missing",
            "referrer_policy_missing",
            "permissions_policy_missing",
        ] {
            assert!(i.contains(&want), "{want} not in {i:?}");
        }
        assert!(!i.iter().any(|x| x.contains("lang")));
        let c = &a.cookies[0];
        assert!(c.session && !c.http_only && !c.secure);
        let ser = serde_json::to_string(&a).unwrap();
        assert!(!ser.contains("abcdef123"), "cookie value leaked");
        let cookie = a
            .issues
            .iter()
            .find(|x| x.id.starts_with("cookie"))
            .unwrap();
        assert_eq!(cookie.sev, Severity::Medium);
        assert!(cookie.detail.contains("HttpOnly") && cookie.detail.contains("Secure"));
    }

    #[test]
    fn hardened_site_is_clean() {
        let a = analyze(
            "https://contoso.ua/",
            &h(&[
                ("content-type", "text/html; charset=utf-8"),
                ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
                ("content-security-policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
                ("x-content-type-options", "nosniff"),
                ("referrer-policy", "strict-origin-when-cross-origin"),
                ("permissions-policy", "camera=()"),
                ("server", "nginx"),
                ("set-cookie", "__Host-session=x; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ]),
            "<html>",
        );
        assert!(a.issues.is_empty(), "{:?}", a.issues);
        assert_eq!(a.hsts.as_ref().unwrap().max_age, Some(63_072_000));
    }

    #[test]
    fn http_and_meta_csp() {
        let html = r#"<head><meta http-equiv="Content-Security-Policy" content="script-src 'self' https://api.dev.contoso.ua; frame-ancestors 'none'"></head>"#;
        let a = analyze(
            "http://contoso.ua/",
            &h(&[("Content-Type", "text/html")]),
            html,
        );
        let i = ids(&a);
        assert!(!i.contains(&"hsts_missing"), "no HSTS check over http");
        assert_eq!(a.csp_source, "meta");
        assert!(
            i.contains(&"clickjacking"),
            "frame-ancestors is ignored in <meta>"
        );
        assert_eq!(a.csp_domains[0].host, "api.dev.contoso.ua");
        assert!(analyze("https://x.ua/", &[], "")
            .issues
            .iter()
            .any(|x| x.id == "hsts_missing"));
    }
}

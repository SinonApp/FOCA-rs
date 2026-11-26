//! Deep web audit: security headers and CSP, JavaScript source maps, exposed API
//! documentation and service endpoints, CORS and HTTP methods: split by access class.
//!
//! | Check | Class | Requests |
//! |---|---|---|
//! | `headers` (HSTS, cookies, framing, nosniff, Referrer/Permissions-Policy, versions) | passive | none: headers already received |
//! | `csp` (assessment, allowed hosts → in-scope hosts / out-of-scope candidates) | passive | none |
//! | `cors_static` (`*` + credentials, `null`) | passive | none |
//! | `sourcemap_refs` (comment, `SourceMap`/`X-SourceMap`, inline `data:` maps) | passive | none |
//! | `sourcemaps` (`.map` download, `<script>.js.map` guess) | standard | GET, in-scope hosts only |
//! | `apidocs` (Swagger/OpenAPI, Swagger UI, Actuator, openid-configuration) | standard | GET, in-scope site |
//! | `cors_origin` (forged `Origin`) | active | GET with `Origin` |
//! | `methods` (`OPTIONS`/`Allow`, `TRACE` reflection, WebDAV `PROPFIND` `Depth: 0`) | active | OPTIONS, TRACE, PROPFIND |
//! | `graphql` (introspection) | active | one POST per endpoint |
//!
//! `PUT`/`DELETE` are never sent: they are reported only when advertised by `Allow`.
//! Hosts found in the CSP, source maps or API docs are never contacted unless they are in scope.

pub mod apidocs;
pub mod csp;
mod fetch;
pub mod headers;
pub mod methods;
pub mod sourcemaps;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use foca_core::{Scope, Severity};
use foca_net::NetClient;

use self::apidocs::{ApiDoc, ApiDocKind};
use self::csp::CspDomain;
use self::headers::HeaderAudit;
use self::methods::{CorsProbe, MethodsOptions, MethodsReport};
use self::sourcemaps::{MapRef, SourceMapInfo};
use crate::tech::PageInput;
use crate::ReconFinding;

/// Access class of a check, from least to most intrusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    /// Analysis of already received responses; no requests at all.
    Passive,
    /// GET requests to in-scope hosts (`Access::TouchesTarget`).
    Standard,
    /// Non-GET probes and forged headers (`Access::Active`), active stage only.
    Active,
}

/// A check and its access class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CheckInfo {
    pub id: &'static str,
    pub level: AuditLevel,
}

/// All checks of this module (see the table in the module docs).
pub const CHECKS: &[CheckInfo] = &[
    CheckInfo {
        id: "headers",
        level: AuditLevel::Passive,
    },
    CheckInfo {
        id: "csp",
        level: AuditLevel::Passive,
    },
    CheckInfo {
        id: "cors_static",
        level: AuditLevel::Passive,
    },
    CheckInfo {
        id: "sourcemap_refs",
        level: AuditLevel::Passive,
    },
    CheckInfo {
        id: "sourcemaps",
        level: AuditLevel::Standard,
    },
    CheckInfo {
        id: "apidocs",
        level: AuditLevel::Standard,
    },
    CheckInfo {
        id: "cors_origin",
        level: AuditLevel::Active,
    },
    CheckInfo {
        id: "methods",
        level: AuditLevel::Active,
    },
    CheckInfo {
        id: "graphql",
        level: AuditLevel::Active,
    },
];

/// A collected script with the response headers if known (`SourceMap` / `X-SourceMap`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditScript {
    pub url: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

/// Input: responses the recon stage already has.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebAuditInput {
    pub pages: Vec<PageInput>,
    pub scripts: Vec<AuditScript>,
    /// Extra GraphQL endpoints (absolute URLs) for the active introspection check.
    pub graphql_endpoints: Vec<String>,
    /// Pages come from a web archive copy (Wayback), not from the live site. Archived response
    /// headers do not describe the live server, so header findings are not raised for them.
    #[serde(default)]
    pub from_archive: bool,
}

impl WebAuditInput {
    /// Builds the input from what [`crate::collect::fetch_site`] gathered.
    pub fn from_recon(input: &crate::ReconInput) -> WebAuditInput {
        WebAuditInput {
            pages: input.pages.clone(),
            scripts: input
                .scripts
                .iter()
                .map(|s| AuditScript {
                    url: s.url.clone(),
                    body: s.body.clone(),
                    headers: Vec::new(),
                })
                .collect(),
            graphql_endpoints: Vec::new(),
            from_archive: false,
        }
    }
}

/// Options.
#[derive(Debug, Clone, PartialEq)]
pub struct WebAuditOptions {
    /// The highest access class allowed (the scan profile).
    pub level: AuditLevel,
    /// Project scope for classifying hosts; `None` uses the client's scope.
    pub scope: Option<Scope>,
    /// Maximum source maps downloaded.
    pub max_maps: usize,
    /// Try `<script>.js.map` for in-scope scripts without a map reference.
    pub guess_maps: bool,
    /// Maximum sites (origins) probed for API docs and methods.
    pub max_sites: usize,
    pub methods: MethodsOptions,
}

impl Default for WebAuditOptions {
    fn default() -> Self {
        WebAuditOptions {
            level: AuditLevel::Passive,
            scope: None,
            max_maps: 10,
            guess_maps: true,
            max_sites: 3,
            methods: MethodsOptions::default(),
        }
    }
}

/// Result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WebAuditReport {
    pub level: Option<AuditLevel>,
    pub headers: Vec<HeaderAudit>,
    /// Hosts allowed by CSP policies (`in_scope` filled).
    pub csp_domains: Vec<CspDomain>,
    /// New in-scope hosts (CSP, source maps, API docs) for the host list.
    pub hosts: Vec<String>,
    /// Out-of-scope hosts: candidates only, never contacted.
    pub candidates: Vec<String>,
    pub map_refs: Vec<MapRef>,
    pub source_maps: Vec<SourceMapInfo>,
    pub api_docs: Vec<ApiDoc>,
    pub cors: Vec<CorsProbe>,
    pub methods: Vec<MethodsReport>,
    /// Number of requests sent to the target by this module.
    pub requests: usize,
    pub errors: Vec<String>,
    pub findings: Vec<ReconFinding>,
    /// The audited pages were a web archive copy: header analysis is informational only and
    /// raises no findings; remaining findings carry the `archive` tag.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_archive: bool,
}

fn host_of(u: &str) -> Option<String> {
    url::Url::parse(u)
        .ok()?
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

fn origin_root(u: &str) -> Option<String> {
    let u = url::Url::parse(u).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    Some(format!("{}/", u.origin().ascii_serialization()))
}

/// Passive part only: no `NetClient`, no requests. `in_scope` classifies hosts.
pub fn analyze_passive(input: &WebAuditInput, in_scope: &dyn Fn(&str) -> bool) -> WebAuditReport {
    let mut rep = WebAuditReport {
        level: Some(AuditLevel::Passive),
        from_archive: input.from_archive,
        ..Default::default()
    };
    for p in &input.pages {
        rep.headers
            .push(headers::analyze(&p.url, &p.headers, &p.html));
    }
    let mut domains: Vec<CspDomain> = Vec::new();
    for h in &rep.headers {
        for d in &h.csp_domains {
            match domains.iter_mut().find(|x| x.host == d.host) {
                Some(x) => {
                    for dir in &d.directives {
                        if !x.directives.contains(dir) {
                            x.directives.push(dir.clone());
                        }
                    }
                    x.wildcard |= d.wildcard;
                }
                None => {
                    let mut d = d.clone();
                    d.in_scope = in_scope(&d.host);
                    domains.push(d);
                }
            }
        }
    }
    rep.csp_domains = domains;
    for s in &input.scripts {
        for r in sourcemaps::map_refs(&s.url, &s.body, &s.headers) {
            if r.via == "inline" {
                match sourcemaps::parse_inline(&r) {
                    Ok(i) => rep.source_maps.push(i),
                    Err(e) => rep.errors.push(format!("{}: {e}", s.url)),
                }
            }
            rep.map_refs.push(r);
        }
    }
    classify_hosts(&mut rep, in_scope);
    rep.findings = build_findings(&rep);
    rep
}

fn classify_hosts(rep: &mut WebAuditReport, in_scope: &dyn Fn(&str) -> bool) {
    let known: BTreeSet<String> = rep.headers.iter().filter_map(|h| host_of(&h.url)).collect();
    let mut all: BTreeSet<String> = rep.csp_domains.iter().map(|d| d.host.clone()).collect();
    for m in &rep.source_maps {
        all.extend(m.urls.iter().filter_map(|u| host_of(u)));
    }
    for d in &rep.api_docs {
        for h in &d.hosts {
            let u = if h.contains("://") {
                h.clone()
            } else {
                format!("https://{h}")
            };
            all.extend(host_of(&u));
        }
    }
    rep.hosts.clear();
    rep.candidates.clear();
    for h in all {
        if known.contains(&h) || !h.contains('.') {
            continue;
        }
        if in_scope(&h) {
            rep.hosts.push(h);
        } else {
            rep.candidates.push(h);
        }
    }
}

/// Runs every check allowed by `opts.level`. Passive level sends no requests.
pub async fn run(
    client: &NetClient,
    input: &WebAuditInput,
    opts: &WebAuditOptions,
) -> WebAuditReport {
    let scope = opts.scope.clone().unwrap_or_else(|| client.scope());
    let in_scope = |h: &str| scope.allows_host(h);
    let mut rep = analyze_passive(input, &in_scope);
    rep.level = Some(opts.level);
    if opts.level < AuditLevel::Standard {
        return rep;
    }

    // Standard: source maps (in-scope only).
    let mut todo: Vec<MapRef> = rep
        .map_refs
        .iter()
        .filter(|r| r.via != "inline")
        .cloned()
        .collect();
    if opts.guess_maps {
        for s in &input.scripts {
            if rep.map_refs.iter().any(|r| r.script_url == s.url) {
                continue;
            }
            if let Some(u) = sourcemaps::guess_url(&s.url) {
                todo.push(MapRef {
                    script_url: s.url.clone(),
                    map_url: u,
                    via: "guess".into(),
                });
            }
        }
    }
    let mut seen = BTreeSet::new();
    for r in todo {
        if rep.source_maps.len() >= opts.max_maps || client.is_cancelled() {
            break;
        }
        if !seen.insert(r.map_url.clone()) {
            continue;
        }
        let Some(h) = host_of(&r.map_url) else {
            continue;
        };
        if !in_scope(&h) {
            continue; // third-party map: never requested
        }
        rep.requests += 1;
        match sourcemaps::fetch_map(client, &r).await {
            Ok(i) => rep.source_maps.push(i),
            // A failed guess is expected and not an error.
            Err(e) if r.via != "guess" => rep.errors.push(format!("{}: {e}", r.map_url)),
            Err(_) => {}
        }
    }

    // Standard: API docs on each in-scope site.
    let mut sites: Vec<String> = Vec::new();
    for p in &input.pages {
        if let (Some(o), Some(h)) = (origin_root(&p.url), host_of(&p.url)) {
            if in_scope(&h) && !sites.contains(&o) && sites.len() < opts.max_sites {
                sites.push(o);
            }
        }
    }
    for s in &sites {
        if client.is_cancelled() {
            break;
        }
        let r = apidocs::probe_standard(client, s).await;
        rep.requests += r.requests;
        rep.api_docs.extend(r.docs);
        rep.errors
            .extend(r.errors.into_iter().filter(|e| !e.contains("HTTP 404")));
    }

    if opts.level >= AuditLevel::Active {
        for s in &sites {
            if client.is_cancelled() {
                break;
            }
            let c = methods::probe_cors(client, s).await;
            rep.requests += 1;
            let denied = c.denied;
            rep.cors.push(c);
            if denied {
                continue;
            }
            let m = methods::probe_methods(client, s, opts.methods).await;
            rep.requests +=
                1 + usize::from(opts.methods.trace) + usize::from(opts.methods.propfind);
            rep.methods.push(m);
        }
        let mut gql: Vec<String> = Vec::new();
        for s in &sites {
            for p in apidocs::GRAPHQL_PATHS {
                if let Ok(u) = url::Url::parse(s).and_then(|b| b.join(p)) {
                    gql.push(u.to_string());
                }
            }
        }
        let from_js = input.scripts.iter().flat_map(|s| {
            crate::js::extract_endpoints(&s.body, Some(&s.url))
                .into_iter()
                .filter(|e| e.kind == "graphql")
                .filter_map(|e| e.resolved)
        });
        for u in input.graphql_endpoints.iter().cloned().chain(from_js) {
            if host_of(&u).is_some_and(|h| in_scope(&h)) && !gql.contains(&u) {
                gql.push(u);
            }
        }
        if !gql.is_empty() && !client.is_cancelled() {
            let r = apidocs::probe_graphql(client, &gql).await;
            rep.requests += r.requests;
            rep.api_docs.extend(r.docs);
        }
    }
    classify_hosts(&mut rep, &in_scope);
    rep.findings = build_findings(&rep);
    rep
}

fn advice(id: &str) -> (&'static str, &'static str) {
    let base = id.split(':').next().unwrap_or(id);
    match base {
        "hsts_missing" | "hsts_disabled" | "hsts_short" | "hsts_invalid" | "hsts_preload_invalid" => (
            "T1557",
            "Отдавать Strict-Transport-Security: max-age=31536000; includeSubDomains (после проверки всех поддоменов: preload).",
        ),
        "cors_wildcard_credentials" | "cors_wildcard" | "cors_null_origin" => (
            "T1190",
            "Разрешать CORS только для явного списка доверенных источников; не сочетать * или null с Allow-Credentials.",
        ),
        "cookie_flags" => (
            "T1539",
            "Выставить сессионным кукам HttpOnly, Secure и SameSite=Lax/Strict (или префикс __Host-).",
        ),
        "version_disclosure" => (
            "T1592.002",
            "Скрыть версии в Server/X-Powered-By (server_tokens off, expose_php Off, удалить X-AspNet-Version).",
        ),
        "clickjacking" | "xfo_allow_from" | "xfo_invalid" => (
            "T1189",
            "Добавить Content-Security-Policy: frame-ancestors 'self' (и X-Frame-Options: SAMEORIGIN для старых браузеров).",
        ),
        "nosniff_missing" => ("", "Добавить X-Content-Type-Options: nosniff."),
        "referrer_policy_missing" | "referrer_policy_unsafe" => (
            "",
            "Задать Referrer-Policy: strict-origin-when-cross-origin.",
        ),
        "permissions_policy_missing" => (
            "",
            "Задать Permissions-Policy, запрещающую ненужные API (camera=(), microphone=(), geolocation=()).",
        ),
        _ if base.starts_with("csp_") => (
            "T1059.007",
            "Ужесточить CSP: script-src с nonce/hash и 'strict-dynamic' без 'unsafe-inline'/'unsafe-eval'/*, object-src 'none', base-uri 'self', frame-ancestors.",
        ),
        _ => ("", ""),
    }
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// Evidence of a header finding: the URL and the security headers actually observed on it (cookie
/// values are never kept, only names and flags).
pub fn observed_headers(h: &HeaderAudit) -> String {
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "(нет)".into());
    let hsts = h.hsts.as_ref().map_or_else(
        || "(нет)".to_string(),
        |x| {
            let mut p = vec![x
                .max_age
                .map_or_else(|| "max-age ?".to_string(), |a| format!("max-age={a}"))];
            if x.include_subdomains {
                p.push("includeSubDomains".into());
            }
            if x.preload {
                p.push("preload".into());
            }
            p.join("; ")
        },
    );
    let csp = if h.csp.is_some() {
        if h.csp_source.is_empty() {
            "есть".to_string()
        } else {
            h.csp_source.clone()
        }
    } else {
        "(нет)".into()
    };
    let mut out = vec![
        format!("URL: {}", h.url),
        format!("Strict-Transport-Security: {hsts}"),
        format!("Content-Security-Policy: {csp}"),
        format!("X-Frame-Options: {}", opt(&h.x_frame_options)),
        format!("X-Content-Type-Options: {}", opt(&h.x_content_type_options)),
        format!("Referrer-Policy: {}", opt(&h.referrer_policy)),
        format!("Permissions-Policy: {}", opt(&h.permissions_policy)),
    ];
    if !h.cookies.is_empty() {
        let names: Vec<&str> = h.cookies.iter().take(10).map(|c| c.name.as_str()).collect();
        out.push(format!("Set-Cookie: {}", names.join(", ")));
    }
    out.join("\n")
}

/// Builds findings for the report (one per host and issue id; evidence never holds secret
/// values).
pub fn build_findings(r: &WebAuditReport) -> Vec<ReconFinding> {
    let mut out: Vec<ReconFinding> = Vec::new();
    let mut push = |f: ReconFinding| {
        if !out.iter().any(|x| x.rule == f.rule && x.key == f.key) {
            out.push(f);
        }
    };
    // Headers of an archive copy are the archive's, possibly stripped or stale: neither a missing
    // nor a weak header can be attributed to the live site.
    let header_issues = if r.from_archive {
        &[][..]
    } else {
        &r.headers[..]
    };
    for h in header_issues {
        let host = host_of(&h.url).unwrap_or_default();
        for i in &h.issues {
            let base = i.id.split(':').next().unwrap_or(&i.id);
            let mut f = ReconFinding::new(
                &format!("recon.web.{base}"),
                format!("{host}|{}", i.id),
                i.title.clone(),
                i.sev,
                &host,
            );
            let (mitre, rec) = advice(&i.id);
            f.mitre = mitre.into();
            f.recommendation = rec.into();
            f.description = i.detail.clone();
            f.evidence = observed_headers(h);
            f.url = Some(h.url.clone());
            f.tags.push("headers".into());
            push(f);
        }
    }
    let main_host = r
        .headers
        .first()
        .and_then(|h| host_of(&h.url))
        .unwrap_or_default();
    let staging: Vec<&CspDomain> = r
        .csp_domains
        .iter()
        .filter(|d| d.hint == "staging")
        .collect();
    if !r.csp_domains.is_empty() {
        let list: Vec<String> = r
            .csp_domains
            .iter()
            .take(30)
            .map(|d| {
                format!(
                    "{}{}{} [{}]{}",
                    if d.wildcard { "*." } else { "" },
                    d.host,
                    if d.in_scope { " (в скоупе)" } else { "" },
                    d.directives.join(","),
                    if d.hint.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", d.hint)
                    }
                )
            })
            .collect();
        let mut f = ReconFinding::new(
            "recon.web.csp_domains",
            &main_host,
            "CSP раскрывает связанные домены",
            if staging.is_empty() {
                Severity::Info
            } else {
                Severity::Low
            },
            &main_host,
        );
        f.mitre = "T1590.001".into();
        f.description = format!(
            "Политика CSP перечисляет {} хостов: API, тестовые стенды и сторонние сервисы. Хосты вне скоупа: только кандидаты, запросы к ним не выполнялись.",
            r.csp_domains.len()
        );
        if !staging.is_empty() {
            f.description.push_str(&format!(
                " Похожие на тестовые/внутренние: {}.",
                staging
                    .iter()
                    .map(|d| d.host.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        f.recommendation = "Убрать из боевой CSP тестовые и внутренние хосты; держать отдельные политики для стендов.".into();
        f.evidence = list.join("; ");
        f.tags.push("csp".into());
        push(f);
    }
    for m in &r.source_maps {
        let host = host_of(&m.script_url).unwrap_or_else(|| main_host.clone());
        let mut f = ReconFinding::new(
            "recon.web.sourcemap",
            format!(
                "{host}|{}",
                if m.map_url == "data:" {
                    &m.script_url
                } else {
                    &m.map_url
                }
            ),
            "Открытая карта исходников JavaScript",
            if m.has_content || !m.local_paths.is_empty() {
                Severity::Medium
            } else {
                Severity::Low
            },
            &host,
        );
        f.mitre = "T1592.002".into();
        f.description = format!(
            "Source map раскрывает исходную структуру фронтенда: {} файлов{}, пакетов npm: {}.",
            m.sources_total,
            if m.has_content {
                " с исходным кодом (sourcesContent)"
            } else {
                ""
            },
            m.packages.len()
        );
        f.recommendation = "Не публиковать .map на боевом сайте (hidden-source-map / удалить при деплое) или закрыть доступ к ним.".into();
        let mut ev = Vec::new();
        if !m.packages.is_empty() {
            ev.push(format!(
                "Пакеты: {}",
                m.packages
                    .iter()
                    .take(15)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !m.local_paths.is_empty() {
            ev.push(format!(
                "Локальные пути: {}",
                m.local_paths
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !m.urls.is_empty() {
            ev.push(format!(
                "URL в коде: {}",
                m.urls
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if m.truncated {
            ev.push("разобрано частично (лимит размера)".into());
        }
        f.evidence = ev.join("; ");
        f.url = (m.map_url != "data:").then(|| m.map_url.clone());
        f.tags.push("sourcemap".into());
        push(f);
        for s in &m.secrets {
            let mut f = ReconFinding::new(
                "recon.web.sourcemap_secret",
                format!("{host}|{}", s.fingerprint),
                format!("Секрет в исходниках source map: {}", s.title),
                s.sev,
                &host,
            );
            f.category = "secrets".into();
            f.mitre = "T1552.001".into();
            f.description =
                "В sourcesContent карты исходников найден секрет (значение замаскировано).".into();
            f.recommendation = "Отозвать и перевыпустить ключ, убрать секреты из клиентского кода, удалить .map с сайта.".into();
            f.evidence = format!("{} (строка {}): {}", s.masked, s.line, s.context);
            f.url = (m.map_url != "data:").then(|| m.map_url.clone());
            f.tags.push("sourcemap".into());
            push(f);
        }
    }
    for d in &r.api_docs {
        let host = host_of(&d.url).unwrap_or_else(|| main_host.clone());
        let (title, rec) = match d.kind {
            ApiDocKind::OpenApi => ("Открытая спецификация API (Swagger/OpenAPI)", "Закрыть спецификацию авторизацией или не публиковать её на боевом контуре; проверить операции без авторизации."),
            ApiDocKind::SwaggerUi => ("Открытый Swagger UI", "Отключить Swagger UI в продуктиве или закрыть его авторизацией/списком IP."),
            ApiDocKind::Graphql => ("Включена интроспекция GraphQL", "Отключить introspection в продуктиве, ограничить глубину/стоимость запросов."),
            ApiDocKind::Actuator => ("Открыт Spring Boot Actuator", "Оставить наружу только health без деталей (management.endpoints.web.exposure.include=health), остальное: на отдельный порт/за авторизацию."),
            ApiDocKind::OpenidConfiguration => ("Конфигурация OpenID Connect", "Публична по стандарту; проверить, что динамическая регистрация клиентов и implicit flow отключены, если не нужны."),
        };
        let mut f = ReconFinding::new(
            &format!("recon.web.apidoc_{}", d.kind.id()),
            format!("{host}|{}", d.url),
            title,
            d.sev,
            &host,
        );
        f.mitre = if d.kind == ApiDocKind::Actuator {
            "T1552"
        } else {
            "T1595.003"
        }
        .into();
        f.description = format!("{title}: {}", d.url);
        f.recommendation = rec.into();
        f.evidence = d.summary_lines().join("; ");
        f.url = Some(d.url.clone());
        f.tags.push("apidocs".into());
        push(f);
    }
    for c in &r.cors {
        if !c.reflected {
            continue;
        }
        let host = host_of(&c.url).unwrap_or_default();
        let mut f = ReconFinding::new(
            "recon.web.cors_reflected",
            format!("{host}|{}", c.url),
            if c.allow_credentials {
                "CORS отражает любой Origin вместе с куками"
            } else {
                "CORS отражает любой Origin"
            },
            if c.allow_credentials {
                Severity::High
            } else {
                Severity::Low
            },
            &host,
        );
        f.mitre = "T1190".into();
        f.description = "На запрос с подставным Origin сервер вернул его же в Access-Control-Allow-Origin, любой сайт может читать ответы (с куками пользователя, если разрешены credentials).".into();
        f.recommendation = advice("cors_wildcard").1.into();
        f.evidence = format!(
            "Origin: {} → Access-Control-Allow-Origin: {}{}",
            methods::PROBE_ORIGIN,
            c.allow_origin.as_deref().unwrap_or(""),
            if c.allow_credentials {
                ", Access-Control-Allow-Credentials: true"
            } else {
                ""
            }
        );
        f.url = Some(c.url.clone());
        f.tags.extend(["active".to_string(), "cors".to_string()]);
        push(f);
    }
    for m in &r.methods {
        let host = host_of(&m.url).unwrap_or_default();
        let mut add = |rule: &str, title: &str, sev: Severity, desc: String, ev: String| {
            let mut f = ReconFinding::new(rule, format!("{host}|{}", m.url), title, sev, &host);
            f.mitre = "T1190".into();
            f.description = desc;
            f.evidence = ev;
            f.recommendation = "Разрешить на веб-сервере только нужные методы (GET, HEAD, POST); отключить TRACE и WebDAV, если не используются.".into();
            f.url = Some(m.url.clone());
            f.tags.extend(["active".to_string(), "methods".to_string()]);
            push(f);
        };
        if !m.unsafe_advertised.is_empty() {
            add(
                "recon.web.methods_unsafe_allowed",
                "Сервер объявляет изменяющие методы",
                Severity::Medium,
                "OPTIONS/Allow перечисляет методы, изменяющие данные. Наличие проверено только по заголовку: PUT/DELETE не отправлялись.".into(),
                format!("Allow: {}", m.allow.join(", ")),
            );
        }
        if m.trace_reflected {
            add(
                "recon.web.trace_enabled",
                "Включён метод TRACE",
                Severity::Low,
                "TRACE возвращает заголовки запроса (Cross-Site Tracing).".into(),
                format!(
                    "TRACE → HTTP {}, маркерный заголовок отражён",
                    m.trace_status.unwrap_or(0)
                ),
            );
        }
        if m.webdav {
            add(
                "recon.web.webdav",
                "Включён WebDAV",
                Severity::Medium,
                "PROPFIND (Depth: 0) вернул 207 Multi-Status.".into(),
                format!(
                    "PROPFIND → HTTP 207{}",
                    m.dav
                        .as_deref()
                        .map(|d| format!(", DAV: {d}"))
                        .unwrap_or_default()
                ),
            );
        }
    }
    out.sort_by(|a, b| {
        sev_rank(b.sev)
            .cmp(&sev_rank(a.sev))
            .then(a.rule.cmp(&b.rule))
    });
    if r.from_archive {
        for f in &mut out {
            f.tags.push("archive".into());
        }
    }
    out
}

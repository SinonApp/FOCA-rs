//! Exposed API documentation and service endpoints: Swagger/OpenAPI specs and Swagger UI,
//! GraphQL introspection, Spring Boot Actuator and `.well-known/openid-configuration`.
//!
//! * Parsers ([`parse_openapi`], [`parse_swagger_ui`], [`parse_actuator`], [`parse_openid`],
//!   [`parse_graphql`], [`summarize`]) are pure: access class `passive`. `foca-fuzz` reuses
//!   [`summarize`] for its own hits.
//! * [`probe_standard`] sends GET requests to well-known paths of an in-scope site (access
//!   class `standard`, `Access::TouchesTarget`). Every hit is validated by content, so soft-404
//!   pages never count.
//! * [`probe_graphql`] sends one POST with a reduced introspection query (access class
//!   `active`, `Access::Active`), only in the active stage.
//!
//! Actuator `env` values are never kept: only property names, and names that look like
//! secrets are listed separately.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use foca_core::Severity;
use foca_net::{Access, Method, NetClient, NetError, NetRequest};

use crate::webaudit::fetch::{host_denied, read_capped};

/// Request log module.
pub const MODULE: &str = "recon.apidocs";
/// Body limit for specs.
pub const MAX_SPEC_BYTES: u64 = 4 << 20;
/// Body limit for other service endpoints.
pub const MAX_SERVICE_BYTES: u64 = 1 << 20;

/// Paths probed by [`probe_standard`] (GET, standard profile).
pub const STANDARD_PATHS: &[&str] = &[
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/.well-known/openid-configuration",
    "/actuator",
];

/// Spring Boot 1.x paths, probed only when `/actuator` is absent.
pub const LEGACY_ACTUATOR_PATHS: &[&str] = &["/health", "/env", "/mappings"];

/// Actuator endpoints read when listed by `/actuator` (GET only; never `heapdump`, `logfile`,
/// `threaddump`, `jolokia` or `shutdown`).
pub const ACTUATOR_READ: &[&str] = &["health", "env", "mappings"];

/// Default GraphQL endpoint paths for [`probe_graphql`].
pub const GRAPHQL_PATHS: &[&str] = &["/graphql", "/api/graphql"];

/// A reduced introspection query: type and field names only.
pub const INTROSPECTION_QUERY: &str = r#"{"query":"query FocaIntrospection{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind fields{name}}}}"}"#;

/// Kind of exposed documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiDocKind {
    OpenApi,
    SwaggerUi,
    Graphql,
    Actuator,
    OpenidConfiguration,
}

impl ApiDocKind {
    pub fn id(self) -> &'static str {
        match self {
            ApiDocKind::OpenApi => "openapi",
            ApiDocKind::SwaggerUi => "swagger_ui",
            ApiDocKind::Graphql => "graphql",
            ApiDocKind::Actuator => "actuator",
            ApiDocKind::OpenidConfiguration => "openid_configuration",
        }
    }
}

/// A validated hit with a parsed summary (no secret values).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiDoc {
    pub kind: ApiDocKind,
    pub url: String,
    pub title: Option<String>,
    /// `swagger 2.0`, `openapi 3.0.1`, Actuator endpoint name, GraphQL root types.
    pub spec_version: Option<String>,
    /// `info.version` of the API.
    pub api_version: Option<String>,
    /// Paths (OpenAPI), request mappings (Actuator), types (GraphQL).
    pub endpoints: usize,
    /// Operations (OpenAPI), query fields (GraphQL), env properties (Actuator).
    pub operations: usize,
    /// Security schemes (`apiKey`, `oauth2`, `http bearer`, …).
    pub auth: Vec<String>,
    /// Operations without any security requirement (OpenAPI only).
    pub unauthenticated: usize,
    /// Hosts and base URLs named by the document.
    pub hosts: Vec<String>,
    /// Names worth showing (Actuator endpoints, mutations, env property names).
    pub names: Vec<String>,
    /// Env property names that look like secrets (values are never kept).
    pub secret_names: Vec<String>,
    /// The body was cut at the size limit or not fully parsed.
    pub truncated: bool,
    pub sev: Severity,
}

impl ApiDoc {
    fn new(kind: ApiDocKind, url: &str, sev: Severity) -> ApiDoc {
        ApiDoc {
            kind,
            url: url.into(),
            title: None,
            spec_version: None,
            api_version: None,
            endpoints: 0,
            operations: 0,
            auth: Vec::new(),
            unauthenticated: 0,
            hosts: Vec::new(),
            names: Vec::new(),
            secret_names: Vec::new(),
            truncated: false,
            sev,
        }
    }

    /// Short evidence lines (values already masked or absent).
    pub fn summary_lines(&self) -> Vec<String> {
        let mut l = Vec::new();
        if let Some(t) = &self.title {
            l.push(format!("Название: {t}"));
        }
        if let Some(v) = &self.spec_version {
            l.push(format!("Формат: {v}"));
        }
        if let Some(v) = &self.api_version {
            l.push(format!("Версия API: {v}"));
        }
        match self.kind {
            ApiDocKind::OpenApi => {
                l.push(format!(
                    "Путей: {}, операций: {}, без авторизации: {}",
                    self.endpoints, self.operations, self.unauthenticated
                ));
                l.push(if self.auth.is_empty() {
                    "Схемы авторизации: нет".into()
                } else {
                    format!("Схемы авторизации: {}", self.auth.join(", "))
                });
            }
            ApiDocKind::Graphql => l.push(format!(
                "Типов: {}, полей Query: {}",
                self.endpoints, self.operations
            )),
            ApiDocKind::Actuator if self.operations > 0 => l.push(format!(
                "Свойств окружения: {} (значения не сохраняются)",
                self.operations
            )),
            ApiDocKind::Actuator if self.endpoints > 0 => {
                l.push(format!("Маршрутов приложения: {}", self.endpoints))
            }
            _ => {}
        }
        if !self.names.is_empty() {
            l.push(clip_list(&self.names, 20));
        }
        if !self.secret_names.is_empty() {
            l.push(format!(
                "Похожие на секреты свойства: {}",
                clip_list(&self.secret_names, 20)
            ));
        }
        if !self.hosts.is_empty() {
            l.push(format!("Хосты: {}", clip_list(&self.hosts, 10)));
        }
        if self.truncated {
            l.push("Ответ разобран частично (лимит размера)".into());
        }
        l
    }
}

fn clip_list(v: &[String], n: usize) -> String {
    let mut s = v.iter().take(n).cloned().collect::<Vec<_>>().join(", ");
    if v.len() > n {
        s.push_str(&format!(" … (+{})", v.len() - n));
    }
    s
}

fn json(body: &[u8]) -> Option<Value> {
    let t = String::from_utf8_lossy(body);
    serde_json::from_str(t.trim_start_matches('\u{feff}').trim()).ok()
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(|x| x.chars().take(120).collect())
}

const HTTP_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Parses a Swagger 2.0 / OpenAPI 3.x JSON spec. A truncated body is recognised by its
/// version field and paths are counted approximately.
pub fn parse_openapi(url: &str, body: &[u8]) -> Option<ApiDoc> {
    let Some(v) = json(body) else {
        let t = String::from_utf8_lossy(&body[..body.len().min(MAX_SPEC_BYTES as usize)]);
        let mut head_end = t.len().min(4096);
        while head_end > 0 && !t.is_char_boundary(head_end) {
            head_end -= 1;
        }
        let head = &t[..head_end];
        let ver = ["\"swagger\"", "\"openapi\""].iter().find_map(|k| {
            let i = head.find(k)?;
            let rest = head[i + k.len()..]
                .trim_start()
                .strip_prefix(':')?
                .trim_start();
            let rest = rest.strip_prefix('"')?;
            Some(format!(
                "{} {}",
                &k[1..k.len() - 1],
                rest.split('"').next()?
            ))
        })?;
        let mut d = ApiDoc::new(ApiDocKind::OpenApi, url, Severity::Medium);
        d.spec_version = Some(ver);
        d.truncated = true;
        d.endpoints = t.matches("\":{\"").count().min(t.matches("\"/").count());
        return Some(d);
    };
    let ver = s(&v, "swagger")
        .map(|x| format!("swagger {x}"))
        .or_else(|| s(&v, "openapi").map(|x| format!("openapi {x}")))?;
    let paths = v.get("paths").and_then(|p| p.as_object());
    if paths.is_none() && v.get("info").is_none() {
        return None;
    }
    let mut d = ApiDoc::new(ApiDocKind::OpenApi, url, Severity::Medium);
    d.spec_version = Some(ver);
    if let Some(i) = v.get("info") {
        d.title = s(i, "title");
        d.api_version = s(i, "version");
    }
    let global_sec = v
        .get("security")
        .and_then(|x| x.as_array())
        .is_some_and(|a| !a.is_empty());
    let schemes = v
        .get("securityDefinitions")
        .or_else(|| v.pointer("/components/securitySchemes"))
        .and_then(|x| x.as_object());
    if let Some(m) = schemes {
        for (name, sch) in m {
            let t = s(sch, "type").unwrap_or_default();
            let extra = s(sch, "scheme")
                .or_else(|| s(sch, "in"))
                .map(|x| format!(" {x}"))
                .unwrap_or_default();
            d.auth.push(format!("{name} ({t}{extra})"));
        }
    }
    if let Some(p) = paths {
        d.endpoints = p.len();
        for item in p.values() {
            let Some(ops) = item.as_object() else {
                continue;
            };
            for (m, op) in ops {
                if !HTTP_METHODS.contains(&m.to_ascii_lowercase().as_str()) {
                    continue;
                }
                d.operations += 1;
                let op_sec = op.get("security").and_then(|x| x.as_array());
                let open = match op_sec {
                    Some(a) => {
                        a.is_empty()
                            || a.iter()
                                .any(|r| r.as_object().is_some_and(|o| o.is_empty()))
                    }
                    None => !global_sec,
                };
                if open {
                    d.unauthenticated += 1;
                }
            }
        }
    }
    let mut hosts = BTreeSet::new();
    if let Some(h) = s(&v, "host") {
        hosts.insert(format!("{h}{}", s(&v, "basePath").unwrap_or_default()));
    }
    if let Some(a) = v.get("servers").and_then(|x| x.as_array()) {
        for sv in a.iter().take(20) {
            if let Some(u) = s(sv, "url") {
                hosts.insert(u);
            }
        }
    }
    d.hosts = hosts.into_iter().collect();
    if d.operations > 0 && d.unauthenticated == d.operations {
        d.sev = Severity::High;
    }
    Some(d)
}

/// Recognises a Swagger UI page and returns the spec URLs it loads (relative to `url`).
pub fn parse_swagger_ui(url: &str, html: &str) -> Option<(ApiDoc, Vec<String>)> {
    let l = html.to_ascii_lowercase();
    if !(l.contains("swagger-ui")
        && (l.contains("swaggeruibundle")
            || l.contains("swagger-ui.css")
            || l.contains("swagger-ui-bundle")))
    {
        return None;
    }
    let base = url::Url::parse(url).ok();
    let mut specs = Vec::new();
    // `url: "/v2/api-docs"` and `urls: [{url: "...", name: ...}]`.
    let mut from = 0;
    while let Some(i) = html[from..].find("url") {
        let at = from + i + 3;
        from = at;
        let rest =
            html[at..].trim_start_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        let val = rest[1..].split(q).next().unwrap_or("");
        if val.is_empty() || val.len() > 300 || val.contains(' ') {
            continue;
        }
        if let Some(u) = base.as_ref().and_then(|b| b.join(val).ok()) {
            let u = u.to_string();
            if !specs.contains(&u) && specs.len() < 10 {
                specs.push(u);
            }
        }
    }
    let mut d = ApiDoc::new(ApiDocKind::SwaggerUi, url, Severity::Low);
    d.hosts = specs.clone();
    Some((d, specs))
}

fn secret_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "apikey",
        "api-key",
        "api_key",
        "private",
        "access-key",
        "accesskey",
    ]
    .iter()
    .any(|k| n.contains(k))
        || n.ends_with(".key")
}

/// Parses Spring Boot Actuator responses: the `/actuator` index (`_links`), `env`
/// (property names only), `health` and `mappings`. `path` is the request path.
pub fn parse_actuator(url: &str, path: &str, body: &[u8]) -> Option<ApiDoc> {
    let v = json(body)?;
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    let last = p.rsplit('/').next().unwrap_or("");
    if let Some(links) = v.get("_links").and_then(|x| x.as_object()) {
        if !links
            .keys()
            .any(|k| k == "self" || k == "health" || k == "env")
        {
            return None;
        }
        let mut d = ApiDoc::new(ApiDocKind::Actuator, url, Severity::Medium);
        d.spec_version = Some("actuator".into());
        d.names = links.keys().filter(|k| *k != "self").cloned().collect();
        let dangerous = [
            "env",
            "heapdump",
            "jolokia",
            "logfile",
            "threaddump",
            "httptrace",
            "shutdown",
            "gateway",
            "configprops",
        ];
        if d.names.iter().any(|n| dangerous.contains(&n.as_str())) {
            d.sev = Severity::High;
        }
        return Some(d);
    }
    if last == "env" {
        let sources = v.get("propertySources").and_then(|x| x.as_array());
        let mut names = BTreeSet::new();
        match sources {
            // Spring Boot 2+: propertySources[].properties{name: {value}}.
            Some(a) => {
                for src in a {
                    if let Some(props) = src.get("properties").and_then(|x| x.as_object()) {
                        names.extend(props.keys().cloned());
                    }
                }
            }
            // Spring Boot 1.x: {"profiles":[], "<source>": {name: value}}.
            None => {
                let o = v.as_object()?;
                if !o.contains_key("profiles") && !o.contains_key("activeProfiles") {
                    return None;
                }
                for (k, sv) in o {
                    if let Some(m) = sv.as_object() {
                        if k != "profiles" {
                            names.extend(m.keys().cloned());
                        }
                    }
                }
            }
        }
        let mut d = ApiDoc::new(ApiDocKind::Actuator, url, Severity::High);
        d.spec_version = Some("actuator env".into());
        d.operations = names.len();
        d.secret_names = names
            .iter()
            .filter(|n| secret_like(n))
            .take(50)
            .cloned()
            .collect();
        if !d.secret_names.is_empty() {
            d.sev = Severity::Critical;
        }
        return Some(d);
    }
    if last == "mappings" {
        let t = String::from_utf8_lossy(body);
        let n = t
            .matches("\"predicate\"")
            .count()
            .max(t.matches("\"bean\"").count());
        if n == 0 && v.get("contexts").is_none() {
            return None;
        }
        let mut d = ApiDoc::new(ApiDocKind::Actuator, url, Severity::Medium);
        d.spec_version = Some("actuator mappings".into());
        d.endpoints = n;
        return Some(d);
    }
    if last == "health" {
        let st = s(&v, "status")?;
        if !matches!(st.as_str(), "UP" | "DOWN" | "OUT_OF_SERVICE" | "UNKNOWN") {
            return None;
        }
        let mut d = ApiDoc::new(ApiDocKind::Actuator, url, Severity::Info);
        d.spec_version = Some("actuator health".into());
        if let Some(c) = v
            .get("components")
            .or_else(|| v.get("details"))
            .and_then(|x| x.as_object())
        {
            d.names = c.keys().cloned().collect();
            d.sev = Severity::Low;
        }
        d.title = Some(format!("status {st}"));
        return Some(d);
    }
    None
}

/// Parses `.well-known/openid-configuration`.
pub fn parse_openid(url: &str, body: &[u8]) -> Option<ApiDoc> {
    let v = json(body)?;
    let issuer = s(&v, "issuer")?;
    if v.get("authorization_endpoint").is_none() && v.get("jwks_uri").is_none() {
        return None;
    }
    let mut d = ApiDoc::new(ApiDocKind::OpenidConfiguration, url, Severity::Info);
    d.title = Some(issuer.clone());
    let mut hosts = BTreeSet::new();
    if let Some(o) = v.as_object() {
        for (k, x) in o {
            if k.ends_with("_endpoint") || k == "jwks_uri" || k == "issuer" {
                if let Some(h) = x
                    .as_str()
                    .and_then(|u| url::Url::parse(u).ok())
                    .and_then(|u| u.host_str().map(str::to_string))
                {
                    hosts.insert(h);
                }
            }
        }
    }
    d.hosts = hosts.into_iter().collect();
    let list = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let grants = list("grant_types_supported");
    if !grants.is_empty() {
        d.names.push(format!("grant types: {}", grants.join(" ")));
    }
    d.auth = list("token_endpoint_auth_methods_supported");
    if v.get("registration_endpoint").is_some() {
        d.names
            .push("registration_endpoint (динамическая регистрация клиентов)".into());
        d.sev = Severity::Low;
    }
    if list("response_types_supported")
        .iter()
        .any(|r| r.split(' ').any(|p| p == "token"))
    {
        d.names.push("implicit flow (response_type=token)".into());
        d.sev = Severity::Low;
    }
    Some(d)
}

/// Parses a GraphQL introspection response.
pub fn parse_graphql(url: &str, body: &[u8]) -> Option<ApiDoc> {
    let v = json(body)?;
    let schema = v.pointer("/data/__schema")?;
    let types = schema.get("types").and_then(|x| x.as_array())?;
    let mut d = ApiDoc::new(ApiDocKind::Graphql, url, Severity::Medium);
    d.endpoints = types
        .iter()
        .filter(|t| !s(t, "name").unwrap_or_default().starts_with("__"))
        .count();
    let root = |k: &str| {
        schema
            .pointer(&format!("/{k}/name"))
            .and_then(|x| x.as_str())
            .map(str::to_string)
    };
    let fields = |name: &Option<String>| -> Vec<String> {
        let Some(n) = name else { return Vec::new() };
        types
            .iter()
            .find(|t| t.get("name").and_then(|x| x.as_str()) == Some(n))
            .and_then(|t| t.get("fields").and_then(|x| x.as_array()))
            .map(|a| a.iter().filter_map(|f| s(f, "name")).collect())
            .unwrap_or_default()
    };
    let q = root("queryType");
    let m = root("mutationType");
    d.operations = fields(&q).len();
    let muts = fields(&m);
    d.spec_version = Some(format!(
        "query {}{}",
        d.operations,
        if m.is_some() {
            format!(", mutation {}", muts.len())
        } else {
            String::new()
        }
    ));
    d.names = muts
        .into_iter()
        .take(30)
        .map(|n| format!("mutation {n}"))
        .collect();
    Some(d)
}

/// Dispatches a response body to the matching parser by path and content (used by
/// `foca-fuzz` for its hits).
pub fn summarize(url: &str, path: &str, body: &[u8]) -> Option<ApiDoc> {
    let p = path.to_ascii_lowercase();
    if p.ends_with("/openid-configuration") {
        return parse_openid(url, body);
    }
    if p.contains("actuator") || LEGACY_ACTUATOR_PATHS.contains(&p.trim_end_matches('/')) {
        if let Some(d) = parse_actuator(url, &p, body) {
            return Some(d);
        }
    }
    if p.contains("graphql") {
        if let Some(d) = parse_graphql(url, body) {
            return Some(d);
        }
    }
    let head = String::from_utf8_lossy(&body[..body.len().min(2048)]).to_ascii_lowercase();
    if head.trim_start().starts_with('<') {
        return parse_swagger_ui(url, &String::from_utf8_lossy(body)).map(|(d, _)| d);
    }
    if head.contains("\"swagger\"") || head.contains("\"openapi\"") {
        return parse_openapi(url, body);
    }
    None
}

async fn get(client: &NetClient, url: &str, limit: u64) -> Result<(u16, Vec<u8>, bool), NetError> {
    let req = NetRequest::get(url, MODULE, Access::TouchesTarget)?;
    let r = client.send(req).await?;
    let st = r.status();
    if !(200..300).contains(&st) {
        r.abort();
        return Ok((st, Vec::new(), false));
    }
    let (b, cut) = read_capped(r, limit).await?;
    Ok((st, b, cut))
}

fn join(base: &str, path: &str) -> Option<String> {
    url::Url::parse(base)
        .ok()?
        .join(path)
        .ok()
        .map(|u| u.to_string())
}

/// Result of a probe run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub docs: Vec<ApiDoc>,
    pub requests: usize,
    pub errors: Vec<String>,
}

/// Standard profile: GET of [`STANDARD_PATHS`] (plus Swagger UI spec URLs and listed Actuator
/// endpoints) on the site `base` (`https://host/`). The host must be in scope (enforced by
/// `NetClient`).
pub async fn probe_standard(client: &NetClient, base: &str) -> ProbeResult {
    let mut out = ProbeResult::default();
    let mut queue: Vec<String> = STANDARD_PATHS
        .iter()
        .filter_map(|p| join(base, p))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut actuator = false;
    let mut legacy = false;
    let mut i = 0;
    loop {
        if i == queue.len() && !actuator && !legacy {
            // Spring Boot 1.x root endpoints only when there is no `/actuator`.
            legacy = true;
            queue.extend(LEGACY_ACTUATOR_PATHS.iter().filter_map(|p| join(base, p)));
        }
        if i >= queue.len() || i >= 40 || client.is_cancelled() {
            break;
        }
        let u = queue[i].clone();
        i += 1;
        if !seen.insert(u.clone()) {
            continue;
        }
        let path = url::Url::parse(&u)
            .map(|x| x.path().to_string())
            .unwrap_or_default();
        let limit = if path.contains("actuator") || path.contains("openid") || legacy {
            MAX_SERVICE_BYTES
        } else {
            MAX_SPEC_BYTES
        };
        out.requests += 1;
        let (st, body, truncated) = match get(client, &u, limit).await {
            Ok(x) => x,
            Err(e) => {
                out.errors.push(format!("{path}: {e}"));
                if host_denied(&e) {
                    break;
                }
                continue;
            }
        };
        if st >= 300 || body.is_empty() {
            continue;
        }
        if let Some((mut d, specs)) = parse_swagger_ui(&u, &String::from_utf8_lossy(&body)) {
            d.truncated = truncated;
            out.docs.push(d);
            // Only same-origin specs: the UI may point to a third-party host.
            queue.extend(specs.into_iter().filter(|s| same_origin(s, base)));
            continue;
        }
        let parsed = if legacy {
            parse_actuator(&u, &path, &body)
        } else {
            summarize(&u, &path, &body)
        };
        let Some(mut d) = parsed else { continue };
        d.truncated |= truncated;
        if d.kind == ApiDocKind::Actuator && d.spec_version.as_deref() == Some("actuator") {
            actuator = true;
            for n in ACTUATOR_READ {
                if d.names.iter().any(|x| x == n) {
                    if let Some(x) = join(base, &format!("/actuator/{n}")) {
                        queue.push(x);
                    }
                }
            }
        }
        out.docs.push(d);
    }
    out
}

fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// Active profile: one POST with [`INTROSPECTION_QUERY`] to each GraphQL endpoint
/// (`Access::Active`, redirects not followed).
pub async fn probe_graphql(client: &NetClient, endpoints: &[String]) -> ProbeResult {
    let mut out = ProbeResult::default();
    for u in endpoints.iter().take(5) {
        if client.is_cancelled() {
            break;
        }
        let req = match NetRequest::new(
            Method::POST,
            u,
            MODULE,
            Access::active("graphql_introspection"),
        ) {
            Ok(r) => r
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .body(INTROSPECTION_QUERY.as_bytes().to_vec())
                .no_redirects()
                .retries(0),
            Err(e) => {
                out.errors.push(e.to_string());
                continue;
            }
        };
        out.requests += 1;
        match client.send(req).await {
            Ok(r) if r.is_success() => match read_capped(r, MAX_SPEC_BYTES).await {
                Ok((b, _)) => {
                    if let Some(d) = parse_graphql(u, &b) {
                        out.docs.push(d);
                    }
                }
                Err(e) => out.errors.push(format!("{u}: {e}")),
            },
            Ok(r) => r.abort(),
            Err(e) => {
                out.errors.push(format!("{u}: {e}"));
                if host_denied(&e) {
                    break;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_v3_and_v2() {
        let spec = serde_json::json!({
            "openapi": "3.0.1",
            "info": {"title": "Portal API", "version": "2.4"},
            "servers": [{"url": "https://api-stage.contoso.ua/v2"}],
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "paths": {
                "/users": {"get": {"security": [{"bearer": []}]}, "post": {}},
                "/health": {"get": {"security": []}},
                "/x": {"parameters": []}
            }
        });
        let d = parse_openapi("u", &serde_json::to_vec(&spec).unwrap()).unwrap();
        assert_eq!(d.spec_version.as_deref(), Some("openapi 3.0.1"));
        assert_eq!((d.endpoints, d.operations, d.unauthenticated), (3, 3, 2));
        assert_eq!(d.auth, ["bearer (http bearer)"]);
        assert_eq!(d.hosts, ["https://api-stage.contoso.ua/v2"]);
        let v2 = br#"{"swagger":"2.0","info":{"title":"t","version":"1"},"host":"api.contoso.ua","basePath":"/v1","security":[{"k":[]}],"securityDefinitions":{"k":{"type":"apiKey","in":"header"}},"paths":{"/a":{"get":{}}}}"#;
        let d = parse_openapi("u", v2).unwrap();
        assert_eq!(d.unauthenticated, 0);
        assert_eq!(d.hosts, ["api.contoso.ua/v1"]);
        assert!(
            parse_openapi(
                "u",
                br#"{"swagger":"2.0","paths":{"/a":{"get":{}},"/b":{"po"#
            )
            .unwrap()
            .truncated
        );
        assert!(parse_openapi("u", b"{\"name\":\"x\"}").is_none());
    }

    #[test]
    fn actuator_env_keeps_names_only() {
        let env = br#"{"activeProfiles":["prod"],"propertySources":[{"name":"app","properties":{"spring.datasource.password":{"value":"S3cr3tPassw0rd!"},"server.port":{"value":"8080"}}}]}"#;
        let d = parse_actuator("u", "/actuator/env", env).unwrap();
        assert_eq!(d.operations, 2);
        assert_eq!(d.secret_names, ["spring.datasource.password"]);
        assert_eq!(d.sev, Severity::Critical);
        assert!(!serde_json::to_string(&d).unwrap().contains("S3cr3t"));
        let idx = br#"{"_links":{"self":{"href":"x"},"health":{"href":"x"},"env":{"href":"x"}}}"#;
        assert_eq!(
            parse_actuator("u", "/actuator", idx).unwrap().names,
            ["env", "health"]
        );
        assert!(parse_actuator("u", "/health", br#"{"status":"UP"}"#).is_some());
        assert!(parse_actuator("u", "/health", br#"{"status":"ok"}"#).is_none());
    }

    #[test]
    fn openid_graphql_swagger_ui() {
        let oid = br#"{"issuer":"https://sso.contoso.ua/realms/main","authorization_endpoint":"https://sso.contoso.ua/auth","registration_endpoint":"https://sso.contoso.ua/reg","response_types_supported":["code","token id_token"]}"#;
        let d = summarize("u", "/.well-known/openid-configuration", oid).unwrap();
        assert_eq!(d.hosts, ["sso.contoso.ua"]);
        assert_eq!(d.sev, Severity::Low);
        let gql = br#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"me"},{"name":"users"}]},{"name":"Mutation","kind":"OBJECT","fields":[{"name":"deleteUser"}]},{"name":"__Type","kind":"OBJECT","fields":[]}]}}}"#;
        let d = parse_graphql("u", gql).unwrap();
        assert_eq!((d.endpoints, d.operations), (2, 2));
        assert_eq!(d.names, ["mutation deleteUser"]);
        let html = r#"<html><link rel="stylesheet" href="swagger-ui.css"><script>window.ui = SwaggerUIBundle({ url: "/v3/api-docs", dom_id: '#swagger-ui' })</script>"#;
        let (_, specs) = parse_swagger_ui("https://a.ua/swagger-ui/index.html", html).unwrap();
        assert_eq!(specs, ["https://a.ua/v3/api-docs"]);
        assert!(summarize("u", "/swagger.json", b"<html>Not found</html>").is_none());
    }

    #[test]
    fn parse_openapi_truncated_utf8_boundary_does_not_panic() {
        let mut raw = br#"{"openapi":"3.0.1","info":{"title":""#.to_vec();
        raw.extend(std::iter::repeat_n(b'a', 4059));
        // 4-byte emoji straddling byte index 4096 inside truncated invalid JSON
        raw.extend_from_slice("🚀".as_bytes());
        raw.extend_from_slice(br#"","/users":{"get":{}"#);
        let d = parse_openapi("https://ex.com/openapi.json", &raw).unwrap();
        assert_eq!(d.spec_version.as_deref(), Some("openapi 3.0.1"));
        assert!(d.truncated);
    }
}

//! Combined analysis: [`analyze_site`] runs every module over already downloaded data and
//! produces [`ReconFinding`]s.
//!
//! Typical engine integration:
//! 1. fetch the home page (and 1-N pages), the favicon and page scripts through `NetClient`
//!    (`Access::TouchesTarget`) into a [`ReconInput`];
//! 2. optionally run [`crate::wellknown::harvest_from_archive`] (Wayback CDX) and
//!    [`crate::grepapp::search`], storing results in `ReconInput::wellknown` / `grepapp`;
//! 3. `let mut rep = analyze_site(&input);`
//! 4. if the user opted in, [`crate::buckets::check_buckets`]`(&client, &mut rep.buckets, &opts)`
//!    followed by `rep.refresh_findings()`;
//! 5. `rep.findings[i].to_finding(now)` converts into the shared finding model.

use std::collections::BTreeSet;

use foca_core::Severity;
use serde::{Deserialize, Serialize};

use crate::buckets::{find_buckets, merge_buckets, Bucket, BucketStatus};
use crate::favicon::{favicon_hash, find_icon_links, FaviconHash, IconLink};
use crate::grepapp::GrepAppResult;
use crate::js::{analyze_js, inline_scripts, JsAnalysis};
use crate::tech::{detect, extract_analytics_ids, AnalyticsId, PageInput, Technology};
use crate::wellknown::WellKnownReport;
use crate::ReconFinding;

/// A downloaded script.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptInput {
    pub url: String,
    pub body: String,
}

/// A downloaded icon.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FaviconInput {
    pub url: String,
    #[serde(with = "foca_core::b64")]
    pub bytes: Vec<u8>,
}

/// Text of a document or page (searched for bucket references).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TextInput {
    pub source: String,
    pub text: String,
}

/// Input of the combined analysis: data that has already been fetched.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReconInput {
    /// Target host (`example.com`), used in findings.
    pub target: String,
    /// Site pages (the first one is treated as the home page).
    pub pages: Vec<PageInput>,
    pub scripts: Vec<ScriptInput>,
    pub favicon: Option<FaviconInput>,
    /// Document text extracted by foca-meta, searched for bucket references.
    pub documents: Vec<TextInput>,
    /// URL list (archive, crawler), searched for buckets.
    pub urls: Vec<String>,
    pub wellknown: Option<WellKnownReport>,
    pub grepapp: Option<GrepAppResult>,
}

/// A favicon hash with its URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaviconResult {
    pub url: String,
    #[serde(flatten)]
    pub hash: FaviconHash,
}

/// Combined recon report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReconReport {
    pub target: String,
    pub favicon: Option<FaviconResult>,
    /// Icon links from the home page (for the caller to download).
    pub icon_links: Vec<IconLink>,
    pub technologies: Vec<Technology>,
    pub analytics_ids: Vec<AnalyticsId>,
    /// One entry per external script plus one for all inline scripts of a page (`<url>#inline`).
    pub js: Vec<JsAnalysis>,
    /// Absolute script URLs from the pages that are candidates for download (not yet passed in
    /// `scripts`).
    pub script_candidates: Vec<String>,
    pub buckets: Vec<Bucket>,
    pub wellknown: Option<WellKnownReport>,
    pub grepapp: Option<GrepAppResult>,
    pub findings: Vec<ReconFinding>,
}

/// Runs the combined analysis (no network access).
pub fn analyze_site(input: &ReconInput) -> ReconReport {
    let mut rep = ReconReport {
        target: input.target.clone(),
        wellknown: input.wellknown.clone(),
        grepapp: input.grepapp.clone(),
        ..Default::default()
    };
    let mut techs: Vec<Technology> = Vec::new();
    let mut ids: BTreeSet<AnalyticsId> = BTreeSet::new();
    let mut bucket_lists = Vec::new();
    let have: BTreeSet<&str> = input.scripts.iter().map(|s| s.url.as_str()).collect();
    for (i, p) in input.pages.iter().enumerate() {
        if i == 0 {
            rep.icon_links = find_icon_links(&p.html, &p.url);
        }
        for t in detect(p) {
            match techs.iter_mut().find(|x| x.name == t.name) {
                Some(e) => {
                    if e.version.is_none() {
                        e.version = t.version;
                        e.outdated = t.outdated;
                    }
                    e.confidence = e.confidence.max(t.confidence);
                }
                None => techs.push(t),
            }
        }
        ids.extend(extract_analytics_ids(&p.html));
        let inl = inline_scripts(&p.html).join("\n;\n");
        if !inl.is_empty() {
            let mut a = analyze_js(&p.url, &inl);
            a.source_url = format!("{}#inline", p.url);
            rep.js.push(a);
        }
        bucket_lists.push(find_buckets(&p.html, &p.url));
        let base = url::Url::parse(&p.url).ok();
        for src in crate::tech::extract_script_srcs(&p.html) {
            let abs = base
                .as_ref()
                .and_then(|b| b.join(&src).ok())
                .map(|u| u.to_string())
                .unwrap_or(src);
            if !have.contains(abs.as_str()) && !rep.script_candidates.contains(&abs) {
                rep.script_candidates.push(abs);
            }
        }
    }
    for s in &input.scripts {
        rep.js.push(analyze_js(&s.url, &s.body));
        ids.extend(extract_analytics_ids(&s.body));
        bucket_lists.push(find_buckets(&s.body, &s.url));
    }
    for d in &input.documents {
        bucket_lists.push(find_buckets(&d.text, &d.source));
    }
    if !input.urls.is_empty() {
        bucket_lists.push(find_buckets(&input.urls.join("\n"), "urls"));
    }
    if let Some(f) = &input.favicon {
        if !f.bytes.is_empty() {
            rep.favicon = Some(FaviconResult {
                url: f.url.clone(),
                hash: favicon_hash(&f.bytes),
            });
        }
    }
    techs.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    rep.technologies = techs;
    rep.analytics_ids = ids.into_iter().collect();
    rep.buckets = merge_buckets(bucket_lists);
    rep.refresh_findings();
    rep
}

fn f(
    rule: &str,
    key: impl Into<String>,
    title: impl Into<String>,
    sev: Severity,
    host: &str,
) -> ReconFinding {
    ReconFinding {
        rule: rule.into(),
        key: key.into(),
        title: title.into(),
        sev,
        category: "web".into(),
        host: host.into(),
        mitre: String::new(),
        description: String::new(),
        recommendation: String::new(),
        evidence: String::new(),
        url: None,
        tags: vec!["recon".into()],
    }
}

impl ReconReport {
    /// Recomputes the findings (e.g. after checking buckets).
    pub fn refresh_findings(&mut self) {
        self.findings = build_findings(self);
    }
}

/// A client key meant for the browser: passed in the query of another site's script URL (unless
/// its JWT claims carry server roles), or a JWT whose claims mark a public client.
fn public_client_key(s: &crate::js::SecretHit, site: &str) -> bool {
    let site = site.split(':').next().unwrap_or(site).to_ascii_lowercase();
    let third_party = s.query_host.as_deref().is_some_and(|h| {
        let base = |x: &str| {
            let p: Vec<&str> = x.rsplitn(3, '.').collect();
            p.iter()
                .take(2)
                .rev()
                .copied()
                .collect::<Vec<_>>()
                .join(".")
        };
        h != site && base(h) != base(&site)
    });
    (third_party && s.key_scope != "secret") || (s.kind == "jwt" && s.key_scope == "client")
}

/// Builds findings with these rules:
/// - `recon.bucket_listing` (high): public bucket listing;
/// - `recon.bucket_missing` (medium): reference to a nonexistent bucket (name takeover);
/// - `recon.bucket_refs` (info): references to cloud storage;
/// - `recon.js_secret` (high/critical; medium for generic, JWT and Google API keys);
/// - `recon.outdated_tech` (medium): outdated version (jQuery, WordPress, PHP, …);
/// - `recon.sourcemap` (low): published source maps;
/// - `recon.robots_hidden` (info): hidden sections in robots.txt;
/// - `recon.code_mentions` (info): the domain in public code (grep.app);
/// - `recon.analytics_pivots`, `recon.favicon` (info): pivots for finding related sites.
pub fn build_findings(r: &ReconReport) -> Vec<ReconFinding> {
    let host = r.target.as_str();
    let mut out = Vec::new();
    // Buckets.
    let mut refs = Vec::new();
    for b in &r.buckets {
        refs.push(format!("{} {}", b.provider.label(), b.name));
        match &b.status {
            BucketStatus::PublicListing { keys, sample } => {
                let mut x = f(
                    "recon.bucket_listing",
                    b.key(),
                    format!(
                        "Публичный листинг бакета {} ({})",
                        b.name,
                        b.provider.label()
                    ),
                    Severity::High,
                    host,
                );
                x.category = "cloud".into();
                x.mitre = "T1530".into();
                x.description = format!("Хранилище отдаёт список объектов без авторизации: {keys} ключей на первой странице. Ссылка найдена в: {}.", b.sources.join(", "));
                x.recommendation = "Закрыть публичный листинг (Block Public Access / private ACL), проверить содержимое на утечки, включить журналирование доступа.".into();
                x.evidence = format!("Примеры ключей: {}", sample.join(", "));
                x.url = b.listing_url();
                out.push(x);
            }
            BucketStatus::NotFound => {
                let mut x = f(
                    "recon.bucket_missing",
                    b.key(),
                    format!("Ссылка на несуществующий бакет {}", b.name),
                    Severity::Medium,
                    host,
                );
                x.category = "cloud".into();
                x.mitre = "T1584".into();
                x.description = format!("Сайт/документы ссылаются на бакет {} ({}), которого нет: имя может зарегистрировать посторонний и подменить контент.", b.name, b.provider.label());
                x.recommendation =
                    "Удалить ссылки или создать бакет с этим именем в своём аккаунте.".into();
                x.evidence = b.evidence.join(", ");
                out.push(x);
            }
            _ => {}
        }
    }
    if !refs.is_empty() {
        let mut x = f(
            "recon.bucket_refs",
            host,
            format!("Ссылки на облачные хранилища: {}", refs.len()),
            Severity::Info,
            host,
        );
        x.category = "cloud".into();
        x.mitre = "T1593".into();
        x.description = "На страницах/в документах есть ссылки на облачные хранилища: их стоит проверить на публичный доступ.".into();
        x.evidence = refs.join("; ");
        out.push(x);
    }
    // Secrets in JS.
    let mut seen = BTreeSet::new();
    for js in &r.js {
        for s in &js.secrets {
            if !seen.insert(s.fingerprint.clone()) {
                continue;
            }
            let sev = match s.kind.as_str() {
                "generic_secret" | "jwt" | "google_api_key" => Severity::Medium,
                _ if s.sev.rank() < Severity::High.rank() => Severity::High,
                _ => s.sev,
            };
            if sev == Severity::Medium && public_client_key(s, host) {
                let mut x = f(
                    "recon.js_secret",
                    &s.fingerprint,
                    format!("Публичный ключ стороннего виджета в JS: {}", s.title),
                    Severity::Info,
                    host,
                );
                x.mitre = "T1552.001".into();
                x.description = format!(
                    "В общедоступном JavaScript ({}, строка {}) найден публичный клиентский ключ стороннего виджета{} (маска {}). Такие ключи передаются в браузер намеренно.",
                    js.source_url,
                    s.line,
                    s.query_host
                        .as_deref()
                        .map(|h| format!(" ({h})"))
                        .unwrap_or_default(),
                    s.masked
                );
                x.recommendation = "Публичный клиентский ключ стороннего виджета: проверьте, что он ограничен доменом.".into();
                x.evidence = s.context.clone();
                x.url = Some(js.source_url.clone());
                x.tags.push(s.kind.clone());
                x.tags.push("public_key".into());
                out.push(x);
                continue;
            }
            let mut x = f(
                "recon.js_secret",
                &s.fingerprint,
                format!("Секрет в JS: {}", s.title),
                sev,
                host,
            );
            x.mitre = "T1552.001".into();
            x.description = format!("В общедоступном JavaScript ({}, строка {}) найдено значение, похожее на «{}» (маска {}).", js.source_url, s.line, s.title, s.masked);
            x.recommendation = "Отозвать и перевыпустить ключ, убрать секреты из клиентского кода (выдавать через бэкенд), проверить журналы использования.".into();
            x.evidence = s.context.clone();
            x.url = Some(js.source_url.clone());
            x.tags.push(s.kind.clone());
            out.push(x);
        }
    }
    // Outdated technologies.
    for t in &r.technologies {
        if let Some(why) = &t.outdated {
            let ver = t.version.clone().unwrap_or_default();
            let mut x = f(
                "recon.outdated_tech",
                format!("{}:{ver}", t.name),
                format!("Устаревшая версия {} {ver}", t.name)
                    .trim_end()
                    .to_string(),
                Severity::Medium,
                host,
            );
            x.mitre = "T1190".into();
            x.description = format!(
                "{} ({}): {why}. Старые версии содержат публично известные уязвимости.",
                t.name, t.category
            );
            x.recommendation = "Обновить компонент до поддерживаемой версии; скрыть версию в заголовках/метатегах.".into();
            x.evidence = t.evidence.join("; ");
            out.push(x);
        }
    }
    // Source maps
    let mut map_seen = BTreeSet::new();
    let maps: Vec<String> =
        r.js.iter()
            .flat_map(|j| j.endpoints.iter())
            .filter(|e| e.kind == "sourcemap")
            .map(|e| e.resolved.clone().unwrap_or_else(|| e.raw.clone()))
            .filter(|m| map_seen.insert(m.clone()))
            .collect();
    if !maps.is_empty() {
        let mut x = f(
            "recon.sourcemap",
            host,
            format!("Опубликованы source map JS: {}", maps.len()),
            Severity::Low,
            host,
        );
        x.mitre = "T1592".into();
        x.description =
            "Карты исходников раскрывают исходный код фронтенда, внутренние пути и комментарии."
                .into();
        x.recommendation = "Не выкладывать *.map в продакшен или ограничить доступ к ним.".into();
        x.evidence = maps.into_iter().take(10).collect::<Vec<_>>().join(", ");
        out.push(x);
    }
    // robots.txt
    if let Some(w) = &r.wellknown {
        let hidden: Vec<&crate::wellknown::HiddenPath> = w
            .hidden_paths
            .iter()
            .filter(|h| h.reason != "search")
            .collect();
        if !hidden.is_empty() {
            let mut x = f(
                "recon.robots_hidden",
                host,
                format!("Скрытые разделы в robots.txt: {}", hidden.len()),
                Severity::Info,
                host,
            );
            x.mitre = "T1594".into();
            x.description = "robots.txt (в т.ч. архивные копии) перечисляет пути, которые владелец не хочет индексировать: админки, бэкапы, тестовые разделы, документы.".into();
            x.recommendation = "Не полагаться на robots.txt для сокрытия; закрыть такие разделы авторизацией или удалить.".into();
            x.evidence = hidden
                .iter()
                .take(30)
                .map(|h| format!("{} [{}]", h.path, h.reason))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(x);
        }
    }
    // grep.app
    if let Some(g) = &r.grepapp {
        if g.total > 0 {
            let repos: BTreeSet<&str> = g.hits.iter().map(|h| h.repo.as_str()).collect();
            let mut x = f(
                "recon.code_mentions",
                host,
                format!("Домен упоминается в публичном коде: {} файлов", g.total),
                Severity::Info,
                host,
            );
            x.mitre = "T1593.003".into();
            x.description = format!("grep.app находит «{}» в открытых репозиториях: там бывают внутренние адреса, учётные данные и конфигурации.", g.query);
            x.recommendation =
                "Просмотреть найденные файлы на утечки конфигураций и секретов.".into();
            x.evidence = repos.into_iter().take(20).collect::<Vec<_>>().join(", ");
            out.push(x);
        }
    }
    // Pivots.
    if !r.analytics_ids.is_empty() {
        let mut x = f(
            "recon.analytics_pivots",
            host,
            format!("ID аналитики/рекламы: {}", r.analytics_ids.len()),
            Severity::Info,
            host,
        );
        x.mitre = "T1594".into();
        x.description =
            "Одинаковые ID счётчиков (GA, GTM, Метрика, AdSense) связывают сайты одного владельца."
                .into();
        x.evidence = r
            .analytics_ids
            .iter()
            .map(|a| format!("{}: {}", a.kind, a.id))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(x);
    }
    if let Some(fv) = &r.favicon {
        let mut x = f(
            "recon.favicon",
            host,
            format!("Хэш favicon: {}", fv.hash.mmh3),
            Severity::Info,
            host,
        );
        x.mitre = "T1596".into();
        x.description =
            "Хэш иконки позволяет найти другие хосты с тем же приложением в Shodan/FOFA/Censys."
                .into();
        x.evidence = fv.hash.queries.join("; ");
        if let Some(k) = &fv.hash.known {
            // Product name (proper noun) from the Recog favicon table: language-neutral.
            x.evidence.push_str(&format!("; Recog: {k}"));
        }
        x.url = Some(fv.url.clone());
        out.push(x);
    }
    out.sort_by(|a, b| b.sev.rank().cmp(&a.sev.rank()).then(a.title.cmp(&b.title)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wellknown::{report_from_bodies, WellKnownKind};

    fn input() -> ReconInput {
        let wk = report_from_bodies([(
            WellKnownKind::Robots,
            "https://web.archive.org/x",
            include_str!("../tests/fixtures/robots.txt"),
        )]);
        ReconInput {
            target: "ex.com".into(),
            pages: vec![PageInput {
                url: "https://ex.com/".into(),
                headers: vec![("Server".into(), "nginx/1.18.0".into())],
                html: include_str!("../tests/fixtures/wp_page.html").into(),
            }],
            scripts: vec![ScriptInput {
                url: "https://ex.com/static/js/app.js".into(),
                body: include_str!("../tests/fixtures/app.js").into(),
            }],
            favicon: Some(FaviconInput {
                url: "https://ex.com/favicon.ico".into(),
                bytes: vec![0, 1, 2, 3],
            }),
            documents: vec![TextInput {
                source: "doc:1".into(),
                text: "см. https://storage.yandexcloud.net/ex-docs/a.pdf".into(),
            }],
            urls: vec!["https://ex-arch.s3.amazonaws.com/old.zip".into()],
            wellknown: Some(wk),
            grepapp: None,
        }
    }

    #[test]
    fn full_report_and_findings() {
        let mut r = analyze_site(&input());
        assert!(r.technologies.iter().any(|t| t.name == "WordPress"));
        assert!(r.analytics_ids.len() >= 5);
        assert_eq!(r.js.len(), 2, "inline + app.js");
        assert!(r.favicon.is_some());
        assert_eq!(
            r.icon_links[0].url,
            "https://ex.com/wp-content/uploads/2021/01/cropped-icon-32x32.png"
        );
        assert!(r
            .script_candidates
            .iter()
            .any(|s| s == "https://ex.com/wp-includes/js/jquery/jquery-1.12.4.min.js"));
        let names: Vec<&str> = r.buckets.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        let rules: Vec<&str> = r.findings.iter().map(|f| f.rule.as_str()).collect();
        for want in [
            "recon.js_secret",
            "recon.outdated_tech",
            "recon.robots_hidden",
            "recon.bucket_refs",
            "recon.sourcemap",
            "recon.analytics_pivots",
            "recon.favicon",
        ] {
            assert!(rules.contains(&want), "{want}: {rules:?}");
        }
        assert!(r
            .findings
            .iter()
            .any(|f| f.title == "Устаревшая версия jQuery 1.12.4"));
        assert_eq!(r.findings[0].sev.rank(), Severity::Critical.rank());
        assert!(!rules.contains(&"recon.bucket_listing"));
        // After the bucket check.
        r.buckets[0].status = BucketStatus::PublicListing {
            keys: 3,
            sample: vec!["a".into()],
        };
        r.refresh_findings();
        let bl = r
            .findings
            .iter()
            .find(|f| f.rule == "recon.bucket_listing")
            .unwrap();
        assert_eq!(bl.sev, Severity::High);
        let core = bl.to_finding("2026-11-21T00:00:00Z");
        assert_eq!(core.module, "recon");
        assert_eq!(core.id, bl.stable_id());
        // Secrets do not leak into the serialized report.
        let js = serde_json::to_string(&r).unwrap();
        for raw in [
            "AKIAZ7Q3LMN4PRS2TUV6",
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "Zx81Kq0pLm2Nv7Rt5Yw3",
            "ghp_aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5",
        ] {
            assert!(!js.contains(raw), "{raw}");
        }
        // The input is serializable (bytes as base64).
        let back: ReconInput =
            serde_json::from_str(&serde_json::to_string(&input()).unwrap()).unwrap();
        assert_eq!(back.favicon.unwrap().bytes, vec![0, 1, 2, 3]);
    }

    #[test]
    fn sourcemap_findings_are_deduplicated() {
        let a = crate::js::analyze_js("https://ex.com/a.js", "//# sourceMappingURL=/app.js.map");
        let b = crate::js::analyze_js("https://ex.com/b.js", "//# sourceMappingURL=/app.js.map");
        let mut r = analyze_site(&input());
        r.js = vec![a, b];
        r.refresh_findings();
        let sm = r
            .findings
            .iter()
            .find(|f| f.rule == "recon.sourcemap")
            .unwrap();
        assert!(sm.title.ends_with(": 1"), "{}", sm.title);
        assert_eq!(sm.evidence, "https://ex.com/app.js.map");
    }

    fn js_secret(page_js: &str) -> ReconFinding {
        let mut r = analyze_site(&input());
        r.js = vec![crate::js::analyze_js("https://ex.com/", page_js)];
        r.refresh_findings();
        r.findings
            .into_iter()
            .find(|f| f.rule == "recon.js_secret")
            .expect("js secret finding")
    }

    #[test]
    fn widget_key_in_third_party_script_url_is_info() {
        let t = crate::js::tests::jwt(r#"{"domain":"ex.com","iat":1700000000}"#);
        let f = js_secret(&format!(
            "var s=document.createElement('script');\
             s.src='https://widget.vendor.example/w.js?apiKey={t}&domain=ex.com';"
        ));
        assert_eq!(f.sev, Severity::Info, "{f:?}");
        assert_eq!(
            f.recommendation,
            "Публичный клиентский ключ стороннего виджета: проверьте, что он ограничен доменом."
        );
        assert!(f
            .title
            .starts_with("Публичный ключ стороннего виджета в JS: "));
        assert!(f.description.contains("(widget.vendor.example)"));
        assert!(f.tags.iter().any(|t| t == "public_key"));
        // The site's own API URL is first-party: claims decide (allowed domains = public key,
        // a write scope = secret).
        let f = js_secret(&format!("fetch('https://api.ex.com/v1?token={t}')"));
        assert_eq!(f.sev, Severity::Info);
        let t = crate::js::tests::jwt(r#"{"sub":"svc","scope":"orders:write"}"#);
        let f = js_secret(&format!("fetch('https://api.ex.com/v1?token={t}')"));
        assert_eq!(f.sev, Severity::Medium);
    }

    #[test]
    fn first_party_key_with_server_role_stays_medium() {
        let t = crate::js::tests::jwt(r#"{"role":"service_role","iss":"app"}"#);
        let f = js_secret(&format!("const KEY = \"{t}\";"));
        assert_eq!(f.sev, Severity::Medium);
        assert!(f.title.starts_with("Секрет в JS: "));
        // Even inside another site's script URL, server claims keep it a secret.
        let f = js_secret(&format!(
            "s.src='https://widget.vendor.example/w.js?apiKey={t}';"
        ));
        assert_eq!(f.sev, Severity::Medium);
    }
}

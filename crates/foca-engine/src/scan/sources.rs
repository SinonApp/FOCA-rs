//! Catalog of the scan: stages, source ids grouped by stage, profiles and the modules
//! each source belongs to.

use serde_json::Value;

pub const STAGES: &[(&str, &str)] = &[
    ("search", "Поиск"),
    ("download", "Загрузка"),
    ("meta", "Извлечение метаданных"),
    ("analysis", "Анализ"),
    ("network", "Сеть и DNS"),
    ("ports", "Порты"),
    ("recon", "Разведка сайта"),
    ("fuzz", "Поиск на сайте"),
    ("report", "Отчёт"),
];

/// Sources that can be retried after a manual check (`scan_retry_source`).
pub const RETRY_SOURCES: &[&str] = &["startpage", "mojeek", "brave_web", "yahoo"];

/// Retry marker in the search stage's shared `skip` set: `retry:<id>`.
pub(crate) const RETRY_PREFIX: &str = "retry:";

/// Keyless web dork engines; if all of them hit a captcha or block, the scan summary shows a hint.
pub(crate) const WEB_ENGINES: &[&str] = &[
    "startpage",
    "brave_web",
    "mojeek",
    "ddg",
    "bing",
    "yahoo",
    "searx_pool",
];

/// Sources requiring Android's embedded WebView (not available in headless background runs).
pub const WEBVIEW_SOURCES: &[&str] = &["startpage", "brave_web", "yahoo", "searx_pool"];

pub const SEARCH_SOURCES: &[&str] = &[
    "crt",
    "crtname",
    "scanmalware",
    "certspotter",
    "anubis",
    "hackertarget",
    "rapiddns",
    "subcenter",
    "thc",
    "shodanct",
    "otx_dns",
    "wayback",
    "cc",
    "arquivo",
    "otx_url",
    "urlscan",
    "hudson",
    "ddg",
    "bing",
    "mojeek",
    "startpage",
    "brave_web",
    "yahoo",
    "searx_pool",
    "brave",
    "searx",
    "crawler",
];

/// Keyless document URL sources (foca-search `URL_SOURCES`): the Arquivo.pt archive, OTX, urlscan,
/// HudsonRock, dorks over search engine HTML results (best effort), and dorks through the embedded
/// browser: Startpage and Brave Search (a hidden WebView on Android, `EngineConfig::render`; Mojeek
/// also uses it when the embedded browser is available).
pub const DOC_SOURCE_IDS: &[&str] = &[
    "arquivo",
    "otx_url",
    "urlscan",
    "hudson",
    "ddg",
    "bing",
    "mojeek",
    "startpage",
    "brave_web",
    "yahoo",
    "searx_pool",
];

/// Third-party endpoints of the infrastructure modules (`Endpoints::sources` overrides):
/// `m365` (login.microsoftonline.com + autodiscover), `mta_sts` (MTA-STS policy base URL,
/// tests only).
pub const INFRA_SOURCE_IDS: &[&str] = &["m365"];

/// Keyless subdomain sources (foca-search `HOST_SOURCES`), queried by the search stage.
/// Scan source: subdomain brute force, permutations, PTR and NSEC walking.
pub(crate) const SRC_SUBDOMAINS: &str = "subdomains";

/// Resolver steps of the subdomain source that can be skipped alone (`scan_skip_source`).
pub(crate) const RESOLVER_STEPS: &[&str] = &["brute", "permute"];

/// Scan source: the TLS/X.509 inspector.
pub(crate) const SRC_TLS: &str = "tls";

/// Sources of the recon stage (ids from `SOURCES`).
pub(crate) const RECON_SOURCES: &[&str] = &["recon", "webaudit", "wellknown", "buckets", "grepapp"];

pub const HOST_SOURCE_IDS: &[&str] = &[
    "crtname",
    "scanmalware",
    "certspotter",
    "anubis",
    "hackertarget",
    "rapiddns",
    "subcenter",
    "thc",
    "shodanct",
    "otx_dns",
];

pub const SOURCES: &[(&str, &str, Option<&str>, bool, bool)] = &[
    ("wayback", "Wayback Machine", None, false, false),
    ("cc", "Common Crawl", None, false, false),
    ("crt", "crt.sh", None, false, false),
    ("crtname", "crt.name", None, false, false),
    ("scanmalware", "ScanMalware", None, false, false),
    ("certspotter", "CertSpotter", None, false, false),
    ("anubis", "Anubis", None, false, false),
    ("hackertarget", "HackerTarget", None, false, false),
    ("rapiddns", "RapidDNS", None, false, false),
    ("subcenter", "subdomain.center", None, false, false),
    ("thc", "THC ip.thc.org", None, false, false),
    ("shodanct", "Shodan CT", None, false, false),
    ("otx_dns", "OTX passive DNS", None, false, false),
    ("arquivo", "Arquivo.pt", None, false, false),
    ("otx_url", "AlienVault OTX (URL)", None, false, false),
    ("urlscan", "urlscan.io", None, false, false),
    ("hudson", "HudsonRock (инфостилеры)", None, false, false),
    ("ddg", "DuckDuckGo (дорки)", None, false, false),
    ("bing", "Bing (дорки)", None, false, false),
    ("mojeek", "Mojeek (дорки)", None, false, false),
    ("startpage", "Startpage (через браузер)", None, false, false),
    (
        "brave_web",
        "Brave Search (через браузер)",
        None,
        false,
        false,
    ),
    ("yahoo", "Yahoo (через браузер)", None, false, false),
    (
        "searx_pool",
        "Публичные SearXNG (через браузер)",
        None,
        false,
        false,
    ),
    ("crawler", "Обход сайта", None, false, true),
    (
        "brave",
        "Brave Search API (с ключом)",
        Some("brave"),
        true,
        false,
    ),
    ("searx", "SearXNG", Some("searx"), false, false),
    ("dns", "DNS / CT", None, false, false),
    ("internetdb", "Shodan InternetDB", None, false, false),
    (
        "plugins",
        "Плагины (WASM и декларативные)",
        None,
        false,
        false,
    ),
    (
        "shodan",
        "Shodan (кэш баннеров)",
        Some("shodan"),
        false,
        false,
    ),
    ("recon", "Сайт: технологии, favicon, JS", None, false, false),
    (
        "webaudit",
        "Веб-аудит: заголовки, CSP, source maps, API",
        None,
        false,
        false,
    ),
    (
        "wellknown",
        "robots / sitemap / security.txt (архив)",
        None,
        false,
        false,
    ),
    ("buckets", "Облачные хранилища", None, false, false),
    ("grepapp", "grep.app (публичный код)", None, false, false),
    ("ports", "Порты (TCP)", None, false, true),
    (
        "subdomains",
        "Перебор и перестановки поддоменов",
        None,
        false,
        true,
    ),
    ("tls", "TLS/X.509-инспектор", None, false, true),
    ("fuzz", "Поиск на сайте", None, false, true),
];

pub const ACTIVE_MODULES: &[&str] = &["axfr", "fuzz", "ports", "nsec"];

pub const TARGET_MODULES: &[&str] = &["dns", "docs", "alive", "subdomains", "tls"];

pub fn profile_id(p: &str) -> &'static str {
    match p {
        "passive" | "Пассивный" => "passive",
        "std" | "Стандартный" => "std",
        "full" | "Полный" => "full",
        "custom" | "Свой" => "custom",
        _ => "std",
    }
}

/// Expands wizard document types into filter extensions, including related ones (jpg -> jpeg, docx -> docm, ...).
pub(crate) fn expand_exts(v: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in v {
        let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
        if e.is_empty() || !e.chars().all(|c| c.is_ascii_alphanumeric()) || e.len() > 8 {
            continue;
        }
        let rel: &[&str] = match e.as_str() {
            "jpg" => &["jpeg"],
            "tiff" => &["tif"],
            "doc" => &["dot"],
            "docx" => &["docm", "dotx"],
            "xlsx" => &["xlsm", "xlsb"],
            "ppt" => &["pps"],
            "pptx" => &["pptm", "ppsx"],
            "mp4" => &["m4v"],
            "mov" => &["qt"],
            "wps" => &["wks"],
            "exe" => &["dll"],
            "jar" => &["war", "ear"],
            "apk" => &["aab"],
            "eps" => &["ps", "ai"],
            "emf" => &["wmf"],
            "tar" => &["tgz", "gz", "bz2", "xz"],
            "mkv" => &["webm"],
            "wmv" => &["wma"],
            "ogg" => &["opus"],
            "kml" => &["kmz"],
            _ => &[],
        };
        for x in std::iter::once(e.as_str()).chain(rel.iter().copied()) {
            if !out.iter().any(|o| o == x) {
                out.push(x.to_string());
            }
        }
    }
    out
}

/// Returns `true` unless the user disabled the source (`settings.sources.<id>.enabled: false`).
pub fn source_enabled(sources_settings: &Value, id: &str) -> bool {
    sources_settings[id]["enabled"].as_bool() != Some(false)
}

/// Returns the run wizard modules that enable the source (custom profile).
pub fn source_modules(id: &str) -> &'static [&'static str] {
    match id {
        "wayback" | "cc" => &["wayback"],
        "crawler" => &["docs"],
        "crt" | "dns" | "crtname" | "scanmalware" | "certspotter" | "anubis" | "hackertarget"
        | "rapiddns" | "subcenter" | "thc" | "otx_dns" | "shodanct" | "internetdb" | "plugins" => {
            &["crt", "dns"]
        }
        "arquivo" => &["wayback", "search"],
        "fuzz" => &["fuzz"],
        "ports" => &["ports"],
        "subdomains" => &["subdomains"],
        "tls" => &["tls"],
        "recon" | "webaudit" | "wellknown" | "buckets" | "grepapp" => &["recon"],
        _ => &["search"],
    }
}

pub(crate) fn default_modules(prof: &str) -> Vec<String> {
    let mut m = vec![
        "search", "crt", "wayback", "cc", "meta", "analysis", "ct", "recon", "infra",
    ];
    if prof != "passive" {
        m.extend(["crawler", "dns", "docs", "alive", "subdomains", "tls"]);
    }
    if prof == "full" {
        m.extend(["axfr", "ports", "fuzz", "nsec"]);
    }
    m.into_iter().map(String::from).collect()
}

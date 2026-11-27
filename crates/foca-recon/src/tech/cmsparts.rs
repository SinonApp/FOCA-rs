//! CMS plugins, themes and modules found by their asset paths in already fetched HTML (no
//! requests): WordPress `/wp-content/plugins/<slug>/`, `/wp-content/themes/<slug>/`,
//! `/wp-content/mu-plugins/<slug>/` (and custom content directories on pages with WordPress
//! hints), Drupal `/modules/<name>/`, `/sites/all/modules/<name>/` and themes, Joomla
//! `/components/com_<name>/`, `/modules/mod_<name>/`, `/plugins/<group>/<name>/`,
//! `/templates/<name>/`, Magento `Vendor_Module` static paths and PrestaShop `/modules/<name>/`.
//!
//! WordPress asset versions come from `?ver=`; a value equal to the WordPress core version is the
//! core's cache buster, not the plugin version, and is ignored (as are timestamps and hashes).
//! Each part becomes a [`Technology`] named after the webappanalyzer entry when the slug is
//! known, otherwise after the slug, with `plugin_of`/`slug` set and a CPE guess
//! (`cpe:2.3:a:*:<slug>:*:*:*:*:*:wordpress:*:*`) for the vulnerability matcher.
//! [`readme_stable_tag`] reads the version from a plugin `readme.txt` (the engine fetches it
//! only in the active profile).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

use super::{self as tech, PageInput, Technology};

/// A plugin, theme or module seen in page assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// `wordpress`, `drupal`, `joomla`, `magento`, `prestashop`.
    pub cms: &'static str,
    /// `plugin`, `theme`, `module`, `component`, `template`.
    pub kind: &'static str,
    pub slug: String,
    pub version: Option<String>,
    /// Example asset path.
    pub path: String,
    /// Absolute URL of the part's directory (`https://site/wp-content/plugins/<slug>/`).
    pub dir: String,
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("cms part regex")
}

/// Asset URLs of the page: `src`, `href`, `srcset`/`data-*` and `url(...)` values, plus JSON
/// escaped paths (`\/wp-content\/...`) found anywhere.
fn asset_urls(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let r = RE.get_or_init(|| {
        re(r#"(?i)(?:(?:src|href|data-[a-z-]+|content)\s*=\s*["']?|url\(\s*["']?)([^"'\s<>()]+)|((?:https?:)?(?:\\/\\/[A-Za-z0-9.:-]+)?(?:\\/[A-Za-z0-9_.%-]+){2,}\\/?[^"'\s<>]*)"#)
    });
    r.captures_iter(html)
        .filter_map(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().replace("\\/", "/").replace("&amp;", "&"))
        .collect()
}

/// `?ver=` / `&ver=` value of an asset URL.
fn ver_param(url: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "ver" || k == "version").then(|| v.trim().to_string())
    })
}

/// A plausible release version: digits and dots, not a timestamp or a build hash.
fn plausible_version(v: &str) -> bool {
    let v = v.trim_start_matches('v');
    !v.is_empty()
        && v.len() <= 20
        && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c.is_ascii_lowercase())
        && v.split(['.', '-'])
            .next()
            .is_some_and(|major| major.len() <= 4)
}

/// WordPress-specific signs that make a custom content directory (`/app/plugins/`) credible.
fn wordpress_hints(html: &str) -> bool {
    let l = html.to_ascii_lowercase();
    l.contains("/wp-includes/") || l.contains("/wp-json/") || l.contains("wp-emoji")
}

struct Rule {
    cms: &'static str,
    kind: &'static str,
    re: Regex,
    /// The page must show this CMS (detected technology or hint) for the rule to count.
    needs_cms: bool,
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        let slug = r"([A-Za-z0-9][A-Za-z0-9_.-]*[A-Za-z0-9])";
        let r = |cms, kind, p: &str, needs_cms| Rule {
            cms,
            kind,
            re: re(&p.replace("SLUG", slug)),
            needs_cms,
        };
        vec![
            r(
                "wordpress",
                "plugin",
                r"(?i)^(.*?/wp-content/(?:mu-)?plugins/)SLUG/",
                false,
            ),
            r(
                "wordpress",
                "theme",
                r"(?i)^(.*?/wp-content/themes/)SLUG/",
                false,
            ),
            r(
                "drupal",
                "module",
                r"(?i)^(.*?/(?:sites/[^/]+/|profiles/[^/]+/)?modules/(?:contrib/|custom/)?)SLUG/",
                true,
            ),
            r(
                "drupal",
                "theme",
                r"(?i)^(.*?/(?:sites/[^/]+/)?themes/(?:contrib/|custom/)?)SLUG/",
                true,
            ),
            r(
                "joomla",
                "component",
                r"(?i)^(.*?/components/)(com_[A-Za-z0-9_]+)/",
                false,
            ),
            r(
                "joomla",
                "module",
                r"(?i)^(.*?/modules/)(mod_[A-Za-z0-9_]+)/",
                false,
            ),
            r(
                "joomla",
                "plugin",
                r"(?i)^(.*?/plugins/(?:system|content|user|editors|captcha|authentication|search|finder|quickicon|extension|installer|fields|privacy|actionlog|api-authentication|webservices|task|multifactorauth|sampledata|behaviour|workflow)/)SLUG/",
                true,
            ),
            r(
                "joomla",
                "template",
                r"(?i)^(.*?/templates/)SLUG/",
                true,
            ),
            r(
                "magento",
                "module",
                r"^(.*?/static/(?:version\d+/)?(?:frontend|adminhtml)/[A-Za-z0-9_]+/[A-Za-z0-9_]+/[a-z]{2}_[A-Z]{2}/)([A-Z][A-Za-z0-9]+_[A-Z][A-Za-z0-9]+)/",
                false,
            ),
            r(
                "prestashop",
                "module",
                r"(?i)^(.*?/modules/)SLUG/",
                true,
            ),
        ]
    })
}

/// Names of the CMS families that `techs` and the page show (`wordpress`, `drupal`, ...).
fn cms_present(techs: &[Technology], html: &str) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    for t in techs {
        match t.name.as_str() {
            "WordPress" => out.insert("wordpress"),
            "Drupal" => out.insert("drupal"),
            "Joomla" => out.insert("joomla"),
            "Magento" => out.insert("magento"),
            "PrestaShop" => out.insert("prestashop"),
            _ => false,
        };
    }
    let l = html.to_ascii_lowercase();
    if l.contains("drupal-settings-json") || l.contains("/sites/default/files/") {
        out.insert("drupal");
    }
    if l.contains("/media/jui/") || (l.contains("/media/system/js/") && l.contains("joomla")) {
        out.insert("joomla");
    }
    if l.contains("prestashop") {
        out.insert("prestashop");
    }
    out
}

/// Path segments that are never a plugin/module name.
fn generic(slug: &str) -> bool {
    matches!(
        slug.to_ascii_lowercase().as_str(),
        "js" | "css"
            | "img"
            | "images"
            | "assets"
            | "dist"
            | "build"
            | "src"
            | "lib"
            | "vendor"
            | "fonts"
            | "core"
            | "system"
            | "index.php"
            | "cache"
    )
}

/// Finds plugins/themes/modules in the asset paths of `pages`. `techs` are the technologies
/// already detected on the site (the WordPress core version and the CMS family come from them).
pub fn find_parts(pages: &[PageInput], techs: &[Technology]) -> Vec<Part> {
    let wp_core = techs
        .iter()
        .find(|t| t.name == "WordPress")
        .and_then(|t| t.version.clone());
    // (cms, kind, slug) -> (path, dir, version counts)
    type Acc = (String, String, BTreeMap<String, usize>);
    let mut found: BTreeMap<(&'static str, &'static str, String), Acc> = BTreeMap::new();
    for page in pages {
        let base = url::Url::parse(&page.url).ok();
        let cms = cms_present(techs, &page.html);
        let wp_custom = wordpress_hints(&page.html) || cms.contains("wordpress");
        for raw in asset_urls(&page.html) {
            let abs = base
                .as_ref()
                .and_then(|b| b.join(&raw).ok())
                .map(|u| u.to_string())
                .unwrap_or(raw.clone());
            let Ok(u) = url::Url::parse(&abs) else {
                continue;
            };
            // first-party assets only: a CDN path tells nothing about this site
            if base
                .as_ref()
                .is_some_and(|b| b.host_str() != u.host_str() && !same_site(b, &u))
            {
                continue;
            }
            let path = u.path().to_string();
            let mut hits: Vec<(&'static str, &'static str, String, String)> = Vec::new();
            for r in rules() {
                if r.needs_cms && !cms.contains(r.cms) {
                    continue;
                }
                if r.cms == "prestashop" && cms.contains("drupal") {
                    continue;
                }
                if let Some(c) = r.re.captures(&path) {
                    let (dir, slug) = (c[1].to_string(), c[2].to_string());
                    if r.cms == "drupal" && dir.starts_with("/core/") {
                        continue;
                    }
                    hits.push((r.cms, r.kind, dir, slug));
                }
            }
            if hits.is_empty() && wp_custom {
                if let Some(h) = custom_wp_dir(&path) {
                    hits.push(h);
                }
            }
            for (cms_id, kind, dir, slug) in hits {
                if generic(&slug) {
                    continue;
                }
                let key_slug = if cms_id == "magento" {
                    slug.clone()
                } else {
                    slug.to_ascii_lowercase()
                };
                let e = found
                    .entry((cms_id, kind, key_slug.clone()))
                    .or_insert_with(|| {
                        let mut d = u.clone();
                        d.set_query(None);
                        d.set_fragment(None);
                        d.set_path(&format!("{dir}{slug}/"));
                        (path.clone(), d.to_string(), BTreeMap::new())
                    });
                if cms_id == "wordpress" {
                    if let Some(v) = ver_param(u.as_str()) {
                        if plausible_version(&v) && wp_core.as_deref() != Some(v.as_str()) {
                            *e.2.entry(v).or_default() += 1;
                        }
                    }
                }
            }
        }
    }
    found
        .into_iter()
        .map(|((cms, kind, slug), (path, dir, vers))| {
            // most frequent version; ties go to the highest
            let version = vers
                .into_iter()
                .max_by(|a, b| {
                    a.1.cmp(&b.1).then_with(|| {
                        if tech::version_lt(&a.0, &b.0) {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    })
                })
                .map(|(v, _)| v);
            Part {
                cms,
                kind,
                slug,
                version,
                path,
                dir,
            }
        })
        .collect()
}

fn same_site(a: &url::Url, b: &url::Url) -> bool {
    let (Some(x), Some(y)) = (a.host_str(), b.host_str()) else {
        return false;
    };
    let base = |h: &str| {
        let p: Vec<&str> = h.rsplitn(3, '.').collect();
        p.iter()
            .take(2)
            .rev()
            .copied()
            .collect::<Vec<_>>()
            .join(".")
    };
    base(x) == base(y)
}

/// A WordPress plugin/theme under a renamed content directory (`/app/plugins/<slug>/`,
/// `/content/themes/<slug>/`), accepted only on pages with WordPress hints.
fn custom_wp_dir(path: &str) -> Option<(&'static str, &'static str, String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let r = RE.get_or_init(|| {
        re(r"(?i)^(.*?/[A-Za-z0-9_-]+/(mu-plugins|plugins|themes)/)([A-Za-z0-9][A-Za-z0-9_.-]*[A-Za-z0-9])/")
    });
    let c = r.captures(path)?;
    let kind = if c[2].eq_ignore_ascii_case("themes") {
        "theme"
    } else {
        "plugin"
    };
    if c[1].contains("/wp-includes/") || c[1].contains("/wp-admin/") {
        return None;
    }
    Some(("wordpress", kind, c[1].to_string(), c[3].to_string()))
}

/// Russian category of a part (translated by `locales/*/findings.json` `tech_cats`).
fn category(p: &Part) -> &'static str {
    match (p.cms, p.kind) {
        ("wordpress", "theme") => "Темы WordPress",
        ("wordpress", _) => "Плагины WordPress",
        ("drupal", "theme") => "Темы Drupal",
        ("drupal", _) => "Модули Drupal",
        ("joomla", _) => "Расширения Joomla",
        ("magento", _) => "Модули Magento",
        _ => "Модули PrestaShop",
    }
}

/// CPE guess of a part: any vendor, the slug as product, the CMS as target software.
pub fn cpe_guess(cms: &str, slug: &str) -> String {
    let product: String = slug
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("cpe:2.3:a:*:{product}:*:*:*:*:*:{cms}:*:*")
}

/// Turns parts into technologies (webappanalyzer names for known WordPress slugs).
pub fn technologies(parts: &[Part]) -> Vec<Technology> {
    parts
        .iter()
        .map(|p| {
            let known = (p.cms == "wordpress")
                .then(|| tech::wordpress_slug(p.kind, &p.slug))
                .flatten();
            let (name, category, cpe, website) = match known {
                Some(k) => (k.name, k.category, k.cpe, k.website),
                None => (p.slug.clone(), category(p).to_string(), None, None),
            };
            let kind_label = match p.kind {
                "theme" => "theme",
                "template" => "template",
                "component" => "component",
                "module" => "module",
                _ => "plugin",
            };
            let mut evidence = vec![format!("{kind_label} path: {}", p.path)];
            if let Some(v) = &p.version {
                evidence.push(format!("?ver={v}"));
            }
            Technology {
                name,
                category,
                version: p.version.clone(),
                confidence: if p.version.is_some() { 100 } else { 90 },
                evidence,
                outdated: None,
                website,
                cpe: Some(cpe.unwrap_or_else(|| cpe_guess(p.cms, &p.slug))),
                signals: vec!["plugin_path".into()],
                plugin_of: Some(p.cms.to_string()),
                slug: Some(p.slug.clone()),
            }
        })
        .collect()
}

/// Merges part technologies into `techs`: a technology the rules already found (by name, or a
/// name equal to the slug ignoring case and punctuation: `WooCommerce` / `woocommerce`) gains
/// the plugin fields, signal and missing version; others are appended.
pub fn merge_into(techs: &mut Vec<Technology>, parts: Vec<Technology>) {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    for p in parts {
        let slug = norm(p.slug.as_deref().unwrap_or(""));
        let same = |t: &Technology| {
            t.name == p.name || (!slug.is_empty() && t.plugin_of.is_none() && norm(&t.name) == slug)
        };
        match techs.iter_mut().find(|t| same(t)) {
            Some(t) => {
                if t.version.is_none() {
                    t.version = p.version;
                }
                t.plugin_of = p.plugin_of;
                t.slug = p.slug;
                if t.cpe.is_none() {
                    t.cpe = p.cpe;
                }
                for s in p.signals {
                    if !t.signals.contains(&s) {
                        t.signals.push(s);
                    }
                }
                for e in p.evidence {
                    if t.evidence.len() < 8 && !t.evidence.contains(&e) {
                        t.evidence.push(e);
                    }
                }
                t.confidence = t.confidence.max(p.confidence);
            }
            None => techs.push(p),
        }
    }
}

/// Bytes of a plugin readme read for its `Stable tag:`.
const README_PREFIX: usize = 16 << 10;

/// Most WordPress plugin readmes checked per scan in the active profile.
pub const MAX_READMES: usize = 30;

/// Active check: fetches `readme.txt` of up to `max` WordPress plugins in `parts` (in-scope
/// hosts only, through the client's rate limiter and scope check as an active operation) and
/// applies their `Stable tag:` to `techs`. Returns the number of requests sent.
pub async fn check_readmes(
    client: &foca_net::NetClient,
    techs: &mut [Technology],
    parts: &[Part],
    max: usize,
) -> usize {
    let mut sent = 0;
    for p in parts
        .iter()
        .filter(|p| p.cms == "wordpress" && p.kind == "plugin")
    {
        if sent >= max || client.is_cancelled() {
            break;
        }
        let url = format!("{}readme.txt", p.dir);
        let access = foca_net::Access::Active {
            operation: "wp_readme".into(),
        };
        let Ok(req) = foca_net::NetRequest::get(&url, "recon", access) else {
            continue;
        };
        sent += 1;
        let mut r = match client.send(req).await.and_then(|r| r.ensure_success()) {
            Ok(r) => r,
            Err(
                foca_net::NetError::OutOfScope { .. }
                | foca_net::NetError::ActiveDenied(_)
                | foca_net::NetError::Cancelled,
            ) => break,
            Err(_) => continue,
        };
        // the version sits in the header: read a prefix only
        let mut body = Vec::new();
        while let Ok(Some(chunk)) = r.chunk().await {
            body.extend_from_slice(&chunk);
            if body.len() >= README_PREFIX {
                r.abort();
                break;
            }
        }
        apply_readme(techs, &p.slug, &String::from_utf8_lossy(&body));
    }
    sent
}

/// `Stable tag:` of a WordPress plugin readme (`trunk` and non-versions are ignored).
pub fn readme_stable_tag(text: &str) -> Option<String> {
    let line = text.lines().take(80).find(|l| {
        l.trim_start()
            .to_ascii_lowercase()
            .starts_with("stable tag:")
    })?;
    let v = line.split_once(':')?.1.trim().to_string();
    plausible_version(&v).then_some(v)
}

/// Applies a plugin readme to the technology with this slug: version when none is known yet,
/// evidence and the `readme` signal. Returns whether anything changed.
pub fn apply_readme(techs: &mut [Technology], slug: &str, text: &str) -> bool {
    let Some(v) = readme_stable_tag(text) else {
        return false;
    };
    let Some(t) = techs
        .iter_mut()
        .find(|t| t.plugin_of.as_deref() == Some("wordpress") && t.slug.as_deref() == Some(slug))
    else {
        return false;
    };
    if t.version.is_none() {
        t.version = Some(v.clone());
    }
    t.evidence.push(format!("readme.txt: Stable tag {v}"));
    if !t.signals.iter().any(|s| s == "readme") {
        t.signals.push("readme".into());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(html: &str) -> PageInput {
        PageInput {
            url: "https://blog.example/".into(),
            headers: vec![],
            html: html.into(),
        }
    }

    fn wp_core(v: &str) -> Vec<Technology> {
        let mut t = technologies(&[]);
        t.push(Technology {
            name: "WordPress".into(),
            category: "CMS".into(),
            version: Some(v.into()),
            confidence: 100,
            evidence: vec![],
            outdated: None,
            website: None,
            cpe: None,
            signals: vec![],
            plugin_of: None,
            slug: None,
        });
        t
    }

    const WP: &str = r#"<html><head><meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="https://blog.example/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4">
<link rel="stylesheet" href="/wp-content/plugins/fancy-gallery-x/css/g.css?ver=6.4.2">
<script src="/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js?ver=8.3.1"></script>
<script src="/wp-content/mu-plugins/site-tools/x.js?ver=1700000000"></script>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.0">
<script src="https://cdn.example.net/wp-content/plugins/elsewhere/x.js?ver=9.9"></script>
<script type="application/ld+json">{"logo":"https:\/\/blog.example\/wp-content\/plugins\/seo-kit\/logo.png"}</script>
</head><body></body></html>"#;

    #[test]
    fn wordpress_plugins_and_theme_with_versions() {
        let parts = find_parts(&[page(WP)], &wp_core("6.4.2"));
        let get = |s: &str| {
            parts
                .iter()
                .find(|p| p.slug == s)
                .unwrap_or_else(|| panic!("{s}: {parts:?}"))
        };
        assert_eq!(get("contact-form-7").version.as_deref(), Some("5.8.4"));
        assert_eq!(get("woocommerce").version.as_deref(), Some("8.3.1"));
        // the core version is the cache buster, a timestamp is no version
        assert_eq!(get("fancy-gallery-x").version, None);
        assert_eq!(get("site-tools").version, None);
        assert_eq!(get("site-tools").kind, "plugin");
        let theme = get("twentytwentyfour");
        assert_eq!(
            (theme.kind, theme.version.as_deref()),
            ("theme", Some("1.0"))
        );
        assert_eq!(
            get("seo-kit").dir,
            "https://blog.example/wp-content/plugins/seo-kit/"
        );
        // third-party CDN paths do not count
        assert!(parts.iter().all(|p| p.slug != "elsewhere"));
        let techs = technologies(&parts);
        let cf7 = techs
            .iter()
            .find(|t| t.slug.as_deref() == Some("contact-form-7"))
            .unwrap();
        assert_eq!(cf7.name, "Contact Form 7");
        assert_eq!(cf7.plugin_of.as_deref(), Some("wordpress"));
        let fg = techs
            .iter()
            .find(|t| t.slug.as_deref() == Some("fancy-gallery-x"))
            .unwrap();
        assert_eq!(fg.name, "fancy-gallery-x");
        assert_eq!(fg.category, "Плагины WordPress");
        assert_eq!(
            fg.cpe.as_deref(),
            Some("cpe:2.3:a:*:fancy_gallery_x:*:*:*:*:*:wordpress:*:*")
        );
        assert_eq!(fg.signals, ["plugin_path"]);
    }

    #[test]
    fn custom_content_dir_needs_wordpress_hints() {
        let html = r#"<script src="/app/plugins/form-kit/f.js?ver=2.1.0"></script>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>"#;
        let parts = find_parts(&[page(html)], &[]);
        assert_eq!(parts.len(), 1, "{parts:?}");
        assert_eq!(parts[0].slug, "form-kit");
        assert_eq!(parts[0].version.as_deref(), Some("2.1.0"));
        let plain = find_parts(
            &[page(
                r#"<script src="/app/plugins/form-kit/f.js"></script>"#,
            )],
            &[],
        );
        assert!(plain.is_empty(), "{plain:?}");
    }

    #[test]
    fn drupal_and_joomla_paths() {
        let drupal = r#"<script type="application/json" data-drupal-selector="drupal-settings-json">{}</script>
<link href="/modules/contrib/webform/css/webform.css?s8x2k" rel="stylesheet">
<script src="/sites/all/modules/views_slideshow/js/v.js"></script>
<link href="/core/modules/system/css/system.css" rel="stylesheet">
<link href="/themes/custom/agency/css/style.css" rel="stylesheet">"#;
        let parts = find_parts(&[page(drupal)], &[]);
        let slugs: Vec<(&str, &str)> = parts.iter().map(|p| (p.kind, p.slug.as_str())).collect();
        assert!(slugs.contains(&("module", "webform")), "{slugs:?}");
        assert!(slugs.contains(&("module", "views_slideshow")), "{slugs:?}");
        assert!(slugs.contains(&("theme", "agency")), "{slugs:?}");
        assert!(!slugs.iter().any(|s| s.1 == "system"), "{slugs:?}");
        let joomla = r#"<script src="/media/jui/js/jquery.min.js"></script>
<link href="/components/com_virtuemart/assets/css/vm.css" rel="stylesheet">
<script src="/modules/mod_menu/tmpl/x.js"></script>
<script src="/plugins/system/jcemediabox/js/a.js"></script>
<link href="/templates/protostar/css/template.css" rel="stylesheet">"#;
        let parts = find_parts(&[page(joomla)], &[]);
        let slugs: Vec<(&str, &str)> = parts.iter().map(|p| (p.kind, p.slug.as_str())).collect();
        for want in [
            ("component", "com_virtuemart"),
            ("module", "mod_menu"),
            ("plugin", "jcemediabox"),
            ("template", "protostar"),
        ] {
            assert!(slugs.contains(&want), "{want:?} {slugs:?}");
        }
        let t = technologies(&parts);
        assert!(t.iter().all(|x| x.plugin_of.as_deref() == Some("joomla")));
        assert!(t[0].cpe.as_deref().unwrap().ends_with(":joomla:*:*"));
    }

    #[test]
    fn readme_stable_tag_versions() {
        let r = "=== Fancy ===\nContributors: x\nStable tag: 2.4.1\nLicense: GPL\n";
        assert_eq!(readme_stable_tag(r).as_deref(), Some("2.4.1"));
        assert_eq!(readme_stable_tag("Stable tag: trunk\n"), None);
        assert_eq!(readme_stable_tag("<html>not found</html>"), None);
        let mut techs = technologies(&find_parts(&[page(WP)], &wp_core("6.4.2")));
        assert!(apply_readme(&mut techs, "fancy-gallery-x", r));
        let t = techs
            .iter()
            .find(|t| t.slug.as_deref() == Some("fancy-gallery-x"))
            .unwrap();
        assert_eq!(t.version.as_deref(), Some("2.4.1"));
        assert!(t.signals.contains(&"readme".to_string()));
        assert!(!apply_readme(&mut techs, "missing", r));
    }
}

//! Collects the input for [`crate::analyze_site`] through `NetClient`: the home page, favicon,
//! scripts and stylesheets of the site (fetched directly with `Access::TouchesTarget`, or from a Wayback
//! copy with `Access::Passive`), plus robots/sitemap/security.txt from the archive (CDX and
//! snapshots). Shared by the engine's site recon stage (`foca-engine`) and the CLI
//! (`foca recon`).

use foca_net::{Access, NetClient, NetRequest};

use crate::report::{FaviconInput, ScriptInput};
use crate::tech::PageInput;
use crate::wellknown::{harvest_from_archive, HarvestOptions, WellKnownReport};
use crate::{analyze_site, ReconInput};

pub const MODULE: &str = "recon";

/// Collection options.
#[derive(Debug, Clone)]
pub struct CollectOptions {
    /// `Some(base)` takes everything about the site from the archive
    /// (`<base>/web/2id_/<url>`) without contacting the target.
    pub archive: Option<String>,
    /// Maximum number of external scripts from the same site.
    pub max_scripts: usize,
    /// Maximum number of same-site stylesheets (`<link rel=stylesheet>`) fetched for CSS
    /// technology signals.
    pub max_styles: usize,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            archive: None,
            max_scripts: 10,
            max_styles: 5,
        }
    }
}

/// Largest stylesheet fetched for CSS signals.
const MAX_STYLE_BYTES: u64 = 1 << 20;

/// Absolute URLs of the `<link rel=stylesheet href>` of a page, in document order.
pub fn stylesheet_links(html: &str, base: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(?is)<link\b[^>]*>").expect("re"));
    let base = url::Url::parse(base).ok();
    let mut out = Vec::new();
    for m in re.find_iter(html) {
        let a = crate::favicon::attrs(m.as_str());
        let get = |k: &str| a.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let is_css = get("rel").is_some_and(|r| {
            r.split_ascii_whitespace()
                .any(|x| x.eq_ignore_ascii_case("stylesheet"))
        });
        let Some(href) = get("href").filter(|_| is_css) else {
            continue;
        };
        let abs = base
            .as_ref()
            .and_then(|b| b.join(&href).ok())
            .map(|u| u.to_string())
            .unwrap_or(href);
        if !out.contains(&abs) {
            out.push(abs);
        }
    }
    out
}

/// A response: headers (for an archive copy, `x-archive-orig-*` with the prefix removed) and
/// body.
pub struct Fetched {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Performs a GET either directly or via the archive.
pub async fn fetch(
    client: &NetClient,
    url: &str,
    archive: Option<&str>,
    limit: u64,
) -> Result<Fetched, String> {
    let (u, access) = match archive {
        Some(base) => (
            format!("{}/web/2id_/{url}", base.trim_end_matches('/')),
            Access::Passive,
        ),
        None => (url.to_string(), Access::TouchesTarget),
    };
    let req = NetRequest::get(&u, MODULE, access).map_err(|e| e.to_string())?;
    let r = client
        .send(req)
        .await
        .and_then(|r| r.ensure_success())
        .map_err(|e| e.to_string())?;
    let headers: Vec<(String, String)> = r
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            let k = k.as_str().to_ascii_lowercase();
            let v = v.to_str().ok()?.to_string();
            if archive.is_some() {
                k.strip_prefix("x-archive-orig-")
                    .map(|k| (k.to_string(), v))
            } else {
                Some((k, v))
            }
        })
        .collect();
    let body = r.bytes_limited(limit).await.map_err(|e| e.to_string())?;
    Ok(Fetched { headers, body })
}

fn same_site(url: &str, host: &str) -> bool {
    // `host` may carry a port (`example.test:8080`); scripts are matched by name only
    let host = host.rsplit_once(':').map_or(host, |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|h| h == host || h.ends_with(&format!(".{host}")))
}

/// Fetches the home page (`https`, then `http`), favicon and same-site scripts into `input`.
///
/// Returns the home page URL.
///
/// # Errors
///
/// Returns an error if the home page could not be fetched.
pub async fn fetch_site(
    client: &NetClient,
    host: &str,
    opts: &CollectOptions,
    input: &mut ReconInput,
) -> Result<String, String> {
    let archive = opts.archive.as_deref();
    let mut last = String::new();
    let mut page: Option<(String, Fetched)> = None;
    for scheme in ["https", "http"] {
        let u = format!("{scheme}://{host}/");
        match fetch(client, &u, archive, 3 << 20).await {
            Ok(f) => {
                page = Some((u, f));
                break;
            }
            Err(e) => last = e,
        }
        if archive.is_some() {
            break; // Wayback resolves the copy and the http variant itself
        }
    }
    let Some((url, f)) = page else {
        return Err(last);
    };
    input.pages.push(PageInput {
        url: url.clone(),
        headers: f.headers,
        html: String::from_utf8_lossy(&f.body).into_owned(),
    });
    let pre = analyze_site(input);
    let icon = pre
        .icon_links
        .first()
        .map(|l| l.url.clone())
        .unwrap_or_else(|| format!("{url}favicon.ico"));
    if let Ok(f) = fetch(client, &icon, archive, 1 << 20).await {
        let head = String::from_utf8_lossy(&f.body[..f.body.len().min(256)]).to_ascii_lowercase();
        if !f.body.is_empty() && !head.contains("<html") && !head.contains("<!doctype") {
            input.favicon = Some(FaviconInput {
                url: icon,
                bytes: f.body,
            });
        }
    }
    for s in pre
        .script_candidates
        .iter()
        .filter(|s| same_site(s, host))
        .take(opts.max_scripts)
    {
        if client.is_cancelled() {
            break;
        }
        if let Ok(f) = fetch(client, s, archive, 2 << 20).await {
            input.scripts.push(ScriptInput {
                url: s.clone(),
                body: String::from_utf8_lossy(&f.body).into_owned(),
            });
        }
    }
    let home = input
        .pages
        .first()
        .map(|p| p.html.clone())
        .unwrap_or_default();
    for s in stylesheet_links(&home, &url)
        .iter()
        .filter(|s| same_site(s, host))
        .take(opts.max_styles)
    {
        if client.is_cancelled() {
            break;
        }
        if let Ok(f) = fetch(client, s, archive, MAX_STYLE_BYTES).await {
            input.styles.push(ScriptInput {
                url: s.clone(),
                body: String::from_utf8_lossy(&f.body).into_owned(),
            });
        }
    }
    Ok(url)
}

/// Collects robots.txt, sitemap.xml and security.txt: Wayback CDX (the last 3 captures with
/// status 200), then the archived copies.
///
/// # Errors
///
/// Returns an error if CDX did not respond for any of the files.
pub async fn wellknown(
    client: &NetClient,
    wayback: &str,
    host: &str,
) -> Result<WellKnownReport, String> {
    let wb = wayback.trim_end_matches('/').to_string();
    let mut cdx = String::new();
    let mut errors = Vec::new();
    for path in ["robots.txt", "sitemap.xml", ".well-known/security.txt"] {
        let u = format!("{wb}/cdx/search/cdx?url={host}/{path}&filter=statuscode:200&limit=-3");
        let r = async {
            let req = NetRequest::get(&u, MODULE, Access::Passive).map_err(|e| e.to_string())?;
            let r = client
                .send(req)
                .await
                .and_then(|r| r.ensure_success())
                .map_err(|e| e.to_string())?;
            r.text_limited(1 << 20).await.map_err(|e| e.to_string())
        }
        .await;
        match r {
            Ok(t) => {
                cdx.push_str(&t);
                cdx.push('\n');
            }
            Err(e) => errors.push(format!("CDX {path}: {e}")),
        }
    }
    if cdx.trim().is_empty() && errors.len() == 3 {
        return Err(errors.join("; "));
    }
    let opts = HarvestOptions {
        archive_base: wb,
        max_child_sitemaps: 5,
        max_body: 4 << 20,
        ..Default::default()
    };
    let mut rep = harvest_from_archive(client, &cdx, &opts).await;
    rep.errors.extend(errors);
    Ok(rep)
}

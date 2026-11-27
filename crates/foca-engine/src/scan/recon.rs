//! Site reconnaissance stage (`foca-recon`): technologies, analytics ids, favicon hash, endpoints
//! and secrets in JavaScript (masked only), robots/sitemap/security.txt from the archive, cloud
//! storage links, and mentions of the domain in public code (grep.app).
//!
//! Access levels:
//! - `external` (passive profile): the target is not contacted; the home page, favicon and scripts
//!   come from the Wayback copy (`<wayback>/web/2025id_/<url>`), headers from `x-archive-orig-*`;
//! - `target` / `active`: the site's home page, favicon and scripts are fetched directly
//!   (`Access::TouchesTarget`);
//! - bucket listing checks run only at `active` (requests go to the cloud provider, not the
//!   target); other levels only list the buckets.
//!
//! Stage sources (`source` events, timeout, `scan_skip_source`): `recon` (site pages),
//! `wellknown` (archive), `buckets`, and `grepapp` (optional; a challenge or 429 yields `blocked`).
//! Results go to the project facts (`engine.recon`) and `recon.*` findings join the shared finding
//! list; rerunning the stage (resume after a stop) overwrites the per-host data. Sites run
//! `settings.net.hosts_parallel` at once; each is stored as soon as it is done. At the active level
//! open non-standard web ports of in-scope hosts get a site recon pass too ([`recon_extra_ports`]).
//!
//! Technology signals: besides the home page, the fetched scripts and stylesheets, the TLS
//! certificate issuer (network stage facts) and robots.txt feed the static rules. On Android
//! (a platform browser is attached) the home page of each site is rendered once in standard and
//! active profiles, up to `settings.recon.render_hosts` sites per scan, with one read-only probe
//! script for browser-only signals (JS globals, DOM, request hosts); pages the crawler already
//! rendered as app shells add theirs (`engine.crawl_browser`). The passive profile renders nothing; without
//! a browser (CLI, desktop) the scan log notes that browser-only signals were not checked. In the
//! active profile up to [`foca_recon::tech::cmsparts::MAX_READMES`] WordPress plugin readmes are read
//! for versions.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use foca_net::Access;
use foca_recon::buckets::{check_buckets, BucketCheckOptions, BucketStatus};
use foca_recon::collect::{self, CollectOptions};
use foca_recon::grepapp::{self, GrepAppError, GrepAppResult};
use foca_recon::tech::browser::{self, BrowserSignals};
use foca_recon::webaudit::{self, AuditLevel, WebAuditInput, WebAuditOptions, WebAuditReport};
use foca_recon::{analyze_site, ReconInput, ReconReport};
use foca_store::ProjectDb;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{reanalyze_bg, Ctx, Stop, RECON_SOURCES, STAGES};
use crate::analysis::facts::{self, NetFacts};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::lock;

/// Project facts key holding the reconnaissance data.
pub const K_RECON: &str = "engine.recon";
/// Default of `settings.recon.render_hosts`: home pages rendered for browser signals per scan.
pub const RENDER_HOSTS: u64 = 10;
/// Time budget of the probe script inside the page.
const PROBE_BUDGET_MS: u64 = 1500;
/// Non-standard web ports that get a site recon pass at the active level.
pub const EXTRA_WEB_PORTS: &[u16] = &[8080, 8443, 3000, 9000, 5601, 9200];
const MAX_EXTRA_SITES: usize = 6;
/// Sites (target domains) per scan.
const MAX_SITES: usize = 3;
/// External scripts per site.
const MAX_SCRIPTS: usize = 5;
/// Number of sitemap URLs and endpoints kept per site (the rest only counted).
const KEEP_SITEMAP: usize = 300;
const KEEP_ENDPOINTS: usize = 300;

/// Reconnaissance data for one site.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteRecon {
    pub host: String,
    /// Home page URL (the original, not the archive copy).
    pub url: String,
    /// `site` for direct access, `archive` for a Wayback copy, `""` if the home page could not be fetched.
    pub via: String,
    pub error: Option<String>,
    pub at: String,
    pub scan: String,
    pub sitemap_total: usize,
    pub endpoints_total: usize,
    pub report: ReconReport,
    /// Web audit of the site (security headers, CSP, source maps, API docs, CORS, methods).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<WebAuditReport>,
    /// A reconnaissance source did not answer in the latest scan; some data comes from earlier runs.
    pub incomplete: bool,
    /// The home page was rendered in the platform browser for browser-only signals.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rendered: bool,
}

/// Status of a stage source (for empty UI states).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SrcState {
    pub status: String,
    pub n: Option<usize>,
    pub error: Option<String>,
}

/// All reconnaissance data of the project (`engine.recon`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReconFacts {
    pub sites: BTreeMap<String, SiteRecon>,
    pub sources: BTreeMap<String, SrcState>,
    pub level: String,
    pub at: Option<String>,
    pub scan: Option<String>,
}

enum End<T> {
    Done(T),
    Timeout,
    Skipped,
}

/// Web audit access class of a scan level: `external` (passive profile) sends nothing,
/// `target` allows GET probes of in-scope hosts, `active` adds method/CORS/GraphQL probes.
pub(crate) fn audit_level(level: &str) -> AuditLevel {
    match level {
        "active" => AuditLevel::Active,
        "target" => AuditLevel::Standard,
        _ => AuditLevel::Passive,
    }
}

fn stage_idx() -> usize {
    STAGES.iter().position(|s| s.0 == "recon").unwrap_or(5)
}

/// Runs a source step under the source timeout, "skip" (`scan_skip_source`) and scan cancellation.
async fn step<T, F: Future<Output = T>>(c: &Ctx, id: &str, fut: F) -> Result<End<T>, Stop> {
    if lock(&c.skip).contains(id) {
        return Ok(End::Skipped);
    }
    let timeout = c.e.source_timeout();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    c.source_event_x(
        id,
        "running",
        None,
        None,
        json!({ "timeout_s": timeout.as_secs(), "deadline_ms": now_ms + timeout.as_millis() as u64 }),
    );
    tokio::pin!(fut);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval(Duration::from_millis(300));
    loop {
        tokio::select! {
            r = &mut fut => return Ok(End::Done(r)),
            _ = &mut deadline => return Ok(End::Timeout),
            _ = c.cancel.cancelled() => return Err(Stop::Cancelled),
            _ = tick.tick() => {
                if lock(&c.skip).contains(id) {
                    return Ok(End::Skipped);
                }
            }
        }
    }
}

fn grep_base(c: &Ctx) -> String {
    c.e.cfg
        .endpoints
        .sources
        .get("grepapp")
        .cloned()
        .unwrap_or_else(|| grepapp::DEFAULT_BASE.into())
}

/// Returns texts to search for buckets: URLs of project tasks (documents found by sources).
fn project_urls(db: &ProjectDb) -> Vec<String> {
    db.task_urls().unwrap_or_default()
}

fn set_src(f: &mut ReconFacts, id: &str, status: &str, n: Option<usize>, err: Option<String>) {
    f.sources.insert(
        id.into(),
        SrcState {
            status: status.into(),
            n,
            error: err,
        },
    );
}

/// Turns a step result into a source event and a facts record.
fn report_end<T>(
    c: &Ctx,
    rf: &mut ReconFacts,
    id: &str,
    end: &End<Result<T, String>>,
    n: impl Fn(&T) -> usize,
) {
    let (status, cnt, err) = match end {
        End::Done(Ok(v)) => ("ok", Some(n(v)), None),
        End::Done(Err(e)) => ("error", None, Some(e.clone())),
        End::Timeout => (
            "timeout",
            None,
            Some("нет ответа за отведённое время".into()),
        ),
        End::Skipped => ("skipped", None, None),
    };
    c.source_event_full(id, status, cnt, err.as_deref());
    set_src(rf, id, status, cnt, err);
}

pub(super) async fn stage_recon(c: &mut Ctx) -> Result<(), Stop> {
    let idx = stage_idx();
    if !c.module("recon") {
        return Ok(());
    }
    let ids = lock(&c.st).source_ids.clone();
    let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
    for id in RECON_SOURCES {
        if ids.iter().any(|x| x == id) && !super::source_enabled(&ss, id) {
            c.source_event(id, "off", None);
        }
    }
    let want = |id: &str| ids.iter().any(|x| x == id) && super::source_enabled(&ss, id);
    let archive = c.level == "external";
    let hosts: Vec<String> = c.domains.iter().take(MAX_SITES).cloned().collect();
    let now = c.e.now_iso();
    let sid = c.scan_id.clone();
    if hosts.is_empty() {
        for id in RECON_SOURCES {
            if want(id) {
                c.source_event_full(id, "off", None, Some("нет доменов в целях"));
            }
        }
        return Ok(());
    }
    let urls = project_urls(&lock(&c.db));
    let recon_net = c.group_net("recon")?;
    let n = hosts.len();
    let c: &Ctx = c;
    let renders = AtomicUsize::new(0);
    let readmes = AtomicUsize::new(0);
    let render_cap = render_cap(c);
    if !archive && want("recon") {
        note_no_browser(c, render_cap);
    }
    let board = c.host_board(n);
    // earlier data per site is kept if a source fails or is skipped
    let prev = facts::get::<ReconFacts>(&lock(&c.db), K_RECON).sites;
    let items: Vec<(String, String)> = hosts.iter().map(|h| (h.clone(), h.clone())).collect();
    let work = |i: usize, host: String| {
        let (recon_net, urls, now, sid, board, prev) =
            (&recon_net, &urls, &now, &sid, &board, &prev);
        let (want, renders, readmes) = (&want, &renders, &readmes);
        async move {
            let host = &host;
            // source states of this site, merged into the stage's in host order at the end
            let mut lf = ReconFacts::default();
            let mut new = 0usize;
            let mut input = ReconInput {
                target: host.clone(),
                ..Default::default()
            };
            if i == 0 {
                input.urls = urls.clone();
            }
            let prev_site = prev.get(host).cloned();
            let (mut page_ok, mut wk_ok, mut ga_ok) = (None, None, None);
            let mut site = SiteRecon {
                host: host.clone(),
                at: now.clone(),
                scan: sid.clone(),
                ..Default::default()
            };
            // 1) site pages
            if want("recon") {
                let opts = CollectOptions {
                    archive: archive.then(|| c.e.cfg.endpoints.wayback.clone()),
                    max_scripts: MAX_SCRIPTS,
                    ..Default::default()
                };
                // the offline harness serves sites on its own port (`EngineConfig::site_port`)
                let fetch_host = match c.e.cfg.site_port {
                    Some(p) if !archive => format!("{host}:{p}"),
                    _ => host.clone(),
                };
                let end = step(
                    c,
                    "recon",
                    collect::fetch_site(recon_net, &fetch_host, &opts, &mut input),
                )
                .await?;
                match &end {
                    End::Done(Ok(u)) => {
                        site.url = u.clone();
                        site.via = if archive { "archive" } else { "site" }.into();
                        if !archive {
                            crawled_scripts(c, recon_net, host, &mut input).await;
                            if let Some(b) =
                                render_home(c, recon_net, u, host, renders, render_cap).await
                            {
                                site.rendered = true;
                                input.browser.push(b);
                            }
                            input.browser.extend(crawled_browser(c, host));
                        }
                    }
                    End::Done(Err(e)) => site.error = Some(e.clone()),
                    _ => {}
                }
                // n is the number of technologies (estimated from what is fetched so far; final after analysis)
                let techs = analyze_site(&input).technologies.len();
                report_end(c, &mut lf, "recon", &end, |_| techs);
                page_ok = Some(matches!(end, End::Done(Ok(_))));
            }
            // 1b) web audit over the fetched pages: passive analysis in the passive profile (no
            // requests), GET probes of in-scope hosts in the standard one, method/CORS/GraphQL
            // probes only at the active level
            let mut web: Option<WebAuditReport> = prev_site.as_ref().and_then(|p| p.web.clone());
            if want("webaudit") {
                if page_ok == Some(true) {
                    let level = audit_level(&c.level);
                    let opts = WebAuditOptions {
                        level,
                        scope: lock(&c.db).core_scope().ok(),
                        ..Default::default()
                    };
                    let mut winput = WebAuditInput::from_recon(&input);
                    winput.from_archive = site.via == "archive";
                    let end = step(c, "webaudit", async {
                        Ok::<WebAuditReport, String>(webaudit::run(recon_net, &winput, &opts).await)
                    })
                    .await?;
                    report_end(c, &mut lf, "webaudit", &end, |r| r.findings.len());
                    if let End::Done(Ok(r)) = end {
                        web = Some(r);
                    } else if web.is_some() {
                        site.incomplete = true;
                    }
                } else {
                    let why = "нет страницы сайта для аудита";
                    c.source_event_full("webaudit", "off", None, Some(why));
                    set_src(&mut lf, "webaudit", "off", None, Some(why.into()));
                }
            }
            board.set_progress(i, 0.4);
            c.progress(idx, board.fraction());
            // 2) robots/sitemap/security.txt from the archive (passive)
            if want("wellknown") {
                let wb = c.e.cfg.endpoints.wayback.clone();
                let end = step(c, "wellknown", collect::wellknown(recon_net, &wb, host)).await?;
                report_end(c, &mut lf, "wellknown", &end, |w| {
                    w.hidden_paths.len() + w.sitemap_urls.len() + w.security.len()
                });
                wk_ok = Some(matches!(end, End::Done(Ok(_))));
                if let End::Done(Ok(w)) = end {
                    input.wellknown = Some(w);
                }
            }
            board.set_progress(i, 0.6);
            c.progress(idx, board.fraction());
            // 3) grep.app, an optional third-party API
            if want("grepapp") {
                let base = grep_base(c);
                let end = step(c, "grepapp", grepapp::search(recon_net, &base, host, 1)).await?;
                let (status, cnt, err): (&str, Option<usize>, Option<String>) = match &end {
                    End::Done(Ok(r)) => ("ok", Some(r.hits.len()), None),
                    End::Done(Err(GrepAppError::Challenge)) => (
                        "blocked",
                        None,
                        Some("защита от ботов (челлендж grep.app)".into()),
                    ),
                    End::Done(Err(e)) => ("error", None, Some(e.to_string())),
                    End::Timeout => (
                        "timeout",
                        None,
                        Some("нет ответа за отведённое время".into()),
                    ),
                    End::Skipped => ("skipped", None, None),
                };
                c.source_event_full("grepapp", status, cnt, err.as_deref());
                set_src(&mut lf, "grepapp", status, cnt, err);
                ga_ok = Some(matches!(end, End::Done(Ok(_))));
                if let End::Done(Ok(r)) = end {
                    input.grepapp = Some(r);
                }
            }
            input.cert_issuer = cert_issuer(c, host);
            let mut rep = analyze_site(&input);
            if c.level == "active" && page_ok == Some(true) && !archive {
                readme_versions(c, recon_net, &input, &mut rep, readmes).await;
            }
            // the source did not answer (error/timeout/skip): earlier data is not erased
            let mut keep_totals = false;
            if let Some(p) = &prev_site {
                if page_ok == Some(false) {
                    let (wk, ga) = (rep.wellknown.take(), rep.grepapp.take());
                    rep = p.report.clone();
                    if wk.is_some() {
                        rep.wellknown = wk;
                    }
                    if ga.is_some() {
                        rep.grepapp = ga;
                    }
                    site.url = p.url.clone();
                    site.via = p.via.clone();
                    site.incomplete = true;
                    keep_totals = true;
                }
                if wk_ok == Some(false) && rep.wellknown.is_none() && p.report.wellknown.is_some() {
                    rep.wellknown = p.report.wellknown.clone();
                    site.incomplete = true;
                    keep_totals = true;
                }
                if ga_ok == Some(false) && rep.grepapp.is_none() && p.report.grepapp.is_some() {
                    rep.grepapp = p.report.grepapp.clone();
                    site.incomplete = true;
                }
                if site.incomplete {
                    rep.refresh_findings();
                }
            }
            // 4) cloud storage: always listed; listing checks only at the active level
            if want("buckets") {
                if c.level == "active" && !rep.buckets.is_empty() {
                    let opts = BucketCheckOptions {
                        enabled: true,
                        access: Access::Passive,
                        max_checks: 20,
                    };
                    let net = c.net.clone();
                    let mut b = rep.buckets.clone();
                    let end = step(c, "buckets", async {
                        check_buckets(&net, &mut b, &opts).await;
                        Ok::<usize, String>(b.len())
                    })
                    .await?;
                    report_end(c, &mut lf, "buckets", &end, |n| *n);
                    if matches!(end, End::Done(_)) {
                        rep.buckets = b;
                        rep.refresh_findings();
                    }
                } else {
                    let nb = rep.buckets.len();
                    c.source_event("buckets", "ok", Some(nb));
                    set_src(&mut lf, "buckets", "ok", Some(nb), None);
                }
            }
            // store compactly
            if let Some(w) = rep.wellknown.as_mut() {
                site.sitemap_total = w.sitemap_urls.len();
                w.sitemap_urls.truncate(KEEP_SITEMAP);
            }
            let mut ep_total = 0;
            for j in &mut rep.js {
                ep_total += j.endpoints.len();
            }
            site.endpoints_total = ep_total;
            if keep_totals {
                // stored lists are already truncated, so totals come from the previous snapshot
                if let Some(p) = &prev_site {
                    site.sitemap_total = site.sitemap_total.max(p.sitemap_total);
                    site.endpoints_total = site.endpoints_total.max(p.endpoints_total);
                }
            }
            let mut left = KEEP_ENDPOINTS;
            for j in &mut rep.js {
                let k = j.endpoints.len().min(left);
                j.endpoints.truncate(k);
                left -= k;
            }
            // recon.* findings join the shared list (stable ids; a rerun does not duplicate them)
            {
                let db = lock(&c.db);
                let mut nf: NetFacts = facts::get(&db, facts::K_NET);
                for f in &rep.findings {
                    let mut x = f.to_finding(now);
                    x.first_scan = Some(sid.clone());
                    if !nf.findings.contains_key(&x.id) {
                        new += 1;
                    }
                    nf.findings.entry(x.id).or_insert(x);
                }
                if let Some(w) = &web {
                    for f in &w.findings {
                        let mut x = f.to_finding(now);
                        x.first_scan = Some(sid.clone());
                        x.source = "Веб-аудит".into();
                        x.module = "webaudit".into();
                        x.active = w.level == Some(AuditLevel::Active)
                            && matches!(
                                f.rule.as_str(),
                                "recon.web.cors_reflected"
                                    | "recon.web.methods_unsafe_allowed"
                                    | "recon.web.trace_enabled"
                                    | "recon.web.webdav"
                                    | "recon.web.apidoc_graphql"
                            );
                        if !nf.findings.contains_key(&x.id) {
                            new += 1;
                        }
                        nf.findings.entry(x.id).or_insert(x);
                    }
                    // in-scope hosts from CSP, source maps and API docs join the host list
                    for h in &w.hosts {
                        let e = nf.host(h);
                        if e.source.is_empty() {
                            e.source = "Веб-аудит (CSP / source map / API)".into();
                            e.first_scan = Some(sid.clone());
                        }
                    }
                }
                facts::put(&db, facts::K_NET, &nf)?;
            }
            // out-of-scope hosts are candidates only (never contacted)
            if let Some(w) = &web {
                for h in &w.candidates {
                    super::infra::oos(c, h, "csp", host, "CSP / source map");
                }
            }
            site.web = web;
            site.report = rep;
            // stored right away, so a stop mid-stage keeps the sites already done
            {
                let db = lock(&c.db);
                let mut cur: ReconFacts = facts::get(&db, K_RECON);
                cur.level = c.level.clone();
                cur.sites.insert(host.clone(), site);
                cur.sources.extend(lf.sources.clone());
                cur.at = Some(now.clone());
                cur.scan = Some(sid.clone());
                facts::put(&db, K_RECON, &cur)?;
            }
            Ok::<_, Stop>((lf, new))
        }
    };
    let outs = c.each_host(&board, items, work).await;
    c.host_board_end(board, if outs.is_ok() { "done" } else { "skipped" });
    let outs = outs?;
    let mut new_findings = 0usize;
    {
        // source states in host order: the last site decides, as when sites ran one by one
        let db = lock(&c.db);
        let mut cur: ReconFacts = facts::get(&db, K_RECON);
        for (lf, nf) in outs {
            cur.sources.extend(lf.sources);
            new_findings += nf;
        }
        facts::put(&db, K_RECON, &cur)?;
    }
    if new_findings > 0 {
        let ids = reanalyze_bg(c).await?;
        c.findings_events(&ids);
    }
    tracing::info!(target: "foca::scan", "{}: разведка сайта {} сайт(ов), новых находок {new_findings}", c.scan_id, n);
    Ok(())
}

/// Site recon of open non-standard web ports of in-scope hosts (active level).
pub(super) async fn recon_extra_ports(c: &mut Ctx) -> Result<(), Stop> {
    if c.level != "active" || !c.module("recon") {
        return Ok(());
    }
    let ids = lock(&c.st).source_ids.clone();
    let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
    if !ids.iter().any(|x| x == "recon") || !super::source_enabled(&ss, "recon") {
        return Ok(());
    }
    let (f, hosts_known): (NetFacts, Vec<KnownHost>) = {
        let db = lock(&c.db);
        (facts::get(&db, facts::K_NET), super::known_hosts(&db))
    };
    let known = super::infra::known_of(&f, &hosts_known);
    let held = super::ports::held_names(c, &f);
    let sites: Vec<String> = f
        .hosts
        .values()
        .filter(|h| h.dangling.is_none() && rules::check(&c.scope, &h.name, &known).ok)
        .filter(|h| !held.contains(&h.name))
        .flat_map(|h| {
            super::infra::open_ports(h)
                .into_iter()
                .filter(|(p, _)| EXTRA_WEB_PORTS.contains(p))
                .map(|(p, _)| format!("{}:{p}", h.name))
                .collect::<Vec<_>>()
        })
        .take(MAX_EXTRA_SITES)
        .collect();
    if sites.is_empty() {
        return Ok(());
    }
    let net = c.group_net("recon")?;
    let now = c.e.now_iso();
    let sid = c.scan_id.clone();
    let c: &Ctx = c;
    // the site recon stage already used part of the per-scan render budget
    let used = facts::get::<ReconFacts>(&lock(&c.db), K_RECON)
        .sites
        .values()
        .filter(|s| s.rendered && s.scan == sid)
        .count();
    let renders = AtomicUsize::new(used);
    let render_cap = render_cap(c);
    let renders = &renders;
    let board = c.host_board(sites.len());
    let items: Vec<(String, String)> = sites.iter().map(|s| (s.clone(), s.clone())).collect();
    let work = |_: usize, site: String| {
        let (net, now, sid) = (&net, &now, &sid);
        async move {
            let mut input = foca_recon::ReconInput {
                target: site.clone(),
                ..Default::default()
            };
            let opts = foca_recon::collect::CollectOptions {
                archive: None,
                max_scripts: 3,
                ..Default::default()
            };
            let url = match foca_recon::collect::fetch_site(net, &site, &opts, &mut input).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::debug!(target: "foca::scan", "recon {site}: {e}");
                    return Ok(0);
                }
            };
            let host = site.split(':').next().unwrap_or(&site).to_string();
            let rendered = match render_home(c, net, &url, &host, renders, render_cap).await {
                Some(b) => {
                    input.browser.push(b);
                    true
                }
                None => false,
            };
            input.cert_issuer = cert_issuer(c, &host);
            let rep = foca_recon::analyze_site(&input);
            let db = lock(&c.db);
            let mut nf: NetFacts = facts::get(&db, facts::K_NET);
            let mut new = 0usize;
            for x in &rep.findings {
                let mut fd = x.to_finding(now);
                fd.first_scan = Some(sid.clone());
                if !nf.findings.contains_key(&fd.id) {
                    new += 1;
                }
                nf.findings.entry(fd.id).or_insert(fd);
            }
            facts::put(&db, facts::K_NET, &nf)?;
            let mut rf: ReconFacts = facts::get(&db, K_RECON);
            rf.sites.insert(
                site.clone(),
                SiteRecon {
                    host: site.clone(),
                    url,
                    via: "site".into(),
                    at: now.clone(),
                    scan: sid.clone(),
                    report: rep,
                    rendered,
                    ..Default::default()
                },
            );
            facts::put(&db, K_RECON, &rf)?;
            Ok::<usize, Stop>(new)
        }
    };
    let outs = c.each_host(&board, items, work).await;
    c.host_board_end(board, if outs.is_ok() { "done" } else { "skipped" });
    let new_findings: usize = outs?.into_iter().sum();
    if new_findings > 0 {
        let ids = super::reanalyze_bg(c).await?;
        c.findings_events(&ids);
    }
    Ok(())
}

fn bucket_view(b: &foca_recon::buckets::Bucket) -> Value {
    let (status, keys) = match &b.status {
        BucketStatus::Unchecked => ("unchecked", None),
        BucketStatus::PublicListing { keys, .. } => ("public", Some(*keys)),
        BucketStatus::Closed => ("closed", None),
        BucketStatus::NotFound => ("not_found", None),
        BucketStatus::Unknown { .. } => ("unknown", None),
    };
    json!({ "provider": b.provider, "label": b.provider.label(), "name": b.name,
        "url": b.listing_url(), "status": status, "keys": keys, "sources": b.sources })
}

/// Web audit view of one site for `project_snapshot.recon.web[]` and the report: header and
/// CSP issues, CSP domains (in scope or candidate), source maps (no source contents), API
/// docs, CORS and method probes. Secrets are never included (only masked findings).
fn web_view(host: &str, w: &WebAuditReport) -> Value {
    json!({
        "host": host,
        "level": w.level,
        "requests": w.requests,
        // Pages came from a web archive copy: header issues are informational only.
        "from_archive": w.from_archive,
        "errors": w.errors,
        "headers": w.headers.iter().map(|h| json!({ "url": h.url, "issues": h.issues })).collect::<Vec<_>>(),
        "csp_domains": w.csp_domains.iter().map(|d| json!({ "host": d.host, "wildcard": d.wildcard,
            "directives": d.directives, "in_scope": d.in_scope, "hint": d.hint })).collect::<Vec<_>>(),
        "hosts": w.hosts,
        "candidates": w.candidates,
        "source_maps": w.source_maps.iter().map(|m| json!({ "url": m.map_url, "script": m.script_url,
            "via": m.via, "sources": m.sources_total, "has_content": m.has_content,
            "packages": m.packages.iter().take(50).collect::<Vec<_>>(),
            "local_paths": m.local_paths.iter().take(20).collect::<Vec<_>>(),
            "secrets": m.secrets.len(), "truncated": m.truncated })).collect::<Vec<_>>(),
        "api_docs": w.api_docs.iter().map(|d| json!({ "kind": d.kind, "url": d.url, "title": d.title,
            "spec_version": d.spec_version, "api_version": d.api_version, "endpoints": d.endpoints,
            "operations": d.operations, "auth": d.auth, "unauthenticated": d.unauthenticated })).collect::<Vec<_>>(),
        "cors": w.cors,
        "methods": w.methods,
    })
}

fn code_view(g: &GrepAppResult) -> Value {
    json!({ "query": g.query, "total": g.total,
        "hits": g.hits.iter().take(50).map(|h| json!({ "repo": h.repo, "path": h.path, "url": h.url,
            "matches": h.total_matches,
            "lines": h.lines.iter().filter(|l| l.matched).take(3).map(|l| json!({ "line": l.line, "text": l.text })).collect::<Vec<_>>() })).collect::<Vec<_>>() })
}

/// Returns site technologies for the scan snapshot (`Scan.snapshot.tech`: name to version), used to compare scans.
pub(crate) fn tech_versions(db: &ProjectDb) -> BTreeMap<String, String> {
    let rf: ReconFacts = facts::get(db, K_RECON);
    let mut m = BTreeMap::new();
    for s in rf.sites.values() {
        for t in &s.report.technologies {
            let v = t.version.clone().unwrap_or_default();
            let e = m.entry(t.name.clone()).or_insert_with(String::new);
            if e.is_empty() {
                *e = v;
            }
        }
    }
    m
}

/// Builds the `project_snapshot.recon` view (see "Site reconnaissance" in `docs/API.md`): flat lists
/// for the Data screen and the report. Secrets are masked.
pub(crate) fn snapshot(db: &ProjectDb) -> Value {
    let rf: ReconFacts = facts::get(db, K_RECON);
    snapshot_of(&rf)
}

pub fn snapshot_of(rf: &ReconFacts) -> Value {
    let mut tech = Vec::new();
    let mut sites = Vec::new();
    let mut analytics = Vec::new();
    let mut hidden = Vec::new();
    let mut sitemap = Vec::new();
    let mut security = Vec::new();
    let mut endpoints = Vec::new();
    let mut secrets = Vec::new();
    let mut buckets: Vec<Value> = Vec::new();
    let mut code = Value::Null;
    let mut web_sites: Vec<Value> = Vec::new();
    let (mut sm_total, mut ep_total) = (0usize, 0usize);
    for (host, s) in &rf.sites {
        let r = &s.report;
        for t in &r.technologies {
            tech.push(
                json!({ "name": t.name, "version": t.version, "category": t.category,
                "outdated": t.outdated, "confidence": t.confidence, "host": host,
                "signals": t.signals, "evidence": t.evidence, "plugin_of": t.plugin_of,
                "slug": t.slug, "cpe": t.cpe }),
            );
        }
        for a in &r.analytics_ids {
            analytics.push(json!({ "kind": a.kind, "id": a.id, "host": host }));
        }
        sites.push(
            json!({ "host": host, "url": s.url, "via": s.via, "error": s.error, "at": s.at, "incomplete": s.incomplete,
            "favicon": r.favicon.as_ref().map(|f| json!({ "url": f.url, "mmh3": f.hash.mmh3,
                "md5": f.hash.md5, "sha256": f.hash.sha256, "size": f.hash.size,
                "queries": f.hash.queries.iter().filter_map(|q| q.split_once(": ")
                    .map(|(e, q)| json!({ "engine": e, "q": q }))).collect::<Vec<_>>() })) }),
        );
        if let Some(w) = &r.wellknown {
            for p in &w.hidden_paths {
                hidden.push(
                    json!({ "path": p.path, "reason": p.reason, "source": p.source, "host": host }),
                );
            }
            for u in &w.sitemap_urls {
                sitemap.push(json!({ "loc": u.loc, "lastmod": u.lastmod, "host": host }));
            }
            sm_total += s.sitemap_total.max(w.sitemap_urls.len());
            for x in &w.security {
                security.push(
                    json!({ "host": host, "source": x.source, "contacts": x.contacts,
                    "emails": x.emails, "expires": x.expires, "policy": x.policy }),
                );
            }
        }
        for j in &r.js {
            for e in &j.endpoints {
                endpoints.push(
                    json!({ "url": e.resolved.clone().unwrap_or_else(|| e.raw.clone()),
                    "kind": e.kind, "method": e.method, "source": e.source, "host": host }),
                );
            }
            for x in &j.secrets {
                secrets.push(json!({ "kind": x.kind, "title": x.title, "mask": x.masked,
                    "source": j.source_url, "line": x.line, "sev": x.sev, "host": host }));
            }
        }
        ep_total += s
            .endpoints_total
            .max(r.js.iter().map(|j| j.endpoints.len()).sum());
        for b in &r.buckets {
            let v = bucket_view(b);
            if !buckets
                .iter()
                .any(|x| x["name"] == v["name"] && x["provider"] == v["provider"])
            {
                buckets.push(v);
            }
        }
        if let Some(w) = &s.web {
            web_sites.push(web_view(host, w));
        }
        if code.is_null() {
            if let Some(g) = &r.grepapp {
                code = code_view(g);
            }
        }
    }
    let src = |id: &str| {
        rf.sources
            .get(id)
            .map(|s| json!({ "status": s.status, "n": s.n, "error": s.error }))
            .unwrap_or(Value::Null)
    };
    json!({
        "at": rf.at, "scan": rf.scan, "level": if rf.level.is_empty() { Value::Null } else { json!(rf.level) },
        "sources": { "recon": src("recon"), "webaudit": src("webaudit"), "wellknown": src("wellknown"), "buckets": src("buckets"), "grepapp": src("grepapp") },
        "sites": sites, "tech": tech, "analytics": analytics, "hidden_paths": hidden,
        "sitemap": sitemap, "sitemap_total": sm_total, "security": security,
        "endpoints": endpoints, "endpoints_total": ep_total, "secrets": secrets,
        "buckets": buckets, "code": code, "web": web_sites,
    })
}

/// Script files the crawler saw on this host beyond the home page's own (secrets and endpoints
/// analysis), fetched directly; standard and active profiles only.
const CRAWLED_SCRIPTS: usize = 10;

async fn crawled_scripts(c: &Ctx, net: &foca_net::NetClient, host: &str, input: &mut ReconInput) {
    let all: std::collections::BTreeMap<String, Vec<String>> =
        facts::get(&lock(&c.db), super::crawl::K_SCRIPTS);
    let Some(list) = all.get(&host.to_ascii_lowercase()) else {
        return;
    };
    let mut n = 0;
    for u in list {
        if n >= CRAWLED_SCRIPTS || net.is_cancelled() {
            break;
        }
        if input.scripts.iter().any(|s| &s.url == u) {
            continue;
        }
        if let Ok(f) = collect::fetch(net, u, None, 2 << 20).await {
            input.scripts.push(foca_recon::report::ScriptInput {
                url: u.clone(),
                body: String::from_utf8_lossy(&f.body).into_owned(),
            });
            n += 1;
        }
    }
}

/// `settings.recon.render_hosts`: home pages rendered per scan (0 turns rendering off).
fn render_cap(c: &Ctx) -> usize {
    c.e.store().settings_get().unwrap_or_default()["recon"]["render_hosts"]
        .as_u64()
        .unwrap_or(RENDER_HOSTS) as usize
}

/// Scan log note when browser-only signals cannot be read (no platform browser or turned off).
fn note_no_browser(c: &Ctx, cap: usize) {
    if c.e.current_render().is_none() {
        tracing::info!(target: "foca::scan", "{}: технологии: браузерные признаки не проверены (нет встроенного браузера: JS-переменные, DOM, XHR)", c.scan_id);
    } else if cap == 0 {
        tracing::info!(target: "foca::scan", "{}: технологии: браузерные признаки отключены (recon.render_hosts = 0)", c.scan_id);
    }
}

/// Renders the home page `url` once in the platform browser with the read-only probe script
/// (standard and active profiles, in-scope hosts, within the per-scan budget).
async fn render_home(
    c: &Ctx,
    net: &foca_net::NetClient,
    url: &str,
    host: &str,
    used: &AtomicUsize,
    cap: usize,
) -> Option<BrowserSignals> {
    if c.level == "external" || !net.host_in_scope(host) {
        return None;
    }
    let render = c.e.current_render()?;
    if used.fetch_add(1, Ordering::SeqCst) >= cap {
        return None;
    }
    let (code, _, _) = browser::probe_script(PROBE_BUDGET_MS);
    let proxy = net.config().proxy.clone().filter(|p| !p.trim().is_empty());
    let req = foca_search::RenderRequest::new("recon", Some(url), Duration::from_secs(40))
        .step(foca_search::RenderStep::Wait {
            gone: vec![],
            present: None,
            timeout_ms: 20_000,
            abort: vec![],
        })
        .step(foca_search::RenderStep::Sleep { ms: 1000 })
        .step(foca_search::RenderStep::Eval {
            code,
            timeout_ms: 3000,
        })
        .collecting_hosts()
        .through_proxy(proxy)
        .logged_as("recon");
    let r = net.cancellable(render.fetch(req)).await.ok()?;
    let mut rec = net.draft("recon", "RENDER", url, host, &Access::TouchesTarget);
    let out = match r {
        Ok(p) => {
            rec.status = p.status;
            rec.bytes = p.html.len() as u64;
            let b = p
                .eval
                .as_deref()
                .and_then(|e| BrowserSignals::from_eval(&p.url, e, &p.hosts));
            tracing::info!(target: "foca::scan", "{}: технологии: {host} отрисован в браузере, {}", c.scan_id,
                b.as_ref().map_or_else(|| "ответа пробы нет".to_string(), BrowserSignals::summary));
            b
        }
        Err(e) => {
            rec.error = Some(format!("network: {e}"));
            None
        }
    };
    net.record(rec);
    out
}

/// Browser signals of this host's pages the crawler rendered (app shells).
fn crawled_browser(c: &Ctx, host: &str) -> Vec<BrowserSignals> {
    let all: BTreeMap<String, Vec<BrowserSignals>> =
        facts::get(&lock(&c.db), super::crawl::K_BROWSER);
    all.get(&host.to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
}

/// Issuer of the host's TLS certificate from the network stage facts.
fn cert_issuer(c: &Ctx, host: &str) -> Option<String> {
    let nf: NetFacts = facts::get(&lock(&c.db), facts::K_NET);
    let h = nf.hosts.get(&host.to_ascii_lowercase())?;
    h.tls.as_ref()?["issuer"].as_str().map(String::from)
}

/// Active profile: WordPress plugin versions from their `readme.txt` (shared per-scan budget).
async fn readme_versions(
    c: &Ctx,
    net: &foca_net::NetClient,
    input: &ReconInput,
    rep: &mut ReconReport,
    used: &AtomicUsize,
) {
    let parts = foca_recon::tech::cmsparts::find_parts(&input.pages, &rep.technologies);
    let want = parts
        .iter()
        .filter(|p| p.cms == "wordpress" && p.kind == "plugin")
        .count();
    if want == 0 {
        return;
    }
    let max = foca_recon::tech::cmsparts::MAX_READMES;
    let start = used.fetch_add(want, Ordering::SeqCst).min(max);
    let left = (max - start).min(want);
    if left == 0 {
        return;
    }
    let sent =
        foca_recon::tech::cmsparts::check_readmes(net, &mut rep.technologies, &parts, left).await;
    tracing::info!(target: "foca::scan", "{}: технологии: проверено readme.txt плагинов WordPress: {sent}", c.scan_id);
}

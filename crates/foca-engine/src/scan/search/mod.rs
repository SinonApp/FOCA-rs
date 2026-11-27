//! Search stage: document search engines, archives and host sources.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use foca_net::Access;
use foca_search::download::Downloader;
use foca_search::sources::{CcDepth, CommonCrawl, PendingDorks};
use foca_search::store::{SharedDb, StoreQueue};
use foca_search::{DocumentSource, ExtFilter, FoundUrl, SearchCtx, SourceReport};
use serde_json::{json, Value};

use crate::analysis::facts::{self, NetFacts};
use crate::engine::lock;

pub(crate) mod dorks;

use super::documents::{crawl, downloader};
use super::sources::WEB_ENGINES;
use super::*;

/// Takes the requested retries (`retry:<id>`) out of the `skip` set.
fn take_retries(skip: &Mutex<std::collections::HashSet<String>>) -> Vec<String> {
    let mut g = lock(skip);
    let ids: Vec<String> = g
        .iter()
        .filter_map(|x| x.strip_prefix(RETRY_PREFIX).map(String::from))
        .collect();
    for id in &ids {
        g.remove(&format!("{RETRY_PREFIX}{id}"));
    }
    ids
}

pub(super) async fn stage_search(c: &mut Ctx) -> Result<(), Stop> {
    let c: &Ctx = c;
    let ep = c.e.cfg.endpoints.clone();
    let keys = c.e.current_keys();
    let ids = lock(&c.st).source_ids.clone();
    // a source is queried if selected and, for the custom profile, its module is enabled
    let want =
        |id: &str| ids.iter().any(|x| x == id) && source_modules(id).iter().any(|m| c.module(m));
    let settings = c.e.store().settings_get()?;
    let mut list: Vec<Box<dyn DocumentSource>> = Vec::new();
    // slow archives first (with parallel querying they do not wait for fast APIs)
    if want("wayback") {
        list.push(Box::new(foca_search::sources::Wayback::with_base(
            &ep.wayback,
        )));
    }
    // a deep Common Crawl sweep runs beside the other sources, a quick one among them
    let mut deep_cc: Option<CommonCrawl> = None;
    if want("cc") {
        let cc = cc_source(c, &settings);
        if cc.is_deep() {
            deep_cc = Some(cc);
        } else {
            list.push(Box::new(cc));
        }
    }
    // keyed dork engines (own SearXNG first, then the Brave API) take dork groups before the
    // keyless engines and the public SearXNG pool
    if want("searx") {
        list.push(Box::new(own_searx(c, keys.get("searx"))));
    }
    if want("brave") {
        let mut b = foca_search::sources::Brave::new(keys.get("brave"));
        if let Some(base) = ep.sources.get("brave") {
            b = b.with_base(base);
        }
        list.push(Box::new(b));
    }
    if want("crt") {
        list.push(Box::new(foca_search::sources::CrtSh::with_base(&ep.crtsh)));
    }
    for id in HOST_SOURCE_IDS {
        if want(id) {
            if let Some(mut h) = foca_search::sources::host_source(id) {
                if *id == "otx_dns" {
                    h = h.with_key(keys.get("otx"));
                }
                list.push(Box::new(match ep.sources.get(*id) {
                    Some(b) => h.with_base(b),
                    None => h,
                }));
            }
        }
    }
    let headless = lock(&c.st).headless;
    let render = c.e.current_render();
    for id in DOC_SOURCE_IDS {
        if want(id) {
            if headless && render.is_none() && WEBVIEW_SOURCES.contains(id) {
                continue;
            }
            if *id == "otx_url" {
                let mut u =
                    foca_search::sources::UrlSource::new(foca_search::sources::UrlKind::Otx)
                        .with_key(keys.get("otx"));
                if let Some(b) = ep.sources.get(*id) {
                    u = u.with_base(b);
                }
                list.push(Box::new(u));
            } else {
                let s = match ep.sources.get(*id) {
                    Some(b) => foca_search::sources::url_source_with_base(id, b),
                    None => foca_search::sources::url_source(id),
                };
                list.extend(s);
            }
        }
    }
    if want("vt") {
        let mut s = foca_search::sources::VirusTotal::new(keys.get("vt"));
        if let Some(b) = ep.sources.get("vt") {
            s = s.with_base(b);
        }
        list.push(Box::new(s));
    }
    if want("st") {
        let mut s = foca_search::sources::SecurityTrails::new(keys.get("st"));
        if let Some(b) = ep.sources.get("st") {
            s = s.with_base(b);
        }
        list.push(Box::new(s));
    }
    if want("github") {
        let mut s = foca_search::sources::GitHubCode::new(keys.get("github"));
        if let Some(b) = ep.sources.get("github") {
            s = s.with_base(b);
        }
        list.push(Box::new(s));
    }
    let (limit, exts) = {
        let s = lock(&c.st);
        (s.limit, s.exts.clone())
    };
    // crawling is a request to the target: never at the passive level
    let crawl_cfg = crawl::cfg(c);
    let mut crawl_out = None;
    if want("crawler") && c.level != "external" {
        let cr = crawl::crawler(c, &crawl_cfg);
        crawl_out = Some(cr.out.clone());
        list.push(Box::new(cr));
    }
    let mut crawl_extra: Vec<(FoundUrl, foca_core::api::DocProvenance)> = Vec::new();
    // wizard document types filter sources, dorks (filetype:) and the download queue
    let ext_filter = (!exts.is_empty()).then(|| foca_search::filter::ExtFilter::new(&exts));
    let enq = Enqueuer::new(c, ext_filter.clone(), limit);
    let mut ct_hosts: BTreeSet<String> = BTreeSet::new();
    let mut found: Vec<foca_search::FoundUrl> = Vec::new();
    let mut host_src: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut tally = Tally::default();
    // web dork engines: id to whether the latest outcome was a captcha/block
    let mut web: std::collections::BTreeMap<String, bool> = Default::default();
    // documents already known to the project; sources skip them before applying their limit
    let known: Arc<std::collections::HashSet<String>> = Arc::new(
        lock(&c.db)
            .task_urls()?
            .iter()
            .map(|u| foca_search::filter::target_key(u))
            .collect(),
    );
    let doms = c.domains.clone();
    let nd = doms.len().max(1);
    // Shared dork board of the scan: one query queue for all search engines, failover on captcha,
    // per-engine budget, and a 24 h result cache (a file in the data directory shared by projects).
    let dork_board = Arc::new(foca_search::sources::DorkBoard::new(
        foca_search::sources::DorkCache::new(Some(c.e.cfg.data_dir.join("dork-cache.json"))),
    ));
    // dork groups postponed by earlier runs go first
    let pending: PendingDorks = dorks::load(&lock(&c.db));
    let filter_now = ext_filter.clone().unwrap_or_default();
    for d in &doms {
        let groups = foca_search::sources::dorkpool::ext_groups(|e| filter_now.allows_ext(e));
        dork_board.plan(d, &pending.first(d, groups));
    }
    let search_net = c.group_net("search")?;
    let make_ctx = |d: &str, k: usize| -> (SearchCtx, Value) {
        let mut ctx = SearchCtx::new(search_net.clone());
        ctx.limit = limit;
        if let Some(f) = &ext_filter {
            ctx.filter = f.clone();
        }
        ctx.known = known.clone();
        ctx.render = c.e.current_render();
        ctx.headless = headless;
        ctx.dorks = Some(dork_board.clone());
        // With several target domains, sources are queried in rounds, one per domain. round/rounds go into
        // the events so the UI does not show "no answer" for domain 1 as the final status.
        let round = json!({ "domain": d, "round": k + 1, "rounds": nd });
        {
            let (e, sid, round) = (c.e.clone(), c.scan_id.clone(), round.clone());
            ctx.on_retry = Some(Arc::new(move |id: &str, n: u32, why: &str| {
                let name = SOURCES.iter().find(|s| s.0 == id).map_or(id, |s| s.1);
                let mut ev = json!({ "type": "source", "scan_id": sid, "id": id, "name": name,
                    "status": "running", "retry": n, "retry_reason": why });
                if let (Some(o), Some(r)) = (ev.as_object_mut(), round.as_object()) {
                    o.extend(r.clone());
                }
                e.emit(ev);
            }));
        }
        (ctx, round)
    };
    let cref: &Ctx = c;
    // the deep Common Crawl lane: one domain after another, its own time budget, the same skip set
    let lane = async {
        let mut out = LaneOut::default();
        let Some(cc) = deep_cc.as_ref() else {
            return Ok::<LaneOut, Stop>(out);
        };
        let minutes = settings["search"]["cc_minutes"]
            .as_u64()
            .unwrap_or(15)
            .clamp(1, 240);
        let ctl = foca_search::SourceCtl {
            timeout: std::time::Duration::from_secs(minutes * 60 / nd as u64 / 10)
                .max(std::time::Duration::from_secs(6)),
            skip: cref.skip.clone(),
            parallel: 1,
        };
        let one: [Box<dyn DocumentSource>; 1] = [Box::new(cc.clone())];
        for (k, d) in doms.iter().enumerate() {
            let (ctx, round) = make_ctx(d, k);
            let res = foca_search::run_sources_ctl(
                &one,
                &ctx,
                d,
                &ctl,
                |id, t| running_event(cref, id, t, &round),
                |r| {
                    source_done_event(cref, r, &round);
                },
            )
            .await;
            match res {
                Ok(r) => out.res.push(r),
                Err(foca_net::NetError::Cancelled) => return Err(Stop::Cancelled),
                Err(e) => return Err(Stop::Error(e.to_string())),
            }
        }
        Ok(out)
    };
    let main = async {
        for (k, d) in doms.iter().enumerate() {
            cref.gate().await?;
            let (ctx, round) = make_ctx(d, k);
            let ctl = foca_search::SourceCtl {
                timeout: cref.e.source_timeout(),
                skip: cref.skip.clone(),
                // up to 4 passive sources at once (different services; one service is queried sequentially)
                parallel: 4,
            };
            // "retry source" after a manual check: one more pass over just those sources
            let mut retry_list: Vec<Box<dyn DocumentSource>> = Vec::new();
            for pass in 0..3 {
                let srcs: &[Box<dyn DocumentSource>] = if pass == 0 { &list } else { &retry_list };
                let total = srcs.len().max(1);
                let mut done = 0usize;
                // Emit source events as they happen (running, then ok/error/timeout/skipped), not after all of them;
                // otherwise the scan screen sits at "N/8 sources" until the slowest one answers.
                let res = foca_search::run_sources_ctl(
                    srcs,
                    &ctx,
                    d,
                    &ctl,
                    |id, timeout| running_event(cref, id, timeout, &round),
                    |r| {
                        done += 1;
                        source_done_event(cref, r, &round);
                        cref.progress(0, (k as f64 + done as f64 / total as f64) / nd as f64);
                    },
                )
                .await;
                let res = match res {
                    Ok(r) => r,
                    Err(foca_net::NetError::Cancelled) => return Err(Stop::Cancelled),
                    Err(e) => return Err(Stop::Error(e.to_string())),
                };
                for r in &res.sources {
                    tally.add(r);
                    if WEB_ENGINES.contains(&r.id.as_str()) {
                        web.insert(r.id.clone(), r.status == foca_search::SourceStatus::Blocked);
                    }
                }
                merge_hosts(&mut ct_hosts, &mut host_src, &res);
                found.extend(res.urls);
                // what the crawl of this domain left besides document URLs
                let ran = res.sources.iter().any(|r| {
                    r.id == "crawler"
                        && !matches!(
                            r.status,
                            foca_search::SourceStatus::Skipped | foca_search::SourceStatus::Nokey
                        )
                });
                if let (Some(out), true, 0) = (&crawl_out, ran, pass) {
                    let o = std::mem::take(&mut *lock(out));
                    let x =
                        crawl::after_domain(cref, &crawl_cfg, d, o, &search_net, &known).await?;
                    crawl_extra.extend(x.items);
                }
                let retry_ids = take_retries(&cref.skip);
                // after a manual check the engine is healthy again and takes the remaining dork groups
                for id in &retry_ids {
                    dork_board.unblock(id);
                }
                retry_list = retry_ids
                    .iter()
                    .flat_map(|id| match ep.sources.get(id.as_str()) {
                        Some(b) => foca_search::sources::url_source_with_base(id, b),
                        None => foca_search::sources::url_source(id),
                    })
                    .collect();
                if retry_list.is_empty() {
                    break;
                }
                tracing::info!(target: "foca::scan", "{}: повтор после проверки {} источн.", cref.scan_id, retry_list.len());
            }
        }
        Ok::<(), Stop>(())
    };
    // both run at once; a stopped or skipped stage drops the lane (its finished snapshots are saved)
    let mut lane = std::pin::pin!(lane);
    let mut lane_out: Option<Result<LaneOut, Stop>> = None;
    {
        let mut main = std::pin::pin!(main);
        loop {
            tokio::select! {
                r = &mut main => { r?; break; }
                o = &mut lane, if lane_out.is_none() => lane_out = Some(o),
            }
        }
    }
    let lane_out = match lane_out {
        Some(o) => o?,
        None => lane.await?,
    };
    for r in lane_out.res {
        for s in &r.sources {
            tally.add(s);
        }
        merge_hosts(&mut ct_hosts, &mut host_src, &r);
        found.extend(r.urls);
    }
    let c: &Ctx = cref;
    let drop = enq.enqueue(found, &known)?;
    // storage files linked from in-scope pages share the download limit with the documents
    // queued above; selected images have their own caps
    if !crawl_extra.is_empty() {
        let queue = StoreQueue::new(c.db.clone(), Some(c.scan_id.clone()));
        let room = crawl::doc_room(c)?;
        let q = crawl::enqueue(c, &queue, crawl_extra, &known, room)?;
        tracing::info!(target: "foca::scan", "{}: в загрузку из обхода (хранилища, изображения): {}, сверх лимита {}", c.scan_id, q.added, q.over_limit);
    }
    if drop.found > 0 {
        let note = queue_note(&drop);
        c.sub_note("queue", drop.added, drop.found, &note);
    }
    c.source_event("dns", "ok", Some(ct_hosts.len()));
    // No source gave data: an explicit warning rather than an empty result. `no_network` only when
    // nothing answered at all; a rate limit, a captcha or any HTTP answer means the network works.
    if tally.attempted > 0 && tally.answered == 0 {
        let reached = tally.limited > 0 || got_http_answer(c);
        if !reached {
            c.warn(
                "no_network",
                "Нет сети или все источники недоступны: результаты скана неполные",
            );
        } else if tally.limited > 0 {
            c.warn(
                "search_sources_limited",
                "Источники поиска не дали данных: все ограничили запросы или показали капчу. \
                 Сеть работает: повторите позже или пройдите проверку",
            );
        } else {
            c.warn(
                "search_sources_failed",
                "Источники поиска не дали данных: все ответили ошибкой. Сеть работает: повторите позже",
            );
        }
    }
    // per-engine dork totals go to the scan log (requests / results / captchas / handed over)
    for (id, st) in dork_board.stats() {
        tracing::info!(target: "foca::scan", "{}: дорки {id}: запросов {}, выдач {}, ссылок {}, капч {}, из кэша {}, отдано {}, взято {}", c.scan_id, st.requests, st.answered, st.links, st.captchas, st.cached, st.moved, st.taken_over);
    }
    // dork groups no engine could run are postponed per project and retried later
    let lost: usize = doms.iter().map(|d| dork_board.lost(d)).sum();
    let captcha_seen = web.values().any(|b| *b)
        || dork_board
            .stats()
            .values()
            .any(|st| st.captchas > 0 || st.blocked);
    let pend = dorks::after_search(c, &dork_board, &doms, captcha_seen)?;
    let retry_min = dorks::retry_minutes(&settings);
    if lost > 0 && web.values().any(|b| *b) {
        c.warn(
            "search_dorks_lost",
            &format!(
                "Часть дорков ({lost}) не выполнил ни один поисковик: все в капче. Они отложены и \
                 повторятся сами: позже в этом скане и в следующем скане"
            ),
        );
    }
    if pend > 0 && retry_min > 0.0 {
        dorks::spawn_retry(c, &enq, &known, filter_now.clone(), retry_min);
    }
    // all queried web search engines showed a captcha or block; a common cause is a VPN or proxy IP
    if web.len() >= 2 && web.values().all(|b| *b) {
        c.warn(
            "search_captcha",
            "Все веб-поисковики показали капчу или заблокировали запросы, частая причина: общий IP \
             VPN или прокси. Пройдите проверку в карточке Startpage/Mojeek или повторите скан с \
             другой сети",
        );
    }
    let db = lock(&c.db);
    let mut f: NetFacts = facts::get(&db, facts::K_NET);
    f.ct_hosts.extend(ct_hosts);
    facts::put(&db, facts::K_NET, &f)?;
    let mut hs: std::collections::BTreeMap<String, Vec<String>> = facts::get(&db, K_HOST_SRC);
    for (h, v) in host_src {
        let e = hs.entry(h).or_default();
        for id in v {
            if !e.contains(&id) {
                e.push(id);
            }
        }
    }
    facts::put(&db, K_HOST_SRC, &hs)?;
    Ok(())
}

/// Source outcome counters of the search stage (for the "no data" warnings).
#[derive(Default)]
struct Tally {
    attempted: usize,
    answered: usize,
    limited: usize,
}

impl Tally {
    fn add(&mut self, r: &SourceReport) {
        use foca_search::SourceStatus as S;
        match r.status {
            S::Ok => {
                self.attempted += 1;
                self.answered += 1;
            }
            S::Error | S::Timeout => self.attempted += 1,
            // the source answered with a rate limit or a captcha: the network works
            S::Limit | S::Blocked => {
                self.attempted += 1;
                self.limited += 1;
            }
            _ => {}
        }
    }
}

/// Results of the deep Common Crawl lane, one per domain.
#[derive(Default)]
struct LaneOut {
    res: Vec<foca_search::SearchResult>,
}

fn merge_hosts(
    ct_hosts: &mut BTreeSet<String>,
    host_src: &mut std::collections::BTreeMap<String, Vec<String>>,
    res: &foca_search::SearchResult,
) {
    ct_hosts.extend(res.hosts.iter().cloned());
    for (h, v) in &res.host_sources {
        let e = host_src.entry(h.clone()).or_default();
        for id in v {
            if !e.contains(id) {
                e.push(id.clone());
            }
        }
    }
}

/// `source` event `running` with the effective deadline (three times longer for slow archives);
/// the UI only shows the time left and never declares "no answer" itself.
fn running_event(c: &Ctx, id: &str, timeout: std::time::Duration, round: &Value) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let mut x = json!({ "timeout_s": timeout.as_secs(),
        "deadline_ms": now_ms + timeout.as_millis() as u64 });
    if let (Some(o), Some(r)) = (x.as_object_mut(), round.as_object()) {
        o.extend(r.clone());
    }
    c.source_event_x(id, "running", None, None, x)
}

/// Final `source` event of a source: an optional source without a key is `off`, a captcha from a
/// browser-based engine carries the manual check URL.
fn source_done_event(c: &Ctx, r: &SourceReport, round: &Value) {
    let st = serde_json::to_value(r.status)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "ok".into());
    let optional = SOURCES.iter().any(|s| s.0 == r.id && s.3);
    let st = if st == "nokey" && optional {
        "off".into()
    } else {
        st
    };
    let mut extra = round.clone();
    if let Some(u) = (st == "blocked")
        .then(|| foca_search::sources::verify_url(&r.id, r.error.as_deref().unwrap_or("")))
        .flatten()
    {
        extra["verify_url"] = json!(u);
    }
    c.source_event_x(&r.id, &st, Some(r.n), r.error.as_deref(), extra);
}

/// The engine runs on the local test bench (endpoints are not the public services).
pub(super) fn test_bench(c: &Ctx) -> bool {
    !c.e.cfg.endpoints.crtsh.starts_with("https://crt.sh")
}

/// Common Crawl source for this run: depth from the wizard or `settings.search`, at least 3 s
/// between calls to the public index (`search.cc_pace_s`), a per-domain cache in the data dir.
fn cc_source(c: &Ctx, settings: &Value) -> CommonCrawl {
    let s = &settings["search"];
    let (mode, years) = {
        let st = lock(&c.st);
        (
            st.cc_depth
                .clone()
                .unwrap_or_else(|| s["cc_depth"].as_str().unwrap_or("latest").to_string()),
            st.cc_years.or(s["cc_years"].as_u64()).unwrap_or(3),
        )
    };
    let mut cc = CommonCrawl::with_collinfo(&c.e.cfg.endpoints.cc_collinfo)
        .with_depth(CcDepth::parse(&mode, years));
    if c.e
        .cfg
        .endpoints
        .cc_collinfo
        .starts_with(foca_search::sources::commoncrawl::CC_INDEX_HOST)
    {
        let pace = s["cc_pace_s"].as_f64().unwrap_or(3.0).clamp(3.0, 60.0);
        cc = cc.with_pace(std::time::Duration::from_secs_f64(pace));
    }
    cc.with_cache_dir(c.e.cfg.data_dir.join("cc-cache"))
}

/// The user's own SearXNG instances (HTTP and local hosts only on the test bench).
fn own_searx(c: &Ctx, raw: Option<String>) -> foca_search::sources::Searx {
    foca_search::sources::Searx::new(raw).with_local(test_bench(c))
}

/// Download queue of the search stage: scope filter, Wayback copies for the passive profile,
/// type filter, dedup against the project and a fair pick across sources. Shared with the
/// in-scan retry of postponed dorks.
#[derive(Clone)]
pub(super) struct Enqueuer {
    db: SharedDb,
    scan_id: String,
    scope: foca_core::api::ScopeDto,
    level: String,
    downloader: Downloader,
    wb: String,
    ext_filter: Option<ExtFilter>,
    limit: usize,
}

impl Enqueuer {
    pub(super) fn new(c: &Ctx, ext_filter: Option<ExtFilter>, limit: usize) -> Self {
        Enqueuer {
            db: c.db.clone(),
            scan_id: c.scan_id.clone(),
            scope: c.scope.clone(),
            level: c.level.clone(),
            downloader: downloader(c),
            wb: c.e.cfg.endpoints.wayback.clone(),
            ext_filter,
            limit,
        }
    }

    pub(super) fn db(&self) -> &SharedDb {
        &self.db
    }

    /// Queues found URLs for download: (1) documents of hosts outside the scope are dropped (a URL
    /// target covers only its own host, so dork hits on its subdomains would only be refused at
    /// download); (2) with the passive profile, target site URLs are replaced with Wayback copies
    /// (`id_`); (3) other types and URLs already known to the project are skipped before the
    /// limit, so a rescan picks up new documents; (4) documents round-robin across sources, images
    /// with a smaller quota.
    pub(super) fn enqueue(
        &self,
        found: Vec<FoundUrl>,
        known: &std::collections::HashSet<String>,
    ) -> Result<QueueDrops, Stop> {
        let mut seen = std::collections::HashSet::new();
        let scope_hosts = known_hosts(&lock(&self.db));
        let mut drop = QueueDrops {
            found: found.len(),
            ..Default::default()
        };
        let fresh: Vec<FoundUrl> = found
            .into_iter()
            .filter(|u| {
                let host = url::Url::parse(u.target_url())
                    .ok()
                    .and_then(|x| x.host_str().map(str::to_ascii_lowercase))
                    .unwrap_or_default();
                let ok = rules::check(&self.scope, &host, &scope_hosts).ok;
                drop.out_of_scope += usize::from(!ok);
                ok
            })
            .filter_map(|mut u| {
                if self.level == "external" && self.downloader.access_for(&u.url) != Access::Passive
                {
                    let orig = u.target_url().to_string();
                    // Use the snapshot/index date, otherwise one near 2025 (Wayback redirects to the nearest
                    // copy; with no copy it returns 404 and the task fails without touching the target).
                    let ts = u
                        .date
                        .clone()
                        .map(|d| d.chars().filter(char::is_ascii_digit).collect::<String>())
                        .filter(|d| d.len() >= 4)
                        .unwrap_or_else(|| "2025".into());
                    u.url = foca_search::sources::copy_url(&self.wb, &ts, &orig);
                    u.original = Some(orig);
                    if self.downloader.access_for(&u.url) != Access::Passive {
                        drop.passive += 1;
                        return None;
                    }
                }
                Some(u)
            })
            .filter(|u| {
                let ok = self
                    .ext_filter
                    .as_ref()
                    .is_none_or(|f| f.matches(u.target_url()).is_some());
                drop.other_type += usize::from(!ok);
                ok
            })
            .filter(|u| {
                let key = foca_search::filter::target_key(u.target_url());
                let ok = !known.contains(&key) && seen.insert(key);
                drop.known += usize::from(!ok);
                ok
            })
            .collect();
        let pick = foca_search::pick_fair(fresh, self.limit);
        let queue = StoreQueue::new(self.db.clone(), Some(self.scan_id.clone()));
        drop.added = queue.enqueue(&pick).map_err(Stop::Error)?;
        tracing::info!(target: "foca::scan", "{}: в загрузку {} новых (лимит {}, известных {}; найдено {}, вне скоупа {}, другой тип {}, уже известны {}, без архивной копии {})",
            self.scan_id, drop.added, self.limit, known.len(), drop.found, drop.out_of_scope, drop.other_type, drop.known, drop.passive);
        Ok(drop)
    }
}

/// Some request of this scan got an HTTP answer (any status): the network is up.
fn got_http_answer(c: &Ctx) -> bool {
    lock(&c.db)
        .requests(Some(&c.scan_id), false)
        .unwrap_or_default()
        .iter()
        .any(|r| r.status.is_some())
}

/// Why found documents did not reach the download queue.
#[derive(Debug, Default)]
pub(super) struct QueueDrops {
    pub(super) found: usize,
    pub(super) added: usize,
    out_of_scope: usize,
    other_type: usize,
    known: usize,
    /// Passive profile: no archive copy can stand in for a target URL.
    passive: usize,
}

/// Summary of the download queue for the search stage row (core message `search.queue`).
fn queue_note(d: &QueueDrops) -> String {
    format!(
        "в загрузку {} из {} (вне скоупа {}, уже известны {}, другой тип {})",
        d.added,
        d.found,
        d.out_of_scope,
        d.known,
        d.other_type + d.passive
    )
}

/// A queue summary as the core emits it (for the i18n sample test).
#[cfg(test)]
pub(crate) fn queue_note_sample() -> String {
    queue_note(&QueueDrops {
        found: 8,
        added: 0,
        out_of_scope: 6,
        known: 1,
        other_type: 1,
        passive: 0,
    })
}

/// Facts key: which sources found each subdomain (`host -> [id, ...]`).
pub(super) const K_HOST_SRC: &str = "engine.host_src";

/// Returns the subdomain source names for the host card ("crt.sh, Anubis, ...").
pub(super) fn host_source_label(ids: &[String]) -> String {
    let names: Vec<&str> = ids
        .iter()
        .map(|id| {
            SOURCES
                .iter()
                .find(|s| s.0 == id)
                .map(|s| s.1)
                .unwrap_or(id.as_str())
        })
        .collect();
    if names.is_empty() {
        "crt.sh".into()
    } else {
        names.join(", ")
    }
}

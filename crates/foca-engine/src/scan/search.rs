//! Search stage: document search engines, archives and host sources.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use foca_net::Access;
use foca_search::store::StoreQueue;
use foca_search::{DocumentSource, SearchCtx};
use serde_json::json;

use crate::analysis::facts::{self, NetFacts};
use crate::engine::lock;

use super::documents::downloader;
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
    let ep = c.e.cfg.endpoints.clone();
    let keys = c.e.current_keys();
    let ids = lock(&c.st).source_ids.clone();
    // a source is queried if selected and, for the custom profile, its module is enabled
    let want =
        |id: &str| ids.iter().any(|x| x == id) && source_modules(id).iter().any(|m| c.module(m));
    let mut list: Vec<Box<dyn DocumentSource>> = Vec::new();
    // slow archives first (with parallel querying they do not wait for fast APIs)
    if want("wayback") {
        list.push(Box::new(foca_search::sources::Wayback::with_base(
            &ep.wayback,
        )));
    }
    if want("cc") {
        list.push(Box::new(foca_search::sources::CommonCrawl::with_collinfo(
            &ep.cc_collinfo,
        )));
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
    if want("brave") {
        list.push(Box::new(foca_search::sources::Brave::new(
            keys.get("brave"),
        )));
    }
    if want("searx") {
        list.push(Box::new(foca_search::sources::Searx::new(
            keys.get("searx"),
        )));
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
    let (limit, exts, crawl_depth) = {
        let s = lock(&c.st);
        (s.limit, s.exts.clone(), s.crawl_depth)
    };
    if want("crawler") && c.level != "external" {
        let mut cr = foca_search::sources::Crawler::default();
        if let Some(d) = crawl_depth {
            cr = cr.with_max_depth(d);
        }
        list.push(Box::new(cr));
    }
    // wizard document types filter sources, dorks (filetype:) and the download queue
    let ext_filter = (!exts.is_empty()).then(|| foca_search::filter::ExtFilter::new(&exts));
    let downloader = downloader(c);
    let queue = StoreQueue::new(c.db.clone(), Some(c.scan_id.clone()));
    let mut ct_hosts: BTreeSet<String> = BTreeSet::new();
    let mut found: Vec<foca_search::FoundUrl> = Vec::new();
    let mut host_src: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut attempted = 0usize;
    let mut answered = 0usize;
    let mut limited = 0usize;
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
    let search_net = c.group_net("search")?;
    for (k, d) in doms.iter().enumerate() {
        c.gate().await?;
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
        let ctl = foca_search::SourceCtl {
            timeout: c.e.source_timeout(),
            skip: c.skip.clone(),
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
                |id, timeout| {
                    // The source deadline comes from the core (the effective one: three times longer for slow archives);
                    // the UI only shows the time left and never declares "no answer" itself.
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis() as u64);
                    let mut x = json!({ "timeout_s": timeout.as_secs(),
                    "deadline_ms": now_ms + timeout.as_millis() as u64 });
                    if let (Some(o), Some(r)) = (x.as_object_mut(), round.as_object()) {
                        o.extend(r.clone());
                    }
                    c.source_event_x(id, "running", None, None, x)
                },
                |r| {
                    done += 1;
                    let st = serde_json::to_value(r.status)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_else(|| "ok".into());
                    // an optional source without a key is "not connected", not an error
                    let optional = SOURCES.iter().any(|s| s.0 == r.id && s.3);
                    let st = if st == "nokey" && optional {
                        "off".into()
                    } else {
                        st
                    };
                    let mut extra = round.clone();
                    // a captcha or challenge from a browser-based engine: provide the manual check URL
                    if let Some(u) = (st == "blocked")
                        .then(|| {
                            foca_search::sources::verify_url(
                                &r.id,
                                r.error.as_deref().unwrap_or(""),
                            )
                        })
                        .flatten()
                    {
                        extra["verify_url"] = json!(u);
                    }
                    c.source_event_x(&r.id, &st, Some(r.n), r.error.as_deref(), extra);
                    c.progress(0, (k as f64 + done as f64 / total as f64) / nd as f64);
                },
            )
            .await;
            let res = match res {
                Ok(r) => r,
                Err(foca_net::NetError::Cancelled) => return Err(Stop::Cancelled),
                Err(e) => return Err(Stop::Error(e.to_string())),
            };
            for r in &res.sources {
                use foca_search::SourceStatus as S;
                match r.status {
                    S::Ok => {
                        attempted += 1;
                        answered += 1;
                    }
                    S::Error | S::Timeout => attempted += 1,
                    // the source answered with a rate limit or a captcha: the network works
                    S::Limit | S::Blocked => {
                        attempted += 1;
                        limited += 1;
                    }
                    _ => {}
                }
                if WEB_ENGINES.contains(&r.id.as_str()) {
                    web.insert(r.id.clone(), r.status == S::Blocked);
                }
            }
            ct_hosts.extend(res.hosts.iter().cloned());
            for (h, v) in res.host_sources {
                let e = host_src.entry(h).or_default();
                for id in v {
                    if !e.contains(&id) {
                        e.push(id);
                    }
                }
            }
            found.extend(res.urls);
            let retry_ids = take_retries(&c.skip);
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
            tracing::info!(target: "foca::scan", "{}: повтор после проверки {} источн.", c.scan_id, retry_list.len());
        }
    }
    // Queue for download: (1) skip URLs already known to the project (dedup against the database before
    // the limit, so a rescan picks up new documents); (2) with the passive profile, target site URLs are
    // replaced with Wayback copies (`id_`); (3) documents of hosts outside the scope are dropped here
    // (a URL target covers only its own host, so dork hits on its subdomains would only be refused
    // at download); (4) documents round-robin across sources, images with a smaller quota.
    let wb = c.e.cfg.endpoints.wayback.clone();
    let mut seen = std::collections::HashSet::new();
    let scope_hosts = known_hosts(&lock(&c.db));
    let mut drop = QueueDrops {
        found: found.len(),
        ..Default::default()
    };
    let fresh: Vec<foca_search::FoundUrl> = found
        .into_iter()
        .filter(|u| {
            let host = url::Url::parse(u.target_url())
                .ok()
                .and_then(|x| x.host_str().map(str::to_ascii_lowercase))
                .unwrap_or_default();
            let ok = rules::check(&c.scope, &host, &scope_hosts).ok;
            drop.out_of_scope += usize::from(!ok);
            ok
        })
        .filter_map(|mut u| {
            if c.level == "external" && downloader.access_for(&u.url) != Access::Passive {
                let orig = u.target_url().to_string();
                // Use the snapshot/index date, otherwise one near 2025 (Wayback redirects to the nearest copy; with
                // no copy it returns 404 and the task fails without touching the target).
                let ts = u
                    .date
                    .clone()
                    .map(|d| d.chars().filter(char::is_ascii_digit).collect::<String>())
                    .filter(|d| d.len() >= 4)
                    .unwrap_or_else(|| "2025".into());
                u.url = foca_search::sources::copy_url(&wb, &ts, &orig);
                u.original = Some(orig);
                if downloader.access_for(&u.url) != Access::Passive {
                    drop.passive += 1;
                    return None;
                }
            }
            Some(u)
        })
        .filter(|u| {
            let ok = ext_filter
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
    let pick = foca_search::pick_fair(fresh, limit);
    let added = queue.enqueue(&pick).map_err(Stop::Error)?;
    drop.added = added;
    tracing::info!(target: "foca::scan", "{}: в загрузку {added} новых (лимит {limit}, известных {}; найдено {}, вне скоупа {}, другой тип {}, уже известны {}, без архивной копии {})",
        c.scan_id, known.len(), drop.found, drop.out_of_scope, drop.other_type, drop.known, drop.passive);
    if drop.found > 0 {
        let note = queue_note(&drop);
        c.sub_note("queue", added, drop.found, &note);
    }
    c.source_event("dns", "ok", Some(ct_hosts.len()));
    // No source gave data: an explicit warning rather than an empty result. `no_network` only when
    // nothing answered at all; a rate limit, a captcha or any HTTP answer means the network works.
    if attempted > 0 && answered == 0 {
        let reached = limited > 0 || got_http_answer(c);
        if !reached {
            c.warn(
                "no_network",
                "Нет сети или все источники недоступны: результаты скана неполные",
            );
        } else if limited > 0 {
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
    let lost: usize = doms.iter().map(|d| dork_board.lost(d)).sum();
    if lost > 0 && web.values().any(|b| *b) {
        c.warn(
            "search_dorks_lost",
            &format!(
                "Часть дорков ({lost}) не выполнил ни один поисковик: все в капче. Пройдите \
                 проверку («Пройти проверку»): оставшиеся дорки продолжатся сами"
            ),
        );
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
struct QueueDrops {
    found: usize,
    added: usize,
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

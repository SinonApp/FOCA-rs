//! Pool of public SearXNG instances used as a dork source through the embedded browser.
//!
//! Public instances almost always disable the JSON API (429/403), and plain HTTP requests for
//! HTML are cut off by the limiter (`botdetection` checks that the client loaded the CSS and a
//! token link), while a real browser gets regular results (3 out of 4 instances from a data
//! center). Hence a WebView behaving like a normal visitor, plus instance rotation:
//!
//! - the list comes from `searx.space/data/instances.json` (cached for 24 h in [`DorkCache`](crate::dorkboard::DorkCache));
//!   only clearnet instances (not Tor) with at least 90 % monthly uptime and 80 % successful
//!   searches are taken, ranked by the number of working engines;
//! - before the first query, the top instances of that list get a quick health ping
//!   ([`health_check`], `GET /healthz`, which SearXNG exempts from its limiter): stale entries of
//!   searx.space (dead hosts, expired certificates, parked domains) are dropped and the rest are
//!   ordered by latency; if no instance answers, the unfiltered list is kept;
//! - an instance that answers 403/429 or with the limiter is marked bad for the rest of the scan
//!   and the query moves to the next one (up to [`TRIES`] per query); once all are bad, the group
//!   goes to other search engines.
//!
//! SearXNG shows no captchas, so no manual check is needed.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use foca_net::{Access, NetClient, NetError, NetRequest};
use serde::{Deserialize, Serialize};

use crate::dorkboard::PageKind;
use crate::render::{RenderRequest, RenderStep, NO_RENDER};
use crate::source::{DocumentSource, Found, SearchCtx, SourceKind};
use crate::sources::dorkpool::{jitter, DorkBackend, DorkPage};
use crate::sources::render_engines::CAPTCHA_ABORT;
use crate::BoxFuture;

/// Instance list URL.
pub const SEARX_SPACE: &str = "https://searx.space/data/instances.json";
/// Instances tried per query before the group is handed to other search engines.
pub const TRIES: usize = 3;
/// Number of best instances kept in the pool.
pub const POOL: usize = 12;

/// Health endpoint of SearXNG (`200 OK` with the body `OK`).
pub const HEALTHZ: &str = "/healthz";
/// Parallel health pings.
pub const HEALTH_CONCURRENCY: usize = 4;
/// Timeout of one health ping.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(6);

/// Health ping result of one instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceHealth {
    pub url: String,
    pub ok: bool,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// Returns `true` for a healthy `/healthz` answer.
pub fn healthz_ok(status: u16, body: &str) -> bool {
    status == 200 && body.trim().eq_ignore_ascii_case("ok")
}

/// Pings `{instance}/healthz` of every instance (third-party services, `Access::Passive`; no
/// redirects, no retries), `HEALTH_CONCURRENCY` at a time. Results keep the input order.
pub async fn health_check(
    net: &NetClient,
    instances: &[String],
    timeout: Duration,
) -> Vec<InstanceHealth> {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(HEALTH_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for (i, base) in instances.iter().enumerate() {
        let (net, sem, base) = (
            net.clone(),
            sem.clone(),
            base.trim_end_matches('/').to_string(),
        );
        set.spawn(async move {
            let _p = sem.acquire_owned().await;
            let start = Instant::now();
            let mut h = InstanceHealth {
                url: base.clone(),
                ok: false,
                status: None,
                latency_ms: 0,
                error: None,
            };
            let res = async {
                let req =
                    NetRequest::get(&format!("{base}{HEALTHZ}"), "searx_pool", Access::Passive)?
                        .timeout(timeout)
                        .retries(0)
                        .no_redirects();
                let r = net.send(req).await?;
                let st = r.status();
                let body = r.text_limited(256).await.unwrap_or_default();
                Ok::<_, NetError>((st, body))
            }
            .await;
            h.latency_ms = start.elapsed().as_millis() as u64;
            match res {
                Ok((st, body)) => {
                    h.status = Some(st);
                    h.ok = healthz_ok(st, &body);
                }
                Err(e) => h.error = Some(format!("{}: {e}", e.code())),
            }
            (i, h)
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            out.push(x);
        }
    }
    out.sort_by_key(|x| x.0);
    out.into_iter().map(|x| x.1).collect()
}

/// Returns the healthy instances ordered by latency (ties keep the input order).
pub fn healthy_ranked(results: &[InstanceHealth]) -> Vec<String> {
    let mut ok: Vec<(usize, &InstanceHealth)> =
        results.iter().enumerate().filter(|(_, h)| h.ok).collect();
    ok.sort_by_key(|(i, h)| (h.latency_ms / 50, *i));
    ok.into_iter().map(|(_, h)| h.url.clone()).collect()
}

fn is_safe_public_instance(raw_url: &str) -> bool {
    let Ok(u) = url::Url::parse(raw_url) else {
        return false;
    };
    if u.scheme() != "https" {
        return false;
    }
    let Some(host) = u.host_str().map(|h| {
        h.trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }) else {
        return false;
    };
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let disallowed = match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                v4.is_unspecified()
                    || v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || (o[0] == 100 && (64..=127).contains(&o[1]))
            }
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let o = v4.octets();
                    v4.is_unspecified()
                        || v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_multicast()
                        || (o[0] == 100 && (64..=127).contains(&o[1]))
                } else {
                    let s0 = v6.segments()[0];
                    v6.is_unspecified()
                        || v6.is_loopback()
                        || v6.is_multicast()
                        || (s0 & 0xfe00) == 0xfc00
                        || (s0 & 0xffc0) == 0xfe80
                }
            }
        };
        if disallowed {
            return false;
        }
    }
    true
}

/// Returns the best instances from searx.space `instances.json` (URLs without a trailing `/`).
pub fn parse_searx_space(json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return vec![];
    };
    let Some(m) = v.get("instances").and_then(|x| x.as_object()) else {
        return vec![];
    };
    let mut rows: Vec<(usize, i64, String)> = Vec::new();
    for (url, i) in m {
        if i.get("network_type").and_then(|x| x.as_str()) != Some("normal") {
            continue;
        }
        if !is_safe_public_instance(url) {
            continue;
        }
        let up = i
            .pointer("/uptime/uptimeMonth")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        let search = i.pointer("/timing/search");
        let ok = search
            .and_then(|s| s.get("success_percentage"))
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        if up < 90.0 || ok < 80.0 {
            continue;
        }
        let engines = search
            .and_then(|s| s.get("working_engine_names"))
            .and_then(|x| x.as_array())
            .map_or(0, |a| a.len());
        if engines == 0 {
            continue;
        }
        rows.push((
            engines,
            (up * 100.0) as i64,
            url.trim_end_matches('/').to_string(),
        ));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
    rows.into_iter().take(POOL).map(|r| r.2).collect()
}

/// Returns SearXNG result links (`article.result a.url_header`, falling back to `h3 > a`).
pub fn parse_searx_html(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut rest = html;
    while let Some(i) = rest.find("<a ") {
        let tag_end = rest[i..].find('>').map_or(rest.len(), |j| i + j);
        let tag = &rest[i..tag_end];
        let take = tag.contains("url_header") || {
            let before = &rest[..i];
            before.ends_with("<h3>") || before.trim_end().ends_with("<h3>")
        };
        if take {
            if let Some(h) = attr_val(tag, "href") {
                let h = h.replace("&amp;", "&");
                if h.starts_with("http") && seen.insert(h.clone()) {
                    out.push(h);
                }
            }
        }
        rest = &rest[tag_end.min(rest.len())..];
        if rest.len() <= 1 {
            break;
        }
    }
    out
}

fn attr_val(tag: &str, name: &str) -> Option<String> {
    for q in ['"', '\''] {
        let key = format!("{name}={q}");
        if let Some(i) = tag.find(&key) {
            let v = &tag[i + key.len()..];
            return v.find(q).map(|j| v[..j].to_string());
        }
    }
    None
}

/// Classifies an instance response.
pub fn classify_searx(status: Option<u16>, html: &str) -> PageKind {
    let low = html.to_ascii_lowercase();
    if matches!(status, Some(403 | 429 | 502 | 503)) {
        PageKind::BlockedIp
    } else if low.contains("url_header") {
        // results present, even if "too many requests" appears somewhere in the page text
        PageKind::Results
    } else if low.contains("too many requests") {
        PageKind::BlockedIp
    } else if low.contains("id=\"results\"") || low.contains("id='results'") {
        PageKind::Results
    } else if low.contains("captcha") {
        PageKind::Captcha
    } else {
        PageKind::BlockedIp
    }
}

/// The `searx_pool` source.
pub struct SearxPool {
    /// Fixed instance list (tests, mirrors); `None` uses searx.space.
    pub fixed: Option<Vec<String>>,
    pub delay_min: Duration,
    pub delay_max: Duration,
    /// Health-ping searx.space instances before use (never applied to `fixed`).
    pub health_check: bool,
    pool: Mutex<Option<Vec<String>>>,
    bad: Mutex<HashSet<String>>,
    cursor: AtomicUsize,
}

impl Default for SearxPool {
    fn default() -> Self {
        SearxPool {
            fixed: None,
            delay_min: Duration::from_secs(4),
            delay_max: Duration::from_secs(9),
            health_check: true,
            pool: Mutex::new(None),
            bad: Mutex::new(HashSet::new()),
            cursor: AtomicUsize::new(0),
        }
    }
}

impl SearxPool {
    /// Creates a source for a single instance URL (tests, a self-hosted instance), without pauses.
    pub fn with_base(base: &str) -> Self {
        SearxPool {
            fixed: Some(vec![base.trim_end_matches('/').to_string()]),
            delay_min: Duration::ZERO,
            delay_max: Duration::ZERO,
            ..Default::default()
        }
    }

    async fn instances(&self, ctx: &SearchCtx) -> Result<Vec<String>, NetError> {
        if let Some(f) = &self.fixed {
            return Ok(f.clone());
        }
        if ctx.net.is_local_only() {
            return Err(NetError::OutOfScope {
                host: "searx.space".into(),
                reason: "local_only".into(),
            });
        }
        if let Some(p) = self.pool.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(p);
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let cached = ctx
            .dorks
            .as_ref()
            .and_then(|b| b.recall("searx_pool", "searx.space", 0, now));
        let list = match cached {
            Some(l) if !l.is_empty() => l,
            _ => {
                let req = NetRequest::get(SEARX_SPACE, "searx_pool", Access::Passive)?
                    .timeout(ctx.req_timeout(Duration::from_secs(30)))
                    .retries(1);
                let r = ctx.net.send(req).await?;
                let st = r.status();
                if !(200..300).contains(&st) {
                    return Err(NetError::Status(st));
                }
                let body = r.text_limited(8 * 1024 * 1024).await?;
                let l = parse_searx_space(&body);
                if let Some(b) = &ctx.dorks {
                    if !l.is_empty() {
                        b.remember("searx_pool", "searx.space", 0, &l, now);
                    }
                }
                l
            }
        };
        if list.is_empty() {
            return Err(NetError::Request(
                "searx.space: нет подходящих экземпляров".into(),
            ));
        }
        let list = if self.health_check {
            self.prefilter(ctx, list).await
        } else {
            list
        };
        *self.pool.lock().unwrap_or_else(|e| e.into_inner()) = Some(list.clone());
        Ok(list)
    }

    /// Keeps the healthy instances of `list`, fastest first; returns `list` unchanged if none
    /// answers (the device may block plain HTTPS to them while the WebView still works).
    async fn prefilter(&self, ctx: &SearchCtx, list: Vec<String>) -> Vec<String> {
        let h = health_check(&ctx.net, &list, ctx.req_timeout(HEALTH_TIMEOUT)).await;
        let good = healthy_ranked(&h);
        tracing::info!(target: "foca::source", "searx_pool: {} из {} экземпляров отвечают на /healthz", good.len(), list.len());
        if good.is_empty() {
            list
        } else {
            good
        }
    }

    fn next_good(&self, list: &[String]) -> Option<String> {
        let bad = self.bad.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..list.len() {
            let i = self.cursor.fetch_add(1, Ordering::Relaxed) % list.len();
            if !bad.contains(&list[i]) {
                return Some(list[i].clone());
            }
        }
        None
    }

    async fn fetch_page(
        &self,
        ctx: &SearchCtx,
        q: &str,
        page: usize,
    ) -> Result<DorkPage, NetError> {
        let Some(render) = ctx.render.clone() else {
            return Err(NetError::Request(NO_RENDER.into()));
        };
        let list = self.instances(ctx).await?;
        let proxy = ctx
            .net
            .config()
            .proxy
            .clone()
            .filter(|p| !p.trim().is_empty());
        let enc: String = url::form_urlencoded::byte_serialize(q.as_bytes()).collect();
        let mut last = PageKind::BlockedIp;
        for _ in 0..TRIES {
            let Some(base) = self.next_good(&list) else {
                break;
            };
            let pg = if page > 1 {
                format!("&pageno={page}")
            } else {
                String::new()
            };
            let u = format!("{base}/search?q={enc}&categories=general&language=all{pg}");
            let host = url::Url::parse(&base)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_string))
                .unwrap_or_default();
            let policy_err = if self.fixed.is_none() && !is_safe_public_instance(&base) {
                Some("searx_pool: небезопасный URL экземпляра".to_string())
            } else if self.fixed.is_none() && ctx.net.is_local_only() {
                Some("searx_pool: local_only".to_string())
            } else if let Err(e) = ctx.net.passive_access(&host, None) {
                Some(e.to_string())
            } else {
                None
            };
            if let Some(why) = policy_err {
                let mut rec = ctx
                    .net
                    .draft("searx_pool", "RENDER", &u, &host, &Access::Passive);
                rec.blocked = true;
                rec.error = Some(why);
                ctx.net.record(rec);
                self.bad
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(base);
                continue;
            }
            let timeout = ctx.req_timeout(Duration::from_secs(60));
            let req = RenderRequest::new("searx", Some(&u), timeout)
                .step(RenderStep::Wait {
                    gone: vec![],
                    present: None,
                    timeout_ms: 15_000,
                    abort: CAPTCHA_ABORT.iter().map(|s| s.to_string()).collect(),
                })
                .through_proxy(proxy.clone())
                .logged_as("searx_pool");
            tracing::info!(target: "foca::source", "searx_pool: {host}, {q}, стр. {page}");
            let r = render.fetch(req).await;
            let mut rec = ctx
                .net
                .draft("searx_pool", "RENDER", &u, &host, &Access::Passive);
            match r {
                Ok(p) => {
                    rec.status = p.status;
                    rec.bytes = p.html.len() as u64;
                    ctx.net.record(rec);
                    let k = classify_searx(p.status, &p.html);
                    if k == PageKind::Results {
                        return Ok(DorkPage {
                            kind: Some(k),
                            has_next: p.html.contains("next_page") || p.html.contains("pageno"),
                            links: parse_searx_html(&p.html),
                            why: None,
                        });
                    }
                    tracing::warn!(target: "foca::source", "searx_pool: {host} отказал ({:?}): следующий экземпляр", p.status);
                    last = k;
                }
                Err(e) => {
                    rec.error = Some(e.clone());
                    ctx.net.record(rec);
                    tracing::warn!(target: "foca::source", "searx_pool: {host}: {e}");
                }
            }
            self.bad
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(base);
        }
        Ok(DorkPage {
            kind: Some(last),
            why: Some("публичные экземпляры SearXNG ограничили запросы".into()),
            ..Default::default()
        })
    }
}

impl DorkBackend for SearxPool {
    fn engine_id(&self) -> &'static str {
        "searx_pool"
    }
    fn or_ok(&self) -> bool {
        true
    }
    fn max_pages(&self) -> usize {
        2
    }
    fn pause(&self) -> Duration {
        jitter(self.delay_min, self.delay_max)
    }
    fn fetch<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        q: &'a str,
        page: usize,
        _first: bool,
    ) -> BoxFuture<'a, Result<DorkPage, NetError>> {
        Box::pin(self.fetch_page(ctx, q, page))
    }
}

impl DocumentSource for SearxPool {
    fn id(&self) -> &'static str {
        "searx_pool"
    }
    fn name(&self) -> &'static str {
        "Публичные SearXNG (через браузер)"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn budget(&self) -> u32 {
        3
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            if ctx.render.is_none() {
                return Err(NetError::Request(NO_RENDER.into()));
            }
            crate::sources::dorkpool::run_dorks(ctx, domain, self).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_healthy_instances() {
        let j = r#"{"instances":{
          "https://a.example/":{"network_type":"normal","uptime":{"uptimeMonth":99.5},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing","duckduckgo","google"]}}},
          "https://b.example/":{"network_type":"normal","uptime":{"uptimeMonth":100.0},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}},
          "https://slow.example/":{"network_type":"normal","uptime":{"uptimeMonth":60.0},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}},
          "http://x.onion/":{"network_type":"tor","uptime":{"uptimeMonth":100.0},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}},
          "https://dead.example/":{"network_type":"normal","uptime":{"uptimeMonth":100.0},"timing":{"search":{"success_percentage":0.0}}}
        }}"#;
        assert_eq!(
            parse_searx_space(j),
            vec!["https://a.example", "https://b.example"]
        );
        assert!(parse_searx_space("nope").is_empty());
    }

    #[test]
    fn classify_and_parse() {
        let h = r#"<div id="results"><article class="result"><a href="https://bugs.python.org/file607/reference.pdf" class="url_header" rel="noreferrer">x</a><h3><a href="https://www.python.org/a.pdf?x=1&amp;y=2">t</a></h3></article></div>"#;
        assert_eq!(classify_searx(Some(200), h), PageKind::Results);
        assert_eq!(
            parse_searx_html(h),
            vec![
                "https://bugs.python.org/file607/reference.pdf",
                "https://www.python.org/a.pdf?x=1&y=2"
            ]
        );
        assert_eq!(
            classify_searx(Some(429), "Too Many Requests"),
            PageKind::BlockedIp
        );
        assert_eq!(
            classify_searx(Some(200), "<html>limiter</html>"),
            PageKind::BlockedIp
        );
    }

    #[tokio::test]
    async fn health_check_filters_and_ranks() {
        use foca_net::testserver::{TestResponse, TestServer};
        let ok = TestServer::start(|r| match r.path() {
            HEALTHZ => TestResponse::ok("OK"),
            _ => TestResponse::status(404),
        })
        .await;
        let slow = TestServer::start(|r| match r.path() {
            HEALTHZ => TestResponse::ok("OK\n").delay(Duration::from_millis(300)),
            _ => TestResponse::status(404),
        })
        .await;
        let limited = TestServer::start(|_| TestResponse::status(429)).await;
        let parked = TestServer::start(|_| TestResponse::ok("<html>domain for sale</html>")).await;
        let moved =
            TestServer::start(|_| TestResponse::redirect(302, "https://example.com/")).await;
        let (scope, _) = foca_core::Scope::from_lines("", "");
        let sink = std::sync::Arc::new(foca_net::MemorySink::new());
        let net = NetClient::new(foca_net::NetConfig::default(), scope, sink.clone()).unwrap();
        let list = vec![
            format!("{}/", slow.url()),
            limited.url(),
            ok.url(),
            parked.url(),
            moved.url(),
            "http://127.0.0.1:1".to_string(),
        ];
        let h = health_check(&net, &list, Duration::from_secs(3)).await;
        assert_eq!(h.len(), 6);
        assert_eq!(h[0].url, slow.url());
        assert_eq!(h.iter().filter(|x| x.ok).count(), 2);
        assert_eq!(h[1].status, Some(429));
        assert!(h[5].error.is_some());
        assert_eq!(healthy_ranked(&h), vec![ok.url(), slow.url()]);
        assert_eq!(slow.hits(HEALTHZ), 1);
        assert!(sink
            .records()
            .iter()
            .all(|r| r.access == "passive" && !r.active));
        // the pool falls back to the unfiltered list when nothing answers
        let pool = SearxPool::default();
        let ctx = SearchCtx::new(net);
        let dead = vec!["http://127.0.0.1:1".to_string()];
        assert_eq!(pool.prefilter(&ctx, dead.clone()).await, dead);
        assert!(healthz_ok(200, " ok\n") && !healthz_ok(204, "OK"));
    }

    #[test]
    fn rotation_skips_bad() {
        let p = SearxPool::default();
        let l = vec!["https://a".to_string(), "https://b".to_string()];
        p.bad.lock().unwrap().insert("https://a".into());
        assert_eq!(p.next_good(&l).as_deref(), Some("https://b"));
        assert_eq!(p.next_good(&l).as_deref(), Some("https://b"));
        p.bad.lock().unwrap().insert("https://b".into());
        assert!(p.next_good(&l).is_none());
    }

    #[test]
    fn parse_searx_space_drops_private_and_local_instances() {
        let j = r#"{"instances":{
          "https://127.0.0.1/":{"network_type":"normal","uptime":{"uptimeMonth":99.9},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}},
          "https://169.254.169.254/":{"network_type":"normal","uptime":{"uptimeMonth":99.9},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}},
          "https://localhost/":{"network_type":"normal","uptime":{"uptimeMonth":99.9},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}},
          "https://good.searx.example/":{"network_type":"normal","uptime":{"uptimeMonth":99.9},"timing":{"search":{"success_percentage":100.0,"working_engine_names":["bing"]}}}
        }}"#;
        assert_eq!(parse_searx_space(j), vec!["https://good.searx.example"]);
    }
}

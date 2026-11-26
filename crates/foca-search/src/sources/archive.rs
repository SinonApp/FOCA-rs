//! Archives and CT: Wayback CDX, Common Crawl Index and crt.sh. All passive.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use foca_net::ct::{self, CtEndpoints};
use foca_net::{Access, NetError, NetRequest};
use serde_json::Value;

use crate::source::{DocumentSource, Found, FoundUrl, SearchCtx, SourceKind};
use crate::BoxFuture;

/// A CDX row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdxRow {
    pub timestamp: String,
    pub original: String,
    pub mimetype: Option<String>,
    pub length: Option<u64>,
    pub status: Option<String>,
}

fn cdx_row(r: &[String], cols: &[Option<usize>; 5]) -> Option<CdxRow> {
    let get = |i: Option<usize>| {
        i.and_then(|i| r.get(i))
            .cloned()
            .filter(|s| s != "-" && !s.is_empty())
    };
    let ts = get(cols[0])?;
    let orig = get(cols[1])?;
    Some(CdxRow {
        timestamp: ts,
        original: orig,
        mimetype: get(cols[2]),
        length: get(cols[3]).and_then(|s| s.parse().ok()),
        status: get(cols[4]),
    })
}

/// Parses a CDX response: `output=json` (the first row is the header; with `showResumeKey=true`
/// an empty array is followed by `[resumeKey]`) or text (space-separated rows in [`WAYBACK_FL`]
/// order). Tolerates a body cut off mid-response (the archive.org gateway may close the stream
/// with a 200): all complete rows are taken and a truncated last row is dropped.
pub fn parse_cdx_json(text: &str) -> Result<(Vec<CdxRow>, Option<String>), NetError> {
    let t = text.trim();
    if t.is_empty() {
        return Ok((vec![], None));
    }
    if !t.starts_with('[') {
        let cols = [Some(0), Some(1), Some(2), Some(4), Some(3)];
        let rows = t
            .lines()
            .filter_map(|l| {
                let parts: Vec<String> = l.split_whitespace().map(String::from).collect();
                if parts.len() < 2 || !parts[0].bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                cdx_row(&parts, &cols)
            })
            .collect();
        return Ok((rows, None));
    }
    // Parse the whole body; if it was cut off, parse line by line (CDX puts each JSON row on its
    // own line: `[[...],` / `[...],` / `[...]]`).
    let v: Vec<Vec<String>> = match serde_json::from_str(t) {
        Ok(v) => v,
        Err(_) => t
            .lines()
            .filter_map(|l| {
                let mut l = l.trim();
                if l.starts_with("[[") {
                    l = &l[1..];
                }
                l = l.trim_end_matches(',');
                if l.ends_with("]]") {
                    l = &l[..l.len() - 1];
                }
                serde_json::from_str::<Vec<String>>(l).ok()
            })
            .collect(),
    };
    let mut it = v.into_iter();
    let Some(header) = it.next() else {
        return Ok((vec![], None));
    };
    let col = |n: &str| header.iter().position(|h| h == n);
    let cols = [
        col("timestamp"),
        col("original"),
        col("mimetype"),
        col("length"),
        col("statuscode"),
    ];
    if cols[0].is_none() || cols[1].is_none() {
        return Err(NetError::Parse(
            "CDX: нет колонок timestamp/original".into(),
        ));
    }
    let mut rows = Vec::new();
    let mut resume = None;
    let mut after_empty = false;
    for r in it {
        if r.is_empty() {
            after_empty = true;
            continue;
        }
        if after_empty {
            resume = r.into_iter().next();
            break;
        }
        if let Some(row) = cdx_row(&r, &cols) {
            rows.push(row);
        }
    }
    Ok((rows, resume))
}

/// Fields of the Wayback CDX query (text output; the order matters for parsing).
pub const WAYBACK_FL: &str = "timestamp,original,mimetype,statuscode,length";

/// Wayback Machine CDX API, modeled on gau/waymore: paginated (`showNumPages`, then `page=N`)
/// and without a heavy server-side MIME filter over the whole domain (that hits the 60 s gateway
/// limit and returns 504). Per page (one index block, about 6k captures) the server filters URLs
/// by extension, while MIME, status and the document/image quota are checked locally. Copies are
/// downloaded via `id_`, which is passive (archive.org, the target is not touched).
#[derive(Debug, Clone)]
pub struct Wayback {
    /// `https://web.archive.org`
    pub base: String,
    /// Index blocks per page (`pageSize`; one block is about 3-6k captures and takes 3-30 s).
    pub page_size: usize,
    /// Maximum number of pages per run (beyond that, pages are sampled evenly across the index).
    pub max_pages: usize,
    /// Start with a quick unpaginated document query (see [`Wayback::quick_url`]).
    pub quick: bool,
}

impl Default for Wayback {
    fn default() -> Self {
        Wayback {
            base: "https://web.archive.org".into(),
            page_size: 1,
            max_pages: 40,
            quick: true,
        }
    }
}

/// Returns the page numbers to query: all of them if there are at most `max`, otherwise an even
/// sample (first, last and evenly spaced in between, covering different subdomains and sections).
pub fn page_plan(total: usize, max: usize) -> Vec<usize> {
    if total == 0 || max == 0 {
        return vec![];
    }
    if total <= max {
        return (0..total).collect();
    }
    let mut out: Vec<usize> = (0..max)
        .map(|i| i * (total - 1) / (max - 1).max(1))
        .collect();
    out.dedup();
    out
}

impl Wayback {
    pub fn with_base(base: &str) -> Self {
        Wayback {
            base: base.trim_end_matches('/').into(),
            ..Default::default()
        }
    }

    /// Returns the copy URL without the Wayback toolbar (`id_` serves the original bytes).
    pub fn copy_url(&self, timestamp: &str, original: &str) -> String {
        copy_url(&self.base, timestamp, original)
    }

    fn cdx(&self) -> Result<url::Url, NetError> {
        url::Url::parse(&format!(
            "{}/cdx/search/cdx",
            self.base.trim_end_matches('/')
        ))
        .map_err(|e| NetError::BadUrl(e.to_string()))
    }

    /// Builds the page count query.
    pub fn num_pages_url(&self, domain: &str) -> Result<String, NetError> {
        let mut u = self.cdx()?;
        u.query_pairs_mut()
            .append_pair("url", domain)
            .append_pair("matchType", "domain")
            .append_pair("showNumPages", "true")
            .append_pair("pageSize", &self.page_size.max(1).to_string());
        Ok(u.to_string())
    }

    /// Builds the query for page `page` (the extension filter runs on the page's block, which is cheap).
    pub fn page_url(
        &self,
        domain: &str,
        page: usize,
        filter: &crate::filter::ExtFilter,
    ) -> Result<String, NetError> {
        let mut u = self.cdx()?;
        u.query_pairs_mut()
            .append_pair("url", domain)
            .append_pair("matchType", "domain")
            .append_pair("fl", WAYBACK_FL)
            .append_pair("filter", &format!("original:{}", filter.url_regex()))
            .append_pair("collapse", "urlkey")
            .append_pair("pageSize", &self.page_size.max(1).to_string())
            .append_pair("page", &page.to_string());
        Ok(u.to_string())
    }

    /// Builds a quick unpaginated query: documents only (no images), `limit` rows. On domains with many
    /// documents CDX fills the limit in seconds; on sparse ones it hits the 60 s gateway limit (504)
    /// and the paginated sampling takes over.
    pub fn quick_url(
        &self,
        domain: &str,
        limit: usize,
        filter: &crate::filter::ExtFilter,
    ) -> Result<Option<String>, NetError> {
        let docs: Vec<&str> = filter
            .exts()
            .filter(|e| !crate::filter::is_image_ext(e))
            .collect();
        if docs.is_empty() {
            return Ok(None);
        }
        let mut u = self.cdx()?;
        u.query_pairs_mut()
            .append_pair("url", domain)
            .append_pair("matchType", "domain")
            .append_pair("fl", WAYBACK_FL)
            .append_pair(
                "filter",
                &format!("original:(?i).*\\.({})(\\?.*)?$", docs.join("|")),
            )
            .append_pair("filter", "statuscode:200")
            .append_pair("collapse", "urlkey")
            .append_pair("limit", &limit.to_string());
        Ok(Some(u.to_string()))
    }

    async fn num_pages(&self, ctx: &SearchCtx, domain: &str) -> Result<Option<usize>, NetError> {
        let req = NetRequest::get(&self.num_pages_url(domain)?, "wayback", Access::Passive)?
            .timeout(ctx.req_timeout(Duration::from_secs(40)))
            .retries(2);
        let r = ctx.net.send(req).await?.ensure_success()?;
        let body = r.text_limited(64 * 1024).await?;
        Ok(body.trim().parse::<usize>().ok())
    }
}

/// Backs off after a failed page: 5·2^(n-1) s, capped by the soft deadline.
async fn cool_down(ctx: &SearchCtx, fails: u32) -> Result<(), NetError> {
    let want = Duration::from_secs(5u64 << fails.saturating_sub(1).min(3));
    let d = match ctx.time_left() {
        Some(l) => want.min(l.saturating_sub(Duration::from_secs(10))),
        None => want,
    };
    if !d.is_zero() {
        ctx.net.cancellable(tokio::time::sleep(d)).await?;
    }
    Ok(())
}

/// Picks the request timeout and retry count so that (retries + 1) × timeout fits the soft deadline.
fn attempt_plan(ctx: &SearchCtx, want: Duration) -> (Duration, u32) {
    match ctx.time_left() {
        None => (want, 2),
        Some(left) => {
            let left = left.saturating_sub(Duration::from_secs(2));
            if left >= want * 3 {
                (want, 2)
            } else if left >= want * 2 {
                (want, 1)
            } else {
                (left.max(Duration::from_secs(5)).min(want), 0)
            }
        }
    }
}

impl Wayback {
    /// Turns CDX rows into copy URLs: status 200, extension passes the filter, MIME type fits.
    fn take_rows(&self, ctx: &SearchCtx, domain: &str, rows: Vec<CdxRow>, col: &mut Collector) {
        for row in rows {
            if row.status.as_deref().is_some_and(|s| s != "200") {
                continue;
            }
            let Some(ext) = ctx.filter.matches(&row.original) else {
                continue;
            };
            if !crate::filter::mime_fits(row.mimetype.as_deref(), &ext) {
                continue;
            }
            col.host(&row.original, domain);
            let mut f = FoundUrl::new(&self.copy_url(&row.timestamp, &row.original), "wayback")
                .with_original(&row.original);
            f.hint_ext = Some(ext);
            f.size = row.length;
            f.mime = row.mimetype;
            f.date = Some(row.timestamp);
            col.push(f);
        }
    }
}

/// Returns the archive copy URL `<base>/web/<ts>id_/<url>`.
pub fn copy_url(base: &str, timestamp: &str, original: &str) -> String {
    format!(
        "{}/web/{timestamp}id_/{original}",
        base.trim_end_matches('/')
    )
}

/// Builds a regex of exact document MIME types for the filter's extensions, excluding fonts
/// (`application/vnd.ms-fontobject`) and other `vnd.*` types that a broad `vnd\..*` would match.
pub fn mime_regex(filter: &crate::filter::ExtFilter) -> String {
    let mut alts: Vec<&str> = Vec::new();
    let mut add = |m: &'static str| {
        if !alts.contains(&m) {
            alts.push(m);
        }
    };
    for e in filter.exts() {
        match e {
            "pdf" => add("application/pdf"),
            "doc" | "dot" => add("application/msword"),
            "rtf" => add("(application|text)/rtf"),
            "svg" => add("image/svg.*"),
            "jpg" | "jpeg" => add("image/jpeg"),
            "png" => add("image/png"),
            "tif" | "tiff" => add("image/tiff"),
            "heic" => add("image/hei.*"),
            "gif" => add("image/gif"),
            "eml" => add("message/rfc822"),
            "msg" => add("application/vnd\\.ms-outlook"),
            "ics" => add("text/calendar"),
            "vcf" => add("text/(x-)?vcard"),
            "mp4" => add("video/mp4"),
            "mov" => add("video/quicktime"),
            "zip" => add("application/(x-)?zip.*"),
            "vsd" | "vsdx" => add("application/vnd\\.(ms-)?visio.*"),
            "pub" => add("application/(vnd\\.ms-publisher|x-mspublisher)"),
            "xls" | "xlt" => add("application/vnd\\.ms-excel.*"),
            "ppt" | "pps" | "pot" => add("application/vnd\\.ms-powerpoint.*"),
            e if e.starts_with("docx") || e.starts_with("dotx") || e == "docm" => {
                add("application/vnd\\.(openxmlformats-officedocument\\.wordprocessingml|ms-word).*")
            }
            e if e.starts_with("xl") => {
                add("application/vnd\\.(openxmlformats-officedocument\\.spreadsheetml|ms-excel).*")
            }
            e if e.starts_with("pp") => add(
                "application/vnd\\.(openxmlformats-officedocument\\.presentationml|ms-powerpoint).*",
            ),
            e if e.starts_with("od") => add("application/vnd\\.oasis\\.opendocument.*"),
            e if e.starts_with("sx") => add("application/vnd\\.sun\\.xml.*"),
            _ => {
                add("application/octet-stream");
                add("application/x-.*");
            }
        }
    }
    if alts.is_empty() {
        return "application/.*".into();
    }
    format!("({})", alts.join("|"))
}

/// Result accumulator for paginated archives: deduplicates by target URL, keeps documents and
/// images apart (images get a smaller quota), and collects the domain's hosts.
pub(crate) struct Collector {
    docs: Vec<FoundUrl>,
    imgs: Vec<FoundUrl>,
    seen: std::collections::HashSet<String>,
    hosts: std::collections::BTreeSet<String>,
    limit: usize,
    known: std::sync::Arc<std::collections::HashSet<String>>,
}

impl Collector {
    pub(crate) fn new(ctx: &SearchCtx) -> Self {
        Collector {
            docs: vec![],
            imgs: vec![],
            seen: Default::default(),
            hosts: Default::default(),
            limit: ctx.limit,
            known: ctx.known.clone(),
        }
    }

    pub(crate) fn host(&mut self, url: &str, domain: &str) {
        if let Some(h) = url::Url::parse(url).ok().and_then(|u| {
            u.host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        }) {
            let h = h.strip_prefix("www.").map(String::from).unwrap_or(h);
            if h != domain && h.ends_with(&format!(".{domain}")) {
                self.hosts.insert(h);
            }
        }
    }

    pub(crate) fn push(&mut self, f: FoundUrl) {
        let key = crate::filter::dedup_key(f.target_url());
        if self.known.contains(&key) || !self.seen.insert(key) {
            return;
        }
        let img = f
            .hint_ext
            .as_deref()
            .is_some_and(crate::filter::is_image_ext);
        if img {
            if self.imgs.len() < crate::filter::image_quota(self.limit) {
                self.imgs.push(f);
            }
        } else if self.docs.len() < self.limit {
            self.docs.push(f);
        }
    }

    pub(crate) fn full(&self) -> bool {
        self.docs.len() >= self.limit
    }

    pub(crate) fn len(&self) -> usize {
        self.docs.len() + self.imgs.len()
    }

    pub(crate) fn finish(self) -> Found {
        let mut urls = self.docs;
        urls.extend(self.imgs);
        Found {
            urls: crate::source::take_balanced(urls, self.limit),
            hosts: self.hosts.into_iter().collect(),
            note: None,
        }
    }
}

impl DocumentSource for Wayback {
    fn id(&self) -> &'static str {
        "wayback"
    }
    /// A CDX index block takes 3-40 s, so this source gets three times the time of fast APIs.
    fn budget(&self) -> u32 {
        3
    }
    fn name(&self) -> &'static str {
        "Wayback Machine"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let mut col = Collector::new(ctx);
            // 1) quick unpaginated document query (one attempt, at most 55 s)
            if self.quick {
                if let Some(u) =
                    self.quick_url(domain, (ctx.limit * 2).clamp(20, 200), &ctx.filter)?
                {
                    let req = NetRequest::get(&u, "wayback", Access::Passive)?
                        .timeout(ctx.req_timeout(Duration::from_secs(55)))
                        .retries(0);
                    match ctx.net.send(req).await {
                        Ok(r) if r.is_success() => {
                            if let Ok(body) = r.text_limited(ctx.net.config().max_body).await {
                                let (rows, _) = parse_cdx_json(&body).unwrap_or_default();
                                self.take_rows(ctx, domain, rows, &mut col);
                            }
                        }
                        Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                        _ => {}
                    }
                }
            }
            // 2) paginated: get the page count; a non-numeric answer means a single page (old CDX servers, fixtures)
            let total = self.num_pages(ctx, domain).await?.unwrap_or(1);
            let plan = page_plan(total, self.max_pages);
            tracing::info!(target: "foca::source", "wayback: {domain}, {total} стр. индекса, опросим до {}", plan.len());
            let mut last_err: Option<NetError> = None;
            let mut ok_pages = 0usize;
            let mut fails = 0u32;
            for page in plan {
                if col.full() || ctx.out_of_time(Duration::from_secs(8)) {
                    break;
                }
                let u = self.page_url(domain, page, &ctx.filter)?;
                // retries must not overrun the soft deadline: timeout × attempts <= time left
                let (to, retries) = attempt_plan(ctx, Duration::from_secs(60));
                let req = NetRequest::get(&u, "wayback", Access::Passive)?
                    .timeout(to)
                    .retries(retries);
                let body = match ctx.net.send(req).await {
                    Ok(r) if r.is_success() => {
                        match r.text_limited(ctx.net.config().max_body).await {
                            Ok(b) => b,
                            // stream cut off: keep what arrived, otherwise move on
                            Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                            Err(e) => {
                                last_err = Some(e);
                                continue;
                            }
                        }
                    }
                    Ok(r) if r.status() == 404 => break,
                    Ok(r) => {
                        // 429/503: archive.org is overloaded or throttling us, so back off progressively
                        // (5, 10, 20 s, ...) instead of sending the next request right away
                        last_err = Some(NetError::Status(r.status()));
                        fails += 1;
                        ctx.retrying("wayback", fails, &format!("HTTP {}", r.status()));
                        cool_down(ctx, fails).await?;
                        continue;
                    }
                    Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                    Err(e) => {
                        ctx.retrying("wayback", fails + 1, &e.to_string());
                        last_err = Some(e);
                        fails += 1;
                        cool_down(ctx, fails).await?;
                        continue;
                    }
                };
                fails = 0;
                ok_pages += 1;
                let (rows, _) = parse_cdx_json(&body).unwrap_or_default();
                self.take_rows(ctx, domain, rows, &mut col);
            }
            if ok_pages == 0 && col.len() == 0 {
                if let Some(e) = last_err {
                    return Err(e);
                }
            }
            Ok(col.finish())
        })
    }
}

/// Parses Common Crawl Index NDJSON.
pub fn parse_cc_ndjson(text: &str) -> Vec<BTreeMap<String, String>> {
    text.lines()
        .filter_map(|l| serde_json::from_str::<BTreeMap<String, Value>>(l.trim()).ok())
        .map(|m| {
            m.into_iter()
                .map(|(k, v)| {
                    let s = match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (k, s)
                })
                .collect()
        })
        .collect()
}

/// In-process cache of collinfo.json for one day: CDX API endpoints of the indexes, newest first.
static COLLINFO: Mutex<Vec<(String, Instant, Vec<String>)>> = Mutex::new(Vec::new());
const COLLINFO_TTL: Duration = Duration::from_secs(24 * 3600);

/// Common Crawl Index: the 2-3 most recent indexes from collinfo.json (cached for a day),
/// paginated, with extension and status filtered on the server and MIME checked locally. An
/// unavailable index (504, TLS reset) is skipped for the next one; the source fails only if none
/// answered. URLs point at the target site; with the passive profile the engine downloads their
/// Wayback copies (`id_`).
#[derive(Debug, Clone)]
pub struct CommonCrawl {
    pub collinfo: String,
    /// Explicit CDX API endpoint of an index (otherwise the latest `max_indexes` from collinfo).
    pub index_api: Option<String>,
    pub max_indexes: usize,
    /// How many indexes to try when the newest are unavailable (504/timeout): older ones from
    /// collinfo are used instead of failing the source.
    pub max_tries: usize,
    pub max_pages: usize,
}

impl Default for CommonCrawl {
    fn default() -> Self {
        CommonCrawl {
            collinfo: "https://index.commoncrawl.org/collinfo.json".into(),
            index_api: None,
            max_indexes: 3,
            max_tries: 5,
            max_pages: 3,
        }
    }
}

impl CommonCrawl {
    pub fn with_collinfo(url: &str) -> Self {
        CommonCrawl {
            collinfo: url.into(),
            ..Default::default()
        }
    }

    /// Returns the CDX API endpoints of the most recent indexes, newest first.
    pub async fn indexes(&self, ctx: &SearchCtx) -> Result<Vec<String>, NetError> {
        if let Some(a) = &self.index_api {
            return Ok(vec![a.clone()]);
        }
        if let Ok(g) = COLLINFO.lock() {
            if let Some((_, t, v)) = g.iter().find(|x| x.0 == self.collinfo) {
                if t.elapsed() < COLLINFO_TTL && !v.is_empty() {
                    return Ok(v.iter().take(self.tries()).cloned().collect());
                }
            }
        }
        let v: Value = ctx
            .net
            .get_json(
                NetRequest::get(&self.collinfo, "cc", Access::Passive)?
                    .timeout(ctx.req_timeout(Duration::from_secs(30)))
                    .retries(1),
            )
            .await?;
        let all: Vec<String> = v
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x["cdx-api"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if all.is_empty() {
            return Err(NetError::Parse("collinfo.json: нет cdx-api".into()));
        }
        if let Ok(mut g) = COLLINFO.lock() {
            g.retain(|x| x.0 != self.collinfo);
            g.push((self.collinfo.clone(), Instant::now(), all.clone()));
        }
        Ok(all.into_iter().take(self.tries()).collect())
    }

    fn tries(&self) -> usize {
        self.max_tries.max(self.max_indexes).max(1)
    }

    /// Returns the CDX API endpoint of the latest index.
    pub async fn latest_index(&self, ctx: &SearchCtx) -> Result<String, NetError> {
        self.indexes(ctx)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| NetError::Parse("collinfo.json: нет cdx-api".into()))
    }

    fn index_url(
        api: &str,
        domain: &str,
        filter: &crate::filter::ExtFilter,
        page: Option<usize>,
    ) -> Result<String, NetError> {
        let mut u = url::Url::parse(api).map_err(|e| NetError::BadUrl(e.to_string()))?;
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("url", &format!("*.{domain}"))
                .append_pair("output", "json");
            match page {
                None => {
                    q.append_pair("showNumPages", "true");
                }
                Some(p) => {
                    q.append_pair("filter", "status:200")
                        .append_pair("filter", &format!("~url:{}", filter.url_regex()))
                        .append_pair("fl", "url,timestamp,mime,status,length")
                        .append_pair("page", &p.to_string());
                }
            }
        }
        Ok(u.to_string())
    }

    /// Queries one index: page count, then pages. `Ok(false)` means the index answered but had nothing.
    async fn one_index(
        &self,
        ctx: &SearchCtx,
        api: &str,
        domain: &str,
        col: &mut Collector,
        budget: Duration,
    ) -> Result<(), NetError> {
        let r = ctx
            .net
            .send(
                NetRequest::get(
                    &Self::index_url(api, domain, &ctx.filter, None)?,
                    "cc",
                    Access::Passive,
                )?
                .timeout(ctx.req_timeout(Duration::from_secs(40).min(budget)))
                .retries(1),
            )
            .await?;
        // 404 "No Captures found" means empty, not an error
        if r.status() == 404 {
            return Ok(());
        }
        let r = r.ensure_success()?;
        let body = r.text_limited(64 * 1024).await?;
        let pages = serde_json::from_str::<Value>(body.trim())
            .ok()
            .and_then(|v| v["pages"].as_u64())
            .unwrap_or(1) as usize;
        for p in 0..pages.min(self.max_pages.max(1)) {
            if col.full() || ctx.out_of_time(Duration::from_secs(6)) {
                break;
            }
            let r = ctx
                .net
                .send(
                    NetRequest::get(
                        &Self::index_url(api, domain, &ctx.filter, Some(p))?,
                        "cc",
                        Access::Passive,
                    )?
                    .timeout(ctx.req_timeout(Duration::from_secs(60).min(budget)))
                    .retries(1),
                )
                .await?;
            if r.status() == 404 {
                break;
            }
            let r = r.ensure_success()?;
            let body = match r.text_limited(ctx.net.config().max_body).await {
                Ok(b) => b,
                Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                Err(_) => continue,
            };
            let rows = parse_cc_ndjson(&body);
            if rows.is_empty() {
                break;
            }
            for m in rows {
                let Some(url) = m.get("url") else { continue };
                if m.get("status").is_some_and(|s| s != "200") {
                    continue;
                }
                let Some(ext) = ctx.filter.matches(url) else {
                    continue;
                };
                if !crate::filter::mime_fits(m.get("mime").map(String::as_str), &ext) {
                    continue;
                }
                col.host(url, domain);
                let mut f = FoundUrl::new(url, "cc");
                f.hint_ext = Some(ext);
                f.size = m.get("length").and_then(|s| s.parse().ok());
                f.date = m.get("timestamp").cloned();
                f.mime = m.get("mime").cloned();
                col.push(f);
            }
        }
        Ok(())
    }
}

impl DocumentSource for CommonCrawl {
    fn id(&self) -> &'static str {
        "cc"
    }
    fn name(&self) -> &'static str {
        "Common Crawl"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let apis = self.indexes(ctx).await?;
            let mut col = Collector::new(ctx);
            let mut errs = Vec::new();
            let mut answered = 0usize;
            for (i, api) in apis.iter().enumerate() {
                if col.full()
                    || answered >= self.max_indexes.max(1)
                    || ctx.out_of_time(Duration::from_secs(6))
                {
                    break;
                }
                // An unavailable index (gateway 504 after 60 s) must not eat the whole source deadline: each
                // remaining index gets its own share so older ones are still reached.
                let left = apis.len().saturating_sub(i).max(1) as u32;
                let budget = ctx
                    .time_left()
                    .map(|t| (t / left).max(Duration::from_secs(10)))
                    .unwrap_or(Duration::from_secs(60));
                match self.one_index(ctx, api, domain, &mut col, budget).await {
                    Ok(()) => answered += 1,
                    Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                    Err(e) => {
                        let id = api.rsplit('/').next().unwrap_or(api);
                        tracing::warn!(target: "foca::source", "cc: индекс {id} недоступен: {e}");
                        errs.push(format!("{id}: {e}"));
                    }
                }
            }
            if answered == 0 && col.len() == 0 && !errs.is_empty() {
                return Err(NetError::Request(format!(
                    "индексы Common Crawl недоступны ({})",
                    errs.join("; ")
                )));
            }
            let mut f = col.finish();
            if !errs.is_empty() {
                f.note = Some(format!(
                    "часть индексов недоступна ({}): данные из ответивших",
                    errs.join("; ")
                ));
            }
            Ok(f)
        })
    }
}

/// crt.sh: subdomains (for the crawler and DNS); yields no documents.
#[derive(Debug, Clone, Default)]
pub struct CrtSh {
    pub endpoints: CtEndpoints,
}

impl CrtSh {
    pub fn with_base(base: &str) -> Self {
        CrtSh {
            endpoints: CtEndpoints {
                crtsh: base.into(),
                ..Default::default()
            },
        }
    }
}

impl DocumentSource for CrtSh {
    fn id(&self) -> &'static str {
        "crt"
    }
    fn name(&self) -> &'static str {
        "crt.sh"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn find<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        domain: &'a str,
    ) -> BoxFuture<'a, Result<Found, NetError>> {
        Box::pin(async move {
            let hosts = ct::crtsh_subdomains(&ctx.net, &self.endpoints, domain).await?;
            Ok(Found {
                urls: vec![],
                hosts,
                note: None,
            })
        })
    }
}

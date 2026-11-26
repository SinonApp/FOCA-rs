//! Shared dork driver of the keyless engines: query planning per file type family and the
//! loop [`run_dorks`] that takes groups from the scan's [`DorkBoard`], pages through results,
//! applies cache, budget, pacing and failover, and keeps only in-scope document links.
//!
//! Without a shared board (`SearchCtx::dorks == None`, e.g. single-source CLI tests) an engine
//! creates a private board and runs every group itself.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use foca_net::NetError;

use crate::dorkboard::{now_s, DorkBoard, PageKind, Take};
use crate::filter::{ext_of_url, url_in_domain};
use crate::source::BLOCKED;
use crate::source::{Found, FoundUrl, SearchCtx};
use crate::sources::archive::Collector;
use crate::BoxFuture;

/// A page with fewer new domain links than this ends pagination.
pub const PAGE_FULL: usize = 6;

/// File type families: one `OR` query per family.
const FAMILIES: &[&[&str]] = &[
    &["pdf"],
    &["doc", "docx", "odt", "rtf"],
    &["xls", "xlsx", "ods"],
    &["ppt", "pptx"],
    // Extended formats: diagrams, publications and mail/calendar/contact exports.
    &["vsdx", "vsd", "pub"],
    &["eml", "msg", "ics", "vcf"],
];

/// Returns the dork type groups for the extensions allowed by the filter, ordered by value.
pub fn ext_groups(allowed: impl Fn(&str) -> bool) -> Vec<Vec<String>> {
    FAMILIES
        .iter()
        .map(|f| {
            f.iter()
                .filter(|e| allowed(e))
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        })
        .filter(|g| !g.is_empty())
        .collect()
}

/// Builds the query text: `site:d filetype:x` for one type, `site:d (filetype:a OR filetype:b)` for several.
pub fn dork_query(domain: &str, exts: &[String]) -> String {
    match exts {
        [one] => format!("site:{domain} filetype:{one}"),
        many => format!(
            "site:{domain} ({})",
            many.iter()
                .map(|e| format!("filetype:{e}"))
                .collect::<Vec<_>>()
                .join(" OR ")
        ),
    }
}

/// Returns an engine's queries for a group: one with `OR` support, otherwise one per type.
pub fn queries_for(domain: &str, exts: &[String], or_ok: bool) -> Vec<(String, Vec<String>)> {
    if or_ok || exts.len() <= 1 {
        vec![(dork_query(domain, exts), exts.to_vec())]
    } else {
        exts.iter()
            .map(|e| (dork_query(domain, std::slice::from_ref(e)), vec![e.clone()]))
            .collect()
    }
}

/// A result page parsed by an engine.
#[derive(Debug, Clone, Default)]
pub struct DorkPage {
    pub kind: Option<PageKind>,
    pub links: Vec<String>,
    pub has_next: bool,
    /// Reason for the missing results, for the log or the error.
    pub why: Option<String>,
}

/// A dork engine for the shared driver [`run_dorks`].
pub trait DorkBackend: Send + Sync {
    fn engine_id(&self) -> &'static str;
    /// Whether the engine understands `(filetype:a OR filetype:b)`.
    fn or_ok(&self) -> bool;
    fn max_pages(&self) -> usize;
    fn pause(&self) -> Duration;
    /// `first` marks the engine's first request in the scan (it may start at the home page).
    fn fetch<'a>(
        &'a self,
        ctx: &'a SearchCtx,
        q: &'a str,
        page: usize,
        first: bool,
    ) -> BoxFuture<'a, Result<DorkPage, NetError>>;
}

/// Returns a random pause in `[min, max]` (jitter without an external RNG).
pub fn jitter(min: Duration, max: Duration) -> Duration {
    let span = max.saturating_sub(min).as_millis() as u64;
    if span == 0 {
        return min;
    }
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 7))
        .unwrap_or(0);
    let x = n
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
        >> 17;
    min + Duration::from_millis(x % (span + 1))
}

fn why_of(kind: PageKind) -> &'static str {
    use crate::dorkboard::{CAPTCHA_WHY, VERIFY_WHY};
    match kind {
        PageKind::Verify => VERIFY_WHY,
        PageKind::Captcha => CAPTCHA_WHY,
        _ => "поисковик заблокировал IP (automated queries)",
    }
}

/// Shared dork loop of an engine: board, cache, budget, pacing, failover, scope filter and dedup.
pub async fn run_dorks(
    ctx: &SearchCtx,
    domain: &str,
    be: &dyn DorkBackend,
) -> Result<Found, NetError> {
    let id = be.engine_id();
    let local;
    let board: &DorkBoard = match &ctx.dorks {
        Some(b) => b.as_ref(),
        None => {
            local = Arc::new(DorkBoard::default());
            local.as_ref()
        }
    };
    let groups = ext_groups(|e| ctx.filter.allows_ext(e));
    board.plan(domain, &groups);
    let _run = board.begin(id);
    let mut col = Collector::new(ctx);
    let mut sent = 0usize;
    let mut answered = 0usize;
    let mut groups_done = 0usize;
    let mut stop_why: Option<String> = None;
    loop {
        if ctx.net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        if col.full() || ctx.out_of_time(Duration::from_secs(20)) {
            break;
        }
        let (idx, exts) = match board.take(id, domain) {
            Take::Done => break,
            Take::Wait => {
                tokio::time::sleep(board.poll).await;
                continue;
            }
            Take::Item(i, e) => (i, e),
        };
        let mut found = 0usize;
        let mut fail: Option<(String, bool)> = None;
        'q: for (q, qexts) in queries_for(domain, &exts, be.or_ok()) {
            let mut seen_q: HashSet<String> = HashSet::new();
            for page in 1..=be.max_pages().max(1) {
                if ctx.net.is_cancelled() {
                    return Err(NetError::Cancelled);
                }
                if col.full() || ctx.out_of_time(Duration::from_secs(20)) {
                    break 'q;
                }
                let now = now_s();
                let (pg, cached) = match board.recall(id, &q, page, now) {
                    Some(links) => (
                        DorkPage {
                            kind: Some(PageKind::Results),
                            has_next: links.len() >= PAGE_FULL,
                            links,
                            why: None,
                        },
                        true,
                    ),
                    None => {
                        if !board.spend(id) {
                            fail = Some(("бюджет запросов движка на скан исчерпан".into(), false));
                            break 'q;
                        }
                        if sent > 0 {
                            tokio::time::sleep(be.pause()).await;
                        }
                        sent += 1;
                        let first = board.first_visit(id);
                        match be.fetch(ctx, &q, page, first).await {
                            Ok(p) => (p, false),
                            Err(NetError::Cancelled) => return Err(NetError::Cancelled),
                            Err(e) => {
                                tracing::warn!(target: "foca::source", "{id}: {q}: {e}");
                                if answered == 0 && col.len() == 0 {
                                    board.give_back(id, domain, idx, false);
                                    return Err(e);
                                }
                                fail = Some((e.to_string(), false));
                                break 'q;
                            }
                        }
                    }
                };
                let kind = pg.kind.unwrap_or(PageKind::Results);
                if kind != PageKind::Results {
                    board.note(id, kind, 0, false);
                    let why = pg.why.clone().unwrap_or_else(|| why_of(kind).to_string());
                    tracing::warn!(target: "foca::source", "{id}: {why} ({q}, стр. {page}): группа другим движкам");
                    fail = Some((why, true));
                    break 'q;
                }
                answered += 1;
                let mut fresh = 0usize;
                // in-domain links that are pages, not documents of the requested types
                let mut not_docs = 0usize;
                let mut in_dom: Vec<String> = Vec::new();
                for u in &pg.links {
                    if !url_in_domain(u, domain) {
                        continue;
                    }
                    in_dom.push(u.clone());
                    if seen_q.insert(crate::filter::dedup_key(u)) {
                        fresh += 1;
                    }
                    col.host(u, domain);
                    let by_ext = ext_of_url(u);
                    let hint = match by_ext {
                        Some(e) if qexts.contains(&e) => Some(e),
                        Some(_) => ctx.filter.matches(u),
                        // a URL without an extension (`.../download/815/`) is taken as a document of the requested type;
                        // the downloader verifies the type by MIME
                        None => ctx.filter.matches(u).or_else(|| qexts.first().cloned()),
                    };
                    let Some(e) = hint else {
                        not_docs += 1;
                        continue;
                    };
                    let mut f = FoundUrl::new(u, id);
                    f.hint_ext = Some(e);
                    col.push(f);
                }
                found += in_dom.len();
                board.note(id, PageKind::Results, in_dom.len(), cached);
                if !cached {
                    board.remember(id, &q, page, &pg.links, now);
                }
                tracing::info!(target: "foca::source", "{id}: {q}, стр. {page}: ссылок {} (новых в домене {fresh}, не документы {not_docs}){}, всего {}", pg.links.len(), if cached { " [кэш]" } else { "" }, col.len());
                // paginate only if the page was full and has a "next" link
                if fresh < PAGE_FULL || !pg.has_next {
                    break;
                }
            }
        }
        match fail {
            Some((why, blocked)) => {
                board.give_back(id, domain, idx, blocked);
                if blocked && col.len() == 0 && answered == 0 {
                    return Err(NetError::Request(format!("{BLOCKED}: {why}")));
                }
                stop_why = Some(why);
                break;
            }
            None => {
                board.finish(id, domain, idx, found);
                groups_done += 1;
            }
        }
    }
    let mut f = col.finish();
    let st = board.stats().get(id).cloned().unwrap_or_default();
    let mut notes = Vec::new();
    if st.taken_over > 0 {
        notes.push(format!(
            "взял у других поисковиков групп: {}",
            st.taken_over
        ));
    }
    if let Some(w) = stop_why {
        notes.push(format!(
            "остановлен: {w}; оставшиеся дорки переданы другим поисковикам"
        ));
    }
    if groups_done == 0 && sent == 0 && f.urls.is_empty() && notes.is_empty() {
        notes.push("все дорки уже выполнили другие поисковики".into());
    }
    if !notes.is_empty() {
        f.note = Some(notes.join("; "));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn groups_and_queries() {
        let gr = ext_groups(|e| e != "rtf" && e != "ods");
        assert_eq!(gr[0], g(&["pdf"]));
        assert_eq!(gr[1], g(&["doc", "docx", "odt"]));
        assert_eq!(gr[2], g(&["xls", "xlsx"]));
        assert_eq!(dork_query("a.ua", &g(&["pdf"])), "site:a.ua filetype:pdf");
        assert_eq!(
            dork_query("a.ua", &g(&["xls", "xlsx"])),
            "site:a.ua (filetype:xls OR filetype:xlsx)"
        );
        assert_eq!(queries_for("a.ua", &g(&["xls", "xlsx"]), false).len(), 2);
        assert_eq!(queries_for("a.ua", &g(&["xls", "xlsx"]), true).len(), 1);
        assert!(ext_groups(|e| e == "jpg").is_empty());
    }

    #[test]
    fn jitter_in_range() {
        for _ in 0..20 {
            let j = jitter(Duration::from_secs(6), Duration::from_secs(14));
            assert!(j >= Duration::from_secs(6) && j <= Duration::from_secs(14));
        }
    }
}

//! Site discovery stage (`foca-fuzz`): forgotten documents, backups, service files and directory
//! listings on the client's site.
//!
//! * Runs only in the active stage (full profile, or custom with the `fuzz` module) and only for
//!   in-scope hosts with `active` (exclusions win).
//! * Goes through the same `NetClient` (scope, request log, kill switch).
//! * Discovered documents join the regular download queue and parsing.
//! * Up to `settings.net.hosts_parallel` hosts run at once: one request budget and one time limit
//!   for all of them, rate and the throttling detector per host (a host that answers 429 stops
//!   alone), pause and stop reach every running host.
//!
//! Commands: `fuzz_estimate`, `wordlists_list`, `wordlists_download`, `wordlists_import`,
//! `wordlists_delete` (see "Site discovery" in `docs/API.md`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use foca_core::api::ScopeDto;
use foca_core::Severity;
use foca_fuzz::wordlists::{self, Wordlist, WordlistError};
use foca_fuzz::{
    ContentSpec, FuzzConfig, FuzzControl, FuzzEvent, FuzzHit, FuzzStats, FuzzTask, Fuzzer, HitKind,
    Module, Risk, StopReason, Template, VhostSpec,
};
use foca_search::store::StoreQueue;
use foca_store::ProjectDb;
use serde_json::{json, Value};
use url::Url;

use super::documents::{download_queue, meta_pending};
use super::{known_hosts, reanalyze_bg, target_domains, Ctx, Stop, STAGES};
use crate::analysis::facts::{self, NetFacts};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::{lock, Core};
use crate::util::arg_str;
use crate::{CmdError, CmdResult, Engine};

/// Brute-force modules for the run wizard: id, title, description.
pub const FUZZ_MODULES: &[(&str, &str, &str)] = &[
    (
        "docs",
        "Документы",
        "Типовые папки и имена офисных файлов, варианты известных имён (год, версия)",
    ),
    (
        "backups",
        "Бэкапы",
        "Резервные копии известных файлов (.bak, ~, .old, .zip) и дампы баз",
    ),
    (
        "exposed",
        "Служебные файлы",
        "Забытые .env, .git, .DS_Store, конфиги: с проверкой формата",
    ),
    (
        "dirlisting",
        "Листинги каталогов",
        "Открытые «Index of /» и ссылки на документы из них",
    ),
    (
        "vhost",
        "Скрытые vhost",
        "Поддомены заказчика на том же адресе (заголовок Host, только из скоупа)",
    ),
    (
        "cms",
        "Пути CMS",
        "Словарь по определённой CMS (WordPress, Joomla, Drupal, SharePoint)",
    ),
];

/// Default modules (a gentle set).
const DEFAULT_MODULES: &[&str] = &["docs", "backups", "exposed", "dirlisting"];
/// Size limit of an imported wordlist.
const IMPORT_MAX: u64 = 64 * 1024 * 1024;
/// Number of web hosts brute-forced per scan (`settings.net.hosts_parallel` of them at once).
const MAX_HOSTS_DEFAULT: u64 = 3;

/// Facts key for the run's brute-force parameters (`scan_start { fuzz: {...} }`).
pub(crate) fn run_key(scan_id: &str) -> String {
    format!("scan_fuzz:{scan_id}")
}

/// Default `settings.fuzz` (see `docs/API.md`).
pub fn default_settings() -> Value {
    json!({
        "modules": DEFAULT_MODULES, "rate": 5, "threads": 4, "max_requests": 3000,
        "max_time_min": 20, "max_hosts": MAX_HOSTS_DEFAULT, "exclude_paths": [], "wordlists": [],
        "follow_redirects": false, "show_paths": false
    })
}

/// Returns the effective parameters: defaults, then `settings.fuzz`, then run parameters.
fn effective(e: &Core, run: Option<&Value>) -> Value {
    let mut v = default_settings();
    if let Ok(s) = e.store().settings_get() {
        if s["fuzz"].is_object() {
            foca_store::settings::merge(&mut v, &s["fuzz"]);
        }
    }
    if let Some(r) = run.filter(|r| r.is_object()) {
        foca_store::settings::merge(&mut v, r);
    }
    v
}

fn modules_of(v: &Value) -> Vec<Module> {
    let mut out: Vec<Module> = v["modules"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(Module::parse)
                .filter(|m| *m != Module::Content)
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Rate used for `settings.fuzz.rate: 0` (no limit): the token bucket's own ceiling.
const UNLIMITED_RATE: f64 = 10_000.0;

/// Builds a `FuzzConfig` from the effective parameters. Manual values are honoured as typed (the
/// UI warns above its recommended ranges); `0` means no limit for the rate, the request budget
/// and the time budget. Only crash-safety invariants apply: at least one thread and durations
/// that cannot overflow an `Instant`.
fn config_of(e: &Core, v: &Value) -> FuzzConfig {
    let rate = v["rate"].as_f64().unwrap_or(5.0);
    let max_min = v["max_time_min"].as_u64().unwrap_or(20);
    let mut c = FuzzConfig {
        threads: usize::try_from(v["threads"].as_u64().unwrap_or(4).max(1)).unwrap_or(usize::MAX),
        rate: if rate.is_finite() && rate > 0.0 {
            rate
        } else {
            UNLIMITED_RATE
        },
        max_requests: match v["max_requests"].as_u64().unwrap_or(3000) {
            0 => u64::MAX,
            n => n,
        },
        max_time: match max_min {
            0 => crate::settings::secs(u64::MAX),
            m => crate::settings::secs(m.saturating_mul(60)),
        },
        follow_redirects: v["follow_redirects"].as_bool().unwrap_or(false),
        exclude_paths: str_list(&v["exclude_paths"]),
        ..Default::default()
    };
    if e.cfg.fuzz_unthrottled {
        c.rate = 1000.0;
        c.jitter = Duration::ZERO;
        c.request_timeout = Duration::from_secs(5);
    }
    c
}

pub(crate) fn wordlist_dir(e: &Core) -> PathBuf {
    e.cfg.data_dir.join("wordlists")
}

fn custom_dir(e: &Core) -> PathBuf {
    wordlist_dir(e).join("custom")
}

/// Resolves a wordlist by id: built-in, downloaded (`dns-top20000`, ...) or custom (`custom:<name>`).
fn resolve_wordlist(e: &Core, id: &str) -> Result<Wordlist, String> {
    if let Some(name) = id.strip_prefix("custom:") {
        let p = custom_dir(e).join(safe_name(name));
        let b = std::fs::read(&p).map_err(|e| format!("словарь {id}: {e}"))?;
        return Ok(Wordlist::from_text(id, &String::from_utf8_lossy(&b)));
    }
    wordlists::resolve(id, Some(&wordlist_dir(e))).map_err(|e| e.to_string())
}

/// Sanitizes a custom wordlist file name: letters, digits and `-_.` only, no paths.
fn safe_name(n: &str) -> String {
    let base = Path::new(n)
        .file_name()
        .map(|x| x.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut s: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        s = "custom.txt".into();
    }
    if !s.ends_with(".txt") {
        s.push_str(".txt");
    }
    s
}

/// Detects the CMS from already known site URLs (passive, no requests).
fn detect_cms(urls: &[String]) -> Option<foca_fuzz::Cms> {
    use foca_fuzz::Cms;
    for u in urls {
        let l = u.to_ascii_lowercase();
        if l.contains("/wp-content/") || l.contains("/wp-includes/") {
            return Some(Cms::WordPress);
        }
        if l.contains("/components/com_") || l.contains("/media/jui/") {
            return Some(Cms::Joomla);
        }
        if l.contains("/sites/default/files/") {
            return Some(Cms::Drupal);
        }
        if l.contains("/_layouts/") || l.contains("/sites/") && l.contains("/shared%20documents/") {
            return Some(Cms::SharePoint);
        }
    }
    None
}

/// Returns web addresses to brute-force: live hosts from network facts (ports 80/443/8080/8443 and the
/// TCP liveness ports) and URL targets, only those with `active` in scope, excluding exclusions and dangling CNAMEs.
fn web_bases(
    e: &Core,
    db: &ProjectDb,
    scope: &ScopeDto,
    domains: &[String],
    for_estimate: bool,
) -> Vec<Url> {
    let f: NetFacts = facts::get(db, facts::K_NET);
    let known: Vec<KnownHost> = f
        .hosts
        .values()
        .map(|h| KnownHost {
            name: h.name.clone(),
            ip: h.ip.clone(),
        })
        .chain(known_hosts(db))
        .collect();
    let ok = |h: &str| rules::check(scope, h, &known).ok;
    let mut out: Vec<Url> = Vec::new();
    let push = |u: Url, out: &mut Vec<Url>| {
        if !out.iter().any(|x| x.as_str() == u.as_str()) {
            out.push(u);
        }
    };
    // URL targets as is (site root)
    for t in &scope.targets {
        if let rules::Entry::Url(h) = rules::entry(&t.v, Some(&t.kind)) {
            if !ok(&h) {
                continue;
            }
            if let Ok(mut u) = Url::parse(&t.v) {
                u.set_path("/");
                u.set_query(None);
                u.set_fragment(None);
                push(u, &mut out);
            }
        }
    }
    let ports = &e.cfg.alive_ports;
    // target domains first, then web-like subdomains, then infrastructure names (name servers,
    // mail relays: found by DNS enumeration, rarely serve a site), each group by name
    let infra_name = |n: &str| {
        let l = n.split('.').next().unwrap_or("");
        let l = l.trim_end_matches(|c: char| c.is_ascii_digit() || c == '-');
        [
            "ns", "dns", "mx", "mail", "smtp", "imap", "pop", "pop3", "relay",
        ]
        .contains(&l)
    };
    let mut hosts: Vec<_> = f.hosts.values().filter(|h| h.dangling.is_none()).collect();
    hosts.sort_by_key(|h| {
        (
            !domains.contains(&h.name),
            infra_name(&h.name),
            h.name.clone(),
        )
    });
    // CDN / cloud / shared-hosting addresses of bulk-added names are never probed
    let np: crate::analysis::scope_bulk::NoProbe =
        facts::get(db, crate::analysis::scope_bulk::K_NO_PROBE);
    let held = super::ports::no_probe_names(&np, scope, &f);
    for h in hosts {
        if !ok(&h.name) || held.contains(&h.name) {
            continue;
        }
        let mut ps: Vec<u16> = h
            .services
            .iter()
            .filter_map(|s| s.0.split('/').next()?.parse().ok())
            .filter(|p| [80, 443, 8080, 8443].contains(p) || ports.contains(p))
            .collect();
        ps.sort_by_key(|p| match p {
            443 => 0,
            80 => 1,
            _ => 2,
        });
        // one address per host: https if 443 is open
        if let Some(p) = ps.first() {
            let scheme = if matches!(p, 443 | 8443) {
                "https"
            } else {
                "http"
            };
            let u = if matches!(p, 80 | 443) {
                format!("{scheme}://{}/", h.name)
            } else {
                format!("{scheme}://{}:{p}/", h.name)
            };
            if let Ok(u) = Url::parse(&u) {
                push(u, &mut out);
            }
        }
    }
    // estimate before the first scan: target domains as https://domain/
    if for_estimate && out.is_empty() {
        for d in domains {
            if ok(d) {
                if let Ok(u) = Url::parse(&format!("https://{d}/")) {
                    push(u, &mut out);
                }
            }
        }
    }
    out
}

/// Builds brute-force tasks (one per web address).
fn build_tasks(
    e: &Core,
    db: &ProjectDb,
    scope: &ScopeDto,
    domains: &[String],
    v: &Value,
    cfg: &FuzzConfig,
    for_estimate: bool,
) -> Result<Vec<FuzzTask>, String> {
    let mods = modules_of(v);
    let wl_ids = str_list(&v["wordlists"]);
    // 0 = every web address of the scope
    let max_hosts = match v["max_hosts"].as_u64().unwrap_or(MAX_HOSTS_DEFAULT) {
        0 => usize::MAX,
        n => usize::try_from(n).unwrap_or(usize::MAX),
    };
    let bases: Vec<Url> = web_bases(e, db, scope, domains, for_estimate)
        .into_iter()
        .take(max_hosts)
        .collect();
    let known_all: Vec<String> = db.task_urls().map_err(|e| e.to_string())?;
    // custom wordlist (content module): words from all selected wordlists at the site root
    let content_wl = if wl_ids.is_empty() {
        None
    } else {
        let mut words = Vec::new();
        for id in &wl_ids {
            words.extend(resolve_wordlist(e, id)?.words);
        }
        Some(Wordlist::from_words("selected", words))
    };
    let all_known_hosts: Vec<KnownHost> = known_hosts(db);
    let vhost_domains: Vec<String> = domains
        .iter()
        .filter(|d| rules::check(scope, d, &all_known_hosts).ok)
        .cloned()
        .collect();
    let mut out = Vec::new();
    for (i, base) in bases.into_iter().enumerate() {
        let host = base.host_str().unwrap_or("").to_ascii_lowercase();
        // this host's URLs (from archives, often with another scheme or port) mapped onto the brute-force base
        let known: Vec<String> = known_all
            .iter()
            .filter_map(|u| {
                foca_search::filter::archived_original(u)
                    .unwrap_or(u)
                    .parse::<Url>()
                    .ok()
            })
            .filter(|x| x.host_str().is_some_and(|h| h.eq_ignore_ascii_case(&host)))
            .map(|mut x| {
                let _ = x.set_scheme(base.scheme());
                let _ = x.set_port(base.port());
                x.to_string()
            })
            .take(500)
            .collect();
        let cms = detect_cms(&known);
        let mut m: Vec<Module> = mods
            .iter()
            .copied()
            .filter(|x| *x != Module::Cms || cms.is_some())
            .filter(|x| *x != Module::Vhost || (i == 0 && !vhost_domains.is_empty()))
            .collect();
        if content_wl.is_some() {
            m.push(Module::Content);
        }
        if m.is_empty() {
            continue;
        }
        let mut t = FuzzTask::new(base.clone(), m);
        t.known_urls = std::iter::once(base.to_string()).chain(known).collect();
        t.cms = cms;
        if t.has(Module::Vhost) {
            let wl = wordlists::builtin("dns-top5000")
                .map_err(|e| e.to_string())?
                .take(cfg.vhost_words);
            t.vhost = Some(VhostSpec {
                domains: vhost_domains.clone(),
                wordlist: wl,
            });
        }
        if let Some(wl) = &content_wl {
            t.content = Some(ContentSpec {
                template: Template::path(&format!("{}FUZZ", base.as_str())),
                wordlist: wl.clone(),
                extensions: vec![],
            });
        }
        out.push(t);
    }
    Ok(out)
}

fn sev_of(r: Risk) -> Severity {
    match r {
        Risk::High => Severity::High,
        Risk::Medium => Severity::Medium,
        Risk::Low => Severity::Low,
        Risk::Info => Severity::Info,
    }
}

/// Builds a project finding from a brute-force hit. Returns `None` if it is not a finding (a
/// document, or a path when "show all paths" is off).
fn hit_finding(
    h: &FuzzHit,
    show_paths: bool,
    now: &str,
    sid: &str,
) -> Option<foca_core::api::Finding> {
    let (rule, sev, title, rec, what): (&str, Severity, &str, &str, &str) = match h.kind {
        HitKind::Document => return None,
        HitKind::GitRepo => (
            "fuzz-git",
            Severity::High,
            "Открытый репозиторий .git",
            "Закрыть доступ к каталогу .git на веб-сервере, удалить его из веб-корня и сменить пароли и ключи, которые когда-либо попадали в историю репозитория.",
            "Каталог .git доступен из интернета: по нему можно восстановить исходный код сайта и историю изменений, включая случайно закоммиченные пароли.",
        ),
        HitKind::DbBackup => (
            "fuzz-db-backup",
            Severity::High,
            "Бэкап базы данных доступен из интернета",
            "Убрать дамп из веб-корня, хранить резервные копии вне сайта и ограничить к ним доступ.",
            "Файл похож на дамп или резервную копию базы данных и отдаётся сервером без авторизации.",
        ),
        HitKind::Backup => (
            "fuzz-backup",
            sev_of(h.risk),
            "Резервная копия файла на сайте",
            "Удалить резервную копию и запретить отдачу файлов *.bak, *~, *.old, *.orig, *.swp на веб-сервере.",
            "Рядом с рабочим файлом лежит его старая или резервная копия; в копиях исходников часто видны пароли и внутренние адреса.",
        ),
        HitKind::Exposed => (
            "fuzz-exposed",
            sev_of(h.risk),
            "Открытый служебный файл",
            "Удалить служебный файл с сайта или закрыть к нему доступ; если в нём были пароли или ключи, сменить их.",
            "Сервер отдаёт служебный файл (конфигурация, журнал, файл окружения), который не должен быть публичным.",
        ),
        HitKind::DsStore => (
            "fuzz-dsstore",
            Severity::Medium,
            "Открытый файл .DS_Store",
            "Удалить .DS_Store с сайта и запретить отдачу файлов .DS_Store на веб-сервере.",
            "Служебный файл macOS раскрывает имена файлов и папок каталога, в том числе не связанных ссылками.",
        ),
        HitKind::DirListing => (
            "fuzz-listing",
            Severity::Medium,
            "Открытый листинг каталога",
            "Отключить листинг каталогов (Apache: Options -Indexes, nginx: autoindex off) и проверить, какие файлы в каталоге должны быть публичными.",
            "Сервер показывает список файлов каталога («Index of /»): любой может увидеть и скачать всё содержимое.",
        ),
        HitKind::Vhost => (
            "fuzz-vhost",
            Severity::Low,
            "Скрытый виртуальный хост",
            "Проверить, должен ли этот сайт быть доступен из интернета; служебные сайты закрыть или ограничить по IP/VPN.",
            "На том же адресе отвечает отдельный сайт с другим именем, которого нет в DNS или ссылках.",
        ),
        HitKind::Directory | HitKind::Content | HitKind::CmsPath => {
            if !show_paths {
                return None;
            }
            (
                "fuzz-path",
                Severity::Info,
                "Найден путь на сайте",
                "Проверить, должен ли этот путь быть публичным.",
                "Путь существует на сайте (найден перебором по словарю).",
            )
        }
    };
    let u = Url::parse(&h.url).ok();
    let url_host = u
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_string();
    let host = h.host.clone().unwrap_or(url_host);
    let path = u.as_ref().map(|u| u.path().to_string()).unwrap_or_default();
    let key = match &h.host {
        Some(hh) => format!("{}|{hh}", h.url),
        None => h.url.clone(),
    };
    let shown = if h.kind == HitKind::Vhost {
        host.clone()
    } else {
        path.clone()
    };
    let mut desc = format!("{what}\n\nАдрес: {}", h.url);
    if let Some(hh) = &h.host {
        desc.push_str(&format!(" (заголовок Host: {hh})"));
    }
    desc.push_str(&format!(
        "\nОтвет: HTTP {}, {} байт{}.",
        h.status,
        h.size,
        h.content_type
            .as_deref()
            .map(|c| format!(", {c}"))
            .unwrap_or_default()
    ));
    let mut evidence = h.evidence.clone();
    if !h.extra.is_empty() {
        let list: Vec<&str> = h.extra.iter().take(20).map(String::as_str).collect();
        evidence.push_str(&format!(
            "\n- {} (из {}):\n{}",
            if h.kind == HitKind::DsStore {
                "имена"
            } else {
                "ссылки"
            },
            h.extra.len(),
            list.join("\n")
        ));
    }
    let mut sev = sev;
    if let Some(a) = &h.artifact {
        evidence.push_str("\n- разбор файла:\n");
        evidence.push_str(&a.lines.join("\n"));
        if a.sev < sev {
            sev = a.sev;
        }
    }
    let mut f = facts::net_finding(
        rule,
        &key,
        format!("{title}: {shown}"),
        sev,
        &host,
        "web",
        "Поиск на сайте",
        "fuzz",
        true,
        now,
        Some(sid),
        desc,
        rec,
        evidence,
        Some(h.url.clone()),
    );
    f.request = format!(
        "GET {} HTTP/1.1\nHost: {}",
        if path.is_empty() { "/" } else { &path },
        host
    );
    Some(f)
}

/// Warning when a host limited requests (429, 503 with `Retry-After`, a challenge page).
pub(crate) const BLOCKED_WARNING: &str =
    "Сайт ограничил запросы: перебор остановлен (повторных попыток нет)";

/// Warning for hosts that gave no HTTP answer at all (refused connections, timeouts, DNS).
pub(crate) fn unreachable_warning(hosts: usize) -> String {
    format!(
        "Хостов недоступно: {hosts}. Соединение не установлено (отказ, таймаут или DNS), перебор \
         на них остановлен: это не ограничение запросов"
    )
}

/// Warning for hosts that answer any address with their home page (random canaries of every
/// path class included): nothing there can be told apart, so the brute force stopped early.
pub(crate) fn catch_all_warning(hosts: usize) -> String {
    format!(
        "Хостов, отвечающих одинаковой страницей на любой адрес: {hosts}. Перебор на них \
         остановлен: найденные пути нельзя отличить от несуществующих"
    )
}

/// Returns the `fuzz` source status for a stop reason.
fn stop_status(s: &StopReason) -> &'static str {
    match s {
        StopReason::Completed => "ok",
        StopReason::Blocked { .. } => "blocked",
        StopReason::Denied { .. } => "error",
        StopReason::Cancelled
        | StopReason::Budget
        | StopReason::MaxTime
        | StopReason::Unreachable { .. }
        | StopReason::CatchAll { .. } => "stopped",
    }
}

fn add_stats(a: &mut FuzzStats, b: &FuzzStats) {
    a.planned += b.planned;
    a.checked += b.checked;
    a.found += b.found;
    a.filtered_calibration += b.filtered_calibration;
    a.filtered_rules += b.filtered_rules;
    a.requests += b.requests;
    a.calibration_requests += b.calibration_requests;
    a.errors += b.errors;
    a.skipped_excluded += b.skipped_excluded;
}

impl Ctx {
    /// Emits a `fuzz` source event with brute-force counters.
    fn fuzz_event(&self, status: &str, stats: &FuzzStats, extra: Value) {
        {
            let mut st = lock(&self.st);
            if let Some(s) = st.sources.iter_mut().find(|s| s.id == "fuzz") {
                s.status = status.into();
            }
        }
        let mut ev = json!({ "type": "source", "scan_id": self.scan_id, "id": "fuzz",
            "name": "Поиск на сайте", "status": status, "n": stats.found,
            "checked": stats.checked, "found": stats.found,
            "filtered": stats.filtered_calibration, "planned": stats.planned,
            "requests": stats.requests });
        if let (Some(o), Some(x)) = (ev.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                o.insert(k.clone(), v.clone());
            }
        }
        crate::services::i18n::annotate(&mut ev, &["error", "detail"]);
        self.e.emit(ev);
    }
}

/// Annotates discarded brute-force responses in the request log (soft 404, calibration, filters,
/// 429); otherwise they look like regular 200s in the target requests table.
fn annotate_log(c: &Ctx, filtered: &[foca_fuzz::Filtered]) {
    if filtered.is_empty() {
        return;
    }
    let items: Vec<(String, String, Option<String>, u64)> = filtered
        .iter()
        .map(|f| {
            (
                foca_net::sink::redact_url(&f.url),
                f.reason.code().to_string(),
                f.content_type.clone(),
                f.size,
            )
        })
        .collect();
    if let Err(e) = lock(&c.db).annotate_requests(Some(&c.scan_id), foca_fuzz::LOG_MODULE, &items) {
        tracing::warn!(target: "foca::scan", "{}: пометки перебора в журнале: {e}", c.scan_id);
    }
}

/// Counters shared by the hosts brute-forced at once: finished hosts and the live counters of
/// the running ones, plus when progress was last sent.
struct FuzzRun {
    done: FuzzStats,
    live: std::collections::BTreeMap<usize, FuzzStats>,
    last_emit: std::time::Instant,
}

impl FuzzRun {
    /// Counters of the whole stage: finished hosts plus what the running ones have done so far.
    fn total(&self) -> FuzzStats {
        let mut t = self.done.clone();
        for s in self.live.values() {
            add_stats(&mut t, s);
        }
        t
    }
}

/// How one host's brute force ended and the documents it found.
struct HostOut {
    stop: StopReason,
    docs: Vec<String>,
}

/// The stop reason of the whole stage from the hosts' own: a user stop, the shared budget or
/// time first, then a host that limited requests (it stopped only that host), then an
/// unreachable host, then a denial.
fn stage_stop(outs: &[HostOut]) -> StopReason {
    let rank = |s: &StopReason| match s {
        StopReason::Cancelled => 7,
        StopReason::Budget => 6,
        StopReason::MaxTime => 5,
        StopReason::Blocked { .. } => 4,
        StopReason::CatchAll { .. } => 3,
        StopReason::Unreachable { .. } => 2,
        StopReason::Denied { .. } => 1,
        StopReason::Completed => 0,
    };
    outs.iter()
        .map(|o| &o.stop)
        .fold(StopReason::Completed, |a, s| {
            if rank(s) > rank(&a) {
                s.clone()
            } else {
                a
            }
        })
}

/// `true` once the user asked to stop the brute force: "stop brute force"
/// (`scan_skip_source { id: "fuzz" }`), Skip or Restart on the stage.
fn fuzz_stop_asked(c: &Ctx) -> bool {
    let skipped = {
        let sk = lock(&c.skip);
        sk.contains("fuzz") || sk.contains(&format!("{}fuzz", super::control::SKIP_STAGE))
    };
    skipped || c.restart_asked("stage", "fuzz")
}

pub(super) async fn stage_fuzz(c: &mut Ctx) -> Result<(), Stop> {
    let idx = STAGES.iter().position(|s| s.0 == "fuzz").unwrap_or(5);
    if c.level != "active" || !c.module("fuzz") {
        return Ok(());
    }
    let run_opts: Value = facts::get(&lock(&c.db), &run_key(&c.scan_id));
    let v = effective(&c.e, Some(&run_opts));
    let cfg = config_of(&c.e, &v);
    let show_paths = v["show_paths"].as_bool().unwrap_or(false);
    let zero = FuzzStats::default();
    let tasks = {
        let db = lock(&c.db);
        build_tasks(&c.e, &db, &c.scope, &c.domains, &v, &cfg, false)
    };
    let tasks = match tasks {
        Ok(t) => t,
        Err(e) => {
            c.fuzz_event("error", &zero, json!({ "error": e, "detail": e }));
            return Ok(());
        }
    };
    if tasks.is_empty() {
        let d = "нет живых веб-адресов в скоупе";
        c.fuzz_event("skipped", &zero, json!({ "detail": d }));
        return Ok(());
    }
    tracing::info!(target: "foca::scan", "{}: поиск на сайте {} адрес(ов), модули {:?}", c.scan_id, tasks.len(), tasks.first().map(|t| &t.modules));
    let c: &Ctx = c;
    let now = c.e.now_iso();
    let sid = c.scan_id.clone();
    let dir = wordlist_dir(&c.e);
    let started = std::time::Instant::now();
    // one budget and one time limit for all hosts, however many run at once
    let budget = cfg.max_requests;
    let pool = Arc::new(AtomicU64::new(0));
    let target_net = c.group_net("target")?;
    let n = tasks.len();
    let shared = Mutex::new(FuzzRun {
        done: FuzzStats::default(),
        live: Default::default(),
        last_emit: std::time::Instant::now(),
    });
    // findings stored by any worker since the last re-analysis
    let dirty = Arc::new(AtomicBool::new(false));
    let board = c.host_board(n);
    let items: Vec<(String, ())> = tasks.iter().map(|t| (t.base.to_string(), ())).collect();
    let tasks = &tasks;
    let work = |i: usize, _: ()| {
        let task = &tasks[i];
        let (cfg, pool, target_net, dir, now, sid) = (
            cfg.clone(),
            pool.clone(),
            target_net.clone(),
            dir.clone(),
            now.clone(),
            sid.clone(),
        );
        let (dirty, shared, board) = (dirty.clone(), &shared, &board);
        async move {
            let out = |stop| HostOut {
                stop,
                docs: Vec::new(),
            };
            if fuzz_stop_asked(c) {
                return Ok(out(StopReason::Cancelled));
            }
            if pool.load(Ordering::SeqCst) >= budget {
                return Ok(out(StopReason::Budget));
            }
            let left = cfg.max_time.saturating_sub(started.elapsed());
            if left.is_zero() {
                return Ok(out(StopReason::MaxTime));
            }
            let mut hc = cfg;
            hc.max_time = left;
            let ctl = FuzzControl::with_cancel(c.cancel.child_token());
            let latest: Arc<Mutex<Option<FuzzStats>>> = Arc::default();
            let (lt, dt, db, now2, sid2) = (
                latest.clone(),
                dirty.clone(),
                c.db.clone(),
                now.clone(),
                sid.clone(),
            );
            let on_event: foca_fuzz::EventFn = Arc::new(move |e: &FuzzEvent| match e {
                FuzzEvent::Progress { stats } | FuzzEvent::Finished { stats, .. } => {
                    *lock(&lt) = Some(stats.clone());
                }
                FuzzEvent::Hit { hit } => {
                    // store the finding in project facts right away, so stopping mid-run does not lose it
                    if let Some(nf) = hit_finding(hit, show_paths, &now2, &sid2) {
                        let d = lock(&db);
                        let mut f: NetFacts = facts::get(&d, facts::K_NET);
                        f.findings.entry(nf.id).or_insert(nf);
                        let _ = facts::put(&d, facts::K_NET, &f);
                        dt.store(true, Ordering::SeqCst);
                    }
                }
                _ => {}
            });
            let fz = Fuzzer::new(target_net, hc)
                .with_control(ctl.clone())
                .with_events(on_event)
                .with_wordlist_dir(dir)
                .with_shared_budget(pool);
            let host = task.base.to_string();
            let where_ = json!({ "host": host, "hosts": n, "host_index": i });
            c.fuzz_event("running", &lock(shared).total(), where_.clone());
            let run = fz.run(task);
            tokio::pin!(run);
            // pause and stop reach this host within a tick; counters go out at most every 800 ms
            let mut tick = tokio::time::interval(Duration::from_millis(150));
            let rep = loop {
                tokio::select! {
                    r = &mut run => break r,
                    _ = tick.tick() => {
                        // propagate scan pause/resume and the stage's own Pause button to this host
                        let held = c.is_held(&["stage:fuzz".to_string(), "source:fuzz".to_string()]);
                        let paused = c.pause.borrow().is_some() || held;
                        if paused && !ctl.is_paused() {
                            ctl.pause();
                        } else if !paused && ctl.is_paused() {
                            ctl.resume();
                        }
                        if fuzz_stop_asked(c) && !ctl.is_cancelled() {
                            tracing::info!(target: "foca::scan", "{}: перебор {host} остановлен пользователем", c.scan_id);
                            ctl.cancel();
                        }
                        // one worker re-analyses for all of them
                        if dirty.swap(false, Ordering::SeqCst) {
                            let new = reanalyze_bg(c).await?;
                            c.findings_events(&new);
                        }
                        if let Some(s) = lock(&latest).clone() {
                            let frac = if s.planned > 0 { s.checked as f64 / s.planned as f64 } else { 0.0 };
                            board.set_progress(i, frac.min(1.0) * 0.99);
                            let agg = {
                                let mut sh = lock(shared);
                                sh.live.insert(i, s);
                                (sh.last_emit.elapsed() >= Duration::from_millis(800)).then(|| {
                                    sh.last_emit = std::time::Instant::now();
                                    sh.total()
                                })
                            };
                            if let Some(agg) = agg {
                                c.fuzz_event("running", &agg, where_.clone());
                                c.progress(idx, board.fraction() * 0.8);
                            }
                        }
                    }
                }
            };
            if c.cancel.is_cancelled() {
                return Err(Stop::Cancelled);
            }
            {
                let mut sh = lock(shared);
                sh.live.remove(&i);
                add_stats(&mut sh.done, &rep.stats);
            }
            annotate_log(c, &rep.filtered);
            tracing::info!(target: "foca::scan", "{}: поиск на {}, {} ({} запросов, {} находок, {} документов)",
                c.scan_id, host, rep.stop.message_ru(), rep.stats.requests, rep.hits.len(), rep.documents.len());
            Ok(HostOut {
                stop: rep.stop,
                docs: rep.documents,
            })
        }
    };
    let outs = match c.each_host(&board, items, work).await {
        Ok(o) => o,
        Err(e) => {
            c.host_board_end(board, "skipped");
            return Err(e);
        }
    };
    let final_stop = stage_stop(&outs);
    c.host_board_end(
        board,
        if final_stop == StopReason::Cancelled {
            "skipped"
        } else {
            "done"
        },
    );
    if dirty.swap(false, Ordering::SeqCst) {
        let new = reanalyze_bg(c).await?;
        c.findings_events(&new);
    }
    let total = lock(&shared).total();
    let blocked_hosts = outs
        .iter()
        .filter(|o| matches!(o.stop, StopReason::Blocked { .. }))
        .count();
    // hosts that never answered are unreachable: a separate note, not the rate-limit one
    let unreachable_hosts = outs
        .iter()
        .filter(|o| matches!(o.stop, StopReason::Unreachable { .. }))
        .count();
    let catch_all_hosts = outs
        .iter()
        .filter(|o| matches!(o.stop, StopReason::CatchAll { .. }))
        .count();
    // documents in host order (the order hosts finished in does not matter)
    let docs: Vec<String> = outs.into_iter().flat_map(|o| o.docs).collect();
    let status = stop_status(&final_stop);
    let detail = final_stop.message_ru();
    if blocked_hosts > 0 {
        c.warn("fuzz_blocked", BLOCKED_WARNING);
    }
    if unreachable_hosts > 0 {
        c.warn("fuzz_unreachable", &unreachable_warning(unreachable_hosts));
    }
    if catch_all_hosts > 0 {
        c.warn("fuzz_catch_all", &catch_all_warning(catch_all_hosts));
    }
    // documents go to the regular download queue (deduplicated against known ones before the limit) and parsing
    let added = {
        let db = lock(&c.db);
        let known: BTreeSet<String> = db
            .task_urls()?
            .iter()
            .map(|u| foca_search::filter::target_key(u))
            .collect();
        drop(db);
        let mut seen = BTreeSet::new();
        let limit = lock(&c.st).limit;
        let fresh: Vec<foca_search::FoundUrl> = docs
            .iter()
            .filter(|u| {
                let k = foca_search::filter::target_key(u);
                !known.contains(&k) && seen.insert(k)
            })
            .take(limit)
            .map(|u| foca_search::FoundUrl::new(u, "fuzz"))
            .collect();
        StoreQueue::new(c.db.clone(), Some(c.scan_id.clone()))
            .enqueue(&fresh)
            .map_err(Stop::Error)?
    };
    c.fuzz_event(
        status,
        &total,
        json!({ "detail": detail, "documents": added, "stop": final_stop,
            "blocked_hosts": blocked_hosts, "unreachable_hosts": unreachable_hosts }),
    );
    if added > 0 {
        download_queue(c, idx).await?;
        meta_pending(c, idx).await?;
    }
    let new = reanalyze_bg(c).await?;
    c.findings_events(&new);
    Ok(())
}

static BUILTIN_LINES: OnceLock<Vec<(String, usize, u64)>> = OnceLock::new();

fn builtin_info() -> &'static [(String, usize, u64)] {
    BUILTIN_LINES.get_or_init(|| {
        wordlists::BUILTIN
            .iter()
            .map(|b| {
                let w = wordlists::builtin(b.id).unwrap_or_default();
                let size: u64 = w.words.iter().map(|x| x.len() as u64 + 1).sum();
                (b.id.to_string(), w.len(), size)
            })
            .collect()
    })
}

/// Returns the display name of a wordlist (Russian; the UI translates it by id via
/// `core.wordlist.<id>.name`).
fn wordlist_name(id: &str) -> String {
    match id {
        "common" => "Частые пути (common)",
        "quickhits" => "Служебные файлы (quickhits)",
        "db-backups" => "Бэкапы баз данных",
        "raft-small-files" => "Файлы (raft small)",
        "raft-small-directories" => "Каталоги (raft small)",
        "dsstore" => "Имена из .DS_Store",
        "dns-top5000" => "Поддомены, топ-5000 (для vhost)",
        "ext-most-common" => "Частые расширения",
        "ext-compressed" => "Расширения архивов",
        "ext-all" => "Все расширения",
        "cms-wordpress" => "WordPress",
        "cms-sharepoint" => "SharePoint",
        "cms-joomla" => "Joomla (плагины)",
        "cms-drupal" => "Drupal (темы)",
        "dns-top20000" => "Поддомены, топ-20000",
        "dns-top110000" => "Поддомены, топ-110000",
        "raft-medium-files" => "Файлы (raft medium)",
        "raft-medium-directories" => "Каталоги (raft medium)",
        _ => return id.replace(['-', '_'], " "),
    }
    .to_string()
}

fn wl_err(e: WordlistError) -> CmdError {
    let code = match e {
        WordlistError::Unknown(_) => "not_found",
        WordlistError::TooLarge(..) => "too_large",
        WordlistError::Checksum { .. } => "checksum",
        WordlistError::Net(_) => "net",
        WordlistError::Io(_) => "io",
    };
    CmdError::new(code, e.to_string())
}

impl Engine {
    /// `fuzz_estimate { project?, modules?, wordlists?, rate? }` estimates the run without network access.
    pub(crate) fn fuzz_estimate(&self, a: &Value) -> CmdResult {
        let project = self.project_arg(a)?;
        let db = self.db(&project)?;
        let mut over = json!({});
        for k in [
            "modules",
            "wordlists",
            "rate",
            "threads",
            "max_requests",
            "max_time_min",
        ] {
            if let Some(x) = a.get(k).filter(|x| !x.is_null()) {
                over[k] = x.clone();
            }
        }
        let v = effective(self, Some(&over));
        let cfg = config_of(self, &v);
        let d = lock(&db);
        let scope = d.scope_get()?;
        let targets: Vec<String> = scope.targets.iter().map(|t| t.v.clone()).collect();
        let domains = target_domains(&scope, &targets);
        let tasks = build_tasks(self, &d, &scope, &domains, &v, &cfg, true)
            .map_err(|e| CmdError::new("bad_args", e))?;
        // the estimate is for the full profile's active stage: the same scope the brute force will get
        let core = crate::scan::core_scope_for(&scope, "active");
        let dir = wordlist_dir(self);
        let (mut cand, mut cal, mut excl) = (0u64, 0u64, 0u64);
        let mut per: std::collections::BTreeMap<String, u64> = Default::default();
        for t in &tasks {
            let e = foca_fuzz::estimate(t, &cfg, Some(&core), Some(&dir))
                .map_err(|e| CmdError::new("bad_args", e))?;
            cand += e.candidates;
            cal += e.calibration;
            excl += e.skipped_excluded;
            for (k, n) in e.per_module {
                *per.entry(k).or_default() += n;
            }
        }
        let total = cand + cal;
        let requests = total.min(cfg.max_requests);
        let secs = foca_fuzz::plan::request_seconds(requests, &cfg).min(cfg.max_time.as_secs_f64());
        // The RU text stays as the fallback; the UI renders `note_msg` in its language.
        let (note, note_code) = if tasks.is_empty() {
            ("нет веб-адресов в скоупе", "fuzz.no_urls")
        } else {
            (
                "без учёта кандидатов, появляющихся по ходу (варианты найденного, листинги, .DS_Store)",
                "fuzz.estimate_note",
            )
        };
        Ok(json!({
            "hosts": tasks.iter().map(|t| t.base.to_string()).collect::<Vec<_>>(),
            "candidates": cand, "calibration": cal, "requests": requests,
            "seconds": secs.ceil() as u64, "capped_by_budget": total > cfg.max_requests,
            "per_module": per, "skipped_excluded": excl,
            // 0 = no limit, as in the settings
            "rate": if cfg.rate >= UNLIMITED_RATE { 0.0 } else { cfg.rate },
            "max_requests": if cfg.max_requests == u64::MAX { 0 } else { cfg.max_requests },
            "max_time_min": if cfg.max_time.as_secs() >= crate::settings::MAX_SETTING_SECS {
                0
            } else {
                cfg.max_time.as_secs() / 60
            },
            "note": note,
            "note_msg": { "code": note_code, "params": {} },
        }))
    }

    /// `wordlists_list`: built-in, large (downloadable) and custom wordlists.
    pub(crate) fn wordlists_list(&self) -> CmdResult {
        let dir = wordlist_dir(self);
        let mut items = Vec::new();
        for (b, (id, lines, size)) in wordlists::BUILTIN.iter().zip(builtin_info()) {
            items.push(
                json!({ "id": id, "kind": "builtin", "name": wordlist_name(id),
                "source": format!("SecLists/{}", b.source), "lines": lines, "size": size,
                "downloaded": true }),
            );
        }
        for l in wordlists::REGISTRY {
            let p = wordlists::remote_path(&dir, l);
            items.push(
                json!({ "id": l.id, "kind": "remote", "name": wordlist_name(l.id),
                "source": format!("SecLists/{}", l.source), "lines": l.lines, "size": l.size,
                "sha256": l.sha256, "downloaded": p.is_file() }),
            );
        }
        if let Ok(rd) = std::fs::read_dir(custom_dir(self)) {
            let mut v: Vec<_> = rd.filter_map(Result::ok).collect();
            v.sort_by_key(|e| e.file_name());
            for e in v {
                let name = e.file_name().to_string_lossy().into_owned();
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                let lines = std::fs::read(e.path())
                    .map(|b| b.split(|c| *c == b'\n').filter(|l| !l.is_empty()).count())
                    .unwrap_or(0);
                items.push(json!({ "id": format!("custom:{name}"), "kind": "custom",
                    "name": name, "source": "свой", "lines": lines, "size": size,
                    "downloaded": true }));
            }
        }
        let selected = str_list(&effective(self, None)["wordlists"]);
        Ok(json!({ "items": items, "selected": selected,
            "seclists_commit": wordlists::SECLISTS_COMMIT,
            "modules": FUZZ_MODULES.iter().map(|(id, n, d)| json!({ "id": id, "name": n, "desc": d })).collect::<Vec<_>>() }))
    }

    /// `wordlists_download { id }` downloads a large wordlist from GitHub (not the target) and verifies its SHA-256.
    pub(crate) async fn wordlists_download(&self, a: &Value) -> CmdResult {
        let id = arg_str(a, "id").ok_or_else(|| CmdError::new("bad_args", "нет id словаря"))?;
        let l = wordlists::REGISTRY
            .iter()
            .find(|l| l.id == id)
            .ok_or_else(|| CmdError::not_found(format!("нет словаря «{id}» для загрузки")))?;
        let sink: Arc<dyn foca_net::RequestSink> =
            match self.project_arg(a).and_then(|p| self.db(&p)) {
                Ok(db) => Arc::new(foca_search::store::StoreSink { db, scan_id: None }),
                Err(_) => Arc::new(foca_net::NullSink),
            };
        let net = self.net_client(foca_core::Scope::default(), sink)?;
        let over = self
            .inner
            .cfg
            .endpoints
            .sources
            .get("seclists")
            .map(|b| format!("{}/{}", b.trim_end_matches('/'), l.source));
        let p = wordlists::download(&net, l, &wordlist_dir(self), over.as_deref())
            .await
            .map_err(wl_err)?;
        tracing::info!(target: "foca::cmd", "словарь {id} скачан: {}", p.display());
        Ok(json!({ "ok": true, "id": id, "size": l.size, "lines": l.lines }))
    }

    /// `wordlists_import { path }` imports a custom wordlist from a file (up to 64 MiB; words are sanitized).
    pub(crate) fn wordlists_import(&self, a: &Value) -> CmdResult {
        let path = arg_str(a, "path").ok_or_else(|| CmdError::new("bad_args", "нет пути"))?;
        let w = wordlists::import_file(Path::new(path), IMPORT_MAX).map_err(wl_err)?;
        if w.is_empty() {
            return Err(CmdError::new("bad_args", "в файле нет подходящих слов"));
        }
        let name = safe_name(arg_str(a, "name").unwrap_or(&w.id));
        let dir = custom_dir(self);
        std::fs::create_dir_all(&dir).map_err(|e| CmdError::new("io", e.to_string()))?;
        let mut text = w.words.join("\n");
        text.push('\n');
        std::fs::write(dir.join(&name), &text).map_err(|e| CmdError::new("io", e.to_string()))?;
        Ok(
            json!({ "ok": true, "id": format!("custom:{name}"), "name": name,
            "lines": w.len(), "dropped": w.dropped, "size": text.len() }),
        )
    }

    /// `wordlists_delete { id }` removes a downloaded or custom wordlist (built-in ones cannot be removed).
    pub(crate) fn wordlists_delete(&self, a: &Value) -> CmdResult {
        let id = arg_str(a, "id").ok_or_else(|| CmdError::new("bad_args", "нет id словаря"))?;
        let p = if let Some(n) = id.strip_prefix("custom:") {
            custom_dir(self).join(safe_name(n))
        } else if let Some(l) = wordlists::REGISTRY.iter().find(|l| l.id == id) {
            wordlists::remote_path(&wordlist_dir(self), l)
        } else if wordlists::BUILTIN.iter().any(|b| b.id == id) {
            return Err(CmdError::new(
                "bad_args",
                "встроенный словарь нельзя удалить",
            ));
        } else {
            return Err(CmdError::not_found(format!("нет словаря «{id}»")));
        };
        let existed = p.is_file();
        if existed {
            std::fs::remove_file(&p).map_err(|e| CmdError::new("io", e.to_string()))?;
        }
        // remove it from the selection
        let sel: Vec<String> = str_list(&effective(self, None)["wordlists"])
            .into_iter()
            .filter(|x| x != id)
            .collect();
        self.store()
            .settings_set(&json!({ "fuzz": { "wordlists": sel } }))?;
        Ok(json!({ "ok": existed }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_hosts_do_not_count_as_rate_limited() {
        let out = |stop: StopReason| HostOut { stop, docs: vec![] };
        let un = StopReason::Unreachable {
            detail: "3 сетевых ошибок без ответа HTTP: network".into(),
        };
        assert_eq!(stop_status(&un), "stopped");
        assert_eq!(
            stage_stop(&[out(StopReason::Completed), out(un.clone())]),
            un
        );
        // a real rate limit on another host still wins
        let bl = StopReason::Blocked {
            detail: "HTTP 429".into(),
        };
        assert_eq!(stage_stop(&[out(un), out(bl.clone())]), bl);
    }

    #[test]
    fn safe_names() {
        assert_eq!(safe_name("../../etc/passwd"), "passwd.txt");
        assert_eq!(safe_name("my list.txt"), "my_list.txt");
        assert_eq!(safe_name(".hidden"), "hidden.txt");
        assert_eq!(safe_name(""), "custom.txt");
    }

    #[test]
    fn cms_from_urls() {
        assert_eq!(
            detect_cms(&["https://a.ua/wp-content/uploads/x.pdf".into()]),
            Some(foca_fuzz::Cms::WordPress)
        );
        assert_eq!(detect_cms(&["https://a.ua/x.pdf".into()]), None);
    }

    #[test]
    fn findings_map() {
        let h = FuzzHit {
            url: "https://a.ua/.git/HEAD".into(),
            host: None,
            status: 200,
            size: 23,
            words: 2,
            lines: 1,
            kind: HitKind::GitRepo,
            risk: Risk::High,
            module: Module::Exposed,
            evidence: "ref: refs/heads/main".into(),
            redirect: None,
            content_type: None,
            extra: vec![],
            artifact: None,
        };
        let f = hit_finding(&h, false, "2026-11-20T10:00:00", "s1").unwrap();
        assert_eq!(f.sev, Severity::High);
        assert_eq!(f.module, "fuzz");
        assert!(f.active);
        assert!(f.title.contains("/.git/HEAD"));
        let d = FuzzHit {
            kind: HitKind::Document,
            ..h.clone()
        };
        assert!(hit_finding(&d, true, "", "s").is_none());
        let p = FuzzHit {
            kind: HitKind::Directory,
            ..h
        };
        assert!(hit_finding(&p, false, "", "s").is_none());
        assert!(hit_finding(&p, true, "", "s").is_some());
    }
}

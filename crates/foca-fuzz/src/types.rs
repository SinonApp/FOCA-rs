//! Fuzzing results, events and statuses.

use serde::{Deserialize, Serialize};

/// Fuzzing module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    /// Free-form template with `FUZZ` × wordlist × extensions (the ffuf core).
    Content,
    /// Common document folders × names × office extensions, plus mutations of known names.
    Docs,
    /// Backup suffixes for known URLs (FOCA Backups Fuzzer) plus Common-DB-Backups.
    Backups,
    /// Forgotten service files (SecLists quickhits) with format verification.
    Exposed,
    /// Open directory listings: detection and collection of document links.
    DirListing,
    /// The client's virtual hosts on the same address (`Host: FUZZ.<domain>`).
    Vhost,
    /// Wordlist for the detected CMS.
    Cms,
}

impl Module {
    pub const ALL: [Module; 7] = [
        Module::Content,
        Module::Docs,
        Module::Backups,
        Module::Exposed,
        Module::DirListing,
        Module::Vhost,
        Module::Cms,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Module::Content => "content",
            Module::Docs => "docs",
            Module::Backups => "backups",
            Module::Exposed => "exposed",
            Module::DirListing => "dirlisting",
            Module::Vhost => "vhost",
            Module::Cms => "cms",
        }
    }

    pub fn parse(s: &str) -> Option<Module> {
        let s = s.trim().to_ascii_lowercase();
        Module::ALL.into_iter().find(|m| {
            m.id() == s
                || (s == "exposed-files" && *m == Module::Exposed)
                || (s == "listing" && *m == Module::DirListing)
        })
    }
}

/// What was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitKind {
    /// A document (office file, PDF, …).
    Document,
    /// A backup or old version of a file.
    Backup,
    /// A database dump or backup.
    DbBackup,
    /// A forgotten service file (quickhits).
    Exposed,
    /// An exposed `.git` (confirmed by the HEAD format).
    GitRepo,
    /// A `.DS_Store` with a list of file names.
    DsStore,
    /// An open directory listing.
    DirListing,
    /// An existing directory (no listing).
    Directory,
    /// A hidden virtual host.
    Vhost,
    /// A CMS path.
    CmsPath,
    /// Any other template match.
    Content,
}

impl HitKind {
    pub fn title_ru(self) -> &'static str {
        match self {
            HitKind::Document => "Документ найден перебором",
            HitKind::Backup => "Резервная копия файла",
            HitKind::DbBackup => "Бэкап базы данных",
            HitKind::Exposed => "Открытый служебный файл",
            HitKind::GitRepo => "Открытый .git",
            HitKind::DsStore => "Открытый .DS_Store",
            HitKind::DirListing => "Листинг каталога",
            HitKind::Directory => "Каталог",
            HitKind::Vhost => "Скрытый vhost",
            HitKind::CmsPath => "Путь CMS",
            HitKind::Content => "Совпадение",
        }
    }
}

/// Risk level of a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Info,
    Low,
    Medium,
    High,
}

/// A hit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzHit {
    pub url: String,
    /// `Host` header if it differs from the URL host (vhost).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub status: u16,
    /// Body size (Content-Length or bytes read).
    pub size: u64,
    pub words: u64,
    pub lines: u64,
    pub kind: HitKind,
    pub risk: Risk,
    pub module: Module,
    /// Short evidence (secrets masked; the content is never stored in full).
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Extra details: names from .DS_Store, links from a listing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
    /// Parsed content of a known artifact (`.git/config`, `.env`, `.ovpn`, `package.json`,
    /// `composer.json`): only the parsed, masked summary is kept, never the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactSummary>,
}

/// Masked summary of an artifact parsed by `foca-analysis::artifacts`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArtifactSummary {
    /// `git_config` | `git_logs` | `env` | `ovpn` | `package_json` | `composer_json`.
    pub kind: String,
    /// Developer identities (`Name <e-mail>`).
    pub people: Vec<String>,
    /// Hosts: remotes, VPN servers, registries, `*_HOST`/`*_URL` values.
    pub hosts: Vec<String>,
    /// Internal Git remotes, VPN servers or registries were found.
    pub internal: bool,
    /// Human-readable lines for the finding evidence (values masked).
    pub lines: Vec<String>,
    /// `crit` | `high` | `warn` | `low` | `info`.
    pub sev: foca_core::Severity,
}

/// Why fuzzing ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
    /// Everything was checked.
    Completed,
    /// Stopped by the user.
    Cancelled,
    /// The request budget is exhausted.
    Budget,
    /// `max_time` elapsed.
    MaxTime,
    /// The site started throttling requests (a run of 429/403/5xx/errors) and fuzzing stopped.
    /// No evasion is attempted.
    Blocked { detail: String },
    /// Active requests are denied by the scope or project settings.
    Denied { detail: String },
}

impl StopReason {
    pub fn message_ru(&self) -> String {
        match self {
            StopReason::Completed => "перебор завершён".into(),
            StopReason::Cancelled => "перебор остановлен пользователем".into(),
            StopReason::Budget => "исчерпан бюджет запросов: перебор остановлен".into(),
            StopReason::MaxTime => "истекло отведённое время: перебор остановлен".into(),
            StopReason::Blocked { detail } => {
                format!("сайт ограничил запросы: перебор остановлен ({detail})")
            }
            StopReason::Denied { detail } => format!("активные запросы запрещены: {detail}"),
        }
    }
}

/// Counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzStats {
    /// Planned candidates (excluding follow-ups added during the run).
    pub planned: u64,
    /// Candidates checked (a response was received).
    pub checked: u64,
    pub found: u64,
    /// Filtered by calibration (soft 404).
    pub filtered_calibration: u64,
    /// Rejected by matchers/filters (plain 404s etc.) or by format verification.
    pub filtered_rules: u64,
    /// Total HTTP requests (calibration included).
    pub requests: u64,
    pub calibration_requests: u64,
    pub errors: u64,
    /// Skipped before sending because of exclusions (paths/hosts).
    pub skipped_excluded: u64,
}

/// Progress event (for the UI and engine).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FuzzEvent {
    Started {
        planned: u64,
    },
    Calibrated {
        context: String,
        samples: usize,
        summary: String,
    },
    Progress {
        stats: FuzzStats,
    },
    Hit {
        hit: FuzzHit,
    },
    Paused,
    Resumed,
    Finished {
        stop: StopReason,
        stats: FuzzStats,
    },
}

/// Why a fuzzing response was discarded (the request log shows it next to the 200 status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterReason {
    /// Calibration probe (random path): a sample of the site's "not found" response.
    Calibration,
    /// Matched the "not found" sample (soft 404).
    Soft404,
    /// Cut by user filters (status/size/words/lines).
    Rules,
    /// 429: the site is rate limiting.
    RateLimited,
}

impl FilterReason {
    /// Returns the log code (`request_log.note`).
    pub fn code(self) -> &'static str {
        match self {
            FilterReason::Calibration => "calibration",
            FilterReason::Soft404 => "soft404",
            FilterReason::Rules => "filtered",
            FilterReason::RateLimited => "rate_limited",
        }
    }
}

/// A discarded response: URL, status, size, content type and reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filtered {
    pub url: String,
    pub status: u16,
    pub size: u64,
    pub content_type: Option<String>,
    pub reason: FilterReason,
}

/// Maximum number of discarded-response records per run (the log is bounded by the request
/// budget).
pub const FILTERED_CAP: usize = 20_000;

/// Fuzzing result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzReport {
    pub hits: Vec<FuzzHit>,
    /// Discarded responses (calibration, soft 404, filters, 429) for the request log notes.
    #[serde(default)]
    pub filtered: Vec<Filtered>,
    /// Candidates for the download queue (documents from hits and listings).
    pub documents: Vec<String>,
    pub stats: FuzzStats,
    pub stop: StopReason,
}

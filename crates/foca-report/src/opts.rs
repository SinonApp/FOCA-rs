//! Report and export options. Parsing tolerates the UI shapes (`report_build.opts`,
//! `ReportDraft`): `tpl_id`/`tpl`, `UA`/`uk`, `min_sev`/`minSev`, `sections`/`sec`,
//! `logo: bool|data-URL`.

use foca_core::Severity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Report template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Template {
    /// Full pentest report: cover, executive summary, scope, findings with evidence, appendices.
    #[default]
    Full,
    /// Short summary (`brief` in the UI): risk and a table of top findings, no evidence.
    #[serde(alias = "brief")]
    Summary,
    /// Data: tables without narrative.
    Data,
    /// One page for management: risk score, top five findings in plain language, three
    /// priority actions.
    Executive,
    /// КСЗІ / compliance: findings × standards (`signatures/standards.toml`) with the auditor's
    /// disclaimer.
    Compliance,
    /// Laboratory work: goal, method, input data, course, findings with standards, conclusions.
    Lab,
}

impl Template {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "full" | "полный" | "полный отчёт пентеста" | "повний" => {
                Some(Self::Full)
            }
            "summary" | "brief" | "сводка" | "краткая сводка" | "зведення" => {
                Some(Self::Summary)
            }
            "data" | "данные" | "дані" => Some(Self::Data),
            "executive" | "exec" | "руководство" | "керівництво" => {
                Some(Self::Executive)
            }
            "compliance" | "kszi" | "ксзі" | "ксзи" | "соответствие" | "відповідність" => {
                Some(Self::Compliance)
            }
            "lab" | "лабораторная работа" | "лабораторна робота" => {
                Some(Self::Lab)
            }
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Summary => "summary",
            Self::Data => "data",
            Self::Executive => "executive",
            Self::Compliance => "compliance",
            Self::Lab => "lab",
        }
    }
    /// Templates rendered by `templates.rs` (their own layout, no section switches).
    pub fn is_standalone(self) -> bool {
        matches!(self, Self::Executive | Self::Compliance | Self::Lab)
    }
    /// All template ids in UI order.
    pub const ALL: [Template; 4] = [Self::Full, Self::Executive, Self::Compliance, Self::Lab];
}

/// Report file format. `pdf` from the UI is built as HTML (the WebView prints the PDF from
/// it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    #[default]
    Html,
    Md,
    Csv,
    Json,
    Docx,
}

impl ReportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "html" | "htm" | "pdf" => Some(Self::Html),
            "md" | "markdown" => Some(Self::Md),
            "csv" => Some(Self::Csv),
            "json" => Some(Self::Json),
            "docx" | "word" => Some(Self::Docx),
            _ => None,
        }
    }
    pub fn ext(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Md => "md",
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Docx => "docx",
        }
    }
    pub fn mime(self) -> &'static str {
        match self {
            Self::Html => "text/html; charset=utf-8",
            Self::Md => "text/markdown; charset=utf-8",
            Self::Csv => "text/csv; charset=utf-8",
            Self::Json => "application/json",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }
    }
}

/// Report language (re-exported from `foca-core`).
pub use foca_core::Lang;

/// How secrets are shown (`{{s:…}}` in evidence and `secrets[]` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretMode {
    /// Replaced with a localized "hidden" placeholder (the safe default).
    #[default]
    Hide,
    /// `Bu••••••23!`, as in the UI preview.
    Partial,
    /// Clear text (only on explicit user choice).
    Full,
}

impl SecretMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "hide" | "hidden" | "off" => Some(Self::Hide),
            "partial" | "mask" => Some(Self::Partial),
            "full" | "show" | "on" => Some(Self::Full),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Hide => "hide",
            Self::Partial => "partial",
            Self::Full => "full",
        }
    }
}

/// Report sections (`sec` in the report builder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Sections {
    pub summary: bool,
    pub scope: bool,
    pub findings: bool,
    pub fixed: bool,
    pub people: bool,
    pub infra: bool,
    pub docs: bool,
    pub log: bool,
    pub appx: bool,
}

impl Default for Sections {
    fn default() -> Self {
        Self::for_template(Template::Full)
    }
}

impl Sections {
    /// Returns the default sections, matching `draft0` in `ui/screens/reports.js`.
    pub fn for_template(t: Template) -> Self {
        Sections {
            summary: true,
            scope: true,
            findings: true,
            fixed: t != Template::Data,
            people: t == Template::Full,
            infra: t != Template::Summary,
            docs: t == Template::Full,
            log: false,
            appx: t == Template::Full,
        }
    }
    pub fn all() -> Self {
        Sections {
            summary: true,
            scope: true,
            findings: true,
            fixed: true,
            people: true,
            infra: true,
            docs: true,
            log: true,
            appx: true,
        }
    }
}

/// Logo of the report author's company.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Logo {
    #[default]
    None,
    /// A circle with the company initials (like the UI preview with `logo: true`).
    Initials,
    /// A raster image (PNG/JPEG/WebP/GIF) in base64, embedded as a `data:` URL. SVG is rejected
    /// because it may contain scripts.
    Image { mime: String, b64: String },
}

impl Logo {
    /// Parses `data:image/png;base64,…` or bare base64 (type detected by signature). Invalid
    /// input yields `None`.
    pub fn from_data(s: &str) -> Logo {
        let s = s.trim();
        let (mime, b64) = if let Some(rest) = s.strip_prefix("data:") {
            let Some((head, data)) = rest.split_once(',') else {
                return Logo::None;
            };
            let Some(mime) = head.strip_suffix(";base64") else {
                return Logo::None;
            };
            (mime.to_ascii_lowercase(), data)
        } else {
            (String::new(), s)
        };
        let b64: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        if b64.is_empty()
            || !b64
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        {
            return Logo::None;
        }
        let Some(bytes) = foca_core::b64::decode(&b64) else {
            return Logo::None;
        };
        let sniff = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            "image/png"
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            "image/jpeg"
        } else if bytes.starts_with(b"GIF8") {
            "image/gif"
        } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            "image/webp"
        } else {
            return Logo::None;
        };
        if !mime.is_empty() && mime != sniff && !(mime == "image/jpg" && sniff == "image/jpeg") {
            return Logo::None;
        }
        Logo::Image {
            mime: sniff.into(),
            b64,
        }
    }
}

/// Project summary written by a cloud AI model (`ai_summarize`), stored with the project and
/// shown as an optional, clearly labelled report section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiSummary {
    /// Markdown text as returned by the model.
    pub text: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    /// RFC 3339 time of generation.
    #[serde(default)]
    pub created: String,
}

/// Options key with the AI summary data (filled by the core from the stored project summary,
/// or passed by the caller); never kept in `raw`.
pub const AI_SUMMARY_DATA_KEY: &str = "ai_summary_data";

/// Options for `build_report`.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportOptions {
    pub tpl: Template,
    pub fmt: ReportFormat,
    pub lang: Lang,
    pub sections: Sections,
    /// Confirmed findings only (`status = confirmed`).
    pub confirmed: bool,
    /// Embed Chain of Custody metadata section when true (false keeps legacy reports unchanged).
    pub custody: bool,
    /// Severity threshold (`None` means all).
    pub min_sev: Option<Severity>,
    /// Only findings picked with "Add to report" (`picked`).
    pub picked_only: bool,
    pub picked: Vec<u64>,
    pub secrets: SecretMode,
    /// Author's company (header, cover).
    pub company: String,
    pub logo: Logo,
    /// Version number in the file name (`_vN`); `None` uses the next one after the project's
    /// reports.
    pub version: Option<u32>,
    /// AI-assisted executive summary, if the project has one.
    pub ai_summary: Option<AiSummary>,
    /// Include `ai_summary` as the "Executive summary (AI-assisted)" section (`opts.ai_summary`,
    /// default true). Without a stored summary nothing is added either way.
    pub include_ai_summary: bool,
    /// Original UI `opts`, stored in the report record verbatim.
    pub raw: Value,
}

impl Default for ReportOptions {
    fn default() -> Self {
        ReportOptions {
            tpl: Template::Full,
            fmt: ReportFormat::Html,
            lang: Lang::Ru,
            sections: Sections::default(),
            confirmed: false,
            custody: false,
            min_sev: None,
            picked_only: false,
            picked: Vec::new(),
            secrets: SecretMode::Hide,
            company: String::new(),
            logo: Logo::None,
            version: None,
            ai_summary: None,
            include_ai_summary: true,
            raw: Value::Null,
        }
    }
}

/// `"all"|"low"|"warn"|"high"|"crit"` (+ `medium`/`critical`).
pub fn parse_min_sev(s: &str) -> Option<Severity> {
    match s.trim().to_lowercase().as_str() {
        "crit" | "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "warn" | "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

impl ReportOptions {
    /// Parses the `opts` of the `report_build` command (or a `ReportDraft`). Unknown values fall
    /// back to defaults.
    pub fn from_ui(v: &Value) -> ReportOptions {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
        let b = |k: &str| v.get(k).and_then(Value::as_bool);
        let tpl = Template::parse(s("template"))
            .or_else(|| Template::parse(s("tpl_id")))
            .or_else(|| Template::parse(s("tpl")))
            .unwrap_or_default();
        let mut sections = Sections::for_template(tpl);
        if let Some(sec) = v
            .get("sections")
            .or_else(|| v.get("sec"))
            .and_then(Value::as_object)
        {
            for (k, val) in sec {
                let on = val.as_bool().unwrap_or(false);
                match k.as_str() {
                    "summary" => sections.summary = on,
                    "scope" => sections.scope = on,
                    "findings" => sections.findings = on,
                    "fixed" => sections.fixed = on,
                    "people" => sections.people = on,
                    "infra" => sections.infra = on,
                    "docs" => sections.docs = on,
                    "log" => sections.log = on,
                    "appx" => sections.appx = on,
                    _ => {}
                }
            }
        }
        let min_sev = v
            .get("min_sev")
            .or_else(|| v.get("minSev"))
            .and_then(Value::as_str)
            .and_then(parse_min_sev);
        let picked = v
            .get("picked")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        let logo = match v.get("logo") {
            Some(Value::Bool(true)) => Logo::Initials,
            Some(Value::String(d)) => Logo::from_data(d),
            _ => Logo::None,
        };
        ReportOptions {
            tpl,
            fmt: ReportFormat::parse(s("fmt")).unwrap_or_default(),
            lang: Lang::parse(s("lang")).unwrap_or(Lang::Ru),
            sections,
            confirmed: b("confirmed").unwrap_or(false),
            custody: b("custody").unwrap_or(false),
            min_sev,
            picked_only: b("picked_only")
                .or_else(|| b("pickedOnly"))
                .unwrap_or(false),
            picked,
            secrets: SecretMode::parse(s("secrets")).unwrap_or_default(),
            company: s("company").to_string(),
            logo,
            version: v.get("version").and_then(Value::as_u64).map(|n| n as u32),
            ai_summary: v
                .get(AI_SUMMARY_DATA_KEY)
                .and_then(|d| serde_json::from_value::<AiSummary>(d.clone()).ok())
                .filter(|a| !a.text.trim().is_empty()),
            include_ai_summary: b("ai_summary").unwrap_or(true),
            raw: {
                let mut raw = v.clone();
                if let Some(o) = raw.as_object_mut() {
                    o.remove(AI_SUMMARY_DATA_KEY);
                }
                raw
            },
        }
    }
}

/// Kind of exported data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportKind {
    Findings,
    Users,
    Emails,
    Paths,
    Software,
    Hosts,
    Docs,
    Log,
    All,
}

impl ExportKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_lowercase().as_str() {
            "findings" => Self::Findings,
            "users" | "people" => Self::Users,
            "emails" | "email" => Self::Emails,
            "paths" => Self::Paths,
            "software" | "sw" => Self::Software,
            "hosts" => Self::Hosts,
            "docs" | "documents" => Self::Docs,
            "log" | "requests" => Self::Log,
            "all" | "project" => Self::All,
            _ => return None,
        })
    }
    /// File name part (like `slug` in the UI).
    pub fn slug(self) -> &'static str {
        match self {
            Self::Findings => "findings",
            Self::Users => "users",
            Self::Emails => "emails",
            Self::Paths => "paths",
            Self::Software => "software",
            Self::Hosts => "hosts",
            Self::Docs => "documents",
            Self::Log => "requests-log",
            Self::All => "project",
        }
    }
}

/// Export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Text with one value per line (clipboard).
    List,
    /// `.txt` wordlist: unique, sorted.
    Dict,
    Csv,
    Json,
    /// Link list for importing a table into Maltego.
    MaltegoCsv,
    Graphml,
    /// Markdown for Obsidian.
    Md,
    /// Clean host/URL target list for `httpx -l`.
    Httpx,
    /// Normalized endpoint/target list for `nuclei -l`.
    Nuclei,
    /// OASIS STIX 2.1 JSON bundle for MISP / OpenCTI / SIEM.
    Stix,
}

impl ExportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_lowercase().as_str() {
            "list" | "text" => Self::List,
            "dict" | "txt" => Self::Dict,
            "csv" => Self::Csv,
            "json" => Self::Json,
            "maltego" | "maltego_csv" | "maltego-csv" => Self::MaltegoCsv,
            "graphml" => Self::Graphml,
            "md" | "markdown" | "obsidian" => Self::Md,
            "httpx" => Self::Httpx,
            "nuclei" => Self::Nuclei,
            "stix" | "stix2" | "stix21" | "stix-json" => Self::Stix,
            _ => return None,
        })
    }
    /// Parses the format from `export_build`: `fmt = "maltego"` + `opts.mal = "graphml"` gives
    /// GraphML.
    pub fn from_ui(fmt: &str, opts: &Value) -> Option<Self> {
        let f = Self::parse(fmt)?;
        Some(
            if f == Self::MaltegoCsv && opts.get("mal").and_then(Value::as_str) == Some("graphml") {
                Self::Graphml
            } else {
                f
            },
        )
    }
}

/// Which wordlist to build (`dict` in the export sheet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DictKind {
    Users,
    Logins,
    Context,
    Emails,
    Paths,
    Software,
    /// Arbitrary `items` list from the UI.
    Custom,
}

impl DictKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_lowercase().as_str() {
            "users" => Self::Users,
            "logins" => Self::Logins,
            "context" | "pentest" | "wordlist" => Self::Context,
            "emails" => Self::Emails,
            "paths" => Self::Paths,
            "software" => Self::Software,
            "custom" => Self::Custom,
            _ => return None,
        })
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Logins => "logins",
            Self::Context => "context",
            Self::Emails => "emails",
            Self::Paths => "paths",
            Self::Software => "software",
            Self::Custom => "custom",
        }
    }
}

/// Markdown: one note per entity (an Obsidian ZIP vault) or a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MdLayout {
    #[default]
    One,
    Many,
}

/// Options for `export`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportOptions {
    /// Columns/fields (keys, see `export::columns(kind)`); `None` uses the defaults.
    pub columns: Option<Vec<String>>,
    /// Export secrets in clear text. Defaults to `false`, which hides them.
    pub include_secrets: bool,
    /// Names → initials, e-mail addresses and logins → masks.
    pub redact_pii: bool,
    /// Wordlist type (defaults to one derived from the export kind).
    pub dict: Option<DictKind>,
    /// Explicit Active Directory NetBIOS domain override for `DictKind::Logins`.
    pub ad_domain: Option<String>,
    /// Login wordlist variants: `ivan.petrov → ipetrov, petrov.i, petrov, ivanpetrov`.
    pub login_variants: bool,
    /// Wordlist: lowercase.
    pub lowercase: bool,
    /// CSV delimiter.
    pub delimiter: char,
    /// UTF-8 BOM in CSV (for Excel).
    pub bom: bool,
    /// Pretty-printed JSON.
    pub pretty: bool,
    pub md_layout: MdLayout,
    /// Subset: finding/document ids (`ids`) or a ready list of values (`items`).
    pub ids: Option<Vec<u64>>,
    pub items: Option<Vec<String>>,
    /// Date in the file name, `YYYY-MM-DD` (empty means today, UTC).
    pub date: String,
    pub lang: Lang,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            columns: None,
            include_secrets: false,
            redact_pii: false,
            dict: None,
            ad_domain: None,
            login_variants: true,
            lowercase: true,
            delimiter: ',',
            bom: true,
            pretty: true,
            md_layout: MdLayout::One,
            ids: None,
            items: None,
            date: String::new(),
            lang: Lang::Ru,
        }
    }
}

impl ExportOptions {
    /// Parses the UI `export_build` `opts`:
    /// `{ dict, delim, bom, pretty, mal, md, secrets, pii, items, ids, columns }`.
    pub fn from_ui(v: &Value) -> ExportOptions {
        let mut o = ExportOptions::default();
        let b = |k: &str| v.get(k).and_then(Value::as_bool);
        if let Some(x) = b("secrets").or_else(|| b("include_secrets")) {
            o.include_secrets = x;
        }
        if let Some(x) = b("pii").or_else(|| b("redact_pii")) {
            o.redact_pii = x;
        }
        if let Some(x) = b("bom") {
            o.bom = x;
        }
        if let Some(x) = b("pretty") {
            o.pretty = x;
        }
        if let Some(x) = b("variants") {
            o.login_variants = x;
        }
        if let Some(x) = b("lower") {
            o.lowercase = x;
        }
        o.dict = v
            .get("dict")
            .and_then(Value::as_str)
            .and_then(DictKind::parse);
        o.ad_domain = v
            .get("ad_domain")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        o.delimiter = match v.get("delim").and_then(Value::as_str) {
            Some(";") => ';',
            Some("tab") | Some("\t") => '\t',
            _ => ',',
        };
        o.md_layout = match v.get("md").and_then(Value::as_str) {
            Some("many") => MdLayout::Many,
            _ => MdLayout::One,
        };
        o.items = v.get("items").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        });
        o.ids = v
            .get("ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect());
        o.columns = v.get("columns").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        });
        if let Some(l) = v.get("lang").and_then(Value::as_str).and_then(Lang::parse) {
            o.lang = l;
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maltego_graphml_from_ui() {
        let g = serde_json::json!({ "mal": "graphml" });
        assert_eq!(
            ExportFormat::from_ui("maltego", &g),
            Some(ExportFormat::Graphml)
        );
        let c = serde_json::json!({ "mal": "csv" });
        assert_eq!(
            ExportFormat::from_ui("maltego", &c),
            Some(ExportFormat::MaltegoCsv)
        );
        assert_eq!(ExportFormat::from_ui("dict", &g), Some(ExportFormat::Dict));
        assert_eq!(ExportFormat::from_ui("exe", &g), None);
    }

    #[test]
    fn from_ui_opts() {
        let o = ReportOptions::from_ui(&json!({
            "tpl": "Полный отчёт пентеста", "tpl_id": "brief", "fmt": "pdf", "lang": "UA",
            "min_sev": "warn", "confirmed": true, "picked_only": true, "picked": [3, 5],
            "sections": { "log": true, "people": false }, "secrets": "partial", "company": "ТОВ «Кібер Аудит»", "logo": true
        }));
        assert_eq!(o.tpl, Template::Summary);
        assert_eq!(o.fmt, ReportFormat::Html);
        assert_eq!(o.lang, Lang::Uk);
        assert_eq!(o.min_sev, Some(Severity::Medium));
        assert!(o.confirmed && o.picked_only && o.sections.log && !o.sections.people);
        assert_eq!(o.picked, vec![3, 5]);
        assert_eq!(o.secrets, SecretMode::Partial);
        assert_eq!(o.logo, Logo::Initials);
        // Defaults are safe.
        let d = ReportOptions::from_ui(&json!({}));
        assert_eq!(d.secrets, SecretMode::Hide);
        assert!(!ExportOptions::default().include_secrets);
    }

    #[test]
    fn logo_only_raster() {
        let png = foca_core::b64::encode(b"\x89PNG\r\n\x1a\n0000");
        assert!(matches!(
            Logo::from_data(&format!("data:image/png;base64,{png}")),
            Logo::Image { .. }
        ));
        let svg = foca_core::b64::encode(b"<svg onload=alert(1)>");
        assert_eq!(
            Logo::from_data(&format!("data:image/svg+xml;base64,{svg}")),
            Logo::None
        );
        assert_eq!(Logo::from_data("javascript:alert(1)"), Logo::None);
        assert_eq!(
            Logo::from_data(&format!("data:image/png;base64,{png}\"><script>")),
            Logo::None
        );
    }
}

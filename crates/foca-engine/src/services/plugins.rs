//! Sandboxed plugin engine.
//!
//! Supports two pure-Rust execution runtimes ([ADR-0011](../docs/adr/0011-port-logic-not-binaries.md)):
//! - Declarative (`"declarative"`): JSON/TOML rules with URL templates, regex extractors
//!   (subdomains/URLs/headers), and scoped HTTP checks via `NetClient`.
//! - WebAssembly (`"wasm"`): pure-Rust stack-machine interpreter enforcing `<= 16 MiB` linear
//!   memory (`256` pages), an instruction `fuel` budget (`<= 50_000`), zero WASI/FS/raw sockets,
//!   and only sandboxed host imports (`host_http_get_scoped`, `host_emit_finding`).
//!
//! Security invariant ([ADR-0009](../docs/adr/0009-passive-never-touches-target.md)):
//! When a scan or test runs in `Access::Passive`, any plugin HTTP request targeting an in-scope
//! host or declaring `net:scoped` / `touches_target` is blocked before leaving the engine.
//! Out-of-scope hosts are always blocked for `net:scoped` plugins.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use foca_core::Scope;
use foca_net::{Access, NetClient, NetRequest};
use regex::Regex;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CmdError;

/// Hard upper bound on WASM linear memory: 256 × 64 KiB = 16 MiB.
pub const MAX_MEMORY_PAGES: u32 = 256;
/// Default fuel limit (instructions) for sandboxed WASM execution.
pub const DEFAULT_FUEL_LIMIT: u64 = 50_000;
/// Maximum raw WASM binary size accepted by the sandbox (2 MiB).
pub const MAX_WASM_BYTES: usize = 2 * 1024 * 1024;
/// Maximum WASM operand stack depth.
const MAX_STACK: usize = 4096;
/// Maximum call nesting depth.
const MAX_CALL_DEPTH: usize = 64;
/// Maximum parameters per WASM function type.
const MAX_FUNC_PARAMS: usize = 256;
/// Maximum results per WASM function type.
const MAX_FUNC_RESULTS: usize = 256;
/// Maximum local variables per WASM function body.
const MAX_LOCALS: usize = 4096;

/// Declarative rule specification for no-code plugins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DeclarativeSpec {
    /// URL template supporting `{domain}` and `{target}` placeholders.
    pub url_template: Option<String>,
    /// Extraction mode: `"hosts" | "urls" | "header_finding" | "meta_pattern"`.
    pub extract_kind: String,
    /// Optional regex pattern applied to response body or metadata text.
    pub pattern: Option<String>,
    /// Optional HTTP header checked when `extract_kind == "header_finding"`.
    pub header_name: Option<String>,
    /// Finding severity when emitting findings (`"info" | "low" | "medium" | "high"`).
    pub severity: String,
    /// Finding title template.
    pub title: Option<String>,
    /// Optional KeyVault service slot sent via header (never logged).
    pub key_slot: Option<String>,
    /// Explicit marker when requests directly touch the target host (`Access::TouchesTarget`).
    pub touches_target: bool,
}

impl Default for DeclarativeSpec {
    fn default() -> Self {
        Self {
            url_template: None,
            extract_kind: "hosts".into(),
            pattern: None,
            header_name: None,
            severity: "low".into(),
            title: None,
            key_slot: None,
            touches_target: false,
        }
    }
}

/// Plugin manifest schema (`plugin.json` / `plugin.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    /// `"source" | "analyzer" | "enricher"`.
    pub kind: String,
    /// `"declarative" | "wasm"`.
    #[serde(default = "default_runtime")]
    pub runtime: String,
    /// Permissions: `"net:passive" | "net:scoped" | "meta:read"`.
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub ed25519_sig: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub declarative: Option<DeclarativeSpec>,
    #[serde(default)]
    pub wasm_b64: Option<String>,
}

fn default_runtime() -> String {
    "declarative".into()
}

fn default_true() -> bool {
    true
}

/// Public summary of an installed/builtin plugin returned by `plugins_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub kind: String,
    pub runtime: String,
    pub permissions: Vec<String>,
    pub sha256: String,
    pub enabled: bool,
    pub builtin: bool,
    pub source: String,
    pub url_template: Option<String>,
}

/// Finding emitted by a declarative or WASM plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFinding {
    pub title: String,
    pub severity: String,
    pub detail: String,
}

/// Result of running a plugin execution or sandbox dry-run test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRunResult {
    pub ok: bool,
    pub id: String,
    pub runtime: String,
    pub fuel_used: u64,
    pub hosts: Vec<String>,
    pub urls: Vec<String>,
    pub findings: Vec<PluginFinding>,
    pub blocked_reason: Option<String>,
    pub http_url: Option<String>,
}

/// Validates plugin id (`[a-z0-9][a-z0-9_-]*`, 2..=64 chars, excluding reserved `"state"`).
pub fn validate_plugin_id(id: &str) -> Result<(), CmdError> {
    let valid = (2..=64).contains(&id.len())
        && id != "state"
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid {
        return Err(CmdError::new(
            "bad_args",
            format!("Недопустимый id плагина «{id}»"),
        ));
    }
    Ok(())
}

fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    let b = s.trim().as_bytes();
    if b.len() != 128 {
        return None;
    }
    let hex_nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(b[i * 2])?;
        let lo = hex_nibble(b[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

/// Computes canonical SHA-256 hex digest for a plugin manifest / payload.
pub fn compute_manifest_sha256(m: &PluginManifest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(m.id.as_bytes());
    hasher.update(b":");
    hasher.update(m.version.as_bytes());
    hasher.update(b":");
    hasher.update(m.runtime.as_bytes());
    if let Some(w) = &m.wasm_b64 {
        hasher.update(b":wasm:");
        hasher.update(w.as_bytes());
    }
    if let Some(d) = &m.declarative {
        if let Some(u) = &d.url_template {
            hasher.update(b":url:");
            hasher.update(u.as_bytes());
        }
        if let Some(p) = &d.pattern {
            hasher.update(b":pat:");
            hasher.update(p.as_bytes());
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Validates manifest fields, runtime, permissions, and declarative regex / WASM magic.
pub fn validate_manifest(m: &mut PluginManifest) -> Result<(), CmdError> {
    validate_plugin_id(&m.id)?;
    if m.name.trim().is_empty() {
        return Err(CmdError::new("bad_args", "Не задано имя плагина (name)"));
    }
    if !matches!(m.kind.as_str(), "source" | "analyzer" | "enricher") {
        return Err(CmdError::new(
            "bad_args",
            format!("Неизвестный kind плагина: {}", m.kind),
        ));
    }
    if !matches!(m.runtime.as_str(), "declarative" | "wasm") {
        return Err(CmdError::new(
            "bad_args",
            format!("Неподдерживаемый runtime плагина: {}", m.runtime),
        ));
    }
    for perm in &m.permissions {
        if !matches!(perm.as_str(), "net:passive" | "net:scoped" | "meta:read") {
            return Err(CmdError::new(
                "bad_args",
                format!("Запрещённое разрешение плагина: {perm}"),
            ));
        }
    }
    if m.runtime == "declarative" {
        if let Some(d) = &m.declarative {
            if let Some(pat) = &d.pattern {
                if !pat.is_empty() {
                    Regex::new(pat).map_err(|e| {
                        CmdError::new("bad_args", format!("Некорректный regex плагина: {e}"))
                    })?;
                }
            }
        }
    } else {
        let b64 = m
            .wasm_b64
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                CmdError::new("bad_args", "Для WASM-плагина требуется wasm_b64 модуль")
            })?;
        let bytes = foca_core::b64::decode(b64)
            .ok_or_else(|| CmdError::new("bad_args", "Некорректный base64 в wasm_b64"))?;
        let _ = WasmModule::parse(&bytes)?;
    }
    let expected = compute_manifest_sha256(m);
    if !m.sha256.trim().is_empty() && !m.sha256.trim().eq_ignore_ascii_case(&expected) {
        return Err(CmdError::new(
            "bad_args",
            "Контрольная сумма sha256 манифеста плагина не совпадает",
        ));
    }
    m.sha256 = expected;
    if let Some(sig_hex) = m
        .ed25519_sig
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let sig = decode_hex_64(sig_hex).ok_or_else(|| {
            CmdError::new(
                "bad_args",
                "Некорректный формат Ed25519 подписи плагина (ожидается 64 байта hex)",
            )
        })?;
        let pk_bytes = crate::services::sigbundle::official_pubkey_bytes();
        let pk = UnparsedPublicKey::new(&ED25519, &pk_bytes);
        pk.verify(m.sha256.as_bytes(), &sig).map_err(|_| {
            CmdError::new(
                "bad_args",
                "Недействительная Ed25519 подпись манифеста плагина",
            )
        })?;
    }
    Ok(())
}

/// Parses a plugin manifest from JSON or TOML string.
pub fn parse_manifest(raw: &str) -> Result<PluginManifest, CmdError> {
    let trimmed = raw.trim();
    let mut m: PluginManifest = if trimmed.starts_with('{') {
        serde_json::from_str(trimmed)
            .map_err(|e| CmdError::new("bad_args", format!("JSON манифеста плагина: {e}")))?
    } else {
        toml::from_str(trimmed)
            .map_err(|e| CmdError::new("bad_args", format!("TOML манифеста плагина: {e}")))?
    };
    m.builtin = false;
    validate_manifest(&mut m)?;
    Ok(m)
}

/// Returns the 4 builtin reference plugins shipped with FOCA-rs.
pub fn builtin_manifests() -> Vec<PluginManifest> {
    let mut list = vec![
        PluginManifest {
            id: "certspotter-ext".into(),
            name: "CertSpotter Extended CT".into(),
            version: "2.0.0".into(),
            author: "FOCA-rs Team".into(),
            description: "Пассивный коллектор сертификатов Certificate Transparency (v1 API)"
                .into(),
            kind: "source".into(),
            runtime: "declarative".into(),
            permissions: vec!["net:passive".into()],
            sha256: String::new(),
            ed25519_sig: None,
            enabled: true,
            builtin: true,
            declarative: Some(DeclarativeSpec {
                url_template: Some(
                    "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                        .into(),
                ),
                extract_kind: "hosts".into(),
                pattern: Some(r#""([a-z0-9.-]+\.[a-z]{2,})""#.into()),
                header_name: None,
                severity: "info".into(),
                title: Some("Поддомен из CertSpotter CT".into()),
                key_slot: None,
                touches_target: false,
            }),
            wasm_b64: None,
        },
        PluginManifest {
            id: "robots-sitemap-parser".into(),
            name: "Robots & Sitemap Enricher".into(),
            version: "2.0.0".into(),
            author: "FOCA-rs Team".into(),
            description: "Извлечение служебных путей и URL из robots.txt и sitemap.xml".into(),
            kind: "enricher".into(),
            runtime: "declarative".into(),
            permissions: vec!["net:scoped".into()],
            sha256: String::new(),
            ed25519_sig: None,
            enabled: true,
            builtin: true,
            declarative: Some(DeclarativeSpec {
                url_template: Some("https://{domain}/robots.txt".into()),
                extract_kind: "urls".into(),
                pattern: Some(r"(?im)^(?:Disallow|Allow|Sitemap):\s*(\S+)".into()),
                header_name: None,
                severity: "info".into(),
                title: Some("Скрытый путь из robots.txt / sitemap".into()),
                key_slot: None,
                touches_target: true,
            }),
            wasm_b64: None,
        },
        PluginManifest {
            id: "ua-gov-edrpou-enricher".into(),
            name: "ЄДРПОУ & КЕП Enricher".into(),
            version: "2.0.0".into(),
            author: "FOCA-rs Team".into(),
            description: "Локальное обогащение карточек организаций по кодам ЄДРПОУ и КЕП (без сети)"
                .into(),
            kind: "enricher".into(),
            runtime: "declarative".into(),
            permissions: vec!["meta:read".into()],
            sha256: String::new(),
            ed25519_sig: None,
            enabled: true,
            builtin: true,
            declarative: Some(DeclarativeSpec {
                url_template: None,
                extract_kind: "meta_pattern".into(),
                pattern: Some(r"\b(\d{8})\b".into()),
                header_name: None,
                severity: "info".into(),
                title: Some("Код ЄДРПОУ в метаданных / сертификате КЕП".into()),
                key_slot: None,
                touches_target: false,
            }),
            wasm_b64: None,
        },
        PluginManifest {
            id: "custom-header-audit".into(),
            name: "Corporate HTTP Header Audit".into(),
            version: "2.0.0".into(),
            author: "FOCA-rs Team".into(),
            description: "Проверка корпоративных заголовков (Strict-Transport-Security / X-Frame-Options)"
                .into(),
            kind: "analyzer".into(),
            runtime: "declarative".into(),
            permissions: vec!["net:scoped".into(), "meta:read".into()],
            sha256: String::new(),
            ed25519_sig: None,
            enabled: false,
            builtin: true,
            declarative: Some(DeclarativeSpec {
                url_template: Some("https://{domain}/".into()),
                extract_kind: "header_finding".into(),
                pattern: None,
                header_name: Some("Strict-Transport-Security".into()),
                severity: "medium".into(),
                title: Some("Отсутствует заголовок безопасности HTTP".into()),
                key_slot: None,
                touches_target: true,
            }),
            wasm_b64: None,
        },
    ];
    for m in &mut list {
        m.sha256 = compute_manifest_sha256(m);
    }
    list
}

/// Persistent enabled/disabled state stored under `<data_dir>/plugins/state.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PluginStateFile {
    enabled: BTreeMap<String, bool>,
}

/// On-disk plugin store under `<data_dir>/plugins/`.
pub struct PluginStore {
    dir: PathBuf,
}

impl PluginStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join("plugins"),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    fn load_state(&self) -> PluginStateFile {
        fs::read_to_string(self.state_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, st: &PluginStateFile) -> Result<(), CmdError> {
        fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join("state.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(st)?)?;
        fs::rename(tmp, self.state_path())?;
        Ok(())
    }

    /// Loads all builtin + custom plugins merged with persistent enabled flags.
    pub fn load_all(&self) -> Vec<PluginManifest> {
        let st = self.load_state();
        let mut out = builtin_manifests();
        let builtin_ids: HashSet<String> = out.iter().map(|m| m.id.clone()).collect();
        if let Ok(rd) = fs::read_dir(&self.dir) {
            let mut custom_paths: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().and_then(|e| e.to_str()) == Some("json")
                        && p.file_name().and_then(|n| n.to_str()) != Some("state.json")
                })
                .collect();
            custom_paths.sort();
            for p in custom_paths {
                if let Ok(raw) = fs::read_to_string(&p) {
                    if let Ok(mut m) = serde_json::from_str::<PluginManifest>(&raw) {
                        m.builtin = false;
                        if !builtin_ids.contains(&m.id) && validate_manifest(&mut m).is_ok() {
                            out.push(m);
                        }
                    }
                }
            }
        }
        for m in &mut out {
            if let Some(&flag) = st.enabled.get(&m.id) {
                m.enabled = flag;
            }
        }
        out
    }

    /// Converts all plugins to `PluginInfo` DTOs.
    pub fn list(&self) -> Vec<PluginInfo> {
        self.load_all().into_iter().map(|m| to_info(&m)).collect()
    }

    /// Installs a custom JSON/TOML manifest onto disk.
    pub fn install(&self, raw: &str) -> Result<PluginInfo, CmdError> {
        let m = parse_manifest(raw)?;
        if builtin_manifests().iter().any(|b| b.id == m.id) {
            return Err(CmdError::new(
                "bad_args",
                format!(
                    "Идентификатор «{}» зарезервирован встроенным плагином",
                    m.id
                ),
            ));
        }
        fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(format!("{}.json", m.id));
        let tmp = self.dir.join(format!("{}.json.tmp", m.id));
        fs::write(&tmp, serde_json::to_vec_pretty(&m)?)?;
        fs::rename(tmp, path)?;
        let mut st = self.load_state();
        st.enabled.insert(m.id.clone(), m.enabled);
        self.save_state(&st)?;
        Ok(to_info(&m))
    }

    /// Enables or disables any builtin or custom plugin.
    pub fn toggle(&self, id: &str, enabled: bool) -> Result<PluginInfo, CmdError> {
        validate_plugin_id(id)?;
        let all = self.load_all();
        if !all.iter().any(|m| m.id == id) {
            return Err(CmdError::not_found(format!("Плагин «{id}» не найден")));
        }
        let mut st = self.load_state();
        st.enabled.insert(id.to_string(), enabled);
        self.save_state(&st)?;
        let updated = self
            .load_all()
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| CmdError::not_found(id))?;
        Ok(to_info(&updated))
    }

    /// Removes a custom plugin. Builtin plugins cannot be deleted.
    pub fn remove(&self, id: &str) -> Result<(), CmdError> {
        validate_plugin_id(id)?;
        if builtin_manifests().iter().any(|b| b.id == id) {
            return Err(CmdError::new(
                "bad_args",
                "Нельзя удалить встроенный плагин: его можно только отключить",
            ));
        }
        let path = self.dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(CmdError::not_found(format!("Плагин «{id}» не найден")));
        }
        fs::remove_file(path)?;
        let mut st = self.load_state();
        st.enabled.remove(id);
        self.save_state(&st)?;
        Ok(())
    }

    /// Finds a single plugin manifest by ID.
    pub fn get(&self, id: &str) -> Result<PluginManifest, CmdError> {
        self.load_all()
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| CmdError::not_found(format!("Плагин «{id}» не найден")))
    }
}

fn to_info(m: &PluginManifest) -> PluginInfo {
    PluginInfo {
        id: m.id.clone(),
        name: m.name.clone(),
        version: m.version.clone(),
        author: m.author.clone(),
        description: m.description.clone(),
        kind: m.kind.clone(),
        runtime: m.runtime.clone(),
        permissions: m.permissions.clone(),
        sha256: m.sha256.clone(),
        enabled: m.enabled,
        builtin: m.builtin,
        source: if m.builtin {
            "builtin".into()
        } else {
            "custom".into()
        },
        url_template: m.declarative.as_ref().and_then(|d| d.url_template.clone()),
    }
}

fn url_in_scope(scope: &Scope, raw: &str) -> bool {
    url::Url::parse(raw)
        .ok()
        .and_then(|u| u.host_str().map(|h| scope.allows_host(h)))
        .unwrap_or(false)
}

/// Checks whether a URL is allowed by `passive` mode, plugin `permissions`, and `Scope` ([ADR-0009]).
pub fn authorize_plugin_url(
    url_str: &str,
    permissions: &[String],
    touches_target: bool,
    passive: bool,
    scope: &Scope,
) -> Result<(), String> {
    let parsed = url::Url::parse(url_str).map_err(|e| format!("bad_url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("blocked_scheme: {}", parsed.scheme()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "bad_url: missing host".to_string())?
        .to_ascii_lowercase();

    let has_scoped = permissions.iter().any(|p| p == "net:scoped");
    let has_passive = permissions.iter().any(|p| p == "net:passive");
    if !has_scoped && !has_passive {
        return Err(
            "blocked_permission: плагин не имеет разрешения net:passive или net:scoped".into(),
        );
    }

    let host_in_scope = scope.allows_host(&host);
    // ADR-0009: passive mode never contacts a target host or executes net:scoped/touches_target.
    if passive && (touches_target || has_scoped || host_in_scope) {
        return Err(format!(
            "blocked_passive: ADR-0009 запрещает плагину обращаться к цели ({host}) в пассивном режиме"
        ));
    }
    if has_scoped && !host_in_scope {
        return Err(format!(
            "blocked_scope: хост {host} не входит в область сканирования (scope)"
        ));
    }
    if !host_in_scope && crate::util::is_private_or_metadata_host(&host) {
        return Err(format!(
            "blocked_ssrf: запрещён запрос к локальному или служебному адресу ({host})"
        ));
    }
    Ok(())
}

/// Executes a declarative or WASM plugin against `target_domain` and optional `sample_body`.
pub async fn run_plugin(
    manifest: &PluginManifest,
    target_domain: &str,
    passive: bool,
    scope: &Scope,
    net: Option<&NetClient>,
    sample_body: Option<&str>,
    fuel_limit: u64,
) -> Result<PluginRunResult, CmdError> {
    if manifest.runtime == "wasm" {
        return run_wasm_plugin(manifest, target_domain, passive, scope, net, fuel_limit).await;
    }

    let spec = manifest
        .declarative
        .as_ref()
        .ok_or_else(|| CmdError::new("bad_plugin", "Отсутствует declarative-спецификация"))?;
    let mut hosts = Vec::new();
    let mut urls = Vec::new();
    let mut findings = Vec::new();
    let mut http_url = None;
    let mut body = sample_body.map(str::to_string);

    if let Some(tpl) = &spec.url_template {
        let resolved = tpl
            .replace("{domain}", target_domain)
            .replace("{target}", target_domain);
        http_url = Some(resolved.clone());
        if let Err(reason) = authorize_plugin_url(
            &resolved,
            &manifest.permissions,
            spec.touches_target,
            passive,
            scope,
        ) {
            return Ok(PluginRunResult {
                ok: false,
                id: manifest.id.clone(),
                runtime: manifest.runtime.clone(),
                fuel_used: 0,
                hosts,
                urls,
                findings,
                blocked_reason: Some(reason),
                http_url,
            });
        }

        if body.is_none() {
            if let Some(client) = net {
                let has_scoped = manifest.permissions.iter().any(|p| p == "net:scoped");
                let access = if passive
                    || (!spec.touches_target && !has_scoped && !url_in_scope(scope, &resolved))
                {
                    Access::Passive
                } else {
                    Access::TouchesTarget
                };
                let req = NetRequest::get(&resolved, "plugin", access)
                    .map_err(|e| CmdError::new("net", e.to_string()))?;
                let resp = client
                    .send(req)
                    .await
                    .map_err(|e| CmdError::new("net", e.to_string()))?;
                if spec.extract_kind == "header_finding" {
                    if let Some(hdr) = &spec.header_name {
                        if resp.header(&hdr.to_ascii_lowercase()).is_none() {
                            findings.push(PluginFinding {
                                title: spec
                                    .title
                                    .clone()
                                    .unwrap_or_else(|| format!("Отсутствует заголовок {hdr}")),
                                severity: spec.severity.clone(),
                                detail: format!("{resolved}: нет {hdr}"),
                            });
                        }
                    }
                }
                body = Some(
                    resp.text_limited(512 * 1024)
                        .await
                        .map_err(|e| CmdError::new("net", e.to_string()))?,
                );
            }
        }
    }

    if let Some(text) = &body {
        if let Some(pat) = &spec.pattern {
            if !pat.is_empty() {
                if let Ok(re) = Regex::new(pat) {
                    let mut seen = HashSet::new();
                    for cap in re.captures_iter(text) {
                        let m = cap.get(1).or_else(|| cap.get(0)).map(|m| m.as_str());
                        if let Some(val) = m {
                            if seen.insert(val.to_string()) {
                                match spec.extract_kind.as_str() {
                                    "hosts" => hosts.push(val.to_ascii_lowercase()),
                                    "urls" => urls.push(val.to_string()),
                                    _ => findings.push(PluginFinding {
                                        title: spec
                                            .title
                                            .clone()
                                            .unwrap_or_else(|| manifest.name.clone()),
                                        severity: spec.severity.clone(),
                                        detail: val.to_string(),
                                    }),
                                }
                            }
                        }
                        if seen.len() >= 100 {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(PluginRunResult {
        ok: true,
        id: manifest.id.clone(),
        runtime: manifest.runtime.clone(),
        fuel_used: 0,
        hosts,
        urls,
        findings,
        blocked_reason: None,
        http_url,
    })
}

async fn run_wasm_plugin(
    manifest: &PluginManifest,
    target_domain: &str,
    passive: bool,
    scope: &Scope,
    net: Option<&NetClient>,
    fuel_limit: u64,
) -> Result<PluginRunResult, CmdError> {
    let b64 = manifest
        .wasm_b64
        .as_deref()
        .ok_or_else(|| CmdError::new("bad_plugin", "Отсутствует wasm_b64"))?;
    let bytes = foca_core::b64::decode(b64)
        .ok_or_else(|| CmdError::new("bad_plugin", "Некорректный base64 в wasm_b64"))?;
    let module = WasmModule::parse(&bytes)?;

    let mut sandbox = WasmSandbox::new(&module, fuel_limit.min(DEFAULT_FUEL_LIMIT))?;
    // Seed domain bytes at offset 0x100 if linear memory has space, so guest code can inspect target.
    sandbox.write_bytes(0x100, target_domain.as_bytes());
    let exec = sandbox.execute_entry(&module)?;

    let mut findings = exec.findings;
    let mut blocked_reason = None;
    let mut http_url = None;
    let mut hosts = Vec::new();

    for url_req in exec.http_urls {
        http_url = Some(url_req.clone());
        if let Err(reason) =
            authorize_plugin_url(&url_req, &manifest.permissions, false, passive, scope)
        {
            blocked_reason = Some(reason);
            return Ok(PluginRunResult {
                ok: false,
                id: manifest.id.clone(),
                runtime: "wasm".into(),
                fuel_used: exec.fuel_used,
                hosts,
                urls: Vec::new(),
                findings,
                blocked_reason,
                http_url,
            });
        }
        if let Some(client) = net {
            let has_scoped = manifest.permissions.iter().any(|p| p == "net:scoped");
            let access = if passive || (!has_scoped && !url_in_scope(scope, &url_req)) {
                Access::Passive
            } else {
                Access::TouchesTarget
            };
            let req = NetRequest::get(&url_req, "plugin", access)
                .map_err(|e| CmdError::new("net", e.to_string()))?;
            let resp = client
                .send(req)
                .await
                .map_err(|e| CmdError::new("net", e.to_string()))?;
            let status = resp.status();
            let text = resp
                .text_limited(256 * 1024)
                .await
                .map_err(|e| CmdError::new("net", e.to_string()))?;
            if status == 200 && !text.is_empty() {
                if let Some(host) = url::Url::parse(&url_req)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                {
                    hosts.push(host);
                }
            } else {
                findings.push(PluginFinding {
                    title: format!("WASM HTTP ответ {status}"),
                    severity: "info".into(),
                    detail: url_req,
                });
            }
        }
    }

    Ok(PluginRunResult {
        ok: true,
        id: manifest.id.clone(),
        runtime: "wasm".into(),
        fuel_used: exec.fuel_used,
        hosts,
        urls: Vec::new(),
        findings,
        blocked_reason,
        http_url,
    })
}

// ================= Pure-Rust Sandboxed WASM Interpreter =================

#[derive(Debug, Clone)]
enum HostImport {
    HttpGetScoped,
    EmitFinding,
}

#[derive(Debug, Clone)]
struct WasmFuncBody {
    type_idx: u32,
    local_count: usize,
    code: Vec<u8>,
    end_map: BTreeMap<usize, usize>,
}

#[derive(Debug, Clone)]
struct DataSeg {
    offset: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct WasmModule {
    types: Vec<(usize, usize)>, // (param_count, result_count)
    imports: Vec<(HostImport, u32)>,
    funcs: Vec<WasmFuncBody>,
    initial_pages: u32,
    entry_func_idx: usize,
    data: Vec<DataSeg>,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn rem(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Result<u8, CmdError> {
        let v = *self
            .b
            .get(self.pos)
            .ok_or_else(|| CmdError::new("bad_plugin", "Неожиданный конец WASM"))?;
        self.pos += 1;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], CmdError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CmdError::new("bad_plugin", "Переполнение смещения WASM"))?;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or_else(|| CmdError::new("bad_plugin", "Выход за пределы секции WASM"))?;
        self.pos = end;
        Ok(s)
    }
    fn uleb(&mut self) -> Result<u32, CmdError> {
        let mut res = 0u32;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            res |= u32::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or_else(|| CmdError::new("bad_plugin", "Переполнение LEB128"))?;
            if byte & 0x80 == 0 {
                return Ok(res);
            }
            shift += 7;
            if shift >= 35 {
                return Err(CmdError::new("bad_plugin", "Некорректное LEB128 в WASM"));
            }
        }
    }
    fn sleb(&mut self) -> Result<i32, CmdError> {
        let mut res = 0i32;
        let mut shift = 0u32;
        let mut byte;
        loop {
            byte = self.u8()?;
            res |= i32::from(byte & 0x7f).wrapping_shl(shift);
            shift += 7;
            if byte & 0x80 == 0 || shift >= 35 {
                break;
            }
        }
        if shift < 32 && (byte & 0x40) != 0 {
            res |= !0i32 << shift;
        }
        Ok(res)
    }
    fn name(&mut self) -> Result<String, CmdError> {
        let len = self.uleb()? as usize;
        let s = self.bytes(len)?;
        std::str::from_utf8(s)
            .map(str::to_string)
            .map_err(|_| CmdError::new("bad_plugin", "Некорректный UTF-8 в имени WASM"))
    }
}

impl WasmModule {
    fn parse(bytes: &[u8]) -> Result<Self, CmdError> {
        if bytes.len() > MAX_WASM_BYTES {
            return Err(CmdError::new("bad_plugin", "WASM-модуль больше 2 МиБ"));
        }
        if bytes.get(..8) != Some(b"\0asm\x01\0\0\0") {
            return Err(CmdError::new(
                "bad_plugin",
                "Неверный заголовок WASM (ожидается \\0asm v1)",
            ));
        }

        let mut r = Reader::new(&bytes[8..]);
        let mut types = Vec::new();
        let mut imports = Vec::new();
        let mut func_type_idxs = Vec::new();
        let mut initial_pages = 1u32;
        let mut exported_funcs: BTreeMap<String, usize> = BTreeMap::new();
        let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut data = Vec::new();

        while r.rem() > 0 {
            let sec_id = r.u8()?;
            let sec_len = r.uleb()? as usize;
            let sec_bytes = r.bytes(sec_len)?;
            let mut sr = Reader::new(sec_bytes);

            match sec_id {
                1 => {
                    let count = sr.uleb()? as usize;
                    for _ in 0..count {
                        let tag = sr.u8()?;
                        if tag != 0x60 {
                            return Err(CmdError::new("bad_plugin", "Ожидается functype 0x60"));
                        }
                        let np = sr.uleb()? as usize;
                        if np > MAX_FUNC_PARAMS {
                            return Err(CmdError::new(
                                "bad_plugin",
                                format!("Число параметров WASM ({np}) превышает лимит {MAX_FUNC_PARAMS}"),
                            ));
                        }
                        sr.bytes(np)?;
                        let nr = sr.uleb()? as usize;
                        if nr > MAX_FUNC_RESULTS {
                            return Err(CmdError::new(
                                "bad_plugin",
                                format!("Число результатов WASM ({nr}) превышает лимит {MAX_FUNC_RESULTS}"),
                            ));
                        }
                        sr.bytes(nr)?;
                        types.push((np, nr));
                    }
                }
                2 => {
                    let count = sr.uleb()? as usize;
                    for _ in 0..count {
                        let module = sr.name()?;
                        let field = sr.name()?;
                        let kind = sr.u8()?;
                        if kind != 0x00 || module != "foca" {
                            return Err(CmdError::new(
                                "bad_plugin",
                                format!(
                                    "Запрещённый WASM импорт {module}::{field} (разрешены только foca::host_*)"
                                ),
                            ));
                        }
                        let type_idx = sr.uleb()?;
                        let host = match field.as_str() {
                            "host_http_get_scoped" => HostImport::HttpGetScoped,
                            "host_emit_finding" => HostImport::EmitFinding,
                            _ => {
                                return Err(CmdError::new(
                                    "bad_plugin",
                                    format!("Неизвестный host-импорт foca::{field}"),
                                ));
                            }
                        };
                        imports.push((host, type_idx));
                    }
                }
                3 => {
                    let count = sr.uleb()? as usize;
                    for _ in 0..count {
                        func_type_idxs.push(sr.uleb()?);
                    }
                }
                5 => {
                    let count = sr.uleb()? as usize;
                    if count > 1 {
                        return Err(CmdError::new(
                            "bad_plugin",
                            "Поддерживается только 1 память WASM",
                        ));
                    }
                    if count == 1 {
                        let flags = sr.u8()?;
                        let init = sr.uleb()?;
                        let max = if flags & 1 != 0 {
                            Some(sr.uleb()?)
                        } else {
                            None
                        };
                        if init > MAX_MEMORY_PAGES {
                            return Err(CmdError::new(
                                "bad_plugin",
                                format!("WASM память {init} страниц превышает лимит {MAX_MEMORY_PAGES} (16 МиБ)"),
                            ));
                        }
                        if let Some(m) = max {
                            if m > MAX_MEMORY_PAGES {
                                return Err(CmdError::new(
                                    "bad_plugin",
                                    format!("Макс. WASM память {m} превышает 16 МиБ"),
                                ));
                            }
                        }
                        initial_pages = init;
                    }
                }
                7 => {
                    let count = sr.uleb()? as usize;
                    for _ in 0..count {
                        let name = sr.name()?;
                        let kind = sr.u8()?;
                        let idx = sr.uleb()? as usize;
                        if kind == 0x00 {
                            exported_funcs.insert(name, idx);
                        }
                    }
                }
                10 => {
                    let count = sr.uleb()? as usize;
                    for _ in 0..count {
                        let bsize = sr.uleb()? as usize;
                        let bbytes = sr.bytes(bsize)?;
                        let mut br = Reader::new(bbytes);
                        let local_groups = br.uleb()? as usize;
                        let mut local_count = 0usize;
                        for _ in 0..local_groups {
                            let n = br.uleb()? as usize;
                            let _ty = br.u8()?;
                            if n > MAX_LOCALS || local_count.saturating_add(n) > MAX_LOCALS {
                                return Err(CmdError::new(
                                    "bad_plugin",
                                    format!(
                                        "Число локальных переменных WASM превышает лимит {MAX_LOCALS}"
                                    ),
                                ));
                            }
                            local_count += n;
                        }
                        let code = br.b[br.pos..].to_vec();
                        bodies.push((local_count, code));
                    }
                }
                11 => {
                    let count = sr.uleb()? as usize;
                    for _ in 0..count {
                        let mode = sr.uleb()?;
                        let offset = if mode == 0 {
                            let mut off = 0usize;
                            loop {
                                let op = sr.u8()?;
                                if op == 0x41 {
                                    off = sr.sleb()?.max(0) as usize;
                                } else if op == 0x0B {
                                    break;
                                } else {
                                    return Err(CmdError::new(
                                        "bad_plugin",
                                        "Неподдерживаемое смещение data-сегмента WASM",
                                    ));
                                }
                            }
                            off
                        } else {
                            return Err(CmdError::new(
                                "bad_plugin",
                                "Поддерживаются только active memory data segments",
                            ));
                        };
                        let len = sr.uleb()? as usize;
                        let seg = sr.bytes(len)?.to_vec();
                        data.push(DataSeg { offset, bytes: seg });
                    }
                }
                _ => {} // Custom / Table / Global / Element ignored
            }
        }

        if func_type_idxs.len() != bodies.len() {
            return Err(CmdError::new(
                "bad_plugin",
                "Несовпадение Function и Code секций WASM",
            ));
        }

        let mut funcs = Vec::with_capacity(bodies.len());
        for (type_idx, (local_count, code)) in func_type_idxs.into_iter().zip(bodies) {
            let end_map = precompute_block_ends(&code)?;
            funcs.push(WasmFuncBody {
                type_idx,
                local_count,
                code,
                end_map,
            });
        }

        let entry_func_idx = exported_funcs
            .get("run")
            .or_else(|| exported_funcs.get("_start"))
            .or_else(|| exported_funcs.values().next())
            .copied()
            .ok_or_else(|| {
                CmdError::new("bad_plugin", "WASM-модуль не экспортирует функцию run")
            })?;

        Ok(Self {
            types,
            imports,
            funcs,
            initial_pages,
            entry_func_idx,
            data,
        })
    }
}

struct WasmExecOutput {
    fuel_used: u64,
    http_urls: Vec<String>,
    findings: Vec<PluginFinding>,
}

struct WasmSandbox {
    mem: Vec<u8>,
    fuel_limit: u64,
    fuel_left: u64,
    http_urls: Vec<String>,
    findings: Vec<PluginFinding>,
}

#[derive(Clone, Copy)]
struct Label {
    start_pc: usize,
    end_pc: usize,
    is_loop: bool,
    stack_height: usize,
}

impl WasmSandbox {
    fn new(m: &WasmModule, fuel_limit: u64) -> Result<Self, CmdError> {
        let mem_bytes = (m.initial_pages as usize)
            .checked_mul(65536)
            .ok_or_else(|| CmdError::new("bad_plugin", "Переполнение размера WASM памяти"))?;
        if mem_bytes > (MAX_MEMORY_PAGES as usize) * 65536 {
            return Err(CmdError::new("bad_plugin", "WASM память превышает 16 МиБ"));
        }
        let mut mem = vec![0u8; mem_bytes];
        for seg in &m.data {
            let end = seg.offset.saturating_add(seg.bytes.len());
            if end > mem.len() {
                return Err(CmdError::new(
                    "bad_plugin",
                    "Data-сегмент выходит за пределы WASM памяти",
                ));
            }
            mem[seg.offset..end].copy_from_slice(&seg.bytes);
        }
        Ok(Self {
            mem,
            fuel_limit,
            fuel_left: fuel_limit,
            http_urls: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn write_bytes(&mut self, offset: usize, bytes: &[u8]) {
        if offset.saturating_add(bytes.len()) <= self.mem.len() {
            self.mem[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn read_utf8(&self, ptr: i32, len: i32) -> Result<String, CmdError> {
        if ptr < 0 || len < 0 {
            return Err(CmdError::new("bad_plugin", "Отрицательный указатель WASM"));
        }
        let p = ptr as usize;
        let l = (len as usize).min(4096);
        let end = p
            .checked_add(l)
            .ok_or_else(|| CmdError::new("bad_plugin", "Переполнение указателя WASM"))?;
        let slice = self
            .mem
            .get(p..end)
            .ok_or_else(|| CmdError::new("bad_plugin", "Указатель вне памяти WASM"))?;
        Ok(String::from_utf8_lossy(slice).to_string())
    }

    fn execute_entry(&mut self, m: &WasmModule) -> Result<WasmExecOutput, CmdError> {
        let mut stack = Vec::new();
        self.call_func(m, m.entry_func_idx, &mut stack, 0)?;
        Ok(WasmExecOutput {
            fuel_used: self.fuel_limit.saturating_sub(self.fuel_left),
            http_urls: std::mem::take(&mut self.http_urls),
            findings: std::mem::take(&mut self.findings),
        })
    }

    fn call_func(
        &mut self,
        m: &WasmModule,
        func_idx: usize,
        stack: &mut Vec<i32>,
        depth: usize,
    ) -> Result<(), CmdError> {
        if depth > MAX_CALL_DEPTH {
            return Err(CmdError::new(
                "bad_plugin",
                "Превышена глубина стека вызовов WASM",
            ));
        }
        if func_idx < m.imports.len() {
            return self.call_import(&m.imports[func_idx].0, stack);
        }
        let body = m
            .funcs
            .get(func_idx - m.imports.len())
            .ok_or_else(|| CmdError::new("bad_plugin", "Неверный индекс функции WASM"))?;
        let (param_count, _) = m
            .types
            .get(body.type_idx as usize)
            .copied()
            .unwrap_or((0, 0));
        let mut locals = vec![0i32; param_count + body.local_count];
        for i in (0..param_count).rev() {
            locals[i] = stack.pop().unwrap_or(0);
        }

        let code = &body.code;
        let end_map = &body.end_map;
        let mut labels: Vec<Label> = vec![Label {
            start_pc: 0,
            end_pc: code.len().saturating_sub(1),
            is_loop: false,
            stack_height: stack.len(),
        }];
        let mut pc = 0usize;

        while pc < code.len() {
            if self.fuel_left == 0 {
                return Err(CmdError::new(
                    "fuel_exhausted",
                    "WASM-плагин остановлен по лимиту инструкций (fuel)",
                ));
            }
            self.fuel_left -= 1;

            let op = code[pc];
            pc += 1;
            match op {
                0x00 => {
                    return Err(CmdError::new("bad_plugin", "WASM unreachable"));
                }
                0x01 => {} // nop
                0x02 | 0x03 => {
                    // block / loop (blocktype skipped, single-byte s33)
                    let block_start = pc - 1;
                    let _bt = read_sleb_at(code, &mut pc)?;
                    let end_pc = *end_map.get(&block_start).unwrap_or(&code.len());
                    labels.push(Label {
                        start_pc: pc,
                        end_pc,
                        is_loop: op == 0x03,
                        stack_height: stack.len(),
                    });
                }
                0x0B => {
                    // end
                    if labels.len() <= 1 {
                        break;
                    }
                    labels.pop();
                }
                0x0C => {
                    // br labelidx
                    let lbl_depth = read_uleb_at(code, &mut pc)? as usize;
                    pc = branch_to(&mut labels, stack, lbl_depth)?;
                }
                0x0D => {
                    // br_if labelidx
                    let lbl_depth = read_uleb_at(code, &mut pc)? as usize;
                    let cond = stack.pop().unwrap_or(0);
                    if cond != 0 {
                        pc = branch_to(&mut labels, stack, lbl_depth)?;
                    }
                }
                0x0F => {
                    // return
                    break;
                }
                0x10 => {
                    // call funcidx
                    let target = read_uleb_at(code, &mut pc)? as usize;
                    self.call_func(m, target, stack, depth + 1)?;
                }
                0x1A => {
                    stack.pop();
                }
                0x20 => {
                    let idx = read_uleb_at(code, &mut pc)? as usize;
                    let v = *locals.get(idx).unwrap_or(&0);
                    push_stack(stack, v)?;
                }
                0x21 => {
                    let idx = read_uleb_at(code, &mut pc)? as usize;
                    let v = stack.pop().unwrap_or(0);
                    if let Some(slot) = locals.get_mut(idx) {
                        *slot = v;
                    }
                }
                0x22 => {
                    let idx = read_uleb_at(code, &mut pc)? as usize;
                    let v = *stack.last().unwrap_or(&0);
                    if let Some(slot) = locals.get_mut(idx) {
                        *slot = v;
                    }
                }
                0x28 => {
                    // i32.load align offset
                    let _align = read_uleb_at(code, &mut pc)?;
                    let offset = read_uleb_at(code, &mut pc)? as usize;
                    let base = stack.pop().unwrap_or(0) as u32 as usize;
                    let addr = base.saturating_add(offset);
                    let raw = self
                        .mem
                        .get(addr..addr.saturating_add(4))
                        .ok_or_else(|| CmdError::new("bad_plugin", "WASM OOB load"))?;
                    push_stack(stack, i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))?;
                }
                0x36 => {
                    // i32.store align offset
                    let _align = read_uleb_at(code, &mut pc)?;
                    let offset = read_uleb_at(code, &mut pc)? as usize;
                    let val = stack.pop().unwrap_or(0);
                    let base = stack.pop().unwrap_or(0) as u32 as usize;
                    let addr = base.saturating_add(offset);
                    let slot = self
                        .mem
                        .get_mut(addr..addr.saturating_add(4))
                        .ok_or_else(|| CmdError::new("bad_plugin", "WASM OOB store"))?;
                    slot.copy_from_slice(&val.to_le_bytes());
                }
                0x41 => {
                    let v = read_sleb_at(code, &mut pc)?;
                    push_stack(stack, v)?;
                }
                0x45 => {
                    let a = stack.pop().unwrap_or(0);
                    push_stack(stack, i32::from(a == 0))?;
                }
                0x46 => {
                    let b = stack.pop().unwrap_or(0);
                    let a = stack.pop().unwrap_or(0);
                    push_stack(stack, i32::from(a == b))?;
                }
                0x47 => {
                    let b = stack.pop().unwrap_or(0);
                    let a = stack.pop().unwrap_or(0);
                    push_stack(stack, i32::from(a != b))?;
                }
                0x49 => {
                    let b = stack.pop().unwrap_or(0) as u32;
                    let a = stack.pop().unwrap_or(0) as u32;
                    push_stack(stack, i32::from(a < b))?;
                }
                0x4B => {
                    let b = stack.pop().unwrap_or(0) as u32;
                    let a = stack.pop().unwrap_or(0) as u32;
                    push_stack(stack, i32::from(a > b))?;
                }
                0x4D => {
                    let b = stack.pop().unwrap_or(0) as u32;
                    let a = stack.pop().unwrap_or(0) as u32;
                    push_stack(stack, i32::from(a <= b))?;
                }
                0x4F => {
                    let b = stack.pop().unwrap_or(0) as u32;
                    let a = stack.pop().unwrap_or(0) as u32;
                    push_stack(stack, i32::from(a >= b))?;
                }
                0x6A => {
                    let b = stack.pop().unwrap_or(0);
                    let a = stack.pop().unwrap_or(0);
                    push_stack(stack, a.wrapping_add(b))?;
                }
                0x6B => {
                    let b = stack.pop().unwrap_or(0);
                    let a = stack.pop().unwrap_or(0);
                    push_stack(stack, a.wrapping_sub(b))?;
                }
                0x6C => {
                    let b = stack.pop().unwrap_or(0);
                    let a = stack.pop().unwrap_or(0);
                    push_stack(stack, a.wrapping_mul(b))?;
                }
                other => {
                    return Err(CmdError::new(
                        "bad_plugin",
                        format!("Неподдерживаемый опкод WASM: 0x{other:02x}"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn call_import(&mut self, imp: &HostImport, stack: &mut Vec<i32>) -> Result<(), CmdError> {
        match imp {
            HostImport::HttpGetScoped => {
                let len = stack.pop().unwrap_or(0);
                let ptr = stack.pop().unwrap_or(0);
                let url_req = self.read_utf8(ptr, len)?;
                if self.http_urls.len() < 16 {
                    self.http_urls.push(url_req);
                }
                push_stack(stack, 0)?;
            }
            HostImport::EmitFinding => {
                let sev_code = stack.pop().unwrap_or(1);
                let len = stack.pop().unwrap_or(0);
                let ptr = stack.pop().unwrap_or(0);
                let title = self.read_utf8(ptr, len)?;
                let severity = match sev_code {
                    3 => "high",
                    2 => "medium",
                    0 => "info",
                    _ => "low",
                }
                .to_string();
                if self.findings.len() < 32 {
                    self.findings.push(PluginFinding {
                        title: title.clone(),
                        severity,
                        detail: title,
                    });
                }
            }
        }
        Ok(())
    }
}

fn push_stack(stack: &mut Vec<i32>, v: i32) -> Result<(), CmdError> {
    if stack.len() >= MAX_STACK {
        return Err(CmdError::new(
            "bad_plugin",
            "Переполнение стека операндов WASM",
        ));
    }
    stack.push(v);
    Ok(())
}

fn read_uleb_at(code: &[u8], pc: &mut usize) -> Result<u32, CmdError> {
    let mut r = Reader::new(&code[*pc..]);
    let v = r.uleb()?;
    *pc += r.pos;
    Ok(v)
}

fn read_sleb_at(code: &[u8], pc: &mut usize) -> Result<i32, CmdError> {
    let mut r = Reader::new(&code[*pc..]);
    let v = r.sleb()?;
    *pc += r.pos;
    Ok(v)
}

fn precompute_block_ends(code: &[u8]) -> Result<BTreeMap<usize, usize>, CmdError> {
    let mut map = BTreeMap::new();
    let mut stack = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let pos = pc;
        let op = code[pc];
        pc += 1;
        match op {
            0x02 | 0x03 => {
                stack.push(pos);
                let _ = read_sleb_at(code, &mut pc)?;
            }
            0x0B => {
                if let Some(start) = stack.pop() {
                    map.insert(start, pc);
                }
            }
            0x0C | 0x0D | 0x10 | 0x20 | 0x21 | 0x22 => {
                let _ = read_uleb_at(code, &mut pc)?;
            }
            0x28 | 0x36 => {
                let _ = read_uleb_at(code, &mut pc)?;
                let _ = read_uleb_at(code, &mut pc)?;
            }
            0x41 => {
                let _ = read_sleb_at(code, &mut pc)?;
            }
            _ => {}
        }
    }
    Ok(map)
}

fn branch_to(
    labels: &mut Vec<Label>,
    stack: &mut Vec<i32>,
    depth: usize,
) -> Result<usize, CmdError> {
    if depth >= labels.len() {
        return Err(CmdError::new(
            "bad_plugin",
            "Неверная глубина ветвления WASM",
        ));
    }
    let idx = labels.len() - 1 - depth;
    let target = labels[idx];
    stack.truncate(target.stack_height);
    if target.is_loop {
        labels.truncate(idx + 1);
        Ok(target.start_pc)
    } else {
        labels.truncate(idx);
        Ok(target.end_pc)
    }
}

/// Runs a plugin on an optional shared NetClient (used by Cmds).
pub fn default_target_scope(domain: &str) -> Scope {
    let (s, _) = Scope::from_lines(domain.trim(), "");
    s
}

/// Convenience helper wrapping an Arc<str>-safe empty run without network.
pub fn empty_plugin_result(id: &str, runtime: &str) -> PluginRunResult {
    PluginRunResult {
        ok: true,
        id: id.into(),
        runtime: runtime.into(),
        fuel_used: 0,
        hosts: Vec::new(),
        urls: Vec::new(),
        findings: Vec::new(),
        blocked_reason: None,
        http_url: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn encode_wasm(sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        for (id, body) in sections {
            out.push(*id);
            push_uleb(&mut out, body.len() as u32);
            out.extend_from_slice(body);
        }
        out
    }

    fn push_uleb(buf: &mut Vec<u8>, mut v: u32) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn infinite_loop_wasm() -> Vec<u8> {
        // Type section: () -> ()
        let sec_type = vec![1, 0x60, 0, 0];
        // Function section: func 0 -> type 0
        let sec_func = vec![1, 0];
        // Memory section: 1 page
        let sec_mem = vec![1, 0, 1];
        // Export section: "run" -> func 0
        let mut sec_exp = vec![1, 3];
        sec_exp.extend_from_slice(b"run");
        sec_exp.extend_from_slice(&[0x00, 0]);
        // Code section: loop (void) br 0 end end
        let body = vec![0x00, 0x03, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        let mut sec_code = vec![1];
        push_uleb(&mut sec_code, body.len() as u32);
        sec_code.extend_from_slice(&body);
        encode_wasm(&[
            (1, sec_type),
            (3, sec_func),
            (5, sec_mem),
            (7, sec_exp),
            (10, sec_code),
        ])
    }

    fn http_get_wasm(url: &str) -> Vec<u8> {
        // Types: type 0 = (i32, i32) -> i32; type 1 = () -> ()
        let sec_type = vec![2, 0x60, 2, 0x7F, 0x7F, 1, 0x7F, 0x60, 0, 0];
        // Import: foca::host_http_get_scoped -> func 0 (type 0)
        let mut sec_imp = vec![1, 4];
        sec_imp.extend_from_slice(b"foca");
        push_uleb(&mut sec_imp, "host_http_get_scoped".len() as u32);
        sec_imp.extend_from_slice(b"host_http_get_scoped");
        sec_imp.extend_from_slice(&[0x00, 0x00]);
        // Func: func 1 -> type 1
        let sec_func = vec![1, 1];
        // Mem: 1 page
        let sec_mem = vec![1, 0, 1];
        // Export: "run" -> func 1
        let mut sec_exp = vec![1, 3];
        sec_exp.extend_from_slice(b"run");
        sec_exp.extend_from_slice(&[0x00, 0x01]);
        // Code for func 1: i32.const 16; i32.const len; call 0; drop; end
        let mut body = vec![0x00, 0x41, 16, 0x41];
        let mut len_buf = Vec::new();
        push_uleb(&mut len_buf, url.len() as u32);
        // sleb32 for small len <= 63 matches uleb32
        body.extend_from_slice(&len_buf);
        body.extend_from_slice(&[0x10, 0x00, 0x1A, 0x0B]);
        let mut sec_code = vec![1];
        push_uleb(&mut sec_code, body.len() as u32);
        sec_code.extend_from_slice(&body);
        // Data: offset 16 -> url bytes
        let mut sec_data = vec![1, 0, 0x41, 16, 0x0B];
        push_uleb(&mut sec_data, url.len() as u32);
        sec_data.extend_from_slice(url.as_bytes());
        encode_wasm(&[
            (1, sec_type),
            (2, sec_imp),
            (3, sec_func),
            (5, sec_mem),
            (7, sec_exp),
            (10, sec_code),
            (11, sec_data),
        ])
    }

    #[test]
    fn install_toggle_remove_custom_plugin_and_protect_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let store = PluginStore::new(dir.path());
        assert_eq!(store.list().len(), 4);

        // Builtin cannot be removed
        assert!(store.remove("certspotter-ext").is_err());

        // Toggle builtin
        let t = store.toggle("certspotter-ext", false).unwrap();
        assert!(!t.enabled);
        assert!(!store.get("certspotter-ext").unwrap().enabled);

        // Install custom TOML plugin
        let raw_toml = r#"
id = "corp-leak-probe"
name = "Corp Leak Probe"
version = "0.1.0"
author = "Security Team"
description = "Checks local leak patterns"
kind = "analyzer"
runtime = "declarative"
permissions = ["meta:read"]

[declarative]
extract_kind = "meta_pattern"
pattern = 'APIKEY-[0-9]{4}'
severity = "high"
title = "Тестовый маркер"
"#;
        let info = store.install(raw_toml).unwrap();
        assert_eq!(info.id, "corp-leak-probe");
        assert_eq!(info.source, "custom");
        assert!(!info.sha256.is_empty());
        assert_eq!(store.list().len(), 5);

        store.remove("corp-leak-probe").unwrap();
        assert_eq!(store.list().len(), 4);
    }

    #[tokio::test]
    async fn wasm_infinite_loop_aborts_on_fuel_limit_quickly() {
        let wasm = infinite_loop_wasm();
        let m = PluginManifest {
            id: "loop-test".into(),
            name: "Loop".into(),
            version: "1.0.0".into(),
            author: "Test".into(),
            description: "Infinite loop test".into(),
            kind: "analyzer".into(),
            runtime: "wasm".into(),
            permissions: vec!["meta:read".into()],
            sha256: String::new(),
            ed25519_sig: None,
            enabled: true,
            builtin: false,
            declarative: None,
            wasm_b64: Some(foca_core::b64::encode(&wasm)),
        };

        let t0 = Instant::now();
        let scope = default_target_scope("example.test");
        let err = run_plugin(&m, "example.test", true, &scope, None, None, 10_000)
            .await
            .unwrap_err();
        let elapsed = t0.elapsed();
        assert_eq!(err.code, "fuel_exhausted", "got {err:?}");
        assert!(
            elapsed.as_millis() < 200,
            "infinite loop took too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn plugin_http_blocked_in_passive_mode_and_out_of_scope() {
        let wasm = http_get_wasm("https://target.example.test/admin");
        let m = PluginManifest {
            id: "wasm-http-scoped".into(),
            name: "Scoped HTTP".into(),
            version: "1.0.0".into(),
            author: "Test".into(),
            description: "Tests ADR-0009 and scope checks".into(),
            kind: "source".into(),
            runtime: "wasm".into(),
            permissions: vec!["net:scoped".into()],
            sha256: String::new(),
            ed25519_sig: None,
            enabled: true,
            builtin: false,
            declarative: None,
            wasm_b64: Some(foca_core::b64::encode(&wasm)),
        };

        let scope = default_target_scope("target.example.test");
        // Passive mode must block net:scoped target access (ADR-0009).
        let passive_res = run_plugin(&m, "target.example.test", true, &scope, None, None, 10_000)
            .await
            .unwrap();
        assert!(!passive_res.ok);
        assert!(passive_res
            .blocked_reason
            .as_deref()
            .is_some_and(|r| r.contains("blocked_passive")));

        // Active mode against out-of-scope host must also be blocked.
        let other_scope = default_target_scope("other.example.test");
        let oos_res = run_plugin(
            &m,
            "other.example.test",
            false,
            &other_scope,
            None,
            None,
            10_000,
        )
        .await
        .unwrap();
        assert!(!oos_res.ok);
        assert!(oos_res
            .blocked_reason
            .as_deref()
            .is_some_and(|r| r.contains("blocked_scope")));
    }

    #[tokio::test]
    async fn declarative_plugin_extracts_hosts_and_findings() {
        let m = builtin_manifests()
            .into_iter()
            .find(|b| b.id == "ua-gov-edrpou-enricher")
            .unwrap();
        let scope = default_target_scope("example.ua");
        let res = run_plugin(
            &m,
            "example.ua",
            true,
            &scope,
            None,
            Some("EDRPOU 12345678 and 87654321 verified"),
            10_000,
        )
        .await
        .unwrap();
        assert!(res.ok);
        assert_eq!(res.findings.len(), 2);
        assert_eq!(res.findings[0].detail, "12345678");
    }

    #[test]
    fn manifest_rejects_state_id_forged_sha256_and_bad_ed25519_sig() {
        let dir = tempfile::tempdir().unwrap();
        let store = PluginStore::new(dir.path());

        let state_toml = r#"
id = "state"
name = "Evil State"
version = "1.0.0"
author = "Test"
description = "Tries to overwrite state.json"
kind = "analyzer"
runtime = "declarative"
permissions = ["meta:read"]
"#;
        assert_eq!(store.install(state_toml).unwrap_err().code, "bad_args");

        let forged_sha_toml = r#"
id = "forged-sha"
name = "Forged SHA"
version = "1.0.0"
author = "Test"
description = "Mismatched sha256"
kind = "analyzer"
runtime = "declarative"
permissions = ["meta:read"]
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
        assert_eq!(store.install(forged_sha_toml).unwrap_err().code, "bad_args");

        let bad_sig_toml = format!(
            "id = \"bad-sig\"\nname = \"Bad Sig\"\nversion = \"1.0.0\"\nauthor = \"Test\"\n\
             description = \"Invalid sig\"\nkind = \"analyzer\"\nruntime = \"declarative\"\n\
             permissions = [\"meta:read\"]\ned25519_sig = \"{}\"\n",
            "ab".repeat(64)
        );
        assert_eq!(store.install(&bad_sig_toml).unwrap_err().code, "bad_args");
    }

    #[test]
    fn scoped_plus_passive_cannot_bypass_scope_and_ssrf_is_blocked() {
        let scope = default_target_scope("target.example.test");
        let both = vec!["net:scoped".into(), "net:passive".into()];
        let err = authorize_plugin_url("https://evil.example.net/api", &both, false, false, &scope)
            .unwrap_err();
        assert!(err.starts_with("blocked_scope"), "got {err}");

        let passive_only = vec!["net:passive".into()];
        for bad in [
            "http://127.0.0.1:8080/secret",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://metadata.google.internal/computeMetadata/v1/",
        ] {
            let e = authorize_plugin_url(bad, &passive_only, false, true, &scope).unwrap_err();
            assert!(
                e.starts_with("blocked_ssrf"),
                "expected ssrf block for {bad}, got {e}"
            );
        }
    }

    #[test]
    fn wasm_excessive_local_count_is_rejected_without_oom() {
        let sec_type = vec![1, 0x60, 0, 0];
        let sec_func = vec![1, 0];
        let mut sec_exp = vec![1, 3];
        sec_exp.extend_from_slice(b"run");
        sec_exp.extend_from_slice(&[0x00, 0]);
        // Code: 1 group of 1_000_000 i32 locals (varint uleb32 for 1_000_000) + `end`
        let mut body = vec![1];
        push_uleb(&mut body, 1_000_000);
        body.push(0x7F);
        body.push(0x0B);
        let mut sec_code = vec![1];
        push_uleb(&mut sec_code, body.len() as u32);
        sec_code.extend_from_slice(&body);
        let wasm = encode_wasm(&[(1, sec_type), (3, sec_func), (7, sec_exp), (10, sec_code)]);
        let err = WasmModule::parse(&wasm).unwrap_err();
        assert_eq!(err.code, "bad_plugin");
    }
}

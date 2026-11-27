//! Ed25519-signed signature bundles.
//!
//! Signature bundles update CISA KEV entries, CPE rules, secret detection rules and (schema
//! `foca-sig-bundle/v2`) whole data tables without rebuilding the APK. A v2 bundle carries
//! `tables`: each one is a table file exactly as shipped in the repo (base64), with its SHA-256
//! and upstream pin; ids are listed in [`TABLES`]. v1 bundles are still read and verified (their
//! canonical payload has no `tables` key, so old signatures stay valid). Every bundle is verified with `Ed25519`
//! (`ring::signature::ED25519`) and `SHA-256` before touching disk. Validated bundles are
//! written atomically to `<data_dir>/signatures/current.json`, keeping the previous bundle in
//! `<data_dir>/signatures/previous.json` for instant rollback.
//!
//! The official update feed is a rolling GitHub release (`DEFAULT_FEED_URL`): a missing asset
//! (HTTP 404) means no newer database has been published, never a successful update. Every check
//! is recorded in `<data_dir>/signatures/last_check.json` and shown by `signatures_status`.
//! The counts in the status come from the rule sets the analysis really loads, not from the
//! numbers a bundle claims.

use std::fs;
use std::path::{Path, PathBuf};

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CmdError;

/// Schema identifier of the signature bundles this build writes.
pub const BUNDLE_SCHEMA: &str = "foca-sig-bundle/v2";
/// Older schema that is still accepted (no `tables`).
pub const BUNDLE_SCHEMA_V1: &str = "foca-sig-bundle/v1";

/// Upstream pins and stats of the ingested sources (written by the ingest scripts).
const SOURCES_LOCK: &str = include_str!("../../../foca-analysis/signatures/sources.lock.json");

/// Data tables a v2 bundle may replace: `(id, source key in sources.lock.json, built-in file)`.
pub const TABLES: &[(&str, &str, &[u8])] = &[
    (
        "webappanalyzer",
        "webappanalyzer",
        foca_recon::tech::UPSTREAM_GZ,
    ),
    ("endoflife", "endoflife", foca_recon::tech::EOL_GZ),
    (
        "saas_dns",
        "webappanalyzer",
        foca_net::saas::UPSTREAM_DNS_JSON.as_bytes(),
    ),
    (
        "gitleaks",
        "gitleaks",
        foca_analysis::secrets::GITLEAKS_TOML.as_bytes(),
    ),
    ("kev_enrich", "epss", foca_analysis::kev::ENRICH_GZ),
    ("retire", "retire", foca_recon::retire::RETIRE_GZ),
    ("recog", "recog", foca_net::recog::RECOG_GZ),
    (
        "favicons_md5",
        "recog",
        foca_recon::favicon::FAVICONS_MD5_TSV.as_bytes(),
    ),
    ("psl", "psl", foca_net::dns::psl::PSL_GZ),
    (
        "takeover",
        "can-i-take-over-xyz",
        foca_net::takeover::TAKEOVER_JSON.as_bytes(),
    ),
];

/// A data table shipped in a v2 bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigTable {
    /// Upstream pin (commit, tag or snapshot date).
    pub version: String,
    /// SHA-256 of the decoded table file.
    pub sha256: String,
    /// The table file as shipped in the repository (gzip or text), base64.
    pub data: String,
}

/// Loaded numbers of one data table for the status screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableInfo {
    pub id: String,
    /// Records the app really loaded (technologies, cycles, rules, ...).
    pub records: u32,
    /// Upstream pin of the data in use.
    pub version: String,
    /// SPDX id or terms of the upstream data.
    pub license: String,
    /// `builtin` or `bundle`.
    pub source: String,
}

/// 32-byte Ed25519 public key used to verify signature bundles.
/// The private signing key is kept offline by the release maintainers.
const OFFICIAL_ED25519_PUBKEY: [u8; 32] = [
    0xad, 0x79, 0x0c, 0xe1, 0xbc, 0x10, 0x39, 0x31, 0x32, 0xf1, 0x3c, 0x76, 0x7f, 0x8e, 0x71, 0x14,
    0x9f, 0xf8, 0x86, 0x05, 0xfe, 0x35, 0x34, 0x2a, 0x76, 0x52, 0x6c, 0x20, 0xd3, 0xda, 0xa2, 0x46,
];

/// Official update feed: the `signatures.bundle` asset of the rolling `signatures` release.
/// A rolling tag is used instead of `releases/latest` because GitHub skips pre-releases there.
pub const DEFAULT_FEED_URL: &str =
    "https://github.com/SinonApp/FOCA-rs/releases/download/signatures/signatures.bundle";

/// A KEV snapshot older than this many days is flagged as stale in the status.
pub const KEV_STALE_DAYS: i64 = 30;

/// Returns the 32-byte Ed25519 public key used to verify signature bundles.
pub fn official_pubkey_bytes() -> [u8; 32] {
    OFFICIAL_ED25519_PUBKEY
}

/// Returns the hex-encoded release Ed25519 public key.
pub fn official_pubkey_hex() -> String {
    hex_encode(&official_pubkey_bytes())
}

/// Counts of signature records in the active database.
///
/// In `signatures_status` these are the loaded numbers: `cpe` = software and OS signatures,
/// `cve` = CISA KEV entries used for matching, `secrets` = secret rules, `standards` = rule to
/// standard references. In a bundle they are informational only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigCounts {
    pub cpe: u32,
    pub cve: u32,
    pub secrets: u32,
    pub standards: u32,
}

/// CISA KEV snapshot a bundle was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigKevCatalog {
    /// `catalogVersion` (`2026.11.20`).
    pub version: String,
    /// `dateReleased` (`YYYY-MM-DD`).
    pub released: String,
    /// Records in the full CISA catalog.
    pub total: u32,
}

/// Additional KEV entry shipped in a signature bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigKevItem {
    pub cve: String,
    pub product_key: String,
    pub vendor: String,
    pub product: String,
    pub date_added: String,
    #[serde(default)]
    pub ransomware: bool,
    pub name: String,
    #[serde(default)]
    pub fixed_in: Option<String>,
}

/// Additional CPE mapping rule shipped in a signature bundle. Stored with the bundle but not used
/// for matching yet (a prefix has no detection pattern), so the status does not count it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigCpeItem {
    pub cpe_prefix: String,
    pub label: String,
    #[serde(default)]
    pub latest_ver: Option<String>,
}

/// Additional secret detection pattern shipped in a signature bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigSecretItem {
    pub id: String,
    pub title: String,
    pub pattern: String,
}

/// A signed signature bundle (`foca-sig-bundle/v1` or `/v2`; the name is kept for API stability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigBundleV1 {
    pub schema: String,
    pub version: String,
    pub released_at: String,
    pub counts: SigCounts,
    /// KEV snapshot of `kev_additions`; absent in older bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kev_catalog: Option<SigKevCatalog>,
    #[serde(default)]
    pub kev_additions: Vec<SigKevItem>,
    #[serde(default)]
    pub cpe_additions: Vec<SigCpeItem>,
    #[serde(default)]
    pub secret_additions: Vec<SigSecretItem>,
    /// v2: data tables by id ([`TABLES`]).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tables: std::collections::BTreeMap<String, SigTable>,
    pub sha256: String,
    pub signature_ed25519: String,
}

/// Current status of the signature database returned by `signatures_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigStatus {
    pub schema: String,
    pub version: String,
    pub updated_at: String,
    /// `"builtin"` or `"bundle"`.
    pub source: String,
    pub sha256: String,
    pub pubkey_ed25519: String,
    pub signature_valid: bool,
    pub can_rollback: bool,
    pub counts: SigCounts,
    pub added_kev: u32,
    pub added_cpe: u32,
    pub added_secrets: u32,
    /// CISA KEV snapshot in use and its age.
    pub kev: KevInfo,
    /// Software and OS detection signatures.
    pub software: SoftwareInfo,
    /// Finding rule to standards mapping.
    pub std_map: StdMapInfo,
    /// Ingested upstream data tables with the numbers really loaded.
    pub tables: Vec<TableInfo>,
    /// Feed checked by `signatures_update` without a `url`.
    pub feed_url: String,
    /// Result of the last `signatures_update`, `None` before the first check.
    pub last_check: Option<LastCheck>,
}

/// CISA KEV catalog numbers (`catalog`, `released` and `total` describe the CISA snapshot, `used`
/// the entries the app matches against: the kept ones plus bundle additions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevInfo {
    pub catalog: String,
    pub released: String,
    pub total: u32,
    pub used: u32,
    /// Product groups that link detected software to KEV entries.
    pub products: u32,
    /// Days since `released`, `None` when the date is unknown.
    pub age_days: Option<i64>,
    /// `age_days` > [`KEV_STALE_DAYS`].
    pub stale: bool,
}

/// Software and OS signature counts (`signatures/software.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub software: u32,
    pub os: u32,
}

/// A standard family present in the mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdFramework {
    pub id: String,
    pub label: String,
    /// Kept for systems certified under the old КСЗІ scheme.
    pub legacy: bool,
}

/// Standards mapping numbers (`signatures/standards.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdMapInfo {
    /// Finding rules with at least one standard.
    pub rules: u32,
    /// Rule to standard references in total.
    pub refs: u32,
    pub frameworks: Vec<StdFramework>,
}

/// Outcome of one update check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCheck {
    /// Local time of the check (`YYYY-MM-DDTHH:MM:SS`).
    pub at: String,
    /// `installed`, `up_to_date`, `no_update` (nothing published at the feed) or `failed`.
    pub outcome: String,
    pub feed_url: String,
    /// Version of the bundle found at the feed.
    #[serde(default)]
    pub version: Option<String>,
    /// Error text for `failed` (a core message, see `error_msg` in the command output).
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

/// Canonical payload bytes covered by `sha256` and `signature_ed25519`.
pub fn canonical_payload(b: &SigBundleV1) -> Vec<u8> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        schema: &'a str,
        version: &'a str,
        released_at: &'a str,
        counts: &'a SigCounts,
        #[serde(skip_serializing_if = "Option::is_none")]
        kev_catalog: Option<&'a SigKevCatalog>,
        kev_additions: &'a [SigKevItem],
        cpe_additions: &'a [SigCpeItem],
        secret_additions: &'a [SigSecretItem],
        #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        tables: &'a std::collections::BTreeMap<String, SigTable>,
    }
    serde_json::to_vec(&Canonical {
        schema: &b.schema,
        version: &b.version,
        released_at: &b.released_at,
        counts: &b.counts,
        kev_catalog: b.kev_catalog.as_ref(),
        kev_additions: &b.kev_additions,
        cpe_additions: &b.cpe_additions,
        secret_additions: &b.secret_additions,
        tables: &b.tables,
    })
    .unwrap_or_default()
}

/// Computes `sha256` and signs `bundle` in place with a 32-byte Ed25519 seed (the maintainer
/// tool `examples/sig_bundle.rs` and tests).
pub fn sign_bundle_with_seed(bundle: &mut SigBundleV1, seed: &[u8; 32]) -> Result<(), CmdError> {
    use ring::signature::Ed25519KeyPair;
    let payload = canonical_payload(bundle);
    bundle.sha256 = sha256_hex(&payload);
    let kp = Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| CmdError::new("bad_args", "invalid Ed25519 seed"))?;
    bundle.signature_ed25519 = hex_encode(kp.sign(&payload).as_ref());
    Ok(())
}

/// Hex public key of a 32-byte Ed25519 seed.
pub fn pubkey_hex_of_seed(seed: &[u8; 32]) -> Result<String, CmdError> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let kp = Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| CmdError::new("bad_args", "invalid Ed25519 seed"))?;
    Ok(hex_encode(kp.public_key().as_ref()))
}

/// Builds an unsigned bundle from the signature data compiled into this build: every kept CISA KEV
/// entry (one item per product key) plus the snapshot header. Secret rules are not included: the
/// built-in ones already ship with the app and a copy would report every secret twice.
pub fn bundle_from_builtin(version: &str, released_at: &str) -> SigBundleV1 {
    let kev = foca_analysis::kev::KevCatalog::builtin();
    let mut kev_additions = Vec::new();
    for (e, k) in kev.keyed_entries() {
        kev_additions.push(SigKevItem {
            cve: e.cve.clone(),
            product_key: k.into(),
            vendor: e.vendor.clone(),
            product: e.product.clone(),
            date_added: e.date_added.clone(),
            ransomware: e.ransomware,
            name: e.name.clone(),
            fixed_in: None,
        });
    }
    let db = loaded_db(None, None);
    SigBundleV1 {
        schema: BUNDLE_SCHEMA.into(),
        version: version.into(),
        released_at: released_at.into(),
        counts: db.counts,
        kev_catalog: Some(SigKevCatalog {
            version: kev.version.clone(),
            released: kev.released.clone(),
            total: kev.total as u32,
        }),
        kev_additions,
        cpe_additions: Vec::new(),
        secret_additions: Vec::new(),
        tables: TABLES
            .iter()
            .map(|(id, src, bytes)| {
                let t = SigTable {
                    version: lock_pin(src),
                    sha256: sha256_hex(bytes),
                    data: b64_encode(bytes),
                };
                (id.to_string(), t)
            })
            .collect(),
        sha256: String::new(),
        signature_ed25519: String::new(),
    }
}

/// Verifies `bundle` against `pubkey_bytes` (`Ed25519`) and validates all fields.
///
/// Error texts are core messages (`core.sig.*` in `locales/<lang>/ui/core.json`).
pub fn verify_bundle(bundle: &SigBundleV1, pubkey_bytes: &[u8; 32]) -> Result<(), CmdError> {
    let bad_sig = |m: &str| CmdError::new("bad_signature", m);
    if bundle.schema != BUNDLE_SCHEMA && bundle.schema != BUNDLE_SCHEMA_V1 {
        return Err(CmdError::new(
            "bad_args",
            format!("Неизвестная схема пакета сигнатур: {}", bundle.schema),
        ));
    }
    if bundle.version.trim().is_empty() || bundle.released_at.trim().is_empty() {
        return Err(CmdError::new(
            "bad_args",
            "Пустая версия или дата выпуска пакета сигнатур",
        ));
    }
    let payload = canonical_payload(bundle);
    let actual_sha = sha256_hex(&payload);
    if !actual_sha.eq_ignore_ascii_case(bundle.sha256.trim()) {
        return Err(bad_sig(
            "Контрольная сумма SHA-256 пакета сигнатур не совпадает с содержимым",
        ));
    }
    let sig_bytes = hex_decode(&bundle.signature_ed25519)
        .ok_or_else(|| bad_sig("Некорректный hex-формат подписи Ed25519"))?;
    if sig_bytes.len() != 64 {
        return Err(bad_sig(
            "Неверная длина подписи Ed25519 (ожидается 64 байта)",
        ));
    }
    let pk = UnparsedPublicKey::new(&ED25519, pubkey_bytes);
    pk.verify(&payload, &sig_bytes)
        .map_err(|_| bad_sig("Цифровая подпись Ed25519 пакета сигнатур недействительна"))?;
    for s in &bundle.secret_additions {
        if s.id.trim().is_empty() || s.pattern.trim().is_empty() {
            return Err(CmdError::new(
                "bad_args",
                "Пустой идентификатор или шаблон правила секрета в пакете",
            ));
        }
        // Validate via foca-analysis rules engine so no broken/ReDoS regex is accepted.
        let cfg = foca_analysis::rules::RulesConfig {
            presets: vec![],
            rules: vec![foca_analysis::rules::UserRule {
                id: s.id.clone(),
                title: s.title.clone(),
                pattern: s.pattern.clone(),
                sev: foca_core::Severity::High,
                enabled: true,
                case_insensitive: false,
                mask: true,
            }],
        };
        foca_analysis::rules::RuleSet::compile(&cfg).map_err(|e| {
            CmdError::new(
                "bad_args",
                format!("Правило секрета {} в пакете не компилируется: {e:?}", s.id),
            )
        })?;
    }
    if !bundle.tables.is_empty() && bundle.schema == BUNDLE_SCHEMA_V1 {
        return Err(CmdError::new(
            "bad_args",
            "Таблицы данных допустимы только в пакете схемы v2",
        ));
    }
    for (id, t) in &bundle.tables {
        let bytes = table_bytes(id, t)?;
        check_table(id, &bytes).map_err(|e| {
            CmdError::new(
                "bad_args",
                format!("Таблица {id} в пакете не читается: {e}"),
            )
        })?;
    }
    Ok(())
}

/// Upstream pin of a source in `sources.lock.json` (tag, commit or snapshot version).
fn lock_pin(source: &str) -> String {
    let lock: serde_json::Value = serde_json::from_str(SOURCES_LOCK).unwrap_or_default();
    let s = &lock["sources"][source];
    let pick = |k: &str| s[k].as_str().map(str::to_string);
    pick("tag")
        .or_else(|| pick("version"))
        .or_else(|| pick("commit").map(|c| c.chars().take(12).collect()))
        .unwrap_or_default()
}

fn lock_license(source: &str) -> String {
    let lock: serde_json::Value = serde_json::from_str(SOURCES_LOCK).unwrap_or_default();
    lock["sources"][source]["license"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for ch in s.bytes() {
        let v = B64.iter().position(|&b| b == ch)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Decodes a bundle table and checks its id and SHA-256.
fn table_bytes(id: &str, t: &SigTable) -> Result<Vec<u8>, CmdError> {
    if !TABLES.iter().any(|(k, ..)| *k == id) {
        return Err(CmdError::new(
            "bad_args",
            format!("Неизвестная таблица в пакете сигнатур: {id}"),
        ));
    }
    let bytes = b64_decode(&t.data)
        .ok_or_else(|| CmdError::new("bad_args", format!("Таблица {id}: некорректный base64")))?;
    if !sha256_hex(&bytes).eq_ignore_ascii_case(t.sha256.trim()) {
        return Err(CmdError::new(
            "bad_signature",
            format!("Таблица {id}: SHA-256 не совпадает с содержимым"),
        ));
    }
    Ok(bytes)
}

fn text(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Parses a table without installing it; returns its record count.
fn check_table(id: &str, bytes: &[u8]) -> Result<usize, String> {
    match id {
        "webappanalyzer" => foca_recon::tech::parse_upstream(bytes),
        "endoflife" => foca_recon::tech::parse_eol(bytes).map(|m| m.values().map(Vec::len).sum()),
        "saas_dns" => foca_net::saas::check_upstream_dns(text(bytes)?),
        "gitleaks" => foca_analysis::secrets::Rules::parse(text(bytes)?).map(|r| r.len()),
        "kev_enrich" => foca_analysis::kev::KevCatalog::builtin()
            .clone()
            .with_enrichment(bytes)
            .map(|c| c.enriched())
            .map_err(|e| e.0),
        "retire" => foca_recon::retire::check(bytes),
        "recog" => foca_net::recog::check(bytes),
        "favicons_md5" => Ok(foca_recon::favicon::check_md5_table(text(bytes)?)),
        "psl" => foca_net::dns::psl::Psl::from_gz(bytes).map(|p| p.len()),
        "takeover" => foca_net::takeover::check(text(bytes)?),
        _ => Err(format!("unknown table {id}")),
    }
}

/// Installs every table of `bundle` into the analysis modules (the built-in table for the ones
/// it does not carry). Without a bundle with tables nothing changes unless a bundle had replaced
/// tables before (rollback): then the built-in tables come back.
fn apply_tables(bundle: Option<&SigBundleV1>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static FROM_BUNDLE: AtomicBool = AtomicBool::new(false);
    let tables = bundle.map(|b| &b.tables).filter(|t| !t.is_empty());
    if tables.is_none() && !FROM_BUNDLE.load(Ordering::SeqCst) {
        return;
    }
    let get = |id: &str| -> Option<Vec<u8>> {
        let t = tables?.get(id)?;
        table_bytes(id, t).ok()
    };
    let builtin = |id: &str| {
        TABLES
            .iter()
            .find(|(k, ..)| *k == id)
            .map(|t| t.2)
            .unwrap_or(&[])
    };
    let pick = |id: &str| get(id).unwrap_or_else(|| builtin(id).to_vec());
    let report = |id: &str, r: Result<usize, String>| {
        if let Err(e) = r {
            tracing::warn!(target: "foca::sig", "таблица {id} не применена: {e}");
        }
    };
    let (tech, eol) = (pick("webappanalyzer"), pick("endoflife"));
    report(
        "webappanalyzer",
        foca_recon::tech::install_upstream(Some(&tech), Some(&eol)).map(|c| c.0),
    );
    let txt = |id: &str| String::from_utf8(pick(id)).unwrap_or_default();
    report(
        "saas_dns",
        foca_net::saas::install_upstream_dns(&txt("saas_dns")),
    );
    report(
        "gitleaks",
        foca_analysis::secrets::install_gitleaks(&txt("gitleaks")),
    );
    report("retire", foca_recon::retire::install(&pick("retire")));
    report("recog", foca_net::recog::install(&pick("recog")));
    foca_recon::favicon::install_md5_table(&txt("favicons_md5"));
    report("psl", foca_net::dns::psl::install(&pick("psl")));
    report("takeover", foca_net::takeover::install(&txt("takeover")));
    FROM_BUNDLE.store(tables.is_some(), Ordering::SeqCst);
}

/// Applies the data tables of the active bundle (at engine start and after an install or
/// rollback). KEV enrichment is applied per lookup by [`active_kev_catalog`].
pub fn activate(data_dir: &Path) {
    apply_tables(active_bundle(data_dir).as_ref());
}

/// Per-table numbers of the data in use.
fn table_infos(
    bundle: Option<&SigBundleV1>,
    kev: &foca_analysis::kev::KevCatalog,
) -> Vec<TableInfo> {
    let tech = foca_recon::tech::counts();
    let (libs, _) = foca_recon::retire::counts();
    let gitleaks = foca_analysis::secrets::Rules::builtin()
        .len()
        .saturating_sub(
            foca_analysis::secrets::Rules::parse(foca_analysis::secrets::BUILTIN_TOML)
                .map_or(0, |r| r.len()),
        );
    TABLES
        .iter()
        .map(|(id, src, _)| {
            let records = match *id {
                "webappanalyzer" => tech.upstream,
                "endoflife" => tech.eol_cycles,
                "saas_dns" => foca_net::saas::upstream_dns_count(),
                "gitleaks" => gitleaks,
                "kev_enrich" => kev.enriched(),
                "retire" => libs,
                "recog" => foca_net::recog::count(),
                "favicons_md5" => foca_recon::favicon::md5_count(),
                "psl" => foca_net::dns::psl::list().len(),
                "takeover" => foca_net::takeover::services().len(),
                _ => 0,
            };
            let from_bundle = bundle.and_then(|b| b.tables.get(*id));
            TableInfo {
                id: id.to_string(),
                records: records as u32,
                version: from_bundle.map_or_else(|| lock_pin(src), |t| t.version.clone()),
                license: lock_license(src),
                source: if from_bundle.is_some() {
                    "bundle"
                } else {
                    "builtin"
                }
                .into(),
            }
        })
        .collect()
}

fn sig_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("signatures")
}

fn current_path(data_dir: &Path) -> PathBuf {
    sig_dir(data_dir).join("current.json")
}

fn previous_path(data_dir: &Path) -> PathBuf {
    sig_dir(data_dir).join("previous.json")
}

fn last_check_path(data_dir: &Path) -> PathBuf {
    sig_dir(data_dir).join("last_check.json")
}

/// Numbers of the signature data the analysis really loads (built-in tables plus `bundle`).
struct LoadedDb {
    counts: SigCounts,
    kev: KevInfo,
    software: SoftwareInfo,
    std_map: StdMapInfo,
    tables: Vec<TableInfo>,
}

fn parse_ymd(s: &str) -> Option<time::Date> {
    let mut it = s.trim().splitn(3, '-');
    let y: i32 = it.next()?.parse().ok()?;
    let m: u8 = it.next()?.parse().ok()?;
    let d: u8 = it.next()?.get(..2)?.parse().ok()?;
    time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()
}

/// Standard families present in the mapping, in display order, labelled from the data.
fn frameworks(std: &foca_analysis::standards::Standards) -> Vec<StdFramework> {
    use foca_analysis::standards as st;
    let any = |f: &dyn Fn(&st::RuleStandards) -> bool| std.rules.iter().any(f);
    let fw = |id: &str, label: String, legacy: bool| StdFramework {
        id: id.into(),
        label,
        legacy,
    };
    let mut out = Vec::new();
    if any(&|r| !r.owasp.is_empty()) {
        out.push(fw("owasp", st::OWASP_TOP10.into(), false));
    }
    if any(&|r| !r.mitre.is_empty()) {
        out.push(fw("mitre", format!("MITRE {}", st::ATTACK_VERSION), false));
    }
    if any(&|r| !r.cwe.is_empty()) {
        let top25 = any(&|r| r.cwe.iter().any(|c| st::is_cwe_top25(c)));
        let label = if top25 { "CWE (Top 25 2025)" } else { "CWE" };
        out.push(fw("cwe", label.into(), false));
    }
    if any(&|r| !r.nist.is_empty()) {
        out.push(fw("ndtzi36", st::NDTZI_3_6_006.into(), false));
        out.push(fw("nist", st::NIST_800_53.into(), false));
    }
    if any(&|r| !r.iso27001.is_empty()) {
        out.push(fw("iso27001", "ISO/IEC 27001:2022".into(), false));
    }
    if any(&|r| !r.wstg.is_empty()) {
        // Same edition as the `wstg` ids in standards.toml.
        out.push(fw("wstg", "OWASP WSTG v4.2".into(), false));
    }
    // Personal data laws: the first word of each article code (`GDPR Art. 32` -> `GDPR`).
    let mut laws: Vec<&str> = Vec::new();
    for r in &std.rules {
        for key in &r.privacy {
            let law = std
                .privacy
                .get(key)
                .and_then(|p| p.code.split_whitespace().next());
            if let Some(law) = law.filter(|l| !laws.contains(l)) {
                laws.push(law);
            }
        }
    }
    for law in laws {
        out.push(fw("privacy", law.into(), false));
    }
    if any(&|r| !r.ndtzi.is_empty() || !r.kszi.is_empty()) {
        out.push(fw("kszi", "НД ТЗІ 2.5-004-99, 3.7-003-05".into(), true));
    }
    out
}

fn loaded_db(bundle: Option<&SigBundleV1>, today: Option<time::Date>) -> LoadedDb {
    let builtin = foca_analysis::kev::KevCatalog::builtin();
    let extended;
    let kev = match bundle.and_then(|b| active_kev_from(b.clone())) {
        Some(c) => {
            extended = c;
            &extended
        }
        None => builtin,
    };
    let snap = bundle.and_then(|b| b.kev_catalog.clone());
    let (catalog, released, total) = match snap {
        Some(c) => (c.version, c.released, c.total),
        None => (
            builtin.version.clone(),
            builtin.released.clone(),
            builtin.total as u32,
        ),
    };
    let age_days = parse_ymd(&released)
        .zip(today)
        .map(|(r, t)| (t - r).whole_days().max(0));
    let std = foca_analysis::standards::Standards::builtin();
    let refs: usize = std
        .rules
        .iter()
        .map(|r| {
            r.mitre.len()
                + r.cwe.len()
                + r.owasp.len()
                + r.wstg.len()
                + r.iso27001.len()
                + r.nist.len()
                + r.privacy.len()
                + r.ndtzi.len()
                + r.kszi.len()
        })
        .sum();
    let (software, os) = foca_analysis::software::Signatures::builtin().len();
    let secrets = foca_analysis::secrets::Rules::builtin().len()
        + bundle.map_or(0, |b| b.secret_additions.len());
    let tables = table_infos(bundle, kev);
    LoadedDb {
        tables,
        counts: SigCounts {
            cpe: (software + os) as u32,
            cve: kev.used() as u32,
            secrets: secrets as u32,
            standards: refs as u32,
        },
        kev: KevInfo {
            catalog,
            released,
            total,
            used: kev.used() as u32,
            products: kev.product_count() as u32,
            age_days,
            stale: age_days.is_some_and(|d| d > KEV_STALE_DAYS),
        },
        software: SoftwareInfo {
            software: software as u32,
            os: os as u32,
        },
        std_map: StdMapInfo {
            rules: std.rules.iter().filter(|r| !r.is_empty()).count() as u32,
            refs: refs as u32,
            frameworks: frameworks(std),
        },
    }
}

fn read_last_check(data_dir: &Path) -> Option<LastCheck> {
    let raw = fs::read_to_string(last_check_path(data_dir)).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_last_check(data_dir: &Path, c: &LastCheck) {
    let _ = fs::create_dir_all(sig_dir(data_dir));
    if let Ok(raw) = serde_json::to_vec_pretty(c) {
        let _ = fs::write(last_check_path(data_dir), raw);
    }
}

fn make_status(
    data_dir: &Path,
    bundle: Option<&SigBundleV1>,
    can_rollback: bool,
    pubkey_bytes: &[u8; 32],
    today: Option<time::Date>,
) -> SigStatus {
    let db = loaded_db(bundle, today);
    let (version, updated_at, source, sha256) = match bundle {
        Some(b) => (
            b.version.clone(),
            b.released_at.clone(),
            "bundle",
            b.sha256.clone(),
        ),
        None => {
            let kev = foca_analysis::kev::KevCatalog::builtin();
            (
                kev.version.clone(),
                kev.released.clone(),
                "builtin",
                sha256_hex(foca_analysis::kev::KEV_GZ),
            )
        }
    };
    SigStatus {
        schema: BUNDLE_SCHEMA.into(),
        version,
        updated_at,
        source: source.into(),
        sha256,
        pubkey_ed25519: hex_encode(pubkey_bytes),
        signature_valid: true,
        can_rollback,
        counts: db.counts,
        added_kev: bundle.map_or(0, |b| b.kev_additions.len() as u32),
        added_cpe: bundle.map_or(0, |b| b.cpe_additions.len() as u32),
        added_secrets: bundle.map_or(0, |b| b.secret_additions.len() as u32),
        kev: db.kev,
        software: db.software,
        std_map: db.std_map,
        tables: db.tables,
        feed_url: DEFAULT_FEED_URL.into(),
        last_check: read_last_check(data_dir),
    }
}

/// Reads the current signature status from `<data_dir>/signatures/current.json` (falling back to
/// the embedded builtin catalog if no bundle is installed). `today` dates the KEV snapshot age.
pub fn status(data_dir: &Path, today: time::Date) -> SigStatus {
    status_with_pubkey(data_dir, &official_pubkey_bytes(), today)
}

pub(crate) fn status_with_pubkey(
    data_dir: &Path,
    pubkey_bytes: &[u8; 32],
    today: time::Date,
) -> SigStatus {
    let prev_exists = previous_path(data_dir).is_file();
    match verified_bundle_at(&current_path(data_dir), pubkey_bytes) {
        Some(b) => make_status(data_dir, Some(&b), true, pubkey_bytes, Some(today)),
        None => make_status(data_dir, None, prev_exists, pubkey_bytes, Some(today)),
    }
}

fn verified_bundle_at(path: &Path, pubkey_bytes: &[u8; 32]) -> Option<SigBundleV1> {
    let raw = fs::read_to_string(path).ok()?;
    let bundle = serde_json::from_str::<SigBundleV1>(&raw).ok()?;
    verify_bundle(&bundle, pubkey_bytes).ok()?;
    Some(bundle)
}

/// Returns the active verified bundle if one is installed on disk.
pub fn active_bundle(data_dir: &Path) -> Option<SigBundleV1> {
    verified_bundle_at(&current_path(data_dir), &official_pubkey_bytes())
}

/// Returns secret rules contributed by an active verified signature bundle (if any).
pub fn active_secret_rules(data_dir: &Path) -> Vec<foca_analysis::rules::UserRule> {
    let Some(b) = active_bundle(data_dir) else {
        return Vec::new();
    };
    b.secret_additions
        .into_iter()
        .map(|s| foca_analysis::rules::UserRule {
            id: s.id,
            title: s.title,
            pattern: s.pattern,
            sev: foca_core::Severity::High,
            enabled: true,
            case_insensitive: false,
            mask: true,
        })
        .collect()
}

/// Appends active signed-bundle secret rules onto `cfg` without duplicating rule IDs.
pub fn merge_rules_with_bundle(
    data_dir: &Path,
    mut cfg: foca_analysis::rules::RulesConfig,
) -> foca_analysis::rules::RulesConfig {
    for extra in active_secret_rules(data_dir) {
        if !cfg.rules.iter().any(|r| r.id == extra.id) {
            cfg.rules.push(extra);
        }
    }
    cfg
}

/// The built-in KEV catalog extended with the entries and the EPSS/CVSS table of `b`, `None`
/// when it adds neither.
fn active_kev_from(b: SigBundleV1) -> Option<foca_analysis::kev::KevCatalog> {
    let enrich = b
        .tables
        .get("kev_enrich")
        .and_then(|t| table_bytes("kev_enrich", t).ok());
    if b.kev_additions.is_empty() && enrich.is_none() {
        return None;
    }
    let extra: Vec<foca_analysis::kev::KevEntry> = b
        .kev_additions
        .into_iter()
        .map(|k| foca_analysis::kev::KevEntry {
            cve: k.cve,
            keys: vec![k.product_key],
            vendor: k.vendor,
            product: k.product,
            date_added: k.date_added,
            ransomware: k.ransomware,
            name: k.name,
        })
        .collect();
    let cat = foca_analysis::kev::KevCatalog::builtin().with_additions(extra);
    match enrich {
        Some(gz) => cat.clone().with_enrichment(&gz).ok().or(Some(cat)),
        None => Some(cat),
    }
}

/// Returns a KEV catalog extended with entries from an active verified signature bundle (if any).
pub fn active_kev_catalog(data_dir: &Path) -> Option<foca_analysis::kev::KevCatalog> {
    active_kev_from(active_bundle(data_dir)?)
}

/// Verifies `bundle_json` (`Ed25519` + `SHA-256`) and atomically installs it as `current.json`,
/// rotating any previous `current.json` to `previous.json`.
pub fn import_bundle(
    data_dir: &Path,
    bundle_json: &str,
    today: time::Date,
) -> Result<SigStatus, CmdError> {
    import_bundle_with_pubkey(data_dir, bundle_json, &official_pubkey_bytes(), today)
}

fn parse_bundle(bundle_json: &str) -> Result<SigBundleV1, CmdError> {
    serde_json::from_str(bundle_json.trim_start_matches('\u{feff}')).map_err(|e| {
        CmdError::new(
            "bad_args",
            format!("Некорректный JSON пакета сигнатур: {e}"),
        )
    })
}

pub(crate) fn import_bundle_with_pubkey(
    data_dir: &Path,
    bundle_json: &str,
    pubkey_bytes: &[u8; 32],
    today: time::Date,
) -> Result<SigStatus, CmdError> {
    let bundle = parse_bundle(bundle_json)?;
    verify_bundle(&bundle, pubkey_bytes)?;
    install(data_dir, &bundle)?;
    apply_tables(Some(&bundle));
    Ok(make_status(
        data_dir,
        Some(&bundle),
        true,
        pubkey_bytes,
        Some(today),
    ))
}

fn install(data_dir: &Path, bundle: &SigBundleV1) -> Result<(), CmdError> {
    let dir = sig_dir(data_dir);
    fs::create_dir_all(&dir).map_err(|e| CmdError::new("io", e.to_string()))?;
    let cur = current_path(data_dir);
    let prev = previous_path(data_dir);
    if cur.is_file() {
        let _ = fs::copy(&cur, &prev);
    }
    let tmp = dir.join("current.json.tmp");
    let serialized =
        serde_json::to_vec_pretty(bundle).map_err(|e| CmdError::new("io", e.to_string()))?;
    fs::write(&tmp, &serialized).map_err(|e| CmdError::new("io", e.to_string()))?;
    fs::rename(&tmp, &cur).map_err(|e| CmdError::new("io", e.to_string()))?;
    Ok(())
}

/// Numeric parts of a version (`2026.11.20` -> `[2026, 11, 20]`) for ordering.
fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

/// Applies the result of fetching the update feed and records the check in `last_check.json`.
///
/// * HTTP 404/410: nothing is published at the feed yet, `no_update`;
/// * a verified bundle not newer than the active database: `up_to_date`, nothing changes;
/// * a verified newer bundle: installed (`installed`);
/// * anything else (network error, bad JSON, bad signature): recorded as `failed` and returned as
///   the error, the active database stays as it was.
pub fn apply_feed(
    data_dir: &Path,
    feed_url: &str,
    fetched: Result<String, CmdError>,
    pubkey_bytes: &[u8; 32],
    now: time::OffsetDateTime,
) -> Result<SigStatus, CmdError> {
    let mut check = LastCheck {
        at: crate::util::iso(now),
        outcome: String::new(),
        feed_url: feed_url.into(),
        version: None,
        error: None,
        error_code: None,
    };
    let result = (|| {
        let raw = match fetched {
            Ok(raw) => raw,
            Err(e) if e.code == "not_published" => return Ok("no_update"),
            Err(e) => return Err(e),
        };
        let bundle = parse_bundle(&raw)?;
        verify_bundle(&bundle, pubkey_bytes)?;
        check.version = Some(bundle.version.clone());
        let active = status_with_pubkey(data_dir, pubkey_bytes, now.date());
        if version_key(&bundle.version) <= version_key(&active.version) {
            return Ok("up_to_date");
        }
        install(data_dir, &bundle)?;
        apply_tables(Some(&bundle));
        Ok("installed")
    })();
    match result {
        Ok(outcome) => {
            check.outcome = outcome.into();
            write_last_check(data_dir, &check);
            Ok(status_with_pubkey(data_dir, pubkey_bytes, now.date()))
        }
        Err(e) => {
            check.outcome = "failed".into();
            check.error = Some(e.message.clone());
            check.error_code = Some(e.code.clone());
            write_last_check(data_dir, &check);
            Err(e)
        }
    }
}

/// Rolls back the signature database to `previous.json` (or to the embedded builtin database if no
/// `previous.json` exists).
pub fn rollback(data_dir: &Path, today: time::Date) -> Result<SigStatus, CmdError> {
    rollback_with_pubkey(data_dir, &official_pubkey_bytes(), today)
}

pub(crate) fn rollback_with_pubkey(
    data_dir: &Path,
    pubkey_bytes: &[u8; 32],
    today: time::Date,
) -> Result<SigStatus, CmdError> {
    let cur = current_path(data_dir);
    let prev = previous_path(data_dir);
    if prev.is_file() {
        if let Some(bundle) = verified_bundle_at(&prev, pubkey_bytes) {
            fs::rename(&prev, &cur).map_err(|e| CmdError::new("io", e.to_string()))?;
            apply_tables(Some(&bundle));
            return Ok(make_status(
                data_dir,
                Some(&bundle),
                true,
                pubkey_bytes,
                Some(today),
            ));
        }
        let _ = fs::remove_file(&prev);
    }
    if cur.is_file() {
        fs::remove_file(&cur).map_err(|e| CmdError::new("io", e.to_string()))?;
    }
    apply_tables(None);
    Ok(make_status(
        data_dir,
        None,
        false,
        pubkey_bytes,
        Some(today),
    ))
}

/// Builds a signed sample bundle (`foca-sig-bundle/v1`) for unit tests.
#[cfg(test)]
fn build_signed_test_bundle(version: &str, released_at: &str, seed: &[u8; 32]) -> SigBundleV1 {
    let kev_additions = vec![
        SigKevItem {
            cve: "CVE-2099-0001".into(),
            product_key: "ms_windows".into(),
            vendor: "Microsoft".into(),
            product: "Windows Remote Desktop Licensing Service".into(),
            date_added: released_at.into(),
            ransomware: true,
            name: "Sample Windows RDL vulnerability".into(),
            fixed_in: Some("10.0.20348.2582".into()),
        },
        SigKevItem {
            cve: "CVE-2099-0002".into(),
            product_key: "php".into(),
            vendor: "PHP".into(),
            product: "PHP CGI".into(),
            date_added: released_at.into(),
            ransomware: false,
            name: "Sample PHP CGI vulnerability".into(),
            fixed_in: None,
        },
    ];
    let cpe_additions = vec![SigCpeItem {
        cpe_prefix: "cpe:/a:gitlab:gitlab".into(),
        label: "GitLab".into(),
        latest_ver: Some("17.5.2".into()),
    }];
    let secret_additions = vec![SigSecretItem {
        id: "sig_cloudflare_api_token".into(),
        title: "Cloudflare API Token".into(),
        pattern: r"cf_token_[A-Za-z0-9_-]{32,45}".into(),
    }];
    let mut bundle = SigBundleV1 {
        schema: BUNDLE_SCHEMA.into(),
        version: version.into(),
        released_at: released_at.into(),
        counts: SigCounts {
            cpe: 0,
            cve: 0,
            secrets: 0,
            standards: 0,
        },
        kev_catalog: None,
        kev_additions,
        cpe_additions,
        secret_additions,
        tables: Default::default(),
        sha256: String::new(),
        signature_ed25519: String::new(),
    };
    sign_bundle_with_seed(&mut bundle, seed).unwrap();
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, datetime};

    const TEST_SEED: [u8; 32] = [0x42u8; 32];
    const TODAY: time::Date = date!(2026 - 11 - 27);

    fn test_pubkey() -> [u8; 32] {
        let hex = pubkey_hex_of_seed(&TEST_SEED).unwrap();
        hex_decode(&hex).unwrap().try_into().unwrap()
    }

    fn not_published() -> Result<String, CmdError> {
        Err(CmdError::new("not_published", "HTTP 404"))
    }

    #[test]
    fn valid_ed25519_bundle_installs_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        assert_ne!(pk, official_pubkey_bytes());
        let st0 = status_with_pubkey(dir.path(), &pk, TODAY);
        assert_eq!(st0.source, "builtin");
        assert!(!st0.can_rollback);

        let b1 = build_signed_test_bundle("2026.11.22", "2026-11-22", &TEST_SEED);
        let json1 = serde_json::to_string(&b1).unwrap();
        let st1 = import_bundle_with_pubkey(dir.path(), &json1, &pk, TODAY).unwrap();
        assert_eq!(st1.source, "bundle");
        assert_eq!(st1.version, "2026.11.22");
        assert!(st1.signature_valid);
        assert!(st1.can_rollback);
        assert_eq!(st1.added_kev, 2);
        assert_eq!(st1.added_cpe, 1);
        assert_eq!(st1.added_secrets, 1);
        // Loaded numbers: two new KEV entries and one extra secret rule really count.
        assert_eq!(st1.counts.cve, st0.counts.cve + 2);
        assert_eq!(st1.kev.used, st0.kev.used + 2);
        assert_eq!(st1.counts.secrets, st0.counts.secrets + 1);
        // CPE prefixes are not used for matching, so the software count stays.
        assert_eq!(st1.counts.cpe, st0.counts.cpe);

        // The release public key must not accept a test-signed bundle.
        assert!(import_bundle(dir.path(), &json1, TODAY).is_err());

        // Second bundle rotates first to previous.json.
        let b2 = build_signed_test_bundle("2026.11.23", "2026-11-23", &TEST_SEED);
        let st2 =
            import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&b2).unwrap(), &pk, TODAY)
                .unwrap();
        assert_eq!(st2.version, "2026.11.23");

        // Rollback 1 -> 2026.11.22.
        let rb1 = rollback_with_pubkey(dir.path(), &pk, TODAY).unwrap();
        assert_eq!(rb1.source, "bundle");
        assert_eq!(rb1.version, "2026.11.22");

        // Rollback 2 -> builtin.
        let rb2 = rollback_with_pubkey(dir.path(), &pk, TODAY).unwrap();
        assert_eq!(rb2.source, "builtin");
        assert!(!rb2.can_rollback);
    }

    fn v2_bundle(version: &str) -> SigBundleV1 {
        let mut b = bundle_from_builtin(version, "2026-11-27");
        b.kev_additions.clear();
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        b
    }

    #[test]
    fn v2_tables_roundtrip_install_and_verify() {
        assert_eq!(b64_decode(&b64_encode(b"foca-rs")).unwrap(), b"foca-rs");
        assert_eq!(b64_encode(b"ab"), "YWI=");
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let b = v2_bundle("2026.11.28");
        assert_eq!(b.schema, BUNDLE_SCHEMA);
        assert_eq!(b.tables.len(), TABLES.len());
        let json = serde_json::to_string(&b).unwrap();
        let st = import_bundle_with_pubkey(dir.path(), &json, &pk, TODAY).unwrap();
        assert_eq!(st.source, "bundle");
        assert!(st
            .tables
            .iter()
            .all(|t| t.source == "bundle" && t.records > 0));
        // The same data as built in: the loaded numbers do not change.
        let builtin = status_with_pubkey(tempfile::tempdir().unwrap().path(), &pk, TODAY);
        for (a, b) in st.tables.iter().zip(&builtin.tables) {
            assert_eq!(a.records, b.records, "{}", a.id);
        }
        assert!(active_kev_from(b.clone()).unwrap().enriched() > 900);
        let rb = rollback_with_pubkey(dir.path(), &pk, TODAY).unwrap();
        assert_eq!(rb.source, "builtin");
    }

    #[test]
    fn tampered_or_unknown_tables_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        // A table whose bytes do not match its SHA-256 (re-signed, so only the table check fails).
        let mut b = v2_bundle("2026.11.28");
        let t = b.tables.get_mut("takeover").unwrap();
        t.data = b64_encode(br#"{"services":[]}"#);
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        let err =
            import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&b).unwrap(), &pk, TODAY)
                .unwrap_err();
        assert!(err.message.contains("takeover"), "{}", err.message);
        // A matching SHA-256 over data the parser rejects.
        let mut b = v2_bundle("2026.11.28");
        let junk = b"not gzip".to_vec();
        b.tables.insert(
            "retire".into(),
            SigTable {
                version: "x".into(),
                sha256: sha256_hex(&junk),
                data: b64_encode(&junk),
            },
        );
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        assert!(import_bundle_with_pubkey(
            dir.path(),
            &serde_json::to_string(&b).unwrap(),
            &pk,
            TODAY
        )
        .is_err());
        // Unknown table ids and tables in a v1 bundle.
        let mut b = v2_bundle("2026.11.28");
        let first = b.tables.values().next().unwrap().clone();
        b.tables.insert("nmap".into(), first);
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        assert!(verify_bundle(&b, &pk).is_err());
        let mut b = v2_bundle("2026.11.28");
        b.schema = BUNDLE_SCHEMA_V1.into();
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        assert!(verify_bundle(&b, &pk).is_err());
        assert_eq!(status_with_pubkey(dir.path(), &pk, TODAY).source, "builtin");
    }

    #[test]
    fn v1_bundles_stay_readable() {
        // A v1 bundle (no tables) keeps its canonical payload: no `tables` key is signed.
        let mut b = build_signed_test_bundle("2026.11.22", "2026-11-22", &TEST_SEED);
        b.schema = BUNDLE_SCHEMA_V1.into();
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        let payload = String::from_utf8(canonical_payload(&b)).unwrap();
        assert!(!payload.contains("tables"));
        let json = serde_json::to_string(&b).unwrap();
        assert!(!json.contains("\"tables\""));
        verify_bundle(&parse_bundle(&json).unwrap(), &test_pubkey()).unwrap();
    }

    #[test]
    fn tampered_payload_or_foreign_signature_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let mut b = build_signed_test_bundle("2026.11.22", "2026-11-22", &TEST_SEED);
        b.counts.cve += 1;
        // Recompute SHA-256 without valid Ed25519 private key -> Ed25519 verify must fail.
        b.sha256 = sha256_hex(&canonical_payload(&b));
        let err =
            import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&b).unwrap(), &pk, TODAY)
                .unwrap_err();
        assert_eq!(err.code, "bad_signature");
        assert!(err.message.contains("Ed25519"));
        assert_eq!(status_with_pubkey(dir.path(), &pk, TODAY).source, "builtin");

        // Signed with a foreign Ed25519 seed -> rejected.
        let foreign = build_signed_test_bundle("2026.11.22", "2026-11-22", &[0x99u8; 32]);
        let err2 = import_bundle_with_pubkey(
            dir.path(),
            &serde_json::to_string(&foreign).unwrap(),
            &pk,
            TODAY,
        )
        .unwrap_err();
        assert_eq!(err2.code, "bad_signature");
        assert_eq!(status_with_pubkey(dir.path(), &pk, TODAY).source, "builtin");
    }

    #[test]
    fn builtin_status_counts_come_from_the_loaded_tables() {
        let dir = tempfile::tempdir().unwrap();
        let st = status(dir.path(), TODAY);
        let kev = foca_analysis::kev::KevCatalog::builtin();
        // CISA KEV only: the snapshot total and the kept entries used for matching differ.
        assert_eq!(st.kev.total, kev.total as u32);
        assert_eq!(st.kev.used, kev.used() as u32);
        assert!(st.kev.used < st.kev.total);
        assert_eq!(st.counts.cve, st.kev.used);
        assert_eq!(st.kev.catalog, kev.version);
        assert_eq!(st.kev.products, kev.product_count() as u32);
        // Our tuned rules plus the gitleaks ones.
        let rules = |t: &str| t.lines().filter(|l| l.trim() == "[[rule]]").count();
        let secrets = rules(foca_analysis::secrets::BUILTIN_TOML)
            + rules(foca_analysis::secrets::GITLEAKS_TOML);
        assert_eq!(st.counts.secrets as usize, secrets);
        // Every ingested table reports the records the modules really loaded.
        let tbl = |id: &str| st.tables.iter().find(|t| t.id == id).unwrap();
        assert_eq!(st.tables.len(), TABLES.len());
        assert!(st
            .tables
            .iter()
            .all(|t| t.records > 0 && !t.version.is_empty()));
        assert!(st.tables.iter().all(|t| t.source == "builtin"));
        assert_eq!(
            tbl("gitleaks").records as usize,
            rules(foca_analysis::secrets::GITLEAKS_TOML)
        );
        assert_eq!(tbl("gitleaks").version, "v8.30.1");
        assert_eq!(tbl("kev_enrich").records, st.kev.used);
        assert_eq!(tbl("psl").license, "MPL-2.0");
        let sw = foca_analysis::software::BUILTIN_TOML
            .lines()
            .filter(|l| l.trim() == "[[software]]")
            .count();
        let os = foca_analysis::software::BUILTIN_TOML
            .lines()
            .filter(|l| l.trim() == "[[os]]")
            .count();
        assert_eq!(
            (st.software.software as usize, st.software.os as usize),
            (sw, os)
        );
        assert_eq!(st.counts.cpe as usize, sw + os);
        // Standards: real references, labelled from the mapping data.
        assert!(st.std_map.refs > st.std_map.rules);
        assert_eq!(st.counts.standards, st.std_map.refs);
        let labels: Vec<&str> = st
            .std_map
            .frameworks
            .iter()
            .map(|f| f.label.as_str())
            .collect();
        for want in [
            "OWASP Top 10:2025",
            "MITRE ATT&CK v20",
            "CWE (Top 25 2025)",
            "НД ТЗІ 3.6-006-24",
            "NIST SP 800-53 Rev. 5",
            "GDPR",
            "2297-VI",
        ] {
            assert!(labels.contains(&want), "{want} in {labels:?}");
        }
        assert!(st.std_map.frameworks.iter().any(|f| f.legacy));
        assert!(st.last_check.is_none());
        assert_eq!(st.feed_url, DEFAULT_FEED_URL);
    }

    #[test]
    fn kev_age_and_staleness() {
        let dir = tempfile::tempdir().unwrap();
        let released = parse_ymd(&foca_analysis::kev::KevCatalog::builtin().released).unwrap();
        let fresh = status(dir.path(), released + time::Duration::days(3));
        assert_eq!(fresh.kev.age_days, Some(3));
        assert!(!fresh.kev.stale);
        let old = status(
            dir.path(),
            released + time::Duration::days(KEV_STALE_DAYS + 1),
        );
        assert!(old.kev.stale);
        assert_eq!(parse_ymd("2026-11-20"), Some(date!(2026 - 11 - 20)));
        assert_eq!(parse_ymd("bad"), None);
    }

    #[test]
    fn feed_404_reports_no_update_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let now = datetime!(2026-11-27 10:15:00 UTC);
        let st = apply_feed(dir.path(), DEFAULT_FEED_URL, not_published(), &pk, now).unwrap();
        assert_eq!(st.source, "builtin");
        let c = st.last_check.unwrap();
        assert_eq!(c.outcome, "no_update");
        assert_eq!(c.at, "2026-11-27T10:15:00");
        assert_eq!(c.feed_url, DEFAULT_FEED_URL);
        assert!(c.version.is_none() && c.error.is_none());
        // The record survives and shows in the plain status.
        let again = status_with_pubkey(dir.path(), &pk, TODAY);
        assert_eq!(again.last_check.unwrap().outcome, "no_update");
    }

    #[test]
    fn feed_with_a_newer_signed_bundle_installs_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let now = datetime!(2026-11-27 10:15:00 UTC);
        let body = serde_json::to_string(&build_signed_test_bundle(
            "2099.1.1",
            "2099-01-01",
            &TEST_SEED,
        ))
        .unwrap();
        let st = apply_feed(dir.path(), "u", Ok(body.clone()), &pk, now).unwrap();
        assert_eq!(st.source, "bundle");
        assert_eq!(st.version, "2099.1.1");
        let c = st.last_check.unwrap();
        assert_eq!(c.outcome, "installed");
        assert_eq!(c.version.as_deref(), Some("2099.1.1"));
        // Same bundle again: up to date, no rotation into previous.json.
        let st2 = apply_feed(dir.path(), "u", Ok(body), &pk, now).unwrap();
        assert_eq!(st2.last_check.unwrap().outcome, "up_to_date");
        assert!(!previous_path(dir.path()).exists());
        // An older bundle than the built-in database is not installed either.
        let dir2 = tempfile::tempdir().unwrap();
        let old = serde_json::to_string(&build_signed_test_bundle(
            "2020.1.1",
            "2020-01-01",
            &TEST_SEED,
        ))
        .unwrap();
        let st3 = apply_feed(dir2.path(), "u", Ok(old), &pk, now).unwrap();
        assert_eq!(st3.source, "builtin");
        assert_eq!(st3.last_check.unwrap().outcome, "up_to_date");
    }

    #[test]
    fn feed_failures_are_recorded_and_returned_as_errors() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let now = datetime!(2026-11-27 10:15:00 UTC);
        let foreign = serde_json::to_string(&build_signed_test_bundle(
            "2099.1.1",
            "2099-01-01",
            &[7u8; 32],
        ))
        .unwrap();
        let err = apply_feed(dir.path(), "u", Ok(foreign), &pk, now).unwrap_err();
        assert_eq!(err.code, "bad_signature");
        let st = status_with_pubkey(dir.path(), &pk, TODAY);
        assert_eq!(st.source, "builtin");
        let c = st.last_check.unwrap();
        assert_eq!(c.outcome, "failed");
        assert_eq!(c.error_code.as_deref(), Some("bad_signature"));
        assert!(c.error.unwrap().contains("Ed25519"));

        let net = CmdError::new("net", "Загрузка пакета сигнатур: таймаут");
        assert!(apply_feed(dir.path(), "u", Err(net), &pk, now).is_err());
        let c = status_with_pubkey(dir.path(), &pk, TODAY)
            .last_check
            .unwrap();
        assert_eq!(c.error_code.as_deref(), Some("net"));
        assert!(apply_feed(dir.path(), "u", Ok("<html>".into()), &pk, now).is_err());
    }

    #[test]
    fn bundle_built_from_the_repo_data_verifies_and_keeps_the_counts() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let mut b = bundle_from_builtin("2099.1.1", "2099-01-01");
        sign_bundle_with_seed(&mut b, &TEST_SEED).unwrap();
        let before = status_with_pubkey(dir.path(), &pk, TODAY);
        let st =
            import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&b).unwrap(), &pk, TODAY)
                .unwrap();
        // Re-adding the built-in entries changes nothing in matching.
        assert_eq!(st.kev.used, before.kev.used);
        assert_eq!(st.counts.secrets, before.counts.secrets);
        assert_eq!(st.kev.catalog, before.kev.catalog);
        assert_eq!(st.kev.total, before.kev.total);
        // Old bundles without `kev_catalog` keep verifying: the field is skipped when absent.
        let mut legacy = b.clone();
        legacy.kev_catalog = None;
        sign_bundle_with_seed(&mut legacy, &TEST_SEED).unwrap();
        assert!(!String::from_utf8(canonical_payload(&legacy))
            .unwrap()
            .contains("kev_catalog"));
        assert!(verify_bundle(&legacy, &pk).is_ok());
    }
}

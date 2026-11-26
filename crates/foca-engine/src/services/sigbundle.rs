//! Ed25519-signed signature bundles.
//!
//! Signature bundles (`foca-sig-bundle/v1`) update CISA KEV entries, CPE rules, and secret
//! detection rules without rebuilding the APK. Every bundle is verified with `Ed25519`
//! (`ring::signature::ED25519`) and `SHA-256` before touching disk. Validated bundles are
//! written atomically to `<data_dir>/signatures/current.json`, keeping the previous bundle in
//! `<data_dir>/signatures/previous.json` for instant rollback.

use std::fs;
use std::path::{Path, PathBuf};

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CmdError;

/// Schema identifier of a v1 signature bundle.
pub const BUNDLE_SCHEMA: &str = "foca-sig-bundle/v1";

/// 32-byte Ed25519 public key used to verify signature bundles.
/// The private signing key is kept offline by the release maintainers.
const OFFICIAL_ED25519_PUBKEY: [u8; 32] = [
    0xa3, 0x25, 0x6d, 0xdc, 0x5b, 0xae, 0x21, 0xf4, 0x07, 0x46, 0x66, 0x3f, 0xde, 0x1e, 0x48, 0xa0,
    0xf4, 0xff, 0x84, 0x87, 0xe9, 0x5a, 0x8b, 0xb7, 0x46, 0x9a, 0x56, 0x02, 0x02, 0x3d, 0xc5, 0x27,
];

/// Returns the 32-byte Ed25519 public key used to verify signature bundles.
pub fn official_pubkey_bytes() -> [u8; 32] {
    OFFICIAL_ED25519_PUBKEY
}

/// Returns the hex-encoded release Ed25519 public key.
pub fn official_pubkey_hex() -> String {
    hex_encode(&official_pubkey_bytes())
}

/// Counts of signature records in the active database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigCounts {
    pub cpe: u32,
    pub cve: u32,
    pub secrets: u32,
    pub standards: u32,
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

/// Additional CPE mapping rule shipped in a signature bundle.
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

/// A signed v1 signature bundle (`foca-sig-bundle/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigBundleV1 {
    pub schema: String,
    pub version: String,
    pub released_at: String,
    pub counts: SigCounts,
    #[serde(default)]
    pub kev_additions: Vec<SigKevItem>,
    #[serde(default)]
    pub cpe_additions: Vec<SigCpeItem>,
    #[serde(default)]
    pub secret_additions: Vec<SigSecretItem>,
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
        kev_additions: &'a [SigKevItem],
        cpe_additions: &'a [SigCpeItem],
        secret_additions: &'a [SigSecretItem],
    }
    serde_json::to_vec(&Canonical {
        schema: &b.schema,
        version: &b.version,
        released_at: &b.released_at,
        counts: &b.counts,
        kev_additions: &b.kev_additions,
        cpe_additions: &b.cpe_additions,
        secret_additions: &b.secret_additions,
    })
    .unwrap_or_default()
}

/// Computes `sha256` and signs `bundle` in place using the given 32-byte Ed25519 seed (tests only).
#[cfg(test)]
pub fn sign_bundle_with_seed(bundle: &mut SigBundleV1, seed: &[u8; 32]) {
    use ring::signature::Ed25519KeyPair;
    let payload = canonical_payload(bundle);
    bundle.sha256 = sha256_hex(&payload);
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("valid 32-byte Ed25519 seed");
    let sig = kp.sign(&payload);
    bundle.signature_ed25519 = hex_encode(sig.as_ref());
}

/// Verifies `bundle` against `pubkey_bytes` (`Ed25519`) and validates all fields.
pub fn verify_bundle(bundle: &SigBundleV1, pubkey_bytes: &[u8; 32]) -> Result<(), CmdError> {
    if bundle.schema != BUNDLE_SCHEMA {
        return Err(CmdError::new(
            "bad_args",
            format!("Неизвестная схема бандла сигнатур: {}", bundle.schema),
        ));
    }
    if bundle.version.trim().is_empty() || bundle.released_at.trim().is_empty() {
        return Err(CmdError::new(
            "bad_args",
            "Пустая версия или дата выпуска бандла сигнатур",
        ));
    }
    let payload = canonical_payload(bundle);
    let actual_sha = sha256_hex(&payload);
    if !actual_sha.eq_ignore_ascii_case(bundle.sha256.trim()) {
        return Err(CmdError::new(
            "bad_args",
            "Контрольная сумма SHA-256 бандла сигнатур не совпадает с содержимым",
        ));
    }
    let sig_bytes = hex_decode(&bundle.signature_ed25519)
        .ok_or_else(|| CmdError::new("bad_args", "Некорректный hex-формат подписи Ed25519"))?;
    if sig_bytes.len() != 64 {
        return Err(CmdError::new(
            "bad_args",
            "Неверная длина подписи Ed25519 (ожидается 64 байта)",
        ));
    }
    let pk = UnparsedPublicKey::new(&ED25519, pubkey_bytes);
    pk.verify(&payload, &sig_bytes).map_err(|_| {
        CmdError::new(
            "bad_args",
            "Цифровая подпись Ed25519 бандла сигнатур недействительна",
        )
    })?;
    for s in &bundle.secret_additions {
        if s.id.trim().is_empty() || s.pattern.trim().is_empty() {
            return Err(CmdError::new(
                "bad_args",
                "Пустой идентификатор или шаблон правила секрета в бандле",
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
        foca_analysis::rules::RuleSet::compile(&cfg)
            .map_err(|e| CmdError::new("bad_args", format!("Правило {}: {e:?}", s.id)))?;
    }
    Ok(())
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

fn builtin_status_for_key(can_rollback: bool, pubkey_bytes: &[u8; 32]) -> SigStatus {
    let kev = foca_analysis::kev::KevCatalog::builtin();
    let standards = foca_analysis::standards::Standards::builtin();
    let secret_rules = foca_analysis::secrets::BUILTIN_TOML
        .matches("[[rule]]")
        .count() as u32;
    SigStatus {
        schema: BUNDLE_SCHEMA.into(),
        version: kev.version.clone(),
        updated_at: kev.released.clone(),
        source: "builtin".into(),
        sha256: sha256_hex(foca_analysis::kev::KEV_GZ),
        pubkey_ed25519: hex_encode(pubkey_bytes),
        signature_valid: true,
        can_rollback,
        counts: SigCounts {
            cpe: kev.product_count() as u32,
            cve: kev.total as u32,
            secrets: secret_rules,
            standards: standards.rules.len() as u32,
        },
        added_kev: 0,
        added_cpe: 0,
        added_secrets: 0,
    }
}

fn status_from_bundle(b: &SigBundleV1, can_rollback: bool, pubkey_bytes: &[u8; 32]) -> SigStatus {
    SigStatus {
        schema: b.schema.clone(),
        version: b.version.clone(),
        updated_at: b.released_at.clone(),
        source: "bundle".into(),
        sha256: b.sha256.clone(),
        pubkey_ed25519: hex_encode(pubkey_bytes),
        signature_valid: true,
        can_rollback,
        counts: b.counts.clone(),
        added_kev: b.kev_additions.len() as u32,
        added_cpe: b.cpe_additions.len() as u32,
        added_secrets: b.secret_additions.len() as u32,
    }
}

/// Reads the current signature status from `<data_dir>/signatures/current.json` (falling back to
/// the embedded builtin catalog if no bundle is installed).
pub fn status(data_dir: &Path) -> SigStatus {
    status_with_pubkey(data_dir, &official_pubkey_bytes())
}

pub(crate) fn status_with_pubkey(data_dir: &Path, pubkey_bytes: &[u8; 32]) -> SigStatus {
    let cur = current_path(data_dir);
    let prev_exists = previous_path(data_dir).is_file();
    if let Ok(raw) = fs::read_to_string(&cur) {
        if let Ok(bundle) = serde_json::from_str::<SigBundleV1>(&raw) {
            if verify_bundle(&bundle, pubkey_bytes).is_ok() {
                return status_from_bundle(&bundle, true, pubkey_bytes);
            }
        }
    }
    builtin_status_for_key(prev_exists, pubkey_bytes)
}

/// Returns the active verified bundle if one is installed on disk.
pub fn active_bundle(data_dir: &Path) -> Option<SigBundleV1> {
    let raw = fs::read_to_string(current_path(data_dir)).ok()?;
    let bundle = serde_json::from_str::<SigBundleV1>(&raw).ok()?;
    verify_bundle(&bundle, &official_pubkey_bytes()).ok()?;
    Some(bundle)
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

/// Returns a KEV catalog extended with entries from an active verified signature bundle (if any).
pub fn active_kev_catalog(data_dir: &Path) -> Option<foca_analysis::kev::KevCatalog> {
    let b = active_bundle(data_dir)?;
    if b.kev_additions.is_empty() {
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
    Some(foca_analysis::kev::KevCatalog::builtin().with_additions(extra))
}

/// Verifies `bundle_json` (`Ed25519` + `SHA-256`) and atomically installs it as `current.json`,
/// rotating any previous `current.json` to `previous.json`.
pub fn import_bundle(data_dir: &Path, bundle_json: &str) -> Result<SigStatus, CmdError> {
    import_bundle_with_pubkey(data_dir, bundle_json, &official_pubkey_bytes())
}

pub(crate) fn import_bundle_with_pubkey(
    data_dir: &Path,
    bundle_json: &str,
    pubkey_bytes: &[u8; 32],
) -> Result<SigStatus, CmdError> {
    let bundle: SigBundleV1 = serde_json::from_str(bundle_json).map_err(|e| {
        CmdError::new(
            "bad_args",
            format!("Некорректный JSON бандла сигнатур: {e}"),
        )
    })?;
    verify_bundle(&bundle, pubkey_bytes)?;
    let dir = sig_dir(data_dir);
    fs::create_dir_all(&dir).map_err(|e| CmdError::new("io", e.to_string()))?;
    let cur = current_path(data_dir);
    let prev = previous_path(data_dir);
    if cur.is_file() {
        let _ = fs::copy(&cur, &prev);
    }
    let tmp = dir.join("current.json.tmp");
    let serialized =
        serde_json::to_vec_pretty(&bundle).map_err(|e| CmdError::new("io", e.to_string()))?;
    fs::write(&tmp, &serialized).map_err(|e| CmdError::new("io", e.to_string()))?;
    fs::rename(&tmp, &cur).map_err(|e| CmdError::new("io", e.to_string()))?;
    Ok(status_from_bundle(&bundle, true, pubkey_bytes))
}

/// Rolls back the signature database to `previous.json` (or to the embedded builtin database if no
/// `previous.json` exists).
pub fn rollback(data_dir: &Path) -> Result<SigStatus, CmdError> {
    rollback_with_pubkey(data_dir, &official_pubkey_bytes())
}

pub(crate) fn rollback_with_pubkey(
    data_dir: &Path,
    pubkey_bytes: &[u8; 32],
) -> Result<SigStatus, CmdError> {
    let cur = current_path(data_dir);
    let prev = previous_path(data_dir);
    if prev.is_file() {
        if let Ok(raw) = fs::read_to_string(&prev) {
            if let Ok(bundle) = serde_json::from_str::<SigBundleV1>(&raw) {
                if verify_bundle(&bundle, pubkey_bytes).is_ok() {
                    fs::rename(&prev, &cur).map_err(|e| CmdError::new("io", e.to_string()))?;
                    return Ok(status_from_bundle(&bundle, true, pubkey_bytes));
                }
            }
        }
        let _ = fs::remove_file(&prev);
    }
    if cur.is_file() {
        fs::remove_file(&cur).map_err(|e| CmdError::new("io", e.to_string()))?;
    }
    Ok(builtin_status_for_key(false, pubkey_bytes))
}

/// Builds a signed sample bundle (`foca-sig-bundle/v1`) for unit tests.
#[cfg(test)]
fn build_signed_test_bundle(version: &str, released_at: &str, seed: &[u8; 32]) -> SigBundleV1 {
    let kev = foca_analysis::kev::KevCatalog::builtin();
    let standards = foca_analysis::standards::Standards::builtin();
    let kev_additions = vec![
        SigKevItem {
            cve: "CVE-2024-38077".into(),
            product_key: "ms_windows".into(),
            vendor: "Microsoft".into(),
            product: "Windows Remote Desktop Licensing Service".into(),
            date_added: released_at.into(),
            ransomware: true,
            name: "Microsoft Windows Remote Desktop Licensing Service RCE".into(),
            fixed_in: Some("10.0.20348.2582".into()),
        },
        SigKevItem {
            cve: "CVE-2024-4577".into(),
            product_key: "php".into(),
            vendor: "PHP".into(),
            product: "PHP CGI".into(),
            date_added: released_at.into(),
            ransomware: true,
            name: "PHP CGI Argument Injection Vulnerability".into(),
            fixed_in: Some("8.3.8".into()),
        },
    ];
    let cpe_additions = vec![
        SigCpeItem {
            cpe_prefix: "cpe:/a:Fortinet:fortios".into(),
            label: "FortiOS".into(),
            latest_ver: Some("7.4.5".into()),
        },
        SigCpeItem {
            cpe_prefix: "cpe:/a:gitlab:gitlab".into(),
            label: "GitLab".into(),
            latest_ver: Some("17.5.2".into()),
        },
    ];
    let secret_additions = vec![SigSecretItem {
        id: "sig_cloudflare_api_token".into(),
        title: "Cloudflare API Token".into(),
        pattern: r"cf_token_[A-Za-z0-9_-]{32,45}".into(),
    }];
    let base_secrets = foca_analysis::secrets::BUILTIN_TOML
        .matches("[[rule]]")
        .count() as u32;
    let mut bundle = SigBundleV1 {
        schema: BUNDLE_SCHEMA.into(),
        version: version.into(),
        released_at: released_at.into(),
        counts: SigCounts {
            cpe: kev.product_count() as u32 + cpe_additions.len() as u32,
            cve: kev.total as u32 + kev_additions.len() as u32,
            secrets: base_secrets + secret_additions.len() as u32,
            standards: standards.rules.len() as u32,
        },
        kev_additions,
        cpe_additions,
        secret_additions,
        sha256: String::new(),
        signature_ed25519: String::new(),
    };
    sign_bundle_with_seed(&mut bundle, seed);
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    fn test_pubkey() -> [u8; 32] {
        let kp = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(kp.public_key().as_ref());
        out
    }

    #[test]
    fn valid_ed25519_bundle_installs_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        assert_ne!(pk, official_pubkey_bytes());
        let st0 = status_with_pubkey(dir.path(), &pk);
        assert_eq!(st0.source, "builtin");
        assert!(!st0.can_rollback);

        let b1 = build_signed_test_bundle("2026.11.22", "2026-11-22", &TEST_SEED);
        let json1 = serde_json::to_string(&b1).unwrap();
        let st1 = import_bundle_with_pubkey(dir.path(), &json1, &pk).unwrap();
        assert_eq!(st1.source, "bundle");
        assert_eq!(st1.version, "2026.11.22");
        assert!(st1.signature_valid);
        assert!(st1.can_rollback);
        assert_eq!(st1.added_kev, 2);
        assert_eq!(st1.added_cpe, 2);
        assert_eq!(st1.added_secrets, 1);

        // The release public key must not accept a test-signed bundle.
        assert!(import_bundle(dir.path(), &json1).is_err());

        // Second bundle rotates first to previous.json.
        let b2 = build_signed_test_bundle("2026.11.23", "2026-11-23", &TEST_SEED);
        let st2 = import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&b2).unwrap(), &pk)
            .unwrap();
        assert_eq!(st2.version, "2026.11.23");

        // Rollback 1 -> 2026.11.22.
        let rb1 = rollback_with_pubkey(dir.path(), &pk).unwrap();
        assert_eq!(rb1.source, "bundle");
        assert_eq!(rb1.version, "2026.11.22");

        // Rollback 2 -> builtin.
        let rb2 = rollback_with_pubkey(dir.path(), &pk).unwrap();
        assert_eq!(rb2.source, "builtin");
        assert!(!rb2.can_rollback);
    }

    #[test]
    fn tampered_payload_or_foreign_signature_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pk = test_pubkey();
        let mut b = build_signed_test_bundle("2026.11.22", "2026-11-22", &TEST_SEED);
        b.counts.cve += 1;
        // Recompute SHA-256 without valid Ed25519 private key -> Ed25519 verify must fail.
        b.sha256 = sha256_hex(&canonical_payload(&b));
        let err = import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&b).unwrap(), &pk)
            .unwrap_err();
        assert_eq!(err.code, "bad_args");
        assert!(err.message.contains("Ed25519"));
        assert_eq!(status_with_pubkey(dir.path(), &pk).source, "builtin");

        // Signed with a foreign Ed25519 seed -> rejected.
        let foreign_seed = [0x99u8; 32];
        let mut foreign = build_signed_test_bundle("2026.11.22", "2026-11-22", &foreign_seed);
        sign_bundle_with_seed(&mut foreign, &foreign_seed);
        let err2 =
            import_bundle_with_pubkey(dir.path(), &serde_json::to_string(&foreign).unwrap(), &pk)
                .unwrap_err();
        assert_eq!(err2.code, "bad_args");
        assert_eq!(status_with_pubkey(dir.path(), &pk).source, "builtin");
    }
}

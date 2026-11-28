//! In-app update from GitHub Releases: version ordering, release selection per build flavor,
//! `SHA256SUMS.txt` parsing and verification of its Ed25519 signature, release note markers and
//! the persisted check state (ETag cache, rate limit backoff).
//!
//! The network side lives in `update.rs`; everything here is pure and unit-tested.
//!
//! Release signature: the maintainer signs `SUMS_DOMAIN || <SHA256SUMS.txt bytes>` with the same
//! Ed25519 key as the signature bundles ([`crate::sigbundle::official_pubkey_bytes`]). The domain
//! prefix keeps a bundle signature from ever verifying as a release signature and vice versa.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::CmdError;

/// GitHub repository the releases come from.
pub const REPO: &str = "SinonApp/FOCA-rs";
/// Release asset with the SHA-256 of every APK (GNU `sha256sum` format).
pub const SUMS_ASSET: &str = "SHA256SUMS.txt";
/// Release asset with the hex Ed25519 signature over [`SUMS_DOMAIN`] followed by [`SUMS_ASSET`].
pub const SIG_ASSET: &str = "SHA256SUMS.txt.sig";
/// Domain separation prefix of the release signature.
pub const SUMS_DOMAIN: &[u8] = b"FOCA-rs release SHA256SUMS v1\n";
/// Seconds between automatic checks.
pub const AUTO_INTERVAL_SECS: i64 = 24 * 3600;
/// Backoff after a rate limit answer without a usable reset time.
pub const DEFAULT_BACKOFF_SECS: i64 = 15 * 60;
/// Largest backoff taken from a server answer (a bogus reset time cannot block checks for days).
pub const MAX_BACKOFF_SECS: i64 = 6 * 3600;

// ---------------------------------------------------------------- versions

/// One dot-separated pre-release identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Alpha(String),
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreId::Num(a), PreId::Num(b)) => a.cmp(b),
            (PreId::Num(_), PreId::Alpha(_)) => Ordering::Less,
            (PreId::Alpha(_), PreId::Num(_)) => Ordering::Greater,
            (PreId::Alpha(a), PreId::Alpha(b)) => a.cmp(b),
        }
    }
}

/// A semantic version (`2.0.0`, `2.0.0-beta.4.1`, an optional leading `v`; build metadata is
/// ignored). Pre-release identifiers compare as in SemVer 2.0: numbers numerically, a shorter
/// list sorts first, and any pre-release sorts before the release itself, so
/// `beta.4 < beta.4.1 < beta.5 < 2.0.0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: [u64; 3],
    pre: Vec<PreId>,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let s = s.split('+').next()?;
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let mut nums = core.split('.');
        let mut out = [0u64; 3];
        for slot in &mut out {
            let part = nums.next()?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *slot = part.parse().ok()?;
        }
        if nums.next().is_some() {
            return None;
        }
        let mut ids = Vec::new();
        if let Some(p) = pre {
            for id in p.split('.') {
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return None;
                }
                ids.push(if id.bytes().all(|b| b.is_ascii_digit()) {
                    PreId::Num(id.parse().ok()?)
                } else {
                    PreId::Alpha(id.to_ascii_lowercase())
                });
            }
        }
        Some(Version {
            core: out,
            pre: ids,
        })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

/// The version of this build (the workspace version).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ---------------------------------------------------------------- releases

/// A release asset from the GitHub API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub url: String,
}

/// A release from `GET /repos/{owner}/{repo}/releases`, reduced to what the update needs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub prerelease: bool,
    pub published_at: String,
    pub html_url: String,
    pub body: String,
    pub assets: Vec<Asset>,
}

/// Parses the GitHub releases list. Drafts and tags that are not app versions (the rolling
/// `signatures` feeds) are skipped.
pub fn parse_releases(json: &str) -> Result<Vec<Release>, CmdError> {
    let v: Value = serde_json::from_str(json).map_err(|e| {
        CmdError::new(
            "update_bad_response",
            format!("Ответ GitHub не разобран: {e}"),
        )
    })?;
    let arr = v.as_array().ok_or_else(|| {
        CmdError::new(
            "update_bad_response",
            "Ответ GitHub не разобран: ожидался список релизов",
        )
    })?;
    let mut out = Vec::new();
    for r in arr {
        if r["draft"].as_bool().unwrap_or(false) {
            continue;
        }
        let tag = r["tag_name"].as_str().unwrap_or_default();
        if !tag.starts_with('v') || Version::parse(tag).is_none() {
            continue;
        }
        let assets = r["assets"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        Some(Asset {
                            name: x["name"].as_str()?.to_string(),
                            size: x["size"].as_u64().unwrap_or(0),
                            url: x["browser_download_url"].as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(Release {
            tag: tag.to_string(),
            version: tag.trim_start_matches('v').to_string(),
            prerelease: r["prerelease"].as_bool().unwrap_or(false),
            published_at: r["published_at"].as_str().unwrap_or_default().to_string(),
            html_url: r["html_url"].as_str().unwrap_or_default().to_string(),
            body: r["body"].as_str().unwrap_or_default().to_string(),
            assets,
        });
    }
    Ok(out)
}

/// Build flavors that ship an APK.
pub const FLAVORS: &[&str] = &["foss", "play"];

/// Release asset name of the APK for a version and flavor.
pub fn apk_asset_name(version: &str, flavor: &str) -> String {
    format!("FOCA-rs-{version}-{flavor}-arm64.apk")
}

/// An available update: the release and the APK of this build's flavor.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub release: Release,
    pub apk: Asset,
}

/// Picks the newest release above `current` that carries the APK of `flavor`. Pre-releases count
/// only with `include_pre`; a release without this flavor's APK is skipped.
pub fn pick_update(
    releases: &[Release],
    current: &str,
    flavor: &str,
    include_pre: bool,
) -> Option<Candidate> {
    let cur = Version::parse(current)?;
    releases
        .iter()
        .filter(|r| include_pre || !r.prerelease)
        .filter_map(|r| {
            let v = Version::parse(&r.version)?;
            if v <= cur || (!include_pre && v.is_prerelease()) {
                return None;
            }
            let want = apk_asset_name(&r.version, flavor);
            let apk = r.assets.iter().find(|a| a.name == want)?.clone();
            Some((
                v,
                Candidate {
                    release: r.clone(),
                    apk,
                },
            ))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, c)| c)
}

// ---------------------------------------------------------------- release note markers

/// Reads an HTML comment marker `<!-- foca:<key> <number> -->` from the release notes.
fn marker(body: &str, key: &str) -> Option<u64> {
    let mut rest = body;
    while let Some(i) = rest.find("<!--") {
        let after = &rest[i + 4..];
        let end = after.find("-->")?;
        let inner = after[..end].trim();
        if let Some(v) = inner
            .strip_prefix("foca:")
            .and_then(|x| x.strip_prefix(key))
            .filter(|x| x.starts_with(char::is_whitespace))
        {
            if let Ok(n) = v.trim().parse() {
                return Some(n);
            }
        }
        rest = &after[end + 3..];
    }
    None
}

/// Project database schema version of the release (`<!-- foca:schema N -->`, added by the
/// release pipeline).
pub fn schema_marker(body: &str) -> Option<u32> {
    marker(body, "schema").and_then(|n| u32::try_from(n).ok())
}

/// Android versionCode of the release (`<!-- foca:version-code N -->`).
pub fn version_code_marker(body: &str) -> Option<u64> {
    marker(body, "version-code")
}

/// Release notes without HTML comments (the markers), trimmed.
pub fn notes_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(i) = rest.find("<!--") {
        out.push_str(&rest[..i]);
        match rest[i..].find("-->") {
            Some(e) => rest = &rest[i + e + 3..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out.trim().replace("\r\n", "\n")
}

// ---------------------------------------------------------------- SHA256SUMS and signature

/// Parses `SHA256SUMS.txt` (`<64 hex>  <name>` or `<64 hex> *<name>` per line, blank lines and
/// `#` comments allowed). Any other line fails the whole file.
pub fn parse_sums(text: &str) -> Result<Vec<(String, String)>, CmdError> {
    let bad = |n: usize| {
        CmdError::new(
            "update_sums_invalid",
            format!("SHA256SUMS.txt: строка {n} не в формате sha256sum"),
        )
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, rest) = line.split_once(' ').ok_or_else(|| bad(i + 1))?;
        let name = rest
            .strip_prefix(' ')
            .or_else(|| rest.strip_prefix('*'))
            .ok_or_else(|| bad(i + 1))?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) || name.is_empty() {
            return Err(bad(i + 1));
        }
        out.push((hash.to_ascii_lowercase(), name.to_string()));
    }
    if out.is_empty() {
        return Err(CmdError::new("update_sums_invalid", "SHA256SUMS.txt пуст"));
    }
    Ok(out)
}

/// The expected SHA-256 of `name` from a parsed `SHA256SUMS.txt`. Two different lines for the
/// same name are refused.
pub fn expected_sha256(sums: &[(String, String)], name: &str) -> Result<String, CmdError> {
    let mut found: Option<&str> = None;
    for (h, n) in sums {
        if n == name {
            if found.is_some_and(|f| f != h) {
                return Err(CmdError::new(
                    "update_sums_invalid",
                    format!("SHA256SUMS.txt: разные суммы для {name}"),
                ));
            }
            found = Some(h);
        }
    }
    found.map(str::to_string).ok_or_else(|| {
        CmdError::new(
            "update_sums_missing",
            format!("SHA256SUMS.txt не содержит {name}"),
        )
    })
}

fn signed_message(sums: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SUMS_DOMAIN.len() + sums.len());
    m.extend_from_slice(SUMS_DOMAIN);
    m.extend_from_slice(sums);
    m
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Verifies `SHA256SUMS.txt.sig` (128 hex characters, surrounding whitespace allowed) over the
/// exact `SHA256SUMS.txt` bytes with the domain prefix.
pub fn verify_sums_signature(sums: &[u8], sig: &str, pubkey: &[u8; 32]) -> Result<(), CmdError> {
    let raw = hex_decode(sig.trim())
        .filter(|b| b.len() == 64)
        .ok_or_else(|| {
            CmdError::new(
                "update_sig_invalid",
                "SHA256SUMS.txt.sig: ожидалось 128 hex-символов",
            )
        })?;
    UnparsedPublicKey::new(&ED25519, pubkey)
        .verify(&signed_message(sums), &raw)
        .map_err(|_| {
            CmdError::new(
                "update_sig_mismatch",
                "Подпись SHA256SUMS.txt не прошла проверку ключом приложения",
            )
        })
}

/// Signs `SHA256SUMS.txt` bytes (hex signature with a trailing newline). The release script
/// produces the same bytes with OpenSSL; this is for tests and tooling.
pub fn sign_sums(sums: &[u8], seed: &[u8; 32]) -> Result<String, CmdError> {
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| CmdError::new("bad_args", "некорректный Ed25519 seed"))?;
    Ok(format!(
        "{}\n",
        hex_encode(kp.sign(&signed_message(sums)).as_ref())
    ))
}

// ---------------------------------------------------------------- rate limits

/// Seconds to wait after a GitHub API refusal, or `None` when the status is not a rate limit.
/// 429 and a 403 with `x-ratelimit-remaining: 0` or `retry-after` are rate limits; the wait comes
/// from `retry-after` or `x-ratelimit-reset` (epoch seconds), capped at [`MAX_BACKOFF_SECS`].
pub fn rate_limit_wait(
    status: u16,
    header: impl Fn(&str) -> Option<String>,
    now_epoch: i64,
) -> Option<i64> {
    let retry_after = header("retry-after").and_then(|v| v.trim().parse::<i64>().ok());
    let remaining = header("x-ratelimit-remaining").and_then(|v| v.trim().parse::<i64>().ok());
    let reset = header("x-ratelimit-reset").and_then(|v| v.trim().parse::<i64>().ok());
    let limited =
        status == 429 || (status == 403 && (remaining == Some(0) || retry_after.is_some()));
    if !limited {
        return None;
    }
    let wait = retry_after
        .or_else(|| reset.map(|r| r - now_epoch))
        .filter(|w| *w > 0)
        .unwrap_or(DEFAULT_BACKOFF_SECS);
    Some(wait.clamp(1, MAX_BACKOFF_SECS))
}

// ---------------------------------------------------------------- download job

/// The running or last download (`update_status.download`), kept by the engine.
#[derive(Default)]
pub(crate) struct UpdateJob {
    pub cancel: Option<tokio_util::sync::CancellationToken>,
    pub progress: Value,
}

// ---------------------------------------------------------------- persisted state

/// Check state kept in `<data>/update/state.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    /// ETag of the last full releases answer and that answer (sent back as `If-None-Match`).
    #[serde(default)]
    pub etag: String,
    #[serde(default)]
    pub releases_json: String,
    /// Local ISO time of the last finished check (success or failure).
    #[serde(default)]
    pub checked_at: String,
    /// Epoch seconds of the last check (drives the daily automatic check).
    #[serde(default)]
    pub checked_epoch: i64,
    /// No API request before this epoch second (rate limit backoff).
    #[serde(default)]
    pub backoff_until: i64,
    /// Error of the last check: `{ code, message }`.
    #[serde(default)]
    pub last_error: Option<Value>,
}

pub fn state_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("update")
}

fn state_path(data_dir: &Path) -> PathBuf {
    state_dir(data_dir).join("state.json")
}

pub fn read_state(data_dir: &Path) -> State {
    std::fs::read(state_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn write_state(data_dir: &Path, st: &State) -> Result<(), CmdError> {
    std::fs::create_dir_all(state_dir(data_dir))?;
    let tmp = state_dir(data_dir).join("state.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(st)?)?;
    std::fs::rename(tmp, state_path(data_dir))?;
    Ok(())
}

/// Whether an automatic check is due (`interval` seconds since the last one).
pub fn auto_due(st: &State, now_epoch: i64) -> bool {
    st.checked_epoch <= 0 || now_epoch - st.checked_epoch >= AUTO_INTERVAL_SECS
}

/// Download directory inside the app cache.
pub fn download_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join("update")
}

/// Cleans the download directory. With `keep` (a download in progress) every file of another
/// asset goes; without it only files of versions not newer than the running one (installed or
/// stale) and unrecognised files, so a partial download of a newer version can still resume.
pub fn prune_downloads(cache_dir: &Path, current: &str, keep: Option<&str>) {
    let Ok(rd) = std::fs::read_dir(download_dir(cache_dir)) else {
        return;
    };
    let cur = Version::parse(current);
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let stale = match keep {
            Some(k) => !name.starts_with(k),
            None => {
                let ver = name
                    .strip_prefix("FOCA-rs-")
                    .and_then(|r| r.split("-foss-").next())
                    .and_then(|r| r.split("-play-").next())
                    .and_then(Version::parse);
                match (&ver, &cur) {
                    (Some(v), Some(c)) => v <= c,
                    _ => true,
                }
            }
        };
        if stale {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("parse {s}"))
    }

    #[test]
    fn version_order_table() {
        let ordered = [
            "1.9.9",
            "2.0.0-alpha",
            "2.0.0-alpha.1",
            "2.0.0-beta",
            "2.0.0-beta.2",
            "2.0.0-beta.4",
            "2.0.0-beta.4.1",
            "2.0.0-beta.4.2",
            "2.0.0-beta.5",
            "2.0.0-beta.10",
            "2.0.0-rc.1",
            "2.0.0",
            "2.0.1",
            "2.1.0",
            "10.0.0",
        ];
        for w in ordered.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
            assert!(v(w[1]) > v(w[0]), "{} > {}", w[1], w[0]);
        }
        assert_eq!(v("v2.0.0-beta.4.1"), v("2.0.0-beta.4.1"));
        assert_eq!(v("2.0.0+build.7"), v("2.0.0"));
        assert_eq!(v("2.0.0-BETA.5"), v("2.0.0-beta.5"));
        for bad in [
            "",
            "2",
            "2.0",
            "2.0.0.0",
            "x.0.0",
            "2.0.0-",
            "2.0.0-beta..1",
            "signatures-v3",
            "2.0.0-be ta",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must not parse");
        }
        assert!(v("2.0.0-beta.1").is_prerelease());
        assert!(!v("2.0.0").is_prerelease());
    }

    fn rel(tag: &str, pre: bool, flavors: &[&str]) -> Release {
        let ver = tag.trim_start_matches('v');
        Release {
            tag: tag.into(),
            version: ver.into(),
            prerelease: pre,
            published_at: "2026-12-01T10:00:00Z".into(),
            html_url: String::new(),
            body: String::new(),
            assets: flavors
                .iter()
                .map(|f| Asset {
                    name: apk_asset_name(ver, f),
                    size: 100,
                    url: format!("https://github.com/{REPO}/releases/download/{tag}/x-{f}"),
                })
                .chain(std::iter::once(Asset {
                    name: SUMS_ASSET.into(),
                    size: 1,
                    url: "u".into(),
                }))
                .collect(),
        }
    }

    #[test]
    fn asset_selection_per_flavor_and_channel() {
        let rs = vec![
            rel("v2.0.0-beta.4.1", true, &["foss", "play"]),
            rel("v2.0.0-beta.5", true, &["foss", "play"]),
            rel("v2.0.0-beta.6", true, &["play"]),
            rel("v1.9.0", false, &["foss", "play"]),
        ];
        let c = pick_update(&rs, "2.0.0-beta.4.1", "foss", true).unwrap();
        assert_eq!(c.release.tag, "v2.0.0-beta.5");
        assert_eq!(c.apk.name, "FOCA-rs-2.0.0-beta.5-foss-arm64.apk");
        let c = pick_update(&rs, "2.0.0-beta.4.1", "play", true).unwrap();
        assert_eq!(c.apk.name, "FOCA-rs-2.0.0-beta.6-play-arm64.apk");
        // Stable channel: no pre-release offered, and the only stable one is older.
        assert!(pick_update(&rs, "2.0.0-beta.4.1", "foss", false).is_none());
        // Up to date.
        assert!(pick_update(&rs, "2.0.0-beta.6", "play", true).is_none());
        // Unknown flavor gets nothing.
        assert!(pick_update(&rs, "2.0.0-beta.4", "x", true).is_none());
        // A stable release marked prerelease=false but with a pre-release version still needs the toggle.
        let odd = vec![rel("v2.0.0-beta.9", false, &["foss"])];
        assert!(pick_update(&odd, "2.0.0-beta.4", "foss", false).is_none());
        let stable = vec![rel("v2.0.0", false, &["foss"])];
        assert_eq!(
            pick_update(&stable, "2.0.0-beta.4", "foss", false)
                .unwrap()
                .release
                .version,
            "2.0.0"
        );
    }

    #[test]
    fn releases_parse_skips_drafts_and_feed_tags() {
        let json = r#"[
          {"tag_name":"signatures-v3","prerelease":true,"draft":false,"assets":[]},
          {"tag_name":"v2.0.0-beta.6","prerelease":true,"draft":true,"assets":[]},
          {"tag_name":"v2.0.0-beta.5","prerelease":true,"draft":false,"published_at":"2026-12-01T10:00:00Z",
           "html_url":"https://github.com/SinonApp/FOCA-rs/releases/tag/v2.0.0-beta.5","body":"Notes",
           "assets":[{"name":"SHA256SUMS.txt","size":208,"browser_download_url":"https://github.com/a"}]}
        ]"#;
        let rs = parse_releases(json).unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].version, "2.0.0-beta.5");
        assert_eq!(rs[0].assets[0].size, 208);
        assert_eq!(
            parse_releases("{}").unwrap_err().code,
            "update_bad_response"
        );
        assert!(parse_releases("<html>").is_err());
    }

    #[test]
    fn markers_and_notes() {
        let body = "Text\r\n<!-- foca:schema 12 -->\n<!-- foca:version-code 2000008 -->\n<!-- other -->\n## Fixed\n- a";
        assert_eq!(schema_marker(body), Some(12));
        assert_eq!(version_code_marker(body), Some(2000008));
        assert_eq!(notes_text(body), "Text\n\n\n\n## Fixed\n- a");
        assert_eq!(schema_marker("<!-- foca:schemas 3 -->"), None);
        assert_eq!(schema_marker("<!-- foca:schema x -->"), None);
        assert_eq!(schema_marker("no markers"), None);
        assert_eq!(notes_text("a <!-- unterminated"), "a");
    }

    const SUMS: &str = "925413d8010149143c58c8333ce18540b01772bc4d822e6d49cedda92cf180bd  FOCA-rs-2.0.0-beta.4.1-play-arm64.apk\n1548a9a25a4bc1d6774c80f636babe47a250108c41adb7c00e5d169a9d91126c  FOCA-rs-2.0.0-beta.4.1-foss-arm64.apk\n";

    #[test]
    fn sums_parsing() {
        let s = parse_sums(SUMS).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(
            expected_sha256(&s, "FOCA-rs-2.0.0-beta.4.1-foss-arm64.apk").unwrap(),
            "1548a9a25a4bc1d6774c80f636babe47a250108c41adb7c00e5d169a9d91126c"
        );
        assert_eq!(
            expected_sha256(&s, "other.apk").unwrap_err().code,
            "update_sums_missing"
        );
        // Binary marker, CRLF, comments and upper-case hex.
        let alt = "# sums\r\n1548A9A25A4BC1D6774C80F636BABE47A250108C41ADB7C00E5D169A9D91126C *a.apk\r\n\r\n";
        let s = parse_sums(alt).unwrap();
        assert_eq!(s[0].1, "a.apk");
        assert!(s[0].0.starts_with("1548a9"));
        for bad in [
            "",
            "abc  a.apk",
            "1548a9a25a4bc1d6774c80f636babe47a250108c41adb7c00e5d169a9d91126c a.apk",
            "1548a9a25a4bc1d6774c80f636babe47a250108c41adb7c00e5d169a9d91126c",
            "zz48a9a25a4bc1d6774c80f636babe47a250108c41adb7c00e5d169a9d91126c  a.apk",
        ] {
            assert!(parse_sums(bad).is_err(), "{bad:?}");
        }
        let dup = format!("{}  a.apk\n{}  a.apk\n", "1".repeat(64), "2".repeat(64));
        assert_eq!(
            expected_sha256(&parse_sums(&dup).unwrap(), "a.apk")
                .unwrap_err()
                .code,
            "update_sums_invalid"
        );
    }

    fn pk_of(seed: &[u8; 32]) -> [u8; 32] {
        use ring::signature::KeyPair;
        let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        kp.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn signature_ok_tampered_and_wrong_domain() {
        let seed = [7u8; 32];
        let pk = pk_of(&seed);
        let sig = sign_sums(SUMS.as_bytes(), &seed).unwrap();
        assert_eq!(sig.trim().len(), 128);
        verify_sums_signature(SUMS.as_bytes(), &sig, &pk).unwrap();
        // One changed byte in the sums.
        let tampered = SUMS.replacen("9254", "9255", 1);
        assert_eq!(
            verify_sums_signature(tampered.as_bytes(), &sig, &pk)
                .unwrap_err()
                .code,
            "update_sig_mismatch"
        );
        // Another key.
        assert_eq!(
            verify_sums_signature(SUMS.as_bytes(), &sig, &pk_of(&[8u8; 32]))
                .unwrap_err()
                .code,
            "update_sig_mismatch"
        );
        // A plain signature over the bytes without the domain prefix (the bundle style) fails.
        let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let plain = hex_encode(kp.sign(SUMS.as_bytes()).as_ref());
        assert_eq!(
            verify_sums_signature(SUMS.as_bytes(), &plain, &pk)
                .unwrap_err()
                .code,
            "update_sig_mismatch"
        );
        // A signature over another domain.
        let mut other = b"FOCA-rs signature bundle v1\n".to_vec();
        other.extend_from_slice(SUMS.as_bytes());
        let foreign = hex_encode(kp.sign(&other).as_ref());
        assert!(verify_sums_signature(SUMS.as_bytes(), &foreign, &pk).is_err());
        // Malformed signature files.
        for bad in ["", "zz", &"a".repeat(127), &"a".repeat(130)] {
            assert_eq!(
                verify_sums_signature(SUMS.as_bytes(), bad, &pk)
                    .unwrap_err()
                    .code,
                "update_sig_invalid"
            );
        }
    }

    /// Output of `scripts/sign-release.sh sign` with the official key (OpenSSL) for two dummy
    /// files: the app must accept it, so the script and the verifier agree byte for byte.
    #[test]
    fn release_script_output_verifies_with_the_embedded_key() {
        let sums = "db273887992f4092e9c1a4cac924f3b962286a429104f703f42a5c6dc15a90fe  FOCA-rs-0.0.1-test-foss-arm64.apk\n8359a59b7127beceab35cf5c02b2494c704bc857168d2d89017a979bf11fd87c  FOCA-rs-0.0.1-test-play-arm64.apk\n";
        let sig = "2e1c9296fc0575369273a100d4a178ca8929afb2faf6808310a53f0eed08eb4033aaf880c21cc210a8b270ba35853b7d440d5dfa2241b2746beb46eeec8c3d07\n";
        let pk = crate::sigbundle::official_pubkey_bytes();
        verify_sums_signature(sums.as_bytes(), sig, &pk).unwrap();
        assert!(verify_sums_signature(sums.replace("\n", "\r\n").as_bytes(), sig, &pk).is_err());
        assert_eq!(parse_sums(sums).unwrap().len(), 2);
    }

    #[test]
    fn rate_limit_classification() {
        let h = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let now = 1_800_000_000;
        assert_eq!(
            rate_limit_wait(
                403,
                h(&[
                    ("x-ratelimit-remaining", "0"),
                    ("x-ratelimit-reset", "1800000600")
                ]),
                now
            ),
            Some(600)
        );
        assert_eq!(
            rate_limit_wait(429, h(&[("retry-after", "42")]), now),
            Some(42)
        );
        assert_eq!(
            rate_limit_wait(429, h(&[]), now),
            Some(DEFAULT_BACKOFF_SECS)
        );
        assert_eq!(
            rate_limit_wait(
                403,
                h(&[
                    ("x-ratelimit-remaining", "0"),
                    ("x-ratelimit-reset", "1900000000")
                ]),
                now
            ),
            Some(MAX_BACKOFF_SECS)
        );
        // A plain 403 (blocked, not limited) and other statuses are not rate limits.
        assert_eq!(
            rate_limit_wait(403, h(&[("x-ratelimit-remaining", "12")]), now),
            None
        );
        assert_eq!(rate_limit_wait(500, h(&[]), now), None);
    }

    #[test]
    fn state_roundtrip_and_auto_due() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_state(dir.path()), State::default());
        let st = State {
            etag: "W/\"x\"".into(),
            checked_epoch: 1000,
            ..Default::default()
        };
        write_state(dir.path(), &st).unwrap();
        assert_eq!(read_state(dir.path()), st);
        assert!(!auto_due(&st, 1000 + AUTO_INTERVAL_SECS - 1));
        assert!(auto_due(&st, 1000 + AUTO_INTERVAL_SECS));
        assert!(auto_due(&State::default(), 5));
    }

    #[test]
    fn prune_keeps_only_newer_downloads() {
        let dir = tempfile::tempdir().unwrap();
        let d = download_dir(dir.path());
        std::fs::create_dir_all(&d).unwrap();
        for n in [
            "FOCA-rs-2.0.0-beta.4-foss-arm64.apk",
            "FOCA-rs-2.0.0-beta.5-foss-arm64.apk",
            "FOCA-rs-2.0.0-beta.6-play-arm64.apk.part",
            "junk.bin",
        ] {
            std::fs::write(d.join(n), b"x").unwrap();
        }
        let left = || {
            let mut v: Vec<String> = std::fs::read_dir(&d)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        prune_downloads(dir.path(), "2.0.0-beta.4.1", None);
        assert_eq!(
            left(),
            [
                "FOCA-rs-2.0.0-beta.5-foss-arm64.apk",
                "FOCA-rs-2.0.0-beta.6-play-arm64.apk.part"
            ]
        );
        prune_downloads(
            dir.path(),
            "2.0.0-beta.4.1",
            Some("FOCA-rs-2.0.0-beta.6-play-arm64.apk"),
        );
        assert_eq!(left(), ["FOCA-rs-2.0.0-beta.6-play-arm64.apk.part"]);
    }
}

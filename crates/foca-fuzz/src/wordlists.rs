//! Wordlists: small built-in lists (SecLists, MIT, gzip-compressed), a registry of large
//! lists downloaded on demand (pinned commit, size, SHA-256), import of custom lists and
//! sanitization.
//!
//! Sanitization drops anything resembling obfuscation, evasion or exploitation: `..`, `%`,
//! `?`, `;`, `\`, whitespace, control characters, `://` schemes, and `.git/*` except
//! `.git/HEAD` (repositories are never dumped; only the presence and format of HEAD is
//! checked).

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Pinned SecLists commit the built-in lists and the registry come from.
pub const SECLISTS_COMMIT: &str = "1a89b46c204032247592a1626e29f841cb0fe2a5";

/// A built-in wordlist.
#[derive(Debug, Clone, Copy)]
pub struct Builtin {
    pub id: &'static str,
    /// Path in the SecLists repository.
    pub source: &'static str,
    gz: &'static [u8],
}

macro_rules! builtin {
    ($id:literal, $src:literal, $file:literal) => {
        Builtin {
            id: $id,
            source: $src,
            gz: include_bytes!(concat!("../wordlists/", $file)),
        }
    };
}

pub const BUILTIN: &[Builtin] = &[
    builtin!(
        "common",
        "Discovery/Web-Content/common.txt",
        "common.txt.gz"
    ),
    builtin!(
        "quickhits",
        "Discovery/Web-Content/quickhits.txt",
        "quickhits.txt.gz"
    ),
    builtin!(
        "db-backups",
        "Discovery/Web-Content/Common-DB-Backups.txt",
        "Common-DB-Backups.txt.gz"
    ),
    builtin!(
        "raft-small-files",
        "Discovery/Web-Content/raft-small-files.txt",
        "raft-small-files.txt.gz"
    ),
    builtin!(
        "raft-small-directories",
        "Discovery/Web-Content/raft-small-directories.txt",
        "raft-small-directories.txt.gz"
    ),
    builtin!(
        "dsstore",
        "Discovery/Web-Content/dsstorewordlist.txt",
        "dsstorewordlist.txt.gz"
    ),
    builtin!(
        "dns-top5000",
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "subdomains-top1million-5000.txt.gz"
    ),
    builtin!(
        "ext-most-common",
        "Fuzzing/extensions-most-common.fuzz.txt",
        "extensions-most-common.fuzz.txt.gz"
    ),
    builtin!(
        "ext-compressed",
        "Fuzzing/extensions-compressed.fuzz.txt",
        "extensions-compressed.fuzz.txt.gz"
    ),
    builtin!(
        "ext-all",
        "Fuzzing/file-extensions-lower-case.txt",
        "file-extensions-lower-case.txt.gz"
    ),
    builtin!(
        "cms-wordpress",
        "Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "cms-wordpress.fuzz.txt.gz"
    ),
    builtin!(
        "cms-sharepoint",
        "Discovery/Web-Content/CMS/Sharepoint.txt",
        "cms-sharepoint.txt.gz"
    ),
    builtin!(
        "cms-joomla",
        "Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
        "cms-joomla-plugins.fuzz.txt.gz"
    ),
    builtin!(
        "cms-drupal",
        "Discovery/Web-Content/CMS/drupal-themes.fuzz.txt",
        "cms-drupal-themes.fuzz.txt.gz"
    ),
];

/// A large wordlist downloaded on demand (the request goes to GitHub, not the target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteList {
    pub id: &'static str,
    pub source: &'static str,
    pub size: u64,
    pub lines: u64,
    pub sha256: &'static str,
}

impl RemoteList {
    /// Returns the raw.githubusercontent.com URL at the pinned commit.
    pub fn url(&self) -> String {
        format!(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/{SECLISTS_COMMIT}/{}",
            self.source
        )
    }
}

/// The registry (sizes and SHA-256 computed from the files at [`SECLISTS_COMMIT`]).
pub const REGISTRY: &[RemoteList] = &[
    RemoteList {
        id: "dns-top20000",
        source: "Discovery/DNS/subdomains-top1million-20000.txt",
        size: 135_562,
        lines: 20_000,
        sha256: "685fad386d19c3b7ecbcd18645606bc5c47a3b2339fa3d79f44c46bd9e79c1ef",
    },
    RemoteList {
        id: "dns-top110000",
        source: "Discovery/DNS/subdomains-top1million-110000.txt",
        size: 1_311_067,
        lines: 110_000,
        sha256: "7b8359732bdee838ecdb9ef2cd3bb9a792347dab0457fd9b33a9b152d8dc238d",
    },
    RemoteList {
        id: "raft-medium-files",
        source: "Discovery/Web-Content/raft-medium-files.txt",
        size: 224_381,
        lines: 17_129,
        sha256: "0a0ae977d8227256d4c4f3a2b96ddbe620c37bba861fe3d28eb529e1aa929e14",
    },
    RemoteList {
        id: "raft-medium-directories",
        source: "Discovery/Web-Content/raft-medium-directories.txt",
        size: 250_427,
        lines: 29_999,
        sha256: "a9626959f818d9e198259665c5a88053b7b061c538f46da215d172bcba305fe9",
    },
    RemoteList {
        id: "dirbuster-small",
        source: "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
        size: 725_433,
        lines: 87_663,
        sha256: "2e58212afcc76205e1274e47e22e2550a8ae8a6bd40b893716d9279aca817b60",
    },
    RemoteList {
        id: "dirbuster-medium",
        source: "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
        size: 1_979_956,
        lines: 220_559,
        sha256: "d7619fe257485f3be56316c888e7392b2a0b1d4fce3593d298e8ab604118eaa7",
    },
    RemoteList {
        id: "cms-wordpress-trickest",
        source: "Discovery/Web-Content/CMS/trickest-cms-wordlist/wordpress.txt",
        size: 198_065,
        lines: 3_686,
        sha256: "012d79ed83be25f2c32cc766265d30f12fa6b4aba550c122f810c6dfdf0806c6",
    },
    RemoteList {
        id: "cms-joomla-trickest",
        source: "Discovery/Web-Content/CMS/trickest-cms-wordlist/joomla.txt",
        size: 294_415,
        lines: 5_501,
        sha256: "401670f03b1fac8528af00886b25526db902a7b63ed8fe5212852767c222caae",
    },
    RemoteList {
        id: "cms-drupal-trickest",
        source: "Discovery/Web-Content/CMS/trickest-cms-wordlist/drupal.txt",
        size: 1_094_827,
        lines: 15_576,
        sha256: "9a017ca11b702eef0d298c216c96742b920a955c313e540eda1e2d4ceb22767a",
    },
    RemoteList {
        id: "cms-wp-plugins",
        source: "Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
        size: 505_299,
        lines: 13_370,
        sha256: "290fa56ee714a093ebec8565e686077aa30da7684d35f70bb2e4720b1029d77d",
    },
];

/// Wordlist error.
#[derive(Debug, thiserror::Error)]
pub enum WordlistError {
    #[error("нет словаря «{0}»")]
    Unknown(String),
    #[error("ввод-вывод: {0}")]
    Io(#[from] std::io::Error),
    #[error("словарь слишком большой ({0} байт, предел {1})")]
    TooLarge(u64, u64),
    #[error("контрольная сумма не совпала: ожидалось {expected}, получено {got}")]
    Checksum { expected: String, got: String },
    #[error("сеть: {0}")]
    Net(#[from] foca_net::NetError),
}

/// A loaded wordlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Wordlist {
    pub id: String,
    pub words: Vec<String>,
    /// Entries dropped by sanitization.
    pub dropped: usize,
}

impl Wordlist {
    pub fn from_words(id: &str, words: impl IntoIterator<Item = String>) -> Wordlist {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut dropped = 0;
        for w in words {
            match sanitize_word(&w) {
                Some(s) => {
                    if seen.insert(s.clone()) {
                        out.push(s);
                    }
                }
                None => {
                    if !w.trim().is_empty() && !w.trim_start().starts_with('#') {
                        dropped += 1;
                    }
                }
            }
        }
        Wordlist {
            id: id.to_string(),
            words: out,
            dropped,
        }
    }

    pub fn from_text(id: &str, text: &str) -> Wordlist {
        Wordlist::from_words(id, text.lines().map(str::to_string))
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn take(mut self, n: usize) -> Wordlist {
        self.words.truncate(n);
        self
    }
}

/// Sanitizes a wordlist entry; `None` means drop it.
pub fn sanitize_word(w: &str) -> Option<String> {
    let t = w.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let t = t.trim_start_matches('/');
    if t.is_empty() || t.len() > 200 {
        return None;
    }
    let bad = t.contains("..")
        || t.contains("://")
        || t.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || is_invisible(c)
                || matches!(
                    c,
                    '%' | '?'
                        | ';'
                        | '\\'
                        | '#'
                        | '<'
                        | '>'
                        | '"'
                        | '\''
                        | '`'
                        | '{'
                        | '}'
                        | '|'
                        | '^'
                )
        });
    if bad {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with(".git/") && lower != ".git/head" {
        return None;
    }
    if lower == ".git/head" {
        return Some(".git/HEAD".to_string());
    }
    Some(t.to_string())
}

/// Invisible formatting characters (LRM/RLM, zero-width, BOM, bidi), a sign of garbage or
/// obfuscation.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{00ad}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{feff}')
}

/// Returns a built-in wordlist by id (SecLists lists are English: ASCII only, no homoglyphs).
///
/// # Errors
///
/// Returns a [`WordlistError`] if the id is unknown or the embedded data cannot be read.
pub fn builtin(id: &str) -> Result<Wordlist, WordlistError> {
    let b = BUILTIN
        .iter()
        .find(|b| b.id == id)
        .ok_or_else(|| WordlistError::Unknown(id.to_string()))?;
    let mut s = String::new();
    flate2::read::GzDecoder::new(b.gz).read_to_string(&mut s)?;
    let total = s.lines().filter(|l| !l.trim().is_empty()).count();
    let ascii = s.lines().filter(|l| l.is_ascii()).map(str::to_string);
    let mut w = Wordlist::from_words(b.id, ascii);
    w.dropped = total.saturating_sub(w.words.len());
    Ok(w)
}

/// Returns the extensions (without the dot) from a built-in list such as `ext-most-common`.
///
/// # Errors
///
/// Returns a [`WordlistError`] if the id is unknown or the embedded data cannot be read.
pub fn builtin_extensions(id: &str) -> Result<Vec<String>, WordlistError> {
    Ok(builtin(id)?
        .words
        .into_iter()
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .filter(|e| !e.is_empty() && !e.contains('/'))
        .collect())
}

/// Returns the total size of the compressed built-in wordlists.
pub fn builtin_compressed_size() -> usize {
    BUILTIN.iter().map(|b| b.gz.len()).sum()
}

/// Imports a custom wordlist from a file, subject to a size limit.
///
/// # Errors
///
/// Returns a [`WordlistError`] if the file cannot be read or exceeds `max_bytes`.
pub fn import_file(path: &Path, max_bytes: u64) -> Result<Wordlist, WordlistError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        return Err(WordlistError::TooLarge(meta.len(), max_bytes));
    }
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    let id = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "custom".into());
    Ok(Wordlist::from_text(&id, &text))
}

/// Returns the path of a downloaded large wordlist in the app directory.
pub fn remote_path(dir: &Path, l: &RemoteList) -> PathBuf {
    dir.join(format!("{}.txt", l.id))
}

/// Returns the SHA-256 digest as hex.
pub fn sha256_hex(b: &[u8]) -> String {
    let d = Sha256::digest(b);
    d.iter().map(|x| format!("{x:02x}")).collect()
}

/// Downloads a large wordlist (`Access::Passive`, from GitHub rather than the target) and
/// verifies its size and SHA-256. `url_override` points to a mirror for offline tests.
pub async fn download(
    net: &foca_net::NetClient,
    l: &RemoteList,
    dir: &Path,
    url_override: Option<&str>,
) -> Result<PathBuf, WordlistError> {
    let url = url_override.map(str::to_string).unwrap_or_else(|| l.url());
    let req = foca_net::NetRequest::get(&url, "wordlist", foca_net::Access::Passive)?;
    let resp = net.send(req).await?.ensure_success()?;
    let body = resp.bytes_limited(l.size + 1).await?;
    if body.len() as u64 != l.size {
        return Err(WordlistError::TooLarge(body.len() as u64, l.size));
    }
    let got = sha256_hex(&body);
    if got != l.sha256 {
        return Err(WordlistError::Checksum {
            expected: l.sha256.to_string(),
            got,
        });
    }
    std::fs::create_dir_all(dir)?;
    let p = remote_path(dir, l);
    let tmp = p.with_extension("part");
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &p)?;
    Ok(p)
}

/// Loads a downloaded wordlist, re-verifying its SHA-256.
///
/// # Errors
///
/// Returns a [`WordlistError`] if the file is missing, unreadable or fails verification.
pub fn load_remote(dir: &Path, id: &str) -> Result<Wordlist, WordlistError> {
    let l = REGISTRY
        .iter()
        .find(|l| l.id == id)
        .ok_or_else(|| WordlistError::Unknown(id.to_string()))?;
    let b = std::fs::read(remote_path(dir, l))?;
    let got = sha256_hex(&b);
    if got != l.sha256 {
        return Err(WordlistError::Checksum {
            expected: l.sha256.to_string(),
            got,
        });
    }
    Ok(Wordlist::from_text(l.id, &String::from_utf8_lossy(&b)))
}

/// Returns a wordlist by id, built-in or downloaded.
///
/// # Errors
///
/// Returns a [`WordlistError`] if the list is unknown or cannot be loaded.
pub fn resolve(id: &str, dir: Option<&Path>) -> Result<Wordlist, WordlistError> {
    if BUILTIN.iter().any(|b| b.id == id) {
        return builtin(id);
    }
    match dir {
        Some(d) => load_remote(d, id),
        None => Err(WordlistError::Unknown(id.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtins_decode_and_budget() {
        for b in BUILTIN {
            let w = builtin(b.id).unwrap();
            assert!(!w.is_empty(), "{}", b.id);
        }
        assert!(builtin_compressed_size() <= 300 * 1024);
        let common = builtin("common").unwrap();
        assert!(common.len() > 4000, "{}", common.len());
    }

    #[test]
    fn quickhits_sanitized() {
        let q = builtin("quickhits").unwrap();
        assert!(q.words.iter().any(|w| w == ".git/HEAD"));
        assert!(q.words.iter().any(|w| w == ".DS_Store"));
        assert!(q.words.iter().any(|w| w == ".env"));
        assert!(!q
            .words
            .iter()
            .any(|w| w.starts_with(".git/") && w != ".git/HEAD"));
        assert!(!q
            .words
            .iter()
            .any(|w| w.contains('%') || w.contains('?') || w.contains("..")));
        assert!(q.words.iter().all(|w| w.is_ascii()));
        assert!(q.dropped > 0);
    }

    #[test]
    fn sanitize_rules() {
        assert_eq!(sanitize_word("/admin/"), Some("admin/".into()));
        assert_eq!(sanitize_word("a%2e%2e"), None);
        assert_eq!(sanitize_word("x?y=1"), None);
        assert_eq!(sanitize_word("../etc/passwd"), None);
        assert_eq!(sanitize_word("New Folder"), None);
        assert_eq!(sanitize_word(".git/config"), None);
        assert_eq!(sanitize_word("# comment"), None);
        assert_eq!(sanitize_word("password.log\u{200e}"), None);
        assert_eq!(sanitize_word("звіт_2024.pdf"), Some("звіт_2024.pdf".into()));
        assert_eq!(sanitize_word("password.log\u{200e}"), None);
        assert_eq!(sanitize_word("звіт_2024.pdf"), Some("звіт_2024.pdf".into()));
    }

    #[test]
    fn extensions_and_import() {
        let e = builtin_extensions("ext-most-common").unwrap();
        assert!(e.contains(&"pdf".to_string()) && e.contains(&"docx".to_string()));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mine.txt");
        std::fs::write(&p, "a\nb\n\n# c\nb\n../x\n").unwrap();
        let w = import_file(&p, 1024).unwrap();
        assert_eq!(w.words, vec!["a", "b"]);
        assert_eq!(w.dropped, 1);
        assert!(matches!(
            import_file(&p, 3),
            Err(WordlistError::TooLarge(..))
        ));
    }

    #[test]
    fn registry_urls_pinned() {
        for l in REGISTRY {
            assert!(l.url().contains(SECLISTS_COMMIT));
            assert_eq!(l.sha256.len(), 64);
        }
    }
}

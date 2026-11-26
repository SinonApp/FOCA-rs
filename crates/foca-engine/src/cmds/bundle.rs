//! Portable encrypted project container `.foca.enc`.
//!
//! Container binary layout:
//! - Magic: `FOCAENC1` (8 bytes)
//! - Header length: `u32` big-endian (4 bytes)
//! - Header JSON (UTF-8, authenticated as AEAD AAD):
//!   `schema`, `kdf`, `iterations` (210_000), `salt_hex` (16 random bytes),
//!   `nonce_hex` (12 random bytes), `kdf_check_hex` (16-byte key verification tag),
//!   `created_at`, `include_files`, `custody_sha256`, optional `signature` (`ReportSignature`).
//! - Ciphertext + 16-byte Poly1305 tag (`ring::aead::CHACHA20_POLY1305`) encrypting an in-memory
//!   ZIP archive with `manifest.json` (`CustodyManifest`), `project.foca` (clean `VACUUM INTO`
//!   SQLite snapshot), and optional `files/<rel>` copies when `include_files = true`.
//!
//! Passwords are never logged, cached, or written to disk/settings.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use ring::hmac;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::engine::{lock, Core};
use crate::util;
use crate::{CmdError, CmdResult, ReportSignature};

const MAGIC: &[u8; 8] = b"FOCAENC1";
const HEADER_SCHEMA: &str = "foca-bundle/v1";
const MANIFEST_SCHEMA: &str = "foca-bundle-manifest/v1";
const PBKDF2_ITERATIONS: u32 = 210_000;
const MIN_PBKDF2_ITERATIONS: u32 = 10_000;
const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ZIP_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleHeader {
    schema: String,
    kdf: String,
    iterations: u32,
    salt_hex: String,
    nonce_hex: String,
    kdf_check_hex: String,
    created_at: String,
    include_files: bool,
    custody_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<ReportSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BundleFileEntry {
    pub rel_path: String,
    pub orig_path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BundleCounts {
    pub docs: usize,
    pub findings: usize,
    pub hosts: usize,
    pub people: usize,
    pub scans: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CustodyManifest {
    pub schema: String,
    pub project_id: String,
    pub project_name: String,
    pub client: String,
    pub exported_at: String,
    pub db_sha256: String,
    pub inputs_sha256: String,
    pub counts: BundleCounts,
    pub files: Vec<BundleFileEntry>,
}

struct Key32;
impl KeyType for Key32 {
    fn len(&self) -> usize {
        32
    }
}

struct BundleKeys {
    aead: [u8; 32],
    check: [u8; 32],
}

fn derive_bundle_keys(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<BundleKeys, CmdError> {
    let iters = NonZeroU32::new(iterations)
        .filter(|_| (MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations))
        .ok_or_else(|| CmdError::new("tampered_bundle", "Некорректные параметры KDF"))?;
    let mut master = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        salt,
        password.as_bytes(),
        &mut master,
    );
    let hkdf_salt = Salt::new(HKDF_SHA256, salt);
    let prk = hkdf_salt.extract(&master);
    let mut aead = [0u8; 32];
    let mut check = [0u8; 32];
    prk.expand(&[b"foca-bundle-aead-v1"], Key32)
        .and_then(|okm| okm.fill(&mut aead))
        .map_err(|_| CmdError::new("internal", "HKDF aead"))?;
    prk.expand(&[b"foca-bundle-check-v1"], Key32)
        .and_then(|okm| okm.fill(&mut check))
        .map_err(|_| CmdError::new("internal", "HKDF check"))?;
    Ok(BundleKeys { aead, check })
}

fn kdf_check_tag(check_key: &[u8; 32]) -> [u8; 16] {
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, check_key);
    let tag = hmac::sign(&mac_key, b"foca-bundle-keycheck-v1");
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(out)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CmdError> {
    let rng = SystemRandom::new();
    let mut buf = [0u8; N];
    rng.fill(&mut buf)
        .map_err(|_| CmdError::new("internal", "Не удалось получить случайные байты"))?;
    Ok(buf)
}

fn safe_filename(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    while out.contains("..") {
        out = out.replace("..", "_");
    }
    let trimmed = out.trim_matches(['.', '_']);
    if trimmed.is_empty() {
        "project".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

fn compute_inputs_sha256(
    db_sha256: &str,
    snap: &foca_core::api::Snapshot,
    files: &[BundleFileEntry],
) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("db:{db_sha256}"));
    let mut doc_hashes: Vec<String> = snap
        .docs
        .iter()
        .map(|d| format!("doc:{}:{}:{}", d.id, d.name, d.size))
        .collect();
    doc_hashes.sort();
    parts.extend(doc_hashes);
    let mut f_hashes: Vec<String> = snap
        .findings
        .iter()
        .map(|f| format!("finding:{}:{:?}:{}", f.id, f.sev, f.title))
        .collect();
    f_hashes.sort();
    parts.extend(f_hashes);
    for f in files {
        parts.push(format!("file:{}:{}", f.rel_path, f.sha256));
    }
    util::hex(&util::sha256(parts.join("\n").as_bytes()))
}

fn sanitize_zip_rel(rel: &str) -> Option<PathBuf> {
    let p = Path::new(rel);
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() || s.contains('\0') {
                    return None;
                }
                clean.push(seg);
            }
            _ => return None,
        }
    }
    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

/// `project_export_encrypted { project, password, include_files? }`
/// Creates an authenticated, password-encrypted `.foca.enc` container containing the
/// project database, `CustodyManifest`, and optional project document files.
pub(crate) fn project_export_encrypted(core: &Core, a: &Value) -> CmdResult {
    let id = core.project_arg(a)?;
    let password = util::req_str(a, "password")?;
    if password.chars().count() < 6 {
        return Err(CmdError::new(
            "bad_args",
            "Пароль контейнера должен содержать минимум 6 символов",
        ));
    }
    let include_files = a["include_files"].as_bool().unwrap_or(false);
    let (snap, _) = core.core_snapshot(&id)?;
    let db = core.db(&id)?;
    let (db_bytes, stored_docs) = {
        let db = lock(&db);
        let bytes = db.export_sqlite_bytes()?;
        let docs = db.documents(true)?;
        (bytes, docs)
    };
    let db_sha256 = util::hex(&util::sha256(&db_bytes));

    let mut files_meta = Vec::new();
    let mut files_data: Vec<(String, Vec<u8>)> = Vec::new();
    if include_files {
        let mut idx = 0usize;
        for d in &stored_docs {
            let Some(lp) = d.local_path.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let path = Path::new(lp);
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            idx += 1;
            let fname = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(safe_filename)
                .unwrap_or_else(|| format!("doc_{idx}.bin"));
            let rel_path = format!("files/{idx:04}_{fname}");
            let sha = util::hex(&util::sha256(&bytes));
            files_meta.push(BundleFileEntry {
                rel_path: rel_path.clone(),
                orig_path: lp.to_string(),
                sha256: sha,
                size: bytes.len() as u64,
            });
            files_data.push((rel_path, bytes));
        }
    }

    let exported_at = core.now_iso();
    let inputs_sha256 = compute_inputs_sha256(&db_sha256, &snap, &files_meta);
    let counts = BundleCounts {
        docs: snap.docs.len(),
        findings: snap.findings.len(),
        hosts: snap.hosts.len(),
        people: snap.people.len(),
        scans: snap.scans.len(),
    };
    let manifest = CustodyManifest {
        schema: MANIFEST_SCHEMA.into(),
        project_id: snap.project.id.clone(),
        project_name: snap.project.name.clone(),
        client: snap.project.client.clone(),
        exported_at: exported_at.clone(),
        db_sha256,
        inputs_sha256: inputs_sha256.clone(),
        counts: counts.clone(),
        files: files_meta,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let custody_sha256 = util::hex(&util::sha256(&manifest_bytes));

    // Build in-memory ZIP archive
    let mut zip_buf = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut zip_buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zw.start_file("manifest.json", opts)
            .map_err(|e| CmdError::new("internal", format!("ZIP manifest: {e}")))?;
        zw.write_all(&manifest_bytes)?;
        zw.start_file("project.foca", opts)
            .map_err(|e| CmdError::new("internal", format!("ZIP db: {e}")))?;
        zw.write_all(&db_bytes)?;
        for (rel, data) in &files_data {
            zw.start_file(rel, opts)
                .map_err(|e| CmdError::new("internal", format!("ZIP file: {e}")))?;
            zw.write_all(data)?;
        }
        zw.finish()
            .map_err(|e| CmdError::new("internal", format!("ZIP finish: {e}")))?;
    }
    let mut plaintext = zip_buf.into_inner();

    let salt = random_bytes::<16>()?;
    let nonce_bytes = random_bytes::<12>()?;
    let keys = derive_bundle_keys(password, &salt, PBKDF2_ITERATIONS)?;
    let check = kdf_check_tag(&keys.check);

    let signer = core.current_signer();
    let signature = signer.as_ref().and_then(|s| match s.sign(&manifest_bytes) {
        Ok(sig) => Some(sig),
        Err(e) => {
            tracing::warn!(target: "foca::engine", "подпись контейнера .foca.enc: {e}");
            None
        }
    });
    let signed = signature.is_some();

    let header = BundleHeader {
        schema: HEADER_SCHEMA.into(),
        kdf: "pbkdf2-hmac-sha256".into(),
        iterations: PBKDF2_ITERATIONS,
        salt_hex: util::hex(&salt),
        nonce_hex: util::hex(&nonce_bytes),
        kdf_check_hex: util::hex(&check),
        created_at: exported_at,
        include_files,
        custody_sha256,
        signature,
    };
    let header_bytes = serde_json::to_vec(&header)?;
    if header_bytes.len() > MAX_HEADER_BYTES {
        return Err(CmdError::new(
            "internal",
            "Заголовок контейнера слишком велик",
        ));
    }

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &keys.aead)
        .map_err(|_| CmdError::new("internal", "Ошибка инициализации ChaCha20-Poly1305"))?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(&header_bytes), &mut plaintext)
        .map_err(|_| CmdError::new("internal", "Ошибка шифрования контейнера"))?;

    let mut container = Vec::with_capacity(MAGIC.len() + 4 + header_bytes.len() + plaintext.len());
    container.extend_from_slice(MAGIC);
    container.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    container.extend_from_slice(&header_bytes);
    container.extend_from_slice(&plaintext);

    let container_sha256 = util::hex(&util::sha256(&container));
    let date = core.now_iso();
    let day = date.get(..10).unwrap_or("2026-11-24");
    let name = format!("{}_{day}.foca.enc", safe_filename(&snap.project.name));
    let dir = core.cfg.data_dir.join("exports");
    std::fs::create_dir_all(&dir)?;
    let out_path = dir.join(&name);
    let tmp_path = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp_path, &container)?;
    std::fs::rename(&tmp_path, &out_path)?;

    Ok(json!({
        "name": name,
        "path": out_path.to_string_lossy(),
        "size": container.len() as u64,
        "sha256": container_sha256,
        "inputs_sha256": inputs_sha256,
        "include_files": include_files,
        "signed": signed,
        "counts": counts,
    }))
}

/// `project_import_encrypted { path, password, new_name? }`
/// Decrypts, authenticates, verifies `CustodyManifest` integrity, and imports a `.foca.enc`
/// container as a fresh project without overwriting any existing project.
pub(crate) fn project_import_encrypted(core: &Core, a: &Value) -> CmdResult {
    let path_str = util::req_str(a, "path")?;
    let password = util::req_str(a, "password")?;
    let new_name = util::arg_str(a, "new_name")
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let path = Path::new(path_str);
    let meta = std::fs::metadata(path)
        .map_err(|_| CmdError::not_found(format!("Файл контейнера не найден: {path_str}")))?;
    if meta.len() > MAX_BUNDLE_BYTES {
        return Err(CmdError::new(
            "bad_args",
            "Размер контейнера превышает допустимый предел (512 МБ)",
        ));
    }
    let raw = std::fs::read(path)?;
    if raw.len() < MAGIC.len() + 4 + aead::CHACHA20_POLY1305.tag_len()
        || &raw[..MAGIC.len()] != MAGIC
    {
        return Err(CmdError::new(
            "tampered_bundle",
            "Повреждённый или неподдерживаемый файл .foca.enc",
        ));
    }
    let header_len = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if header_len == 0
        || header_len > MAX_HEADER_BYTES
        || raw.len() < 12 + header_len + CHACHA20_POLY1305.tag_len()
    {
        return Err(CmdError::new(
            "tampered_bundle",
            "Повреждённый заголовок контейнера .foca.enc",
        ));
    }
    let header_bytes = &raw[12..12 + header_len];
    let header: BundleHeader = serde_json::from_slice(header_bytes).map_err(|_| {
        CmdError::new(
            "tampered_bundle",
            "Некорректный JSON заголовка контейнера .foca.enc",
        )
    })?;
    if header.schema != HEADER_SCHEMA || header.kdf != "pbkdf2-hmac-sha256" {
        return Err(CmdError::new(
            "tampered_bundle",
            "Неподдерживаемая схема контейнера .foca.enc",
        ));
    }
    let salt = decode_hex(&header.salt_hex)
        .filter(|b| b.len() == 16)
        .ok_or_else(|| CmdError::new("tampered_bundle", "Повреждённая соль KDF в контейнере"))?;
    let nonce_vec = decode_hex(&header.nonce_hex)
        .filter(|b| b.len() == 12)
        .ok_or_else(|| CmdError::new("tampered_bundle", "Повреждённый nonce в контейнере"))?;
    let expected_check = decode_hex(&header.kdf_check_hex)
        .filter(|b| b.len() == 16)
        .ok_or_else(|| CmdError::new("tampered_bundle", "Повреждённая метка KDF в контейнере"))?;

    let keys = derive_bundle_keys(password, &salt, header.iterations)?;
    let actual_check = kdf_check_tag(&keys.check);
    if !util::ct_eq(&actual_check, &expected_check) {
        return Err(CmdError::new(
            "bad_password",
            "Неверный пароль для расшифровки .foca.enc",
        ));
    }

    let mut ct = raw[12 + header_len..].to_vec();
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &keys.aead)
        .map_err(|_| CmdError::new("internal", "Ошибка инициализации ChaCha20-Poly1305"))?;
    let opening_key = LessSafeKey::new(unbound);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_vec);
    let plaintext = opening_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(header_bytes),
            &mut ct,
        )
        .map_err(|_| {
            CmdError::new(
                "tampered_bundle",
                "Нарушена целостность контейнера .foca.enc (ошибка AEAD Poly1305)",
            )
        })?;

    let mut za = ZipArchive::new(Cursor::new(plaintext))
        .map_err(|_| CmdError::new("tampered_bundle", "Повреждённый внутренний архив .foca.enc"))?;

    let mut total_extracted: u64 = 0;
    let read_entry = |za: &mut ZipArchive<Cursor<&mut [u8]>>,
                      name: &str,
                      total_extracted: &mut u64|
     -> Result<Vec<u8>, CmdError> {
        let mut f = za.by_name(name).map_err(|_| {
            CmdError::new(
                "tampered_bundle",
                format!("В контейнере отсутствует обязательный файл {name}"),
            )
        })?;
        if f.size() > MAX_ZIP_ENTRY_BYTES {
            return Err(CmdError::new(
                "tampered_bundle",
                format!("Файл {name} в контейнере превышает лимит"),
            ));
        }
        let mut buf = Vec::with_capacity((f.size().min(1 << 20)) as usize);
        (&mut f)
            .take(MAX_ZIP_ENTRY_BYTES.saturating_add(1))
            .read_to_end(&mut buf)?;
        let actual = buf.len() as u64;
        if actual > MAX_ZIP_ENTRY_BYTES {
            return Err(CmdError::new(
                "tampered_bundle",
                format!("Файл {name} в контейнере превышает лимит при распаковке"),
            ));
        }
        *total_extracted = total_extracted.saturating_add(actual);
        if *total_extracted > MAX_BUNDLE_BYTES {
            return Err(CmdError::new(
                "tampered_bundle",
                "Содержимое архива .foca.enc превышает общий лимит распаковки",
            ));
        }
        Ok(buf)
    };

    let manifest_bytes = read_entry(&mut za, "manifest.json", &mut total_extracted)?;
    let actual_custody_sha = util::hex(&util::sha256(&manifest_bytes));
    if !util::ct_eq(
        actual_custody_sha.as_bytes(),
        header.custody_sha256.as_bytes(),
    ) {
        return Err(CmdError::new(
            "tampered_bundle",
            "Хеш CustodyManifest не совпадает с заголовком контейнера",
        ));
    }
    let manifest: CustodyManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| CmdError::new("tampered_bundle", "Повреждённый CustodyManifest"))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(CmdError::new(
            "tampered_bundle",
            "Неподдерживаемая версия CustodyManifest",
        ));
    }

    let current_signer = core.current_signer();
    let verified_signature = match &header.signature {
        Some(sig) => match &current_signer {
            Some(signer) => {
                let ok = signer.verify(&manifest_bytes, sig).unwrap_or(false);
                if !ok {
                    return Err(CmdError::new(
                        "tampered_bundle",
                        "Недействительная цифровая подпись контейнера .foca.enc",
                    ));
                }
                Some(true)
            }
            None => None,
        },
        None => None,
    };

    let db_bytes = read_entry(&mut za, "project.foca", &mut total_extracted)?;
    let actual_db_sha = util::hex(&util::sha256(&db_bytes));
    if !util::ct_eq(actual_db_sha.as_bytes(), manifest.db_sha256.as_bytes()) {
        return Err(CmdError::new(
            "tampered_bundle",
            "Хеш базы данных проекта не совпадает с CustodyManifest",
        ));
    }

    // Verify all included file hashes before importing
    let mut extracted_files: Vec<(BundleFileEntry, PathBuf, Vec<u8>)> = Vec::new();
    for fmeta in &manifest.files {
        let clean_rel = sanitize_zip_rel(&fmeta.rel_path).ok_or_else(|| {
            CmdError::new("tampered_bundle", "Небезопасный путь файла в контейнере")
        })?;
        let bytes = read_entry(&mut za, &fmeta.rel_path, &mut total_extracted)?;
        let sha = util::hex(&util::sha256(&bytes));
        if !util::ct_eq(sha.as_bytes(), fmeta.sha256.as_bytes()) {
            return Err(CmdError::new(
                "tampered_bundle",
                format!(
                    "Хеш файла {} не совпадает с CustodyManifest",
                    fmeta.rel_path
                ),
            ));
        }
        extracted_files.push((fmeta.clone(), clean_rel, bytes));
    }

    let summary = core.store().import_project_db(&db_bytes, new_name)?;
    let dest_root = core.cfg.data_dir.join("files").join(&summary.id);
    let rollback = |err: CmdError| -> CmdError {
        core.forget_db(&summary.id);
        let _ = core.store().delete_project(&summary.id);
        let _ = std::fs::remove_dir_all(&dest_root);
        err
    };

    let mut files_restored = 0usize;
    let mut path_map = BTreeMap::new();
    if !extracted_files.is_empty() {
        if let Err(e) = std::fs::create_dir_all(&dest_root) {
            return Err(rollback(e.into()));
        }
        for (idx, (fmeta, clean_rel, bytes)) in extracted_files.into_iter().enumerate() {
            let leaf = clean_rel
                .file_name()
                .and_then(|s| s.to_str())
                .map(safe_filename)
                .unwrap_or_else(|| format!("doc_{idx}.bin"));
            let dest_file = dest_root.join(format!("{:04}_{leaf}", idx + 1));
            if let Err(e) = std::fs::write(&dest_file, &bytes) {
                return Err(rollback(e.into()));
            }
            path_map.insert(fmeta.orig_path, dest_file.to_string_lossy().to_string());
            files_restored += 1;
        }
    }
    // Always sanitize/remap all local_path entries (and clear any unmapped attacker paths).
    let db = match core.db(&summary.id) {
        Ok(db) => db,
        Err(e) => return Err(rollback(e)),
    };
    if let Err(e) = lock(&db).remap_or_clear_doc_local_paths(&path_map) {
        return Err(rollback(e.into()));
    }

    Ok(json!({
        "project": summary,
        "custody": manifest,
        "verified_signature": verified_signature,
        "files_restored": files_restored,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_and_path_sanitization_work() {
        let k1 = derive_bundle_keys("SecretPass!1", b"0123456789abcdef", 10_000).unwrap();
        let k2 = derive_bundle_keys("SecretPass!1", b"0123456789abcdef", 10_000).unwrap();
        let k3 = derive_bundle_keys("OtherPass!1", b"0123456789abcdef", 10_000).unwrap();
        assert_eq!(k1.aead, k2.aead);
        assert_eq!(k1.check, k2.check);
        assert_ne!(k1.aead, k1.check);
        assert_ne!(k1.aead, k3.aead);
        assert_eq!(kdf_check_tag(&k1.check), kdf_check_tag(&k2.check));
        assert_ne!(kdf_check_tag(&k1.check), kdf_check_tag(&k3.check));
        assert!(derive_bundle_keys("SecretPass!1", b"0123456789abcdef", u32::MAX).is_err());
        assert!(derive_bundle_keys("SecretPass!1", b"0123456789abcdef", 100).is_err());
        assert!(sanitize_zip_rel("../evil.txt").is_none());
        assert!(sanitize_zip_rel("/abs/path").is_none());
        assert_eq!(
            sanitize_zip_rel("files/0001_doc.pdf"),
            Some(PathBuf::from("files/0001_doc.pdf"))
        );
    }
}

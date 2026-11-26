//! Optional on-device OCR pipeline (disabled by default).
//!
//! Rust core defines the platform-agnostic [`OcrProvider`] trait and [`maybe_ocr`] policy gate;
//! on Android, `OcrEngine.kt` implements it via on-device Google ML Kit Text Recognition without
//! bundling `tesseract` or making any network calls (ADR-0011).

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum recognized text kept per document (matches the 64 KiB FTS5 indexing cap).
pub const MAX_OCR_TEXT_BYTES: usize = 64 * 1024;
/// Minimum existing text length (trimmed chars) above which a document is considered to already
/// have a text layer and OCR is skipped.
pub const MIN_EXISTING_TEXT_CHARS: usize = 40;

/// Request passed to [`OcrProvider::recognize`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcrRequest {
    pub path: String,
    pub mime: String,
    pub max_pages: u32,
}

/// Recognized text returned by [`OcrProvider::recognize`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcrResult {
    pub text: String,
    pub pages: u32,
    pub engine: String,
}

/// Platform OCR implementation (Android ML Kit via JNI on device; mockable in tests).
pub trait OcrProvider: Send + Sync {
    fn recognize(&self, req: OcrRequest) -> Result<OcrResult, String>;
}

/// Effective `settings.ocr` configuration (`enabled: false` by default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcrSettings {
    pub enabled: bool,
    pub max_pages: u32,
    pub max_mb: u64,
}

impl Default for OcrSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pages: 10,
            max_mb: 15,
        }
    }
}

impl OcrSettings {
    pub fn from_settings(settings: &Value) -> Self {
        let ocr = settings.get("ocr").unwrap_or(&Value::Null);
        let enabled = ocr.get("enabled").and_then(Value::as_bool).unwrap_or(false);
        let max_pages = ocr
            .get("max_pages")
            .and_then(Value::as_u64)
            .unwrap_or(10)
            .clamp(1, 50) as u32;
        let max_mb = ocr
            .get("max_mb")
            .and_then(Value::as_u64)
            .unwrap_or(15)
            .clamp(1, 50);
        Self {
            enabled,
            max_pages,
            max_mb,
        }
    }
}

/// Returns the OCR-eligible MIME type if `bytes` or `name` represents a PDF or raster image.
pub fn detect_ocr_mime(name: &str, bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        return Some("image/tiff");
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pdf" => Some("application/pdf"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "tif" | "tiff" => Some("image/tiff"),
        "heic" | "heif" => Some("image/heic"),
        _ => None,
    }
}

/// Truncates a UTF-8 string to at most `max_bytes` on a valid character boundary.
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Runs on-device OCR when enabled and the document lacks an existing text layer.
///
/// Recognized text is never written to logs; the caller passes the returned text through
/// `foca_analysis::pii::sanitize` / `ProjectDb::set_analyzed` before storage or FTS5 indexing.
pub fn maybe_ocr(
    cfg: &OcrSettings,
    provider: Option<&dyn OcrProvider>,
    path: &Path,
    name: &str,
    bytes: &[u8],
    existing_text: Option<&str>,
) -> Option<String> {
    if !cfg.enabled {
        return None;
    }
    let prov = provider?;
    let max_bytes = (cfg.max_mb as usize).saturating_mul(1024 * 1024);
    if bytes.is_empty() || bytes.len() > max_bytes {
        return None;
    }
    if existing_text.is_some_and(|t| t.trim().chars().count() >= MIN_EXISTING_TEXT_CHARS) {
        return None;
    }
    let mime = detect_ocr_mime(name, bytes)?;
    let req = OcrRequest {
        path: path.to_string_lossy().into_owned(),
        mime: mime.to_string(),
        max_pages: cfg.max_pages,
    };
    match prov.recognize(req) {
        Ok(res) => {
            let trimmed = res.text.trim();
            if trimmed.is_empty() {
                return None;
            }
            let capped = truncate_utf8(trimmed, MAX_OCR_TEXT_BYTES);
            tracing::debug!(
                target: "foca::ocr",
                "OCR ({}) {}: {} стр., {} байт",
                res.engine,
                name,
                res.pages,
                capped.len()
            );
            Some(capped)
        }
        Err(e) => {
            tracing::warn!(target: "foca::ocr", "OCR пропущен для {name}: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountOcr(AtomicUsize);

    impl OcrProvider for CountOcr {
        fn recognize(&self, req: OcrRequest) -> Result<OcrResult, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(OcrResult {
                text: format!("recognized from {} ({})", req.mime, req.max_pages),
                pages: 1,
                engine: "mock".into(),
            })
        }
    }

    #[test]
    fn disabled_by_default_and_gates_size_mime_and_existing_text() {
        let def = OcrSettings::from_settings(&serde_json::json!({}));
        assert!(!def.enabled);
        assert_eq!(def.max_pages, 10);
        assert_eq!(def.max_mb, 15);

        let prov = CountOcr(AtomicUsize::new(0));
        let pdf = b"%PDF-1.4 scan bytes";
        let p = Path::new("scan.pdf");

        // 1. Disabled by default -> never calls provider.
        assert_eq!(maybe_ocr(&def, Some(&prov), p, "scan.pdf", pdf, None), None);
        assert_eq!(prov.0.load(Ordering::SeqCst), 0);

        // 2. Enabled, but existing text layer >= 40 chars -> skipped.
        let on = OcrSettings {
            enabled: true,
            max_pages: 5,
            max_mb: 1,
        };
        let long_text = "Достатньо довгий текстовий шар документа PDF, який не потребує OCR.";
        assert_eq!(
            maybe_ocr(&on, Some(&prov), p, "scan.pdf", pdf, Some(long_text)),
            None
        );
        assert_eq!(prov.0.load(Ordering::SeqCst), 0);

        // 3. Enabled, non-image/non-PDF file -> skipped.
        assert_eq!(
            maybe_ocr(
                &on,
                Some(&prov),
                Path::new("a.docx"),
                "a.docx",
                b"PK\x03\x04",
                None
            ),
            None
        );
        assert_eq!(prov.0.load(Ordering::SeqCst), 0);

        // 4. Enabled, scanned PDF without text -> invokes provider.
        let out = maybe_ocr(&on, Some(&prov), p, "scan.pdf", pdf, Some("   ")).unwrap();
        assert_eq!(out, "recognized from application/pdf (5)");
        assert_eq!(prov.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn truncate_utf8_respects_cyrillic_char_boundaries() {
        let s = "ІПНїєґ";
        let t = truncate_utf8(s, 5);
        assert_eq!(t, "ІП");
    }
}

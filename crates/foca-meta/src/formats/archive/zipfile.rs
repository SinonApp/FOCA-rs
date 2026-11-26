//! Plain ZIP archives: entry list, timestamps, archive comment, suspicious (Zip-Slip) entry
//! names and recursive parsing of members through [`Ctx::extract_child`] under the shared
//! decompression budget.
//!
//! Nothing is ever written to disk: members are decompressed into memory and identified by the
//! entry name only as a label.

use foca_core::{Attachment, DocFormat, Metadata};

use crate::util::{clean_str, decode_text, truncate};
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError, MAX_CHILDREN};

/// Maximum number of listed archive entries.
const MAX_LISTED: usize = 1000;

/// Returns `true` for entry names that would escape an extraction directory.
pub(crate) fn is_unsafe_name(name: &str) -> bool {
    let n = name.replace('\\', "/");
    let b = n.as_bytes();
    n.starts_with('/')
        || (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic())
        || n.split('/').any(|c| c == "..")
        || n.contains('\0')
}

/// Formats a DOS date/time as ISO 8601 without an offset.
fn dos_time(dt: zip::DateTime) -> Option<String> {
    if !dt.is_valid() || dt.year() < 1981 {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    ))
}

pub fn extract(bytes: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut z = SafeZip::open(bytes, ctx.max_entries())?;
    let mut meta = Metadata::new(DocFormat::Zip);
    if let Some(c) = clean_str(&decode_text(z.comment())) {
        meta.description = Some(truncate(&c, 2048));
    }
    let names: Vec<String> = z.names().to_vec();
    let (mut files, mut dirs, mut total, mut encrypted) = (0u64, 0u64, 0u64, 0u64);
    let mut unsafe_names = Vec::new();
    let mut times: Vec<String> = Vec::new();
    for n in &names {
        let info = z.info(n);
        if is_unsafe_name(n) {
            unsafe_names.push(truncate(n, 256));
        }
        if n.ends_with('/') {
            dirs += 1;
            continue;
        }
        files += 1;
        let Some(info) = info else { continue };
        total = total.saturating_add(info.size);
        if info.encrypted {
            encrypted += 1;
        }
        if let Some(t) = info.modified.and_then(dos_time) {
            times.push(t);
        }
        if meta.attachments.len() < MAX_LISTED {
            meta.attachments.push(Attachment {
                name: truncate(n, 512),
                size: Some(info.size),
                mime: None,
            });
        }
    }
    meta.stats.insert("files".into(), files);
    if dirs > 0 {
        meta.stats.insert("dirs".into(), dirs);
    }
    meta.stats.insert("uncompressed_bytes".into(), total);
    if encrypted > 0 {
        meta.encrypted = true;
        meta.stats.insert("encrypted_entries".into(), encrypted);
    }
    times.sort();
    meta.created = times.first().cloned();
    meta.modified = times.last().cloned();
    if !unsafe_names.is_empty() {
        meta.warnings.push(format!(
            "ZIP: {} entries with path traversal names",
            unsafe_names.len()
        ));
        meta.fields.insert(
            "zip:unsafe_names".into(),
            truncate(&unsafe_names.join("; "), 2048),
        );
    }
    if !ctx.can_descend() {
        return Ok(meta);
    }
    for n in &names {
        if n.ends_with('/') || meta.embedded.len() >= MAX_CHILDREN {
            continue;
        }
        let short = n.rsplit(['/', '\\']).next().unwrap_or(n);
        // a single oversized member (a video, a disk image) is skipped instead of failing the
        // whole archive; a forged declared size is still caught by `SafeZip::read`
        if let Some(size) = z.info(n).map(|i| i.size) {
            if size > ctx.remaining() || size > ctx.max_file() {
                meta.warnings.push(format!(
                    "{}: {size} bytes exceed the decompression budget, skipped",
                    truncate(n, 128)
                ));
                continue;
            }
        }
        let Some(b) = z.read(n, ctx)? else { continue };
        ctx.attach_child(&mut meta, &b, short, n)?;
    }
    Ok(meta)
}

/// Calls `f(name, bytes)` for every file member of a ZIP archive, in archive order, under the
/// limits (entry count, shared decompression budget, `max_file` per member). Directory entries,
/// encrypted and corrupt members are skipped. Entry names are labels only: callers must never
/// use them as file-system paths.
///
/// # Errors
///
/// Returns [`MetaError`] if the archive cannot be opened or a limit is exceeded.
pub fn for_each_zip_member(
    bytes: &[u8],
    limits: &crate::Limits,
    mut f: impl FnMut(&str, &[u8]),
) -> Result<(), MetaError> {
    crate::check_size(bytes, limits)?;
    let budget = std::cell::Cell::new(limits.max_unzipped_total);
    let ctx = Ctx::standalone(limits, &budget);
    crate::guard("zip", || {
        let mut z = SafeZip::open(bytes, limits.max_entries)?;
        let names: Vec<String> = z.names().to_vec();
        for n in &names {
            if n.ends_with('/') {
                continue;
            }
            if z.info(n).is_some_and(|i| i.size > limits.max_file) {
                continue;
            }
            if let Some(b) = z.read(n, &ctx)? {
                f(n, &b);
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_names() {
        for n in ["../x", "a/../../b", "/etc/passwd", "C:\\x", "a\\..\\b"] {
            assert!(is_unsafe_name(n), "{n}");
        }
        for n in ["a/b.txt", "..a/b", "x..y"] {
            assert!(!is_unsafe_name(n), "{n}");
        }
    }
}

//! 7-Zip archive container (`.7z`, magic `37 7A BC AF 27 1C`).
//!
//! Pure-Rust parser for the 32-byte 7z SignatureHeader and the trailing Header / FilesInfo stream:
//! extracts UTF-16LE member file names (`kName = 0x11`), checks for Zip-Slip path traversal
//! (`crate::formats::archive::zipfile::is_unsafe_name`), enforces [`Ctx`] decompression and entry limits, and
//! recursively inspects stored/uncompressed embedded documents via [`crate::Ctx::attach_child`].

use foca_core::{Attachment, DocFormat, Metadata};

use crate::formats::archive::zipfile::is_unsafe_name;
use crate::formats::detect::{detect_with_hint, SEVENZ_MAGIC as MAGIC};
use crate::util::truncate;
use crate::MAX_CHILDREN;
use crate::{Ctx, MetaError};

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    if b.len() < 32 || !b.starts_with(&MAGIC) {
        return Err(MetaError::malformed("7z", "bad 7z signature header"));
    }
    let ver_major = b[6];
    let ver_minor = b[7];
    let next_header_offset =
        u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]);
    let next_header_size =
        u64::from_le_bytes([b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[27]]);

    // Charge header inspection against the shared decompression budget (zip-bomb defense).
    ctx.spend(next_header_size)?;

    let hdr_start = 32u64
        .checked_add(next_header_offset)
        .ok_or_else(|| MetaError::malformed("7z", "next_header_offset overflow"))?;
    let hdr_end = hdr_start
        .checked_add(next_header_size)
        .ok_or_else(|| MetaError::malformed("7z", "next_header_size overflow"))?;
    if hdr_end > b.len() as u64 {
        return Err(MetaError::malformed(
            "7z",
            "next header points past end of file",
        ));
    }

    let mut meta = Metadata::new(DocFormat::SevenZ);
    meta.fields
        .insert("7z:version".into(), format!("{ver_major}.{ver_minor}"));
    Metadata::add_unique(&mut meta.software, "7-Zip");

    let hdr = &b[hdr_start as usize..hdr_end as usize];
    let payload = &b[32..hdr_start as usize];

    let names = extract_7z_names(hdr, ctx.max_entries())?;
    let mut unsafe_names = Vec::new();
    for name in &names {
        if is_unsafe_name(name) {
            unsafe_names.push(truncate(name, 256));
        }
        if meta.attachments.len() < 1000 {
            meta.attachments.push(Attachment {
                name: truncate(name, 256),
                size: Some(0),
                mime: None,
            });
        }
    }

    meta.stats
        .insert("archive_files".into(), names.len() as u64);
    meta.stats
        .insert("archive_unsafe_names".into(), unsafe_names.len() as u64);
    if !unsafe_names.is_empty() {
        meta.fields
            .insert("archive:unsafe_names".into(), unsafe_names.join("\n"));
        meta.warnings.push(format!(
            "7z: небезопасные пути элементов (Zip-Slip): {}",
            unsafe_names.len()
        ));
    }

    // Recursively inspect any stored/uncompressed documents inside the 7z payload slice
    inspect_stored_children(&mut meta, ctx, payload, &names)?;

    Ok(meta)
}

/// Extracts UTF-16LE file names from a 7z Header (`kName = 0x11` property block or contiguous
/// null-terminated UTF-16LE runs inside `kFilesInfo = 0x05`).
fn extract_7z_names(hdr: &[u8], max_entries: usize) -> Result<Vec<String>, MetaError> {
    let mut names = Vec::new();
    // Look for kName (0x11) property block: [0x11, size_varint, external_byte(0x00), utf16le_z...]
    let mut i = 0usize;
    while i + 4 < hdr.len() {
        if hdr[i] == 0x11 {
            let (sz, used) = read_7z_uint64(&hdr[i + 1..]);
            let block_start = i + 1 + used;
            if used > 0 && sz >= 3 && hdr.get(block_start) == Some(&0) {
                if let Some(utf16_bytes) = usize::try_from(sz)
                    .ok()
                    .and_then(|s| block_start.checked_add(s))
                    .and_then(|end| hdr.get(block_start + 1..end))
                {
                    parse_utf16le_names(utf16_bytes, &mut names, max_entries)?;
                    if !names.is_empty() {
                        return Ok(names);
                    }
                }
            }
        }
        i += 1;
    }
    Ok(names)
}

fn parse_utf16le_names(
    buf: &[u8],
    out: &mut Vec<String>,
    max_entries: usize,
) -> Result<(), MetaError> {
    let mut cur = Vec::new();
    for chunk in buf.as_chunks::<2>().0 {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            if !cur.is_empty() {
                if out.len() >= max_entries {
                    return Err(MetaError::TooManyEntries("7z file names".into()));
                }
                let s = String::from_utf16_lossy(&cur).trim().to_string();
                if !s.is_empty() {
                    out.push(s);
                }
                cur.clear();
            }
        } else {
            cur.push(u);
        }
    }
    if !cur.is_empty() {
        if out.len() >= max_entries {
            return Err(MetaError::TooManyEntries("7z file names".into()));
        }
        let s = String::from_utf16_lossy(&cur).trim().to_string();
        if !s.is_empty() {
            out.push(s);
        }
    }
    Ok(())
}

/// Decodes a 7z variable-length `UINT64` returning `(value, bytes_consumed)`.
fn read_7z_uint64(b: &[u8]) -> (u64, usize) {
    if b.is_empty() {
        return (0, 0);
    }
    let first = b[0];
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 && (first & mask) != 0 {
        mask >>= 1;
        extra += 1;
    }
    if 1 + extra > b.len() {
        return (0, 0);
    }
    let mut val = 0u64;
    for j in 0..extra {
        val |= (b[1 + j] as u64) << (8 * j);
    }
    if extra < 8 {
        let high = (first as u64) & ((1u64 << (8 - extra)) - 1);
        val |= high << (8 * extra);
    }
    (val, 1 + extra)
}

fn inspect_stored_children(
    meta: &mut Metadata,
    ctx: &Ctx,
    payload: &[u8],
    names: &[String],
) -> Result<(), MetaError> {
    if payload.is_empty() || meta.embedded.len() >= MAX_CHILDREN {
        return Ok(());
    }
    // Check if the payload starts directly with a known document signature (e.g. stored/Copy coder)
    let label = names.first().map(String::as_str).unwrap_or("member_0");
    if detect_with_hint(payload, Some(label)) != DocFormat::Unknown {
        ctx.spend(payload.len() as u64)?;
        ctx.attach_child(meta, payload, label, label)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_7z_uint64_all_ones_prefix_does_not_shift_overflow() {
        let b = [0xFF, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            read_7z_uint64(&b),
            (u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]), 9)
        );
    }

    #[test]
    fn extract_7z_names_ignores_huge_block_size_without_overflow() {
        let mut hdr = vec![0x11]; // FilesInfo / Name property marker
                                  // 8-byte u64 size near u64::MAX
        hdr.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        hdr.push(0); // external=0
        let names = extract_7z_names(&hdr, 16).unwrap();
        assert!(names.is_empty());
    }
}

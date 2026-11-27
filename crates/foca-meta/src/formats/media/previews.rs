//! Preview and thumbnail JPEGs of RAW and TIFF files: collection from the IFD chain and
//! SubIFDs, and the comparison of the smallest JPEG (thumbnail) with the largest preview (a
//! thumbnail that differs from the preview hints at an edited or cropped image).

use foca_core::{Metadata, Thumbnail};

use super::image_extra::Ifd;

/// Maximum size of one preview JPEG taken from a RAW file.
pub(crate) const MAX_PREVIEW: usize = 32 << 20;

/// Entries of the first IFD of a small TIFF block (CR3 `CMTn`).
pub(crate) fn first_ifd(t: &[u8]) -> Option<(Ifd<'_>, usize)> {
    let le = match t.get(0..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let ifd = Ifd { base: t, le };
    let first = ifd.u32(4)? as usize;
    Some((ifd, first))
}

/// Collects JPEG previews of a TIFF-based RAW: IFD chain and SubIFDs (JPEGInterchangeFormat or
/// a single JPEG strip). Returns the Panasonic `JpgFromRaw` (0x002E) blocks, whose EXIF the
/// caller merges.
pub(crate) fn tiff_previews<'t>(meta: &mut Metadata, t: &'t [u8]) -> Vec<&'t [u8]> {
    let mut full = Vec::new();
    let Some((ifd, first)) = first_ifd(t) else {
        return full;
    };
    let mut queue = vec![first];
    let mut seen = Vec::new();
    while let Some(at) = queue.pop() {
        if at == 0 || seen.contains(&at) || seen.len() >= 32 {
            continue;
        }
        seen.push(at);
        let entries = ifd.entries(at);
        let mut jpeg_off = None;
        let mut jpeg_len = None;
        let mut strip = None;
        let mut strip_len = None;
        let mut compression = 0;
        for (tag, ty, count, v) in &entries {
            match tag {
                0x0201 => jpeg_off = ifd.num(*ty, v),
                0x0202 => jpeg_len = ifd.num(*ty, v),
                0x0111 if *count == 1 => strip = ifd.num(*ty, v),
                0x0117 if *count == 1 => strip_len = ifd.num(*ty, v),
                0x0103 => compression = ifd.num(*ty, v).unwrap_or(0),
                0x014A => {
                    for c in v.as_chunks::<4>().0.iter().take(16) {
                        if let Some(o) = ifd.u32_of(c) {
                            queue.push(o as usize);
                        }
                    }
                }
                _ => {}
            }
        }
        // Panasonic JpgFromRaw is larger than the generic entry reader allows
        if let Some(v) = large_undefined(&ifd, at, 0x002E) {
            if v.starts_with(&[0xFF, 0xD8]) {
                add_preview(meta, v);
                full.push(v);
            }
        }
        let mut take = |o: Option<u64>, l: Option<u64>| {
            if let (Some(o), Some(l)) = (o, l) {
                let (o, l) = (o as usize, (l as usize).min(MAX_PREVIEW));
                if let Some(j) = o.checked_add(l).and_then(|e| t.get(o..e)) {
                    if j.starts_with(&[0xFF, 0xD8]) {
                        add_preview(meta, j);
                    }
                }
            }
        };
        take(jpeg_off, jpeg_len);
        if matches!(compression, 6 | 7) {
            take(strip, strip_len);
        }
        // next IFD in the chain
        let n = ifd.u16(at).unwrap_or(0) as usize;
        if let Some(next) = ifd.u32(at + 2 + n * 12) {
            queue.push(next as usize);
        }
    }
    full
}

/// The value of an undefined-type entry `tag` of the IFD at `at`, up to [`MAX_PREVIEW`] bytes.
fn large_undefined<'t>(ifd: &Ifd<'t>, at: usize, tag: u16) -> Option<&'t [u8]> {
    let n = usize::from(ifd.u16(at)?).min(512);
    for i in 0..n {
        let e = at + 2 + i * 12;
        if ifd.u16(e)? == tag && ifd.u16(e + 2)? == 7 {
            let len = (ifd.u32(e + 4)? as usize).min(MAX_PREVIEW);
            let off = ifd.u32(e + 8)? as usize;
            return ifd.base.get(off..off.checked_add(len)?);
        }
    }
    None
}

/// Previews found so far, kept in `fields` as sizes until `finish_previews`.
pub(crate) fn add_preview(meta: &mut Metadata, jpg: &[u8]) {
    if !jpg.starts_with(&[0xFF, 0xD8]) {
        return;
    }
    let n = meta.stats.entry("previews".into()).or_insert(0);
    *n += 1;
    let largest = meta
        .fields
        .get("raw:preview_bytes")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if jpg.len() > largest {
        meta.fields
            .insert("raw:preview_bytes".into(), jpg.len().to_string());
        PREVIEW.with(|p| *p.borrow_mut() = jpg.to_vec());
    }
    match &meta.thumbnail {
        Some(t) if t.data.len() <= jpg.len() => {}
        _ => {
            meta.thumbnail = Some(Thumbnail {
                mime: "image/jpeg".into(),
                data: jpg.to_vec(),
                differs: None,
            });
        }
    }
}

thread_local! {
    /// The largest preview of the RAW file being parsed (compared with the thumbnail).
    static PREVIEW: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Compares the smallest JPEG (thumbnail) with the largest preview; always call it after
/// collecting previews (it clears the per-thread preview buffer).
pub(crate) fn finish_previews(meta: &mut Metadata) {
    let preview = PREVIEW.with(|p| std::mem::take(&mut *p.borrow_mut()));
    let Some(t) = meta.thumbnail.as_mut() else {
        return;
    };
    if preview.is_empty() || preview.len() == t.data.len() || t.differs.is_some() {
        return;
    }
    t.differs = std::panic::catch_unwind(|| crate::thumbcmp::thumbnail_differs(&preview, &t.data))
        .ok()
        .flatten();
}

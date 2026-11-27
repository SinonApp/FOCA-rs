//! PostScript, EPS and pre-PDF Illustrator files (DSC comments and embedded XMP), plus the
//! Windows metafile headers (EMF description string and reference device size, WMF type).

use foca_core::{DocFormat, Metadata, PersonRole};

use crate::util::{clean_str, decode_text, rd_u32le, truncate, utf16le};
use crate::{Ctx, MetaError};

/// DOS EPS binary header (`C5 D0 D3 C6`).
pub(crate) const DOS_EPS: [u8; 4] = [0xC5, 0xD0, 0xD3, 0xC6];
const MAX_HEADER: usize = 256 * 1024;

pub(crate) fn is_postscript(b: &[u8]) -> bool {
    b.starts_with(b"%!PS") || b.starts_with(&DOS_EPS) || b.starts_with(b"\x04%!PS")
}

pub fn extract_eps(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("eps", || {
        let mut meta = Metadata::new(DocFormat::Eps);
        let ps: &[u8] = if b.starts_with(&DOS_EPS) {
            let off = rd_u32le(b, 4).unwrap_or(0) as usize;
            let len = rd_u32le(b, 8).unwrap_or(0) as usize;
            meta.fields.insert("eps:dos_header".into(), "yes".into());
            b.get(off..off.saturating_add(len).min(b.len()))
                .unwrap_or(&[])
        } else {
            b
        };
        let head = decode_text(&ps[..ps.len().min(MAX_HEADER)]);
        if let Some(first) = head.lines().next() {
            meta.fields
                .insert("ps:version".into(), truncate(first.trim(), 128));
        }
        dsc(&mut meta, &head);
        // XMP packet anywhere in the first megabytes
        let scan = &ps[..ps.len().min(8 << 20)];
        if let Some(s) = crate::util::find(scan, b"<x:xmpmeta", 0)
            .or_else(|| crate::util::find(scan, b"<?xpacket begin", 0))
        {
            let end = crate::util::find(scan, b"</x:xmpmeta>", s)
                .map(|e| e + 12)
                .unwrap_or(scan.len().min(s + (1 << 20)));
            let map = crate::xmp::parse(&scan[s..end], ctx);
            crate::xmp::apply(&mut meta, &map, "xmp");
        }
        Ok(meta)
    })
}

fn dsc(meta: &mut Metadata, head: &str) {
    let mut last: Option<String> = None;
    let mut fonts: Vec<String> = Vec::new();
    for line in head.lines().take(5000) {
        let line = line.trim_end();
        if line.starts_with("%%EndComments") || line.starts_with("%%BeginProlog") {
            break;
        }
        let (key, val) = if let Some(rest) = line.strip_prefix("%%+") {
            match &last {
                Some(k) => (k.clone(), rest.trim().to_string()),
                None => continue,
            }
        } else if let Some(rest) = line.strip_prefix("%%").or_else(|| line.strip_prefix('%')) {
            let Some((k, v)) = rest.split_once(':') else {
                continue;
            };
            (k.trim().to_string(), v.trim().to_string())
        } else {
            continue;
        };
        last = Some(key.clone());
        let Some(v) = clean_str(ps_string(&val)) else {
            continue;
        };
        let v = truncate(&v, 512);
        match key.as_str() {
            "Creator" | "AI8_CreatorVersion" | "AI5_FileFormat" => {
                Metadata::add_unique(&mut meta.software, &v);
                if key == "Creator" {
                    meta.application = Some(v.clone());
                }
            }
            "Producer" => {
                Metadata::add_unique(&mut meta.software, &v);
                meta.producer = Some(v.clone());
            }
            "For" => {
                meta.add_person(&v, PersonRole::Author, "dsc:For");
                meta.author.get_or_insert(v.clone());
            }
            "Title" => meta.title = Some(v.clone()),
            "CreationDate" => {
                meta.created = crate::util::normalize_date(&v).or(Some(v.clone()));
            }
            "DocumentFonts" | "DocumentNeededResources" | "DocumentSuppliedResources" => {
                for f in v.split_whitespace() {
                    if f == "font" || f == "(atend)" || fonts.len() >= 100 {
                        continue;
                    }
                    let f = f.to_string();
                    if !fonts.contains(&f) {
                        fonts.push(f);
                    }
                }
                continue;
            }
            "Routing" => {
                meta.add_person(&v, PersonRole::Other, "dsc:Routing");
            }
            _ => {}
        }
        if meta.fields.len() < 200 {
            meta.fields.insert(format!("dsc:{}", truncate(&key, 64)), v);
        }
    }
    meta.fonts = fonts;
}

/// DSC values may be PostScript strings: `(text)`.
fn ps_string(v: &str) -> &str {
    v.strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(v)
}

pub(crate) fn is_emf(b: &[u8]) -> bool {
    rd_u32le(b, 0) == Some(1) && b.get(40..44) == Some(b" EMF")
}

pub(crate) fn is_wmf(b: &[u8]) -> bool {
    b.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A])
        || (matches!(b.get(0..2), Some([1, 0] | [2, 0]))
            && b.get(2..4) == Some(&[9, 0])
            && matches!(b.get(4..6), Some([0, 3] | [0, 1])))
}

pub fn extract_emf(b: &[u8]) -> Metadata {
    let mut meta = Metadata::new(DocFormat::Emf);
    let n = rd_u32le(b, 44).unwrap_or(0) as usize;
    let off = rd_u32le(b, 48).unwrap_or(0) as usize;
    if n > 0 && off >= 88 {
        if let Some(raw) = b.get(off..off.saturating_add(n.min(1024) * 2).min(b.len())) {
            let s = utf16le(raw);
            let mut parts = s.split('\0').filter_map(clean_str);
            if let Some(app) = parts.next() {
                Metadata::add_unique(&mut meta.software, &app);
                meta.application = Some(truncate(&app, 256));
            }
            if let Some(t) = parts.next() {
                meta.title = Some(truncate(&t, 512));
            }
        }
    }
    if let (Some(px), Some(py), Some(mx), Some(my)) = (
        rd_u32le(b, 72),
        rd_u32le(b, 76),
        rd_u32le(b, 80),
        rd_u32le(b, 84),
    ) {
        meta.fields
            .insert("emf:device_pixels".into(), format!("{px}x{py}"));
        meta.fields
            .insert("emf:device_mm".into(), format!("{mx}x{my}"));
    }
    meta
}

pub fn extract_wmf(b: &[u8]) -> Metadata {
    let mut meta = Metadata::new(DocFormat::Wmf);
    if b.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) {
        meta.fields.insert("wmf:placeable".into(), "yes".into());
    }
    meta
}

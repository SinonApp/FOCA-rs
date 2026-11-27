//! Photoshop Image Resource Blocks (`8BIM`, JPEG APP13 and PSD) and IPTC-IIM records.
//!
//! Resource ids and IPTC datasets follow the ExifTool `Photoshop.pm` and `IPTC.pm` tag tables
//! (GPL-1+/Artistic, ported here as tables): caption, copyright flag and URL, writer/reader
//! application (VersionInfo), slice group name, saved path names, EXIF, XMP and the thumbnail.

use foca_core::{DocFormat, Metadata, PersonRole};

use super::image;
use crate::util::{clean_str, decode_text, truncate};
use crate::{xmp, Ctx, MetaError};

/// Maximum number of resource blocks read from one resource section.
const MAX_BLOCKS: usize = 4096;

fn be16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// A Photoshop Unicode string (`u32` count of UTF-16BE units) at `o`; returns the string and the
/// offset after it.
pub(crate) fn unicode_string(b: &[u8], o: usize) -> Option<(String, usize)> {
    let n = be32(b, o)? as usize;
    let start = o + 4;
    let end = start.checked_add(n.checked_mul(2)?)?;
    let raw = b.get(start..end)?;
    let u: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .take_while(|&c| c != 0)
        .collect();
    Some((String::from_utf16_lossy(&u), end))
}

/// One image resource: id, Pascal name and data.
pub(crate) struct Resource<'a> {
    pub id: u16,
    pub name: String,
    pub data: &'a [u8],
}

/// Splits an image resource section into blocks (signatures `8BIM` and the rare vendor ones).
pub(crate) fn blocks(b: &[u8]) -> Vec<Resource<'_>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 12 <= b.len() && out.len() < MAX_BLOCKS {
        if !matches!(
            &b[p..p + 4],
            b"8BIM" | b"MeSa" | b"PHUT" | b"AgHg" | b"DCSR"
        ) {
            break;
        }
        let id = be16(b, p + 4).unwrap_or(0);
        let nlen = usize::from(b[p + 6]);
        let name = b
            .get(p + 7..p + 7 + nlen)
            .map(decode_text)
            .unwrap_or_default();
        // the Pascal name (length byte included) is padded to an even size
        let q = p + 6 + (1 + nlen).next_multiple_of(2);
        let Some(sz) = be32(b, q).map(|s| s as usize) else {
            break;
        };
        let start = q + 4;
        let end = start.saturating_add(sz).min(b.len());
        out.push(Resource {
            id,
            name,
            data: &b[start..end],
        });
        p = start.saturating_add(sz.next_multiple_of(2));
    }
    out
}

/// Applies all resources of a section; `thumb_label` names the embedded thumbnail child.
pub(crate) fn apply(
    meta: &mut Metadata,
    section: &[u8],
    ctx: &Ctx,
    thumb_label: &str,
) -> Result<bool, MetaError> {
    let mut xmp_seen = false;
    let mut paths: Vec<String> = Vec::new();
    for r in blocks(section) {
        match r.id {
            0x0404 => iptc_records(meta, r.data),
            0x03F0 => {
                if let Some(s) = clean_str(&decode_text(r.data)) {
                    meta.description.get_or_insert(truncate(&s, 1024));
                    meta.fields
                        .insert("photoshop:Caption".into(), truncate(&s, 1024));
                }
            }
            0x040A => {
                if r.data.first() == Some(&1) {
                    meta.fields
                        .insert("photoshop:CopyrightFlag".into(), "true".into());
                }
            }
            0x040B => {
                if let Some(s) = clean_str(&decode_text(r.data)) {
                    Metadata::add_unique(&mut meta.links, &truncate(&s, 1024));
                    meta.fields
                        .insert("photoshop:URL".into(), truncate(&s, 1024));
                }
            }
            0x0421 => version_info(meta, r.data),
            0x041A => {
                // slices: version, bounding rectangle, then the group name
                if be32(r.data, 0) == Some(6) {
                    if let Some(s) = unicode_string(r.data, 20).and_then(|(s, _)| clean_str(&s)) {
                        meta.fields
                            .insert("photoshop:SlicesGroupName".into(), truncate(&s, 256));
                    }
                }
            }
            0x07D0..=0x0BB6 => {
                if let Some(n) = clean_str(&r.name) {
                    if paths.len() < 100 && !paths.contains(&n) {
                        paths.push(n);
                    }
                }
            }
            0x0BB7 => {
                if let Some(n) = r.data.first().and_then(|&l| {
                    r.data
                        .get(1..1 + usize::from(l))
                        .and_then(|s| clean_str(&decode_text(s)))
                }) {
                    meta.fields
                        .insert("photoshop:ClippingPathName".into(), truncate(&n, 256));
                }
            }
            0x0424 => {
                let map = xmp::parse(r.data, ctx);
                if !map.is_empty() {
                    xmp::apply(meta, &map, "xmp");
                    xmp_seen = true;
                }
            }
            0x0422 | 0x0423 => {
                let tiff = r.data.strip_prefix(b"Exif\0\0").unwrap_or(r.data);
                image::apply_exif_tiff(meta, tiff.to_vec(), ctx);
            }
            0x040C | 0x0409 => {
                // 28-byte thumbnail header, then a JFIF JPEG
                if let Some(jpg) = r.data.get(28..).filter(|j| j.starts_with(&[0xFF, 0xD8])) {
                    if meta.thumbnail.is_none() {
                        meta.thumbnail = Some(foca_core::Thumbnail {
                            mime: "image/jpeg".into(),
                            data: jpg.to_vec(),
                            differs: None,
                        });
                    }
                    if meta.format == DocFormat::Psd {
                        ctx.spend(jpg.len() as u64)?;
                        ctx.attach_child(meta, jpg, "thumbnail.jpg", thumb_label)?;
                    }
                }
            }
            _ => {}
        }
    }
    if !paths.is_empty() {
        meta.fields.insert(
            "photoshop:PathNames".into(),
            truncate(&paths.join("; "), 2048),
        );
    }
    Ok(xmp_seen)
}

/// VersionInfo (0x0421): version, has-real-merged flag, writer and reader names.
fn version_info(meta: &mut Metadata, d: &[u8]) {
    let Some((writer, next)) = unicode_string(d, 5) else {
        return;
    };
    if let Some(w) = clean_str(&writer) {
        // "Adobe Photoshop" adds nothing next to a versioned "Adobe Photoshop 7.0"
        if !meta.software.iter().any(|s| s.starts_with(w.as_str())) {
            Metadata::add_unique(&mut meta.software, &truncate(&w, 256));
        }
        meta.fields
            .insert("photoshop:WriterName".into(), truncate(&w, 256));
    }
    if let Some(r) = unicode_string(d, next).and_then(|(s, _)| clean_str(&s)) {
        meta.fields
            .insert("photoshop:ReaderName".into(), truncate(&r, 256));
    }
}

/// IPTC-IIM records (record 1 envelope for the character set, record 2 application).
pub(crate) fn iptc_records(meta: &mut Metadata, d: &[u8]) {
    let mut p = 0;
    let mut kw = Vec::new();
    let mut utf8 = false;
    let mut n = 0;
    while p + 5 <= d.len() && d[p] == 0x1C && n < 10_000 {
        n += 1;
        let rec = d[p + 1];
        let ds = d[p + 2];
        let len = usize::from(u16::from_be_bytes([d[p + 3], d[p + 4]]));
        if len & 0x8000 != 0 {
            break;
        }
        let Some(v) = d.get(p + 5..p + 5 + len) else {
            break;
        };
        p += 5 + len;
        if rec == 1 && ds == 90 {
            // CodedCharacterSet: ESC % G is UTF-8
            utf8 = v.windows(3).any(|w| w == b"\x1b%G");
            continue;
        }
        if rec != 2 {
            continue;
        }
        let text = if utf8 {
            String::from_utf8_lossy(v).into_owned()
        } else {
            decode_text(v)
        };
        let Some(s) = clean_str(&text) else {
            continue;
        };
        let key = match ds {
            5 => "ObjectName",
            15 => "Category",
            20 => "SupplementalCategories",
            25 => {
                kw.push(s.clone());
                continue;
            }
            40 => "SpecialInstructions",
            55 => "DateCreated",
            60 => "TimeCreated",
            62 => "DigitalCreationDate",
            63 => "DigitalCreationTime",
            65 => "OriginatingProgram",
            70 => "ProgramVersion",
            80 => "By-line",
            85 => "By-lineTitle",
            90 => "City",
            92 => "Sub-location",
            95 => "Province-State",
            100 => "CountryCode",
            101 => "Country",
            103 => "OriginalTransmissionReference",
            105 => "Headline",
            110 => "Credit",
            115 => "Source",
            116 => "CopyrightNotice",
            118 => "Contact",
            120 => "Caption-Abstract",
            122 => "Writer-Editor",
            135 => "LanguageIdentifier",
            _ => continue,
        };
        match ds {
            80 => {
                meta.add_person(&s, PersonRole::Author, "iptc:By-line");
                meta.author.get_or_insert(s.clone());
            }
            122 => meta.add_person(&s, PersonRole::Other, "iptc:Writer-Editor"),
            118 => meta.add_person(&s, PersonRole::Other, "iptc:Contact"),
            65 => Metadata::add_unique(&mut meta.software, &s),
            105 => {
                meta.title.get_or_insert(s.clone());
            }
            110 | 116 => {
                meta.custom
                    .entry("copyright".into())
                    .or_insert_with(|| truncate(&s, 512));
            }
            120 => {
                meta.description.get_or_insert(s.clone());
            }
            135 => {
                meta.language.get_or_insert(truncate(&s, 32));
            }
            _ => {}
        }
        let k = format!("iptc:{key}");
        match meta.fields.get_mut(&k) {
            Some(prev) if !prev.split("; ").any(|x| x == s) && prev.len() < 2048 => {
                prev.push_str("; ");
                prev.push_str(&truncate(&s, 512));
            }
            Some(_) => {}
            None => {
                meta.fields.insert(k, truncate(&s, 512));
            }
        }
    }
    if let (Some(d), Some(t)) = (
        meta.fields.get("iptc:DateCreated").cloned(),
        meta.fields.get("iptc:TimeCreated").cloned(),
    ) {
        if d.len() == 8 && meta.created.is_none() {
            let iso = format!(
                "{}-{}-{}T{}:{}:{}",
                &d[0..4],
                &d[4..6],
                &d[6..8],
                t.get(0..2).unwrap_or("00"),
                t.get(2..4).unwrap_or("00"),
                t.get(4..6).unwrap_or("00")
            );
            meta.created = crate::util::normalize_date(&iso);
        }
    }
    if !kw.is_empty() {
        let k = truncate(&kw.join(", "), 2048);
        meta.fields.insert("iptc:Keywords".into(), k.clone());
        meta.keywords.get_or_insert(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(id: u16, name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = b"8BIM".to_vec();
        v.extend(id.to_be_bytes());
        v.push(name.len() as u8);
        v.extend(name);
        if (1 + name.len()) % 2 == 1 {
            v.push(0);
        }
        v.extend((data.len() as u32).to_be_bytes());
        v.extend(data);
        if data.len() % 2 == 1 {
            v.push(0);
        }
        v
    }

    fn ustr(s: &str) -> Vec<u8> {
        let u: Vec<u16> = s.encode_utf16().collect();
        let mut v = (u.len() as u32).to_be_bytes().to_vec();
        for c in u {
            v.extend(c.to_be_bytes());
        }
        v
    }

    #[test]
    fn resources_and_utf8_iptc() {
        let mut vi = vec![0, 0, 0, 1, 1];
        vi.extend(ustr("Adobe Photoshop"));
        vi.extend(ustr("Adobe Photoshop CC 2019"));
        let mut iptc = vec![0x1C, 1, 90, 0, 3, 0x1B, b'%', b'G'];
        for (ds, v) in [
            (80u8, "Олена Коваль".as_bytes()),
            (90, "東京".as_bytes()),
            (25, b"one"),
            (25, b"two"),
            (116, "© Агентство".as_bytes()),
        ] {
            iptc.extend([0x1C, 2, ds]);
            iptc.extend((v.len() as u16).to_be_bytes());
            iptc.extend(v);
        }
        let mut sec = res(0x0421, b"", &vi);
        sec.extend(res(0x0404, b"", &iptc));
        sec.extend(res(0x07D0, b"Path 1", &[0; 26]));
        sec.extend(res(0x040B, b"", b"https://intranet.example/x"));
        let limits = crate::Limits::default();
        let budget = std::cell::Cell::new(limits.max_unzipped_total);
        let ctx = Ctx::standalone(&limits, &budget);
        let mut m = Metadata::new(DocFormat::Jpeg);
        apply(&mut m, &sec, &ctx, "thumb").unwrap();
        assert_eq!(m.author.as_deref(), Some("Олена Коваль"));
        assert_eq!(m.fields["iptc:City"], "東京");
        assert_eq!(m.fields["iptc:Keywords"], "one, two");
        assert_eq!(m.fields["photoshop:PathNames"], "Path 1");
        assert_eq!(m.custom["copyright"], "© Агентство");
        assert!(m.software.iter().any(|s| s == "Adobe Photoshop"));
        assert!(m.links.iter().any(|l| l.contains("intranet")));
    }
}
